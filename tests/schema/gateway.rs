//! ADR 0037. Exercise gateway privileges under the actual provisioned logins.
use super::*;

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn gateway_roles_and_function_boundaries() {
    let db = TestDb::migrated().await;
    for role in [API, WORKER, ISSUANCE] {
        let mut c = connect(&db.0, role).await;
        for sql in [
            "SELECT ciphertext FROM openmettle.gateway_generations",
            "UPDATE openmettle.gateway_bindings SET state='ready'",
            "UPDATE openmettle.gateway_settlements SET measured=0",
            "INSERT INTO openmettle.gateway_nonces DEFAULT VALUES",
        ] {
            expect_state(&mut c, sql, "42501").await;
        }
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn sweeps_can_read_only_pending_rows_in_age_order() {
    let db = TestDb::migrated().await;
    let mut c = connect(&db.0, pg::GATEWAY).await;
    // An empty fixture normally chooses a sequential scan. Check that each
    // bounded sweep has an ordered index path with no residual state filter.
    c.execute("SET enable_seqscan = off").await.unwrap();
    for (sql, index) in [
        (
            "EXPLAIN (COSTS OFF) SELECT id FROM openmettle.gateway_requests
          WHERE state='reserved' ORDER BY created_at,id LIMIT 10",
            "gateway_requests_reserved_idx",
        ),
        (
            "EXPLAIN (COSTS OFF) SELECT id FROM openmettle.gateway_requests
          WHERE state='handed_off' AND NOT settled_final ORDER BY created_at,id LIMIT 10",
            "gateway_requests_outstanding_idx",
        ),
        (
            "EXPLAIN (COSTS OFF) SELECT request_id FROM openmettle.gateway_settlements
          WHERE NOT final ORDER BY updated_at,request_id LIMIT 10",
            "gateway_settlements_nonfinal_idx",
        ),
    ] {
        let plan = sqlx::query_scalar::<_, String>(sql)
            .fetch_all(&mut c)
            .await
            .unwrap()
            .join("\n");
        assert!(
            plan.contains(index) && !plan.contains("Filter:") && !plan.contains("Sort"),
            "{plan}"
        );
    }
    let plan = sqlx::query_scalar::<_, String>(concat!(
        "EXPLAIN (COSTS OFF) ",
        include_str!("../../src/authz/gateway/backfill.sql")
    ))
    .bind(INSTALL)
    .bind(None::<String>)
    .bind(None::<String>)
    .bind(4_i64)
    .fetch_all(&mut c)
    .await
    .unwrap()
    .join("\n");
    assert!(
        plan.contains("quota_reservations_overdue_handoff_idx"),
        "{plan}"
    );
}

use openmettle_core::{
    authz::gateway::{self, Authority, Call, Intent, Reservation},
    provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
    runs::WriteTransaction,
};
use sqlx::{PgPool, postgres::PgPoolOptions};
const INSTALL: &str = "00000000-0000-4000-8000-000000000023";
const PRINCIPAL: &str = "00000000-0000-4000-8000-000000000024";
const BUDGET: &str = "00000000-0000-4000-8000-000000000025";
const LEASE: &str = "00000000-0000-4000-8000-000000000026";
async fn uuid(c: &mut PgConnection) -> String {
    sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(c)
        .await
        .unwrap()
}
fn pool(db: &TestDb, role: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(3)
        .connect_lazy_with(db.1.options(role))
}
fn keys() -> GatewayKeys {
    GatewayKeys::new(&[("fixture".into(), [42; 32])]).unwrap()
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn populated_upgrade_races_intents_and_fences_generations() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(5));
    migrate::apply(&settings, &MIGRATIONS[..22]).await.unwrap();
    let mut c = connect(&db.0, API).await;
    let actor = new_user(&mut c).await;
    let scope = personal_scope(&mut c, &actor).await;
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT personal_user_id::text FROM openmettle.scopes WHERE id=$1::uuid"
        )
        .bind(scope)
        .fetch_one(&mut c)
        .await
        .unwrap(),
        actor
    );
    new_user(&mut c).await;
    let g = pool(&db, pg::GATEWAY);
    let binding: String = sqlx::query_scalar(
        "INSERT INTO openmettle.gateway_bindings (installation,user_id,principal,budget)
        VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid) RETURNING id::text",
    )
    .bind(INSTALL)
    .bind(&actor)
    .bind(PRINCIPAL)
    .bind(BUDGET)
    .fetch_one(&g)
    .await
    .unwrap();
    for col in ["principal", "budget", "user_id"] {
        let stmt = format!(
            "INSERT INTO openmettle.gateway_bindings (installation,user_id,principal,budget)
           SELECT installation,{}, {}, {} FROM openmettle.gateway_bindings",
            if col == "user_id" {
                "user_id".to_string()
            } else {
                format!("'{}'::uuid", new_user(&mut c).await)
            },
            if col == "principal" {
                "principal"
            } else {
                "gen_random_uuid()"
            },
            if col == "budget" {
                "budget"
            } else {
                "gen_random_uuid()"
            }
        );
        expect_state(&mut connect(&db.0, pg::GATEWAY).await, &stmt, "23505").await;
    }
    let params = serde_json::json!({"budget":BUDGET});
    let i = Intent {
        binding: &binding,
        revision: 1,
        generation: 1,
        action: "issue",
        expected_revision: 0,
        parameters: &params,
    };
    let (a, b) = tokio::join!(gateway::intent(&g, &i), gateway::intent(&g, &i));
    let op = a.unwrap();
    assert_eq!(op, b.unwrap());
    assert_eq!(
        gateway::intent(
            &g,
            &Intent {
                expected_revision: 9,
                ..i
            }
        )
        .await
        .unwrap_err(),
        gateway::Error::Conflict
    );
    let ctx = Context {
        installation: INSTALL,
        user_id: &actor,
        binding_id: &binding,
        principal: PRINCIPAL,
        generation: 1,
    };
    let sealer = GatewaySealer::new(keys(), g.clone());
    let bearer = Bearer::new(b"fixture-user-key").unwrap();
    let (fingerprint, mut e) = sealer.seal(&ctx, &bearer).await.unwrap();
    for role in [API, WORKER, ISSUANCE] {
        assert!(
            GatewaySealer::new(keys(), pool(&db, role))
                .seal(&ctx, &bearer)
                .await
                .is_err()
        );
    }
    // Force the first reservation to collide with the committed nonce. Only
    // this isolated fixture may choose a nonce; production always uses SystemRandom.
    let mut owner = connect(&db.0, OWNER).await;
    owner
        .execute(
            "CREATE SEQUENCE openmettle.fixture_gateway_attempt;
        CREATE FUNCTION openmettle.fixture_gateway_collision() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
        BEGIN
            IF nextval('openmettle.fixture_gateway_attempt')=1 THEN
                SELECT n.nonce INTO NEW.nonce FROM openmettle.gateway_nonces n
                WHERE n.key_fingerprint=NEW.key_fingerprint LIMIT 1;
            END IF;
            RETURN NEW;
        END $$;
        CREATE TRIGGER fixture_gateway_collision BEFORE INSERT ON openmettle.gateway_nonces
        FOR EACH ROW EXECUTE FUNCTION openmettle.fixture_gateway_collision()",
        )
        .await
        .unwrap();
    let (_, second) = sealer.seal(&ctx, &bearer).await.unwrap();
    assert_ne!(second.nonce, e.nonce);
    assert_eq!(
        keys().open(&ctx, &second).unwrap().authorization(),
        bearer.authorization()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT last_value FROM openmettle.fixture_gateway_attempt")
            .fetch_one(&mut owner)
            .await
            .unwrap(),
        2
    );
    let rollover =
        GatewayKeys::new(&[("new".into(), [43; 32]), ("fixture".into(), [42; 32])]).unwrap();
    assert_eq!(
        rollover.open(&ctx, &e).unwrap().authorization(),
        bearer.authorization()
    );
    assert!(
        GatewayKeys::new(&[("new".into(), [43; 32])])
            .unwrap()
            .open(&ctx, &e)
            .is_err()
    );
    for other in [
        Context {
            installation: LEASE,
            ..ctx
        },
        Context {
            principal: LEASE,
            ..ctx
        },
        Context {
            user_id: LEASE,
            ..ctx
        },
        Context {
            binding_id: LEASE,
            ..ctx
        },
        Context {
            generation: 2,
            ..ctx
        },
    ] {
        assert!(rollover.open(&other, &e).is_err());
    }
    e.ciphertext[0] ^= 1;
    assert!(rollover.open(&ctx, &e).is_err());
    e.ciphertext[0] ^= 1;
    assert_eq!(
        sqlstate(
            sqlx::query(
                "INSERT INTO openmettle.gateway_nonces (key_fingerprint,nonce) VALUES ($1,$2)"
            )
            .bind(fingerprint.as_slice())
            .bind(e.nonce.as_slice())
            .execute(&g)
            .await
        ),
        "23505"
    );
    sqlx::query("INSERT INTO openmettle.gateway_generations (binding_id,generation,remote_key,expires_at,key_id,key_fingerprint,nonce,ciphertext)
        VALUES ($1::uuid,1,gen_random_uuid(),clock_timestamp()+interval '1 hour',$2,$3,$4,$5)")
        .bind(&binding).bind(&e.key_id).bind(fingerprint.as_slice()).bind(e.nonce.as_slice()).bind(&e.ciphertext).execute(&g).await.unwrap();
    sqlx::query("UPDATE openmettle.gateway_intents SET claim=$2::uuid,due_at=clock_timestamp()+interval '1 minute' WHERE operation_id=$1::uuid")
        .bind(&op)
        .bind(LEASE)
        .execute(&g)
        .await
        .unwrap();
    expect_state(
        &mut connect(&db.0, pg::GATEWAY).await,
        "UPDATE openmettle.gateway_intents SET complete=true WHERE claim IS NOT NULL",
        "23514",
    )
    .await;
    assert!(
        !gateway::publish_generation(&g, &binding, &op, LEASE, None)
            .await
            .unwrap()
    );
    sqlx::query("INSERT INTO openmettle.gateway_audit (binding_id,desired_revision,operation_id,step,outcome,remote_handle)
        SELECT binding_id,1,$1::uuid,'key','confirmed',remote_key FROM openmettle.gateway_generations")
        .bind(&op).execute(&g).await.unwrap();
    let (left, right) = tokio::join!(
        gateway::publish_generation(&g, &binding, &op, LEASE, None),
        gateway::publish_generation(&g, &binding, &op, LEASE, None)
    );
    assert_ne!(left.unwrap(), right.unwrap());
    // Two confirmed successors raced from generation one. A delayed reply
    // cannot publish over the successor that won the predecessor check.
    let mut successors = Vec::new();
    for generation in [2, 3] {
        let operation = gateway::intent(
            &g,
            &Intent {
                action: "rotate",
                generation,
                ..i
            },
        )
        .await
        .unwrap();
        let (fingerprint, sealed) = sealer
            .seal(&Context { generation, ..ctx }, &bearer)
            .await
            .unwrap();
        let remote = uuid(&mut c).await;
        sqlx::query(
            "INSERT INTO openmettle.gateway_generations
            (binding_id,generation,remote_key,expires_at,key_id,key_fingerprint,nonce,ciphertext)
            VALUES ($1::uuid,$2,$3::uuid,now()+interval '1 hour',$4,$5,$6,$7)",
        )
        .bind(&binding)
        .bind(generation)
        .bind(&remote)
        .bind(sealed.key_id)
        .bind(fingerprint.as_slice())
        .bind(sealed.nonce.as_slice())
        .bind(sealed.ciphertext)
        .execute(&g)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_intents SET claim=$2::uuid,due_at=now()+interval '1 minute'
            WHERE operation_id=$1::uuid",
        )
        .bind(&operation)
        .bind(LEASE)
        .execute(&g)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_audit
            (binding_id,desired_revision,operation_id,step,outcome,remote_handle)
            VALUES ($1::uuid,1,$2::uuid,'key','confirmed',$3::uuid)",
        )
        .bind(&binding)
        .bind(&operation)
        .bind(&remote)
        .execute(&g)
        .await
        .unwrap();
        successors.push(operation);
    }
    let (a, b) = tokio::join!(
        gateway::publish_generation(&g, &binding, &successors[0], LEASE, Some(1)),
        gateway::publish_generation(&g, &binding, &successors[1], LEASE, Some(1))
    );
    let first = a.unwrap();
    assert_ne!(first, b.unwrap());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT active_generation FROM openmettle.gateway_bindings WHERE id=$1::uuid"
        )
        .bind(&binding)
        .fetch_one(&g)
        .await
        .unwrap(),
        if first { 2 } else { 3 }
    );
    let stale = &successors[usize::from(first)];
    assert!(
        !gateway::publish_generation(&g, &binding, stale, LEASE, Some(1))
            .await
            .unwrap()
    );
    sqlx::query("UPDATE openmettle.gateway_bindings SET desired_revision=2,state='suspended' WHERE id=$1::uuid")
        .bind(&binding).execute(&g).await.unwrap();
    assert_eq!(
        gateway::intent(&g, &i).await.unwrap_err(),
        gateway::Error::Conflict
    );
    assert!(
        !gateway::publish_generation(&g, &binding, &op, LEASE, Some(1))
            .await
            .unwrap()
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn handoff_rechecks_authority_and_only_a_released_run_round_can_retry() {
    let db = TestDb::migrated().await;
    db.admin()
        .await
        .execute(
            "INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit)
        VALUES('personal','usage_tokens',1000000),('project','usage_tokens',1000000)",
        )
        .await
        .unwrap();

    let mut c = connect(&db.0, OWNER).await;
    authz_store::providers(&mut c).await;
    let actor =
        authz_store::account(&mut c, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let other =
        authz_store::account(&mut c, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let scope = authz_runs::personal_of(&db, &actor).await;
    let foreign = authz_runs::personal_of(&db, &other).await;
    let credential = authz_runs::seeded_session(&db, &actor, 4, None).await;
    let other_credential = authz_runs::seeded_session(&db, &other, 5, None).await;
    let api = pool(&db, API);
    let worker = pool(&db, WORKER);
    let g = pool(&db, pg::GATEWAY);
    let binding: String = sqlx::query_scalar(
        "INSERT INTO openmettle.gateway_bindings (installation,user_id,principal,budget)
        VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid) RETURNING id::text",
    )
    .bind(INSTALL)
    .bind(&actor.user)
    .bind(PRINCIPAL)
    .bind(BUDGET)
    .fetch_one(&g)
    .await
    .unwrap();
    let ctx = Context {
        installation: INSTALL,
        user_id: &actor.user,
        binding_id: &binding,
        principal: PRINCIPAL,
        generation: 1,
    };
    let (finger, e) = GatewaySealer::new(keys(), g.clone())
        .seal(&ctx, &Bearer::generate().unwrap())
        .await
        .unwrap();
    sqlx::query("INSERT INTO openmettle.gateway_generations (binding_id,generation,remote_key,expires_at,key_id,key_fingerprint,nonce,ciphertext)
        VALUES ($1::uuid,1,gen_random_uuid(),clock_timestamp()+interval '1 hour',$2,$3,$4,$5)")
        .bind(&binding).bind(&e.key_id).bind(finger.as_slice()).bind(e.nonce.as_slice()).bind(e.ciphertext).execute(&g).await.unwrap();
    sqlx::query("INSERT INTO openmettle.gateway_policy (binding_id,revision,scope_id,approval_id,model,report_source,provider_generation,approval_generation,user_generation,capabilities)
        VALUES ($1::uuid,1,$2::uuid,$3::uuid,'a',gen_random_uuid(),0,0,0,'{\"inference\":true}')")
        .bind(&binding).bind(&scope).bind(&actor.approval).execute(&g).await.unwrap();
    sqlx::query("INSERT INTO openmettle.user_capability_grants (user_id,capability,granted,updated_by_user_id)
        VALUES ($1::uuid,'inference',true,$1::uuid)").bind(&actor.user).execute(&api).await.unwrap();
    let ring = keys();
    struct GatewayHandoffFx {
        catalog: openmettle_core::model_config::Catalog,
        effective: openmettle_core::model_config::Effective,
        request: openmettle_core::provider_http::inference::Request,
        route: openmettle_core::provider_http::inference::Gateway,
    }
    impl GatewayHandoffFx {
        fn new(units: i64, cost: Option<u64>, requires_device_slot: bool) -> Self {
            use openmettle_core::{
                model_config::{Catalog, Selection},
                provider_http::{
                    Trust,
                    inference::{Gateway, History, Protocol, Qualification, Request, Timeouts},
                },
            };
            let ca = crate::ca::Ca::new();
            let mut doc: serde_json::Value =
                serde_json::from_slice(include_bytes!("../fixtures/conversation-catalog-v1.json"))
                    .unwrap();
            let entry = &mut doc["models"]["a"];
            entry["context_window"] = serde_json::json!(units);
            entry["output_limit"] = serde_json::json!(units);
            entry["requires_device_slot"] = serde_json::json!(requires_device_slot);
            if let Some(c) = cost {
                entry["cost_bound"] = serde_json::json!({
                    "fixed_micros": c,
                    "micros_per_token": 0
                });
            } else {
                entry.as_object_mut().unwrap().remove("cost_bound");
            }
            doc["presets"]["study"]["defaults"]["controls"]["output_reserve"] =
                serde_json::json!((units / 2).max(1));
            let catalog = Catalog::load(&serde_json::to_vec(&doc).unwrap()).unwrap();
            let effective = catalog
                .resolve(
                    &Selection::default(),
                    &serde_json::from_value(serde_json::json!({
                        "model": "a",
                        "layer": {"controls": {"context_window": units, "output_reserve": (units / 2).max(1)}}
                    }))
                    .unwrap(),
                    None,
                    |_, _| true,
                )
                .unwrap();
            let route = Gateway::new(
                "https://provider.example.test/v1/chat/completions",
                Trust::Bundle(&ca.pem()),
                &[],
                Qualification {
                    model: effective.model.clone(),
                    pin: effective.profile.clone(),
                    protocol: Protocol::Chat,
                    json: true,
                    sse: false,
                    functions: None,
                    images: false,
                    parallel: false,
                    usage: true,
                    tool_separator_whitespace: false,
                },
                Timeouts {
                    setup: Duration::from_secs(5),
                    idle: Duration::from_secs(30),
                    overall: Duration::from_secs(45),
                },
            )
            .unwrap();
            let request = Request {
                history: vec![History::User("gateway handoff fixture".into())],
                tools: None,
                parallel: None,
                stream: false,
            };
            Self {
                catalog,
                effective,
                request,
                route,
            }
        }
        fn billable(&self) -> openmettle_core::provider_http::BillableInferenceRef<'_> {
            openmettle_core::provider_http::BillableInferenceRef {
                installation: INSTALL,
                route: &self.route,
            }
        }
        fn prepare(
            &self,
            server: bool,
        ) -> openmettle_core::provider_http::inference::PreparedRequest<'_> {
            self.billable()
                .prepare(&self.catalog, &self.effective, &self.request, server)
                .unwrap()
        }
    }
    let fx = GatewayHandoffFx::new(10, None, false);
    let dev_fx = GatewayHandoffFx::new(10, None, true);
    let cost_fx = GatewayHandoffFx::new(10, Some(80), false);
    // Same identity and reservation across every read: toggling current authority
    // immediately changes eligibility, even though the request already committed.
    let id = uuid(&mut c).await;
    fn caller<'a>(
        actor: &'a authz_store::Account,
        sid: &'a str,
        sc: &'a str,
        reservation: &'a str,
    ) -> Call<'a> {
        Call {
            installation: INSTALL,
            model: "a",
            units: 10,
            reservation: Reservation {
                id: reservation,
                scope_id: sc,
                actor: &actor.user,
                approval: &actor.approval,
            },
            authority: Authority::Session {
                credential: sid,
                native_audience: None,
            },
        }
    }
    let pending = gateway::reserve(&api, caller(&actor, &credential, &scope, &id))
        .await
        .unwrap();
    assert!(matches!(
        pending
            .handoff(&api, &ring, &fx.billable(), fx.prepare(false))
            .await,
        Err(gateway::Error::Refused)
    ));
    sqlx::query("UPDATE openmettle.gateway_bindings SET active_generation=1,observed_revision=1,state='ready'").execute(&g).await.unwrap();
    for (deny, restore) in [
        (
            "UPDATE openmettle.local_sessions SET revoked=true",
            "UPDATE openmettle.local_sessions SET revoked=false",
        ),
        (
            "UPDATE openmettle.local_sessions SET expires_ms=2",
            "UPDATE openmettle.local_sessions SET expires_ms=4102444800000",
        ),
        (
            "UPDATE openmettle.users SET session_generation=1",
            "UPDATE openmettle.users SET session_generation=0",
        ),
        (
            "UPDATE openmettle.local_identity_approvals SET active=false",
            "UPDATE openmettle.local_identity_approvals SET active=true",
        ),
        (
            "UPDATE openmettle.user_capability_grants SET granted=false",
            "UPDATE openmettle.user_capability_grants SET granted=true",
        ),
        (
            "UPDATE openmettle.gateway_generations SET expires_at=now()",
            "UPDATE openmettle.gateway_generations SET expires_at=now()+interval '1 hour'",
        ),
    ] {
        c.execute(deny).await.unwrap();
        assert!(
            matches!(
                pending
                    .handoff(&api, &ring, &fx.billable(), fx.prepare(false))
                    .await,
                Err(gateway::Error::Refused)
            ),
            "{deny}"
        );
        c.execute(restore).await.unwrap();
    }
    for (sid, sc) in [(&other_credential, &scope), (&credential, &foreign)] {
        let id = uuid(&mut c).await;
        let p = gateway::reserve(&api, caller(&actor, sid, sc, &id))
            .await
            .unwrap();
        assert!(matches!(
            p.handoff(&api, &ring, &fx.billable(), fx.prepare(false))
                .await,
            Err(gateway::Error::Refused)
        ));
        let (a, b) = tokio::join!(p.release(&api), p.release(&api));
        assert_ne!(a.unwrap(), b.unwrap());
        // A caller's released reservation is terminal even for a fresh request UUID.
        assert_eq!(sqlstate(sqlx::query("INSERT INTO openmettle.gateway_requests
            (id,reservation_id,scope_id,actor_user_id,approval_id,installation,model,units,dispatch_hash,session_id)
            VALUES (gen_random_uuid(),$1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,'a',10,sha256('x'::bytea),$6)")
            .bind(&id).bind(sc).bind(&actor.user).bind(&actor.approval).bind(INSTALL).bind(&sid[..43])
            .execute(&api).await), "23505");
    }
    assert!(!pending.release(&worker).await.unwrap());
    assert!(
        pending
            .handoff(&api, &ring, &fx.billable(), fx.prepare(false))
            .await
            .is_ok()
    );
    assert!(!pending.release(&api).await.unwrap());
    assert!(matches!(
        pending
            .handoff(&api, &ring, &fx.billable(), fx.prepare(false))
            .await,
        Err(gateway::Error::Refused)
    ));
    let race_id = uuid(&mut c).await;
    let race = gateway::reserve(&api, caller(&actor, &credential, &scope, &race_id))
        .await
        .unwrap();
    let race_billable = fx.billable();
    let (released, handed) = tokio::join!(
        race.release(&api),
        race.handoff(&api, &ring, &race_billable, fx.prepare(false))
    );
    assert_ne!(released.unwrap(), handed.is_ok());

    // A confirmed project policy pins one editor grant cycle. Removing and
    // granting the same role again cannot revive the old policy.
    use openmettle_core::authz::{Grantee, ProjectRole, projects};
    let (project, project_scope) = run_admission::new_project(&db, &other, "gateway-project").await;
    let editor = Grantee::User(actor.user.clone());
    let mut project_api = run_admission::api(&db).await;
    authz_store::applied(
        projects::set_project_member_role(
            &mut project_api,
            &authz_store::ctx(&other, "gateway-grant"),
            &project,
            &editor,
            ProjectRole::Editor,
        )
        .await,
    );
    sqlx::query("INSERT INTO openmettle.gateway_policy (binding_id,revision,scope_id,approval_id,model,report_source,
        provider_generation,approval_generation,user_generation,grant_cycle,capabilities)
        SELECT p.binding_id,p.revision,g.scope_id,p.approval_id,p.model,p.report_source,0,0,0,h.cycle_id,p.capabilities
        FROM openmettle.gateway_policy p, openmettle.grant_assignments g
        JOIN openmettle.grant_changes h ON h.assignment_id=g.id AND h.revision=g.last_revision
        WHERE g.scope_id=$1::uuid AND g.grantee_user_id=$2::uuid AND g.assignment_key='editor'")
        .bind(&project_scope).bind(&actor.user).execute(&g).await.unwrap();
    let id = uuid(&mut c).await;
    let project_call = gateway::reserve(&api, caller(&actor, &credential, &project_scope, &id))
        .await
        .unwrap();
    // A pre-v15 project can legitimately have no settings. Its grants remain live.
    sqlx::query("DELETE FROM openmettle.project_settings WHERE project_id=$1::uuid")
        .bind(&project)
        .execute(&mut c)
        .await
        .unwrap();
    project_call
        .handoff(&api, &ring, &fx.billable(), fx.prepare(false))
        .await
        .unwrap();
    let id = uuid(&mut c).await;
    let next = gateway::reserve(&api, caller(&actor, &credential, &project_scope, &id))
        .await
        .unwrap();
    authz_store::applied(
        projects::revoke_project_member(
            &mut project_api,
            &authz_store::ctx(&other, "gateway-revoke"),
            &project,
            &editor,
        )
        .await,
    );
    assert!(matches!(
        next.handoff(&api, &ring, &fx.billable(), fx.prepare(false))
            .await,
        Err(gateway::Error::Refused)
    ));
    authz_store::applied(
        projects::set_project_member_role(
            &mut project_api,
            &authz_store::ctx(&other, "gateway-regrant"),
            &project,
            &editor,
            ProjectRole::Editor,
        )
        .await,
    );
    assert!(matches!(
        next.handoff(&api, &ring, &fx.billable(), fx.prepare(false))
            .await,
        Err(gateway::Error::Refused)
    ));

    let r = run_admission::request(&db, &scope, "personal", &actor, "gateway-rounds").await;
    let run = run_admission::admitted(&db, &r).await;
    sqlx::query("UPDATE openmettle.runs SET round_limit=1 WHERE id=$1::uuid")
        .bind(&run)
        .execute(&mut c)
        .await
        .unwrap();
    let claim = openmettle_core::authz::runs::claim_next(
        &mut run_admission::worker(&db).await,
        &run_admission::OPEN,
        &run_admission::LEASES,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(claim.round_limit, 1);
    let hold_id = uuid(&mut c).await;
    let reserve = || Reservation {
        id: &hold_id,
        scope_id: &scope,
        actor: &actor.user,
        approval: &actor.approval,
    };
    let mut api_c = api.acquire().await.unwrap();
    let mut tx = WriteTransaction::begin(&mut api_c).await.unwrap();
    for _ in 0..2 {
        gateway::hold(&mut tx, &reserve(), Some(&run), 30)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    let round = |n, token| Call {
        reservation: reserve(),
        installation: INSTALL,
        model: "a",
        units: 10,
        authority: Authority::Lease {
            run: &run,
            round: n,
            token,
        },
    };
    let insert_round = |scope| {
        sqlx::query("INSERT INTO openmettle.gateway_requests
        (id,reservation_id,scope_id,actor_user_id,approval_id,installation,model,units,dispatch_hash,run_id,round)
        VALUES (gen_random_uuid(),$1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,'a',10,sha256(repeat('x',32)::bytea),$6::uuid,1)")
        .bind(&hold_id).bind(scope).bind(&actor.user).bind(&actor.approval).bind(INSTALL).bind(&run)
    };
    assert_eq!(
        sqlstate(insert_round(&foreign).execute(&worker).await),
        "23503"
    );
    let (left, right) = tokio::join!(
        insert_round(&scope).execute(&worker),
        insert_round(&scope).execute(&worker)
    );
    let loser = if left.is_ok() {
        right
    } else {
        right.unwrap();
        left
    };
    assert_eq!(sqlstate(loser), "23505");
    let first: String = sqlx::query_scalar(
        "SELECT id::text FROM openmettle.gateway_requests WHERE reservation_id=$1::uuid",
    )
    .bind(&hold_id)
    .fetch_one(&g)
    .await
    .unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT openmettle.gateway_release($1::uuid,repeat('x',32)::bytea)"
        )
        .bind(&first)
        .fetch_one(&worker)
        .await
        .unwrap()
    );
    assert!(gateway::reserve(&worker, round(1, LEASE)).await.is_err());
    let mut p = gateway::reserve(&worker, round(1, &claim.claim_token))
        .await
        .unwrap();
    assert_ne!(p.id, first);
    assert_eq!(
        sqlstate(insert_round(&scope).execute(&worker).await),
        "23505"
    );
    assert!(matches!(
        p.handoff(&api, &ring, &fx.billable(), fx.prepare(true))
            .await,
        Err(gateway::Error::Refused)
    ));
    c.execute("UPDATE openmettle.runs SET lease_expires_at=clock_timestamp()")
        .await
        .unwrap();
    assert!(matches!(
        p.handoff(&worker, &ring, &fx.billable(), fx.prepare(true))
            .await,
        Err(gateway::Error::Refused)
    ));
    c.execute("UPDATE openmettle.runs SET lease_expires_at=execution_expires_at")
        .await
        .unwrap();
    // A leased run with no committed device_reservations hold MUST reject a device-slot profile
    // before committing gateway_requests.
    assert!(matches!(
        p.handoff(&worker, &ring, &dev_fx.billable(), dev_fx.prepare(true))
            .await,
        Err(gateway::Error::Refused)
    ));
    // The marker carries the database-canonical id, so an equivalent noncanonical spelling of
    // `Pending::id` (braced, uppercase) still resolves to this request and is still refused.
    let spelled = format!("{{{}}}", p.id.to_uppercase());
    let canonical = std::mem::replace(&mut p.id, spelled);
    assert!(matches!(
        p.handoff(&worker, &ring, &dev_fx.billable(), dev_fx.prepare(true))
            .await,
        Err(gateway::Error::Refused)
    ));
    let state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.gateway_requests WHERE id=$1::uuid")
            .bind(&canonical)
            .fetch_one(&g)
            .await
            .unwrap();
    assert_eq!(state, "reserved");
    p.id = canonical;
    let gateway::BillableDispatch::Server(_) = p
        .handoff(&worker, &ring, &fx.billable(), fx.prepare(true))
        .await
        .unwrap()
    else {
        panic!("a leased handoff must yield BillableDispatch::Server");
    };
    assert!(!p.release(&worker).await.unwrap());
    assert_eq!(
        sqlstate(insert_round(&scope).execute(&worker).await),
        "23505"
    );
    check_settlement_finality(&g, &p.id, &pending.id).await;

    // A metered but unsent request at the front of the index cannot hide an older-writer orphan.
    let bound_reservation = uuid(&mut c).await;
    let bound = gateway::reserve(
        &api,
        caller(&actor, &credential, &scope, &bound_reservation),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE openmettle.gateway_requests SET created_at='2000-01-01' WHERE id=$1::uuid")
        .bind(&bound.id)
        .execute(&mut c)
        .await
        .unwrap();
    let legacy = uuid(&mut c).await;
    let mut tx = WriteTransaction::begin(&mut api_c).await.unwrap();
    gateway::hold(
        &mut tx,
        &caller(&actor, &credential, &scope, &legacy).reservation,
        None,
        10,
    )
    .await
    .unwrap();
    let orphan = uuid(&mut c).await;
    sqlx::query("INSERT INTO openmettle.gateway_requests
        (reservation_id,scope_id,actor_user_id,approval_id,installation,model,units,dispatch_hash,session_id,id)
        VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,'a',10,sha256(repeat('x',32)::bytea),$6,$7::uuid)")
        .bind(&legacy).bind(&scope).bind(&actor.user).bind(&actor.approval).bind(INSTALL).bind(&credential[..43]).bind(&orphan)
        .execute(tx.connection().unwrap()).await.unwrap();
    tx.commit().await.unwrap();
    sqlx::query("UPDATE openmettle.gateway_requests SET created_at='2000-01-02' WHERE id=$1::uuid")
        .bind(&orphan)
        .execute(&mut c)
        .await
        .unwrap();
    let page = |after, id| {
        sqlx::query_as::<_,(String,String,i32,i32)>("SELECT next_created_at::text,
        next_id::text,raw_keys_scanned,released_count FROM openmettle.quota_release_orphan_gateway_requests(
        interval '15 minutes',$1::text::timestamptz,$2::uuid,'2000-01-03','ffffffff-ffff-ffff-ffff-ffffffffffff',1)")
        .bind(after).bind(id)
    };
    let (at, id, raw, released) = page("-infinity", "00000000-0000-0000-0000-000000000000")
        .fetch_one(&worker)
        .await
        .unwrap();
    assert_eq!((id.as_str(), raw, released), (bound.id.as_str(), 1, 0));
    let (_, id, raw, released) = page(&at, &id).fetch_one(&worker).await.unwrap();
    assert_eq!((id, raw, released), (orphan, 1, 1));
    assert!(bound.release(&api).await.unwrap());

    c.execute(
        "UPDATE openmettle.quota_defaults SET hard_limit=1000,cost_denomination='USD_MICROS'
        WHERE scope_kind='instance' AND resource_kind='usage_cost_micros'",
    )
    .await
    .unwrap();
    c.execute(
        "INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit)
        VALUES ('personal','usage_cost_micros',100)",
    )
    .await
    .unwrap();
    let cost_reservation = uuid(&mut c).await;
    let cost_call = gateway::reserve_with_cost(
        &api,
        caller(&actor, &credential, &scope, &cost_reservation),
        Some(80),
    )
    .await
    .unwrap();
    cost_call
        .handoff(&api, &ring, &cost_fx.billable(), cost_fx.prepare(false))
        .await
        .unwrap();
    let request = &cost_call.id;
    for (rev, tokens, cost, token_total, cost_total) in [
        (0, Some(20_i64), None, "40", "0"),
        (1, None, Some("79.12"), "40", "80"),
        (2, None, Some("0"), "40", "0"),
    ] {
        sqlx::query("INSERT INTO openmettle.gateway_usage_reports
            (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens,cost,unit)
            SELECT id,report_source,gen_random_uuid(),$2,true,$3,$3,$4::text::numeric,
            CASE WHEN $4::text IS NOT NULL THEN 'USD_MICROS' END FROM openmettle.gateway_requests WHERE id=$1::uuid")
            .bind(request).bind(rev as i64).bind(tokens).bind(cost).execute(&g).await.unwrap();
        let update = sqlx::query("INSERT INTO openmettle.gateway_settlements(request_id,revision,final,measured,outstanding)
            VALUES($1::uuid,$2,true,$3::bigint,0) ON CONFLICT(request_id) DO UPDATE
            SET revision=excluded.revision,measured=excluded.measured,final=true")
            .bind(request).bind(rev as i64).bind(tokens.map(|n|n*2));
        prelocked_settlement(&g, request, update).await.unwrap();
        let settle = sqlx::query(
            "SELECT openmettle.quota_settle_gateway_usage(request_id,source,report_id,revision)
            FROM openmettle.gateway_usage_reports WHERE request_id=$1::uuid AND revision=$2",
        )
        .bind(request)
        .bind(rev as i64);
        if rev == 1 {
            // This revision settles cost. Both requests charge the same cost and token budgets.
            let other_id = uuid(&mut c).await;
            let unsent = gateway::reserve_with_cost(
                &api,
                caller(&actor, &credential, &scope, &other_id),
                Some(10),
            )
            .await
            .unwrap();
            let order: Vec<String> = sqlx::query_scalar(
                "SELECT resource_kind FROM openmettle.quota_reservations
                WHERE gateway_request_id=$1::uuid ORDER BY created_at",
            )
            .bind(&unsent.id)
            .fetch_all(&g)
            .await
            .unwrap();
            assert_eq!(order, ["usage_cost_micros", "usage_tokens"]);
            let mut blocker = c.begin().await.unwrap();
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid() FROM openmettle.quota_reservations
                WHERE gateway_request_id=$1::uuid AND resource_kind='usage_tokens' FOR NO KEY UPDATE")
                .bind(&unsent.id).fetch_one(&mut *blocker).await.unwrap();
            let release = unsent.release(&api);
            let settle_while_unwind_waits = async {
                wait_for_blocked_peer(&db, pid).await;
                tokio::time::timeout(Duration::from_secs(5), settle.execute(&g))
                    .await
                    .expect("waiting unwind must leave the shared budgets available")
                    .unwrap();
                blocker.commit().await.unwrap();
            };
            let (released, ()) = tokio::join!(release, settle_while_unwind_waits);
            assert!(released.unwrap());
        } else {
            settle.execute(&g).await.unwrap();
        }
        let values: Vec<String> = sqlx::query_scalar(
            "SELECT settled_units::text FROM openmettle.quota_reservations
            WHERE gateway_request_id=$1::uuid ORDER BY resource_kind",
        )
        .bind(request)
        .fetch_all(&worker)
        .await
        .unwrap();
        assert_eq!(values, [cost_total, token_total]);
        let drift:(i64,i64)=sqlx::query_as("SELECT budget_mismatches,settlement_mismatches FROM openmettle.quota_verify_accounting_drift()")
            .fetch_one(&worker).await.unwrap();
        assert_eq!(drift, (0, 0));
    }
    c.execute("CREATE TABLE openmettle.fixture_quota_refs (
        scope_id uuid, reservation_id uuid, request_id uuid,
        FOREIGN KEY (scope_id,reservation_id) REFERENCES openmettle.gateway_reservations (scope_id,id),
        FOREIGN KEY (scope_id,request_id) REFERENCES openmettle.gateway_requests (scope_id,id))")
        .await.unwrap();
    let quota_ref = |scope, reservation, request| {
        sqlx::query("INSERT INTO openmettle.fixture_quota_refs VALUES ($1::uuid,$2::uuid,$3::uuid)")
            .bind(scope)
            .bind(reservation)
            .bind(request)
    };
    quota_ref(&scope, Some(&hold_id), Some(&p.id))
        .execute(&mut c)
        .await
        .unwrap();
    for (hold, request) in [(Some(&hold_id), None), (None, Some(&p.id))] {
        assert_eq!(
            sqlstate(quota_ref(&foreign, hold, request).execute(&mut c).await),
            "23503"
        );
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT allocated FROM openmettle.gateway_reservations WHERE id=$1::uuid"
        )
        .bind(&hold_id)
        .fetch_one(&g)
        .await
        .unwrap(),
        10
    );
}

// These requests have already handed off under two different callers. Only the
// gateway login writes evidence or advances the settlement.
async fn prelocked_settlement<'q>(
    pool: &PgPool,
    request: &str,
    query: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT openmettle.quota_lock_gateway_request_for_settlement($1::uuid)")
        .bind(request)
        .execute(&mut *tx)
        .await?;
    let result = query.execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(result)
}
async fn check_settlement_finality(g: &PgPool, run_request: &str, caller_request: &str) {
    let report = |request,
                  source,
                  revision: i64,
                  final_report,
                  reasoning: Option<i64>,
                  included: Option<bool>| {
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
            (request_id,source,report_id,revision,final,reasoning_tokens,reasoning_included)
            SELECT id,coalesce($2::uuid,report_source),gen_random_uuid(),$3,$4,$5,$6
            FROM openmettle.gateway_requests WHERE id=$1::uuid",
        )
        .bind(request)
        .bind(source)
        .bind(revision)
        .bind(final_report)
        .bind(reasoning)
        .bind(included)
    };
    assert_eq!(
        sqlstate(
            report(run_request, Some(LEASE), 1, false, None, None)
                .execute(g)
                .await
        ),
        "23503"
    );
    assert_eq!(
        sqlstate(
            report(run_request, None, 1, false, Some(0), None)
                .execute(g)
                .await
        ),
        "23514"
    );
    for (revision, final_report, included) in [
        (1, false, false),
        (2, true, true),
        (3, false, true),
        (4, true, false),
    ] {
        report(
            run_request,
            None,
            revision,
            final_report,
            Some(5),
            Some(included),
        )
        .execute(g)
        .await
        .unwrap();
    }
    // A different report ID or finality cannot reuse the request revision.
    assert_eq!(
        sqlstate(
            report(run_request, None, 1, true, None, None)
                .execute(g)
                .await
        ),
        "23505"
    );

    let settlement = |request, revision: i64, final_report| {
        sqlx::query(
        "INSERT INTO openmettle.gateway_settlements (request_id,revision,final,measured,outstanding)
         VALUES ($1::uuid,$2,$3,(SELECT reasoning_tokens FROM openmettle.gateway_usage_reports WHERE request_id=$1::uuid AND revision=$2),0) ON CONFLICT (request_id) DO NOTHING")
        .bind(request).bind(revision).bind(final_report)
    };
    let update = |revision: i64, final_report| {
        sqlx::query(
        "UPDATE openmettle.gateway_settlements SET revision=$2,final=$3 WHERE request_id=$1::uuid")
        .bind(run_request).bind(revision).bind(final_report)
    };
    let unresolved = |request| {
        sqlx::query_scalar::<_,bool>(
        "SELECT EXISTS (SELECT FROM openmettle.gateway_requests WHERE id=$1::uuid AND state='handed_off' AND NOT settled_final)")
        .bind(request)
    };

    assert!(unresolved(run_request).fetch_one(g).await.unwrap());
    assert_eq!(
        sqlstate(prelocked_settlement(g, run_request, settlement(run_request, 1, true)).await),
        "23503"
    );
    prelocked_settlement(g, run_request, settlement(run_request, 1, false))
        .await
        .unwrap();
    assert_eq!(
        prelocked_settlement(g, run_request, settlement(run_request, 2, true))
            .await
            .unwrap()
            .rows_affected(),
        0
    );
    assert!(unresolved(run_request).fetch_one(g).await.unwrap());
    assert_eq!(
        sqlstate(prelocked_settlement(g, run_request, update(2, false)).await),
        "23503"
    );
    prelocked_settlement(g, run_request, update(2, true))
        .await
        .unwrap();
    assert!(!unresolved(run_request).fetch_one(g).await.unwrap());
    assert_eq!(
        sqlstate(prelocked_settlement(g, run_request, update(3, false)).await),
        "23514"
    );
    prelocked_settlement(g, run_request, update(4, true))
        .await
        .unwrap();
    assert_eq!(
        sqlstate(prelocked_settlement(g, run_request, update(2, true)).await),
        "23514"
    );

    // A request can also receive its first settlement as a final report.
    assert!(unresolved(caller_request).fetch_one(g).await.unwrap());
    report(caller_request, None, 1, true, None, None)
        .execute(g)
        .await
        .unwrap();
    prelocked_settlement(g, caller_request, settlement(caller_request, 1, true))
        .await
        .unwrap();
    assert!(!unresolved(caller_request).fetch_one(g).await.unwrap());

    // Revision 3 was stored by the gateway but refused by the settlement ledger.
    let reconcile = |rev: i64| {
        sqlx::query(
            "SELECT openmettle.quota_settle_gateway_usage(request_id,source,report_id,revision)
            FROM openmettle.gateway_usage_reports WHERE request_id=$1::uuid AND revision=$2",
        )
        .bind(run_request)
        .bind(rev)
    };
    assert_eq!(sqlstate(reconcile(3).execute(g).await), "23514");
    assert_eq!(sqlstate(sqlx::query("SELECT openmettle.quota_settle_gateway_usage(request_id,source,gen_random_uuid(),revision)
        FROM openmettle.gateway_usage_reports WHERE request_id=$1::uuid AND revision=1").bind(run_request).execute(g).await),"23514");
    for rev in [4, 1, 2, 4] {
        reconcile(rev).execute(g).await.unwrap();
    }
    let folded:(String,String,i64)=sqlx::query_as("SELECT state,settled_units::text,accepted_source_revision
        FROM openmettle.quota_reservations WHERE gateway_request_id=$1::uuid AND resource_kind='usage_tokens'")
        .bind(run_request).fetch_one(g).await.unwrap();
    assert_eq!(folded, ("handoff_committed".into(), "5".into(), 4));
    // A final total can exceed bigint. An evidence-free revision still advances the cursor.
    for (rev, component, expected) in [
        (5, Some(i64::MAX), "27670116110564327421"),
        (6, None, "27670116110564327421"),
        (7, Some(0), "0"),
    ] {
        sqlx::query("INSERT INTO openmettle.gateway_usage_reports
            (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens,reasoning_tokens,reasoning_included)
            SELECT id,report_source,gen_random_uuid(),$2,true,$3,$3,$3,
            CASE WHEN $3::bigint IS NOT NULL THEN false END FROM openmettle.gateway_requests WHERE id=$1::uuid")
            .bind(run_request).bind(rev as i64).bind(component).execute(g).await.unwrap();
        let update = sqlx::query(
            "UPDATE openmettle.gateway_settlements SET revision=$2,final=true,
             measured=$3::text::numeric WHERE request_id=$1::uuid",
        )
        .bind(run_request)
        .bind(rev as i64)
        .bind(component.map(|_| expected));
        prelocked_settlement(g, run_request, update).await.unwrap();
        reconcile(rev as i64).execute(g).await.unwrap();
        let recorded:(String,String,i64,i64)=sqlx::query_as("SELECT state,settled_units::text,held_units,accepted_source_revision
            FROM openmettle.quota_reservations WHERE gateway_request_id=$1::uuid AND resource_kind='usage_tokens'")
            .bind(run_request).fetch_one(g).await.unwrap();
        assert_eq!(recorded, ("settled".into(), expected.into(), 0, rev as i64));
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn missing_overlapping_or_overprivileged_gateway_is_refused() {
    let db = TestDb::exclusive().await;
    const RESTORE: &[&str] = &[
        "ALTER ROLE openmettle_fixture_hidden_gateway RENAME TO openmettle_gateway",
        "REVOKE openmettle_gateway FROM openmettle_fixture_capped",
    ];
    let _restore = Restore(RESTORE);
    let mut admin = db.admin().await;
    let settings = db.settings(Duration::from_secs(5));
    migrate::apply(&settings, &MIGRATIONS[..22]).await.unwrap();
    admin
        .execute("ALTER ROLE openmettle_gateway RENAME TO openmettle_fixture_hidden_gateway")
        .await
        .unwrap();
    assert!(matches!(
        migrate::apply(&settings, MIGRATIONS).await,
        Err(Failure::Migrate(MigrateError::ExecuteMigration(_, 23)))
    ));
    assert_eq!(db.history().await, versions_through(22));
    assert!(!db.exists("openmettle.gateway_bindings").await);
    admin.execute(RESTORE[0]).await.unwrap();
    admin
        .execute("GRANT openmettle_gateway TO openmettle_fixture_capped")
        .await
        .unwrap();
    refused_with(&settings,MIGRATIONS,"role openmettle_fixture_capped reaches more than one of openmettle_api, openmettle_issuance, openmettle_worker and openmettle_gateway").await;
    admin.execute(RESTORE[1]).await.unwrap();
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    for (grant, revoke, reason) in [
        (
            "GRANT SELECT (ciphertext) ON openmettle.gateway_generations TO openmettle_worker",
            "REVOKE SELECT (ciphertext) ON openmettle.gateway_generations FROM openmettle_worker",
            "openmettle_worker has SELECT on openmettle.gateway_generations.ciphertext",
        ),
        (
            "GRANT UPDATE (active) ON openmettle.local_identity_approvals TO openmettle_gateway",
            "REVOKE UPDATE (active) ON openmettle.local_identity_approvals FROM openmettle_gateway",
            "openmettle_gateway has UPDATE on openmettle.local_identity_approvals.active",
        ),
        (
            "REVOKE UPDATE (lock_guard) ON openmettle.projects FROM openmettle_gateway",
            "GRANT UPDATE (lock_guard) ON openmettle.projects TO openmettle_gateway",
            "openmettle_gateway lacks UPDATE on openmettle.projects.lock_guard",
        ),
        (
            "ALTER FUNCTION openmettle.gateway_release(uuid,bytea) SET search_path=public",
            "ALTER FUNCTION openmettle.gateway_release(uuid,bytea) SET search_path=pg_catalog",
            "unsafe or missing gateway function openmettle.gateway_release(uuid,bytea)",
        ),
        (
            "GRANT EXECUTE ON FUNCTION openmettle.gateway_handoff(uuid,bytea,bytea,bytea,uuid) TO PUBLIC",
            "REVOKE EXECUTE ON FUNCTION openmettle.gateway_handoff(uuid,bytea,bytea,bytea,uuid) FROM PUBLIC",
            "unsafe or missing gateway function openmettle.gateway_handoff(uuid,bytea,bytea,bytea,uuid)",
        ),
    ] {
        admin.execute(grant).await.unwrap();
        let failure = migrate::apply(&settings, MIGRATIONS).await.unwrap_err();
        assert!(
            matches!(failure, Failure::Refused(_)) && failure.to_string().contains(reason),
            "{failure}"
        );
        admin.execute(revoke).await.unwrap();
    }
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn family_wall_clock_policy_covers_gap_fold_midnight_and_child_switch() {
    use gateway::family::{FamilyPolicy, Hours};
    let db = TestDb::migrated().await;
    let mut c = connect(&db.0, pg::GATEWAY).await;
    let mut f = FamilyPolicy {
        revision: 1,
        zone: "America/New_York".into(),
        quiet: Some(Hours {
            start_minute: 90,
            end_minute: 180,
        }),
        study: Some(Hours {
            start_minute: 23 * 60,
            end_minute: 60,
        }),
        study_models: ["school".into()].into(),
        disabled_models: ["disabled".into()].into(),
    };
    for (utc, model, allowed) in [
        ("2026-03-08T06:29:59Z", "a", true),
        ("2026-03-08T06:30:00Z", "a", false),
        ("2026-03-08T06:59:59Z", "a", false),
        ("2026-03-08T07:00:00Z", "a", true),
        ("2026-11-01T05:29:59Z", "a", true),
        ("2026-11-01T05:30:00Z", "a", false),
        ("2026-11-01T06:29:59Z", "a", true),
        ("2026-11-01T06:30:00Z", "a", false),
        ("2026-11-01T07:59:59Z", "a", false),
        ("2026-11-01T08:00:00Z", "a", true),
        ("2026-11-01T03:10:00Z", "a", false),
        ("2026-11-01T04:30:00Z", "school", true),
        ("2026-11-01T08:00:00Z", "disabled", false),
    ] {
        let at = chrono::DateTime::parse_from_rfc3339(utc)
            .unwrap()
            .timestamp_millis();
        assert_eq!(
            f.permits(&mut c, model, Some(at)).await.unwrap(),
            allowed,
            "{utc}"
        );
    }
    f.zone = "Unknown/Zone".into();
    assert_eq!(
        f.permits(&mut c, "a", None).await,
        Err(gateway::Error::Refused)
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn discovery_rehydrates_committed_group_observations_without_a_hint() {
    use gateway::reconcile::{ModelRequest, Profile, Sweep};
    use openmettle_core::{
        authz::{Grantee, ProjectRole, projects},
        model_config::Catalog,
        provider_http::gateway::problem::{Access, Problem},
    };
    let db = TestDb::migrated().await;
    let mut c = connect(&db.0, OWNER).await;
    authz_store::providers(&mut c).await;
    let actor =
        authz_store::account(&mut c, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let owner =
        authz_store::account(&mut c, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let (project, scope) = run_admission::new_project(&db, &owner, "family-project").await;
    authz_store::applied(
        projects::set_project_member_role(
            &mut run_admission::api(&db).await,
            &authz_store::ctx(&owner, "family-grant"),
            &project,
            &Grantee::OidcGroup("synthetic-team".into()),
            ProjectRole::Editor,
        )
        .await,
    );
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(&mut c)
            .await
            .unwrap();
    let mut owner = authz_store::present_membership_at(&db, &actor, now).await;
    let catalog =
        Catalog::load(include_bytes!("../fixtures/conversation-catalog-v1.json")).unwrap();
    let profile = Profile {
        installation: INSTALL,
        report_source: PRINCIPAL,
        revision: 1,
        rotation_epoch: 0,
        renew_before: Duration::from_secs(30),
        catalog: &catalog,
        families: &Default::default(),
    };
    let g = pool(&db, pg::GATEWAY);
    let mut s = Sweep::default();
    let revision = || {
        sqlx::query_scalar::<_, i64>(
            "SELECT desired_revision FROM openmettle.gateway_bindings WHERE user_id=$1::uuid",
        )
        .bind(&actor.user)
        .fetch_one(&g)
    };
    let request = || ModelRequest {
        access: Access::Entitled,
        user: &actor.user,
        scope: &scope,
        approval: &actor.approval,
        model: None,
    };
    s.discover(&g, &profile, 64).await.unwrap();
    assert_eq!(revision().await.unwrap(), 1);
    assert_eq!(
        profile
            .select_model(&g, request(), None, || panic!("binding precedes selection"))
            .await,
        Err(Problem::Provisioning)
    );
    owner
        .execute("UPDATE openmettle.membership_observations SET observation.state='absent'")
        .await
        .unwrap();
    assert_eq!(
        profile.select_model(&g, request(), None, || panic!()).await,
        Err(Problem::Policy)
    );
    s.discover(&g, &profile, 64).await.unwrap();
    assert_eq!(revision().await.unwrap(), 2);
    s.discover(&g, &profile, 64).await.unwrap();
    assert_eq!(revision().await.unwrap(), 2);
    owner
        .execute("UPDATE openmettle.membership_observations SET observation.state='present'")
        .await
        .unwrap();
    s.discover(&g, &profile, 64).await.unwrap();
    assert_eq!(revision().await.unwrap(), 3);
    sqlx::query("UPDATE openmettle.local_identity_approvals SET active=false WHERE id=$1::uuid")
        .bind(&actor.approval)
        .execute(&mut owner)
        .await
        .unwrap();
    s.discover(&g, &profile, 64).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT state FROM openmettle.gateway_bindings WHERE user_id=$1::uuid"
        )
        .bind(&actor.user)
        .fetch_one(&g)
        .await
        .unwrap(),
        "suspended"
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn unknown_child_zone_suspends_only_that_binding_and_advances_discovery() {
    use gateway::{
        family::FamilyPolicy,
        reconcile::{Profile, Sweep},
    };
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let a =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let b =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let (first, last) = if a.user < b.user { (a, b) } else { (b, a) };
    let catalog = openmettle_core::model_config::Catalog::load(include_bytes!(
        "../fixtures/conversation-catalog-v1.json"
    ))
    .unwrap();
    let mut families = openmettle_core::provider_http::gateway::FamilyDirectory {
        revision: 1,
        ..Default::default()
    };
    let g = pool(&db, pg::GATEWAY);
    let profile = Profile {
        installation: INSTALL,
        report_source: PRINCIPAL,
        revision: 1,
        rotation_epoch: 0,
        renew_before: Duration::from_secs(60),
        catalog: &catalog,
        families: &families,
    };
    let mut sweep = Sweep::default();
    // Commit the earlier child first. The unprocessed later account has no intents yet.
    assert_eq!(sweep.discover(&g, &profile, 1).await.unwrap(), 1);
    families.revision = 2;
    families.children.insert(
        first.user.clone(),
        FamilyPolicy {
            revision: 1,
            zone: "Unknown/Zone".into(),
            quiet: None,
            study: None,
            study_models: Default::default(),
            disabled_models: Default::default(),
        },
    );
    let profile = Profile {
        installation: INSTALL,
        report_source: PRINCIPAL,
        revision: 1,
        rotation_epoch: 0,
        renew_before: Duration::from_secs(60),
        catalog: &catalog,
        families: &families,
    };
    let mut sweep = Sweep::default();
    assert_eq!(sweep.discover(&g, &profile, 1).await.unwrap(), 1);
    assert_eq!(sweep.discover(&g, &profile, 1).await.unwrap(), 1);
    let bindings: Vec<(String, String)> = sqlx::query_as(
        "SELECT user_id::text,state FROM openmettle.gateway_bindings ORDER BY user_id",
    )
    .fetch_all(&g)
    .await
    .unwrap();
    assert_eq!(
        bindings,
        vec![
            (first.user, "suspended".into()),
            (last.user, "provisioning".into())
        ]
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn unmetered_handoff_replays_only_accepted_token_components_after_upgrade() {
    use gateway::settlement::{Outcome, ingest};
    use openmettle_core::provider_http::gateway::UsageReport;
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(5));
    migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let actor =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let scope = authz_runs::personal_of(&db, &actor).await;
    let credential = authz_runs::seeded_session(&db, &actor, 4, None).await;
    let api = pool(&db, API);
    let g = pool(&db, pg::GATEWAY);
    let binding: String = sqlx::query_scalar(
        "INSERT INTO openmettle.gateway_bindings(installation,user_id,principal,budget)
        VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid) RETURNING id::text",
    )
    .bind(INSTALL)
    .bind(&actor.user)
    .bind(PRINCIPAL)
    .bind(BUDGET)
    .fetch_one(&g)
    .await
    .unwrap();
    let (finger, e) = GatewaySealer::new(keys(), g.clone())
        .seal(
            &Context {
                installation: INSTALL,
                user_id: &actor.user,
                binding_id: &binding,
                principal: PRINCIPAL,
                generation: 1,
            },
            &Bearer::generate().unwrap(),
        )
        .await
        .unwrap();
    sqlx::query("INSERT INTO openmettle.gateway_generations (binding_id,generation,remote_key,expires_at,key_id,key_fingerprint,nonce,ciphertext)
        VALUES ($1::uuid,1,gen_random_uuid(),now()+interval '1 hour',$2,$3,$4,$5)").bind(&binding).bind(e.key_id).bind(finger.as_slice())
        .bind(e.nonce.as_slice()).bind(e.ciphertext).execute(&g).await.unwrap();
    sqlx::query("INSERT INTO openmettle.gateway_policy(binding_id,revision,scope_id,approval_id,model,report_source,
        provider_generation,approval_generation,user_generation,capabilities) VALUES ($1::uuid,1,$2::uuid,$3::uuid,'a',$4::uuid,0,0,0,'{}')")
        .bind(&binding).bind(&scope).bind(&actor.approval).bind(LEASE).execute(&g).await.unwrap();
    g.execute("UPDATE openmettle.gateway_bindings SET state='ready',observed_revision=1,active_generation=1").await.unwrap();
    let request = uuid(&mut owner).await;
    let reservation = uuid(&mut owner).await;
    sqlx::query(
        "INSERT INTO openmettle.gateway_reservations(id,scope_id,actor_user_id,approval_id,units)
        VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,100)",
    )
    .bind(&reservation)
    .bind(&scope)
    .bind(&actor.user)
    .bind(&actor.approval)
    .execute(&api)
    .await
    .unwrap();
    sqlx::query("INSERT INTO openmettle.gateway_requests(id,reservation_id,scope_id,actor_user_id,approval_id,session_id,installation,model,units,dispatch_hash)
        VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6,$7::uuid,'a',100,sha256($8))")
        .bind(&request).bind(&reservation).bind(&scope).bind(&actor.user).bind(&actor.approval).bind(&credential[..43]).bind(INSTALL)
        .bind([8_u8;32].as_slice()).execute(&api).await.unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT FROM openmettle.gateway_handoff($1::uuid,$2,$3,NULL,NULL))"
        )
        .bind(&request)
        .bind([8_u8; 32].as_slice())
        .bind([104_u8; 32].as_slice())
        .fetch_one(&api)
        .await
        .unwrap()
    );
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    let mut r = UsageReport {
        request,
        scope,
        source: LEASE.into(),
        installation: INSTALL.into(),
        principal: PRINCIPAL.into(),
        report_id: uuid(&mut owner).await,
        revision: 0,
        r#final: false,
        prompt_tokens: None,
        completion_tokens: None,
        reasoning_tokens: None,
        reasoning_included: None,
        cost: None,
        unit: None,
    };
    let request = r.request.clone();
    let balance = || {
        sqlx::query_as::<_,(Option<String>,i64)>("SELECT measured::text,outstanding FROM openmettle.gateway_settlements WHERE request_id=$1::uuid").bind(&request).fetch_one(&g)
    };
    for (rev, prompt, completion, reasoning, included, final_report, raw, held) in [
        (1, Some(20), Some(10), Some(5), false, false, Some(35), 65),
        (3, None, Some(15), None, false, false, Some(15), 60),
        (4, Some(10), Some(5), None, false, true, Some(15), 60),
        (5, None, None, None, false, true, None, 60),
        (6, Some(2), Some(1), Some(5), true, true, Some(7), 0),
        (7, Some(0), Some(0), Some(0), true, true, Some(0), 0),
    ] {
        r.revision = rev;
        r.prompt_tokens = prompt;
        r.completion_tokens = completion;
        r.reasoning_tokens = reasoning;
        r.reasoning_included = Some(included);
        r.r#final = final_report;
        assert_eq!(ingest(&g, &r).await, Ok(Outcome::Applied));
        assert_eq!(balance().await.unwrap(), (raw.map(|n| n.to_string()), held));
        let reference: i64 = sqlx::query_scalar(
            "SELECT held FROM openmettle.quota_gateway_fold($1::uuid,'usage_tokens',100,$2)
            ORDER BY rev DESC LIMIT 1",
        )
        .bind(&request)
        .bind(rev)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(held, reference);
        let (key, candidate_age): (String, Option<i64>) =
            sqlx::query_as(include_str!("../../src/authz/gateway/legacy_backfill.sql"))
                .bind(None::<String>)
                .bind(1_i64)
                .bind(INSTALL)
                .fetch_one(&g)
                .await
                .unwrap();
        assert_eq!(key, request);
        assert_eq!(candidate_age.is_some(), final_report && held > 0);
        if rev == 3 {
            let mut superseded = r.clone();
            superseded.revision = 2;
            superseded.prompt_tokens = Some(i64::MAX);
            assert_eq!(ingest(&g, &superseded).await, Ok(Outcome::Superseded));
        }
    }
    let drift:(i64,i64,i64,i64)=sqlx::query_as("SELECT storage_mismatches,budget_mismatches,settlement_mismatches,pending_gateway_reconciliations
        FROM openmettle.quota_verify_accounting_drift()").fetch_one(&mut owner).await.unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
}
