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
async fn authority_is_rechecked_at_handoff_and_unsent_release_is_serialized() {
    let db = TestDb::migrated().await;
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
        pending.handoff(&api, &ring).await,
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
                pending.handoff(&api, &ring).await,
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
            p.handoff(&api, &ring).await,
            Err(gateway::Error::Refused)
        ));
        let (a, b) = tokio::join!(p.release(&api), p.release(&api));
        assert_ne!(a.unwrap(), b.unwrap());
    }
    assert!(!pending.release(&worker).await.unwrap());
    assert!(pending.handoff(&api, &ring).await.is_ok());
    assert!(!pending.release(&api).await.unwrap());
    assert!(matches!(
        pending.handoff(&api, &ring).await,
        Err(gateway::Error::Refused)
    ));
    let race_id = uuid(&mut c).await;
    let race = gateway::reserve(&api, caller(&actor, &credential, &scope, &race_id))
        .await
        .unwrap();
    let (released, handed) = tokio::join!(race.release(&api), race.handoff(&api, &ring));
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
    project_call.handoff(&api, &ring).await.unwrap();
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
        next.handoff(&api, &ring).await,
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
        next.handoff(&api, &ring).await,
        Err(gateway::Error::Refused)
    ));

    let r = run_admission::request(&db, &scope, "personal", &actor, "gateway-rounds").await;
    let run = run_admission::admitted(&db, &r).await;
    let claim = openmettle_core::authz::runs::claim_next(
        &mut run_admission::worker(&db).await,
        &run_admission::OPEN,
        &run_admission::LEASES,
    )
    .await
    .unwrap()
    .unwrap();
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
    let invalid_scope = sqlx::query("INSERT INTO openmettle.gateway_requests
        (id,reservation_id,scope_id,actor_user_id,approval_id,installation,model,units,dispatch_hash,run_id,round)
        VALUES (gen_random_uuid(),$1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,'a',1,sha256('x'::bytea),$6::uuid,1)")
        .bind(&hold_id).bind(&foreign).bind(&actor.user).bind(&actor.approval).bind(INSTALL).bind(&run)
        .execute(&worker).await;
    assert_eq!(sqlstate(invalid_scope), "23503");
    let p = gateway::reserve(&worker, round(1, LEASE)).await.unwrap();
    assert!(matches!(
        p.handoff(&worker, &ring).await,
        Err(gateway::Error::Refused)
    ));
    assert!(p.release(&worker).await.unwrap());
    let p = gateway::reserve(&worker, round(2, &claim.claim_token))
        .await
        .unwrap();
    assert!(matches!(
        p.handoff(&api, &ring).await,
        Err(gateway::Error::Refused)
    ));
    assert!(p.handoff(&worker, &ring).await.is_ok());
    assert!(!p.release(&worker).await.unwrap());
    let report =
        "INSERT INTO openmettle.gateway_usage_reports (request_id,source,report_id,revision,final)
        SELECT id,coalesce($2::uuid,report_source),gen_random_uuid(),1,true
        FROM openmettle.gateway_requests WHERE id=$1::uuid";
    assert_eq!(
        sqlstate(
            sqlx::query(report)
                .bind(&p.id)
                .bind(LEASE)
                .execute(&g)
                .await
        ),
        "23503"
    );
    sqlx::query(report)
        .bind(&p.id)
        .bind(None::<&str>)
        .execute(&g)
        .await
        .unwrap();
    assert_eq!(
        sqlstate(
            sqlx::query(report)
                .bind(&p.id)
                .bind(None::<&str>)
                .execute(&g)
                .await
        ),
        "23505"
    );
    let p = gateway::reserve(&worker, round(3, &claim.claim_token))
        .await
        .unwrap();
    c.execute("UPDATE openmettle.runs SET lease_expires_at=clock_timestamp()")
        .await
        .unwrap();
    assert!(matches!(
        p.handoff(&worker, &ring).await,
        Err(gateway::Error::Refused)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT allocated FROM openmettle.gateway_reservations WHERE id=$1::uuid"
        )
        .bind(&hold_id)
        .fetch_one(&g)
        .await
        .unwrap(),
        20
    );
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
