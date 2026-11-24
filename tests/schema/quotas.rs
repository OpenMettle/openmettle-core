use super::*;

/// The admission snapshot of a run on catalog model `a` that requires no capability: the model
/// and capabilities a round is handed off against (ADR 0044), with the round token ceiling the
/// quota functions read.
pub(super) fn snapshot(ceiling: u64) -> Vec<u8> {
    snapshot_of("a", ceiling)
}

/// Records the dispatch of a handed-off request, as the proxy does before it reports usage.
/// These tests settle a round without the proxy, and the library keeps the round's dispatch
/// secret to itself, so the fixture writes the mark as the database owner.
async fn dispatched(owner: &mut PgConnection, request: &str) {
    let marked = sqlx::query(
        "UPDATE openmettle.gateway_requests SET dispatched_at=clock_timestamp()
          WHERE id=$1::uuid AND state='handed_off' AND dispatched_at IS NULL",
    )
    .bind(request)
    .execute(owner)
    .await
    .unwrap();
    assert_eq!(marked.rows_affected(), 1);
}

/// [`snapshot`] for another model.
pub(super) fn snapshot_of(model: &str, ceiling: u64) -> Vec<u8> {
    snapshot_priced(model, ceiling, None)
}

/// [`snapshot_of`] with an optional admission-pinned [`openmettle_core::model_config::CostBound`].
pub(super) fn snapshot_priced(
    model: &str,
    ceiling: u64,
    cost_bound: Option<openmettle_core::model_config::CostBound>,
) -> Vec<u8> {
    let mut doc = serde_json::json!({
        "effective": {"model": model, "ceiling": {"value": ceiling}},
        "required_capabilities": {},
    });
    if let Some(cb) = cost_bound {
        doc["cost_bound"] = serde_json::json!({
            "fixed_micros": cb.fixed_micros,
            "micros_per_token": cb.micros_per_token,
        });
    }
    doc.to_string().into_bytes()
}

pub(super) struct TurnHandoffFixture {
    installation: String,
    catalog: openmettle_core::model_config::Catalog,
    effective: openmettle_core::model_config::Effective,
    request: openmettle_core::provider_http::inference::Request,
    route: openmettle_core::provider_http::inference::Gateway,
}

impl TurnHandoffFixture {
    fn new(
        installation: &str,
        protocol: openmettle_core::provider_http::inference::Protocol,
        model: &str,
        round_tokens: i64,
        cost_bound: Option<openmettle_core::model_config::CostBound>,
        requires_device_slot: bool,
    ) -> Self {
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
        // A model the fixture catalog lacks takes the profile of `a`.
        if doc["models"][model].is_null() {
            doc["models"][model] = doc["models"]["a"].clone();
        }
        let entry = &mut doc["models"][model];
        entry["context_window"] = serde_json::json!(round_tokens);
        entry["output_limit"] = serde_json::json!(round_tokens);
        entry["requires_device_slot"] = serde_json::json!(requires_device_slot);
        if let Some(cb) = cost_bound {
            entry["cost_bound"] = serde_json::json!({
                "fixed_micros": cb.fixed_micros,
                "micros_per_token": cb.micros_per_token
            });
        } else {
            entry.as_object_mut().unwrap().remove("cost_bound");
        }
        doc["presets"]["study"]["model"] = serde_json::json!(model);
        doc["presets"]["study"]["defaults"]["controls"]["output_reserve"] =
            serde_json::json!((round_tokens / 2).max(1));
        let catalog = Catalog::load(&serde_json::to_vec(&doc).unwrap()).unwrap();
        let effective = catalog
            .resolve(
                &Selection::default(),
                &serde_json::from_value(serde_json::json!({"preset": "study"})).unwrap(),
                None,
                |_, _| true,
            )
            .unwrap();
        let path = match protocol {
            Protocol::Chat => "/v1/chat/completions",
            Protocol::Responses => "/v1/responses",
        };
        let route = Gateway::new(
            &format!("https://provider.example.test{path}"),
            Trust::Bundle(&ca.pem()),
            &[],
            Qualification {
                model: effective.model.clone(),
                pin: effective.profile.clone(),
                protocol,
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
            history: vec![History::User("quota handoff fixture".into())],
            tools: None,
            parallel: None,
            stream: false,
        };
        Self {
            installation: installation.to_owned(),
            catalog,
            effective,
            request,
            route,
        }
    }

    pub(super) fn chat(
        installation: &str,
        model: &str,
        round_tokens: i64,
        round_cost: Option<u128>,
        requires_device_slot: bool,
    ) -> Self {
        Self::new(
            installation,
            openmettle_core::provider_http::inference::Protocol::Chat,
            model,
            round_tokens,
            round_cost.map(|cost| openmettle_core::model_config::CostBound {
                fixed_micros: u64::try_from(cost).unwrap(),
                micros_per_token: 0,
            }),
            requires_device_slot,
        )
    }

    pub(super) fn chat_priced(
        installation: &str,
        model: &str,
        round_tokens: i64,
        cost_bound: openmettle_core::model_config::CostBound,
        requires_device_slot: bool,
    ) -> Self {
        Self::new(
            installation,
            openmettle_core::provider_http::inference::Protocol::Chat,
            model,
            round_tokens,
            Some(cost_bound),
            requires_device_slot,
        )
    }

    pub(super) fn billable(&self) -> openmettle_core::provider_http::BillableInferenceRef<'_> {
        openmettle_core::provider_http::BillableInferenceRef {
            installation: &self.installation,
            route: &self.route,
        }
    }

    fn prepare(&self) -> openmettle_core::provider_http::inference::PreparedRequest<'_> {
        self.prepare_mode(true)
    }

    pub(super) fn prepare_mode(
        &self,
        server: bool,
    ) -> openmettle_core::provider_http::inference::PreparedRequest<'_> {
        self.billable()
            .prepare(&self.catalog, &self.effective, &self.request, server)
            .unwrap()
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn device_handoff_keeps_every_slot_charged_until_durable_release_evidence_exists() {
    let db = TestDb::migrated().await;
    let mut api = connect(&db.0, API).await;
    let mut worker = connect(&db.0, WORKER).await;
    let mut owner = connect(&db.0, OWNER).await;
    let actor = new_user(&mut api).await;
    let scope = personal_scope(&mut api, &actor).await;
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit)
        VALUES('personal','device_reservations',1),('instance','device_reservations',1)",
        )
        .await
        .unwrap();
    let reserve = |key| {
        sqlx::query_scalar::<_,String>(
        "SELECT openmettle.quota_reserve($1::uuid,$2::uuid,'device_reservations',1,$3,NULL,NULL,NULL,
            clock_timestamp()+interval '15 minutes')::text")
        .bind(&scope).bind(&actor).bind(key)
    };
    let hold = reserve("device").fetch_one(&mut api).await.unwrap();
    assert_eq!(hold, reserve("device").fetch_one(&mut api).await.unwrap());
    let grant: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut api)
        .await
        .unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT openmettle.quota_commit_handoff($1::uuid,$2::uuid)")
            .bind(&hold)
            .bind(&grant)
            .fetch_one(&mut api)
            .await
            .unwrap()
    );
    sqlx::query(
        "UPDATE openmettle.quota_reservations SET lease_expires_at=now()-interval '1 hour'
        WHERE id=$1::uuid",
    )
    .bind(&hold)
    .execute(&mut owner)
    .await
    .unwrap();
    assert!(
        !sqlx::query_scalar::<_, bool>("SELECT openmettle.quota_release_unsent($1::uuid)")
            .bind(&hold)
            .fetch_one(&mut worker)
            .await
            .unwrap()
    );
    assert_eq!(
        sqlstate(
            sqlx::query("SELECT openmettle.quota_release_device_slot($1::uuid,$2::uuid)")
                .bind(&hold)
                .bind(&grant)
                .execute(&mut worker)
                .await
        ),
        "OMQ06"
    );
    assert_eq!(
        sqlstate(reserve("second").fetch_one(&mut api).await),
        "OMQ01"
    );
    let charges: Vec<(String, String)> = sqlx::query_as(
        "SELECT active_used::text,reserved_held::text
        FROM openmettle.quota_budgets ORDER BY target_kind",
    )
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(charges, vec![("0".into(), "1".into()); 2]);
    let state: (String, i64) = sqlx::query_as(
        "SELECT state,held_units FROM openmettle.quota_reservations
        WHERE id=$1::uuid",
    )
    .bind(&hold)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(state, ("handoff_committed".into(), 1));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn empty_upgrade_requires_operator_adoption_and_metering_activation() {
    for fresh in [false, true] {
        let db = TestDb::new().await;
        let settings = db.settings(Duration::from_secs(10));
        if !fresh {
            migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
        }
        migrate::apply(&settings, MIGRATIONS).await.unwrap();
        let mut owner = connect(&db.0, OWNER).await;
        let markers: (bool, bool, bool, bool) = sqlx::query_as(
            "SELECT metering_enforced,bootstrap_auto_pin_allowed,
            volume_id IS NULL,adoption_run_id IS NULL FROM openmettle.quota_enforcement
            CROSS JOIN openmettle.storage_volume_control",
        )
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(markers, (fresh, fresh, true, true));
        let mut worker = connect(&db.0, WORKER).await;
        assert_eq!(
            sqlstate(
                sqlx::query("SELECT openmettle.storage_lock_pinned_volume()")
                    .execute(&mut worker)
                    .await
            ),
            "OMQ03"
        );
        assert_eq!(
            sqlstate(
                sqlx::query("SELECT openmettle.storage_pin_volume_id(gen_random_uuid())")
                    .execute(&mut worker)
                    .await
            ),
            "42501"
        );
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn competing_project_holds_charge_project_actor_and_instance_atomically() {
    let db = TestDb::migrated().await;
    let mut api = connect(&db.0, API).await;
    let mut other = connect(&db.0, API).await;
    let mut owner = connect(&db.0, OWNER).await;
    let actor = new_user(&mut api).await;
    personal_scope(&mut api, &actor).await;
    let (_, scope) = project(&mut api, &actor).await;
    owner.execute("INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit)
        VALUES ('project','device_reservations',5),('personal','device_reservations',1),('instance','device_reservations',7)").await.unwrap();
    let reserve = |key| {
        sqlx::query_scalar::<_, String>(
            "SELECT openmettle.quota_reserve($1::uuid,$2::uuid,
        'device_reservations',1,$3,NULL,NULL,NULL,clock_timestamp()+interval '1 hour')::text",
        )
        .bind(&scope)
        .bind(&actor)
        .bind(key)
    };
    let (a, b) = tokio::join!(
        reserve("one").fetch_one(&mut api),
        reserve("two").fetch_one(&mut other)
    );
    let (id, key) = match (a, b) {
        (Ok(id), Err(e)) => {
            assert_eq!(sqlstate::<()>(Err(e)), "OMQ01");
            (id, "one")
        }
        (Err(e), Ok(id)) => {
            assert_eq!(sqlstate::<()>(Err(e)), "OMQ01");
            (id, "two")
        }
        result => panic!("expected exactly one admission, got {result:?}"),
    };
    assert_eq!(reserve(key).fetch_one(&mut api).await.unwrap(), id);
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM openmettle.quota_reservations),
        (SELECT count(*) FROM openmettle.quota_reservation_charges),
        (SELECT count(*) FROM openmettle.quota_budgets WHERE reserved_held=1)",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(counts, (1, 3, 3));
    let drift: i64 = sqlx::query_scalar(
        "SELECT budget_mismatches FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(drift, 0);
    let mut worker = connect(&db.0, WORKER).await;
    let warnings: Vec<(String,String,String,i16)> = sqlx::query_as(
        "SELECT target_kind,scope_kind,resource_kind,threshold_pct FROM openmettle.quota_take_warnings(10) ORDER BY threshold_pct")
        .fetch_all(&mut worker).await.unwrap();
    for ((target, kind, resource, pct), expected) in warnings.iter().zip([80, 90, 100]) {
        assert_eq!(
            (target.as_str(), kind.as_str(), resource.as_str(), *pct),
            ("scope", "personal", "device_reservations", expected)
        );
    }
    assert_eq!(warnings.len(), 3);
    let remaining: i64 =
        sqlx::query_scalar("SELECT count(*) FROM openmettle.quota_take_warnings(10)")
            .fetch_one(&mut worker)
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    for released in [true, false] {
        assert_eq!(
            sqlx::query_scalar::<_, bool>("SELECT openmettle.quota_release_unsent($1::uuid)")
                .bind(&id)
                .fetch_one(&mut api)
                .await
                .unwrap(),
            released
        );
    }
    let outstanding: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT FROM openmettle.quota_budgets WHERE reserved_held<>0)",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert!(!outstanding);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn worker_release_waits_for_a_locked_unexpired_hold_and_sweep_skips_it() {
    let db = TestDb::migrated().await;
    let mut api = connect(&db.0, API).await;
    let actor = new_user(&mut api).await;
    let scope = personal_scope(&mut api, &actor).await;
    let mut worker = connect(&db.0, WORKER).await;
    let mut owner = connect(&db.0, OWNER).await;
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit)
        VALUES('personal','device_reservations',1),('instance','device_reservations',1)",
        )
        .await
        .unwrap();
    let hold: String = sqlx::query_scalar(
        "SELECT openmettle.quota_reserve($1::uuid,$2::uuid,
        'device_reservations',1,'slot',NULL,NULL,NULL,clock_timestamp()+interval '1 hour')::text",
    )
    .bind(scope)
    .bind(actor)
    .fetch_one(&mut worker)
    .await
    .unwrap();
    let sweep = || {
        sqlx::query_scalar::<_, bool>("SELECT openmettle.quota_release_unsent($1::uuid,NULL,true)")
            .bind(&hold)
    };
    assert_eq!(sqlstate(sweep().fetch_one(&mut api).await), "42501");
    assert!(!sweep().fetch_one(&mut worker).await.unwrap());
    let mut lock = owner.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.quota_reservations WHERE id=$1::uuid FOR UPDATE")
        .bind(&hold)
        .execute(&mut *lock)
        .await
        .unwrap();
    let release = sqlx::query_scalar::<_, bool>("SELECT openmettle.quota_release_unsent($1::uuid)")
        .bind(&hold)
        .fetch_one(&mut worker);
    tokio::pin!(release);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut release)
            .await
            .is_err()
    );
    lock.commit().await.unwrap();
    assert!(release.await.unwrap());
    let source: String = sqlx::query_scalar("SELECT source_key FROM openmettle.quota_reconciliations WHERE reservation_id=$1::uuid AND kind='release'")
        .bind(&hold).fetch_one(&mut owner).await.unwrap();
    assert_eq!(source, "release");
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn run_renewal_preserves_storage_settlement_margin_for_late_reservations() {
    use openmettle_core::{
        runs::WriteTransaction,
        storage::{ReservationInput, reserve},
    };
    let db = TestDb::migrated().await;
    run_admission::seed_token_budget(&db).await;
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let actor =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let scope = authz_runs::personal_of(&db, &actor).await;
    let req = run_admission::request(&db, &scope, "personal", &actor, "renewal").await;
    let run = run_admission::admitted(&db, &req).await;
    let claim = openmettle_core::authz::runs::claim_next(
        &mut run_admission::worker(&db).await,
        &run_admission::OPEN,
        &run_admission::LEASES,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(claim.run_id, run);
    owner.execute("UPDATE openmettle.storage_instance SET personal_limit_bytes=1000,instance_budget_bytes=1000").await.unwrap();
    let mut api = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let hold = reserve(
        &mut tx,
        &ReservationInput {
            scope: &scope,
            actor: &actor.user,
            key: "late",
            artifact: "00000000-0000-4000-8000-000000000015",
            max_bytes: 10,
            run: Some(&run),
            operation: None,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    // created_at before the deadline, with the producer's 60 second settlement margin.
    let lease = || {
        sqlx::query_scalar::<_, String>(
            "SELECT lease_expires_at::text FROM openmettle.storage_reservations WHERE id=$1::uuid",
        )
        .bind(&hold.id)
    };
    let before = lease().fetch_one(&mut owner).await.unwrap();
    sqlx::query("UPDATE openmettle.runs SET lease_expires_at=lease_expires_at WHERE id=$1::uuid")
        .bind(&run)
        .execute(&mut owner)
        .await
        .unwrap();
    assert_eq!(lease().fetch_one(&mut owner).await.unwrap(), before);
    // An already elapsed execution deadline may precede the storage row's creation.
    sqlx::query("UPDATE openmettle.runs SET execution_expires_at=now()-interval '1 hour',lease_expires_at=now()-interval '1 hour' WHERE id=$1::uuid")
        .bind(&run).execute(&mut owner).await.unwrap();
    assert_eq!(lease().fetch_one(&mut owner).await.unwrap(), before);
}

/// Seed one gateway binding + session request + 3-column `> i64::MAX` token settlement
/// (`prompt + completion + reasoning = 3 * i64::MAX = 27670116110564327421`) through the real
/// runtime roles (`openmettle_api` + `openmettle_gateway`).
pub(super) async fn settle_oversized_three_column_tokens(
    db: &TestDb,
    actor: &authz_store::Account,
    scope: &str,
    session_cookie: &str,
) {
    use openmettle_core::{
        authz::gateway::{self, Authority, Call, Reservation},
        provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
    };
    const INSTALL: &str = "00000000-0000-4000-8000-000000000023";
    const PRINCIPAL: &str = "00000000-0000-4000-8000-000000000024";
    const BUDGET: &str = "00000000-0000-4000-8000-000000000025";

    let api_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&db.url(API))
        .await
        .unwrap();
    let gw_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&db.url(pg::GATEWAY))
        .await
        .unwrap();
    let ring = GatewayKeys::new(&[("fixture".into(), [42; 32])]).unwrap();
    let binding: String = sqlx::query_scalar(
        "INSERT INTO openmettle.gateway_bindings (installation, user_id, principal, budget)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid) RETURNING id::text",
    )
    .bind(INSTALL)
    .bind(&actor.user)
    .bind(PRINCIPAL)
    .bind(BUDGET)
    .fetch_one(&gw_pool)
    .await
    .unwrap();
    let ctx = Context {
        installation: INSTALL,
        user_id: &actor.user,
        binding_id: &binding,
        principal: PRINCIPAL,
        generation: 1,
    };
    let (finger, sealed) = GatewaySealer::new(
        GatewayKeys::new(&[("fixture".into(), [42; 32])]).unwrap(),
        gw_pool.clone(),
    )
    .seal(&ctx, &Bearer::generate().unwrap())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_generations
             (binding_id, generation, remote_key, expires_at, key_id, key_fingerprint, nonce, ciphertext)
         VALUES ($1::uuid, 1, gen_random_uuid(), clock_timestamp() + interval '1 hour', $2, $3, $4, $5)",
    )
    .bind(&binding)
    .bind(&sealed.key_id)
    .bind(finger.as_slice())
    .bind(sealed.nonce.as_slice())
    .bind(sealed.ciphertext)
    .execute(&gw_pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_policy
             (binding_id, revision, scope_id, approval_id, model, report_source,
              provider_generation, approval_generation, user_generation, capabilities)
         VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'a', gen_random_uuid(), 0, 0, 0, '{}'::jsonb)",
    )
    .bind(&binding)
    .bind(scope)
    .bind(&actor.approval)
    .execute(&gw_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.gateway_bindings
            SET active_generation = 1, observed_revision = 1, state = 'ready'
          WHERE id = $1::uuid",
    )
    .bind(&binding)
    .execute(&gw_pool)
    .await
    .unwrap();

    let res_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&api_pool)
        .await
        .unwrap();
    let call = gateway::reserve(
        &api_pool,
        Call {
            installation: INSTALL,
            model: "a",
            units: 100,
            reservation: Reservation {
                id: &res_id,
                scope_id: scope,
                actor: &actor.user,
                approval: &actor.approval,
            },
            authority: Authority::Session {
                credential: session_cookie,
                native_audience: None,
            },
        },
    )
    .await
    .unwrap();
    let fx = TurnHandoffFixture::chat(INSTALL, "a", 100, None, false);
    let dev_fx = TurnHandoffFixture::chat(INSTALL, "a", 100, None, true);
    // Caller sessions cannot hand off device-slot profiles and stay reserved on refusal.
    assert!(matches!(
        call.handoff(
            &api_pool,
            &ring,
            &dev_fx.billable(),
            dev_fx.prepare_mode(false)
        )
        .await,
        Err(gateway::Error::Refused)
    ));
    let pre_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.gateway_requests WHERE id = $1::uuid")
            .bind(&call.id)
            .fetch_one(&gw_pool)
            .await
            .unwrap();
    assert_eq!(pre_state, "reserved");
    call.handoff(&api_pool, &ring, &fx.billable(), fx.prepare_mode(false))
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_usage_reports
             (request_id, source, report_id, revision, final,
              prompt_tokens, completion_tokens, reasoning_tokens, reasoning_included)
         SELECT id, report_source, gen_random_uuid(), 0, true, $2, $2, $2, false
           FROM openmettle.gateway_requests WHERE id = $1::uuid",
    )
    .bind(&call.id)
    .bind(i64::MAX)
    .execute(&gw_pool)
    .await
    .unwrap();
    let mut gtx = gw_pool.begin().await.unwrap();
    sqlx::query("SELECT openmettle.quota_lock_gateway_request_for_settlement($1::uuid)")
        .bind(&call.id)
        .execute(&mut *gtx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_settlements (request_id, revision, final, measured, outstanding)
         VALUES ($1::uuid, 0, true, $2::text::numeric, 0)",
    )
    .bind(&call.id)
    .bind("27670116110564327421")
    .execute(&mut *gtx)
    .await
    .unwrap();
    gtx.commit().await.unwrap();
    sqlx::query(
        "SELECT openmettle.quota_settle_gateway_usage(request_id, source, report_id, revision)
           FROM openmettle.gateway_usage_reports WHERE request_id = $1::uuid AND revision = 0",
    )
    .bind(&call.id)
    .execute(&gw_pool)
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn quota_store_enforces_upgrade_gate_denomination_idempotency_and_wide_summary() {
    use openmettle_core::{
        authz::{
            DenialReason,
            store::{self, AuditContext, StoreError},
        },
        quotas::{self, QuotaError, QuotaResourceKind as K},
    };

    // 1. Upgraded DB (`applied = 23` -> `24` -> `25` -> `26`) verifies historical boundaries
    //    at each version and gates override writes until metering_enforced = true.
    let upgraded = TestDb::new().await;
    let settings = upgraded.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
    migrate::apply(&settings, &MIGRATIONS[..24]).await.unwrap();
    migrate::apply(&settings, &MIGRATIONS[..25]).await.unwrap();
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    let mut u_owner = connect(&upgraded.0, OWNER).await;
    authz_store::providers(&mut u_owner).await;
    let u_admin = authz_store::account(
        &mut u_owner,
        authz_store::PROVIDER,
        true,
        authz_store::FUTURE,
    )
    .await;
    authz_store::make_admin(&mut u_owner, &u_admin).await;
    let u_scope = authz_runs::personal_of(&upgraded, &u_admin).await;
    let mut u_api = connect(&upgraded.0, API).await;
    let u_ctx = AuditContext {
        actor_user_id: &u_admin.user,
        actor_approval_id: &u_admin.approval,
        now_ms: authz_store::NOW,
        request_key: "upgrade-gate-key",
        reason: "before activation",
    };
    assert!(matches!(
        quotas::set_scope_override(&mut u_api, &u_ctx, &u_scope, K::StorageBytes, 1024, None).await,
        Err(QuotaError::UpgradeNotEnforced)
    ));
    u_owner
        .execute("UPDATE openmettle.quota_enforcement SET metering_enforced=true,metering_enforced_at=clock_timestamp() WHERE id")
        .await
        .unwrap();
    // Flipping metering_enforced alone on an upgraded DB MUST still gate override writes until
    // overrides_enforced is also activated (migration 26 rolling-upgrade completion gate).
    assert!(matches!(
        quotas::set_scope_override(&mut u_api, &u_ctx, &u_scope, K::StorageBytes, 1024, None).await,
        Err(QuotaError::UpgradeNotEnforced)
    ));
    u_owner
        .execute("UPDATE openmettle.quota_enforcement SET overrides_enforced=true,overrides_enforced_at=clock_timestamp() WHERE id")
        .await
        .unwrap();
    // Active adoption run also blocks override writes until cleared.
    u_owner
        .execute("UPDATE openmettle.storage_volume_control SET adoption_run_id=gen_random_uuid() WHERE id")
        .await
        .unwrap();
    assert!(matches!(
        quotas::set_scope_override(&mut u_api, &u_ctx, &u_scope, K::StorageBytes, 1024, None).await,
        Err(QuotaError::AdoptionInProgress)
    ));
    u_owner
        .execute("UPDATE openmettle.storage_volume_control SET adoption_run_id=NULL WHERE id")
        .await
        .unwrap();
    let created =
        quotas::set_scope_override(&mut u_api, &u_ctx, &u_scope, K::StorageBytes, 1024, None)
            .await
            .unwrap();
    assert_eq!(
        (created.hard_limit.as_str(), created.revision.as_str()),
        ("1024", "1")
    );

    // 2. Fresh DB: non-admin refusal, OMQ02, per-actor project refusal, replay, and >i64::MAX settlement.
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let admin =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    authz_store::make_admin(&mut owner, &admin).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let alice_scope = authz_runs::personal_of(&db, &alice).await;
    let (_, project_scope) = project(&mut connect(&db.0, API).await, &alice.user).await;
    let mut api = connect(&db.0, API).await;

    let alice_ctx = AuditContext {
        actor_user_id: &alice.user,
        actor_approval_id: &alice.approval,
        now_ms: authz_store::NOW,
        request_key: "non-admin-key",
        reason: "denied",
    };
    assert!(matches!(
        quotas::set_scope_override(&mut api, &alice_ctx, &alice_scope, K::UsageTokens, 50, None)
            .await,
        Err(QuotaError::Store(StoreError::Denied(DenialReason::Policy(
            _
        ))))
    ));

    let admin_ctx = |key| AuditContext {
        actor_user_id: &admin.user,
        actor_approval_id: &admin.approval,
        now_ms: authz_store::NOW,
        request_key: key,
        reason: "synthetic reason",
    };
    assert!(matches!(
        quotas::set_scope_override(
            &mut api,
            &admin_ctx("omq02"),
            &alice_scope,
            K::UsageCostMicros,
            500,
            None,
        )
        .await,
        Err(QuotaError::CostDenominationUnconfigured)
    ));
    assert!(matches!(
        quotas::set_scope_override(
            &mut api,
            &admin_ctx("per-actor-proj"),
            &project_scope,
            K::LiveRunsPerActor,
            2,
            None,
        )
        .await,
        Err(QuotaError::Store(StoreError::InvalidInput(_)))
    ));
    assert!(matches!(
        quotas::set_scope_override(
            &mut api,
            &admin_ctx("round-cap-0"),
            &alice_scope,
            K::RoundCap,
            0,
            None,
        )
        .await,
        Err(QuotaError::Store(StoreError::InvalidInput(_)))
    ));

    let first = quotas::set_scope_override(
        &mut api,
        &admin_ctx("idemp-1"),
        &alice_scope,
        K::UsageTokens,
        1000,
        None,
    )
    .await
    .unwrap();
    let replayed = quotas::set_scope_override(
        &mut api,
        &admin_ctx("idemp-1"),
        &alice_scope,
        K::UsageTokens,
        1000,
        None,
    )
    .await
    .unwrap();
    assert_eq!(first, replayed);
    assert_eq!(first.revision, "1");
    assert!(matches!(
        quotas::set_scope_override(
            &mut api,
            &admin_ctx("idemp-1"),
            &alice_scope,
            K::UsageTokens,
            2000,
            None,
        )
        .await,
        Err(QuotaError::Store(StoreError::Conflict(store::KEY_REUSED)))
    ));

    // Settle a 3-column > i64::MAX token report and verify both read_summary and zero drift.
    let session_tok = authz_runs::seeded_session(&db, &alice, 7, None).await;
    settle_oversized_three_column_tokens(&db, &alice, &alice_scope, &session_tok).await;

    let summary = quotas::read_summary(&mut api, &alice_scope, Some(&alice.user), None)
        .await
        .unwrap();
    assert_eq!(summary.usage[0].resource_kind, "usage_tokens");
    assert_eq!(summary.usage[0].active_used, "27670116110564327421");
    assert_eq!(summary.usage[0].remaining.as_deref(), Some("0"));
    assert_eq!(summary.usage[0].status, "hard_limit");
    assert!(summary.usage[0].last_reconciled_at.is_some());
    assert_eq!(summary.execution.executing_runs_per_scope.limit, None);
    assert_eq!(
        summary.execution.executing_runs_per_scope.limit_source,
        "worker"
    );
    let actor_exec = summary
        .execution
        .executing_runs_per_actor
        .as_ref()
        .expect("personal summary includes executing_runs_per_actor");
    assert_eq!(actor_exec.limit, None);
    assert_eq!(actor_exec.limit_source, "worker");

    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'executing_runs_per_actor', 3),
                    ('personal', 'executing_runs_per_scope', 7)",
        )
        .await
        .unwrap();
    let summary_with_db_defaults =
        quotas::read_summary(&mut api, &alice_scope, Some(&alice.user), None)
            .await
            .unwrap();
    assert_eq!(
        summary_with_db_defaults
            .execution
            .executing_runs_per_scope
            .limit
            .as_deref(),
        Some("7")
    );
    assert_eq!(
        summary_with_db_defaults
            .execution
            .executing_runs_per_scope
            .limit_source,
        "default"
    );
    let actor_exec_db = summary_with_db_defaults
        .execution
        .executing_runs_per_actor
        .as_ref()
        .expect("personal summary includes executing_runs_per_actor");
    assert_eq!(actor_exec_db.limit.as_deref(), Some("3"));
    assert_eq!(actor_exec_db.limit_source, "default");

    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut connect(&db.0, WORKER).await)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn quota_override_locks_single_audit_and_expired_override_warnings() {
    use openmettle_core::{
        authz::store::AuditContext,
        quotas::{self, QuotaError, QuotaResourceKind as K},
        runs::WriteTransaction,
        storage::{self, ReservationInput},
    };

    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let admin =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    authz_store::make_admin(&mut owner, &admin).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let scope = authz_runs::personal_of(&db, &alice).await;

    // 1. Unpinned volume (volume_id IS NULL, adoption_run_id IS NULL) permits overrides, AND
    //    holding storage_volume_control FOR UPDATE serializes concurrent override writes.
    let (vol, adopt): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT volume_id::text, adoption_run_id::text FROM openmettle.storage_volume_control WHERE id",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!((vol, adopt), (None, None));

    let mut adoption_tx = owner.begin().await.unwrap();
    sqlx::query("SELECT id FROM openmettle.storage_volume_control WHERE id FOR UPDATE")
        .execute(&mut *adoption_tx)
        .await
        .unwrap();
    let db_name = db.0.clone();
    let admin_id = admin.user.clone();
    let admin_app = admin.approval.clone();
    let scope_clone = scope.clone();
    let writer = tokio::spawn(async move {
        let mut c = connect(&db_name, API).await;
        let ctx = AuditContext {
            actor_user_id: &admin_id,
            actor_approval_id: &admin_app,
            now_ms: authz_store::NOW,
            request_key: "adopt-race-key",
            reason: "racing adoption",
        };
        quotas::set_scope_override(&mut c, &ctx, &scope_clone, K::StorageBytes, 4096, None).await
    });
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        !writer.is_finished(),
        "override write must wait on storage_volume_control FOR SHARE while adoption holds FOR UPDATE"
    );
    sqlx::query(
        "UPDATE openmettle.storage_volume_control SET adoption_run_id = gen_random_uuid() WHERE id",
    )
    .execute(&mut *adoption_tx)
    .await
    .unwrap();
    adoption_tx.commit().await.unwrap();
    assert!(matches!(
        writer.await.unwrap(),
        Err(QuotaError::AdoptionInProgress)
    ));
    owner
        .execute("UPDATE openmettle.storage_volume_control SET adoption_run_id = NULL WHERE id")
        .await
        .unwrap();

    // 2. Exactly one authorization_audit row per mutation, and replay of k1 after k2 + revoke keeps rev 1.
    let mut api = connect(&db.0, API).await;
    let mk_ctx = |key| AuditContext {
        actor_user_id: &admin.user,
        actor_approval_id: &admin.approval,
        now_ms: authz_store::NOW,
        request_key: key,
        reason: "single audit check",
    };
    let s1 = quotas::set_scope_override(&mut api, &mk_ctx("k1"), &scope, K::UsageTokens, 500, None)
        .await
        .unwrap();
    assert_eq!(s1.revision, "1");
    let s2 = quotas::set_scope_override(&mut api, &mk_ctx("k2"), &scope, K::UsageTokens, 900, None)
        .await
        .unwrap();
    assert_eq!(s2.revision, "2");
    let r3 = quotas::revoke_scope_override(&mut api, &mk_ctx("k3"), &scope, K::UsageTokens)
        .await
        .unwrap();
    assert_eq!(r3.revision, "3");
    // Replaying k1 after k2 and revoke returns the original recorded revision 1.
    let s1_replay =
        quotas::set_scope_override(&mut api, &mk_ctx("k1"), &scope, K::UsageTokens, 500, None)
            .await
            .unwrap();
    assert_eq!(s1_replay, s1);
    let audit_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.authorization_audit
          WHERE actor_user_id = $1::uuid
            AND action IN ('quota.override.set', 'quota.override.revoke')",
    )
    .bind(&admin.user)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(audit_rows, 3);

    // 3. Expired temporary low storage override reverts limit_revision to 0 and clears obsolete warnings.
    owner
        .execute(
            "UPDATE openmettle.storage_instance
                SET instance_budget_bytes = 100000, personal_limit_bytes = 10000, project_limit_bytes = 10000",
        )
        .await
        .unwrap();
    quotas::set_scope_override(
        &mut api,
        &mk_ctx("temp-low-storage"),
        &scope,
        K::StorageBytes,
        1000,
        Some("2028-01-01T00:00:00.000000Z"),
    )
    .await
    .unwrap();
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    storage::reserve(
        &mut tx,
        &ReservationInput {
            scope: &scope,
            actor: &alice.user,
            key: "warn-exp-1",
            artifact: "00000000-0000-4000-8000-000000000099",
            max_bytes: 850,
            run: None,
            operation: None,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let before_exp = quotas::read_summary(&mut api, &scope, Some(&alice.user), None)
        .await
        .unwrap();
    assert_eq!(before_exp.storage.status, "warning");
    assert_eq!(before_exp.warnings.len(), 1);
    assert_eq!(before_exp.warnings[0].threshold_pct, 80);

    // Expire the temporary override; default limit (10000) applies -> 850/10000 = 8.5% -> ok, 0 warnings.
    sqlx::query(
        "UPDATE openmettle.quota_overrides
            SET expires_at = clock_timestamp() - interval '1 second'
          WHERE scope_id = $1::uuid AND resource_kind = 'storage_bytes'",
    )
    .bind(&scope)
    .execute(&mut owner)
    .await
    .unwrap();
    let after_exp = quotas::read_summary(&mut api, &scope, Some(&alice.user), None)
        .await
        .unwrap();
    assert_eq!(after_exp.storage.limit_bytes.as_deref(), Some("10000"));
    assert_eq!(after_exp.storage.limit_source, "default");
    assert_eq!(after_exp.storage.status, "ok");
    assert!(
        after_exp.warnings.is_empty(),
        "obsolete override warning remained after expiry: {:?}",
        after_exp.warnings
    );
    let active_limit_rev: i64 = sqlx::query_scalar(
        "SELECT limit_revision FROM openmettle.quota_limit($1::uuid, 'personal', 'storage_bytes')",
    )
    .bind(&scope)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(active_limit_rev, 0);
}

pub(super) async fn branch_and_message(
    api: &mut PgConnection,
    scope: &str,
    chat: &str,
) -> (String, String) {
    let msg = message(api, scope, chat, None).await.unwrap();
    let branch: String = sqlx::query_scalar(
        "INSERT INTO openmettle.conversation_branches (scope_id, conversation_id)
         VALUES ($1::uuid, $2::uuid) RETURNING id::text",
    )
    .bind(scope)
    .bind(chat)
    .fetch_one(&mut *api)
    .await
    .unwrap();
    (branch, msg)
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn schema_23_run_budget_survives_upgrade_to_26_and_legacy_worker_dispatch() {
    use openmettle_core::{
        authz::{
            leases::LeaseSettings,
            runs::{self as authz_queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
        },
        quotas::{self, RunBudgetReservation},
        runs::{RunInput, WriteTransaction},
    };

    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();

    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let scope = authz_runs::personal_of(&db, &alice).await;
    let chat = authz_runs::chat(&db, &scope, "personal", &alice).await;
    let mut api = connect(&db.0, API).await;
    let (branch, message) = branch_and_message(&mut api, &scope, &chat).await;
    let limits = AdmissionLimits {
        live_per_actor: 4,
        live_per_scope: 8,
        queued_in_instance: 32,
        queue_timeout: Duration::from_secs(300),
        round_cap: 10,
    };
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let admitted = authz_queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &scope,
                actor: &alice.user,
                conversation: &chat,
                branch: &branch,
                message: &message,
                key: "schema-23-run",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: b"{}",
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(2),
            now_ms: authz_store::NOW,
            cost_qualified: None,
        },
        &limits,
    )
    .await
    .unwrap();
    let run_id = match admitted {
        Admission::Admitted { run_id, .. } => run_id,
        other => panic!("expected admitted run, got {other:?}"),
    };
    let refusal = quotas::reserve_admitted_run_budget(
        &mut tx,
        &RunBudgetReservation {
            scope_id: &scope,
            scope_kind: "personal",
            actor_user_id: &alice.user,
            actor_approval_id: &alice.approval,
            run_id: &run_id,
            token_units: 8192,
            per_round_cost_micros: None,
            round_limit: 1,
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    assert!(refusal.is_none());
    tx.commit().await.unwrap();

    // Schema 23 must already record the gateway_reservations row before 0024 exists.
    let gw_units: i64 = sqlx::query_scalar(
        "SELECT units FROM openmettle.gateway_reservations WHERE run_id = $1::uuid",
    )
    .bind(&run_id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(gw_units, 8192);

    // Upgrade 23 -> 26, enable metering, configure usage_tokens, and dispatch via worker claim.
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 100000)",
        )
        .await
        .unwrap();
    owner
        .execute(
            "UPDATE openmettle.quota_enforcement
                SET metering_enforced = true, metering_enforced_at = clock_timestamp()
              WHERE id",
        )
        .await
        .unwrap();

    let mut worker = connect(&db.0, WORKER).await;
    let claimed = authz_queue::claim_next(
        &mut worker,
        &ClaimLimits {
            executing_per_actor: 4,
            executing_per_scope: 8,
        },
        &LeaseSettings {
            lease: Duration::from_secs(60),
            execution_timeout: Duration::from_secs(600),
        },
    )
    .await
    .unwrap()
    .expect("claimed schema-23 run after upgrade");
    assert_eq!(claimed.run_id, run_id);

    sqlx::query("SELECT openmettle.quota_ensure_legacy_run_holds($1::uuid, $2::uuid, $3::uuid)")
        .bind(&claimed.scope_id)
        .bind(&claimed.run_id)
        .bind(&claimed.claim_token)
        .execute(&mut worker)
        .await
        .unwrap();

    let held: (String, i64, String) = sqlx::query_as(
        "SELECT resource_kind, held_units, state
           FROM openmettle.quota_reservations
          WHERE run_id = $1::uuid AND gateway_request_id IS NULL",
    )
    .bind(&run_id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(held, ("usage_tokens".into(), 8192, "held".into()));

    // Verify the prior-binary grants allowlist SQL across MIGRATIONS[23..] decodes cleanly
    // with zero NULLs after 0026 drops the superseded 6-arg/4-arg override signatures.
    let quota_sql: String = MIGRATIONS[23..]
        .iter()
        .map(|m| m.sql)
        .collect::<Vec<_>>()
        .join("\n");
    let grants: Vec<String> = sqlx::query_scalar(
        r"SELECT DISTINCT trim(role) || ' has EXECUTE on function ' || proc::text
            FROM regexp_matches($1, 'GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+(openmettle\.\w+\([^)]*\))\s+TO\s+([^;]+);','gi') parts,
                 unnest(string_to_array(parts[2],',')) role,
                 LATERAL (SELECT to_regprocedure(parts[1]) AS proc) p
           WHERE p.proc IS NOT NULL",
    )
    .bind(&quota_sql)
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert!(
        grants.iter().any(|g| {
            g == "openmettle_api has EXECUTE on function openmettle.storage_lock_not_adopting()"
        }),
        "{grants:?}"
    );
    assert!(
        grants.iter().any(|g| g.contains(
            "openmettle.quota_upsert_scope_override(uuid,uuid,text,bigint,timestamp with time zone,text,text,jsonb)"
        )),
        "{grants:?}"
    );
    assert!(
        grants.iter().any(|g| g
            .contains("openmettle.quota_revoke_scope_override(uuid,uuid,text,text,text,jsonb)")),
        "{grants:?}"
    );
    for expected in [
        "openmettle_worker has EXECUTE on function openmettle.quota_ensure_legacy_run_holds(uuid,uuid,uuid)",
        "openmettle_worker has EXECUTE on function openmettle.quota_prepare_turn_round(uuid,uuid,uuid,bigint,bigint,boolean,boolean,boolean,boolean)",
        "openmettle_worker has EXECUTE on function openmettle.quota_run_round_cost_slice(uuid,uuid,uuid)",
        "openmettle_worker has EXECUTE on function openmettle.quota_authorize_unmetered_turn_round(uuid,uuid,uuid)",
        "openmettle_worker has EXECUTE on function openmettle.quota_lock_turn_handoff_prefix(uuid,bytea,uuid,uuid,uuid)",
        "openmettle_worker has EXECUTE on function openmettle.quota_lock_run_actor_prefix(uuid,uuid)",
        "openmettle_worker has EXECUTE on function openmettle.quota_recover_unsent_turn_round(uuid,uuid,uuid,integer)",
        "openmettle_worker has EXECUTE on function openmettle.quota_commit_turn_handoff(uuid,bytea,uuid,uuid,uuid,boolean,uuid,boolean)",
        "openmettle_api has EXECUTE on function openmettle.quota_ensure_replayed_run_gateway_reservation(uuid,uuid,uuid,bigint)",
    ] {
        assert!(
            grants.iter().any(|g| g == expected),
            "{expected} not in {grants:?}"
        );
    }
    for role in ["openmettle_api", "openmettle_worker"] {
        let expected = format!(
            "{role} has EXECUTE on function openmettle.quota_release_terminal_runs(uuid[])"
        );
        assert!(
            grants.iter().any(|g| g == &expected),
            "{expected} not in {grants:?}"
        );
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn cancel_and_expire_immediately_release_holds_unless_operation_is_in_flight() {
    use openmettle_core::{
        authz::runs::{
            self as authz_queue, Admission, AdmissionLimits, CancelOutcome, RunAdmission,
        },
        quotas::{self, RunBudgetReservation},
        runs::{RunInput, WriteTransaction},
    };

    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let scope = authz_runs::personal_of(&db, &alice).await;
    let chat = authz_runs::chat(&db, &scope, "personal", &alice).await;
    let mut api = connect(&db.0, API).await;
    let (branch, message) = branch_and_message(&mut api, &scope, &chat).await;

    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 20000),
                    ('personal', 'device_reservations', 1)",
        )
        .await
        .unwrap();

    let limits = AdmissionLimits {
        live_per_actor: 4,
        live_per_scope: 8,
        queued_in_instance: 32,
        queue_timeout: Duration::from_secs(300),
        round_cap: 10,
    };
    async fn admit_with_holds(
        api: &mut PgConnection,
        alice: &authz_store::Account,
        target: (&str, &str, &str, &str),
        limits: &AdmissionLimits,
        key: &str,
    ) -> String {
        let (scope, chat, branch, message) = target;
        let mut tx = WriteTransaction::begin(api).await.unwrap();
        let Admission::Admitted { run_id, .. } = authz_queue::admit_run(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope,
                    actor: &alice.user,
                    conversation: chat,
                    branch,
                    message,
                    key,
                    format: "openmettle.conversation",
                    version: 1,
                    input: b"{}",
                    config: b"{}",
                },
                actor_approval_id: &alice.approval,
                capabilities: &[],
                requested_rounds: Some(1),
                now_ms: authz_store::NOW,
                cost_qualified: None,
            },
            limits,
        )
        .await
        .unwrap() else {
            panic!("expected admitted run");
        };
        assert!(
            quotas::reserve_admitted_run_budget(
                &mut tx,
                &RunBudgetReservation {
                    scope_id: scope,
                    scope_kind: "personal",
                    actor_user_id: &alice.user,
                    actor_approval_id: &alice.approval,
                    run_id: &run_id,
                    token_units: 12000,
                    per_round_cost_micros: None,
                    round_limit: 1,
                    requires_device_slot: true,
                },
            )
            .await
            .unwrap()
            .is_none()
        );
        tx.commit().await.unwrap();
        run_id
    }

    // 1. Expiring a queued run immediately releases both token and device parent holds.
    let run_exp = admit_with_holds(
        &mut api,
        &alice,
        (&scope, &chat, &branch, &message),
        &limits,
        "exp-1",
    )
    .await;
    sqlx::query(
        "UPDATE openmettle.runs
            SET created_at = clock_timestamp() - interval '2 seconds',
                queue_expires_at = clock_timestamp() - interval '1 second'
          WHERE id = $1::uuid",
    )
    .bind(&run_exp)
    .execute(&mut owner)
    .await
    .unwrap();
    let mut worker = connect(&db.0, WORKER).await;
    assert_eq!(
        authz_queue::expire_queued(&mut worker, 10).await.unwrap(),
        vec![run_exp.clone()]
    );
    let held_after_expire: i64 = sqlx::query_scalar(
        "SELECT coalesce(sum(reserved_held), 0)::bigint FROM openmettle.quota_budgets",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(held_after_expire, 0);

    // 2. Cancelling a waiting run with an outcome_unknown operation succeeds without releasing holds early.
    let run_wait = admit_with_holds(
        &mut api,
        &alice,
        (&scope, &chat, &branch, &message),
        &limits,
        "wait-op-1",
    )
    .await;
    sqlx::query(
        "UPDATE openmettle.runs SET state = 'waiting', wait_reason = NULL WHERE id = $1::uuid",
    )
    .bind(&run_wait)
    .execute(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.operations
             (scope_id, run_id, logical_key, target, capability, format, format_version,
              request, request_identity, request_digest, outcome, revision,
              observation_format, observation_version, evidence)
         VALUES ($1::uuid, $2::uuid, 'op-unknown', 'synthetic-target', 'non_repeatable',
                 'openmettle.op', 1, '\\x01'::bytea, '\\x01'::bytea, sha256('\\x01'::bytea),
                 'outcome_unknown', 1, 'openmettle.obs', 1, '\\x01'::bytea)",
    )
    .bind(&scope)
    .bind(&run_wait)
    .execute(&mut owner)
    .await
    .unwrap();
    let principal = openmettle_core::authz::store::hydrate_api_principal(
        &mut api,
        &alice.user,
        &alice.approval,
        authz_store::NOW,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        authz_queue::cancel_run(&mut api, &principal, &scope, &run_wait)
            .await
            .unwrap(),
        CancelOutcome::Cancelled
    );
    let still_held: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.quota_reservations
          WHERE run_id = $1::uuid AND state = 'held'",
    )
    .bind(&run_wait)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(still_held, 2);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn schema_23_cost_device_upgrade_pre_pr3_worker_recovery_and_gateway_reserve_slice() {
    use openmettle_core::{
        authz::{
            gateway::{self, Authority, Call, Reservation, TurnRound},
            leases::LeaseSettings,
            runs::{self as authz_queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
        },
        quotas::{self, RunBudgetReservation},
        runs::{RunInput, WriteTransaction},
    };
    use sqlx::postgres::PgPoolOptions;

    const INSTALL: &str = "00000000-0000-4000-8000-000000000073";

    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();

    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let scope = authz_runs::personal_of(&db, &alice).await;
    let chat = authz_runs::chat(&db, &scope, "personal", &alice).await;
    let mut api = connect(&db.0, API).await;
    let (branch, message) = branch_and_message(&mut api, &scope, &chat).await;
    let limits = AdmissionLimits {
        live_per_actor: 8,
        live_per_scope: 8,
        queued_in_instance: 32,
        queue_timeout: Duration::from_secs(300),
        round_cap: 10,
    };

    // 1. Admit a 1-round run on schema 23 (records gateway_reservations = 450, no quota_reservations).
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted {
        run_id: run_s23, ..
    } = authz_queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &scope,
                actor: &alice.user,
                conversation: &chat,
                branch: &branch,
                message: &message,
                key: "s23-cost-dev",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot(450),
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(1),
            now_ms: authz_store::NOW,
            cost_qualified: None,
        },
        &limits,
    )
    .await
    .unwrap()
    else {
        panic!("expected schema-23 admission");
    };
    assert!(
        quotas::reserve_admitted_run_budget(
            &mut tx,
            &RunBudgetReservation {
                scope_id: &scope,
                scope_kind: "personal",
                actor_user_id: &alice.user,
                actor_approval_id: &alice.approval,
                run_id: &run_s23,
                token_units: 450,
                per_round_cost_micros: None,
                round_limit: 1,
                requires_device_slot: false,
            },
        )
        .await
        .unwrap()
        .is_none()
    );
    tx.commit().await.unwrap();

    // Upgrade 23 -> 26, activate metering, configure static 1000-micro cost limit + 1 device slot,
    // and pre-charge 200 micros active_used (leaving 800 remaining: enough for 450, NOT 1000!).
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    owner
        .execute(
            "UPDATE openmettle.quota_defaults
                SET cost_denomination = 'usd_micros'
              WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros'",
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 100000),
                    ('personal', 'usage_cost_micros', 1000),
                    ('personal', 'device_reservations', 1)",
        )
        .await
        .unwrap();
    owner
        .execute(
            "UPDATE openmettle.quota_enforcement
                SET metering_enforced = true, metering_enforced_at = clock_timestamp()
              WHERE id",
        )
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.quota_budgets
             (target_kind, scope_id, resource_kind, window_kind, window_start, active_used, reserved_held)
         VALUES ('scope', $1::uuid, 'usage_cost_micros', 'static', 'epoch'::timestamptz, 200, 0)",
    )
    .bind(&scope)
    .execute(&mut owner)
    .await
    .unwrap();

    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(WORKER));
    let mut worker = connect(&db.0, WORKER).await;
    let lease_cfg = LeaseSettings {
        lease: Duration::from_secs(60),
        execution_timeout: Duration::from_secs(600),
    };
    let claim_cfg = ClaimLimits {
        executing_per_actor: 4,
        executing_per_scope: 8,
    };
    let claimed_s23 = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .expect("claimed schema-23 run");
    assert_eq!(claimed_s23.run_id, run_s23);

    // reserve_turn_round recovers BOTH device_reservations (1) and 450-micro cost hold (NOT 1000!),
    // succeeding with 200 active + 450 reserved = 650 <= 1000.
    let pending_s23 = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &scope,
            actor: &alice.user,
            approval: &alice.approval,
            run_id: &run_s23,
            round: 1,
            claim_token: &claimed_s23.claim_token,
            installation: INSTALL,
            model: "a",
            round_tokens: 450,
            round_cost: Some(450),
            cost_bound: Some(openmettle_core::model_config::CostBound {
                fixed_micros: 450,
                micros_per_token: 0,
            }),
            requires_device_slot: true,
        },
    )
    .await
    .unwrap();
    let parent_holds: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT resource_kind, reserved_units, held_units
           FROM openmettle.quota_reservations
          WHERE run_id = $1::uuid AND gateway_request_id IS NULL
          ORDER BY resource_kind",
    )
    .bind(&run_s23)
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        parent_holds,
        vec![
            ("device_reservations".into(), 1, 1),
            ("usage_cost_micros".into(), 450, 0),
            ("usage_tokens".into(), 450, 0),
        ]
    );
    // Release Round 1 unsent (returns 450 micros to parent hold), then verify gateway::reserve with
    // cost_ceiling = None derives the 450-micro per-round slice from the parent hold (NOT 1000!).
    assert!(pending_s23.release(&worker_pool).await.unwrap());
    let pending_auto = gateway::reserve(
        &worker_pool,
        Call {
            reservation: Reservation {
                id: &run_s23,
                scope_id: &scope,
                actor: &alice.user,
                approval: &alice.approval,
            },
            installation: INSTALL,
            model: "a",
            units: 450,
            authority: Authority::Lease {
                run: &run_s23,
                round: 1,
                token: &claimed_s23.claim_token,
            },
        },
    )
    .await
    .unwrap();
    let child_cost: i64 = sqlx::query_scalar(
        "SELECT reserved_units FROM openmettle.quota_reservations
          WHERE gateway_request_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&pending_auto.id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(child_cost, 450);
    assert!(pending_auto.release(&worker_pool).await.unwrap());
    openmettle_core::authz::leases::settle(
        &mut worker,
        &claimed_s23.lease(),
        &lease_cfg,
        openmettle_core::authz::leases::Settle::Succeeded,
    )
    .await
    .unwrap();

    // 2. Pre-PR3 live queued run inserted WITHOUT a gateway_reservations row recovers cleanly on
    //    direct worker dispatch (`reserve_turn_round`), creating gateway_reservations + quota holds.
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted {
        run_id: run_legacy, ..
    } = authz_queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &scope,
                actor: &alice.user,
                conversation: &chat,
                branch: &branch,
                message: &message,
                key: "pre-pr3-no-gw-res",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot(300),
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(2),
            now_ms: authz_store::NOW,
            cost_qualified: None,
        },
        &limits,
    )
    .await
    .unwrap()
    else {
        panic!("expected pre-PR3 admission");
    };
    tx.commit().await.unwrap();
    let pre_gw: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.gateway_reservations WHERE run_id = $1::uuid",
    )
    .bind(&run_legacy)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(pre_gw, 0);

    let claimed_legacy = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .expect("claimed pre-PR3 run");
    assert_eq!(claimed_legacy.run_id, run_legacy);
    let pending_legacy = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &scope,
            actor: &alice.user,
            approval: &alice.approval,
            run_id: &run_legacy,
            round: 1,
            claim_token: &claimed_legacy.claim_token,
            installation: INSTALL,
            model: "a",
            round_tokens: 300,
            round_cost: Some(300),
            cost_bound: Some(openmettle_core::model_config::CostBound {
                fixed_micros: 300,
                micros_per_token: 0,
            }),
            requires_device_slot: true,
        },
    )
    .await
    .unwrap();
    let gw_recovered: (i64, i64) = sqlx::query_as(
        "SELECT units, allocated FROM openmettle.gateway_reservations WHERE run_id = $1::uuid",
    )
    .bind(&run_legacy)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(gw_recovered, (600, 300));
    assert!(pending_legacy.release(&worker_pool).await.unwrap());
    openmettle_core::authz::leases::settle(
        &mut worker,
        &claimed_legacy.lease(),
        &lease_cfg,
        openmettle_core::authz::leases::Settle::Succeeded,
    )
    .await
    .unwrap();
    let remaining_held: i64 = sqlx::query_scalar(
        "SELECT coalesce(sum(reserved_held), 0)::bigint FROM openmettle.quota_budgets",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(remaining_held, 0);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn schema_25_expiry_gating_and_batch_terminal_hold_release() {
    use openmettle_core::{
        authz::{
            approvals,
            leases::{self, LeaseSettings, Settle},
            projects::{self, ProjectSettingsInput},
            runs::{self as authz_queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
        },
        quotas::{self, RunBudgetReservation},
        runs::{RunInput, WriteTransaction},
    };
    use serde_json::json;

    // Part A (Finding #5): on schema 25 (before 0026 exists), expire_queued as openmettle_worker
    // on a run with an origin_role = 'api' parent hold must commit cleanly without 42501.
    let db25 = TestDb::new().await;
    let settings25 = db25.settings(Duration::from_secs(10));
    migrate::apply(&settings25, &MIGRATIONS[..25])
        .await
        .unwrap();
    let mut owner25 = connect(&db25.0, OWNER).await;
    authz_store::providers(&mut owner25).await;
    let alice25 = authz_store::account(
        &mut owner25,
        authz_store::PROVIDER,
        true,
        authz_store::FUTURE,
    )
    .await;
    let scope25 = authz_runs::personal_of(&db25, &alice25).await;
    owner25
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 100000)",
        )
        .await
        .unwrap();
    owner25
        .execute(
            "UPDATE openmettle.quota_enforcement
                SET metering_enforced = true, metering_enforced_at = clock_timestamp()
              WHERE id AND NOT metering_enforced",
        )
        .await
        .unwrap();
    let chat25 = authz_runs::chat(&db25, &scope25, "personal", &alice25).await;
    let mut api25 = connect(&db25.0, API).await;
    let (branch25, msg25) = branch_and_message(&mut api25, &scope25, &chat25).await;
    let limits = AdmissionLimits {
        live_per_actor: 8,
        live_per_scope: 8,
        queued_in_instance: 32,
        queue_timeout: Duration::from_secs(300),
        round_cap: 10,
    };
    let mut tx = WriteTransaction::begin(&mut api25).await.unwrap();
    let Admission::Admitted { run_id: r25, .. } = authz_queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &scope25,
                actor: &alice25.user,
                conversation: &chat25,
                branch: &branch25,
                message: &msg25,
                key: "s25-expire",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: b"{}",
            },
            actor_approval_id: &alice25.approval,
            capabilities: &[],
            requested_rounds: Some(1),
            now_ms: authz_store::NOW,
            cost_qualified: None,
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("expected schema-25 admission");
    };
    assert!(
        quotas::reserve_admitted_run_budget(
            &mut tx,
            &RunBudgetReservation {
                scope_id: &scope25,
                scope_kind: "personal",
                actor_user_id: &alice25.user,
                actor_approval_id: &alice25.approval,
                run_id: &r25,
                token_units: 5000,
                per_round_cost_micros: None,
                round_limit: 1,
                requires_device_slot: false,
            },
        )
        .await
        .unwrap()
        .is_none()
    );
    tx.commit().await.unwrap();
    sqlx::query(
        "UPDATE openmettle.runs
            SET created_at = clock_timestamp() - interval '2 seconds',
                queue_expires_at = clock_timestamp() - interval '1 second'
          WHERE id = $1::uuid",
    )
    .bind(&r25)
    .execute(&mut owner25)
    .await
    .unwrap();
    let mut worker25 = connect(&db25.0, WORKER).await;
    assert_eq!(
        authz_queue::expire_queued(&mut worker25, 10).await.unwrap(),
        vec![r25]
    );

    // Part B (Findings #2 & #6): on schema 26, batch expire_queued across personal & project scopes,
    // approvals::expire_waits, leases::settle, and leases::settle_expired all release holds cleanly.
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let personal_scope = authz_runs::personal_of(&db, &alice).await;
    let mut api = connect(&db.0, API).await;
    let defaults = json!({});
    let proj_id = authz_store::applied(
        projects::create_project(
            &mut api,
            &authz_store::ctx(&alice, "batch-proj"),
            &ProjectSettingsInput {
                name: "Batch Quota Project",
                instructions: "",
                defaults: &defaults,
            },
        )
        .await,
    );
    let proj_scope: String =
        sqlx::query_scalar("SELECT scope_id::text FROM openmettle.projects WHERE id = $1::uuid")
            .bind(&proj_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    owner
        .execute(
            "UPDATE openmettle.quota_defaults
                SET cost_denomination = 'usd_micros', hard_limit = 100000
              WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros'",
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 100000),
                    ('project', 'usage_tokens', 100000),
                    ('instance', 'usage_tokens', 500000),
                    ('personal', 'usage_cost_micros', 50000),
                    ('project', 'usage_cost_micros', 50000),
                    ('personal', 'device_reservations', 4),
                    ('project', 'device_reservations', 4),
                    ('instance', 'device_reservations', 8)",
        )
        .await
        .unwrap();
    let p_chat = authz_runs::chat(&db, &personal_scope, "personal", &alice).await;
    let (p_branch, p_msg) = branch_and_message(&mut api, &personal_scope, &p_chat).await;
    let pr_chat = authz_runs::chat(&db, &proj_scope, "project", &alice).await;
    let (pr_branch, pr_msg) = branch_and_message(&mut api, &proj_scope, &pr_chat).await;

    let mut admit_all = async |scope_id: &str,
                               scope_kind: &'static str,
                               chat_id: &str,
                               branch_id: &str,
                               msg_id: &str,
                               key: &str| {
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        let Admission::Admitted { run_id, .. } = authz_queue::admit_run(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope: scope_id,
                    actor: &alice.user,
                    conversation: chat_id,
                    branch: branch_id,
                    message: msg_id,
                    key,
                    format: "openmettle.conversation",
                    version: 1,
                    input: b"{}",
                    config: b"{}",
                },
                actor_approval_id: &alice.approval,
                capabilities: &[],
                requested_rounds: Some(1),
                now_ms: authz_store::NOW,
                cost_qualified: Some(true),
            },
            &limits,
        )
        .await
        .unwrap() else {
            panic!("expected admission");
        };
        assert!(
            quotas::reserve_admitted_run_budget(
                &mut tx,
                &RunBudgetReservation {
                    scope_id,
                    scope_kind,
                    actor_user_id: &alice.user,
                    actor_approval_id: &alice.approval,
                    run_id: &run_id,
                    token_units: 1000,
                    per_round_cost_micros: Some(500),
                    round_limit: 1,
                    requires_device_slot: true,
                },
            )
            .await
            .unwrap()
            .is_none()
        );
        tx.commit().await.unwrap();
        run_id
    };

    // 1. Cross-scope batch expire_queued releases device + cost + token holds across both scopes.
    let r_pers = admit_all(
        &personal_scope,
        "personal",
        &p_chat,
        &p_branch,
        &p_msg,
        "b-exp-1",
    )
    .await;
    let r_proj = admit_all(
        &proj_scope,
        "project",
        &pr_chat,
        &pr_branch,
        &pr_msg,
        "b-exp-2",
    )
    .await;
    sqlx::query(
        "UPDATE openmettle.runs
            SET created_at = clock_timestamp() - interval '2 seconds',
                queue_expires_at = clock_timestamp() - interval '1 second'
          WHERE id = ANY($1::text[]::uuid[])",
    )
    .bind(&[r_pers.clone(), r_proj.clone()])
    .execute(&mut owner)
    .await
    .unwrap();
    let mut worker = connect(&db.0, WORKER).await;
    let expired = authz_queue::expire_queued(&mut worker, 10).await.unwrap();
    assert_eq!(expired.len(), 2);
    let total_held: i64 = sqlx::query_scalar(
        "SELECT coalesce(sum(reserved_held), 0)::bigint FROM openmettle.quota_budgets",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(total_held, 0);

    // 2. approvals::expire_waits releases holds for an expired waiting run.
    let r_wait = admit_all(
        &personal_scope,
        "personal",
        &p_chat,
        &p_branch,
        &p_msg,
        "b-wait",
    )
    .await;
    sqlx::query(
        "UPDATE openmettle.runs SET state = 'waiting', wait_reason = NULL WHERE id = $1::uuid",
    )
    .bind(&r_wait)
    .execute(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        approvals::expire_waits(&mut worker, 10).await.unwrap(),
        vec![r_wait]
    );
    let total_held: i64 = sqlx::query_scalar(
        "SELECT coalesce(sum(reserved_held), 0)::bigint FROM openmettle.quota_budgets",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(total_held, 0);

    // 3. leases::settle (Succeeded) and leases::settle_expired release parent holds immediately.
    let r_ok = admit_all(
        &personal_scope,
        "personal",
        &p_chat,
        &p_branch,
        &p_msg,
        "b-ok",
    )
    .await;
    let r_dead = admit_all(
        &proj_scope,
        "project",
        &pr_chat,
        &pr_branch,
        &pr_msg,
        "b-dead",
    )
    .await;
    let lease_cfg = LeaseSettings {
        lease: Duration::from_secs(60),
        execution_timeout: Duration::from_secs(600),
    };
    let claim_cfg = ClaimLimits {
        executing_per_actor: 4,
        executing_per_scope: 8,
    };
    let c1 = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    let c2 = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    let (ok_claim, dead_claim) = if c1.run_id == r_ok {
        (c1, c2)
    } else {
        (c2, c1)
    };
    leases::settle(
        &mut worker,
        &ok_claim.lease(),
        &lease_cfg,
        Settle::Succeeded,
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.runs
            SET lease_expires_at = clock_timestamp() - interval '2 seconds',
                execution_expires_at = clock_timestamp() - interval '1 second'
          WHERE id = $1::uuid",
    )
    .bind(&dead_claim.run_id)
    .execute(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        leases::settle_expired(&mut worker, 10).await.unwrap(),
        vec![r_dead]
    );
    let total_held: i64 = sqlx::query_scalar(
        "SELECT coalesce(sum(reserved_held), 0)::bigint FROM openmettle.quota_budgets",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(total_held, 0);
    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn mid_run_recovered_cost_hold_slice_replayed_backfill_and_single_run_expiry_release() {
    use openmettle_core::{
        authz::{
            approvals::{
                self, DecisionInput, EffectPolicy, EffectSession, HumanDecision, Proposal, Review,
            },
            gateway::{self, Authority, Call, Reservation},
            leases::{self, LeaseSettings, Settle},
            runs::{self as authz_queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
            store::StoreError,
        },
        quotas::{self, RunBudgetReservation},
        runs::{RunInput, WriteTransaction},
        sessions,
    };
    use sqlx::postgres::PgPoolOptions;

    const INSTALL: &str = "00000000-0000-4000-8000-000000000097";

    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let scope = authz_runs::personal_of(&db, &alice).await;
    // Start token-only (no cost limits yet) so Rounds 1 & 2 run before cost metering is enabled.
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 100000)",
        )
        .await
        .unwrap();

    let mut api = connect(&db.0, API).await;
    let mut worker = connect(&db.0, WORKER).await;
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(WORKER));
    let chat = authz_runs::chat(&db, &scope, "personal", &alice).await;
    let (branch, msg) = branch_and_message(&mut api, &scope, &chat).await;
    let limits = AdmissionLimits {
        live_per_actor: 8,
        live_per_scope: 8,
        queued_in_instance: 32,
        queue_timeout: Duration::from_secs(300),
        round_cap: 10,
    };
    let lease_cfg = LeaseSettings {
        lease: Duration::from_secs(60),
        execution_timeout: Duration::from_secs(600),
    };
    let claim_cfg = ClaimLimits {
        executing_per_actor: 4,
        executing_per_scope: 8,
    };

    // Part A (P2 #6 & #7): 4-round run completes Rounds 1 & 2 before cost limits are configured.
    // Then cost limits are enabled with only 250 micros remaining (enough for 2 * 100 = 200, NOT 1000).
    // Round 3 via reserve_with_cost(..., Some(100)) recovers 200 (not 1000!) and allocates 100.
    // Round 4 via reserve(..., None) computes exact slice 100 via quota_run_round_cost_slice (not 200/4 = 50!).
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted {
        run_id: r_multi, ..
    } = authz_queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &scope,
                actor: &alice.user,
                conversation: &chat,
                branch: &branch,
                message: &msg,
                key: "multi-round-mid-cost",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot(100),
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(4),
            now_ms: authz_store::NOW,
            cost_qualified: None,
        },
        &limits,
    )
    .await
    .unwrap()
    else {
        panic!("expected admission");
    };
    assert!(
        quotas::reserve_admitted_run_budget(
            &mut tx,
            &RunBudgetReservation {
                scope_id: &scope,
                scope_kind: "personal",
                actor_user_id: &alice.user,
                actor_approval_id: &alice.approval,
                run_id: &r_multi,
                token_units: 400,
                per_round_cost_micros: None,
                round_limit: 1,
                requires_device_slot: false,
            },
        )
        .await
        .unwrap()
        .is_none()
    );
    tx.commit().await.unwrap();

    let claimed = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .expect("claimed 4-round run");
    assert_eq!(claimed.run_id, r_multi);
    let make_call = |round: i32| Call {
        reservation: Reservation {
            id: &r_multi,
            scope_id: &scope,
            actor: &alice.user,
            approval: &alice.approval,
        },
        installation: INSTALL,
        model: "a",
        units: 100,
        authority: Authority::Lease {
            run: &r_multi,
            round,
            token: &claimed.claim_token,
        },
    };
    let p1 = gateway::reserve(&worker_pool, make_call(1)).await.unwrap();
    let p2 = gateway::reserve(&worker_pool, make_call(2)).await.unwrap();

    // Enable 1,000-micro cost limit and reserve 750 micros via a separate real hold -> only 250
    // micros remain available (enough for 2 remaining rounds * 100 = 200, NOT full 1,000 ceiling).
    owner
        .execute(
            "UPDATE openmettle.quota_defaults
                SET cost_denomination = 'usd_micros'
              WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros'",
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_cost_micros', 1000)",
        )
        .await
        .unwrap();
    let prior_cost_hold: String = sqlx::query_scalar(
        "SELECT openmettle.quota_reserve(
             $1::uuid, $2::uuid, 'usage_cost_micros', 750, 'prior-cost-hold',
             NULL, NULL, NULL, clock_timestamp() + interval '15 minutes'
         )::text",
    )
    .bind(&scope)
    .bind(&alice.user)
    .fetch_one(&mut api)
    .await
    .unwrap();

    // Round 3 supplies Some(100) -> recovers 200-micro parent (2 remaining rounds) and takes 100.
    let p3 = gateway::reserve_with_cost(&worker_pool, make_call(3), Some(100))
        .await
        .unwrap();
    let (parent_res, parent_held): (i64, i64) = sqlx::query_as(
        "SELECT reserved_units, held_units FROM openmettle.quota_reservations
          WHERE run_id = $1::uuid AND gateway_request_id IS NULL
            AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&r_multi)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!((parent_res, parent_held), (200, 100));
    let r3_cost: i64 = sqlx::query_scalar(
        "SELECT reserved_units FROM openmettle.quota_reservations
          WHERE gateway_request_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&p3.id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(r3_cost, 100);

    // Direct worker EXECUTE check on quota_run_round_cost_slice before Round 4: 100 held / 1 left = 100.
    let slice: Option<i64> = sqlx::query_scalar(
        "SELECT openmettle.quota_run_round_cost_slice($1::uuid, $2::uuid, NULL)",
    )
    .bind(&scope)
    .bind(&r_multi)
    .fetch_one(&mut worker)
    .await
    .unwrap();
    assert_eq!(slice, Some(100));

    // Round 4 supplies None -> must derive 100 micros (NOT 200 / 4 = 50!).
    let p4 = gateway::reserve(&worker_pool, make_call(4)).await.unwrap();
    let r4_cost: i64 = sqlx::query_scalar(
        "SELECT reserved_units FROM openmettle.quota_reservations
          WHERE gateway_request_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&p4.id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(r4_cost, 100);
    let parent_held_after_r4: i64 = sqlx::query_scalar(
        "SELECT held_units FROM openmettle.quota_reservations
          WHERE run_id = $1::uuid AND gateway_request_id IS NULL
            AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&r_multi)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(parent_held_after_r4, 0);

    // Clean up Rounds 1..4, settle r_multi, and release the 750-micro helper hold so budgets return to 0.
    for p in [p1, p2, p3, p4] {
        assert!(p.release(&worker_pool).await.unwrap());
    }
    leases::settle(&mut worker, &claimed.lease(), &lease_cfg, Settle::Succeeded)
        .await
        .unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT openmettle.quota_release_unsent($1::uuid)")
            .bind(&prior_cost_hold)
            .fetch_one(&mut api)
            .await
            .unwrap()
    );

    // Part B (P2 #8 & #9): backfill_replayed_run_budget skips terminal/non-queued runs and uses
    // the locked run's original actor_approval_id when a user replays from a second linked approval.
    let approval_2: String = sqlx::query_scalar(
        "WITH i AS (INSERT INTO openmettle.user_identities (user_id, issuer, subject)
                    VALUES ($1::uuid, 'https://authz-store.example.test', 'second-subject') RETURNING id)
         INSERT INTO openmettle.local_identity_approvals
             (provider_id, identity_id, active, expires_ms, changed_by, change_reason)
         SELECT $2::uuid, i.id, true, $3, 'fixture-owner', 'second synthetic approval' FROM i
         RETURNING id::text",
    )
    .bind(&alice.user)
    .bind(authz_store::PROVIDER)
    .bind(authz_store::FUTURE)
    .fetch_one(&mut owner)
    .await
    .unwrap();

    let admit_bare = async |c: &mut PgConnection, key: &str| {
        let mut tx = WriteTransaction::begin(c).await.unwrap();
        let Admission::Admitted { run_id, .. } = authz_queue::admit_run(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope: &scope,
                    actor: &alice.user,
                    conversation: &chat,
                    branch: &branch,
                    message: &msg,
                    key,
                    format: "openmettle.conversation",
                    version: 1,
                    input: b"{}",
                    config: b"{}",
                },
                actor_approval_id: &alice.approval,
                capabilities: &[],
                requested_rounds: Some(1),
                now_ms: authz_store::NOW,
                cost_qualified: Some(true),
            },
            &limits,
        )
        .await
        .unwrap() else {
            panic!("expected bare admission");
        };
        tx.commit().await.unwrap();
        run_id
    };

    // B1: Cancelled run -> backfill skips cleanly with zero gateway_reservations or quota holds.
    let r_cancelled = admit_bare(&mut api, "replay-cancelled").await;
    let actor = authz_store::principal(&db, &alice).await;
    authz_queue::cancel_run(&mut api, &actor, &scope, &r_cancelled)
        .await
        .unwrap();
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    assert_eq!(
        quotas::backfill_replayed_run_budget(
            &mut tx,
            &RunBudgetReservation {
                scope_id: &scope,
                scope_kind: "personal",
                actor_user_id: &alice.user,
                actor_approval_id: &approval_2,
                run_id: &r_cancelled,
                token_units: 200,
                per_round_cost_micros: Some(100),
                round_limit: 1,
                requires_device_slot: false,
            },
        )
        .await
        .unwrap(),
        (false, None)
    );
    tx.commit().await.unwrap();
    let ghost_rows: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM openmettle.gateway_reservations WHERE run_id = $1::uuid),
                (SELECT count(*) FROM openmettle.quota_reservations WHERE run_id = $1::uuid)",
    )
    .bind(&r_cancelled)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(ghost_rows, (0, 0));

    // B2: Live queued run replayed under approval_2 -> succeeds using alice.approval (no 23503!).
    let r_replayed = admit_bare(&mut api, "replay-second-approval").await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    assert_eq!(
        quotas::backfill_replayed_run_budget(
            &mut tx,
            &RunBudgetReservation {
                scope_id: &scope,
                scope_kind: "personal",
                actor_user_id: &alice.user,
                actor_approval_id: &approval_2,
                run_id: &r_replayed,
                token_units: 200,
                per_round_cost_micros: Some(100),
                round_limit: 1,
                requires_device_slot: false,
            },
        )
        .await
        .unwrap(),
        (true, None)
    );
    tx.commit().await.unwrap();
    let stored_gw_approval: String = sqlx::query_scalar(
        "SELECT approval_id::text FROM openmettle.gateway_reservations WHERE run_id = $1::uuid",
    )
    .bind(&r_replayed)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(stored_gw_approval, alice.approval);
    authz_queue::cancel_run(&mut api, &actor, &scope, &r_replayed)
        .await
        .unwrap();

    // Part C (P2 #10): single-run approvals::decide failing an expired wait releases parent holds.
    struct NoopPolicy;
    impl EffectPolicy for NoopPolicy {
        fn review(&self, _: &str, _: &str, _: &Proposal) -> Result<Option<Review>, StoreError> {
            Ok(None)
        }
    }
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted { run_id: r_wait, .. } = authz_queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &scope,
                actor: &alice.user,
                conversation: &chat,
                branch: &branch,
                message: &msg,
                key: "single-run-expired-wait",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: b"{}",
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(1),
            now_ms: authz_store::NOW,
            cost_qualified: Some(true),
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("expected wait admission");
    };
    assert!(
        quotas::reserve_admitted_run_budget(
            &mut tx,
            &RunBudgetReservation {
                scope_id: &scope,
                scope_kind: "personal",
                actor_user_id: &alice.user,
                actor_approval_id: &alice.approval,
                run_id: &r_wait,
                token_units: 300,
                per_round_cost_micros: Some(150),
                round_limit: 1,
                requires_device_slot: false,
            },
        )
        .await
        .unwrap()
        .is_none()
    );
    tx.commit().await.unwrap();

    let wait_id: String = sqlx::query_scalar(
        "INSERT INTO openmettle.run_approvals
             (scope_id, run_id, actor_user_id, logical_key, tool_id, tool_version,
              canonical_arguments, destination, authority_evidence, binding_digest,
              approval_expires_at, resume_execution_expires_at)
         SELECT scope_id, id, actor_user_id, 'exp-wait', 'lookup', '1', '{}', 'fixture', 'fixture',
                sha256('fixture'), clock_timestamp() - interval '1 second',
                clock_timestamp() + interval '5 minutes'
           FROM openmettle.runs WHERE id = $1::uuid
         RETURNING id::text",
    )
    .bind(&r_wait)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.runs
            SET state = 'waiting', wait_reason = 'approval', approval_wait_id = $1::uuid
          WHERE id = $2::uuid",
    )
    .bind(&wait_id)
    .bind(&r_wait)
    .execute(&mut owner)
    .await
    .unwrap();

    let token = authz_runs::seeded_session(&db, &alice, 1, None).await;
    let sess_policy =
        sessions::Policy::new(Duration::from_secs(60), 10, Duration::from_secs(3)).unwrap();
    let eff_sess = EffectSession::validate(&mut api, &token, &sess_policy, None)
        .await
        .unwrap();
    let digest = "0".repeat(64);
    let err = approvals::decide(
        &mut api,
        &eff_sess,
        &DecisionInput {
            scope: &scope,
            run: &r_wait,
            approval: &wait_id,
            decision: HumanDecision::Approve,
            binding_digest: &digest,
            idempotency_key: "late-approve",
        },
        &NoopPolicy,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, StoreError::Conflict(_)));

    let wait_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
            .bind(&r_wait)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(wait_state, "failed");
    let total_held: i64 = sqlx::query_scalar(
        "SELECT coalesce(sum(reserved_held), 0)::bigint FROM openmettle.quota_budgets",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(total_held, 0);
    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn atomic_turn_handoff_rollback_unmetered_guard_personal_cost_expiry_and_legacy_gw_reuse() {
    use openmettle_core::{
        authz::{
            gateway::{self, TurnRound},
            leases::{self, LeaseSettings, Settle},
            runs::{self as authz_queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
        },
        provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
        quotas::{self, RunBudgetReservation},
        runs::{RunInput, WriteTransaction},
    };
    use sqlx::postgres::PgPoolOptions;

    const INSTALL: &str = "00000000-0000-4000-8000-0000000000a1";
    const PRINCIPAL: &str = "00000000-0000-4000-8000-0000000000a2";
    const BUDGET: &str = "00000000-0000-4000-8000-0000000000a3";
    const GRANT_1: &str = "00000000-0000-4000-8000-00000000d101";
    const GRANT_2: &str = "00000000-0000-4000-8000-00000000d102";
    const KEY_BYTES: [u8; 32] = [91; 32];

    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let scope = authz_runs::personal_of(&db, &alice).await;
    owner
        .execute(
            "UPDATE openmettle.quota_defaults
                SET cost_denomination = 'usd_micros'
              WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros'",
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 100000),
                    ('personal', 'usage_cost_micros', 10000),
                    ('personal', 'device_reservations', 2)",
        )
        .await
        .unwrap();

    // Provision gateway binding, sealed key generation, and active policy for model `a`.
    let g_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(pg::GATEWAY));
    let binding: String = sqlx::query_scalar(
        "INSERT INTO openmettle.gateway_bindings (installation, user_id, principal, budget)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid) RETURNING id::text",
    )
    .bind(INSTALL)
    .bind(&alice.user)
    .bind(PRINCIPAL)
    .bind(BUDGET)
    .fetch_one(&g_pool)
    .await
    .unwrap();
    let report_source: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    let (finger, env) = GatewaySealer::new(
        GatewayKeys::new(&[("atomic-k1".into(), KEY_BYTES)]).unwrap(),
        g_pool.clone(),
    )
    .seal(
        &Context {
            installation: INSTALL,
            user_id: &alice.user,
            binding_id: &binding,
            principal: PRINCIPAL,
            generation: 1,
        },
        &Bearer::new(b"atomic-handoff-bearer").unwrap(),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_generations
             (binding_id, generation, remote_key, expires_at, key_id, key_fingerprint, nonce, ciphertext)
         VALUES ($1::uuid, 1, gen_random_uuid(), clock_timestamp() + interval '1 hour', $2, $3, $4, $5)",
    )
    .bind(&binding)
    .bind(&env.key_id)
    .bind(finger.as_slice())
    .bind(env.nonce.as_slice())
    .bind(env.ciphertext)
    .execute(&g_pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_policy
             (binding_id, revision, scope_id, approval_id, model, report_source,
              provider_generation, approval_generation, user_generation, capabilities)
         VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'a', $4::uuid, 0, 0, 0, '{}'::jsonb)",
    )
    .bind(&binding)
    .bind(&scope)
    .bind(&alice.approval)
    .bind(&report_source)
    .execute(&g_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.gateway_bindings
            SET active_generation = 1, observed_revision = 1, state = 'ready'
          WHERE id = $1::uuid",
    )
    .bind(&binding)
    .execute(&g_pool)
    .await
    .unwrap();

    let mut api = connect(&db.0, API).await;
    let mut worker = connect(&db.0, WORKER).await;
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(WORKER));
    let chat = authz_runs::chat(&db, &scope, "personal", &alice).await;
    let (branch, msg) = branch_and_message(&mut api, &scope, &chat).await;
    let limits = AdmissionLimits {
        live_per_actor: 8,
        live_per_scope: 8,
        queued_in_instance: 32,
        queue_timeout: Duration::from_secs(300),
        round_cap: 10,
    };
    let lease_cfg = LeaseSettings {
        lease: Duration::from_secs(60),
        execution_timeout: Duration::from_secs(600),
    };
    let claim_cfg = ClaimLimits {
        executing_per_actor: 4,
        executing_per_scope: 8,
    };

    let admit_dev = async |c: &mut PgConnection, key: &str| {
        let mut tx = WriteTransaction::begin(c).await.unwrap();
        let Admission::Admitted { run_id, .. } = authz_queue::admit_run(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope: &scope,
                    actor: &alice.user,
                    conversation: &chat,
                    branch: &branch,
                    message: &msg,
                    key,
                    format: "openmettle.conversation",
                    version: 1,
                    input: b"{}",
                    config: &snapshot_priced(
                        "a",
                        100,
                        Some(openmettle_core::model_config::CostBound {
                            fixed_micros: 100,
                            micros_per_token: 0,
                        }),
                    ),
                },
                actor_approval_id: &alice.approval,
                capabilities: &[],
                requested_rounds: Some(2),
                now_ms: authz_store::NOW,
                cost_qualified: Some(true),
            },
            &limits,
        )
        .await
        .unwrap() else {
            panic!("expected device run admission");
        };
        assert!(
            quotas::reserve_admitted_run_budget(
                &mut tx,
                &RunBudgetReservation {
                    scope_id: &scope,
                    scope_kind: "personal",
                    actor_user_id: &alice.user,
                    actor_approval_id: &alice.approval,
                    run_id: &run_id,
                    token_units: 200,
                    per_round_cost_micros: Some(100),
                    round_limit: 2,
                    requires_device_slot: true,
                },
            )
            .await
            .unwrap()
            .is_none()
        );
        tx.commit().await.unwrap();
        run_id
    };

    // Part A (P1 #1): Atomic TurnPending::handoff rollback on duplicate device_grant_id (23505)
    // and pre-handoff cancel — gateway_requests never strands in 'handed_off' and pending.release()
    // immediately unwinds the unsent round slices back to the parent holds.
    let r1 = admit_dev(&mut api, "dev-atomic-1").await;
    let r2 = admit_dev(&mut api, "dev-atomic-2").await;
    let c1 = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    let c2 = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    let (claim1, claim2) = if c1.run_id == r1 { (c1, c2) } else { (c2, c1) };

    let p1 = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &scope,
            actor: &alice.user,
            approval: &alice.approval,
            run_id: &r1,
            round: 1,
            claim_token: &claim1.claim_token,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(100),
            cost_bound: Some(openmettle_core::model_config::CostBound {
                fixed_micros: 100,
                micros_per_token: 0,
            }),
            requires_device_slot: true,
        },
    )
    .await
    .unwrap();
    let fx = TurnHandoffFixture::chat(INSTALL, "a", 100, Some(100), true);
    let _disp1 = p1
        .handoff(&worker_pool, Some(GRANT_1), &fx.billable(), fx.prepare())
        .await
        .unwrap();

    // Part B1 (P1 #2): quota_authorize_unmetered_turn_round refuses with OMQ04 when metering_enforced = true.
    assert_eq!(
        sqlstate(
            sqlx::query(
                "SELECT openmettle.quota_authorize_unmetered_turn_round($1::uuid, $2::uuid, $3::uuid)",
            )
            .bind(&scope)
            .bind(&r2)
            .bind(&claim2.claim_token)
            .execute(&mut worker)
            .await
        ),
        "OMQ04"
    );

    // Run 2 reserves Round 1, then attempts handoff with colliding GRANT_1 (23505).
    let p2 = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &scope,
            actor: &alice.user,
            approval: &alice.approval,
            run_id: &r2,
            round: 1,
            claim_token: &claim2.claim_token,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(100),
            cost_bound: Some(openmettle_core::model_config::CostBound {
                fixed_micros: 100,
                micros_per_token: 0,
            }),
            requires_device_slot: true,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        p2.handoff(&worker_pool, Some(GRANT_1), &fx.billable(), fx.prepare(),)
            .await,
        Err(gateway::Error::Refused)
    ));
    let req2_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.gateway_requests WHERE id = $1::uuid")
            .bind(&p2.id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(req2_state, "reserved");
    assert!(p2.release(&worker_pool).await.unwrap());
    let req2_released: String =
        sqlx::query_scalar("SELECT state FROM openmettle.gateway_requests WHERE id = $1::uuid")
            .bind(&p2.id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(req2_released, "released");
    let r2_parents: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT resource_kind, reserved_units, held_units
           FROM openmettle.quota_reservations
          WHERE run_id = $1::uuid AND gateway_request_id IS NULL
          ORDER BY resource_kind",
    )
    .bind(&r2)
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        r2_parents,
        vec![
            ("device_reservations".into(), 1, 1),
            ("usage_cost_micros".into(), 200, 200),
            ("usage_tokens".into(), 200, 200),
        ]
    );

    // Pre-handoff cancel on Run 2 also rolls back gateway_requests cleanly and unwinds via release().
    let p2_cancel = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &scope,
            actor: &alice.user,
            approval: &alice.approval,
            run_id: &r2,
            round: 1,
            claim_token: &claim2.claim_token,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(100),
            cost_bound: Some(openmettle_core::model_config::CostBound {
                fixed_micros: 100,
                micros_per_token: 0,
            }),
            requires_device_slot: true,
        },
    )
    .await
    .unwrap();
    let actor = authz_store::principal(&db, &alice).await;
    authz_queue::cancel_run(&mut api, &actor, &scope, &r2)
        .await
        .unwrap();
    assert!(matches!(
        p2_cancel
            .handoff(&worker_pool, Some(GRANT_2), &fx.billable(), fx.prepare(),)
            .await,
        Err(gateway::Error::Refused)
    ));
    let req2c_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.gateway_requests WHERE id = $1::uuid")
            .bind(&p2_cancel.id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(req2c_state, "reserved");
    assert!(p2_cancel.release(&worker_pool).await.unwrap());
    leases::settle(&mut worker, &claim2.lease(), &lease_cfg, Settle::Stopped)
        .await
        .unwrap();

    // Part C (P2 #3): Expiring personal usage_cost_micros override fails closed on Round 2 even
    // while an instance usage_cost_micros default remains configured.
    owner
        .execute(
            "DELETE FROM openmettle.quota_defaults
              WHERE scope_kind = 'personal' AND resource_kind = 'usage_cost_micros'",
        )
        .await
        .unwrap();
    owner
        .execute(
            "UPDATE openmettle.quota_defaults
                SET hard_limit = 5000
              WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros'",
        )
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.quota_overrides
             (scope_id, scope_kind, resource_kind, hard_limit, expires_at, reason, updated_by_user_id)
         VALUES ($1::uuid, 'personal', 'usage_cost_micros', 1000,
                 clock_timestamp() + interval '1 hour', 'temp personal cost', $2::uuid)",
    )
    .bind(&scope)
    .bind(&alice.user)
    .execute(&mut owner)
    .await
    .unwrap();

    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted {
        run_id: r_exp_cost, ..
    } = authz_queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &scope,
                actor: &alice.user,
                conversation: &chat,
                branch: &branch,
                message: &msg,
                key: "personal-cost-override-expiry",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot(100),
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(2),
            now_ms: authz_store::NOW,
            cost_qualified: Some(true),
        },
        &limits,
    )
    .await
    .unwrap()
    else {
        panic!("expected cost override admission");
    };
    assert!(
        quotas::reserve_admitted_run_budget(
            &mut tx,
            &RunBudgetReservation {
                scope_id: &scope,
                scope_kind: "personal",
                actor_user_id: &alice.user,
                actor_approval_id: &alice.approval,
                run_id: &r_exp_cost,
                token_units: 200,
                per_round_cost_micros: Some(200),
                round_limit: 2,
                requires_device_slot: false,
            },
        )
        .await
        .unwrap()
        .is_none()
    );
    tx.commit().await.unwrap();
    let claim_exp = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim_exp.run_id, r_exp_cost);
    let p_exp1 = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &scope,
            actor: &alice.user,
            approval: &alice.approval,
            run_id: &r_exp_cost,
            round: 1,
            claim_token: &claim_exp.claim_token,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(200),
            cost_bound: Some(openmettle_core::model_config::CostBound {
                fixed_micros: 200,
                micros_per_token: 0,
            }),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    assert!(p_exp1.release(&worker_pool).await.unwrap());

    // Expire the personal override while instance hard_limit = 5000 stays active.
    sqlx::query(
        "UPDATE openmettle.quota_overrides
            SET expires_at = clock_timestamp() - interval '1 second'
          WHERE scope_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&scope)
    .execute(&mut owner)
    .await
    .unwrap();
    let sql_ceiling: Option<i64> =
        sqlx::query_scalar("SELECT openmettle.quota_cost_ceiling($1::uuid, $2::uuid)")
            .bind(&scope)
            .bind(&alice.user)
            .fetch_one(&mut worker)
            .await
            .unwrap();
    assert_eq!(sql_ceiling, None);
    assert!(matches!(
        gateway::reserve_turn_round(
            &worker_pool,
            TurnRound {
                scope_id: &scope,
                actor: &alice.user,
                approval: &alice.approval,
                run_id: &r_exp_cost,
                round: 2,
                claim_token: &claim_exp.claim_token,
                installation: INSTALL,
                model: "a",
                round_tokens: 100,
                round_cost: Some(200),
                cost_bound: Some(openmettle_core::model_config::CostBound {
                    fixed_micros: 200,
                    micros_per_token: 0,
                }),
                requires_device_slot: false,
            },
        )
        .await,
        Err(gateway::Error::Refused)
    ));
    leases::settle(
        &mut worker,
        &claim_exp.lease(),
        &lease_cfg,
        Settle::Failed(leases::FailReason::StepFailed),
    )
    .await
    .unwrap();

    // Restore personal usage_cost_micros default for Part D.
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_cost_micros', 10000)",
        )
        .await
        .unwrap();

    // Part D (P2 #4 & #6): Pre-existing legacy gateway_reservations row with id <> run_id reuses
    // cleanly on replay backfill without 23505, preserving existing units for usage_tokens and
    // working with quota_run_round_cost_slice's reservation_id lookup.
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted {
        run_id: r_legacy_gw,
        ..
    } = authz_queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &scope,
                actor: &alice.user,
                conversation: &chat,
                branch: &branch,
                message: &msg,
                key: "legacy-distinct-gw-id",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot(250),
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(2),
            now_ms: authz_store::NOW,
            cost_qualified: Some(true),
        },
        &limits,
    )
    .await
    .unwrap()
    else {
        panic!("expected legacy gw admission");
    };
    let distinct_gw_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(tx.connection().unwrap())
        .await
        .unwrap();
    assert_ne!(distinct_gw_id, r_legacy_gw);
    sqlx::query(
        "INSERT INTO openmettle.gateway_reservations
             (id, scope_id, actor_user_id, approval_id, run_id, units)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, 555)",
    )
    .bind(&distinct_gw_id)
    .bind(&scope)
    .bind(&alice.user)
    .bind(&alice.approval)
    .bind(&r_legacy_gw)
    .execute(tx.connection().unwrap())
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    assert_eq!(
        quotas::backfill_replayed_run_budget(
            &mut tx,
            &RunBudgetReservation {
                scope_id: &scope,
                scope_kind: "personal",
                actor_user_id: &alice.user,
                actor_approval_id: &alice.approval,
                run_id: &r_legacy_gw,
                token_units: 999,
                per_round_cost_micros: Some(150),
                round_limit: 2,
                requires_device_slot: false,
            },
        )
        .await
        .unwrap(),
        (true, None)
    );
    tx.commit().await.unwrap();

    let stored_gw: (String, i64) = sqlx::query_as(
        "SELECT id::text, units FROM openmettle.gateway_reservations WHERE run_id = $1::uuid",
    )
    .bind(&r_legacy_gw)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(stored_gw, (distinct_gw_id, 555));
    let tok_units: i64 = sqlx::query_scalar(
        "SELECT reserved_units FROM openmettle.quota_reservations
          WHERE run_id = $1::uuid AND gateway_request_id IS NULL
            AND resource_kind = 'usage_tokens'",
    )
    .bind(&r_legacy_gw)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(tok_units, 555);
    let slice_legacy: Option<i64> = sqlx::query_scalar(
        "SELECT openmettle.quota_run_round_cost_slice($1::uuid, $2::uuid, NULL)",
    )
    .bind(&scope)
    .bind(&r_legacy_gw)
    .fetch_one(&mut worker)
    .await
    .unwrap();
    assert_eq!(slice_legacy, Some(150));

    // Part B2 (P1 #2): On an upgraded pre-activation DB (metering_enforced = false),
    // quota_authorize_unmetered_turn_round allows a running run with no holds and blocks once
    // metering_enforced flips to true.
    let db_up = TestDb::new().await;
    let settings_up = db_up.settings(Duration::from_secs(10));
    migrate::apply(&settings_up, &MIGRATIONS[..23])
        .await
        .unwrap();
    let mut owner_up = connect(&db_up.0, OWNER).await;
    authz_store::providers(&mut owner_up).await;
    let bob = authz_store::account(
        &mut owner_up,
        authz_store::PROVIDER,
        true,
        authz_store::FUTURE,
    )
    .await;
    let bob_scope = authz_runs::personal_of(&db_up, &bob).await;
    migrate::apply(&settings_up, MIGRATIONS).await.unwrap();
    let mut api_up = connect(&db_up.0, API).await;
    let mut worker_up = connect(&db_up.0, WORKER).await;
    let bob_chat = authz_runs::chat(&db_up, &bob_scope, "personal", &bob).await;
    let (bob_branch, bob_msg) = branch_and_message(&mut api_up, &bob_scope, &bob_chat).await;
    let mut tx_up = WriteTransaction::begin(&mut api_up).await.unwrap();
    let Admission::Admitted { run_id: r_up, .. } = authz_queue::admit_run(
        &mut tx_up,
        &RunAdmission {
            input: RunInput {
                scope: &bob_scope,
                actor: &bob.user,
                conversation: &bob_chat,
                branch: &bob_branch,
                message: &bob_msg,
                key: "unmetered-pre-activation",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: b"{}",
            },
            actor_approval_id: &bob.approval,
            capabilities: &[],
            requested_rounds: Some(1),
            now_ms: authz_store::NOW,
            cost_qualified: None,
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("expected pre-activation admission");
    };
    tx_up.commit().await.unwrap();
    let claim_up = authz_queue::claim_next(&mut worker_up, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim_up.run_id, r_up);
    sqlx::query(
        "SELECT openmettle.quota_authorize_unmetered_turn_round($1::uuid, $2::uuid, $3::uuid)",
    )
    .bind(&bob_scope)
    .bind(&r_up)
    .bind(&claim_up.claim_token)
    .execute(&mut worker_up)
    .await
    .unwrap();
    owner_up
        .execute(
            "UPDATE openmettle.quota_enforcement
                SET metering_enforced = true, metering_enforced_at = clock_timestamp()
              WHERE id AND NOT metering_enforced",
        )
        .await
        .unwrap();
    assert_eq!(
        sqlstate(
            sqlx::query(
                "SELECT openmettle.quota_authorize_unmetered_turn_round($1::uuid, $2::uuid, $3::uuid)",
            )
            .bind(&bob_scope)
            .bind(&r_up)
            .bind(&claim_up.claim_token)
            .execute(&mut worker_up)
            .await
        ),
        "OMQ04"
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn pre_activation_charged_parents_pre26_replay_savepoint_and_n1_legacy_holds() {
    use openmettle_core::{
        authz::{
            gateway::{self, Authority, Call, Reservation, TurnRound, settlement},
            leases::{self, LeaseSettings, Settle},
            runs::{self as authz_queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
        },
        provider_http::gateway::UsageReport,
        provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
        quotas::{self, RunBudgetReservation},
        runs::{RunInput, WriteTransaction},
    };
    use sqlx::postgres::PgPoolOptions;

    const INSTALL: &str = "00000000-0000-4000-8000-0000000000b1";
    const PRINCIPAL: &str = "00000000-0000-4000-8000-0000000000b2";
    const BUDGET: &str = "00000000-0000-4000-8000-0000000000b3";
    const KEY_BYTES: [u8; 32] = [95; 32];

    let limits = AdmissionLimits {
        live_per_actor: 8,
        live_per_scope: 8,
        queued_in_instance: 32,
        queue_timeout: Duration::from_secs(300),
        round_cap: 10,
    };
    let lease_cfg = LeaseSettings {
        lease: Duration::from_secs(60),
        execution_timeout: Duration::from_secs(600),
    };
    let claim_cfg = ClaimLimits {
        executing_per_actor: 4,
        executing_per_scope: 8,
    };

    // Part A (P1 #1 & P2 #4): Upgraded DB with metering_enforced = false.
    // 1) A run with already-charged token + cost parent holds (via gateway::hold_with_cost)
    //    dispatched via reserve_turn_round + TurnPending::handoff allocates child holds, settles
    //    provider usage against them, and releases only the unused remainder on terminal settle.
    // 2) A legacy run without parent holds dispatched via gateway::reserve (and draining N-1
    //    3-arg quota_ensure_legacy_run_holds) also allocates child holds and settles cleanly.
    // 3) Standalone Authority::Session gateway::reserve still creates quota holds when !enforced.
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let scope = authz_runs::personal_of(&db, &alice).await;
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    let enforced: bool =
        sqlx::query_scalar("SELECT metering_enforced FROM openmettle.quota_enforcement WHERE id")
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert!(!enforced);
    owner
        .execute(
            "UPDATE openmettle.quota_defaults
                SET cost_denomination = 'usd_micros'
              WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros'",
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 100000),
                    ('personal', 'usage_cost_micros', 10000)",
        )
        .await
        .unwrap();

    // Provision gateway binding, generation, and policy.
    let g_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(pg::GATEWAY));
    let binding: String = sqlx::query_scalar(
        "INSERT INTO openmettle.gateway_bindings (installation, user_id, principal, budget)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid) RETURNING id::text",
    )
    .bind(INSTALL)
    .bind(&alice.user)
    .bind(PRINCIPAL)
    .bind(BUDGET)
    .fetch_one(&g_pool)
    .await
    .unwrap();
    let report_source: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    let keys = GatewayKeys::new(&[("preact-k1".into(), KEY_BYTES)]).unwrap();
    let (finger, env) = GatewaySealer::new(
        GatewayKeys::new(&[("preact-k1".into(), KEY_BYTES)]).unwrap(),
        g_pool.clone(),
    )
    .seal(
        &Context {
            installation: INSTALL,
            user_id: &alice.user,
            binding_id: &binding,
            principal: PRINCIPAL,
            generation: 1,
        },
        &Bearer::new(b"preact-bearer").unwrap(),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_generations
             (binding_id, generation, remote_key, expires_at, key_id, key_fingerprint, nonce, ciphertext)
         VALUES ($1::uuid, 1, gen_random_uuid(), clock_timestamp() + interval '1 hour', $2, $3, $4, $5)",
    )
    .bind(&binding)
    .bind(&env.key_id)
    .bind(finger.as_slice())
    .bind(env.nonce.as_slice())
    .bind(env.ciphertext)
    .execute(&g_pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_policy
             (binding_id, revision, scope_id, approval_id, model, report_source,
              provider_generation, approval_generation, user_generation, capabilities)
         VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'a', $4::uuid, 0, 0, 0, '{}'::jsonb)",
    )
    .bind(&binding)
    .bind(&scope)
    .bind(&alice.approval)
    .bind(&report_source)
    .execute(&g_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.gateway_bindings
            SET active_generation = 1, observed_revision = 1, state = 'ready'
          WHERE id = $1::uuid",
    )
    .bind(&binding)
    .execute(&g_pool)
    .await
    .unwrap();

    let mut api = connect(&db.0, API).await;
    let mut worker = connect(&db.0, WORKER).await;
    let api_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(API));
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(WORKER));
    let chat = authz_runs::chat(&db, &scope, "personal", &alice).await;
    let (branch, msg) = branch_and_message(&mut api, &scope, &chat).await;

    // A1: Draining N-1 3-arg quota_ensure_legacy_run_holds + gateway::reserve work when !enforced
    // (run first while active_used == 0 since 3-arg reserves the full personal cost ceiling).
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted { run_id: r_n1, .. } = authz_queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &scope,
                actor: &alice.user,
                conversation: &chat,
                branch: &branch,
                message: &msg,
                key: "preact-n1-legacy",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot(150),
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(1),
            now_ms: authz_store::NOW,
            cost_qualified: Some(true),
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("expected n1 admission");
    };
    sqlx::query(
        "INSERT INTO openmettle.gateway_reservations
             (id, scope_id, actor_user_id, approval_id, run_id, units)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $1::uuid, 150)",
    )
    .bind(&r_n1)
    .bind(&scope)
    .bind(&alice.user)
    .bind(&alice.approval)
    .execute(tx.connection().unwrap())
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let claim_n1 = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim_n1.run_id, r_n1);
    sqlx::query("SELECT openmettle.quota_ensure_legacy_run_holds($1::uuid, $2::uuid, $3::uuid)")
        .bind(&scope)
        .bind(&r_n1)
        .bind(&claim_n1.claim_token)
        .execute(&mut worker)
        .await
        .unwrap();
    let p_n1 = gateway::reserve_with_cost(
        &worker_pool,
        Call {
            reservation: Reservation {
                id: &r_n1,
                scope_id: &scope,
                actor: &alice.user,
                approval: &alice.approval,
            },
            installation: INSTALL,
            model: "a",
            units: 150,
            authority: Authority::Lease {
                run: &r_n1,
                round: 1,
                token: &claim_n1.claim_token,
            },
        },
        Some(200),
    )
    .await
    .unwrap();
    assert!(p_n1.release(&worker_pool).await.unwrap());
    leases::settle(
        &mut worker,
        &claim_n1.lease(),
        &lease_cfg,
        Settle::Succeeded,
    )
    .await
    .unwrap();

    // A2: Run with pre-existing charged token + cost parent holds via gateway::hold_with_cost
    // dispatched via reserve_turn_round + TurnPending::handoff while !enforced allocates child
    // holds, settles provider usage against them, and releases only the unused remainder.
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted { run_id: r_held, .. } = authz_queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &scope,
                actor: &alice.user,
                conversation: &chat,
                branch: &branch,
                message: &msg,
                key: "preact-charged-parents",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot_priced(
                    "a",
                    200,
                    Some(openmettle_core::model_config::CostBound {
                        fixed_micros: 100,
                        micros_per_token: 1,
                    }),
                ),
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(2),
            now_ms: authz_store::NOW,
            cost_qualified: Some(true),
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("expected admission");
    };
    gateway::hold_with_cost(
        &mut tx,
        &Reservation {
            id: &r_held,
            scope_id: &scope,
            actor: &alice.user,
            approval: &alice.approval,
        },
        Some(&r_held),
        400,
        Some(600),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let claim_held = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim_held.run_id, r_held);
    let pending_held = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &scope,
            actor: &alice.user,
            approval: &alice.approval,
            run_id: &r_held,
            round: 1,
            claim_token: &claim_held.claim_token,
            installation: INSTALL,
            model: "a",
            round_tokens: 200,
            round_cost: Some(300),
            cost_bound: Some(openmettle_core::model_config::CostBound {
                fixed_micros: 100,
                micros_per_token: 1,
            }),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let fx = TurnHandoffFixture::chat_priced(
        INSTALL,
        "a",
        200,
        openmettle_core::model_config::CostBound {
            fixed_micros: 100,
            micros_per_token: 1,
        },
        false,
    );
    let _disp = pending_held
        .handoff(&worker_pool, None, &fx.billable(), fx.prepare())
        .await
        .unwrap();
    let child_rows: Vec<(String, i64, String)> = sqlx::query_as(
        "SELECT resource_kind, reserved_units, state
           FROM openmettle.quota_reservations
          WHERE gateway_request_id = $1::uuid
          ORDER BY resource_kind",
    )
    .bind(&pending_held.id)
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        child_rows,
        vec![
            ("usage_cost_micros".into(), 300, "handoff_committed".into()),
            ("usage_tokens".into(), 200, "handoff_committed".into()),
        ]
    );
    let report_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    dispatched(&mut owner, &pending_held.id).await;
    assert_eq!(
        settlement::ingest(
            &g_pool,
            &UsageReport {
                request: pending_held.id.clone(),
                installation: INSTALL.into(),
                principal: alice.user.clone(),
                scope: scope.clone(),
                source: INSTALL.into(),
                report_id,
                revision: 1,
                r#final: true,
                prompt_tokens: Some(90),
                completion_tokens: Some(30),
                reasoning_tokens: None,
                reasoning_included: None,
                cost: None,
                unit: None,
            },
        )
        .await
        .unwrap(),
        settlement::Outcome::Applied
    );
    leases::settle(
        &mut worker,
        &claim_held.lease(),
        &lease_cfg,
        Settle::Succeeded,
    )
    .await
    .unwrap();
    let settled_budgets: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT resource_kind, active_used::bigint, reserved_held::bigint
           FROM openmettle.quota_budgets
          WHERE scope_id = $1::uuid
          ORDER BY resource_kind",
    )
    .bind(&scope)
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        settled_budgets,
        vec![
            ("usage_cost_micros".into(), 220, 0),
            ("usage_tokens".into(), 120, 0),
        ]
    );

    // A3: Standalone Authority::Session gateway::reserve still creates quota holds when !enforced.
    let sess_token = authz_runs::seeded_session(&db, &alice, 1, None).await;
    let sess_res_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    let p_sess = gateway::reserve_with_cost(
        &api_pool,
        Call {
            reservation: Reservation {
                id: &sess_res_id,
                scope_id: &scope,
                actor: &alice.user,
                approval: &alice.approval,
            },
            installation: INSTALL,
            model: "a",
            units: 80,
            authority: Authority::Session {
                credential: &sess_token,
                native_audience: None,
            },
        },
        Some(120),
    )
    .await
    .unwrap();
    let sess_holds: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.quota_reservations WHERE gateway_request_id = $1::uuid",
    )
    .bind(&p_sess.id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(sess_holds, 2);
    assert!(p_sess.release(&api_pool).await.unwrap());
    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));

    // A4: Device-slot quota holds activate with metering (ADR 0040). Before activation a leased,
    // token-funded legacy Pending::handoff for a device-slot profile commits without a run
    // device_reservations hold; once metering_enforced flips, the same shape is refused with
    // the request left reserved and releasable.
    let dev_fx = TurnHandoffFixture::chat(INSTALL, "a", 100, Some(50), true);
    let mut dev_runs = Vec::new();
    for key in ["preact-device-before", "preact-device-after"] {
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        let Admission::Admitted { run_id, .. } = authz_queue::admit_run(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope: &scope,
                    actor: &alice.user,
                    conversation: &chat,
                    branch: &branch,
                    message: &msg,
                    key,
                    format: "openmettle.conversation",
                    version: 1,
                    input: b"{}",
                    config: &snapshot_priced(
                        "a",
                        100,
                        Some(openmettle_core::model_config::CostBound {
                            fixed_micros: 100,
                            micros_per_token: 0,
                        }),
                    ),
                },
                actor_approval_id: &alice.approval,
                capabilities: &[],
                requested_rounds: Some(1),
                now_ms: authz_store::NOW,
                cost_qualified: Some(true),
            },
            &limits,
        )
        .await
        .unwrap() else {
            panic!("expected device admission");
        };
        tx.commit().await.unwrap();
        let claim = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claim.run_id, run_id);
        dev_runs.push(claim);
    }
    fn device_call<'a>(
        claim: &'a authz_queue::ClaimedRun,
        scope: &'a str,
        actor: &'a str,
        approval: &'a str,
    ) -> Call<'a> {
        Call {
            reservation: Reservation {
                id: &claim.run_id,
                scope_id: scope,
                actor,
                approval,
            },
            installation: INSTALL,
            model: "a",
            units: 100,
            authority: Authority::Lease {
                run: &claim.run_id,
                round: 1,
                token: &claim.claim_token,
            },
        }
    }
    /// (request state, usage_tokens child holds, run device_reservations holds)
    async fn device_state(
        owner: &mut sqlx::PgConnection,
        request: &str,
        run: &str,
    ) -> (String, i64, i64) {
        sqlx::query_as(
            "SELECT (SELECT state FROM openmettle.gateway_requests WHERE id = $1::uuid),
                    (SELECT count(*) FROM openmettle.quota_reservations
                      WHERE gateway_request_id = $1::uuid AND resource_kind = 'usage_tokens'),
                    (SELECT count(*) FROM openmettle.quota_reservations
                      WHERE run_id = $2::uuid AND resource_kind = 'device_reservations')",
        )
        .bind(request)
        .bind(run)
        .fetch_one(owner)
        .await
        .unwrap()
    }
    let p_before = gateway::reserve_with_cost(
        &worker_pool,
        device_call(&dev_runs[0], &scope, &alice.user, &alice.approval),
        Some(50),
    )
    .await
    .unwrap();
    let gateway::BillableDispatch::Server(_) = p_before
        .handoff(&worker_pool, &keys, &dev_fx.billable(), dev_fx.prepare())
        .await
        .unwrap()
    else {
        panic!("a leased handoff must yield BillableDispatch::Server");
    };
    assert_eq!(
        device_state(&mut owner, &p_before.id, &dev_runs[0].run_id).await,
        ("handed_off".into(), 1, 0)
    );
    owner
        .execute(
            "UPDATE openmettle.quota_enforcement
                SET metering_enforced = true, metering_enforced_at = clock_timestamp()
              WHERE id AND NOT metering_enforced",
        )
        .await
        .unwrap();
    let p_after = gateway::reserve_with_cost(
        &worker_pool,
        device_call(&dev_runs[1], &scope, &alice.user, &alice.approval),
        Some(50),
    )
    .await
    .unwrap();
    assert!(matches!(
        p_after
            .handoff(&worker_pool, &keys, &dev_fx.billable(), dev_fx.prepare())
            .await,
        Err(gateway::Error::Refused)
    ));
    assert_eq!(
        device_state(&mut owner, &p_after.id, &dev_runs[1].run_id).await,
        ("reserved".into(), 1, 0)
    );
    assert!(p_after.release(&worker_pool).await.unwrap());
    // The refusal is the device-slot check: the released round retries with a non-device profile.
    let plain_fx = TurnHandoffFixture::chat(INSTALL, "a", 100, Some(50), false);
    let p_retry = gateway::reserve_with_cost(
        &worker_pool,
        device_call(&dev_runs[1], &scope, &alice.user, &alice.approval),
        Some(50),
    )
    .await
    .unwrap();
    let gateway::BillableDispatch::Server(_) = p_retry
        .handoff(
            &worker_pool,
            &keys,
            &plain_fx.billable(),
            plain_fx.prepare(),
        )
        .await
        .unwrap()
    else {
        panic!("a leased handoff must yield BillableDispatch::Server");
    };

    // Part B (P2 #4 / #5): On schema 25 (pre-0026 fallback without helper), exact replay backfill
    // on a queued run with an existing gateway_reservations row (id <> run_id, units = 300) under a
    // 400-token limit when replay passes recomputed token_units = 500 rolls back the savepoint on
    // 23505 and returns Ok((false, None)) (deferring to the worker rather than returning 429).
    let db25 = TestDb::new().await;
    let settings25 = db25.settings(Duration::from_secs(10));
    migrate::apply(&settings25, &MIGRATIONS[..25])
        .await
        .unwrap();
    let mut owner25 = connect(&db25.0, OWNER).await;
    authz_store::providers(&mut owner25).await;
    let carol = authz_store::account(
        &mut owner25,
        authz_store::PROVIDER,
        true,
        authz_store::FUTURE,
    )
    .await;
    let scope25 = authz_runs::personal_of(&db25, &carol).await;
    owner25
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 400)",
        )
        .await
        .unwrap();
    owner25
        .execute(
            "UPDATE openmettle.quota_enforcement
                SET metering_enforced = true, metering_enforced_at = clock_timestamp()
              WHERE id AND NOT metering_enforced",
        )
        .await
        .unwrap();
    let mut api25 = connect(&db25.0, API).await;
    let chat25 = authz_runs::chat(&db25, &scope25, "personal", &carol).await;
    let (branch25, msg25) = branch_and_message(&mut api25, &scope25, &chat25).await;
    let mut tx25 = WriteTransaction::begin(&mut api25).await.unwrap();
    let Admission::Admitted { run_id: r25, .. } = authz_queue::admit_run(
        &mut tx25,
        &RunAdmission {
            input: RunInput {
                scope: &scope25,
                actor: &carol.user,
                conversation: &chat25,
                branch: &branch25,
                message: &msg25,
                key: "pre26-distinct-gw-replay",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: b"{}",
            },
            actor_approval_id: &carol.approval,
            capabilities: &[],
            requested_rounds: Some(1),
            now_ms: authz_store::NOW,
            cost_qualified: None,
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("expected schema-25 admission");
    };
    let legacy_gw_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(tx25.connection().unwrap())
        .await
        .unwrap();
    assert_ne!(legacy_gw_id, r25);
    sqlx::query(
        "INSERT INTO openmettle.gateway_reservations
             (id, scope_id, actor_user_id, approval_id, run_id, units)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, 300)",
    )
    .bind(&legacy_gw_id)
    .bind(&scope25)
    .bind(&carol.user)
    .bind(&carol.approval)
    .bind(&r25)
    .execute(tx25.connection().unwrap())
    .await
    .unwrap();
    tx25.commit().await.unwrap();

    let mut tx25 = WriteTransaction::begin(&mut api25).await.unwrap();
    assert_eq!(
        quotas::backfill_replayed_run_budget(
            &mut tx25,
            &RunBudgetReservation {
                scope_id: &scope25,
                scope_kind: "personal",
                actor_user_id: &carol.user,
                actor_approval_id: &carol.approval,
                run_id: &r25,
                token_units: 500,
                per_round_cost_micros: None,
                round_limit: 1,
                requires_device_slot: false,
            },
        )
        .await
        .unwrap(),
        (false, None)
    );
    tx25.commit().await.unwrap();
    let gw_after: (String, i64) = sqlx::query_as(
        "SELECT id::text, units FROM openmettle.gateway_reservations WHERE run_id = $1::uuid",
    )
    .bind(&r25)
    .fetch_one(&mut owner25)
    .await
    .unwrap();
    assert_eq!(gw_after, (legacy_gw_id, 300));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn expired_last_cost_limit_still_settles_parent_and_unqualified_turn_fails_closed() {
    use openmettle_core::{
        authz::{
            gateway::{self, TurnRound, settlement},
            leases::{self, LeaseSettings, Settle},
            runs::{self as authz_queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
        },
        provider_http::gateway::UsageReport,
        provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
        quotas::{self, RunBudgetReservation},
        runs::{RunInput, WriteTransaction},
    };
    use sqlx::postgres::PgPoolOptions;

    const INSTALL: &str = "00000000-0000-4000-8000-0000000000c1";
    const PRINCIPAL: &str = "00000000-0000-4000-8000-0000000000c2";
    const BUDGET: &str = "00000000-0000-4000-8000-0000000000c3";
    const GRANT_RACE: &str = "00000000-0000-4000-8000-00000000d201";
    const KEY_BYTES: [u8; 32] = [99; 32];

    let limits = AdmissionLimits {
        live_per_actor: 8,
        live_per_scope: 8,
        queued_in_instance: 32,
        queue_timeout: Duration::from_secs(300),
        round_cap: 10,
    };
    let lease_cfg = LeaseSettings {
        lease: Duration::from_secs(60),
        execution_timeout: Duration::from_secs(600),
    };
    let claim_cfg = ClaimLimits {
        executing_per_actor: 4,
        executing_per_scope: 8,
    };

    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let scope = authz_runs::personal_of(&db, &alice).await;
    owner
        .execute(
            "UPDATE openmettle.quota_defaults
                SET cost_denomination = 'usd_micros'
              WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros'",
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 100000)",
        )
        .await
        .unwrap();
    // Temporary personal cost override is the ONLY cost limit (instance/project defaults are NULL).
    sqlx::query(
        "INSERT INTO openmettle.quota_overrides
             (scope_id, scope_kind, resource_kind, hard_limit, expires_at, reason, updated_by_user_id)
         VALUES ($1::uuid, 'personal', 'usage_cost_micros', 1000,
                 clock_timestamp() + interval '1 hour', 'temporary personal cost limit', $2::uuid)",
    )
    .bind(&scope)
    .bind(&alice.user)
    .execute(&mut owner)
    .await
    .unwrap();

    // Provision gateway binding, generation, and policy for model `a`.
    let g_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(pg::GATEWAY));
    let binding: String = sqlx::query_scalar(
        "INSERT INTO openmettle.gateway_bindings (installation, user_id, principal, budget)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid) RETURNING id::text",
    )
    .bind(INSTALL)
    .bind(&alice.user)
    .bind(PRINCIPAL)
    .bind(BUDGET)
    .fetch_one(&g_pool)
    .await
    .unwrap();
    let report_source: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    let (finger, env) = GatewaySealer::new(
        GatewayKeys::new(&[("exp-k1".into(), KEY_BYTES)]).unwrap(),
        g_pool.clone(),
    )
    .seal(
        &Context {
            installation: INSTALL,
            user_id: &alice.user,
            binding_id: &binding,
            principal: PRINCIPAL,
            generation: 1,
        },
        &Bearer::new(b"exp-cost-bearer").unwrap(),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_generations
             (binding_id, generation, remote_key, expires_at, key_id, key_fingerprint, nonce, ciphertext)
         VALUES ($1::uuid, 1, gen_random_uuid(), clock_timestamp() + interval '1 hour', $2, $3, $4, $5)",
    )
    .bind(&binding)
    .bind(&env.key_id)
    .bind(finger.as_slice())
    .bind(env.nonce.as_slice())
    .bind(env.ciphertext)
    .execute(&g_pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_policy
             (binding_id, revision, scope_id, approval_id, model, report_source,
              provider_generation, approval_generation, user_generation, capabilities)
         VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'a', $4::uuid, 0, 0, 0, '{}'::jsonb)",
    )
    .bind(&binding)
    .bind(&scope)
    .bind(&alice.approval)
    .bind(&report_source)
    .execute(&g_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.gateway_bindings
            SET active_generation = 1, observed_revision = 1, state = 'ready'
          WHERE id = $1::uuid",
    )
    .bind(&binding)
    .execute(&g_pool)
    .await
    .unwrap();

    let mut api = connect(&db.0, API).await;
    let mut worker = connect(&db.0, WORKER).await;
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(WORKER));
    let chat = authz_runs::chat(&db, &scope, "personal", &alice).await;
    let (branch, msg) = branch_and_message(&mut api, &scope, &chat).await;

    // Part A (P1 #1): Admit 2-round run under the temporary personal cost override (600-micro hold),
    // then expire that ONLY cost limit before Round 1 dispatches. Round 1 MUST still allocate a
    // 300-micro child hold from the existing parent, settle 175 micros, and release the 425 remainder.
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted { run_id: r1, .. } = authz_queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &scope,
                actor: &alice.user,
                conversation: &chat,
                branch: &branch,
                message: &msg,
                key: "expired-last-cost-limit",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot_priced(
                    "a",
                    200,
                    Some(openmettle_core::model_config::CostBound {
                        fixed_micros: 100,
                        micros_per_token: 1,
                    }),
                ),
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(2),
            now_ms: authz_store::NOW,
            cost_qualified: Some(true),
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("expected admission");
    };
    assert!(
        quotas::reserve_admitted_run_budget(
            &mut tx,
            &RunBudgetReservation {
                scope_id: &scope,
                scope_kind: "personal",
                actor_user_id: &alice.user,
                actor_approval_id: &alice.approval,
                run_id: &r1,
                token_units: 400,
                per_round_cost_micros: Some(300),
                round_limit: 2,
                requires_device_slot: false,
            },
        )
        .await
        .unwrap()
        .is_none()
    );
    tx.commit().await.unwrap();

    // Expire the only cost override so zero active cost limits remain across all tiers.
    sqlx::query(
        "UPDATE openmettle.quota_overrides
            SET expires_at = clock_timestamp() - interval '1 second'
          WHERE scope_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&scope)
    .execute(&mut owner)
    .await
    .unwrap();

    let claim1 = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim1.run_id, r1);
    let p1 = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &scope,
            actor: &alice.user,
            approval: &alice.approval,
            run_id: &r1,
            round: 1,
            claim_token: &claim1.claim_token,
            installation: INSTALL,
            model: "a",
            round_tokens: 200,
            round_cost: Some(300),
            cost_bound: Some(openmettle_core::model_config::CostBound {
                fixed_micros: 100,
                micros_per_token: 1,
            }),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let fx = TurnHandoffFixture::chat_priced(
        INSTALL,
        "a",
        200,
        openmettle_core::model_config::CostBound {
            fixed_micros: 100,
            micros_per_token: 1,
        },
        false,
    );
    let _disp1 = p1
        .handoff(&worker_pool, None, &fx.billable(), fx.prepare())
        .await
        .unwrap();
    let r1_child_cost: (i64, String) = sqlx::query_as(
        "SELECT reserved_units, state FROM openmettle.quota_reservations
          WHERE gateway_request_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&p1.id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(r1_child_cost, (300, "handoff_committed".into()));

    let report_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    dispatched(&mut owner, &p1.id).await;
    assert_eq!(
        settlement::ingest(
            &g_pool,
            &UsageReport {
                request: p1.id.clone(),
                installation: INSTALL.into(),
                principal: alice.user.clone(),
                scope: scope.clone(),
                source: INSTALL.into(),
                report_id,
                revision: 1,
                r#final: true,
                prompt_tokens: Some(70),
                completion_tokens: Some(30),
                reasoning_tokens: None,
                reasoning_included: None,
                cost: None,
                unit: None,
            },
        )
        .await
        .unwrap(),
        settlement::Outcome::Applied
    );
    leases::settle(&mut worker, &claim1.lease(), &lease_cfg, Settle::Succeeded)
        .await
        .unwrap();
    let cost_budget: (i64, i64) = sqlx::query_as(
        "SELECT active_used::bigint, reserved_held::bigint FROM openmettle.quota_budgets
          WHERE scope_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&scope)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(cost_budget, (200, 0));

    // Part B (P2 #5): With a cost limit active and an existing usage_cost_micros parent hold on
    // the run, reserve_turn_round for a catalog profile lacking cost_bound (round_cost = None)
    // MUST fail closed with Error::Refused (never slicing the existing cost parent).
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_cost_micros', 10000)",
        )
        .await
        .unwrap();
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted { run_id: r2, .. } = authz_queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &scope,
                actor: &alice.user,
                conversation: &chat,
                branch: &branch,
                message: &msg,
                key: "existing-cost-parent-unqualified-turn",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot(200),
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(2),
            now_ms: authz_store::NOW,
            cost_qualified: Some(true),
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("expected admission");
    };
    assert!(
        quotas::reserve_admitted_run_budget(
            &mut tx,
            &RunBudgetReservation {
                scope_id: &scope,
                scope_kind: "personal",
                actor_user_id: &alice.user,
                actor_approval_id: &alice.approval,
                run_id: &r2,
                token_units: 400,
                per_round_cost_micros: Some(300),
                round_limit: 2,
                requires_device_slot: false,
            },
        )
        .await
        .unwrap()
        .is_none()
    );
    tx.commit().await.unwrap();
    let claim2 = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim2.run_id, r2);
    assert!(matches!(
        gateway::reserve_turn_round(
            &worker_pool,
            TurnRound {
                scope_id: &scope,
                actor: &alice.user,
                approval: &alice.approval,
                run_id: &r2,
                round: 1,
                claim_token: &claim2.claim_token,
                installation: INSTALL,
                model: "a",
                round_tokens: 200,
                round_cost: None,
                cost_bound: None,
                requires_device_slot: false,
            },
        )
        .await,
        Err(gateway::Error::Refused)
    ));
    leases::settle(
        &mut worker,
        &claim2.lease(),
        &lease_cfg,
        Settle::Failed(leases::FailReason::StepFailed),
    )
    .await
    .unwrap();
    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));

    // Part C (P2 #3): Deferred enforce_gateway_handoff_holds rejects device-slot handoff with
    // OMQ04 (mapped to Error::Refused) if metering_enforced flips true between reserve_turn_round
    // and TurnPending::handoff, rolling back gateway_requests to 'reserved' for immediate release.
    let db_up = TestDb::new().await;
    let settings_up = db_up.settings(Duration::from_secs(10));
    migrate::apply(&settings_up, &MIGRATIONS[..23])
        .await
        .unwrap();
    let mut owner_up = connect(&db_up.0, OWNER).await;
    authz_store::providers(&mut owner_up).await;
    let bob = authz_store::account(
        &mut owner_up,
        authz_store::PROVIDER,
        true,
        authz_store::FUTURE,
    )
    .await;
    let bob_scope = authz_runs::personal_of(&db_up, &bob).await;
    migrate::apply(&settings_up, MIGRATIONS).await.unwrap();
    let g_up = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db_up.1.options(pg::GATEWAY));
    let b_up: String = sqlx::query_scalar(
        "INSERT INTO openmettle.gateway_bindings (installation, user_id, principal, budget)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid) RETURNING id::text",
    )
    .bind(INSTALL)
    .bind(&bob.user)
    .bind(PRINCIPAL)
    .bind(BUDGET)
    .fetch_one(&g_up)
    .await
    .unwrap();
    let rs_up: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut owner_up)
        .await
        .unwrap();
    let (f_up, e_up) = GatewaySealer::new(
        GatewayKeys::new(&[("race-k1".into(), KEY_BYTES)]).unwrap(),
        g_up.clone(),
    )
    .seal(
        &Context {
            installation: INSTALL,
            user_id: &bob.user,
            binding_id: &b_up,
            principal: PRINCIPAL,
            generation: 1,
        },
        &Bearer::new(b"race-bearer").unwrap(),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_generations
             (binding_id, generation, remote_key, expires_at, key_id, key_fingerprint, nonce, ciphertext)
         VALUES ($1::uuid, 1, gen_random_uuid(), clock_timestamp() + interval '1 hour', $2, $3, $4, $5)",
    )
    .bind(&b_up)
    .bind(&e_up.key_id)
    .bind(f_up.as_slice())
    .bind(e_up.nonce.as_slice())
    .bind(e_up.ciphertext)
    .execute(&g_up)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_policy
             (binding_id, revision, scope_id, approval_id, model, report_source,
              provider_generation, approval_generation, user_generation, capabilities)
         VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'a', $4::uuid, 0, 0, 0, '{}'::jsonb)",
    )
    .bind(&b_up)
    .bind(&bob_scope)
    .bind(&bob.approval)
    .bind(&rs_up)
    .execute(&g_up)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.gateway_bindings
            SET active_generation = 1, observed_revision = 1, state = 'ready'
          WHERE id = $1::uuid",
    )
    .bind(&b_up)
    .execute(&g_up)
    .await
    .unwrap();
    owner_up
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 100000),
                    ('personal', 'device_reservations', 1)",
        )
        .await
        .unwrap();

    let mut api_up = connect(&db_up.0, API).await;
    let mut worker_up = connect(&db_up.0, WORKER).await;
    let wp_up = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db_up.1.options(WORKER));
    let bob_chat = authz_runs::chat(&db_up, &bob_scope, "personal", &bob).await;
    let (bob_branch, bob_msg) = branch_and_message(&mut api_up, &bob_scope, &bob_chat).await;
    let mut tx_up = WriteTransaction::begin(&mut api_up).await.unwrap();
    let Admission::Admitted { run_id: r_up, .. } = authz_queue::admit_run(
        &mut tx_up,
        &RunAdmission {
            input: RunInput {
                scope: &bob_scope,
                actor: &bob.user,
                conversation: &bob_chat,
                branch: &bob_branch,
                message: &bob_msg,
                key: "device-activation-race",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot(100),
            },
            actor_approval_id: &bob.approval,
            capabilities: &[],
            requested_rounds: Some(1),
            now_ms: authz_store::NOW,
            cost_qualified: None,
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("expected admission");
    };
    // Give the run a token parent hold (but NO device_reservations hold) while !metering_enforced.
    gateway::hold(
        &mut tx_up,
        &gateway::Reservation {
            id: &r_up,
            scope_id: &bob_scope,
            actor: &bob.user,
            approval: &bob.approval,
        },
        Some(&r_up),
        100,
    )
    .await
    .unwrap();
    tx_up.commit().await.unwrap();

    let claim_up = authz_queue::claim_next(&mut worker_up, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    let p_race = gateway::reserve_turn_round(
        &wp_up,
        TurnRound {
            scope_id: &bob_scope,
            actor: &bob.user,
            approval: &bob.approval,
            run_id: &r_up,
            round: 1,
            claim_token: &claim_up.claim_token,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: None,
            cost_bound: None,
            requires_device_slot: true,
        },
    )
    .await
    .unwrap();
    // Flip metering_enforced = true BEFORE TurnPending::handoff: token hold is present, so ONLY
    // the deferred device_reservations check in enforce_gateway_handoff_holds triggers OMQ04!
    owner_up
        .execute(
            "UPDATE openmettle.quota_enforcement
                SET metering_enforced = true, metering_enforced_at = clock_timestamp()
              WHERE id AND NOT metering_enforced",
        )
        .await
        .unwrap();
    let fx = TurnHandoffFixture::chat(INSTALL, "a", 100, None, true);
    assert!(matches!(
        p_race
            .handoff(&wp_up, Some(GRANT_RACE), &fx.billable(), fx.prepare(),)
            .await,
        Err(gateway::Error::Refused)
    ));
    let race_req_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.gateway_requests WHERE id = $1::uuid")
            .bind(&p_race.id)
            .fetch_one(&mut owner_up)
            .await
            .unwrap();
    assert_eq!(race_req_state, "reserved");
    assert!(p_race.release(&wp_up).await.unwrap());
    let race_req_released: String =
        sqlx::query_scalar("SELECT state FROM openmettle.gateway_requests WHERE id = $1::uuid")
            .bind(&p_race.id)
            .fetch_one(&mut owner_up)
            .await
            .unwrap();
    assert_eq!(race_req_released, "released");
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn re_review_8_single_snapshot_cost_unqualified_activation_race_and_disable_user_lock_order()
{
    use openmettle_core::{
        authz::{
            gateway::{self, TurnRound},
            leases::{self, LeaseSettings, Settle},
            runs::{self as authz_queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
            store::{self, WriteOutcome},
        },
        provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
        quotas::{self, RunBudgetReservation},
        runs::{RunInput, WriteTransaction},
    };
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;
    use tokio::sync::Barrier;

    const INSTALL: &str = "00000000-0000-4000-8000-000000000081";
    const PRINCIPAL: &str = "00000000-0000-4000-8000-000000000082";
    const BUDGET: &str = "00000000-0000-4000-8000-000000000083";
    const KEY_BYTES: [u8; 32] = [88u8; 32];

    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let admin =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    authz_store::make_admin(&mut owner, &admin).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let scope = authz_runs::personal_of(&db, &alice).await;

    owner
        .execute(
            "UPDATE openmettle.quota_defaults
                SET cost_denomination = 'usd_micros'
              WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros'",
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 100000)",
        )
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.quota_overrides
             (scope_id, scope_kind, resource_kind, hard_limit, expires_at, reason, updated_by_user_id)
         VALUES ($1::uuid, 'personal', 'usage_cost_micros', 5000,
                 clock_timestamp() + interval '1 hour', 're-review-8 initial cost limit', $2::uuid)",
    )
    .bind(&scope)
    .bind(&admin.user)
    .execute(&mut owner)
    .await
    .unwrap();

    // Provision gateway binding, generation, and policy for model `a`.
    let g_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(pg::GATEWAY));
    let binding: String = sqlx::query_scalar(
        "INSERT INTO openmettle.gateway_bindings (installation, user_id, principal, budget)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid) RETURNING id::text",
    )
    .bind(INSTALL)
    .bind(&alice.user)
    .bind(PRINCIPAL)
    .bind(BUDGET)
    .fetch_one(&g_pool)
    .await
    .unwrap();
    let report_source: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    let (finger, env) = GatewaySealer::new(
        GatewayKeys::new(&[("rr8-k1".into(), KEY_BYTES)]).unwrap(),
        g_pool.clone(),
    )
    .seal(
        &Context {
            installation: INSTALL,
            user_id: &alice.user,
            binding_id: &binding,
            principal: PRINCIPAL,
            generation: 1,
        },
        &Bearer::new(b"rr8-bearer").unwrap(),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_generations
             (binding_id, generation, remote_key, expires_at, key_id, key_fingerprint, nonce, ciphertext)
         VALUES ($1::uuid, 1, gen_random_uuid(), clock_timestamp() + interval '1 hour', $2, $3, $4, $5)",
    )
    .bind(&binding)
    .bind(&env.key_id)
    .bind(finger.as_slice())
    .bind(env.nonce.as_slice())
    .bind(env.ciphertext)
    .execute(&g_pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_policy
             (binding_id, revision, scope_id, approval_id, model, report_source,
              provider_generation, approval_generation, user_generation, capabilities)
         VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'a', $4::uuid, 0, 0, 0, '{}'::jsonb)",
    )
    .bind(&binding)
    .bind(&scope)
    .bind(&alice.approval)
    .bind(&report_source)
    .execute(&g_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.gateway_bindings
            SET active_generation = 1, observed_revision = 1, state = 'ready'
          WHERE id = $1::uuid",
    )
    .bind(&binding)
    .execute(&g_pool)
    .await
    .unwrap();

    let mut api = connect(&db.0, API).await;
    let mut worker = connect(&db.0, WORKER).await;
    let worker_pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_lazy_with(db.1.options(WORKER));
    let chat = authz_runs::chat(&db, &scope, "personal", &alice).await;
    let (branch, msg) = branch_and_message(&mut api, &scope, &chat).await;
    let limits = AdmissionLimits {
        live_per_actor: 16,
        live_per_scope: 16,
        queued_in_instance: 32,
        queue_timeout: Duration::from_secs(300),
        round_cap: 10,
    };
    let lease_cfg = LeaseSettings {
        lease: Duration::from_secs(60),
        execution_timeout: Duration::from_secs(600),
    };
    let claim_cfg = ClaimLimits {
        executing_per_actor: 8,
        executing_per_scope: 16,
    };

    // Part A (P1 #1): Single-snapshot cost_limit_state across an override expiring right at the
    // reservation boundary must NEVER skip allocating the usage_cost_micros child hold while a
    // held usage_cost_micros parent exists.
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted { run_id: r1, .. } = authz_queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &scope,
                actor: &alice.user,
                conversation: &chat,
                branch: &branch,
                message: &msg,
                key: "rr8-boundary-expiry",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot(100),
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(2),
            now_ms: authz_store::NOW,
            cost_qualified: Some(true),
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("expected admission");
    };
    assert!(
        quotas::reserve_admitted_run_budget(
            &mut tx,
            &RunBudgetReservation {
                scope_id: &scope,
                scope_kind: "personal",
                actor_user_id: &alice.user,
                actor_approval_id: &alice.approval,
                run_id: &r1,
                token_units: 200,
                per_round_cost_micros: Some(1000),
                round_limit: 2,
                requires_device_slot: false,
            },
        )
        .await
        .unwrap()
        .is_none()
    );
    tx.commit().await.unwrap();

    let claim1 = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim1.run_id, r1);

    // Arm override to expire 4ms from now and repeatedly reserve + release rounds right across the
    // expiry instant; every single round MUST carry both usage_cost_micros and usage_tokens holds.
    sqlx::query(
        "UPDATE openmettle.quota_overrides
            SET expires_at = clock_timestamp() + interval '4 milliseconds'
          WHERE scope_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&scope)
    .execute(&mut owner)
    .await
    .unwrap();
    for round in 1..=6 {
        let pending = gateway::reserve_turn_round(
            &worker_pool,
            TurnRound {
                scope_id: &scope,
                actor: &alice.user,
                approval: &alice.approval,
                run_id: &r1,
                round,
                claim_token: &claim1.claim_token,
                installation: INSTALL,
                model: "a",
                round_tokens: 100,
                round_cost: Some(750),
                cost_bound: Some(openmettle_core::model_config::CostBound {
                    fixed_micros: 750,
                    micros_per_token: 0,
                }),
                requires_device_slot: false,
            },
        )
        .await
        .unwrap();
        let children: Vec<(String, i64)> = sqlx::query_as(
            "SELECT resource_kind, held_units
               FROM openmettle.quota_reservations
              WHERE gateway_request_id = $1::uuid
                AND state = 'held'
              ORDER BY resource_kind ASC",
        )
        .bind(&pending.id)
        .fetch_all(&mut owner)
        .await
        .unwrap();
        assert_eq!(
            children,
            vec![
                ("usage_cost_micros".to_owned(), 750),
                ("usage_tokens".to_owned(), 100),
            ],
            "round {round} must never drop usage_cost_micros child while cost parent is held"
        );
        assert!(pending.release(&worker_pool).await.unwrap());
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    // Part B1 (P2 #2 + issue #166): With all cost limits now expired/NULL, an unqualified profile
    // (`round_cost = None`) MUST NOT slice `r1`'s existing parent `usage_cost_micros` hold into an
    // unpriced unbound round (`Err(Error::Refused)`). On a fresh run without a parent cost hold,
    // `reserve_turn_round` with `round_cost = None` succeeds without a cost hold, and if an admin
    // activates a cost override before `TurnPending::handoff`, deferred
    // `enforce_gateway_handoff_holds` MUST reject the handoff with OMQ04 (`Error::Refused`),
    // leaving `gateway_requests` in `'reserved'` so `pending.release()` cleanly unwinds it.
    sqlx::query(
        "UPDATE openmettle.quota_overrides
            SET expires_at = clock_timestamp() - interval '1 second'
          WHERE scope_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&scope)
    .execute(&mut owner)
    .await
    .unwrap();
    assert!(matches!(
        gateway::reserve_turn_round(
            &worker_pool,
            TurnRound {
                scope_id: &scope,
                actor: &alice.user,
                approval: &alice.approval,
                run_id: &r1,
                round: 7,
                claim_token: &claim1.claim_token,
                installation: INSTALL,
                model: "a",
                round_tokens: 100,
                round_cost: None,
                cost_bound: None,
                requires_device_slot: false,
            },
        )
        .await,
        Err(gateway::Error::Refused)
    ));
    leases::settle(
        &mut worker,
        &claim1.lease(),
        &lease_cfg,
        Settle::Failed(leases::FailReason::StepFailed),
    )
    .await
    .unwrap();

    let mut tx_u = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted { run_id: r_u, .. } = authz_queue::admit_run(
        &mut tx_u,
        &RunAdmission {
            input: RunInput {
                scope: &scope,
                actor: &alice.user,
                conversation: &chat,
                branch: &branch,
                message: &msg,
                key: "rr8-unqual-activation-race",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot(100),
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(1),
            now_ms: authz_store::NOW,
            cost_qualified: Some(false),
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("expected admission");
    };
    assert!(
        quotas::reserve_admitted_run_budget(
            &mut tx_u,
            &RunBudgetReservation {
                scope_id: &scope,
                scope_kind: "personal",
                actor_user_id: &alice.user,
                actor_approval_id: &alice.approval,
                run_id: &r_u,
                token_units: 100,
                per_round_cost_micros: None,
                round_limit: 1,
                requires_device_slot: false,
            },
        )
        .await
        .unwrap()
        .is_none()
    );
    tx_u.commit().await.unwrap();
    let claim_u = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim_u.run_id, r_u);
    let p_unqual = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &scope,
            actor: &alice.user,
            approval: &alice.approval,
            run_id: &r_u,
            round: 1,
            claim_token: &claim_u.claim_token,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: None,
            cost_bound: None,
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    // Activate a cost override BEFORE TurnPending::handoff.
    sqlx::query(
        "UPDATE openmettle.quota_overrides
            SET expires_at = NULL, hard_limit = 5000
          WHERE scope_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&scope)
    .execute(&mut owner)
    .await
    .unwrap();
    let fx = TurnHandoffFixture::chat(INSTALL, "a", 100, None, false);
    assert!(matches!(
        p_unqual
            .handoff(&worker_pool, None, &fx.billable(), fx.prepare())
            .await,
        Err(gateway::Error::Refused)
    ));
    let unqual_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.gateway_requests WHERE id = $1::uuid")
            .bind(&p_unqual.id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(unqual_state, "reserved");
    assert!(p_unqual.release(&worker_pool).await.unwrap());
    let unqual_released: String =
        sqlx::query_scalar("SELECT state FROM openmettle.gateway_requests WHERE id = $1::uuid")
            .bind(&p_unqual.id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(unqual_released, "released");
    leases::settle(
        &mut worker,
        &claim_u.lease(),
        &lease_cfg,
        Settle::Failed(leases::FailReason::StepFailed),
    )
    .await
    .unwrap();

    // Part B2 (P2 #2): On a deployment where cost_denomination IS NULL and a round was reserved
    // with a qualified cost bound while no cost limit existed (so no cost child was allocated),
    // activating a cost limit with cost_denomination still NULL before handoff MUST fail closed
    // with OMQ04 (Error::Refused) and roll back gateway_requests to 'reserved'.
    {
        let db2 = TestDb::migrated().await;
        let mut owner2 = connect(&db2.0, OWNER).await;
        authz_store::providers(&mut owner2).await;
        let bob = authz_store::account(
            &mut owner2,
            authz_store::PROVIDER,
            true,
            authz_store::FUTURE,
        )
        .await;
        let bob_scope = authz_runs::personal_of(&db2, &bob).await;
        owner2
            .execute(
                "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
                 VALUES ('personal', 'usage_tokens', 100000)",
            )
            .await
            .unwrap();
        let g2 = PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with(db2.1.options(pg::GATEWAY));
        let b2: String = sqlx::query_scalar(
            "INSERT INTO openmettle.gateway_bindings (installation, user_id, principal, budget)
             VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid) RETURNING id::text",
        )
        .bind(INSTALL)
        .bind(&bob.user)
        .bind(PRINCIPAL)
        .bind(BUDGET)
        .fetch_one(&g2)
        .await
        .unwrap();
        let rs2: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut owner2)
            .await
            .unwrap();
        let (f2, e2) = GatewaySealer::new(
            GatewayKeys::new(&[("rr8-k2".into(), KEY_BYTES)]).unwrap(),
            g2.clone(),
        )
        .seal(
            &Context {
                installation: INSTALL,
                user_id: &bob.user,
                binding_id: &b2,
                principal: PRINCIPAL,
                generation: 1,
            },
            &Bearer::new(b"rr8-bearer-2").unwrap(),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_generations
                 (binding_id, generation, remote_key, expires_at, key_id, key_fingerprint, nonce, ciphertext)
             VALUES ($1::uuid, 1, gen_random_uuid(), clock_timestamp() + interval '1 hour', $2, $3, $4, $5)",
        )
        .bind(&b2)
        .bind(&e2.key_id)
        .bind(f2.as_slice())
        .bind(e2.nonce.as_slice())
        .bind(e2.ciphertext)
        .execute(&g2)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_policy
                 (binding_id, revision, scope_id, approval_id, model, report_source,
                  provider_generation, approval_generation, user_generation, capabilities)
             VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'a', $4::uuid, 0, 0, 0, '{}'::jsonb)",
        )
        .bind(&b2)
        .bind(&bob_scope)
        .bind(&bob.approval)
        .bind(&rs2)
        .execute(&g2)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_bindings
                SET active_generation = 1, observed_revision = 1, state = 'ready'
              WHERE id = $1::uuid",
        )
        .bind(&b2)
        .execute(&g2)
        .await
        .unwrap();

        let mut api2 = connect(&db2.0, API).await;
        let mut worker2 = connect(&db2.0, WORKER).await;
        let wp2 = PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with(db2.1.options(WORKER));
        let bob_chat = authz_runs::chat(&db2, &bob_scope, "personal", &bob).await;
        let (bob_branch, bob_msg) = branch_and_message(&mut api2, &bob_scope, &bob_chat).await;
        let mut tx2 = WriteTransaction::begin(&mut api2).await.unwrap();
        let Admission::Admitted { run_id: r2, .. } = authz_queue::admit_run(
            &mut tx2,
            &RunAdmission {
                input: RunInput {
                    scope: &bob_scope,
                    actor: &bob.user,
                    conversation: &bob_chat,
                    branch: &bob_branch,
                    message: &bob_msg,
                    key: "rr8-null-denom-race",
                    format: "openmettle.conversation",
                    version: 1,
                    input: b"{}",
                    config: &snapshot_priced(
                        "a",
                        100,
                        Some(openmettle_core::model_config::CostBound {
                            fixed_micros: 500,
                            micros_per_token: 0,
                        }),
                    ),
                },
                actor_approval_id: &bob.approval,
                capabilities: &[],
                requested_rounds: Some(1),
                now_ms: authz_store::NOW,
                cost_qualified: Some(true),
            },
            &limits,
        )
        .await
        .unwrap() else {
            panic!("expected admission");
        };
        assert!(
            quotas::reserve_admitted_run_budget(
                &mut tx2,
                &RunBudgetReservation {
                    scope_id: &bob_scope,
                    scope_kind: "personal",
                    actor_user_id: &bob.user,
                    actor_approval_id: &bob.approval,
                    run_id: &r2,
                    token_units: 100,
                    per_round_cost_micros: Some(500),
                    round_limit: 1,
                    requires_device_slot: false,
                },
            )
            .await
            .unwrap()
            .is_none()
        );
        tx2.commit().await.unwrap();
        let claim2 = authz_queue::claim_next(&mut worker2, &claim_cfg, &lease_cfg)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claim2.run_id, r2);
        let p_null_denom = gateway::reserve_turn_round(
            &wp2,
            TurnRound {
                scope_id: &bob_scope,
                actor: &bob.user,
                approval: &bob.approval,
                run_id: &r2,
                round: 1,
                claim_token: &claim2.claim_token,
                installation: INSTALL,
                model: "a",
                round_tokens: 100,
                round_cost: Some(500),
                cost_bound: Some(openmettle_core::model_config::CostBound {
                    fixed_micros: 500,
                    micros_per_token: 0,
                }),
                requires_device_slot: false,
            },
        )
        .await
        .unwrap();
        // Insert a cost limit with cost_denomination STILL NULL before handoff.
        owner2
            .execute(
                "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
                 VALUES ('personal', 'usage_cost_micros', 5000)",
            )
            .await
            .unwrap();
        let fx = TurnHandoffFixture::chat(INSTALL, "a", 100, Some(500), false);
        assert!(matches!(
            p_null_denom
                .handoff(&wp2, None, &fx.billable(), fx.prepare())
                .await,
            Err(gateway::Error::Refused)
        ));
        let null_denom_state: String =
            sqlx::query_scalar("SELECT state FROM openmettle.gateway_requests WHERE id = $1::uuid")
                .bind(&p_null_denom.id)
                .fetch_one(&mut owner2)
                .await
                .unwrap();
        assert_eq!(null_denom_state, "reserved");
        assert!(p_null_denom.release(&wp2).await.unwrap());
        leases::settle(
            &mut worker2,
            &claim2.lease(),
            &lease_cfg,
            Settle::Failed(leases::FailReason::StepFailed),
        )
        .await
        .unwrap();
        let drift2: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
               FROM openmettle.quota_verify_accounting_drift()",
        )
        .fetch_one(&mut worker2)
        .await
        .unwrap();
        assert_eq!(drift2, (0, 0, 0, 0));
    }

    // Clear alice's cost override before Part C so legacy runs without round_cost can reserve
    // freely whenever reserve_turn_round wins the race against disable_user.
    sqlx::query(
        "DELETE FROM openmettle.quota_overrides
          WHERE scope_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&scope)
    .execute(&mut owner)
    .await
    .unwrap();

    // Part C (P2 #3): Racing authz::store::disable_user against gateway::reserve_turn_round on
    // legacy runs missing gateway_reservations MUST NEVER deadlock with PostgreSQL 40P01, because
    // reserve_turn_round acquires openmettle.quota_lock_run_actor_prefix(...) before runs.
    let api_pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_lazy_with(db.1.options(API));
    let mut reserved_wins = 0usize;
    let mut disabled_wins = 0usize;
    for iter in 0..8usize {
        // Re-enable alice between race iterations without changing user_generation.
        sqlx::query("UPDATE openmettle.users SET disabled_at = NULL WHERE id = $1::uuid")
            .bind(&alice.user)
            .execute(&mut owner)
            .await
            .unwrap();
        // Admit a run WITHOUT inserting gateway_reservations so reserve_turn_round hits the
        // legacy backfill INSERT INTO gateway_reservations (which FK-locks users + approvals).
        let mut tx_r = WriteTransaction::begin(&mut api).await.unwrap();
        let key = format!("rr8-lock-race-{iter}");
        let Admission::Admitted { run_id: r_race, .. } = authz_queue::admit_run(
            &mut tx_r,
            &RunAdmission {
                input: RunInput {
                    scope: &scope,
                    actor: &alice.user,
                    conversation: &chat,
                    branch: &branch,
                    message: &msg,
                    key: &key,
                    format: "openmettle.conversation",
                    version: 1,
                    input: b"{}",
                    config: &snapshot(100),
                },
                actor_approval_id: &alice.approval,
                capabilities: &[],
                requested_rounds: Some(1),
                now_ms: authz_store::NOW,
                cost_qualified: None,
            },
            &limits,
        )
        .await
        .unwrap() else {
            panic!("expected admission");
        };
        tx_r.commit().await.unwrap();
        let claim_r = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claim_r.run_id, r_race);

        let barrier = Arc::new(Barrier::new(2));
        let b1 = Arc::clone(&barrier);
        let b2 = Arc::clone(&barrier);
        let api_pool_c = api_pool.clone();
        let wp_c = worker_pool.clone();
        let admin_c = admin.clone();
        let victim_user_d = alice.user.clone();
        let victim_user_r = alice.user.clone();
        let victim_approval = alice.approval.clone();
        let scope_c = scope.clone();
        let run_c = r_race.clone();
        let claim_tok = claim_r.claim_token.clone();
        let disable_key = format!("rr8-disable-{iter}");

        let disable_fut = async move {
            let mut conn = api_pool_c.acquire().await.unwrap();
            let audit_ctx = authz_store::ctx(&admin_c, &disable_key);
            b1.wait().await;
            store::disable_user(&mut conn, &audit_ctx, &victim_user_d).await
        };
        let reserve_fut = async move {
            b2.wait().await;
            gateway::reserve_turn_round(
                &wp_c,
                TurnRound {
                    scope_id: &scope_c,
                    actor: &victim_user_r,
                    approval: &victim_approval,
                    run_id: &run_c,
                    round: 1,
                    claim_token: &claim_tok,
                    installation: INSTALL,
                    model: "a",
                    round_tokens: 100,
                    round_cost: None,
                    cost_bound: None,
                    requires_device_slot: false,
                },
            )
            .await
        };

        let (disable_res, reserve_res) = tokio::join!(disable_fut, reserve_fut);
        assert!(
            matches!(disable_res, Ok(WriteOutcome::Applied { .. })),
            "disable_user failed on iter {iter} (possible 40P01 deadlock): {disable_res:?}"
        );
        match reserve_res {
            Ok(pending) => {
                reserved_wins += 1;
                // Clean up the unsent round so no open reservation lingers after the race.
                let _ = pending.release(&worker_pool).await.unwrap();
            }
            Err(gateway::Error::Refused) => {
                disabled_wins += 1;
            }
            Err(other) => {
                panic!(
                    "reserve_turn_round hit unexpected error on iter {iter} (possible 40P01 deadlock): {other:?}"
                );
            }
        }
        // disable_user marks a running run cancelling; settle it cleanly to terminal cancelled.
        let _ = leases::settle(&mut worker, &claim_r.lease(), &lease_cfg, Settle::Stopped).await;
    }
    assert_eq!(reserved_wins + disabled_wins, 8);

    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn stale_lease_on_reserve_turn_round_and_gateway_reserve_returns_refused() {
    use openmettle_core::{
        authz::{
            gateway::{self, Authority, Call, Reservation, TurnRound, settlement},
            leases::{self, LeaseSettings, Settle},
            runs::{self as authz_queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
        },
        provider_http::gateway::UsageReport,
        provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
        quotas::{self, RunBudgetReservation},
        runs::{RunInput, WriteTransaction},
    };
    use sqlx::postgres::PgPoolOptions;

    const INSTALL: &str = "00000000-0000-4000-8000-000000000091";
    const PRINCIPAL: &str = "00000000-0000-4000-8000-000000000092";
    const BUDGET: &str = "00000000-0000-4000-8000-000000000093";
    const STALE_CLAIM: &str = "00000000-0000-4000-8000-000000000099";
    const GRANT_OK: &str = "00000000-0000-4000-8000-00000000d901";
    const KEY_BYTES: [u8; 32] = [91u8; 32];

    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let scope = authz_runs::personal_of(&db, &alice).await;
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 100000),
                    ('personal', 'device_reservations', 1)",
        )
        .await
        .unwrap();

    let g_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(pg::GATEWAY));
    let binding: String = sqlx::query_scalar(
        "INSERT INTO openmettle.gateway_bindings (installation, user_id, principal, budget)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid) RETURNING id::text",
    )
    .bind(INSTALL)
    .bind(&alice.user)
    .bind(PRINCIPAL)
    .bind(BUDGET)
    .fetch_one(&g_pool)
    .await
    .unwrap();
    let report_source: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    let keys = GatewayKeys::new(&[("rr9-k1".into(), KEY_BYTES)]).unwrap();
    let (finger, env) = GatewaySealer::new(
        GatewayKeys::new(&[("rr9-k1".into(), KEY_BYTES)]).unwrap(),
        g_pool.clone(),
    )
    .seal(
        &Context {
            installation: INSTALL,
            user_id: &alice.user,
            binding_id: &binding,
            principal: PRINCIPAL,
            generation: 1,
        },
        &Bearer::new(b"rr9-bearer").unwrap(),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_generations
             (binding_id, generation, remote_key, expires_at, key_id, key_fingerprint, nonce, ciphertext)
         VALUES ($1::uuid, 1, gen_random_uuid(), clock_timestamp() + interval '1 hour', $2, $3, $4, $5)",
    )
    .bind(&binding)
    .bind(&env.key_id)
    .bind(finger.as_slice())
    .bind(env.nonce.as_slice())
    .bind(env.ciphertext)
    .execute(&g_pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_policy
             (binding_id, revision, scope_id, approval_id, model, report_source,
              provider_generation, approval_generation, user_generation, capabilities)
         VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'a', $4::uuid, 0, 0, 0, '{}'::jsonb)",
    )
    .bind(&binding)
    .bind(&scope)
    .bind(&alice.approval)
    .bind(&report_source)
    .execute(&g_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.gateway_bindings
            SET active_generation = 1, observed_revision = 1, state = 'ready'
          WHERE id = $1::uuid",
    )
    .bind(&binding)
    .execute(&g_pool)
    .await
    .unwrap();

    let mut api = connect(&db.0, API).await;
    let mut worker = connect(&db.0, WORKER).await;
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(WORKER));
    let chat = authz_runs::chat(&db, &scope, "personal", &alice).await;
    let (branch, msg) = branch_and_message(&mut api, &scope, &chat).await;
    let limits = AdmissionLimits {
        live_per_actor: 8,
        live_per_scope: 8,
        queued_in_instance: 32,
        queue_timeout: Duration::from_secs(300),
        round_cap: 4,
    };
    let lease_cfg = LeaseSettings {
        lease: Duration::from_secs(60),
        execution_timeout: Duration::from_secs(600),
    };
    let claim_cfg = ClaimLimits {
        executing_per_actor: 4,
        executing_per_scope: 8,
    };

    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted { run_id: r1, .. } = authz_queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &scope,
                actor: &alice.user,
                conversation: &chat,
                branch: &branch,
                message: &msg,
                key: "rr9-stale-lease",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot(100),
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(1),
            now_ms: authz_store::NOW,
            cost_qualified: None,
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("expected admission");
    };
    assert!(
        quotas::reserve_admitted_run_budget(
            &mut tx,
            &RunBudgetReservation {
                scope_id: &scope,
                scope_kind: "personal",
                actor_user_id: &alice.user,
                actor_approval_id: &alice.approval,
                run_id: &r1,
                token_units: 100,
                per_round_cost_micros: None,
                round_limit: 1,
                requires_device_slot: true,
            },
        )
        .await
        .unwrap()
        .is_none()
    );
    tx.commit().await.unwrap();

    let claim1 = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim1.run_id, r1);

    // 1. Stale/mismatched claim_token (42501 in quota_unwind_superseded_round) maps to Error::Refused.
    assert!(matches!(
        gateway::reserve_turn_round(
            &worker_pool,
            TurnRound {
                scope_id: &scope,
                actor: &alice.user,
                approval: &alice.approval,
                run_id: &r1,
                round: 1,
                claim_token: STALE_CLAIM,
                installation: INSTALL,
                model: "a",
                round_tokens: 100,
                round_cost: None,
                cost_bound: None,
                requires_device_slot: true,
            },
        )
        .await,
        Err(gateway::Error::Refused)
    ));
    assert!(matches!(
        gateway::reserve(
            &worker_pool,
            Call {
                reservation: Reservation {
                    id: &r1,
                    scope_id: &scope,
                    actor: &alice.user,
                    approval: &alice.approval,
                },
                installation: INSTALL,
                model: "a",
                units: 100,
                authority: Authority::Lease {
                    run: &r1,
                    round: 1,
                    token: STALE_CLAIM,
                },
            },
        )
        .await,
        Err(gateway::Error::Refused)
    ));

    // 2. TurnPending stores requires_device_slot from reservation so handoff without a grant fails
    // closed with Error::Refused without callers re-supplying the boolean flag.
    let p_dev = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &scope,
            actor: &alice.user,
            approval: &alice.approval,
            run_id: &r1,
            round: 1,
            claim_token: &claim1.claim_token,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: None,
            cost_bound: None,
            requires_device_slot: true,
        },
    )
    .await
    .unwrap();
    let fx = TurnHandoffFixture::chat(INSTALL, "a", 100, None, true);
    assert!(matches!(
        p_dev
            .handoff(&worker_pool, None, &fx.billable(), fx.prepare())
            .await,
        Err(gateway::Error::Refused)
    ));
    let state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.gateway_requests WHERE id = $1::uuid")
            .bind(&p_dev.id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(state, "reserved");
    assert!(p_dev.release(&worker_pool).await.unwrap());

    // 3. Expired lease (42501 in quota_unwind_superseded_round) maps to Error::Refused on both paths.
    sqlx::query(
        "UPDATE openmettle.runs
            SET lease_expires_at = clock_timestamp() - interval '1 second'
          WHERE id = $1::uuid",
    )
    .bind(&r1)
    .execute(&mut owner)
    .await
    .unwrap();
    assert!(matches!(
        gateway::reserve_turn_round(
            &worker_pool,
            TurnRound {
                scope_id: &scope,
                actor: &alice.user,
                approval: &alice.approval,
                run_id: &r1,
                round: 2,
                claim_token: &claim1.claim_token,
                installation: INSTALL,
                model: "a",
                round_tokens: 100,
                round_cost: None,
                cost_bound: None,
                requires_device_slot: true,
            },
        )
        .await,
        Err(gateway::Error::Refused)
    ));
    assert!(matches!(
        gateway::reserve(
            &worker_pool,
            Call {
                reservation: Reservation {
                    id: &r1,
                    scope_id: &scope,
                    actor: &alice.user,
                    approval: &alice.approval,
                },
                installation: INSTALL,
                model: "a",
                units: 100,
                authority: Authority::Lease {
                    run: &r1,
                    round: 2,
                    token: &claim1.claim_token,
                },
            },
        )
        .await,
        Err(gateway::Error::Refused)
    ));

    // 4. Cancelling run with live lease (quota_unwind_superseded_round passes, then
    // quota_prepare_turn_round raises P0002) maps to Error::Refused on both paths.
    sqlx::query(
        "UPDATE openmettle.runs
            SET lease_expires_at = clock_timestamp() + interval '1 minute'
          WHERE id = $1::uuid",
    )
    .bind(&r1)
    .execute(&mut owner)
    .await
    .unwrap();
    let actor = authz_store::principal(&db, &alice).await;
    authz_queue::cancel_run(&mut api, &actor, &scope, &r1)
        .await
        .unwrap();
    assert!(matches!(
        gateway::reserve_turn_round(
            &worker_pool,
            TurnRound {
                scope_id: &scope,
                actor: &alice.user,
                approval: &alice.approval,
                run_id: &r1,
                round: 3,
                claim_token: &claim1.claim_token,
                installation: INSTALL,
                model: "a",
                round_tokens: 100,
                round_cost: None,
                cost_bound: None,
                requires_device_slot: true,
            },
        )
        .await,
        Err(gateway::Error::Refused)
    ));
    assert!(matches!(
        gateway::reserve(
            &worker_pool,
            Call {
                reservation: Reservation {
                    id: &r1,
                    scope_id: &scope,
                    actor: &alice.user,
                    approval: &alice.approval,
                },
                installation: INSTALL,
                model: "a",
                units: 100,
                authority: Authority::Lease {
                    run: &r1,
                    round: 3,
                    token: &claim1.claim_token,
                },
            },
        )
        .await,
        Err(gateway::Error::Refused)
    ));

    leases::settle(&mut worker, &claim1.lease(), &lease_cfg, Settle::Stopped)
        .await
        .unwrap();

    // 5. Public gateway::reserve + Pending::handoff on a leased run with a persisted 'held'
    // device_reservations row MUST fail closed with Error::Refused (OMQ04), rolling back
    // gateway_requests to 'reserved' so release() returns true. Once quota_commit_device_handoff
    // commits a grant on that device hold, a subsequent gateway::reserve + Pending::handoff
    // succeeds cleanly.
    let mut tx2 = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted { run_id: r2, .. } = authz_queue::admit_run(
        &mut tx2,
        &RunAdmission {
            input: RunInput {
                scope: &scope,
                actor: &alice.user,
                conversation: &chat,
                branch: &branch,
                message: &msg,
                key: "rr10-pending-device-handoff",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot(100),
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(1),
            now_ms: authz_store::NOW,
            cost_qualified: None,
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("expected admission");
    };
    assert!(
        quotas::reserve_admitted_run_budget(
            &mut tx2,
            &RunBudgetReservation {
                scope_id: &scope,
                scope_kind: "personal",
                actor_user_id: &alice.user,
                actor_approval_id: &alice.approval,
                run_id: &r2,
                token_units: 100,
                per_round_cost_micros: None,
                round_limit: 1,
                requires_device_slot: true,
            },
        )
        .await
        .unwrap()
        .is_none()
    );
    tx2.commit().await.unwrap();
    let claim2 = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim2.run_id, r2);

    let pending_blocked = gateway::reserve(
        &worker_pool,
        Call {
            reservation: Reservation {
                id: &r2,
                scope_id: &scope,
                actor: &alice.user,
                approval: &alice.approval,
            },
            installation: INSTALL,
            model: "a",
            units: 100,
            authority: Authority::Lease {
                run: &r2,
                round: 1,
                token: &claim2.claim_token,
            },
        },
    )
    .await
    .unwrap();
    let dev_fx = TurnHandoffFixture::chat(INSTALL, "a", 100, None, true);
    let resp_dev_fx = TurnHandoffFixture::new(
        INSTALL,
        openmettle_core::provider_http::inference::Protocol::Responses,
        "a",
        100,
        None,
        true,
    );
    assert!(matches!(
        pending_blocked
            .handoff(&worker_pool, &keys, &dev_fx.billable(), dev_fx.prepare())
            .await,
        Err(gateway::Error::Refused)
    ));
    let blocked_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.gateway_requests WHERE id = $1::uuid")
            .bind(&pending_blocked.id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(blocked_state, "reserved");
    assert!(pending_blocked.release(&worker_pool).await.unwrap());
    let released_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.gateway_requests WHERE id = $1::uuid")
            .bind(&pending_blocked.id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(released_state, "released");

    // Commit the run's device_reservations grant, then verify Pending::handoff still rejects a
    // cross-gateway PreparedRequest before commit and succeeds with the matching route.
    let dev_hold_id: String = sqlx::query_scalar(
        "SELECT id::text FROM openmettle.quota_reservations
          WHERE scope_id = $1::uuid AND run_id = $2::uuid
            AND gateway_request_id IS NULL AND resource_kind = 'device_reservations'",
    )
    .bind(&scope)
    .bind(&r2)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let committed: bool = sqlx::query_scalar(
        "SELECT openmettle.quota_commit_device_handoff($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid)",
    )
    .bind(&dev_hold_id)
    .bind(&scope)
    .bind(&r2)
    .bind(&claim2.claim_token)
    .bind(GRANT_OK)
    .fetch_one(&mut worker)
    .await
    .unwrap();
    assert!(committed);

    let pending_ok = gateway::reserve(
        &worker_pool,
        Call {
            reservation: Reservation {
                id: &r2,
                scope_id: &scope,
                actor: &alice.user,
                approval: &alice.approval,
            },
            installation: INSTALL,
            model: "a",
            units: 100,
            authority: Authority::Lease {
                run: &r2,
                round: 1,
                token: &claim2.claim_token,
            },
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        pending_ok
            .handoff(
                &worker_pool,
                &keys,
                &resp_dev_fx.billable(),
                dev_fx.prepare()
            )
            .await,
        Err(gateway::Error::Refused)
    ));
    let cross_gw_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.gateway_requests WHERE id = $1::uuid")
            .bind(&pending_ok.id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(cross_gw_state, "reserved");
    let _disp_ok: gateway::BillableDispatch<'_> = pending_ok
        .handoff(&worker_pool, &keys, &dev_fx.billable(), dev_fx.prepare())
        .await
        .unwrap();
    let ok_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.gateway_requests WHERE id = $1::uuid")
            .bind(&pending_ok.id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(ok_state, "handed_off");

    let report_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    assert_eq!(
        settlement::ingest(
            &g_pool,
            &UsageReport {
                request: pending_ok.id.clone(),
                installation: INSTALL.into(),
                principal: PRINCIPAL.into(),
                scope: scope.clone(),
                source: report_source.clone(),
                report_id,
                revision: 0,
                r#final: true,
                prompt_tokens: Some(40),
                completion_tokens: Some(20),
                reasoning_tokens: None,
                reasoning_included: None,
                cost: None,
                unit: None,
            },
        )
        .await
        .unwrap(),
        settlement::Outcome::Applied
    );
    leases::settle(&mut worker, &claim2.lease(), &lease_cfg, Settle::Succeeded)
        .await
        .unwrap();
    // Committed device slot remains handoff_committed with its grant even after terminal settle
    // until durable device-release evidence exists (OMQ06).
    let dev_after: (String, Option<String>) = sqlx::query_as(
        "SELECT state, device_grant_id::text FROM openmettle.quota_reservations WHERE id = $1::uuid",
    )
    .bind(&dev_hold_id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        dev_after,
        ("handoff_committed".into(), Some(GRANT_OK.into()))
    );
    assert_eq!(
        sqlstate(
            sqlx::query("SELECT openmettle.quota_release_device_slot($1::uuid, $2::uuid)")
                .bind(&dev_hold_id)
                .bind(GRANT_OK)
                .execute(&mut worker)
                .await
        ),
        "OMQ06"
    );

    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn mid_reservation_and_pre_handoff_metering_activation_retries_and_materializes_holds() {
    use openmettle_core::{
        authz::{
            gateway::{self, TurnRound, settlement},
            leases::{self, LeaseSettings, Settle},
            runs::{self as authz_queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
        },
        provider_http::gateway::UsageReport,
        provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
        runs::{RunInput, WriteTransaction},
    };
    use sqlx::postgres::PgPoolOptions;

    const INSTALL: &str = "00000000-0000-4000-8000-0000000000b1";
    const PRINCIPAL: &str = "00000000-0000-4000-8000-0000000000b2";
    const BUDGET: &str = "00000000-0000-4000-8000-0000000000b3";
    const GRANT_1: &str = "00000000-0000-4000-8000-00000000db01";
    const GRANT_2: &str = "00000000-0000-4000-8000-00000000db02";
    const KEY_BYTES: [u8; 32] = [111u8; 32];
    const ADVISORY_KEY: i64 = 991_102;

    let limits = AdmissionLimits {
        live_per_actor: 8,
        live_per_scope: 8,
        queued_in_instance: 32,
        queue_timeout: Duration::from_secs(300),
        round_cap: 4,
    };
    let lease_cfg = LeaseSettings {
        lease: Duration::from_secs(60),
        execution_timeout: Duration::from_secs(600),
    };
    let claim_cfg = ClaimLimits {
        executing_per_actor: 4,
        executing_per_scope: 8,
    };

    // Part A: metering_enforced flips false -> true deterministically AFTER
    // quota_prepare_turn_round(..., false) returns early and BEFORE quotas::bind_request runs.
    // reserve_turn_round must roll back Attempt 1 and retry with force_holds = true, creating
    // all parent + child holds cleanly with zero P0002/Database error.
    {
        let db = TestDb::new().await;
        let settings = db.settings(Duration::from_secs(10));
        migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
        let mut owner = connect(&db.0, OWNER).await;
        authz_store::providers(&mut owner).await;
        let alice =
            authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE)
                .await;
        let scope = authz_runs::personal_of(&db, &alice).await;
        migrate::apply(&settings, MIGRATIONS).await.unwrap();

        owner
            .execute(
                "UPDATE openmettle.quota_defaults
                    SET cost_denomination = 'usd_micros'
                  WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros'",
            )
            .await
            .unwrap();
        owner
            .execute(
                "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
                 VALUES ('personal', 'usage_tokens', 100000),
                        ('personal', 'usage_cost_micros', 5000),
                        ('personal', 'device_reservations', 1)",
            )
            .await
            .unwrap();

        let g_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with(db.1.options(pg::GATEWAY));
        let binding: String = sqlx::query_scalar(
            "INSERT INTO openmettle.gateway_bindings (installation, user_id, principal, budget)
             VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid) RETURNING id::text",
        )
        .bind(INSTALL)
        .bind(&alice.user)
        .bind(PRINCIPAL)
        .bind(BUDGET)
        .fetch_one(&g_pool)
        .await
        .unwrap();
        let report_source: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut owner)
            .await
            .unwrap();
        let (finger, env) = GatewaySealer::new(
            GatewayKeys::new(&[("rr11-k1".into(), KEY_BYTES)]).unwrap(),
            g_pool.clone(),
        )
        .seal(
            &Context {
                installation: INSTALL,
                user_id: &alice.user,
                binding_id: &binding,
                principal: PRINCIPAL,
                generation: 1,
            },
            &Bearer::new(b"rr11-bearer-a").unwrap(),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_generations
                 (binding_id, generation, remote_key, expires_at, key_id, key_fingerprint, nonce, ciphertext)
             VALUES ($1::uuid, 1, gen_random_uuid(), clock_timestamp() + interval '1 hour', $2, $3, $4, $5)",
        )
        .bind(&binding)
        .bind(&env.key_id)
        .bind(finger.as_slice())
        .bind(env.nonce.as_slice())
        .bind(env.ciphertext)
        .execute(&g_pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_policy
                 (binding_id, revision, scope_id, approval_id, model, report_source,
                  provider_generation, approval_generation, user_generation, capabilities)
             VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'a', $4::uuid, 0, 0, 0, '{}'::jsonb)",
        )
        .bind(&binding)
        .bind(&scope)
        .bind(&alice.approval)
        .bind(&report_source)
        .execute(&g_pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_bindings
                SET active_generation = 1, observed_revision = 1, state = 'ready'
              WHERE id = $1::uuid",
        )
        .bind(&binding)
        .execute(&g_pool)
        .await
        .unwrap();

        let mut api = connect(&db.0, API).await;
        let mut worker = connect(&db.0, WORKER).await;
        let worker_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with(db.1.options(WORKER));
        let chat = authz_runs::chat(&db, &scope, "personal", &alice).await;
        let (branch, msg) = branch_and_message(&mut api, &scope, &chat).await;
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        let Admission::Admitted { run_id: r1, .. } = authz_queue::admit_run(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope: &scope,
                    actor: &alice.user,
                    conversation: &chat,
                    branch: &branch,
                    message: &msg,
                    key: "rr11-mid-reserve-activation",
                    format: "openmettle.conversation",
                    version: 1,
                    input: b"{}",
                    config: &snapshot_priced(
                        "a",
                        100,
                        Some(openmettle_core::model_config::CostBound {
                            fixed_micros: 100,
                            micros_per_token: 2,
                        }),
                    ),
                },
                actor_approval_id: &alice.approval,
                capabilities: &[],
                requested_rounds: Some(1),
                now_ms: authz_store::NOW,
                cost_qualified: Some(true),
            },
            &limits,
        )
        .await
        .unwrap() else {
            panic!("expected admission");
        };
        tx.commit().await.unwrap();
        let claim1 = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claim1.run_id, r1);

        // Pause Attempt 1 deterministically inside INSERT INTO openmettle.gateway_requests (strictly
        // AFTER quota_prepare_turn_round(..., false) returned without parent holds and BEFORE
        // quotas::bind_request reads metering_enforced).
        owner
            .execute(
                r#"CREATE FUNCTION openmettle.test_pause_before_bind()
                   RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
                   BEGIN
                       IF NOT (SELECT metering_enforced FROM openmettle.quota_enforcement WHERE id) THEN
                           PERFORM pg_catalog.pg_advisory_lock(991102);
                           PERFORM pg_catalog.pg_advisory_unlock(991102);
                       END IF;
                       RETURN NEW;
                   END;
                   $$;
                   CREATE TRIGGER test_pause_before_bind_trg
                       BEFORE INSERT ON openmettle.gateway_requests
                       FOR EACH ROW EXECUTE FUNCTION openmettle.test_pause_before_bind();"#,
            )
            .await
            .unwrap();
        let mut owner_lock = connect(&db.0, OWNER).await;
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(ADVISORY_KEY)
            .execute(&mut owner_lock)
            .await
            .unwrap();

        let wp_c = worker_pool.clone();
        let scope_c = scope.clone();
        let actor_c = alice.user.clone();
        let approval_c = alice.approval.clone();
        let run_c = r1.clone();
        let claim_tok = claim1.claim_token.clone();
        let reserve_task = tokio::spawn(async move {
            gateway::reserve_turn_round(
                &wp_c,
                TurnRound {
                    scope_id: &scope_c,
                    actor: &actor_c,
                    approval: &approval_c,
                    run_id: &run_c,
                    round: 1,
                    claim_token: &claim_tok,
                    installation: INSTALL,
                    model: "a",
                    round_tokens: 100,
                    round_cost: Some(300),
                    cost_bound: Some(openmettle_core::model_config::CostBound {
                        fixed_micros: 100,
                        micros_per_token: 2,
                    }),
                    requires_device_slot: true,
                },
            )
            .await
        });

        // Wait until Attempt 1 is parked inside INSERT INTO gateway_requests on the advisory lock.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                     SELECT 1 FROM pg_locks
                      WHERE locktype = 'advisory'
                        AND objid = $1::int
                        AND NOT granted
                 )",
            )
            .bind(ADVISORY_KEY as i32)
            .fetch_one(&mut owner)
            .await
            .unwrap();
            if waiting {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "reserve_turn_round did not reach test pause trigger"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Flip metering_enforced = true BEFORE unblocking Attempt 1 into bind_request.
        owner
            .execute(
                "UPDATE openmettle.quota_enforcement
                    SET metering_enforced = true, metering_enforced_at = clock_timestamp()
                  WHERE id AND NOT metering_enforced",
            )
            .await
            .unwrap();
        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(ADVISORY_KEY)
            .execute(&mut owner_lock)
            .await
            .unwrap();

        let pending = reserve_task
            .await
            .unwrap()
            .expect("mid-reservation activation must retry and materialize parent + child holds");
        let parents: Vec<(String, i64, i64)> = sqlx::query_as(
            "SELECT resource_kind, reserved_units, held_units
               FROM openmettle.quota_reservations
              WHERE run_id = $1::uuid AND gateway_request_id IS NULL
              ORDER BY resource_kind",
        )
        .bind(&r1)
        .fetch_all(&mut owner)
        .await
        .unwrap();
        assert_eq!(
            parents,
            vec![
                ("device_reservations".into(), 1, 1),
                ("usage_cost_micros".into(), 300, 0),
                ("usage_tokens".into(), 100, 0),
            ]
        );
        let children: Vec<(String, i64, String)> = sqlx::query_as(
            "SELECT resource_kind, held_units, state
               FROM openmettle.quota_reservations
              WHERE gateway_request_id = $1::uuid
              ORDER BY resource_kind",
        )
        .bind(&pending.id)
        .fetch_all(&mut owner)
        .await
        .unwrap();
        assert_eq!(
            children,
            vec![
                ("usage_cost_micros".into(), 300, "held".into()),
                ("usage_tokens".into(), 100, "held".into()),
            ]
        );
        let fx = TurnHandoffFixture::chat_priced(
            INSTALL,
            "a",
            100,
            openmettle_core::model_config::CostBound {
                fixed_micros: 100,
                micros_per_token: 2,
            },
            true,
        );
        let _disp = pending
            .handoff(&worker_pool, Some(GRANT_1), &fx.billable(), fx.prepare())
            .await
            .unwrap();
        let report_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut owner)
            .await
            .unwrap();
        dispatched(&mut owner, &pending.id).await;
        assert_eq!(
            settlement::ingest(
                &g_pool,
                &UsageReport {
                    request: pending.id.clone(),
                    installation: INSTALL.into(),
                    principal: alice.user.clone(),
                    scope: scope.clone(),
                    source: INSTALL.into(),
                    report_id,
                    revision: 1,
                    r#final: true,
                    prompt_tokens: Some(40),
                    completion_tokens: Some(20),
                    reasoning_tokens: None,
                    reasoning_included: None,
                    cost: None,
                    unit: None,
                },
            )
            .await
            .unwrap(),
            settlement::Outcome::Applied
        );
        leases::settle(&mut worker, &claim1.lease(), &lease_cfg, Settle::Succeeded)
            .await
            .unwrap();
        let drift: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
               FROM openmettle.quota_verify_accounting_drift()",
        )
        .fetch_one(&mut worker)
        .await
        .unwrap();
        assert_eq!(drift, (0, 0, 0, 0));
    }

    // Part B: metering_enforced flips false -> true AFTER reserve_turn_round commits and BEFORE
    // TurnPending::handoff runs. First handoff fails closed with Error::Refused, release() unwinds
    // the unsent row, and retrying reserve_turn_round + handoff on the same round materializes
    // all holds and succeeds cleanly.
    {
        let db = TestDb::new().await;
        let settings = db.settings(Duration::from_secs(10));
        migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
        let mut owner = connect(&db.0, OWNER).await;
        authz_store::providers(&mut owner).await;
        let bob =
            authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE)
                .await;
        let scope = authz_runs::personal_of(&db, &bob).await;
        migrate::apply(&settings, MIGRATIONS).await.unwrap();

        owner
            .execute(
                "UPDATE openmettle.quota_defaults
                    SET cost_denomination = 'usd_micros'
                  WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros'",
            )
            .await
            .unwrap();
        owner
            .execute(
                "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
                 VALUES ('personal', 'usage_tokens', 100000),
                        ('personal', 'usage_cost_micros', 5000),
                        ('personal', 'device_reservations', 1)",
            )
            .await
            .unwrap();

        let g_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with(db.1.options(pg::GATEWAY));
        let binding: String = sqlx::query_scalar(
            "INSERT INTO openmettle.gateway_bindings (installation, user_id, principal, budget)
             VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid) RETURNING id::text",
        )
        .bind(INSTALL)
        .bind(&bob.user)
        .bind(PRINCIPAL)
        .bind(BUDGET)
        .fetch_one(&g_pool)
        .await
        .unwrap();
        let report_source: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut owner)
            .await
            .unwrap();
        let (finger, env) = GatewaySealer::new(
            GatewayKeys::new(&[("rr11-k2".into(), KEY_BYTES)]).unwrap(),
            g_pool.clone(),
        )
        .seal(
            &Context {
                installation: INSTALL,
                user_id: &bob.user,
                binding_id: &binding,
                principal: PRINCIPAL,
                generation: 1,
            },
            &Bearer::new(b"rr11-bearer-b").unwrap(),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_generations
                 (binding_id, generation, remote_key, expires_at, key_id, key_fingerprint, nonce, ciphertext)
             VALUES ($1::uuid, 1, gen_random_uuid(), clock_timestamp() + interval '1 hour', $2, $3, $4, $5)",
        )
        .bind(&binding)
        .bind(&env.key_id)
        .bind(finger.as_slice())
        .bind(env.nonce.as_slice())
        .bind(env.ciphertext)
        .execute(&g_pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_policy
                 (binding_id, revision, scope_id, approval_id, model, report_source,
                  provider_generation, approval_generation, user_generation, capabilities)
             VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'a', $4::uuid, 0, 0, 0, '{}'::jsonb)",
        )
        .bind(&binding)
        .bind(&scope)
        .bind(&bob.approval)
        .bind(&report_source)
        .execute(&g_pool)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_bindings
                SET active_generation = 1, observed_revision = 1, state = 'ready'
              WHERE id = $1::uuid",
        )
        .bind(&binding)
        .execute(&g_pool)
        .await
        .unwrap();

        let mut api = connect(&db.0, API).await;
        let mut worker = connect(&db.0, WORKER).await;
        let worker_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with(db.1.options(WORKER));
        let chat = authz_runs::chat(&db, &scope, "personal", &bob).await;
        let (branch, msg) = branch_and_message(&mut api, &scope, &chat).await;
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        let Admission::Admitted { run_id: r2, .. } = authz_queue::admit_run(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope: &scope,
                    actor: &bob.user,
                    conversation: &chat,
                    branch: &branch,
                    message: &msg,
                    key: "rr11-pre-handoff-activation",
                    format: "openmettle.conversation",
                    version: 1,
                    input: b"{}",
                    config: &snapshot_priced(
                        "a",
                        100,
                        Some(openmettle_core::model_config::CostBound {
                            fixed_micros: 100,
                            micros_per_token: 2,
                        }),
                    ),
                },
                actor_approval_id: &bob.approval,
                capabilities: &[],
                requested_rounds: Some(1),
                now_ms: authz_store::NOW,
                cost_qualified: Some(true),
            },
            &limits,
        )
        .await
        .unwrap() else {
            panic!("expected admission");
        };
        tx.commit().await.unwrap();
        let claim2 = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(claim2.run_id, r2);

        let p_pre = gateway::reserve_turn_round(
            &worker_pool,
            TurnRound {
                scope_id: &scope,
                actor: &bob.user,
                approval: &bob.approval,
                run_id: &r2,
                round: 1,
                claim_token: &claim2.claim_token,
                installation: INSTALL,
                model: "a",
                round_tokens: 100,
                round_cost: Some(300),
                cost_bound: Some(openmettle_core::model_config::CostBound {
                    fixed_micros: 100,
                    micros_per_token: 2,
                }),
                requires_device_slot: true,
            },
        )
        .await
        .unwrap();
        // Activate metering_enforced AFTER reserve_turn_round committed without holds.
        owner
            .execute(
                "UPDATE openmettle.quota_enforcement
                    SET metering_enforced = true, metering_enforced_at = clock_timestamp()
                  WHERE id AND NOT metering_enforced",
            )
            .await
            .unwrap();
        let fx = TurnHandoffFixture::chat_priced(
            INSTALL,
            "a",
            100,
            openmettle_core::model_config::CostBound {
                fixed_micros: 100,
                micros_per_token: 2,
            },
            true,
        );
        assert!(matches!(
            p_pre
                .handoff(&worker_pool, Some(GRANT_2), &fx.billable(), fx.prepare(),)
                .await,
            Err(gateway::Error::Refused)
        ));
        assert!(p_pre.release(&worker_pool).await.unwrap());

        // Retrying reserve_turn_round + handoff on round 1 materializes all holds and dispatches.
        let p_retry = gateway::reserve_turn_round(
            &worker_pool,
            TurnRound {
                scope_id: &scope,
                actor: &bob.user,
                approval: &bob.approval,
                run_id: &r2,
                round: 1,
                claim_token: &claim2.claim_token,
                installation: INSTALL,
                model: "a",
                round_tokens: 100,
                round_cost: Some(300),
                cost_bound: Some(openmettle_core::model_config::CostBound {
                    fixed_micros: 100,
                    micros_per_token: 2,
                }),
                requires_device_slot: true,
            },
        )
        .await
        .unwrap();
        let _disp = p_retry
            .handoff(&worker_pool, Some(GRANT_2), &fx.billable(), fx.prepare())
            .await
            .unwrap();
        let report_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut owner)
            .await
            .unwrap();
        dispatched(&mut owner, &p_retry.id).await;
        assert_eq!(
            settlement::ingest(
                &g_pool,
                &UsageReport {
                    request: p_retry.id.clone(),
                    installation: INSTALL.into(),
                    principal: bob.user.clone(),
                    scope: scope.clone(),
                    source: INSTALL.into(),
                    report_id,
                    revision: 1,
                    r#final: true,
                    prompt_tokens: Some(45),
                    completion_tokens: Some(15),
                    reasoning_tokens: None,
                    reasoning_included: None,
                    cost: None,
                    unit: None,
                },
            )
            .await
            .unwrap(),
            settlement::Outcome::Applied
        );
        leases::settle(&mut worker, &claim2.lease(), &lease_cfg, Settle::Succeeded)
            .await
            .unwrap();
        let drift: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
               FROM openmettle.quota_verify_accounting_drift()",
        )
        .fetch_one(&mut worker)
        .await
        .unwrap();
        assert_eq!(drift, (0, 0, 0, 0));
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn override_expiring_during_budget_lock_wait_is_refused_by_post_lock_clock_timestamp() {
    use sqlx::postgres::PgPoolOptions;

    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    let mut owner_lock = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let scope = authz_runs::personal_of(&db, &alice).await;

    // 1. quota_reserve + quota_limit: default personal usage_tokens = 500; seed quota_budgets row
    //    via a tiny reserve + release, then add a short-lived 2000-token override (+180ms).
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 500)",
        )
        .await
        .unwrap();
    let api_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(API));
    let seed_hold: String = sqlx::query_scalar(
        "SELECT openmettle.quota_reserve(
             $1::uuid, $2::uuid, 'usage_tokens', 1, 'seed-lock-wait',
             NULL, NULL, NULL, clock_timestamp() + interval '5 minutes'
         )::text",
    )
    .bind(&scope)
    .bind(&alice.user)
    .fetch_one(&api_pool)
    .await
    .unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT openmettle.quota_release_unsent($1::uuid)")
            .bind(&seed_hold)
            .fetch_one(&api_pool)
            .await
            .unwrap()
    );

    sqlx::query(
        "INSERT INTO openmettle.quota_overrides
             (scope_id, scope_kind, resource_kind, hard_limit, expires_at, reason, updated_by_user_id)
         VALUES ($1::uuid, 'personal', 'usage_tokens', 2000,
                 clock_timestamp() + interval '250 milliseconds', 'lock-wait-override', $2::uuid)",
    )
    .bind(&scope)
    .bind(&alice.user)
    .execute(&mut owner)
    .await
    .unwrap();

    // Connection 1 locks the personal quota_budgets row while the 2000-token override is STILL active.
    let lock_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut owner_lock)
        .await
        .unwrap();
    let mut lock_tx = owner_lock.begin().await.unwrap();
    sqlx::query(
        "SELECT id FROM openmettle.quota_budgets
          WHERE target_kind = 'scope' AND scope_id = $1::uuid
            AND resource_kind = 'usage_tokens'
            FOR UPDATE",
    )
    .bind(&scope)
    .fetch_one(&mut *lock_tx)
    .await
    .unwrap();

    // Connection 2 enters quota_reserve BEFORE expiry (statement_timestamp() sees override active)
    // and blocks on the quota_budgets row lock held by Connection 1.
    let api_pool_c = api_pool.clone();
    let scope_c = scope.clone();
    let user_c = alice.user.clone();
    let reserve_task = tokio::spawn(async move {
        sqlx::query_scalar::<_, String>(
            "SELECT openmettle.quota_reserve(
                 $1::uuid, $2::uuid, 'usage_tokens', 1000, 'lock-wait-expiry-check',
                 NULL, NULL, NULL, clock_timestamp() + interval '5 minutes'
             )::text",
        )
        .bind(&scope_c)
        .bind(&user_c)
        .fetch_one(&api_pool_c)
        .await
    });

    // Wait until Connection 2 is blocked on Connection 1's transaction lock inside quota_reserve.
    let wait_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1
                   FROM pg_locks waiter
                   JOIN pg_locks holder
                     ON holder.locktype = waiter.locktype
                    AND holder.transactionid = waiter.transactionid
                    AND holder.granted
                    AND holder.pid = $1
                  WHERE waiter.locktype = 'transactionid'
                    AND NOT waiter.granted
             )",
        )
        .bind(lock_pid)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        if blocked {
            break;
        }
        assert!(
            Instant::now() < wait_deadline,
            "quota_reserve did not block on quota_budgets lock"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Hold the lock until clock_timestamp() strictly passes the override's expires_at.
    let exp_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let expired: bool = sqlx::query_scalar(
            "SELECT clock_timestamp() > expires_at
               FROM openmettle.quota_overrides
              WHERE scope_id = $1::uuid AND resource_kind = 'usage_tokens'",
        )
        .bind(&scope)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        if expired {
            break;
        }
        assert!(Instant::now() < exp_deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // Release the lock: Connection 2 re-evaluates quota_limit() at post-lock clock_timestamp(),
    // sees the expired override, and MUST fail closed with OMQ01 against default 500!
    lock_tx.rollback().await.unwrap();
    let reserve_res = reserve_task.await.unwrap();
    assert_eq!(
        sqlstate(reserve_res),
        "OMQ01",
        "override expired during budget lock wait must fail closed against restored default"
    );

    // 2. quota_record_storage_warning: hold storage_accounts FOR UPDATE across storage override
    //    expiry so post-lock clock_timestamp() sees default 1000 bytes (850/1000 = 85% >= 80%) and
    //    emits the warning at limit_revision = 0 instead of using pre-wait statement_timestamp().
    owner
        .execute(
            "UPDATE openmettle.storage_instance
                SET instance_budget_bytes = 100000, personal_limit_bytes = 1000, project_limit_bytes = 1000",
        )
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.storage_accounts (scope_id, active_bytes, retained_bytes, reserved_bytes)
         VALUES ($1::uuid, 850, 0, 0)
         ON CONFLICT (scope_id) DO UPDATE SET active_bytes = 850, retained_bytes = 0, reserved_bytes = 0",
    )
    .bind(&scope)
    .execute(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.quota_overrides
             (scope_id, scope_kind, resource_kind, hard_limit, expires_at, reason, updated_by_user_id)
         VALUES ($1::uuid, 'personal', 'storage_bytes', 10000,
                 clock_timestamp() + interval '250 milliseconds', 'storage-lock-wait-override', $2::uuid)",
    )
    .bind(&scope)
    .bind(&alice.user)
    .execute(&mut owner)
    .await
    .unwrap();

    let mut s_lock_tx = owner_lock.begin().await.unwrap();
    sqlx::query(
        "SELECT scope_id FROM openmettle.storage_accounts WHERE scope_id = $1::uuid FOR UPDATE",
    )
    .bind(&scope)
    .fetch_one(&mut *s_lock_tx)
    .await
    .unwrap();

    let scope_s = scope.clone();
    let warn_task = tokio::spawn(async move {
        sqlx::query("SELECT openmettle.quota_record_storage_warning($1::uuid, 850)")
            .bind(&scope_s)
            .execute(&api_pool)
            .await
    });

    let sw_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1
                   FROM pg_locks waiter
                   JOIN pg_locks holder
                     ON holder.locktype = waiter.locktype
                    AND holder.transactionid = waiter.transactionid
                    AND holder.granted
                    AND holder.pid = $1
                  WHERE waiter.locktype = 'transactionid'
                    AND NOT waiter.granted
             )",
        )
        .bind(lock_pid)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        if blocked {
            break;
        }
        assert!(Instant::now() < sw_deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let sexp_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let expired: bool = sqlx::query_scalar(
            "SELECT clock_timestamp() > expires_at
               FROM openmettle.quota_overrides
              WHERE scope_id = $1::uuid AND resource_kind = 'storage_bytes'",
        )
        .bind(&scope)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        if expired {
            break;
        }
        assert!(Instant::now() < sexp_deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    s_lock_tx.rollback().await.unwrap();
    warn_task.await.unwrap().unwrap();

    let warn_revs: Vec<i64> = sqlx::query_scalar(
        "SELECT limit_revision FROM openmettle.quota_warning_events
          WHERE scope_id = $1::uuid AND resource_kind = 'storage_bytes' AND threshold_pct = 80",
    )
    .bind(&scope)
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        warn_revs,
        vec![0],
        "post-lock clock_timestamp() must see expired storage override and emit default 80% warning at limit_revision = 0"
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn two_pass_quota_reserve_post_lock_expiry_for_instance_wait_omq05_and_optional_project() {
    use sqlx::postgres::PgPoolOptions;

    let wait_blocked_on = async |owner: &mut PgConnection, lock_pid: i32| {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                     SELECT 1
                       FROM pg_locks waiter
                       JOIN pg_locks holder
                         ON holder.locktype = waiter.locktype
                        AND holder.transactionid = waiter.transactionid
                        AND holder.granted
                        AND holder.pid = $1
                      WHERE waiter.locktype = 'transactionid'
                        AND NOT waiter.granted
                 )",
            )
            .bind(lock_pid)
            .fetch_one(&mut *owner)
            .await
            .unwrap();
            if blocked {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "quota_reserve did not block on lock_pid={lock_pid}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    let expire_override = async |owner: &mut PgConnection, scope: &str, resource: &str| {
        sqlx::query(
            "UPDATE openmettle.quota_overrides
                SET expires_at = clock_timestamp() - interval '1 second'
              WHERE scope_id = $1::uuid AND resource_kind = $2",
        )
        .bind(scope)
        .bind(resource)
        .execute(&mut *owner)
        .await
        .unwrap();
    };
    let err_code_detail = |res: Result<String, sqlx::Error>| -> (String, Option<String>) {
        let err = res.expect_err("expected database error");
        let db_err = err.as_database_error().expect("pg database error");
        (
            db_err.code().unwrap_or_default().into_owned(),
            db_err
                .try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
                .and_then(|e| e.detail())
                .map(str::to_owned),
        )
    };

    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    let mut owner_lock = connect(&db.0, OWNER).await;
    let lock_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut owner_lock)
        .await
        .unwrap();
    authz_store::providers(&mut owner).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let personal_scope = authz_runs::personal_of(&db, &alice).await;
    let (_, project_scope) = project(&mut connect(&db.0, API).await, &alice.user).await;
    let api_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(API));

    // 1. Personal override expires while waiting on the INSTANCE budget lock -> OMQ01 (DETAIL=personal).
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 500),
                    ('instance', 'usage_tokens', 50000)",
        )
        .await
        .unwrap();
    let seed1: String = sqlx::query_scalar(
        "SELECT openmettle.quota_reserve(
             $1::uuid, $2::uuid, 'usage_tokens', 1, 'rr13-seed-1',
             NULL, NULL, NULL, clock_timestamp() + interval '5 minutes'
         )::text",
    )
    .bind(&personal_scope)
    .bind(&alice.user)
    .fetch_one(&api_pool)
    .await
    .unwrap();
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT openmettle.quota_release_unsent($1::uuid)")
            .bind(&seed1)
            .fetch_one(&api_pool)
            .await
            .unwrap()
    );
    sqlx::query(
        "INSERT INTO openmettle.quota_overrides
             (scope_id, scope_kind, resource_kind, hard_limit, expires_at, reason, updated_by_user_id)
         VALUES ($1::uuid, 'personal', 'usage_tokens', 2000,
                 clock_timestamp() + interval '1 hour', 'rr13-inst-wait', $2::uuid)",
    )
    .bind(&personal_scope)
    .bind(&alice.user)
    .execute(&mut owner)
    .await
    .unwrap();

    // Connection 1 locks ONLY the instance budget row while personal override (2000) is active.
    let mut inst_tx = owner_lock.begin().await.unwrap();
    sqlx::query(
        "SELECT id FROM openmettle.quota_budgets
          WHERE target_kind = 'instance' AND scope_id IS NULL
            AND resource_kind = 'usage_tokens'
            FOR NO KEY UPDATE",
    )
    .fetch_one(&mut *inst_tx)
    .await
    .unwrap();

    let api_c = api_pool.clone();
    let ps_c = personal_scope.clone();
    let u_c = alice.user.clone();
    let t1 = tokio::spawn(async move {
        sqlx::query_scalar::<_, String>(
            "SELECT openmettle.quota_reserve(
                 $1::uuid, $2::uuid, 'usage_tokens', 1000, 'rr13-personal-exp-on-inst-wait',
                 NULL, NULL, NULL, clock_timestamp() + interval '5 minutes'
             )::text",
        )
        .bind(&ps_c)
        .bind(&u_c)
        .fetch_one(&api_c)
        .await
    });
    wait_blocked_on(&mut owner, lock_pid).await;
    expire_override(&mut owner, &personal_scope, "usage_tokens").await;
    inst_tx.rollback().await.unwrap();
    assert_eq!(
        err_code_detail(t1.await.unwrap()),
        ("OMQ01".into(), Some("personal".into())),
        "personal override expiring while waiting on instance lock must fail closed with OMQ01 (personal)"
    );

    // 2. Only personal limit (no personal default) expires while waiting on instance lock ->
    //    MUST raise OMQ05 (DETAIL=personal), NOT 40001.
    owner
        .execute(
            "DELETE FROM openmettle.quota_defaults
              WHERE scope_kind = 'personal' AND resource_kind = 'usage_tokens'",
        )
        .await
        .unwrap();
    sqlx::query(
        "UPDATE openmettle.quota_overrides
            SET hard_limit = 2000,
                expires_at = clock_timestamp() + interval '1 hour'
          WHERE scope_id = $1::uuid AND resource_kind = 'usage_tokens'",
    )
    .bind(&personal_scope)
    .execute(&mut owner)
    .await
    .unwrap();

    let mut inst_tx2 = owner_lock.begin().await.unwrap();
    sqlx::query(
        "SELECT id FROM openmettle.quota_budgets
          WHERE target_kind = 'instance' AND scope_id IS NULL
            AND resource_kind = 'usage_tokens'
            FOR NO KEY UPDATE",
    )
    .fetch_one(&mut *inst_tx2)
    .await
    .unwrap();

    let api_c2 = api_pool.clone();
    let ps_c2 = personal_scope.clone();
    let u_c2 = alice.user.clone();
    let t2 = tokio::spawn(async move {
        sqlx::query_scalar::<_, String>(
            "SELECT openmettle.quota_reserve(
                 $1::uuid, $2::uuid, 'usage_tokens', 1000, 'rr13-only-personal-exp-omq05',
                 NULL, NULL, NULL, clock_timestamp() + interval '5 minutes'
             )::text",
        )
        .bind(&ps_c2)
        .bind(&u_c2)
        .fetch_one(&api_c2)
        .await
    });
    wait_blocked_on(&mut owner, lock_pid).await;
    expire_override(&mut owner, &personal_scope, "usage_tokens").await;
    inst_tx2.rollback().await.unwrap();
    assert_eq!(
        err_code_detail(t2.await.unwrap()),
        ("OMQ05".into(), Some("personal".into())),
        "expiring the sole personal limit during lock wait must raise OMQ05 (personal), not 40001"
    );

    // 3. Optional project override (with project default NULL) expires while waiting on instance
    //    lock -> Pass 1 locks the project budget row, then Pass 2 skips charging project and
    //    succeeds charging personal + instance cleanly!
    sqlx::query(
        "DELETE FROM openmettle.quota_overrides
          WHERE scope_id = $1::uuid AND resource_kind = 'usage_tokens'",
    )
    .bind(&personal_scope)
    .execute(&mut owner)
    .await
    .unwrap();
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 5000)",
        )
        .await
        .unwrap();
    // Pre-create the project budget row (revision = 1, active = 0, held = 0) so a separate
    // connection can observe Pass 1's FOR NO KEY UPDATE lock via NOWAIT (55P03) while blocked.
    sqlx::query(
        "INSERT INTO openmettle.quota_budgets
             (target_kind, scope_id, resource_kind, window_kind, window_start)
         VALUES ('scope', $1::uuid, 'usage_tokens', 'static', 'epoch'::timestamptz)",
    )
    .bind(&project_scope)
    .execute(&mut owner)
    .await
    .unwrap();
    // Active project override (500 < requested 1000) forces Pass 1 to lock the project budget row;
    // expiring it while blocked on instance causes Pass 2 to skip the optional project tier.
    sqlx::query(
        "INSERT INTO openmettle.quota_overrides
             (scope_id, scope_kind, resource_kind, hard_limit, expires_at, reason, updated_by_user_id)
         VALUES ($1::uuid, 'project', 'usage_tokens', 500,
                 clock_timestamp() + interval '1 hour', 'rr13-opt-project-exp', $2::uuid)",
    )
    .bind(&project_scope)
    .bind(&alice.user)
    .execute(&mut owner)
    .await
    .unwrap();

    let mut inst_tx3 = owner_lock.begin().await.unwrap();
    sqlx::query(
        "SELECT id FROM openmettle.quota_budgets
          WHERE target_kind = 'instance' AND scope_id IS NULL
            AND resource_kind = 'usage_tokens'
            FOR NO KEY UPDATE",
    )
    .fetch_one(&mut *inst_tx3)
    .await
    .unwrap();

    let api_c3 = api_pool.clone();
    let proj_c = project_scope.clone();
    let u_c3 = alice.user.clone();
    let t3 = tokio::spawn(async move {
        sqlx::query_scalar::<_, String>(
            "SELECT openmettle.quota_reserve(
                 $1::uuid, $2::uuid, 'usage_tokens', 1000, 'rr13-opt-project-skip',
                 NULL, NULL, NULL, clock_timestamp() + interval '5 minutes'
             )::text",
        )
        .bind(&proj_c)
        .bind(&u_c3)
        .fetch_one(&api_c3)
        .await
    });
    wait_blocked_on(&mut owner, lock_pid).await;

    // While blocked on instance and BEFORE expiring the override, verify Pass 1 holds FOR NO KEY
    // UPDATE on the project budget row (55P03 on NOWAIT) with zero charges yet.
    let proj_counters: (i64, i64, i64) = sqlx::query_as(
        "SELECT active_used::bigint, reserved_held::bigint, revision
           FROM openmettle.quota_budgets
          WHERE scope_id = $1::uuid AND resource_kind = 'usage_tokens'",
    )
    .bind(&project_scope)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(proj_counters, (0, 0, 1));
    assert_eq!(
        sqlstate(
            sqlx::query(
                "SELECT id FROM openmettle.quota_budgets
                  WHERE scope_id = $1::uuid AND resource_kind = 'usage_tokens'
                    FOR NO KEY UPDATE NOWAIT",
            )
            .bind(&project_scope)
            .fetch_one(&mut owner)
            .await
        ),
        "55P03",
        "Pass 1 must hold FOR NO KEY UPDATE on the project budget row before blocking on instance"
    );

    expire_override(&mut owner, &project_scope, "usage_tokens").await;
    inst_tx3.rollback().await.unwrap();
    let hold_id = t3.await.unwrap().expect(
        "expiring optional project override during lock wait must skip project and succeed",
    );

    // After commit, project budget lock is released (NOWAIT succeeds) and its counters & revision
    // are completely untouched (0, 0, 1).
    let proj_after: (i64, i64, i64) = sqlx::query_as(
        "SELECT active_used::bigint, reserved_held::bigint, revision
           FROM openmettle.quota_budgets
          WHERE scope_id = $1::uuid AND resource_kind = 'usage_tokens'
            FOR NO KEY UPDATE NOWAIT",
    )
    .bind(&project_scope)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(proj_after, (0, 0, 1));

    let charge_roles: Vec<String> = sqlx::query_scalar(
        "SELECT charge_role FROM openmettle.quota_reservation_charges
          WHERE reservation_id = $1::uuid
          ORDER BY charge_role ASC",
    )
    .bind(&hold_id)
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        charge_roles,
        vec!["actor_scope".to_owned(), "instance".to_owned()],
        "expired optional project tier must not be charged"
    );
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT openmettle.quota_release_unsent($1::uuid)")
            .bind(&hold_id)
            .fetch_one(&api_pool)
            .await
            .unwrap()
    );
    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut connect(&db.0, WORKER).await)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn reserve_turn_round_returns_retryable_on_40001_and_succeeds_on_retry() {
    use openmettle_core::{
        authz::{
            gateway::{self, TurnRound, settlement},
            leases::{self, LeaseSettings, Settle},
            runs::{self as authz_queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
        },
        provider_http::gateway::UsageReport,
        provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
        runs::{RunInput, WriteTransaction},
    };
    use sqlx::postgres::PgPoolOptions;

    const INSTALL: &str = "00000000-0000-4000-8000-0000000000f1";
    const PRINCIPAL: &str = "00000000-0000-4000-8000-0000000000f2";
    const BUDGET: &str = "00000000-0000-4000-8000-0000000000f3";
    const KEY_BYTES: [u8; 32] = [141u8; 32];

    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    let mut owner_lock = connect(&db.0, OWNER).await;
    let lock_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut owner_lock)
        .await
        .unwrap();
    authz_store::providers(&mut owner).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let (_, project_scope) = run_admission::new_project(&db, &alice, "rr14-retry-project").await;
    let grant_cycle: String = sqlx::query_scalar(
        "SELECT h.cycle_id::text
           FROM openmettle.grant_assignments g
           JOIN openmettle.grant_changes h
             ON h.assignment_id = g.id AND h.revision = g.last_revision
          WHERE g.scope_id = $1::uuid
            AND g.grantee_user_id = $2::uuid
            AND g.target_kind = 'project'
            AND g.assignment_format = 'openmettle.project-role'
            AND g.assignment_key IN ('editor', 'owner')
            AND h.decision = 'grant'
          LIMIT 1",
    )
    .bind(&project_scope)
    .bind(&alice.user)
    .fetch_one(&mut owner)
    .await
    .unwrap();

    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 100000),
                    ('instance', 'usage_tokens', 100000)",
        )
        .await
        .unwrap();
    // Seed the instance budget row so Connection 1 can lock it before reserve_turn_round runs.
    owner
        .execute(
            "INSERT INTO openmettle.quota_budgets
                 (target_kind, scope_id, resource_kind, window_kind, window_start)
             VALUES ('instance', NULL, 'usage_tokens', 'static', 'epoch'::timestamptz)",
        )
        .await
        .unwrap();

    let g_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(pg::GATEWAY));
    let binding: String = sqlx::query_scalar(
        "INSERT INTO openmettle.gateway_bindings (installation, user_id, principal, budget)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid) RETURNING id::text",
    )
    .bind(INSTALL)
    .bind(&alice.user)
    .bind(PRINCIPAL)
    .bind(BUDGET)
    .fetch_one(&g_pool)
    .await
    .unwrap();
    let report_source: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    let (finger, env) = GatewaySealer::new(
        GatewayKeys::new(&[("rr14-k1".into(), KEY_BYTES)]).unwrap(),
        g_pool.clone(),
    )
    .seal(
        &Context {
            installation: INSTALL,
            user_id: &alice.user,
            binding_id: &binding,
            principal: PRINCIPAL,
            generation: 1,
        },
        &Bearer::new(b"rr14-bearer").unwrap(),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_generations
             (binding_id, generation, remote_key, expires_at, key_id, key_fingerprint, nonce, ciphertext)
         VALUES ($1::uuid, 1, gen_random_uuid(), clock_timestamp() + interval '1 hour', $2, $3, $4, $5)",
    )
    .bind(&binding)
    .bind(&env.key_id)
    .bind(finger.as_slice())
    .bind(env.nonce.as_slice())
    .bind(env.ciphertext)
    .execute(&g_pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_policy
             (binding_id, revision, scope_id, approval_id, model, report_source,
              provider_generation, approval_generation, user_generation, capabilities, grant_cycle)
         VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'a', $4::uuid, 0, 0, 0, '{}'::jsonb, $5::uuid)",
    )
    .bind(&binding)
    .bind(&project_scope)
    .bind(&alice.approval)
    .bind(&report_source)
    .bind(&grant_cycle)
    .execute(&g_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.gateway_bindings
            SET active_generation = 1, observed_revision = 1, state = 'ready'
          WHERE id = $1::uuid",
    )
    .bind(&binding)
    .execute(&g_pool)
    .await
    .unwrap();

    // Admit a legacy/pre-activation run in project_scope WITHOUT parent quota holds so
    // reserve_turn_round materializes parent holds through quota_prepare_turn_round -> quota_reserve.
    let mut api = connect(&db.0, API).await;
    let mut worker = connect(&db.0, WORKER).await;
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(WORKER));
    let chat = authz_runs::chat(&db, &project_scope, "project", &alice).await;
    let (branch, msg) = branch_and_message(&mut api, &project_scope, &chat).await;
    let limits = AdmissionLimits {
        live_per_actor: 8,
        live_per_scope: 8,
        queued_in_instance: 32,
        queue_timeout: Duration::from_secs(300),
        round_cap: 4,
    };
    let lease_cfg = LeaseSettings {
        lease: Duration::from_secs(60),
        execution_timeout: Duration::from_secs(600),
    };
    let claim_cfg = ClaimLimits {
        executing_per_actor: 4,
        executing_per_scope: 8,
    };
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted { run_id: r1, .. } = authz_queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &project_scope,
                actor: &alice.user,
                conversation: &chat,
                branch: &branch,
                message: &msg,
                key: "rr14-retryable-40001",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot(200),
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(1),
            now_ms: authz_store::NOW,
            cost_qualified: None,
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("expected admission");
    };
    tx.commit().await.unwrap();
    let claim1 = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim1.run_id, r1);

    // Hold the instance budget lock while project usage_tokens is unconfigured (NULL in Pass 1).
    let mut inst_tx = owner_lock.begin().await.unwrap();
    sqlx::query(
        "SELECT id FROM openmettle.quota_budgets
          WHERE target_kind = 'instance' AND scope_id IS NULL
            AND resource_kind = 'usage_tokens'
            FOR NO KEY UPDATE",
    )
    .fetch_one(&mut *inst_tx)
    .await
    .unwrap();

    let wp_c = worker_pool.clone();
    let proj_c = project_scope.clone();
    let actor_c = alice.user.clone();
    let approval_c = alice.approval.clone();
    let run_c = r1.clone();
    let tok_c = claim1.claim_token.clone();
    let first_task = tokio::spawn(async move {
        gateway::reserve_turn_round(
            &wp_c,
            TurnRound {
                scope_id: &proj_c,
                actor: &actor_c,
                approval: &approval_c,
                run_id: &run_c,
                round: 1,
                claim_token: &tok_c,
                installation: INSTALL,
                model: "a",
                round_tokens: 200,
                round_cost: None,
                cost_bound: None,
                requires_device_slot: false,
            },
        )
        .await
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let blocked: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1
                   FROM pg_locks waiter
                   JOIN pg_locks holder
                     ON holder.locktype = waiter.locktype
                    AND holder.transactionid = waiter.transactionid
                    AND holder.granted
                    AND holder.pid = $1
                  WHERE waiter.locktype = 'transactionid'
                    AND NOT waiter.granted
             )",
        )
        .bind(lock_pid)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        if blocked {
            break;
        }
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Activate an optional project usage_tokens override while reserve_turn_round is blocked on
    // instance -> Pass 2 sees project flip NULL -> NOT NULL without a Pass 1 lock -> 40001 ->
    // gateway::Error::Retryable (NOT Error::Database).
    sqlx::query(
        "INSERT INTO openmettle.quota_overrides
             (scope_id, scope_kind, resource_kind, hard_limit, expires_at, reason, updated_by_user_id)
         VALUES ($1::uuid, 'project', 'usage_tokens', 50000, NULL, 'rr14-mid-wait-project-tier', $2::uuid)",
    )
    .bind(&project_scope)
    .bind(&alice.user)
    .execute(&mut owner)
    .await
    .unwrap();
    inst_tx.rollback().await.unwrap();

    assert!(
        matches!(first_task.await.unwrap(), Err(gateway::Error::Retryable)),
        "40001 from quota_reserve during lock wait must map to gateway::Error::Retryable"
    );

    // Immediate retry on the rolled-back reservation succeeds, charging all 3 tiers cleanly.
    let pending = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &project_scope,
            actor: &alice.user,
            approval: &alice.approval,
            run_id: &r1,
            round: 1,
            claim_token: &claim1.claim_token,
            installation: INSTALL,
            model: "a",
            round_tokens: 200,
            round_cost: None,
            cost_bound: None,
            requires_device_slot: false,
        },
    )
    .await
    .expect("immediate retry after Error::Retryable must succeed");
    let fx = TurnHandoffFixture::chat(INSTALL, "a", 200, None, false);
    let _disp = pending
        .handoff(&worker_pool, None, &fx.billable(), fx.prepare())
        .await
        .unwrap();
    let charge_roles: Vec<String> = sqlx::query_scalar(
        "SELECT c.charge_role
           FROM openmettle.quota_reservation_charges c
           JOIN openmettle.quota_reservations r ON r.id = c.reservation_id
          WHERE r.run_id = $1::uuid AND r.gateway_request_id IS NULL
            AND r.resource_kind = 'usage_tokens'
          ORDER BY c.charge_role ASC",
    )
    .bind(&r1)
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        charge_roles,
        vec![
            "actor_scope".to_owned(),
            "instance".to_owned(),
            "primary_scope".to_owned(),
        ]
    );

    let report_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    dispatched(&mut owner, &pending.id).await;
    assert_eq!(
        settlement::ingest(
            &g_pool,
            &UsageReport {
                request: pending.id.clone(),
                installation: INSTALL.into(),
                principal: alice.user.clone(),
                scope: project_scope.clone(),
                source: INSTALL.into(),
                report_id,
                revision: 1,
                r#final: true,
                prompt_tokens: Some(80),
                completion_tokens: Some(40),
                reasoning_tokens: None,
                reasoning_included: None,
                cost: None,
                unit: None,
            },
        )
        .await
        .unwrap(),
        settlement::Outcome::Applied
    );
    leases::settle(&mut worker, &claim1.lease(), &lease_cfg, Settle::Succeeded)
        .await
        .unwrap();
    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
}
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn replacement_holds_and_cost_slice_account_for_prior_bearer_rounds() {
    use openmettle_core::{
        authz::{
            gateway::{self, TurnRound, settlement},
            leases::{self, LeaseSettings, Settle},
            runs::{self as authz_queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
        },
        provider_http::gateway::UsageReport,
        provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
        runs::{Payload, RunInput, WriteTransaction, append_event},
    };
    use sqlx::postgres::PgPoolOptions;

    const INSTALL: &str = "00000000-0000-4000-8000-0000000000f7";
    const PRINCIPAL: &str = "00000000-0000-4000-8000-0000000000f8";
    const BUDGET: &str = "00000000-0000-4000-8000-0000000000f9";
    const KEY_BYTES: [u8; 32] = [151; 32];

    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let alice_scope = authz_runs::personal_of(&db, &alice).await;
    let bob =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let bob_scope = authz_runs::personal_of(&db, &bob).await;

    // Tight personal defaults of exact 450 tokens and 450 cost micros: fits ONE remaining round
    // (450) but MUST reject an oversized 2-round (900) hold.
    owner
        .execute(
            "UPDATE openmettle.quota_defaults
                SET cost_denomination = 'usd_micros'
              WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros'",
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 450),
                    ('personal', 'usage_cost_micros', 450)",
        )
        .await
        .unwrap();

    let g_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(pg::GATEWAY));
    let binding: String = sqlx::query_scalar(
        "INSERT INTO openmettle.gateway_bindings (installation, user_id, principal, budget)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid) RETURNING id::text",
    )
    .bind(INSTALL)
    .bind(&alice.user)
    .bind(PRINCIPAL)
    .bind(BUDGET)
    .fetch_one(&g_pool)
    .await
    .unwrap();
    let report_source: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    let (finger, env) = GatewaySealer::new(
        GatewayKeys::new(&[("rr15-k1".into(), KEY_BYTES)]).unwrap(),
        g_pool.clone(),
    )
    .seal(
        &Context {
            installation: INSTALL,
            user_id: &alice.user,
            binding_id: &binding,
            principal: PRINCIPAL,
            generation: 1,
        },
        &Bearer::new(b"rr15-bearer").unwrap(),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_generations
             (binding_id, generation, remote_key, expires_at, key_id, key_fingerprint, nonce, ciphertext)
         VALUES ($1::uuid, 1, gen_random_uuid(), clock_timestamp() + interval '1 hour', $2, $3, $4, $5)",
    )
    .bind(&binding)
    .bind(&env.key_id)
    .bind(finger.as_slice())
    .bind(env.nonce.as_slice())
    .bind(env.ciphertext)
    .execute(&g_pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_policy
             (binding_id, revision, scope_id, approval_id, model, report_source,
              provider_generation, approval_generation, user_generation, capabilities)
         VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'a', $4::uuid, 0, 0, 0, '{}'::jsonb)",
    )
    .bind(&binding)
    .bind(&alice_scope)
    .bind(&alice.approval)
    .bind(&report_source)
    .execute(&g_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.gateway_bindings
            SET active_generation = 1, observed_revision = 1, state = 'ready'
          WHERE id = $1::uuid",
    )
    .bind(&binding)
    .execute(&g_pool)
    .await
    .unwrap();

    let mut api = connect(&db.0, API).await;
    let mut worker = connect(&db.0, WORKER).await;
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(WORKER));
    let limits = AdmissionLimits {
        live_per_actor: 8,
        live_per_scope: 8,
        queued_in_instance: 32,
        queue_timeout: Duration::from_secs(300),
        round_cap: 4,
    };
    let lease_cfg = LeaseSettings {
        lease: Duration::from_secs(60),
        execution_timeout: Duration::from_secs(600),
    };
    let claim_cfg = ClaimLimits {
        executing_per_actor: 4,
        executing_per_scope: 8,
    };

    // Subcase A: round_limit = 2, units = 900 (allocated = 0), prior bearer model-round:1 ({}) ->
    // reserve_turn_round sizes BOTH usage_tokens and usage_cost_micros parent holds to 450 (not 900).
    let chat_a = authz_runs::chat(&db, &alice_scope, "personal", &alice).await;
    let (branch_a, msg_a) = branch_and_message(&mut api, &alice_scope, &chat_a).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted { run_id: r_a, .. } = authz_queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &alice_scope,
                actor: &alice.user,
                conversation: &chat_a,
                branch: &branch_a,
                message: &msg_a,
                key: "rr15-bearer-round-a",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot_priced(
                    "a",
                    450,
                    Some(openmettle_core::model_config::CostBound {
                        fixed_micros: 0,
                        micros_per_token: 1,
                    }),
                ),
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(2),
            now_ms: authz_store::NOW,
            cost_qualified: None,
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("expected admission");
    };
    // Simulate pre-activation admission: gateway_reservations exists with units = 900, allocated = 0,
    // and no quota_reservations parent holds yet.
    sqlx::query(
        "INSERT INTO openmettle.gateway_reservations
             (id, scope_id, actor_user_id, approval_id, run_id, units)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $1::uuid, 900)",
    )
    .bind(&r_a)
    .bind(&alice_scope)
    .bind(&alice.user)
    .bind(&alice.approval)
    .execute(tx.connection().unwrap())
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let claim_a = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim_a.run_id, r_a);

    // Record durable bearer Round 1 event (payload '{}') and current metered Round 2 event.
    {
        let mut wtx = WriteTransaction::begin(&mut worker).await.unwrap();
        append_event(
            &mut wtx,
            &alice_scope,
            &r_a,
            "model-round:1",
            Payload {
                format: "openmettle.model-round",
                version: 1,
                bytes: b"{}",
            },
        )
        .await
        .unwrap();
        append_event(
            &mut wtx,
            &alice_scope,
            &r_a,
            "model-round:2",
            Payload {
                format: "openmettle.model-round",
                version: 1,
                bytes: br#"{"metered":true}"#,
            },
        )
        .await
        .unwrap();
        wtx.commit().await.unwrap();
    }

    let pending_a = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &alice_scope,
            actor: &alice.user,
            approval: &alice.approval,
            run_id: &r_a,
            round: 2,
            claim_token: &claim_a.claim_token,
            installation: INSTALL,
            model: "a",
            round_tokens: 450,
            round_cost: Some(450),
            cost_bound: Some(openmettle_core::model_config::CostBound {
                fixed_micros: 0,
                micros_per_token: 1,
            }),
            requires_device_slot: false,
        },
    )
    .await
    .expect("tight 450/450 personal budgets must admit final metered Round 2 after bearer Round 1");

    let parent_holds_a: Vec<(String, i64)> = sqlx::query_as(
        "SELECT resource_kind, reserved_units
           FROM openmettle.quota_reservations
          WHERE run_id = $1::uuid AND gateway_request_id IS NULL
          ORDER BY resource_kind ASC",
    )
    .bind(&r_a)
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        parent_holds_a,
        vec![
            ("usage_cost_micros".to_owned(), 450),
            ("usage_tokens".to_owned(), 450),
        ]
    );

    let fx = TurnHandoffFixture::chat_priced(
        INSTALL,
        "a",
        450,
        openmettle_core::model_config::CostBound {
            fixed_micros: 0,
            micros_per_token: 1,
        },
        false,
    );
    let _disp_a = pending_a
        .handoff(&worker_pool, None, &fx.billable(), fx.prepare())
        .await
        .unwrap();
    let report_id_a: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    dispatched(&mut owner, &pending_a.id).await;
    assert_eq!(
        settlement::ingest(
            &g_pool,
            &UsageReport {
                request: pending_a.id.clone(),
                installation: INSTALL.into(),
                principal: alice.user.clone(),
                scope: alice_scope.clone(),
                source: INSTALL.into(),
                report_id: report_id_a,
                revision: 1,
                r#final: true,
                prompt_tokens: Some(80),
                completion_tokens: Some(40),
                reasoning_tokens: None,
                reasoning_included: None,
                cost: None,
                unit: None,
            },
        )
        .await
        .unwrap(),
        settlement::Outcome::Applied
    );
    leases::settle(&mut worker, &claim_a.lease(), &lease_cfg, Settle::Succeeded)
        .await
        .unwrap();

    // Subcase B: quota_run_round_cost_slice counts prior bearer Round 1 so a 900-micro parent hold
    // on a 2-round run yields slice 900 (not 450) for Round 2 both before and after req2 insertion.
    owner
        .execute(
            "UPDATE openmettle.quota_defaults
                SET hard_limit = 2000
              WHERE scope_kind = 'personal' AND resource_kind = 'usage_cost_micros'",
        )
        .await
        .unwrap();
    let chat_b = authz_runs::chat(&db, &bob_scope, "personal", &bob).await;
    let (branch_b, msg_b) = branch_and_message(&mut api, &bob_scope, &chat_b).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted { run_id: r_b, .. } = authz_queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &bob_scope,
                actor: &bob.user,
                conversation: &chat_b,
                branch: &branch_b,
                message: &msg_b,
                key: "rr15-cost-slice-b",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot(450),
            },
            actor_approval_id: &bob.approval,
            capabilities: &[],
            requested_rounds: Some(2),
            now_ms: authz_store::NOW,
            cost_qualified: None,
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("expected admission");
    };
    sqlx::query(
        "INSERT INTO openmettle.gateway_reservations
             (id, scope_id, actor_user_id, approval_id, run_id, units)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $1::uuid, 900)",
    )
    .bind(&r_b)
    .bind(&bob_scope)
    .bind(&bob.user)
    .bind(&bob.approval)
    .execute(tx.connection().unwrap())
    .await
    .unwrap();
    sqlx::query(
        "SELECT openmettle.quota_reserve(
             $1::uuid, $2::uuid, 'usage_cost_micros', 900, 'run:' || $3, $3::uuid,
             NULL, NULL, clock_timestamp() + interval '5 minutes'
         )",
    )
    .bind(&bob_scope)
    .bind(&bob.user)
    .bind(&r_b)
    .execute(tx.connection().unwrap())
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let claim_b = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim_b.run_id, r_b);

    {
        let mut wtx = WriteTransaction::begin(&mut worker).await.unwrap();
        append_event(
            &mut wtx,
            &bob_scope,
            &r_b,
            "model-round:1",
            Payload {
                format: "openmettle.model-round",
                version: 1,
                bytes: b"{}",
            },
        )
        .await
        .unwrap();
        wtx.commit().await.unwrap();
    }
    let slice_before: i64 = sqlx::query_scalar(
        "SELECT openmettle.quota_run_round_cost_slice($1::uuid, $2::uuid, NULL)",
    )
    .bind(&bob_scope)
    .bind(&r_b)
    .fetch_one(&mut worker)
    .await
    .unwrap();
    assert_eq!(slice_before, 900);

    // Insert current metered Round 2 event + gateway_requests row and re-check slice with p_current_request.
    let req_b: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_requests
             (id, reservation_id, scope_id, actor_user_id, approval_id,
              installation, model, units, dispatch_hash, run_id, round)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid,
                 $6::uuid, 'a', 450, sha256(repeat('b', 32)::bytea), $2::uuid, 2)",
    )
    .bind(&req_b)
    .bind(&r_b)
    .bind(&bob_scope)
    .bind(&bob.user)
    .bind(&bob.approval)
    .bind(INSTALL)
    .execute(&mut worker)
    .await
    .unwrap();
    {
        let mut wtx = WriteTransaction::begin(&mut worker).await.unwrap();
        append_event(
            &mut wtx,
            &bob_scope,
            &r_b,
            "model-round:2",
            Payload {
                format: "openmettle.model-round",
                version: 1,
                bytes: br#"{"metered":true}"#,
            },
        )
        .await
        .unwrap();
        wtx.commit().await.unwrap();
    }
    let slice_with_req: i64 = sqlx::query_scalar(
        "SELECT openmettle.quota_run_round_cost_slice($1::uuid, $2::uuid, $3::uuid)",
    )
    .bind(&bob_scope)
    .bind(&r_b)
    .bind(&req_b)
    .fetch_one(&mut worker)
    .await
    .unwrap();
    assert_eq!(slice_with_req, 900);

    // Subcase C: 3-arg quota_ensure_legacy_run_holds (draining N-1 workers) also sizes the
    // replacement usage_tokens parent hold to 450 (not 900) after bearer Round 1, fitting bob's
    // tight 450 personal token budget!
    sqlx::query("SELECT openmettle.gateway_release($1::uuid, repeat('b', 32)::bytea)")
        .bind(&req_b)
        .execute(&mut worker)
        .await
        .unwrap();
    sqlx::query("SELECT openmettle.quota_ensure_legacy_run_holds($1::uuid, $2::uuid, $3::uuid)")
        .bind(&bob_scope)
        .bind(&r_b)
        .bind(&claim_b.claim_token)
        .execute(&mut worker)
        .await
        .expect("3-arg quota_ensure_legacy_run_holds must size tokens to 450 after bearer Round 1");
    let legacy_token_hold: i64 = sqlx::query_scalar(
        "SELECT reserved_units
           FROM openmettle.quota_reservations
          WHERE run_id = $1::uuid AND gateway_request_id IS NULL
            AND resource_kind = 'usage_tokens'",
    )
    .bind(&r_b)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(legacy_token_hold, 450);

    leases::settle(&mut worker, &claim_b.lease(), &lease_cfg, Settle::Succeeded)
        .await
        .unwrap();
    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn public_turn_handoff_rejects_mismatched_and_cross_gateway_prepared_before_commit() {
    use openmettle_core::{
        authz::{
            gateway::{self, TurnRound, settlement},
            leases::{self, LeaseSettings, Settle},
            runs::{self as authz_queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
        },
        provider_http::{gateway::UsageReport, inference::Protocol},
        quotas::{self, RunBudgetReservation},
        runs::{RunInput, WriteTransaction},
    };
    use sqlx::postgres::PgPoolOptions;

    const INSTALL: &str = "00000000-0000-4000-8000-000000001818";

    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let alice_scope = authz_runs::personal_of(&db, &alice).await;

    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_tokens', 10000)",
        )
        .await
        .unwrap();
    owner
        .execute(
            "UPDATE openmettle.quota_defaults
                SET cost_denomination = 'usd_micros'
              WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros'",
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_cost_micros', 10000)",
        )
        .await
        .unwrap();

    let g_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(pg::GATEWAY));
    let mut api = connect(&db.0, API).await;
    let mut worker = connect(&db.0, WORKER).await;
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(db.1.options(WORKER));
    let limits = AdmissionLimits {
        live_per_actor: 8,
        live_per_scope: 8,
        queued_in_instance: 32,
        queue_timeout: Duration::from_secs(300),
        round_cap: 4,
    };
    let lease_cfg = LeaseSettings {
        lease: Duration::from_secs(60),
        execution_timeout: Duration::from_secs(600),
    };
    let claim_cfg = ClaimLimits {
        executing_per_actor: 4,
        executing_per_scope: 8,
    };

    let chat_fx = TurnHandoffFixture::chat_priced(
        INSTALL,
        "a",
        450,
        openmettle_core::model_config::CostBound {
            fixed_micros: 0,
            micros_per_token: 1,
        },
        false,
    );
    let resp_fx = TurnHandoffFixture::new(
        INSTALL,
        Protocol::Responses,
        "a",
        450,
        Some(openmettle_core::model_config::CostBound {
            fixed_micros: 450,
            micros_per_token: 0,
        }),
        false,
    );
    let wrong_tokens_fx = TurnHandoffFixture::chat(INSTALL, "a", 1024, Some(450), false);
    let wrong_cost_none_fx = TurnHandoffFixture::chat(INSTALL, "a", 450, None, false);
    let wrong_cost_val_fx = TurnHandoffFixture::chat(INSTALL, "a", 450, Some(600), false);
    let wrong_device_fx = TurnHandoffFixture::chat(INSTALL, "a", 450, Some(450), true);
    let chat_billable = chat_fx.billable();
    let resp_billable = resp_fx.billable();

    // Passing a Chat-prepared PreparedRequest to a same-model, same-pin Responses
    // BillableInferenceRef fails BEFORE handoff commit with Error::Refused, while the matching
    // Chat route commits cleanly.
    let chat_b = authz_runs::chat(&db, &alice_scope, "personal", &alice).await;
    let (branch_b, msg_b) = branch_and_message(&mut api, &alice_scope, &chat_b).await;
    let mut tx_b = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted { run_id: r_b, .. } = authz_queue::admit_run(
        &mut tx_b,
        &RunAdmission {
            input: RunInput {
                scope: &alice_scope,
                actor: &alice.user,
                conversation: &chat_b,
                branch: &branch_b,
                message: &msg_b,
                key: "rr18-cross-gateway",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snapshot_priced(
                    "a",
                    450,
                    Some(openmettle_core::model_config::CostBound {
                        fixed_micros: 0,
                        micros_per_token: 1,
                    }),
                ),
            },
            actor_approval_id: &alice.approval,
            capabilities: &[],
            requested_rounds: Some(1),
            now_ms: authz_store::NOW,
            cost_qualified: None,
        },
        &limits,
    )
    .await
    .unwrap() else {
        panic!("expected admission");
    };
    assert!(
        quotas::reserve_admitted_run_budget(
            &mut tx_b,
            &RunBudgetReservation {
                scope_id: &alice_scope,
                scope_kind: "personal",
                actor_user_id: &alice.user,
                actor_approval_id: &alice.approval,
                run_id: &r_b,
                token_units: 450,
                per_round_cost_micros: Some(450),
                round_limit: 1,
                requires_device_slot: false,
            },
        )
        .await
        .unwrap()
        .is_none()
    );
    tx_b.commit().await.unwrap();

    let claim_b = authz_queue::claim_next(&mut worker, &claim_cfg, &lease_cfg)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim_b.run_id, r_b);

    let pending_b = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &alice_scope,
            actor: &alice.user,
            approval: &alice.approval,
            run_id: &r_b,
            round: 1,
            claim_token: &claim_b.claim_token,
            installation: INSTALL,
            model: "a",
            round_tokens: 450,
            round_cost: Some(450),
            cost_bound: Some(openmettle_core::model_config::CostBound {
                fixed_micros: 0,
                micros_per_token: 1,
            }),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    // Mismatched reservation bounds (round_tokens, round_cost None / 600, requires_device_slot)
    // and cross-gateway same-pin dispatch MUST all fail closed BEFORE handoff commit.
    for (bad_billable, bad_prepared) in [
        (wrong_tokens_fx.billable(), wrong_tokens_fx.prepare()),
        (wrong_cost_none_fx.billable(), wrong_cost_none_fx.prepare()),
        (wrong_cost_val_fx.billable(), wrong_cost_val_fx.prepare()),
        (wrong_device_fx.billable(), wrong_device_fx.prepare()),
        (resp_billable, chat_fx.prepare()),
    ] {
        assert!(matches!(
            pending_b
                .handoff(&worker_pool, None, &bad_billable, bad_prepared)
                .await,
            Err(gateway::Error::Refused)
        ));
    }

    // Missing wire output cap (output_reserve = None) and oversized output cap
    // (output_reserve = 600 > ceiling = 450) MUST both fail BillableInferenceRef::prepare(..., true)
    // with Error::Validation AND fail TurnPending::handoff with Error::Refused even when prepared
    // directly via Gateway::prepare(..., true).
    let eff_no_output_cap = chat_fx
        .catalog
        .resolve(
            &openmettle_core::model_config::Selection::default(),
            &serde_json::from_value(serde_json::json!({"model": "a"})).unwrap(),
            None,
            |_, _| true,
        )
        .unwrap();
    assert_eq!(eff_no_output_cap.ceiling.value, Some(450));
    assert_eq!(eff_no_output_cap.output_reserve.value, None);
    assert_eq!(
        chat_billable
            .prepare(&chat_fx.catalog, &eff_no_output_cap, &chat_fx.request, true)
            .err(),
        Some(openmettle_core::provider_http::inference::Error::Validation)
    );
    let direct_no_output_cap = chat_fx
        .route
        .prepare(&chat_fx.catalog, &eff_no_output_cap, &chat_fx.request, true)
        .unwrap();
    assert!(matches!(
        pending_b
            .handoff(&worker_pool, None, &chat_billable, direct_no_output_cap,)
            .await,
        Err(gateway::Error::Refused)
    ));

    let overcap_fx = TurnHandoffFixture::chat(INSTALL, "a", 1024, Some(450), false);
    let mut eff_over_cap = overcap_fx.effective.clone();
    eff_over_cap.ceiling.value = Some(450);
    eff_over_cap.output_reserve.value = Some(600);
    let overcap_billable = overcap_fx.billable();
    assert_eq!(
        overcap_billable
            .prepare(
                &overcap_fx.catalog,
                &eff_over_cap,
                &overcap_fx.request,
                true,
            )
            .err(),
        Some(openmettle_core::provider_http::inference::Error::Validation)
    );
    let direct_over_cap = overcap_fx
        .route
        .prepare(
            &overcap_fx.catalog,
            &eff_over_cap,
            &overcap_fx.request,
            true,
        )
        .unwrap();
    assert!(matches!(
        pending_b
            .handoff(&worker_pool, None, &overcap_billable, direct_over_cap,)
            .await,
        Err(gateway::Error::Refused)
    ));
    let req_b_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.gateway_requests WHERE id = $1::uuid")
            .bind(&pending_b.id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(req_b_state, "reserved");
    let committed_b: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.quota_reservations
          WHERE run_id = $1::uuid AND state = 'handoff_committed'",
    )
    .bind(&r_b)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(committed_b, 0);

    // Matching originating Chat route hands off cleanly and returns single-use TurnDispatch.
    let _turn_dispatch_b: gateway::TurnDispatch<'_> = pending_b
        .handoff(&worker_pool, None, &chat_billable, chat_fx.prepare())
        .await
        .unwrap();
    let report_id_b: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    dispatched(&mut owner, &pending_b.id).await;
    assert_eq!(
        settlement::ingest(
            &g_pool,
            &UsageReport {
                request: pending_b.id.clone(),
                installation: INSTALL.into(),
                principal: alice.user.clone(),
                scope: alice_scope.clone(),
                source: INSTALL.into(),
                report_id: report_id_b,
                revision: 1,
                r#final: true,
                prompt_tokens: Some(100),
                completion_tokens: Some(50),
                reasoning_tokens: None,
                reasoning_included: None,
                cost: None,
                unit: None,
            },
        )
        .await
        .unwrap(),
        settlement::Outcome::Applied
    );
    leases::settle(&mut worker, &claim_b.lease(), &lease_cfg, Settle::Succeeded)
        .await
        .unwrap();
    let drift_b: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker)
    .await
    .unwrap();
    assert_eq!(drift_b, (0, 0, 0, 0));
}

async fn backend_pid(c: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(c)
        .await
        .unwrap()
}

/// The one session waiting on a lock that `holder` holds.
async fn waiter_on(db: &TestDb, holder: i32) -> i32 {
    wait_for_blocked_peer(db, holder).await;
    sqlx::query_scalar(
        "SELECT pid FROM pg_stat_activity
          WHERE datname = current_database() AND $1 = ANY(pg_blocking_pids(pid))",
    )
    .bind(holder)
    .fetch_one(&mut db.admin().await)
    .await
    .unwrap()
}

/// Migration 30. `sessions::disable_user` locks only the user row, not `account_admin_lock`. On
/// schema 29 a quota override decided while that disable is in flight, or before it starts,
/// commits after the disable. From schema 30 the first waits for the disable and is refused, and
/// in the second the disable waits for the override to commit. Each paused override waits under
/// the API's 2-second lock limit while the observer polls every 10 ms; an observer stalled past
/// that limit fails the test with `55P03`, and cannot make it pass.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn quota_overrides_serialize_with_disabling_the_acting_administrator_from_schema_30() {
    use openmettle_core::{
        authz::{DenialReason, PolicyReason, store::StoreError},
        quotas::{self, QuotaError, QuotaResourceKind as K},
        runs::WriteTransaction,
    };

    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..29]).await.unwrap();
    let mut owner = connect(&db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let admin =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    authz_store::make_admin(&mut owner, &admin).await;
    let alice =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    let scope = authz_runs::personal_of(&db, &alice).await;
    let policy = openmettle_core::sessions::Policy::new(
        Duration::from_secs(60),
        10,
        Duration::from_secs(30),
    )
    .unwrap();
    let override_row = "SELECT hard_limit, revoked_at IS NULL FROM openmettle.quota_overrides
                         WHERE scope_id = $1::uuid AND resource_kind = $2";
    let audit_rows = "SELECT count(*) FROM openmettle.authorization_audit";
    let reenable = "UPDATE openmettle.users SET disabled_at = NULL WHERE id = $1::uuid";

    for schema in [29, 30] {
        let serialized = schema == 30;
        if serialized {
            migrate::apply(&settings, MIGRATIONS).await.unwrap();
            assert_eq!(db.history().await, all_versions());
            // Same signature, invoker security, search_path and privileges, and its only callers
            // are the two override writers.
            let (definer, config, executable): (bool, Vec<String>, bool) = sqlx::query_as(
                "SELECT prosecdef, proconfig,
                        has_function_privilege('openmettle_api', p.oid, 'EXECUTE')
                   FROM pg_proc p
                  WHERE p.oid = 'openmettle.quota_lock_override(uuid,uuid,text)'::regprocedure",
            )
            .fetch_one(&mut owner)
            .await
            .unwrap();
            assert_eq!(
                (definer, config, executable),
                (false, vec!["search_path=pg_catalog".to_owned()], false)
            );
            let callers: Vec<String> = sqlx::query_scalar(
                "SELECT p.proname::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                  WHERE n.nspname = 'openmettle' AND p.prosrc LIKE '%quota_lock_override%'
                  ORDER BY 1",
            )
            .fetch_all(&mut owner)
            .await
            .unwrap();
            assert_eq!(
                callers,
                ["quota_revoke_scope_override", "quota_upsert_scope_override"]
            );
        }

        // 1. The disable is in flight when the override decides: the statements of
        //    sessions::disable_user, held uncommitted.
        for op in ["set", "revoke"] {
            if op == "revoke" {
                let key = format!("{schema}-before-revoke");
                quotas::set_scope_override(
                    &mut connect(&db.0, API).await,
                    &authz_store::ctx(&admin, &key),
                    &scope,
                    K::UsageTokens,
                    500,
                    None,
                )
                .await
                .unwrap();
            }
            let before: (i64, bool) = sqlx::query_as(override_row)
                .bind(&scope)
                .bind("usage_tokens")
                .fetch_optional(&mut owner)
                .await
                .unwrap()
                .unwrap_or((0, false));
            let audited: i64 = sqlx::query_scalar(audit_rows)
                .fetch_one(&mut owner)
                .await
                .unwrap();
            let mut disabler = connect(&db.0, API).await;
            let disabler_pid = backend_pid(&mut disabler).await;
            let mut tx = WriteTransaction::begin(&mut disabler).await.unwrap();
            for sql in [
                "SELECT session_generation FROM openmettle.users WHERE id = $1::uuid FOR UPDATE",
                "UPDATE openmettle.users SET disabled_at = GREATEST(created_at, clock_timestamp()),
                     session_generation = session_generation + 1 WHERE id = $1::uuid",
            ] {
                sqlx::query(sql)
                    .bind(&admin.user)
                    .execute(tx.connection().unwrap())
                    .await
                    .unwrap();
            }
            let writer = tokio::spawn({
                let (name, admin, scope) = (db.0.clone(), admin.clone(), scope.clone());
                async move {
                    let mut c = connect(&name, API).await;
                    let key = format!("{schema}-{op}");
                    let ctx = authz_store::ctx(&admin, &key);
                    if op == "set" {
                        quotas::set_scope_override(&mut c, &ctx, &scope, K::UsageTokens, 700, None)
                            .await
                    } else {
                        quotas::revoke_scope_override(&mut c, &ctx, &scope, K::UsageTokens).await
                    }
                }
            });
            wait_for_blocked_peer(&db, disabler_pid).await;
            tx.commit().await.unwrap();
            let result = writer.await.unwrap();
            let after: (i64, bool) = sqlx::query_as(override_row)
                .bind(&scope)
                .bind("usage_tokens")
                .fetch_one(&mut owner)
                .await
                .unwrap();
            let audited_after: i64 = sqlx::query_scalar(audit_rows)
                .fetch_one(&mut owner)
                .await
                .unwrap();
            if serialized {
                assert!(
                    matches!(
                        result,
                        Err(QuotaError::Store(StoreError::Denied(reason)))
                            if reason == DenialReason::Policy(PolicyReason::NotAccountAdmin)
                    ),
                    "schema {schema} {op}: {result:?}"
                );
                assert_eq!((after, audited_after), (before, audited), "{op}");
            } else {
                // The defect: applied by an administrator whose disable had already committed.
                assert!(result.is_ok(), "schema {schema} {op}: {result:?}");
                assert_eq!(audited_after, audited + 1, "{op}");
            }
            sqlx::query(reenable)
                .bind(&admin.user)
                .execute(&mut owner)
                .await
                .unwrap();
        }

        // 2. The override has decided and waits on a storage account lock when the disable
        //    starts.
        let generation: i64 = sqlx::query_scalar(
            "SELECT session_generation FROM openmettle.users WHERE id = $1::uuid",
        )
        .bind(&admin.user)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        let mut fixture = connect(&db.0, OWNER).await;
        let fixture_pid = backend_pid(&mut fixture).await;
        fixture.execute("BEGIN").await.unwrap();
        sqlx::query("INSERT INTO openmettle.storage_accounts (scope_id) VALUES ($1::uuid) ON CONFLICT DO NOTHING")
            .bind(&scope)
            .execute(&mut fixture)
            .await
            .unwrap();
        sqlx::query("SELECT FROM openmettle.storage_accounts WHERE scope_id = $1::uuid FOR UPDATE")
            .bind(&scope)
            .execute(&mut fixture)
            .await
            .unwrap();
        let limit = 4096 + schema;
        let writer = tokio::spawn({
            let (name, admin, scope) = (db.0.clone(), admin.clone(), scope.clone());
            async move {
                let key = format!("{schema}-storage");
                let ctx = authz_store::ctx(&admin, &key);
                let mut c = connect(&name, API).await;
                quotas::set_scope_override(&mut c, &ctx, &scope, K::StorageBytes, limit, None).await
            }
        });
        let writer_pid = waiter_on(&db, fixture_pid).await;
        let disabler = tokio::spawn({
            let (name, user) = (db.0.clone(), admin.user.clone());
            async move {
                let mut c = connect(&name, API).await;
                openmettle_core::sessions::disable_user(&mut c, &user, generation, &policy).await
            }
        });
        let disabler = if serialized {
            wait_for_blocked_peer(&db, writer_pid).await;
            Some(disabler)
        } else {
            // The defect: the disable commits while the decided override is still pending.
            disabler.await.unwrap().unwrap();
            assert!(!writer.is_finished());
            None
        };
        fixture.execute("ROLLBACK").await.unwrap();
        writer.await.unwrap().unwrap();
        if let Some(disabler) = disabler {
            disabler.await.unwrap().unwrap();
        }
        let stored: (i64, bool) = sqlx::query_as(override_row)
            .bind(&scope)
            .bind("storage_bytes")
            .fetch_one(&mut owner)
            .await
            .unwrap();
        assert_eq!(stored, (limit, true));
        let after: i64 = sqlx::query_scalar(
            "SELECT session_generation FROM openmettle.users WHERE id = $1::uuid",
        )
        .bind(&admin.user)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(after, generation + 1);
        // The disabled administrator's next override is refused.
        let refused = quotas::set_scope_override(
            &mut connect(&db.0, API).await,
            &authz_store::ctx(&admin, &format!("{schema}-after")),
            &scope,
            K::StorageBytes,
            1,
            None,
        )
        .await;
        assert!(
            matches!(
                refused,
                Err(QuotaError::Store(StoreError::Denied(
                    DenialReason::InactivePrincipal
                )))
            ),
            "{refused:?}"
        );
        sqlx::query(reenable)
            .bind(&admin.user)
            .execute(&mut owner)
            .await
            .unwrap();
    }
}
