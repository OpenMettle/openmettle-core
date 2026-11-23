use super::*;

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
    call.handoff(&api_pool, &ring).await.unwrap();
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

    let summary = quotas::read_summary(
        &mut api,
        &alice_scope,
        Some(&alice.user),
        None,
        Some(openmettle_core::authz::runs::ClaimLimits {
            executing_per_actor: 3,
            executing_per_scope: 7,
        }),
    )
    .await
    .unwrap();
    assert_eq!(summary.usage[0].resource_kind, "usage_tokens");
    assert_eq!(summary.usage[0].active_used, "27670116110564327421");
    assert_eq!(summary.usage[0].remaining.as_deref(), Some("0"));
    assert_eq!(summary.usage[0].status, "hard_limit");
    assert!(summary.usage[0].last_reconciled_at.is_some());
    assert_eq!(
        summary.execution.executing_runs_per_scope.limit.as_deref(),
        Some("7")
    );
    assert_eq!(
        summary.execution.executing_runs_per_scope.limit_source,
        "default"
    );
    let actor_exec = summary
        .execution
        .executing_runs_per_actor
        .as_ref()
        .expect("personal summary includes executing_runs_per_actor");
    assert_eq!(actor_exec.limit.as_deref(), Some("3"));
    assert_eq!(actor_exec.limit_source, "default");

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
    let before_exp = quotas::read_summary(&mut api, &scope, Some(&alice.user), None, None)
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
    let after_exp = quotas::read_summary(&mut api, &scope, Some(&alice.user), None, None)
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

async fn branch_and_message(api: &mut PgConnection, scope: &str, chat: &str) -> (String, String) {
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
                config: br#"{"effective":{"ceiling":{"value":450}}}"#,
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
                config: br#"{"effective":{"ceiling":{"value":300}}}"#,
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
                config: br#"{"effective":{"ceiling":{"value":100}}}"#,
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
    let keys = GatewayKeys::new(&[("atomic-k1".into(), KEY_BYTES)]).unwrap();
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
                    config: br#"{"effective":{"ceiling":{"value":100}}}"#,
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
            requires_device_slot: true,
        },
    )
    .await
    .unwrap();
    let _disp1 = p1
        .handoff(&worker_pool, &keys, Some(GRANT_1))
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
            requires_device_slot: true,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        p2.handoff(&worker_pool, &keys, Some(GRANT_1)).await,
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
        p2_cancel.handoff(&worker_pool, &keys, Some(GRANT_2)).await,
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
                config: br#"{"effective":{"ceiling":{"value":100}}}"#,
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
                config: br#"{"effective":{"ceiling":{"value":250}}}"#,
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
                config: br#"{"effective":{"ceiling":{"value":150}}}"#,
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
                config: br#"{"effective":{"ceiling":{"value":200}}}"#,
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
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let _disp = pending_held
        .handoff(&worker_pool, &keys, None)
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
    assert_eq!(
        settlement::ingest(
            &g_pool,
            &UsageReport {
                request: pending_held.id.clone(),
                installation: INSTALL.into(),
                principal: PRINCIPAL.into(),
                scope: scope.clone(),
                source: report_source.clone(),
                report_id,
                revision: 0,
                r#final: true,
                prompt_tokens: Some(90),
                completion_tokens: Some(30),
                reasoning_tokens: None,
                reasoning_included: None,
                cost: Some("175".into()),
                unit: Some("usd_micros".into()),
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
            ("usage_cost_micros".into(), 175, 0),
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
    let keys = GatewayKeys::new(&[("exp-k1".into(), KEY_BYTES)]).unwrap();
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
                config: br#"{"effective":{"ceiling":{"value":200}}}"#,
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
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let _disp1 = p1.handoff(&worker_pool, &keys, None).await.unwrap();
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
    assert_eq!(
        settlement::ingest(
            &g_pool,
            &UsageReport {
                request: p1.id.clone(),
                installation: INSTALL.into(),
                principal: PRINCIPAL.into(),
                scope: scope.clone(),
                source: report_source.clone(),
                report_id,
                revision: 0,
                r#final: true,
                prompt_tokens: Some(70),
                completion_tokens: Some(30),
                reasoning_tokens: None,
                reasoning_included: None,
                cost: Some("175".into()),
                unit: Some("usd_micros".into()),
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
    assert_eq!(cost_budget, (175, 0));

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
                config: br#"{"effective":{"ceiling":{"value":200}}}"#,
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
    let keys_up = GatewayKeys::new(&[("race-k1".into(), KEY_BYTES)]).unwrap();
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
                config: br#"{"effective":{"ceiling":{"value":100}}}"#,
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
    assert!(matches!(
        p_race.handoff(&wp_up, &keys_up, Some(GRANT_RACE)).await,
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
    let keys = GatewayKeys::new(&[("rr8-k1".into(), KEY_BYTES)]).unwrap();
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
                config: br#"{"effective":{"ceiling":{"value":100}}}"#,
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

    // Part B1 (P2 #2): With all cost limits now expired/NULL, reserve_turn_round with an
    // unqualified profile (round_cost = None) succeeds and slices the legacy cost parent. If an
    // admin activates a cost override before TurnPending::handoff, deferred
    // enforce_gateway_handoff_holds MUST reject the handoff with OMQ04 (Error::Refused), leaving
    // gateway_requests in 'reserved' so pending.release() cleanly unwinds it.
    sqlx::query(
        "UPDATE openmettle.quota_overrides
            SET expires_at = clock_timestamp() - interval '1 second'
          WHERE scope_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&scope)
    .execute(&mut owner)
    .await
    .unwrap();
    let p_unqual = gateway::reserve_turn_round(
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
    assert!(matches!(
        p_unqual.handoff(&worker_pool, &keys, None).await,
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
        &claim1.lease(),
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
        let keys2 = GatewayKeys::new(&[("rr8-k2".into(), KEY_BYTES)]).unwrap();
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
                    config: br#"{"effective":{"ceiling":{"value":100}}}"#,
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
        assert!(matches!(
            p_null_denom.handoff(&wp2, &keys2, None).await,
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
                    config: br#"{"effective":{"ceiling":{"value":100}}}"#,
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
            gateway::{self, Authority, Call, Reservation, TurnRound},
            leases::{self, LeaseSettings, Settle},
            runs::{self as authz_queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
        },
        provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
        quotas::{self, RunBudgetReservation},
        runs::{RunInput, WriteTransaction},
    };
    use sqlx::postgres::PgPoolOptions;

    const INSTALL: &str = "00000000-0000-4000-8000-000000000091";
    const PRINCIPAL: &str = "00000000-0000-4000-8000-000000000092";
    const BUDGET: &str = "00000000-0000-4000-8000-000000000093";
    const STALE_CLAIM: &str = "00000000-0000-4000-8000-000000000099";
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
                config: br#"{"effective":{"ceiling":{"value":100}}}"#,
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
            requires_device_slot: true,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        p_dev.handoff(&worker_pool, &keys, None).await,
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
    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
}
