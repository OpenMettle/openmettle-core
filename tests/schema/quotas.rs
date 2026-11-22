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

    // 1. Upgraded DB (`applied = 23` -> `24`) gates override writes until metering_enforced = true.
    let upgraded = TestDb::new().await;
    let settings = upgraded.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
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

    let summary = quotas::read_summary(&mut api, &alice_scope, Some(&alice.user), None)
        .await
        .unwrap();
    assert_eq!(summary.usage[0].resource_kind, "usage_tokens");
    assert_eq!(summary.usage[0].active_used, "27670116110564327421");
    assert_eq!(summary.usage[0].remaining.as_deref(), Some("0"));
    assert_eq!(summary.usage[0].status, "hard_limit");
    assert!(summary.usage[0].last_reconciled_at.is_some());

    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut connect(&db.0, WORKER).await)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
}
