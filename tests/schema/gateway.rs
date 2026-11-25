//! ADR 0037 / ADR 0044. Exercise gateway privileges, run-round reservations, settlement
//! finality, and boundary checks under the actual provisioned logins.
use super::*;
use openmettle_core::{
    authz::gateway::{self, Authority, Call, Reservation, TurnRound, settlement},
    model_config::CostBound,
    provider_http::gateway::UsageReport,
    runs::WriteTransaction,
};
use sqlx::{PgPool, postgres::PgPoolOptions};

const INSTALL: &str = "00000000-0000-4000-8000-000000000023";
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

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn gateway_roles_and_function_boundaries() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    for table in [
        "openmettle.gateway_bindings",
        "openmettle.gateway_generations",
        "openmettle.gateway_nonces",
        "openmettle.gateway_policy",
        "openmettle.gateway_intents",
        "openmettle.gateway_audit",
    ] {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(table)
            .fetch_one(&mut owner)
            .await
            .unwrap();
        assert!(!exists, "superseded table {table} must not exist");
    }
    for role in [API, WORKER, ISSUANCE, pg::GATEWAY] {
        let mut c = connect(&db.0, role).await;
        for sql in [
            "UPDATE openmettle.gateway_settlements SET measured=0",
            "INSERT INTO openmettle.gateway_usage_reports DEFAULT VALUES",
        ] {
            expect_state(&mut c, sql, "42501").await;
        }
    }
    let mut gw = connect(&db.0, pg::GATEWAY).await;
    for sql in [
        "SELECT id FROM openmettle.gateway_requests",
        "SELECT id FROM openmettle.gateway_reservations",
        "SELECT request_id FROM openmettle.gateway_usage_reports",
        "SELECT request_id FROM openmettle.gateway_settlements",
        "SELECT id FROM openmettle.quota_reservations",
        "SELECT id FROM openmettle.users",
        "SELECT id FROM openmettle.projects",
        "SELECT openmettle.quota_lock_gateway_request_for_settlement(gen_random_uuid())",
        "SELECT openmettle.quota_settle_gateway_usage(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),1)",
    ] {
        expect_state(&mut gw, sql, "42501").await;
    }
    let mut api = connect(&db.0, API).await;
    for sql in [
        "INSERT INTO openmettle.gateway_requests (id,reservation_id,scope_id,actor_user_id,approval_id,installation,model,units,dispatch_hash,run_id,round) VALUES (gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),'a',1,sha256('x'),gen_random_uuid(),1)",
        "SELECT openmettle.gateway_release(gen_random_uuid(),repeat('x',32)::bytea)",
        "SELECT openmettle.quota_recover_lost_handoff(gen_random_uuid(),repeat('x',32)::bytea,gen_random_uuid(),gen_random_uuid(),gen_random_uuid())",
    ] {
        expect_state(&mut api, sql, "42501").await;
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn sweeps_can_read_only_pending_rows_in_age_order() {
    let db = TestDb::migrated().await;
    let mut c = connect(&db.0, OWNER).await;
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
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn run_round_reservation_release_orphan_sweep_and_settlement_finality() {
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
    let api = pool(&db, API);
    let worker = pool(&db, WORKER);
    let g = pool(&db, pg::GATEWAY);
    let owner_pool = pool(&db, OWNER);

    // 1. Run-owned hold idempotency, composite FK, round uniqueness, release, and retry.
    let plain_snap = quotas::snapshot_priced("a", 10, None);
    let r = run_admission::request(&db, &scope, "personal", &actor, "gateway-rounds").await;
    let run = run_admission::admitted(&db, &r).await;
    sqlx::query(
        "UPDATE openmettle.runs
         SET round_limit=1,snapshot_format='openmettle.conversation',config_snapshot=$2
         WHERE id=$1::uuid",
    )
    .bind(&run)
    .bind(&plain_snap)
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
    let insert_round = |sc| {
        sqlx::query("INSERT INTO openmettle.gateway_requests
        (id,reservation_id,scope_id,actor_user_id,approval_id,installation,model,units,dispatch_hash,run_id,round)
        VALUES (gen_random_uuid(),$1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,'a',10,sha256(repeat('x',32)::bytea),$6::uuid,1)")
        .bind(&hold_id).bind(sc).bind(&actor.user).bind(&actor.approval).bind(INSTALL).bind(&run)
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
    .fetch_one(&mut c)
    .await
    .unwrap();
    assert_eq!(
        sqlstate(
            sqlx::query("SELECT openmettle.gateway_release($1::uuid,repeat('x',32)::bytea)")
                .bind(&first)
                .execute(&api)
                .await
        ),
        "42501"
    );
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
    let p = gateway::reserve(&worker, round(1, &claim.claim_token))
        .await
        .unwrap();
    assert_ne!(p.id, first);
    assert_eq!(
        sqlstate(insert_round(&scope).execute(&worker).await),
        "23505"
    );
    // Mark `p` handed off and dispatched via binding-free round handoff + dispatch so settlement
    // finality and composite quota FKs can be exercised on it.
    let bearer_bytes = [0x44_u8; 32];
    let secret_bytes = [0x55_u8; 32];
    sqlx::query(
        "UPDATE openmettle.gateway_requests SET dispatch_hash=sha256($2) WHERE id=$1::uuid",
    )
    .bind(&p.id)
    .bind(secret_bytes.as_slice())
    .execute(&mut c)
    .await
    .unwrap();
    {
        let mut wtx = worker.begin().await.unwrap();
        sqlx::query("SELECT openmettle.quota_lock_turn_handoff_prefix($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid)")
            .bind(&p.id).bind(secret_bytes.as_slice()).bind(&scope).bind(&run).bind(&claim.claim_token)
            .execute(&mut *wtx).await.unwrap();
        let ok: bool = sqlx::query_scalar(
            "SELECT openmettle.gateway_handoff_round($1::uuid,$2,$3::uuid,sha256($4))",
        )
        .bind(&p.id)
        .bind(secret_bytes.as_slice())
        .bind(&claim.claim_token)
        .bind(bearer_bytes.as_slice())
        .fetch_one(&mut *wtx)
        .await
        .unwrap();
        assert!(ok);
        sqlx::query("SELECT openmettle.quota_commit_turn_handoff($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid,false,NULL,true)")
            .bind(&p.id).bind(secret_bytes.as_slice()).bind(&scope).bind(&run).bind(&claim.claim_token)
            .execute(&mut *wtx).await.unwrap();
        sqlx::query("SELECT openmettle.gateway_handoff_round_confirm($1::uuid,$2,$3::uuid)")
            .bind(&p.id)
            .bind(secret_bytes.as_slice())
            .bind(&claim.claim_token)
            .execute(&mut *wtx)
            .await
            .unwrap();
        wtx.commit().await.unwrap();
    }
    sqlx::query("SELECT FROM openmettle.gateway_dispatch($1::uuid,sha256($2))")
        .bind(&p.id)
        .bind(bearer_bytes.as_slice())
        .execute(&g)
        .await
        .unwrap();
    assert!(!p.release(&worker).await.unwrap());
    assert_eq!(
        sqlstate(insert_round(&scope).execute(&worker).await),
        "23505"
    );

    // Second handed-off + dispatched round for single-step final settlement check.
    let r_direct = run_admission::request(&db, &scope, "personal", &actor, "gateway-final").await;
    let run_direct = run_admission::admitted(&db, &r_direct).await;
    sqlx::query(
        "UPDATE openmettle.runs
         SET snapshot_format='openmettle.conversation',config_snapshot=$2
         WHERE id=$1::uuid",
    )
    .bind(&run_direct)
    .bind(&plain_snap)
    .execute(&mut c)
    .await
    .unwrap();
    let claim_direct = openmettle_core::authz::runs::claim_next(
        &mut run_admission::worker(&db).await,
        &run_admission::OPEN,
        &run_admission::LEASES,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(claim_direct.run_id, run_direct);
    let mut tx_d = WriteTransaction::begin(&mut api_c).await.unwrap();
    gateway::hold(
        &mut tx_d,
        &Reservation {
            id: &run_direct,
            scope_id: &scope,
            actor: &actor.user,
            approval: &actor.approval,
        },
        Some(&run_direct),
        10,
    )
    .await
    .unwrap();
    tx_d.commit().await.unwrap();
    let p_direct = gateway::reserve_turn_round(
        &worker,
        TurnRound {
            scope_id: &scope,
            actor: &actor.user,
            approval: &actor.approval,
            run_id: &run_direct,
            round: 1,
            claim_token: &claim_direct.claim_token,
            installation: INSTALL,
            model: "a",
            round_tokens: 10,
            round_cost: None,
            cost_bound: None,
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let fx_plain = quotas::TurnHandoffFixture::chat(INSTALL, "a", 10, None, false);
    let _disp_direct = p_direct
        .handoff(
            &worker,
            None,
            &fx_plain.billable(),
            fx_plain.prepare_mode(true),
        )
        .await
        .unwrap();
    sqlx::query(
        "UPDATE openmettle.gateway_requests SET dispatched_at=clock_timestamp() WHERE id=$1::uuid",
    )
    .bind(&p_direct.id)
    .execute(&mut c)
    .await
    .unwrap();
    check_settlement_finality(&owner_pool, &p.id, &p_direct.id).await;

    // 2. A metered but unsent run request at the front of the index cannot hide an older-writer
    //    unmetered orphan behind it.
    let r_m = run_admission::request(&db, &scope, "personal", &actor, "orphan-metered").await;
    let run_m = run_admission::admitted(&db, &r_m).await;
    let claim_m = openmettle_core::authz::runs::claim_next(
        &mut run_admission::worker(&db).await,
        &run_admission::OPEN,
        &run_admission::LEASES,
    )
    .await
    .unwrap()
    .unwrap();
    let mut tx_m = WriteTransaction::begin(&mut api_c).await.unwrap();
    gateway::hold(
        &mut tx_m,
        &Reservation {
            id: &run_m,
            scope_id: &scope,
            actor: &actor.user,
            approval: &actor.approval,
        },
        Some(&run_m),
        10,
    )
    .await
    .unwrap();
    tx_m.commit().await.unwrap();
    let bound = gateway::reserve(
        &worker,
        Call {
            reservation: Reservation {
                id: &run_m,
                scope_id: &scope,
                actor: &actor.user,
                approval: &actor.approval,
            },
            installation: INSTALL,
            model: "a",
            units: 10,
            authority: Authority::Lease {
                run: &run_m,
                round: 1,
                token: &claim_m.claim_token,
            },
        },
    )
    .await
    .unwrap();
    sqlx::query("UPDATE openmettle.gateway_requests SET created_at='2000-01-01' WHERE id=$1::uuid")
        .bind(&bound.id)
        .execute(&mut c)
        .await
        .unwrap();

    let r_o = run_admission::request(&db, &scope, "personal", &actor, "orphan-legacy").await;
    let run_o = run_admission::admitted(&db, &r_o).await;
    let mut tx_o = WriteTransaction::begin(&mut api_c).await.unwrap();
    gateway::hold(
        &mut tx_o,
        &Reservation {
            id: &run_o,
            scope_id: &scope,
            actor: &actor.user,
            approval: &actor.approval,
        },
        Some(&run_o),
        10,
    )
    .await
    .unwrap();
    tx_o.commit().await.unwrap();
    let orphan = uuid(&mut c).await;
    sqlx::query("INSERT INTO openmettle.gateway_requests
        (reservation_id,scope_id,actor_user_id,approval_id,installation,model,units,dispatch_hash,run_id,round,id)
        VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,'a',10,sha256(repeat('x',32)::bytea),$1::uuid,1,$6::uuid)")
        .bind(&run_o).bind(&scope).bind(&actor.user).bind(&actor.approval).bind(INSTALL).bind(&orphan)
        .execute(&worker).await.unwrap();
    sqlx::query("UPDATE openmettle.gateway_requests SET created_at='2000-01-02' WHERE id=$1::uuid")
        .bind(&orphan)
        .execute(&mut c)
        .await
        .unwrap();
    sqlx::query("UPDATE openmettle.runs SET state='cancelled' WHERE id=$1::uuid")
        .bind(&run_o)
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
    assert!(bound.release(&worker).await.unwrap());

    // 3. Cost-hold settlement through `gateway_settle_report` does not block behind an unrelated
    //    waiting unwind on shared token/cost budgets.
    c.execute(
        "UPDATE openmettle.quota_defaults SET hard_limit=1000,cost_denomination='usd_micros'
        WHERE scope_kind='instance' AND resource_kind='usage_cost_micros'",
    )
    .await
    .unwrap();
    c.execute(
        "INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit)
        VALUES ('personal','usage_cost_micros',1000)",
    )
    .await
    .unwrap();
    let cost_cb = CostBound {
        fixed_micros: 20,
        micros_per_token: 2,
    };
    let cost_fx = quotas::TurnHandoffFixture::chat_priced(INSTALL, "a", 10, cost_cb, false);
    let cost_snap = quotas::snapshot_priced("a", 10, Some(cost_cb));
    let admit_cost_run = |key: &str| {
        let db = &db;
        let scope = scope.clone();
        let actor = actor.clone();
        let snap = cost_snap.clone();
        let key = key.to_owned();
        async move {
            let chat = authz_runs::chat(db, &scope, "personal", &actor).await;
            let mut api_l = connect(&db.0, API).await;
            let (branch, message) = quotas::branch_and_message(&mut api_l, &scope, &chat).await;
            let mut tx_c = WriteTransaction::begin(&mut api_l).await.unwrap();
            let openmettle_core::authz::runs::Admission::Admitted { run_id, .. } =
                openmettle_core::authz::runs::admit_run(
                    &mut tx_c,
                    &openmettle_core::authz::runs::RunAdmission {
                        input: openmettle_core::runs::RunInput {
                            scope: &scope,
                            actor: &actor.user,
                            conversation: &chat,
                            branch: &branch,
                            message: &message,
                            key: &key,
                            format: "openmettle.conversation",
                            version: 1,
                            input: b"{}",
                            config: &snap,
                        },
                        actor_approval_id: &actor.approval,
                        capabilities: &[],
                        requested_rounds: Some(1),
                        now_ms: authz_store::NOW,
                        cost_qualified: Some(true),
                    },
                    &openmettle_core::authz::runs::AdmissionLimits {
                        live_per_actor: 16,
                        live_per_scope: 16,
                        queued_in_instance: 32,
                        queue_timeout: Duration::from_secs(300),
                        round_cap: 4,
                    },
                )
                .await
                .unwrap()
            else {
                panic!("expected cost admission");
            };
            gateway::hold_with_cost(
                &mut tx_c,
                &Reservation {
                    id: &run_id,
                    scope_id: &scope,
                    actor: &actor.user,
                    approval: &actor.approval,
                },
                Some(&run_id),
                10,
                Some(40),
            )
            .await
            .unwrap();
            tx_c.commit().await.unwrap();
            let claim = openmettle_core::authz::runs::claim_next(
                &mut run_admission::worker(db).await,
                &openmettle_core::authz::runs::ClaimLimits {
                    executing_per_actor: 16,
                    executing_per_scope: 16,
                },
                &run_admission::LEASES,
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(claim.run_id, run_id);
            (run_id, claim.claim_token)
        }
    };
    let (cost_run, cost_claim) = admit_cost_run("cost-settle-1").await;
    let cost_pending = gateway::reserve_turn_round(
        &worker,
        TurnRound {
            scope_id: &scope,
            actor: &actor.user,
            approval: &actor.approval,
            run_id: &cost_run,
            round: 1,
            claim_token: &cost_claim,
            installation: INSTALL,
            model: "a",
            round_tokens: 10,
            round_cost: Some(40),
            cost_bound: Some(cost_cb),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let _cost_disp = cost_pending
        .handoff(
            &worker,
            None,
            &cost_fx.billable(),
            cost_fx.prepare_mode(true),
        )
        .await
        .unwrap();
    sqlx::query(
        "UPDATE openmettle.gateway_requests SET dispatched_at=clock_timestamp() WHERE id=$1::uuid",
    )
    .bind(&cost_pending.id)
    .execute(&mut c)
    .await
    .unwrap();

    let (other_run, other_claim) = admit_cost_run("cost-settle-2").await;
    let unsent = gateway::reserve_turn_round(
        &worker,
        TurnRound {
            scope_id: &scope,
            actor: &actor.user,
            approval: &actor.approval,
            run_id: &other_run,
            round: 1,
            claim_token: &other_claim,
            installation: INSTALL,
            model: "a",
            round_tokens: 10,
            round_cost: Some(40),
            cost_bound: Some(cost_cb),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let order: Vec<String> = sqlx::query_scalar(
        "SELECT resource_kind FROM openmettle.quota_reservations
        WHERE gateway_request_id=$1::uuid ORDER BY created_at",
    )
    .bind(&unsent.id)
    .fetch_all(&mut c)
    .await
    .unwrap();
    assert_eq!(order, ["usage_cost_micros", "usage_tokens"]);
    let mut blocker = c.begin().await.unwrap();
    let pid: i32 = sqlx::query_scalar(
        "SELECT pg_backend_pid() FROM openmettle.quota_reservations
        WHERE gateway_request_id=$1::uuid AND resource_kind='usage_tokens' FOR NO KEY UPDATE",
    )
    .bind(&unsent.id)
    .fetch_one(&mut *blocker)
    .await
    .unwrap();
    let release = unsent.release(&worker);
    let cost_report = UsageReport {
        request: cost_pending.id.clone(),
        installation: INSTALL.into(),
        principal: actor.user.clone(),
        scope: scope.clone(),
        source: INSTALL.into(),
        report_id: cost_pending.id.clone(),
        revision: 1,
        r#final: true,
        prompt_tokens: Some(6),
        completion_tokens: Some(4),
        reasoning_tokens: None,
        reasoning_included: None,
        cost: None,
        unit: None,
    };
    let settle_while_unwind_waits = async {
        wait_for_blocked_peer(&db, pid).await;
        tokio::time::timeout(Duration::from_secs(5), settlement::ingest(&g, &cost_report))
            .await
            .expect("waiting unwind must leave the shared budgets available")
            .unwrap();
        blocker.commit().await.unwrap();
    };
    let (released, ()) = tokio::join!(release, settle_while_unwind_waits);
    assert!(released.unwrap());
    let values: Vec<String> = sqlx::query_scalar(
        "SELECT settled_units::text FROM openmettle.quota_reservations
        WHERE gateway_request_id=$1::uuid ORDER BY resource_kind",
    )
    .bind(&cost_pending.id)
    .fetch_all(&worker)
    .await
    .unwrap();
    // 10 tokens * 2 micros/token + 20 fixed = 40 micros.
    assert_eq!(values, ["40", "10"]);
    let drift: (i64, i64) = sqlx::query_as(
        "SELECT budget_mismatches,settlement_mismatches FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&worker)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0));

    // 4. Composite scope foreign keys and allocated reservation total.
    c.execute(
        "CREATE TABLE openmettle.fixture_quota_refs (
        scope_id uuid, reservation_id uuid, request_id uuid,
        FOREIGN KEY (scope_id,reservation_id) REFERENCES openmettle.gateway_reservations (scope_id,id),
        FOREIGN KEY (scope_id,request_id) REFERENCES openmettle.gateway_requests (scope_id,id))",
    )
    .await
    .unwrap();
    let quota_ref = |sc, reservation, request| {
        sqlx::query("INSERT INTO openmettle.fixture_quota_refs VALUES ($1::uuid,$2::uuid,$3::uuid)")
            .bind(sc)
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
        .fetch_one(&mut c)
        .await
        .unwrap(),
        10
    );
}

async fn prelocked_settlement<'q>(
    pool: &PgPool,
    request: &str,
    query: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT 1 FROM openmettle.gateway_requests WHERE id=$1::uuid FOR NO KEY UPDATE")
        .bind(request)
        .execute(&mut *tx)
        .await?;
    let result = query.execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(result)
}

async fn check_settlement_finality(owner: &PgPool, run_request: &str, direct_request: &str) {
    let report = |request,
                  source,
                  revision: i64,
                  final_report,
                  prompt: Option<i64>,
                  completion: Option<i64>,
                  reasoning: Option<i64>,
                  included: Option<bool>| {
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
            (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens,reasoning_tokens,reasoning_included)
            SELECT id,coalesce($2::uuid,report_source),gen_random_uuid(),$3,$4,$5,$6,$7,$8
            FROM openmettle.gateway_requests WHERE id=$1::uuid",
        )
        .bind(request)
        .bind(source)
        .bind(revision)
        .bind(final_report)
        .bind(prompt)
        .bind(completion)
        .bind(reasoning)
        .bind(included)
    };
    assert_eq!(
        sqlstate(
            report(run_request, Some(LEASE), 1, false, None, None, None, None)
                .execute(owner)
                .await
        ),
        "23503"
    );
    assert_eq!(
        sqlstate(
            report(run_request, None, 1, false, None, None, Some(0), None)
                .execute(owner)
                .await
        ),
        "23514"
    );
    for (revision, final_report, prompt, completion, included) in [
        (1, false, None, None, false),
        (2, true, Some(2), Some(5), true),
        (3, false, Some(2), Some(5), true),
        (4, true, Some(2), Some(5), false),
    ] {
        report(
            run_request,
            None,
            revision,
            final_report,
            prompt,
            completion,
            Some(5),
            Some(included),
        )
        .execute(owner)
        .await
        .unwrap();
    }
    // A different report ID or finality cannot reuse the request revision.
    assert_eq!(
        sqlstate(
            report(run_request, None, 1, true, Some(1), Some(1), None, None)
                .execute(owner)
                .await
        ),
        "23505"
    );

    let settlement = |request, revision: i64, final_report, measured: Option<i64>, out: i64| {
        sqlx::query(
            "INSERT INTO openmettle.gateway_settlements (request_id,revision,final,measured,outstanding)
             VALUES ($1::uuid,$2,$3,$4,$5) ON CONFLICT (request_id) DO NOTHING",
        )
        .bind(request)
        .bind(revision)
        .bind(final_report)
        .bind(measured)
        .bind(out)
    };
    let update = |revision: i64, final_report, measured: i64, out: i64| {
        sqlx::query(
            "UPDATE openmettle.gateway_settlements SET revision=$2,final=$3,measured=$4,outstanding=$5
              WHERE request_id=$1::uuid",
        )
        .bind(run_request)
        .bind(revision)
        .bind(final_report)
        .bind(measured)
        .bind(out)
    };
    let unresolved = |request| {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT FROM openmettle.gateway_requests WHERE id=$1::uuid AND state='handed_off' AND NOT settled_final)",
        )
        .bind(request)
    };

    assert!(unresolved(run_request).fetch_one(owner).await.unwrap());
    assert_eq!(
        sqlstate(
            prelocked_settlement(
                owner,
                run_request,
                settlement(run_request, 1, true, Some(5), 0)
            )
            .await
        ),
        "23503"
    );
    prelocked_settlement(
        owner,
        run_request,
        settlement(run_request, 1, false, Some(5), 5),
    )
    .await
    .unwrap();
    assert_eq!(
        prelocked_settlement(
            owner,
            run_request,
            settlement(run_request, 2, true, Some(7), 0)
        )
        .await
        .unwrap()
        .rows_affected(),
        0
    );
    assert!(unresolved(run_request).fetch_one(owner).await.unwrap());
    assert_eq!(
        sqlstate(prelocked_settlement(owner, run_request, update(2, false, 7, 3)).await),
        "23503"
    );
    // Final settlement must fold quota holds in the same transaction.
    {
        let mut tx = owner.begin().await.unwrap();
        sqlx::query(
            "SELECT 1 FROM openmettle.gateway_requests WHERE id=$1::uuid FOR NO KEY UPDATE",
        )
        .bind(run_request)
        .execute(&mut *tx)
        .await
        .unwrap();
        update(2, true, 7, 0).execute(&mut *tx).await.unwrap();
        sqlx::query(
            "SELECT openmettle.quota_settle_gateway_usage(request_id,source,report_id,revision)
               FROM openmettle.gateway_usage_reports WHERE request_id=$1::uuid AND revision=2",
        )
        .bind(run_request)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    assert!(!unresolved(run_request).fetch_one(owner).await.unwrap());
    assert_eq!(
        sqlstate(prelocked_settlement(owner, run_request, update(3, false, 7, 3)).await),
        "23514"
    );
    {
        let mut tx = owner.begin().await.unwrap();
        sqlx::query(
            "SELECT 1 FROM openmettle.gateway_requests WHERE id=$1::uuid FOR NO KEY UPDATE",
        )
        .bind(run_request)
        .execute(&mut *tx)
        .await
        .unwrap();
        update(4, true, 12, 0).execute(&mut *tx).await.unwrap();
        sqlx::query(
            "SELECT openmettle.quota_settle_gateway_usage(request_id,source,report_id,revision)
               FROM openmettle.gateway_usage_reports WHERE request_id=$1::uuid AND revision=4",
        )
        .bind(run_request)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    assert_eq!(
        sqlstate(prelocked_settlement(owner, run_request, update(2, true, 7, 0)).await),
        "23514"
    );

    // A request can also receive its first settlement as a final report.
    assert!(unresolved(direct_request).fetch_one(owner).await.unwrap());
    report(direct_request, None, 1, true, Some(3), Some(2), None, None)
        .execute(owner)
        .await
        .unwrap();
    {
        let mut tx = owner.begin().await.unwrap();
        sqlx::query(
            "SELECT 1 FROM openmettle.gateway_requests WHERE id=$1::uuid FOR NO KEY UPDATE",
        )
        .bind(direct_request)
        .execute(&mut *tx)
        .await
        .unwrap();
        settlement(direct_request, 1, true, Some(5), 0)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "SELECT openmettle.quota_settle_gateway_usage(request_id,source,report_id,revision)
               FROM openmettle.gateway_usage_reports WHERE request_id=$1::uuid AND revision=1",
        )
        .bind(direct_request)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    assert!(!unresolved(direct_request).fetch_one(owner).await.unwrap());

    // Revision 3 was stored in reports but refused by the settlement ledger.
    let reconcile = |rev: i64| {
        sqlx::query(
            "SELECT openmettle.quota_settle_gateway_usage(request_id,source,report_id,revision)
            FROM openmettle.gateway_usage_reports WHERE request_id=$1::uuid AND revision=$2",
        )
        .bind(run_request)
        .bind(rev)
    };
    assert_eq!(sqlstate(reconcile(3).execute(owner).await), "23514");
    assert_eq!(
        sqlstate(
            sqlx::query(
                "SELECT openmettle.quota_settle_gateway_usage(request_id,source,gen_random_uuid(),revision)
                 FROM openmettle.gateway_usage_reports WHERE request_id=$1::uuid AND revision=1"
            )
            .bind(run_request)
            .execute(owner)
            .await
        ),
        "23514"
    );
    for rev in [4, 1, 2, 4] {
        reconcile(rev).execute(owner).await.unwrap();
    }
    let folded: (String, String, i64) = sqlx::query_as(
        "SELECT state,settled_units::text,accepted_source_revision
         FROM openmettle.quota_reservations WHERE gateway_request_id=$1::uuid AND resource_kind='usage_tokens'",
    )
    .bind(run_request)
    .fetch_one(owner)
    .await
    .unwrap();
    assert_eq!(folded, ("settled".into(), "12".into(), 4));

    // A final total can exceed bigint (`3 * i64::MAX`), and a later complete correction can reset to 0.
    for (rev, component, expected) in [(5, i64::MAX, "27670116110564327421"), (6, 0, "0")] {
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
             (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens,reasoning_tokens,reasoning_included)
             SELECT id,report_source,gen_random_uuid(),$2,true,$3,$3,$3,false
               FROM openmettle.gateway_requests WHERE id=$1::uuid",
        )
        .bind(run_request)
        .bind(rev as i64)
        .bind(component)
        .execute(owner)
        .await
        .unwrap();
        let mut tx = owner.begin().await.unwrap();
        sqlx::query(
            "SELECT 1 FROM openmettle.gateway_requests WHERE id=$1::uuid FOR NO KEY UPDATE",
        )
        .bind(run_request)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_settlements SET revision=$2,final=true,
             measured=$3::text::numeric,outstanding=0 WHERE request_id=$1::uuid",
        )
        .bind(run_request)
        .bind(rev as i64)
        .bind(expected)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "SELECT openmettle.quota_settle_gateway_usage(request_id,source,report_id,revision)
             FROM openmettle.gateway_usage_reports WHERE request_id=$1::uuid AND revision=$2",
        )
        .bind(run_request)
        .bind(rev as i64)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let recorded: (String, String, i64, i64) = sqlx::query_as(
            "SELECT state,settled_units::text,held_units,accepted_source_revision
             FROM openmettle.quota_reservations WHERE gateway_request_id=$1::uuid AND resource_kind='usage_tokens'",
        )
        .bind(run_request)
        .fetch_one(owner)
        .await
        .unwrap();
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
            "GRANT SELECT ON openmettle.gateway_requests TO openmettle_gateway",
            "REVOKE SELECT ON openmettle.gateway_requests FROM openmettle_gateway",
            "openmettle_gateway has SELECT on openmettle.gateway_requests",
        ),
        (
            "GRANT UPDATE (lock_guard) ON openmettle.projects TO openmettle_gateway",
            "REVOKE UPDATE (lock_guard) ON openmettle.projects FROM openmettle_gateway",
            "openmettle_gateway has UPDATE on openmettle.projects.lock_guard",
        ),
        (
            "GRANT EXECUTE ON FUNCTION openmettle.quota_lock_gateway_request_for_settlement(uuid) TO openmettle_gateway",
            "REVOKE EXECUTE ON FUNCTION openmettle.quota_lock_gateway_request_for_settlement(uuid) FROM openmettle_gateway",
            "openmettle_gateway has EXECUTE on function openmettle.quota_lock_gateway_request_for_settlement(uuid)",
        ),
        (
            "GRANT INSERT (id) ON openmettle.gateway_requests TO openmettle_api",
            "REVOKE INSERT (id) ON openmettle.gateway_requests FROM openmettle_api",
            "openmettle_api has INSERT on openmettle.gateway_requests.id",
        ),
        (
            "GRANT EXECUTE ON FUNCTION openmettle.gateway_release(uuid,bytea) TO openmettle_api",
            "REVOKE EXECUTE ON FUNCTION openmettle.gateway_release(uuid,bytea) FROM openmettle_api",
            "openmettle_api has EXECUTE on function openmettle.gateway_release(uuid,bytea)",
        ),
        (
            "ALTER FUNCTION openmettle.gateway_release(uuid,bytea) SET search_path=public",
            "ALTER FUNCTION openmettle.gateway_release(uuid,bytea) SET search_path=pg_catalog",
            "unsafe or missing gateway function openmettle.gateway_release(uuid,bytea)",
        ),
        (
            "GRANT EXECUTE ON FUNCTION openmettle.gateway_settle_report(uuid,uuid,uuid,uuid,uuid,uuid,bigint,boolean,bigint,bigint,bigint,boolean,numeric,text,text) TO PUBLIC",
            "REVOKE EXECUTE ON FUNCTION openmettle.gateway_settle_report(uuid,uuid,uuid,uuid,uuid,uuid,bigint,boolean,bigint,bigint,bigint,boolean,numeric,text,text) FROM PUBLIC",
            "unsafe or missing quota function openmettle.gateway_settle_report(",
        ),
        (
            "REVOKE EXECUTE ON FUNCTION openmettle.gateway_settle_report(uuid,uuid,uuid,uuid,uuid,uuid,bigint,boolean,bigint,bigint,bigint,boolean,numeric,text,text) FROM openmettle_gateway",
            "GRANT EXECUTE ON FUNCTION openmettle.gateway_settle_report(uuid,uuid,uuid,uuid,uuid,uuid,bigint,boolean,bigint,bigint,bigint,boolean,numeric,text,text) TO openmettle_gateway",
            "unsafe or missing quota function openmettle.gateway_settle_report(",
        ),
        (
            "ALTER FUNCTION openmettle.gateway_settle_report(uuid,uuid,uuid,uuid,uuid,uuid,bigint,boolean,bigint,bigint,bigint,boolean,numeric,text,text) SET search_path=public",
            "ALTER FUNCTION openmettle.gateway_settle_report(uuid,uuid,uuid,uuid,uuid,uuid,bigint,boolean,bigint,bigint,bigint,boolean,numeric,text,text) SET search_path=pg_catalog",
            "unsafe or missing quota function openmettle.gateway_settle_report(",
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
