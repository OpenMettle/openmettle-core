//! ADR 0033 PR2. The owner backdates synthetic deadlines. Store callers use their runtime roles.
use super::authz_runs::{cancelled_once, personal_of, terminal_events};
use super::authz_store::{
    Account, FUTURE, NOW, PROVIDER, UNKNOWN, account, applied, ctx, make_admin, principal,
    providers,
};
use super::run_admission::{
    LEASES, OPEN, admitted, api, bare_run, events, new_project, owner_exec, request, worker,
};
use super::*;
use openmettle_core::{
    authz::{
        leases::*,
        projects,
        runs::{self as queue, CancelOutcome, ClaimedRun, RunRecheckOutcome, RunRecheckRequest},
        store::{self, StoreError},
    },
    runs::{self as durable, Intent, Observation, Payload, WriteTransaction},
};

struct Fixture {
    db: TestDb,
    actor: Account,
    scope: String,
}

impl Fixture {
    async fn new() -> Self {
        Self::on(TestDb::migrated().await).await
    }

    async fn on(db: TestDb) -> Self {
        super::run_admission::seed_token_budget(&db).await;
        let mut owner = connect(&db.0, OWNER).await;
        providers(&mut owner).await;
        let actor = account(&mut owner, PROVIDER, true, FUTURE).await;
        let scope = personal_of(&db, &actor).await;
        Self { db, actor, scope }
    }

    async fn admit(&self, key: &str) -> String {
        let r = request(&self.db, &self.scope, "personal", &self.actor, key).await;
        admitted(&self.db, &r).await
    }

    async fn claim(&self, key: &str) -> ClaimedRun {
        let id = self.admit(key).await;
        let run = queue::claim_next(&mut worker(&self.db).await, &OPEN, &LEASES)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(run.run_id, id);
        run
    }

    async fn cancel(&self, run: &ClaimedRun) -> CancelOutcome {
        let p = principal(&self.db, &self.actor).await;
        queue::cancel_run(&mut api(&self.db).await, &p, &run.scope_id, &run.run_id)
            .await
            .unwrap()
    }
}

const EVIDENCE: Payload<'static> = Payload {
    format: "synthetic.evidence",
    version: 1,
    bytes: b"{}",
};

async fn intent(
    c: &mut PgConnection,
    l: &Lease<'_>,
    capability: &str,
) -> Result<String, LeaseError> {
    with_lease(c, l, Fence::Step, async |tx, _| {
        durable::record_intent(
            tx,
            &Intent {
                scope: l.scope_id,
                run: l.run_id,
                key: capability,
                target: "synthetic-tool",
                capability,
                request: EVIDENCE,
            },
        )
        .await
    })
    .await
}

async fn observe(
    c: &mut PgConnection,
    l: &Lease<'_>,
    op: &str,
    outcome: &str,
) -> Result<i64, LeaseError> {
    with_lease(c, l, Fence::Hold, async |tx, _| {
        durable::record_observation(
            tx,
            &Observation {
                scope: l.scope_id,
                run: l.run_id,
                operation: op,
                key: "observed",
                expected_revision: 0,
                outcome,
                handle: Some("synthetic-handle"),
                evidence: EVIDENCE,
            },
        )
        .await
    })
    .await
}

async fn deadlines(c: &mut PgConnection, id: &str) -> (String, String) {
    sqlx::query_as("SELECT lease_expires_at::text, execution_expires_at::text FROM openmettle.runs WHERE id = $1::uuid")
        .bind(id).fetch_one(c).await.unwrap()
}

async fn make_due(db: &TestDb, run: &ClaimedRun) {
    owner_exec(db, "UPDATE openmettle.runs SET lease_expires_at = now(), execution_expires_at = now() WHERE id = $1::uuid", &run.run_id).await;
}

async fn terminal(db: &TestDb, id: &str, format: &str, bytes: &[u8]) {
    assert_eq!(
        terminal_events(db, id).await,
        [(format.to_owned(), bytes.to_vec())]
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for isolated PostgreSQL 18"]
async fn worker_expires_waits_when_the_queued_sweep_fails() {
    let f = Fixture::new().await;
    let bare = request(&f.db, &f.scope, "personal", &f.actor, "broken-queue").await;
    let queued = bare_run(&f.db, &bare).await;
    let waiting = f.admit("legacy-wait").await;
    let mut owner = connect(&f.db.0, OWNER).await;
    sqlx::query("UPDATE openmettle.runs SET state='waiting' WHERE id=$1::uuid")
        .bind(&waiting)
        .execute(&mut owner)
        .await
        .unwrap();
    // A conflicting terminal event rolls back every attempt to expire the queued row.
    let mut tx = WriteTransaction::begin(&mut owner).await.unwrap();
    durable::append_event(&mut tx, &f.scope, &queued, "run-terminal", EVIDENCE)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(
        queue::expire_queued(&mut worker(&f.db).await, 100).await,
        Err(StoreError::Conflict(_))
    ));

    let _worker = Process(
        binary("worker")
            .env("OPENMETTLE_WORKER_DATABASE_URL", f.db.url(WORKER))
            .env("OPENMETTLE_WORKER_BIND", address())
            .env("OPENMETTLE_WORKER_SWEEP_MS", "1000")
            .spawn()
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        while terminal_events(&f.db, &waiting).await.is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("worker did not settle the waiting run");
    terminal(
        &f.db,
        &waiting,
        "openmettle.run-invalid-wait",
        br#"{"reason":"invalid_wait"}"#,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for isolated PostgreSQL 18"]
async fn duplicate_claims_and_reclaims_emit_one_event_per_token() {
    let f = Fixture::new().await;
    let id = f.admit("only").await;
    let (mut a, mut b) = (worker(&f.db).await, worker(&f.db).await);
    let (x, y) = tokio::join!(
        queue::claim_next(&mut a, &OPEN, &LEASES),
        queue::claim_next(&mut b, &OPEN, &LEASES)
    );
    let claims: Vec<_> = [x.unwrap(), y.unwrap()].into_iter().flatten().collect();
    let [run] = claims.as_slice() else {
        panic!("expected exactly one claim")
    };
    assert_eq!(run.run_id, id);
    assert!(run.lease_remaining > Duration::ZERO && run.lease_remaining <= LEASES.lease);
    assert!(
        run.execution_remaining > run.lease_remaining
            && run.execution_remaining <= LEASES.execution_timeout
    );
    let (_, deadline) = deadlines(&mut a, &id).await;
    release_lease(&mut a, &run.lease()).await.unwrap();

    // Reclaim keeps its existing executing slot. It can run while dispatch is locked.
    let mut owner = connect(&f.db.0, OWNER).await;
    let mut dispatch = owner.begin().await.unwrap();
    dispatch
        .execute("SELECT FROM openmettle.run_dispatch_lock FOR NO KEY UPDATE")
        .await
        .unwrap();
    let (x, y) = tokio::join!(reclaim_next(&mut a, &LEASES), reclaim_next(&mut b, &LEASES));
    let reclaims: Vec<_> = [x.unwrap(), y.unwrap()].into_iter().flatten().collect();
    let [new] = reclaims.as_slice() else {
        panic!("expected exactly one reclaim")
    };
    assert_eq!((new.state, new.cancel), (ExecState::Running, None));
    assert_ne!(run.claim_token, new.run.claim_token);
    assert_eq!(deadline, deadlines(&mut b, &id).await.1);
    let history = events(&f.db, &id).await;
    assert_eq!(history.len(), 3);
    assert_eq!(
        history[1],
        (
            2,
            format!("claim:{}", run.claim_token),
            "openmettle.run-claimed".into(),
            b"{}".to_vec()
        )
    );
    assert_eq!(
        history[2],
        (
            3,
            format!("reclaim:{}", new.run.claim_token),
            "openmettle.run-reclaimed".into(),
            b"{}".to_vec()
        )
    );
    dispatch.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for isolated PostgreSQL 18"]
async fn stale_and_lapsed_holders_cannot_write_observe_renew_or_settle() {
    let f = Fixture::new().await;
    let run = f.claim("stale").await;
    let mut c = worker(&f.db).await;
    let l = run.lease();
    let op = intent(&mut c, &l, "repeatable_read").await.unwrap();
    release_lease(&mut c, &l).await.unwrap();
    assert!(matches!(
        renew_lease(&mut c, &l, &LEASES).await,
        Err(LeaseError::Expired)
    ));
    let new = reclaim_next(&mut c, &LEASES).await.unwrap().unwrap();
    let before = events(&f.db, &run.run_id).await;
    assert!(matches!(
        intent(&mut c, &l, "lookup").await,
        Err(LeaseError::StaleClaim)
    ));
    assert!(matches!(
        observe(&mut c, &l, &op, "succeeded").await,
        Err(LeaseError::StaleClaim)
    ));
    assert!(matches!(
        renew_lease(&mut c, &l, &LEASES).await,
        Err(LeaseError::StaleClaim)
    ));
    assert!(matches!(
        settle(&mut c, &l, &LEASES, Settle::Succeeded).await,
        Err(LeaseError::StaleClaim)
    ));
    assert!(matches!(
        release_lease(
            &mut c,
            &Lease {
                scope_id: UNKNOWN,
                ..l
            }
        )
        .await,
        Err(LeaseError::Store(StoreError::NotFound))
    ));
    assert_eq!(before, events(&f.db, &run.run_id).await);
    assert_eq!(
        settle(&mut c, &new.run.lease(), &LEASES, Settle::Succeeded)
            .await
            .unwrap(),
        Settled::Terminal { state: "succeeded" }
    );
    assert!(
        matches!(intent(&mut c, &l, "lookup").await, Err(LeaseError::Terminal { state }) if state == "succeeded")
    );
    terminal(&f.db, &run.run_id, "openmettle.run-succeeded", b"{}").await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for isolated PostgreSQL 18"]
async fn renewal_never_shortens_outlives_the_deadline_or_revives_a_lease() {
    let f = Fixture::new().await;
    let run = f.claim("renew").await;
    let mut c = worker(&f.db).await;
    owner_exec(
        &f.db,
        "UPDATE openmettle.runs SET lease_expires_at = execution_expires_at WHERE id = $1::uuid",
        &run.run_id,
    )
    .await;
    let original = deadlines(&mut c, &run.run_id).await;
    let held = renew_lease(&mut c, &run.lease(), &LEASES).await.unwrap();
    assert!(held.lease_remaining > LEASES.lease);
    assert_eq!(original, deadlines(&mut c, &run.run_id).await);
    owner_exec(&f.db, "UPDATE openmettle.runs SET lease_expires_at = now() + interval '1 second', execution_expires_at = now() + interval '15 seconds' WHERE id = $1::uuid", &run.run_id).await;
    renew_lease(&mut c, &run.lease(), &LEASES).await.unwrap();
    let (lease, execution) = deadlines(&mut c, &run.run_id).await;
    assert_eq!(lease, execution);
    release_lease(&mut c, &run.lease()).await.unwrap();
    assert!(matches!(
        renew_lease(&mut c, &run.lease(), &LEASES).await,
        Err(LeaseError::Expired)
    ));
    assert!(reclaim_next(&mut c, &LEASES).await.unwrap().is_none());
    assert!(settle_expired(&mut c, 1).await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for isolated PostgreSQL 18"]
async fn idle_fenced_transaction_rolls_back_then_recovery_can_take_the_row() {
    let f = Fixture::new().await;
    let run = f.claim("idle").await;
    let mut c = worker(&f.db).await;
    // Leave enough time to enter the fence. Recovery skips the lock while the writer is idle.
    let (mut other, l) = (worker(&f.db).await, run.lease());
    let (ready, started) = tokio::sync::oneshot::channel();
    let idle = with_lease(&mut c, &l, Fence::Step, async |tx, _| {
        durable::append_event(tx, l.scope_id, l.run_id, "uncommitted", EVIDENCE).await?;
        ready.send(()).unwrap();
        tokio::time::sleep(Duration::from_millis(5500)).await;
        Ok(())
    });
    let recover = async {
        started.await.unwrap();
        assert!(reclaim_next(&mut other, &LEASES).await.unwrap().is_none());
        // Backdating queues behind the held lock. Only the server's idle timeout releases it.
        owner_exec(
            &f.db,
            "UPDATE openmettle.runs SET lease_expires_at = now() WHERE id = $1::uuid",
            &run.run_id,
        )
        .await;
        reclaim_next(&mut other, &LEASES).await.unwrap().unwrap()
    };
    let (result, new) = tokio::join!(idle, recover);
    assert!(matches!(
        result,
        Err(LeaseError::Store(StoreError::Database(_)))
    ));
    assert_ne!(run.claim_token, new.run.claim_token);
    assert!(
        events(&f.db, &run.run_id)
            .await
            .iter()
            .all(|e| e.1 != "uncommitted")
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for isolated PostgreSQL 18"]
async fn cooperative_cancellation_stops_new_work_and_allows_inflight_observation() {
    let f = Fixture::new().await;
    let run = f.claim("cancel").await;
    let (l, mut c) = (run.lease(), worker(&f.db).await);
    let op = intent(&mut c, &l, "lookup").await.unwrap();
    let before = deadlines(&mut api(&f.db).await, l.run_id).await;
    for _ in 0..2 {
        assert_eq!(
            f.cancel(&run).await,
            CancelOutcome::Requested {
                state: "cancelling".into()
            }
        );
    }
    let history = events(&f.db, l.run_id).await;
    assert_eq!(history.len(), 4);
    assert_eq!(
        history[3],
        (
            4,
            "cancel-requested".into(),
            "openmettle.run-cancel-requested".into(),
            br#"{"reason":"requested"}"#.to_vec()
        )
    );
    assert!(terminal_events(&f.db, l.run_id).await.is_empty());
    let mut api = api(&f.db).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    durable::append_event(&mut tx, l.scope_id, l.run_id, "api-event", EVIDENCE)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(deadlines(&mut api, l.run_id).await, before);
    let held = renew_lease(&mut c, &l, &LEASES).await.unwrap();
    assert_eq!(
        (held.state, held.cancel),
        (ExecState::Cancelling, Some(CancelReason::Requested))
    );
    assert!(matches!(
        intent(&mut c, &l, "non_repeatable").await,
        Err(LeaseError::Stopping(_))
    ));
    assert_eq!(observe(&mut c, &l, &op, "succeeded").await.unwrap(), 1);
    assert_eq!(
        settle(&mut c, &l, &LEASES, Settle::Stopped).await.unwrap(),
        Settled::Terminal { state: "cancelled" }
    );
    cancelled_once(&f.db, l.run_id, "requested").await;
    assert!(matches!(
        observe(&mut c, &l, &op, "succeeded").await,
        Err(LeaseError::Terminal { .. })
    ));
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for isolated PostgreSQL 18"]
async fn completion_racing_cancellation_reports_finished_work_once() {
    let f = Fixture::new().await;
    let run = f.claim("race").await;
    let (mut c, mut api) = (worker(&f.db).await, api(&f.db).await);
    let (l, p) = (run.lease(), principal(&f.db, &f.actor).await);
    let (cancel, done) = tokio::join!(
        queue::cancel_run(&mut api, &p, l.scope_id, l.run_id),
        settle(&mut c, &l, &LEASES, Settle::Succeeded)
    );
    assert!(matches!(
        cancel.unwrap(),
        CancelOutcome::Requested { .. } | CancelOutcome::Terminal { .. }
    ));
    assert_eq!(done.unwrap(), Settled::Terminal { state: "succeeded" });
    terminal(&f.db, l.run_id, "openmettle.run-succeeded", b"{}").await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for isolated PostgreSQL 18"]
async fn uncertain_effects_reconcile_once_and_are_never_replayed() {
    let f = Fixture::new().await;
    let mut c = worker(&f.db).await;
    for (capability, unknown) in [
        ("lookup", true),
        ("non_repeatable", false),
        ("idempotent", false),
        ("idempotent", true),
    ] {
        let run = f.claim(&format!("{capability}-{unknown}")).await;
        let l = run.lease();
        let id = intent(&mut c, &l, capability).await.unwrap();
        if unknown {
            observe(&mut c, &l, &id, "outcome_unknown").await.unwrap();
        }
        let ops = unresolved_operations(&mut c, &l, 1).await.unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].id, id);
        assert_eq!(
            ops[0].downstream_handle.as_deref(),
            unknown.then_some("synthetic-handle")
        );
        assert!(matches!(
            settle(&mut c, &l, &LEASES, Settle::Succeeded).await,
            Err(LeaseError::Store(StoreError::Conflict(
                "unresolved operation"
            )))
        ));
        assert_eq!(
            settle(&mut c, &l, &LEASES, Settle::Stopped).await.unwrap(),
            Settled::Reconciling { unresolved: 1 }
        );
        assert_eq!(
            f.cancel(&run).await,
            CancelOutcome::Requested {
                state: "reconciling".into()
            }
        );
        release_lease(&mut c, &l).await.unwrap();
        let new = reclaim_next(&mut c, &LEASES).await.unwrap().unwrap();
        assert_eq!(
            (new.state, new.cancel),
            (ExecState::Reconciling, Some(CancelReason::Requested))
        );
        assert_eq!(
            ops,
            unresolved_operations(&mut c, &new.run.lease(), 1000)
                .await
                .unwrap()
        );
        let tables = ["operations"];
        let before = snapshot(&mut c, &tables).await;
        make_due(&f.db, &run).await;
        assert_eq!(settle_expired(&mut c, 1).await.unwrap(), [l.run_id]);
        assert_eq!(before, snapshot(&mut c, &tables).await);
        terminal(
            &f.db,
            l.run_id,
            "openmettle.run-interrupted",
            br#"{"unresolved":1}"#,
        )
        .await;
        let history = events(&f.db, l.run_id).await;
        let transitions: Vec<_> = history
            .iter()
            .filter(|e| e.1 == "run-reconciling")
            .collect();
        assert_eq!(transitions.len(), 1);
        assert_eq!(
            (&*transitions[0].2, transitions[0].3.as_slice()),
            (
                "openmettle.run-reconciling",
                br#"{"unresolved":1}"#.as_slice()
            )
        );
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for isolated PostgreSQL 18"]
async fn recovered_intents_keep_their_identity_and_only_reads_are_repeatable() {
    let f = Fixture::new().await;
    let run = f.claim("resume").await;
    let mut c = worker(&f.db).await;
    let mut ids = Vec::new();
    for cap in ["repeatable_read", "idempotent"] {
        ids.push((cap, intent(&mut c, &run.lease(), cap).await.unwrap()));
    }
    release_lease(&mut c, &run.lease()).await.unwrap();
    let new = reclaim_next(&mut c, &LEASES).await.unwrap().unwrap();
    let l = new.run.lease();
    let unresolved = unresolved_operations(&mut c, &l, 2).await.unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0].id, ids[1].1);
    let req = RunRecheckRequest {
        scope_id: l.scope_id,
        run_id: l.run_id,
        actor_approval_id: &run.actor_approval_id,
        capabilities: &[],
        extra_target: None,
        now_ms: NOW,
    };
    assert_eq!(
        queue::recheck_leased(&mut c, &l, &req, &LEASES)
            .await
            .unwrap(),
        RunRecheckOutcome::Continue
    );
    for (cap, id) in ids {
        assert_eq!(intent(&mut c, &l, cap).await.unwrap(), id);
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for isolated PostgreSQL 18"]
async fn deadline_sweeps_reclaim_and_late_settlement_have_one_outcome() {
    let f = Fixture::new().await;
    let run = f.claim("deadline").await;
    make_due(&f.db, &run).await;
    let (mut a, mut b, mut c, mut d) = (
        worker(&f.db).await,
        worker(&f.db).await,
        worker(&f.db).await,
        worker(&f.db).await,
    );
    let l = run.lease();
    let (first, second, reclaim, late) = tokio::join!(
        settle_expired(&mut a, 1),
        settle_expired(&mut b, 1),
        reclaim_next(&mut c, &LEASES),
        settle(&mut d, &l, &LEASES, Settle::Succeeded)
    );
    let mut ids = first.unwrap();
    ids.extend(second.unwrap());
    // Both sweeps may skip the row while the late holder locks it to classify the lapse.
    ids.extend(settle_expired(&mut a, 1).await.unwrap());
    assert_eq!(ids, [l.run_id]);
    assert!(reclaim.unwrap().is_none());
    assert!(matches!(
        late,
        Err(LeaseError::Expired | LeaseError::Terminal { .. })
    ));
    terminal(
        &f.db,
        l.run_id,
        "openmettle.run-failed",
        br#"{"reason":"deadline_exceeded"}"#,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for isolated PostgreSQL 18"]
async fn version_20_column_grants_and_constraints_are_minimal() {
    let f = Fixture::new().await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let id = f.admit("checks").await;
    for role in [API, WORKER, ISSUANCE] {
        for column in [
            "claim_token",
            "claimed_at",
            "lease_expires_at",
            "execution_expires_at",
            "cancel_reason",
        ] {
            let (read, insert, update, grantable): (bool, bool, bool, bool) = sqlx::query_as(
                "SELECT has_column_privilege($1, 'openmettle.runs', $2, 'SELECT'),
                        has_column_privilege($1, 'openmettle.runs', $2, 'INSERT'),
                        has_column_privilege($1, 'openmettle.runs', $2, 'UPDATE'),
                        has_column_privilege($1, 'openmettle.runs', $2, 'UPDATE WITH GRANT OPTION')")
                .bind(role).bind(column).fetch_one(&mut owner).await.unwrap();
            assert_eq!(
                (read, insert, update, grantable),
                (
                    role != ISSUANCE,
                    false,
                    role == WORKER || (role == API && column == "cancel_reason"),
                    false
                ),
                "{role} {column}"
            );
        }
    }
    for column in ["lease_expires_at", "execution_expires_at"] {
        expect_state(
            &mut api(&f.db).await,
            &format!("UPDATE openmettle.runs SET {column} = now()"),
            "42501",
        )
        .await;
    }
    for change in [
        "execution_expires_at = now()",
        "lease_expires_at = now()",
        "cancel_reason = 'other'",
        "state = 'cancelling'",
    ] {
        expect_state(
            &mut owner,
            &format!("UPDATE openmettle.runs SET {change} WHERE id = '{id}'"),
            "23514",
        )
        .await;
    }
    let run = queue::claim_next(&mut worker(&f.db).await, &OPEN, &LEASES)
        .await
        .unwrap()
        .unwrap();
    expect_state(&mut owner, &format!("UPDATE openmettle.runs SET lease_expires_at = execution_expires_at + interval '1 microsecond' WHERE id = '{}'", run.run_id), "23514").await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for isolated PostgreSQL 18"]
async fn populated_v19_upgrade_preserves_rows_and_settles_legacy_claims() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..19]).await.unwrap();
    let f = Fixture::on(db).await;
    let id = f.admit("legacy").await;
    let bare = bare_run(
        &f.db,
        &request(&f.db, &f.scope, "personal", &f.actor, "bare").await,
    )
    .await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let mut tx = WriteTransaction::begin(&mut owner).await.unwrap();
    let token: String = sqlx::query_scalar("UPDATE openmettle.runs SET state = 'running', claim_token = gen_random_uuid(), claimed_at = now() WHERE id = $1::uuid RETURNING claim_token::text")
        .bind(&id).fetch_one(tx.connection().unwrap()).await.unwrap();
    durable::append_event(
        &mut tx,
        &f.scope,
        &id,
        &format!("claim:{token}"),
        Payload {
            format: "openmettle.run-claimed",
            ..EVIDENCE
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    // Snapshot every application table, including synthetic identity, membership and message rows.
    let tables: Vec<String> = sqlx::query_scalar("SELECT tablename::text FROM pg_tables WHERE schemaname = 'openmettle' AND tablename <> '_sqlx_migrations' ORDER BY tablename")
        .fetch_all(&mut owner).await.unwrap();
    let tables: Vec<_> = tables.iter().map(String::as_str).collect();
    let before = snapshot_at(&mut owner, &tables, 19).await;
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(f.db.history().await, all_versions());
    assert_eq!(snapshot_at(&mut owner, &tables, 19).await, before);
    let mut c = worker(&f.db).await;
    assert!(reclaim_next(&mut c, &LEASES).await.unwrap().is_none());
    assert_eq!(settle_expired(&mut c, 1).await.unwrap(), [id.as_str()]);
    terminal(
        &f.db,
        &id,
        "openmettle.run-failed",
        br#"{"reason":"deadline_exceeded"}"#,
    )
    .await;
    assert!(terminal_events(&f.db, &bare).await.is_empty());
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for isolated PostgreSQL 18"]
async fn archive_and_disable_keep_first_reasons_and_skip_already_requested_rows() {
    let f = Fixture::new().await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let (project, scope) = new_project(&f.db, &f.actor, "project").await;
    let mut c = worker(&f.db).await;
    let mut project_runs = Vec::new();
    for key in ["running", "already-requested", "reconciling"] {
        let id = admitted(
            &f.db,
            &request(&f.db, &scope, "project", &f.actor, key).await,
        )
        .await;
        let run = queue::claim_next(&mut c, &OPEN, &LEASES)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(run.run_id, id);
        if key == "already-requested" {
            f.cancel(&run).await;
        } else if key == "reconciling" {
            intent(&mut c, &run.lease(), "lookup").await.unwrap();
            assert_eq!(
                settle(&mut c, &run.lease(), &LEASES, Settle::Stopped)
                    .await
                    .unwrap(),
                Settled::Reconciling { unresolved: 1 }
            );
        }
        project_runs.push(run);
    }
    let personal = f.claim("disabled").await;
    applied(
        projects::archive_project(&mut api(&f.db).await, &ctx(&f.actor, "archive"), &project).await,
    );
    let before: Vec<(String, String)> = sqlx::query_as(
        "SELECT id::text, xmin::text FROM openmettle.runs WHERE scope_id = $1::uuid ORDER BY id",
    )
    .bind(&scope)
    .fetch_all(&mut owner)
    .await
    .unwrap();
    applied(
        store::disable_user(
            &mut api(&f.db).await,
            &ctx(&admin, "disable"),
            &f.actor.user,
        )
        .await,
    );
    let after: Vec<(String, String)> = sqlx::query_as(
        "SELECT id::text, xmin::text FROM openmettle.runs WHERE scope_id = $1::uuid ORDER BY id",
    )
    .bind(&scope)
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(before, after);
    for (run, (state, reason)) in project_runs.iter().chain([&personal]).zip([
        (ExecState::Cancelling, CancelReason::Revoked),
        (ExecState::Cancelling, CancelReason::Requested),
        (ExecState::Reconciling, CancelReason::Revoked),
        (ExecState::Cancelling, CancelReason::Revoked),
    ]) {
        let held = renew_lease(&mut c, &run.lease(), &LEASES).await.unwrap();
        assert_eq!((held.state, held.cancel), (state, Some(reason)));
        assert!(terminal_events(&f.db, &run.run_id).await.is_empty());
        assert_eq!(
            events(&f.db, &run.run_id)
                .await
                .iter()
                .filter(|e| e.1 == "cancel-requested")
                .count(),
            1
        );
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for isolated PostgreSQL 18"]
async fn leased_recheck_settles_revocation_under_the_fence_with_the_configured_window() {
    let f = Fixture::new().await;
    let mut c = worker(&f.db).await;
    let mut leases = Vec::new();
    for key in ["long-window", "short-window"] {
        let run = f.claim(key).await;
        intent(&mut c, &run.lease(), "lookup").await.unwrap();
        if key == "short-window" {
            owner_exec(&f.db, "UPDATE openmettle.runs SET lease_expires_at = now() + interval '15 seconds', execution_expires_at = now() + interval '20 seconds' WHERE id = $1::uuid", &run.run_id).await;
        }
        leases.push(run);
    }
    sqlx::query(
        "UPDATE openmettle.local_identity_approvals SET active = false WHERE id = $1::uuid",
    )
    .bind(&f.actor.approval)
    .execute(&mut connect(&f.db.0, OWNER).await)
    .await
    .unwrap();
    for run in &leases {
        let l = run.lease();
        let req = RunRecheckRequest {
            scope_id: l.scope_id,
            run_id: l.run_id,
            actor_approval_id: &run.actor_approval_id,
            capabilities: &[],
            extra_target: None,
            now_ms: NOW,
        };
        let before = events(&f.db, l.run_id).await;
        assert!(matches!(
            queue::recheck_leased(
                &mut c,
                &Lease {
                    claim_token: UNKNOWN,
                    ..l
                },
                &req,
                &LEASES
            )
            .await,
            Err(LeaseError::StaleClaim)
        ));
        assert!(matches!(
            queue::recheck_leased(
                &mut c,
                &l,
                &RunRecheckRequest {
                    run_id: UNKNOWN,
                    ..req
                },
                &LEASES
            )
            .await,
            Err(LeaseError::Store(StoreError::InvalidInput(_)))
        ));
        assert_eq!(before, events(&f.db, l.run_id).await);
        assert!(matches!(
            queue::recheck_leased(&mut c, &l, &req, &LEASES)
                .await
                .unwrap(),
            RunRecheckOutcome::Invalidated(_)
        ));
    }
    let long = leases[0].lease();
    let held = renew_lease(&mut c, &long, &LEASES).await.unwrap();
    assert_eq!(
        (held.state, held.cancel),
        (ExecState::Reconciling, Some(CancelReason::Revoked))
    );
    let ops = unresolved_operations(&mut c, &long, 10).await.unwrap();
    observe(&mut c, &long, &ops[0].id, "failed").await.unwrap();
    assert_eq!(
        settle(&mut c, &long, &LEASES, Settle::Stopped)
            .await
            .unwrap(),
        Settled::Terminal { state: "cancelled" }
    );
    cancelled_once(&f.db, long.run_id, "revoked").await;
    terminal(
        &f.db,
        &leases[1].run_id,
        "openmettle.run-interrupted",
        br#"{"unresolved":1}"#,
    )
    .await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for isolated PostgreSQL 18"]
async fn fence_checks_the_clock_after_a_lock_wait_and_rolls_back_body_errors() {
    let f = Fixture::new().await;
    let run = f.claim("lock-wait").await;
    let (mut c, l) = (worker(&f.db).await, run.lease());
    let result = with_lease(&mut c, &l, Fence::Step, async |tx, _| {
        durable::append_event(tx, l.scope_id, l.run_id, "rolled-back", EVIDENCE).await?;
        Err::<(), _>(durable::Error::Conflict)
    })
    .await;
    assert!(matches!(
        result,
        Err(LeaseError::Store(StoreError::Conflict(_)))
    ));
    let before = events(&f.db, l.run_id).await;
    assert_eq!(before.len(), 2);

    // The competing locker does not update the tuple. The fence must still see that the
    // lease expired while it waited. Use the DB clock to release the lock past expiry.
    owner_exec(&f.db, "UPDATE openmettle.runs SET lease_expires_at = clock_timestamp() + interval '1 second' WHERE id = $1::uuid", l.run_id).await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let mut lock = owner.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.runs WHERE id = $1::uuid FOR NO KEY UPDATE")
        .bind(l.run_id)
        .execute(&mut *lock)
        .await
        .unwrap();
    let unlock = async {
        super::authz_store::wait_for_lock_waiters(&f.db, 1).await;
        sqlx::query("SELECT pg_sleep(greatest(0, extract(epoch FROM lease_expires_at - clock_timestamp()))::float8 + 0.01)
                     FROM openmettle.runs WHERE id = $1::uuid")
            .bind(l.run_id).execute(&mut *lock).await.unwrap();
        lock.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(intent(&mut c, &l, "lookup"), unlock);
    assert!(matches!(result, Err(LeaseError::Expired)));
    assert_eq!(events(&f.db, l.run_id).await, before);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL for isolated PostgreSQL 18"]
async fn invalid_raw_cancelling_row_rolls_back_the_upgrade() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..19]).await.unwrap();
    let f = Fixture::on(db).await;
    let id = f.admit("legacy-invalid").await;
    owner_exec(
        &f.db,
        "UPDATE openmettle.runs SET state = 'cancelling' WHERE id = $1::uuid",
        &id,
    )
    .await;
    assert!(migrate::apply(&settings, MIGRATIONS).await.is_err());
    assert_eq!(f.db.history().await, versions_through(19));
    let mut owner = connect(&f.db.0, OWNER).await;
    let cols: i64 = sqlx::query_scalar("SELECT count(*) FROM information_schema.columns WHERE table_schema = 'openmettle' AND table_name = 'runs' AND column_name IN ('lease_expires_at','execution_expires_at','cancel_reason')")
        .fetch_one(&mut owner).await.unwrap();
    assert_eq!(cols, 0);
    owner_exec(
        &f.db,
        "UPDATE openmettle.runs SET state = 'running' WHERE id = $1::uuid",
        &id,
    )
    .await;
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(
        settle_expired(&mut worker(&f.db).await, 1).await.unwrap(),
        [id]
    );
}

#[path = "worker_runtime.rs"]
mod worker_runtime;

mod live_turns {
    use super::*;
    use crate::{auth_config_support::Dir, ca::Ca};
    use openmettle_core::{
        artifact_fs::{self, Upload},
        authz::branches::{
            self, Conversation, Operation, Part, Root, UserInput,
            snapshot::{Intent, Snapshots},
        },
        authz::{Grantee, ProjectRole, ResourceAccess, ResourceKind},
        model_config::{Catalog, ConfigSnapshot, SNAPSHOT_FORMAT, SNAPSHOT_VERSION, Selection},
        runs::RunInput,
    };
    use serde_json::{Value, json};
    use std::{
        path::{Path, PathBuf},
        sync::OnceLock,
    };
    use tokio::sync::{mpsc, oneshot};

    struct ModelRequest {
        path: String,
        request_id: Option<String>,
        body: Value,
        reply: oneshot::Sender<Value>,
    }
    impl ModelRequest {
        fn respond(self, value: Value) {
            self.reply.send(value).expect("gateway request still open");
        }
    }
    struct Provider {
        port: u16,
        ca: Ca,
        requests: mpsc::Receiver<ModelRequest>,
    }
    impl Provider {
        async fn new() -> Self {
            Self::with_bearer("synthetic-turn-credential".into()).await
        }
        async fn with_bearer(expected_bearer: String) -> Self {
            use http_body_util::{BodyExt, Full};
            use hyper::{Response, server::conn::http1, service::service_fn};
            use hyper_util::rt::TokioIo;
            let expected_header = Arc::new(format!("Bearer {expected_bearer}"));
            let ca = Ca::new();
            let identity = ca.leaf("provider.example.test", false);
            let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(identity.chain, identity.key)
            .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .unwrap();
            let port = listener.local_addr().unwrap().port();
            let (send, requests) = mpsc::channel(4);
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    let send = send.clone();
                    let expected_header = expected_header.clone();
                    tokio::spawn(async move {
                        let tls = acceptor.accept(stream).await.unwrap();
                        let service =
                            service_fn(move |r: hyper::Request<hyper::body::Incoming>| {
                                let send = send.clone();
                                let expected_header = expected_header.clone();
                                async move {
                                    let path = r.uri().path().to_owned();
                                    let request_id = r
                                        .headers()
                                        .get("x-request-id")
                                        .and_then(|v| v.to_str().ok())
                                        .map(str::to_owned);
                                    assert_eq!(
                                        r.headers()["authorization"],
                                        expected_header.as_str()
                                    );
                                    let bytes = r.into_body().collect().await.unwrap().to_bytes();
                                    let (reply, rx) = oneshot::channel();
                                    send.send(ModelRequest {
                                        path,
                                        request_id,
                                        body: serde_json::from_slice(&bytes).unwrap(),
                                        reply,
                                    })
                                    .await
                                    .ok()
                                    .unwrap();
                                    let value = rx.await.unwrap_or(Value::Null);
                                    Ok::<_, std::convert::Infallible>(
                                        Response::builder()
                                            .header("content-type", "application/json")
                                            .body(Full::new(bytes::Bytes::from(value.to_string())))
                                            .unwrap(),
                                    )
                                }
                            });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(tls), service)
                            .await;
                    });
                }
            });
            Self { port, ca, requests }
        }
        async fn request(&mut self) -> ModelRequest {
            tokio::time::timeout(Duration::from_secs(15), self.requests.recv())
                .await
                .expect("worker reached TLS gateway")
                .unwrap()
        }
    }

    fn worker_binary() -> &'static Path {
        static BINARY: OnceLock<PathBuf> = OnceLock::new();
        BINARY.get_or_init(|| {
            // Cargo compiles the library without cfg(test) for integration tests. Start
            // its test executable to use the real gateway with its test-only loopback resolver.
            let build = Command::new(env!("CARGO"))
                .args([
                    "test",
                    "--lib",
                    "--locked",
                    "--offline",
                    "--no-run",
                    "--message-format=json",
                ])
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .output()
                .unwrap();
            assert!(
                build.status.success(),
                "worker fixture build: {}",
                stderr(&build)
            );
            String::from_utf8(build.stdout)
                .unwrap()
                .lines()
                .filter_map(|line| {
                    let v: Value = serde_json::from_str(line).ok()?;
                    (v["target"]["name"] == "openmettle_core" && v["profile"]["test"] == true)
                        .then(|| PathBuf::from(v["executable"].as_str().unwrap()))
                })
                .next()
                .expect("library test executable")
        })
    }

    struct Chat {
        f: Fixture,
        root: Root,
        catalog: Value,
        session: Option<openmettle_core::authz::approvals::EffectSession>,
        artifacts: Option<PathBuf>,
        stop_during_observation: bool,
        unmetered: bool,
        device_grant_id: Option<String>,
    }

    impl Chat {
        async fn new() -> Self {
            Self::on(Fixture::new().await).await
        }

        async fn on(f: Fixture) -> Self {
            let root = applied(
                branches::create_conversation(
                    &mut api(&f.db).await,
                    &ctx(&f.actor, "conversation"),
                    &f.scope,
                )
                .await,
            );
            let mut catalog: Value =
                serde_json::from_slice(include_bytes!("../fixtures/conversation-catalog-v1.json"))
                    .unwrap();
            let a = &mut catalog["models"]["a"];
            a["pin"]["provider"] = "synthetic-sglang".into();
            a["reasoning_format"] = "reasoning_content".into();
            a["replay"] = json!([{"source":{"profile":a["pin"],"format":"reasoning_content"},"max_tokens_per_byte":2,"fixed_tokens":7}]);
            catalog["models"]["b"]["pin"]["provider"] = "synthetic-external".into();
            catalog["models"]["b"]["replay"] = json!([]);
            Self {
                f,
                root,
                catalog,
                session: None,
                artifacts: None,
                stop_during_observation: false,
                unmetered: false,
                device_grant_id: None,
            }
        }

        async fn with_tools(mut self) -> Self {
            let token = crate::authz_runs::seeded_session(&self.f.db, &self.f.actor, 1, None).await;
            let policy = openmettle_core::sessions::Policy::new(
                Duration::from_secs(60),
                10,
                Duration::from_secs(3),
            )
            .unwrap();
            self.session = Some(
                openmettle_core::authz::approvals::EffectSession::validate(
                    &mut api(&self.f.db).await,
                    &token,
                    &policy,
                    None,
                )
                .await
                .unwrap(),
            );
            self
        }

        async fn submit(&self, key: &str, model: &str, rounds: i64) -> (String, String) {
            self.submit_parts(key, model, rounds, &[Part::Text(key.into())])
                .await
        }

        async fn submit_parts(
            &self,
            key: &str,
            model: &str,
            rounds: i64,
            parts: &[Part],
        ) -> (String, String) {
            let f = &self.f;
            let chat = Conversation {
                scope: &f.scope,
                id: &self.root.conversation_id,
            };
            let branch = &self.root.branch_id;
            let mut c = api(&f.db).await;
            let head: Option<String> = sqlx::query_scalar("SELECT head_message_id::text FROM openmettle.branch_heads WHERE branch_id=$1::uuid")
                .bind(branch).fetch_one(&mut c).await.unwrap();
            let input: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
                .fetch_one(&mut c)
                .await
                .unwrap();
            let selection: Selection = serde_json::from_value(
                json!({"model":model,"layer":{"controls":{"output_reserve":256}}}),
            )
            .unwrap();
            let op = Operation::Append(UserInput { id: &input, parts });
            let intent = Intent {
                source_branch_id: branch,
                expected_head_message_id: head.as_deref(),
                operation: op,
                selection: &selection,
                requested_rounds: Some(rounds),
            };
            let catalog = Catalog::load(&serde_json::to_vec(&self.catalog).unwrap()).unwrap();
            let config = ConfigSnapshot {
                effective: catalog
                    .resolve(&Selection::default(), &selection, None, |_, _| true)
                    .unwrap(),
                required_capabilities: catalog.model(model).unwrap().required_capabilities.clone(),
                policy_revision: "openmettle.authz/1".into(),
            };
            let actor = principal(&f.db, &f.actor).await;
            let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
            branches::prepare_turn(
                &mut tx,
                &ctx(&f.actor, key),
                chat,
                branch,
                head.as_deref(),
                op,
            )
            .await
            .unwrap();
            let history = branches::history(tx.connection().unwrap(), &actor, chat, branch, NOW)
                .await
                .unwrap()
                .unwrap();
            let pins = Snapshots::encode(&intent, &history, &catalog, &config).unwrap();
            let capabilities: Vec<_> = config
                .required_capabilities
                .iter()
                .map(|(name, gate)| queue::CapabilityUse { name, gate: *gate })
                .collect();
            let admission = queue::RunAdmission {
                input: RunInput {
                    scope: &f.scope,
                    actor: &f.actor.user,
                    conversation: chat.id,
                    branch,
                    message: &input,
                    key,
                    format: SNAPSHOT_FORMAT,
                    version: SNAPSHOT_VERSION,
                    input: &pins.input,
                    config: &pins.config,
                },
                actor_approval_id: &f.actor.approval,
                capabilities: &capabilities,
                requested_rounds: Some(rounds),
                now_ms: NOW,
                cost_qualified: None,
            };
            let limits = queue::AdmissionLimits {
                live_per_actor: 4,
                live_per_scope: 4,
                queued_in_instance: 4,
                round_cap: 4,
                queue_timeout: Duration::from_secs(60),
            };
            let admitted = match &self.session {
                Some(session) => {
                    queue::admit_run_with_mode(&mut tx, &admission, &limits, session).await
                }
                None => queue::admit_run(&mut tx, &admission, &limits).await,
            }
            .unwrap();
            let queue::Admission::Admitted { run_id, .. } = admitted else {
                panic!("admission")
            };
            tx.commit().await.unwrap();
            (run_id, input)
        }

        async fn ensure_metered_gateway(&self) -> (String, String, [u8; 32]) {
            use openmettle_core::provider_keys::gateway::{
                Bearer, Context, GatewayKeys, GatewaySealer,
            };
            use sqlx::postgres::PgPoolOptions;

            const INSTALL: &str = "00000000-0000-4000-8000-000000000091";
            const PRINCIPAL: &str = "00000000-0000-4000-8000-000000000092";
            const BUDGET: &str = "00000000-0000-4000-8000-000000000093";
            const KEY_ID: &str = "live-turns-k1";
            const KEY_BYTES: [u8; 32] = [61; 32];

            let g_pool = PgPoolOptions::new()
                .max_connections(2)
                .connect_lazy_with(self.f.db.1.options(pg::GATEWAY));
            let existing: Option<String> = sqlx::query_scalar(
                "SELECT id::text FROM openmettle.gateway_bindings
                  WHERE installation = $1::uuid AND user_id = $2::uuid",
            )
            .bind(INSTALL)
            .bind(&self.f.actor.user)
            .fetch_optional(&g_pool)
            .await
            .unwrap();
            if existing.is_some() {
                return (INSTALL.into(), KEY_ID.into(), KEY_BYTES);
            }
            let binding: String = sqlx::query_scalar(
                "INSERT INTO openmettle.gateway_bindings (installation, user_id, principal, budget)
                 VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid) RETURNING id::text",
            )
            .bind(INSTALL)
            .bind(&self.f.actor.user)
            .bind(PRINCIPAL)
            .bind(BUDGET)
            .fetch_one(&g_pool)
            .await
            .unwrap();
            let mut owner = connect(&self.f.db.0, OWNER).await;
            let report_source: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
                .fetch_one(&mut owner)
                .await
                .unwrap();
            let scope_kind: String =
                sqlx::query_scalar("SELECT kind FROM openmettle.scopes WHERE id = $1::uuid")
                    .bind(&self.f.scope)
                    .fetch_one(&mut owner)
                    .await
                    .unwrap();
            let grant_cycle: Option<String> = if scope_kind == "project" {
                sqlx::query_scalar(
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
                .bind(&self.f.scope)
                .bind(&self.f.actor.user)
                .fetch_optional(&mut owner)
                .await
                .unwrap()
            } else {
                None
            };
            let keys = GatewayKeys::new(&[(KEY_ID.into(), KEY_BYTES)]).unwrap();
            let (finger, env) = GatewaySealer::new(keys, g_pool.clone())
                .seal(
                    &Context {
                        installation: INSTALL,
                        user_id: &self.f.actor.user,
                        binding_id: &binding,
                        principal: PRINCIPAL,
                        generation: 1,
                    },
                    &Bearer::new(b"synthetic-turn-credential").unwrap(),
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
            let models = self.catalog["models"].as_object().unwrap();
            for (model_name, model_cfg) in models {
                let mut caps = serde_json::Map::new();
                if let Some(req_caps) = model_cfg
                    .get("required_capabilities")
                    .and_then(Value::as_object)
                {
                    for (cap, gate) in req_caps {
                        caps.insert(cap.clone(), Value::Bool(gate.as_str() == Some("opt_in")));
                    }
                }
                sqlx::query(
                    "INSERT INTO openmettle.gateway_policy
                         (binding_id, revision, scope_id, approval_id, model, report_source,
                          provider_generation, approval_generation, user_generation, capabilities, grant_cycle)
                     VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4, $5::uuid, 0, 0, 0, $6::jsonb, $7::uuid)",
                )
                .bind(&binding)
                .bind(&self.f.scope)
                .bind(&self.f.actor.approval)
                .bind(model_name)
                .bind(&report_source)
                .bind(Value::Object(caps).to_string())
                .bind(grant_cycle.as_deref())
                .execute(&g_pool)
                .await
                .unwrap();
            }
            sqlx::query(
                "UPDATE openmettle.gateway_bindings
                    SET active_generation = 1, observed_revision = 1, state = 'ready'
                  WHERE id = $1::uuid",
            )
            .bind(&binding)
            .execute(&g_pool)
            .await
            .unwrap();
            (INSTALL.into(), KEY_ID.into(), KEY_BYTES)
        }

        async fn start(&self, provider: &Provider) -> Process {
            let metered = if self.unmetered {
                None
            } else {
                let (installation, key_id, key_bytes) = self.ensure_metered_gateway().await;
                Some(json!({
                    "installation": installation,
                    "key_id": key_id,
                    "key_bytes": key_bytes,
                    "device_grant_id": self.device_grant_id,
                }))
            };
            let mut child = Command::new(worker_binary())
                .env("OPENMETTLE_TEST_TURN_WORKER", "1")
                .args([
                    "--ignored",
                    "--exact",
                    "worker::turns::schema_fixture::worker_process",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()
                .unwrap();
            let input = child.stdin.as_mut().unwrap();
            serde_json::to_writer(&mut *input,&json!({"database":self.f.db.url(WORKER),"catalog":self.catalog,
                "tools":self.session.is_some(),"scope":self.f.scope,"actor":self.f.actor.user,"ca":String::from_utf8(provider.ca.pem()).unwrap(),"port":provider.port,
                "artifacts":self.artifacts,"stop_during_observation":self.stop_during_observation,"metered":metered})).unwrap();
            writeln!(input).unwrap();
            Process(child)
        }

        async fn done(&self, run: &str, state: &str, reason: Option<&str>) {
            let mut c = api(&self.f.db).await;
            tokio::time::timeout(Duration::from_secs(25), async {
                loop {
                    let stored: String =
                        sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id=$1::uuid")
                            .bind(run)
                            .fetch_one(&mut c)
                            .await
                            .unwrap();
                    if queue::is_terminal(&stored) {
                        assert_eq!(stored, state);
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("worker settlement");
            let payload = reason.map_or_else(|| json!({}), |r| json!({"reason":r}));
            terminal(
                &self.f.db,
                run,
                &format!("openmettle.run-{state}"),
                payload.to_string().as_bytes(),
            )
            .await;
        }

        async fn graph(&self) -> (i64, i64, i64, Option<String>) {
            sqlx::query_as("SELECT (SELECT count(*) FROM openmettle.messages WHERE conversation_id=$1::uuid),
            (SELECT count(*) FROM openmettle.message_turns WHERE conversation_id=$1::uuid),
            (SELECT count(*) FROM openmettle.message_parts WHERE conversation_id=$1::uuid),head_message_id::text
            FROM openmettle.branch_heads WHERE branch_id=$2::uuid")
            .bind(&self.root.conversation_id).bind(&self.root.branch_id).fetch_one(&mut api(&self.f.db).await).await.unwrap()
        }
    }

    fn completion(text: Value, reasoning: Option<&str>, usage: Value) -> Value {
        json!({"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":text,
            "reasoning_content":reasoning}}],"usage":usage})
    }

    fn tool_call(name: &str, arguments: &str) -> Value {
        json!({"choices":[{"index":0,"finish_reason":"tool_calls","message":{
            "role":"assistant","tool_calls":[{"id":"call-1","type":"function","function":{"name":name,"arguments":arguments}}]}}],
            "usage":{"prompt_tokens":71,"completion_tokens":8}})
    }

    async fn outcomes(chat: &Chat, run: &str) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT outcome FROM openmettle.operations WHERE scope_id=$1::uuid AND run_id=$2::uuid",
        )
        .bind(&chat.f.scope)
        .bind(run)
        .fetch_all(&mut worker(&chat.f.db).await)
        .await
        .unwrap()
    }

    async fn shared_image_chat(dir: &Dir) -> (Chat, Account, String, String) {
        let mut f = Fixture::new().await;
        let creator = f.actor.clone();
        let (project, scope) = new_project(&f.db, &creator, "image project").await;
        f.scope = scope;
        let editor = account(&mut connect(&f.db.0, OWNER).await, PROVIDER, true, FUTURE).await;
        let grantee = Grantee::User(editor.user.clone());
        let mut c = api(&f.db).await;
        applied(
            projects::set_project_member_role(
                &mut c,
                &ctx(&creator, "editor"),
                &project,
                &grantee,
                ProjectRole::Editor,
            )
            .await,
        );
        let mut chat = Chat::on(f).await;
        chat.catalog["models"]["a"]["required_capabilities"] = json!({"model.a":"on_by_default"});
        connect(&chat.f.db.0, OWNER).await.execute(
            "UPDATE openmettle.storage_instance SET instance_budget_bytes=1024,project_limit_bytes=1024",
        ).await.unwrap();
        let root = PathBuf::from(dir.path(""));
        let store = artifact_fs::Store::open(&root).unwrap();
        let artifact = openmettle_core::storage::upload_artifact(
            &mut c,
            &chat.f.scope,
            &creator.user,
            "image",
        )
        .await
        .unwrap();
        let upload = Upload {
            scope: &chat.f.scope,
            actor: &creator.user,
            key: "image",
            artifact: &artifact,
            max_bytes: 128,
            content_type: "multipart/form-data; boundary=sample",
        };
        let body = http_body_util::Full::new(bytes::Bytes::from_static(
            b"--sample\r\nContent-Disposition: form-data; name=\"file\"; filename=\"sample.png\"\r\nContent-Type: image/png\r\n\r\npixels\r\n\
              --sample\r\nContent-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n{}\r\n--sample--\r\n"
        ));
        let pool = sqlx::PgPool::connect(&chat.f.db.url(API)).await.unwrap();
        let image = artifact_fs::ingest(&pool, &store, &upload, body, |_| true)
            .await
            .unwrap();
        for (kind, id, access) in [
            (ResourceKind::Artifact, &artifact, ResourceAccess::Read),
            (
                ResourceKind::Conversation,
                &chat.root.conversation_id,
                ResourceAccess::Write,
            ),
        ] {
            applied(
                projects::share_resource(&mut c, &ctx(&creator, id), kind, id, &grantee, access)
                    .await,
            );
        }
        chat.f.actor = editor;
        chat.artifacts = Some(root);
        (chat, creator, artifact, image.revision)
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn worker_images_load_in_order_and_revoked_history_is_omitted() {
        let dir = Dir::new();
        let (chat, creator, artifact, revision) = shared_image_chat(&dir).await;
        let mut server = Provider::new().await;
        let parts = [
            Part::Text("describe".into()),
            Part::Attachment(revision.clone()),
        ];
        let (first, _) = chat.submit_parts("visible", "a", 2, &parts).await;
        let worker = chat.start(&server).await;
        let request = server.request().await;
        assert_eq!(
            request.body["messages"].as_array().unwrap().last().unwrap()["content"],
            json!([
                {"type":"text","text":"describe"}, {"type":"image_url","image_url":{"url":"data:image/png;base64,cGl4ZWxz"}}
            ])
        );
        request.respond(completion(json!("image received"), None, Value::Null));
        chat.done(&first, "succeeded", None).await;
        drop(worker);

        let (second, _) = chat.submit("follow up", "a", 2).await;
        // The immutable snapshot still names the revision. Revoke only the artifact share.
        applied(
            projects::unshare_resource(
                &mut api(&chat.f.db).await,
                &ctx(&creator, "unshare image"),
                ResourceKind::Artifact,
                &artifact,
                &Grantee::User(chat.f.actor.user.clone()),
            )
            .await,
        );
        let _worker = chat.start(&server).await;
        let next = server.request().await;
        let messages = next.body["messages"].as_array().unwrap();
        assert_eq!(
            messages[messages.len() - 3..],
            [
                json!({"role":"user", "content":"describe"}),
                json!({"role":"assistant", "content":"image received"}),
                json!({"role":"user", "content":"follow up"}),
            ]
        );
        assert!(!next.body.to_string().contains(&revision));
        next.respond(completion(json!("text only"), None, Value::Null));
        chat.done(&second, "succeeded", None).await;
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn revoked_run_authority_cancels_before_attachment_reads() {
        for revoke_share in [false, true] {
            let dir = Dir::new();
            let (chat, creator, _, revision) = shared_image_chat(&dir).await;
            let chat = chat.with_tools().await;
            let mut server = Provider::new().await;
            let parts = [Part::Text("describe".into()), Part::Attachment(revision)];
            let (id, _) = chat
                .submit_parts("revoke between rounds", "a", 3, &parts)
                .await;
            let _worker = chat.start(&server).await;
            let first = server.request().await;
            if revoke_share {
                applied(
                    projects::unshare_resource(
                        &mut api(&chat.f.db).await,
                        &ctx(&creator, "unshare chat"),
                        ResourceKind::Conversation,
                        &chat.root.conversation_id,
                        &Grantee::User(chat.f.actor.user.clone()),
                    )
                    .await,
                );
            } else {
                owner_exec(&chat.f.db, "INSERT INTO openmettle.user_capability_denies(user_id,capability,denied,updated_by_user_id)
                    VALUES ($1::uuid,'model.a',true,$1::uuid)", &chat.f.actor.user).await;
            }
            // Settlement must finish while even the first path read is blocked. This
            // excludes reading reasoning or opening the on-disk revision in this round.
            let mut owner = connect(&chat.f.db.0, OWNER).await;
            let mut hold = owner.begin().await.unwrap();
            hold.execute("LOCK TABLE openmettle.message_turns IN ACCESS EXCLUSIVE MODE")
                .await
                .unwrap();
            first.respond(tool_call("lookup", "{"));
            chat.done(&id, "cancelled", Some("revoked")).await;
            hold.commit().await.unwrap();
            assert!(server.requests.try_recv().is_err());
            assert!(outcomes(&chat, &id).await.is_empty());
        }
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn loss_of_identity_during_prompt_hydration_settles_revoked() {
        for retire_provider in [false, true] {
            let chat = Chat::new().await.with_tools().await;
            let mut server = Provider::new().await;
            let (id, input) = chat.submit("identity race", "a", 3).await;
            let _worker = chat.start(&server).await;
            let first = server.request().await;

            // The rejected tool arguments request another round without executing a tool.
            // Hold its prompt query after the leased authority check has succeeded.
            let mut owner = connect(&chat.f.db.0, OWNER).await;
            let mut hold = owner.begin().await.unwrap();
            hold.execute("LOCK TABLE openmettle.branch_heads IN ACCESS EXCLUSIVE MODE")
                .await
                .unwrap();
            first.respond(tool_call("lookup", "{"));
            crate::authz_store::wait_for_lock_waiters(&chat.f.db, 1).await;
            if retire_provider {
                sqlx::query("INSERT INTO openmettle.login_provider_revisions(provider_id, revision) VALUES ($1::uuid, NULL)")
                    .bind(PROVIDER).execute(&mut *hold).await.unwrap();
            } else {
                sqlx::query(
                    "UPDATE openmettle.local_identity_approvals SET expires_ms=1 WHERE id=$1::uuid",
                )
                .bind(&chat.f.actor.approval)
                .execute(&mut *hold)
                .await
                .unwrap();
            }
            hold.commit().await.unwrap();
            chat.done(&id, "cancelled", Some("revoked")).await;
            assert_eq!(chat.graph().await, (1, 1, 1, Some(input)));
            assert!(outcomes(&chat, &id).await.is_empty());
            assert!(server.requests.try_recv().is_err());
        }
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn invalid_arguments_continue_without_a_tool_effect() {
        let chat = Chat::new().await.with_tools().await;
        let mut server = Provider::new().await;
        let (id, _) = chat.submit("invalid arguments", "a", 2).await;
        let _worker = chat.start(&server).await;
        server.request().await.respond(tool_call("lookup", "{"));
        let next = server.request().await;
        let messages = next.body["messages"].as_array().unwrap();
        let error = messages.last().unwrap();
        assert_eq!(error["role"], "tool");
        assert_eq!(error["tool_call_id"], "call-1");
        assert_eq!(
            serde_json::from_str::<Value>(error["content"].as_str().unwrap()).unwrap(),
            json!({"error":{"code":"invalid_tool_arguments"}})
        );
        next.respond(completion(json!("corrected"), None, Value::Null));
        chat.done(&id, "succeeded", None).await;
        assert!(outcomes(&chat, &id).await.is_empty());
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn shutdown_mid_observation_commits_and_hands_off_the_lease() {
        let mut chat = Chat::new().await.with_tools().await;
        chat.stop_during_observation = true;
        let mut server = Provider::new().await;
        let (id, input) = chat.submit("drain observation", "a", 3).await;
        let mut child = chat.start(&server).await;
        server.request().await.respond(tool_call("lookup", "{}"));
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("worker shut down after the observation");
        assert_eq!(outcomes(&chat, &id).await, ["succeeded"]);
        let (state, released): (String, bool) = sqlx::query_as(
            "SELECT state, lease_expires_at <= clock_timestamp() FROM openmettle.runs WHERE id=$1::uuid"
        ).bind(&id).fetch_one(&mut worker(&chat.f.db).await).await.unwrap();
        assert_eq!(state, "running");
        assert!(released);
        assert_eq!(chat.graph().await, (1, 1, 1, Some(input)));
        assert!(terminal_events(&chat.f.db, &id).await.is_empty());
        assert!(server.requests.try_recv().is_err());
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn crash_after_observed_tool_refuses_restart_without_transcript() {
        let chat = Chat::new().await.with_tools().await;
        let mut server = Provider::new().await;
        let (id, input) = chat.submit("crash after lookup", "a", 4).await;
        let original = chat.start(&server).await;
        server.request().await.respond(tool_call("lookup", "{}"));
        let mut next = server.request().await;
        assert_eq!(outcomes(&chat, &id).await, ["succeeded"]);
        drop(original);
        tokio::time::timeout(Duration::from_secs(5), next.reply.closed())
            .await
            .unwrap();
        owner_exec(
            &chat.f.db,
            "UPDATE openmettle.runs SET lease_expires_at=clock_timestamp() WHERE id=$1::uuid",
            &id,
        )
        .await;
        let _replacement = chat.start(&server).await;
        chat.done(&id, "failed", Some("step_failed")).await;
        assert_eq!(outcomes(&chat, &id).await, ["succeeded"]);
        assert_eq!(
            events(&chat.f.db, &id)
                .await
                .iter()
                .filter(|e| e.2 == "openmettle.model-round")
                .count(),
            2
        );
        assert_eq!(chat.graph().await, (1, 1, 1, Some(input)));
        assert!(server.requests.try_recv().is_err());
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn invalidated_tool_intent_releases_the_reconciling_lease() {
        let chat = Chat::new().await.with_tools().await;
        let mut server = Provider::new().await;
        let (id, input) = chat.submit("changed approval", "a", 3).await;
        let _worker = chat.start(&server).await;
        let pending = server.request().await;
        let mut w = worker(&chat.f.db).await;
        let token: String =
            sqlx::query_scalar("SELECT claim_token::text FROM openmettle.runs WHERE id=$1::uuid")
                .bind(&id)
                .fetch_one(&mut w)
                .await
                .unwrap();
        let lease = Lease {
            scope_id: &chat.f.scope,
            run_id: &id,
            claim_token: &token,
        };
        super::intent(&mut w, &lease, "non_repeatable")
            .await
            .unwrap();
        // Introduce a different pending approval while the model is answering.
        // record_fenced_intent must invalidate this dispatch with one unresolved effect.
        sqlx::query("WITH pending AS (INSERT INTO openmettle.run_approvals
            (scope_id,run_id,actor_user_id,logical_key,tool_id,tool_version,canonical_arguments,
             destination,authority_evidence,binding_digest,approval_expires_at,resume_execution_expires_at)
            SELECT scope_id,id,actor_user_id,'other','lookup','1','{}','fixture','fixture',
                   sha256('fixture'),execution_expires_at,execution_expires_at FROM openmettle.runs WHERE id=$1::uuid
            RETURNING id,run_id)
            UPDATE openmettle.runs r SET approval_wait_id=p.id FROM pending p WHERE r.id=p.run_id")
            .bind(&id).execute(&mut w).await.unwrap();
        pending.respond(tool_call("lookup", "{}"));
        // The 30 s lease must be released promptly so the reconciler can claim it now.
        tokio::time::timeout(Duration::from_secs(8), async {
            while terminal_events(&chat.f.db, &id).await.is_empty() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("reconciler took the released lease");
        terminal(
            &chat.f.db,
            &id,
            "openmettle.run-interrupted",
            br#"{"unresolved":1}"#,
        )
        .await;
        let reason: String =
            sqlx::query_scalar("SELECT cancel_reason FROM openmettle.runs WHERE id=$1::uuid")
                .bind(&id)
                .fetch_one(&mut w)
                .await
                .unwrap();
        assert_eq!(reason, "revoked");
        assert_eq!(outcomes(&chat, &id).await, ["intent"]);
        assert_eq!(chat.graph().await, (1, 1, 1, Some(input)));
        assert!(server.requests.try_recv().is_err());
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn publication_validation_failure_settles_and_preserves_input() {
        let chat = Chat::new().await;
        let mut server = Provider::new().await;
        let (id, input) = chat.submit("invalid answer", "a", 2).await;
        let _worker = chat.start(&server).await;
        let pending = server.request().await;
        // The worker treats zero inserted assistant turns as a publication validation error.
        // The preceding message insert must roll back before the fresh failure fence.
        connect(&chat.f.db.0, OWNER).await.execute(
            "CREATE FUNCTION omit_answer() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$;
             CREATE TRIGGER omit_answer BEFORE INSERT ON openmettle.message_turns FOR EACH ROW EXECUTE FUNCTION omit_answer()"
        ).await.unwrap();
        pending.respond(completion(json!("valid model answer"), None, Value::Null));
        chat.done(&id, "failed", Some("step_failed")).await;
        assert_eq!(chat.graph().await, (1, 1, 1, Some(input)));
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18"]
    async fn lease_expiry_during_publication_rolls_back_all_answer_rows() {
        let chat = Chat::new().await;
        let (id, input) = chat.submit("late writer", "a", 4).await;
        let mut w = worker(&chat.f.db).await;
        let run = queue::claim_next(&mut w, &OPEN, &LEASES)
            .await
            .unwrap()
            .unwrap();
        let mut c = api(&chat.f.db).await;
        let mut blocking = c.begin().await.unwrap();
        sqlx::query("SELECT head_message_id FROM openmettle.branch_heads WHERE branch_id=$1::uuid FOR NO KEY UPDATE")
            .bind(&chat.root.branch_id).execute(&mut *blocking).await.unwrap();
        let answer_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut w)
            .await
            .unwrap();
        owner_exec(&chat.f.db,"UPDATE openmettle.runs SET lease_expires_at=clock_timestamp()+interval '1 second' WHERE id=$1::uuid",&id).await;
        let attempt = tokio::spawn(async move {
            settle_answer(
                &mut w,
                &run.lease(),
                &LEASES,
                &branches::Answer {
                    id: &answer_id,
                    parts: &[Part::Text("late answer".into())],
                    reasoning: None,
                    input_count: Some(4),
                    output_count: Some(2),
                },
            )
            .await
        });
        crate::authz_store::wait_for_lock_waiters(&chat.f.db, 1).await;
        sqlx::query("SELECT pg_sleep(greatest(0,extract(epoch FROM lease_expires_at-clock_timestamp()))::double precision)
            FROM openmettle.runs WHERE id=$1::uuid").bind(&id).execute(&mut *blocking).await.unwrap();
        blocking.commit().await.unwrap();
        assert!(matches!(attempt.await.unwrap(), Err(LeaseError::Expired)));
        assert_eq!(chat.graph().await, (1, 1, 1, Some(input)));
        assert!(terminal_events(&chat.f.db, &id).await.is_empty());
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn revoking_a_pinned_model_capability_blocks_the_tool_step() {
        let mut chat = Chat::new().await.with_tools().await;
        chat.catalog["models"]["a"]["required_capabilities"] = json!({"model.a":"on_by_default"});
        let mut server = Provider::new().await;
        let (id, input) = chat.submit("pinned capability", "a", 3).await;
        let _worker = chat.start(&server).await;
        let pending = server.request().await;
        sqlx::query("INSERT INTO openmettle.user_capability_denies(user_id,capability,denied,updated_by_user_id)
            VALUES($1::uuid,'model.a',true,$1::uuid)").bind(&chat.f.actor.user)
            .execute(&mut connect(&chat.f.db.0,OWNER).await).await.unwrap();
        pending.respond(tool_call("lookup", "{}"));
        chat.done(&id, "cancelled", Some("revoked")).await;
        assert_eq!(chat.graph().await, (1, 1, 1, Some(input)));
        let n: i64 =
            sqlx::query_scalar("SELECT count(*) FROM openmettle.operations WHERE run_id=$1::uuid")
                .bind(id)
                .fetch_one(&mut worker(&chat.f.db).await)
                .await
                .unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18"]
    async fn terminal_event_conflict_rolls_back_the_answer_and_head() {
        let chat = Chat::new().await;
        let (run_id, input) = chat.submit("atomic publication", "a", 4).await;
        let mut c = worker(&chat.f.db).await;
        let run = queue::claim_next(&mut c, &OPEN, &LEASES)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(run.run_id, run_id);
        with_lease(&mut c, &run.lease(), Fence::Hold, async |tx, _| {
            durable::append_event(tx, &run.scope_id, &run.run_id, "run-terminal", EVIDENCE).await
        })
        .await
        .unwrap();
        let id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut c)
            .await
            .unwrap();
        let result = settle_answer(
            &mut c,
            &run.lease(),
            &LEASES,
            &branches::Answer {
                id: &id,
                parts: &[Part::Text("must roll back".into())],
                reasoning: None,
                input_count: Some(9),
                output_count: Some(2),
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(LeaseError::Store(StoreError::Conflict(_)))
        ));
        assert_eq!(chat.graph().await, (1, 1, 1, Some(input)));
        let state: String =
            sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id=$1::uuid")
                .bind(run_id)
                .fetch_one(&mut c)
                .await
                .unwrap();
        assert_eq!(state, "running");
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn reviewed_tool_continuation_uses_only_final_usage_and_obeys_round_cap() {
        let chat = Chat::new().await.with_tools().await;
        let mut server = Provider::new().await;
        let _worker = chat.start(&server).await;
        let (id, _) = chat.submit("lookup", "a", 2).await;
        let first = server.request().await;
        assert_eq!(first.body["tools"][0]["function"]["name"], "lookup");
        first.respond(tool_call("lookup", "{}"));
        let second = server.request().await;
        let path = second.body["messages"].as_array().unwrap();
        assert_eq!(path[path.len() - 2]["tool_calls"][0]["id"], "call-1");
        assert_eq!(
            path.last().unwrap(),
            &json!({"role":"tool","tool_call_id":"call-1","content":"registered result"})
        );
        second.respond(completion(
            json!("final"),
            None,
            json!({"prompt_tokens":91,"completion_tokens":3}),
        ));
        chat.done(&id, "succeeded", None).await;
        let counts: (i64, i64) = sqlx::query_as(
            "SELECT input_count,output_count FROM openmettle.message_turns WHERE run_id=$1::uuid",
        )
        .bind(&id)
        .fetch_one(&mut worker(&chat.f.db).await)
        .await
        .unwrap();
        assert_eq!(counts, (91, 3));
        for (name, cap, reason) in [
            ("lookup", 1, "round_limit"),
            ("undeclared", 2, "step_failed"),
        ] {
            let (id, _) = chat.submit(reason, "a", cap).await;
            let before = chat.graph().await;
            server.request().await.respond(tool_call(name, "{}"));
            chat.done(&id, "failed", Some(reason)).await;
            assert_eq!(before, chat.graph().await);
            let effects: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM openmettle.operations WHERE run_id=$1::uuid",
            )
            .bind(&id)
            .fetch_one(&mut worker(&chat.f.db).await)
            .await
            .unwrap();
            assert_eq!(effects, 0);
        }
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn publishes_measured_ordered_parts_and_only_qualified_reasoning() {
        let chat = Chat::new().await;
        let mut server = Provider::new().await;
        let _worker = chat.start(&server).await;
        let (one, input) = chat.submit("one", "a", 4).await;
        server.request().await.respond(completion(
            Value::Null,
            Some("private reasoning"),
            json!({"prompt_tokens":37,"completion_tokens":9}),
        ));
        chat.done(&one, "succeeded", None).await;
        let mut w = worker(&chat.f.db).await;
        let (id,parent,blocks,bytes,i,o): (String,String,String,i32,Option<i64>,Option<i64>) = sqlx::query_as(
            "SELECT message_id::text,parent_message_id::text,reasoning_blocks::text,reasoning_bytes,input_count,output_count
            FROM openmettle.message_turns t JOIN openmettle.messages m ON m.id=t.message_id WHERE run_id=$1::uuid")
            .bind(&one).fetch_one(&mut w).await.unwrap();
        assert_eq!(chat.graph().await, (2, 2, 1, Some(id)));
        assert_eq!(parent, input);
        assert_eq!((i, o), (Some(37), Some(9)));
        assert_eq!(bytes as usize, blocks.len());
        assert_eq!(
            serde_json::from_str::<Value>(&blocks).unwrap(),
            json!([{"text":"private reasoning"}])
        );

        let (two, _) = chat.submit("two", "a", 4).await;
        let second = server.request().await;
        assert_eq!(second.path, "/v1/chat/completions");
        let qualified = second.body["messages"].as_array().unwrap();
        assert_eq!(
            qualified[qualified.len() - 3..],
            [
                json!({"role":"user","content":"one"}),
                json!({"role":"assistant","reasoning_content":"private reasoning"}),
                json!({"role":"user","content":"two"})
            ]
        );
        second.respond(completion(
            json!([{"type":"text","text":"first"},{"type":"text","text":"second"}]),
            None,
            Value::Null,
        ));
        chat.done(&two, "succeeded", None).await;
        let parts:Vec<(i32,String)> = sqlx::query_as("SELECT ordinal,text_value FROM openmettle.message_parts p
            JOIN openmettle.message_turns t USING(message_id) WHERE run_id=$1::uuid ORDER BY ordinal").bind(&two).fetch_all(&mut w).await.unwrap();
        assert_eq!(parts, [(0, "first".into()), (1, "second".into())]);
        let usage = |id| {
            sqlx::query_as::<_,(Option<i64>,Option<i64>)>("SELECT input_count,output_count FROM openmettle.message_turns WHERE run_id=$1::uuid").bind(id)
        };
        assert_eq!(usage(&two).fetch_one(&mut w).await.unwrap(), (None, None));
        let (three, _) = chat.submit("three", "b", 4).await;
        let third = server.request().await;
        assert_eq!(third.path, "/v1/responses");
        let unqualified = &third.body;
        assert_eq!(unqualified["model"], "b");
        assert!(!unqualified.to_string().contains("private reasoning"));
        let roles: Vec<_> = unqualified["input"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["role"].as_str().unwrap())
            .collect();
        assert_eq!(roles, ["user", "user", "assistant", "user"]);
        third.respond(json!({"status":"completed","output":[{"type":"message","id":"reply",
            "role":"assistant","status":"completed","content":[{"type":"output_text","text":"other profile"}]}],
            "usage":{"output_tokens":4}}));
        chat.done(&three, "succeeded", None).await;
        assert_eq!(
            usage(&three).fetch_one(&mut w).await.unwrap(),
            (None, Some(4))
        );
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn head_conflict_and_cancellation_commit_no_graph_writes() {
        for cancel in [false, true] {
            let chat = Chat::new().await;
            let mut server = Provider::new().await;
            let (id, input) = chat.submit("race", "a", 4).await;
            let _worker = chat.start(&server).await;
            let pending = server.request().await;
            if cancel {
                let actor = principal(&chat.f.db, &chat.f.actor).await;
                queue::cancel_run(&mut api(&chat.f.db).await, &actor, &chat.f.scope, &id)
                    .await
                    .unwrap();
            } else {
                // Race a complete, valid publication by a competing API writer.
                let mut api = api(&chat.f.db).await;
                let mut tx = api.begin().await.unwrap();
                let next = message(
                    &mut tx,
                    &chat.f.scope,
                    &chat.root.conversation_id,
                    Some(&input),
                )
                .await
                .unwrap();
                sqlx::query("INSERT INTO openmettle.message_turns(scope_id,conversation_id,message_id,author_user_id)
                    VALUES($1::uuid,$2::uuid,$3::uuid,$4::uuid)").bind(&chat.f.scope).bind(&chat.root.conversation_id).bind(&next).bind(&chat.f.actor.user)
                    .execute(&mut *tx).await.unwrap();
                sqlx::query("INSERT INTO openmettle.message_parts(scope_id,conversation_id,message_id,ordinal,kind,text_value)
                    VALUES($1::uuid,$2::uuid,$3::uuid,0,'text','competing turn')").bind(&chat.f.scope).bind(&chat.root.conversation_id).bind(&next)
                    .execute(&mut *tx).await.unwrap();
                sqlx::query("UPDATE openmettle.branch_heads SET head_message_id=$1::uuid WHERE branch_id=$2::uuid")
                    .bind(&next).bind(&chat.root.branch_id).execute(&mut *tx).await.unwrap();
                tx.commit().await.unwrap();
            }
            let before = chat.graph().await;
            pending.respond(completion(
                json!("discard me"),
                Some("discard blocks"),
                Value::Null,
            ));
            if cancel {
                chat.done(&id, "cancelled", Some("requested")).await;
            } else {
                chat.done(&id, "failed", Some("step_failed")).await;
            }
            assert_eq!(chat.graph().await, before);
        }
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn lost_holder_and_worker_restart_publish_once() {
        let chat = Chat::new().await;
        let mut first = Provider::new().await;
        let (id, input) = chat.submit("recover", "a", 4).await;
        let mut old = chat.start(&first).await;
        let stale_request = first.request().await;
        let token: String =
            sqlx::query_scalar("SELECT claim_token::text FROM openmettle.runs WHERE id=$1::uuid")
                .bind(&id)
                .fetch_one(&mut worker(&chat.f.db).await)
                .await
                .unwrap();
        owner_exec(
            &chat.f.db,
            "UPDATE openmettle.runs SET lease_expires_at=clock_timestamp() WHERE id=$1::uuid",
            &id,
        )
        .await;
        let mut second = Provider::new().await;
        let _replacement = chat.start(&second).await;
        let fresh_request = second.request().await;
        stale_request.respond(completion(json!("old"), None, Value::Null));
        let stale = Lease {
            scope_id: &chat.f.scope,
            run_id: &id,
            claim_token: &token,
        };
        assert!(matches!(
            settle_answer(
                &mut worker(&chat.f.db).await,
                &stale,
                &LEASES,
                &branches::Answer {
                    id: &input,
                    parts: &[],
                    reasoning: None,
                    input_count: None,
                    output_count: None,
                }
            )
            .await,
            Err(LeaseError::StaleClaim)
        ));
        // Drain the first process while the replacement still owns the claim.
        drop(old.0.stdin.take());
        tokio::task::spawn_blocking(move || assert!(old.0.wait().unwrap().success()))
            .await
            .unwrap();
        assert_eq!(chat.graph().await, (1, 1, 1, Some(input)));
        fresh_request.respond(completion(json!("replacement"), None, Value::Null));
        chat.done(&id, "succeeded", None).await;
        let (messages, turns, parts, head) = chat.graph().await;
        assert_eq!((messages, turns, parts), (2, 2, 2));
        let value: String = sqlx::query_scalar(
            "SELECT text_value FROM openmettle.message_parts WHERE message_id=$1::uuid",
        )
        .bind(head)
        .fetch_one(&mut api(&chat.f.db).await)
        .await
        .unwrap();
        assert_eq!(value, "replacement");
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn process_crash_preserves_the_round_budget_on_restart() {
        for rounds in [1, 2] {
            let chat = Chat::new().await;
            let mut provider = Provider::new().await;
            let (id, input) = chat.submit("crash during inference", "a", rounds).await;
            let original = chat.start(&provider).await;
            let mut request = provider.request().await;
            drop(original); // Kill and wait, without giving the worker a drain or handoff.
            tokio::time::timeout(Duration::from_secs(5), request.reply.closed())
                .await
                .expect("crashed worker disconnected");
            assert_eq!(chat.graph().await, (1, 1, 1, Some(input.clone())));
            owner_exec(
                &chat.f.db,
                "UPDATE openmettle.runs SET lease_expires_at=clock_timestamp() WHERE id=$1::uuid",
                &id,
            )
            .await;
            let _restarted = chat.start(&provider).await;
            if rounds == 1 {
                chat.done(&id, "failed", Some("round_limit")).await;
                assert_eq!(chat.graph().await, (1, 1, 1, Some(input)));
                assert!(provider.requests.try_recv().is_err());
            } else {
                provider
                    .request()
                    .await
                    .respond(completion(json!("recovered"), None, Value::Null));
                chat.done(&id, "succeeded", None).await;
                let (messages, turns, parts, head) = chat.graph().await;
                assert_eq!((messages, turns, parts), (2, 2, 2));
                assert_ne!(head, Some(input));
            }
        }
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn pre_handoff_crash_recovers_unsent_round_and_succeeds_within_round_limit() {
        use crate::authz_http::{Api, As, browser, success};
        use openmettle_core::{
            authz::{
                gateway::{self, TurnRound, settlement},
                leases::{self, Fence, LeaseSettings},
                runs::{self as authz_queue, ClaimLimits},
            },
            provider_http::gateway::UsageReport,
            provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
            runs::Payload,
        };
        use sqlx::postgres::PgPoolOptions;

        const INSTALL: &str = "00000000-0000-4000-8000-0000000000d1";
        const PRINCIPAL: &str = "00000000-0000-4000-8000-0000000000d2";
        const BUDGET: &str = "00000000-0000-4000-8000-0000000000d3";
        const KEY_BYTES: [u8; 32] = [79; 32];

        for rounds in [1i64, 2i64] {
            let db = TestDb::migrated().await;
            let mut owner = connect(&db.0, OWNER).await;
            providers(&mut owner).await;
            let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
            let scope = personal_of(&db, &alice).await;
            let alice_cookie = browser(&db, &alice, 1).await;
            let alice_b = As::Browser(&alice_cookie);

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
                            ('personal', 'usage_cost_micros', 1000)",
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
            let keys = GatewayKeys::new(&[("prehandoff-k1".into(), KEY_BYTES)]).unwrap();
            let (finger, env) = GatewaySealer::new(keys, g_pool.clone())
                .seal(
                    &Context {
                        installation: INSTALL,
                        user_id: &alice.user,
                        binding_id: &binding,
                        principal: PRINCIPAL,
                        generation: 1,
                    },
                    &Bearer::new(b"prehandoff-round-token").unwrap(),
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

            let dir = Dir::new();
            std::fs::create_dir(dir.path("artifacts")).unwrap();
            let mut doc = auth_config_support::document_v2_native(&dir, &Ca::new().pem());
            doc["cursor_keys"] = auth_config_support::cursor_keys(&dir);
            let mut catalog: Value =
                serde_json::from_slice(include_bytes!("../fixtures/conversation-catalog-v1.json"))
                    .unwrap();
            catalog["models"]["a"]["pin"]["provider"] = "synthetic-sglang".into();
            catalog["models"]["a"]["prompt_bound"] = json!({
                "fixed_tokens": 4,
                "tokens_per_turn": 4,
                "tokens_per_part": 2,
                "tokens_per_byte": 1,
                "tokens_per_attachment": 10
            });
            catalog["models"]["a"]["cost_bound"] = json!({
                "fixed_micros": 0,
                "micros_per_token": 1
            });
            doc["catalog_file"] =
                json!(dir.write("catalog.json", &serde_json::to_vec(&catalog).unwrap()));
            doc["admission_limits"] = json!({
                "live_per_actor": 4,
                "live_per_scope": 8,
                "queued_in_instance": 32,
                "queue_timeout_seconds": 300,
                "round_cap": 10
            });
            let http_api = Api::configured(&db, dir, doc, 4);

            let conv = success(
                http_api.call(
                    alice_b,
                    "POST",
                    "/v1/conversations",
                    Some(&format!("ph-conv-{rounds}")),
                    Some(&json!({})),
                ),
                201,
            );
            let conv_id = conv["conversation_id"].as_str().unwrap();
            let branch_id = conv["branch_id"].as_str().unwrap();
            let admitted = success(
                http_api.call(
                    alice_b,
                    "POST",
                    "/v1/runs",
                    Some(&format!("ph-run-{rounds}")),
                    Some(&json!({
                        "conversation_id": conv_id,
                        "branch_id": branch_id,
                        "proposal": {
                            "expected_head_message_id": null,
                            "turn": {
                                "mode": "append",
                                "input_message_id": format!("00000000-0000-4000-8000-00000000d00{rounds}"),
                                "parts": [{"text": "crash before handoff"}]
                            },
                            "selection": {
                                "model": "a",
                                "layer": {"controls": {"context_window": "450", "output_reserve": "100"}}
                            },
                            "requested_rounds": rounds
                        }
                    })),
                ),
                201,
            );
            let run_id = admitted["run_id"].as_str().unwrap().to_owned();

            // Simulate predecessor Worker 1 committing model-round:1 + reserve_turn_round
            // (`gateway_requests.state = 'reserved'`, zero HTTP sent) and crashing before handoff.
            let mut w1 = worker(&db).await;
            let w1_pool = PgPoolOptions::new()
                .max_connections(2)
                .connect_lazy_with(db.1.options(WORKER));
            let lease_cfg = LeaseSettings {
                lease: Duration::from_secs(60),
                execution_timeout: Duration::from_secs(600),
            };
            let claim_cfg = ClaimLimits {
                executing_per_actor: 4,
                executing_per_scope: 8,
            };
            let claim1 = authz_queue::claim_next(&mut w1, &claim_cfg, &lease_cfg)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(claim1.run_id, run_id);
            leases::with_lease(&mut w1, &claim1.lease(), Fence::Step, async |tx, _| {
                openmettle_core::runs::append_event(
                    tx,
                    &scope,
                    &run_id,
                    "model-round:1",
                    Payload {
                        format: "openmettle.model-round",
                        version: 1,
                        bytes: b"{}",
                    },
                )
                .await?;
                Ok(())
            })
            .await
            .unwrap();
            let unsent = gateway::reserve_turn_round(
                &w1_pool,
                TurnRound {
                    scope_id: &scope,
                    actor: &alice.user,
                    approval: &alice.approval,
                    run_id: &run_id,
                    round: 1,
                    claim_token: &claim1.claim_token,
                    installation: INSTALL,
                    model: "a",
                    round_tokens: 450,
                    round_cost: Some(450),
                    requires_device_slot: false,
                },
            )
            .await
            .unwrap();
            let unsent_id = unsent.id.clone();
            drop(unsent); // Crash before TurnPending::handoff!
            owner_exec(
                &db,
                "UPDATE openmettle.runs SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
                &run_id,
            )
            .await;

            // Start replacement Worker 2 against loopback TLS provider.
            let mut provider = Provider::with_bearer("prehandoff-round-token".into()).await;
            let mut child = Command::new(worker_binary())
                .env("OPENMETTLE_TEST_TURN_WORKER", "1")
                .args([
                    "--ignored",
                    "--exact",
                    "worker::turns::schema_fixture::worker_process",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()
                .unwrap();
            let stdin = child.stdin.as_mut().unwrap();
            serde_json::to_writer(
                &mut *stdin,
                &json!({
                    "database": db.url(WORKER),
                    "catalog": catalog,
                    "tools": false,
                    "scope": scope,
                    "actor": alice.user,
                    "ca": String::from_utf8(provider.ca.pem()).unwrap(),
                    "port": provider.port,
                    "artifacts": null,
                    "stop_during_observation": false,
                    "metered": {
                        "installation": INSTALL,
                        "key_id": "prehandoff-k1",
                        "key_bytes": KEY_BYTES,
                    }
                }),
            )
            .unwrap();
            writeln!(stdin).unwrap();
            let _worker_proc = Process(child);

            // Replacement worker MUST unwind the unsent Round 1 row, reuse Round 1 (even with
            // round_limit = 1), dispatch over TLS, and settle `succeeded`.
            let req = provider.request().await;
            let req_id = req
                .request_id
                .clone()
                .expect("replacement worker must send x-request-id");
            assert_ne!(req_id, unsent_id);
            let old_state: String = sqlx::query_scalar(
                "SELECT state FROM openmettle.gateway_requests WHERE id = $1::uuid",
            )
            .bind(&unsent_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
            assert_eq!(old_state, "released");

            let report_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
                .fetch_one(&mut owner)
                .await
                .unwrap();
            assert_eq!(
                settlement::ingest(
                    &g_pool,
                    &UsageReport {
                        request: req_id,
                        installation: INSTALL.into(),
                        principal: PRINCIPAL.into(),
                        scope: scope.clone(),
                        source: report_source,
                        report_id,
                        revision: 0,
                        r#final: true,
                        prompt_tokens: Some(60),
                        completion_tokens: Some(20),
                        reasoning_tokens: None,
                        reasoning_included: None,
                        cost: Some("120".into()),
                        unit: Some("usd_micros".into()),
                    },
                )
                .await
                .unwrap(),
                settlement::Outcome::Applied
            );
            req.respond(completion(
                json!("recovered before handoff"),
                None,
                json!({"prompt_tokens": 60, "completion_tokens": 20}),
            ));

            let mut api_c = api(&db).await;
            tokio::time::timeout(Duration::from_secs(25), async {
                loop {
                    let stored: String =
                        sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                            .bind(&run_id)
                            .fetch_one(&mut api_c)
                            .await
                            .unwrap();
                    if queue::is_terminal(&stored) {
                        assert_eq!(
                            stored, "succeeded",
                            "run with round_limit={rounds} must succeed after recovering unsent Round 1"
                        );
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("replacement worker settled recovered run");

            let round_events: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM openmettle.run_events
                  WHERE scope_id = $1::uuid AND run_id = $2::uuid
                    AND format = 'openmettle.model-round'",
            )
            .bind(&scope)
            .bind(&run_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
            assert_eq!(
                round_events, 1,
                "reused round must not append duplicate model-round event"
            );

            let drift: (i64, i64, i64, i64) = sqlx::query_as(
                "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
                   FROM openmettle.quota_verify_accounting_drift()",
            )
            .fetch_one(&mut worker(&db).await)
            .await
            .unwrap();
            assert_eq!(drift, (0, 0, 0, 0));
        }
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn bearer_crash_replaced_by_metered_worker_preserves_round_budget() {
        use crate::authz_http::{Api, As, browser, success};
        use openmettle_core::{
            migrate,
            provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
        };
        use sqlx::postgres::PgPoolOptions;

        const INSTALL: &str = "00000000-0000-4000-8000-0000000000e1";
        const PRINCIPAL: &str = "00000000-0000-4000-8000-0000000000e2";
        const BUDGET: &str = "00000000-0000-4000-8000-0000000000e3";
        const KEY_BYTES: [u8; 32] = [83; 32];

        for rounds in [1i64, 2i64] {
            // Upgrade from schema 23 -> latest so metering_enforced starts false and a pre-activation
            // Route::bearer worker can legitimately dispatch Round 1 without gateway_requests rows.
            let db = TestDb::new().await;
            let settings = db.settings(Duration::from_secs(10));
            migrate::apply(&settings, &migrate::MIGRATIONS[..23])
                .await
                .unwrap();
            let mut owner = connect(&db.0, OWNER).await;
            providers(&mut owner).await;
            let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
            let scope = personal_of(&db, &alice).await;
            migrate::apply(&settings, migrate::MIGRATIONS)
                .await
                .unwrap();
            let alice_cookie = browser(&db, &alice, 1).await;
            let alice_b = As::Browser(&alice_cookie);

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
                            ('personal', 'usage_cost_micros', 1000)",
                )
                .await
                .unwrap();

            // Provision gateway binding with sealed `synthetic-bearer` so both bearer Worker 1 and
            // metered Worker 2 target the same loopback TLS Provider.
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
            let keys = GatewayKeys::new(&[("b2m-k1".into(), KEY_BYTES)]).unwrap();
            let (finger, env) = GatewaySealer::new(keys, g_pool.clone())
                .seal(
                    &Context {
                        installation: INSTALL,
                        user_id: &alice.user,
                        binding_id: &binding,
                        principal: PRINCIPAL,
                        generation: 1,
                    },
                    &Bearer::new(b"synthetic-turn-credential").unwrap(),
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

            let dir = Dir::new();
            std::fs::create_dir(dir.path("artifacts")).unwrap();
            let mut doc = auth_config_support::document_v2_native(&dir, &Ca::new().pem());
            doc["cursor_keys"] = auth_config_support::cursor_keys(&dir);
            let mut catalog: Value =
                serde_json::from_slice(include_bytes!("../fixtures/conversation-catalog-v1.json"))
                    .unwrap();
            catalog["models"]["a"]["pin"]["provider"] = "synthetic-sglang".into();
            catalog["models"]["a"]["prompt_bound"] = json!({
                "fixed_tokens": 4,
                "tokens_per_turn": 4,
                "tokens_per_part": 2,
                "tokens_per_byte": 1,
                "tokens_per_attachment": 10
            });
            catalog["models"]["a"]["cost_bound"] = json!({
                "fixed_micros": 0,
                "micros_per_token": 1
            });
            doc["catalog_file"] =
                json!(dir.write("catalog.json", &serde_json::to_vec(&catalog).unwrap()));
            doc["admission_limits"] = json!({
                "live_per_actor": 4,
                "live_per_scope": 8,
                "queued_in_instance": 32,
                "queue_timeout_seconds": 300,
                "round_cap": 10
            });
            let http_api = Api::configured(&db, dir, doc, 4);

            let conv = success(
                http_api.call(
                    alice_b,
                    "POST",
                    "/v1/conversations",
                    Some(&format!("b2m-conv-{rounds}")),
                    Some(&json!({})),
                ),
                201,
            );
            let conv_id = conv["conversation_id"].as_str().unwrap();
            let branch_id = conv["branch_id"].as_str().unwrap();
            let admitted = success(
                http_api.call(
                    alice_b,
                    "POST",
                    "/v1/runs",
                    Some(&format!("b2m-run-{rounds}")),
                    Some(&json!({
                        "conversation_id": conv_id,
                        "branch_id": branch_id,
                        "proposal": {
                            "expected_head_message_id": null,
                            "turn": {
                                "mode": "append",
                                "input_message_id": format!("00000000-0000-4000-8000-00000000e00{rounds}"),
                                "parts": [{"text": "bearer crash then metered replacement"}]
                            },
                            "selection": {
                                "model": "a",
                                "layer": {"controls": {"context_window": "450", "output_reserve": "100"}}
                            },
                            "requested_rounds": rounds
                        }
                    })),
                ),
                201,
            );
            let run_id = admitted["run_id"].as_str().unwrap().to_owned();

            // 1. Start Worker 1 with Route::bearer ("metered": null), let it send Round 1 over TLS,
            //    and kill it mid-inference before answer publication.
            let mut provider = Provider::new().await;
            let mut w1_child = Command::new(worker_binary())
                .env("OPENMETTLE_TEST_TURN_WORKER", "1")
                .args([
                    "--ignored",
                    "--exact",
                    "worker::turns::schema_fixture::worker_process",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()
                .unwrap();
            let w1_stdin = w1_child.stdin.as_mut().unwrap();
            serde_json::to_writer(
                &mut *w1_stdin,
                &json!({
                    "database": db.url(WORKER),
                    "catalog": catalog,
                    "tools": false,
                    "scope": scope,
                    "actor": alice.user,
                    "ca": String::from_utf8(provider.ca.pem()).unwrap(),
                    "port": provider.port,
                    "artifacts": null,
                    "stop_during_observation": false,
                    "metered": null,
                }),
            )
            .unwrap();
            writeln!(w1_stdin).unwrap();
            let w1_proc = Process(w1_child);

            let mut req1 = provider.request().await;
            assert!(
                req1.request_id.is_none(),
                "predecessor Route::bearer worker must not attach gateway x-request-id"
            );
            drop(w1_proc);
            tokio::time::timeout(Duration::from_secs(5), req1.reply.closed())
                .await
                .expect("crashed bearer worker disconnected");
            owner_exec(
                &db,
                "UPDATE openmettle.runs SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
                &run_id,
            )
            .await;

            // 2. Start Replacement Worker 2 with Route::metered. Because Worker 1's model-round:1
            //    has no durable metered evidence, Worker 2 MUST NOT reuse Round 1.
            let mut w2_child = Command::new(worker_binary())
                .env("OPENMETTLE_TEST_TURN_WORKER", "1")
                .args([
                    "--ignored",
                    "--exact",
                    "worker::turns::schema_fixture::worker_process",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()
                .unwrap();
            let w2_stdin = w2_child.stdin.as_mut().unwrap();
            serde_json::to_writer(
                &mut *w2_stdin,
                &json!({
                    "database": db.url(WORKER),
                    "catalog": catalog,
                    "tools": false,
                    "scope": scope,
                    "actor": alice.user,
                    "ca": String::from_utf8(provider.ca.pem()).unwrap(),
                    "port": provider.port,
                    "artifacts": null,
                    "stop_during_observation": false,
                    "metered": {
                        "installation": INSTALL,
                        "key_id": "b2m-k1",
                        "key_bytes": KEY_BYTES,
                    }
                }),
            )
            .unwrap();
            writeln!(w2_stdin).unwrap();
            let _w2_proc = Process(w2_child);

            let mut api_c = api(&db).await;
            if rounds == 1 {
                tokio::time::timeout(Duration::from_secs(25), async {
                    loop {
                        let state: String = sqlx::query_scalar(
                            "SELECT state FROM openmettle.runs WHERE id = $1::uuid",
                        )
                        .bind(&run_id)
                        .fetch_one(&mut api_c)
                        .await
                        .unwrap();
                        if queue::is_terminal(&state) {
                            assert_eq!(state, "failed");
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await
                .expect("round_limit=1 run failed without reusing bearer round");
                terminal(
                    &db,
                    &run_id,
                    "openmettle.run-failed",
                    json!({"reason": "round_limit"}).to_string().as_bytes(),
                )
                .await;
                assert!(
                    provider.requests.try_recv().is_err(),
                    "metered replacement must never send a second provider request when round_limit=1"
                );
            } else {
                let req2 = provider.request().await;
                assert!(
                    req2.request_id.is_some(),
                    "metered replacement must dispatch Round 2 through gateway"
                );
                req2.respond(completion(
                    json!("metered round 2 answer"),
                    None,
                    json!({"prompt_tokens": 50, "completion_tokens": 20}),
                ));
                tokio::time::timeout(Duration::from_secs(25), async {
                    loop {
                        let state: String = sqlx::query_scalar(
                            "SELECT state FROM openmettle.runs WHERE id = $1::uuid",
                        )
                        .bind(&run_id)
                        .fetch_one(&mut api_c)
                        .await
                        .unwrap();
                        if queue::is_terminal(&state) {
                            assert_eq!(state, "succeeded");
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await
                .expect("round_limit=2 run advanced to Round 2 and succeeded");
                let events: Vec<(String, String)> = sqlx::query_as(
                    "SELECT append_key, convert_from(payload, 'UTF8')
                       FROM openmettle.run_events
                      WHERE scope_id = $1::uuid AND run_id = $2::uuid
                        AND format = 'openmettle.model-round'
                      ORDER BY sequence ASC",
                )
                .bind(&scope)
                .bind(&run_id)
                .fetch_all(&mut owner)
                .await
                .unwrap();
                assert_eq!(
                    events,
                    vec![
                        ("model-round:1".into(), "{}".into()),
                        ("model-round:2".into(), r#"{"metered":true}"#.into()),
                    ]
                );
            }
            let drift: (i64, i64, i64, i64) = sqlx::query_as(
                "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
                   FROM openmettle.quota_verify_accounting_drift()",
            )
            .fetch_one(&mut worker(&db).await)
            .await
            .unwrap();
            assert_eq!(drift, (0, 0, 0, 0));
        }
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn turn_executor_retries_retryable_40001_reservation_and_succeeds() {
        use openmettle_core::{authz::gateway::settlement, provider_http::gateway::UsageReport};
        use sqlx::postgres::PgPoolOptions;

        let chat = Chat::new().await;
        let db = &chat.f.db;
        let mut owner = connect(&db.0, OWNER).await;
        let mut owner_lock = connect(&db.0, OWNER).await;
        let lock_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut owner_lock)
            .await
            .unwrap();

        // Add static instance usage_tokens default + pre-created budget row to hold during Pass 1.
        owner
            .execute(
                "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
                 VALUES ('instance', 'usage_tokens', 1000000000)
                 ON CONFLICT (scope_kind, resource_kind) DO NOTHING",
            )
            .await
            .unwrap();
        owner
            .execute(
                "INSERT INTO openmettle.quota_budgets
                     (target_kind, scope_id, resource_kind, window_kind, window_start)
                 VALUES ('instance', NULL, 'usage_tokens', 'static', 'epoch'::timestamptz)
                 ON CONFLICT DO NOTHING",
            )
            .await
            .unwrap();

        let (installation, _, _) = chat.ensure_metered_gateway().await;
        let g_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with(db.1.options(pg::GATEWAY));
        let (principal, report_source): (String, String) = sqlx::query_as(
            "SELECT b.principal::text, p.report_source::text
               FROM openmettle.gateway_bindings b
               JOIN openmettle.gateway_policy p ON p.binding_id = b.id
              WHERE b.installation = $1::uuid AND b.user_id = $2::uuid AND p.model = 'a'
              LIMIT 1",
        )
        .bind(&installation)
        .bind(&chat.f.actor.user)
        .fetch_one(&g_pool)
        .await
        .unwrap();

        // Admit a pre-activation/legacy run WITHOUT parent quota holds so TurnExecutor triggers
        // quota_prepare_turn_round -> quota_reserve on Round 1.
        let (run_id, _) = chat.submit("rr14-turn-retry-40001", "a", 1).await;

        // Hold the instance budget lock before starting TurnExecutor so its first reserve_turn_round
        // blocks inside quota_reserve Pass 1.
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

        let mut provider = Provider::new().await;
        let _worker_proc = chat.start(&provider).await;

        // Wait until the TurnExecutor worker is blocked on lock_pid inside quota_reserve.
        let wait_deadline = Instant::now() + Duration::from_secs(10);
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
                "TurnExecutor did not block on instance budget lock"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Flip personal usage_tokens from static -> windowed (3600s) while TurnExecutor is blocked
        // on instance -> Pass 2 raises 40001 -> gateway::Error::Retryable -> TurnExecutor retries
        // automatically within the live lease and dispatches once!
        owner
            .execute(
                "UPDATE openmettle.quota_defaults
                    SET window_seconds = 3600
                  WHERE scope_kind = 'personal' AND resource_kind = 'usage_tokens'",
            )
            .await
            .unwrap();
        inst_tx.rollback().await.unwrap();

        let req = provider.request().await;
        let req_id = req
            .request_id
            .clone()
            .expect("retried metered dispatch must attach x-request-id");
        let report_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut owner)
            .await
            .unwrap();
        assert_eq!(
            settlement::ingest(
                &g_pool,
                &UsageReport {
                    request: req_id,
                    installation,
                    principal,
                    scope: chat.f.scope.clone(),
                    source: report_source,
                    report_id,
                    revision: 0,
                    r#final: true,
                    prompt_tokens: Some(40),
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
        req.respond(completion(
            json!("retried cleanly after 40001"),
            None,
            json!({"prompt_tokens": 40, "completion_tokens": 15}),
        ));

        chat.done(&run_id, "succeeded", None).await;

        assert!(
            provider.requests.try_recv().is_err(),
            "retried reservation must dispatch to the provider exactly once"
        );
        let round_events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM openmettle.run_events
              WHERE scope_id = $1::uuid AND run_id = $2::uuid
                AND format = 'openmettle.model-round'",
        )
        .bind(&chat.f.scope)
        .bind(&run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(round_events, 1);

        // Confirm the retried reservation charged the newly windowed personal budget.
        let win_kind: String = sqlx::query_scalar(
            "SELECT b.window_kind
               FROM openmettle.quota_reservation_charges c
               JOIN openmettle.quota_reservations r ON r.id = c.reservation_id
               JOIN openmettle.quota_budgets b ON b.id = c.budget_id
              WHERE r.run_id = $1::uuid AND r.gateway_request_id IS NULL
                AND r.resource_kind = 'usage_tokens' AND c.charge_role = 'primary_scope'",
        )
        .bind(&run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(win_kind, "windowed");

        let drift: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
               FROM openmettle.quota_verify_accounting_drift()",
        )
        .fetch_one(&mut worker(db).await)
        .await
        .unwrap();
        assert_eq!(drift, (0, 0, 0, 0));
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn bearer_round_replaced_by_metered_worker_fits_tight_single_round_budget() {
        use crate::authz_http::{Api, As, browser, success};
        use openmettle_core::{
            authz::gateway::settlement,
            migrate,
            provider_http::gateway::UsageReport,
            provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
        };
        use sqlx::postgres::PgPoolOptions;

        const INSTALL: &str = "00000000-0000-4000-8000-0000000000ea";
        const PRINCIPAL: &str = "00000000-0000-4000-8000-0000000000eb";
        const BUDGET: &str = "00000000-0000-4000-8000-0000000000ec";
        const KEY_BYTES: [u8; 32] = [94; 32];

        // Upgrade from schema 23 -> latest so metering_enforced starts false and a pre-activation
        // Route::bearer worker dispatches Round 1 before metering activates.
        let db = TestDb::new().await;
        let settings = db.settings(Duration::from_secs(10));
        migrate::apply(&settings, &migrate::MIGRATIONS[..23])
            .await
            .unwrap();
        let mut owner = connect(&db.0, OWNER).await;
        providers(&mut owner).await;
        let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
        let scope = personal_of(&db, &alice).await;
        migrate::apply(&settings, migrate::MIGRATIONS)
            .await
            .unwrap();
        let alice_cookie = browser(&db, &alice, 1).await;
        let alice_b = As::Browser(&alice_cookie);

        // Tight personal budgets of EXACT 450 tokens and 450 cost micros: fits Round 2 (450/450)
        // after bearer Round 1, and fails closed if replacement tries to reserve 2 rounds (900/900).
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
        let keys = GatewayKeys::new(&[("b2m-tight-k1".into(), KEY_BYTES)]).unwrap();
        let (finger, env) = GatewaySealer::new(keys, g_pool.clone())
            .seal(
                &Context {
                    installation: INSTALL,
                    user_id: &alice.user,
                    binding_id: &binding,
                    principal: PRINCIPAL,
                    generation: 1,
                },
                &Bearer::new(b"synthetic-turn-credential").unwrap(),
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

        let dir = Dir::new();
        std::fs::create_dir(dir.path("artifacts")).unwrap();
        let mut doc = auth_config_support::document_v2_native(&dir, &Ca::new().pem());
        doc["cursor_keys"] = auth_config_support::cursor_keys(&dir);
        let mut catalog: Value =
            serde_json::from_slice(include_bytes!("../fixtures/conversation-catalog-v1.json"))
                .unwrap();
        catalog["models"]["a"]["pin"]["provider"] = "synthetic-sglang".into();
        catalog["models"]["a"]["prompt_bound"] = json!({
            "fixed_tokens": 4,
            "tokens_per_turn": 4,
            "tokens_per_part": 2,
            "tokens_per_byte": 1,
            "tokens_per_attachment": 10
        });
        catalog["models"]["a"]["cost_bound"] = json!({
            "fixed_micros": 0,
            "micros_per_token": 1
        });
        doc["catalog_file"] =
            json!(dir.write("catalog.json", &serde_json::to_vec(&catalog).unwrap()));
        doc["admission_limits"] = json!({
            "live_per_actor": 4,
            "live_per_scope": 8,
            "queued_in_instance": 32,
            "queue_timeout_seconds": 300,
            "round_cap": 10
        });
        let http_api = Api::configured(&db, dir, doc, 4);

        let conv = success(
            http_api.call(
                alice_b,
                "POST",
                "/v1/conversations",
                Some("b2m-tight-conv"),
                Some(&json!({})),
            ),
            201,
        );
        let conv_id = conv["conversation_id"].as_str().unwrap();
        let branch_id = conv["branch_id"].as_str().unwrap();
        let admitted = success(
            http_api.call(
                alice_b,
                "POST",
                "/v1/runs",
                Some("b2m-tight-run"),
                Some(&json!({
                    "conversation_id": conv_id,
                    "branch_id": branch_id,
                    "proposal": {
                        "expected_head_message_id": null,
                        "turn": {
                            "mode": "append",
                            "input_message_id": "00000000-0000-4000-8000-00000000ea02",
                            "parts": [{"text": "bearer round 1 then metered round 2 tight budget"}]
                        },
                        "selection": {
                            "model": "a",
                            "layer": {"controls": {"context_window": "450", "output_reserve": "100"}}
                        },
                        "requested_rounds": 2
                    }
                })),
            ),
            201,
        );
        let run_id = admitted["run_id"].as_str().unwrap().to_owned();

        // 1. Pre-activation bearer Worker 1 sends Round 1 and crashes.
        let mut provider = Provider::new().await;
        let mut w1_child = Command::new(worker_binary())
            .env("OPENMETTLE_TEST_TURN_WORKER", "1")
            .args([
                "--ignored",
                "--exact",
                "worker::turns::schema_fixture::worker_process",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let w1_stdin = w1_child.stdin.as_mut().unwrap();
        serde_json::to_writer(
            &mut *w1_stdin,
            &json!({
                "database": db.url(WORKER),
                "catalog": catalog,
                "tools": false,
                "scope": scope,
                "actor": alice.user,
                "ca": String::from_utf8(provider.ca.pem()).unwrap(),
                "port": provider.port,
                "artifacts": null,
                "stop_during_observation": false,
                "metered": null,
            }),
        )
        .unwrap();
        writeln!(w1_stdin).unwrap();
        let w1_proc = Process(w1_child);

        let mut req1 = provider.request().await;
        assert!(req1.request_id.is_none());
        drop(w1_proc);
        tokio::time::timeout(Duration::from_secs(5), req1.reply.closed())
            .await
            .expect("crashed bearer worker disconnected");
        owner_exec(
            &db,
            "UPDATE openmettle.runs SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE id = $1::uuid",
            &run_id,
        )
        .await;

        // 2. Enable metering BEFORE metered replacement Worker 2 takes over Round 2.
        owner
            .execute(
                "UPDATE openmettle.quota_enforcement
                    SET metering_enforced = true, metering_enforced_at = clock_timestamp()
                  WHERE id",
            )
            .await
            .unwrap();

        let mut w2_child = Command::new(worker_binary())
            .env("OPENMETTLE_TEST_TURN_WORKER", "1")
            .args([
                "--ignored",
                "--exact",
                "worker::turns::schema_fixture::worker_process",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let w2_stdin = w2_child.stdin.as_mut().unwrap();
        serde_json::to_writer(
            &mut *w2_stdin,
            &json!({
                "database": db.url(WORKER),
                "catalog": catalog,
                "tools": false,
                "scope": scope,
                "actor": alice.user,
                "ca": String::from_utf8(provider.ca.pem()).unwrap(),
                "port": provider.port,
                "artifacts": null,
                "stop_during_observation": false,
                "metered": {
                    "installation": INSTALL,
                    "key_id": "b2m-tight-k1",
                    "key_bytes": KEY_BYTES,
                }
            }),
        )
        .unwrap();
        writeln!(w2_stdin).unwrap();
        let _w2_proc = Process(w2_child);

        let req2 = provider.request().await;
        let req2_id = req2
            .request_id
            .clone()
            .expect("metered replacement Round 2 must attach x-request-id");

        let parent_holds: Vec<(String, i64)> = sqlx::query_as(
            "SELECT resource_kind, reserved_units
               FROM openmettle.quota_reservations
              WHERE run_id = $1::uuid AND gateway_request_id IS NULL
              ORDER BY resource_kind ASC",
        )
        .bind(&run_id)
        .fetch_all(&mut owner)
        .await
        .unwrap();
        assert_eq!(
            parent_holds,
            vec![
                ("usage_cost_micros".to_owned(), 450),
                ("usage_tokens".to_owned(), 450),
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
                    request: req2_id,
                    installation: INSTALL.into(),
                    principal: PRINCIPAL.into(),
                    scope: scope.clone(),
                    source: report_source,
                    report_id,
                    revision: 0,
                    r#final: true,
                    prompt_tokens: Some(80),
                    completion_tokens: Some(40),
                    reasoning_tokens: None,
                    reasoning_included: None,
                    cost: Some("120".into()),
                    unit: Some("usd_micros".into()),
                },
            )
            .await
            .unwrap(),
            settlement::Outcome::Applied
        );
        req2.respond(completion(
            json!("metered round 2 fits tight 450/450 budget"),
            None,
            json!({"prompt_tokens": 80, "completion_tokens": 40}),
        ));

        let mut api_c = api(&db).await;
        tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                let state: String =
                    sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                        .bind(&run_id)
                        .fetch_one(&mut api_c)
                        .await
                        .unwrap();
                if queue::is_terminal(&state) {
                    assert_eq!(state, "succeeded");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("metered Round 2 settled succeeded under tight 450/450 budget");

        assert!(provider.requests.try_recv().is_err());
        let drift: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
               FROM openmettle.quota_verify_accounting_drift()",
        )
        .fetch_one(&mut worker(&db).await)
        .await
        .unwrap();
        assert_eq!(drift, (0, 0, 0, 0));
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn turn_executor_retries_missing_cost_hold_when_first_cost_limit_activates_before_handoff()
     {
        use openmettle_core::{authz::gateway::settlement, provider_http::gateway::UsageReport};
        use sqlx::postgres::PgPoolOptions;

        let mut chat = Chat::new().await;
        // Qualified fixed cost bound of 300 micros per round; NO usage_cost_micros limit initially.
        chat.catalog["models"]["a"]["cost_bound"] = json!({
            "fixed_micros": 300,
            "micros_per_token": 0
        });
        let db = &chat.f.db;
        let mut owner = connect(&db.0, OWNER).await;
        let mut owner_lock = connect(&db.0, OWNER).await;
        let lock_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut owner_lock)
            .await
            .unwrap();

        let (installation, _, _) = chat.ensure_metered_gateway().await;
        let g_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with(db.1.options(pg::GATEWAY));
        let (principal, report_source): (String, String) = sqlx::query_as(
            "SELECT b.principal::text, p.report_source::text
               FROM openmettle.gateway_bindings b
               JOIN openmettle.gateway_policy p ON p.binding_id = b.id
              WHERE b.installation = $1::uuid AND b.user_id = $2::uuid AND p.model = 'a'
              LIMIT 1",
        )
        .bind(&installation)
        .bind(&chat.f.actor.user)
        .fetch_one(&g_pool)
        .await
        .unwrap();

        let (run_id, _) = chat
            .submit("rr15-first-cost-limit-handoff-retry", "a", 1)
            .await;

        // Hold quota_enforcement FOR UPDATE before starting TurnExecutor: reserve_turn_round uses a
        // plain SELECT so it commits with enforced_at_bind=true, cost_bound_at_bind=false, then
        // handoff_turn's deferred enforce_gateway_handoff_holds blocks on FOR SHARE.
        let mut enf_tx = owner_lock.begin().await.unwrap();
        sqlx::query("SELECT id FROM openmettle.quota_enforcement WHERE id FOR UPDATE")
            .fetch_one(&mut *enf_tx)
            .await
            .unwrap();

        let mut provider = Provider::new().await;
        let _worker_proc = chat.start(&provider).await;

        let wait_deadline = Instant::now() + Duration::from_secs(10);
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
                "TurnExecutor handoff_turn did not pause on quota_enforcement lock"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Confirm Attempt 1 committed reserve_turn_round without a usage_cost_micros hold and has
        // not yet committed handoff.
        let initial_reserved: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM openmettle.gateway_requests
              WHERE run_id = $1::uuid AND state = 'reserved'",
        )
        .bind(&run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(initial_reserved, 1);
        let initial_cost_holds: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM openmettle.quota_reservations
              WHERE run_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
        )
        .bind(&run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(initial_cost_holds, 0);

        // Enable the first applicable usage_cost_micros limit (5,000 personal) atomically inside
        // enf_tx and commit so enforce_gateway_handoff_holds immediately observes it, raises OMQ04,
        // rolls back Attempt 1 pre-dispatch, and TurnExecutor releases + retries once with cost holds.
        sqlx::query(
            "UPDATE openmettle.quota_defaults
                SET cost_denomination = 'usd_micros'
              WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros'",
        )
        .execute(&mut *enf_tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ('personal', 'usage_cost_micros', 5000)",
        )
        .execute(&mut *enf_tx)
        .await
        .unwrap();
        enf_tx.commit().await.unwrap();

        let req = provider.request().await;
        let req_id = req
            .request_id
            .clone()
            .expect("retried metered dispatch must attach x-request-id");

        // Attempt 1 must have been released cleanly and Attempt 2 must be handed_off with both
        // parent and child usage_cost_micros (300) holds materialized alongside usage_tokens.
        let req_states: Vec<String> = sqlx::query_scalar(
            "SELECT state FROM openmettle.gateway_requests
              WHERE run_id = $1::uuid ORDER BY state ASC",
        )
        .bind(&run_id)
        .fetch_all(&mut owner)
        .await
        .unwrap();
        assert_eq!(
            req_states,
            vec!["handed_off".to_owned(), "released".to_owned()]
        );

        let cost_parent: (i64, String) = sqlx::query_as(
            "SELECT reserved_units, state FROM openmettle.quota_reservations
              WHERE run_id = $1::uuid AND gateway_request_id IS NULL
                AND resource_kind = 'usage_cost_micros'",
        )
        .bind(&run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(cost_parent, (300, "held".to_owned()));

        let child_holds: Vec<(String, i64, String)> = sqlx::query_as(
            "SELECT resource_kind, reserved_units, state
               FROM openmettle.quota_reservations
              WHERE gateway_request_id = $1::uuid
              ORDER BY resource_kind ASC",
        )
        .bind(&req_id)
        .fetch_all(&mut owner)
        .await
        .unwrap();
        assert_eq!(child_holds.len(), 2);
        assert_eq!(
            child_holds[0],
            (
                "usage_cost_micros".to_owned(),
                300,
                "handoff_committed".to_owned()
            )
        );
        assert_eq!(child_holds[1].0, "usage_tokens");
        assert_eq!(child_holds[1].2, "handoff_committed");

        let report_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut owner)
            .await
            .unwrap();
        assert_eq!(
            settlement::ingest(
                &g_pool,
                &UsageReport {
                    request: req_id,
                    installation,
                    principal,
                    scope: chat.f.scope.clone(),
                    source: report_source,
                    report_id,
                    revision: 0,
                    r#final: true,
                    prompt_tokens: Some(40),
                    completion_tokens: Some(15),
                    reasoning_tokens: None,
                    reasoning_included: None,
                    cost: Some("210".into()),
                    unit: Some("usd_micros".into()),
                },
            )
            .await
            .unwrap(),
            settlement::Outcome::Applied
        );
        req.respond(completion(
            json!("retried cleanly after first cost limit enabled"),
            None,
            json!({"prompt_tokens": 40, "completion_tokens": 15}),
        ));

        chat.done(&run_id, "succeeded", None).await;
        assert!(
            provider.requests.try_recv().is_err(),
            "retried handoff must dispatch to the provider exactly once"
        );
        let round_events: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM openmettle.run_events
              WHERE scope_id = $1::uuid AND run_id = $2::uuid
                AND format = 'openmettle.model-round'",
        )
        .bind(&chat.f.scope)
        .bind(&run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(round_events, 1);

        let drift: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
               FROM openmettle.quota_verify_accounting_drift()",
        )
        .fetch_one(&mut worker(db).await)
        .await
        .unwrap();
        assert_eq!(drift, (0, 0, 0, 0));
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn oversized_image_wire_body_fails_before_gateway_reservation_or_handoff() {
        use openmettle_core::quotas::{self, RunBudgetReservation};

        // 1,572,864 raw PNG bytes (= 1536 KiB = BODY / 4 * 3) fits both worker_prompt's 1536 KiB
        // image budget and request.rs per-image cap, then expands via base64 + JSON envelope past
        // the 2 MiB BODY wire limit inside BillableInferenceRef::prepare.
        const RAW_PNG_LEN: usize = 1536 * 1024;

        let dir = Dir::new();
        let mut chat = Chat::new().await;
        chat.catalog["models"]["a"]["cost_bound"] = json!({
            "fixed_micros": 0,
            "micros_per_token": 1
        });
        let mut owner = connect(&chat.f.db.0, OWNER).await;
        owner
            .execute(
                "UPDATE openmettle.storage_instance
                    SET instance_budget_bytes = 8388608,
                        personal_limit_bytes = 8388608,
                        project_limit_bytes = 8388608",
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
                 VALUES ('personal', 'usage_cost_micros', 1000000)",
            )
            .await
            .unwrap();

        let root = PathBuf::from(dir.path(""));
        let store = artifact_fs::Store::open(&root).unwrap();
        let mut api_c = api(&chat.f.db).await;
        let artifact = openmettle_core::storage::upload_artifact(
            &mut api_c,
            &chat.f.scope,
            &chat.f.actor.user,
            "oversized-wire-img",
        )
        .await
        .unwrap();
        let upload = Upload {
            scope: &chat.f.scope,
            actor: &chat.f.actor.user,
            key: "oversized-wire-img",
            artifact: &artifact,
            max_bytes: (RAW_PNG_LEN + 4096) as i64,
            content_type: "multipart/form-data; boundary=sample",
        };
        let mut multipart = Vec::with_capacity(RAW_PNG_LEN + 256);
        multipart.extend_from_slice(
            b"--sample\r\nContent-Disposition: form-data; name=\"file\"; filename=\"large.png\"\r\nContent-Type: image/png\r\n\r\n",
        );
        // Valid PNG signature prefix + deterministic payload totaling RAW_PNG_LEN bytes.
        const PNG_SIG: &[u8] = b"\x89PNG\r\n\x1a\n";
        multipart.extend_from_slice(PNG_SIG);
        multipart.resize(multipart.len() + (RAW_PNG_LEN - PNG_SIG.len()), 0x42);
        multipart.extend_from_slice(
            b"\r\n--sample\r\nContent-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n{}\r\n--sample--\r\n",
        );
        let pool = sqlx::PgPool::connect(&chat.f.db.url(API)).await.unwrap();
        let image = artifact_fs::ingest(
            &pool,
            &store,
            &upload,
            http_body_util::Full::new(bytes::Bytes::from(multipart)),
            |_| true,
        )
        .await
        .unwrap();
        chat.artifacts = Some(root);

        let parts = [
            Part::Text("describe this large image".into()),
            Part::Attachment(image.revision),
        ];
        let (run_id, _) = chat
            .submit_parts("oversized-wire-run", "a", 1, &parts)
            .await;
        {
            let mut tx = WriteTransaction::begin(&mut api_c).await.unwrap();
            assert!(
                quotas::reserve_admitted_run_budget(
                    &mut tx,
                    &RunBudgetReservation {
                        scope_id: &chat.f.scope,
                        scope_kind: "personal",
                        actor_user_id: &chat.f.actor.user,
                        actor_approval_id: &chat.f.actor.approval,
                        run_id: &run_id,
                        token_units: 16384,
                        per_round_cost_micros: Some(16384),
                        round_limit: 1,
                        requires_device_slot: false,
                    },
                )
                .await
                .unwrap()
                .is_none()
            );
            tx.commit().await.unwrap();
        }

        let mut server = Provider::new().await;
        let _worker = chat.start(&server).await;
        chat.done(&run_id, "failed", Some("step_failed")).await;

        assert!(
            server.requests.try_recv().is_err(),
            "oversized wire body must never open an HTTP connection to provider"
        );
        // Confirm prompt hydration succeeded and recorded Round 1, then prepare() rejected the
        // oversized encoded wire body BEFORE reserve_turn_round / handoff_turn created any row.
        let (round_events, gw_requests, committed_holds): (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM openmettle.run_events
                      WHERE scope_id = $1::uuid AND run_id = $2::uuid
                        AND format = 'openmettle.model-round'),
                    (SELECT count(*) FROM openmettle.gateway_requests
                      WHERE run_id = $2::uuid),
                    (SELECT count(*) FROM openmettle.quota_reservations
                      WHERE run_id = $2::uuid AND state = 'handoff_committed')",
        )
        .bind(&chat.f.scope)
        .bind(&run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!((round_events, gw_requests, committed_holds), (1, 0, 0));

        let parent_holds: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT resource_kind, state, held_units
               FROM openmettle.quota_reservations
              WHERE run_id = $1::uuid AND gateway_request_id IS NULL
              ORDER BY resource_kind ASC",
        )
        .bind(&run_id)
        .fetch_all(&mut owner)
        .await
        .unwrap();
        assert_eq!(
            parent_holds,
            vec![
                ("usage_cost_micros".to_owned(), "released".to_owned(), 0),
                ("usage_tokens".to_owned(), "released".to_owned(), 0),
            ]
        );

        let usage_totals: (i64, i64) = sqlx::query_as(
            "SELECT coalesce(sum(reserved_held), 0)::bigint,
                    coalesce(sum(active_used), 0)::bigint
               FROM openmettle.quota_budgets
              WHERE resource_kind IN ('usage_tokens', 'usage_cost_micros')",
        )
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(usage_totals, (0, 0));

        let drift: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
               FROM openmettle.quota_verify_accounting_drift()",
        )
        .fetch_one(&mut worker(&chat.f.db).await)
        .await
        .unwrap();
        assert_eq!(drift, (0, 0, 0, 0));
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn oversized_bearer_header_rolls_back_handoff_before_commit() {
        use openmettle_core::{
            provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
            quotas::{self, RunBudgetReservation},
        };
        use sqlx::postgres::PgPoolOptions;

        let mut chat = Chat::new().await;
        chat.catalog["models"]["a"]["cost_bound"] = json!({
            "fixed_micros": 0,
            "micros_per_token": 1
        });
        let mut owner = connect(&chat.f.db.0, OWNER).await;
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
                 VALUES ('personal', 'usage_cost_micros', 1000000)",
            )
            .await
            .unwrap();

        let (installation, key_id, key_bytes) = chat.ensure_metered_gateway().await;
        let g_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with(chat.f.db.1.options(pg::GATEWAY));
        let (binding_id, principal): (String, String) = sqlx::query_as(
            "SELECT id::text, principal::text
               FROM openmettle.gateway_bindings
              WHERE installation = $1::uuid AND user_id = $2::uuid",
        )
        .bind(&installation)
        .bind(&chat.f.actor.user)
        .fetch_one(&g_pool)
        .await
        .unwrap();
        // Seal an 896-byte valid Bearer (accepted by Bearer::new) whose complete outbound HTTP
        // headers (Host + Connection + x-request-id + Authorization + Accept + Content-Type +
        // Content-Length) exceed MAX_REQUEST_HEADER_BYTES (1024).
        let keys = GatewayKeys::new(&[(key_id, key_bytes)]).unwrap();
        let long_bearer = Bearer::new(&[b'b'; 896]).expect("896-byte bearer is valid");
        let (finger, env) = GatewaySealer::new(keys, g_pool.clone())
            .seal(
                &Context {
                    installation: &installation,
                    user_id: &chat.f.actor.user,
                    binding_id: &binding_id,
                    principal: &principal,
                    generation: 1,
                },
                &long_bearer,
            )
            .await
            .unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_generations
                SET key_id = $2, key_fingerprint = $3, nonce = $4, ciphertext = $5
              WHERE binding_id = $1::uuid AND generation = 1",
        )
        .bind(&binding_id)
        .bind(&env.key_id)
        .bind(finger.as_slice())
        .bind(env.nonce.as_slice())
        .bind(env.ciphertext)
        .execute(&g_pool)
        .await
        .unwrap();

        let (run_id, _) = chat.submit("oversized-bearer-run", "a", 1).await;
        {
            let mut api_c = api(&chat.f.db).await;
            let mut tx = WriteTransaction::begin(&mut api_c).await.unwrap();
            assert!(
                quotas::reserve_admitted_run_budget(
                    &mut tx,
                    &RunBudgetReservation {
                        scope_id: &chat.f.scope,
                        scope_kind: "personal",
                        actor_user_id: &chat.f.actor.user,
                        actor_approval_id: &chat.f.actor.approval,
                        run_id: &run_id,
                        token_units: 16384,
                        per_round_cost_micros: Some(16384),
                        round_limit: 1,
                        requires_device_slot: false,
                    },
                )
                .await
                .unwrap()
                .is_none()
            );
            tx.commit().await.unwrap();
        }

        let mut server = Provider::new().await;
        let _worker = chat.start(&server).await;
        chat.done(&run_id, "failed", Some("step_failed")).await;

        assert!(
            server.requests.try_recv().is_err(),
            "oversized Authorization header must fail before opening provider TLS connection"
        );
        let req_states: Vec<String> = sqlx::query_scalar(
            "SELECT state FROM openmettle.gateway_requests WHERE run_id = $1::uuid",
        )
        .bind(&run_id)
        .fetch_all(&mut owner)
        .await
        .unwrap();
        assert_eq!(req_states, vec!["released".to_owned()]);

        let committed_holds: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM openmettle.quota_reservations
              WHERE run_id = $1::uuid AND state = 'handoff_committed'",
        )
        .bind(&run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(committed_holds, 0);

        let parent_holds: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT resource_kind, state, held_units
               FROM openmettle.quota_reservations
              WHERE run_id = $1::uuid AND gateway_request_id IS NULL
              ORDER BY resource_kind ASC",
        )
        .bind(&run_id)
        .fetch_all(&mut owner)
        .await
        .unwrap();
        assert_eq!(
            parent_holds,
            vec![
                ("usage_cost_micros".to_owned(), "released".to_owned(), 0),
                ("usage_tokens".to_owned(), "released".to_owned(), 0),
            ]
        );

        let usage_totals: (i64, i64) = sqlx::query_as(
            "SELECT coalesce(sum(reserved_held), 0)::bigint,
                    coalesce(sum(active_used), 0)::bigint
               FROM openmettle.quota_budgets
              WHERE resource_kind IN ('usage_tokens', 'usage_cost_micros')",
        )
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(usage_totals, (0, 0));

        let drift: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
               FROM openmettle.quota_verify_accounting_drift()",
        )
        .fetch_one(&mut worker(&chat.f.db).await)
        .await
        .unwrap();
        assert_eq!(drift, (0, 0, 0, 0));
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn deadline_and_mid_stream_cancel_close_inference_without_answers() {
        for cancel in [true, false] {
            let chat = Chat::new().await;
            let mut server = Provider::new().await;
            let (id, input) = chat.submit("stall", "a", 4).await;
            let _worker = chat.start(&server).await;
            let mut pending = server.request().await;
            if cancel {
                let actor = principal(&chat.f.db, &chat.f.actor).await;
                queue::cancel_run(&mut api(&chat.f.db).await, &actor, &chat.f.scope, &id)
                    .await
                    .unwrap();
                chat.done(&id, "cancelled", Some("requested")).await;
            } else {
                owner_exec(&chat.f.db,"UPDATE openmettle.runs SET lease_expires_at=now(),execution_expires_at=now() WHERE id=$1::uuid",&id).await;
                chat.done(&id, "failed", Some("deadline_exceeded")).await;
            }
            tokio::time::timeout(Duration::from_secs(15), pending.reply.closed())
                .await
                .expect("peer closed");
            assert_eq!(chat.graph().await, (1, 1, 1, Some(input)));
        }
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn metered_turn_dispatches_cost_bound_settles_and_releases_unused_rounds() {
        use crate::authz_http::{Api, As, browser, success};
        use openmettle_core::{
            authz::gateway::settlement,
            provider_http::gateway::UsageReport,
            provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
        };
        use sqlx::postgres::PgPoolOptions;

        const INSTALL: &str = "00000000-0000-4000-8000-000000000083";
        const PRINCIPAL: &str = "00000000-0000-4000-8000-000000000084";
        const BUDGET: &str = "00000000-0000-4000-8000-000000000085";
        const KEY_BYTES: [u8; 32] = [77; 32];

        let db = TestDb::migrated().await;
        let mut owner = connect(&db.0, OWNER).await;
        providers(&mut owner).await;
        let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
        let scope = personal_of(&db, &alice).await;
        let alice_cookie = browser(&db, &alice, 1).await;
        let alice_b = As::Browser(&alice_cookie);

        // Configure 1,000-micro static cost budget and ample token budget.
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
                        ('personal', 'usage_cost_micros', 1000)",
            )
            .await
            .unwrap();

        // Provision gateway binding, sealed bearer generation, and active policy for model `a`.
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
        let keys = GatewayKeys::new(&[("metered-k1".into(), KEY_BYTES)]).unwrap();
        let (finger, env) = GatewaySealer::new(keys, g_pool.clone())
            .seal(
                &Context {
                    installation: INSTALL,
                    user_id: &alice.user,
                    binding_id: &binding,
                    principal: PRINCIPAL,
                    generation: 1,
                },
                &Bearer::new(b"metered-round-token").unwrap(),
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

        // Mount real API binary with qualified `cost_bound` (1 micro/token) and `prompt_bound`.
        let dir = Dir::new();
        std::fs::create_dir(dir.path("artifacts")).unwrap();
        let mut doc = auth_config_support::document_v2_native(&dir, &Ca::new().pem());
        doc["cursor_keys"] = auth_config_support::cursor_keys(&dir);
        let mut catalog: Value =
            serde_json::from_slice(include_bytes!("../fixtures/conversation-catalog-v1.json"))
                .unwrap();
        catalog["models"]["a"]["pin"]["provider"] = "synthetic-sglang".into();
        catalog["models"]["a"]["prompt_bound"] = json!({
            "fixed_tokens": 4,
            "tokens_per_turn": 4,
            "tokens_per_part": 2,
            "tokens_per_byte": 1,
            "tokens_per_attachment": 10
        });
        catalog["models"]["a"]["cost_bound"] = json!({
            "fixed_micros": 0,
            "micros_per_token": 1
        });
        doc["catalog_file"] =
            json!(dir.write("catalog.json", &serde_json::to_vec(&catalog).unwrap()));
        doc["admission_limits"] = json!({
            "live_per_actor": 4,
            "live_per_scope": 8,
            "queued_in_instance": 32,
            "queue_timeout_seconds": 300,
            "round_cap": 10
        });
        let http_api = Api::configured(&db, dir, doc, 4);

        // Admit a 2-round run with 450-micro per-round ceiling -> reserves 900 micros total.
        let conv = success(
            http_api.call(
                alice_b,
                "POST",
                "/v1/conversations",
                Some("m-conv"),
                Some(&json!({})),
            ),
            201,
        );
        let conv_id = conv["conversation_id"].as_str().unwrap();
        let branch_id = conv["branch_id"].as_str().unwrap();
        let make_run = |msg_id: &str, rounds: i64| {
            json!({
                "conversation_id": conv_id,
                "branch_id": branch_id,
                "proposal": {
                    "expected_head_message_id": null,
                    "turn": {
                        "mode": "append",
                        "input_message_id": msg_id,
                        "parts": [{"text": "hello metered world"}]
                    },
                    "selection": {
                        "model": "a",
                        "layer": {"controls": {"context_window": "450", "output_reserve": "100"}}
                    },
                    "requested_rounds": rounds
                }
            })
        };
        let admitted = success(
            http_api.call(
                alice_b,
                "POST",
                "/v1/runs",
                Some("metered-run-1"),
                Some(&make_run("00000000-0000-4000-8000-00000000b001", 2)),
            ),
            201,
        );
        let run_id = admitted["run_id"].as_str().unwrap().to_owned();
        let q_before = success(
            http_api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
            200,
        );
        assert_eq!(q_before["usage"][1]["reserved_held"], "900");
        assert_eq!(q_before["usage"][1]["remaining"], "100");

        // Start real TurnExecutor worker with Route::metered against loopback TLS Provider.
        let mut provider = Provider::with_bearer("metered-round-token".into()).await;
        let mut child = Command::new(worker_binary())
            .env("OPENMETTLE_TEST_TURN_WORKER", "1")
            .args([
                "--ignored",
                "--exact",
                "worker::turns::schema_fixture::worker_process",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.as_mut().unwrap();
        serde_json::to_writer(
            &mut *stdin,
            &json!({
                "database": db.url(WORKER),
                "catalog": catalog,
                "tools": false,
                "scope": scope,
                "actor": alice.user,
                "ca": String::from_utf8(provider.ca.pem()).unwrap(),
                "port": provider.port,
                "artifacts": null,
                "stop_during_observation": false,
                "metered": {
                    "installation": INSTALL,
                    "key_id": "metered-k1",
                    "key_bytes": KEY_BYTES,
                }
            }),
        )
        .unwrap();
        writeln!(stdin).unwrap();
        let _worker_proc = Process(child);

        // Round 1 reaches TLS provider with decrypted gateway bearer AND x-request-id header;
        // feed the peer-observed x-request-id directly into settlement::ingest (proving real wire correlation).
        let req = provider.request().await;
        let req_id = req
            .request_id
            .clone()
            .expect("metered send must attach x-request-id header");
        let (child_cost, parent_rem): (i64, i64) = sqlx::query_as(
            "SELECT (SELECT reserved_units FROM openmettle.quota_reservations
                      WHERE gateway_request_id = $1::uuid AND resource_kind = 'usage_cost_micros'),
                    (SELECT held_units FROM openmettle.quota_reservations
                      WHERE run_id = $2::uuid AND gateway_request_id IS NULL
                        AND resource_kind = 'usage_cost_micros')",
        )
        .bind(&req_id)
        .bind(&run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!((child_cost, parent_rem), (450, 450));

        // Settle Round 1 at 200 micros (150 tokens) through real gateway::settlement::ingest.
        let report_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut owner)
            .await
            .unwrap();
        let outcome = settlement::ingest(
            &g_pool,
            &UsageReport {
                request: req_id.clone(),
                installation: INSTALL.into(),
                principal: PRINCIPAL.into(),
                scope: scope.clone(),
                source: report_source,
                report_id,
                revision: 0,
                r#final: true,
                prompt_tokens: Some(100),
                completion_tokens: Some(50),
                reasoning_tokens: None,
                reasoning_included: None,
                cost: Some("200".into()),
                unit: Some("usd_micros".into()),
            },
        )
        .await
        .unwrap();
        assert_eq!(outcome, settlement::Outcome::Applied);

        // Reply with final answer; worker publishes answer, settles Succeeded, and releases the
        // unused 450-micro Round 2 parent hold immediately.
        req.respond(completion(
            json!("metered answer"),
            None,
            json!({"prompt_tokens": 100, "completion_tokens": 50}),
        ));
        let mut api_c = api(&db).await;
        tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                let stored: String =
                    sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                        .bind(&run_id)
                        .fetch_one(&mut api_c)
                        .await
                        .unwrap();
                if queue::is_terminal(&stored) {
                    assert_eq!(stored, "succeeded");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("worker settled metered run");

        // Zero accounting drift and unused Round 2 hold released -> 200 active, 0 held, 800 remaining.
        let drift: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
               FROM openmettle.quota_verify_accounting_drift()",
        )
        .fetch_one(&mut worker(&db).await)
        .await
        .unwrap();
        assert_eq!(drift, (0, 0, 0, 0));
        let q_after = success(
            http_api.call(alice_b, "GET", "/v1/quotas/personal", None, None),
            200,
        );
        assert_eq!(q_after["usage"][1]["active_used"], "200");
        assert_eq!(q_after["usage"][1]["reserved_held"], "0");
        assert_eq!(q_after["usage"][1]["remaining"], "800");

        // Subsequent 450-micro POST /v1/runs succeeds with 201 Created (200 + 450 = 650 <= 1000).
        let conv2 = success(
            http_api.call(
                alice_b,
                "POST",
                "/v1/conversations",
                Some("m-conv-2"),
                Some(&json!({})),
            ),
            201,
        );
        let next_run = success(
            http_api.call(
                alice_b,
                "POST",
                "/v1/runs",
                Some("metered-run-2"),
                Some(&json!({
                    "conversation_id": conv2["conversation_id"],
                    "branch_id": conv2["branch_id"],
                    "proposal": {
                        "expected_head_message_id": null,
                        "turn": {
                            "mode": "append",
                            "input_message_id": "00000000-0000-4000-8000-00000000b002",
                            "parts": [{"text": "second metered run"}]
                        },
                        "selection": {
                            "model": "a",
                            "layer": {"controls": {"context_window": "450", "output_reserve": "100"}}
                        },
                        "requested_rounds": 1
                    }
                })),
            ),
            201,
        );
        assert!(next_run["run_id"].is_string());
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn unmetered_bearer_route_fails_closed_when_metering_is_enforced() {
        use openmettle_core::quotas::{self, RunBudgetReservation};

        let mut chat = Chat::new().await;
        chat.unmetered = true;
        let mut server = Provider::new().await;
        let (id, _) = chat.submit("unmetered-fail-closed", "a", 2).await;
        let mut api_c = api(&chat.f.db).await;
        let mut tx = WriteTransaction::begin(&mut api_c).await.unwrap();
        assert!(
            quotas::reserve_admitted_run_budget(
                &mut tx,
                &RunBudgetReservation {
                    scope_id: &chat.f.scope,
                    scope_kind: "personal",
                    actor_user_id: &chat.f.actor.user,
                    actor_approval_id: &chat.f.actor.approval,
                    run_id: &id,
                    token_units: 16384,
                    per_round_cost_micros: None,
                    round_limit: 2,
                    requires_device_slot: false,
                },
            )
            .await
            .unwrap()
            .is_none()
        );
        tx.commit().await.unwrap();

        let _worker = chat.start(&server).await;
        chat.done(&id, "failed", Some("step_failed")).await;
        assert!(server.requests.try_recv().is_err());
        let held: i64 = sqlx::query_scalar(
            "SELECT coalesce(sum(reserved_held), 0)::bigint FROM openmettle.quota_budgets",
        )
        .fetch_one(&mut connect(&chat.f.db.0, OWNER).await)
        .await
        .unwrap();
        assert_eq!(held, 0);

        // Also fail closed on schema 25 (quota_enforcement exists, metering_enforced = false,
        // without schema-26's FOR SHARE guard helper) so MVCC cannot race activation.
        let db25 = TestDb::new().await;
        let settings25 = db25.settings(Duration::from_secs(10));
        migrate::apply(&settings25, &MIGRATIONS[..23])
            .await
            .unwrap();
        let mut owner25 = connect(&db25.0, OWNER).await;
        providers(&mut owner25).await;
        let actor25 = account(&mut owner25, PROVIDER, true, FUTURE).await;
        let scope25 = personal_of(&db25, &actor25).await;
        migrate::apply(&settings25, &MIGRATIONS[..25])
            .await
            .unwrap();
        let enforced25: bool = sqlx::query_scalar(
            "SELECT metering_enforced FROM openmettle.quota_enforcement WHERE id",
        )
        .fetch_one(&mut owner25)
        .await
        .unwrap();
        assert!(!enforced25);
        let mut chat25 = Chat::on(Fixture {
            db: db25,
            actor: actor25,
            scope: scope25,
        })
        .await;
        chat25.unmetered = true;
        let (id25, _) = chat25.submit("unmetered-schema25", "a", 1).await;
        let _worker25 = chat25.start(&server).await;
        chat25.done(&id25, "failed", Some("step_failed")).await;
        assert!(server.requests.try_recv().is_err());
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn token_only_deployment_dispatches_cost_bound_model() {
        use crate::authz_http::{Api, As, browser, success};
        use openmettle_core::{
            authz::gateway::settlement,
            provider_http::gateway::UsageReport,
            provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
        };
        use sqlx::postgres::PgPoolOptions;

        const INSTALL: &str = "00000000-0000-4000-8000-000000000094";
        const PRINCIPAL: &str = "00000000-0000-4000-8000-000000000095";
        const BUDGET: &str = "00000000-0000-4000-8000-000000000096";
        const KEY_BYTES: [u8; 32] = [88; 32];

        let db = TestDb::migrated().await;
        let mut owner = connect(&db.0, OWNER).await;
        providers(&mut owner).await;
        let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
        let scope = personal_of(&db, &alice).await;
        let alice_cookie = browser(&db, &alice, 1).await;
        let alice_b = As::Browser(&alice_cookie);

        // Token-only deployment: cost_denomination stays NULL and no usage_cost_micros hard_limit exists.
        owner
            .execute(
                "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
                 VALUES ('personal', 'usage_tokens', 100000)",
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
        let keys = GatewayKeys::new(&[("token-only-k1".into(), KEY_BYTES)]).unwrap();
        let (finger, env) = GatewaySealer::new(keys, g_pool.clone())
            .seal(
                &Context {
                    installation: INSTALL,
                    user_id: &alice.user,
                    binding_id: &binding,
                    principal: PRINCIPAL,
                    generation: 1,
                },
                &Bearer::new(b"token-only-round-bearer").unwrap(),
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

        let dir = Dir::new();
        std::fs::create_dir(dir.path("artifacts")).unwrap();
        let mut doc = auth_config_support::document_v2_native(&dir, &Ca::new().pem());
        doc["cursor_keys"] = auth_config_support::cursor_keys(&dir);
        let mut catalog: Value =
            serde_json::from_slice(include_bytes!("../fixtures/conversation-catalog-v1.json"))
                .unwrap();
        catalog["models"]["a"]["pin"]["provider"] = "synthetic-sglang".into();
        catalog["models"]["a"]["prompt_bound"] = json!({
            "fixed_tokens": 4,
            "tokens_per_turn": 4,
            "tokens_per_part": 2,
            "tokens_per_byte": 1,
            "tokens_per_attachment": 10
        });
        catalog["models"]["a"]["cost_bound"] = json!({
            "fixed_micros": i64::MAX,
            "micros_per_token": 1
        });
        doc["catalog_file"] =
            json!(dir.write("catalog.json", &serde_json::to_vec(&catalog).unwrap()));
        doc["admission_limits"] = json!({
            "live_per_actor": 4,
            "live_per_scope": 8,
            "queued_in_instance": 32,
            "queue_timeout_seconds": 300,
            "round_cap": 10
        });
        let http_api = Api::configured(&db, dir, doc, 4);

        let conv = success(
            http_api.call(
                alice_b,
                "POST",
                "/v1/conversations",
                Some("to-conv"),
                Some(&json!({})),
            ),
            201,
        );
        let admitted = success(
            http_api.call(
                alice_b,
                "POST",
                "/v1/runs",
                Some("to-run-1"),
                Some(&json!({
                    "conversation_id": conv["conversation_id"],
                    "branch_id": conv["branch_id"],
                    "proposal": {
                        "expected_head_message_id": null,
                        "turn": {
                            "mode": "append",
                            "input_message_id": "00000000-0000-4000-8000-00000000c001",
                            "parts": [{"text": "hello token-only cost-bound world"}]
                        },
                        "selection": {
                            "model": "a",
                            "layer": {"controls": {"context_window": "450", "output_reserve": "100"}}
                        },
                        "requested_rounds": 1
                    }
                })),
            ),
            201,
        );
        let run_id = admitted["run_id"].as_str().unwrap().to_owned();

        let mut provider = Provider::with_bearer("token-only-round-bearer".into()).await;
        let mut child = Command::new(worker_binary())
            .env("OPENMETTLE_TEST_TURN_WORKER", "1")
            .args([
                "--ignored",
                "--exact",
                "worker::turns::schema_fixture::worker_process",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.as_mut().unwrap();
        serde_json::to_writer(
            &mut *stdin,
            &json!({
                "database": db.url(WORKER),
                "catalog": catalog,
                "tools": false,
                "scope": scope,
                "actor": alice.user,
                "ca": String::from_utf8(provider.ca.pem()).unwrap(),
                "port": provider.port,
                "artifacts": null,
                "stop_during_observation": false,
                "metered": {
                    "installation": INSTALL,
                    "key_id": "token-only-k1",
                    "key_bytes": KEY_BYTES,
                }
            }),
        )
        .unwrap();
        writeln!(stdin).unwrap();
        let _worker_proc = Process(child);

        let req = provider.request().await;
        let req_id = req
            .request_id
            .clone()
            .expect("metered send must attach x-request-id");
        let cost_holds: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM openmettle.quota_reservations
              WHERE run_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
        )
        .bind(&run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(cost_holds, 0);

        let report_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut owner)
            .await
            .unwrap();
        assert_eq!(
            settlement::ingest(
                &g_pool,
                &UsageReport {
                    request: req_id,
                    installation: INSTALL.into(),
                    principal: PRINCIPAL.into(),
                    scope: scope.clone(),
                    source: report_source,
                    report_id,
                    revision: 0,
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
        req.respond(completion(
            json!("token-only answer"),
            None,
            json!({"prompt_tokens": 80, "completion_tokens": 40}),
        ));
        let mut api_c = api(&db).await;
        tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                let stored: String =
                    sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                        .bind(&run_id)
                        .fetch_one(&mut api_c)
                        .await
                        .unwrap();
                if queue::is_terminal(&stored) {
                    assert_eq!(stored, "succeeded");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("token-only metered run settled");
        let drift: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
               FROM openmettle.quota_verify_accounting_drift()",
        )
        .fetch_one(&mut worker(&db).await)
        .await
        .unwrap();
        assert_eq!(drift, (0, 0, 0, 0));
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn device_slot_profile_requires_grant_commits_handoff_and_survives_cancel() {
        use openmettle_core::quotas::{self, RunBudgetReservation};

        const GRANT_ID: &str = "00000000-0000-4000-8000-00000000d001";

        let mut chat = Chat::new().await;
        chat.catalog["models"]["a"]["requires_device_slot"] = json!(true);
        let mut owner = connect(&chat.f.db.0, OWNER).await;
        owner
            .execute(
                "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
                 VALUES ('personal', 'device_reservations', 1)",
            )
            .await
            .unwrap();
        let mut server = Provider::new().await;

        // Subcase A: missing device_grant_id fails closed BEFORE HTTP send and releases all holds.
        let (r1, _) = chat.submit("dev-missing-grant", "a", 2).await;
        {
            let mut api_c = api(&chat.f.db).await;
            let mut tx = WriteTransaction::begin(&mut api_c).await.unwrap();
            assert!(
                quotas::reserve_admitted_run_budget(
                    &mut tx,
                    &RunBudgetReservation {
                        scope_id: &chat.f.scope,
                        scope_kind: "personal",
                        actor_user_id: &chat.f.actor.user,
                        actor_approval_id: &chat.f.actor.approval,
                        run_id: &r1,
                        token_units: 16384,
                        per_round_cost_micros: None,
                        round_limit: 2,
                        requires_device_slot: true,
                    },
                )
                .await
                .unwrap()
                .is_none()
            );
            tx.commit().await.unwrap();
        }
        let w1 = chat.start(&server).await;
        chat.done(&r1, "failed", Some("step_failed")).await;
        assert!(server.requests.try_recv().is_err());
        let held_after_r1: i64 = sqlx::query_scalar(
            "SELECT coalesce(sum(reserved_held), 0)::bigint FROM openmettle.quota_budgets",
        )
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(held_after_r1, 0);
        drop(w1);

        // Subcase B: valid device_grant_id commits handoff BEFORE HTTP send, and survives cancel.
        chat.device_grant_id = Some(GRANT_ID.into());
        let (r2, _) = chat.submit("dev-with-grant", "a", 2).await;
        {
            let mut api_c = api(&chat.f.db).await;
            let mut tx = WriteTransaction::begin(&mut api_c).await.unwrap();
            assert!(
                quotas::reserve_admitted_run_budget(
                    &mut tx,
                    &RunBudgetReservation {
                        scope_id: &chat.f.scope,
                        scope_kind: "personal",
                        actor_user_id: &chat.f.actor.user,
                        actor_approval_id: &chat.f.actor.approval,
                        run_id: &r2,
                        token_units: 16384,
                        per_round_cost_micros: None,
                        round_limit: 2,
                        requires_device_slot: true,
                    },
                )
                .await
                .unwrap()
                .is_none()
            );
            tx.commit().await.unwrap();
        }
        let _w2 = chat.start(&server).await;
        let _req = server.request().await;
        assert!(_req.request_id.is_some());

        // Device hold must ALREADY be handoff_committed with GRANT_ID when Round 1 reaches the peer.
        let dev_state: (String, Option<String>) = sqlx::query_as(
            "SELECT state, device_grant_id::text
               FROM openmettle.quota_reservations
              WHERE run_id = $1::uuid AND gateway_request_id IS NULL
                AND resource_kind = 'device_reservations'",
        )
        .bind(&r2)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(
            dev_state,
            ("handoff_committed".into(), Some(GRANT_ID.into()))
        );

        // Cancel mid-flight: unused Round 2 token hold releases, while committed device slot stays charged.
        let actor = principal(&chat.f.db, &chat.f.actor).await;
        queue::cancel_run(&mut api(&chat.f.db).await, &actor, &chat.f.scope, &r2)
            .await
            .unwrap();
        chat.done(&r2, "cancelled", Some("requested")).await;

        let token_parent_held: i64 = sqlx::query_scalar(
            "SELECT held_units FROM openmettle.quota_reservations
              WHERE run_id = $1::uuid AND gateway_request_id IS NULL
                AND resource_kind = 'usage_tokens'",
        )
        .bind(&r2)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(token_parent_held, 0);
        let dev_after_cancel: (String, i64) = sqlx::query_as(
            "SELECT r.state, b.reserved_held::bigint
               FROM openmettle.quota_reservations r
               JOIN openmettle.quota_budgets b
                 ON b.scope_id = r.scope_id AND b.resource_kind = r.resource_kind
              WHERE r.run_id = $1::uuid AND r.gateway_request_id IS NULL
                AND r.resource_kind = 'device_reservations'",
        )
        .bind(&r2)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(dev_after_cancel, ("handoff_committed".into(), 1));
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn refused_handoff_immediately_releases_unsent_round_hold() {
        use openmettle_core::quotas::{self, RunBudgetReservation};
        use sqlx::postgres::PgPoolOptions;

        let chat = Chat::new().await;
        let _ = chat.ensure_metered_gateway().await;
        // Suspend the binding so reserve_turn_round allocates Round 1 child hold cleanly, then
        // pending.handoff returns Refused and must release the unsent round hold immediately.
        let g_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with(chat.f.db.1.options(pg::GATEWAY));
        sqlx::query("UPDATE openmettle.gateway_bindings SET state = 'suspended'")
            .execute(&g_pool)
            .await
            .unwrap();

        let mut server = Provider::new().await;
        let (id, _) = chat.submit("refused-handoff", "a", 2).await;
        {
            let mut api_c = api(&chat.f.db).await;
            let mut tx = WriteTransaction::begin(&mut api_c).await.unwrap();
            assert!(
                quotas::reserve_admitted_run_budget(
                    &mut tx,
                    &RunBudgetReservation {
                        scope_id: &chat.f.scope,
                        scope_kind: "personal",
                        actor_user_id: &chat.f.actor.user,
                        actor_approval_id: &chat.f.actor.approval,
                        run_id: &id,
                        token_units: 16384,
                        per_round_cost_micros: None,
                        round_limit: 2,
                        requires_device_slot: false,
                    },
                )
                .await
                .unwrap()
                .is_none()
            );
            tx.commit().await.unwrap();
        }

        let _worker = chat.start(&server).await;
        chat.done(&id, "failed", Some("step_failed")).await;
        assert!(server.requests.try_recv().is_err());

        let mut owner = connect(&chat.f.db.0, OWNER).await;
        let req_state: String = sqlx::query_scalar(
            "SELECT state FROM openmettle.gateway_requests
              WHERE run_id = $1::uuid AND round = 1",
        )
        .bind(&id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(req_state, "released");
        let held: i64 = sqlx::query_scalar(
            "SELECT coalesce(sum(reserved_held), 0)::bigint FROM openmettle.quota_budgets",
        )
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(held, 0);
    }

    #[tokio::test]
    #[ignore = "isolated PostgreSQL 18 and synthetic TLS gateway"]
    async fn funded_parent_cost_hold_completes_both_rounds_after_limit_lowered_and_refuses_new_admission()
     {
        use crate::authz_http::{Api, As, browser, success};
        use openmettle_core::{
            authz::gateway::settlement,
            provider_http::gateway::UsageReport,
            provider_keys::gateway::{Bearer, Context, GatewayKeys, GatewaySealer},
        };
        use sqlx::postgres::PgPoolOptions;

        const INSTALL: &str = "00000000-0000-4000-8000-000000001920";
        const PRINCIPAL: &str = "00000000-0000-4000-8000-000000001921";
        const BUDGET: &str = "00000000-0000-4000-8000-000000001922";
        const KEY_BYTES: [u8; 32] = [0x71; 32];

        let db = TestDb::migrated().await;
        let mut owner = connect(&db.0, OWNER).await;
        providers(&mut owner).await;
        let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
        crate::authz_store::make_admin(&mut owner, &admin).await;
        let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
        let scope = personal_of(&db, &alice).await;
        let admin_cookie = browser(&db, &admin, 2).await;
        let admin_n = As::Browser(&admin_cookie);
        let alice_cookie = browser(&db, &alice, 1).await;
        let alice_b = As::Browser(&alice_cookie);

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
                        ('personal', 'usage_cost_micros', 500)",
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
        let keys = GatewayKeys::new(&[("lowered-k1".into(), KEY_BYTES)]).unwrap();
        let (finger, env) = GatewaySealer::new(keys, g_pool.clone())
            .seal(
                &Context {
                    installation: INSTALL,
                    user_id: &alice.user,
                    binding_id: &binding,
                    principal: PRINCIPAL,
                    generation: 1,
                },
                &Bearer::new(b"lowered-limit-bearer").unwrap(),
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

        let dir = Dir::new();
        std::fs::create_dir(dir.path("artifacts")).unwrap();
        let mut doc = auth_config_support::document_v2_native(&dir, &Ca::new().pem());
        doc["cursor_keys"] = auth_config_support::cursor_keys(&dir);
        let mut catalog: Value =
            serde_json::from_slice(include_bytes!("../fixtures/conversation-catalog-v1.json"))
                .unwrap();
        catalog["models"]["a"]["pin"]["provider"] = "synthetic-sglang".into();
        catalog["models"]["a"]["prompt_bound"] = json!({
            "fixed_tokens": 4,
            "tokens_per_turn": 4,
            "tokens_per_part": 2,
            "tokens_per_byte": 1,
            "tokens_per_attachment": 10
        });
        catalog["models"]["a"]["cost_bound"] = json!({
            "fixed_micros": 100,
            "micros_per_token": 0
        });
        doc["catalog_file"] =
            json!(dir.write("catalog.json", &serde_json::to_vec(&catalog).unwrap()));
        doc["admission_limits"] = json!({
            "live_per_actor": 4,
            "live_per_scope": 8,
            "queued_in_instance": 32,
            "queue_timeout_seconds": 300,
            "round_cap": 10
        });
        let http_api = Api::configured(&db, dir, doc, 4);

        // Admit a 2-round run with 100 micros/round -> reserves 200 funded cost micro-units.
        let conv = success(
            http_api.call(
                alice_b,
                "POST",
                "/v1/conversations",
                Some("lowered-conv"),
                Some(&json!({})),
            ),
            201,
        );
        let conv_id = conv["conversation_id"].as_str().unwrap();
        let branch_id = conv["branch_id"].as_str().unwrap();
        let make_run = |msg_id: &str, rounds: i64| {
            json!({
                "conversation_id": conv_id,
                "branch_id": branch_id,
                "proposal": {
                    "expected_head_message_id": null,
                    "turn": {
                        "mode": "append",
                        "input_message_id": msg_id,
                        "parts": [{"text": "two rounds under lowered limit"}]
                    },
                    "selection": {
                        "model": "a",
                        "layer": {"controls": {"context_window": "8192", "output_reserve": "1024"}}
                    },
                    "requested_rounds": rounds
                }
            })
        };
        let admitted = success(
            http_api.call(
                alice_b,
                "POST",
                "/v1/runs",
                Some("lowered-run-1"),
                Some(&make_run("00000000-0000-4000-8000-00000000c001", 2)),
            ),
            201,
        );
        let run_id = admitted["run_id"].as_str().unwrap().to_owned();

        // Lower personal usage_cost_micros override to 50 while the run is in flight.
        success(
            http_api.call(
                admin_n,
                "PUT",
                &format!("/v1/admin/scopes/{scope}/quotas/usage_cost_micros"),
                Some("lowered-override-50"),
                Some(&json!({"hard_limit": "50", "reason": "lower cost limit below funded round"})),
            ),
            200,
        );

        // A NEW run admission on a second conversation MUST fail closed with 429 quota.
        let conv2 = success(
            http_api.call(
                alice_b,
                "POST",
                "/v1/conversations",
                Some("lowered-conv-2"),
                Some(&json!({})),
            ),
            201,
        );
        let (refused_status, refused_body) = http_api.call(
            alice_b,
            "POST",
            "/v1/runs",
            Some("lowered-run-new-refused"),
            Some(&json!({
                "conversation_id": conv2["conversation_id"],
                "branch_id": conv2["branch_id"],
                "proposal": {
                    "expected_head_message_id": null,
                    "turn": {
                        "mode": "append",
                        "input_message_id": "00000000-0000-4000-8000-00000000c002",
                        "parts": [{"text": "new run must fail under lowered limit"}]
                    },
                    "selection": {
                        "model": "a",
                        "layer": {"controls": {"context_window": "8192", "output_reserve": "1024"}}
                    },
                    "requested_rounds": 1
                }
            })),
        );
        assert_eq!(refused_status, 429, "{refused_body}");
        assert_eq!(refused_body["code"], "quota");
        assert_eq!(refused_body["quota"]["resource_kind"], "usage_cost_micros");
        assert_eq!(refused_body["quota"]["scope_kind"], "personal");

        // Start real TurnExecutor worker with tools enabled (2 rounds) against TLS Provider.
        let mut provider = Provider::with_bearer("lowered-limit-bearer".into()).await;
        let mut child = Command::new(worker_binary())
            .env("OPENMETTLE_TEST_TURN_WORKER", "1")
            .args([
                "--ignored",
                "--exact",
                "worker::turns::schema_fixture::worker_process",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.as_mut().unwrap();
        serde_json::to_writer(
            &mut *stdin,
            &json!({
                "database": db.url(WORKER),
                "catalog": catalog,
                "tools": true,
                "scope": scope,
                "actor": alice.user,
                "ca": String::from_utf8(provider.ca.pem()).unwrap(),
                "port": provider.port,
                "artifacts": null,
                "stop_during_observation": false,
                "metered": {
                    "installation": INSTALL,
                    "key_id": "lowered-k1",
                    "key_bytes": KEY_BYTES,
                }
            }),
        )
        .unwrap();
        writeln!(stdin).unwrap();
        let _worker_proc = Process(child);

        // Round 1 allocates 100 micros from funded parent hold despite active limit = 50,
        // hands off via TurnDispatch::send, and reaches the TLS provider with x-request-id.
        let req1 = provider.request().await;
        let req1_id = req1
            .request_id
            .clone()
            .expect("round 1 TurnDispatch::send must attach x-request-id");

        // Lower personal usage_cost_micros override further to 0 BEFORE Round 2!
        success(
            http_api.call(
                admin_n,
                "PUT",
                &format!("/v1/admin/scopes/{scope}/quotas/usage_cost_micros"),
                Some("lowered-override-0"),
                Some(&json!({"hard_limit": "0", "reason": "zero cost limit before round 2"})),
            ),
            200,
        );
        let report1: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut owner)
            .await
            .unwrap();
        assert_eq!(
            settlement::ingest(
                &g_pool,
                &UsageReport {
                    request: req1_id,
                    installation: INSTALL.into(),
                    principal: PRINCIPAL.into(),
                    scope: scope.clone(),
                    source: report_source.clone(),
                    report_id: report1,
                    revision: 0,
                    r#final: true,
                    prompt_tokens: Some(40),
                    completion_tokens: Some(20),
                    reasoning_tokens: None,
                    reasoning_included: None,
                    cost: Some("60".into()),
                    unit: Some("usd_micros".into()),
                },
            )
            .await
            .unwrap(),
            settlement::Outcome::Applied
        );
        req1.respond(tool_call("lookup", "{}"));

        // Round 2 allocates the remaining 100 funded parent micros despite active limit = 0,
        // hands off via TurnDispatch::send, and completes the run.
        let req2 = provider.request().await;
        let req2_id = req2
            .request_id
            .clone()
            .expect("round 2 TurnDispatch::send must attach x-request-id");
        let report2: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut owner)
            .await
            .unwrap();
        assert_eq!(
            settlement::ingest(
                &g_pool,
                &UsageReport {
                    request: req2_id,
                    installation: INSTALL.into(),
                    principal: PRINCIPAL.into(),
                    scope: scope.clone(),
                    source: report_source.clone(),
                    report_id: report2,
                    revision: 0,
                    r#final: true,
                    prompt_tokens: Some(50),
                    completion_tokens: Some(30),
                    reasoning_tokens: None,
                    reasoning_included: None,
                    cost: Some("55".into()),
                    unit: Some("usd_micros".into()),
                },
            )
            .await
            .unwrap(),
            settlement::Outcome::Applied
        );
        req2.respond(completion(
            json!("completed both rounds"),
            None,
            Value::Null,
        ));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let state: String =
                sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                    .bind(&run_id)
                    .fetch_one(&mut owner)
                    .await
                    .unwrap();
            if state == "succeeded" {
                break;
            }
            assert_eq!(state, "running", "unexpected run state: {state}");
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for two-round funded run to succeed"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        let cost_totals: (i64, i64) = sqlx::query_as(
            "SELECT active_used::bigint, reserved_held::bigint
               FROM openmettle.quota_budgets
              WHERE target_kind = 'scope' AND scope_id = $1::uuid
                AND resource_kind = 'usage_cost_micros'",
        )
        .bind(&scope)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(cost_totals, (115, 0));

        let drift: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT storage_mismatches, budget_mismatches, settlement_mismatches, pending_gateway_reconciliations
               FROM openmettle.quota_verify_accounting_drift()",
        )
        .fetch_one(&mut worker(&db).await)
        .await
        .unwrap();
        assert_eq!(drift, (0, 0, 0, 0));
    }
}
