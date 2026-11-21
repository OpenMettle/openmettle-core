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
    for (capability, unknown) in [("lookup", true), ("non_repeatable", false)] {
        let run = f.claim(capability).await;
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
async fn replay_safe_operations_resume_under_their_original_logical_keys() {
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
    assert!(
        unresolved_operations(&mut c, &l, 1)
            .await
            .unwrap()
            .is_empty()
    );
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
