//! One pool connection forces the runner to return it before every adapter call and drain.
use super::*;
use openmettle_core::{
    WorkerSettings,
    worker::{
        self as runtime, ActiveRun, Executor, OwnedObservation, StepContext, StepResult, Stop,
    },
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

struct Step {
    claim: ClaimedRun,
    cx: StepContext,
    reply: oneshot::Sender<StepResult>,
}

struct Lookup {
    op: String,
    cx: StepContext,
    reply: oneshot::Sender<Option<OwnedObservation>>,
}

struct Adapter {
    steps: mpsc::UnboundedSender<Step>,
    lookups: mpsc::UnboundedSender<Lookup>,
}

impl Executor for Adapter {
    async fn step(&self, run: &ActiveRun, cx: StepContext) -> StepResult {
        assert_eq!(run.state, ExecState::Running);
        assert!(cx.deadline <= run.execution_deadline);
        let (reply, rx) = oneshot::channel();
        self.steps
            .send(Step {
                claim: run.claim.clone(),
                cx,
                reply,
            })
            .ok()
            .unwrap();
        // A fault-injected adapter can ignore the stop watch indefinitely.
        rx.await.unwrap()
    }

    async fn reconcile(
        &self,
        _: &ActiveRun,
        op: &UnresolvedOperation,
        cx: StepContext,
    ) -> Option<OwnedObservation> {
        let (reply, rx) = oneshot::channel();
        self.lookups
            .send(Lookup {
                op: op.id.clone(),
                cx,
                reply,
            })
            .ok()
            .unwrap();
        rx.await.unwrap()
    }
}

struct Worker {
    task: JoinHandle<()>,
    shutdown: oneshot::Sender<()>,
    steps: mpsc::UnboundedReceiver<Step>,
    lookups: mpsc::UnboundedReceiver<Lookup>,
}

async fn bounded<T>(f: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(25), f)
        .await
        .expect("worker test deadline")
}

impl Worker {
    async fn start(db: &TestDb) -> Self {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(1))
            .connect(&db.url(WORKER))
            .await
            .unwrap();
        let (step_tx, steps) = mpsc::unbounded_channel();
        let (lookup_tx, lookups) = mpsc::unbounded_channel();
        let (shutdown, stop) = oneshot::channel();
        let executor = Arc::new(Adapter {
            steps: step_tx,
            lookups: lookup_tx,
        });
        let settings = WorkerSettings::parse(Duration::from_secs(1), |key| {
            Ok(Some(
                match key {
                    "RUN_SLOTS" | "EXECUTING_PER_ACTOR" | "EXECUTING_PER_SCOPE" => "1",
                    "LEASE_MS" => "30000",
                    "EXECUTION_TIMEOUT_MS" => "180000",
                    "POLL_MS" => "100",
                    _ => return Ok(None),
                }
                .to_owned(),
            ))
        })
        .unwrap();
        let task = tokio::spawn(async move {
            runtime::run(
                &pool,
                None,
                settings,
                executor,
                async {
                    let _ = stop.await;
                },
                Duration::from_secs(8),
            )
            .await;
        });
        Self {
            task,
            shutdown,
            steps,
            lookups,
        }
    }

    async fn step(&mut self) -> Step {
        bounded(self.steps.recv()).await.expect("step")
    }
    async fn lookup(&mut self) -> Lookup {
        bounded(self.lookups.recv())
            .await
            .expect("reconciliation pass")
    }
}

async fn stopped(cx: &mut StepContext) -> Stop {
    bounded(cx.stop.wait_for(Option::is_some))
        .await
        .unwrap()
        .unwrap()
}

async fn wait_terminal(f: &Fixture, id: &str, format: &str, bytes: &[u8]) {
    bounded(async {
        while terminal_events(&f.db, id).await.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    terminal(&f.db, id, format, bytes).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn finished_during_cancel_drain_wins_over_the_request() {
    let f = Fixture::new().await;
    let id = f.admit("finish-during-cancel").await;
    let mut w = Worker::start(&f.db).await;
    let mut step = w.step().await;
    f.cancel(&step.claim).await;
    assert_eq!(stopped(&mut step.cx).await, Stop::Cancel);
    step.reply.send(StepResult::Finished).ok().unwrap();
    wait_terminal(&f, &id, "openmettle.run-succeeded", b"{}").await;
    w.shutdown.send(()).unwrap();
    bounded(w.task).await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn no_run_is_claimed_while_the_restore_gate_is_closed() {
    let f = Fixture::new().await;
    let id = f.admit("restore-gate").await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let (origin_us, lifecycle_origin_us): (i64, i64) = sqlx::query_as(
        "SELECT (extract(epoch FROM coverage_started_at) * 1000000)::bigint,
                (extract(epoch FROM lifecycle_coverage_started_at) * 1000000)::bigint
           FROM openmettle.deletion_journal_head WHERE id",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "SELECT openmettle.restore_gate_lock($1, 0, decode(repeat('00', 32), 'hex'), true, NULL, true, $2, decode(repeat('00', 32), 'hex'))",
    )
    .bind(origin_us)
    .bind(lifecycle_origin_us)
    .execute(&mut owner)
    .await
    .unwrap();
    let mut w = Worker::start(&f.db).await;
    // Fifteen claim polls (POLL_MS 100) pass without a claim while journal replay is pending.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(w.steps.try_recv().is_err());
    sqlx::query(
        "SELECT openmettle.restore_gate_open(
                    c.restore_run_id,
                    c.volume_claim_token,
                    $1,
                    0,
                    decode(repeat('00', 32), 'hex'),
                    (SELECT volume_id FROM openmettle.storage_volume_control WHERE id),
                    $2,
                    decode(repeat('00', 32), 'hex')
                )
           FROM openmettle.restore_claim_volume_phase($1, 0, decode(repeat('00', 32), 'hex'), $2, decode(repeat('00', 32), 'hex')) AS c",
    )
    .bind(origin_us)
    .bind(lifecycle_origin_us)
    .execute(&mut owner)
    .await
    .unwrap();
    let step = w.step().await;
    step.reply.send(StepResult::Finished).ok().unwrap();
    wait_terminal(&f, &id, "openmettle.run-succeeded", b"{}").await;
    w.shutdown.send(()).unwrap();
    bounded(w.task).await.unwrap();
}

/// P2 #11 regression: `claim_next` holds `restore_reconciliation_gate FOR SHARE` inside its own
/// transaction after acquiring `run_dispatch_lock`, so a claim waiting on `run_dispatch_lock`
/// returns `None` once `restore_gate_lock` closes the gate.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn claim_next_waiting_on_dispatch_lock_returns_none_after_gate_closes() {
    let f = Fixture::new().await;
    let _id = f.admit("gated-race").await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let (origin_us, lifecycle_origin_us): (i64, i64) = sqlx::query_as(
        "SELECT (extract(epoch FROM coverage_started_at) * 1000000)::bigint,
                (extract(epoch FROM lifecycle_coverage_started_at) * 1000000)::bigint
           FROM openmettle.deletion_journal_head WHERE id",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    // Hold run_dispatch_lock so `claim_next` enters its transaction and blocks before checking
    // the restore gate.
    let mut blocker = connect(&f.db.0, OWNER).await;
    let mut hold = blocker.begin().await.unwrap();
    let holder: i32 = sqlx::query_scalar(
        "SELECT pg_backend_pid() FROM openmettle.run_dispatch_lock FOR NO KEY UPDATE",
    )
    .fetch_one(&mut *hold)
    .await
    .unwrap();
    let claiming = tokio::spawn({
        let db = f.db.0.clone();
        async move {
            let mut w = connect(&db, WORKER).await;
            let limits = openmettle_core::authz::runs::ClaimLimits {
                executing_per_actor: 4,
                executing_per_scope: 4,
            };
            openmettle_core::authz::runs::claim_next(&mut w, &limits, &LEASES).await
        }
    });
    wait_for_blocked_peer(&f.db, holder).await;
    // Close the gate while `claim_next` is blocked on `run_dispatch_lock`, then release the lock.
    sqlx::query(
        "SELECT openmettle.restore_gate_lock($1, 0, decode(repeat('00', 32), 'hex'), true, NULL, true, $2, decode(repeat('00', 32), 'hex'))",
    )
    .bind(origin_us)
    .bind(lifecycle_origin_us)
    .execute(&mut owner)
    .await
    .unwrap();
    hold.rollback().await.unwrap();
    assert!(claiming.await.unwrap().unwrap().is_none());
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn shutdown_drain_settles_finished_and_failed_steps_once() {
    let f = Fixture::new().await;
    for (key, result, format, payload) in [
        (
            "finished",
            StepResult::Finished,
            "openmettle.run-succeeded",
            b"{}".as_slice(),
        ),
        (
            "failed",
            StepResult::Failed(FailReason::StepFailed),
            "openmettle.run-failed",
            br#"{"reason":"step_failed"}"#,
        ),
    ] {
        let id = f.admit(key).await;
        let mut w = Worker::start(&f.db).await;
        let mut step = w.step().await;
        w.shutdown.send(()).unwrap();
        assert_eq!(stopped(&mut step.cx).await, Stop::Shutdown);
        step.reply.send(result).ok().unwrap();
        bounded(w.task).await.unwrap();
        terminal(&f.db, &id, format, payload).await;
        assert!(
            reclaim_next(&mut worker(&f.db).await, &LEASES)
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn finished_with_an_unresolved_intent_falls_back_to_reconciliation() {
    let f = Fixture::new().await;
    let id = f.admit("unresolved-finish").await;
    let mut w = Worker::start(&f.db).await;
    let step = w.step().await;
    let op = intent(&mut worker(&f.db).await, &step.claim.lease(), "lookup")
        .await
        .unwrap();
    step.reply.send(StepResult::Finished).ok().unwrap();
    let lookup = w.lookup().await;
    assert_eq!(lookup.op, op);
    lookup.reply.send(None).ok().unwrap();
    wait_terminal(
        &f,
        &id,
        "openmettle.run-interrupted",
        br#"{"unresolved":1}"#,
    )
    .await;
    w.shutdown.send(()).unwrap();
    bounded(w.task).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn ignored_cancel_aborts_step_and_fences_blocking_child_then_reconciles_once() {
    let f = Fixture::new().await;
    let id = f.admit("ignored-stop").await;
    let mut w = Worker::start(&f.db).await;
    let mut step = w.step().await;
    let op = intent(
        &mut worker(&f.db).await,
        &step.claim.lease(),
        "non_repeatable",
    )
    .await
    .unwrap();
    let (release, blocked) = std::sync::mpsc::channel();
    let (started, ready) = oneshot::channel();
    let (attempt, result) = oneshot::channel();
    let claim = step.claim.clone();
    let pool = PgPool::connect(&f.db.url(WORKER)).await.unwrap();
    assert!(step.cx.tasks.spawn(async move {
        tokio::task::block_in_place(|| {
            started.send(()).unwrap();
            blocked.recv_timeout(Duration::from_secs(30)).unwrap();
            tokio::runtime::Handle::current().block_on(async {
                let refused =
                    intent(&mut pool.acquire().await.unwrap(), &claim.lease(), "lookup").await;
                attempt
                    .send(matches!(
                        refused,
                        Err(LeaseError::Terminal { .. } | LeaseError::StaleClaim)
                    ))
                    .unwrap();
            });
        });
    }));
    bounded(ready).await.unwrap();
    f.cancel(&step.claim).await;
    assert_eq!(stopped(&mut step.cx).await, Stop::Cancel);
    assert!(matches!(
        intent(&mut worker(&f.db).await, &step.claim.lease(), "lookup").await,
        Err(LeaseError::Stopping(_))
    ));
    let lookup = w.lookup().await;
    assert_eq!(lookup.op, op);
    assert!(step.reply.is_closed());
    assert!(!step.cx.tasks.spawn(async {}));
    lookup.reply.send(None).ok().unwrap();
    wait_terminal(
        &f,
        &id,
        "openmettle.run-interrupted",
        br#"{"unresolved":1}"#,
    )
    .await;
    release.send(()).unwrap();
    assert!(bounded(result).await.unwrap());
    assert!(w.steps.try_recv().is_err() && w.lookups.try_recv().is_err());
    w.shutdown.send(()).unwrap();
    bounded(w.task).await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn lost_renewal_sends_lease_lost_and_writes_nothing_more() {
    let f = Fixture::new().await;
    let id = f.admit("lost-renewal").await;
    let mut w = Worker::start(&f.db).await;
    let mut step = w.step().await;
    let history = events(&f.db, &id).await;
    owner_exec(
        &f.db,
        "UPDATE openmettle.runs SET claim_token = gen_random_uuid() WHERE id = $1::uuid",
        &id,
    )
    .await;
    let original = deadlines(&mut worker(&f.db).await, &id).await;
    assert_eq!(stopped(&mut step.cx).await, Stop::LeaseLost);
    step.reply.send(StepResult::Finished).ok().unwrap();
    w.shutdown.send(()).unwrap();
    bounded(w.task).await.unwrap();
    assert_eq!(history, events(&f.db, &id).await);
    assert_eq!(original, deadlines(&mut worker(&f.db).await, &id).await);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn shutdown_hands_over_immediately_and_crash_recovers_only_after_lapse() {
    let f = Fixture::new().await;
    let id = f.admit("handover").await;
    let mut a = Worker::start(&f.db).await;
    let mut step = a.step().await;
    a.shutdown.send(()).unwrap();
    assert_eq!(stopped(&mut step.cx).await, Stop::Shutdown);
    step.reply.send(StepResult::Continue).ok().unwrap();
    bounded(a.task).await.unwrap();
    let mut b = Worker::start(&f.db).await;
    let mut second = tokio::time::timeout(Duration::from_secs(3), b.step())
        .await
        .unwrap();
    assert_ne!(step.claim.claim_token, second.claim.claim_token);
    b.task.abort();
    assert!(b.task.await.unwrap_err().is_cancelled());
    bounded(second.reply.closed()).await;
    assert!(!second.cx.tasks.spawn(async {}));
    assert!(
        reclaim_next(&mut worker(&f.db).await, &LEASES)
            .await
            .unwrap()
            .is_none()
    );
    owner_exec(
        &f.db,
        "UPDATE openmettle.runs SET lease_expires_at = now() WHERE id = $1::uuid",
        &id,
    )
    .await;
    let mut c = Worker::start(&f.db).await;
    let last = c.step().await;
    assert_ne!(last.claim.claim_token, second.claim.claim_token);
    last.reply.send(StepResult::Finished).ok().unwrap();
    wait_terminal(&f, &id, "openmettle.run-succeeded", b"{}").await;
    c.shutdown.send(()).unwrap();
    bounded(c.task).await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn interrupted_reconciliation_is_released_and_evidence_recorded_by_new_holder() {
    let f = Fixture::new().await;
    let claim = f.claim("recover-intent").await;
    let op = intent(&mut worker(&f.db).await, &claim.lease(), "lookup")
        .await
        .unwrap();
    f.cancel(&claim).await;
    release_lease(&mut worker(&f.db).await, &claim.lease())
        .await
        .unwrap();
    let mut a = Worker::start(&f.db).await;
    let mut lookup = a.lookup().await;
    assert_eq!(lookup.op, op);
    a.shutdown.send(()).unwrap();
    assert_eq!(stopped(&mut lookup.cx).await, Stop::Shutdown);
    lookup.reply.send(None).ok().unwrap();
    bounded(a.task).await.unwrap();
    let mut b = Worker::start(&f.db).await;
    let lookup = tokio::time::timeout(Duration::from_secs(3), b.lookup())
        .await
        .unwrap();
    assert_eq!(lookup.op, op);
    lookup
        .reply
        .send(Some(OwnedObservation {
            key: "verified".into(),
            outcome: "succeeded".into(),
            handle: None,
            format: EVIDENCE.format.into(),
            version: 1,
            evidence: b"{}".into(),
        }))
        .ok()
        .unwrap();
    wait_terminal(
        &f,
        &claim.run_id,
        "openmettle.run-cancelled",
        br#"{"reason":"requested"}"#,
    )
    .await;
    assert!(b.steps.try_recv().is_err());
    b.shutdown.send(()).unwrap();
    bounded(b.task).await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn execution_deadline_drains_the_final_step() {
    let f = Fixture::new().await;
    let mut w = Worker::start(&f.db).await;
    for (key, result, format, payload) in [
        (
            "deadline-continue",
            StepResult::Continue,
            "openmettle.run-failed",
            br#"{"reason":"deadline_exceeded"}"#.as_slice(),
        ),
        (
            "deadline-finish",
            StepResult::Finished,
            "openmettle.run-succeeded",
            b"{}",
        ),
    ] {
        let id = f.admit(key).await;
        let mut step = w.step().await;
        // Renewal reads the shortened execution allowance from the primary. Its local
        // stop point leaves a full settlement margin before the durable deadline.
        owner_exec(
            &f.db,
            "UPDATE openmettle.runs SET lease_expires_at = now() + interval '22 seconds',
        execution_expires_at = now() + interval '22 seconds' WHERE id = $1::uuid",
            &id,
        )
        .await;
        assert_eq!(stopped(&mut step.cx).await, Stop::Deadline);
        step.reply.send(result).ok().unwrap();
        wait_terminal(&f, &id, format, payload).await;
        assert!(w.steps.try_recv().is_err());
    }
    w.shutdown.send(()).unwrap();
    bounded(w.task).await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn rechecks_authority_before_the_next_step_and_first_dispatch() {
    let f = Fixture::new().await;
    let first = f.admit("revoked-after-step").await;
    let mut w = Worker::start(&f.db).await;
    let step = w.step().await;
    let op = intent(&mut worker(&f.db).await, &step.claim.lease(), "lookup")
        .await
        .unwrap();
    let second = f.admit("revoked-before-dispatch").await;
    sqlx::query(
        "UPDATE openmettle.local_identity_approvals SET active = false WHERE id = $1::uuid",
    )
    .bind(&f.actor.approval)
    .execute(&mut connect(&f.db.0, OWNER).await)
    .await
    .unwrap();
    step.reply.send(StepResult::Continue).ok().unwrap();
    // The denied recheck moved the run to reconciling. The next holder can observe the
    // outstanding operation as soon as the invalidated holder finishes draining.
    let lookup = tokio::time::timeout(Duration::from_secs(5), w.lookup())
        .await
        .unwrap();
    assert_eq!(lookup.op, op);
    lookup
        .reply
        .send(Some(OwnedObservation {
            key: "revocation-lookup".into(),
            outcome: "succeeded".into(),
            handle: None,
            format: EVIDENCE.format.into(),
            version: 1,
            evidence: b"{}".into(),
        }))
        .ok()
        .unwrap();
    for id in [&first, &second] {
        wait_terminal(
            &f,
            id,
            "openmettle.run-cancelled",
            br#"{"reason":"revoked"}"#,
        )
        .await;
    }
    assert!(w.steps.try_recv().is_err());
    w.shutdown.send(()).unwrap();
    bounded(w.task).await.unwrap();
}
