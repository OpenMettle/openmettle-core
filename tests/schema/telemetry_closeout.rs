//! Stage 1 Telemetry Closeout (`#10` `V1-10` & `#26` `V1-29`) PostgreSQL 18.1 evidence:
//! - Post-commit recording of `openmettle.runs.queue.age` across all queue-exit transitions
//!   (`claimed`, `resumed`, `cancelled`, `expired`), non-emission for non-queue cancellations
//!   (`running`, undecided `waiting`, `HumanDecision::Deny`), and non-emission on rolled-back
//!   transactions (deferred constraint failure at `COMMIT`).
//! - End-to-end `/v1/runs*` HTTP correlation (`request_id`, `run_id`) and canary redaction
//!   through the real `openmettle-api` binary over PostgreSQL 18.1.
use super::{
    approvals::{LIMITS as APPROVAL_LIMITS, Policy as ApprovalPolicy, proposal},
    authz_http::{Api, As, browser},
    authz_runs::{chat, personal_of, seeded_session},
    authz_store::{
        Account, FUTURE, NOW, PROVIDER, account, applied, ctx, make_admin, principal, providers,
        wait_for_lock_waiters,
    },
    run_admission::{
        LEASES, OPEN, admitted, api, new_project, owner_exec, request, seed_token_budget, worker,
    },
    *,
};
use openmettle_core::{
    authz::{
        Grantee, ProjectRole,
        approvals::{self, DecisionInput, EffectSession, HumanDecision},
        leases::{self, Handoff, Lease, LeaseError, Settled},
        projects,
        runs::{
            self as queue, Admission, CancelOutcome, ClaimedRun, RunAdmission, RunRecheckOutcome,
            RunRecheckRequest,
        },
        store,
    },
    runs::{RunInput, WriteTransaction},
    sessions,
    telemetry::metrics::{self, RunQueueAgeOutcome},
    worker::StepTasks,
};
use serde_json::{Value, json};
use std::fs;

async fn effect_session(db: &TestDb, actor: &Account, n: u8) -> EffectSession {
    let token = seeded_session(db, actor, n, None).await;
    let policy =
        sessions::Policy::new(Duration::from_secs(60), 10, Duration::from_secs(3)).unwrap();
    EffectSession::validate(&mut api(db).await, &token, &policy, None)
        .await
        .unwrap()
}

async fn admit_approval_run(
    db: &TestDb,
    scope: &str,
    scope_kind: &str,
    actor: &Account,
    session: &EffectSession,
    key: &str,
) -> ClaimedRun {
    let conv = chat(db, scope, scope_kind, actor).await;
    let mut owner = connect(&db.0, OWNER).await;
    let branch: String = sqlx::query_scalar(
        "INSERT INTO openmettle.conversation_branches (scope_id, conversation_id)
         VALUES ($1::uuid, $2::uuid) RETURNING id::text",
    )
    .bind(scope)
    .bind(&conv)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let msg = message(&mut owner, scope, &conv, None).await.unwrap();
    let mut c = api(db).await;
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    let config = json!({"execution_mode": "ordinary"}).to_string();
    let req = RunAdmission {
        input: RunInput {
            scope,
            actor: &actor.user,
            conversation: &conv,
            branch: &branch,
            message: &msg,
            key,
            format: "synthetic.run",
            version: 1,
            input: b"message",
            config: config.as_bytes(),
        },
        actor_approval_id: &actor.approval,
        capabilities: &[],
        requested_rounds: None,
        now_ms: session.context().observed_ms(),
        cost_qualified: None,
    };
    let outcome = queue::admit_run_with_mode(&mut tx, &req, &APPROVAL_LIMITS, session)
        .await
        .unwrap();
    assert!(matches!(outcome, Admission::Admitted { .. }));
    tx.commit().await.unwrap();
    queue::claim_next(&mut worker(db).await, &OPEN, &LEASES)
        .await
        .unwrap()
        .unwrap()
}

fn queue_age_counts() -> [u64; 4] {
    let store = metrics::global();
    [
        store.run_queue_age_snapshot(RunQueueAgeOutcome::Claimed).0,
        store.run_queue_age_snapshot(RunQueueAgeOutcome::Resumed).0,
        store
            .run_queue_age_snapshot(RunQueueAgeOutcome::Cancelled)
            .0,
        store.run_queue_age_snapshot(RunQueueAgeOutcome::Expired).0,
    ]
}

fn queue_age_delta(before: [u64; 4]) -> [u64; 4] {
    let after = queue_age_counts();
    [
        after[0] - before[0],
        after[1] - before[1],
        after[2] - before[2],
        after[3] - before[3],
    ]
}

async fn backdate_approved_wait(owner: &mut PgConnection, run_id: &str, approval_id: &str) {
    sqlx::query(
        "UPDATE openmettle.runs
            SET created_at = clock_timestamp() - interval '120 seconds'
          WHERE id = $1::uuid",
    )
    .bind(run_id)
    .execute(&mut *owner)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.run_approval_decisions
            SET decided_at = clock_timestamp() - interval '2 seconds'
          WHERE approval_id = $1::uuid",
    )
    .bind(approval_id)
    .execute(&mut *owner)
    .await
    .unwrap();
}

fn assert_decided_age_delta(outcome: RunQueueAgeOutcome, before: (u64, f64, Vec<u64>)) {
    let after = metrics::global().run_queue_age_snapshot(outcome);
    assert_eq!(after.0 - before.0, 1, "expected +1 count for {outcome:?}");
    let sum_delta = after.1 - before.1;
    assert!(
        (1.0..15.0).contains(&sum_delta),
        "expected {outcome:?} age measured from decided_at (~2s, not created_at 120s), got sum_delta={sum_delta}"
    );
    let le_15_idx = metrics::QUEUE_AGE_BUCKETS
        .iter()
        .position(|&b| b == 15.0)
        .expect("15.0s bucket present in QUEUE_AGE_BUCKETS");
    let le_15_delta: u64 = (0..=le_15_idx).map(|i| after.2[i] - before.2[i]).sum();
    let gt_15_delta: u64 = ((le_15_idx + 1)..after.2.len())
        .map(|i| after.2[i] - before.2[i])
        .sum();
    assert_eq!(
        le_15_delta, 1,
        "expected +1 in <=15s buckets for {outcome:?}"
    );
    assert_eq!(gt_15_delta, 0, "expected 0 in >15s buckets for {outcome:?}");
}

async fn install_deferred_commit_failure_trigger(
    owner: &mut PgConnection,
    fn_name: &str,
    trigger_name: &str,
    target_state: &str,
) {
    for sql in [
        format!(
            "CREATE FUNCTION openmettle.{fn_name}() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN
                 RAISE EXCEPTION 'synthetic commit failure';
             END;
             $$"
        ),
        format!(
            "CREATE CONSTRAINT TRIGGER {trigger_name}
                 AFTER UPDATE ON openmettle.runs
                 DEFERRABLE INITIALLY DEFERRED
                 FOR EACH ROW
                 WHEN (NEW.state = '{target_state}')
                 EXECUTE FUNCTION openmettle.{fn_name}()"
        ),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(&mut *owner)
            .await
            .unwrap();
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn run_queue_age_records_post_commit_across_all_queue_exit_paths_and_excludes_non_queue_cancellations()
 {
    // Hold the exclusive fixture lock so no parallel schema test mutates global queue-age metrics.
    let db = TestDb::migrated_exclusive().await;
    seed_token_budget(&db).await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let alice_scope = personal_of(&db, &alice).await;
    let bob_scope = personal_of(&db, &bob).await;
    let alice_principal = principal(&db, &alice).await;
    let alice_session = effect_session(&db, &alice, 1).await;
    let policy = ApprovalPolicy::default();

    // 1. Claiming a freshly queued run increments `claimed` by 1.
    let before = queue_age_counts();
    let sum_before = metrics::global()
        .run_queue_age_snapshot(RunQueueAgeOutcome::Claimed)
        .1;
    let claimed = admit_approval_run(
        &db,
        &alice_scope,
        "personal",
        &alice,
        &alice_session,
        "qa-claim",
    )
    .await;
    assert_eq!(queue_age_delta(before), [1, 0, 0, 0]);
    assert!(
        metrics::global()
            .run_queue_age_snapshot(RunQueueAgeOutcome::Claimed)
            .1
            >= sum_before
    );

    // 2. Parking for human approval, approving, and re-claiming increments `resumed` by 1,
    // measured from `run_approval_decisions.decided_at` (~2s), NOT `runs.created_at` (120s).
    let parked = approvals::park(
        &mut worker(&db).await,
        &claimed.lease(),
        &StepTasks::default().handle(),
        &proposal("qa-resume"),
        &policy,
        &LEASES,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    let before_approve = queue_age_counts();
    approvals::decide(
        &mut api(&db).await,
        &alice_session,
        &DecisionInput {
            scope: &alice_scope,
            run: &claimed.run_id,
            approval: &parked.approval_id,
            decision: HumanDecision::Approve,
            binding_digest: &parked.binding_digest,
            idempotency_key: "qa-approve",
        },
        &policy,
    )
    .await
    .unwrap();
    // Approving does not exit the queue; claiming the resumable waiting run does.
    assert_eq!(queue_age_delta(before_approve), [0, 0, 0, 0]);
    backdate_approved_wait(&mut owner, &claimed.run_id, &parked.approval_id).await;
    let before_resume_snap = metrics::global().run_queue_age_snapshot(RunQueueAgeOutcome::Resumed);
    let before_resume_slow =
        metrics::global().run_queue_slow_exits_count(RunQueueAgeOutcome::Resumed);
    let resumed = queue::claim_next(&mut worker(&db).await, &OPEN, &LEASES)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resumed.run_id, claimed.run_id);
    assert_eq!(queue_age_delta(before_approve), [0, 1, 0, 0]);
    assert_decided_age_delta(RunQueueAgeOutcome::Resumed, before_resume_snap);
    assert_eq!(
        metrics::global().run_queue_slow_exits_count(RunQueueAgeOutcome::Resumed)
            - before_resume_slow,
        0,
        "resumed wait measured from decided_at (~2s) must not increment slow_exits"
    );

    // 3. Negative: cancelling an actively `running` run must NOT emit `cancelled` queue age.
    let before_running_cancel = queue_age_counts();
    let running_cancel = queue::cancel_run(
        &mut api(&db).await,
        &alice_principal,
        &alice_scope,
        &resumed.run_id,
    )
    .await
    .unwrap();
    assert_eq!(
        running_cancel,
        CancelOutcome::Requested {
            state: "cancelling".to_owned()
        }
    );
    assert_eq!(queue_age_delta(before_running_cancel), [0, 0, 0, 0]);

    // 4. Expiring a queued run with >60s wait increments both `expired` queue age and `slow_exits` (+1).
    let exp_req = request(&db, &alice_scope, "personal", &alice, "qa-expire").await;
    let exp_id = admitted(&db, &exp_req).await;
    owner_exec(
        &db,
        "UPDATE openmettle.runs
            SET created_at = clock_timestamp() - interval '75 seconds',
                queue_expires_at = clock_timestamp() - interval '1 second'
          WHERE id = $1::uuid",
        &exp_id,
    )
    .await;
    let before_expire = queue_age_counts();
    let before_expire_slow =
        metrics::global().run_queue_slow_exits_count(RunQueueAgeOutcome::Expired);
    let expired = queue::expire_queued(&mut worker(&db).await, 10)
        .await
        .unwrap();
    assert_eq!(expired, vec![exp_id]);
    assert_eq!(queue_age_delta(before_expire), [0, 0, 0, 1]);
    assert_eq!(
        metrics::global().run_queue_slow_exits_count(RunQueueAgeOutcome::Expired)
            - before_expire_slow,
        1
    );

    // 5. Caller `cancel_run` on a `queued` run increments `cancelled` by 1.
    let q_cancel_req = request(&db, &alice_scope, "personal", &alice, "qa-cancel-queued").await;
    let q_cancel_id = admitted(&db, &q_cancel_req).await;
    let before_q_cancel = queue_age_counts();
    assert_eq!(
        queue::cancel_run(
            &mut api(&db).await,
            &alice_principal,
            &alice_scope,
            &q_cancel_id,
        )
        .await
        .unwrap(),
        CancelOutcome::Cancelled
    );
    assert_eq!(queue_age_delta(before_q_cancel), [0, 0, 1, 0]);

    // 6. Negative: caller `cancel_run` on an UNDECIDED `waiting` run (blocked on human)
    // must NOT emit `cancelled` queue age.
    let wait_claim = admit_approval_run(
        &db,
        &alice_scope,
        "personal",
        &alice,
        &alice_session,
        "qa-wait-undecided",
    )
    .await;
    let _undecided_parked = approvals::park(
        &mut worker(&db).await,
        &wait_claim.lease(),
        &StepTasks::default().handle(),
        &proposal("qa-undecided"),
        &policy,
        &LEASES,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    let before_undecided = queue_age_counts();
    assert_eq!(
        queue::cancel_run(
            &mut api(&db).await,
            &alice_principal,
            &alice_scope,
            &wait_claim.run_id,
        )
        .await
        .unwrap(),
        CancelOutcome::Cancelled
    );
    assert_eq!(queue_age_delta(before_undecided), [0, 0, 0, 0]);

    // 7. Negative: `approvals::decide(HumanDecision::Deny)` cancels an undecided wait and
    // must NOT emit `cancelled` queue age.
    let deny_claim = admit_approval_run(
        &db,
        &alice_scope,
        "personal",
        &alice,
        &alice_session,
        "qa-wait-deny",
    )
    .await;
    let deny_parked = approvals::park(
        &mut worker(&db).await,
        &deny_claim.lease(),
        &StepTasks::default().handle(),
        &proposal("qa-deny"),
        &policy,
        &LEASES,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    let before_deny = queue_age_counts();
    approvals::decide(
        &mut api(&db).await,
        &alice_session,
        &DecisionInput {
            scope: &alice_scope,
            run: &deny_claim.run_id,
            approval: &deny_parked.approval_id,
            decision: HumanDecision::Deny,
            binding_digest: &deny_parked.binding_digest,
            idempotency_key: "qa-deny-decision",
        },
        &policy,
    )
    .await
    .unwrap();
    assert_eq!(queue_age_delta(before_deny), [0, 0, 0, 0]);

    // 8. Positive: caller `cancel_run` on an APPROVED (resumable) `waiting` run DOES emit
    // `cancelled` queue age (+1), measured from `decided_at` (~2s), NOT `runs.created_at` (120s).
    let approved_cancel_claim = admit_approval_run(
        &db,
        &alice_scope,
        "personal",
        &alice,
        &alice_session,
        "qa-wait-approved-cancel",
    )
    .await;
    let approved_parked = approvals::park(
        &mut worker(&db).await,
        &approved_cancel_claim.lease(),
        &StepTasks::default().handle(),
        &proposal("qa-approved-cancel"),
        &policy,
        &LEASES,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    approvals::decide(
        &mut api(&db).await,
        &alice_session,
        &DecisionInput {
            scope: &alice_scope,
            run: &approved_cancel_claim.run_id,
            approval: &approved_parked.approval_id,
            decision: HumanDecision::Approve,
            binding_digest: &approved_parked.binding_digest,
            idempotency_key: "qa-approve-then-cancel",
        },
        &policy,
    )
    .await
    .unwrap();
    backdate_approved_wait(
        &mut owner,
        &approved_cancel_claim.run_id,
        &approved_parked.approval_id,
    )
    .await;
    let before_resumable_cancel = queue_age_counts();
    let before_resumable_snap =
        metrics::global().run_queue_age_snapshot(RunQueueAgeOutcome::Cancelled);
    assert_eq!(
        queue::cancel_run(
            &mut api(&db).await,
            &alice_principal,
            &alice_scope,
            &approved_cancel_claim.run_id,
        )
        .await
        .unwrap(),
        CancelOutcome::Cancelled
    );
    assert_eq!(queue_age_delta(before_resumable_cancel), [0, 0, 1, 0]);
    assert_decided_age_delta(RunQueueAgeOutcome::Cancelled, before_resumable_snap);

    // 9. `recheck_run` policy revocation while `queued` emits `cancelled` (+1).
    let (proj_recheck, proj_recheck_scope) = new_project(&db, &alice, "qa-proj-recheck").await;
    applied(
        projects::set_project_member_role(
            &mut api(&db).await,
            &ctx(&alice, "qa-bob-editor"),
            &proj_recheck,
            &Grantee::User(bob.user.clone()),
            ProjectRole::Editor,
        )
        .await,
    );
    let bob_proj_req = request(&db, &proj_recheck_scope, "project", &bob, "qa-recheck").await;
    let bob_proj_run = admitted(&db, &bob_proj_req).await;
    // Demote Bob to Viewer so `recheck_run` revokes his queued run.
    applied(
        projects::set_project_member_role(
            &mut api(&db).await,
            &ctx(&alice, "qa-bob-viewer"),
            &proj_recheck,
            &Grantee::User(bob.user.clone()),
            ProjectRole::Viewer,
        )
        .await,
    );
    let before_recheck = queue_age_counts();
    let recheck_outcome = queue::recheck_run(
        &mut worker(&db).await,
        &RunRecheckRequest {
            scope_id: &proj_recheck_scope,
            run_id: &bob_proj_run,
            actor_approval_id: &bob.approval,
            capabilities: &[],
            extra_target: None,
            now_ms: NOW,
        },
    )
    .await
    .unwrap();
    assert!(matches!(recheck_outcome, RunRecheckOutcome::Invalidated(_)));
    assert_eq!(queue_age_delta(before_recheck), [0, 0, 1, 0]);

    // 10. `archive_project` cancels 2 queued runs in the scope -> `cancelled` (+2).
    let (proj_arch, proj_arch_scope) = new_project(&db, &alice, "qa-proj-arch").await;
    let arch_r1 = request(&db, &proj_arch_scope, "project", &alice, "qa-arch-1").await;
    let arch_r2 = request(&db, &proj_arch_scope, "project", &alice, "qa-arch-2").await;
    let _ = admitted(&db, &arch_r1).await;
    let _ = admitted(&db, &arch_r2).await;
    let before_arch = queue_age_counts();
    applied(
        projects::archive_project(
            &mut api(&db).await,
            &ctx(&alice, "qa-archive-exec"),
            &proj_arch,
        )
        .await,
    );
    assert_eq!(queue_age_delta(before_arch), [0, 0, 2, 0]);

    // 11. `disable_user` cancels 1 queued run for Bob -> `cancelled` (+1).
    let bob_personal_req = request(&db, &bob_scope, "personal", &bob, "qa-disable").await;
    let _ = admitted(&db, &bob_personal_req).await;
    let before_disable = queue_age_counts();
    applied(
        store::disable_user(
            &mut api(&db).await,
            &ctx(&admin, "qa-disable-bob"),
            &bob.user,
        )
        .await,
    );
    assert_eq!(queue_age_delta(before_disable), [0, 0, 1, 0]);

    // 12. Rollback boundary: a deferred constraint trigger fails `COMMIT` *after* `CANCEL_ONE`
    // has already returned a `queue_age_s` (>60s) row to Rust. Neither queue age nor slow_exits
    // may be recorded!
    let rb_req = request(&db, &alice_scope, "personal", &alice, "qa-rollback").await;
    let rb_id = admitted(&db, &rb_req).await;
    owner_exec(
        &db,
        "UPDATE openmettle.runs
            SET created_at = clock_timestamp() - interval '75 seconds'
          WHERE id = $1::uuid",
        &rb_id,
    )
    .await;
    install_deferred_commit_failure_trigger(
        &mut owner,
        "fail_cancel_commit_for_test",
        "fail_cancel_commit_test",
        "cancelled",
    )
    .await;
    let before_rollback = queue_age_counts();
    let before_rollback_slow =
        metrics::global().run_queue_slow_exits_count(RunQueueAgeOutcome::Cancelled);
    let rb_err =
        queue::cancel_run(&mut api(&db).await, &alice_principal, &alice_scope, &rb_id).await;
    assert!(
        rb_err.is_err(),
        "expected deferred trigger to fail COMMIT, got {rb_err:?}"
    );
    assert_eq!(queue_age_delta(before_rollback), [0, 0, 0, 0]);
    assert_eq!(
        metrics::global().run_queue_slow_exits_count(RunQueueAgeOutcome::Cancelled)
            - before_rollback_slow,
        0
    );
    let state_after: String =
        sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
            .bind(&rb_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(state_after, "queued");
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn bulk_cancel_racing_decide_records_approved_wait_queue_age_from_decided_at() {
    let db = TestDb::migrated_exclusive().await;
    seed_token_budget(&db).await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let alice_session = effect_session(&db, &alice, 1).await;
    let policy = ApprovalPolicy::default();
    let (proj, proj_scope) = new_project(&db, &alice, "qa-race-proj").await;

    let claimed = admit_approval_run(
        &db,
        &proj_scope,
        "project",
        &alice,
        &alice_session,
        "qa-race-run",
    )
    .await;
    let parked = approvals::park(
        &mut worker(&db).await,
        &claimed.lease(),
        &StepTasks::default().handle(),
        &proposal("qa-race-approval"),
        &policy,
        &LEASES,
        Duration::from_secs(60),
    )
    .await
    .unwrap();

    // Hold the run row lock in Tx A while inserting an `approve` decision (simulating a
    // concurrent `approvals::decide` about to commit), with `created_at` 120s old and
    // `decided_at` 2s old.
    let mut tx_a = owner.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.runs WHERE id = $1::uuid FOR NO KEY UPDATE")
        .bind(&claimed.run_id)
        .execute(&mut *tx_a)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE openmettle.runs
            SET created_at = clock_timestamp() - interval '120 seconds'
          WHERE id = $1::uuid",
    )
    .bind(&claimed.run_id)
    .execute(&mut *tx_a)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.run_approval_decisions
             (approval_id, scope_id, run_id, actor_user_id, deciding_session_id,
              binding_digest, decision, request_key, decided_at)
         SELECT id, scope_id, run_id, actor_user_id, repeat('a', 43),
                binding_digest, 'approve', 'qa-race-decision',
                clock_timestamp() - interval '2 seconds'
           FROM openmettle.run_approvals
          WHERE id = $1::uuid",
    )
    .bind(&parked.approval_id)
    .execute(&mut *tx_a)
    .await
    .unwrap();

    let before_counts = queue_age_counts();
    let before_snap = metrics::global().run_queue_age_snapshot(RunQueueAgeOutcome::Cancelled);

    // Tx B (`archive_project` -> `cancel_scope_runs`) must wait on the run row lock in
    // `LOCK_SCOPE_RUNS`, then read `run_approval_decisions` in a fresh `READ COMMITTED`
    // snapshot after Tx A commits.
    let mut archive_conn = api(&db).await;
    let alice_ctx_user = alice.clone();
    let proj_id = proj.clone();
    let archive_task = tokio::spawn(async move {
        projects::archive_project(
            &mut archive_conn,
            &ctx(&alice_ctx_user, "qa-race-archive"),
            &proj_id,
        )
        .await
    });

    wait_for_lock_waiters(&db, 1).await;
    tx_a.commit().await.unwrap();
    applied(archive_task.await.unwrap());

    assert_eq!(queue_age_delta(before_counts), [0, 0, 1, 0]);
    assert_decided_age_delta(RunQueueAgeOutcome::Cancelled, before_snap);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn expire_waits_records_expired_queue_age_only_for_approved_waits() {
    let db = TestDb::migrated_exclusive().await;
    seed_token_budget(&db).await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let alice_scope = personal_of(&db, &alice).await;
    let alice_session = effect_session(&db, &alice, 1).await;
    let policy = ApprovalPolicy::default();

    // 1. Undecided wait (blocked on human): must NOT record `expired` queue age.
    let undecided = admit_approval_run(
        &db,
        &alice_scope,
        "personal",
        &alice,
        &alice_session,
        "qa-exp-undecided",
    )
    .await;
    let undecided_parked = approvals::park(
        &mut worker(&db).await,
        &undecided.lease(),
        &StepTasks::default().handle(),
        &proposal("qa-exp-u"),
        &policy,
        &LEASES,
        Duration::from_secs(60),
    )
    .await
    .unwrap();

    // 2. Approved wait (resumable in the worker queue): MUST record `expired` queue age
    // measured from `decided_at` (~2s), NOT `runs.created_at` (120s).
    let approved = admit_approval_run(
        &db,
        &alice_scope,
        "personal",
        &alice,
        &alice_session,
        "qa-exp-approved",
    )
    .await;
    let approved_parked = approvals::park(
        &mut worker(&db).await,
        &approved.lease(),
        &StepTasks::default().handle(),
        &proposal("qa-exp-a"),
        &policy,
        &LEASES,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    approvals::decide(
        &mut api(&db).await,
        &alice_session,
        &DecisionInput {
            scope: &alice_scope,
            run: &approved.run_id,
            approval: &approved_parked.approval_id,
            decision: HumanDecision::Approve,
            binding_digest: &approved_parked.binding_digest,
            idempotency_key: "qa-exp-approve",
        },
        &policy,
    )
    .await
    .unwrap();
    backdate_approved_wait(&mut owner, &approved.run_id, &approved_parked.approval_id).await;

    sqlx::query(
        "UPDATE openmettle.run_approvals
            SET approval_expires_at = clock_timestamp() - interval '1 second'
          WHERE id IN ($1::uuid, $2::uuid)",
    )
    .bind(&undecided_parked.approval_id)
    .bind(&approved_parked.approval_id)
    .execute(&mut owner)
    .await
    .unwrap();

    let before_counts = queue_age_counts();
    let before_snap = metrics::global().run_queue_age_snapshot(RunQueueAgeOutcome::Expired);
    let expired = approvals::expire_waits(&mut worker(&db).await, 10)
        .await
        .unwrap();
    assert_eq!(expired.len(), 2);
    assert!(expired.contains(&undecided.run_id));
    assert!(expired.contains(&approved.run_id));
    assert_eq!(queue_age_delta(before_counts), [0, 0, 0, 1]);
    assert_decided_age_delta(RunQueueAgeOutcome::Expired, before_snap);

    // 3. Rollback safety: deferred commit failure must record zero `expired` queue age.
    let rb = admit_approval_run(
        &db,
        &alice_scope,
        "personal",
        &alice,
        &alice_session,
        "qa-exp-rollback",
    )
    .await;
    let rb_parked = approvals::park(
        &mut worker(&db).await,
        &rb.lease(),
        &StepTasks::default().handle(),
        &proposal("qa-exp-rb"),
        &policy,
        &LEASES,
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    approvals::decide(
        &mut api(&db).await,
        &alice_session,
        &DecisionInput {
            scope: &alice_scope,
            run: &rb.run_id,
            approval: &rb_parked.approval_id,
            decision: HumanDecision::Approve,
            binding_digest: &rb_parked.binding_digest,
            idempotency_key: "qa-exp-rb-approve",
        },
        &policy,
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.run_approvals
            SET approval_expires_at = clock_timestamp() - interval '1 second'
          WHERE id = $1::uuid",
    )
    .bind(&rb_parked.approval_id)
    .execute(&mut owner)
    .await
    .unwrap();
    install_deferred_commit_failure_trigger(
        &mut owner,
        "fail_expire_wait_commit_for_test",
        "fail_expire_wait_commit_test",
        "failed",
    )
    .await;
    let before_rb = queue_age_counts();
    let rb_err = approvals::expire_waits(&mut worker(&db).await, 10).await;
    assert!(
        rb_err.is_err(),
        "expected deferred trigger to fail expire_waits COMMIT, got {rb_err:?}"
    );
    assert_eq!(queue_age_delta(before_rb), [0, 0, 0, 0]);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn leases_handoff_reports_committed_disposition_on_stale_fence_and_cancelled_run() {
    let db = TestDb::migrated().await;
    seed_token_budget(&db).await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let alice_scope = personal_of(&db, &alice).await;
    let alice_principal = principal(&db, &alice).await;

    // 1. Clean shutdown handoff on an active run releases the claim (`Handoff::Released`).
    let req_a = request(&db, &alice_scope, "personal", &alice, "qa-handoff-a").await;
    let _id_a = admitted(&db, &req_a).await;
    let claim_a = queue::claim_next(&mut worker(&db).await, &OPEN, &LEASES)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        leases::handoff(&mut worker(&db).await, &claim_a.lease(), &LEASES)
            .await
            .unwrap(),
        Handoff::Released
    );

    // 2. Re-claim and request cancellation: `handoff` settles to terminal `cancelled`.
    let reclaimed_a = leases::reclaim_next(&mut worker(&db).await, &LEASES)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reclaimed_a.run.run_id, claim_a.run_id);
    assert_eq!(
        queue::cancel_run(
            &mut api(&db).await,
            &alice_principal,
            &alice_scope,
            &reclaimed_a.run.run_id,
        )
        .await
        .unwrap(),
        CancelOutcome::Requested {
            state: "cancelling".to_owned()
        }
    );
    assert_eq!(
        leases::handoff(&mut worker(&db).await, &reclaimed_a.run.lease(), &LEASES)
            .await
            .unwrap(),
        Handoff::Settled(Settled::Terminal { state: "cancelled" })
    );

    // 3. Calling `handoff` again on the already-terminal run reports `LeaseError::Terminal`.
    let terminal_err = leases::handoff(&mut worker(&db).await, &reclaimed_a.run.lease(), &LEASES)
        .await
        .unwrap_err();
    assert!(
        matches!(terminal_err, LeaseError::Terminal { ref state } if state == "cancelled"),
        "expected LeaseError::Terminal(cancelled), got {terminal_err:?}"
    );

    // 4. Calling `handoff` with a stale claim token reports `LeaseError::StaleClaim`.
    let req_b = request(&db, &alice_scope, "personal", &alice, "qa-handoff-b").await;
    let _id_b = admitted(&db, &req_b).await;
    let claim_b = queue::claim_next(&mut worker(&db).await, &OPEN, &LEASES)
        .await
        .unwrap()
        .unwrap();
    let stale_lease = Lease {
        scope_id: &claim_b.scope_id,
        run_id: &claim_b.run_id,
        claim_token: "00000000-0000-4000-8000-00000000cafe",
    };
    let stale_err = leases::handoff(&mut worker(&db).await, &stale_lease, &LEASES)
        .await
        .unwrap_err();
    assert!(
        matches!(stale_err, LeaseError::StaleClaim),
        "expected LeaseError::StaleClaim, got {stale_err:?}"
    );
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn api_runs_endpoints_correlate_request_and_run_id_and_redact_invalid_path_canaries() {
    let db = TestDb::migrated().await;
    seed_token_budget(&db).await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let alice_cookie = browser(&db, &alice, 1).await;
    let alice_b = As::Browser(&alice_cookie);

    let dir = auth_config_support::Dir::new();
    fs::create_dir(dir.path("artifacts")).unwrap();
    let mut doc = auth_config_support::document_v2_native(&dir, &ca::Ca::new().pem());
    doc["cursor_keys"] = auth_config_support::cursor_keys(&dir);
    let mut catalog: Value =
        serde_json::from_slice(include_bytes!("../fixtures/conversation-catalog-v1.json")).unwrap();
    let prompt_bound = json!({
        "fixed_tokens": 4,
        "tokens_per_turn": 4,
        "tokens_per_part": 2,
        "tokens_per_byte": 1,
        "tokens_per_attachment": 10
    });
    catalog["models"]["a"]["prompt_bound"] = prompt_bound;
    catalog["models"]["a"]["cost_bound"] = json!({
        "fixed_micros": 0,
        "micros_per_token": 1
    });
    doc["catalog_file"] = json!(dir.write("catalog.json", &serde_json::to_vec(&catalog).unwrap()));
    doc["admission_limits"] = json!({
        "live_per_actor": 4,
        "live_per_scope": 8,
        "queued_in_instance": 32,
        "queue_timeout_seconds": 300,
        "round_cap": 10
    });
    let (api, log_path) = Api::configured_logged(&db, dir, doc, 4);

    // 1. Create a conversation and admit a run via `POST /v1/runs`.
    let (status, conv) = api.call(
        alice_b,
        "POST",
        "/v1/conversations",
        Some("tel-conv-1"),
        Some(&json!({})),
    );
    assert_eq!(status, 201, "{conv}");
    let conv_id = conv["conversation_id"].as_str().unwrap();
    let branch_id = conv["branch_id"].as_str().unwrap();

    let (status, created) = api.call(
        alice_b,
        "POST",
        "/v1/runs",
        Some("tel-run-1"),
        Some(&json!({
            "conversation_id": conv_id,
            "branch_id": branch_id,
            "proposal": {
                "expected_head_message_id": null,
                "turn": {
                    "mode": "append",
                    "input_message_id": "00000000-0000-4000-8000-00000000b001",
                    "parts": [{"text": "hello telemetry"}]
                },
                "selection": {"preset": "study"},
                "requested_rounds": 2
            }
        })),
    );
    assert_eq!(status, 201, "{created}");
    let run_id = created["run_id"].as_str().unwrap().to_owned();

    // 2. Authenticated `GET /v1/runs/{run_id}` and `GET /v1/runs/{run_id}/approvals`.
    let (status, _) = api.call(alice_b, "GET", &format!("/v1/runs/{run_id}"), None, None);
    assert_eq!(status, 200);
    let (status, _) = api.call(
        alice_b,
        "GET",
        &format!("/v1/runs/{run_id}/approvals"),
        None,
        None,
    );
    assert_eq!(status, 200);

    // 3. Invalid-UUID path canary (400) must never appear in telemetry logs.
    const PATH_CANARY: &str = "not-a-uuid-CANARY-secret-999";
    let (status, _) = api.call(
        alice_b,
        "GET",
        &format!("/v1/runs/{PATH_CANARY}"),
        None,
        None,
    );
    assert_eq!(status, 400);

    // 4. Unauthenticated request (401) must never record `run_id`.
    let (status, _, _) = api.raw(&format!(
        "GET /v1/runs/{run_id} HTTP/1.1\r\nhost: app.example.test\r\nconnection: close\r\n\r\n"
    ));
    assert_eq!(status, 401);

    // 5. Authenticated `POST /v1/runs/{run_id}/cancel`.
    let (status, _) = api.call(
        alice_b,
        "POST",
        &format!("/v1/runs/{run_id}/cancel"),
        Some("tel-cancel-1"),
        None,
    );
    assert_eq!(status, 200);

    // Poll until the API stderr log writer flushes all 6 `/v1/runs*` completion events.
    let deadline = Instant::now() + Duration::from_secs(5);
    let events: Vec<Value> = loop {
        let raw = fs::read_to_string(&log_path).unwrap_or_default();
        let parsed: Vec<Value> = raw
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|v| v.get("event").and_then(Value::as_str) == Some("http.request.completed"))
            .filter(|v| {
                v.get("http.route")
                    .and_then(Value::as_str)
                    .is_some_and(|r| r.starts_with("/v1/runs"))
            })
            .collect();
        if parsed.len() >= 6 {
            break parsed;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for /v1/runs completion logs, got {} events:\n{raw}",
            parsed.len()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    let raw_log = fs::read_to_string(&log_path).unwrap();
    assert!(
        !raw_log.contains(PATH_CANARY),
        "invalid path canary leaked to stderr logs"
    );

    let find = |route: &str, status: u64| -> &Value {
        events
            .iter()
            .find(|e| {
                e.get("http.route").and_then(Value::as_str) == Some(route)
                    && e.get("http.response.status_code").and_then(Value::as_u64) == Some(status)
            })
            .unwrap_or_else(|| panic!("missing log for ({route}, {status}) in {events:#?}"))
    };

    for (route, status) in [
        ("/v1/runs", 201),
        ("/v1/runs/{run_id}", 200),
        ("/v1/runs/{run_id}/approvals", 200),
        ("/v1/runs/{run_id}/cancel", 200),
    ] {
        let ev = find(route, status);
        assert!(
            ev.get("request_id").and_then(Value::as_str).is_some(),
            "missing request_id on {ev}"
        );
        assert_eq!(
            ev.get("run_id").and_then(Value::as_str),
            Some(run_id.as_str()),
            "missing or wrong run_id on {ev}"
        );
    }

    // Both 400 (invalid UUID) and 401 (unauthenticated) must omit `run_id`.
    for status in [400u64, 401u64] {
        let ev = find("/v1/runs/{run_id}", status);
        assert!(
            ev.get("run_id").is_none(),
            "unexpected run_id on {status} response: {ev}"
        );
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn coordinator_resume_records_post_commit_error_and_never_resumed_when_commit_fails() {
    use openmettle_core::{
        capacity::{
            self, Controller,
            adapter::{BackendDeviceConfig, FencedBackend, GroupCoordinator},
        },
        telemetry::metrics::{CapacityOperation, CapacityOutcome, Metrics},
    };
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;

    const GROUP: &str = "00000000-0000-4000-8000-00000000d001";
    const GPU0: &str = "00000000-0000-4000-8000-00000000d0d0";
    const GIB: i64 = 1 << 30;
    const TOTAL: i64 = 24 * GIB;
    const FLOOR: i64 = 16 * GIB;
    const HEADROOM: i64 = GIB;

    let db = TestDb::migrated_exclusive().await;
    let mut owner = connect(&db.0, OWNER).await;
    sqlx::query(
        "INSERT INTO openmettle.capacity_groups (id, observation_ttl_ms)
         VALUES ($1::uuid, 60000)",
    )
    .bind(GROUP)
    .execute(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.capacity_devices (id, group_id, chat_floor_bytes)
         VALUES ($1::uuid, $2::uuid, $3)",
    )
    .bind(GPU0)
    .bind(GROUP)
    .bind(FLOOR)
    .execute(&mut owner)
    .await
    .unwrap();

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(role_options(&db.0, WORKER))
        .await
        .unwrap();
    let mut worker_conn = worker(&db).await;
    let controller = Controller::acquire(&mut worker_conn, GROUP, Duration::from_secs(60))
        .await
        .unwrap();
    let epoch = controller.epoch();
    let backend = FencedBackend::new(
        GROUP,
        vec![BackendDeviceConfig {
            device_id: GPU0.into(),
            total_bytes: TOTAL,
            safety_headroom_bytes: HEADROOM,
            active_chat_floor_bytes: FLOOR,
            backed_chat_floor_bytes: FLOOR,
            reclaimable_bytes: 0,
            unattributed_used_bytes: 0,
        }],
    )
    .unwrap();
    let registry = Arc::new(Metrics::new());
    let coord = GroupCoordinator::with_metrics(pool, controller, backend, registry.clone());

    coord.takeover_and_reconcile().await.unwrap();
    let obs = coord.adapter().observe().unwrap();
    let now_us: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp()) * 1000000)::bigint")
            .fetch_one(&mut worker_conn)
            .await
            .unwrap();
    assert!(
        capacity::publish(
            &mut worker_conn,
            coord.controller(),
            &capacity::Observation {
                revision: 1,
                observed_at_us: now_us,
                commit_watermark: 0,
                devices: &obs,
            },
        )
        .await
        .unwrap()
    );

    // Install a deferred constraint trigger that fails `COMMIT` AFTER `openmettle.capacity_resume`
    // has updated `ready_epoch` and returned `true` to Rust.
    sqlx::query(
        "CREATE OR REPLACE FUNCTION openmettle.fail_resume_commit_for_test()
         RETURNS trigger
         LANGUAGE plpgsql
         AS $$
         BEGIN
             RAISE EXCEPTION 'simulated deferred commit failure on capacity_resume'
                 USING ERRCODE = '40001';
         END;
         $$",
    )
    .execute(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "CREATE CONSTRAINT TRIGGER fail_resume_commit_test
             AFTER UPDATE ON openmettle.capacity_groups
             DEFERRABLE INITIALLY DEFERRED
             FOR EACH ROW
             WHEN (NEW.ready_epoch IS NOT NULL AND OLD.ready_epoch IS DISTINCT FROM NEW.ready_epoch)
             EXECUTE FUNCTION openmettle.fail_resume_commit_for_test()",
    )
    .execute(&mut owner)
    .await
    .unwrap();

    let err = coord.resume().await;
    assert_eq!(err, Err(capacity::Error::Database));
    assert_eq!(
        registry.capacity_grant_count(CapacityOperation::Resume, CapacityOutcome::Resumed),
        0,
        "rolled-back resume commit must never record Resumed"
    );
    assert_eq!(
        registry.capacity_grant_count(CapacityOperation::Resume, CapacityOutcome::Error),
        1,
        "rolled-back resume commit must record Error"
    );
    let ready_after_rollback: Option<i64> = sqlx::query_scalar(
        "SELECT ready_epoch FROM openmettle.capacity_groups WHERE id = $1::uuid",
    )
    .bind(GROUP)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(ready_after_rollback, None);

    // Remove the trigger and verify a committed resume records `Resumed == 1`.
    sqlx::query("DROP TRIGGER fail_resume_commit_test ON openmettle.capacity_groups")
        .execute(&mut owner)
        .await
        .unwrap();
    assert_eq!(coord.resume().await, Ok(true));
    assert_eq!(
        registry.capacity_grant_count(CapacityOperation::Resume, CapacityOutcome::Resumed),
        1
    );
    assert_eq!(
        registry.capacity_grant_count(CapacityOperation::Resume, CapacityOutcome::Error),
        1
    );
    let ready_after_commit: Option<i64> = sqlx::query_scalar(
        "SELECT ready_epoch FROM openmettle.capacity_groups WHERE id = $1::uuid",
    )
    .bind(GROUP)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(ready_after_commit, Some(epoch));
}

#[derive(Default)]
struct CapacityTraceRecorder {
    state: std::sync::Mutex<CapacityTraceState>,
}

#[derive(Default)]
struct CapacityTraceState {
    next_id: u64,
    active_depth: usize,
    max_depth: usize,
    spans: std::collections::BTreeMap<u64, std::collections::BTreeMap<String, String>>,
    closed_spans: Vec<std::collections::BTreeMap<String, String>>,
    events: Vec<std::collections::BTreeMap<String, String>>,
}

struct FieldCollector<'a>(&'a mut std::collections::BTreeMap<String, String>);

impl tracing::field::Visit for FieldCollector<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

impl tracing::Subscriber for CapacityTraceRecorder {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "openmettle_core::telemetry"
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut guard = self.state.lock().unwrap();
        guard.next_id += 1;
        let id = guard.next_id;
        if span.metadata().name() == "capacity.grant" {
            let mut fields = std::collections::BTreeMap::new();
            span.record(&mut FieldCollector(&mut fields));
            guard.active_depth += 1;
            guard.max_depth = guard.max_depth.max(guard.active_depth);
            guard.spans.insert(id, fields);
        }
        tracing::span::Id::from_u64(id)
    }

    fn record(&self, span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        let mut guard = self.state.lock().unwrap();
        if let Some(fields) = guard.spans.get_mut(&span.into_u64()) {
            values.record(&mut FieldCollector(fields));
        }
    }

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = std::collections::BTreeMap::new();
        event.record(&mut FieldCollector(&mut fields));
        if fields.get("event").map(String::as_str) == Some("capacity.grant.completed") {
            self.state.lock().unwrap().events.push(fields);
        }
    }

    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}

    fn try_close(&self, id: tracing::span::Id) -> bool {
        let mut guard = self.state.lock().unwrap();
        if let Some(fields) = guard.spans.remove(&id.into_u64()) {
            guard.active_depth = guard.active_depth.saturating_sub(1);
            guard.closed_spans.push(fields);
        }
        true
    }
}

async fn seed_capacity_group_and_claimed_runs(
    db: &TestDb,
    owner: &mut PgConnection,
    group: &str,
    gpu0: &str,
    floor: i64,
    count: usize,
) -> (String, Vec<ClaimedRun>) {
    use openmettle_core::quotas::{self, RunBudgetReservation};

    providers(owner).await;
    let alice = account(owner, PROVIDER, true, FUTURE).await;
    let scope = personal_of(db, &alice).await;
    sqlx::query(
        "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
         VALUES ('personal', 'usage_tokens', 1000000),
                ('personal', 'device_reservations', 8)",
    )
    .execute(&mut *owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.capacity_groups (id, observation_ttl_ms)
         VALUES ($1::uuid, 60000)",
    )
    .bind(group)
    .execute(&mut *owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.capacity_devices (id, group_id, chat_floor_bytes)
         VALUES ($1::uuid, $2::uuid, $3)",
    )
    .bind(gpu0)
    .bind(group)
    .bind(floor)
    .execute(&mut *owner)
    .await
    .unwrap();

    let conv = chat(db, &scope, "personal", &alice).await;
    let branch: String = sqlx::query_scalar(
        "INSERT INTO openmettle.conversation_branches (scope_id, conversation_id)
         VALUES ($1::uuid, $2::uuid) RETURNING id::text",
    )
    .bind(&scope)
    .bind(&conv)
    .fetch_one(&mut *owner)
    .await
    .unwrap();
    let msg = message(&mut *owner, &scope, &conv, None).await.unwrap();
    let mut api_conn = api(db).await;
    let limits = queue::AdmissionLimits {
        live_per_actor: 16,
        live_per_scope: 16,
        queued_in_instance: 32,
        queue_timeout: Duration::from_secs(300),
        round_cap: 4,
    };
    for i in 0..count {
        let key = format!("cap-tel-run-{i}");
        let mut tx = WriteTransaction::begin(&mut api_conn).await.unwrap();
        let Admission::Admitted { run_id, .. } = queue::admit_run(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope: &scope,
                    actor: &alice.user,
                    conversation: &conv,
                    branch: &branch,
                    message: &msg,
                    key: &key,
                    format: "openmettle.conversation",
                    version: 1,
                    input: b"{}",
                    config: b"{}",
                },
                actor_approval_id: &alice.approval,
                capabilities: &[],
                requested_rounds: Some(1),
                now_ms: NOW,
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
                    run_id: &run_id,
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
    }
    let mut worker_conn = worker(db).await;
    let mut claims = Vec::with_capacity(count);
    for _ in 0..count {
        claims.push(
            queue::claim_next(&mut worker_conn, &OPEN, &LEASES)
                .await
                .unwrap()
                .unwrap(),
        );
    }
    (scope, claims)
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn capacity_grant_outer_transaction_rollback_never_emits_granted_telemetry() {
    use openmettle_core::{
        capacity::{
            self, Controller, Decision, DeviceBytes, GrantRequest, GrantState,
            adapter::{
                BackendDeviceConfig, CapacityWait, CoordinatorError, FencedBackend,
                GroupCoordinator,
            },
        },
        telemetry::metrics::{CapacityOperation, CapacityOutcome, Metrics},
    };
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;

    const GROUP: &str = "00000000-0000-4000-8000-00000000d011";
    const GPU0: &str = "00000000-0000-4000-8000-00000000d0d1";
    const GIB: i64 = 1 << 30;
    const TOTAL: i64 = 24 * GIB;
    const FLOOR: i64 = 16 * GIB;
    const HEADROOM: i64 = GIB;

    let db = TestDb::migrated_exclusive().await;
    let mut owner = connect(&db.0, OWNER).await;
    let (scope, claims) =
        seed_capacity_group_and_claimed_runs(&db, &mut owner, GROUP, GPU0, FLOOR, 2).await;

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(role_options(&db.0, WORKER))
        .await
        .unwrap();
    let mut worker_conn = worker(&db).await;
    let stale_controller = Controller::acquire(&mut worker_conn, GROUP, Duration::from_secs(60))
        .await
        .unwrap();
    sqlx::query(
        "UPDATE openmettle.capacity_groups
            SET lease_expires_at = clock_timestamp() - interval '1 second'
          WHERE id = $1::uuid",
    )
    .bind(GROUP)
    .execute(&mut owner)
    .await
    .unwrap();
    let controller = Controller::acquire(&mut worker_conn, GROUP, Duration::from_secs(60))
        .await
        .unwrap();
    let backend = FencedBackend::new(
        GROUP,
        vec![BackendDeviceConfig {
            device_id: GPU0.into(),
            total_bytes: TOTAL,
            safety_headroom_bytes: HEADROOM,
            active_chat_floor_bytes: FLOOR,
            backed_chat_floor_bytes: FLOOR,
            reclaimable_bytes: 0,
            unattributed_used_bytes: 0,
        }],
    )
    .unwrap();
    let registry = Arc::new(Metrics::new());
    let coord = GroupCoordinator::with_metrics(pool, controller, backend, registry.clone());
    coord.takeover_and_reconcile().await.unwrap();
    let obs = coord.adapter().observe().unwrap();
    let now_us: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp()) * 1000000)::bigint")
            .fetch_one(&mut worker_conn)
            .await
            .unwrap();
    assert!(
        capacity::publish(
            &mut worker_conn,
            coord.controller(),
            &capacity::Observation {
                revision: 1,
                observed_at_us: now_us,
                commit_watermark: 0,
                devices: &obs,
            },
        )
        .await
        .unwrap()
    );
    assert!(coord.resume().await.unwrap());

    let footprint = [DeviceBytes {
        device_id: GPU0.into(),
        bytes: 2 * GIB,
    }];
    let req0 = GrantRequest {
        scope_id: &scope,
        run_id: &claims[0].run_id,
        claim_token: &claims[0].claim_token,
        request_key: "outer-tx-rollback-grant",
        profile: "synthetic-image",
        footprint: &footprint,
    };

    // 1. Caller-owned `WriteTransaction` that calls `capacity::grant` and rolls back/drops MUST
    //    NOT emit `outcome="granted"` on metrics, spans, or events.
    let recorder = Arc::new(CapacityTraceRecorder::default());
    let _sub_guard = tracing::subscriber::set_default(recorder.clone());
    let before_global_granted =
        metrics::global().capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Granted);
    {
        let mut crashed = worker(&db).await;
        let mut tx = WriteTransaction::begin(&mut crashed).await.unwrap();
        let decision = capacity::grant(tx.connection().unwrap(), coord.controller(), &req0)
            .await
            .unwrap();
        assert!(matches!(
            decision,
            Decision::Grant {
                state: GrantState::Granted,
                ..
            }
        ));
        drop(tx);
    }
    assert_eq!(
        metrics::global().capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Granted),
        before_global_granted,
        "rolled-back outer transaction must not emit global Granted metric"
    );
    {
        let st = recorder.state.lock().unwrap();
        assert!(
            st.closed_spans.is_empty() && st.events.is_empty(),
            "rolled-back outer transaction must not emit pre-commit capacity.grant span/event"
        );
    }
    let grant_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM openmettle.capacity_grants")
        .fetch_one(&mut owner)
        .await
        .unwrap();
    assert_eq!(grant_rows, 0);

    // 2. Autocommit `capacity::grant` commits immediately and DOES emit `outcome="granted"`.
    let autocommit_decision = capacity::grant(&mut worker_conn, coord.controller(), &req0)
        .await
        .unwrap();
    let Decision::Grant {
        grant_id: autocommit_grant_id,
        state: GrantState::Granted,
    } = autocommit_decision
    else {
        panic!("expected autocommit grant");
    };
    assert_eq!(
        metrics::global().capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Granted),
        before_global_granted + 1
    );
    {
        let mut st = recorder.state.lock().unwrap();
        assert_eq!(st.closed_spans.len(), 1);
        assert_eq!(
            st.closed_spans[0].get("lease_id").map(String::as_str),
            Some(autocommit_grant_id.as_str())
        );
        assert_eq!(
            st.closed_spans[0]
                .get("operation.outcome")
                .map(String::as_str),
            Some("granted")
        );
        assert_eq!(st.events.len(), 1);
        assert_eq!(
            st.events[0].get("operation.outcome").map(String::as_str),
            Some("granted")
        );
        st.closed_spans.clear();
        st.events.clear();
    }

    // 2a. Autocommit failures (both pre-SQL `Error::Invalid` and DB-raised `Error::Fenced`) MUST
    //     emit telemetry via Simple Query Protocol confirmation rather than false-suppressing.
    let before_auto_refused =
        metrics::global().capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Refused);
    let before_auto_fenced =
        metrics::global().capacity_grant_count(CapacityOperation::Resume, CapacityOutcome::Fenced);
    let invalid_req = GrantRequest {
        scope_id: "not-a-uuid",
        run_id: &claims[1].run_id,
        claim_token: &claims[1].claim_token,
        request_key: "autocommit-invalid-grant",
        profile: "synthetic-image",
        footprint: &footprint,
    };
    for _ in 0..5 {
        assert_eq!(
            capacity::grant(&mut worker_conn, coord.controller(), &invalid_req).await,
            Err(capacity::Error::Invalid)
        );
    }
    assert_eq!(
        metrics::global().capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Refused),
        before_auto_refused + 5,
        "idle autocommit Error::Invalid calls must record Refused telemetry every time"
    );
    {
        let mut st = recorder.state.lock().unwrap();
        assert_eq!(st.closed_spans.len(), 5);
        assert_eq!(st.events.len(), 5);
        for span in &st.closed_spans {
            assert_eq!(
                span.get("operation.outcome").map(String::as_str),
                Some("refused")
            );
        }
        for event in &st.events {
            assert_eq!(
                event.get("operation.outcome").map(String::as_str),
                Some("refused")
            );
        }
        st.closed_spans.clear();
        st.events.clear();
    }
    assert_eq!(
        capacity::resume(&mut worker_conn, &stale_controller).await,
        Err(capacity::Error::Fenced)
    );
    assert_eq!(
        metrics::global().capacity_grant_count(CapacityOperation::Resume, CapacityOutcome::Fenced),
        before_auto_fenced + 1,
        "idle autocommit DB-raised Error::Fenced must record Fenced telemetry"
    );
    {
        let mut st = recorder.state.lock().unwrap();
        assert_eq!(st.closed_spans.len(), 1);
        assert_eq!(
            st.closed_spans[0]
                .get("operation.outcome")
                .map(String::as_str),
            Some("fenced")
        );
        assert_eq!(st.events.len(), 1);
        assert_eq!(
            st.events[0].get("operation.outcome").map(String::as_str),
            Some("fenced")
        );
        st.closed_spans.clear();
        st.events.clear();
    }

    // 2b. Literal SQL `BEGIN` on a raw `PgConnection` bypasses SQLx's `is_in_transaction()` flag;
    //     `capacity::resume`, `capacity::grant`, and `capacity::reconcile` (including pre-SQL
    //     `Error::Invalid` and DB-aborted `25P02` `Error::Fenced`) must suppress telemetry and
    //     roll back cleanly.
    let before_raw_granted =
        metrics::global().capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Granted);
    let before_raw_refused =
        metrics::global().capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Refused);
    let before_raw_resumed =
        metrics::global().capacity_grant_count(CapacityOperation::Resume, CapacityOutcome::Resumed);
    let before_raw_releasing = metrics::global()
        .capacity_grant_count(CapacityOperation::Reconcile, CapacityOutcome::Releasing);
    let before_raw_fenced =
        metrics::global().capacity_grant_count(CapacityOperation::Resume, CapacityOutcome::Fenced);
    {
        let mut raw_conn = worker(&db).await;
        sqlx::query("BEGIN").execute(&mut raw_conn).await.unwrap();

        let bad_req = GrantRequest {
            scope_id: "not-a-uuid",
            run_id: &claims[1].run_id,
            claim_token: &claims[1].claim_token,
            request_key: "raw-begin-invalid-grant",
            profile: "synthetic-image",
            footprint: &footprint,
        };
        assert_eq!(
            capacity::grant(&mut raw_conn, coord.controller(), &bad_req).await,
            Err(capacity::Error::Invalid)
        );

        assert!(
            capacity::resume(&mut raw_conn, coord.controller())
                .await
                .unwrap()
        );
        let raw_req = GrantRequest {
            scope_id: &scope,
            run_id: &claims[1].run_id,
            claim_token: &claims[1].claim_token,
            request_key: "raw-begin-rollback-grant",
            profile: "synthetic-image",
            footprint: &footprint,
        };
        let raw_decision = capacity::grant(&mut raw_conn, coord.controller(), &raw_req)
            .await
            .unwrap();
        assert!(matches!(
            raw_decision,
            Decision::Grant {
                state: GrantState::Granted,
                ..
            }
        ));
        let raw_reconcile = capacity::reconcile(
            &mut raw_conn,
            coord.controller(),
            &autocommit_grant_id,
            capacity::Evidence::Releasing,
        )
        .await
        .unwrap();
        assert_eq!(raw_reconcile, GrantState::Releasing);

        sqlx::query("ROLLBACK")
            .execute(&mut raw_conn)
            .await
            .unwrap();

        // Aborted literal `BEGIN` (`25P02` after DB-raised `Error::Fenced`) must also suppress
        // telemetry cleanly and preserve the original `Error::Fenced`.
        sqlx::query("BEGIN").execute(&mut raw_conn).await.unwrap();
        assert_eq!(
            capacity::resume(&mut raw_conn, &stale_controller).await,
            Err(capacity::Error::Fenced)
        );
        sqlx::query("ROLLBACK")
            .execute(&mut raw_conn)
            .await
            .unwrap();
    }
    assert_eq!(
        metrics::global().capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Granted),
        before_raw_granted,
        "rolled-back literal BEGIN must not emit global Granted metric"
    );
    assert_eq!(
        metrics::global().capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Refused),
        before_raw_refused,
        "literal BEGIN pre-SQL Invalid must not emit global Refused metric"
    );
    assert_eq!(
        metrics::global().capacity_grant_count(CapacityOperation::Resume, CapacityOutcome::Resumed),
        before_raw_resumed,
        "rolled-back literal BEGIN must not emit global Resumed metric"
    );
    assert_eq!(
        metrics::global()
            .capacity_grant_count(CapacityOperation::Reconcile, CapacityOutcome::Releasing),
        before_raw_releasing,
        "rolled-back literal BEGIN must not emit global Releasing metric"
    );
    assert_eq!(
        metrics::global().capacity_grant_count(CapacityOperation::Resume, CapacityOutcome::Fenced),
        before_raw_fenced,
        "aborted literal BEGIN (25P02) must not emit global Fenced metric"
    );
    {
        let st = recorder.state.lock().unwrap();
        assert!(
            st.closed_spans.is_empty() && st.events.is_empty(),
            "literal BEGIN block must not emit pre-commit capacity.grant spans or events"
        );
    }
    let post_rollback_grant_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM openmettle.capacity_grants")
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(
        post_rollback_grant_rows, 1,
        "only autocommit grant row should remain after ROLLBACK"
    );
    let autocommit_grant_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.capacity_grants WHERE id = $1::uuid")
            .bind(&autocommit_grant_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(
        autocommit_grant_state, "granted",
        "reconcile(Releasing) inside rolled-back literal BEGIN must leave DB state unchanged"
    );

    // 3. Deferred commit failure on `GroupCoordinator::dispatch_grant`'s `confirm_dispatch_tx`
    //    must record `Error`, NEVER `Granted`.
    sqlx::query(
        "CREATE OR REPLACE FUNCTION openmettle.fail_confirm_commit_for_test()
         RETURNS trigger
         LANGUAGE plpgsql
         AS $$
         BEGIN
             RAISE EXCEPTION 'simulated deferred commit failure on confirm_dispatch'
                 USING ERRCODE = '40001';
         END;
         $$",
    )
    .execute(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "CREATE CONSTRAINT TRIGGER fail_confirm_commit_test
             AFTER UPDATE ON openmettle.capacity_grants
             DEFERRABLE INITIALLY DEFERRED
             FOR EACH ROW
             WHEN (NEW.dispatch_state = 'confirmed' AND OLD.dispatch_state IS DISTINCT FROM NEW.dispatch_state)
             EXECUTE FUNCTION openmettle.fail_confirm_commit_for_test()",
    )
    .execute(&mut owner)
    .await
    .unwrap();

    let req1 = GrantRequest {
        scope_id: &scope,
        run_id: &claims[1].run_id,
        claim_token: &claims[1].claim_token,
        request_key: "confirm-commit-fail-grant",
        profile: "synthetic-image",
        footprint: &footprint,
    };
    let wait = CapacityWait::start();
    assert_eq!(
        coord.dispatch_grant(&req1, &wait).await,
        Err(CoordinatorError::Store(capacity::Error::Database))
    );
    assert_eq!(
        registry.capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Granted),
        0,
        "rolled-back confirm_dispatch commit must never record Granted"
    );
    assert_eq!(
        registry.capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Error),
        1
    );
    {
        let st = recorder.state.lock().unwrap();
        assert_eq!(st.max_depth, 1);
        assert_eq!(st.closed_spans.len(), 1);
        assert_eq!(
            st.closed_spans[0]
                .get("operation.outcome")
                .map(String::as_str),
            Some("error")
        );
        assert_eq!(st.events.len(), 1);
        assert_eq!(
            st.events[0].get("operation.outcome").map(String::as_str),
            Some("error")
        );
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn capacity_probe_failures_never_replace_committed_results() {
    use openmettle_core::{
        capacity::{
            self, Controller, Decision, DeviceBytes, DeviceObservation, Evidence, GrantRequest,
            GrantState, Observation,
        },
        telemetry::metrics::{CapacityOperation, CapacityOutcome},
    };
    use std::sync::Arc;

    struct DbPrivilegeRestore {
        db: String,
        statements: Vec<String>,
    }
    impl Drop for DbPrivilegeRestore {
        fn drop(&mut self) {
            admin_blocking(Some(self.db.clone()), self.statements.clone());
        }
    }

    const GROUP: &str = "00000000-0000-4000-8000-00000000d031";
    const GPU0: &str = "00000000-0000-4000-8000-00000000d0d3";
    const GIB: i64 = 1 << 30;
    const TOTAL: i64 = 24 * GIB;
    const FLOOR: i64 = 16 * GIB;
    const HEADROOM: i64 = GIB;

    let db = TestDb::migrated_exclusive().await;
    let _restore = DbPrivilegeRestore {
        db: db.0.clone(),
        statements: vec![
            "GRANT SELECT ON openmettle.capacity_groups TO openmettle_worker".to_owned(),
            "GRANT EXECUTE ON FUNCTION pg_catalog.pg_current_xact_id_if_assigned() TO PUBLIC"
                .to_owned(),
        ],
    };

    let mut superuser = admin(Some(&db.0)).await;
    let mut owner = connect(&db.0, OWNER).await;
    let (scope, claims) =
        seed_capacity_group_and_claimed_runs(&db, &mut owner, GROUP, GPU0, FLOOR, 2).await;

    let mut worker_conn = worker(&db).await;
    let controller = Controller::acquire(&mut worker_conn, GROUP, Duration::from_secs(60))
        .await
        .unwrap();
    capacity::set_backend_unknown(&mut worker_conn, &controller, false)
        .await
        .unwrap();
    let now_us: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp()) * 1000000)::bigint")
            .fetch_one(&mut worker_conn)
            .await
            .unwrap();
    let obs = [DeviceObservation {
        device_id: GPU0.into(),
        total_bytes: TOTAL,
        committed_bytes: 0,
        actual_used_bytes: FLOOR,
        reclaimable_bytes: 0,
        safety_headroom_bytes: HEADROOM,
        active_chat_floor_bytes: FLOOR,
        grantable_bytes: TOTAL - FLOOR - HEADROOM,
    }];
    assert!(
        capacity::publish(
            &mut worker_conn,
            &controller,
            &Observation {
                revision: 1,
                observed_at_us: now_us,
                commit_watermark: 0,
                devices: &obs,
            },
        )
        .await
        .unwrap()
    );

    let footprint = [DeviceBytes {
        device_id: GPU0.into(),
        bytes: 2 * GIB,
    }];
    let req0 = GrantRequest {
        scope_id: &scope,
        run_id: &claims[0].run_id,
        claim_token: &claims[0].claim_token,
        request_key: "probe-failure-resilience-grant",
        profile: "synthetic-image",
        footprint: &footprint,
    };

    let recorder = Arc::new(CapacityTraceRecorder::default());
    let _sub_guard = tracing::subscriber::set_default(recorder.clone());

    // 1. Before `resume`, `capacity::grant` returns `Ok(Decision::Unavailable)`. Revoking
    //    `SELECT ON openmettle.capacity_groups` from `openmettle_worker` makes the post-decision
    //    `group_observation_stale` probe fail with 42501; `grant` MUST still return
    //    `Ok(Decision::Unavailable)` and emit `Unavailable` telemetry.
    let before_unavailable = metrics::global()
        .capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Unavailable);
    sqlx::query("REVOKE SELECT ON openmettle.capacity_groups FROM openmettle_worker")
        .execute(&mut superuser)
        .await
        .unwrap();
    assert_eq!(
        capacity::grant(&mut worker_conn, &controller, &req0)
            .await
            .unwrap(),
        Decision::Unavailable
    );
    sqlx::query("GRANT SELECT ON openmettle.capacity_groups TO openmettle_worker")
        .execute(&mut superuser)
        .await
        .unwrap();
    assert_eq!(
        metrics::global()
            .capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Unavailable),
        before_unavailable + 1
    );
    {
        let mut st = recorder.state.lock().unwrap();
        assert_eq!(st.closed_spans.len(), 1);
        assert_eq!(
            st.closed_spans[0]
                .get("operation.outcome")
                .map(String::as_str),
            Some("unavailable")
        );
        assert_eq!(st.events.len(), 1);
        assert_eq!(
            st.events[0].get("operation.outcome").map(String::as_str),
            Some("unavailable")
        );
        st.closed_spans.clear();
        st.events.clear();
    }

    // 2. Revoking `EXECUTE` on `pg_catalog.pg_current_xact_id_if_assigned()` MUST NOT abort a
    //    caller-owned literal `BEGIN` transaction OR break autocommit post-commit telemetry:
    //    a) Under literal `BEGIN`, `capacity::resume`, `grant`, and `reconcile` keep the
    //       connection healthy (subsequent `SELECT 1` succeeds without `25P02`), `COMMIT`
    //       persists cleanly as observed from an independent connection, and zero pre-commit
    //       spans/events/counters are emitted.
    //    b) Still under revoked `EXECUTE`, autocommit `resume`, `grant`, and `reconcile` both
    //       persist their state changes and emit post-commit telemetry cleanly.
    let before_resumed =
        metrics::global().capacity_grant_count(CapacityOperation::Resume, CapacityOutcome::Resumed);
    let before_granted =
        metrics::global().capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Granted);
    let before_releasing = metrics::global()
        .capacity_grant_count(CapacityOperation::Reconcile, CapacityOutcome::Releasing);
    let before_resume_err =
        metrics::global().capacity_grant_count(CapacityOperation::Resume, CapacityOutcome::Error);
    let before_grant_err =
        metrics::global().capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Error);
    let before_reconcile_err = metrics::global()
        .capacity_grant_count(CapacityOperation::Reconcile, CapacityOutcome::Error);

    sqlx::query(
        "REVOKE EXECUTE ON FUNCTION pg_catalog.pg_current_xact_id_if_assigned() FROM PUBLIC",
    )
    .execute(&mut superuser)
    .await
    .unwrap();

    // (a) Caller-owned literal `BEGIN` block must remain un-aborted and commit cleanly:
    sqlx::raw_sql("BEGIN")
        .execute(&mut worker_conn)
        .await
        .unwrap();
    assert!(
        capacity::resume(&mut worker_conn, &controller)
            .await
            .unwrap()
    );
    let tx_decision = capacity::grant(&mut worker_conn, &controller, &req0)
        .await
        .unwrap();
    let Decision::Grant {
        grant_id: tx_grant_id,
        state: GrantState::Granted,
    } = tx_decision
    else {
        panic!("expected Ok(Decision::Grant {{ state: Granted }}) inside BEGIN");
    };
    let tx_reconciled = capacity::reconcile(
        &mut worker_conn,
        &controller,
        &tx_grant_id,
        Evidence::Releasing,
    )
    .await
    .unwrap();
    assert_eq!(tx_reconciled, GrantState::Releasing);
    let probe_select: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&mut worker_conn)
        .await
        .expect("caller-owned BEGIN transaction must not enter 25P02");
    assert_eq!(probe_select, 1);
    sqlx::raw_sql("COMMIT")
        .execute(&mut worker_conn)
        .await
        .unwrap();

    let committed_ready: bool = sqlx::query_scalar(
        "SELECT ready_epoch IS NOT NULL AND ready_epoch = controller_epoch
           FROM openmettle.capacity_groups
          WHERE id = $1::uuid",
    )
    .bind(GROUP)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert!(
        committed_ready,
        "literal BEGIN commit must persist ready_epoch under revoked pg_current_xact_id_if_assigned"
    );
    let committed_grant_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.capacity_grants WHERE id = $1::uuid")
            .bind(&tx_grant_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(committed_grant_state, "releasing");
    assert_eq!(
        metrics::global().capacity_grant_count(CapacityOperation::Resume, CapacityOutcome::Resumed),
        before_resumed
    );
    assert_eq!(
        metrics::global().capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Granted),
        before_granted
    );
    assert_eq!(
        metrics::global()
            .capacity_grant_count(CapacityOperation::Reconcile, CapacityOutcome::Releasing),
        before_releasing
    );
    {
        let st = recorder.state.lock().unwrap();
        assert!(
            st.closed_spans.is_empty() && st.events.is_empty(),
            "literal BEGIN block must not emit pre-commit spans or events"
        );
    }

    // (b) Autocommit calls under revoked `pg_current_xact_id_if_assigned()` still persist AND
    //     emit post-commit telemetry without erroring.
    let req1 = GrantRequest {
        scope_id: &scope,
        run_id: &claims[1].run_id,
        claim_token: &claims[1].claim_token,
        request_key: "probe-failure-resilience-grant-autocommit",
        profile: "synthetic-image",
        footprint: &footprint,
    };
    assert!(
        capacity::resume(&mut worker_conn, &controller)
            .await
            .unwrap()
    );
    let decision = capacity::grant(&mut worker_conn, &controller, &req1)
        .await
        .unwrap();
    let Decision::Grant {
        grant_id,
        state: GrantState::Granted,
    } = decision
    else {
        panic!("expected Ok(Decision::Grant {{ state: Granted }}) in autocommit");
    };
    let persisted_granted: String =
        sqlx::query_scalar("SELECT state FROM openmettle.capacity_grants WHERE id = $1::uuid")
            .bind(&grant_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(persisted_granted, "granted");

    let reconciled = capacity::reconcile(
        &mut worker_conn,
        &controller,
        &grant_id,
        Evidence::Releasing,
    )
    .await
    .unwrap();
    assert_eq!(reconciled, GrantState::Releasing);
    let persisted_releasing: String =
        sqlx::query_scalar("SELECT state FROM openmettle.capacity_grants WHERE id = $1::uuid")
            .bind(&grant_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(persisted_releasing, "releasing");

    sqlx::query("GRANT EXECUTE ON FUNCTION pg_catalog.pg_current_xact_id_if_assigned() TO PUBLIC")
        .execute(&mut superuser)
        .await
        .unwrap();

    assert_eq!(
        metrics::global().capacity_grant_count(CapacityOperation::Resume, CapacityOutcome::Resumed),
        before_resumed + 1
    );
    assert_eq!(
        metrics::global().capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Granted),
        before_granted + 1
    );
    assert_eq!(
        metrics::global()
            .capacity_grant_count(CapacityOperation::Reconcile, CapacityOutcome::Releasing),
        before_releasing + 1
    );
    assert_eq!(
        metrics::global().capacity_grant_count(CapacityOperation::Resume, CapacityOutcome::Error),
        before_resume_err
    );
    assert_eq!(
        metrics::global().capacity_grant_count(CapacityOperation::Grant, CapacityOutcome::Error),
        before_grant_err
    );
    assert_eq!(
        metrics::global()
            .capacity_grant_count(CapacityOperation::Reconcile, CapacityOutcome::Error),
        before_reconcile_err
    );
    {
        let st = recorder.state.lock().unwrap();
        assert_eq!(st.closed_spans.len(), 3);
        assert_eq!(st.events.len(), 3);
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn takeover_and_reconcile_emits_correlated_capacity_grant_spans_and_events_post_commit() {
    use openmettle_core::{
        capacity::{
            self, Controller, Decision, DeviceBytes, GrantRequest, GrantState,
            adapter::{
                BackendDeviceConfig, CapacityWait, CoordinatorError, DispatchOutcome,
                FencedBackend, GroupCoordinator,
            },
        },
        telemetry::metrics::{CapacityOperation, CapacityOutcome, Metrics},
    };
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;

    const GROUP: &str = "00000000-0000-4000-8000-00000000d021";
    const GPU0: &str = "00000000-0000-4000-8000-00000000d0d2";
    const GIB: i64 = 1 << 30;
    const TOTAL: i64 = 24 * GIB;
    const FLOOR: i64 = 16 * GIB;
    const HEADROOM: i64 = GIB;

    let db = TestDb::migrated_exclusive().await;
    let mut owner = connect(&db.0, OWNER).await;
    let (scope, claims) =
        seed_capacity_group_and_claimed_runs(&db, &mut owner, GROUP, GPU0, FLOOR, 2).await;

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(role_options(&db.0, WORKER))
        .await
        .unwrap();
    let mut worker_conn = worker(&db).await;
    let c1 = Controller::acquire(&mut worker_conn, GROUP, Duration::from_secs(60))
        .await
        .unwrap();
    let backend = Arc::new(
        FencedBackend::new(
            GROUP,
            vec![BackendDeviceConfig {
                device_id: GPU0.into(),
                total_bytes: TOTAL,
                safety_headroom_bytes: HEADROOM,
                active_chat_floor_bytes: FLOOR,
                backed_chat_floor_bytes: FLOOR,
                reclaimable_bytes: 0,
                unattributed_used_bytes: 0,
            }],
        )
        .unwrap(),
    );
    let coord1 =
        GroupCoordinator::with_metrics(pool.clone(), c1, backend.clone(), Arc::new(Metrics::new()));
    coord1.takeover_and_reconcile().await.unwrap();
    let obs = backend.observe().unwrap();
    let now_us: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp()) * 1000000)::bigint")
            .fetch_one(&mut worker_conn)
            .await
            .unwrap();
    assert!(
        capacity::publish(
            &mut worker_conn,
            coord1.controller(),
            &capacity::Observation {
                revision: 1,
                observed_at_us: now_us,
                commit_watermark: 0,
                devices: &obs,
            },
        )
        .await
        .unwrap()
    );
    assert!(coord1.resume().await.unwrap());

    let footprint = [DeviceBytes {
        device_id: GPU0.into(),
        bytes: 2 * GIB,
    }];
    // Grant 1 is dispatched onto the backend (exact match during Epoch 2 takeover -> reattested).
    let DispatchOutcome::Dispatched {
        grant_id: grant1, ..
    } = coord1
        .dispatch_grant(
            &GrantRequest {
                scope_id: &scope,
                run_id: &claims[0].run_id,
                claim_token: &claims[0].claim_token,
                request_key: "takeover-live-grant",
                profile: "synthetic-image",
                footprint: &footprint,
            },
            &CapacityWait::start(),
        )
        .await
        .unwrap()
    else {
        panic!("expected dispatched grant 1");
    };
    // Grant 2 is committed in PostgreSQL only (not present on backend -> released as not_allocated).
    let Decision::Grant {
        grant_id: grant2,
        state: GrantState::Granted,
    } = capacity::grant(
        &mut worker_conn,
        coord1.controller(),
        &GrantRequest {
            scope_id: &scope,
            run_id: &claims[1].run_id,
            claim_token: &claims[1].claim_token,
            request_key: "takeover-unbacked-grant",
            profile: "synthetic-image",
            footprint: &footprint,
        },
    )
    .await
    .unwrap()
    else {
        panic!("expected durable grant 2");
    };

    // Expire Epoch 1 controller lease so Epoch 2 takes over.
    sqlx::query(
        "UPDATE openmettle.capacity_groups
            SET lease_expires_at = clock_timestamp() - interval '1 second'
          WHERE id = $1::uuid",
    )
    .bind(GROUP)
    .execute(&mut owner)
    .await
    .unwrap();

    let c2 = Controller::acquire(&mut worker_conn, GROUP, Duration::from_secs(60))
        .await
        .unwrap();
    let registry2 = Arc::new(Metrics::new());
    let coord2 =
        GroupCoordinator::with_metrics(pool.clone(), c2, backend.clone(), registry2.clone());

    let recorder = Arc::new(CapacityTraceRecorder::default());
    let _sub_guard = tracing::subscriber::set_default(recorder.clone());

    let report = coord2.takeover_and_reconcile().await.unwrap();
    assert_eq!(report.attested, 1);
    assert_eq!(report.released, 1);
    assert_eq!(report.unknown, 0);
    assert_eq!(
        registry2.capacity_grant_count(CapacityOperation::Reconcile, CapacityOutcome::Granted),
        1
    );
    assert_eq!(
        registry2.capacity_grant_count(CapacityOperation::Reconcile, CapacityOutcome::NotAllocated),
        1
    );

    {
        let mut st = recorder.state.lock().unwrap();
        assert_eq!(
            st.max_depth, 1,
            "takeover_and_reconcile must emit zero nested capacity.grant spans"
        );
        assert_eq!(st.closed_spans.len(), 2, "{:?}", st.closed_spans);
        assert_eq!(st.events.len(), 2, "{:?}", st.events);

        let span_by_grant = |gid: &str| {
            st.closed_spans
                .iter()
                .find(|s| s.get("lease_id").map(String::as_str) == Some(gid))
                .cloned()
                .unwrap_or_else(|| panic!("missing span for grant {gid}: {:?}", st.closed_spans))
        };
        let event_by_grant = |gid: &str| {
            st.events
                .iter()
                .find(|e| e.get("lease_id").map(String::as_str) == Some(gid))
                .cloned()
                .unwrap_or_else(|| panic!("missing event for grant {gid}: {:?}", st.events))
        };

        let s1 = span_by_grant(&grant1);
        let e1 = event_by_grant(&grant1);
        assert_eq!(
            s1.get("operation.kind").map(String::as_str),
            Some("reconcile")
        );
        assert_eq!(
            s1.get("operation.outcome").map(String::as_str),
            Some("granted")
        );
        assert_eq!(
            e1.get("operation.kind").map(String::as_str),
            Some("reconcile")
        );
        assert_eq!(
            e1.get("operation.outcome").map(String::as_str),
            Some("granted")
        );

        let s2 = span_by_grant(&grant2);
        let e2 = event_by_grant(&grant2);
        assert_eq!(
            s2.get("operation.kind").map(String::as_str),
            Some("reconcile")
        );
        assert_eq!(
            s2.get("operation.outcome").map(String::as_str),
            Some("not_allocated")
        );
        assert_eq!(
            e2.get("operation.kind").map(String::as_str),
            Some("reconcile")
        );
        assert_eq!(
            e2.get("operation.outcome").map(String::as_str),
            Some("not_allocated")
        );
        st.closed_spans.clear();
        st.events.clear();
    }

    // Deferred commit failure during Epoch 3 reattestation must emit `error`, NEVER `granted`.
    sqlx::query(
        "UPDATE openmettle.capacity_groups
            SET lease_expires_at = clock_timestamp() - interval '1 second'
          WHERE id = $1::uuid",
    )
    .bind(GROUP)
    .execute(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "CREATE OR REPLACE FUNCTION openmettle.fail_reattest_commit_for_test()
         RETURNS trigger
         LANGUAGE plpgsql
         AS $$
         BEGIN
             RAISE EXCEPTION 'simulated deferred commit failure on takeover reconcile'
                 USING ERRCODE = '40001';
         END;
         $$",
    )
    .execute(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "CREATE CONSTRAINT TRIGGER fail_reattest_commit_test
             AFTER UPDATE ON openmettle.capacity_grants
             DEFERRABLE INITIALLY DEFERRED
             FOR EACH ROW
             WHEN (OLD.reconciled_epoch IS DISTINCT FROM NEW.reconciled_epoch)
             EXECUTE FUNCTION openmettle.fail_reattest_commit_for_test()",
    )
    .execute(&mut owner)
    .await
    .unwrap();

    let c3 = Controller::acquire(&mut worker_conn, GROUP, Duration::from_secs(60))
        .await
        .unwrap();
    let registry3 = Arc::new(Metrics::new());
    let coord3 = GroupCoordinator::with_metrics(pool, c3, backend, registry3.clone());
    assert_eq!(
        coord3.takeover_and_reconcile().await,
        Err(CoordinatorError::Store(capacity::Error::Database))
    );
    assert_eq!(
        registry3.capacity_grant_count(CapacityOperation::Reconcile, CapacityOutcome::Granted),
        0
    );
    assert_eq!(
        registry3.capacity_grant_count(CapacityOperation::Reconcile, CapacityOutcome::Error),
        1
    );
    {
        let st = recorder.state.lock().unwrap();
        assert_eq!(st.closed_spans.len(), 1);
        assert_eq!(
            st.closed_spans[0].get("lease_id").map(String::as_str),
            Some(grant1.as_str())
        );
        assert_eq!(
            st.closed_spans[0]
                .get("operation.outcome")
                .map(String::as_str),
            Some("error")
        );
        assert_eq!(st.events.len(), 1);
        assert_eq!(
            st.events[0].get("operation.outcome").map(String::as_str),
            Some("error")
        );
    }
}

#[derive(Default)]
struct WorkerOpTraceRecorder {
    state: std::sync::Mutex<WorkerOpTraceState>,
}

#[derive(Default)]
struct WorkerOpTraceState {
    next_id: u64,
    spans: std::collections::BTreeMap<u64, std::collections::BTreeMap<String, String>>,
    closed_spans: Vec<std::collections::BTreeMap<String, String>>,
    events: Vec<(String, std::collections::BTreeMap<String, String>)>,
}

impl tracing::Subscriber for WorkerOpTraceRecorder {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "openmettle_core::telemetry"
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut guard = self.state.lock().unwrap();
        guard.next_id += 1;
        let id = guard.next_id;
        if span.metadata().name() == "worker.operation" {
            let mut fields = std::collections::BTreeMap::new();
            span.record(&mut FieldCollector(&mut fields));
            guard.spans.insert(id, fields);
        }
        tracing::span::Id::from_u64(id)
    }

    fn record(&self, span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        let mut guard = self.state.lock().unwrap();
        if let Some(fields) = guard.spans.get_mut(&span.into_u64()) {
            values.record(&mut FieldCollector(fields));
        }
    }

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = std::collections::BTreeMap::new();
        event.record(&mut FieldCollector(&mut fields));
        if fields.get("event").map(String::as_str) == Some("worker.operation.completed") {
            self.state
                .lock()
                .unwrap()
                .events
                .push((event.metadata().level().as_str().to_owned(), fields));
        }
    }

    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}

    fn try_close(&self, id: tracing::span::Id) -> bool {
        let mut guard = self.state.lock().unwrap();
        if let Some(fields) = guard.spans.remove(&id.into_u64()) {
            guard.closed_spans.push(fields);
        }
        true
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn worker_tool_operation_known_fault_and_replay_emit_failed_outcome_preserving_envelope() {
    use openmettle_core::{
        artifact_fs::Store,
        authz::leases::ExecState,
        mcp::{self, ScopedAdapter, ToolFault},
        telemetry::derive_run_lease_id,
        worker::{ActiveRun, StepContext, StepResult},
    };
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;
    use tokio::sync::watch;

    let db = TestDb::migrated().await;
    seed_token_budget(&db).await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let alice_scope = personal_of(&db, &alice).await;
    let alice_session = effect_session(&db, &alice, 1).await;
    let claim = admit_approval_run(
        &db,
        &alice_scope,
        "personal",
        &alice,
        &alice_session,
        "tel-tool-fault-run",
    )
    .await;

    let api_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(role_options(&db.0, API))
        .await
        .unwrap();
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(role_options(&db.0, WORKER))
        .await
        .unwrap();
    let dir = crate::auth_config_support::Dir::new();
    let root = std::path::PathBuf::from(dir.path("payload"));
    fs::create_dir(&root).unwrap();
    Store::open(&root)
        .unwrap()
        .initialize_api(&api_pool)
        .await
        .unwrap();
    let store = Store::open(&root).unwrap();
    store.probe_writable().unwrap();

    let (_stop_tx, stop_rx) = watch::channel(None);
    let tasks = StepTasks::default();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let step = StepContext {
        deadline,
        stop: stop_rx,
        tasks: tasks.handle(),
    };
    let run = ActiveRun {
        state: ExecState::Running,
        execution_deadline: deadline,
        claim: claim.clone(),
    };
    let expected_lease_id = derive_run_lease_id(&claim.run_id, &claim.claim_token);
    let adapter = ScopedAdapter::new(worker_pool, store, LEASES);

    // Seed an existing readable artifact owned by Alice in her scope so `record_fenced_intent`
    // authorizes the read intent and dispatches into `EffectDispatch::send` -> `range::read`,
    // where the missing `revision_id` produces a known `ToolFault::Semantic` observation.
    const ARTIFACT_ID: &str = "00000000-0000-4000-8000-00000000f001";
    sqlx::query(
        "INSERT INTO openmettle.artifacts (id, scope_id, scope_kind, owner_user_id)
         VALUES ($1::uuid, $2::uuid, 'personal', $3::uuid)",
    )
    .bind(ARTIFACT_ID)
    .bind(&alice_scope)
    .bind(&alice.user)
    .execute(&mut owner)
    .await
    .unwrap();

    let missing_args = json!({
        "artifact_id": ARTIFACT_ID,
        "revision_id": "00000000-0000-4000-8000-00000000f002",
        "offset": 0,
        "max_bytes": 1024,
    })
    .to_string();
    let expected_envelope = ToolFault::Semantic.envelope();

    let recorder = Arc::new(WorkerOpTraceRecorder::default());
    let _sub_guard = tracing::subscriber::set_default(recorder.clone());

    // 1. Fresh known `ToolFault::Semantic`: `observe_known(..., false, &envelope)` +
    //    `recheck_replay_effect_authority` must still return `StepResult::ToolOutput(envelope)`
    //    to the model while recording `operation.outcome = "failed"` on span and log event.
    let fresh = adapter
        .call(
            &run,
            step.clone(),
            "tel-missing-fault",
            mcp::READ_RANGE,
            "1",
            missing_args.as_bytes(),
        )
        .await;
    let StepResult::ToolOutput(fresh_env) = fresh else {
        panic!("expected StepResult::ToolOutput for fresh known ToolFault");
    };
    assert_eq!(fresh_env, expected_envelope);

    let (op_id, db_outcome, attempts): (String, String, i32) = sqlx::query_as(
        "SELECT id::text, outcome, dispatched_attempts
           FROM openmettle.operations
          WHERE run_id = $1::uuid AND logical_key = 'tel-missing-fault'",
    )
    .bind(&claim.run_id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(db_outcome, "failed");
    assert_eq!(attempts, 1);

    // 2. Replayed failed `Observed` tool operation (same logical key): `start_permit_with_outcome`
    //    replays the stored fault envelope without re-executing the adapter and must ALSO record
    //    `operation.outcome = "failed"` on both span and log event.
    let replayed = adapter
        .call(
            &run,
            step,
            "tel-missing-fault",
            mcp::READ_RANGE,
            "1",
            missing_args.as_bytes(),
        )
        .await;
    let StepResult::ToolOutput(replayed_env) = replayed else {
        panic!("expected StepResult::ToolOutput for replayed failed tool op");
    };
    assert_eq!(replayed_env, expected_envelope);

    let attempts_after_replay: i32 = sqlx::query_scalar(
        "SELECT dispatched_attempts FROM openmettle.operations WHERE id = $1::uuid",
    )
    .bind(&op_id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        attempts_after_replay, 1,
        "replaying an observed failed tool call must not dispatch a second attempt"
    );

    let st = recorder.state.lock().unwrap();
    assert_eq!(st.closed_spans.len(), 2, "{:?}", st.closed_spans);
    assert_eq!(st.events.len(), 2, "{:?}", st.events);
    for idx in 0..2 {
        let span = &st.closed_spans[idx];
        assert_eq!(
            span.get("run_id").map(String::as_str),
            Some(claim.run_id.as_str())
        );
        assert_eq!(
            span.get("lease_id").map(String::as_str),
            Some(expected_lease_id.as_str())
        );
        assert_eq!(
            span.get("operation_id").map(String::as_str),
            Some(op_id.as_str())
        );
        assert_eq!(span.get("operation.kind").map(String::as_str), Some("tool"));
        assert_eq!(
            span.get("operation.outcome").map(String::as_str),
            Some("failed"),
            "call #{idx} span must record operation.outcome=failed, got {span:?}"
        );
        assert!(
            !span.values().any(|v| v.contains(&claim.claim_token)),
            "claim_token leaked into worker.operation span"
        );

        let (level, ev) = &st.events[idx];
        assert_eq!(level, "WARN");
        assert_eq!(
            ev.get("run_id").map(String::as_str),
            Some(claim.run_id.as_str())
        );
        assert_eq!(
            ev.get("lease_id").map(String::as_str),
            Some(expected_lease_id.as_str())
        );
        assert_eq!(
            ev.get("operation_id").map(String::as_str),
            Some(op_id.as_str())
        );
        assert_eq!(ev.get("operation.kind").map(String::as_str), Some("tool"));
        assert_eq!(
            ev.get("operation.outcome").map(String::as_str),
            Some("failed"),
            "call #{idx} event must record operation.outcome=failed, got {ev:?}"
        );
        assert!(
            !ev.values().any(|v| v.contains(&claim.claim_token)),
            "claim_token leaked into worker.operation.completed event"
        );
    }
}
