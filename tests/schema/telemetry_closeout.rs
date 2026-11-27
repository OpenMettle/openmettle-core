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
    actor: &Account,
    session: &EffectSession,
    key: &str,
) -> ClaimedRun {
    let conv = chat(db, scope, "personal", actor).await;
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
    let claimed = admit_approval_run(&db, &alice_scope, &alice, &alice_session, "qa-claim").await;
    assert_eq!(queue_age_delta(before), [1, 0, 0, 0]);
    assert!(
        metrics::global()
            .run_queue_age_snapshot(RunQueueAgeOutcome::Claimed)
            .1
            >= sum_before
    );

    // 2. Parking for human approval, approving, and re-claiming increments `resumed` by 1.
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
    let resumed = queue::claim_next(&mut worker(&db).await, &OPEN, &LEASES)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resumed.run_id, claimed.run_id);
    assert_eq!(queue_age_delta(before_approve), [0, 1, 0, 0]);

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

    // 4. Expiring a queued run increments `expired` by 1.
    let exp_req = request(&db, &alice_scope, "personal", &alice, "qa-expire").await;
    let exp_id = admitted(&db, &exp_req).await;
    owner_exec(
        &db,
        "UPDATE openmettle.runs SET queue_expires_at = created_at + interval '1 microsecond'
          WHERE id = $1::uuid",
        &exp_id,
    )
    .await;
    let before_expire = queue_age_counts();
    let expired = queue::expire_queued(&mut worker(&db).await, 10)
        .await
        .unwrap();
    assert_eq!(expired, vec![exp_id]);
    assert_eq!(queue_age_delta(before_expire), [0, 0, 0, 1]);

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
    let deny_claim =
        admit_approval_run(&db, &alice_scope, &alice, &alice_session, "qa-wait-deny").await;
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
    // `cancelled` queue age (+1).
    let approved_cancel_claim = admit_approval_run(
        &db,
        &alice_scope,
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
    let before_resumable_cancel = queue_age_counts();
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
    // has already returned a `queue_age_s` row to Rust. No metric may be recorded!
    let rb_req = request(&db, &alice_scope, "personal", &alice, "qa-rollback").await;
    let rb_id = admitted(&db, &rb_req).await;
    owner
        .execute(
            "CREATE FUNCTION openmettle.fail_commit_for_test() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN
                 RAISE EXCEPTION 'synthetic commit failure';
             END;
             $$;
             CREATE CONSTRAINT TRIGGER fail_cancel_commit_test
                 AFTER UPDATE OF state ON openmettle.runs
                 DEFERRABLE INITIALLY DEFERRED
                 FOR EACH ROW
                 WHEN (NEW.state = 'cancelled')
                 EXECUTE FUNCTION openmettle.fail_commit_for_test();",
        )
        .await
        .unwrap();
    let before_rollback = queue_age_counts();
    let rb_err =
        queue::cancel_run(&mut api(&db).await, &alice_principal, &alice_scope, &rb_id).await;
    assert!(
        rb_err.is_err(),
        "expected deferred trigger to fail COMMIT, got {rb_err:?}"
    );
    assert_eq!(queue_age_delta(before_rollback), [0, 0, 0, 0]);
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
