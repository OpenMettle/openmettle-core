//! ADR 0032 (V1-10 PR2) evidence: durable run admission, the fair claim, caller cancellation,
//! queue expiry, terminal events and the version-19 privileges. Admission and cancellation run
//! as `openmettle_api`, claims as `openmettle_worker`; the owner role seeds fixtures and reads
//! results. Every value is synthetic. Isolated CI PostgreSQL 18 only.
use super::authz_runs::{cancelled_once, chat, personal_of, terminal_events};
use super::authz_store::{
    Account, FUTURE, NOW, PROVIDER, UNKNOWN, account, applied, conflict, ctx, denied, make_admin,
    principal, providers, wait_for_lock_waiters,
};
use super::*;
use openmettle_core::{
    authz::{
        DenialReason, Grantee, Principal, ProjectRole,
        projects::{self, ProjectSettingsInput},
        runs::{
            self as queue, Admission, AdmissionLimits, CancelOutcome, ClaimLimits, ClaimedRun,
            RunAdmission, RunLimit, RunRecheckOutcome, RunRecheckRequest,
        },
        store::{self, KEY_REUSED, StoreError},
    },
    runs::{self, RunInput, WriteTransaction},
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

const LIMITS: AdmissionLimits = AdmissionLimits {
    live_per_actor: 1000,
    live_per_scope: 10_000,
    queued_in_instance: 10_000,
    queue_timeout: Duration::from_secs(3600),
    round_cap: 50,
};
const OPEN: ClaimLimits = ClaimLimits {
    executing_per_actor: 1024,
    executing_per_scope: 1024,
};
const ARCHIVED: &str = "project is archived";
const EXPIRED: (&str, &[u8]) = ("openmettle.run-expired", b"{}");
const NEW_COLUMNS: &str =
    "- 'actor_approval_id' - 'round_limit' - 'queue_expires_at' - 'claim_token' - 'claimed_at'";

/// One admission request: a conversation, its branch and input message, and a key.
#[derive(Clone)]
struct Request {
    scope: String,
    actor: Account,
    conversation: String,
    branch: String,
    message: String,
    key: String,
    input: Vec<u8>,
}

impl Request {
    fn input(&self) -> RunInput<'_> {
        RunInput {
            scope: &self.scope,
            actor: &self.actor.user,
            conversation: &self.conversation,
            branch: &self.branch,
            message: &self.message,
            key: &self.key,
            format: "openmettle.synthetic-run",
            version: 1,
            input: &self.input,
            config: b"{}",
        }
    }

    /// The same conversation, branch and message under another key.
    fn keyed(&self, key: &str) -> Self {
        Self {
            key: key.to_owned(),
            ..self.clone()
        }
    }
}

async fn api(db: &TestDb) -> PgConnection {
    connect(&db.0, API).await
}

async fn worker(db: &TestDb) -> PgConnection {
    connect(&db.0, WORKER).await
}

/// A request on a new conversation, branch and input message of `actor` in `scope`.
async fn request(db: &TestDb, scope: &str, kind: &str, actor: &Account, key: &str) -> Request {
    let conversation = chat(db, scope, kind, actor).await;
    let mut c = api(db).await;
    let message = message(&mut c, scope, &conversation, None).await.unwrap();
    let branch: String = sqlx::query_scalar(
        "INSERT INTO openmettle.conversation_branches (scope_id, conversation_id)
         VALUES ($1::uuid, $2::uuid) RETURNING id::text",
    )
    .bind(scope)
    .bind(&conversation)
    .fetch_one(&mut c)
    .await
    .unwrap();
    Request {
        scope: scope.to_owned(),
        actor: actor.clone(),
        conversation,
        branch,
        message,
        key: key.to_owned(),
        input: b"synthetic input".to_vec(),
    }
}

/// Admit in one API transaction, committed only when admitted.
async fn admit_on(
    c: &mut PgConnection,
    r: &Request,
    limits: &AdmissionLimits,
    rounds: Option<i64>,
) -> Result<Admission, StoreError> {
    let mut tx = WriteTransaction::begin(c).await.unwrap();
    let request = RunAdmission {
        input: r.input(),
        actor_approval_id: &r.actor.approval,
        capabilities: &[],
        requested_rounds: rounds,
        now_ms: NOW,
    };
    let outcome = queue::admit_run(&mut tx, &request, limits).await;
    if matches!(outcome, Ok(Admission::Admitted { .. })) {
        tx.commit().await.unwrap();
    } else {
        tx.rollback().await.unwrap();
    }
    outcome
}

async fn admit(db: &TestDb, r: &Request) -> Result<Admission, StoreError> {
    admit_on(&mut api(db).await, r, &LIMITS, None).await
}

async fn admitted(db: &TestDb, r: &Request) -> String {
    match admit(db, r).await {
        Ok(Admission::Admitted { run_id, .. }) => run_id,
        other => panic!("expected an admission, got {other:?}"),
    }
}

/// Admit every request on its own connection, released together by a barrier.
async fn admit_together(
    db: &TestDb,
    requests: Vec<Request>,
    limits: AdmissionLimits,
) -> Vec<Result<Admission, StoreError>> {
    let barrier = Arc::new(tokio::sync::Barrier::new(requests.len()));
    let tasks: Vec<_> = requests
        .into_iter()
        .map(|r| {
            let barrier = barrier.clone();
            let options = role_options(&db.0, API);
            tokio::spawn(async move {
                let mut c = PgConnection::connect_with(&options).await.unwrap();
                barrier.wait().await;
                admit_on(&mut c, &r, &limits, None).await
            })
        })
        .collect();
    let mut outcomes = Vec::new();
    for task in tasks {
        outcomes.push(task.await.unwrap());
    }
    outcomes
}

/// (admitted, refused) of a batch in which every refusal must be `limit`.
fn tally(outcomes: &[Result<Admission, StoreError>], limit: RunLimit) -> (usize, usize) {
    let mut result = (0, 0);
    for outcome in outcomes {
        match outcome {
            Ok(Admission::Admitted { .. }) => result.0 += 1,
            Ok(Admission::Refused(refused)) if *refused == limit => result.1 += 1,
            other => panic!("expected an admission or {limit:?}, got {other:?}"),
        }
    }
    result
}

/// A run written by bare `create_run`, without admission columns.
async fn bare_run(db: &TestDb, r: &Request) -> String {
    let mut c = api(db).await;
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    let run = runs::create_run(&mut tx, &r.input()).await.unwrap();
    tx.commit().await.unwrap();
    run
}

/// (project ID, scope ID) of a project created by `owner` through the PR4a store.
async fn new_project(db: &TestDb, owner: &Account, key: &str) -> (String, String) {
    let defaults = json!({});
    let settings = ProjectSettingsInput {
        name: "Synthetic project",
        instructions: "",
        defaults: &defaults,
    };
    let project =
        applied(projects::create_project(&mut api(db).await, &ctx(owner, key), &settings).await);
    let scope =
        sqlx::query_scalar("SELECT scope_id::text FROM openmettle.projects WHERE id = $1::uuid")
            .bind(&project)
            .fetch_one(&mut connect(&db.0, OWNER).await)
            .await
            .unwrap();
    (project, scope)
}

async fn editor(db: &TestDb, owner: &Account, project: &str, member: &Account) {
    let key = format!("member-{}", member.user);
    let grantee = Grantee::User(member.user.clone());
    applied(
        projects::set_project_member_role(
            &mut api(db).await,
            &ctx(owner, &key),
            project,
            &grantee,
            ProjectRole::Editor,
        )
        .await,
    );
}

async fn claim_with(db: &TestDb, limits: &ClaimLimits) -> Option<ClaimedRun> {
    queue::claim_next(&mut worker(db).await, limits)
        .await
        .unwrap()
}

async fn claim(db: &TestDb) -> Option<ClaimedRun> {
    claim_with(db, &OPEN).await
}

async fn expire(db: &TestDb, limit: u32) -> Vec<String> {
    queue::expire_queued(&mut worker(db).await, limit)
        .await
        .unwrap()
}

async fn owner_exec(db: &TestDb, sql: &str, run_id: &str) {
    sqlx::query(AssertSqlSafe(sql.to_owned()))
        .bind(run_id)
        .execute(&mut connect(&db.0, OWNER).await)
        .await
        .unwrap();
}

async fn set_state(db: &TestDb, run_id: &str, state: &str) {
    let wait = (state == "waiting").then_some("synthetic-wait");
    sqlx::query("UPDATE openmettle.runs SET state = $2, wait_reason = $3 WHERE id = $1::uuid")
        .bind(run_id)
        .bind(state)
        .bind(wait)
        .execute(&mut connect(&db.0, OWNER).await)
        .await
        .unwrap();
}

/// Move the run's queue deadline into the past (it stays after `created_at`).
async fn expire_now(db: &TestDb, run_id: &str) {
    let sql = "UPDATE openmettle.runs SET queue_expires_at = created_at + interval '1 microsecond'
                WHERE id = $1::uuid";
    owner_exec(db, sql, run_id).await;
}

async fn state(db: &TestDb, run_id: &str) -> String {
    sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
        .bind(run_id)
        .fetch_one(&mut connect(&db.0, OWNER).await)
        .await
        .unwrap()
}

async fn scalar(db: &TestDb, sql: &str) -> i64 {
    sqlx::query_scalar(AssertSqlSafe(sql.to_owned()))
        .fetch_one(&mut connect(&db.0, OWNER).await)
        .await
        .unwrap()
}

/// Every event of the run: (sequence, append key, format, payload).
async fn events(db: &TestDb, run_id: &str) -> Vec<(i64, String, String, Vec<u8>)> {
    sqlx::query_as(
        "SELECT sequence, append_key, format, payload FROM openmettle.run_events
          WHERE run_id = $1::uuid ORDER BY sequence",
    )
    .bind(run_id)
    .fetch_all(&mut connect(&db.0, OWNER).await)
    .await
    .unwrap()
}

fn created() -> (i64, String, String, Vec<u8>) {
    (
        1,
        "run-created".into(),
        "openmettle.run-created".into(),
        Vec::new(),
    )
}

fn claimed_event(claim: &ClaimedRun) -> (i64, String, String, Vec<u8>) {
    (
        2,
        format!("claim:{}", claim.claim_token),
        "openmettle.run-claimed".into(),
        b"{}".to_vec(),
    )
}

async fn expired_once(db: &TestDb, run_id: &str) {
    assert_eq!(state(db, run_id).await, "failed");
    assert_eq!(
        terminal_events(db, run_id).await,
        [(EXPIRED.0.to_owned(), EXPIRED.1.to_vec())]
    );
}

async fn recheck(db: &TestDb, claim: &ClaimedRun) -> RunRecheckOutcome {
    let request = RunRecheckRequest {
        scope_id: &claim.scope_id,
        run_id: &claim.run_id,
        actor_approval_id: &claim.actor_approval_id,
        capabilities: &[],
        extra_target: None,
        now_ms: NOW,
    };
    queue::recheck_run(&mut worker(db).await, &request)
        .await
        .unwrap()
}

// --- admission ---------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn identical_admissions_admit_once_and_replays_keep_the_original_admission() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let (project, scope) = new_project(&db, &alice, "create").await;
    let r = request(&db, &scope, "project", &alice, "turn-1").await;

    // Concurrent identical admissions: one run and one run-created event.
    let outcomes = admit_together(&db, vec![r.clone(); 6], LIMITS).await;
    let mut ids = BTreeSet::new();
    let mut fresh = 0;
    for outcome in outcomes {
        match outcome.unwrap() {
            Admission::Admitted {
                run_id,
                round_limit,
            } => {
                assert_eq!(round_limit, 50);
                fresh += 1;
                ids.insert(run_id);
            }
            Admission::Replayed {
                run_id,
                state,
                round_limit,
            } => {
                assert_eq!((state.as_str(), round_limit), ("queued", Some(50)));
                ids.insert(run_id);
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!((fresh, ids.len()), (1, 1));
    let run = ids.pop_first().unwrap();
    assert_eq!(scalar(&db, "SELECT count(*) FROM openmettle.runs").await, 1);
    assert_eq!(events(&db, &run).await, [created()]);
    // The admission decisions are stored once with the run, on the database clock.
    let (approval, rounds, deadline): (String, i32, bool) = sqlx::query_as(
        "SELECT actor_approval_id::text, round_limit,
                queue_expires_at - created_at BETWEEN interval '1 hour' AND interval '1 hour 1 minute'
           FROM openmettle.runs WHERE id = $1::uuid",
    )
    .bind(&run)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        (approval, rounds, deadline),
        (alice.approval.clone(), 50, true)
    );

    // The replay lookup V1-07 calls before inserting a new input message.
    let found = queue::find_run(&mut api(&db).await, &scope, &alice.user, "turn-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            found.run_id.as_str(),
            found.state.as_str(),
            found.round_limit
        ),
        (run.as_str(), "queued", Some(50))
    );
    assert_eq!(found.input_message_id, r.message);
    assert!(found.matches(&r.input()));
    let changed = Request {
        input: b"changed input".to_vec(),
        ..r.clone()
    };
    assert!(!found.matches(&changed.input()));
    let others = queue::find_run(&mut api(&db).await, &scope, &bob.user, "turn-1").await;
    assert!(others.unwrap().is_none());

    // A changed request under the same key conflicts and writes nothing.
    assert_eq!(conflict(admit(&db, &changed).await), KEY_REUSED);
    // Requested rounds are capped; below 1 is refused before any write.
    let capped = r.keyed("turn-2");
    let outcome = admit_on(&mut api(&db).await, &capped, &LIMITS, Some(80)).await;
    let Admission::Admitted {
        run_id: capped_run,
        round_limit: 50,
    } = outcome.unwrap()
    else {
        panic!("expected the cap");
    };
    let asked = r.keyed("turn-3");
    let outcome = admit_on(&mut api(&db).await, &asked, &LIMITS, Some(7)).await;
    let Admission::Admitted {
        run_id: asked_run,
        round_limit: 7,
    } = outcome.unwrap()
    else {
        panic!("expected the requested rounds");
    };
    let zero = admit_on(&mut api(&db).await, &r.keyed("turn-4"), &LIMITS, Some(0)).await;
    assert!(matches!(zero, Err(StoreError::InvalidInput("round_limit"))));
    // A retry after a policy, cap or limit change replays the original admission.
    let strict = AdmissionLimits {
        live_per_actor: 1,
        live_per_scope: 1,
        queued_in_instance: 1,
        round_cap: 3,
        ..LIMITS
    };
    for (retry, id, rounds) in [(&r, &run, 50), (&asked, &asked_run, 7)] {
        let replay = admit_on(&mut api(&db).await, retry, &strict, Some(2)).await;
        assert_eq!(
            replay.unwrap(),
            Admission::Replayed {
                run_id: id.clone(),
                state: "queued".into(),
                round_limit: Some(rounds),
            }
        );
    }
    assert_eq!(scalar(&db, "SELECT count(*) FROM openmettle.runs").await, 3);

    // Archive cancels every run with one terminal event; a replay still returns the original.
    let archived =
        projects::archive_project(&mut api(&db).await, &ctx(&alice, "archive"), &project).await;
    applied(archived);
    for id in [&run, &capped_run, &asked_run] {
        assert_eq!(state(&db, id).await, "cancelled");
        cancelled_once(&db, id, "revoked").await;
    }
    assert_eq!(
        admit(&db, &r).await.unwrap(),
        Admission::Replayed {
            run_id: run.clone(),
            state: "cancelled".into(),
            round_limit: Some(50),
        }
    );
    // A new request in the archived project is refused after authorization.
    assert_eq!(conflict(admit(&db, &r.keyed("turn-5")).await), ARCHIVED);
    assert_eq!(scalar(&db, "SELECT count(*) FROM openmettle.runs").await, 3);
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn concurrent_admissions_admit_exactly_the_actor_scope_and_queue_limits() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let carol = account(&mut owner, PROVIDER, true, FUTURE).await;
    let dave = account(&mut owner, PROVIDER, true, FUTURE).await;
    let alice_personal = personal_of(&db, &alice).await;
    let (_, first_scope) = new_project(&db, &alice, "first").await;
    let (second, second_scope) = new_project(&db, &alice, "second").await;
    for member in [&bob, &carol, &dave] {
        editor(&db, &alice, &second, member).await;
    }

    // The actor limit holds across two scopes: both paths serialize on alice's user row.
    let mut requests = Vec::new();
    for i in 0..8 {
        let (scope, kind) = if i % 2 == 0 {
            (&alice_personal, "personal")
        } else {
            (&first_scope, "project")
        };
        requests.push(request(&db, scope, kind, &alice, &format!("actor-{i}")).await);
    }
    let actor_limit = AdmissionLimits {
        live_per_actor: 3,
        ..LIMITS
    };
    let outcomes = admit_together(&db, requests, actor_limit).await;
    assert_eq!(tally(&outcomes, RunLimit::ActorLimit), (3, 5));
    let alice_live = format!(
        "SELECT count(*) FROM openmettle.runs WHERE actor_user_id = '{}'
           AND state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')",
        alice.user
    );
    assert_eq!(scalar(&db, &alice_live).await, 3);

    // The scope limit holds across four actors in one project.
    let mut requests = Vec::new();
    for (i, actor) in [&alice, &bob, &carol, &dave].into_iter().enumerate() {
        for j in 0..2 {
            let key = format!("scope-{i}-{j}");
            requests.push(request(&db, &second_scope, "project", actor, &key).await);
        }
    }
    let scope_limit = AdmissionLimits {
        live_per_scope: 3,
        ..LIMITS
    };
    let outcomes = admit_together(&db, requests, scope_limit).await;
    assert_eq!(tally(&outcomes, RunLimit::ScopeLimit), (3, 5));
    let scope_live = format!(
        "SELECT count(*) FROM openmettle.runs WHERE scope_id = '{second_scope}'
           AND state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')"
    );
    assert_eq!(scalar(&db, &scope_live).await, 3);
    let (runs_before, events_before) = (
        scalar(&db, "SELECT count(*) FROM openmettle.runs").await,
        scalar(&db, "SELECT count(*) FROM openmettle.run_events").await,
    );

    // A waiting run holds no worker but is live, so it still counts against the actor: with the
    // limit at alice's live count, waiting leaves her refused.
    let live = scalar(&db, &alice_live).await;
    let actor_limit = AdmissionLimits {
        live_per_actor: u32::try_from(live).unwrap(),
        ..LIMITS
    };
    let (queued, queued_scope): (String, String) = sqlx::query_as(
        "SELECT id::text, scope_id::text FROM openmettle.runs
          WHERE actor_user_id = $1::uuid ORDER BY id LIMIT 1",
    )
    .bind(&alice.user)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let waiting: String = sqlx::query_scalar(
        "SELECT id::text FROM openmettle.runs WHERE actor_user_id = $1::uuid AND id <> $2::uuid
          ORDER BY id LIMIT 1",
    )
    .bind(&alice.user)
    .bind(&queued)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    set_state(&db, &waiting, "waiting").await;
    let next = request(&db, &alice_personal, "personal", &alice, "after-limit").await;
    let refused = admit_on(&mut api(&db).await, &next, &actor_limit, None).await;
    assert_eq!(refused.unwrap(), Admission::Refused(RunLimit::ActorLimit));
    // Refusals wrote nothing.
    assert_eq!(
        (
            scalar(&db, "SELECT count(*) FROM openmettle.runs").await,
            scalar(&db, "SELECT count(*) FROM openmettle.run_events").await
        ),
        (runs_before, events_before)
    );
    // A run that finishes frees its slot.
    let alice_principal = principal(&db, &alice).await;
    let cancelled = queue::cancel_run(
        &mut api(&db).await,
        &alice_principal,
        &queued_scope,
        &queued,
    )
    .await;
    assert_eq!(cancelled.unwrap(), CancelOutcome::Cancelled);
    let admitted = admit_on(&mut api(&db).await, &next, &actor_limit, None).await;
    assert!(matches!(admitted, Ok(Admission::Admitted { .. })));

    // The instance queue: refused at the configured number of queued runs, wherever they are.
    let queued = scalar(
        &db,
        "SELECT count(*) FROM openmettle.runs WHERE state = 'queued'",
    )
    .await;
    let dave_personal = personal_of(&db, &dave).await;
    let fresh = request(&db, &dave_personal, "personal", &dave, "queue").await;
    let full = AdmissionLimits {
        queued_in_instance: u32::try_from(queued).unwrap(),
        ..LIMITS
    };
    let refused = admit_on(&mut api(&db).await, &fresh, &full, None).await;
    assert_eq!(refused.unwrap(), Admission::Refused(RunLimit::QueueFull));
    let room = AdmissionLimits {
        queued_in_instance: full.queued_in_instance + 1,
        ..LIMITS
    };
    let admitted = admit_on(&mut api(&db).await, &fresh, &room, None).await;
    assert!(matches!(admitted, Ok(Admission::Admitted { .. })));
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn admission_racing_archive_delete_or_disable_never_leaves_a_live_run() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;

    async fn revoke(
        c: &mut PgConnection,
        path: &str,
        (owner, admin): (&Account, &Account),
        (project, runner): (&str, &Account),
        key: &str,
    ) {
        let outcome = match path {
            "archive" => projects::archive_project(c, &ctx(owner, key), project).await,
            "delete" => projects::delete_project(c, &ctx(owner, key), project).await,
            _ => store::disable_user(c, &ctx(admin, key), &runner.user).await,
        };
        applied(outcome);
    }

    fn refusal(path: &str, outcome: Result<Admission, StoreError>) {
        match path {
            "archive" => assert_eq!(conflict(outcome), ARCHIVED),
            "delete" => assert_eq!(denied(outcome), DenialReason::NotFound),
            _ => assert_eq!(denied(outcome), DenialReason::InactivePrincipal),
        }
    }

    async fn nothing_live(db: &TestDb, path: &str, scope: &str, runner: &Account) {
        let column = if path == "disable" {
            ("actor_user_id", runner.user.as_str())
        } else {
            ("scope_id", scope)
        };
        let ids: Vec<(String, String)> = sqlx::query_as(AssertSqlSafe(format!(
            "SELECT id::text, state FROM openmettle.runs WHERE {} = $1::uuid ORDER BY id",
            column.0
        )))
        .bind(column.1)
        .fetch_all(&mut connect(&db.0, OWNER).await)
        .await
        .unwrap();
        for (id, state) in ids {
            assert_eq!(state, "cancelled", "{path}");
            cancelled_once(db, &id, "revoked").await;
        }
    }

    for path in ["archive", "delete", "disable"] {
        // Deterministic order: an uncommitted admission holds the project row (or the runner's
        // user row); the revocation waits for it, then cancels the run it admitted.
        let runner = account(&mut owner, PROVIDER, true, FUTURE).await;
        let (project, scope) = new_project(&db, &alice, &format!("{path}-held-project")).await;
        editor(&db, &alice, &project, &runner).await;
        let r = request(&db, &scope, "project", &runner, "held").await;
        let mut c = api(&db).await;
        let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
        let admission = RunAdmission {
            input: r.input(),
            actor_approval_id: &runner.approval,
            capabilities: &[],
            requested_rounds: None,
            now_ms: NOW,
        };
        let Admission::Admitted { run_id, .. } = queue::admit_run(&mut tx, &admission, &LIMITS)
            .await
            .unwrap()
        else {
            panic!("expected an admission");
        };
        let mut revoker = api(&db).await;
        // Distinct from the creation key: an audited request_key is unique per actor.
        let key = format!("{path}-held-revoke");
        let revoking = revoke(
            &mut revoker,
            path,
            (&alice, &admin),
            (&project, &runner),
            &key,
        );
        let commit = async {
            wait_for_lock_waiters(&db, 1).await;
            tx.commit().await.unwrap();
        };
        tokio::join!(revoking, commit);
        assert_eq!(state(&db, &run_id).await, "cancelled", "{path}");
        cancelled_once(&db, &run_id, "revoked").await;
        // Afterwards a new admission is refused and leaves nothing.
        refusal(path, admit(&db, &r.keyed("after")).await);
        nothing_live(&db, path, &scope, &runner).await;

        // Unordered races: whichever commits first, no run stays live.
        for round in 0..4 {
            let runner = account(&mut owner, PROVIDER, true, FUTURE).await;
            let (project, scope) = new_project(&db, &alice, &format!("{path}-{round}")).await;
            editor(&db, &alice, &project, &runner).await;
            let mut requests = Vec::new();
            for i in 0..3 {
                requests.push(request(&db, &scope, "project", &runner, &format!("r{i}")).await);
            }
            let (mut a, mut b, mut c, mut d) = (
                api(&db).await,
                api(&db).await,
                api(&db).await,
                api(&db).await,
            );
            let key = format!("{path}-race-{round}");
            let (x, y, z, ()) = tokio::join!(
                admit_on(&mut a, &requests[0], &LIMITS, None),
                admit_on(&mut b, &requests[1], &LIMITS, None),
                admit_on(&mut c, &requests[2], &LIMITS, None),
                revoke(&mut d, path, (&alice, &admin), (&project, &runner), &key),
            );
            for outcome in [x, y, z] {
                if !matches!(outcome, Ok(Admission::Admitted { .. })) {
                    refusal(path, outcome);
                }
            }
            nothing_live(&db, path, &scope, &runner).await;
        }
    }
}

// --- caller cancellation and expiry ------------------------------------------------------------

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn callers_cancel_only_their_own_queued_runs_exactly_once() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let scope = personal_of(&db, &alice).await;
    let bob_scope = personal_of(&db, &bob).await;
    let r = request(&db, &scope, "personal", &alice, "cancel").await;
    let run = admitted(&db, &r).await;
    let alice_p = principal(&db, &alice).await;
    let bob_p = principal(&db, &bob).await;
    let cancel = async |p: &Principal, scope: &str, run: &str| {
        queue::cancel_run(&mut api(&db).await, p, scope, run).await
    };

    // Another actor's run, a missing run and a run named in the wrong scope are concealed;
    // an inactive principal is refused first.
    for (p, s, id) in [
        (&bob_p, scope.as_str(), run.as_str()),
        (&alice_p, scope.as_str(), UNKNOWN),
        (&alice_p, bob_scope.as_str(), run.as_str()),
    ] {
        assert_eq!(denied(cancel(p, s, id).await), DenialReason::NotFound);
    }
    let inactive = Principal {
        account_active: false,
        ..alice_p.clone()
    };
    let refused = cancel(&inactive, &scope, &run).await;
    assert_eq!(denied(refused), DenialReason::InactivePrincipal);
    assert_eq!(state(&db, &run).await, "queued");
    assert!(terminal_events(&db, &run).await.is_empty());

    // Queued becomes cancelled once; a repeat reports it terminal and appends nothing.
    assert_eq!(
        cancel(&alice_p, &scope, &run).await.unwrap(),
        CancelOutcome::Cancelled
    );
    assert_eq!(state(&db, &run).await, "cancelled");
    cancelled_once(&db, &run, "requested").await;
    assert_eq!(
        cancel(&alice_p, &scope, &run).await.unwrap(),
        CancelOutcome::Terminal {
            state: "cancelled".into()
        }
    );
    cancelled_once(&db, &run, "requested").await;
    assert_eq!(events(&db, &run).await.len(), 2);

    // Started work is unchanged (cooperative cancellation is V1-11); terminal runs too.
    for (i, current) in ["running", "waiting", "cancelling", "reconciling"]
        .into_iter()
        .enumerate()
    {
        let id = admitted(&db, &r.keyed(&format!("started-{i}"))).await;
        set_state(&db, &id, current).await;
        assert_eq!(
            cancel(&alice_p, &scope, &id).await.unwrap(),
            CancelOutcome::Executing {
                state: current.into()
            }
        );
        assert_eq!(state(&db, &id).await, current);
        assert!(terminal_events(&db, &id).await.is_empty());
    }
    for (i, ended) in ["succeeded", "failed", "interrupted"]
        .into_iter()
        .enumerate()
    {
        let id = admitted(&db, &r.keyed(&format!("ended-{i}"))).await;
        set_state(&db, &id, ended).await;
        assert_eq!(
            cancel(&alice_p, &scope, &id).await.unwrap(),
            CancelOutcome::Terminal {
                state: ended.into()
            }
        );
        assert!(terminal_events(&db, &id).await.is_empty());
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn expired_and_unadmitted_runs_are_never_claimed_and_fail_exactly_once() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let scope = personal_of(&db, &alice).await;
    let r = request(&db, &scope, "personal", &alice, "expired").await;

    // An admitted run past its deadline and a bare `create_run` row are never claimed.
    let late = admitted(&db, &r).await;
    expire_now(&db, &late).await;
    let bare = bare_run(&db, &r.keyed("bare")).await;
    assert_eq!(claim(&db).await, None);
    assert_eq!(
        (state(&db, &late).await, state(&db, &bare).await),
        ("queued".into(), "queued".into())
    );
    // The sweep fails both with one terminal event each; a second sweep finds nothing.
    let mut due = vec![late.clone(), bare.clone()];
    due.sort();
    assert_eq!(expire(&db, 1000).await, due);
    for id in &due {
        expired_once(&db, id).await;
    }
    assert_eq!(expire(&db, 1000).await, Vec::<String>::new());
    for id in &due {
        expired_once(&db, id).await;
    }

    // A run within its deadline is untouched by the sweep and claimable.
    let live = admitted(&db, &r.keyed("live")).await;
    assert!(expire(&db, 1000).await.is_empty());
    assert_eq!(claim(&db).await.unwrap().run_id, live);

    // The sweep honours its bound in ascending ID order; the API role may run it too.
    let mut late = Vec::new();
    for i in 0..3 {
        let id = admitted(&db, &r.keyed(&format!("late-{i}"))).await;
        expire_now(&db, &id).await;
        late.push(id);
    }
    late.sort();
    assert_eq!(expire(&db, 2).await, late[..2].to_vec());
    let swept = queue::expire_queued(&mut api(&db).await, 1).await.unwrap();
    assert_eq!(swept, late[2..].to_vec());
    for id in &late {
        expired_once(&db, id).await;
    }
    for bad in [0, 1001] {
        let refused = queue::expire_queued(&mut worker(&db).await, bad).await;
        assert!(matches!(refused, Err(StoreError::InvalidInput("limit"))));
    }

    // Claim and sweep racing on the deadline: never both, and exactly one outcome event.
    for round in 0..8u64 {
        let id = admitted(&db, &r.keyed(&format!("race-{round}"))).await;
        let sql = "UPDATE openmettle.runs SET queue_expires_at = clock_timestamp() + interval '20 milliseconds'
                    WHERE id = $1::uuid";
        owner_exec(&db, sql, &id).await;
        tokio::time::sleep(Duration::from_millis(14 + round)).await;
        let (mut w1, mut w2) = (worker(&db).await, worker(&db).await);
        let (claimed, swept) = tokio::join!(
            queue::claim_next(&mut w1, &OPEN),
            queue::expire_queued(&mut w2, 10),
        );
        let claimed = claimed.unwrap();
        let mut swept = swept.unwrap();
        if claimed.is_none() && swept.is_empty() {
            // Both looked before (sweep) and after (claim) the deadline; it is due now.
            tokio::time::sleep(Duration::from_millis(25)).await;
            swept = expire(&db, 10).await;
        }
        match claimed {
            Some(claim) => {
                assert_eq!(claim.run_id, id, "round {round}");
                assert!(swept.is_empty(), "round {round}");
                assert_eq!(state(&db, &id).await, "running");
                assert_eq!(events(&db, &id).await, [created(), claimed_event(&claim)]);
            }
            None => {
                assert_eq!(swept, [id.as_str()], "round {round}");
                expired_once(&db, &id).await;
                assert_eq!(events(&db, &id).await.len(), 2);
            }
        }
    }
}

// --- the fair claim ----------------------------------------------------------------------------

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn concurrent_claimers_never_share_a_run_or_exceed_the_executing_limits() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let a = account(&mut owner, PROVIDER, true, FUTURE).await;
    let b = account(&mut owner, PROVIDER, true, FUTURE).await;
    let c = account(&mut owner, PROVIDER, true, FUTURE).await;
    let a_scope = personal_of(&db, &a).await;
    let (project, scope) = new_project(&db, &a, "create").await;
    editor(&db, &a, &project, &b).await;
    editor(&db, &a, &project, &c).await;
    let mut approvals = BTreeMap::new();
    for i in 0..4 {
        for (actor, s, kind) in [
            (&a, &a_scope, "personal"),
            (&b, &scope, "project"),
            (&c, &scope, "project"),
        ] {
            let r = request(&db, s, kind, actor, &format!("run-{i}")).await;
            approvals.insert(admitted(&db, &r).await, actor.approval.clone());
        }
    }
    let limits = ClaimLimits {
        executing_per_actor: 2,
        executing_per_scope: 3,
    };

    // Eight claimers, each claiming until nothing qualifies.
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let barrier = barrier.clone();
            let options = role_options(&db.0, WORKER);
            tokio::spawn(async move {
                let mut w = PgConnection::connect_with(&options).await.unwrap();
                barrier.wait().await;
                let mut claims = Vec::new();
                while let Some(claim) = queue::claim_next(&mut w, &limits).await.unwrap() {
                    claims.push(claim);
                }
                claims
            })
        })
        .collect();
    let mut claims = Vec::new();
    for task in tasks {
        claims.extend(task.await.unwrap());
    }
    // a: 2 of its 4 (its scope allows 3); the project: 3 of 8, at most 2 per actor.
    let ids: BTreeSet<&str> = claims.iter().map(|c| c.run_id.as_str()).collect();
    assert_eq!((claims.len(), ids.len()), (5, 5));
    let per_actor: Vec<(String, i64)> = sqlx::query_as(
        "SELECT actor_user_id::text, count(*) FROM openmettle.runs WHERE state = 'running'
          GROUP BY actor_user_id ORDER BY 1",
    )
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert!(per_actor.iter().all(|(_, n)| *n <= 2), "{per_actor:?}");
    let in_project = claims.iter().filter(|x| x.scope_id == scope).count();
    assert_eq!((claims.len() - in_project, in_project), (2, 3));
    for claim in &claims {
        assert_eq!(claim.actor_approval_id, approvals[&claim.run_id]);
        assert_eq!(claim.round_limit, 50);
        assert_eq!(state(&db, &claim.run_id).await, "running");
        assert_eq!(
            events(&db, &claim.run_id).await,
            [created(), claimed_event(claim)]
        );
        let token: Option<String> = sqlx::query_scalar(
            "SELECT claim_token::text FROM openmettle.runs
              WHERE id = $1::uuid AND claimed_at IS NOT NULL",
        )
        .bind(&claim.run_id)
        .fetch_one(&mut owner)
        .await
        .unwrap();
        assert_eq!(token.as_deref(), Some(claim.claim_token.as_str()));
    }
    assert_eq!(claim_with(&db, &limits).await, None);

    // A waiting run holds no worker, so a's next queued run becomes claimable.
    let a_running = claims.iter().find(|x| x.scope_id == a_scope).unwrap();
    set_state(&db, &a_running.run_id, "waiting").await;
    let next = claim_with(&db, &limits).await.unwrap();
    assert_eq!(next.scope_id, a_scope);
    assert_eq!(claim_with(&db, &limits).await, None);
    // ...but it is live, so it still counts against a's admission limit (4 live runs).
    let r = request(&db, &a_scope, "personal", &a, "over").await;
    let full = AdmissionLimits {
        live_per_actor: 4,
        ..LIMITS
    };
    let refused = admit_on(&mut api(&db).await, &r, &full, None).await;
    assert_eq!(refused.unwrap(), Admission::Refused(RunLimit::ActorLimit));
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn claims_serve_idle_actors_first_in_fifo_order_and_skip_locked_rows() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let mut accounts = Vec::new();
    for _ in 0..5 {
        accounts.push(account(&mut owner, PROVIDER, true, FUTURE).await);
    }
    let [a, b, e, f, h] = &accounts[..] else {
        unreachable!()
    };
    let single = async |actor: &Account, key: &str| {
        let scope = personal_of(&db, actor).await;
        admitted(&db, &request(&db, &scope, "personal", actor, key).await).await
    };

    // a executes one run and then queues 50 more, all older than anyone else's.
    let a_scope = personal_of(&db, a).await;
    let r = request(&db, &a_scope, "personal", a, "a-0").await;
    let first = admitted(&db, &r).await;
    assert_eq!(claim(&db).await.unwrap().run_id, first);
    let mut backlog = Vec::new();
    for i in 1..=50 {
        backlog.push(admitted(&db, &r.keyed(&format!("a-{i}"))).await);
    }
    let b1 = single(b, "b-1").await;
    let e1 = single(e, "e-1").await;
    let f1 = single(f, "f-1").await;

    // b is idle and a holds a worker, so b's newer run goes first; idle actors are FIFO.
    for expected in [&b1, &e1, &f1] {
        assert_eq!(&claim(&db).await.unwrap().run_id, expected);
    }
    // Every actor now holds one worker: the tie is FIFO, so a's oldest queued run is next.
    assert_eq!(claim(&db).await.unwrap().run_id, backlog[0]);

    // A run row held by the API (as a cancel or recheck holds it) is skipped, not awaited.
    let h1 = single(h, "h-1").await;
    let mut held = api(&db).await;
    let mut tx = held.begin().await.unwrap();
    sqlx::query("SELECT state FROM openmettle.runs WHERE id = $1::uuid FOR NO KEY UPDATE")
        .bind(&h1)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let started = Instant::now();
    let skipped = claim(&db).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(skipped.run_id, backlog[1]);
    tx.commit().await.unwrap();
    assert_eq!(claim(&db).await.unwrap().run_id, h1);
    assert_eq!(state(&db, &backlog[2]).await, "queued");
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn the_recheck_after_a_claim_cancels_revoked_runs_with_one_terminal_event() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let carol = account(&mut owner, PROVIDER, true, FUTURE).await;
    let (project, scope) = new_project(&db, &alice, "create").await;
    editor(&db, &alice, &project, &bob).await;
    let bob_run = admitted(&db, &request(&db, &scope, "project", &bob, "bob").await).await;
    let carol_scope = personal_of(&db, &carol).await;
    let carol_request = request(&db, &carol_scope, "personal", &carol, "carol").await;
    let carol_run = admitted(&db, &carol_request).await;
    let mut claims = BTreeMap::new();
    while let Some(next) = claim(&db).await {
        claims.insert(next.run_id.clone(), next);
    }
    let (bob_claim, carol_claim) = (&claims[&bob_run], &claims[&carol_run]);
    assert_eq!(bob_claim.actor_approval_id, bob.approval);
    assert_eq!(carol_claim.actor_approval_id, carol.approval);
    for claim in [bob_claim, carol_claim] {
        assert_eq!(recheck(&db, claim).await, RunRecheckOutcome::Continue);
    }

    // Membership revocation, which the API cannot see in the run, is caught after the claim.
    let revoked = projects::revoke_project_member(
        &mut api(&db).await,
        &ctx(&alice, "bob-out"),
        &project,
        &Grantee::User(bob.user.clone()),
    )
    .await;
    applied(revoked);
    // Approval withdrawal.
    sqlx::query(
        "UPDATE openmettle.local_identity_approvals SET active = false WHERE id = $1::uuid",
    )
    .bind(&carol.approval)
    .execute(&mut owner)
    .await
    .unwrap();
    for (claim, reason) in [
        (bob_claim, DenialReason::NotFound),
        (carol_claim, DenialReason::InactivePrincipal),
    ] {
        assert_eq!(
            recheck(&db, claim).await,
            RunRecheckOutcome::Invalidated(reason)
        );
        assert_eq!(state(&db, &claim.run_id).await, "cancelled");
        cancelled_once(&db, &claim.run_id, "revoked").await;
        assert_eq!(
            recheck(&db, claim).await,
            RunRecheckOutcome::Terminal {
                state: "cancelled".into()
            }
        );
        // created, claimed, cancelled: nothing more.
        assert_eq!(events(&db, &claim.run_id).await.len(), 3);
    }
}

// --- schema 19 ---------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn queue_privileges_and_constraints_are_minimal_at_version_19() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(5));
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    let mut admin = db.admin().await;
    // (insert admission, update admission, update claim, insert claim, select dispatch lock,
    //  update lock_guard, update id, other dispatch privileges, delete or truncate runs)
    for (role, expected) in [
        (
            API,
            [true, false, false, false, false, false, false, false, false],
        ),
        (ISSUANCE, [false; 9]),
        (
            WORKER,
            [false, false, true, false, true, true, false, false, false],
        ),
    ] {
        let row = sqlx::query(
            "SELECT has_column_privilege($1, 'openmettle.runs', 'actor_approval_id', 'INSERT')
                    AND has_column_privilege($1, 'openmettle.runs', 'round_limit', 'INSERT')
                    AND has_column_privilege($1, 'openmettle.runs', 'queue_expires_at', 'INSERT'),
                    has_column_privilege($1, 'openmettle.runs', 'actor_approval_id', 'UPDATE')
                    OR has_column_privilege($1, 'openmettle.runs', 'round_limit', 'UPDATE')
                    OR has_column_privilege($1, 'openmettle.runs', 'queue_expires_at', 'UPDATE'),
                    has_column_privilege($1, 'openmettle.runs', 'claim_token', 'UPDATE')
                    AND has_column_privilege($1, 'openmettle.runs', 'claimed_at', 'UPDATE'),
                    has_column_privilege($1, 'openmettle.runs', 'claim_token', 'INSERT')
                    OR has_column_privilege($1, 'openmettle.runs', 'claimed_at', 'INSERT'),
                    has_table_privilege($1, 'openmettle.run_dispatch_lock', 'SELECT'),
                    has_column_privilege($1, 'openmettle.run_dispatch_lock', 'lock_guard', 'UPDATE'),
                    has_column_privilege($1, 'openmettle.run_dispatch_lock', 'id', 'UPDATE'),
                    has_table_privilege($1, 'openmettle.run_dispatch_lock',
                                        'INSERT,DELETE,TRUNCATE,REFERENCES,TRIGGER'),
                    has_table_privilege($1, 'openmettle.runs', 'DELETE,TRUNCATE')",
        )
        .bind(role)
        .fetch_one(&mut admin)
        .await
        .unwrap();
        let observed: Vec<bool> = (0..9).map(|i| row.get(i)).collect();
        assert_eq!(observed, expected, "{role}");
    }

    // Refused statements for each role.
    let mut api = connect(&db.0, API).await;
    for sql in [
        "UPDATE openmettle.runs SET claim_token = gen_random_uuid(), claimed_at = now()",
        "UPDATE openmettle.runs SET round_limit = 1",
        "UPDATE openmettle.runs SET queue_expires_at = now()",
        "SELECT FROM openmettle.run_dispatch_lock",
        "DELETE FROM openmettle.runs",
    ] {
        expect_state(&mut api, sql, "42501").await;
    }
    let mut w = connect(&db.0, WORKER).await;
    for sql in [
        "UPDATE openmettle.runs SET actor_approval_id = NULL",
        "UPDATE openmettle.runs SET round_limit = 1",
        "UPDATE openmettle.runs SET queue_expires_at = now()",
        "INSERT INTO openmettle.run_dispatch_lock (id) VALUES (false)",
        "UPDATE openmettle.run_dispatch_lock SET id = true",
        "DELETE FROM openmettle.run_dispatch_lock",
        "DELETE FROM openmettle.runs",
    ] {
        expect_state(&mut w, sql, "42501").await;
    }
    // The worker's granted lock works outside any claim too.
    w.execute("SELECT FROM openmettle.run_dispatch_lock FOR NO KEY UPDATE")
        .await
        .unwrap();
    let mut issuance = connect(&db.0, ISSUANCE).await;
    for sql in [
        "SELECT FROM openmettle.runs",
        "SELECT FROM openmettle.run_dispatch_lock",
    ] {
        expect_state(&mut issuance, sql, "42501").await;
    }

    // The constraints keep admission and claim columns consistent and the lock a singleton.
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let scope = personal_of(&db, &alice).await;
    let r = request(&db, &scope, "personal", &alice, "constraints").await;
    let bare = bare_run(&db, &r).await;
    let admitted_run = admitted(&db, &r.keyed("admitted")).await;
    let approval = &alice.approval;
    for sql in [
        format!("UPDATE openmettle.runs SET round_limit = 5 WHERE id = '{bare}'"),
        format!(
            "UPDATE openmettle.runs SET actor_approval_id = '{approval}', round_limit = 0,
                    queue_expires_at = created_at + interval '1 hour' WHERE id = '{bare}'"
        ),
        format!(
            "UPDATE openmettle.runs SET actor_approval_id = '{approval}', round_limit = 5,
                    queue_expires_at = created_at WHERE id = '{bare}'"
        ),
        format!(
            "UPDATE openmettle.runs SET claim_token = gen_random_uuid(), claimed_at = now()
              WHERE id = '{bare}'"
        ),
        format!(
            "UPDATE openmettle.runs SET claim_token = gen_random_uuid() WHERE id = '{admitted_run}'"
        ),
        format!("UPDATE openmettle.runs SET queue_expires_at = NULL WHERE id = '{admitted_run}'"),
        "INSERT INTO openmettle.run_dispatch_lock (id) VALUES (false)".into(),
        "UPDATE openmettle.run_dispatch_lock SET lock_guard = true".into(),
    ] {
        expect_state(&mut owner, &sql, "23514").await;
    }
    expect_state(
        &mut owner,
        "INSERT INTO openmettle.run_dispatch_lock (id) VALUES (true)",
        "23505",
    )
    .await;
    assert_eq!(
        scalar(&db, "SELECT count(*) FROM openmettle.run_dispatch_lock").await,
        1
    );

    // The boundary audit refuses any queue privilege beyond the version-19 contract.
    for (grant, revoke, violation) in [
        (
            "GRANT UPDATE (claim_token) ON openmettle.runs TO openmettle_api",
            "REVOKE UPDATE (claim_token) ON openmettle.runs FROM openmettle_api",
            "openmettle_api has UPDATE on openmettle.runs.claim_token",
        ),
        (
            "GRANT UPDATE (round_limit) ON openmettle.runs TO openmettle_worker",
            "REVOKE UPDATE (round_limit) ON openmettle.runs FROM openmettle_worker",
            "openmettle_worker has UPDATE on openmettle.runs.round_limit",
        ),
        (
            "GRANT INSERT (queue_expires_at) ON openmettle.runs TO openmettle_worker",
            "REVOKE INSERT (queue_expires_at) ON openmettle.runs FROM openmettle_worker",
            "openmettle_worker has INSERT on openmettle.runs.queue_expires_at",
        ),
        (
            "GRANT UPDATE (actor_approval_id) ON openmettle.runs TO openmettle_api",
            "REVOKE UPDATE (actor_approval_id) ON openmettle.runs FROM openmettle_api",
            "openmettle_api has UPDATE on openmettle.runs.actor_approval_id",
        ),
        (
            "GRANT SELECT ON openmettle.run_dispatch_lock TO openmettle_api",
            "REVOKE SELECT ON openmettle.run_dispatch_lock FROM openmettle_api",
            "openmettle_api has SELECT on openmettle.run_dispatch_lock",
        ),
        (
            "GRANT SELECT ON openmettle.run_dispatch_lock TO openmettle_issuance",
            "REVOKE SELECT ON openmettle.run_dispatch_lock FROM openmettle_issuance",
            "openmettle_issuance has SELECT on openmettle.run_dispatch_lock",
        ),
        (
            "GRANT DELETE ON openmettle.run_dispatch_lock TO openmettle_worker",
            "REVOKE DELETE ON openmettle.run_dispatch_lock FROM openmettle_worker",
            "openmettle_worker has DELETE on openmettle.run_dispatch_lock",
        ),
        (
            "GRANT UPDATE (lock_guard) ON openmettle.run_dispatch_lock TO openmettle_worker
              WITH GRANT OPTION",
            "REVOKE GRANT OPTION FOR UPDATE (lock_guard) ON openmettle.run_dispatch_lock
              FROM openmettle_worker",
            "openmettle_worker has grant option for UPDATE on openmettle.run_dispatch_lock.lock_guard",
        ),
    ] {
        owner.execute(grant).await.unwrap();
        refused_with(&settings, MIGRATIONS, violation).await;
        owner.execute(revoke).await.unwrap();
    }
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn populated_upgrade_from_version_18_leaves_existing_runs_unadmitted() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..18]).await.unwrap();
    assert_eq!(db.history().await, versions_through(18));
    assert!(!db.exists("openmettle.run_dispatch_lock").await);
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let scope = personal_of(&db, &alice).await;
    let r = request(&db, &scope, "personal", &alice, "before").await;
    // Bare `create_run` names only pre-19 columns, so it works on schema 18.
    let old = bare_run(&db, &r).await;
    let rows = async || {
        let mut c = connect(&db.0, OWNER).await;
        let mut rows: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT (to_jsonb(t) {NEW_COLUMNS})::text FROM openmettle.runs t ORDER BY id"
        )))
        .fetch_all(&mut c)
        .await
        .unwrap();
        let events: Vec<String> = sqlx::query_scalar(
            "SELECT to_jsonb(e)::text FROM openmettle.run_events e ORDER BY run_id, sequence",
        )
        .fetch_all(&mut c)
        .await
        .unwrap();
        rows.extend(events);
        rows
    };
    let before = rows().await;
    assert_eq!(before.len(), 2);

    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(db.history().await, all_versions());
    assert_eq!(rows().await, before);
    let unadmitted = "SELECT count(*) FROM openmettle.runs
                       WHERE actor_approval_id IS NULL AND round_limit IS NULL
                         AND queue_expires_at IS NULL AND claim_token IS NULL
                         AND claimed_at IS NULL";
    assert_eq!(scalar(&db, unadmitted).await, 1);
    // The pre-19 run is never claimed; the first sweep fails it with one terminal event.
    assert_eq!(claim(&db).await, None);
    assert_eq!(expire(&db, 1000).await, [old.as_str()]);
    expired_once(&db, &old).await;
    // Admission works on the upgraded schema.
    let fresh = admitted(&db, &r.keyed("after")).await;
    assert_eq!(claim(&db).await.unwrap().run_id, fresh);
}
