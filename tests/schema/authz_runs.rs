//! ADR 0027 PR5: worker execution-time recheck and live run invalidation. Rechecks run as
//! `openmettle_worker` (and `openmettle_api`). Revocations run through the PR3 and PR4a writers
//! as `openmettle_api`. The owner role seeds fixtures and reads results. Every value is
//! synthetic.
use super::authz_store::{
    Account, FUTURE, NOW, PROVIDER, UNKNOWN, account, applied, ctx, make_admin, present_membership,
    providers, wait_for_lock_waiters,
};
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openmettle_core::{
    authz::{
        CapabilityGate, DenialReason, Grantee, PolicyReason, ProjectRole, ResourceAccess,
        ResourceKind,
        projects::{self, ProjectSettingsInput},
        runs::{self as recheck, CapabilityUse, RunRecheckOutcome, RunRecheckRequest},
        store::{self, StoreError, WriteOutcome},
    },
    runs::{self, RunInput, WriteTransaction},
    sessions,
};
use serde_json::json;
use sha2::{Digest, Sha256};

const CONVERSATION: ResourceKind = ResourceKind::Conversation;
const ARTIFACT: ResourceKind = ResourceKind::Artifact;
const OIDC_TEAM: &str = "synthetic-team";
const RETIRING: &str = "00000000-0000-0000-0000-0000000005b1";
const YOLO: CapabilityUse<'static> = CapabilityUse {
    name: "runs.use_yolo",
    gate: CapabilityGate::OptIn,
};
const SEARCH: CapabilityUse<'static> = CapabilityUse {
    name: "web_search",
    gate: CapabilityGate::OnByDefault,
};
const CONTINUE: RunRecheckOutcome = RunRecheckOutcome::Continue;
const INACTIVE: DenialReason = DenialReason::InactivePrincipal;
const HIDDEN: DenialReason = DenialReason::NotFound;
/// Every non-terminal ADR 0004 state.
const LIVE: [&str; 5] = ["queued", "running", "waiting", "cancelling", "reconciling"];
/// Terminal states other than `cancelled`.
const ENDED: [&str; 3] = ["succeeded", "failed", "interrupted"];

fn policy(reason: PolicyReason) -> DenialReason {
    DenialReason::Policy(reason)
}

fn terminal(state: &str) -> RunRecheckOutcome {
    RunRecheckOutcome::Terminal {
        state: state.into(),
    }
}

async fn api(db: &TestDb) -> PgConnection {
    connect(&db.0, API).await
}

#[derive(Clone)]
pub(super) struct Run {
    scope: String,
    id: String,
    conversation: String,
    owner: Account,
}

/// A queued run on a new message of `conversation`, through the ADR 0004 writer as the API.
async fn start(db: &TestDb, scope: &str, conversation: &str, owner: &Account) -> Run {
    let mut c = api(db).await;
    let message = message(&mut c, scope, conversation, None).await.unwrap();
    let branch: String = sqlx::query_scalar(
        "INSERT INTO openmettle.conversation_branches (scope_id, conversation_id)
         VALUES ($1::uuid, $2::uuid) RETURNING id::text",
    )
    .bind(scope)
    .bind(conversation)
    .fetch_one(&mut c)
    .await
    .unwrap();
    let key = format!("run-{message}");
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    let id = runs::create_run(
        &mut tx,
        &RunInput {
            scope,
            actor: &owner.user,
            conversation,
            branch: &branch,
            message: &message,
            key: &key,
            format: "openmettle.synthetic-run",
            version: 1,
            input: b"synthetic input",
            config: b"{}",
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    Run {
        scope: scope.to_owned(),
        id,
        conversation: conversation.to_owned(),
        owner: owner.clone(),
    }
}

pub(super) async fn chat(db: &TestDb, scope: &str, kind: &str, owner: &Account) -> String {
    conversation(&mut api(db).await, scope, kind, &owner.user)
        .await
        .unwrap()
}

pub(super) async fn personal_of(db: &TestDb, account: &Account) -> String {
    sqlx::query_scalar("SELECT id::text FROM openmettle.scopes WHERE personal_user_id = $1::uuid")
        .bind(&account.user)
        .fetch_one(&mut connect(&db.0, OWNER).await)
        .await
        .unwrap()
}

/// A run on a new conversation of `owner` in their personal scope.
async fn personal_run(db: &TestDb, owner: &Account) -> Run {
    let scope = personal_of(db, owner).await;
    let conversation = chat(db, &scope, "personal", owner).await;
    start(db, &scope, &conversation, owner).await
}

/// A run on a new conversation of `owner` in a project scope.
pub(super) async fn project_run(db: &TestDb, scope: &str, owner: &Account) -> Run {
    let conversation = chat(db, scope, "project", owner).await;
    start(db, scope, &conversation, owner).await
}

pub(super) async fn artifact(db: &TestDb, scope: &str, kind: &str, owner: &Account) -> String {
    sqlx::query_scalar(
        "INSERT INTO openmettle.artifacts (id, scope_id, scope_kind, owner_user_id)
         VALUES (gen_random_uuid(), $1::uuid, $2, $3::uuid) RETURNING id::text",
    )
    .bind(scope)
    .bind(kind)
    .bind(&owner.user)
    .fetch_one(&mut connect(&db.0, OWNER).await)
    .await
    .unwrap()
}

/// (project ID, scope ID) of a project created by `owner` through the PR4a store.
async fn create_project(db: &TestDb, owner: &Account, key: &str) -> (String, String) {
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

async fn member(
    db: &TestDb,
    actor: &Account,
    key: &str,
    project: &str,
    grantee: &Grantee,
    role: ProjectRole,
) {
    applied(
        projects::set_project_member_role(
            &mut api(db).await,
            &ctx(actor, key),
            project,
            grantee,
            role,
        )
        .await,
    );
}

async fn share(
    db: &TestDb,
    actor: &Account,
    key: &str,
    (kind, id): (ResourceKind, &str),
    grantee: &Grantee,
    access: ResourceAccess,
) {
    applied(
        projects::share_resource(
            &mut api(db).await,
            &ctx(actor, key),
            kind,
            id,
            grantee,
            access,
        )
        .await,
    );
}

fn user(account: &Account) -> Grantee {
    Grantee::User(account.user.clone())
}

async fn set_state(db: &TestDb, run: &Run, state: &str) {
    let wait = (state == "waiting").then_some("synthetic-wait");
    sqlx::query("UPDATE openmettle.runs SET state = $2, wait_reason = $3 WHERE id = $1::uuid")
        .bind(&run.id)
        .bind(state)
        .bind(wait)
        .execute(&mut connect(&db.0, OWNER).await)
        .await
        .unwrap();
}

/// (state, wait_reason) read as the owner role.
pub(super) async fn state_of(db: &TestDb, run: &Run) -> (String, Option<String>) {
    sqlx::query_as("SELECT state, wait_reason FROM openmettle.runs WHERE id = $1::uuid")
        .bind(&run.id)
        .fetch_one(&mut connect(&db.0, OWNER).await)
        .await
        .unwrap()
}

fn cancelled() -> (String, Option<String>) {
    ("cancelled".into(), None)
}

/// The run's terminal events (format, payload) under the ADR 0032 key, read as the owner role.
pub(super) async fn terminal_events(db: &TestDb, run_id: &str) -> Vec<(String, Vec<u8>)> {
    sqlx::query_as(
        "SELECT format, payload FROM openmettle.run_events
          WHERE run_id = $1::uuid AND append_key = 'run-terminal' AND format_version = 1",
    )
    .bind(run_id)
    .fetch_all(&mut connect(&db.0, OWNER).await)
    .await
    .unwrap()
}

/// Exactly one `openmettle.run-cancelled` v1 terminal event with `reason`.
pub(super) async fn cancelled_once(db: &TestDb, run_id: &str, reason: &str) {
    let payload = format!(r#"{{"reason":"{reason}"}}"#).into_bytes();
    assert_eq!(
        terminal_events(db, run_id).await,
        [("openmettle.run-cancelled".to_owned(), payload)],
        "{run_id}"
    );
}

async fn revoked_once(db: &TestDb, run: &Run) {
    cancelled_once(db, &run.id, "revoked").await;
}

async fn recheck_on(
    c: &mut PgConnection,
    run: &Run,
    capabilities: &[CapabilityUse<'_>],
    extra_target: Option<(ResourceKind, &str)>,
    now_ms: i64,
) -> Result<RunRecheckOutcome, StoreError> {
    let request = RunRecheckRequest {
        scope_id: &run.scope,
        run_id: &run.id,
        actor_approval_id: &run.owner.approval,
        capabilities,
        extra_target,
        now_ms,
    };
    recheck::recheck_run(c, &request).await
}

async fn recheck_as(
    db: &TestDb,
    role: &str,
    run: &Run,
    capabilities: &[CapabilityUse<'_>],
    extra_target: Option<(ResourceKind, &str)>,
    now_ms: i64,
) -> Result<RunRecheckOutcome, StoreError> {
    let mut c = connect(&db.0, role).await;
    recheck_on(&mut c, run, capabilities, extra_target, now_ms).await
}

/// One worker recheck at `NOW`.
async fn worker(db: &TestDb, run: &Run, capabilities: &[CapabilityUse<'_>]) -> RunRecheckOutcome {
    recheck_as(db, WORKER, run, capabilities, None, NOW)
        .await
        .unwrap()
}

/// The worker invalidates the run exactly once: the row becomes `cancelled` with no wait reason
/// and a repeated recheck reports it terminal without changing it.
async fn invalidated_at(
    db: &TestDb,
    run: &Run,
    capabilities: &[CapabilityUse<'_>],
    extra: Option<(ResourceKind, &str)>,
    now_ms: i64,
    reason: DenialReason,
) {
    let outcome = recheck_as(db, WORKER, run, capabilities, extra, now_ms).await;
    assert_eq!(outcome.unwrap(), RunRecheckOutcome::Invalidated(reason));
    assert_eq!(state_of(db, run).await, cancelled());
    revoked_once(db, run).await;
    let again = recheck_as(db, WORKER, run, capabilities, extra, now_ms).await;
    assert_eq!(again.unwrap(), terminal("cancelled"));
    assert_eq!(state_of(db, run).await, cancelled());
    revoked_once(db, run).await;
}

async fn invalidated(
    db: &TestDb,
    run: &Run,
    capabilities: &[CapabilityUse<'_>],
    reason: DenialReason,
) {
    invalidated_at(db, run, capabilities, None, NOW, reason).await;
}

/// A domain-separated, length-prefixed SHA-256 digest: the ADR 0013 and ADR 0023 framing,
/// encoded independently of `src/runs.rs`.
pub(super) fn framed_digest(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut framed = domain.to_vec();
    for field in fields {
        framed.extend_from_slice(&(field.len() as u64).to_be_bytes());
        framed.extend_from_slice(field);
    }
    Sha256::digest(&framed).to_vec()
}

/// A browser session issued to `account` through its approval, stored as issuance stores it.
/// Returns the credential the browser would present.
async fn session(db: &TestDb, account: &Account, n: u8) -> String {
    seeded_session(db, account, n, None).await
}

/// A session issued to `account` through its approval, stored as issuance stores it: a browser
/// session, or with `audience` a delivered native bearer of that registration (ADR 0023).
/// Returns the credential the client would present. `n` must differ per session.
pub(super) async fn seeded_session(
    db: &TestDb,
    account: &Account,
    n: u8,
    audience: Option<&[u8]>,
) -> String {
    let id = URL_SAFE_NO_PAD.encode([n; 32]);
    let secret = [n.wrapping_add(100); 32];
    let gate = URL_SAFE_NO_PAD.encode([n.wrapping_add(50); 32]);
    let domain: &[u8] = match audience {
        None => b"openmettle/session-secret/1\0",
        Some(_) => b"openmettle/native-session-secret/1\0",
    };
    let mut owner = connect(&db.0, OWNER).await;
    sqlx::query(
        "WITH reservation AS (
             INSERT INTO openmettle.login_nonce_reservations (key_id, nonce)
             VALUES ('fixture-v1', substring(sha256(convert_to($1, 'UTF8')) FROM 1 FOR 12))
             RETURNING key_id, nonce
         ), gate AS (
             INSERT INTO openmettle.login_transactions
                 (id, binding, expires_ms, state_hash, nonce_hash, caller_hash,
                  key_id, nonce, ciphertext, consumed, session_issued)
             SELECT $1, decode('01', 'hex'), $5, sha256(convert_to($1 || ':state', 'UTF8')),
                    sha256(convert_to($1 || ':nonce', 'UTF8')),
                    sha256(convert_to($1 || ':caller', 'UTF8')), key_id, nonce, NULL, true, true
               FROM reservation
             RETURNING id
         )
         INSERT INTO openmettle.local_sessions
             (id, secret_hash, login_id, provider_id, identity_id, approval_id, user_id,
              issued_client, issued_epoch, issued_revision, provider_generation,
              approval_generation, user_generation, created_ms, expires_ms)
         SELECT $2, $3, gate.id, a.provider_id, a.identity_id, a.id, i.user_id, 'synthetic',
                (SELECT max(epoch) FROM openmettle.login_provider_revisions
                  WHERE provider_id = a.provider_id), 1, 0, 0, 0, 1, $5
           FROM gate, openmettle.local_identity_approvals a
           JOIN openmettle.user_identities i ON i.id = a.identity_id
          WHERE a.id = $4::uuid",
    )
    .bind(&gate)
    .bind(&id)
    .bind(framed_digest(domain, &[id.as_bytes(), &secret]))
    .bind(&account.approval)
    .bind(FUTURE)
    .execute(&mut owner)
    .await
    .unwrap();
    if let Some(audience) = audience {
        // A redeemed handoff: unsealed, bound to the serving registration's audience.
        sqlx::query(
            "INSERT INTO openmettle.native_handoffs
                 (session_id, code_hash, registration, audience, challenge, sealed, expires_ms)
             VALUES ($1, sha256(convert_to($1 || ':code', 'UTF8')), decode(repeat('0b', 32), 'hex'),
                     $2, decode(repeat('0c', 32), 'hex'), NULL, $3)",
        )
        .bind(&id)
        .bind(audience)
        .bind(FUTURE)
        .execute(&mut owner)
        .await
        .unwrap();
    }
    format!("{id}.{}", URL_SAFE_NO_PAD.encode(secret))
}

// --- continuation and logout -------------------------------------------------------------------

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn authorized_runs_continue_and_logout_never_cancels_them() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let mine = personal_run(&db, &alice).await;
    let (project, scope) = create_project(&db, &alice, "create").await;
    member(
        &db,
        &alice,
        "bob",
        &project,
        &user(&bob),
        ProjectRole::Editor,
    )
    .await;
    let theirs = project_run(&db, &scope, &bob).await;
    set_state(&db, &theirs, "running").await;
    let waiting = project_run(&db, &scope, &alice).await;
    set_state(&db, &waiting, "waiting").await;

    // Logging out of the sessions the runs started from changes nothing for them.
    let session_policy =
        sessions::Policy::new(Duration::from_secs(3600), 16, Duration::from_secs(5)).unwrap();
    for (n, account) in [(1, &alice), (2, &bob)] {
        let credential = session(&db, account, n).await;
        sessions::logout(&mut api(&db).await, &credential, &session_policy)
            .await
            .unwrap();
    }
    let revoked: i64 =
        sqlx::query_scalar("SELECT count(*) FROM openmettle.local_sessions WHERE revoked")
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(revoked, 2);
    for run in [&mine, &theirs, &waiting] {
        for role in [WORKER, API] {
            let outcome = recheck_as(&db, role, run, &[SEARCH], None, NOW).await;
            assert_eq!(outcome.unwrap(), CONTINUE, "{role}");
        }
    }
    assert_eq!(state_of(&db, &mine).await, ("queued".into(), None));
    assert_eq!(state_of(&db, &theirs).await, ("running".into(), None));
    assert_eq!(
        state_of(&db, &waiting).await,
        ("waiting".into(), Some("synthetic-wait".into()))
    );

    // A run is addressed by its scope and ID; malformed input never reaches the database.
    let missing = Run {
        id: UNKNOWN.into(),
        ..mine.clone()
    };
    let elsewhere = Run {
        scope: scope.clone(),
        ..mine.clone()
    };
    for run in [&missing, &elsewhere] {
        let outcome = recheck_as(&db, WORKER, run, &[], None, NOW).await;
        assert!(matches!(outcome, Err(StoreError::NotFound)));
    }
    let malformed = Run {
        id: "not-a-uuid".into(),
        ..mine.clone()
    };
    let outcome = recheck_as(&db, WORKER, &malformed, &[], None, NOW).await;
    assert!(matches!(outcome, Err(StoreError::InvalidInput("run_id"))));
    let bad = [CapabilityUse {
        name: "Web Search",
        gate: CapabilityGate::OnByDefault,
    }];
    let outcome = recheck_as(&db, WORKER, &mine, &bad, None, NOW).await;
    assert!(matches!(
        outcome,
        Err(StoreError::InvalidInput("capability"))
    ));

    // The recheck needs no administrator, audit, settings or session row: the worker can read
    // none of them, nor change anything on a run except its lifecycle columns.
    let mut w = connect(&db.0, WORKER).await;
    for sql in [
        "SELECT * FROM openmettle.account_admins",
        "SELECT * FROM openmettle.project_settings",
        "SELECT * FROM openmettle.authorization_audit",
        "SELECT * FROM openmettle.local_sessions",
        "UPDATE openmettle.runs SET actor_user_id = actor_user_id",
        "UPDATE openmettle.runs SET input_snapshot = input_snapshot",
        "DELETE FROM openmettle.runs",
    ] {
        expect_state(&mut w, sql, "42501").await;
    }
    assert_eq!(
        recheck_on(&mut w, &theirs, &[], None, NOW).await.unwrap(),
        CONTINUE
    );
}

// --- principal and capability revocations ------------------------------------------------------

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn principal_revocations_invalidate_at_the_next_worker_recheck() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    // A second provider for the same issuer, retired below.
    sqlx::query(
        "INSERT INTO openmettle.login_providers (id, issuer, client_id, changed_by, change_reason)
         SELECT $1::uuid, issuer, 'synthetic-retiring', 'fixture-owner', 'synthetic provider'
           FROM openmettle.login_providers WHERE id = $2::uuid",
    )
    .bind(RETIRING)
    .bind(PROVIDER)
    .execute(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.login_provider_revisions (provider_id, revision)
         VALUES ($1::uuid, 'v1')",
    )
    .bind(RETIRING)
    .execute(&mut owner)
    .await
    .unwrap();
    let withdrawn = account(&mut owner, PROVIDER, true, FUTURE).await;
    let expiring = account(&mut owner, PROVIDER, true, NOW + 1000).await;
    let retired = account(&mut owner, RETIRING, true, FUTURE).await;
    let a = personal_run(&db, &withdrawn).await;
    let b = personal_run(&db, &expiring).await;
    set_state(&db, &b, "running").await;
    let c = personal_run(&db, &retired).await;
    set_state(&db, &c, "waiting").await;
    for run in [&a, &b, &c] {
        assert_eq!(worker(&db, run, &[]).await, CONTINUE);
    }

    // Approval withdrawal.
    sqlx::query(
        "UPDATE openmettle.local_identity_approvals SET active = false WHERE id = $1::uuid",
    )
    .bind(&withdrawn.approval)
    .execute(&mut owner)
    .await
    .unwrap();
    invalidated(&db, &a, &[], INACTIVE).await;

    // Approval expiry, decided at the recheck time.
    let outcome = recheck_as(&db, WORKER, &b, &[], None, NOW + 999).await;
    assert_eq!(outcome.unwrap(), CONTINUE);
    invalidated_at(&db, &b, &[], None, NOW + 1000, INACTIVE).await;

    // Provider retirement at its current authority epoch.
    sqlx::query(
        "INSERT INTO openmettle.login_provider_revisions (provider_id, revision)
         VALUES ($1::uuid, NULL)",
    )
    .bind(RETIRING)
    .execute(&mut owner)
    .await
    .unwrap();
    invalidated(&db, &c, &[], INACTIVE).await;

    // An approval that is not the run owner's fails closed.
    let borrowed = Run {
        owner: Account {
            approval: retired.approval.clone(),
            ..withdrawn.clone()
        },
        ..personal_run(&db, &withdrawn).await
    };
    sqlx::query("UPDATE openmettle.local_identity_approvals SET active = true WHERE id = $1::uuid")
        .bind(&withdrawn.approval)
        .execute(&mut owner)
        .await
        .unwrap();
    invalidated(&db, &borrowed, &[], INACTIVE).await;

    // Terminal runs are never touched, even for an inactive owner.
    for state in ENDED {
        let run = personal_run(&db, &retired).await;
        set_state(&db, &run, state).await;
        assert_eq!(worker(&db, &run, &[]).await, terminal(state));
        assert_eq!(state_of(&db, &run).await, (state.to_owned(), None));
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn disable_user_cancels_every_live_run_it_owns_in_the_same_transaction() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let carol = account(&mut owner, PROVIDER, true, FUTURE).await;
    let dave = account(&mut owner, PROVIDER, true, FUTURE).await;
    let (project, scope) = create_project(&db, &dave, "create").await;
    member(
        &db,
        &dave,
        "carol",
        &project,
        &user(&carol),
        ProjectRole::Editor,
    )
    .await;
    let mut live = Vec::new();
    for state in LIVE {
        let run = personal_run(&db, &carol).await;
        set_state(&db, &run, state).await;
        live.push(run);
    }
    live.push(project_run(&db, &scope, &carol).await);
    let mut ended = Vec::new();
    for state in ENDED {
        let run = personal_run(&db, &carol).await;
        set_state(&db, &run, state).await;
        ended.push((state, run));
    }
    let others = [
        personal_run(&db, &dave).await,
        project_run(&db, &scope, &dave).await,
    ];

    applied(store::disable_user(&mut api(&db).await, &ctx(&admin, "disable"), &carol.user).await);
    // Cancelled when the disablement commits, before any worker recheck, each with one
    // terminal event (ADR 0032).
    for run in &live {
        assert_eq!(state_of(&db, run).await, cancelled());
        revoked_once(&db, run).await;
        assert_eq!(worker(&db, run, &[]).await, terminal("cancelled"));
    }
    for (state, run) in &ended {
        assert_eq!(state_of(&db, run).await, ((*state).to_owned(), None));
        assert!(terminal_events(&db, &run.id).await.is_empty());
    }
    for run in &others {
        assert_eq!(state_of(&db, run).await, ("queued".into(), None));
        assert!(terminal_events(&db, &run.id).await.is_empty());
        assert_eq!(worker(&db, run, &[]).await, CONTINUE);
    }
    // A replayed request cancels nothing new; re-enabling revives no run.
    let replay =
        store::disable_user(&mut api(&db).await, &ctx(&admin, "disable"), &carol.user).await;
    assert!(matches!(replay, Ok(WriteOutcome::Replayed { .. })));
    applied(store::enable_user(&mut api(&db).await, &ctx(&admin, "enable"), &carol.user).await);
    for run in &live {
        assert_eq!(state_of(&db, run).await, cancelled());
        revoked_once(&db, run).await;
    }
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn capability_revocations_invalidate_only_runs_that_use_them() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let mut c = api(&db).await;
    let plain = personal_run(&db, &alice).await;

    // Withdrawing the opt-in assignment.
    let yolo = personal_run(&db, &alice).await;
    assert_eq!(
        worker(&db, &yolo, &[YOLO]).await,
        RunRecheckOutcome::Invalidated(policy(PolicyReason::CapabilityNotGranted))
    );
    let yolo = personal_run(&db, &alice).await;
    applied(
        store::set_user_capability_grant(
            &mut c,
            &ctx(&admin, "grant"),
            &alice.user,
            YOLO.name,
            true,
        )
        .await,
    );
    assert_eq!(worker(&db, &yolo, &[YOLO]).await, CONTINUE);
    applied(
        store::set_user_capability_grant(
            &mut c,
            &ctx(&admin, "revoke"),
            &alice.user,
            YOLO.name,
            false,
        )
        .await,
    );
    invalidated(
        &db,
        &yolo,
        &[YOLO],
        policy(PolicyReason::CapabilityNotGranted),
    )
    .await;

    // A user deny.
    let searching = personal_run(&db, &alice).await;
    assert_eq!(worker(&db, &searching, &[SEARCH]).await, CONTINUE);
    applied(
        store::set_user_capability_deny(
            &mut c,
            &ctx(&admin, "user-deny"),
            &alice.user,
            SEARCH.name,
            true,
        )
        .await,
    );
    invalidated(
        &db,
        &searching,
        &[SEARCH],
        policy(PolicyReason::CapabilityDenied),
    )
    .await;
    applied(
        store::set_user_capability_deny(
            &mut c,
            &ctx(&admin, "user-allow"),
            &alice.user,
            SEARCH.name,
            false,
        )
        .await,
    );

    // A platform deny, which also wins over an assignment.
    let searching = personal_run(&db, &alice).await;
    assert_eq!(worker(&db, &searching, &[SEARCH]).await, CONTINUE);
    applied(
        store::set_platform_capability_deny(
            &mut c,
            &ctx(&admin, "platform-deny"),
            SEARCH.name,
            true,
        )
        .await,
    );
    invalidated(
        &db,
        &searching,
        &[SEARCH],
        policy(PolicyReason::CapabilityDenied),
    )
    .await;

    // A run that uses none of them continues throughout.
    assert_eq!(worker(&db, &plain, &[]).await, CONTINUE);
    assert_eq!(state_of(&db, &plain).await, ("queued".into(), None));
}

// --- membership, group, OIDC and share revocations ---------------------------------------------

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn membership_group_and_oidc_revocations_invalidate_project_runs() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let carol = account(&mut owner, PROVIDER, true, FUTURE).await;
    let removed = account(&mut owner, PROVIDER, true, FUTURE).await;
    let grouped = account(&mut owner, PROVIDER, true, FUTURE).await;
    let oidc = account(&mut owner, PROVIDER, true, FUTURE).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    // `oidc` holds current present evidence of OIDC group `synthetic-team` until NOW + 60 s.
    drop(present_membership(&db, &oidc).await);
    let (project, scope) = create_project(&db, &alice, "create").await;
    let mut c = api(&db).await;
    let group = applied(store::create_local_group(&mut c, &ctx(&admin, "group"), "Builders").await);
    for (key, account) in [("m1", &removed), ("m2", &grouped)] {
        applied(
            store::add_local_group_member(&mut c, &ctx(&admin, key), &group, &account.user).await,
        );
    }
    let editor = ProjectRole::Editor;
    member(&db, &alice, "bob", &project, &user(&bob), editor).await;
    member(&db, &alice, "carol", &project, &user(&carol), editor).await;
    let local = Grantee::LocalGroup(group.clone());
    member(&db, &alice, "group", &project, &local, editor).await;
    let team = Grantee::OidcGroup(OIDC_TEAM.into());
    member(&db, &alice, "oidc", &project, &team, editor).await;
    let bob_run = project_run(&db, &scope, &bob).await;
    let carol_run = project_run(&db, &scope, &carol).await;
    set_state(&db, &carol_run, "running").await;
    let removed_run = project_run(&db, &scope, &removed).await;
    let grouped_run = project_run(&db, &scope, &grouped).await;
    set_state(&db, &grouped_run, "waiting").await;
    let oidc_run = project_run(&db, &scope, &oidc).await;
    let alice_run = project_run(&db, &scope, &alice).await;
    for run in [
        &bob_run,
        &carol_run,
        &removed_run,
        &grouped_run,
        &oidc_run,
        &alice_run,
    ] {
        assert_eq!(worker(&db, run, &[]).await, CONTINUE);
    }

    // Direct membership removal conceals the project.
    let revoked = projects::revoke_project_member(
        &mut api(&db).await,
        &ctx(&alice, "bob-out"),
        &project,
        &user(&bob),
    )
    .await;
    applied(revoked);
    invalidated(&db, &bob_run, &[], HIDDEN).await;

    // Demotion to viewer keeps the project visible but forbids running.
    member(
        &db,
        &alice,
        "carol-view",
        &project,
        &user(&carol),
        ProjectRole::Viewer,
    )
    .await;
    invalidated(&db, &carol_run, &[], policy(PolicyReason::InsufficientRole)).await;

    // Local group member removal, then disablement of the whole group.
    let removal =
        store::remove_local_group_member(&mut c, &ctx(&admin, "m1-out"), &group, &removed.user)
            .await;
    applied(removal);
    invalidated(&db, &removed_run, &[], HIDDEN).await;
    assert_eq!(worker(&db, &grouped_run, &[]).await, CONTINUE);
    applied(store::disable_local_group(&mut c, &ctx(&admin, "group-off"), &group).await);
    invalidated(&db, &grouped_run, &[], HIDDEN).await;

    // OIDC evidence that is stale at the recheck time.
    let outcome = recheck_as(&db, WORKER, &oidc_run, &[], None, NOW + 59_999).await;
    assert_eq!(outcome.unwrap(), CONTINUE);
    invalidated_at(&db, &oidc_run, &[], None, NOW + 60_000, HIDDEN).await;

    // The project owner's own run is untouched by every change above.
    assert_eq!(worker(&db, &alice_run, &[]).await, CONTINUE);
    assert_eq!(state_of(&db, &alice_run).await, ("queued".into(), None));
}

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn share_revocation_and_downgrade_invalidate_runs_and_artifact_steps() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let dave = account(&mut owner, PROVIDER, true, FUTURE).await;
    let (project, scope) = create_project(&db, &alice, "create").await;
    member(
        &db,
        &alice,
        "dave",
        &project,
        &user(&dave),
        ProjectRole::Editor,
    )
    .await;
    let write = ResourceAccess::Write;

    // Dave runs on two of Alice's conversations shared with him for writing.
    let unshared_chat = chat(&db, &scope, "project", &alice).await;
    let downgraded_chat = chat(&db, &scope, "project", &alice).await;
    share(
        &db,
        &alice,
        "s1",
        (CONVERSATION, &unshared_chat),
        &user(&dave),
        write,
    )
    .await;
    share(
        &db,
        &alice,
        "s2",
        (CONVERSATION, &downgraded_chat),
        &user(&dave),
        write,
    )
    .await;
    let on_unshared = start(&db, &scope, &unshared_chat, &dave).await;
    let on_downgraded = start(&db, &scope, &downgraded_chat, &dave).await;
    set_state(&db, &on_downgraded, "running").await;
    assert_eq!(worker(&db, &on_unshared, &[]).await, CONTINUE);
    assert_eq!(worker(&db, &on_downgraded, &[]).await, CONTINUE);

    let unshare = projects::unshare_resource(
        &mut api(&db).await,
        &ctx(&alice, "u1"),
        CONVERSATION,
        &unshared_chat,
        &user(&dave),
    )
    .await;
    applied(unshare);
    invalidated(&db, &on_unshared, &[], HIDDEN).await;
    share(
        &db,
        &alice,
        "s2-read",
        (CONVERSATION, &downgraded_chat),
        &user(&dave),
        ResourceAccess::Read,
    )
    .await;
    invalidated(
        &db,
        &on_downgraded,
        &[],
        policy(PolicyReason::InsufficientAccess),
    )
    .await;

    // A step of Dave's own run that writes Alice's artifact rechecks both targets.
    let art = artifact(&db, &scope, "project", &alice).await;
    share(&db, &alice, "a1", (ARTIFACT, &art), &user(&dave), write).await;
    let own = project_run(&db, &scope, &dave).await;
    let step = Some((ARTIFACT, art.as_str()));
    let outcome = recheck_as(&db, WORKER, &own, &[], step, NOW).await;
    assert_eq!(outcome.unwrap(), CONTINUE);
    share(
        &db,
        &alice,
        "a1-read",
        (ARTIFACT, &art),
        &user(&dave),
        ResourceAccess::Read,
    )
    .await;
    // Without the artifact the run itself is still authorized.
    assert_eq!(worker(&db, &own, &[]).await, CONTINUE);
    invalidated_at(
        &db,
        &own,
        &[],
        step,
        NOW,
        policy(PolicyReason::InsufficientAccess),
    )
    .await;

    // An extra target outside the run's scope, or one that does not exist, is concealed.
    let dave_scope = personal_of(&db, &dave).await;
    let foreign = artifact(&db, &dave_scope, "personal", &dave).await;
    for target in [foreign.as_str(), UNKNOWN] {
        let run = project_run(&db, &scope, &dave).await;
        invalidated_at(&db, &run, &[], Some((ARTIFACT, target)), NOW, HIDDEN).await;
    }
    // An extra conversation needs its own write access besides the run's own conversation.
    let run = project_run(&db, &scope, &dave).await;
    let other_chat = Some((CONVERSATION, unshared_chat.as_str()));
    invalidated_at(&db, &run, &[], other_chat, NOW, HIDDEN).await;
}

// --- project lifecycle -------------------------------------------------------------------------

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn archive_and_delete_cancel_live_project_runs_in_the_same_transaction() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let (archived, archived_scope) = create_project(&db, &alice, "p1").await;
    let (deleted, deleted_scope) = create_project(&db, &alice, "p2").await;
    member(
        &db,
        &alice,
        "bob",
        &archived,
        &user(&bob),
        ProjectRole::Editor,
    )
    .await;
    let mut live = Vec::new();
    for (i, state) in LIVE.into_iter().enumerate() {
        let runner = if i % 2 == 0 { &alice } else { &bob };
        let run = project_run(&db, &archived_scope, runner).await;
        set_state(&db, &run, state).await;
        live.push(run);
    }
    let mut ended = Vec::new();
    for state in ENDED {
        let run = project_run(&db, &archived_scope, &bob).await;
        set_state(&db, &run, state).await;
        ended.push((state, run));
    }
    let other_project = [
        project_run(&db, &deleted_scope, &alice).await,
        project_run(&db, &deleted_scope, &alice).await,
    ];
    set_state(&db, &other_project[1], "running").await;
    let personal = personal_run(&db, &bob).await;

    // The worker cannot observe lifecycle, so the API must cancel.
    let mut w = connect(&db.0, WORKER).await;
    expect_state(&mut w, "SELECT * FROM openmettle.project_settings", "42501").await;
    applied(
        projects::archive_project(&mut api(&db).await, &ctx(&alice, "archive"), &archived).await,
    );
    for run in &live {
        assert_eq!(state_of(&db, run).await, cancelled());
        revoked_once(&db, run).await;
        assert_eq!(
            recheck_on(&mut w, run, &[], None, NOW).await.unwrap(),
            terminal("cancelled")
        );
    }
    for (state, run) in &ended {
        assert_eq!(state_of(&db, run).await, ((*state).to_owned(), None));
        assert!(terminal_events(&db, &run.id).await.is_empty());
    }
    for run in other_project.iter().chain([&personal]) {
        assert_eq!(worker(&db, run, &[]).await, CONTINUE);
    }

    // Restore revives nothing; delete cancels the other project's runs.
    applied(
        projects::restore_project(&mut api(&db).await, &ctx(&alice, "restore"), &archived).await,
    );
    for run in &live {
        assert_eq!(state_of(&db, run).await, cancelled());
        revoked_once(&db, run).await;
    }
    applied(projects::delete_project(&mut api(&db).await, &ctx(&alice, "delete"), &deleted).await);
    for run in &other_project {
        assert_eq!(state_of(&db, run).await, cancelled());
        revoked_once(&db, run).await;
        assert_eq!(worker(&db, run, &[]).await, terminal("cancelled"));
    }
    assert_eq!(state_of(&db, &personal).await, ("queued".into(), None));
    assert!(terminal_events(&db, &personal.id).await.is_empty());
}

// --- concurrency -------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "isolated CI PostgreSQL 18 required"]
async fn a_held_recheck_never_blocks_on_and_never_deadlocks_with_bulk_cancellation() {
    let db = TestDb::migrated().await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let admin = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &admin).await;
    let (project, scope) = create_project(&db, &alice, "create").await;
    member(
        &db,
        &alice,
        "bob",
        &project,
        &user(&bob),
        ProjectRole::Editor,
    )
    .await;
    let run = project_run(&db, &scope, &alice).await;
    let sibling = project_run(&db, &scope, &alice).await;

    // The worker holds the run row as a recheck does, then performs the recheck's reads while
    // the archive holds the project row and waits for the run row.
    let mut held = connect(&db.0, WORKER).await;
    let mut tx = held.begin().await.unwrap();
    sqlx::query("SELECT state FROM openmettle.runs WHERE id = $1::uuid FOR NO KEY UPDATE")
        .bind(&run.id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let mut c = api(&db).await;
    let archive_ctx = ctx(&alice, "archive");
    let archiving = projects::archive_project(&mut c, &archive_ctx, &project);
    let recheck_reads = async {
        wait_for_lock_waiters(&db, 1).await;
        let principal = store::hydrate_worker_principal(&mut tx, &alice.user, &alice.approval, NOW);
        assert!(principal.await.unwrap().unwrap().is_active());
        store::load_platform_capabilities(&mut tx).await.unwrap();
        let hydrated = projects::hydrate_project(&mut tx, &project, NOW).await;
        assert!(hydrated.unwrap().is_some());
        let target = projects::hydrate_resource(&mut tx, CONVERSATION, &run.conversation, NOW);
        assert!(target.await.unwrap().is_some());
        tx.commit().await.unwrap();
    };
    let (archived, ()) = tokio::join!(archiving, recheck_reads);
    applied(archived);
    for r in [&run, &sibling] {
        assert_eq!(state_of(&db, r).await, cancelled());
        revoked_once(&db, r).await;
    }

    // A worker that cancels the run it holds first leaves the waiting disablement nothing to
    // change on that row, and no error.
    let mut held = connect(&db.0, WORKER).await;
    let mine = personal_run(&db, &bob).await;
    let other = personal_run(&db, &bob).await;
    let mut tx = held.begin().await.unwrap();
    sqlx::query("SELECT state FROM openmettle.runs WHERE id = $1::uuid FOR NO KEY UPDATE")
        .bind(&mine.id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let disable_ctx = ctx(&admin, "disable-bob");
    let disabling = store::disable_user(&mut c, &disable_ctx, &bob.user);
    let worker_cancel = async {
        wait_for_lock_waiters(&db, 1).await;
        sqlx::query(
            "UPDATE openmettle.runs SET state = 'cancelled', wait_reason = NULL
              WHERE id = $1::uuid",
        )
        .bind(&mine.id)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    };
    let (disabled, ()) = tokio::join!(disabling, worker_cancel);
    applied(disabled);
    for r in [&mine, &other] {
        assert_eq!(state_of(&db, r).await, cancelled());
    }
    // The raw worker statement bypassed the protocol; the disablement cancelled only `other`.
    assert!(terminal_events(&db, &mine.id).await.is_empty());
    revoked_once(&db, &other).await;

    // Rechecks racing a disablement and an archive that both cover the same runs: every
    // transaction commits (no deadlock or lock timeout) and every run ends cancelled.
    for round in 0..6 {
        let runner = account(&mut owner, PROVIDER, true, FUTURE).await;
        let (project, scope) = create_project(&db, &alice, &format!("race-{round}")).await;
        let key = format!("race-member-{round}");
        member(
            &db,
            &alice,
            &key,
            &project,
            &user(&runner),
            ProjectRole::Editor,
        )
        .await;
        let mut races = Vec::new();
        for _ in 0..3 {
            races.push(project_run(&db, &scope, &runner).await);
        }
        let (mut a, mut b) = (api(&db).await, api(&db).await);
        let mut w1 = connect(&db.0, WORKER).await;
        let mut w2 = connect(&db.0, WORKER).await;
        let mut w3 = connect(&db.0, WORKER).await;
        let disable_key = format!("race-disable-{round}");
        let archive_key = format!("race-archive-{round}");
        let disable_ctx = ctx(&admin, &disable_key);
        let archive_ctx = ctx(&alice, &archive_key);
        let (disabled, archived, x, y, z) = tokio::join!(
            store::disable_user(&mut a, &disable_ctx, &runner.user),
            projects::archive_project(&mut b, &archive_ctx, &project),
            recheck_on(&mut w1, &races[0], &[], None, NOW),
            recheck_on(&mut w2, &races[1], &[], None, NOW),
            recheck_on(&mut w3, &races[2], &[], None, NOW),
        );
        applied(disabled);
        applied(archived);
        for outcome in [x, y, z] {
            let outcome = outcome.unwrap();
            assert!(
                outcome == CONTINUE
                    || outcome == RunRecheckOutcome::Invalidated(INACTIVE)
                    || outcome == terminal("cancelled"),
                "round {round}: {outcome:?}"
            );
        }
        // Whichever path cancelled a run, it recorded the one terminal event.
        for r in &races {
            assert_eq!(state_of(&db, r).await, cancelled(), "round {round}");
            revoked_once(&db, r).await;
        }
    }
}
