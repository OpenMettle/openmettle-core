//! ADR 0044 (V1-06 proxy increment 2a): a run round is handed off without a gateway binding,
//! generation or policy row (`openmettle.gateway_handoff_round`, worker only), and the proxy
//! spends its one dispatch with the round's secret (`openmettle.gateway_dispatch`, gateway
//! only). Both functions are called directly, under the provisioned role logins.
//!
//! The fixture is a database upgraded from version 23 with one account, so metering is not
//! enforced and a round needs no quota hold: the round's rows are written by hand with a secret
//! the test knows. The quota and worker-lease suites cover the handoff through the library
//! with its holds.
use super::authz_store::{Account, FUTURE, NOW, PROVIDER, account, applied, ctx, providers};
use super::*;
use openmettle_core::{
    authz::{
        Grantee, ProjectRole,
        gateway::{
            Error as StoreError,
            settlement::{self, Outcome},
        },
        leases::LeaseSettings,
        projects,
        runs::{self as queue, Admission, AdmissionLimits, ClaimLimits, RunAdmission},
    },
    provider_http::gateway::UsageReport,
    runs::{RunInput, WriteTransaction},
};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;

const INSTALL: &str = "00000000-0000-4000-8000-0000000000b1";
const UNKNOWN: &str = "00000000-0000-4000-8000-0000000000bf";
const LIMITS: AdmissionLimits = AdmissionLimits {
    live_per_actor: 64,
    live_per_scope: 64,
    queued_in_instance: 64,
    queue_timeout: Duration::from_secs(300),
    round_cap: 4,
};
const CLAIMS: ClaimLimits = ClaimLimits {
    executing_per_actor: 64,
    executing_per_scope: 64,
};
const LEASES: LeaseSettings = LeaseSettings {
    lease: Duration::from_secs(120),
    execution_timeout: Duration::from_secs(600),
};
const HANDOFF: &str = "SELECT openmettle.gateway_handoff_round($1::uuid,$2,$3::uuid)";
const DISPATCH: &str = "SELECT replayed,installation,scope,source,principal,model
    FROM openmettle.gateway_dispatch($1::uuid,$2)";

/// One row of `gateway_dispatch`: whether it is a replay, then the routing fields.
type Dispatched = (
    bool,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// A snapshot of model `a` that requires `capabilities`.
fn requiring(capabilities: serde_json::Value) -> Vec<u8> {
    json!({"effective": {"model": "a"}, "required_capabilities": capabilities})
        .to_string()
        .into_bytes()
}

/// One claimed run.
struct Claimed {
    actor: Account,
    scope: String,
    id: String,
    lease: String,
    reservation: String,
}

/// One reserved round and what only its holder knows.
struct Round {
    run: String,
    request: String,
    secret: [u8; 32],
    lease: String,
}

struct Rounds {
    db: TestDb,
    owner: PgConnection,
    actor: Account,
    scope: String,
    /// Numbers the admission keys and dispatch secrets of this fixture.
    next: u8,
}

impl Rounds {
    async fn new() -> Self {
        let db = TestDb::new().await;
        let settings = db.settings(Duration::from_secs(10));
        migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
        let mut owner = connect(&db.0, OWNER).await;
        providers(&mut owner).await;
        let actor = account(&mut owner, PROVIDER, true, FUTURE).await;
        let scope = authz_runs::personal_of(&db, &actor).await;
        migrate::apply(&settings, MIGRATIONS).await.unwrap();
        let enforced: bool =
            sqlx::query_scalar("SELECT metering_enforced FROM openmettle.quota_enforcement")
                .fetch_one(&mut owner)
                .await
                .unwrap();
        assert!(!enforced);
        Self {
            db,
            owner,
            actor,
            scope,
            next: 1,
        }
    }

    fn number(&mut self) -> u8 {
        self.next += 1;
        self.next
    }

    /// A run of `actor` on a new conversation in `scope`, admitted with the snapshot
    /// `(format, version, config)` for `rounds` rounds and claimed by a worker.
    async fn claimed(
        &mut self,
        actor: &Account,
        (scope, kind): (&str, &str),
        (format, version, config): (&str, i32, &[u8]),
        rounds: i64,
    ) -> Claimed {
        let chat = authz_runs::chat(&self.db, scope, kind, actor).await;
        let mut api = connect(&self.db.0, API).await;
        let (branch, message) = quotas::branch_and_message(&mut api, scope, &chat).await;
        let key = format!("round-{}", self.number());
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        let admitted = queue::admit_run(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope,
                    actor: &actor.user,
                    conversation: &chat,
                    branch: &branch,
                    message: &message,
                    key: &key,
                    format,
                    version,
                    input: b"{}",
                    config,
                },
                actor_approval_id: &actor.approval,
                capabilities: &[],
                requested_rounds: Some(rounds),
                now_ms: NOW,
                cost_qualified: None,
            },
            &LIMITS,
        )
        .await
        .unwrap();
        let run_id = match admitted {
            Admission::Admitted { run_id, .. } => run_id,
            other => panic!("expected an admission, got {other:?}"),
        };
        tx.commit().await.unwrap();
        let claim = queue::claim_next(&mut connect(&self.db.0, WORKER).await, &CLAIMS, &LEASES)
            .await
            .unwrap()
            .expect("a queued run");
        assert_eq!(claim.run_id, run_id);
        let reservation: String = sqlx::query_scalar(
            "INSERT INTO openmettle.gateway_reservations
                 (id,scope_id,actor_user_id,approval_id,run_id,units)
             VALUES (gen_random_uuid(),$1::uuid,$2::uuid,$3::uuid,$4::uuid,1000)
             RETURNING id::text",
        )
        .bind(scope)
        .bind(&actor.user)
        .bind(&actor.approval)
        .bind(&run_id)
        .fetch_one(&mut self.owner)
        .await
        .unwrap();
        Claimed {
            actor: actor.clone(),
            scope: scope.to_owned(),
            id: run_id,
            lease: claim.claim_token,
            reservation,
        }
    }

    /// Reserves `round` of `run` for `model`, as the worker role, under a new dispatch secret.
    async fn reserve(&mut self, run: &Claimed, round: i32, model: &str) -> Round {
        let request: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut self.owner)
            .await
            .unwrap();
        let secret = [self.number(); 32];
        sqlx::query(
            "INSERT INTO openmettle.gateway_requests
                 (id,reservation_id,scope_id,actor_user_id,approval_id,installation,model,units,
                  dispatch_hash,run_id,round)
             VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::uuid,$7,10,sha256($8),
                     $9::uuid,$10)",
        )
        .bind(&request)
        .bind(&run.reservation)
        .bind(&run.scope)
        .bind(&run.actor.user)
        .bind(&run.actor.approval)
        .bind(INSTALL)
        .bind(model)
        .bind(secret.as_slice())
        .bind(&run.id)
        .bind(round)
        .execute(&mut connect(&self.db.0, WORKER).await)
        .await
        .unwrap();
        Round {
            run: run.id.clone(),
            request,
            secret,
            lease: run.lease.clone(),
        }
    }

    /// Round 1, for model `a`, of a new personal-scope run of the fixture's account admitted
    /// with `config` as an `openmettle.conversation` version 1 snapshot.
    async fn round(&mut self, config: &[u8]) -> Round {
        let (actor, scope) = (self.actor.clone(), self.scope.clone());
        let snapshot = ("openmettle.conversation", 1, config);
        let run = self
            .claimed(&actor, (&scope, "personal"), snapshot, 1)
            .await;
        self.reserve(&run, 1, "a").await
    }

    /// Calls `gateway_handoff_round` as `role`, in its own `READ COMMITTED` transaction.
    async fn handoff_as(
        &self,
        role: &str,
        round: &Round,
        secret: &[u8],
        lease: &str,
    ) -> Result<bool, sqlx::Error> {
        sqlx::query_scalar(HANDOFF)
            .bind(&round.request)
            .bind(secret)
            .bind(lease)
            .fetch_one(&mut connect(&self.db.0, role).await)
            .await
    }

    async fn handoff(&self, round: &Round) -> bool {
        self.handoff_as(WORKER, round, &round.secret, &round.lease)
            .await
            .unwrap()
    }

    /// The request's state, report source, whether it names a binding, and whether it was
    /// dispatched.
    async fn stored(&mut self, round: &Round) -> (String, Option<String>, bool, bool) {
        sqlx::query_as(
            "SELECT state,report_source::text,binding_id IS NOT NULL,dispatched_at IS NOT NULL
               FROM openmettle.gateway_requests WHERE id=$1::uuid",
        )
        .bind(&round.request)
        .fetch_one(&mut self.owner)
        .await
        .unwrap()
    }

    /// The handoff is refused and the request stays `reserved`.
    async fn refused(&mut self, round: &Round, why: &str) {
        assert!(!self.handoff(round).await, "{why}");
        assert_eq!(
            self.stored(round).await,
            ("reserved".to_owned(), None, false, false),
            "{why}"
        );
    }

    /// The handoff succeeds: the request reports under its installation and names no binding.
    async fn authorized(&mut self, round: &Round, why: &str) {
        assert!(self.handoff(round).await, "{why}");
        assert_eq!(
            self.stored(round).await,
            (
                "handed_off".to_owned(),
                Some(INSTALL.to_owned()),
                false,
                false
            ),
            "{why}"
        );
    }

    /// Runs one statement with `$1` bound to `id`, as the owner.
    async fn owner_exec(&mut self, sql: &'static str, id: &str) {
        let done = sqlx::query(sql)
            .bind(id)
            .execute(&mut self.owner)
            .await
            .unwrap();
        assert_eq!(done.rows_affected(), 1, "{sql}");
    }

    /// Every row of `gateway_dispatch` for `request` and `secret`, called as `role`.
    async fn dispatch_as(
        &self,
        role: &str,
        request: &str,
        secret: &[u8],
    ) -> Result<Vec<Dispatched>, sqlx::Error> {
        sqlx::query_as(DISPATCH)
            .bind(request)
            .bind(secret)
            .fetch_all(&mut connect(&self.db.0, role).await)
            .await
    }

    async fn dispatch(&self, round: &Round) -> Vec<Dispatched> {
        self.dispatch_as(pg::GATEWAY, &round.request, &round.secret)
            .await
            .unwrap()
    }

    /// The row of a first dispatch of a round of the fixture's account.
    fn routed(&self) -> Dispatched {
        (
            false,
            Some(INSTALL.to_owned()),
            Some(self.scope.clone()),
            Some(INSTALL.to_owned()),
            Some(self.actor.user.clone()),
            Some("a".to_owned()),
        )
    }

    /// Rows in the ADR 0037 provisioning tables.
    async fn provisioned(&mut self) -> i64 {
        sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM openmettle.gateway_bindings)
                  + (SELECT count(*) FROM openmettle.gateway_generations)
                  + (SELECT count(*) FROM openmettle.gateway_policy)
                  + (SELECT count(*) FROM openmettle.gateway_intents)",
        )
        .fetch_one(&mut self.owner)
        .await
        .unwrap()
    }
}

const REPLAY: Dispatched = (true, None, None, None, None, None);

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_run_round_is_handed_off_without_a_binding_generation_or_policy() {
    let mut f = Rounds::new().await;
    let round = f.round(&quotas::snapshot(100)).await;
    // Only the holder of the dispatch secret and of the run's lease can hand the round off.
    for (secret, lease) in [
        (&[0xee; 32][..], round.lease.as_str()),
        (&round.secret[..31], round.lease.as_str()),
        (&round.secret[..], UNKNOWN),
    ] {
        let handed = f.handoff_as(WORKER, &round, secret, lease).await.unwrap();
        assert!(!handed);
    }
    assert_eq!(
        f.stored(&round).await,
        ("reserved".to_owned(), None, false, false)
    );
    f.authorized(&round, "a live run round of an enabled, approved user")
        .await;
    // The handoff cannot be repeated.
    assert!(!f.handoff(&round).await);
    assert_eq!(f.provisioned().await, 0);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn the_handoff_is_restricted_to_the_worker_and_to_read_committed() {
    let mut f = Rounds::new().await;
    let round = f.round(&quotas::snapshot(100)).await;
    for role in [API, pg::GATEWAY, ISSUANCE] {
        let denied = f
            .handoff_as(role, &round, &round.secret, &round.lease)
            .await;
        assert_eq!(sqlstate(denied), "42501", "{role}");
    }
    // A snapshot taken before the function's locks could miss a committed revocation.
    let mut worker = connect(&f.db.0, WORKER).await;
    worker
        .execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
        .await
        .unwrap();
    let stale = sqlx::query_scalar::<_, bool>(HANDOFF)
        .bind(&round.request)
        .bind(round.secret.as_slice())
        .bind(&round.lease)
        .fetch_one(&mut worker)
        .await;
    assert_eq!(sqlstate(stale), "25000");
    worker.execute("ROLLBACK").await.unwrap();
    assert_eq!(
        f.stored(&round).await,
        ("reserved".to_owned(), None, false, false)
    );
    f.authorized(&round, "the worker under READ COMMITTED")
        .await;
}

/// Each case withdraws one thing the handoff checks, sees the round refused and still
/// `reserved`, and then, where the change can be undone, undoes it and sees the same round
/// handed off: nothing else about the round refused it.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn each_withdrawn_authority_refuses_the_round_and_leaves_it_reserved() {
    let mut f = Rounds::new().await;
    let (user, approval) = (f.actor.user.clone(), f.actor.approval.clone());
    let plain = quotas::snapshot(100);
    for (why, withdraw, restore, id) in [
        (
            "a disabled user",
            "UPDATE openmettle.users SET disabled_at=clock_timestamp() WHERE id=$1::uuid",
            "UPDATE openmettle.users SET disabled_at=NULL WHERE id=$1::uuid",
            &user,
        ),
        (
            "an inactive approval",
            "UPDATE openmettle.local_identity_approvals SET active=false WHERE id=$1::uuid",
            "UPDATE openmettle.local_identity_approvals SET active=true WHERE id=$1::uuid",
            &approval,
        ),
        (
            "an expired approval",
            "UPDATE openmettle.local_identity_approvals SET expires_ms=1 WHERE id=$1::uuid",
            "UPDATE openmettle.local_identity_approvals SET expires_ms=4102444800000
              WHERE id=$1::uuid",
            &approval,
        ),
    ] {
        let round = f.round(&plain).await;
        f.owner_exec(withdraw, id).await;
        f.refused(&round, why).await;
        f.owner_exec(restore, id).await;
        f.authorized(&round, why).await;
    }

    // A stale lease: another holder's token, then this holder's after it expired.
    let round = f.round(&plain).await;
    let other = f
        .handoff_as(WORKER, &round, &round.secret, UNKNOWN)
        .await
        .unwrap();
    assert!(!other);
    f.owner_exec(
        "UPDATE openmettle.runs SET lease_expires_at=clock_timestamp()-interval '1 second'
          WHERE id=$1::uuid",
        &round.run,
    )
    .await;
    f.refused(&round, "an expired lease").await;
    f.owner_exec(
        "UPDATE openmettle.runs SET lease_expires_at=clock_timestamp()+interval '1 minute'
          WHERE id=$1::uuid",
        &round.run,
    )
    .await;
    f.authorized(&round, "a renewed lease").await;

    // A cancelled run.
    let round = f.round(&plain).await;
    let principal = authz_store::principal(&f.db, &f.actor).await;
    queue::cancel_run(
        &mut connect(&f.db.0, API).await,
        &principal,
        &f.scope,
        &round.run,
    )
    .await
    .unwrap();
    f.refused(&round, "a cancelled run").await;

    // A round over the run's limit of one, next to round 1 of the same run.
    let (actor, scope) = (f.actor.clone(), f.scope.clone());
    let snapshot = ("openmettle.conversation", 1, &plain[..]);
    let run = f.claimed(&actor, (&scope, "personal"), snapshot, 1).await;
    let second = f.reserve(&run, 2, "a").await;
    f.refused(&second, "round 2 of a one-round run").await;
    let first = f.reserve(&run, 1, "a").await;
    f.authorized(&first, "round 1 of a one-round run").await;

    // A model other than the snapshot's, next to the snapshot's model on the same run.
    let run = f.claimed(&actor, (&scope, "personal"), snapshot, 2).await;
    let other_model = f.reserve(&run, 1, "b").await;
    f.refused(&other_model, "a model the run was not admitted for")
        .await;
    let admitted_model = f.reserve(&run, 2, "a").await;
    f.authorized(&admitted_model, "the model the run was admitted for")
        .await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn required_capabilities_come_from_the_snapshot_and_are_checked_live() {
    let mut f = Rounds::new().await;
    let user = f.actor.user.clone();
    // Available unless denied, for the user or for the platform.
    let round = f
        .round(&requiring(json!({"fixture.round": "on_by_default"})))
        .await;
    f.owner_exec(
        "INSERT INTO openmettle.user_capability_denies (user_id,capability,denied,updated_by_user_id)
         VALUES ($1::uuid,'fixture.round',true,$1::uuid)",
        &user,
    )
    .await;
    f.refused(&round, "a capability denied to the user").await;
    f.owner_exec(
        "UPDATE openmettle.user_capability_denies SET denied=false WHERE user_id=$1::uuid",
        &user,
    )
    .await;
    f.owner_exec(
        "INSERT INTO openmettle.platform_capability_denies (capability,denied,updated_by_user_id)
         VALUES ('fixture.round',true,$1::uuid)",
        &user,
    )
    .await;
    f.refused(&round, "a capability denied on the platform")
        .await;
    f.owner_exec(
        "UPDATE openmettle.platform_capability_denies SET denied=false
          WHERE updated_by_user_id=$1::uuid",
        &user,
    )
    .await;
    f.authorized(&round, "a capability no longer denied").await;

    // Opt-in: refused until granted.
    let round = f
        .round(&requiring(json!({"fixture.optin": "opt_in"})))
        .await;
    f.refused(&round, "an opt-in capability that was not granted")
        .await;
    f.owner_exec(
        "INSERT INTO openmettle.user_capability_grants (user_id,capability,granted,updated_by_user_id)
         VALUES ($1::uuid,'fixture.optin',true,$1::uuid)",
        &user,
    )
    .await;
    f.authorized(&round, "a granted opt-in capability").await;
}

/// A snapshot that is not the admission document the function expects refuses the round: it
/// never falls back to an unchecked model or to no required capability.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn an_unreadable_snapshot_refuses_the_round() {
    let mut f = Rounds::new().await;
    let (actor, scope) = (f.actor.clone(), f.scope.clone());
    let readable = quotas::snapshot(100);
    let unreadable: [(&str, i32, &[u8]); 13] = [
        ("openmettle.conversation", 1, b"{}"),
        ("openmettle.conversation", 1, b"null"),
        ("openmettle.conversation", 1, b"not json"),
        ("openmettle.conversation", 1, b"\xff\xfe"),
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"a"}}"#,
        ),
        (
            "openmettle.conversation",
            1,
            br#"{"required_capabilities":{}}"#,
        ),
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":["a"]},"required_capabilities":{}}"#,
        ),
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"a"},"required_capabilities":[]}"#,
        ),
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"a"},"required_capabilities":{"fixture.round":true}}"#,
        ),
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"a"},"required_capabilities":{"fixture.round":"required"}}"#,
        ),
        // A nesting no writer produces.
        (
            "openmettle.conversation",
            1,
            br#"{"config":{"effective":{"model":"a"},"required_capabilities":{}}}"#,
        ),
        // The readable document under another format or version.
        ("openmettle.synthetic-run", 1, &readable),
        ("openmettle.conversation", 2, &readable),
    ];
    for snapshot in unreadable {
        let run = f.claimed(&actor, (&scope, "personal"), snapshot, 1).await;
        let round = f.reserve(&run, 1, "a").await;
        let why = format!(
            "{} {} {}",
            snapshot.0,
            snapshot.1,
            String::from_utf8_lossy(snapshot.2)
        );
        f.refused(&round, &why).await;
    }
    let round = f.round(&readable).await;
    f.authorized(&round, "the readable snapshot").await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_project_round_needs_a_live_editor_role_in_a_project_that_is_not_archived() {
    let mut f = Rounds::new().await;
    let lead = f.actor.clone();
    let member = account(&mut f.owner, PROVIDER, true, FUTURE).await;
    let (project, scope) = run_admission::new_project(&f.db, &lead, "rounds-project").await;
    let grantee = Grantee::User(member.user.clone());
    let database = f.db.0.clone();
    let role = async |key: &str, role: ProjectRole| {
        applied(
            projects::set_project_member_role(
                &mut connect(&database, API).await,
                &ctx(&lead, key),
                &project,
                &grantee,
                role,
            )
            .await,
        );
    };
    role("rounds-editor", ProjectRole::Editor).await;
    let plain = quotas::snapshot(100);
    let snapshot = ("openmettle.conversation", 1, &plain[..]);

    // The role is read when the round is handed off, not pinned at admission.
    let run = f.claimed(&member, (&scope, "project"), snapshot, 1).await;
    let round = f.reserve(&run, 1, "a").await;
    role("rounds-viewer", ProjectRole::Viewer).await;
    f.refused(&round, "a member demoted to viewer").await;
    role("rounds-editor-again", ProjectRole::Editor).await;
    f.authorized(&round, "a member who is an editor again")
        .await;

    let run = f.claimed(&member, (&scope, "project"), snapshot, 1).await;
    let round = f.reserve(&run, 1, "a").await;
    f.owner_exec(
        "UPDATE openmettle.project_settings SET archived_at=greatest(created_at,clock_timestamp())
          WHERE project_id=$1::uuid",
        &project,
    )
    .await;
    f.refused(&round, "an archived project").await;
    f.owner_exec(
        "UPDATE openmettle.project_settings SET archived_at=NULL WHERE project_id=$1::uuid",
        &project,
    )
    .await;
    f.authorized(&round, "a restored project").await;
    assert_eq!(f.provisioned().await, 0);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn the_dispatch_is_restricted_to_the_gateway_and_proves_the_secret() {
    let mut f = Rounds::new().await;
    let plain = quotas::snapshot(100);
    let reserved = f.round(&plain).await;
    let round = f.round(&plain).await;
    f.authorized(&round, "a live run round").await;
    for role in [API, WORKER, ISSUANCE] {
        let denied = f.dispatch_as(role, &round.request, &round.secret).await;
        assert_eq!(sqlstate(denied), "42501", "{role}");
    }
    let mut gateway = connect(&f.db.0, pg::GATEWAY).await;
    gateway
        .execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
        .await
        .unwrap();
    let stale = sqlx::query_as::<_, Dispatched>(DISPATCH)
        .bind(&round.request)
        .bind(round.secret.as_slice())
        .fetch_all(&mut gateway)
        .await;
    assert_eq!(sqlstate(stale), "25000");
    gateway.execute("ROLLBACK").await.unwrap();

    // A wrong secret, an unknown request and a request not handed off yet are refused alike:
    // no row, and nothing spent.
    for (request, secret) in [
        (round.request.as_str(), &[0xee; 32][..]),
        (round.request.as_str(), &round.secret[..31]),
        (round.request.as_str(), &reserved.secret[..]),
        (UNKNOWN, &round.secret[..]),
        (reserved.request.as_str(), &reserved.secret[..]),
    ] {
        let rows = f.dispatch_as(pg::GATEWAY, request, secret).await.unwrap();
        assert_eq!(rows, []);
    }
    assert!(!f.stored(&round).await.3);
    assert!(!f.stored(&reserved).await.3);

    // The first dispatch returns the stored routing fields; the actor is the principal of a
    // request without a binding. Every later one is a replay.
    assert_eq!(f.dispatch(&round).await, [f.routed()]);
    assert!(f.stored(&round).await.3);
    assert_eq!(f.dispatch(&round).await, [REPLAY]);
    assert_eq!(f.dispatch(&round).await, [REPLAY]);
    // A replay is reported only to the holder of the secret.
    let rows = f
        .dispatch_as(pg::GATEWAY, &round.request, &[0xee; 32])
        .await
        .unwrap();
    assert_eq!(rows, []);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn concurrent_dispatches_of_one_round_spend_it_exactly_once() {
    let mut f = Rounds::new().await;
    let plain = quotas::snapshot(100);
    for _ in 0..6 {
        let round = f.round(&plain).await;
        f.authorized(&round, "a live run round").await;
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let callers: Vec<_> = (0..3)
            .map(|_| {
                let barrier = barrier.clone();
                let options = role_options(&f.db.0, pg::GATEWAY);
                let (request, secret) = (round.request.clone(), round.secret);
                tokio::spawn(async move {
                    let mut c = PgConnection::connect_with(&options).await.unwrap();
                    barrier.wait().await;
                    sqlx::query_as::<_, Dispatched>(DISPATCH)
                        .bind(request)
                        .bind(secret.as_slice())
                        .fetch_all(&mut c)
                        .await
                        .unwrap()
                })
            })
            .collect();
        let mut rows = Vec::new();
        for caller in callers {
            rows.extend(caller.await.unwrap());
        }
        rows.sort();
        assert_eq!(rows, [f.routed(), REPLAY, REPLAY]);
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_cancelled_run_is_not_dispatched() {
    let mut f = Rounds::new().await;
    let round = f.round(&quotas::snapshot(100)).await;
    f.authorized(&round, "a live run round").await;
    let principal = authz_store::principal(&f.db, &f.actor).await;
    queue::cancel_run(
        &mut connect(&f.db.0, API).await,
        &principal,
        &f.scope,
        &round.run,
    )
    .await
    .unwrap();
    assert_eq!(f.dispatch(&round).await, []);
    assert_eq!(
        f.stored(&round).await,
        (
            "handed_off".to_owned(),
            Some(INSTALL.to_owned()),
            false,
            false
        )
    );
}

/// A dispatch that waits for the request row decides after the wait: a cancellation committed
/// meanwhile is seen. The holder stands for a settlement or another dispatch in flight.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_run_cancelled_while_its_dispatch_waited_is_not_dispatched() {
    let mut f = Rounds::new().await;
    let round = f.round(&quotas::snapshot(100)).await;
    f.authorized(&round, "a live run round").await;
    let mut holder = connect(&f.db.0, OWNER).await;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut holder)
        .await
        .unwrap();
    holder.execute("BEGIN").await.unwrap();
    sqlx::query("SELECT FROM openmettle.gateway_requests WHERE id=$1::uuid FOR NO KEY UPDATE")
        .bind(&round.request)
        .execute(&mut holder)
        .await
        .unwrap();
    let options = role_options(&f.db.0, pg::GATEWAY);
    let (request, secret) = (round.request.clone(), round.secret);
    let waiting = tokio::spawn(async move {
        let mut c = PgConnection::connect_with(&options).await.unwrap();
        sqlx::query_as::<_, Dispatched>(DISPATCH)
            .bind(request)
            .bind(secret.as_slice())
            .fetch_all(&mut c)
            .await
            .unwrap()
    });
    wait_for_blocked_peer(&f.db, pid).await;
    let principal = authz_store::principal(&f.db, &f.actor).await;
    queue::cancel_run(
        &mut connect(&f.db.0, API).await,
        &principal,
        &f.scope,
        &round.run,
    )
    .await
    .unwrap();
    holder.execute("COMMIT").await.unwrap();
    assert_eq!(waiting.await.unwrap(), []);
    assert!(!f.stored(&round).await.3);
}

/// The CHECK that replaced migration 23's unnamed one accepts a request without a binding and
/// refuses every half-set combination. `gateway::unmetered_handoff_replays_only_accepted_token_
/// components_after_upgrade` carries a bound, handed-off row of version 23 through the upgrade.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn the_handoff_check_accepts_unbound_rows_and_rejects_half_set_ones() {
    let mut f = Rounds::new().await;
    let plain = quotas::snapshot(100);
    let reserved = f.round(&plain).await;
    let handed = f.round(&plain).await;
    f.authorized(&handed, "a live run round").await;
    assert_eq!(f.dispatch(&handed).await, [f.routed()]);
    let checks: Vec<String> = sqlx::query_scalar(
        "SELECT conname::text FROM pg_constraint
          WHERE conrelid='openmettle.gateway_requests'::regclass AND contype='c'
            AND pg_get_constraintdef(oid) LIKE '%binding_id%'",
    )
    .fetch_all(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(checks, ["gateway_requests_handoff_check"]);
    for (id, change) in [
        (&reserved.request, "dispatched_at=clock_timestamp()"),
        (&reserved.request, "report_source=installation"),
        (
            &reserved.request,
            "state='released',report_source=installation",
        ),
        (
            &reserved.request,
            "binding_id=gen_random_uuid(),generation=1,policy_revision=1",
        ),
        (&handed.request, "report_source=NULL"),
        (&handed.request, "binding_id=gen_random_uuid()"),
        (&handed.request, "binding_id=gen_random_uuid(),generation=1"),
        (&handed.request, "generation=1,policy_revision=1"),
    ] {
        let sql = format!("UPDATE openmettle.gateway_requests SET {change} WHERE id='{id}'");
        let refused = sqlx::query(AssertSqlSafe(sql.clone()))
            .execute(&mut f.owner)
            .await;
        let Err(sqlx::Error::Database(error)) = refused else {
            panic!("{sql} was accepted");
        };
        assert_eq!(
            (error.code().as_deref(), error.constraint()),
            (Some("23514"), Some("gateway_requests_handoff_check")),
            "{sql}"
        );
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_request_without_a_binding_settles_under_its_actor_and_installation() {
    let mut f = Rounds::new().await;
    let round = f.round(&quotas::snapshot(100)).await;
    f.authorized(&round, "a live run round").await;
    let gateway = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(pg::GATEWAY));
    let report = UsageReport {
        request: round.request.clone(),
        installation: INSTALL.into(),
        principal: f.actor.user.clone(),
        scope: f.scope.clone(),
        source: INSTALL.into(),
        report_id: round.request.clone(),
        revision: 0,
        r#final: true,
        prompt_tokens: Some(4),
        completion_tokens: Some(3),
        reasoning_tokens: None,
        reasoning_included: None,
        cost: None,
        unit: None,
    };
    assert_eq!(f.dispatch(&round).await, [f.routed()]);
    // Another principal, source, installation or scope does not name this request.
    for wrong in [
        UsageReport {
            principal: UNKNOWN.into(),
            ..report.clone()
        },
        UsageReport {
            source: UNKNOWN.into(),
            ..report.clone()
        },
        UsageReport {
            installation: UNKNOWN.into(),
            ..report.clone()
        },
        UsageReport {
            scope: UNKNOWN.into(),
            ..report.clone()
        },
    ] {
        assert_eq!(
            settlement::ingest(&gateway, &wrong).await,
            Err(StoreError::Refused)
        );
    }
    assert_eq!(
        settlement::ingest(&gateway, &report).await,
        Ok(Outcome::Applied)
    );
    assert_eq!(
        settlement::ingest(&gateway, &report).await,
        Ok(Outcome::Duplicate)
    );
    let settled: (i64, bool, Option<String>, i64, bool) = sqlx::query_as(
        "SELECT s.revision,s.final,s.measured::text,s.outstanding,q.settled_final
           FROM openmettle.gateway_settlements s
           JOIN openmettle.gateway_requests q ON q.id=s.request_id
          WHERE s.request_id=$1::uuid",
    )
    .bind(&round.request)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(settled, (0, true, Some("7".to_owned()), 0, true));
    assert_eq!(f.provisioned().await, 0);
}
