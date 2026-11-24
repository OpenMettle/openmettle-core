//! ADR 0044 (V1-06 proxy increment 2a): a run round is handed off without a gateway binding,
//! generation or policy row (`openmettle.gateway_handoff_round`, worker only), and the proxy
//! spends its one dispatch with the round's bearer (`openmettle.gateway_dispatch`, gateway
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
        Grantee, ProjectRole, ResourceAccess, ResourceKind,
        gateway::{
            Error as StoreError,
            settlement::{self, Outcome},
        },
        leases::{self, Lease, LeaseSettings},
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
/// The worker sends the hash of the bearer it chose, never the bearer.
const HANDOFF: &str = "SELECT openmettle.gateway_handoff_round($1::uuid,$2,$3::uuid,sha256($4))";
/// The last statement of a handoff transaction.
const CONFIRM: &str = "SELECT openmettle.gateway_handoff_round_confirm($1::uuid,$2,$3::uuid)";
/// The proxy sends the hash of the bearer its caller presented, never the bearer.
const DISPATCH: &str = "SELECT replayed,installation,scope,source,principal,model
    FROM openmettle.gateway_dispatch($1::uuid,sha256($2))";

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
    /// The dispatch secret: the reserving worker's proof to the database.
    secret: [u8; 32],
    /// The bearer the worker would present to the proxy; the database stores its hash.
    bearer: [u8; 32],
    lease: String,
}

struct Rounds {
    db: TestDb,
    owner: PgConnection,
    actor: Account,
    scope: String,
    /// Numbers the admission keys, dispatch secrets and bearers of this fixture.
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
        self.claimed_on(actor, (scope, &chat), (format, version, config), rounds)
            .await
    }

    /// [`Self::claimed`] on the existing conversation `chat`, which `actor` need not own.
    async fn claimed_on(
        &mut self,
        actor: &Account,
        (scope, chat): (&str, &str),
        (format, version, config): (&str, i32, &[u8]),
        rounds: i64,
    ) -> Claimed {
        let mut api = connect(&self.db.0, API).await;
        let (branch, message) = quotas::branch_and_message(&mut api, scope, chat).await;
        let key = format!("round-{}", self.number());
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        let admitted = queue::admit_run(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope,
                    actor: &actor.user,
                    conversation: chat,
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
            bearer: [self.number(); 32],
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

    /// Runs a handoff transaction as `role` under `READ COMMITTED`: `gateway_handoff_round`,
    /// then `gateway_handoff_round_confirm`, then the commit. It is refused when the first
    /// returns false or the second withdraws the authority (42501).
    async fn handoff_as(
        &self,
        role: &str,
        round: &Round,
        secret: &[u8],
        lease: &str,
    ) -> Result<bool, sqlx::Error> {
        let mut c = connect(&self.db.0, role).await;
        c.execute("BEGIN").await?;
        let handed: bool = sqlx::query_scalar(HANDOFF)
            .bind(&round.request)
            .bind(secret)
            .bind(lease)
            .bind(round.bearer.as_slice())
            .fetch_one(&mut c)
            .await?;
        if !handed {
            c.execute("ROLLBACK").await?;
            return Ok(false);
        }
        let confirmed = sqlx::query(CONFIRM)
            .bind(&round.request)
            .bind(secret)
            .bind(lease)
            .execute(&mut c)
            .await;
        match confirmed {
            Ok(_) => {
                c.execute("COMMIT").await?;
                Ok(true)
            }
            Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("42501") => {
                c.execute("ROLLBACK").await?;
                Ok(false)
            }
            Err(e) => Err(e),
        }
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

    /// Every row of `gateway_dispatch` for `request` and `bearer`, called as `role`.
    async fn dispatch_as(
        &self,
        role: &str,
        request: &str,
        bearer: &[u8],
    ) -> Result<Vec<Dispatched>, sqlx::Error> {
        sqlx::query_as(DISPATCH)
            .bind(request)
            .bind(bearer)
            .fetch_all(&mut connect(&self.db.0, role).await)
            .await
    }

    async fn dispatch(&self, round: &Round) -> Vec<Dispatched> {
        self.dispatch_as(pg::GATEWAY, &round.request, &round.bearer)
            .await
            .unwrap()
    }

    /// Starts a dispatch of `round` on a gateway connection of its own, already open.
    async fn dispatching(&self, round: &Round) -> tokio::task::JoinHandle<Vec<Dispatched>> {
        let mut c = connect(&self.db.0, pg::GATEWAY).await;
        let (request, bearer) = (round.request.clone(), round.bearer);
        tokio::spawn(async move {
            sqlx::query_as(DISPATCH)
                .bind(request)
                .bind(bearer.as_slice())
                .fetch_all(&mut c)
                .await
                .unwrap()
        })
    }

    /// Starts the library's lease release of `round`'s run on `worker`.
    fn releasing(
        &self,
        mut worker: PgConnection,
        round: &Round,
    ) -> tokio::task::JoinHandle<Result<(), leases::LeaseError>> {
        let (scope, run, claim) = (self.scope.clone(), round.run.clone(), round.lease.clone());
        tokio::spawn(async move {
            let lease = Lease {
                scope_id: &scope,
                run_id: &run,
                claim_token: &claim,
            };
            leases::release_lease(&mut worker, &lease).await
        })
    }

    /// Waits until `sql`, with `$1` bound to `id`, is true on the database's own clock.
    async fn until(&mut self, sql: &'static str, id: &str, why: &str) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let done: bool = sqlx::query_scalar(sql)
                .bind(id)
                .fetch_one(&mut self.owner)
                .await
                .unwrap();
            if done {
                return;
            }
            assert!(Instant::now() < deadline, "{why}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
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

/// A final usage report and its settlement for request `$1`, written as the owner.
const SETTLED: [&str; 2] = [
    "INSERT INTO openmettle.gateway_usage_reports
         (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens)
     SELECT id,report_source,gen_random_uuid(),0,true,1,1
       FROM openmettle.gateway_requests WHERE id=$1::uuid",
    "INSERT INTO openmettle.gateway_settlements (request_id,revision,final,measured,outstanding)
     VALUES ($1::uuid,0,true,2,0)",
];

async fn backend_pid(c: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(c)
        .await
        .unwrap()
}

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
    // The dispatch secret crosses the worker's database connection, so it is never the bearer.
    let reused = Round {
        run: round.run.clone(),
        request: round.request.clone(),
        secret: round.secret,
        bearer: round.secret,
        lease: round.lease.clone(),
    };
    assert!(!f.handoff(&reused).await);
    assert_eq!(
        f.stored(&round).await,
        ("reserved".to_owned(), None, false, false)
    );
    f.authorized(&round, "a live run round of an enabled, approved user")
        .await;
    // The handoff stored the hash of the bearer and of the claim, and neither value.
    let digests: (bool, bool) = sqlx::query_as(
        "SELECT bearer_hash=sha256($2),claim_hash=sha256(uuid_send($3::uuid))
           FROM openmettle.gateway_requests WHERE id=$1::uuid",
    )
    .bind(&round.request)
    .bind(round.bearer.as_slice())
    .bind(&round.lease)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(digests, (true, true));
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
        .bind(round.bearer.as_slice())
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

    // The provider's latest revision is disabled, then followed by a new one.
    let round = f.round(&plain).await;
    f.owner_exec(
        "INSERT INTO openmettle.login_provider_revisions (provider_id,revision)
         VALUES ($1::uuid,NULL)",
        PROVIDER,
    )
    .await;
    f.refused(&round, "a provider whose latest revision is disabled")
        .await;
    f.owner_exec(
        "INSERT INTO openmettle.login_provider_revisions (provider_id,revision)
         VALUES ($1::uuid,'v2')",
        PROVIDER,
    )
    .await;
    f.authorized(&round, "a provider with a new revision").await;

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
    let unreadable: [(&str, i32, &[u8]); 18] = [
        // A repeated key, at any depth: jsonb would keep the last one, here the permissive one.
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"a"},"required_capabilities":{"fixture.optin":"opt_in"},"required_capabilities":{}}"#,
        ),
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"b"},"effective":{"model":"a"},"required_capabilities":{}}"#,
        ),
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"b","model":"a"},"required_capabilities":{}}"#,
        ),
        // A capability name outside the rule matches no deny row.
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"a"},"required_capabilities":{"Fixture.Round":"on_by_default"}}"#,
        ),
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"a"},"required_capabilities":{"":"on_by_default"}}"#,
        ),
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

    // An editor who does not own the conversation also needs a write share on it.
    let chat = authz_runs::chat(&f.db, &scope, "project", &lead).await;
    let share = async |key: &str, granted: bool| {
        let mut api = connect(&database, API).await;
        let (context, kind) = (ctx(&lead, key), ResourceKind::Conversation);
        applied(if granted {
            let write = ResourceAccess::Write;
            projects::share_resource(&mut api, &context, kind, &chat, &grantee, write).await
        } else {
            projects::unshare_resource(&mut api, &context, kind, &chat, &grantee).await
        });
    };
    share("rounds-share", true).await;
    let run = f.claimed_on(&member, (&scope, &chat), snapshot, 1).await;
    let round = f.reserve(&run, 1, "a").await;
    share("rounds-unshare", false).await;
    f.refused(&round, "an editor whose write share was revoked")
        .await;
    share("rounds-share-again", true).await;
    f.authorized(&round, "an editor with a write share again")
        .await;
    assert_eq!(f.provisioned().await, 0);
}

/// The quota commit and the deferred handoff check can wait on quota locks. An approval or a
/// lease that lapses during that wait is not handed off: the confirm step reads the authority
/// again after the wait.
///
/// Both waits are observed, not timed. The handoff first waits behind an account administration
/// change, before it locks any row; that change shortens the expiry and commits, so the handoff
/// reads an authority that is still live. The confirm step then waits behind a quota
/// administration change, which commits only after the expiry is seen to have passed. Once the
/// handoff holds its row locks nothing can write the expiry, so only time can withdraw it.
///
/// The expiry is three seconds after the statement that sets it. A handoff that reads the
/// authority later than that is refused, and says so at once: the attempt is dropped and
/// started over, three times at most. An attempt whose handoff was accepted must be seen
/// waiting on the quota holder and must outlast the expiry.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn authority_that_lapses_during_a_quota_wait_is_not_handed_off() {
    let mut f = Rounds::new().await;
    let approval = f.actor.approval.clone();
    let plain = quotas::snapshot(100);
    for (why, shorten, lapsed, restore, by_approval) in [
        (
            "an approval that expired during the wait",
            "UPDATE openmettle.local_identity_approvals
                SET expires_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint+3000
              WHERE id=$1::uuid",
            "SELECT expires_ms<floor(extract(epoch FROM clock_timestamp())*1000)::bigint
               FROM openmettle.local_identity_approvals WHERE id=$1::uuid",
            "UPDATE openmettle.local_identity_approvals SET expires_ms=4102444800000
              WHERE id=$1::uuid",
            true,
        ),
        (
            "a lease that lapsed during the wait",
            "UPDATE openmettle.runs
                SET lease_expires_at=clock_timestamp()+interval '3000 milliseconds'
              WHERE id=$1::uuid",
            "SELECT lease_expires_at<clock_timestamp() FROM openmettle.runs WHERE id=$1::uuid",
            "UPDATE openmettle.runs SET lease_expires_at=clock_timestamp()+interval '1 minute'
              WHERE id=$1::uuid",
            false,
        ),
    ] {
        let round = f.round(&plain).await;
        let id = if by_approval {
            approval.clone()
        } else {
            round.run.clone()
        };
        let mut attempts = 0;
        let confirmed = loop {
            attempts += 1;
            assert!(
                attempts <= 3,
                "{why}: the handoff missed the expiry three times"
            );
            let mut accounts = connect(&f.db.0, OWNER).await;
            let mut quota = connect(&f.db.0, OWNER).await;
            let accounts_pid = backend_pid(&mut accounts).await;
            let quota_pid = backend_pid(&mut quota).await;
            for (holder, lock) in [
                (
                    &mut accounts,
                    "SELECT FROM openmettle.account_admin_lock FOR UPDATE",
                ),
                (
                    &mut quota,
                    "SELECT FROM openmettle.quota_enforcement FOR UPDATE",
                ),
            ] {
                holder.execute("BEGIN").await.unwrap();
                holder.execute(lock).await.unwrap();
            }
            let mut c = connect(&f.db.0, WORKER).await;
            let (request, secret, bearer, lease) = (
                round.request.clone(),
                round.secret,
                round.bearer,
                round.lease.clone(),
            );
            let (report, first) = tokio::sync::oneshot::channel();
            let waiting = tokio::spawn(async move {
                c.execute("BEGIN").await.unwrap();
                // Waits for the account holder before it locks or reads anything it checks.
                let handed: bool = sqlx::query_scalar(HANDOFF)
                    .bind(&request)
                    .bind(secret.as_slice())
                    .bind(&lease)
                    .bind(bearer.as_slice())
                    .fetch_one(&mut c)
                    .await
                    .unwrap();
                report.send(handed).unwrap();
                // Waits for the quota holder inside the deferred handoff check.
                let confirmed = match handed {
                    true => Some(
                        sqlx::query(CONFIRM)
                            .bind(&request)
                            .bind(secret.as_slice())
                            .bind(&lease)
                            .execute(&mut c)
                            .await
                            .map(|_| ()),
                    ),
                    false => None,
                };
                let _ = c.execute("ROLLBACK").await;
                confirmed
            });
            wait_for_blocked_peer(&f.db, accounts_pid).await;
            let shortened = sqlx::query(shorten)
                .bind(&id)
                .execute(&mut accounts)
                .await
                .unwrap();
            assert_eq!(shortened.rows_affected(), 1, "{why}");
            accounts.execute("COMMIT").await.unwrap();
            if !first.await.unwrap() {
                // The handoff read the authority after the expiry: nothing was tested.
                quota.execute("ROLLBACK").await.unwrap();
                assert!(waiting.await.unwrap().is_none());
                f.owner_exec(restore, &id).await;
                continue;
            }
            wait_for_blocked_peer(&f.db, quota_pid).await;
            f.until(lapsed, &id, why).await;
            quota.execute("COMMIT").await.unwrap();
            break waiting.await.unwrap().expect("the confirm step ran");
        };
        assert_eq!(sqlstate(confirmed), "42501", "{why}");
        assert_eq!(
            f.stored(&round).await,
            ("reserved".to_owned(), None, false, false),
            "{why}"
        );
        f.owner_exec(restore, &id).await;
        f.authorized(&round, why).await;
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn the_dispatch_is_restricted_to_the_gateway_and_proves_the_bearer() {
    let mut f = Rounds::new().await;
    let plain = quotas::snapshot(100);
    let reserved = f.round(&plain).await;
    let round = f.round(&plain).await;
    f.authorized(&round, "a live run round").await;
    for role in [API, WORKER, ISSUANCE] {
        let denied = f.dispatch_as(role, &round.request, &round.bearer).await;
        assert_eq!(sqlstate(denied), "42501", "{role}");
    }
    let mut gateway = connect(&f.db.0, pg::GATEWAY).await;
    gateway
        .execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
        .await
        .unwrap();
    let stale = sqlx::query_as::<_, Dispatched>(DISPATCH)
        .bind(&round.request)
        .bind(round.bearer.as_slice())
        .fetch_all(&mut gateway)
        .await;
    assert_eq!(sqlstate(stale), "25000");
    gateway.execute("ROLLBACK").await.unwrap();

    // A wrong bearer, an unknown request and a request not handed off yet are refused alike:
    // no row, and nothing spent.
    for (request, bearer) in [
        (round.request.as_str(), &[0xee; 32][..]),
        (round.request.as_str(), &round.bearer[..31]),
        (round.request.as_str(), &reserved.bearer[..]),
        (UNKNOWN, &round.bearer[..]),
        (reserved.request.as_str(), &reserved.bearer[..]),
        // The dispatch secret is the worker's proof to the database, never a bearer.
        (round.request.as_str(), &round.secret[..]),
    ] {
        let rows = f.dispatch_as(pg::GATEWAY, request, bearer).await.unwrap();
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
    // A replay is reported only to the holder of the bearer.
    for other in [&[0xee; 32], &round.secret] {
        let rows = f
            .dispatch_as(pg::GATEWAY, &round.request, other)
            .await
            .unwrap();
        assert_eq!(rows, []);
    }
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
                let (request, bearer) = (round.request.clone(), round.bearer);
                tokio::spawn(async move {
                    let mut c = PgConnection::connect_with(&options).await.unwrap();
                    barrier.wait().await;
                    sqlx::query_as::<_, Dispatched>(DISPATCH)
                        .bind(request)
                        .bind(bearer.as_slice())
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

/// A run past its lease or its execution deadline that no sweep has settled yet is still
/// `running` and not cancelled. Its round is not dispatched.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn an_expired_run_that_no_sweep_settled_is_not_dispatched() {
    let mut f = Rounds::new().await;
    let round = f.round(&quotas::snapshot(100)).await;
    f.authorized(&round, "a live run round").await;
    for (why, expire) in [
        (
            "a lapsed lease",
            "UPDATE openmettle.runs SET lease_expires_at=clock_timestamp()-interval '1 second'
              WHERE id=$1::uuid",
        ),
        (
            "a passed execution deadline",
            "UPDATE openmettle.runs SET lease_expires_at=clock_timestamp()-interval '2 seconds',
                    execution_expires_at=clock_timestamp()-interval '1 second'
              WHERE id=$1::uuid",
        ),
    ] {
        f.owner_exec(expire, &round.run).await;
        assert_eq!(f.dispatch(&round).await, [], "{why}");
        assert!(!f.stored(&round).await.3, "{why}");
        f.owner_exec(
            "UPDATE openmettle.runs SET lease_expires_at=clock_timestamp()+interval '1 minute',
                    execution_expires_at=clock_timestamp()+interval '10 minutes'
              WHERE id=$1::uuid",
            &round.run,
        )
        .await;
    }
    assert_eq!(f.dispatch(&round).await, [f.routed()]);
}

/// The handoff records which claim authorized it. A holder that renews its lease keeps that
/// claim and its round still dispatches. A run reclaimed by another holder is `running`, not
/// cancelled and inside a new lease, and the previous holder's unspent round is still not
/// dispatched. A round spent before the reclaim still reports a replay.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_reclaimed_run_does_not_dispatch_the_previous_holders_round() {
    let mut f = Rounds::new().await;
    let plain = quotas::snapshot(100);
    let mut worker = connect(&f.db.0, WORKER).await;

    let renewed = f.round(&plain).await;
    f.authorized(&renewed, "a live run round").await;
    let before: String =
        sqlx::query_scalar("SELECT lease_expires_at::text FROM openmettle.runs WHERE id=$1::uuid")
            .bind(&renewed.run)
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    let lease = Lease {
        scope_id: &f.scope,
        run_id: &renewed.run,
        claim_token: &renewed.lease,
    };
    leases::renew_lease(&mut worker, &lease, &LEASES)
        .await
        .unwrap();
    let after: String =
        sqlx::query_scalar("SELECT lease_expires_at::text FROM openmettle.runs WHERE id=$1::uuid")
            .bind(&renewed.run)
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    assert_ne!(before, after, "the renewal moved the lease");
    assert_eq!(f.dispatch(&renewed).await, [f.routed()]);

    let unspent = f.round(&plain).await;
    let spent = f.round(&plain).await;
    for round in [&unspent, &spent] {
        f.authorized(round, "a live run round").await;
    }
    assert_eq!(f.dispatch(&spent).await, [f.routed()]);
    for round in [&unspent, &spent] {
        f.owner_exec(
            "UPDATE openmettle.runs SET lease_expires_at=clock_timestamp()-interval '1 second'
              WHERE id=$1::uuid",
            &round.run,
        )
        .await;
    }
    let mut reclaimed = Vec::new();
    while let Some(next) = leases::reclaim_next(&mut worker, &LEASES).await.unwrap() {
        assert!(![&unspent.lease, &spent.lease].contains(&&next.run.claim_token));
        reclaimed.push(next.run.run_id);
    }
    reclaimed.sort();
    let mut expected = [unspent.run.clone(), spent.run.clone()];
    expected.sort();
    assert_eq!(reclaimed, expected);
    // The reclaimed run would pass every other dispatch condition.
    let live: bool = sqlx::query_scalar(
        "SELECT state='running' AND cancel_reason IS NULL AND lease_expires_at>clock_timestamp()
                AND execution_expires_at>clock_timestamp()
           FROM openmettle.runs WHERE id=$1::uuid",
    )
    .bind(&unspent.run)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert!(live);
    assert_eq!(f.dispatch(&unspent).await, []);
    assert!(!f.stored(&unspent).await.3);
    assert_eq!(f.dispatch(&spent).await, [REPLAY]);
}

/// The dispatch reads its clock inside the updating statement, which by then holds its
/// relation lock: a lease that ran out while the dispatch waited for that lock is not
/// dispatched. The holder stands for a schema change or an explicit table lock in flight; a
/// `SHARE` lock admits the function's row locks and blocks its update.
///
/// The waiting dispatch holds the run, so nothing but time can end the lease: it is set to run
/// out two seconds after the dispatch starts, and the table lock is released only once the
/// database's clock is past it. The outcome does not depend on those two seconds. Only a clock
/// read before the wait would have to be read within them to be caught.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_lease_that_lapsed_while_the_dispatch_waited_for_its_table_lock_is_not_dispatched() {
    let mut f = Rounds::new().await;
    let round = f.round(&quotas::snapshot(100)).await;
    f.authorized(&round, "a live run round").await;
    let mut holder = connect(&f.db.0, OWNER).await;
    let pid = backend_pid(&mut holder).await;
    holder.execute("BEGIN").await.unwrap();
    holder
        .execute("LOCK TABLE openmettle.gateway_requests IN SHARE MODE")
        .await
        .unwrap();
    f.owner_exec(
        "UPDATE openmettle.runs SET lease_expires_at=clock_timestamp()+interval '2 seconds'
          WHERE id=$1::uuid",
        &round.run,
    )
    .await;
    let waiting = f.dispatching(&round).await;
    wait_for_blocked_peer(&f.db, pid).await;
    f.until(
        "SELECT lease_expires_at<clock_timestamp() FROM openmettle.runs WHERE id=$1::uuid",
        &round.run,
        "the lease never ran out",
    )
    .await;
    holder.execute("COMMIT").await.unwrap();
    assert_eq!(waiting.await.unwrap(), []);
    assert!(!f.stored(&round).await.3);
}

/// A lease release in flight when the dispatch starts: the dispatch waits for it on the run
/// row and is refused once it has committed.
///
/// The release is the library's. A `SHARE` lock on `runs`, held by the test, admits its row
/// lock and blocks its update, which keeps its transaction open with the run locked. That
/// transaction waits two seconds for a lock at most: the test has that long to see the
/// dispatch blocked, and past it the release fails and the test with it.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_dispatch_waits_for_a_lease_release_in_flight_and_is_refused() {
    let mut f = Rounds::new().await;
    let round = f.round(&quotas::snapshot(100)).await;
    f.authorized(&round, "a live run round").await;
    let mut holder = connect(&f.db.0, OWNER).await;
    let holder_pid = backend_pid(&mut holder).await;
    holder.execute("BEGIN").await.unwrap();
    holder
        .execute("LOCK TABLE openmettle.runs IN SHARE MODE")
        .await
        .unwrap();
    let mut worker = connect(&f.db.0, WORKER).await;
    let worker_pid = backend_pid(&mut worker).await;
    let releasing = f.releasing(worker, &round);
    wait_for_blocked_peer(&f.db, holder_pid).await;
    // A caller that does not prove the bearer locks nothing, so it waits for nothing.
    let stranger = f.dispatch_as(pg::GATEWAY, &round.request, &[0xee; 32]);
    assert_eq!(stranger.await.unwrap(), []);
    let dispatching = f.dispatching(&round).await;
    wait_for_blocked_peer(&f.db, worker_pid).await;
    holder.execute("COMMIT").await.unwrap();
    releasing.await.unwrap().unwrap();
    assert_eq!(dispatching.await.unwrap(), []);
    assert!(!f.stored(&round).await.3);
}

/// The same with a reclaim in flight: the dispatch waits for the new holder's claim on the run
/// row and is refused once it has committed, although the run is then live again.
///
/// The reclaim is the library's. It writes the new claim and then appends an event; a `SHARE`
/// lock on `run_events` blocks that insert and keeps its transaction open, for two seconds at
/// most as above.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_dispatch_waits_for_a_reclaim_in_flight_and_is_refused() {
    let mut f = Rounds::new().await;
    let round = f.round(&quotas::snapshot(100)).await;
    f.authorized(&round, "a live run round").await;
    f.owner_exec(
        "UPDATE openmettle.runs SET lease_expires_at=clock_timestamp()-interval '1 second'
          WHERE id=$1::uuid",
        &round.run,
    )
    .await;
    let mut holder = connect(&f.db.0, OWNER).await;
    let holder_pid = backend_pid(&mut holder).await;
    holder.execute("BEGIN").await.unwrap();
    holder
        .execute("LOCK TABLE openmettle.run_events IN SHARE MODE")
        .await
        .unwrap();
    let mut worker = connect(&f.db.0, WORKER).await;
    let worker_pid = backend_pid(&mut worker).await;
    let reclaiming = tokio::spawn(async move { leases::reclaim_next(&mut worker, &LEASES).await });
    wait_for_blocked_peer(&f.db, holder_pid).await;
    let dispatching = f.dispatching(&round).await;
    wait_for_blocked_peer(&f.db, worker_pid).await;
    holder.execute("COMMIT").await.unwrap();
    let reclaimed = reclaiming.await.unwrap().unwrap().expect("the lapsed run");
    assert_eq!(reclaimed.run.run_id, round.run);
    assert_ne!(reclaimed.run.claim_token, round.lease);
    assert_eq!(dispatching.await.unwrap(), []);
    assert!(!f.stored(&round).await.3);
}

/// A dispatch in flight when the release starts: the release waits for it on the run row. The
/// dispatch was granted and stays granted. The release then completes, another holder reclaims
/// the run, and the round it finds is spent.
///
/// No reclaim can wait behind a granted dispatch: a reclaim takes only a lease that has run
/// out and skips a locked run, and a dispatch is granted only inside the lease.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_lease_release_waits_for_a_dispatch_in_flight_which_stays_granted() {
    let mut f = Rounds::new().await;
    let round = f.round(&quotas::snapshot(100)).await;
    f.authorized(&round, "a live run round").await;
    let mut gateway = connect(&f.db.0, pg::GATEWAY).await;
    let gateway_pid = backend_pid(&mut gateway).await;
    gateway.execute("BEGIN").await.unwrap();
    let granted: Vec<Dispatched> = sqlx::query_as(DISPATCH)
        .bind(&round.request)
        .bind(round.bearer.as_slice())
        .fetch_all(&mut gateway)
        .await
        .unwrap();
    assert_eq!(granted, [f.routed()]);
    let releasing = f.releasing(connect(&f.db.0, WORKER).await, &round);
    wait_for_blocked_peer(&f.db, gateway_pid).await;
    gateway.execute("COMMIT").await.unwrap();
    releasing.await.unwrap().unwrap();
    assert!(f.stored(&round).await.3);
    let reclaimed = leases::reclaim_next(&mut connect(&f.db.0, WORKER).await, &LEASES)
        .await
        .unwrap()
        .expect("the released run");
    assert_eq!(reclaimed.run.run_id, round.run);
    assert_eq!(f.dispatch(&round).await, [REPLAY]);
}

/// A request handed off with a gateway binding, the ADR 0037 way, has no bearer hash and is
/// never dispatched, even for a live run: that transport may already have sent it.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_request_handed_off_with_a_binding_is_never_dispatched() {
    let mut f = Rounds::new().await;
    let round = f.round(&quotas::snapshot(100)).await;
    let user = f.actor.user.clone();
    for bind in [
        "INSERT INTO openmettle.gateway_bindings (installation,user_id,principal,budget)
         SELECT installation,actor_user_id,gen_random_uuid(),gen_random_uuid()
           FROM openmettle.gateway_requests WHERE id=$1::uuid",
        "INSERT INTO openmettle.gateway_nonces (key_fingerprint,nonce)
         SELECT sha256('fixture'),substring(sha256('nonce') FOR 12)
           FROM openmettle.gateway_requests WHERE id=$1::uuid",
        "INSERT INTO openmettle.gateway_generations
             (binding_id,generation,remote_key,expires_at,key_id,key_fingerprint,nonce,ciphertext)
         SELECT b.id,1,gen_random_uuid(),clock_timestamp()+interval '1 hour','fixture',
                sha256('fixture'),substring(sha256('nonce') FOR 12),sha256('ciphertext')
           FROM openmettle.gateway_requests q
           JOIN openmettle.gateway_bindings b ON b.user_id=q.actor_user_id WHERE q.id=$1::uuid",
        "INSERT INTO openmettle.gateway_policy
             (binding_id,revision,scope_id,approval_id,model,report_source,provider_generation,
              approval_generation,user_generation,capabilities)
         SELECT b.id,1,q.scope_id,q.approval_id,q.model,gen_random_uuid(),0,0,0,'{}'
           FROM openmettle.gateway_requests q
           JOIN openmettle.gateway_bindings b ON b.user_id=q.actor_user_id WHERE q.id=$1::uuid",
        "UPDATE openmettle.gateway_requests q SET state='handed_off',binding_id=p.binding_id,
                generation=1,policy_revision=1,report_source=p.report_source
           FROM openmettle.gateway_policy p WHERE q.id=$1::uuid",
    ] {
        f.owner_exec(bind, &round.request).await;
    }
    let bound: bool = sqlx::query_scalar(
        "SELECT state='handed_off' AND binding_id IS NOT NULL FROM openmettle.gateway_requests
          WHERE id=$1::uuid AND actor_user_id=$2::uuid",
    )
    .bind(&round.request)
    .bind(&user)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert!(bound);
    for presented in [&round.bearer, &round.secret] {
        let rows = f
            .dispatch_as(pg::GATEWAY, &round.request, presented)
            .await
            .unwrap();
        assert_eq!(rows, []);
    }
    assert!(!f.stored(&round).await.3);
}

/// A request that already has a settlement gets no first dispatch: whatever reported its usage
/// already sent it.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_settled_request_is_not_dispatched() {
    let mut f = Rounds::new().await;
    let round = f.round(&quotas::snapshot(100)).await;
    f.authorized(&round, "a live run round").await;
    for sql in SETTLED {
        f.owner_exec(sql, &round.request).await;
    }
    assert_eq!(f.dispatch(&round).await, []);
    assert!(!f.stored(&round).await.3);
}

/// A dispatch that waits for the request row decides after the wait: a settlement committed
/// meanwhile is seen. The holder is that settlement in flight: it locks the request first and
/// never the run, so the dispatch, which holds the run by then, waits for it here.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_request_settled_while_its_dispatch_waited_is_not_dispatched() {
    let mut f = Rounds::new().await;
    let round = f.round(&quotas::snapshot(100)).await;
    f.authorized(&round, "a live run round").await;
    let mut holder = connect(&f.db.0, OWNER).await;
    let pid = backend_pid(&mut holder).await;
    holder.execute("BEGIN").await.unwrap();
    sqlx::query("SELECT FROM openmettle.gateway_requests WHERE id=$1::uuid FOR NO KEY UPDATE")
        .bind(&round.request)
        .execute(&mut holder)
        .await
        .unwrap();
    let waiting = f.dispatching(&round).await;
    wait_for_blocked_peer(&f.db, pid).await;
    for sql in SETTLED {
        sqlx::query(sql)
            .bind(&round.request)
            .execute(&mut holder)
            .await
            .unwrap();
    }
    holder.execute("COMMIT").await.unwrap();
    assert_eq!(waiting.await.unwrap(), []);
    assert!(!f.stored(&round).await.3);
}

/// The CHECK that replaced migration 23's unnamed one accepts a request without a binding and
/// refuses every half-set combination. A request handed off without a binding carries a bearer
/// hash and a claim hash; no other request does, and the bearer hash is never the dispatch hash. `gateway::unmetered_handoff_replays_only_accepted_token_
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
    // A session-owned request, reserved by the API role.
    let (session_owned, reservation): (String, String) =
        sqlx::query_as("SELECT gen_random_uuid()::text,gen_random_uuid()::text")
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    let mut api = connect(&f.db.0, API).await;
    sqlx::query(
        "INSERT INTO openmettle.gateway_reservations (id,scope_id,actor_user_id,approval_id,units)
         VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,100)",
    )
    .bind(&reservation)
    .bind(&f.scope)
    .bind(&f.actor.user)
    .bind(&f.actor.approval)
    .execute(&mut api)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_requests
             (id,reservation_id,scope_id,actor_user_id,approval_id,session_id,installation,model,
              units,dispatch_hash)
         VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,repeat('A',43),$6::uuid,'a',100,
                 sha256('session'))",
    )
    .bind(&session_owned)
    .bind(&reservation)
    .bind(&f.scope)
    .bind(&f.actor.user)
    .bind(&f.actor.approval)
    .bind(INSTALL)
    .execute(&mut api)
    .await
    .unwrap();
    for (id, change) in [
        // Without a binding, a handed-off request belongs to a run and reports under its
        // installation.
        (
            &session_owned,
            "state='handed_off',report_source=installation,bearer_hash=sha256('b'),
             claim_hash=sha256('c')",
        ),
        (
            &reserved.request,
            "state='handed_off',report_source=gen_random_uuid(),bearer_hash=sha256('b'),
             claim_hash=sha256('c')",
        ),
        // Handed off without a binding and without the digests.
        (
            &reserved.request,
            "state='handed_off',report_source=installation",
        ),
        (
            &reserved.request,
            "state='handed_off',report_source=installation,bearer_hash=sha256('b')",
        ),
        // A request that is not handed off carries neither digest.
        (
            &reserved.request,
            "bearer_hash=sha256('b'),claim_hash=sha256('c')",
        ),
        // A request handed off with a binding carries neither digest.
        (
            &reserved.request,
            "state='handed_off',report_source=gen_random_uuid(),binding_id=gen_random_uuid(),
             generation=1,policy_revision=1,bearer_hash=sha256('b'),claim_hash=sha256('c')",
        ),
        (&handed.request, "bearer_hash=NULL"),
        (&handed.request, "claim_hash=NULL"),
        (&handed.request, "bearer_hash=NULL,claim_hash=NULL"),
        (&handed.request, "bearer_hash=dispatch_hash"),
        (&handed.request, "bearer_hash=sha256('b')||'\\x00'"),
        (&handed.request, "claim_hash=substring(claim_hash FOR 31)"),
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
    // No report is accepted before the proxy spent the dispatch: it is the only reporter.
    assert_eq!(
        settlement::ingest(&gateway, &report).await,
        Err(StoreError::Refused)
    );
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
