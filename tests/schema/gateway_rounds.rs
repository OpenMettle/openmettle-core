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
        Self::at(MIGRATIONS.len()).await
    }

    /// The fixture on a database migrated through version `through`.
    async fn at(through: usize) -> Self {
        let db = TestDb::new().await;
        let settings = db.settings(Duration::from_secs(10));
        migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
        let mut owner = connect(&db.0, OWNER).await;
        providers(&mut owner).await;
        let actor = account(&mut owner, PROVIDER, true, FUTURE).await;
        let scope = authz_runs::personal_of(&db, &actor).await;
        migrate::apply(&settings, &MIGRATIONS[..through])
            .await
            .unwrap();
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
        self.claimed_on_at(actor, (scope, chat), (format, version, config), rounds, NOW)
            .await
    }

    async fn claimed_on_at(
        &mut self,
        actor: &Account,
        (scope, chat): (&str, &str),
        (format, version, config): (&str, i32, &[u8]),
        rounds: i64,
        now_ms: i64,
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
                now_ms,
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

    /// The request's state, report source, whether it lacks a per-round bearer hash while handed
    /// off (always false once binding-free), and whether it was dispatched.
    async fn stored(&mut self, round: &Round) -> (String, Option<String>, bool, bool) {
        sqlx::query_as(
            "SELECT state,report_source::text,state='handed_off' AND bearer_hash IS NULL,dispatched_at IS NOT NULL
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

    /// Superseded ADR 0037 provisioning tables: none exists after migration 37.
    async fn provisioned(&mut self) -> i64 {
        sqlx::query_scalar(
            "SELECT (to_regclass('openmettle.gateway_bindings') IS NOT NULL)::int::bigint
                  + (to_regclass('openmettle.gateway_generations') IS NOT NULL)::int::bigint
                  + (to_regclass('openmettle.gateway_policy') IS NOT NULL)::int::bigint
                  + (to_regclass('openmettle.gateway_nonces') IS NOT NULL)::int::bigint
                  + (to_regclass('openmettle.gateway_intents') IS NOT NULL)::int::bigint
                  + (to_regclass('openmettle.gateway_audit') IS NOT NULL)::int::bigint",
        )
        .fetch_one(&mut self.owner)
        .await
        .unwrap()
    }
}

const REPLAY: Dispatched = (true, None, None, None, None, None);

/// A final usage report and its settlement for dispatched request `$1`, written as the owner.
const SETTLED: [&str; 2] = [
    "INSERT INTO openmettle.gateway_usage_reports
         (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens)
     SELECT id,report_source,gen_random_uuid(),0,true,1,1
       FROM openmettle.gateway_requests WHERE id=$1::uuid",
    "INSERT INTO openmettle.gateway_settlements (request_id,revision,final,measured,outstanding)
     VALUES ($1::uuid,0,true,2,0)",
];

/// A revision-0 `not_dispatched` closure for undispatched unbound request `$1`, written as owner.
const SETTLED_NOT_DISPATCHED: [&str; 2] = [
    "INSERT INTO openmettle.gateway_usage_reports
         (request_id,source,report_id,revision,final,incomplete)
     SELECT id,report_source,id,0,true,'not_dispatched'
       FROM openmettle.gateway_requests WHERE id=$1::uuid",
    "INSERT INTO openmettle.gateway_settlements (request_id,revision,final,measured,outstanding)
     VALUES ($1::uuid,0,true,NULL,0)",
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
    let unreadable: &[(&str, i32, &[u8])] = &[
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
        // Invalid `cost_bound` shapes (migration 34 / Review #1 P1 #1).
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"a"},"required_capabilities":{},"cost_bound":[]}"#,
        ),
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"a"},"required_capabilities":{},"cost_bound":{"fixed_micros":10}}"#,
        ),
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"a"},"required_capabilities":{},"cost_bound":{"fixed_micros":0,"micros_per_token":0}}"#,
        ),
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"a"},"required_capabilities":{},"cost_bound":{"fixed_micros":1,"micros_per_token":1,"extra":1}}"#,
        ),
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"a"},"required_capabilities":{},"cost_bound":{"fixed_micros":null,"micros_per_token":1}}"#,
        ),
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"a"},"required_capabilities":{},"cost_bound":{"micros_per_token":1.0}}"#,
        ),
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"a"},"required_capabilities":{},"cost_bound":{"micros_per_token":1e2}}"#,
        ),
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"a"},"required_capabilities":{},"cost_bound":{"micros_per_token":-1}}"#,
        ),
        (
            "openmettle.conversation",
            1,
            br#"{"effective":{"model":"a"},"required_capabilities":{},"cost_bound":{"micros_per_token":9223372036854775808}}"#,
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
    for &snapshot in unreadable {
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
/// A request that already has a settlement gets no first dispatch: e.g. an undispatched request
/// already closed as `not_dispatched`.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_settled_request_is_not_dispatched() {
    let mut f = Rounds::new().await;
    let round = f.round(&quotas::snapshot(100)).await;
    f.authorized(&round, "a live run round").await;
    for sql in SETTLED_NOT_DISPATCHED {
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
    for sql in SETTLED_NOT_DISPATCHED {
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

/// The binding-free CHECK constraints of migration 37 accept valid run-owned rounds and refuse
/// every half-set handoff combination. `openmettle_api` has no privilege on `gateway_requests`.
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
            AND conname IN ('gateway_requests_cost_bound_check', 'gateway_requests_handoff_check')
          ORDER BY conname",
    )
    .fetch_all(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(
        checks,
        [
            "gateway_requests_cost_bound_check",
            "gateway_requests_handoff_check",
        ]
    );
    // Superseded columns are gone and run_id / round are NOT NULL.
    let dropped_cols: Vec<String> = sqlx::query_scalar(
        "SELECT attname::text FROM pg_attribute
          WHERE attrelid='openmettle.gateway_requests'::regclass
            AND NOT attisdropped AND attnum > 0
            AND attname IN ('binding_id','generation','policy_revision','session_id')",
    )
    .fetch_all(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(dropped_cols, Vec::<String>::new());
    let not_nulls: Vec<(String, bool)> = sqlx::query_as(
        "SELECT attname::text, attnotnull FROM pg_attribute
          WHERE attrelid='openmettle.gateway_requests'::regclass
            AND NOT attisdropped AND attname IN ('run_id','round')
          ORDER BY attname",
    )
    .fetch_all(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(
        not_nulls,
        [("round".to_owned(), true), ("run_id".to_owned(), true)]
    );
    // Migration 37 revokes openmettle_api's INSERT on gateway_requests.
    let mut api = connect(&f.db.0, API).await;
    let api_insert = sqlx::query(
        "INSERT INTO openmettle.gateway_requests
             (id,reservation_id,scope_id,actor_user_id,approval_id,installation,model,
              units,dispatch_hash,run_id,round)
         VALUES (gen_random_uuid(),$1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,'a',100,
                 sha256('api'),$1::uuid,99)",
    )
    .bind(&reserved.run)
    .bind(&f.scope)
    .bind(&f.actor.user)
    .bind(&f.actor.approval)
    .bind(INSTALL)
    .execute(&mut api)
    .await;
    assert_eq!(sqlstate(api_insert), "42501");
    for (id, change) in [
        // A handed-off request reports under its installation.
        (
            &reserved.request,
            "state='handed_off',report_source=gen_random_uuid(),bearer_hash=sha256('b'),
             claim_hash=sha256('c')",
        ),
        // Handed off without the digests.
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
        (&handed.request, "report_source=NULL"),
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
        revision: 1,
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
    assert_eq!(settled, (1, true, Some("7".to_owned()), 0, true));
    assert_eq!(f.provisioned().await, 0);
}

/// A final report of `round` at the proxy's revision, with the given token counts.
fn report_of(f: &Rounds, round: &Round, counts: Option<(i64, i64)>) -> UsageReport {
    UsageReport {
        request: round.request.clone(),
        installation: INSTALL.into(),
        principal: f.actor.user.clone(),
        scope: f.scope.clone(),
        source: INSTALL.into(),
        report_id: round.request.clone(),
        revision: 1,
        r#final: true,
        prompt_tokens: counts.map(|(prompt, _)| prompt),
        completion_tokens: counts.map(|(_, completion)| completion),
        reasoning_tokens: None,
        reasoning_included: None,
        cost: None,
        unit: None,
    }
}

/// The reports of `request` (revision, reason), its settlement (revision, finality, measured
/// units, outstanding units), and whether it left the scan of outstanding requests.
#[allow(clippy::type_complexity)]
async fn ledger(
    f: &mut Rounds,
    request: &str,
) -> (
    Vec<(i64, Option<String>)>,
    Option<(i64, bool, Option<String>, i64)>,
    bool,
) {
    let reports = sqlx::query_as(
        "SELECT revision,incomplete FROM openmettle.gateway_usage_reports
          WHERE request_id=$1::uuid ORDER BY revision",
    )
    .bind(request)
    .fetch_all(&mut f.owner)
    .await
    .unwrap();
    let settlement = sqlx::query_as(
        "SELECT revision,final,measured::text,outstanding
           FROM openmettle.gateway_settlements WHERE request_id=$1::uuid",
    )
    .bind(request)
    .fetch_optional(&mut f.owner)
    .await
    .unwrap();
    let settled_final = sqlx::query_scalar(
        "SELECT settled_final FROM openmettle.gateway_requests WHERE id=$1::uuid",
    )
    .bind(request)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    (reports, settlement, settled_final)
}

/// ADR 0044, increment 3a. A dispatched request that ended without usage is closed by a final
/// report that carries the reason and no count. Without the reason, a final report that would
/// leave the request's units outstanding is refused: accepted, it would mark the request
/// settled, hide it from every scan of outstanding requests and keep its hold for good.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_request_that_ended_without_usage_is_closed_by_its_reason_and_never_by_a_bare_final_report()
 {
    let mut f = Rounds::new().await;
    let round = f.round(&quotas::snapshot(100)).await;
    f.authorized(&round, "a live run round").await;
    let gateway = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(pg::GATEWAY));
    let unused = report_of(&f, &round, None);
    let untouched = (vec![], None, false);

    // The proxy reports only after it spent the dispatch, also when it has no usage to report.
    assert_eq!(
        settlement::ingest_incomplete(&gateway, &unused, "model_not_served").await,
        Err(StoreError::Refused)
    );
    assert_eq!(f.dispatch(&round).await, [f.routed()]);

    // The trap: a final report with no count and no reason, or with one count only, also when
    // that count covers all 10 units of the request and leaves nothing outstanding.
    let prompt_only = UsageReport {
        prompt_tokens: Some(4),
        ..unused.clone()
    };
    let whole = UsageReport {
        prompt_tokens: Some(10),
        ..unused.clone()
    };
    for bare in [&unused, &prompt_only, &whole] {
        assert_eq!(
            settlement::ingest(&gateway, bare).await,
            Err(StoreError::Refused),
            "{:?}",
            bare.prompt_tokens
        );
    }
    // Migration 37: `openmettle_gateway` itself is refused direct writes to usage/settlement tables
    // (42501); the database triggers also refuse invalid final settlements even for `openmettle_owner`.
    {
        let mut gw_direct = connect(&f.db.0, pg::GATEWAY).await;
        let gw_refused = sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports (request_id,source,report_id,revision,final)
             VALUES ($1::uuid,$2::uuid,$1::uuid,1,true)",
        )
        .bind(&round.request)
        .bind(INSTALL)
        .execute(&mut gw_direct)
        .await;
        assert_eq!(sqlstate(gw_refused), "42501");

        let mut direct = connect(&f.db.0, OWNER).await;
        let stored = sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports (request_id,source,report_id,revision,final)
             VALUES ($1::uuid,$2::uuid,$1::uuid,1,true)",
        )
        .bind(&round.request)
        .bind(INSTALL)
        .execute(&mut direct)
        .await;
        assert!(stored.is_ok(), "{stored:?}");
        let settled = sqlx::query(
            "INSERT INTO openmettle.gateway_settlements
                 (request_id,revision,final,measured,outstanding)
             VALUES ($1::uuid,1,true,NULL,0)",
        )
        .bind(&round.request)
        .execute(&mut direct)
        .await;
        let Err(sqlx::Error::Database(error)) = settled else {
            panic!("a final settlement without counts or a reason was accepted");
        };
        assert_eq!(error.code().as_deref(), Some("23514"));
        // The raw report has no settlement and counts for nothing; remove it as the owner.
        f.owner_exec(
            "DELETE FROM openmettle.gateway_usage_reports WHERE request_id=$1::uuid",
            &round.request,
        )
        .await;

        // Nor may a final settlement keep a positive outstanding balance, even with a valid
        // reason that closes the fold on this unmetered request.
        use sqlx::Connection;
        let mut tx = direct.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,incomplete)
             VALUES ($1::uuid,$2::uuid,$1::uuid,1,true,'no_usage')",
        )
        .bind(&round.request)
        .bind(INSTALL)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_settlements
                 (request_id,revision,final,measured,outstanding)
             VALUES ($1::uuid,1,true,NULL,10)",
        )
        .bind(&round.request)
        .execute(&mut *tx)
        .await
        .unwrap();
        let Err(sqlx::Error::Database(error)) = tx.commit().await else {
            panic!("a final settlement kept a positive outstanding balance");
        };
        assert_eq!(error.code().as_deref(), Some("23514"));
    }
    // The vocabulary is closed, and only a final report carries a reason.
    for unknown in ["dispatch_unconfirmed", "no usage", ""] {
        assert_eq!(
            settlement::ingest_incomplete(&gateway, &unused, unknown).await,
            Err(StoreError::Refused),
            "{unknown}"
        );
    }
    let interim = UsageReport {
        r#final: false,
        ..unused.clone()
    };
    assert_eq!(
        settlement::ingest_incomplete(&gateway, &interim, "incomplete").await,
        Err(StoreError::Refused)
    );
    assert_eq!(ledger(&mut f, &round.request).await, untouched);

    assert_eq!(
        settlement::ingest_incomplete(&gateway, &unused, "upstream_status").await,
        Ok(Outcome::Applied)
    );
    // A retried write stores nothing new; another reason under the same identity conflicts.
    assert_eq!(
        settlement::ingest_incomplete(&gateway, &unused, "upstream_status").await,
        Ok(Outcome::Duplicate)
    );
    assert_eq!(
        settlement::ingest_incomplete(&gateway, &unused, "no_usage").await,
        Err(StoreError::Conflict)
    );
    assert_eq!(
        settlement::ingest(&gateway, &unused).await,
        Err(StoreError::Conflict)
    );
    assert_eq!(
        ledger(&mut f, &round.request).await,
        (
            vec![(1, Some("upstream_status".to_owned()))],
            Some((1, true, None, 0)),
            true
        )
    );
    assert_eq!(f.provisioned().await, 0);
}

/// Migration 31 on a database that already holds reports: a settled report keeps its counts and
/// gets no reason, a request that was dispatched and never reported can then be closed, and the
/// new column takes exactly the reasons of its two groups, on a final report only.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn migration_31_keeps_stored_reports_and_adds_the_reason_of_an_incomplete_one() {
    let mut f = Rounds::at(30).await;
    let settled = f.round(&quotas::snapshot(100)).await;
    let open = f.round(&quotas::snapshot(100)).await;
    for round in [&settled, &open] {
        f.authorized(round, "a live run round").await;
        assert_eq!(f.dispatch(round).await, [f.routed()]);
    }
    for sql in SETTLED {
        f.owner_exec(sql, &settled.request).await;
    }
    let has_column = "SELECT EXISTS (SELECT FROM information_schema.columns
        WHERE table_schema='openmettle' AND table_name='gateway_usage_reports'
          AND column_name=$1)";
    let before: bool = sqlx::query_scalar(has_column)
        .bind("incomplete")
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert!(!before);

    let settings = f.db.settings(Duration::from_secs(10));
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(f.db.history().await, all_versions());
    // The stored report and its settlement are as they were.
    assert_eq!(
        ledger(&mut f, &settled.request).await,
        (
            vec![(0, None)],
            Some((0, true, Some("2".to_owned()), 0)),
            true
        )
    );
    // The request nobody reported is closed through the library, as the gateway.
    let gateway = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(pg::GATEWAY));
    let unused = report_of(&f, &open, None);
    assert_eq!(
        settlement::ingest_incomplete(&gateway, &unused, "caller_disconnected").await,
        Ok(Outcome::Applied)
    );
    assert_eq!(
        ledger(&mut f, &open.request).await,
        (
            vec![(1, Some("caller_disconnected".to_owned()))],
            Some((1, true, None, 0)),
            true
        )
    );

    // The CHECK, written to as the owner: every reason of both groups on a final report, and
    // nothing else.
    let insert = "INSERT INTO openmettle.gateway_usage_reports
            (request_id,source,report_id,revision,final,incomplete)
        SELECT id,report_source,gen_random_uuid(),$2,$3,$4
          FROM openmettle.gateway_requests WHERE id=$1::uuid";
    let reasons = [
        "model_not_served",
        "model_mismatch",
        "request_body",
        "upstream_connect",
        "upstream_transport",
        "upstream_timeout",
        "upstream_status",
        "upstream_encoding",
        "incomplete",
        "caller_disconnected",
        "no_usage",
        "unparsable",
    ];
    for (n, reason) in reasons.into_iter().enumerate() {
        let stored = sqlx::query(insert)
            .bind(&open.request)
            .bind(10 + n as i64)
            .bind(true)
            .bind(reason)
            .execute(&mut f.owner)
            .await;
        assert!(stored.is_ok(), "{reason}: {stored:?}");
    }
    for (is_final, reason) in [
        (true, "dispatch_unconfirmed"),
        (true, "Incomplete"),
        (true, ""),
        (false, "incomplete"),
    ] {
        let refused = sqlx::query(insert)
            .bind(&open.request)
            .bind(99_i64)
            .bind(is_final)
            .bind(reason)
            .execute(&mut f.owner)
            .await;
        let Err(sqlx::Error::Database(error)) = refused else {
            panic!("{reason:?} on a report with final={is_final} was accepted");
        };
        assert_eq!(
            (error.code().as_deref(), error.constraint()),
            (
                Some("23514"),
                Some("gateway_usage_reports_incomplete_check")
            ),
            "{reason:?}"
        );
    }
}

const SWEEP_CANDIDATES: &str = "SELECT created_at::text, id::text, eligible
    FROM openmettle.gateway_unreported_candidates(
        '-infinity'::timestamptz,
        '00000000-0000-0000-0000-000000000000'::uuid,
        'infinity'::timestamptz,
        'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid,
        $1
    )";
const SWEEP_CLOSE: &str = "SELECT openmettle.gateway_close_unreported($1::uuid)";

/// ADR 0044, increment 3b (migration 32): the worker sweep closes undispatched requests once
/// `gateway_dispatch` can no longer grant them (`not_dispatched`, no grace) and dispatched
/// requests 15 minutes past the run's execution deadline (`unreported`), while leaving live
/// rounds, in-grace dispatched rounds, reserved requests, and bound ADR 0037 requests intact.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn the_unreported_sweep_closes_undispatched_and_past_grace_rounds_and_leaves_live_and_bound_ones()
 {
    let mut f = Rounds::new().await;
    let plain = quotas::snapshot(100);

    // Role and isolation boundaries on the sweep functions.
    let probe = f.round(&plain).await;
    f.authorized(&probe, "a live run round").await;
    for role in [API, pg::GATEWAY, ISSUANCE] {
        let mut c = connect(&f.db.0, role).await;
        let denied_list = sqlx::query_as::<_, (String, String, bool)>(SWEEP_CANDIDATES)
            .bind(10_i32)
            .fetch_all(&mut c)
            .await;
        assert_eq!(sqlstate(denied_list), "42501", "{role} candidates");
        let denied_close = sqlx::query_scalar::<_, Option<String>>(SWEEP_CLOSE)
            .bind(&probe.request)
            .fetch_one(&mut c)
            .await;
        assert_eq!(sqlstate(denied_close), "42501", "{role} close");
    }
    let mut worker = connect(&f.db.0, WORKER).await;
    for bad_limit in [0_i32, 1001_i32] {
        let invalid = sqlx::query_as::<_, (String, String, bool)>(SWEEP_CANDIDATES)
            .bind(bad_limit)
            .fetch_all(&mut worker)
            .await;
        assert_eq!(sqlstate(invalid), "22023", "limit {bad_limit}");
    }
    worker
        .execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
        .await
        .unwrap();
    let stale = sqlx::query_scalar::<_, Option<String>>(SWEEP_CLOSE)
        .bind(&probe.request)
        .fetch_one(&mut worker)
        .await;
    assert_eq!(sqlstate(stale), "25000");
    worker.execute("ROLLBACK").await.unwrap();

    // A reserved (not handed off) request is excluded from the index; a still-live undispatched
    // round is returned with `eligible = false` (so the pass cursor advances past it) and is
    // never closed.
    let reserved = f.round(&plain).await;
    let listed: Vec<(String, String, bool)> = sqlx::query_as(SWEEP_CANDIDATES)
        .bind(100_i32)
        .fetch_all(&mut worker)
        .await
        .unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|(_, id, eligible)| (id.as_str(), *eligible))
            .collect::<Vec<_>>(),
        [(probe.request.as_str(), false)]
    );
    for id in [&reserved.request, &probe.request] {
        let closed: Option<String> = sqlx::query_scalar(SWEEP_CLOSE)
            .bind(id)
            .fetch_one(&mut worker)
            .await
            .unwrap();
        assert_eq!(closed, None, "must not sweep {id}");
    }
    // Live round can still be dispatched afterwards.
    assert_eq!(f.dispatch(&probe).await, [f.routed()]);

    // Undispatched requests become eligible for `not_dispatched` as soon as the run cannot be
    // dispatched: cancelled, reclaimed, settled/failed, lapsed lease, or past execution deadline.
    let cancelled = f.round(&plain).await;
    let reclaimed = f.round(&plain).await;
    let failed = f.round(&plain).await;
    let lapsed_lease = f.round(&plain).await;
    let past_deadline = f.round(&plain).await;
    for r in [
        &cancelled,
        &reclaimed,
        &failed,
        &lapsed_lease,
        &past_deadline,
    ] {
        f.authorized(r, "a live run round").await;
    }

    let principal = authz_store::principal(&f.db, &f.actor).await;
    queue::cancel_run(
        &mut connect(&f.db.0, API).await,
        &principal,
        &f.scope,
        &cancelled.run,
    )
    .await
    .unwrap();
    f.owner_exec(
        "UPDATE openmettle.runs SET lease_expires_at=clock_timestamp()-interval '1 second'
          WHERE id=$1::uuid",
        &reclaimed.run,
    )
    .await;
    let reclaimed_run = leases::reclaim_next(&mut worker, &LEASES)
        .await
        .unwrap()
        .expect("reclaimable run");
    assert_eq!(reclaimed_run.run.run_id, reclaimed.run);
    leases::settle(
        &mut worker,
        &Lease {
            scope_id: &f.scope,
            run_id: &failed.run,
            claim_token: &failed.lease,
        },
        &LEASES,
        leases::Settle::Failed(leases::FailReason::StepFailed),
    )
    .await
    .unwrap();
    f.owner_exec(
        "UPDATE openmettle.runs SET lease_expires_at=clock_timestamp()-interval '1 second'
          WHERE id=$1::uuid",
        &lapsed_lease.run,
    )
    .await;
    f.owner_exec(
        "UPDATE openmettle.runs SET lease_expires_at=clock_timestamp()-interval '2 seconds',
                execution_expires_at=clock_timestamp()-interval '1 second'
          WHERE id=$1::uuid",
        &past_deadline.run,
    )
    .await;

    let page: Vec<(String, String, bool)> = sqlx::query_as(SWEEP_CANDIDATES)
        .bind(100_i32)
        .fetch_all(&mut worker)
        .await
        .unwrap();
    let mut found: Vec<String> = page
        .iter()
        .filter(|(_, _, eligible)| *eligible)
        .map(|(_, id, _)| id.clone())
        .collect();
    let ineligible: Vec<&str> = page
        .iter()
        .filter(|(_, _, eligible)| !*eligible)
        .map(|(_, id, _)| id.as_str())
        .collect();
    assert_eq!(ineligible, [probe.request.as_str()]);
    found.sort();
    let mut expected_not_dispatched = vec![
        cancelled.request.clone(),
        reclaimed.request.clone(),
        failed.request.clone(),
        lapsed_lease.request.clone(),
        past_deadline.request.clone(),
    ];
    expected_not_dispatched.sort();
    assert_eq!(found, expected_not_dispatched);

    for (why, r) in [
        ("cancelled", &cancelled),
        ("reclaimed", &reclaimed),
        ("failed", &failed),
        ("lapsed lease", &lapsed_lease),
        ("past execution deadline", &past_deadline),
    ] {
        let closed: Option<String> = sqlx::query_scalar(SWEEP_CLOSE)
            .bind(&r.request)
            .fetch_one(&mut worker)
            .await
            .unwrap();
        assert_eq!(closed.as_deref(), Some("not_dispatched"), "{why}");
        assert_eq!(
            ledger(&mut f, &r.request).await,
            (
                vec![(0, Some("not_dispatched".to_owned()))],
                Some((0, true, None, 0)),
                true
            ),
            "{why}"
        );
        // Second call is a no-op, and the original bearer can never dispatch it.
        let again: Option<String> = sqlx::query_scalar(SWEEP_CLOSE)
            .bind(&r.request)
            .fetch_one(&mut worker)
            .await
            .unwrap();
        assert_eq!(again, None, "{why}");
        assert_eq!(f.dispatch(r).await, [], "{why}");
        assert_eq!(
            f.stored(r).await,
            (
                "handed_off".to_owned(),
                Some(INSTALL.to_owned()),
                false,
                false
            ),
            "{why}"
        );
    }

    // Dispatched unreported request: NOT swept before execution_expires_at + 15 minutes even
    // after the run fails; swept as `unreported` once that 15-minute grace passes.
    let dispatched_round = f.round(&plain).await;
    f.authorized(&dispatched_round, "a live run round").await;
    assert_eq!(f.dispatch(&dispatched_round).await, [f.routed()]);
    leases::settle(
        &mut worker,
        &Lease {
            scope_id: &f.scope,
            run_id: &dispatched_round.run,
            claim_token: &dispatched_round.lease,
        },
        &LEASES,
        leases::Settle::Failed(leases::FailReason::StepFailed),
    )
    .await
    .unwrap();
    // 14 minutes past execution_expires_at is still inside the 15-minute grace window.
    f.owner_exec(
        "UPDATE openmettle.runs
            SET lease_expires_at=clock_timestamp()-interval '15 minutes',
                execution_expires_at=clock_timestamp()-interval '14 minutes'
          WHERE id=$1::uuid",
        &dispatched_round.run,
    )
    .await;
    let in_grace: Option<String> = sqlx::query_scalar(SWEEP_CLOSE)
        .bind(&dispatched_round.request)
        .fetch_one(&mut worker)
        .await
        .unwrap();
    assert_eq!(in_grace, None, "must not sweep within 15-minute grace");

    f.owner_exec(
        "UPDATE openmettle.runs
            SET lease_expires_at=clock_timestamp()-interval '16 minutes',
                execution_expires_at=clock_timestamp()-interval '16 minutes'
          WHERE id=$1::uuid",
        &dispatched_round.run,
    )
    .await;
    let past_grace: Option<String> = sqlx::query_scalar(SWEEP_CLOSE)
        .bind(&dispatched_round.request)
        .fetch_one(&mut worker)
        .await
        .unwrap();
    assert_eq!(past_grace.as_deref(), Some("unreported"));
    assert_eq!(
        ledger(&mut f, &dispatched_round.request).await,
        (
            vec![(0, Some("unreported".to_owned()))],
            Some((0, true, None, 0)),
            true
        )
    );

    // Parked-for-approval run (`runs.execution_expires_at IS NULL`, original deadline preserved
    // in `run_approvals.resume_execution_expires_at`): waits 15 minutes past the preserved
    // deadline, then sweeps as `unreported` even if the run failed without resuming.
    let parked = f.round(&plain).await;
    f.authorized(&parked, "a live run round").await;
    assert_eq!(f.dispatch(&parked).await, [f.routed()]);
    let approval_id: String = sqlx::query_scalar(
        "INSERT INTO openmettle.run_approvals
             (scope_id,run_id,actor_user_id,logical_key,tool_id,tool_version,
              canonical_arguments,destination,authority_evidence,binding_digest,
              approval_expires_at,resume_execution_expires_at)
         SELECT scope_id,id,actor_user_id,'sweep-park-key','tool.x','1',
                '{}'::text::bytea,'dest','{}'::text::bytea,sha256('bind'),
                clock_timestamp()-interval '14 minutes',
                clock_timestamp()-interval '14 minutes'
           FROM openmettle.runs WHERE id=$1::uuid
         RETURNING id::text",
    )
    .bind(&parked.run)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.runs
            SET state='failed', wait_reason=NULL, approval_wait_id=$2::uuid,
                claim_token=NULL, claimed_at=NULL, lease_expires_at=NULL, execution_expires_at=NULL
          WHERE id=$1::uuid",
    )
    .bind(&parked.run)
    .bind(&approval_id)
    .execute(&mut f.owner)
    .await
    .unwrap();
    let parked_in_grace: Option<String> = sqlx::query_scalar(SWEEP_CLOSE)
        .bind(&parked.request)
        .fetch_one(&mut worker)
        .await
        .unwrap();
    assert_eq!(
        parked_in_grace, None,
        "parked run uses resume_execution_expires_at + 15m grace"
    );
    sqlx::query(
        "UPDATE openmettle.run_approvals
            SET approval_expires_at=clock_timestamp()-interval '16 minutes',
                resume_execution_expires_at=clock_timestamp()-interval '16 minutes'
          WHERE id=$1::uuid",
    )
    .bind(&approval_id)
    .execute(&mut f.owner)
    .await
    .unwrap();
    let parked_past_grace: Option<String> = sqlx::query_scalar(SWEEP_CLOSE)
        .bind(&parked.request)
        .fetch_one(&mut worker)
        .await
        .unwrap();
    assert_eq!(parked_past_grace.as_deref(), Some("unreported"));
    let remaining: Vec<(String, String, bool)> = sqlx::query_as(SWEEP_CANDIDATES)
        .bind(100_i32)
        .fetch_all(&mut worker)
        .await
        .unwrap();
    assert_eq!(
        remaining
            .iter()
            .map(|(_, id, eligible)| (id.as_str(), *eligible))
            .collect::<Vec<_>>(),
        [(probe.request.as_str(), false)]
    );
}

/// Concurrent race between `gateway_dispatch` and `gateway_close_unreported` on the same
/// request: deterministic lock ordering in both directions plus barrier races never deadlock,
/// never double-close, and leave every request in one consistent state.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_concurrent_dispatch_and_unreported_sweep_never_deadlock_or_double_close() {
    let mut f = Rounds::new().await;
    let plain = quotas::snapshot(100);

    // 1. Sweep holds `gateway_requests FOR UPDATE` (blocked behind a SHARE table lock on
    //    `gateway_settlements`), and `gateway_dispatch` arrives behind it: sweep commits
    //    `not_dispatched`, and `gateway_dispatch` unblocks and returns no row.
    let sweep_first = f.round(&plain).await;
    f.authorized(&sweep_first, "a live run round").await;
    f.owner_exec(
        "UPDATE openmettle.runs SET lease_expires_at=clock_timestamp()-interval '1 second'
          WHERE id=$1::uuid",
        &sweep_first.run,
    )
    .await;
    let mut holder = connect(&f.db.0, OWNER).await;
    let holder_pid = backend_pid(&mut holder).await;
    holder.execute("BEGIN").await.unwrap();
    holder
        .execute("LOCK TABLE openmettle.gateway_settlements IN SHARE MODE")
        .await
        .unwrap();
    let mut worker = connect(&f.db.0, WORKER).await;
    let worker_pid = backend_pid(&mut worker).await;
    let req_id = sweep_first.request.clone();
    let sweeping = tokio::spawn(async move {
        sqlx::query_scalar::<_, Option<String>>(SWEEP_CLOSE)
            .bind(req_id)
            .fetch_one(&mut worker)
            .await
            .unwrap()
    });
    wait_for_blocked_peer(&f.db, holder_pid).await;
    let dispatching = f.dispatching(&sweep_first).await;
    wait_for_blocked_peer(&f.db, worker_pid).await;
    holder.execute("COMMIT").await.unwrap();
    assert_eq!(sweeping.await.unwrap().as_deref(), Some("not_dispatched"));
    assert_eq!(dispatching.await.unwrap(), []);
    assert!(!f.stored(&sweep_first).await.3);

    // 2. `gateway_dispatch` holds `gateway_requests` in an open transaction while the sweep
    //    runs: the sweep uses SKIP LOCKED so it returns None without blocking, dispatch
    //    commits, and a later sweep leaves the in-grace dispatched request open.
    let dispatch_first = f.round(&plain).await;
    f.authorized(&dispatch_first, "a live run round").await;
    let mut gateway = connect(&f.db.0, pg::GATEWAY).await;
    gateway.execute("BEGIN").await.unwrap();
    let granted: Vec<Dispatched> = sqlx::query_as(DISPATCH)
        .bind(&dispatch_first.request)
        .bind(dispatch_first.bearer.as_slice())
        .fetch_all(&mut gateway)
        .await
        .unwrap();
    assert_eq!(granted, [f.routed()]);
    let mut worker = connect(&f.db.0, WORKER).await;
    let skipped: Option<String> = sqlx::query_scalar(SWEEP_CLOSE)
        .bind(&dispatch_first.request)
        .fetch_one(&mut worker)
        .await
        .unwrap();
    assert_eq!(skipped, None);
    gateway.execute("COMMIT").await.unwrap();
    assert!(f.stored(&dispatch_first).await.3);
    let after_commit: Option<String> = sqlx::query_scalar(SWEEP_CLOSE)
        .bind(&dispatch_first.request)
        .fetch_one(&mut worker)
        .await
        .unwrap();
    assert_eq!(after_commit, None);

    // 3. Barrier race across 6 rounds: cancel, dispatch, and sweep start together.
    let principal = authz_store::principal(&f.db, &f.actor).await;
    for _ in 0..6 {
        let round = f.round(&plain).await;
        f.authorized(&round, "a live run round").await;
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let (b1, b2, b3) = (barrier.clone(), barrier.clone(), barrier.clone());
        let (db_cancel, db_disp, db_sweep) = (f.db.0.clone(), f.db.0.clone(), f.db.0.clone());
        let (scope, run_id, principal_c) = (f.scope.clone(), round.run.clone(), principal.clone());
        let (req_disp, bearer_disp) = (round.request.clone(), round.bearer);
        let req_sweep = round.request.clone();

        let t_cancel = tokio::spawn(async move {
            let mut api = connect(&db_cancel, API).await;
            b1.wait().await;
            queue::cancel_run(&mut api, &principal_c, &scope, &run_id)
                .await
                .unwrap();
        });
        let t_dispatch = tokio::spawn(async move {
            let mut gw = connect(&db_disp, pg::GATEWAY).await;
            b2.wait().await;
            sqlx::query_as::<_, Dispatched>(DISPATCH)
                .bind(req_disp)
                .bind(bearer_disp.as_slice())
                .fetch_all(&mut gw)
                .await
                .unwrap()
        });
        let t_sweep = tokio::spawn(async move {
            let mut wk = connect(&db_sweep, WORKER).await;
            b3.wait().await;
            sqlx::query_scalar::<_, Option<String>>(SWEEP_CLOSE)
                .bind(req_sweep)
                .fetch_one(&mut wk)
                .await
                .unwrap()
        });
        t_cancel.await.unwrap();
        let disp_rows = t_dispatch.await.unwrap();
        let sweep_reason = t_sweep.await.unwrap();

        let (_, _, _, dispatched) = f.stored(&round).await;
        if dispatched {
            assert_eq!(disp_rows, [f.routed()]);
            assert_eq!(sweep_reason, None);
            assert_eq!(ledger(&mut f, &round.request).await, (vec![], None, false));
        } else {
            assert_eq!(disp_rows, []);
            if sweep_reason.is_none() {
                // Sweep skipped while cancel or dispatch held locks; closing now succeeds cleanly.
                let closed: Option<String> = sqlx::query_scalar(SWEEP_CLOSE)
                    .bind(&round.request)
                    .fetch_one(&mut worker)
                    .await
                    .unwrap();
                assert_eq!(closed.as_deref(), Some("not_dispatched"));
            } else {
                assert_eq!(sweep_reason.as_deref(), Some("not_dispatched"));
            }
            assert_eq!(f.dispatch(&round).await, []);
            assert_eq!(
                ledger(&mut f, &round.request).await,
                (
                    vec![(0, Some("not_dispatched".to_owned()))],
                    Some((0, true, None, 0)),
                    true
                )
            );
        }
    }
}

/// Upgrading from schema 31 to 32 preserves existing reports, enables the worker sweep, and
/// enforces the sweep-only role guard, revision-0 CHECK, and dispatched/undispatched trigger rules.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn migration_32_upgrades_from_31_and_enforces_sweep_reason_guards() {
    let mut f = Rounds::at(31).await;
    let plain = quotas::snapshot(100);
    let settled_usage = f.round(&plain).await;
    let settled_reason = f.round(&plain).await;
    let open_undispatched = f.round(&plain).await;
    let open_unreported = f.round(&plain).await;
    for r in [
        &settled_usage,
        &settled_reason,
        &open_undispatched,
        &open_unreported,
    ] {
        f.authorized(r, "a live run round").await;
    }
    let gateway = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(pg::GATEWAY));
    for r in [&settled_usage, &settled_reason, &open_unreported] {
        assert_eq!(f.dispatch(r).await, [f.routed()]);
    }
    assert_eq!(
        settlement::ingest(&gateway, &report_of(&f, &settled_usage, Some((4, 3)))).await,
        Ok(Outcome::Applied)
    );
    assert_eq!(
        settlement::ingest_incomplete(&gateway, &report_of(&f, &settled_reason, None), "no_usage")
            .await,
        Ok(Outcome::Applied)
    );
    f.owner_exec(
        "UPDATE openmettle.runs SET state='failed' WHERE id=$1::uuid",
        &open_undispatched.run,
    )
    .await;
    f.owner_exec(
        "UPDATE openmettle.runs
            SET state='failed',
                lease_expires_at=clock_timestamp()-interval '20 minutes',
                execution_expires_at=clock_timestamp()-interval '20 minutes'
          WHERE id=$1::uuid",
        &open_unreported.run,
    )
    .await;

    let settings = f.db.settings(Duration::from_secs(10));
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(f.db.history().await, all_versions());

    // Previously stored reports are untouched; open requests are swept cleanly.
    assert_eq!(
        ledger(&mut f, &settled_usage.request).await,
        (
            vec![(1, None)],
            Some((1, true, Some("7".to_owned()), 0)),
            true
        )
    );
    assert_eq!(
        ledger(&mut f, &settled_reason.request).await,
        (
            vec![(1, Some("no_usage".to_owned()))],
            Some((1, true, None, 0)),
            true
        )
    );
    let mut worker = connect(&f.db.0, WORKER).await;
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(SWEEP_CLOSE)
            .bind(&open_undispatched.request)
            .fetch_one(&mut worker)
            .await
            .unwrap()
            .as_deref(),
        Some("not_dispatched")
    );
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(SWEEP_CLOSE)
            .bind(&open_unreported.request)
            .fetch_one(&mut worker)
            .await
            .unwrap()
            .as_deref(),
        Some("unreported")
    );

    // The gateway role cannot emit sweep-only reasons through the library or directly in SQL.
    let probe_disp = f.round(&plain).await;
    let probe_undisp = f.round(&plain).await;
    f.authorized(&probe_disp, "live").await;
    f.authorized(&probe_undisp, "live").await;
    assert_eq!(f.dispatch(&probe_disp).await, [f.routed()]);
    for reason in ["not_dispatched", "unreported"] {
        assert_eq!(
            settlement::ingest_incomplete(
                &gateway,
                &UsageReport {
                    revision: 0,
                    ..report_of(&f, &probe_disp, None)
                },
                reason,
            )
            .await,
            Err(StoreError::Refused),
            "{reason}"
        );
        let mut gw = connect(&f.db.0, pg::GATEWAY).await;
        let forged = sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,incomplete)
             VALUES ($1::uuid,$2::uuid,$1::uuid,0,true,$3)",
        )
        .bind(&probe_disp.request)
        .bind(INSTALL)
        .bind(reason)
        .execute(&mut gw)
        .await;
        assert_eq!(sqlstate(forged), "42501", "gateway forged {reason}");
    }

    // Table CHECK rejects sweep-only reasons at revision != 0 or final = false even as owner.
    for (rev, is_final, reason) in [
        (1_i64, true, "not_dispatched"),
        (1_i64, true, "unreported"),
        (0_i64, false, "not_dispatched"),
        (0_i64, false, "unreported"),
    ] {
        let refused = sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,incomplete)
             VALUES ($1::uuid,$2::uuid,gen_random_uuid(),$3,$4,$5)",
        )
        .bind(&probe_disp.request)
        .bind(INSTALL)
        .bind(rev)
        .bind(is_final)
        .bind(reason)
        .execute(&mut f.owner)
        .await;
        let Err(sqlx::Error::Database(error)) = refused else {
            panic!("accepted {reason} rev={rev} final={is_final}");
        };
        assert_eq!(
            (error.code().as_deref(), error.constraint()),
            (
                Some("23514"),
                Some("gateway_usage_reports_incomplete_check")
            )
        );
    }

    // Deferred trigger enforces dispatched_at IS NULL for `not_dispatched`, dispatched_at IS NOT
    // NULL for `unreported`, and forbids a later revision alongside `not_dispatched`.
    for (why, req_id, reason, with_rev1) in [
        (
            "not_dispatched on dispatched",
            &probe_disp.request,
            "not_dispatched",
            false,
        ),
        (
            "unreported on undispatched",
            &probe_undisp.request,
            "unreported",
            false,
        ),
        (
            "not_dispatched with rev 1",
            &probe_undisp.request,
            "not_dispatched",
            true,
        ),
    ] {
        use sqlx::Connection;
        let mut tx = f.owner.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,incomplete)
             VALUES ($1::uuid,$2::uuid,$1::uuid,0,true,$3)",
        )
        .bind(req_id)
        .bind(INSTALL)
        .bind(reason)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_settlements
                 (request_id,revision,final,measured,outstanding)
             VALUES ($1::uuid,0,true,NULL,0)",
        )
        .bind(req_id)
        .execute(&mut *tx)
        .await
        .unwrap();
        if with_rev1 {
            sqlx::query(
                "INSERT INTO openmettle.gateway_usage_reports
                     (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens)
                 VALUES ($1::uuid,$2::uuid,gen_random_uuid(),1,true,3,2)",
            )
            .bind(req_id)
            .bind(INSTALL)
            .execute(&mut *tx)
            .await
            .unwrap();
            sqlx::query(
                "UPDATE openmettle.gateway_settlements
                    SET revision=1,final=true,measured=5,outstanding=0
                  WHERE request_id=$1::uuid",
            )
            .bind(req_id)
            .execute(&mut *tx)
            .await
            .unwrap();
        }
        let Err(sqlx::Error::Database(error)) = tx.commit().await else {
            panic!("{why}: committed");
        };
        assert_eq!(error.code().as_deref(), Some("23514"), "{why}");
    }
}

/// Migration 32 cleans unaccepted raw revision-0 reports on unbound unsettled requests (leaving
/// already-settled schema 29–30 revision-0 requests intact and failing closed if an unsettled
/// unbound request has an accepted revision-0 report), reserves revision 0 on unbound requests to
/// `openmettle_owner` while keeping revision 0 available on bound ADR 0037 requests, and blocks
/// bare or single-count final corrections after `unreported` on unmetered requests.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn migration_32_cleans_unaccepted_rev0_and_reserves_unbound_rev0_to_owner() {
    use sqlx::Connection;

    // 1. Schema 31 -> 32 upgrade with historical settled rev-0 AND dangling raw rev-0 rows.
    let mut f = Rounds::at(31).await;
    let plain = quotas::snapshot(100);
    let historical_rev0 = f.round(&plain).await;
    let historical_partial_final = f.round(&plain).await;
    let dangling_undisp = f.round(&plain).await;
    let dangling_unrep = f.round(&plain).await;
    for r in [
        &historical_rev0,
        &historical_partial_final,
        &dangling_undisp,
        &dangling_unrep,
    ] {
        f.authorized(r, "a live run round").await;
    }
    assert_eq!(f.dispatch(&historical_rev0).await, [f.routed()]);
    assert_eq!(f.dispatch(&historical_partial_final).await, [f.routed()]);
    assert_eq!(f.dispatch(&dangling_unrep).await, [f.routed()]);
    for sql in SETTLED {
        f.owner_exec(sql, &historical_rev0.request).await;
    }
    let historical_rev0_report_id: String = sqlx::query_scalar(
        "SELECT report_id::text FROM openmettle.gateway_usage_reports
          WHERE request_id=$1::uuid AND revision=0",
    )
    .bind(&historical_rev0.request)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();

    // Schema 31 accepted a single-count final correction at revision 2 after revision 1 had
    // already closed the fold. Seed that schema-31 state as `openmettle_gateway` so migration 32
    // upgrades across it, then verify exact replay of revision 2 AND a subsequent complete
    // revision-3 correction under the new binary.
    let mut gw = connect(&f.db.0, pg::GATEWAY).await;
    let gateway_v31 = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(pg::GATEWAY));
    assert_eq!(
        settlement::ingest(
            &gateway_v31,
            &report_of(&f, &historical_partial_final, Some((10, 5)))
        )
        .await,
        Ok(Outcome::Applied)
    );
    let mut partial_rev2 = report_of(&f, &historical_partial_final, None);
    partial_rev2.revision = 2;
    partial_rev2.prompt_tokens = Some(12);
    partial_rev2.completion_tokens = None;
    {
        let mut tx = gw.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,prompt_tokens)
             VALUES ($1::uuid,$2::uuid,$1::uuid,2,true,12)",
        )
        .bind(&historical_partial_final.request)
        .bind(INSTALL)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_settlements
                SET revision=2,final=true,measured=12,outstanding=0
              WHERE request_id=$1::uuid",
        )
        .bind(&historical_partial_final.request)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("SELECT openmettle.quota_settle_gateway_usage($1::uuid,$2::uuid,$1::uuid,2)")
            .bind(&historical_partial_final.request)
            .bind(INSTALL)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    // Simulate a gateway writer that left unaccepted raw revision-0 rows under schema 31.
    for r in [&dangling_undisp, &dangling_unrep] {
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens)
             VALUES ($1::uuid,$2::uuid,gen_random_uuid(),0,true,4,3)",
        )
        .bind(&r.request)
        .bind(INSTALL)
        .execute(&mut gw)
        .await
        .unwrap();
    }
    f.owner_exec(
        "UPDATE openmettle.runs SET state='failed' WHERE id=$1::uuid",
        &dangling_undisp.run,
    )
    .await;
    f.owner_exec(
        "UPDATE openmettle.runs
            SET state='failed',
                lease_expires_at=clock_timestamp()-interval '20 minutes',
                execution_expires_at=clock_timestamp()-interval '20 minutes'
          WHERE id=$1::uuid",
        &dangling_unrep.run,
    )
    .await;

    let settings = f.db.settings(Duration::from_secs(10));
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(f.db.history().await, all_versions());

    // Historical settled revision-0 row is preserved intact.
    assert_eq!(
        ledger(&mut f, &historical_rev0.request).await,
        (
            vec![(0, None)],
            Some((0, true, Some("2".to_owned()), 0)),
            true
        )
    );
    // Dangling raw revision-0 rows were cleaned so the sweep closes both without 23505.
    let mut worker = connect(&f.db.0, WORKER).await;
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(SWEEP_CLOSE)
            .bind(&dangling_undisp.request)
            .fetch_one(&mut worker)
            .await
            .unwrap()
            .as_deref(),
        Some("not_dispatched")
    );
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(SWEEP_CLOSE)
            .bind(&dangling_unrep.request)
            .fetch_one(&mut worker)
            .await
            .unwrap()
            .as_deref(),
        Some("unreported")
    );

    // 2. Unmetered bare/single-count final correction after `unreported` is refused by both
    //    `settlement::ingest` and direct SQL, while exact replays of historical schema <= 31
    //    revision-0 and single-count final reports return `Duplicate` and a subsequent complete
    //    revision-3 correction succeeds.
    let gateway = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(pg::GATEWAY));
    let exact_rev0 = UsageReport {
        report_id: historical_rev0_report_id,
        revision: 0,
        ..report_of(&f, &historical_rev0, Some((1, 1)))
    };
    assert_eq!(
        settlement::ingest(&gateway, &exact_rev0).await,
        Ok(Outcome::Duplicate)
    );
    assert_eq!(
        settlement::ingest(
            &gateway,
            &UsageReport {
                prompt_tokens: Some(9),
                ..exact_rev0.clone()
            }
        )
        .await,
        Err(StoreError::Conflict)
    );
    assert_eq!(
        settlement::ingest(&gateway, &partial_rev2).await,
        Ok(Outcome::Duplicate)
    );
    let complete_rev3 = UsageReport {
        revision: 3,
        ..report_of(&f, &historical_partial_final, Some((12, 6)))
    };
    assert_eq!(
        settlement::ingest(&gateway, &complete_rev3).await,
        Ok(Outcome::Applied)
    );
    assert_eq!(
        settlement::ingest(&gateway, &partial_rev2).await,
        Ok(Outcome::Duplicate)
    );
    assert_eq!(
        settlement::ingest(
            &gateway,
            &UsageReport {
                revision: 4,
                prompt_tokens: Some(15),
                completion_tokens: None,
                ..report_of(&f, &historical_partial_final, None)
            }
        )
        .await,
        Err(StoreError::Refused)
    );
    for (prompt, completion) in [(None, None), (Some(5), None), (None, Some(3))] {
        let mut r = report_of(&f, &dangling_unrep, None);
        r.prompt_tokens = prompt;
        r.completion_tokens = completion;
        assert_eq!(
            settlement::ingest(&gateway, &r).await,
            Err(StoreError::Refused)
        );
    }
    {
        let mut direct_owner = connect(&f.db.0, OWNER).await;
        let mut tx = direct_owner.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final)
             VALUES ($1::uuid,$2::uuid,gen_random_uuid(),1,true)",
        )
        .bind(&dangling_unrep.request)
        .bind(INSTALL)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_settlements
                SET revision=1,final=true,measured=NULL,outstanding=0
              WHERE request_id=$1::uuid",
        )
        .bind(&dangling_unrep.request)
        .execute(&mut *tx)
        .await
        .unwrap();
        let Err(sqlx::Error::Database(error)) = tx.commit().await else {
            panic!("unmetered bare final report committed after unreported");
        };
        assert_eq!(error.code().as_deref(), Some("23514"));
    }
    assert_eq!(
        ledger(&mut f, &dangling_unrep.request).await,
        (
            vec![(0, Some("unreported".to_owned()))],
            Some((0, true, None, 0)),
            true
        )
    );

    // 3. Post-32 / post-37: `openmettle_gateway` cannot write revision 0 through either
    //    `settlement` or direct SQL (42501).
    let fresh = f.round(&plain).await;
    f.authorized(&fresh, "live").await;
    assert_eq!(f.dispatch(&fresh).await, [f.routed()]);
    assert_eq!(
        settlement::ingest(
            &gateway,
            &UsageReport {
                revision: 0,
                ..report_of(&f, &fresh, Some((4, 3)))
            },
        )
        .await,
        Err(StoreError::Refused)
    );
    assert_eq!(
        settlement::ingest_incomplete(
            &gateway,
            &UsageReport {
                revision: 0,
                ..report_of(&f, &fresh, None)
            },
            "no_usage",
        )
        .await,
        Err(StoreError::Refused)
    );
    for (what, sql) in [
        (
            "measured rev 0",
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens)
             VALUES ($1::uuid,$2::uuid,gen_random_uuid(),0,true,4,3)",
        ),
        (
            "non-final rev 0",
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,prompt_tokens)
             VALUES ($1::uuid,$2::uuid,gen_random_uuid(),0,false,4)",
        ),
        (
            "proxy reason rev 0",
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,incomplete)
             VALUES ($1::uuid,$2::uuid,gen_random_uuid(),0,true,'no_usage')",
        ),
    ] {
        let refused = sqlx::query(sql)
            .bind(&fresh.request)
            .bind(INSTALL)
            .execute(&mut gw)
            .await;
        assert_eq!(sqlstate(refused), "42501", "{what}");
    }

    // 4. Fail-closed upgrade: a non-final revision-0 settlement on an unbound unsettled request
    //    blocks migration 32 with 23514.
    let mut bad = Rounds::at(31).await;
    let corrupt = bad.round(&plain).await;
    bad.authorized(&corrupt, "live").await;
    assert_eq!(bad.dispatch(&corrupt).await, [bad.routed()]);
    sqlx::query(
        "INSERT INTO openmettle.gateway_usage_reports
             (request_id,source,report_id,revision,final,prompt_tokens)
         VALUES ($1::uuid,$2::uuid,gen_random_uuid(),0,false,4)",
    )
    .bind(&corrupt.request)
    .bind(INSTALL)
    .execute(&mut bad.owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_settlements
             (request_id,revision,final,measured,outstanding)
         VALUES ($1::uuid,0,false,4,96)",
    )
    .bind(&corrupt.request)
    .execute(&mut bad.owner)
    .await
    .unwrap();
    let bad_settings = bad.db.settings(Duration::from_secs(10));
    let failed = migrate::apply(&bad_settings, MIGRATIONS).await;
    let err = failed.expect_err("corrupt rev-0 non-final settlement must block migration 32");
    assert!(
        err.to_string().contains("accepted revision-0 report") || err.to_string().contains("23514"),
        "unexpected migration error: {err:?}"
    );
}

/// Migration 34 (issue #166):
/// 1. Upgrade preflight fails closed (23514) on any unbound request with an unsettled
///    `usage_cost_micros` hold (`held` or `handoff_committed`, whether `settled_final` is false
///    or true from a pre-34 report), and the 0034 library refuses handing off a cost-bound round
///    on schema 33.
/// 2. Historical pre-34 settled unbound cost rows (settled with `cost` or swept at rev 0)
///    survive `33 -> 34` with zero drift, and exact replays return `Outcome::Duplicate`.
/// 3. Post-34 bound ADR 0037 requests still accept caller-supplied `cost`/`unit`.
/// 4. Pathological `tokens * rate + fixed >= 1e38` fails closed with `23514` / `Refused`.
/// 5. 6-arg `gateway_handoff_round` rejects invalid pricing args (`23514`),
///    `enforce_gateway_handoff_holds` rejects missing/mismatched recorded pricing (`OMQ04`), and
///    `resolve_cost_from_state` refuses `Profile(None)` when a run has a parent cost hold even
///    after cost limits expire.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn migration_34_upgrade_preflight_historical_replay_overflow_and_bound_cost() {
    use openmettle_core::{
        authz::gateway::{self, TurnRound},
        model_config::CostBound,
        quotas::{self as budgets, RunBudgetReservation},
    };
    use sqlx::Connection;

    const HANDOFF_PRICED: &str =
        "SELECT openmettle.gateway_handoff_round($1::uuid,$2,$3::uuid,sha256($4),$5,$6)";

    async fn enable_cost_metering(owner: &mut PgConnection) {
        owner
            .execute(
                "UPDATE openmettle.quota_enforcement
                    SET metering_enforced = true,
                        metering_enforced_at = coalesce(metering_enforced_at, clock_timestamp()),
                        overrides_enforced = true,
                        overrides_enforced_at = coalesce(overrides_enforced_at, clock_timestamp())
                  WHERE id",
            )
            .await
            .unwrap();
        owner
            .execute(
                "INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit)
                 VALUES ('personal','usage_tokens',1000000)",
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
                "INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit)
                 VALUES ('personal','usage_cost_micros',1000000)",
            )
            .await
            .unwrap();
    }

    async fn admit_and_claim(
        f: &mut Rounds,
        units: i64,
        cost_bound: Option<CostBound>,
        rounds: i64,
        pin_in_snapshot: bool,
    ) -> (String, String) {
        let per_round_cost = cost_bound.map(|cb| {
            u128::from(cb.fixed_micros) + u128::from(units as u64) * u128::from(cb.micros_per_token)
        });
        let chat = authz_runs::chat(&f.db, &f.scope, "personal", &f.actor).await;
        let mut api = connect(&f.db.0, API).await;
        let (branch, message) = quotas::branch_and_message(&mut api, &f.scope, &chat).await;
        let key = format!("m34-{}", f.number());
        let snap = quotas::snapshot_priced(
            "a",
            units as u64,
            pin_in_snapshot.then_some(cost_bound).flatten(),
        );
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        let Admission::Admitted { run_id, .. } = queue::admit_run(
            &mut tx,
            &RunAdmission {
                input: RunInput {
                    scope: &f.scope,
                    actor: &f.actor.user,
                    conversation: &chat,
                    branch: &branch,
                    message: &message,
                    key: &key,
                    format: "openmettle.conversation",
                    version: 1,
                    input: b"{}",
                    config: &snap,
                },
                actor_approval_id: &f.actor.approval,
                capabilities: &[],
                requested_rounds: Some(rounds),
                now_ms: NOW,
                cost_qualified: per_round_cost.map(|_| true),
            },
            &LIMITS,
        )
        .await
        .unwrap() else {
            panic!("expected admission");
        };
        let refused = budgets::reserve_admitted_run_budget(
            &mut tx,
            &RunBudgetReservation {
                scope_id: &f.scope,
                scope_kind: "personal",
                actor_user_id: &f.actor.user,
                actor_approval_id: &f.actor.approval,
                run_id: &run_id,
                token_units: units * rounds,
                per_round_cost_micros: per_round_cost,
                round_limit: i32::try_from(rounds).unwrap(),
                requires_device_slot: false,
            },
        )
        .await
        .unwrap();
        assert!(refused.is_none(), "{refused:?}");
        tx.commit().await.unwrap();
        let mut worker = connect(&f.db.0, WORKER).await;
        let claim = queue::claim_next(&mut worker, &CLAIMS, &LEASES)
            .await
            .unwrap()
            .expect("claimed run");
        assert_eq!(claim.run_id, run_id);
        (run_id, claim.claim_token)
    }

    async fn handoff_raw(
        f: &Rounds,
        request_id: &str,
        run_id: &str,
        claim_token: &str,
        secret: &[u8; 32],
        bearer: &[u8; 32],
        pricing: Option<(Option<i64>, Option<i64>)>,
    ) -> Result<bool, sqlx::Error> {
        // Rekey dispatch_hash to a known secret (library keeps its secret private).
        let mut owner = connect(&f.db.0, OWNER).await;
        sqlx::query(
            "UPDATE openmettle.gateway_requests SET dispatch_hash = sha256($2) WHERE id = $1::uuid",
        )
        .bind(request_id)
        .bind(secret.as_slice())
        .execute(&mut owner)
        .await
        .unwrap();
        let mut worker = connect(&f.db.0, WORKER).await;
        let mut tx = worker.begin().await.unwrap();
        sqlx::query(
            "SELECT openmettle.quota_lock_turn_handoff_prefix(
                 $1::uuid, $2::bytea, $3::uuid, $4::uuid, $5::uuid
             )",
        )
        .bind(request_id)
        .bind(secret.as_slice())
        .bind(&f.scope)
        .bind(run_id)
        .bind(claim_token)
        .execute(&mut *tx)
        .await?;
        let ok: bool = match pricing {
            Some((fixed, rate)) => {
                sqlx::query_scalar(HANDOFF_PRICED)
                    .bind(request_id)
                    .bind(secret.as_slice())
                    .bind(claim_token)
                    .bind(bearer.as_slice())
                    .bind(fixed)
                    .bind(rate)
                    .fetch_one(&mut *tx)
                    .await?
            }
            None => {
                sqlx::query_scalar(HANDOFF)
                    .bind(request_id)
                    .bind(secret.as_slice())
                    .bind(claim_token)
                    .bind(bearer.as_slice())
                    .fetch_one(&mut *tx)
                    .await?
            }
        };
        if !ok {
            tx.rollback().await?;
            return Ok(false);
        }
        sqlx::query(
            "SELECT openmettle.quota_commit_turn_handoff(
                 $1::uuid, $2::bytea, $3::uuid, $4::uuid, $5::uuid, false, NULL, false
             )",
        )
        .bind(request_id)
        .bind(secret.as_slice())
        .bind(&f.scope)
        .bind(run_id)
        .bind(claim_token)
        .execute(&mut *tx)
        .await?;
        sqlx::query(CONFIRM)
            .bind(request_id)
            .bind(secret.as_slice())
            .bind(claim_token)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    let std_cb = CostBound {
        fixed_micros: 50,
        micros_per_token: 1,
    };

    // --- 1. Pre-34 fail-closed checks (library + migration 34 preflight) ---
    {
        let mut f = Rounds::at(33).await;
        enable_cost_metering(&mut f.owner).await;
        let worker_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with(f.db.1.options(WORKER));
        let (run_id, claim) = admit_and_claim(&mut f, 100, Some(std_cb), 1, false).await;
        let pending = gateway::reserve_turn_round(
            &worker_pool,
            TurnRound {
                scope_id: &f.scope,
                actor: &f.actor.user,
                approval: &f.actor.approval,
                run_id: &run_id,
                round: 1,
                claim_token: &claim,
                installation: INSTALL,
                model: "a",
                round_tokens: 100,
                round_cost: Some(150),
                cost_bound: Some(std_cb),
                requires_device_slot: false,
            },
        )
        .await
        .unwrap();

        // The 0034 library refuses to hand off a cost-bound round on schema 33.
        let fx = quotas::TurnHandoffFixture::chat_priced(INSTALL, "a", 100, std_cb, false);
        assert!(matches!(
            pending
                .handoff(&worker_pool, None, &fx.billable(), fx.prepare_mode(true))
                .await,
            Err(StoreError::Refused)
        ));

        // Simulate a schema-33 worker handing off the round via 4-arg gateway_handoff_round.
        let secret = [0x34; 32];
        let bearer = [0x43; 32];
        assert!(
            handoff_raw(&f, &pending.id, &run_id, &claim, &secret, &bearer, None)
                .await
                .unwrap()
        );

        // Unsettled unbound cost hold (`settled_final = false`) blocks migration 34 with 23514.
        let settings = f.db.settings(Duration::from_secs(10));
        let err = migrate::apply(&settings, MIGRATIONS)
            .await
            .expect_err("unsettled unbound cost hold must block migration 34");
        assert!(
            err.to_string().contains("23514"),
            "expected SQLSTATE 23514, got: {err:?}"
        );

        // Even after a pre-34 complete usage report marks `settled_final = true` while leaving
        // `usage_cost_micros` stuck in `handoff_committed` (issue #166), migration 34 STILL
        // fails closed with 23514.
        let mut gw = connect(&f.db.0, pg::GATEWAY).await;
        sqlx::query("SELECT FROM openmettle.gateway_dispatch($1::uuid, sha256($2))")
            .bind(&pending.id)
            .bind(bearer.as_slice())
            .execute(&mut gw)
            .await
            .unwrap();
        let gw_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with(f.db.1.options(pg::GATEWAY));
        assert_eq!(
            settlement::ingest(
                &gw_pool,
                &UsageReport {
                    request: pending.id.clone(),
                    installation: INSTALL.into(),
                    principal: f.actor.user.clone(),
                    scope: f.scope.clone(),
                    source: INSTALL.into(),
                    report_id: pending.id.clone(),
                    revision: 1,
                    r#final: true,
                    prompt_tokens: Some(10),
                    completion_tokens: Some(5),
                    reasoning_tokens: None,
                    reasoning_included: None,
                    cost: None,
                    unit: None,
                },
            )
            .await,
            Ok(Outcome::Applied)
        );
        let stuck: (bool, String) = sqlx::query_as(
            "SELECT q.settled_final, h.state
               FROM openmettle.gateway_requests q
               JOIN openmettle.quota_reservations h ON h.gateway_request_id = q.id
              WHERE q.id = $1::uuid AND h.resource_kind = 'usage_cost_micros'",
        )
        .bind(&pending.id)
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
        assert_eq!(stuck, (true, "handoff_committed".to_owned()));
        let err = migrate::apply(&settings, MIGRATIONS)
            .await
            .expect_err("issue-#166 stuck cost hold must still block migration 34");
        assert!(
            err.to_string().contains("23514"),
            "expected SQLSTATE 23514, got: {err:?}"
        );
    }

    // --- 2. Clean 33 -> 34 upgrade preserves historical settled rows + exact replay ---
    let mut f = Rounds::at(33).await;
    enable_cost_metering(&mut f.owner).await;
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(WORKER));
    let gw_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(pg::GATEWAY));

    // Historical row A: pre-34 unbound cost row settled with caller-supplied cost = 125.
    let (run_a, claim_a) = admit_and_claim(&mut f, 100, Some(std_cb), 1, false).await;
    let pending_a = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &run_a,
            round: 1,
            claim_token: &claim_a,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(150),
            cost_bound: Some(std_cb),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let secret_a = [0x51; 32];
    let bearer_a = [0x52; 32];
    assert!(
        handoff_raw(
            &f,
            &pending_a.id,
            &run_a,
            &claim_a,
            &secret_a,
            &bearer_a,
            None,
        )
        .await
        .unwrap()
    );
    let mut gw = connect(&f.db.0, pg::GATEWAY).await;
    sqlx::query("SELECT FROM openmettle.gateway_dispatch($1::uuid, sha256($2))")
        .bind(&pending_a.id)
        .bind(bearer_a.as_slice())
        .execute(&mut gw)
        .await
        .unwrap();
    let hist_report = UsageReport {
        request: pending_a.id.clone(),
        installation: INSTALL.into(),
        principal: f.actor.user.clone(),
        scope: f.scope.clone(),
        source: INSTALL.into(),
        report_id: pending_a.id.clone(),
        revision: 1,
        r#final: true,
        prompt_tokens: Some(20),
        completion_tokens: Some(10),
        reasoning_tokens: None,
        reasoning_included: None,
        cost: Some("125".into()),
        unit: Some("usd_micros".into()),
    };
    {
        // Insert directly as openmettle_gateway on schema 33 (simulating a pre-34 writer).
        let mut tx = gw.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens,cost,unit)
             VALUES ($1::uuid,$2::uuid,$1::uuid,1,true,20,10,125,'usd_micros')",
        )
        .bind(&pending_a.id)
        .bind(INSTALL)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_settlements
                 (request_id,revision,final,measured,outstanding)
             VALUES ($1::uuid,1,true,30,0)",
        )
        .bind(&pending_a.id)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("SELECT openmettle.quota_settle_gateway_usage($1::uuid,$2::uuid,$1::uuid,1)")
            .bind(&pending_a.id)
            .bind(INSTALL)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    // Historical row B: pre-34 unbound cost row closed by `not_dispatched` sweep at revision 0.
    let (run_b, claim_b) = admit_and_claim(&mut f, 100, Some(std_cb), 1, false).await;
    let pending_b = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &run_b,
            round: 1,
            claim_token: &claim_b,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(150),
            cost_bound: Some(std_cb),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    assert!(
        handoff_raw(
            &f,
            &pending_b.id,
            &run_b,
            &claim_b,
            &[0x61; 32],
            &[0x62; 32],
            None,
        )
        .await
        .unwrap()
    );
    f.owner_exec(
        "UPDATE openmettle.runs SET state='failed' WHERE id=$1::uuid",
        &run_b,
    )
    .await;
    let mut worker_c = connect(&f.db.0, WORKER).await;
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(SWEEP_CLOSE)
            .bind(&pending_b.id)
            .fetch_one(&mut worker_c)
            .await
            .unwrap()
            .as_deref(),
        Some("not_dispatched")
    );

    // Upgrade 33 -> 34 succeeds cleanly! (Migration 37 intentionally refuses historical
    // caller-priced `cost`/`unit` rows, so this migration-34 test targets schema 34.)
    let settings = f.db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..34]).await.unwrap();
    assert_eq!(f.db.history().await, versions_through(34));

    // Zero drift across historical pre-34 rows, and exact replay returns Duplicate.
    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches,
                pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker_c)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
    assert_eq!(
        settlement::ingest(&gw_pool, &hist_report).await,
        Ok(Outcome::Duplicate)
    );
    assert_eq!(
        settlement::ingest(
            &gw_pool,
            &UsageReport {
                cost: Some("126".into()),
                ..hist_report.clone()
            }
        )
        .await,
        Err(StoreError::Conflict)
    );

    // --- 4. Post-34 invalid pricing args (23514), snapshot mismatch (false) and OMQ04 guards ---
    let (run_p, claim_p) = admit_and_claim(&mut f, 100, Some(std_cb), 1, true).await;
    let pending_p = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &run_p,
            round: 1,
            claim_token: &claim_p,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(150),
            cost_bound: Some(std_cb),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    for (fixed, rate) in [
        (Some(10), None),
        (None, Some(10)),
        (Some(-1), Some(0)),
        (Some(0), Some(-1)),
        (Some(0), Some(0)),
    ] {
        let err = handoff_raw(
            &f,
            &pending_p.id,
            &run_p,
            &claim_p,
            &[0x71; 32],
            &[0x72; 32],
            Some((fixed, rate)),
        )
        .await;
        assert_eq!(sqlstate(err), "23514", "pricing ({fixed:?}, {rate:?})");
    }
    // 4-arg handoff (NULL pricing), wrong-ceiling pricing (40, 1), and swapped-split pricing
    // (150, 0) are all refused by 6-arg `gateway_handoff_round` returning `false` because
    // `runs.config_snapshot` pins `(50, 1)`.
    for (what, pricing) in [
        ("null pricing via 4-arg", None),
        ("mismatched pricing", Some((Some(40), Some(1)))),
        ("swapped split pricing", Some((Some(150), Some(0)))),
    ] {
        let ok = handoff_raw(
            &f,
            &pending_p.id,
            &run_p,
            &claim_p,
            &[0x73; 32],
            &[0x74; 32],
            pricing,
        )
        .await
        .unwrap();
        assert!(!ok, "{what} must be refused by gateway_handoff_round");
    }
    // Direct `openmettle_owner` UPDATE attempting swapped split `(150, 0)` on a `(50, 1)` snapshot
    // is still rejected at commit by `enforce_gateway_handoff_holds` with `OMQ04`.
    {
        let mut tx = f.owner.begin().await.unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_requests
                SET state='handed_off', report_source=installation,
                    bearer_hash=sha256($2), claim_hash=sha256(uuid_send($3::uuid)),
                    cost_fixed_micros=150, cost_micros_per_token=0
              WHERE id=$1::uuid",
        )
        .bind(&pending_p.id)
        .bind([0x77_u8; 32].as_slice())
        .bind(&claim_p)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.quota_reservations
                SET state='handoff_committed', revision=revision+1
              WHERE gateway_request_id=$1::uuid AND state='held'",
        )
        .bind(&pending_p.id)
        .execute(&mut *tx)
        .await
        .unwrap();
        assert_eq!(sqlstate(tx.commit().await), "OMQ04");
    }
    // A pre-34-style snapshot omitting `cost_bound` with a bound cost hold passes
    // `gateway_handoff_round(..., NULL, NULL)` and is rejected at commit with `OMQ04`.
    let (run_unpinned, claim_unpinned) = admit_and_claim(&mut f, 100, Some(std_cb), 1, false).await;
    let pending_unpinned = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &run_unpinned,
            round: 1,
            claim_token: &claim_unpinned,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(150),
            cost_bound: Some(std_cb),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let orig_unpinned_hash: Vec<u8> = sqlx::query_scalar(
        "SELECT dispatch_hash FROM openmettle.gateway_requests WHERE id = $1::uuid",
    )
    .bind(&pending_unpinned.id)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    let err = handoff_raw(
        &f,
        &pending_unpinned.id,
        &run_unpinned,
        &claim_unpinned,
        &[0x78; 32],
        &[0x79; 32],
        None,
    )
    .await;
    assert_eq!(sqlstate(err), "OMQ04", "unpinned snapshot with cost hold");
    sqlx::query("UPDATE openmettle.gateway_requests SET dispatch_hash = $2 WHERE id = $1::uuid")
        .bind(&pending_unpinned.id)
        .bind(&orig_unpinned_hash)
        .execute(&mut f.owner)
        .await
        .unwrap();
    assert!(pending_unpinned.release(&worker_pool).await.unwrap());
    // Matching pricing (50 + 100*1 = 150) commits cleanly.
    assert!(
        handoff_raw(
            &f,
            &pending_p.id,
            &run_p,
            &claim_p,
            &[0x75; 32],
            &[0x76; 32],
            Some((Some(50), Some(1))),
        )
        .await
        .unwrap()
    );

    // --- 5. Pathological `measured >= 1e38`: ignored on token-only, refused with cost hold ---
    {
        let mut f_over = Rounds::new().await;
        let big_cb = CostBound {
            fixed_micros: i64::MAX as u64,
            micros_per_token: i64::MAX as u64,
        };
        let snap = quotas::snapshot_priced("a", 100, Some(big_cb));
        let r = f_over.round(&snap).await;
        let mut worker = connect(&f_over.db.0, WORKER).await;
        let mut tx = worker.begin().await.unwrap();
        let ok: bool = sqlx::query_scalar(HANDOFF_PRICED)
            .bind(&r.request)
            .bind(r.secret.as_slice())
            .bind(&r.lease)
            .bind(r.bearer.as_slice())
            .bind(Some(i64::MAX))
            .bind(Some(i64::MAX))
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert!(ok);
        sqlx::query(CONFIRM)
            .bind(&r.request)
            .bind(r.secret.as_slice())
            .bind(&r.lease)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(f_over.dispatch(&r).await, [f_over.routed()]);
        let over_gw = PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with(f_over.db.1.options(pg::GATEWAY));
        assert_eq!(
            settlement::ingest(
                &over_gw,
                &UsageReport {
                    prompt_tokens: Some(i64::MAX),
                    completion_tokens: Some(i64::MAX),
                    ..report_of(&f_over, &r, None)
                },
            )
            .await,
            Ok(Outcome::Applied)
        );
    }

    // --- 6. `resolve_cost_from_state` refuses Profile(None) when parent cost hold exists even
    //        after all cost limits have been removed/expired (`state.any_limit == false`) ---
    let (run_exp, claim_exp) = admit_and_claim(&mut f, 100, Some(std_cb), 2, true).await;
    // Remove the personal cost limit so `state.any_limit == false` while `run_exp` still holds
    // its 300-micro parent `usage_cost_micros` reservation.
    f.owner
        .execute(
            "DELETE FROM openmettle.quota_defaults
              WHERE scope_kind = 'personal' AND resource_kind = 'usage_cost_micros'",
        )
        .await
        .unwrap();
    assert!(matches!(
        gateway::reserve_turn_round(
            &worker_pool,
            TurnRound {
                scope_id: &f.scope,
                actor: &f.actor.user,
                approval: &f.actor.approval,
                run_id: &run_exp,
                round: 1,
                claim_token: &claim_exp,
                installation: INSTALL,
                model: "a",
                round_tokens: 100,
                round_cost: None,
                cost_bound: None,
                requires_device_slot: false,
            },
        )
        .await,
        Err(StoreError::Refused)
    ));

    let final_drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches,
                pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker_c)
    .await
    .unwrap();
    assert_eq!(final_drift, (0, 0, 0, 0));
}

async fn enable_cost_metering_defaults(owner: &mut PgConnection, cost_limit: i64) {
    owner
        .execute(
            "UPDATE openmettle.quota_enforcement
                SET metering_enforced = true,
                    metering_enforced_at = coalesce(metering_enforced_at, clock_timestamp()),
                    overrides_enforced = true,
                    overrides_enforced_at = coalesce(overrides_enforced_at, clock_timestamp())
              WHERE id",
        )
        .await
        .unwrap();
    owner
        .execute(
            "INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit)
             VALUES ('personal','usage_tokens',1000000)",
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
    sqlx::query(
        "INSERT INTO openmettle.quota_defaults(scope_kind,resource_kind,hard_limit)
         VALUES ('personal','usage_cost_micros',$1)",
    )
    .bind(cost_limit)
    .execute(owner)
    .await
    .unwrap();
}

async fn admit_and_claim_priced(
    f: &mut Rounds,
    units: i64,
    cost_bound: Option<openmettle_core::model_config::CostBound>,
    rounds: i64,
    include_snapshot_cost_bound: bool,
) -> (String, String) {
    use openmettle_core::quotas::{self as budgets, RunBudgetReservation};
    let per_round_cost = cost_bound.map(|cb| {
        u128::from(cb.fixed_micros) + u128::from(units as u64) * u128::from(cb.micros_per_token)
    });
    let chat = authz_runs::chat(&f.db, &f.scope, "personal", &f.actor).await;
    let mut api = connect(&f.db.0, API).await;
    let (branch, message) = quotas::branch_and_message(&mut api, &f.scope, &chat).await;
    let key = format!("r1-{}", f.number());
    let snap = quotas::snapshot_priced(
        "a",
        units as u64,
        include_snapshot_cost_bound.then_some(cost_bound).flatten(),
    );
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted { run_id, .. } = queue::admit_run(
        &mut tx,
        &RunAdmission {
            input: RunInput {
                scope: &f.scope,
                actor: &f.actor.user,
                conversation: &chat,
                branch: &branch,
                message: &message,
                key: &key,
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snap,
            },
            actor_approval_id: &f.actor.approval,
            capabilities: &[],
            requested_rounds: Some(rounds),
            now_ms: NOW,
            cost_qualified: per_round_cost.map(|_| true),
        },
        &LIMITS,
    )
    .await
    .unwrap() else {
        panic!("expected admission");
    };
    let refused = budgets::reserve_admitted_run_budget(
        &mut tx,
        &RunBudgetReservation {
            scope_id: &f.scope,
            scope_kind: "personal",
            actor_user_id: &f.actor.user,
            actor_approval_id: &f.actor.approval,
            run_id: &run_id,
            token_units: units * rounds,
            per_round_cost_micros: per_round_cost,
            round_limit: i32::try_from(rounds).unwrap(),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    assert!(refused.is_none(), "{refused:?}");
    tx.commit().await.unwrap();
    let mut worker = connect(&f.db.0, WORKER).await;
    let claim = queue::claim_next(&mut worker, &CLAIMS, &LEASES)
        .await
        .unwrap()
        .expect("claimed run");
    assert_eq!(claim.run_id, run_id);
    (run_id, claim.claim_token)
}

/// Review #1 P1 #1: on a 100-token round admitted with `CostBound { fixed_micros: 50,
/// micros_per_token: 1 }` (`reserved_units = 150`), both Rust (`TurnPending::handoff`) and direct
/// `openmettle_worker` SQL `gateway_handoff_round(..., 150, 0)` must refuse substituting `(150, 0)`
/// even though `150 + 100 * 0 == 150`.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn review_1_p1_1_handoff_rejects_cost_bound_split_substitution() {
    use openmettle_core::{
        authz::gateway::{self, TurnRound},
        model_config::CostBound,
    };
    use sqlx::Connection;

    const HANDOFF_PRICED: &str =
        "SELECT openmettle.gateway_handoff_round($1::uuid,$2,$3::uuid,sha256($4),$5,$6)";

    let mut f = Rounds::new().await;
    enable_cost_metering_defaults(&mut f.owner, 1_000_000).await;
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(WORKER));

    let admitted_cb = CostBound {
        fixed_micros: 50,
        micros_per_token: 1,
    };
    let swapped_cb = CostBound {
        fixed_micros: 150,
        micros_per_token: 0,
    };
    let (run_id, claim) = admit_and_claim_priced(&mut f, 100, Some(admitted_cb), 2, true).await;

    // Rust path: TurnPending::handoff refuses swapped (150, 0) PreparedRequest.
    let pending = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &run_id,
            round: 1,
            claim_token: &claim,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(150),
            cost_bound: Some(admitted_cb),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let swapped_fx = quotas::TurnHandoffFixture::chat_priced(INSTALL, "a", 100, swapped_cb, false);
    assert!(
        matches!(
            pending
                .handoff(
                    &worker_pool,
                    None,
                    &swapped_fx.billable(),
                    swapped_fx.prepare_mode(true)
                )
                .await,
            Err(StoreError::Refused)
        ),
        "TurnPending::handoff must refuse swapped (150, 0) split on a (50, 1) run"
    );

    // Direct openmettle_worker SQL path: 6-arg gateway_handoff_round(..., 150, 0) returns false.
    let secret = [0x81_u8; 32];
    let bearer = [0x82_u8; 32];
    sqlx::query(
        "UPDATE openmettle.gateway_requests SET dispatch_hash = sha256($2) WHERE id = $1::uuid",
    )
    .bind(&pending.id)
    .bind(secret.as_slice())
    .execute(&mut f.owner)
    .await
    .unwrap();
    let mut worker = connect(&f.db.0, WORKER).await;
    let mut tx = worker.begin().await.unwrap();
    let ok: bool = sqlx::query_scalar(HANDOFF_PRICED)
        .bind(&pending.id)
        .bind(secret.as_slice())
        .bind(&claim)
        .bind(bearer.as_slice())
        .bind(Some(150_i64))
        .bind(Some(0_i64))
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert!(
        !ok,
        "direct openmettle_worker SQL gateway_handoff_round must refuse swapped (150, 0) split"
    );
}

/// Review #1 P1 #2: direct `openmettle_gateway` SQL must not settle an undispatched unbound
/// request with measured usage, whether `final = true` OR `final = false`.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn review_1_p1_2_undispatched_unbound_request_rejects_direct_final_and_nonfinal_settlement() {
    use sqlx::Connection;

    let mut f = Rounds::new().await;
    let plain = quotas::snapshot(100);
    for (label, is_final, outstanding) in [("final", true, 0_i64), ("non-final", false, 88_i64)] {
        let round = f.round(&plain).await;
        f.authorized(&round, label).await;
        // Request is handed_off with dispatched_at IS NULL.
        // Migration 37: `openmettle_gateway` is refused direct table writes (42501);
        // the trigger also refuses direct owner settlement at commit (23514).
        let mut gw = connect(&f.db.0, pg::GATEWAY).await;
        assert_eq!(
            sqlstate(
                sqlx::query(
                    "INSERT INTO openmettle.gateway_usage_reports
                         (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens)
                     VALUES ($1::uuid,$2::uuid,gen_random_uuid(),1,$3,7,5)",
                )
                .bind(&round.request)
                .bind(INSTALL)
                .bind(is_final)
                .execute(&mut gw)
                .await
            ),
            "42501"
        );
        let mut owner_c = connect(&f.db.0, OWNER).await;
        let mut tx = owner_c.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens)
             VALUES ($1::uuid,$2::uuid,gen_random_uuid(),1,$3,7,5)",
        )
        .bind(&round.request)
        .bind(INSTALL)
        .bind(is_final)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_settlements
                 (request_id,revision,final,measured,outstanding)
             VALUES ($1::uuid,1,$2,12,$3)",
        )
        .bind(&round.request)
        .bind(is_final)
        .bind(outstanding)
        .execute(&mut *tx)
        .await
        .unwrap();
        let err = tx.commit().await;
        assert_eq!(
            sqlstate(err),
            "23514",
            "undispatched unbound {label} settlement must be refused at commit"
        );
    }
}

/// Review #1 P2 #3: migration 34 cleans up unaccepted historical raw cost reports on unbound
/// requests and forbids newly accepting `cost`/`unit` on unbound settlements, while preserving
/// exact replay of already-accepted schema-33 cost reports as `Outcome::Duplicate`.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn review_1_p2_3_migration_34_cleans_unaccepted_unbound_cost_reports_and_forbids_accepting_them()
 {
    use openmettle_core::authz::gateway::{self, TurnRound};
    use sqlx::Connection;

    let mut f = Rounds::at(33).await;
    enable_cost_metering_defaults(&mut f.owner, 1_000_000).await;
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(WORKER));
    let gw_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(pg::GATEWAY));
    let (run_id, claim) = admit_and_claim_priced(
        &mut f,
        100,
        Some(openmettle_core::model_config::CostBound {
            fixed_micros: 50,
            micros_per_token: 1,
        }),
        1,
        false,
    )
    .await;
    let pending = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &run_id,
            round: 1,
            claim_token: &claim,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(150),
            cost_bound: Some(openmettle_core::model_config::CostBound {
                fixed_micros: 50,
                micros_per_token: 1,
            }),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let secret = [0x91_u8; 32];
    let bearer = [0x92_u8; 32];
    sqlx::query(
        "UPDATE openmettle.gateway_requests SET dispatch_hash = sha256($2) WHERE id = $1::uuid",
    )
    .bind(&pending.id)
    .bind(secret.as_slice())
    .execute(&mut f.owner)
    .await
    .unwrap();
    {
        let mut w = connect(&f.db.0, WORKER).await;
        let mut tx = w.begin().await.unwrap();
        sqlx::query("SELECT openmettle.quota_lock_turn_handoff_prefix($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid)")
            .bind(&pending.id).bind(secret.as_slice()).bind(&f.scope).bind(&run_id).bind(&claim)
            .execute(&mut *tx).await.unwrap();
        let ok: bool = sqlx::query_scalar(HANDOFF)
            .bind(&pending.id)
            .bind(secret.as_slice())
            .bind(&claim)
            .bind(bearer.as_slice())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert!(ok);
        sqlx::query("SELECT openmettle.quota_commit_turn_handoff($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid,false,NULL,false)")
            .bind(&pending.id).bind(secret.as_slice()).bind(&f.scope).bind(&run_id).bind(&claim)
            .execute(&mut *tx).await.unwrap();
        sqlx::query(CONFIRM)
            .bind(&pending.id)
            .bind(secret.as_slice())
            .bind(&claim)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    let mut gw = connect(&f.db.0, pg::GATEWAY).await;
    sqlx::query("SELECT FROM openmettle.gateway_dispatch($1::uuid, sha256($2))")
        .bind(&pending.id)
        .bind(bearer.as_slice())
        .execute(&mut gw)
        .await
        .unwrap();
    // Accept rev 1 with cost=125 on schema 33, plus seed an unaccepted raw rev 2 carrying cost=500.
    {
        let mut tx = gw.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens,cost,unit)
             VALUES ($1::uuid,$2::uuid,$1::uuid,1,true,20,10,125,'usd_micros')",
        )
        .bind(&pending.id)
        .bind(INSTALL)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_settlements
                 (request_id,revision,final,measured,outstanding)
             VALUES ($1::uuid,1,true,30,0)",
        )
        .bind(&pending.id)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("SELECT openmettle.quota_settle_gateway_usage($1::uuid,$2::uuid,$1::uuid,1)")
            .bind(&pending.id)
            .bind(INSTALL)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens,cost,unit)
             VALUES ($1::uuid,$2::uuid,gen_random_uuid(),2,true,20,10,500,'usd_micros')",
        )
        .bind(&pending.id)
        .bind(INSTALL)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    let settings = f.db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..34]).await.unwrap();

    let rev2_remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.gateway_usage_reports
          WHERE request_id = $1::uuid AND revision = 2",
    )
    .bind(&pending.id)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(
        rev2_remaining, 0,
        "migration 34 must delete unaccepted historical raw cost reports on unbound requests"
    );

    // Exact replay of already-accepted rev 1 still returns Duplicate.
    assert_eq!(
        settlement::ingest(
            &gw_pool,
            &UsageReport {
                request: pending.id.clone(),
                installation: INSTALL.into(),
                principal: f.actor.user.clone(),
                scope: f.scope.clone(),
                source: INSTALL.into(),
                report_id: pending.id.clone(),
                revision: 1,
                r#final: true,
                prompt_tokens: Some(20),
                completion_tokens: Some(10),
                reasoning_tokens: None,
                reasoning_included: None,
                cost: Some("125".into()),
                unit: Some("usd_micros".into()),
            },
        )
        .await,
        Ok(Outcome::Duplicate)
    );

    // Commit-time guard in `enforce_gateway_final_settlement_closes()` independently forbids
    // accepting a cost/unit-bearing raw report on BOTH final and non-final settlements, and
    // `openmettle_gateway` itself is refused direct table writes with 42501.
    let mut f_guard = Rounds::new().await;
    let mut gw_guard = connect(&f_guard.db.0, pg::GATEWAY).await;
    let mut owner_guard = connect(&f_guard.db.0, OWNER).await;
    let plain = quotas::snapshot(100);
    for (label, is_final, outstanding) in [("final", true, 0_i64), ("non-final", false, 70_i64)] {
        let r = f_guard.round(&plain).await;
        f_guard.authorized(&r, label).await;
        assert_eq!(f_guard.dispatch(&r).await, [f_guard.routed()]);
        f_guard
            .owner
            .execute(
                "ALTER TABLE openmettle.gateway_usage_reports
                 DISABLE TRIGGER gateway_usage_reports_bound_cost_guard",
            )
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens,cost,unit)
             VALUES ($1::uuid,$2::uuid,gen_random_uuid(),1,$3,20,10,99,'usd_micros')",
        )
        .bind(&r.request)
        .bind(INSTALL)
        .bind(is_final)
        .execute(&mut f_guard.owner)
        .await
        .unwrap();
        f_guard
            .owner
            .execute(
                "ALTER TABLE openmettle.gateway_usage_reports
                 ENABLE TRIGGER gateway_usage_reports_bound_cost_guard",
            )
            .await
            .unwrap();
        assert_eq!(
            sqlstate(
                sqlx::query(
                    "INSERT INTO openmettle.gateway_settlements
                         (request_id,revision,final,measured,outstanding)
                     VALUES ($1::uuid,1,$2,30,$3)",
                )
                .bind(&r.request)
                .bind(is_final)
                .bind(outstanding)
                .execute(&mut gw_guard)
                .await
            ),
            "42501"
        );
        let mut tx = owner_guard.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_settlements
                 (request_id,revision,final,measured,outstanding)
             VALUES ($1::uuid,1,$2,30,$3)",
        )
        .bind(&r.request)
        .bind(is_final)
        .bind(outstanding)
        .execute(&mut *tx)
        .await
        .unwrap();
        assert_eq!(
            sqlstate(tx.commit().await),
            "23514",
            "unbound {label} settlement accepting cost/unit raw row must be refused at commit"
        );
    }
}

/// Review #1 P2 #4: a dispatched schema-33 cost-held request swept as `unreported` at rev 0
/// passes migration 34 preflight; on schema 34 a late rev-1 complete token report must be refused
/// (`Error::Refused`) before backfill without advancing `accepted_source_revision`, then after
/// `openmettle.gateway_backfill_legacy_request_cost_bound` (with zero drift at rev 0) re-ingesting
/// rev 1 must apply `final_correction` charging `tokens * rate + fixed` with zero drift.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn review_1_p2_4_late_rev1_after_schema_33_unreported_sweep_refuses_until_backfill() {
    use openmettle_core::authz::gateway::{self, TurnRound};
    use sqlx::Connection;

    let mut f = Rounds::at(33).await;
    enable_cost_metering_defaults(&mut f.owner, 1_000_000).await;
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(WORKER));
    let gw_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(pg::GATEWAY));
    let (run_id, claim) = admit_and_claim_priced(
        &mut f,
        100,
        Some(openmettle_core::model_config::CostBound {
            fixed_micros: 50,
            micros_per_token: 1,
        }),
        1,
        false,
    )
    .await;
    let pending = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &run_id,
            round: 1,
            claim_token: &claim,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(150),
            cost_bound: Some(openmettle_core::model_config::CostBound {
                fixed_micros: 50,
                micros_per_token: 1,
            }),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let secret = [0xa1_u8; 32];
    let bearer = [0xa2_u8; 32];
    sqlx::query(
        "UPDATE openmettle.gateway_requests SET dispatch_hash = sha256($2) WHERE id = $1::uuid",
    )
    .bind(&pending.id)
    .bind(secret.as_slice())
    .execute(&mut f.owner)
    .await
    .unwrap();
    {
        let mut w = connect(&f.db.0, WORKER).await;
        let mut tx = w.begin().await.unwrap();
        sqlx::query("SELECT openmettle.quota_lock_turn_handoff_prefix($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid)")
            .bind(&pending.id).bind(secret.as_slice()).bind(&f.scope).bind(&run_id).bind(&claim)
            .execute(&mut *tx).await.unwrap();
        let ok: bool = sqlx::query_scalar(HANDOFF)
            .bind(&pending.id)
            .bind(secret.as_slice())
            .bind(&claim)
            .bind(bearer.as_slice())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert!(ok);
        sqlx::query("SELECT openmettle.quota_commit_turn_handoff($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid,false,NULL,false)")
            .bind(&pending.id).bind(secret.as_slice()).bind(&f.scope).bind(&run_id).bind(&claim)
            .execute(&mut *tx).await.unwrap();
        sqlx::query(CONFIRM)
            .bind(&pending.id)
            .bind(secret.as_slice())
            .bind(&claim)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    let mut gw = connect(&f.db.0, pg::GATEWAY).await;
    sqlx::query("SELECT FROM openmettle.gateway_dispatch($1::uuid, sha256($2))")
        .bind(&pending.id)
        .bind(bearer.as_slice())
        .execute(&mut gw)
        .await
        .unwrap();
    f.owner_exec(
        "UPDATE openmettle.runs
            SET claimed_at = clock_timestamp() - interval '30 minutes',
                lease_expires_at = clock_timestamp() - interval '25 minutes',
                execution_expires_at = clock_timestamp() - interval '20 minutes'
          WHERE id = $1::uuid",
        &run_id,
    )
    .await;
    let mut worker_c = connect(&f.db.0, WORKER).await;
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(SWEEP_CLOSE)
            .bind(&pending.id)
            .fetch_one(&mut worker_c)
            .await
            .unwrap()
            .as_deref(),
        Some("unreported")
    );

    // Also seed a second schema-33 `unreported`-swept cost hold to verify a late rev-1 incomplete
    // report (`upstream_status`) on an unpriced legacy cost hold still settles at 0 without backfill.
    let (run_inc, claim_inc) = admit_and_claim_priced(
        &mut f,
        100,
        Some(openmettle_core::model_config::CostBound {
            fixed_micros: 50,
            micros_per_token: 1,
        }),
        1,
        false,
    )
    .await;
    let pending_inc = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &run_inc,
            round: 1,
            claim_token: &claim_inc,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(150),
            cost_bound: Some(openmettle_core::model_config::CostBound {
                fixed_micros: 50,
                micros_per_token: 1,
            }),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let secret_inc = [0xa3_u8; 32];
    let bearer_inc = [0xa4_u8; 32];
    sqlx::query(
        "UPDATE openmettle.gateway_requests SET dispatch_hash = sha256($2) WHERE id = $1::uuid",
    )
    .bind(&pending_inc.id)
    .bind(secret_inc.as_slice())
    .execute(&mut f.owner)
    .await
    .unwrap();
    {
        let mut w = connect(&f.db.0, WORKER).await;
        let mut tx = w.begin().await.unwrap();
        sqlx::query("SELECT openmettle.quota_lock_turn_handoff_prefix($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid)")
            .bind(&pending_inc.id).bind(secret_inc.as_slice()).bind(&f.scope).bind(&run_inc).bind(&claim_inc)
            .execute(&mut *tx).await.unwrap();
        let ok: bool = sqlx::query_scalar(HANDOFF)
            .bind(&pending_inc.id)
            .bind(secret_inc.as_slice())
            .bind(&claim_inc)
            .bind(bearer_inc.as_slice())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert!(ok);
        sqlx::query("SELECT openmettle.quota_commit_turn_handoff($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid,false,NULL,false)")
            .bind(&pending_inc.id).bind(secret_inc.as_slice()).bind(&f.scope).bind(&run_inc).bind(&claim_inc)
            .execute(&mut *tx).await.unwrap();
        sqlx::query(CONFIRM)
            .bind(&pending_inc.id)
            .bind(secret_inc.as_slice())
            .bind(&claim_inc)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    sqlx::query("SELECT FROM openmettle.gateway_dispatch($1::uuid, sha256($2))")
        .bind(&pending_inc.id)
        .bind(bearer_inc.as_slice())
        .execute(&mut gw)
        .await
        .unwrap();
    f.owner_exec(
        "UPDATE openmettle.runs
            SET claimed_at = clock_timestamp() - interval '30 minutes',
                lease_expires_at = clock_timestamp() - interval '25 minutes',
                execution_expires_at = clock_timestamp() - interval '20 minutes'
          WHERE id = $1::uuid",
        &run_inc,
    )
    .await;
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(SWEEP_CLOSE)
            .bind(&pending_inc.id)
            .fetch_one(&mut worker_c)
            .await
            .unwrap()
            .as_deref(),
        Some("unreported")
    );

    let settings = f.db.settings(Duration::from_secs(10));
    migrate::apply(&settings, MIGRATIONS).await.unwrap();

    // Late rev-1 incomplete report (`upstream_status`) still settles at 0 without backfill.
    assert_eq!(
        settlement::ingest_incomplete(
            &gw_pool,
            &UsageReport {
                request: pending_inc.id.clone(),
                installation: INSTALL.into(),
                principal: f.actor.user.clone(),
                scope: f.scope.clone(),
                source: INSTALL.into(),
                report_id: pending_inc.id.clone(),
                revision: 1,
                r#final: true,
                prompt_tokens: None,
                completion_tokens: None,
                reasoning_tokens: None,
                reasoning_included: None,
                cost: None,
                unit: None,
            },
            "upstream_status",
        )
        .await,
        Ok(Outcome::Applied)
    );
    let inc_cost: (String, i64, String, Option<i64>) = sqlx::query_as(
        "SELECT state, held_units, settled_units::text, accepted_source_revision
           FROM openmettle.quota_reservations
          WHERE gateway_request_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&pending_inc.id)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(inc_cost, ("settled".into(), 0, "0".into(), Some(1)));

    let late_report = UsageReport {
        request: pending.id.clone(),
        installation: INSTALL.into(),
        principal: f.actor.user.clone(),
        scope: f.scope.clone(),
        source: INSTALL.into(),
        report_id: pending.id.clone(),
        revision: 1,
        r#final: true,
        prompt_tokens: Some(20),
        completion_tokens: Some(10),
        reasoning_tokens: None,
        reasoning_included: None,
        cost: None,
        unit: None,
    };
    // (a) Before backfill: late rev-1 complete token report MUST be refused!
    assert_eq!(
        settlement::ingest(&gw_pool, &late_report).await,
        Err(StoreError::Refused),
        "late rev-1 complete token report on unpriced schema-33 unreported cost hold must be refused before backfill"
    );
    let rev_before: Option<i64> = sqlx::query_scalar(
        "SELECT accepted_source_revision FROM openmettle.quota_reservations
          WHERE gateway_request_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&pending.id)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(rev_before, Some(0));

    // (b) Non-owner roles and mismatched/invalid pricing are refused; owner backfill succeeds
    // and keeps drift zero at rev 0.
    for role in [WORKER, pg::GATEWAY, API] {
        let mut c = connect(&f.db.0, role).await;
        assert_eq!(
            sqlstate(
                sqlx::query(
                    "SELECT openmettle.gateway_backfill_legacy_request_cost_bound($1::uuid, 50, 1)"
                )
                .bind(&pending.id)
                .execute(&mut c)
                .await
            ),
            "42501",
            "{role} must not call gateway_backfill_legacy_request_cost_bound"
        );
    }
    for (fixed, rate) in [(0_i64, 0_i64), (40, 1)] {
        assert_eq!(
            sqlstate(
                sqlx::query(
                    "SELECT openmettle.gateway_backfill_legacy_request_cost_bound($1::uuid, $2, $3)"
                )
                .bind(&pending.id)
                .bind(fixed)
                .bind(rate)
                .execute(&mut f.owner)
                .await
            ),
            "23514",
            "invalid/mismatched backfill ({fixed}, {rate}) must be refused"
        );
    }
    sqlx::query("SELECT openmettle.gateway_backfill_legacy_request_cost_bound($1::uuid, 50, 1)")
        .bind(&pending.id)
        .execute(&mut f.owner)
        .await
        .unwrap();
    let drift_at_0: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches,
                pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker_c)
    .await
    .unwrap();
    assert_eq!(drift_at_0, (0, 0, 0, 0));

    // (c) Re-ingesting rev 1 applies final_correction charging 30 * 1 + 50 = 80 micros with zero drift.
    assert_eq!(
        settlement::ingest(&gw_pool, &late_report).await,
        Ok(Outcome::Applied)
    );
    let cost_settled: (String, i64, String, Option<i64>) = sqlx::query_as(
        "SELECT state, held_units, settled_units::text, accepted_source_revision
           FROM openmettle.quota_reservations
          WHERE gateway_request_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&pending.id)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(cost_settled, ("settled".into(), 0, "80".into(), Some(1)));
    let drift_at_1: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches,
                pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker_c)
    .await
    .unwrap();
    assert_eq!(drift_at_1, (0, 0, 0, 0));
}

/// Review #1 P2 #5: holding an uncommitted `INSERT INTO openmettle.gateway_usage_reports` on
/// schema 33 while `migrate::apply` to 34 runs concurrently must not deadlock when the report
/// writer finishes its settlement and commits shortly afterward.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn review_1_p2_5_migration_34_lock_retry_avoids_deadlock_with_concurrent_report_writer() {
    use sqlx::Connection;

    let mut f = Rounds::at(33).await;
    let plain = quotas::snapshot(100);
    let round = f.round(&plain).await;
    f.authorized(&round, "token-only schema 33 round").await;
    assert_eq!(f.dispatch(&round).await, [f.routed()]);

    let mut gw = connect(&f.db.0, pg::GATEWAY).await;
    let mut gw_tx = gw.begin().await.unwrap();
    // Hold ROW EXCLUSIVE on `gateway_usage_reports` alone via a 0-row INSERT as `openmettle_gateway`
    // (the exact lock state immediately after a bare `INSERT INTO gateway_usage_reports` acquires
    // its target table lock and before its FK trigger locks `gateway_requests` in ROW SHARE).
    sqlx::query(
        "INSERT INTO openmettle.gateway_usage_reports
             (request_id,source,report_id,revision,final)
         SELECT $1::uuid,$2::uuid,$1::uuid,1,true WHERE false",
    )
    .bind(&round.request)
    .bind(INSTALL)
    .execute(&mut *gw_tx)
    .await
    .unwrap();

    let settings = f.db.settings(Duration::from_secs(10));
    let db_name = f.db.0.clone();
    let writer = async {
        // Wait deterministically until `openmettle-migrate` has entered migration 34's `DO` block.
        let mut observer = connect(&db_name, OWNER).await;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let active: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1 FROM pg_stat_activity
                      WHERE datname = $1
                        AND application_name = $2
                        AND state = 'active'
                        AND query LIKE '%enforce_gateway_report_bound_cost%'
                 )",
            )
            .bind(&db_name)
            .bind(migrate::APPLICATION_NAME)
            .fetch_one(&mut observer)
            .await
            .unwrap();
            if active {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "migrator never entered migration 34 lock acquisition"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(80)).await;

        // Now perform the report insert (which locks `gateway_requests` in ROW SHARE for the FK)
        // and settlement, then commit. Without `NOWAIT` retry, the migrator already holds
        // `ACCESS EXCLUSIVE` on `gateway_requests` while waiting on `gateway_usage_reports`,
        // deadlocking (40P01) with this insert!
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens)
             VALUES ($1::uuid,$2::uuid,$1::uuid,1,true,10,5)",
        )
        .bind(&round.request)
        .bind(INSTALL)
        .execute(&mut *gw_tx)
        .await
        .expect("concurrent gateway usage report insert must not deadlock with migration 34");
        sqlx::query(
            "INSERT INTO openmettle.gateway_settlements
                 (request_id,revision,final,measured,outstanding)
             VALUES ($1::uuid,1,true,15,0)",
        )
        .bind(&round.request)
        .execute(&mut *gw_tx)
        .await
        .expect("concurrent gateway settlement must not deadlock with migration 34");
        gw_tx
            .commit()
            .await
            .expect("concurrent gateway commit must succeed");
    };
    let ((), mig_res) = tokio::join!(writer, migrate::apply(&settings, MIGRATIONS));
    mig_res.expect("migration 34 must succeed cleanly after concurrent writer commits");
    assert_eq!(f.db.history().await, all_versions());
}

/// Review #1 P3 #6: `measured >= 1e38` must be refused (`Error::Refused`) when a
/// `usage_cost_micros` hold exists, while the same large token counts + large unused `cost_bound`
/// must succeed on a token-only request without a `usage_cost_micros` hold.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn review_1_p3_6_token_only_request_ignores_overflowing_unused_cost_bound_while_cost_hold_refuses()
 {
    use openmettle_core::{
        authz::gateway::{self, TurnRound},
        model_config::CostBound,
    };
    use sqlx::Connection;

    const HANDOFF_PRICED: &str =
        "SELECT openmettle.gateway_handoff_round($1::uuid,$2,$3::uuid,sha256($4),$5,$6)";

    // Case A: token-only request (no usage_cost_micros hold) with large unused cost_bound succeeds!
    {
        let mut f = Rounds::new().await;
        let big_cb = CostBound {
            fixed_micros: i64::MAX as u64,
            micros_per_token: i64::MAX as u64,
        };
        let snap = quotas::snapshot_priced("a", 100, Some(big_cb));
        let r = f.round(&snap).await;
        let mut worker = connect(&f.db.0, WORKER).await;
        let mut tx = worker.begin().await.unwrap();
        let ok: bool = sqlx::query_scalar(HANDOFF_PRICED)
            .bind(&r.request)
            .bind(r.secret.as_slice())
            .bind(&r.lease)
            .bind(r.bearer.as_slice())
            .bind(Some(i64::MAX))
            .bind(Some(i64::MAX))
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert!(ok);
        sqlx::query(CONFIRM)
            .bind(&r.request)
            .bind(r.secret.as_slice())
            .bind(&r.lease)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(f.dispatch(&r).await, [f.routed()]);
        let gw_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with(f.db.1.options(pg::GATEWAY));
        assert_eq!(
            settlement::ingest(
                &gw_pool,
                &UsageReport {
                    prompt_tokens: Some(i64::MAX),
                    completion_tokens: Some(i64::MAX),
                    ..report_of(&f, &r, None)
                },
            )
            .await,
            Ok(Outcome::Applied),
            "token-only request without a usage_cost_micros hold must ignore unused cost_bound overflow"
        );
    }

    // Case B: cost-held request (`usage_cost_micros` hold present) with measured >= 1e38 refuses!
    {
        let mut f = Rounds::new().await;
        enable_cost_metering_defaults(&mut f.owner, i64::MAX).await;
        let worker_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with(f.db.1.options(WORKER));
        let gw_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_lazy_with(f.db.1.options(pg::GATEWAY));
        let huge_rate = CostBound {
            fixed_micros: 0,
            micros_per_token: i64::MAX as u64,
        };
        let (run_id, claim) = admit_and_claim_priced(&mut f, 1, Some(huge_rate), 1, true).await;
        let pending = gateway::reserve_turn_round(
            &worker_pool,
            TurnRound {
                scope_id: &f.scope,
                actor: &f.actor.user,
                approval: &f.actor.approval,
                run_id: &run_id,
                round: 1,
                claim_token: &claim,
                installation: INSTALL,
                model: "a",
                round_tokens: 1,
                round_cost: Some(i64::MAX as u128),
                cost_bound: Some(huge_rate),
                requires_device_slot: false,
            },
        )
        .await
        .unwrap();
        let fx = quotas::TurnHandoffFixture::chat_priced(INSTALL, "a", 1, huge_rate, false);
        let _disp = pending
            .handoff(&worker_pool, None, &fx.billable(), fx.prepare_mode(true))
            .await
            .unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_requests SET dispatched_at = clock_timestamp()
              WHERE id = $1::uuid AND dispatched_at IS NULL",
        )
        .bind(&pending.id)
        .execute(&mut f.owner)
        .await
        .unwrap();
        assert_eq!(
            settlement::ingest(
                &gw_pool,
                &UsageReport {
                    request: pending.id.clone(),
                    installation: INSTALL.into(),
                    principal: f.actor.user.clone(),
                    scope: f.scope.clone(),
                    source: INSTALL.into(),
                    report_id: pending.id.clone(),
                    revision: 1,
                    r#final: true,
                    prompt_tokens: Some(i64::MAX),
                    completion_tokens: Some(i64::MAX),
                    reasoning_tokens: None,
                    reasoning_included: None,
                    cost: None,
                    unit: None,
                },
            )
            .await,
            Err(StoreError::Refused),
            "cost-held request with measured >= 1e38 must fail closed with Refused"
        );
    }
}

/// Review #2 P1 (Fix #4): a schema-33 cost-held request swept as `unreported` at rev 0 AND
/// corrected by a complete token-only rev-1 report *before* migration 34 must preserve zero
/// accounting drift across the 33 -> 34 upgrade, allow exact rev-1 duplicate replay, refuse a new
/// rev-2 token correction until `gateway_backfill_legacy_request_cost_bound` runs, reconcile the
/// already-accepted rev-1 cost upon backfill with zero drift, and then accept rev 2 cleanly.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn review_2_p1_pre_upgrade_unreported_plus_rev1_preserves_zero_drift_and_backfills() {
    use openmettle_core::{
        authz::gateway::{self, TurnRound},
        model_config::CostBound,
    };
    use sqlx::Connection;

    let mut f = Rounds::at(33).await;
    enable_cost_metering_defaults(&mut f.owner, 1_000_000).await;
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(WORKER));
    let gw_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(pg::GATEWAY));
    let cb = CostBound {
        fixed_micros: 50,
        micros_per_token: 1,
    };
    let (run_id, claim) = admit_and_claim_priced(&mut f, 100, Some(cb), 1, false).await;
    let pending = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &run_id,
            round: 1,
            claim_token: &claim,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(150),
            cost_bound: Some(cb),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let secret = [0xb1_u8; 32];
    let bearer = [0xb2_u8; 32];
    sqlx::query(
        "UPDATE openmettle.gateway_requests SET dispatch_hash = sha256($2) WHERE id = $1::uuid",
    )
    .bind(&pending.id)
    .bind(secret.as_slice())
    .execute(&mut f.owner)
    .await
    .unwrap();
    {
        let mut w = connect(&f.db.0, WORKER).await;
        let mut tx = w.begin().await.unwrap();
        sqlx::query(
            "SELECT openmettle.quota_lock_turn_handoff_prefix($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid)",
        )
        .bind(&pending.id)
        .bind(secret.as_slice())
        .bind(&f.scope)
        .bind(&run_id)
        .bind(&claim)
        .execute(&mut *tx)
        .await
        .unwrap();
        let ok: bool = sqlx::query_scalar(HANDOFF)
            .bind(&pending.id)
            .bind(secret.as_slice())
            .bind(&claim)
            .bind(bearer.as_slice())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert!(ok);
        sqlx::query(
            "SELECT openmettle.quota_commit_turn_handoff($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid,false,NULL,false)",
        )
        .bind(&pending.id)
        .bind(secret.as_slice())
        .bind(&f.scope)
        .bind(&run_id)
        .bind(&claim)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(CONFIRM)
            .bind(&pending.id)
            .bind(secret.as_slice())
            .bind(&claim)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    let mut gw = connect(&f.db.0, pg::GATEWAY).await;
    sqlx::query("SELECT FROM openmettle.gateway_dispatch($1::uuid, sha256($2))")
        .bind(&pending.id)
        .bind(bearer.as_slice())
        .execute(&mut gw)
        .await
        .unwrap();
    f.owner_exec(
        "UPDATE openmettle.runs
            SET claimed_at = clock_timestamp() - interval '30 minutes',
                lease_expires_at = clock_timestamp() - interval '25 minutes',
                execution_expires_at = clock_timestamp() - interval '20 minutes'
          WHERE id = $1::uuid",
        &run_id,
    )
    .await;
    let mut worker_c = connect(&f.db.0, WORKER).await;
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(SWEEP_CLOSE)
            .bind(&pending.id)
            .fetch_one(&mut worker_c)
            .await
            .unwrap()
            .as_deref(),
        Some("unreported")
    );

    // Accept rev 1 (20 + 10 = 30 tokens, cost = None) STILL ON SCHEMA 33 before upgrading.
    let rev1 = UsageReport {
        request: pending.id.clone(),
        installation: INSTALL.into(),
        principal: f.actor.user.clone(),
        scope: f.scope.clone(),
        source: INSTALL.into(),
        report_id: pending.id.clone(),
        revision: 1,
        r#final: true,
        prompt_tokens: Some(20),
        completion_tokens: Some(10),
        reasoning_tokens: None,
        reasoning_included: None,
        cost: None,
        unit: None,
    };
    assert_eq!(
        settlement::ingest(&gw_pool, &rev1).await,
        Ok(Outcome::Applied)
    );

    // Also seed a schema-33 caller-priced cost=0 row so we verify backfill still refuses
    // caller-priced histories (`cost IS NOT NULL`).
    let (run_cp, claim_cp) = admit_and_claim_priced(&mut f, 100, Some(cb), 1, false).await;
    let pending_cp = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &run_cp,
            round: 1,
            claim_token: &claim_cp,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(150),
            cost_bound: Some(cb),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let secret_cp = [0xb3_u8; 32];
    let bearer_cp = [0xb4_u8; 32];
    sqlx::query(
        "UPDATE openmettle.gateway_requests SET dispatch_hash = sha256($2) WHERE id = $1::uuid",
    )
    .bind(&pending_cp.id)
    .bind(secret_cp.as_slice())
    .execute(&mut f.owner)
    .await
    .unwrap();
    {
        let mut w = connect(&f.db.0, WORKER).await;
        let mut tx = w.begin().await.unwrap();
        sqlx::query(
            "SELECT openmettle.quota_lock_turn_handoff_prefix($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid)",
        )
        .bind(&pending_cp.id)
        .bind(secret_cp.as_slice())
        .bind(&f.scope)
        .bind(&run_cp)
        .bind(&claim_cp)
        .execute(&mut *tx)
        .await
        .unwrap();
        assert!(
            sqlx::query_scalar::<_, bool>(HANDOFF)
                .bind(&pending_cp.id)
                .bind(secret_cp.as_slice())
                .bind(&claim_cp)
                .bind(bearer_cp.as_slice())
                .fetch_one(&mut *tx)
                .await
                .unwrap()
        );
        sqlx::query(
            "SELECT openmettle.quota_commit_turn_handoff($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid,false,NULL,false)",
        )
        .bind(&pending_cp.id)
        .bind(secret_cp.as_slice())
        .bind(&f.scope)
        .bind(&run_cp)
        .bind(&claim_cp)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(CONFIRM)
            .bind(&pending_cp.id)
            .bind(secret_cp.as_slice())
            .bind(&claim_cp)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    sqlx::query("SELECT FROM openmettle.gateway_dispatch($1::uuid, sha256($2))")
        .bind(&pending_cp.id)
        .bind(bearer_cp.as_slice())
        .execute(&mut gw)
        .await
        .unwrap();
    {
        let mut tx = gw.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens,cost,unit)
             VALUES ($1::uuid,$2::uuid,$1::uuid,1,true,10,5,0,'usd_micros')",
        )
        .bind(&pending_cp.id)
        .bind(INSTALL)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_settlements
                 (request_id,revision,final,measured,outstanding)
             VALUES ($1::uuid,1,true,15,0)",
        )
        .bind(&pending_cp.id)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("SELECT openmettle.quota_settle_gateway_usage($1::uuid,$2::uuid,$1::uuid,1)")
            .bind(&pending_cp.id)
            .bind(INSTALL)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    let pre_drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches,
                pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker_c)
    .await
    .unwrap();
    assert_eq!(pre_drift, (0, 0, 0, 0));

    // Upgrade 33 -> 34 must preserve zero accounting drift immediately!
    let settings = f.db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..34]).await.unwrap();
    let post_drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches,
                pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker_c)
    .await
    .unwrap();
    assert_eq!(
        post_drift,
        (0, 0, 0, 0),
        "33 -> 34 upgrade must preserve 0 accounting drift on pre-accepted unreported + rev-1 history"
    );

    // Exact replay of rev 1 returns Duplicate, while a new rev-2 token correction before backfill
    // fails closed (`Error::Refused`) without advancing `accepted_source_revision`.
    assert_eq!(
        settlement::ingest(&gw_pool, &rev1).await,
        Ok(Outcome::Duplicate)
    );
    let rev2 = UsageReport {
        revision: 2,
        prompt_tokens: Some(25),
        completion_tokens: Some(15),
        ..rev1.clone()
    };
    assert_eq!(
        settlement::ingest(&gw_pool, &rev2).await,
        Err(StoreError::Refused),
        "new rev-2 token correction on unpriced legacy cost hold must be refused before backfill"
    );

    // Caller-priced cost=0 history is still refused by backfill (`23514`), whereas the unpriced
    // swept + rev-1 history backfills cleanly, charging 30 * 1 + 50 = 80 micros with 0 drift!
    assert_eq!(
        sqlstate(
            sqlx::query(
                "SELECT openmettle.gateway_backfill_legacy_request_cost_bound($1::uuid, 50, 1)"
            )
            .bind(&pending_cp.id)
            .execute(&mut f.owner)
            .await
        ),
        "23514"
    );
    sqlx::query("SELECT openmettle.gateway_backfill_legacy_request_cost_bound($1::uuid, 50, 1)")
        .bind(&pending.id)
        .execute(&mut f.owner)
        .await
        .expect("owner backfill must reconcile pre-accepted rev-1 token report");
    let after_backfill: (String, i64, String, Option<i64>) = sqlx::query_as(
        "SELECT state, held_units, settled_units::text, accepted_source_revision
           FROM openmettle.quota_reservations
          WHERE gateway_request_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&pending.id)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(after_backfill, ("settled".into(), 0, "80".into(), Some(1)));
    let drift_backfilled: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches,
                pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker_c)
    .await
    .unwrap();
    assert_eq!(drift_backfilled, (0, 0, 0, 0));

    // And rev 2 (25 + 15 = 40 tokens -> 90 micros) now applies cleanly with 0 drift!
    assert_eq!(
        settlement::ingest(&gw_pool, &rev2).await,
        Ok(Outcome::Applied)
    );
    let after_rev2: (String, i64, String, Option<i64>) = sqlx::query_as(
        "SELECT state, held_units, settled_units::text, accepted_source_revision
           FROM openmettle.quota_reservations
          WHERE gateway_request_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&pending.id)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(after_rev2, ("settled".into(), 0, "90".into(), Some(2)));
    let drift_rev2: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches,
                pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker_c)
    .await
    .unwrap();
    assert_eq!(drift_rev2, (0, 0, 0, 0));
}

/// Review #2 P2 (Fix #1): raw JSON `cost_bound` number spellings rejected by Rust (`1e2`, `1E2`,
/// `-0`) must also be rejected by PostgreSQL handoff checks (`gateway_round_authority`,
/// `gateway_handoff_round`, and `enforce_gateway_handoff_holds`) before `jsonb` normalization.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn review_2_p2_snapshot_cost_bound_rejects_exponent_and_negative_zero_tokens() {
    use sqlx::Connection;

    const HANDOFF_PRICED: &str =
        "SELECT openmettle.gateway_handoff_round($1::uuid,$2,$3::uuid,sha256($4),$5,$6)";

    assert!(
        serde_json::from_str::<openmettle_core::model_config::CostBound>(
            r#"{"fixed_micros":1,"micros_per_token":100}"#
        )
        .is_ok()
    );
    let mut f = Rounds::new().await;
    for (label, raw_cb, norm_fixed, norm_rate) in [
        (
            "rate 1e2",
            r#"{"fixed_micros":1,"micros_per_token":1e2}"#,
            1_i64,
            100_i64,
        ),
        (
            "rate 1E2",
            r#"{"fixed_micros":1,"micros_per_token":1E2}"#,
            1_i64,
            100_i64,
        ),
        (
            "rate -0",
            r#"{"fixed_micros":1,"micros_per_token":-0}"#,
            1_i64,
            0_i64,
        ),
        (
            "fixed 1e2",
            r#"{"fixed_micros":1e2,"micros_per_token":1}"#,
            100_i64,
            1_i64,
        ),
        (
            "fixed -0",
            r#"{"fixed_micros":-0,"micros_per_token":1}"#,
            0_i64,
            1_i64,
        ),
    ] {
        assert!(
            serde_json::from_str::<openmettle_core::model_config::CostBound>(raw_cb).is_err(),
            "Rust CostBound must reject {label}"
        );
        let raw_snap = format!(
            r#"{{"effective":{{"model":"a","ceiling":{{"value":100}}}},"required_capabilities":{{}},"cost_bound":{raw_cb}}}"#
        );
        let r = f.round(raw_snap.as_bytes()).await;

        // 1. Worker SQL `gateway_handoff_round` must return false.
        let mut worker = connect(&f.db.0, WORKER).await;
        let mut tx = worker.begin().await.unwrap();
        let ok: bool = sqlx::query_scalar(HANDOFF_PRICED)
            .bind(&r.request)
            .bind(r.secret.as_slice())
            .bind(&r.lease)
            .bind(r.bearer.as_slice())
            .bind(Some(norm_fixed))
            .bind(Some(norm_rate))
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        assert!(
            !ok,
            "gateway_handoff_round must reject malformed JSON number token ({label})"
        );

        // 2. Direct owner UPDATE bypassing `gateway_handoff_round` must also fail `OMQ04` at commit
        // via `enforce_gateway_handoff_holds`.
        let mut owner_tx = f.owner.begin().await.unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_requests
                SET state = 'handed_off',
                    report_source = installation,
                    bearer_hash = sha256($2),
                    claim_hash = sha256(uuid_send($3::uuid)),
                    cost_fixed_micros = $4,
                    cost_micros_per_token = $5
              WHERE id = $1::uuid",
        )
        .bind(&r.request)
        .bind(r.bearer.as_slice())
        .bind(&r.lease)
        .bind(norm_fixed)
        .bind(norm_rate)
        .execute(&mut *owner_tx)
        .await
        .unwrap();
        assert_eq!(
            sqlstate(owner_tx.commit().await),
            "OMQ04",
            "enforce_gateway_handoff_holds must reject malformed JSON number token ({label})"
        );
    }
}

/// Review #3 P2: on schema 31 an `incomplete` report at rev 1 could close both holds (`settled` at
/// `0`, `accepted_source_revision = 1`) and a direct SQL writer could then commit rev 2 (`30`
/// tokens) into `gateway_usage_reports` + `gateway_settlements` without calling
/// `quota_settle_gateway_usage` (leaving `max(quota_accepted_gateway_reports.revision) = 2` while
/// both holds stay at `accepted_source_revision = 1`). After upgrading through 33 to 34,
/// `gateway_backfill_legacy_request_cost_bound` must reconcile through the latest accepted revision
/// (`2`) in canonical hold-before-budget lock order, charging `80` micros and `30` tokens with zero
/// pending reconciliations and zero accounting drift.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn review_3_p2_backfill_reconciles_unconsumed_schema_31_accepted_revisions() {
    use openmettle_core::{
        authz::gateway::{self, TurnRound},
        model_config::CostBound,
    };
    use sqlx::Connection;

    let mut f = Rounds::at(31).await;
    enable_cost_metering_defaults(&mut f.owner, 1_000_000).await;
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(WORKER));
    let gw_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(pg::GATEWAY));
    let cb = CostBound {
        fixed_micros: 50,
        micros_per_token: 1,
    };
    let (run_id, claim) = admit_and_claim_priced(&mut f, 100, Some(cb), 1, true).await;
    let pending = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &run_id,
            round: 1,
            claim_token: &claim,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(150),
            cost_bound: Some(cb),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let secret = [0xc1_u8; 32];
    let bearer = [0xc2_u8; 32];
    sqlx::query(
        "UPDATE openmettle.gateway_requests SET dispatch_hash = sha256($2) WHERE id = $1::uuid",
    )
    .bind(&pending.id)
    .bind(secret.as_slice())
    .execute(&mut f.owner)
    .await
    .unwrap();
    {
        let mut w = connect(&f.db.0, WORKER).await;
        let mut tx = w.begin().await.unwrap();
        sqlx::query(
            "SELECT openmettle.quota_lock_turn_handoff_prefix($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid)",
        )
        .bind(&pending.id)
        .bind(secret.as_slice())
        .bind(&f.scope)
        .bind(&run_id)
        .bind(&claim)
        .execute(&mut *tx)
        .await
        .unwrap();
        assert!(
            sqlx::query_scalar::<_, bool>(HANDOFF)
                .bind(&pending.id)
                .bind(secret.as_slice())
                .bind(&claim)
                .bind(bearer.as_slice())
                .fetch_one(&mut *tx)
                .await
                .unwrap()
        );
        sqlx::query(
            "SELECT openmettle.quota_commit_turn_handoff($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid,false,NULL,false)",
        )
        .bind(&pending.id)
        .bind(secret.as_slice())
        .bind(&f.scope)
        .bind(&run_id)
        .bind(&claim)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(CONFIRM)
            .bind(&pending.id)
            .bind(secret.as_slice())
            .bind(&claim)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    let mut gw = connect(&f.db.0, pg::GATEWAY).await;
    sqlx::query("SELECT FROM openmettle.gateway_dispatch($1::uuid, sha256($2))")
        .bind(&pending.id)
        .bind(bearer.as_slice())
        .execute(&mut gw)
        .await
        .unwrap();
    let rev1 = UsageReport {
        request: pending.id.clone(),
        installation: INSTALL.into(),
        principal: f.actor.user.clone(),
        scope: f.scope.clone(),
        source: INSTALL.into(),
        report_id: pending.id.clone(),
        revision: 1,
        r#final: true,
        prompt_tokens: None,
        completion_tokens: None,
        reasoning_tokens: None,
        reasoning_included: None,
        cost: None,
        unit: None,
    };
    assert_eq!(
        settlement::ingest_incomplete(&gw_pool, &rev1, "no_usage").await,
        Ok(Outcome::Applied)
    );

    // On schema 31, commit an accepted rev-2 token report without calling
    // `quota_settle_gateway_usage` (leaving both holds at `accepted_source_revision = 1`), and also
    // seed a second schema-31 request where rev 1 (`incomplete`) + rev 2 (`15` tokens) WERE
    // consumed (`accepted_source_revision = 2`) and rev 3 (`30` tokens) was accepted without
    // calling `quota_settle_gateway_usage` (verifying consumed + unconsumed revisions compose
    // without undercharging or double-charging).
    let (run_b, claim_b) = admit_and_claim_priced(&mut f, 100, Some(cb), 1, true).await;
    let pending_b = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &run_b,
            round: 1,
            claim_token: &claim_b,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(150),
            cost_bound: Some(cb),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let secret_b = [0xc3_u8; 32];
    let bearer_b = [0xc4_u8; 32];
    sqlx::query(
        "UPDATE openmettle.gateway_requests SET dispatch_hash = sha256($2) WHERE id = $1::uuid",
    )
    .bind(&pending_b.id)
    .bind(secret_b.as_slice())
    .execute(&mut f.owner)
    .await
    .unwrap();
    {
        let mut w = connect(&f.db.0, WORKER).await;
        let mut tx = w.begin().await.unwrap();
        sqlx::query(
            "SELECT openmettle.quota_lock_turn_handoff_prefix($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid)",
        )
        .bind(&pending_b.id)
        .bind(secret_b.as_slice())
        .bind(&f.scope)
        .bind(&run_b)
        .bind(&claim_b)
        .execute(&mut *tx)
        .await
        .unwrap();
        assert!(
            sqlx::query_scalar::<_, bool>(HANDOFF)
                .bind(&pending_b.id)
                .bind(secret_b.as_slice())
                .bind(&claim_b)
                .bind(bearer_b.as_slice())
                .fetch_one(&mut *tx)
                .await
                .unwrap()
        );
        sqlx::query(
            "SELECT openmettle.quota_commit_turn_handoff($1::uuid,$2,$3::uuid,$4::uuid,$5::uuid,false,NULL,false)",
        )
        .bind(&pending_b.id)
        .bind(secret_b.as_slice())
        .bind(&f.scope)
        .bind(&run_b)
        .bind(&claim_b)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(CONFIRM)
            .bind(&pending_b.id)
            .bind(secret_b.as_slice())
            .bind(&claim_b)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }
    sqlx::query("SELECT FROM openmettle.gateway_dispatch($1::uuid, sha256($2))")
        .bind(&pending_b.id)
        .bind(bearer_b.as_slice())
        .execute(&mut gw)
        .await
        .unwrap();
    let rev1_b = UsageReport {
        request: pending_b.id.clone(),
        report_id: pending_b.id.clone(),
        ..rev1.clone()
    };
    assert_eq!(
        settlement::ingest_incomplete(&gw_pool, &rev1_b, "no_usage").await,
        Ok(Outcome::Applied)
    );
    assert_eq!(
        settlement::ingest(
            &gw_pool,
            &UsageReport {
                revision: 2,
                prompt_tokens: Some(10),
                completion_tokens: Some(5),
                ..rev1_b.clone()
            },
        )
        .await,
        Ok(Outcome::Applied)
    );
    {
        let mut tx = gw.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens)
             VALUES ($1::uuid,$2::uuid,$1::uuid,2,true,20,10),
                    ($3::uuid,$2::uuid,$3::uuid,3,true,20,10)",
        )
        .bind(&pending.id)
        .bind(INSTALL)
        .bind(&pending_b.id)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_settlements
                SET revision = 2, final = true, measured = 30, outstanding = 0
              WHERE request_id = $1::uuid",
        )
        .bind(&pending.id)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.gateway_settlements
                SET revision = 3, final = true, measured = 30, outstanding = 0
              WHERE request_id = $1::uuid",
        )
        .bind(&pending_b.id)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    let settings = f.db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..33]).await.unwrap();
    migrate::apply(&settings, MIGRATIONS).await.unwrap();

    // Snapshot-mismatched pricing is refused because `runs.config_snapshot` pinned (50, 1).
    assert_eq!(
        sqlstate(
            sqlx::query(
                "SELECT openmettle.gateway_backfill_legacy_request_cost_bound($1::uuid, 150, 0)"
            )
            .bind(&pending.id)
            .execute(&mut f.owner)
            .await
        ),
        "23514"
    );

    // Backfill with (50, 1) must reconcile BOTH requests' holds through their latest accepted
    // revisions (rev 2 on `pending`, rev 3 on `pending_b`: 80 micros + 30 tokens each, 0 pending
    // reconciliations, 0 drift).
    for (req_id, expected_rev) in [(&pending.id, 2_i64), (&pending_b.id, 3_i64)] {
        sqlx::query(
            "SELECT openmettle.gateway_backfill_legacy_request_cost_bound($1::uuid, 50, 1)",
        )
        .bind(req_id)
        .execute(&mut f.owner)
        .await
        .unwrap();
        let cost_hold: (String, i64, String) = sqlx::query_as(
            "SELECT settled_units::text, accepted_source_revision, state
               FROM openmettle.quota_reservations
              WHERE gateway_request_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
        )
        .bind(req_id)
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
        assert_eq!(cost_hold, ("80".into(), expected_rev, "settled".into()));
        let tok_hold: (String, i64, String) = sqlx::query_as(
            "SELECT settled_units::text, accepted_source_revision, state
               FROM openmettle.quota_reservations
              WHERE gateway_request_id = $1::uuid AND resource_kind = 'usage_tokens'",
        )
        .bind(req_id)
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
        assert_eq!(tok_hold, ("30".into(), expected_rev, "settled".into()));
    }

    let mut worker_c = connect(&f.db.0, WORKER).await;
    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches,
                pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker_c)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
}

/// One row of `openmettle.gateway_dispatch_scoped`: replay flag, routing fields, and `cache_owner`.
type ScopedDispatched = (
    bool,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

const DISPATCH_SCOPED: &str =
    "SELECT replayed,installation,scope,source,principal,model,cache_owner
    FROM openmettle.gateway_dispatch_scoped($1::uuid,sha256($2))";

const SCOPED_REPLAY: ScopedDispatched = (true, None, None, None, None, None, None);

async fn dispatch_scoped_as(
    db: &TestDb,
    role: &str,
    request: &str,
    bearer: &[u8],
) -> Result<Vec<ScopedDispatched>, sqlx::Error> {
    sqlx::query_as(DISPATCH_SCOPED)
        .bind(request)
        .bind(bearer)
        .fetch_all(&mut connect(&db.0, role).await)
        .await
}

async fn dispatch_scoped(f: &Rounds, round: &Round) -> Vec<ScopedDispatched> {
    dispatch_scoped_as(&f.db, pg::GATEWAY, &round.request, &round.bearer)
        .await
        .unwrap()
}

/// Admits, claims, reserves, hands off, and returns a single-round request on `chat` for `actor`.
async fn handoff_round_on(f: &mut Rounds, actor: &Account, scope: &str, chat: &str) -> Round {
    let now_ms: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    let plain = quotas::snapshot(100);
    let run = f
        .claimed_on_at(
            actor,
            (scope, chat),
            ("openmettle.conversation", 1, &plain),
            1,
            now_ms,
        )
        .await;
    let round = f.reserve(&run, 1, "a").await;
    f.authorized(&round, "live run round on conversation").await;
    round
}

/// Enrolls `account` in a fresh `'present'` ADR 0021 `membership_observations` row for
/// `(project_id, scope_id)` using `selector_kind` (`'group'` or `'app_role'`) and `claim_value`.
#[allow(clippy::too_many_arguments)]
async fn enroll_mapped_member(
    db: &TestDb,
    account: &Account,
    project_id: &str,
    scope_id: &str,
    rule_id: &str,
    selector_kind: &str,
    claim_value: &str,
    key_tag: &str,
) {
    use openmettle_core::grants::{
        self, Assignment, ChangeInput, Decision, Grantee as GrantGrantee, MappingInput, Target,
    };
    const ISSUER: &str = "https://authz-store.example.test";
    let mut owner = connect(&db.0, OWNER).await;
    let now_ms: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut owner)
            .await
            .unwrap();
    let mut api = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    grants::record_mapping_revision(
        &mut tx,
        &MappingInput {
            rule: rule_id,
            provider: PROVIDER,
            issuer: ISSUER,
            actor: &account.user,
            key: &format!("cache-rule-{key_tag}"),
            expected_revision: 0,
            enabled: true,
            selector_kind,
            claim_name: if selector_kind == "group" {
                "groups"
            } else {
                "roles"
            },
            claim_value,
            binding_format: "openmettle.project-member",
            binding_version: 1,
            binding: project_id.as_bytes(),
        },
    )
    .await
    .unwrap();
    let receipt = grants::change_grant(
        &mut tx,
        &ChangeInput {
            assignment: Assignment {
                scope: scope_id,
                target: Target::Project(project_id),
                grantee: GrantGrantee::User(&account.user),
                format: "openmettle.project-member",
                version: 1,
                key: &account.approval,
                mapping_rule: Some(rule_id),
            },
            actor: &account.user,
            key: &format!("cache-grant-{key_tag}"),
            expected_revision: 0,
            mapping_revision: Some(1),
            decision: Decision::Grant,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    sqlx::query(
        "WITH c AS (
           INSERT INTO openmettle.membership_configuration_changes
               (request_id, approval_id, previous_revision, rule_id, rule_revision, project_id,
                scope_id, max_age_seconds, enabled, baseline_change, floor_ms, actor, reason)
           VALUES (gen_random_uuid(), $1::uuid, 0, $2::uuid, 1, $3::uuid, $4::uuid, 3600, true,
                   NULL, NULL, gen_random_uuid(), 'synthetic cache-owner mapped enrollment')
           RETURNING revision)
         INSERT INTO openmettle.membership_observations
             (approval_id, config_revision, enabled, floor_ms, rule_id, rule_revision, project_id,
              scope_id, max_age_seconds, issued_ms, expires_ms, observation, epoch,
              approval_generation, user_generation)
         SELECT $1::uuid, c.revision, true, NULL, $2::uuid, 1, $3::uuid, $4::uuid, 3600,
                $6 - 60000, $6 + 600000, ROW('present', $5::uuid)::openmettle.membership_evidence,
                (SELECT max(epoch) FROM openmettle.login_provider_revisions
                  WHERE provider_id = $7::uuid), 0, 0
           FROM c",
    )
    .bind(&account.approval)
    .bind(rule_id)
    .bind(project_id)
    .bind(scope_id)
    .bind(&receipt.change)
    .bind(now_ms)
    .bind(PROVIDER)
    .execute(&mut owner)
    .await
    .unwrap();
}

/// ADR 0044 increment 5 (migration 36): `openmettle.gateway_dispatch_scoped` enforces role,
/// isolation, replay, archived/deleted project defense-in-depth, and ADR 0027 `cache_owner`
/// separation across personal scopes, private project conversations, all effective share forms
/// (project, user direct/local-group/mapped app_role/mapped group/OIDC group, local_group,
/// oidc_group), and all Gate 2b stale/ineffective share fail-closed cases.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn gateway_dispatch_scoped_computes_cache_owner_under_adr_0027() {
    use openmettle_core::authz::store;

    let mut f = Rounds::new().await;
    let alice = f.actor.clone();
    let bob = account(&mut f.owner, PROVIDER, true, FUTURE).await;
    let carol = account(&mut f.owner, PROVIDER, true, FUTURE).await;
    let dave = account(&mut f.owner, PROVIDER, true, FUTURE).await;
    let erin = account(&mut f.owner, PROVIDER, true, FUTURE).await;
    let frank = account(&mut f.owner, PROVIDER, true, FUTURE).await;
    authz_store::make_admin(&mut f.owner, &alice).await;

    // 1. Personal scope: `cache_owner` is NULL, role/isolation/replay/wrong-bearer checks hold,
    //    and 6-column `gateway_dispatch` delegates cleanly.
    let personal_round = f.round(&quotas::snapshot(100)).await;
    f.authorized(&personal_round, "personal scope round").await;
    for role in [API, WORKER, ISSUANCE] {
        let denied =
            dispatch_scoped_as(&f.db, role, &personal_round.request, &personal_round.bearer).await;
        assert_eq!(sqlstate(denied), "42501", "{role}");
    }
    {
        let mut gw = connect(&f.db.0, pg::GATEWAY).await;
        gw.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
            .await
            .unwrap();
        let err = sqlx::query_as::<_, ScopedDispatched>(DISPATCH_SCOPED)
            .bind(&personal_round.request)
            .bind(personal_round.bearer.as_slice())
            .fetch_all(&mut gw)
            .await;
        assert_eq!(sqlstate(err), "25000");
        gw.execute("ROLLBACK").await.unwrap();
    }
    assert_eq!(
        dispatch_scoped_as(&f.db, pg::GATEWAY, &personal_round.request, &[0xee; 32])
            .await
            .unwrap(),
        []
    );
    assert_eq!(
        dispatch_scoped(&f, &personal_round).await,
        [(
            false,
            Some(INSTALL.to_owned()),
            Some(f.scope.clone()),
            Some(INSTALL.to_owned()),
            Some(alice.user.clone()),
            Some("a".to_owned()),
            None,
        )]
    );
    assert_eq!(dispatch_scoped(&f, &personal_round).await, [SCOPED_REPLAY]);
    assert_eq!(f.dispatch(&personal_round).await, [REPLAY]);

    let personal_legacy = f.round(&quotas::snapshot(100)).await;
    f.authorized(&personal_legacy, "6-col wrapper").await;
    assert_eq!(f.dispatch(&personal_legacy).await, [f.routed()]);
    assert_eq!(dispatch_scoped(&f, &personal_legacy).await, [SCOPED_REPLAY]);

    // 2. Project scope setup.
    let (project_id, project_scope) =
        run_admission::new_project(&f.db, &alice, "cache-owner-project").await;
    let chat = authz_runs::chat(&f.db, &project_scope, "project", &alice).await;
    let expected_owner = |actor: &Account, cache_owner: Option<&str>| {
        vec![(
            false,
            Some(INSTALL.to_owned()),
            Some(project_scope.clone()),
            Some(INSTALL.to_owned()),
            Some(actor.user.clone()),
            Some("a".to_owned()),
            cache_owner.map(str::to_owned),
        )]
    };

    // Unshared project conversation -> `cache_owner = c.owner_user_id` (Alice).
    let r_priv = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_priv).await,
        expected_owner(&alice, Some(&alice.user))
    );

    // Self-share inserted directly in SQL must NOT switch to shared (`grantee_user_id <> owner`).
    sqlx::query(
        "WITH a AS (
           INSERT INTO openmettle.grant_assignments
               (scope_id, target_kind, conversation_id, grantee_kind, grantee_user_id,
                assignment_format, assignment_version, assignment_key, source_kind,
                created_by_user_id, last_revision)
           VALUES ($1::uuid, 'conversation', $2::uuid, 'user', $3::uuid,
                   'openmettle.resource-grant', 1, 'read', 'direct', $3::uuid, 1)
           RETURNING id),
         cid AS (SELECT gen_random_uuid() AS id)
         INSERT INTO openmettle.grant_changes
             (id, scope_id, assignment_id, revision, source_kind, actor_user_id, request_key,
              decision, cycle_id, request_identity, request_digest)
         SELECT cid.id, $1::uuid, a.id, 1, 'direct', $3::uuid, 'self-share-test',
                'grant', cid.id, '\\x01'::bytea, sha256('self-share-test')
           FROM a, cid",
    )
    .bind(&project_scope)
    .bind(&chat)
    .bind(&alice.user)
    .execute(&mut f.owner)
    .await
    .unwrap();
    let r_self = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_self).await,
        expected_owner(&alice, Some(&alice.user))
    );

    // 3. `Grantee::Project` share -> `cache_owner = NULL` for both Alice (owner) and Bob (editor).
    applied(
        projects::set_project_member_role(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-bob-editor"),
            &project_id,
            &Grantee::User(bob.user.clone()),
            ProjectRole::Editor,
        )
        .await,
    );
    applied(
        projects::share_resource(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-share-proj"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::Project,
            ResourceAccess::Write,
        )
        .await,
    );
    let r_proj_alice = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    let r_proj_bob = handoff_round_on(&mut f, &bob, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_proj_alice).await,
        expected_owner(&alice, None)
    );
    assert_eq!(
        dispatch_scoped(&f, &r_proj_bob).await,
        expected_owner(&bob, None)
    );
    // Unshare `Grantee::Project` -> immediately back to `cache_owner = Alice`.
    applied(
        projects::unshare_resource(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-unshare-proj"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::Project,
        )
        .await,
    );
    let r_unshared = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_unshared).await,
        expected_owner(&alice, Some(&alice.user))
    );

    // 4. `Grantee::User(bob)` direct project role -> `cache_owner = NULL`; then test stale Gate 2b
    //    conditions on `bob`: disabled user, expired approval, inactive approval, retired provider,
    //    revoked project role, and collaborator refusal when unshared between handoff & dispatch.
    applied(
        projects::share_resource(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-share-bob"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::User(bob.user.clone()),
            ResourceAccess::Write,
        )
        .await,
    );
    let r_bob_alice = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    let r_bob_collab = handoff_round_on(&mut f, &bob, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_bob_alice).await,
        expected_owner(&alice, None)
    );
    assert_eq!(
        dispatch_scoped(&f, &r_bob_collab).await,
        expected_owner(&bob, None)
    );

    // Disabled grantee user -> fail-closed to owner isolation.
    applied(
        store::disable_user(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-disable-bob"),
            &bob.user,
        )
        .await,
    );
    let r_bob_disabled = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_bob_disabled).await,
        expected_owner(&alice, Some(&alice.user))
    );
    f.owner_exec(
        "UPDATE openmettle.users SET disabled_at = NULL WHERE id = $1::uuid",
        &bob.user,
    )
    .await;

    // Inactive grantee approval -> fail-closed to owner isolation.
    f.owner_exec(
        "UPDATE openmettle.local_identity_approvals SET active = false WHERE id = $1::uuid",
        &bob.approval,
    )
    .await;
    let r_bob_inact = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_bob_inact).await,
        expected_owner(&alice, Some(&alice.user))
    );
    f.owner_exec(
        "UPDATE openmettle.local_identity_approvals SET active = true WHERE id = $1::uuid",
        &bob.approval,
    )
    .await;

    // Expired grantee approval -> fail-closed to owner isolation.
    f.owner_exec(
        "UPDATE openmettle.local_identity_approvals SET expires_ms = 1 WHERE id = $1::uuid",
        &bob.approval,
    )
    .await;
    let r_bob_exp = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_bob_exp).await,
        expected_owner(&alice, Some(&alice.user))
    );
    f.owner_exec(
        "UPDATE openmettle.local_identity_approvals SET expires_ms = 4102444800000 WHERE id = $1::uuid",
        &bob.approval,
    )
    .await;

    // Retired grantee provider -> fail-closed to owner isolation without affecting Alice.
    {
        const RETIRABLE_PROVIDER: &str = "00000000-0000-4000-8000-00000000c201";
        sqlx::query(
            "INSERT INTO openmettle.login_providers
                 (id, issuer, client_id, changed_by, change_reason)
             VALUES ($1::uuid, 'https://authz-store.example.test', 'synthetic-retirable',
                     'fixture-owner', 'synthetic retirable provider')",
        )
        .bind(RETIRABLE_PROVIDER)
        .execute(&mut f.owner)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.login_provider_revisions (provider_id, revision)
             VALUES ($1::uuid, 'v1')",
        )
        .bind(RETIRABLE_PROVIDER)
        .execute(&mut f.owner)
        .await
        .unwrap();
        let grace = account(&mut f.owner, RETIRABLE_PROVIDER, true, FUTURE).await;
        let grace_chat = authz_runs::chat(&f.db, &project_scope, "project", &alice).await;
        applied(
            projects::set_project_member_role(
                &mut connect(&f.db.0, API).await,
                &ctx(&alice, "co-grace-viewer"),
                &project_id,
                &Grantee::User(grace.user.clone()),
                ProjectRole::Viewer,
            )
            .await,
        );
        applied(
            projects::share_resource(
                &mut connect(&f.db.0, API).await,
                &ctx(&alice, "co-share-grace"),
                ResourceKind::Conversation,
                &grace_chat,
                &Grantee::User(grace.user.clone()),
                ResourceAccess::Read,
            )
            .await,
        );
        let r_grace_live = handoff_round_on(&mut f, &alice, &project_scope, &grace_chat).await;
        assert_eq!(
            dispatch_scoped(&f, &r_grace_live).await,
            expected_owner(&alice, None)
        );
        sqlx::query(
            "INSERT INTO openmettle.login_provider_revisions (provider_id, revision)
             VALUES ($1::uuid, NULL)",
        )
        .bind(RETIRABLE_PROVIDER)
        .execute(&mut f.owner)
        .await
        .unwrap();
        let r_grace_retired = handoff_round_on(&mut f, &alice, &project_scope, &grace_chat).await;
        assert_eq!(
            dispatch_scoped(&f, &r_grace_retired).await,
            expected_owner(&alice, Some(&alice.user))
        );
    }

    // Collaborator round handed off while shared, then Bob's project role is revoked BEFORE
    // dispatch -> Alice's round falls back to `Some(alice)`, while Bob's stale in-flight round
    // is refused (never enters Alice's private cache bucket!).
    let r_bob_stale_inflight = handoff_round_on(&mut f, &bob, &project_scope, &chat).await;
    applied(
        projects::revoke_project_member(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-revoke-bob"),
            &project_id,
            &Grantee::User(bob.user.clone()),
        )
        .await,
    );
    let r_bob_revoked = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_bob_revoked).await,
        expected_owner(&alice, Some(&alice.user))
    );
    assert_eq!(
        dispatch_scoped(&f, &r_bob_stale_inflight).await,
        [],
        "collaborator round whose share became ineffective must not enter owner private cache"
    );
    assert!(!f.stored(&r_bob_stale_inflight).await.3);
    applied(
        projects::unshare_resource(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-unshare-bob"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::User(bob.user.clone()),
        )
        .await,
    );

    // 5. `Grantee::LocalGroup` and `Grantee::User(carol)` via local-group project membership.
    let group_id = applied(
        store::create_local_group(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-mk-grp"),
            "cache-test-group",
        )
        .await,
    );
    applied(
        store::add_local_group_member(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-add-carol"),
            &group_id,
            &carol.user,
        )
        .await,
    );
    applied(
        projects::set_project_member_role(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-grp-editor"),
            &project_id,
            &Grantee::LocalGroup(group_id.clone()),
            ProjectRole::Editor,
        )
        .await,
    );
    // 5a. Direct share to `Grantee::LocalGroup` -> shared (`None`) for Alice & Carol.
    applied(
        projects::share_resource(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-share-grp"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::LocalGroup(group_id.clone()),
            ResourceAccess::Write,
        )
        .await,
    );
    let r_lg_alice = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    let r_lg_carol = handoff_round_on(&mut f, &carol, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_lg_alice).await,
        expected_owner(&alice, None)
    );
    assert_eq!(
        dispatch_scoped(&f, &r_lg_carol).await,
        expected_owner(&carol, None)
    );
    // Disable local group -> Gate 2b fail-closed (`Some(alice)`).
    applied(
        store::disable_local_group(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-disable-grp"),
            &group_id,
        )
        .await,
    );
    let r_lg_dis = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_lg_dis).await,
        expected_owner(&alice, Some(&alice.user))
    );
    applied(
        store::enable_local_group(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-enable-grp"),
            &group_id,
        )
        .await,
    );
    // Revoke local group's project role -> Gate 2b fail-closed (`Some(alice)`).
    applied(
        projects::revoke_project_member(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-revoke-grp-role"),
            &project_id,
            &Grantee::LocalGroup(group_id.clone()),
        )
        .await,
    );
    let r_lg_rev = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_lg_rev).await,
        expected_owner(&alice, Some(&alice.user))
    );
    applied(
        projects::unshare_resource(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-unshare-grp"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::LocalGroup(group_id.clone()),
        )
        .await,
    );

    // 5b. Share to `Grantee::User(carol)` whose ONLY project membership is through `group_id`.
    applied(
        projects::set_project_member_role(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-grp-viewer"),
            &project_id,
            &Grantee::LocalGroup(group_id.clone()),
            ProjectRole::Viewer,
        )
        .await,
    );
    applied(
        projects::share_resource(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-share-carol"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::User(carol.user.clone()),
            ResourceAccess::Read,
        )
        .await,
    );
    let r_carol_lg = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_carol_lg).await,
        expected_owner(&alice, None)
    );
    // Remove Carol from local group -> Carol loses project membership -> `Some(alice)`.
    f.owner_exec(
        "UPDATE openmettle.local_group_memberships SET active = false WHERE user_id = $1::uuid",
        &carol.user,
    )
    .await;
    let r_carol_removed = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_carol_removed).await,
        expected_owner(&alice, Some(&alice.user))
    );
    applied(
        projects::unshare_resource(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-unshare-carol"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::User(carol.user.clone()),
        )
        .await,
    );

    // 6. `Grantee::OidcGroup` share & revocation (Gate 2b).
    let oidc_team = "cache-oidc-team";
    applied(
        projects::set_project_member_role(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-oidc-role"),
            &project_id,
            &Grantee::OidcGroup(oidc_team.into()),
            ProjectRole::Editor,
        )
        .await,
    );
    applied(
        projects::share_resource(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-share-oidc"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::OidcGroup(oidc_team.into()),
            ResourceAccess::Write,
        )
        .await,
    );
    let r_oidc = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_oidc).await,
        expected_owner(&alice, None)
    );
    // Revoke OIDC group project role -> Gate 2b fail-closed (`Some(alice)`).
    applied(
        projects::revoke_project_member(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-revoke-oidc"),
            &project_id,
            &Grantee::OidcGroup(oidc_team.into()),
        )
        .await,
    );
    let r_oidc_rev = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_oidc_rev).await,
        expected_owner(&alice, Some(&alice.user))
    );
    applied(
        projects::unshare_resource(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "co-unshare-oidc"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::OidcGroup(oidc_team.into()),
        )
        .await,
    );

    // 7. `Grantee::User` holding project membership via mapped `openmettle.project-member`:
    //    - Dave: `selector_kind = 'app_role'` directly onto `project_id`
    //    - Erin: `selector_kind = 'group'` directly onto `project_id`
    //    - Frank: `selector_kind = 'group'` enrolled on ANOTHER project whose `claim_value`
    //      matches a direct `oidc_group` `project-role` on `project_id`!
    let now_ms: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    let share_ctx = |key: &'static str| openmettle_core::authz::store::AuditContext {
        now_ms,
        ..ctx(&alice, key)
    };
    enroll_mapped_member(
        &f.db,
        &dave,
        &project_id,
        &project_scope,
        "00000000-0000-4000-8000-00000000c101",
        "app_role",
        "project-viewer-role",
        "dave-approle",
    )
    .await;
    applied(
        projects::share_resource(
            &mut connect(&f.db.0, API).await,
            &share_ctx("co-share-dave"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::User(dave.user.clone()),
            ResourceAccess::Read,
        )
        .await,
    );
    let r_dave = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_dave).await,
        expected_owner(&alice, None),
        "mapped project-member with selector_kind = app_role must make user share effective"
    );
    // Expire Dave's observation -> stale -> fail-closed to `Some(alice)`.
    f.owner_exec(
        "UPDATE openmettle.membership_observations SET expires_ms = issued_ms WHERE approval_id = $1::uuid",
        &dave.approval,
    )
    .await;
    let r_dave_stale = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_dave_stale).await,
        expected_owner(&alice, Some(&alice.user)),
        "stale mapped observation must fail closed to owner cache isolation"
    );
    applied(
        projects::unshare_resource(
            &mut connect(&f.db.0, API).await,
            &share_ctx("co-unshare-dave"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::User(dave.user.clone()),
        )
        .await,
    );

    // Erin: mapped `group` directly on `project_id`, then test absent & disabled & generation mismatch.
    enroll_mapped_member(
        &f.db,
        &erin,
        &project_id,
        &project_scope,
        "00000000-0000-4000-8000-00000000c102",
        "group",
        "mapped-direct-group",
        "erin-group",
    )
    .await;
    applied(
        projects::share_resource(
            &mut connect(&f.db.0, API).await,
            &share_ctx("co-share-erin"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::User(erin.user.clone()),
            ResourceAccess::Read,
        )
        .await,
    );
    let r_erin = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_erin).await,
        expected_owner(&alice, None),
        "mapped project-member with selector_kind = group must make user share effective"
    );
    // Bump Erin's user session_generation -> observation generation mismatch -> fail-closed.
    f.owner_exec(
        "UPDATE openmettle.users SET session_generation = session_generation + 1 WHERE id = $1::uuid",
        &erin.user,
    )
    .await;
    let r_erin_gen = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_erin_gen).await,
        expected_owner(&alice, Some(&alice.user))
    );
    applied(
        projects::unshare_resource(
            &mut connect(&f.db.0, API).await,
            &share_ctx("co-unshare-erin"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::User(erin.user.clone()),
        )
        .await,
    );

    // Frank: `group` observation enrolled on a DIFFERENT project, matching direct `oidc_group`
    // project-role on `project_id`.
    let (other_proj, other_scope) =
        run_admission::new_project(&f.db, &frank, "other-oidc-project").await;
    enroll_mapped_member(
        &f.db,
        &frank,
        &other_proj,
        &other_scope,
        "00000000-0000-4000-8000-00000000c103",
        "group",
        "cross-proj-oidc-team",
        "frank-cross",
    )
    .await;
    applied(
        projects::set_project_member_role(
            &mut connect(&f.db.0, API).await,
            &share_ctx("co-cross-oidc-role"),
            &project_id,
            &Grantee::OidcGroup("cross-proj-oidc-team".into()),
            ProjectRole::Editor,
        )
        .await,
    );
    applied(
        projects::share_resource(
            &mut connect(&f.db.0, API).await,
            &share_ctx("co-share-frank"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::User(frank.user.clone()),
            ResourceAccess::Write,
        )
        .await,
    );
    let r_frank_alice = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    let r_frank_collab = handoff_round_on(&mut f, &frank, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_frank_alice).await,
        expected_owner(&alice, None)
    );
    assert_eq!(
        dispatch_scoped(&f, &r_frank_collab).await,
        expected_owner(&frank, None)
    );
    // Revoke the `oidc_group` project role -> Frank loses project membership -> `Some(alice)`.
    applied(
        projects::revoke_project_member(
            &mut connect(&f.db.0, API).await,
            &share_ctx("co-revoke-cross-oidc"),
            &project_id,
            &Grantee::OidcGroup("cross-proj-oidc-team".into()),
        )
        .await,
    );
    let r_frank_rev = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_frank_rev).await,
        expected_owner(&alice, Some(&alice.user))
    );
    applied(
        projects::unshare_resource(
            &mut connect(&f.db.0, API).await,
            &share_ctx("co-unshare-frank"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::User(frank.user.clone()),
        )
        .await,
    );

    // 8. Archived and deleted project defense-in-depth at dispatch.
    let r_arch = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    f.owner_exec(
        "UPDATE openmettle.project_settings SET archived_at = greatest(created_at, clock_timestamp())
          WHERE project_id = $1::uuid",
        &project_id,
    )
    .await;
    assert_eq!(dispatch_scoped(&f, &r_arch).await, []);
    assert!(!f.stored(&r_arch).await.3);
    f.owner_exec(
        "UPDATE openmettle.project_settings SET archived_at = NULL, deleted_at = greatest(created_at, clock_timestamp())
          WHERE project_id = $1::uuid",
        &project_id,
    )
    .await;
    assert_eq!(dispatch_scoped(&f, &r_arch).await, []);
    assert!(!f.stored(&r_arch).await.3);
    f.owner_exec(
        "UPDATE openmettle.project_settings SET deleted_at = NULL WHERE project_id = $1::uuid",
        &project_id,
    )
    .await;
    assert_eq!(
        dispatch_scoped(&f, &r_arch).await,
        expected_owner(&alice, Some(&alice.user))
    );
}

/// Concurrent `unshare_resource` (holding `projects FOR NO KEY UPDATE`) serializes cleanly with
/// `gateway_dispatch_scoped` (`projects FOR SHARE`), while a wrong bearer takes zero locks.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn gateway_dispatch_scoped_blocks_on_inflight_unshare_and_observes_revocation() {
    use openmettle_core::grants::{
        self, Assignment, ChangeInput, Decision, Grantee as GrantGrantee, Target,
    };

    let mut f = Rounds::new().await;
    let alice = f.actor.clone();
    let (project_id, project_scope) =
        run_admission::new_project(&f.db, &alice, "concurrent-unshare-proj").await;
    let chat = authz_runs::chat(&f.db, &project_scope, "project", &alice).await;
    applied(
        projects::share_resource(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "conc-share-proj"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::Project,
            ResourceAccess::Read,
        )
        .await,
    );
    let round = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;

    // Hold `projects FOR NO KEY UPDATE` and revoke the `Grantee::Project` share uncommitted.
    let mut writer = connect(&f.db.0, API).await;
    let writer_pid = backend_pid(&mut writer).await;
    let mut tx = WriteTransaction::begin(&mut writer).await.unwrap();
    sqlx::query("SELECT FROM openmettle.projects WHERE id = $1::uuid FOR NO KEY UPDATE")
        .bind(&project_id)
        .execute(tx.connection().unwrap())
        .await
        .unwrap();
    let (rev, cycle_id): (i64, Option<String>) = sqlx::query_as(
        "SELECT ga.last_revision, gh.cycle_id::text
           FROM openmettle.grant_assignments ga
           JOIN openmettle.grant_changes gh
             ON gh.assignment_id = ga.id AND gh.revision = ga.last_revision
          WHERE ga.scope_id = $1::uuid AND ga.target_kind = 'conversation'
            AND ga.target_id = $2::uuid AND ga.grantee_kind = 'project'
            AND ga.assignment_format = 'openmettle.resource-grant'
            AND ga.assignment_version = 1 AND ga.assignment_key = 'read'",
    )
    .bind(&project_scope)
    .bind(&chat)
    .fetch_one(tx.connection().unwrap())
    .await
    .unwrap();
    grants::change_grant(
        &mut tx,
        &ChangeInput {
            assignment: Assignment {
                scope: &project_scope,
                target: Target::Conversation(&chat),
                grantee: GrantGrantee::Project,
                format: "openmettle.resource-grant",
                version: 1,
                key: "read",
                mapping_rule: None,
            },
            actor: &alice.user,
            key: "conc-unshare-tx",
            expected_revision: rev,
            mapping_revision: None,
            decision: Decision::Revoke(cycle_id.as_deref()),
        },
    )
    .await
    .unwrap();

    // Wrong bearer takes ZERO locks and returns immediately even while projects row is locked.
    assert_eq!(
        dispatch_scoped_as(&f.db, pg::GATEWAY, &round.request, &[0xdd; 32])
            .await
            .unwrap(),
        []
    );

    // Valid bearer blocks behind `projects FOR NO KEY UPDATE`, then observes the committed revoke.
    let mut gw = connect(&f.db.0, pg::GATEWAY).await;
    let (req_id, bearer) = (round.request.clone(), round.bearer);
    let waiting = tokio::spawn(async move {
        sqlx::query_as::<_, ScopedDispatched>(DISPATCH_SCOPED)
            .bind(req_id)
            .bind(bearer.as_slice())
            .fetch_all(&mut gw)
            .await
            .unwrap()
    });
    wait_for_blocked_peer(&f.db, writer_pid).await;
    tx.commit().await.unwrap();

    assert_eq!(
        waiting.await.unwrap(),
        [(
            false,
            Some(INSTALL.to_owned()),
            Some(project_scope.clone()),
            Some(INSTALL.to_owned()),
            Some(alice.user.clone()),
            Some("a".to_owned()),
            Some(alice.user.clone()),
        )]
    );
}

/// Migration 35 -> 36 upgrade adds `openmettle.gateway_dispatch_scoped`, keeps 6-column
/// `openmettle.gateway_dispatch` compatible, and dispatches pre-36 handed-off rounds cleanly.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn migration_35_to_36_upgrade_adds_scoped_dispatch_and_preserves_existing_rounds() {
    let mut f = Rounds::at(35).await;
    let has_scoped: bool = sqlx::query_scalar(
        "SELECT to_regprocedure('openmettle.gateway_dispatch_scoped(uuid,bytea)') IS NOT NULL",
    )
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert!(!has_scoped);

    let (_, project_scope) =
        run_admission::new_project(&f.db, &f.actor.clone(), "upgrade-36-proj").await;
    let chat = authz_runs::chat(&f.db, &project_scope, "project", &f.actor).await;
    let alice = f.actor.clone();
    let pre_upgrade_round = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    let pre_upgrade_personal = f.round(&quotas::snapshot(100)).await;
    f.authorized(&pre_upgrade_personal, "pre-36 personal round")
        .await;

    let settings = f.db.settings(Duration::from_secs(10));
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(f.db.history().await, all_versions());

    // Pre-36 unshared project round dispatches with `cache_owner = alice`.
    assert_eq!(
        dispatch_scoped(&f, &pre_upgrade_round).await,
        [(
            false,
            Some(INSTALL.to_owned()),
            Some(project_scope.clone()),
            Some(INSTALL.to_owned()),
            Some(alice.user.clone()),
            Some("a".to_owned()),
            Some(alice.user.clone()),
        )]
    );
    // 6-column `gateway_dispatch` remains compatible on pre-36 personal round.
    assert_eq!(f.dispatch(&pre_upgrade_personal).await, [f.routed()]);
}

/// Review #1 P1: first dispatch must verify the actor's own current `editor`/`owner` project role
/// and conversation `write` access independently of `share.effective` (`cache_owner`).
/// - Revoking or downgrading collaborator Bob's `write` share while Carol's `read` share survives
///   must refuse Bob's first dispatch while keeping `cache_owner = NULL` for Alice.
/// - Demoting conversation owner Alice to `viewer` (after adding a second project owner) must
///   refuse Alice's first dispatch.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn review_1_p1_dispatch_requires_actor_own_role_and_write_share() {
    let mut f = Rounds::new().await;
    let alice = f.actor.clone();
    let bob = account(&mut f.owner, PROVIDER, true, FUTURE).await;
    let carol = account(&mut f.owner, PROVIDER, true, FUTURE).await;
    let dave = account(&mut f.owner, PROVIDER, true, FUTURE).await;

    let (project_id, project_scope) =
        run_admission::new_project(&f.db, &alice, "rev1-p1-proj").await;
    let expected_owner = |actor: &Account, cache_owner: Option<&str>| {
        vec![(
            false,
            Some(INSTALL.to_owned()),
            Some(project_scope.clone()),
            Some(INSTALL.to_owned()),
            Some(actor.user.clone()),
            Some("a".to_owned()),
            cache_owner.map(str::to_owned),
        )]
    };
    for (key, target, role) in [
        ("rev1-p1-bob-ed", &bob.user, ProjectRole::Editor),
        ("rev1-p1-carol-vw", &carol.user, ProjectRole::Viewer),
        ("rev1-p1-dave-own", &dave.user, ProjectRole::Owner),
    ] {
        applied(
            projects::set_project_member_role(
                &mut connect(&f.db.0, API).await,
                &ctx(&alice, key),
                &project_id,
                &Grantee::User(target.clone()),
                role,
            )
            .await,
        );
    }

    let chat = authz_runs::chat(&f.db, &project_scope, "project", &alice).await;
    applied(
        projects::share_resource(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "rev1-p1-share-bob-w"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::User(bob.user.clone()),
            ResourceAccess::Write,
        )
        .await,
    );
    applied(
        projects::share_resource(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "rev1-p1-share-carol-r"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::User(carol.user.clone()),
            ResourceAccess::Read,
        )
        .await,
    );

    // 1a. Bob hands off two rounds while holding Write; then Bob's share is downgraded to Read
    //     while Carol's Read share remains active (`share.effective = true`).
    let r_bob_downgraded = handoff_round_on(&mut f, &bob, &project_scope, &chat).await;
    let r_bob_unshared = handoff_round_on(&mut f, &bob, &project_scope, &chat).await;
    applied(
        projects::share_resource(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "rev1-p1-downgrade-bob-r"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::User(bob.user.clone()),
            ResourceAccess::Read,
        )
        .await,
    );
    assert_eq!(
        dispatch_scoped(&f, &r_bob_downgraded).await,
        [],
        "collaborator downgraded to read must be refused even when share.effective is true"
    );
    assert!(!f.stored(&r_bob_downgraded).await.3);

    // 1b. Unshare Bob completely while Carol's Read share survives (`share.effective = true`).
    applied(
        projects::unshare_resource(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "rev1-p1-unshare-bob"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::User(bob.user.clone()),
        )
        .await,
    );
    assert_eq!(
        dispatch_scoped(&f, &r_bob_unshared).await,
        [],
        "unshared collaborator must be refused even when another collaborator share survives"
    );
    assert!(!f.stored(&r_bob_unshared).await.3);

    // Alice (owner) still dispatches and sees `cache_owner = NULL` because Carol's Read share lives.
    let r_alice_shared = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;
    assert_eq!(
        dispatch_scoped(&f, &r_alice_shared).await,
        expected_owner(&alice, None)
    );

    // 2. Owner demoted to Viewer after handoff -> owner shortcut must NOT bypass current role check!
    let private_chat = authz_runs::chat(&f.db, &project_scope, "project", &alice).await;
    let r_alice_demoted = handoff_round_on(&mut f, &alice, &project_scope, &private_chat).await;
    applied(
        projects::set_project_member_role(
            &mut connect(&f.db.0, API).await,
            &ctx(&dave, "rev1-p1-demote-alice-vw"),
            &project_id,
            &Grantee::User(alice.user.clone()),
            ProjectRole::Viewer,
        )
        .await,
    );
    assert_eq!(
        dispatch_scoped(&f, &r_alice_demoted).await,
        [],
        "conversation owner demoted to viewer must be refused at first dispatch"
    );
    assert!(!f.stored(&r_alice_demoted).await.3);
}

/// Review #1 P2: an in-flight withdrawal of the sole direct-user collaborator's approval
/// (`identity-approval-change.psql`, `local_identity_approvals FOR UPDATE`) or mapped membership
/// (`configure-project-membership.psql` / `withdraw-project-membership.psql`,
/// `membership_observations FOR UPDATE`) blocks `gateway_dispatch_scoped` until commit so dispatch
/// observes the revocation and isolates `cache_owner` back to the conversation owner.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn review_1_p2_dispatch_blocks_on_inflight_collaborator_approval_and_membership_withdrawal() {
    let mut f = Rounds::new().await;
    let alice = f.actor.clone();
    let bob = account(&mut f.owner, PROVIDER, true, FUTURE).await;
    let eve = account(&mut f.owner, PROVIDER, true, FUTURE).await;

    let (project_id, project_scope) =
        run_admission::new_project(&f.db, &alice, "rev1-p2-collab-lock-proj").await;
    let expected_owner = |actor: &Account, cache_owner: Option<&str>| {
        vec![(
            false,
            Some(INSTALL.to_owned()),
            Some(project_scope.clone()),
            Some(INSTALL.to_owned()),
            Some(actor.user.clone()),
            Some("a".to_owned()),
            cache_owner.map(str::to_owned),
        )]
    };
    applied(
        projects::set_project_member_role(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "rev1-p2-bob-vw"),
            &project_id,
            &Grantee::User(bob.user.clone()),
            ProjectRole::Viewer,
        )
        .await,
    );
    let chat_bob = authz_runs::chat(&f.db, &project_scope, "project", &alice).await;
    applied(
        projects::share_resource(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "rev1-p2-share-bob"),
            ResourceKind::Conversation,
            &chat_bob,
            &Grantee::User(bob.user.clone()),
            ResourceAccess::Read,
        )
        .await,
    );
    let r_alice_bob = handoff_round_on(&mut f, &alice, &project_scope, &chat_bob).await;

    // 1. In-flight approval withdrawal on sole collaborator `bob` (`local_identity_approvals FOR UPDATE`).
    {
        let mut writer = connect(&f.db.0, OWNER).await;
        let writer_pid = backend_pid(&mut writer).await;
        let mut tx = WriteTransaction::begin(&mut writer).await.unwrap();
        sqlx::query(
            "SELECT id FROM openmettle.local_identity_approvals WHERE id = $1::uuid FOR UPDATE",
        )
        .bind(&bob.approval)
        .execute(tx.connection().unwrap())
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.local_identity_approvals
                SET active = false, revision = revision + 1, access_generation = access_generation + 1
              WHERE id = $1::uuid",
        )
        .bind(&bob.approval)
        .execute(tx.connection().unwrap())
        .await
        .unwrap();

        let mut gw = connect(&f.db.0, pg::GATEWAY).await;
        let (req_id, bearer) = (r_alice_bob.request.clone(), r_alice_bob.bearer);
        let waiting = tokio::spawn(async move {
            sqlx::query_as::<_, ScopedDispatched>(DISPATCH_SCOPED)
                .bind(req_id)
                .bind(bearer.as_slice())
                .fetch_all(&mut gw)
                .await
                .unwrap()
        });
        wait_for_blocked_peer(&f.db, writer_pid).await;
        tx.commit().await.unwrap();

        assert_eq!(
            waiting.await.unwrap(),
            expected_owner(&alice, Some(&alice.user)),
            "dispatch must wait for collaborator approval withdrawal and isolate to owner"
        );
    }

    // 2. In-flight mapped membership disablement on sole collaborator `eve`
    //    (`membership_observations FOR UPDATE`, matching configure/withdraw-project-membership.psql).
    let now_ms: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
    enroll_mapped_member(
        &f.db,
        &eve,
        &project_id,
        &project_scope,
        "00000000-0000-4000-8000-00000000c299",
        "app_role",
        "rev1-p2-mapped-role",
        "eve-approle",
    )
    .await;
    let chat_eve = authz_runs::chat(&f.db, &project_scope, "project", &alice).await;
    applied(
        projects::share_resource(
            &mut connect(&f.db.0, API).await,
            &openmettle_core::authz::store::AuditContext {
                now_ms,
                ..ctx(&alice, "rev1-p2-share-eve")
            },
            ResourceKind::Conversation,
            &chat_eve,
            &Grantee::User(eve.user.clone()),
            ResourceAccess::Read,
        )
        .await,
    );
    let r_alice_eve = handoff_round_on(&mut f, &alice, &project_scope, &chat_eve).await;

    {
        let mut writer = connect(&f.db.0, OWNER).await;
        let writer_pid = backend_pid(&mut writer).await;
        let mut tx = WriteTransaction::begin(&mut writer).await.unwrap();
        sqlx::query(
            "SELECT id FROM openmettle.local_identity_approvals WHERE id = $1::uuid FOR SHARE",
        )
        .bind(&eve.approval)
        .execute(tx.connection().unwrap())
        .await
        .unwrap();
        sqlx::query(
            "SELECT approval_id FROM openmettle.membership_observations
              WHERE approval_id = $1::uuid FOR UPDATE",
        )
        .bind(&eve.approval)
        .execute(tx.connection().unwrap())
        .await
        .unwrap();
        sqlx::query(
            "UPDATE openmettle.membership_observations SET enabled = false
              WHERE approval_id = $1::uuid",
        )
        .bind(&eve.approval)
        .execute(tx.connection().unwrap())
        .await
        .unwrap();

        let mut gw = connect(&f.db.0, pg::GATEWAY).await;
        let (req_id, bearer) = (r_alice_eve.request.clone(), r_alice_eve.bearer);
        let waiting = tokio::spawn(async move {
            sqlx::query_as::<_, ScopedDispatched>(DISPATCH_SCOPED)
                .bind(req_id)
                .bind(bearer.as_slice())
                .fetch_all(&mut gw)
                .await
                .unwrap()
        });
        wait_for_blocked_peer(&f.db, writer_pid).await;
        tx.commit().await.unwrap();

        assert_eq!(
            waiting.await.unwrap(),
            expected_owner(&alice, Some(&alice.user)),
            "dispatch must wait for collaborator mapped membership withdrawal and isolate to owner"
        );
    }
}

/// Review #2 P2 #1: capability writers (`store::set_user_capability_grant` /
/// `set_user_capability_deny` / `set_platform_capability_deny`) must acquire
/// `account_admin_lock FOR UPDATE` so an in-flight capability withdrawal blocks
/// `gateway_dispatch_scoped` (`account_admin_lock FOR SHARE`) and refuses dispatch on commit.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn review_2_p2_capability_withdrawal_acquires_admin_lock_and_blocks_dispatch() {
    use openmettle_core::authz::store;

    let mut f = Rounds::new().await;
    let alice = f.actor.clone();
    authz_store::make_admin(&mut f.owner, &alice).await;

    // Grant opt-in capability `runs.use_yolo` to Alice through the audited store API.
    applied(
        store::set_user_capability_grant(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "rev2-p2-grant-yolo"),
            &alice.user,
            "runs.use_yolo",
            true,
        )
        .await,
    );

    // Admit, claim, reserve, and hand off a round whose snapshot requires opt-in `runs.use_yolo`.
    let mut snap: serde_json::Value = serde_json::from_slice(&quotas::snapshot(100)).unwrap();
    snap["required_capabilities"] = serde_json::json!({ "runs.use_yolo": "opt_in" });
    let snap_bytes = serde_json::to_vec(&snap).unwrap();
    let r_cap = f.round(&snap_bytes).await;
    f.authorized(&r_cap, "round requiring opt-in runs.use_yolo")
        .await;

    // 1. Prove `store::set_user_capability_grant(..., false)` acquires `account_admin_lock FOR UPDATE`
    //    by holding `account_admin_lock FOR SHARE` (the same lock `gateway_dispatch_scoped` takes
    //    inside `SECURITY DEFINER`) in a separate transaction and verifying the store writer blocks
    //    until the shared lock releases.
    let mut lock_hold = connect(&f.db.0, OWNER).await;
    let hold_pid = backend_pid(&mut lock_hold).await;
    let mut hold_tx = WriteTransaction::begin(&mut lock_hold).await.unwrap();
    sqlx::query("SELECT id FROM openmettle.account_admin_lock FOR SHARE")
        .execute(hold_tx.connection().unwrap())
        .await
        .unwrap();

    let mut api_conn = connect(&f.db.0, API).await;
    let alice_clone = alice.clone();
    let withdraw_task = tokio::spawn(async move {
        store::set_user_capability_grant(
            &mut api_conn,
            &ctx(&alice_clone, "rev2-p2-withdraw-yolo"),
            &alice_clone.user,
            "runs.use_yolo",
            false,
        )
        .await
    });
    wait_for_blocked_peer(&f.db, hold_pid).await;
    hold_tx.rollback().await.unwrap();
    applied(withdraw_task.await.unwrap());

    // After withdrawal committed, `gateway_dispatch_scoped` refuses `r_cap`.
    assert_eq!(
        dispatch_scoped(&f, &r_cap).await,
        [],
        "dispatch must refuse after opt-in capability withdrawal"
    );
    assert!(!f.stored(&r_cap).await.3);

    // 2. Reverse direction: re-grant, hand off a second round, hold an in-flight capability
    //    withdrawal (`account_admin_lock FOR UPDATE` + `granted = false`), and confirm
    //    `gateway_dispatch_scoped` blocks until commit and then refuses dispatch.
    applied(
        store::set_user_capability_grant(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "rev2-p2-regrant-yolo"),
            &alice.user,
            "runs.use_yolo",
            true,
        )
        .await,
    );
    let r_cap2 = f.round(&snap_bytes).await;
    f.authorized(&r_cap2, "second round requiring opt-in runs.use_yolo")
        .await;

    let mut admin_writer = connect(&f.db.0, API).await;
    let admin_pid = backend_pid(&mut admin_writer).await;
    let mut admin_tx = WriteTransaction::begin(&mut admin_writer).await.unwrap();
    sqlx::query("SELECT id FROM openmettle.account_admin_lock WHERE id FOR UPDATE")
        .execute(admin_tx.connection().unwrap())
        .await
        .unwrap();
    sqlx::query(
        "UPDATE openmettle.user_capability_grants
            SET granted = false, revision = revision + 1, updated_at = clock_timestamp()
          WHERE user_id = $1::uuid AND capability = 'runs.use_yolo'",
    )
    .bind(&alice.user)
    .execute(admin_tx.connection().unwrap())
    .await
    .unwrap();

    let mut gw = connect(&f.db.0, pg::GATEWAY).await;
    let (req_id, bearer) = (r_cap2.request.clone(), r_cap2.bearer);
    let waiting = tokio::spawn(async move {
        sqlx::query_as::<_, ScopedDispatched>(DISPATCH_SCOPED)
            .bind(req_id)
            .bind(bearer.as_slice())
            .fetch_all(&mut gw)
            .await
            .unwrap()
    });
    wait_for_blocked_peer(&f.db, admin_pid).await;
    admin_tx.commit().await.unwrap();
    assert_eq!(waiting.await.unwrap(), []);
    assert!(!f.stored(&r_cap2).await.3);
}

/// Review #2 P2 #2: if a collaborator gains a new approval (`first-identity-approval.psql`) AFTER
/// `gateway_dispatch_scoped` scanned `local_identity_approvals FOR SHARE` (while parked on a later
/// lock) and that new approval is concurrently under `FOR UPDATE` withdrawal, the final `UPDATE`
/// must restrict `share.effective` to the provider/approval/observation/rule IDs actually locked in
/// this transaction and isolate `cache_owner` to the conversation owner.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn review_2_p2_newly_added_unlocked_collaborator_approval_cannot_select_shared_cache() {
    let mut f = Rounds::new().await;
    let alice = f.actor.clone();
    let bob = account(&mut f.owner, PROVIDER, true, FUTURE).await;

    let (project_id, project_scope) =
        run_admission::new_project(&f.db, &alice, "rev2-p2-new-approval-proj").await;
    let expected_owner = |actor: &Account, cache_owner: Option<&str>| {
        vec![(
            false,
            Some(INSTALL.to_owned()),
            Some(project_scope.clone()),
            Some(INSTALL.to_owned()),
            Some(actor.user.clone()),
            Some("a".to_owned()),
            cache_owner.map(str::to_owned),
        )]
    };
    applied(
        projects::set_project_member_role(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "rev2-p2-bob-vw"),
            &project_id,
            &Grantee::User(bob.user.clone()),
            ProjectRole::Viewer,
        )
        .await,
    );
    let chat = authz_runs::chat(&f.db, &project_scope, "project", &alice).await;
    applied(
        projects::share_resource(
            &mut connect(&f.db.0, API).await,
            &ctx(&alice, "rev2-p2-share-bob"),
            ResourceKind::Conversation,
            &chat,
            &Grantee::User(bob.user.clone()),
            ResourceAccess::Read,
        )
        .await,
    );

    // Give Bob a second OIDC identity with NO approval yet, and withdraw Bob's initial approval so
    // Bob has zero active approvals when `gateway_dispatch_scoped` scans `local_identity_approvals`.
    let bob_ident2: String = sqlx::query_scalar(
        "INSERT INTO openmettle.user_identities (user_id, issuer, subject)
         VALUES ($1::uuid, 'https://authz-store.example.test', 'bob-second-subject')
         RETURNING id::text",
    )
    .bind(&bob.user)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    f.owner_exec(
        "UPDATE openmettle.local_identity_approvals SET active = false WHERE id = $1::uuid",
        &bob.approval,
    )
    .await;

    let r_alice = handoff_round_on(&mut f, &alice, &project_scope, &chat).await;

    // Hold `runs FOR NO KEY UPDATE` on `r_alice`'s run so `gateway_dispatch_scoped` completes its
    // `local_identity_approvals FOR SHARE` scan and parks right before `runs FOR SHARE`.
    let mut run_blocker = connect(&f.db.0, OWNER).await;
    let run_blocker_pid = backend_pid(&mut run_blocker).await;
    let mut run_tx = WriteTransaction::begin(&mut run_blocker).await.unwrap();
    sqlx::query("SELECT FROM openmettle.runs WHERE id = $1::uuid FOR NO KEY UPDATE")
        .bind(&r_alice.run)
        .execute(run_tx.connection().unwrap())
        .await
        .unwrap();

    let mut gw = connect(&f.db.0, pg::GATEWAY).await;
    let (req_id, bearer) = (r_alice.request.clone(), r_alice.bearer);
    let waiting = tokio::spawn(async move {
        sqlx::query_as::<_, ScopedDispatched>(DISPATCH_SCOPED)
            .bind(req_id)
            .bind(bearer.as_slice())
            .fetch_all(&mut gw)
            .await
            .unwrap()
    });
    wait_for_blocked_peer(&f.db, run_blocker_pid).await;

    // Now insert and commit a brand-new active approval `bob_ap2` for `bob_ident2` AFTER dispatch's
    // approval lock scan, then hold an uncommitted withdrawal (`FOR UPDATE`, `active = false`) on
    // `bob_ap2` while releasing `run_tx`.
    let bob_ap2: String = sqlx::query_scalar(
        "INSERT INTO openmettle.local_identity_approvals
             (provider_id, identity_id, revision, access_generation, active, expires_ms,
              changed_by, change_reason)
         VALUES ($1::uuid, $2::uuid, 1, 0, true, 4102444800000, 'fixture-owner', 'late first approval')
         RETURNING id::text",
    )
    .bind(PROVIDER)
    .bind(&bob_ident2)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();

    let mut withdraw_conn = connect(&f.db.0, OWNER).await;
    let mut withdraw_tx = WriteTransaction::begin(&mut withdraw_conn).await.unwrap();
    sqlx::query(
        "SELECT id FROM openmettle.local_identity_approvals WHERE id = $1::uuid FOR UPDATE",
    )
    .bind(&bob_ap2)
    .execute(withdraw_tx.connection().unwrap())
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.local_identity_approvals
            SET active = false, revision = revision + 1, access_generation = access_generation + 1
          WHERE id = $1::uuid",
    )
    .bind(&bob_ap2)
    .execute(withdraw_tx.connection().unwrap())
    .await
    .unwrap();

    // Release `run_tx`: `gateway_dispatch_scoped` runs its final `UPDATE` while `withdraw_tx` is
    // still open. Because `bob_ap2` was NOT in `v_locked_approvals`, it must NOT select `None`!
    run_tx.rollback().await.unwrap();
    let result = waiting.await.unwrap();
    withdraw_tx.commit().await.unwrap();

    assert_eq!(
        result,
        expected_owner(&alice, Some(&alice.user)),
        "unlocked late collaborator approval under concurrent withdrawal must not select shared cache"
    );
}

/// Migration 37 (ADR 0044, increment 6):
/// 1. Superseded ADR 0037 tables, columns, indexes, and functions are gone, and
///    `gateway_requests.{run_id, round}` are `NOT NULL`.
/// 2. `openmettle_gateway` has zero table/column privileges (`42501` on direct SQL and internal
///    quota helpers) and settles exclusively via `openmettle.gateway_settle_report(...)`,
///    preserving `Applied`, `Duplicate`, `Superseded`, `Conflict`, incomplete reasons, late
///    revision-1 correction after `unreported`, cost-hold folds, and all refusals.
/// 3. `openmettle_api` has `42501` on `gateway_requests`, `gateway_release`, and
///    `quota_recover_lost_handoff` while run-admission `gateway::hold_with_cost` succeeds.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn migration_37_removes_superseded_objects_and_enforces_function_only_gateway_and_worker_round_boundaries()
 {
    use openmettle_core::{
        authz::gateway::{self, Reservation, TurnRound},
        model_config::CostBound,
    };

    let mut f = Rounds::new().await;
    enable_cost_metering_defaults(&mut f.owner, 1_000_000).await;

    // 1. Verify dropped tables, columns, indexes, and functions do not exist.
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
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
        assert!(!exists, "superseded table {table} must be dropped");
    }
    for index in [
        "openmettle.gateway_requests_caller_reservation_idx",
        "openmettle.gateway_requests_unbound_outstanding_idx",
    ] {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(index)
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
        assert!(!exists, "superseded index {index} must be dropped");
    }
    for func in [
        "openmettle.gateway_handoff(uuid,bytea,bytea,bytea,uuid)",
        "openmettle.quota_commit_handoff(uuid,bytea)",
    ] {
        let exists: bool = sqlx::query_scalar("SELECT to_regprocedure($1) IS NOT NULL")
            .bind(func)
            .fetch_one(&mut f.owner)
            .await
            .unwrap();
        assert!(!exists, "superseded function {func} must be dropped");
    }
    let retained_device_handoff: bool = sqlx::query_scalar(
        "SELECT to_regprocedure('openmettle.quota_commit_handoff(uuid,uuid)') IS NOT NULL",
    )
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert!(retained_device_handoff);

    // 2. `openmettle_gateway` has zero table/column privileges and zero internal quota helper grants.
    let mut gw = connect(&f.db.0, pg::GATEWAY).await;
    for sql in [
        "SELECT id FROM openmettle.gateway_requests",
        "SELECT id FROM openmettle.gateway_reservations",
        "SELECT request_id FROM openmettle.gateway_usage_reports",
        "SELECT request_id FROM openmettle.gateway_settlements",
        "SELECT id FROM openmettle.quota_reservations",
        "SELECT id FROM openmettle.users",
        "SELECT id FROM openmettle.projects",
        "SELECT id FROM openmettle.account_admin_lock",
        "INSERT INTO openmettle.gateway_usage_reports (request_id,source,report_id,revision,final) VALUES (gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),1,true)",
        "INSERT INTO openmettle.gateway_settlements (request_id,revision,final,measured,outstanding) VALUES (gen_random_uuid(),1,true,1,0)",
        "UPDATE openmettle.projects SET lock_guard=lock_guard WHERE false",
        "SELECT openmettle.quota_lock_gateway_request_for_settlement(gen_random_uuid())",
        "SELECT openmettle.quota_settle_gateway_usage(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),1)",
    ] {
        assert_eq!(sqlstate(gw.execute(sql).await), "42501", "gateway: {sql}");
    }

    // 3. `openmettle_api` has 42501 on round-level gateway functions/tables, while run admission
    //    `gateway::hold_with_cost` (`INSERT INTO openmettle.gateway_reservations`) succeeds.
    let mut api = connect(&f.db.0, API).await;
    for sql in [
        "INSERT INTO openmettle.gateway_requests (id,reservation_id,scope_id,actor_user_id,approval_id,installation,model,units,dispatch_hash,run_id,round) VALUES (gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),'a',1,sha256('x'),gen_random_uuid(),1)",
        "SELECT openmettle.gateway_release(gen_random_uuid(), repeat('x', 32)::bytea)",
        "SELECT openmettle.quota_recover_lost_handoff(gen_random_uuid(), repeat('x', 32)::bytea, gen_random_uuid(), gen_random_uuid(), gen_random_uuid())",
    ] {
        assert_eq!(sqlstate(api.execute(sql).await), "42501", "api: {sql}");
    }
    let chat = authz_runs::chat(&f.db, &f.scope, "personal", &f.actor).await;
    let (branch, message) = quotas::branch_and_message(&mut api, &f.scope, &chat).await;
    let std_cb = CostBound {
        fixed_micros: 50,
        micros_per_token: 2,
    };
    let snap = quotas::snapshot_priced("a", 100, Some(std_cb));
    let mut api_tx = WriteTransaction::begin(&mut api).await.unwrap();
    let Admission::Admitted {
        run_id: api_run, ..
    } = queue::admit_run(
        &mut api_tx,
        &RunAdmission {
            input: RunInput {
                scope: &f.scope,
                actor: &f.actor.user,
                conversation: &chat,
                branch: &branch,
                message: &message,
                key: "m37-api-hold",
                format: "openmettle.conversation",
                version: 1,
                input: b"{}",
                config: &snap,
            },
            actor_approval_id: &f.actor.approval,
            capabilities: &[],
            requested_rounds: Some(1),
            now_ms: NOW,
            cost_qualified: Some(true),
        },
        &LIMITS,
    )
    .await
    .unwrap()
    else {
        panic!("expected admission");
    };
    gateway::hold_with_cost(
        &mut api_tx,
        &Reservation {
            id: &api_run,
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
        },
        Some(&api_run),
        100,
        Some(250),
    )
    .await
    .unwrap();
    api_tx.commit().await.unwrap();

    // 4. Non-gateway roles and non-READ-COMMITTED isolation are refused by `gateway_settle_report`.
    const SETTLE_CALL: &str = "SELECT openmettle.gateway_settle_report(
        $1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6::uuid,
        $7,$8,$9,$10,$11,$12,$13::text::numeric,$14,$15)";
    for role in [API, WORKER, ISSUANCE] {
        let mut c = connect(&f.db.0, role).await;
        let err = sqlx::query(SETTLE_CALL)
            .bind(UNKNOWN)
            .bind(INSTALL)
            .bind(&f.actor.user)
            .bind(&f.scope)
            .bind(INSTALL)
            .bind(UNKNOWN)
            .bind(1_i64)
            .bind(true)
            .bind(Some(10_i64))
            .bind(Some(5_i64))
            .bind(None::<i64>)
            .bind(None::<bool>)
            .bind(None::<String>)
            .bind(None::<String>)
            .bind(None::<String>)
            .execute(&mut c)
            .await;
        assert_eq!(
            sqlstate(err),
            "42501",
            "role {role} calling gateway_settle_report"
        );
    }
    {
        gw.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
            .await
            .unwrap();
        let err = sqlx::query(SETTLE_CALL)
            .bind(UNKNOWN)
            .bind(INSTALL)
            .bind(&f.actor.user)
            .bind(&f.scope)
            .bind(INSTALL)
            .bind(UNKNOWN)
            .bind(1_i64)
            .bind(true)
            .bind(Some(10_i64))
            .bind(Some(5_i64))
            .bind(None::<i64>)
            .bind(None::<bool>)
            .bind(None::<String>)
            .bind(None::<String>)
            .bind(None::<String>)
            .execute(&mut gw)
            .await;
        assert_eq!(sqlstate(err), "25000");
        gw.execute("ROLLBACK").await.unwrap();
    }

    // 5. End-to-end `gateway::consume` + `settlement::{ingest, ingest_incomplete}` matrix through
    //    `gateway_dispatch_scoped` and `gateway_settle_report` as `openmettle_gateway`.
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(WORKER));
    let gw_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(pg::GATEWAY));
    let mut worker_c = connect(&f.db.0, WORKER).await;
    let claim = queue::claim_next(&mut worker_c, &CLAIMS, &LEASES)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim.run_id, api_run);
    let pending = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &api_run,
            round: 1,
            claim_token: &claim.claim_token,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(250),
            cost_bound: Some(std_cb),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let fx = quotas::TurnHandoffFixture::chat_priced(INSTALL, "a", 100, std_cb, false);
    let _disp = pending
        .handoff(&worker_pool, None, &fx.billable(), fx.prepare_mode(true))
        .await
        .unwrap();
    let bearer_raw = [0x37_u8; 32];
    sqlx::query(
        "UPDATE openmettle.gateway_requests SET bearer_hash = sha256($2) WHERE id = $1::uuid",
    )
    .bind(&pending.id)
    .bind(bearer_raw.as_slice())
    .execute(&mut f.owner)
    .await
    .unwrap();

    // Undispatched request is refused by `settlement::ingest`.
    let base_report = UsageReport {
        request: pending.id.clone(),
        installation: INSTALL.into(),
        principal: f.actor.user.clone(),
        scope: f.scope.clone(),
        source: INSTALL.into(),
        report_id: pending.id.clone(),
        revision: 2,
        r#final: true,
        prompt_tokens: Some(15),
        completion_tokens: Some(5),
        reasoning_tokens: None,
        reasoning_included: None,
        cost: None,
        unit: None,
    };
    assert_eq!(
        settlement::ingest(&gw_pool, &base_report).await,
        Err(StoreError::Refused)
    );

    // Spend dispatch via `openmettle.gateway_dispatch_scoped` as `openmettle_gateway`.
    let dispatched_rows: Vec<ScopedDispatched> = sqlx::query_as(DISPATCH_SCOPED)
        .bind(&pending.id)
        .bind(bearer_raw.as_slice())
        .fetch_all(&gw_pool)
        .await
        .unwrap();
    assert_eq!(dispatched_rows.len(), 1);
    assert!(!dispatched_rows[0].0);
    let replayed_rows: Vec<ScopedDispatched> = sqlx::query_as(DISPATCH_SCOPED)
        .bind(&pending.id)
        .bind(bearer_raw.as_slice())
        .fetch_all(&gw_pool)
        .await
        .unwrap();
    assert_eq!(replayed_rows.len(), 1);
    assert!(replayed_rows[0].0);

    // Shape refusals: revision 0, caller-supplied cost/unit, bare final.
    for bad in [
        UsageReport {
            revision: 0,
            ..base_report.clone()
        },
        UsageReport {
            cost: Some("10".into()),
            unit: Some("usd_micros".into()),
            ..base_report.clone()
        },
        UsageReport {
            prompt_tokens: None,
            completion_tokens: None,
            ..base_report.clone()
        },
    ] {
        assert_eq!(
            settlement::ingest(&gw_pool, &bad).await,
            Err(StoreError::Refused)
        );
    }

    // Applied -> Duplicate -> Conflict -> Superseded (lower rev & non-final after final).
    assert_eq!(
        settlement::ingest(&gw_pool, &base_report).await,
        Ok(Outcome::Applied)
    );
    assert_eq!(
        settlement::ingest(&gw_pool, &base_report).await,
        Ok(Outcome::Duplicate)
    );
    assert_eq!(
        settlement::ingest(
            &gw_pool,
            &UsageReport {
                completion_tokens: Some(6),
                ..base_report.clone()
            }
        )
        .await,
        Err(StoreError::Conflict)
    );
    let lower_rev_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert_eq!(
        settlement::ingest(
            &gw_pool,
            &UsageReport {
                report_id: lower_rev_id,
                revision: 1,
                r#final: true,
                prompt_tokens: Some(10),
                completion_tokens: Some(4),
                ..base_report.clone()
            }
        )
        .await,
        Ok(Outcome::Superseded)
    );
    let nonfinal_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert_eq!(
        settlement::ingest(
            &gw_pool,
            &UsageReport {
                report_id: nonfinal_id,
                revision: 3,
                r#final: false,
                prompt_tokens: Some(10),
                completion_tokens: Some(4),
                ..base_report.clone()
            }
        )
        .await,
        Ok(Outcome::Superseded)
    );
    // Token hold settled to 20, cost hold settled to 50 + 20 * 2 = 90 micros.
    let holds: Vec<(String, String, i64, String)> = sqlx::query_as(
        "SELECT resource_kind, state, held_units, settled_units::text
           FROM openmettle.quota_reservations
          WHERE gateway_request_id = $1::uuid
          ORDER BY resource_kind",
    )
    .bind(&pending.id)
    .fetch_all(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(
        holds,
        [
            (
                "usage_cost_micros".to_owned(),
                "settled".to_owned(),
                0,
                "90".to_owned()
            ),
            (
                "usage_tokens".to_owned(),
                "settled".to_owned(),
                0,
                "20".to_owned()
            ),
        ]
    );

    // Incomplete reason (`no_usage`) and late revision-1 correction after `unreported` sweep.
    let (inc_run, inc_claim) = admit_and_claim_priced(&mut f, 100, Some(std_cb), 1, true).await;
    let inc_pending = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &inc_run,
            round: 1,
            claim_token: &inc_claim,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(250),
            cost_bound: Some(std_cb),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let _inc_disp = inc_pending
        .handoff(&worker_pool, None, &fx.billable(), fx.prepare_mode(true))
        .await
        .unwrap();
    let inc_raw = [0x39_u8; 32];
    sqlx::query(
        "UPDATE openmettle.gateway_requests SET bearer_hash = sha256($2) WHERE id = $1::uuid",
    )
    .bind(&inc_pending.id)
    .bind(inc_raw.as_slice())
    .execute(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(
        sqlx::query_as::<_, ScopedDispatched>(DISPATCH_SCOPED)
            .bind(&inc_pending.id)
            .bind(inc_raw.as_slice())
            .fetch_all(&gw_pool)
            .await
            .unwrap()
            .len(),
        1
    );
    let inc_report = UsageReport {
        request: inc_pending.id.clone(),
        installation: INSTALL.into(),
        principal: f.actor.user.clone(),
        scope: f.scope.clone(),
        source: INSTALL.into(),
        report_id: inc_pending.id.clone(),
        revision: 1,
        r#final: true,
        prompt_tokens: None,
        completion_tokens: None,
        reasoning_tokens: None,
        reasoning_included: None,
        cost: None,
        unit: None,
    };
    assert_eq!(
        settlement::ingest_incomplete(&gw_pool, &inc_report, "no_usage").await,
        Ok(Outcome::Applied)
    );
    assert_eq!(
        settlement::ingest_incomplete(&gw_pool, &inc_report, "no_usage").await,
        Ok(Outcome::Duplicate)
    );

    let (unrep_run, unrep_claim) = admit_and_claim_priced(&mut f, 100, Some(std_cb), 1, true).await;
    let unrep_pending = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &unrep_run,
            round: 1,
            claim_token: &unrep_claim,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(250),
            cost_bound: Some(std_cb),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let _unrep_disp = unrep_pending
        .handoff(&worker_pool, None, &fx.billable(), fx.prepare_mode(true))
        .await
        .unwrap();
    let unrep_raw = [0x38_u8; 32];
    sqlx::query(
        "UPDATE openmettle.gateway_requests SET bearer_hash = sha256($2) WHERE id = $1::uuid",
    )
    .bind(&unrep_pending.id)
    .bind(unrep_raw.as_slice())
    .execute(&mut f.owner)
    .await
    .unwrap();
    let unrep_disp_rows: Vec<ScopedDispatched> = sqlx::query_as(DISPATCH_SCOPED)
        .bind(&unrep_pending.id)
        .bind(unrep_raw.as_slice())
        .fetch_all(&gw_pool)
        .await
        .unwrap();
    assert_eq!(unrep_disp_rows.len(), 1);
    assert!(!unrep_disp_rows[0].0);
    f.owner_exec(
        "UPDATE openmettle.runs
            SET state = 'failed',
                lease_expires_at = clock_timestamp() - interval '16 minutes',
                execution_expires_at = clock_timestamp() - interval '16 minutes'
          WHERE id = $1::uuid",
        &unrep_run,
    )
    .await;
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(SWEEP_CLOSE)
            .bind(&unrep_pending.id)
            .fetch_one(&mut worker_c)
            .await
            .unwrap()
            .as_deref(),
        Some("unreported")
    );
    let late_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut f.owner)
        .await
        .unwrap();
    assert_eq!(
        settlement::ingest(
            &gw_pool,
            &UsageReport {
                request: unrep_pending.id.clone(),
                installation: INSTALL.into(),
                principal: f.actor.user.clone(),
                scope: f.scope.clone(),
                source: INSTALL.into(),
                report_id: late_id,
                revision: 1,
                r#final: true,
                prompt_tokens: Some(10),
                completion_tokens: Some(5),
                reasoning_tokens: None,
                reasoning_included: None,
                cost: None,
                unit: None,
            }
        )
        .await,
        Ok(Outcome::Applied)
    );
    let late_cost: String = sqlx::query_scalar(
        "SELECT settled_units::text FROM openmettle.quota_reservations
          WHERE gateway_request_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&unrep_pending.id)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(late_cost, "80");

    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches,
                pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker_c)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
}

/// Migration 37 `36 -> 37` upgrade coverage:
/// 1. Fails closed (`23514`) on every legacy preflight condition:
///    (a) bound `gateway_requests`, (b) caller-session `gateway_requests`,
///    (c) caller-session `gateway_reservations` (`run_id IS NULL`),
///    (d) caller-priced `gateway_usage_reports` (`cost`/`unit IS NOT NULL`).
/// 2. Upgrades cleanly on populated run-owned `gateway_reservations`, `gateway_requests`,
///    `gateway_usage_reports`, `gateway_settlements`, and `quota_reservations`; exact replay of
///    a pre-37 accepted report returns `Outcome::Duplicate` and post-upgrade settlement of an
///    in-flight round succeeds with zero drift.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn migration_37_upgrade_fails_closed_on_legacy_rows_and_preserves_populated_run_history() {
    use openmettle_core::{
        authz::gateway::{self, TurnRound},
        model_config::CostBound,
    };

    let plain = quotas::snapshot(100);

    // 1a. Bound `gateway_requests` row blocks migration 37 with 23514.
    {
        let mut f = Rounds::at(36).await;
        let round = f.round(&plain).await;
        for sql in [
            "INSERT INTO openmettle.gateway_bindings (installation,user_id,principal,budget)
             SELECT installation,actor_user_id,gen_random_uuid(),gen_random_uuid()
               FROM openmettle.gateway_requests WHERE id=$1::uuid",
            "INSERT INTO openmettle.gateway_nonces (key_fingerprint,nonce)
             SELECT sha256('m37-bound'),substring(sha256('m37-nonce') FOR 12)
               FROM openmettle.gateway_requests WHERE id=$1::uuid",
            "INSERT INTO openmettle.gateway_generations
                 (binding_id,generation,remote_key,expires_at,key_id,key_fingerprint,nonce,ciphertext)
             SELECT b.id,1,gen_random_uuid(),clock_timestamp()+interval '1 hour','m37-bound',
                    sha256('m37-bound'),substring(sha256('m37-nonce') FOR 12),sha256('ct')
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
            f.owner_exec(sql, &round.request).await;
        }
        let settings = f.db.settings(Duration::from_secs(10));
        let err = migrate::apply(&settings, MIGRATIONS)
            .await
            .expect_err("bound gateway_requests row must block migration 37");
        assert!(err.to_string().contains("23514"), "{err:?}");
        assert_eq!(f.db.history().await, versions_through(36));
    }

    // 1b. Caller-session `gateway_requests` (`session_id IS NOT NULL`) blocks migration 37.
    {
        let mut f = Rounds::at(36).await;
        let (res_id, req_id): (String, String) =
            sqlx::query_as("SELECT gen_random_uuid()::text, gen_random_uuid()::text")
                .fetch_one(&mut f.owner)
                .await
                .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_reservations (id,scope_id,actor_user_id,approval_id,units)
             VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,100)",
        )
        .bind(&res_id)
        .bind(&f.scope)
        .bind(&f.actor.user)
        .bind(&f.actor.approval)
        .execute(&mut f.owner)
        .await
        .unwrap();
        let mut api = connect(&f.db.0, API).await;
        sqlx::query(
            "INSERT INTO openmettle.gateway_requests
                 (id,reservation_id,scope_id,actor_user_id,approval_id,session_id,installation,
                  model,units,dispatch_hash)
             VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,repeat('S',43),$6::uuid,'a',100,
                     sha256('sess'))",
        )
        .bind(&req_id)
        .bind(&res_id)
        .bind(&f.scope)
        .bind(&f.actor.user)
        .bind(&f.actor.approval)
        .bind(INSTALL)
        .execute(&mut api)
        .await
        .unwrap();
        let settings = f.db.settings(Duration::from_secs(10));
        let err = migrate::apply(&settings, MIGRATIONS)
            .await
            .expect_err("caller-session gateway_requests row must block migration 37");
        assert!(err.to_string().contains("23514"), "{err:?}");
        assert_eq!(f.db.history().await, versions_through(36));
    }

    // 1c. Caller-session `gateway_reservations` (`run_id IS NULL`) alone blocks migration 37.
    {
        let mut f = Rounds::at(36).await;
        sqlx::query(
            "INSERT INTO openmettle.gateway_reservations (id,scope_id,actor_user_id,approval_id,units)
             VALUES (gen_random_uuid(),$1::uuid,$2::uuid,$3::uuid,100)",
        )
        .bind(&f.scope)
        .bind(&f.actor.user)
        .bind(&f.actor.approval)
        .execute(&mut f.owner)
        .await
        .unwrap();
        let settings = f.db.settings(Duration::from_secs(10));
        let err = migrate::apply(&settings, MIGRATIONS)
            .await
            .expect_err("caller-session gateway_reservations row must block migration 37");
        assert!(err.to_string().contains("23514"), "{err:?}");
        assert_eq!(f.db.history().await, versions_through(36));
    }

    // 1d. Caller-priced `gateway_usage_reports` (`cost`/`unit IS NOT NULL`) blocks migration 37.
    {
        let mut f = Rounds::at(36).await;
        let round = f.round(&plain).await;
        f.authorized(&round, "priced").await;
        assert_eq!(f.dispatch(&round).await, [f.routed()]);
        f.owner
            .execute(
                "ALTER TABLE openmettle.gateway_usage_reports
                 DISABLE TRIGGER gateway_usage_reports_bound_cost_guard",
            )
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.gateway_usage_reports
                 (request_id,source,report_id,revision,final,prompt_tokens,completion_tokens,cost,unit)
             VALUES ($1::uuid,$2::uuid,$1::uuid,1,true,10,5,99,'usd_micros')",
        )
        .bind(&round.request)
        .bind(INSTALL)
        .execute(&mut f.owner)
        .await
        .unwrap();
        f.owner
            .execute(
                "ALTER TABLE openmettle.gateway_usage_reports
                 ENABLE TRIGGER gateway_usage_reports_bound_cost_guard",
            )
            .await
            .unwrap();
        let settings = f.db.settings(Duration::from_secs(10));
        let err = migrate::apply(&settings, MIGRATIONS)
            .await
            .expect_err("caller-priced gateway_usage_reports row must block migration 37");
        assert!(err.to_string().contains("23514"), "{err:?}");
        assert_eq!(f.db.history().await, versions_through(36));
    }

    // 2. Populated `36 -> 37` upgrade preserves settled, swept, and in-flight run rounds,
    //    replays accepted pre-37 reports as `Outcome::Duplicate`, and settles in-flight rounds
    //    cleanly after upgrade with zero accounting drift.
    let mut f = Rounds::at(36).await;
    enable_cost_metering_defaults(&mut f.owner, 1_000_000).await;
    let worker_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(WORKER));
    let gw_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_lazy_with(f.db.1.options(pg::GATEWAY));
    let std_cb = CostBound {
        fixed_micros: 50,
        micros_per_token: 1,
    };
    let fx = quotas::TurnHandoffFixture::chat_priced(INSTALL, "a", 100, std_cb, false);

    // Round 1: settled before upgrade.
    let (run1, claim1) = admit_and_claim_priced(&mut f, 100, Some(std_cb), 1, true).await;
    let p1 = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &run1,
            round: 1,
            claim_token: &claim1,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(150),
            cost_bound: Some(std_cb),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let _d1 = p1
        .handoff(&worker_pool, None, &fx.billable(), fx.prepare_mode(true))
        .await
        .unwrap();
    let b1_raw = [0x39_u8; 32];
    sqlx::query(
        "UPDATE openmettle.gateway_requests SET bearer_hash = sha256($2) WHERE id = $1::uuid",
    )
    .bind(&p1.id)
    .bind(b1_raw.as_slice())
    .execute(&mut f.owner)
    .await
    .unwrap();
    let d1_rows: Vec<ScopedDispatched> = sqlx::query_as(DISPATCH_SCOPED)
        .bind(&p1.id)
        .bind(b1_raw.as_slice())
        .fetch_all(&gw_pool)
        .await
        .unwrap();
    assert_eq!(d1_rows.len(), 1);
    assert!(!d1_rows[0].0);
    let report1 = UsageReport {
        request: p1.id.clone(),
        installation: INSTALL.into(),
        principal: f.actor.user.clone(),
        scope: f.scope.clone(),
        source: INSTALL.into(),
        report_id: p1.id.clone(),
        revision: 1,
        r#final: true,
        prompt_tokens: Some(17),
        completion_tokens: Some(2),
        reasoning_tokens: None,
        reasoning_included: None,
        cost: None,
        unit: None,
    };
    assert_eq!(
        settlement::ingest(&gw_pool, &report1).await,
        Ok(Outcome::Applied)
    );

    // Round 2: dispatched before upgrade, settled AFTER upgrade via `gateway_settle_report`.
    let (run2, claim2) = admit_and_claim_priced(&mut f, 100, Some(std_cb), 1, true).await;
    let p2 = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &run2,
            round: 1,
            claim_token: &claim2,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(150),
            cost_bound: Some(std_cb),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let _d2 = p2
        .handoff(&worker_pool, None, &fx.billable(), fx.prepare_mode(true))
        .await
        .unwrap();
    let b2_raw = [0x3a_u8; 32];
    sqlx::query(
        "UPDATE openmettle.gateway_requests SET bearer_hash = sha256($2) WHERE id = $1::uuid",
    )
    .bind(&p2.id)
    .bind(b2_raw.as_slice())
    .execute(&mut f.owner)
    .await
    .unwrap();
    let d2_rows: Vec<ScopedDispatched> = sqlx::query_as(DISPATCH_SCOPED)
        .bind(&p2.id)
        .bind(b2_raw.as_slice())
        .fetch_all(&gw_pool)
        .await
        .unwrap();
    assert_eq!(d2_rows.len(), 1);
    assert!(!d2_rows[0].0);

    // Round 3: swept `not_dispatched` before upgrade.
    let (run3, claim3) = admit_and_claim_priced(&mut f, 100, Some(std_cb), 1, true).await;
    let p3 = gateway::reserve_turn_round(
        &worker_pool,
        TurnRound {
            scope_id: &f.scope,
            actor: &f.actor.user,
            approval: &f.actor.approval,
            run_id: &run3,
            round: 1,
            claim_token: &claim3,
            installation: INSTALL,
            model: "a",
            round_tokens: 100,
            round_cost: Some(150),
            cost_bound: Some(std_cb),
            requires_device_slot: false,
        },
    )
    .await
    .unwrap();
    let _d3 = p3
        .handoff(&worker_pool, None, &fx.billable(), fx.prepare_mode(true))
        .await
        .unwrap();
    f.owner_exec(
        "UPDATE openmettle.runs SET state = 'failed' WHERE id = $1::uuid",
        &run3,
    )
    .await;
    let mut worker_c = connect(&f.db.0, WORKER).await;
    assert_eq!(
        sqlx::query_scalar::<_, Option<String>>(SWEEP_CLOSE)
            .bind(&p3.id)
            .fetch_one(&mut worker_c)
            .await
            .unwrap()
            .as_deref(),
        Some("not_dispatched")
    );

    // Apply migration 37 cleanly!
    let settings = f.db.settings(Duration::from_secs(10));
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(f.db.history().await, all_versions());

    // Exact replay of accepted pre-37 report returns Duplicate via `gateway_settle_report`.
    assert_eq!(
        settlement::ingest(&gw_pool, &report1).await,
        Ok(Outcome::Duplicate)
    );
    // In-flight pre-37 dispatched round settles cleanly via `gateway_settle_report`.
    let report2 = UsageReport {
        request: p2.id.clone(),
        installation: INSTALL.into(),
        principal: f.actor.user.clone(),
        scope: f.scope.clone(),
        source: INSTALL.into(),
        report_id: p2.id.clone(),
        revision: 1,
        r#final: true,
        prompt_tokens: Some(25),
        completion_tokens: Some(5),
        reasoning_tokens: None,
        reasoning_included: None,
        cost: None,
        unit: None,
    };
    assert_eq!(
        settlement::ingest(&gw_pool, &report2).await,
        Ok(Outcome::Applied)
    );
    let r2_cost: String = sqlx::query_scalar(
        "SELECT settled_units::text FROM openmettle.quota_reservations
          WHERE gateway_request_id = $1::uuid AND resource_kind = 'usage_cost_micros'",
    )
    .bind(&p2.id)
    .fetch_one(&mut f.owner)
    .await
    .unwrap();
    assert_eq!(r2_cost, "80");

    let drift: (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT storage_mismatches, budget_mismatches, settlement_mismatches,
                pending_gateway_reconciliations
           FROM openmettle.quota_verify_accounting_drift()",
    )
    .fetch_one(&mut worker_c)
    .await
    .unwrap();
    assert_eq!(drift, (0, 0, 0, 0));
}
