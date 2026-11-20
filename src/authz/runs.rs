//! Worker execution-time recheck and live run invalidation (ADR 0027 PR5), and durable run
//! admission, the fair work-queue claim, caller cancellation and queue expiry (ADR 0032).
//!
//! [`recheck_run`] works as `openmettle_worker` or `openmettle_api`. In one READ COMMITTED
//! transaction it locks the run row, re-hydrates the run owner from the primary, decides with
//! [`super::authorize_run_continuation`] and, on a denial, moves the run to `cancelled`. It never
//! reads `account_admins`, `project_settings`, `authorization_audit` or any session or secret
//! column. Logging out never cancels a run: the originating session is not consulted.
//!
//! The worker cannot observe project archive or delete, because it has no `SELECT` on
//! `project_settings`. The API therefore cancels the affected non-terminal runs in the same
//! transaction as `archive_project`, `delete_project` and `disable_user`.
//!
//! # Lock order
//!
//! - [`recheck_run`] locks exactly one run row `FOR NO KEY UPDATE`. Afterwards it only reads
//!   without row locks and updates the row it already holds. It never waits while holding a
//!   run lock, so it cannot close a wait cycle.
//! - Bulk cancellation is the last statement of `archive_project` and `delete_project` (after
//!   the project row lock) and of `disable_user` (after `account_admin_lock` and the user row).
//!   It locks every affected run row in ascending `id` order before updating any. Overlapping
//!   bulk cancellations therefore acquire their shared rows in the same order.
//! - No path locks a run row and then waits on a project, user or `account_admin_lock` row.
//! - [`admit_run`] locks the project row (or the personal owner's user row), then the actor's
//!   user row, then inserts the new run, which no other transaction sees until it commits.
//! - [`claim_next`] locks `run_dispatch_lock`, then one run row with `SKIP LOCKED`, so it never
//!   waits on a run lock while holding the dispatch lock. [`expire_queued`] locks run rows with
//!   `SKIP LOCKED` in ascending `id` order. [`cancel_run`] locks one run row.
//!
//! Every terminal transition made here appends exactly one terminal event under the append key
//! `run-terminal`, in the transaction that sets the state.
use super::{
    CapabilityGate, DenialReason, PlatformPolicy, Principal, Resource, ResourceKind, RunAuthority,
    RunContinuation, Scope, projects,
    store::{self, KEY_REUSED, StoreError, uuid},
};
use crate::runs::{self as durable, AdmissionColumns, Payload, RunInput, WriteTransaction};
use sqlx::PgConnection;
use std::time::Duration;

/// Run states after which no recheck or cancellation changes the row (ADR 0004 vocabulary).
pub const TERMINAL_STATES: [&str; 4] = ["succeeded", "failed", "cancelled", "interrupted"];

/// `queued`, `running`, `waiting`, `cancelling` and `reconciling` are not terminal.
pub fn is_terminal(state: &str) -> bool {
    TERMINAL_STATES.contains(&state)
}

// Keep in step with `TERMINAL_STATES`; the unit tests compare them.
macro_rules! non_terminal {
    () => {
        "state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')"
    };
}

const LOCK_RUN: &str = "SELECT actor_user_id::text, conversation_id::text, state
   FROM openmettle.runs WHERE scope_id = $1::uuid AND id = $2::uuid FOR NO KEY UPDATE";

const CANCEL_ONE: &str = concat!(
    "UPDATE openmettle.runs SET state = 'cancelled', wait_reason = NULL
      WHERE scope_id = $1::uuid AND id = $2::uuid AND ",
    non_terminal!()
);

// The materialized CTE locks every affected row in ascending ID order before any is updated.
// Both bulk statements return the cancelled `(scope_id, id)` pairs for their terminal events.
const CANCEL_SCOPE: &str = concat!(
    "WITH doomed AS MATERIALIZED (
       SELECT id FROM openmettle.runs WHERE scope_id = $1::uuid AND ",
    non_terminal!(),
    " ORDER BY id FOR NO KEY UPDATE)
     UPDATE openmettle.runs r SET state = 'cancelled', wait_reason = NULL
       FROM doomed WHERE r.id = doomed.id AND r.",
    non_terminal!(),
    " RETURNING r.scope_id::text, r.id::text"
);

const CANCEL_USER: &str = concat!(
    "WITH doomed AS MATERIALIZED (
       SELECT id FROM openmettle.runs WHERE actor_user_id = $1::uuid AND ",
    non_terminal!(),
    " ORDER BY id FOR NO KEY UPDATE)
     UPDATE openmettle.runs r SET state = 'cancelled', wait_reason = NULL
       FROM doomed WHERE r.id = doomed.id AND r.",
    non_terminal!(),
    " RETURNING r.scope_id::text, r.id::text"
);

/// The append key of the one terminal event a run may have (ADR 0032).
const TERMINAL_KEY: &str = "run-terminal";
const CANCEL_REQUESTED: Payload<'static> = Payload {
    format: "openmettle.run-cancelled",
    version: 1,
    bytes: br#"{"reason":"requested"}"#,
};
const CANCEL_REVOKED: Payload<'static> = Payload {
    format: "openmettle.run-cancelled",
    version: 1,
    bytes: br#"{"reason":"revoked"}"#,
};
const EXPIRED: Payload<'static> = Payload {
    format: "openmettle.run-expired",
    version: 1,
    bytes: b"{}",
};
const CLAIMED: Payload<'static> = Payload {
    format: "openmettle.run-claimed",
    version: 1,
    bytes: b"{}",
};

/// One capability the next run step uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityUse<'a> {
    pub name: &'a str,
    pub gate: CapabilityGate,
}

/// One execution-time recheck, before dispatch and before each tool or provider step.
#[derive(Clone, Copy, Debug)]
pub struct RunRecheckRequest<'a> {
    pub scope_id: &'a str,
    pub run_id: &'a str,
    /// The identity approval the run was admitted under. An approval that is not one of the
    /// run owner's reads as inactive and invalidates the run: it fails closed.
    pub actor_approval_id: &'a str,
    pub capabilities: &'a [CapabilityUse<'a>],
    /// A conversation or artifact the step writes besides the run's conversation. It needs the
    /// same `RunExecute` (write) access and must be in the run's scope.
    pub extra_target: Option<(ResourceKind, &'a str)>,
    pub now_ms: i64,
}

impl RunRecheckRequest<'_> {
    /// Input checks, made before any database work.
    pub fn validate(&self) -> Result<(), StoreError> {
        uuid(self.scope_id, "scope_id")?;
        uuid(self.run_id, "run_id")?;
        uuid(self.actor_approval_id, "actor_approval_id")?;
        if !self
            .capabilities
            .iter()
            .all(|c| super::valid_capability(c.name))
        {
            return Err(StoreError::InvalidInput("capability"));
        }
        if let Some((kind, id)) = self.extra_target {
            if !kind.shareable() {
                return Err(StoreError::InvalidInput("resource kind"));
            }
            uuid(id, "resource_id")?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunRecheckOutcome {
    /// Authorized at this observation; the run row is unchanged. Recheck at the next step.
    Continue,
    /// This recheck moved the run to `cancelled` with no wait reason. It is not retried.
    Invalidated(DenialReason),
    /// The run was already terminal, for example cancelled by the API. Nothing changed.
    Terminal { state: String },
}

/// Recheck one run on the primary and cancel it when its owner no longer holds the authority
/// it needs. `NotFound` means no run with this ID exists in this scope.
pub async fn recheck_run(
    c: &mut PgConnection,
    request: &RunRecheckRequest<'_>,
) -> Result<RunRecheckOutcome, StoreError> {
    request.validate()?;
    transaction(c, async |c| recheck_locked(c, request).await).await
}

/// One bounded READ COMMITTED transaction ([`store::begin`]): commit on success, roll back
/// otherwise.
async fn transaction<T>(
    c: &mut PgConnection,
    body: impl AsyncFnOnce(&mut PgConnection) -> Result<T, StoreError>,
) -> Result<T, StoreError> {
    let mut tx = store::begin(c).await?;
    let result = match tx.connection() {
        Ok(c) => body(c).await,
        Err(error) => Err(error.into()),
    };
    match result {
        Ok(value) => {
            tx.commit().await?;
            Ok(value)
        }
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}

/// Append an event to a run whose row this transaction holds. `Conflict` means a different
/// event is already recorded under `key`.
async fn append(
    c: &mut PgConnection,
    scope_id: &str,
    run_id: &str,
    key: &str,
    payload: Payload<'_>,
) -> Result<(), StoreError> {
    match durable::append_to_locked_run(c, scope_id, run_id, key, payload).await {
        Ok(_) => Ok(()),
        Err(durable::Error::Conflict) => Err(StoreError::Conflict("run event already recorded")),
        Err(error) => Err(error.into()),
    }
}

/// The run's one terminal event; the caller has just made the locked run terminal.
async fn terminal_event(
    c: &mut PgConnection,
    scope_id: &str,
    run_id: &str,
    payload: Payload<'_>,
) -> Result<(), StoreError> {
    append(c, scope_id, run_id, TERMINAL_KEY, payload).await
}

async fn recheck_locked(
    c: &mut PgConnection,
    r: &RunRecheckRequest<'_>,
) -> Result<RunRecheckOutcome, StoreError> {
    let (owner, conversation, state): (String, String, String) = sqlx::query_as(LOCK_RUN)
        .bind(r.scope_id)
        .bind(r.run_id)
        .fetch_optional(&mut *c)
        .await?
        .ok_or(StoreError::NotFound)?;
    if is_terminal(&state) {
        return Ok(RunRecheckOutcome::Terminal { state });
    }
    let principal =
        store::hydrate_worker_principal(c, &owner, r.actor_approval_id, r.now_ms).await?;
    let platform = store::load_platform_capabilities(c).await?;
    let scope = run_scope(c, r.scope_id, r.now_ms).await?;
    let target =
        projects::hydrate_resource(c, ResourceKind::Conversation, &conversation, r.now_ms).await?;
    let extra = match r.extra_target {
        Some((kind, id)) => Some(projects::hydrate_resource(c, kind, id, r.now_ms).await?),
        None => None,
    };
    let capabilities = r
        .capabilities
        .iter()
        .map(|c| (c.name.to_owned(), c.gate))
        .collect();
    let decision = evaluate(
        principal.as_ref(),
        &platform,
        scope,
        target,
        extra,
        capabilities,
    );
    let RunContinuation::Invalidate(reason) = decision else {
        return Ok(RunRecheckOutcome::Continue);
    };
    // The row is locked and non-terminal, so exactly this run changes.
    sqlx::query(CANCEL_ONE)
        .bind(r.scope_id)
        .bind(r.run_id)
        .execute(&mut *c)
        .await?;
    terminal_event(c, r.scope_id, r.run_id, CANCEL_REVOKED).await?;
    Ok(RunRecheckOutcome::Invalidated(reason))
}

/// The run's own scope, hydrated independently of its target so that a target outside it is
/// concealed. `None` if the scope row is missing or names neither a user nor a project.
async fn run_scope(
    c: &mut PgConnection,
    scope_id: &str,
    now_ms: i64,
) -> Result<Option<Scope>, StoreError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT personal_user_id::text, project_id::text FROM openmettle.scopes
          WHERE id = $1::uuid",
    )
    .bind(scope_id)
    .fetch_optional(&mut *c)
    .await?;
    Ok(match row {
        Some((Some(owner_user_id), _)) => Some(Scope::Personal {
            scope_id: scope_id.to_owned(),
            owner_user_id,
        }),
        Some((None, Some(project))) => projects::hydrate_project(c, &project, now_ms)
            .await?
            .map(Scope::Project),
        _ => None,
    })
}

/// The pure decision. A missing principal, scope, conversation or requested extra target
/// invalidates; `extra` is `Some(None)` when a requested target does not exist. The
/// originating session is never consulted.
fn evaluate(
    principal: Option<&Principal>,
    platform: &PlatformPolicy,
    scope: Option<Scope>,
    target: Option<Resource>,
    extra: Option<Option<Resource>>,
    capabilities: Vec<(String, CapabilityGate)>,
) -> RunContinuation {
    let owner = match super::require(principal) {
        Ok(owner) => owner,
        Err(reason) => return RunContinuation::Invalidate(reason),
    };
    let (Some(scope), Some(target)) = (scope, target) else {
        return RunContinuation::Invalidate(DenialReason::NotFound);
    };
    let extra = match extra {
        Some(None) => return RunContinuation::Invalidate(DenialReason::NotFound),
        Some(Some(resource)) => Some(resource),
        None => None,
    };
    let mut run = RunAuthority {
        scope,
        target: Some(target),
        capabilities,
        originating_session_active: false,
    };
    let decision = super::authorize_run_continuation(owner, platform, &run);
    match (decision, extra) {
        (RunContinuation::Continue, Some(extra)) => {
            run.target = Some(extra);
            run.capabilities.clear();
            super::authorize_run_continuation(owner, platform, &run)
        }
        (decision, _) => decision,
    }
}

/// Cancel every non-terminal run in one scope, as `openmettle_api`, each with its terminal
/// event. Call it as the last statement of a project archive or delete, after the project row
/// lock.
pub(super) async fn cancel_scope_runs(
    c: &mut PgConnection,
    scope_id: &str,
) -> Result<u64, StoreError> {
    cancel_revoked(c, CANCEL_SCOPE, scope_id).await
}

/// Cancel every non-terminal run the user owns, as `openmettle_api`, each with its terminal
/// event. Call it as the last statement of a user disablement, after `account_admin_lock` and
/// the user row lock.
pub(super) async fn cancel_user_runs(
    c: &mut PgConnection,
    user_id: &str,
) -> Result<u64, StoreError> {
    cancel_revoked(c, CANCEL_USER, user_id).await
}

/// Append one terminal event per cancelled run, in ascending run ID order. The statement already
/// holds every returned row, so the appends take no new run lock.
async fn cancel_revoked(
    c: &mut PgConnection,
    sql: &'static str,
    id: &str,
) -> Result<u64, StoreError> {
    let cancelled: Vec<(String, String)> = sqlx::query_as(sql).bind(id).fetch_all(&mut *c).await?;
    terminal_events(c, cancelled, CANCEL_REVOKED).await
}

async fn terminal_events(
    c: &mut PgConnection,
    mut runs: Vec<(String, String)>,
    payload: Payload<'_>,
) -> Result<u64, StoreError> {
    runs.sort_by(|a, b| a.1.cmp(&b.1));
    for (scope_id, run_id) in &runs {
        terminal_event(c, scope_id, run_id, payload).await?;
    }
    Ok(runs.len() as u64)
}

// --- admission (ADR 0032, `openmettle_api`) ----------------------------------------------------

/// Deployment admission limits, validated before any query. There are no defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionLimits {
    /// Live (non-terminal) runs per actor, 1 to 1000. Exact.
    pub live_per_actor: u32,
    /// Live runs per scope, 1 to 10 000. Exact.
    pub live_per_scope: u32,
    /// Queued runs in the instance, 1 to 10 000. May overshoot by the number of concurrent
    /// admission transactions.
    pub queued_in_instance: u32,
    /// 1 s to 24 h, measured on the database clock from admission.
    pub queue_timeout: Duration,
    /// Per-turn round cap, 1 to 1000.
    pub round_cap: i32,
}

impl AdmissionLimits {
    /// Range checks, made before any database work.
    pub fn validate(&self) -> Result<(), StoreError> {
        let timeouts = Duration::from_secs(1)..=Duration::from_secs(86_400);
        for (valid, field) in [
            ((1..=1000).contains(&self.live_per_actor), "live_per_actor"),
            (
                (1..=10_000).contains(&self.live_per_scope),
                "live_per_scope",
            ),
            (
                (1..=10_000).contains(&self.queued_in_instance),
                "queued_in_instance",
            ),
            (timeouts.contains(&self.queue_timeout), "queue_timeout"),
            ((1..=1000).contains(&self.round_cap), "round_cap"),
        ] {
            if !valid {
                return Err(StoreError::InvalidInput(field));
            }
        }
        Ok(())
    }
}

/// The stored round limit: the requested count capped at `cap`, or `cap` when none was
/// requested. A request below 1 is refused.
pub fn effective_round_limit(requested: Option<i64>, cap: i32) -> Result<i32, StoreError> {
    match requested {
        None => Ok(cap),
        // `cap` fits in i32, so the minimum does too.
        Some(rounds) if rounds >= 1 => Ok(rounds.min(i64::from(cap)) as i32),
        Some(_) => Err(StoreError::InvalidInput("round_limit")),
    }
}

/// One run admission. `input.actor` is the user authenticated by the session whose approval is
/// `actor_approval_id`.
pub struct RunAdmission<'a> {
    pub input: RunInput<'a>,
    pub actor_approval_id: &'a str,
    /// The capabilities the run needs, decided now and again at every recheck.
    pub capabilities: &'a [CapabilityUse<'a>],
    /// The round count the caller validated from its request, if any.
    pub requested_rounds: Option<i64>,
    pub now_ms: i64,
}

impl RunAdmission<'_> {
    /// Input checks, made before any database work.
    pub fn validate(&self) -> Result<(), StoreError> {
        durable::run_identity(&self.input).map_err(|_| StoreError::InvalidInput("run input"))?;
        uuid(self.actor_approval_id, "actor_approval_id")?;
        if !self
            .capabilities
            .iter()
            .all(|c| super::valid_capability(c.name))
        {
            return Err(StoreError::InvalidInput("capability"));
        }
        Ok(())
    }
}

/// The limit that refused an admission. Nothing was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunLimit {
    /// The actor's live runs are at the limit (429 `rate_limited`).
    ActorLimit,
    /// The scope's live runs are at the limit (429 `rate_limited`).
    ScopeLimit,
    /// The instance queue is full (503 `unavailable`).
    QueueFull,
}

/// Commit the caller's transaction only after `Admitted`, and roll it back otherwise: a replay
/// or refusal must not keep an input message the caller inserted for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    /// A new `queued` run and its `run-created` event, written in the caller's transaction.
    Admitted {
        run_id: String,
        round_limit: i32,
    },
    /// This request was admitted before. Nothing was written and no limit was checked.
    /// `round_limit` is `None` for a run written by bare `create_run` or before migration 19.
    Replayed {
        run_id: String,
        state: String,
        round_limit: Option<i32>,
    },
    Refused(RunLimit),
}

/// The recorded run of one actor's idempotency key in one scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunReplay {
    pub run_id: String,
    pub state: String,
    pub round_limit: Option<i32>,
    pub conversation_id: String,
    pub branch_id: String,
    /// Reuse it on retry: the input message is part of the run identity (ADR 0004).
    pub input_message_id: String,
    request_identity: Vec<u8>,
    request_digest: Vec<u8>,
}

impl RunReplay {
    /// Whether `input` is exactly the recorded request. Admission decisions are not compared.
    pub fn matches(&self, input: &RunInput<'_>) -> bool {
        durable::run_identity(input).is_ok_and(|identity| {
            durable::digest(&identity) == self.request_digest && identity == self.request_identity
        })
    }
}

/// The read-only replay lookup of admission step 4. V1-07 calls it before inserting a new input
/// message so a retry reuses the original input identity; [`admit_run`] repeats it under its
/// locks. `actor_user_id` is the authenticated caller: only their own run is returned.
pub async fn find_run(
    c: &mut PgConnection,
    scope_id: &str,
    actor_user_id: &str,
    idempotency_key: &str,
) -> Result<Option<RunReplay>, StoreError> {
    uuid(scope_id, "scope_id")?;
    uuid(actor_user_id, "actor_user_id")?;
    if !durable::bounded(idempotency_key, 128) {
        return Err(StoreError::InvalidInput("idempotency_key"));
    }
    lookup(c, scope_id, actor_user_id, idempotency_key).await
}

type ReplayRow = (
    String,
    String,
    Option<i32>,
    String,
    String,
    String,
    Vec<u8>,
    Vec<u8>,
);

async fn lookup(
    c: &mut PgConnection,
    scope_id: &str,
    actor_user_id: &str,
    idempotency_key: &str,
) -> Result<Option<RunReplay>, StoreError> {
    let row: Option<ReplayRow> = sqlx::query_as(
        "SELECT id::text, state, round_limit, conversation_id::text, branch_id::text,
                input_message_id::text, request_identity, request_digest
           FROM openmettle.runs
          WHERE scope_id = $1::uuid AND actor_user_id = $2::uuid AND idempotency_key = $3",
    )
    .bind(scope_id)
    .bind(actor_user_id)
    .bind(idempotency_key)
    .fetch_optional(c)
    .await?;
    Ok(row.map(
        |(run_id, state, round_limit, conversation, branch, message, i, d)| RunReplay {
            run_id,
            state,
            round_limit,
            conversation_id: conversation,
            branch_id: branch,
            input_message_id: message,
            request_identity: i,
            request_digest: d,
        },
    ))
}

// Each bounded count repeats its partial index predicate verbatim.
const LIVE_COUNTS: &str = concat!(
    "SELECT (SELECT count(*) FROM (SELECT 1 FROM openmettle.runs
              WHERE actor_user_id = $1::uuid AND ",
    non_terminal!(),
    " LIMIT $3) a),
            (SELECT count(*) FROM (SELECT 1 FROM openmettle.runs
              WHERE scope_id = $2::uuid AND ",
    non_terminal!(),
    " LIMIT $4) s),
            (SELECT count(*) FROM (SELECT 1 FROM openmettle.runs
              WHERE ",
    non_terminal!(),
    " AND state = 'queued' LIMIT $5) q)"
);

const LOCK_USER: &str = "SELECT FROM openmettle.users WHERE id = $1::uuid FOR NO KEY UPDATE";

/// Admit one run in the caller's READ COMMITTED transaction (ADR 0032): lock the scope and the
/// actor, authorize, replay, check the lifecycle and the limits, then insert the `queued` run
/// with its approval, effective round limit and queue deadline, and its `run-created` event.
///
/// A missing scope, a deleted or invisible project or conversation is `Denied(NotFound)`; an
/// inactive actor, a missing role or capability is `Denied`; another request under a recorded
/// key is `Conflict(KEY_REUSED)`; an archived project is `Conflict(ARCHIVED)`. Sets
/// `lock_timeout` and `statement_timeout` for the rest of the caller's transaction.
pub async fn admit_run(
    tx: &mut WriteTransaction<'_>,
    request: &RunAdmission<'_>,
    limits: &AdmissionLimits,
) -> Result<Admission, StoreError> {
    limits.validate()?;
    request.validate()?;
    let round_limit = effective_round_limit(request.requested_rounds, limits.round_cap)?;
    let r = &request.input;
    let now = request.now_ms;
    let c = tx.connection()?;
    // Exact limits rely on each statement after a lock seeing every earlier commit.
    let (_, _, isolation): (String, String, String) = sqlx::query_as(
        "SELECT set_config('lock_timeout', '2s', true), set_config('statement_timeout', '3s', true),
                current_setting('transaction_isolation')",
    )
    .fetch_one(&mut *c)
    .await?;
    if isolation != "read committed" {
        return Err(StoreError::InvalidInput("transaction isolation"));
    }
    let (personal_owner, project_id): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT personal_user_id::text, project_id::text FROM openmettle.scopes
          WHERE id = $1::uuid",
    )
    .bind(r.scope)
    .fetch_optional(&mut *c)
    .await?
    .unwrap_or_default();
    // Steps 1 and 2: the scope row, then the actor's row. In a personal scope the owner is the
    // only actor `RunExecute` admits, so the first lock covers both.
    if let Some(owner) = &personal_owner {
        sqlx::query(LOCK_USER).bind(owner).execute(&mut *c).await?;
    } else if let Some(project) = &project_id {
        sqlx::query("SELECT FROM openmettle.projects WHERE id = $1::uuid FOR NO KEY UPDATE")
            .bind(project)
            .execute(&mut *c)
            .await?;
        sqlx::query(LOCK_USER)
            .bind(r.actor)
            .execute(&mut *c)
            .await?;
    }
    // Step 3: authorize after the locks with the recheck's decision.
    let principal =
        store::hydrate_api_principal(c, r.actor, request.actor_approval_id, now).await?;
    let platform = store::load_platform_capabilities(c).await?;
    let (scope, archived) = match (personal_owner, project_id) {
        (Some(owner_user_id), _) => (
            Some(Scope::Personal {
                scope_id: r.scope.to_owned(),
                owner_user_id,
            }),
            false,
        ),
        (None, Some(project)) => match projects::load_project_settings(c, &project).await? {
            Some(settings) if !settings.deleted => (
                projects::hydrate_project(c, &project, now)
                    .await?
                    .map(Scope::Project),
                settings.archived,
            ),
            _ => (None, false),
        },
        (None, None) => (None, false),
    };
    let target =
        projects::hydrate_resource(c, ResourceKind::Conversation, r.conversation, now).await?;
    let capabilities = request
        .capabilities
        .iter()
        .map(|c| (c.name.to_owned(), c.gate))
        .collect();
    let decision = evaluate(
        principal.as_ref(),
        &platform,
        scope,
        target,
        None,
        capabilities,
    );
    if let RunContinuation::Invalidate(reason) = decision {
        return Err(StoreError::Denied(reason));
    }
    // Step 4: an exact replay is returned whatever the lifecycle or the current limits.
    if let Some(replay) = lookup(c, r.scope, r.actor, r.key).await? {
        return replayed(replay, r);
    }
    // Steps 5 and 6.
    if archived {
        return Err(projects::ARCHIVED);
    }
    let (actor_live, scope_live, queued): (i64, i64, i64) = sqlx::query_as(LIVE_COUNTS)
        .bind(r.actor)
        .bind(r.scope)
        .bind(i64::from(limits.live_per_actor))
        .bind(i64::from(limits.live_per_scope))
        .bind(i64::from(limits.queued_in_instance))
        .fetch_one(&mut *c)
        .await?;
    for (count, limit, refusal) in [
        (actor_live, limits.live_per_actor, RunLimit::ActorLimit),
        (scope_live, limits.live_per_scope, RunLimit::ScopeLimit),
        (queued, limits.queued_in_instance, RunLimit::QueueFull),
    ] {
        if count >= i64::from(limit) {
            return Ok(Admission::Refused(refusal));
        }
    }
    // Step 7: the new row is the reservation of the run slot.
    let columns = AdmissionColumns {
        approval: request.actor_approval_id,
        round_limit,
        // At most 24 hours, validated above.
        queue_timeout_ms: limits.queue_timeout.as_millis() as i64,
    };
    let (run_id, inserted) = match durable::insert_run(tx, r, Some(&columns)).await {
        Ok(inserted) => inserted,
        Err(durable::Error::Conflict) => return Err(StoreError::Conflict(KEY_REUSED)),
        Err(error) => return Err(error.into()),
    };
    if !inserted {
        // Only a writer outside these locks (bare `create_run`) can have recorded the key.
        let replay = lookup(tx.connection()?, r.scope, r.actor, r.key).await?;
        return replayed(replay.ok_or(StoreError::NotFound)?, r);
    }
    Ok(Admission::Admitted {
        run_id,
        round_limit,
    })
}

fn replayed(replay: RunReplay, input: &RunInput<'_>) -> Result<Admission, StoreError> {
    if !replay.matches(input) {
        return Err(StoreError::Conflict(KEY_REUSED));
    }
    Ok(Admission::Replayed {
        run_id: replay.run_id,
        state: replay.state,
        round_limit: replay.round_limit,
    })
}

// --- caller cancellation and queue expiry (ADR 0032) -------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CancelOutcome {
    /// This call moved the queued run to `cancelled` with its terminal event.
    Cancelled,
    /// Already terminal and unchanged, so repeating a cancel is idempotent.
    Terminal { state: String },
    /// Started (`running`, `waiting`, `cancelling` or `reconciling`) and unchanged:
    /// cooperative cancellation of started work is V1-11.
    Executing { state: String },
}

/// Cancel a queued run of `principal`, hydrated by the route for this request, as
/// `openmettle_api`. A missing run or another actor's run is concealed (`Denied(NotFound)`).
pub async fn cancel_run(
    c: &mut PgConnection,
    principal: &Principal,
    scope_id: &str,
    run_id: &str,
) -> Result<CancelOutcome, StoreError> {
    super::require(Some(principal)).map_err(StoreError::Denied)?;
    uuid(scope_id, "scope_id")?;
    uuid(run_id, "run_id")?;
    transaction(c, async |c| {
        let row: Option<(String, String, String)> = sqlx::query_as(LOCK_RUN)
            .bind(scope_id)
            .bind(run_id)
            .fetch_optional(&mut *c)
            .await?;
        let Some((_, _, state)) = row.filter(|(actor, _, _)| *actor == principal.user_id) else {
            return Err(StoreError::Denied(DenialReason::NotFound));
        };
        if is_terminal(&state) {
            return Ok(CancelOutcome::Terminal { state });
        }
        if state != "queued" {
            return Ok(CancelOutcome::Executing { state });
        }
        sqlx::query(CANCEL_ONE)
            .bind(scope_id)
            .bind(run_id)
            .execute(&mut *c)
            .await?;
        terminal_event(c, scope_id, run_id, CANCEL_REQUESTED).await?;
        Ok(CancelOutcome::Cancelled)
    })
    .await
}

const EXPIRE: &str = concat!(
    "WITH due AS MATERIALIZED (
       SELECT id FROM openmettle.runs WHERE ",
    non_terminal!(),
    " AND state = 'queued'
         AND (queue_expires_at <= clock_timestamp() OR queue_expires_at IS NULL)
       ORDER BY id LIMIT $1 FOR NO KEY UPDATE SKIP LOCKED)
     UPDATE openmettle.runs r SET state = 'failed', wait_reason = NULL
       FROM due WHERE r.id = due.id AND r.state = 'queued'
     RETURNING r.scope_id::text, r.id::text"
);

/// Fail up to `limit` (1 to 1000) queued runs whose deadline has passed or that have none
/// (written before migration 19 or by bare `create_run`), each with its terminal event, skipping
/// locked rows. Returns the failed run IDs in ascending order. Either role may run it.
pub async fn expire_queued(c: &mut PgConnection, limit: u32) -> Result<Vec<String>, StoreError> {
    if !(1..=1000).contains(&limit) {
        return Err(StoreError::InvalidInput("limit"));
    }
    transaction(c, async |c| {
        let expired: Vec<(String, String)> = sqlx::query_as(EXPIRE)
            .bind(i64::from(limit))
            .fetch_all(&mut *c)
            .await?;
        let mut ids: Vec<String> = expired.iter().map(|(_, run)| run.clone()).collect();
        terminal_events(c, expired, EXPIRED).await?;
        ids.sort();
        Ok(ids)
    })
    .await
}

// --- fair claim (ADR 0032, `openmettle_worker`) ------------------------------------------------

/// Executing limits for [`claim_next`], validated before any query.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClaimLimits {
    /// Executing runs per actor, 1 to 1024.
    pub executing_per_actor: u32,
    /// Executing runs per scope, 1 to 1024.
    pub executing_per_scope: u32,
}

impl ClaimLimits {
    /// Range checks, made before any database work.
    pub fn validate(&self) -> Result<(), StoreError> {
        if !(1..=1024).contains(&self.executing_per_actor) {
            return Err(StoreError::InvalidInput("executing_per_actor"));
        }
        if !(1..=1024).contains(&self.executing_per_scope) {
            return Err(StoreError::InvalidInput("executing_per_scope"));
        }
        Ok(())
    }
}

/// A run this claim moved to `running`. It executes nothing until [`recheck_run`] with
/// `actor_approval_id` returns `Continue`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimedRun {
    pub scope_id: String,
    pub run_id: String,
    pub claim_token: String,
    pub actor_approval_id: String,
    pub round_limit: i32,
}

// Executing means holding a worker: `running`, `cancelling` or `reconciling`, not `waiting`.
// Least-loaded actor first, then FIFO by admission time and ID.
const CLAIM: &str = concat!(
    "WITH executing AS (
       SELECT actor_user_id, scope_id FROM openmettle.runs
        WHERE ",
    non_terminal!(),
    "
          AND state IN ('running', 'cancelling', 'reconciling')
     ), actor_load AS (
       SELECT actor_user_id, count(*) AS n FROM executing GROUP BY actor_user_id
     ), scope_load AS (
       SELECT scope_id, count(*) AS n FROM executing GROUP BY scope_id
     ), next AS (
       SELECT r.id FROM openmettle.runs r
         LEFT JOIN actor_load a ON a.actor_user_id = r.actor_user_id
         LEFT JOIN scope_load s ON s.scope_id = r.scope_id
        WHERE r.",
    non_terminal!(),
    "
          AND r.state = 'queued'
          AND r.queue_expires_at > clock_timestamp()
          AND coalesce(a.n, 0) < $1
          AND coalesce(s.n, 0) < $2
        ORDER BY coalesce(a.n, 0), r.created_at, r.id
        LIMIT 1
        FOR NO KEY UPDATE OF r SKIP LOCKED
     )
     UPDATE openmettle.runs r
        SET state = 'running', claim_token = gen_random_uuid(), claimed_at = clock_timestamp()
       FROM next WHERE r.id = next.id
     RETURNING r.scope_id::text, r.id::text, r.claim_token::text,
               r.actor_approval_id::text, r.round_limit"
);

/// Claim the next queued run fairly in one short transaction, as `openmettle_worker`, with its
/// `openmettle.run-claimed` event under `claim:<claim_token>`. `None` when no run qualifies.
pub async fn claim_next(
    c: &mut PgConnection,
    limits: &ClaimLimits,
) -> Result<Option<ClaimedRun>, StoreError> {
    limits.validate()?;
    transaction(c, async |c| {
        // Claims serialize here, so the next statement's snapshot includes every earlier claim.
        sqlx::query("SELECT FROM openmettle.run_dispatch_lock FOR NO KEY UPDATE")
            .execute(&mut *c)
            .await?;
        let claimed: Option<(String, String, String, String, i32)> = sqlx::query_as(CLAIM)
            .bind(i64::from(limits.executing_per_actor))
            .bind(i64::from(limits.executing_per_scope))
            .fetch_optional(&mut *c)
            .await?;
        let Some((scope_id, run_id, claim_token, actor_approval_id, round_limit)) = claimed else {
            return Ok(None);
        };
        let key = format!("claim:{claim_token}");
        append(c, &scope_id, &run_id, &key, CLAIMED).await?;
        Ok(Some(ClaimedRun {
            scope_id,
            run_id,
            claim_token,
            actor_approval_id,
            round_limit,
        }))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{
        Grant, Origin, PolicyReason, Project, ProjectRole, ResourceAccess, ResourceShare,
    };
    use std::collections::BTreeSet;

    const ID: &str = "00000000-0000-0000-0000-000000000001";
    const OWNER: &str = "00000000-0000-0000-0000-0000000000a1";
    const OTHER: &str = "00000000-0000-0000-0000-0000000000b2";
    const PERSONAL: &str = "00000000-0000-0000-0000-0000000000c1";
    const PROJECT: &str = "00000000-0000-0000-0000-0000000000d1";

    fn request<'a>(capabilities: &'a [CapabilityUse<'a>]) -> RunRecheckRequest<'a> {
        RunRecheckRequest {
            scope_id: ID,
            run_id: ID,
            actor_approval_id: ID,
            capabilities,
            extra_target: None,
            now_ms: 1,
        }
    }

    fn owner() -> Principal {
        Principal {
            user_id: OWNER.into(),
            personal_scope_id: PERSONAL.into(),
            account_active: true,
            approval_active: true,
            provider_active: true,
            ..Principal::default()
        }
    }

    fn personal() -> Scope {
        Scope::Personal {
            scope_id: PERSONAL.into(),
            owner_user_id: OWNER.into(),
        }
    }

    fn project(role: ProjectRole) -> Scope {
        Scope::Project(Project {
            id: PROJECT.into(),
            grants: vec![Grant {
                grantee: crate::authz::Grantee::User(OWNER.into()),
                permission: role,
                origin: Origin::Direct,
                recorded_active: true,
            }],
        })
    }

    fn resource(kind: ResourceKind, scope: Scope, creator: &str) -> Resource {
        Resource {
            kind,
            id: ID.into(),
            creator_user_id: creator.into(),
            scope,
            shares: Vec::new(),
        }
    }

    fn shared(mut r: Resource, access: ResourceAccess) -> Resource {
        let share: ResourceShare = Grant {
            grantee: crate::authz::Grantee::User(OWNER.into()),
            permission: access,
            origin: Origin::Direct,
            recorded_active: true,
        };
        r.shares.push(share);
        r
    }

    fn decide(
        principal: Option<&Principal>,
        scope: Option<Scope>,
        target: Option<Resource>,
        extra: Option<Option<Resource>>,
        capabilities: &[(&str, CapabilityGate)],
    ) -> RunContinuation {
        let platform = PlatformPolicy::default();
        let capabilities = capabilities
            .iter()
            .map(|(n, g)| ((*n).to_owned(), *g))
            .collect();
        evaluate(principal, &platform, scope, target, extra, capabilities)
    }

    fn invalid(reason: DenialReason) -> RunContinuation {
        RunContinuation::Invalidate(reason)
    }

    #[test]
    fn terminal_states_match_the_adr_0004_vocabulary_and_the_sql_predicate() {
        for state in ["succeeded", "failed", "cancelled", "interrupted"] {
            assert!(is_terminal(state), "{state}");
            assert!(non_terminal!().contains(&format!("'{state}'")), "{state}");
        }
        for state in ["queued", "running", "waiting", "cancelling", "reconciling"] {
            assert!(!is_terminal(state), "{state}");
            assert!(!non_terminal!().contains(&format!("'{state}'")), "{state}");
        }
        for state in ["", "Cancelled", "cancelled ", "done"] {
            assert!(!is_terminal(state), "{state:?}");
        }
        for sql in [CANCEL_ONE, CANCEL_SCOPE, CANCEL_USER] {
            assert!(
                sql.contains("state = 'cancelled', wait_reason = NULL"),
                "{sql}"
            );
        }
        for sql in [CANCEL_SCOPE, CANCEL_USER] {
            assert!(sql.contains("ORDER BY id FOR NO KEY UPDATE"), "{sql}");
            assert!(sql.contains("AS MATERIALIZED"), "{sql}");
        }
    }

    #[test]
    fn requests_are_validated_before_any_database_work() {
        let yolo = [CapabilityUse {
            name: "runs.use_yolo",
            gate: CapabilityGate::OptIn,
        }];
        assert!(request(&yolo).validate().is_ok());
        let artifact = RunRecheckRequest {
            extra_target: Some((ResourceKind::Artifact, ID)),
            ..request(&[])
        };
        assert!(artifact.validate().is_ok());
        for bad in ["", "not-a-uuid", "00000000-0000-0000-0000-00000000000A"] {
            for (field, r) in [
                (
                    "scope_id",
                    RunRecheckRequest {
                        scope_id: bad,
                        ..request(&[])
                    },
                ),
                (
                    "run_id",
                    RunRecheckRequest {
                        run_id: bad,
                        ..request(&[])
                    },
                ),
                (
                    "actor_approval_id",
                    RunRecheckRequest {
                        actor_approval_id: bad,
                        ..request(&[])
                    },
                ),
                (
                    "resource_id",
                    RunRecheckRequest {
                        extra_target: Some((ResourceKind::Artifact, bad)),
                        ..request(&[])
                    },
                ),
            ] {
                assert!(
                    matches!(r.validate(), Err(StoreError::InvalidInput(f)) if f == field),
                    "{field} {bad:?}"
                );
            }
        }
        let long = "a".repeat(129);
        for name in ["", "Web_search", "web search", "ü", long.as_str()] {
            let capabilities = [
                yolo[0],
                CapabilityUse {
                    name,
                    gate: CapabilityGate::OnByDefault,
                },
            ];
            assert!(
                matches!(
                    request(&capabilities).validate(),
                    Err(StoreError::InvalidInput("capability"))
                ),
                "{name:?}"
            );
        }
        for kind in [
            ResourceKind::Memory,
            ResourceKind::Tool,
            ResourceKind::Connection,
        ] {
            let r = RunRecheckRequest {
                extra_target: Some((kind, ID)),
                ..request(&[])
            };
            assert!(matches!(
                r.validate(),
                Err(StoreError::InvalidInput("resource kind"))
            ));
        }
    }

    #[test]
    fn missing_or_inactive_owner_invalidates_before_anything_else() {
        let chat = || Some(resource(ResourceKind::Conversation, personal(), OWNER));
        assert_eq!(
            decide(None, Some(personal()), chat(), None, &[]),
            invalid(DenialReason::Unauthenticated)
        );
        for inactive in [
            Principal {
                account_active: false,
                ..owner()
            },
            Principal {
                approval_active: false,
                ..owner()
            },
            Principal {
                provider_active: false,
                ..owner()
            },
        ] {
            assert_eq!(
                decide(Some(&inactive), None, None, Some(None), &[]),
                invalid(DenialReason::InactivePrincipal)
            );
        }
    }

    #[test]
    fn missing_scope_conversation_or_extra_target_is_concealed() {
        let p = owner();
        let chat = || Some(resource(ResourceKind::Conversation, personal(), OWNER));
        assert_eq!(
            decide(Some(&p), Some(personal()), chat(), None, &[]),
            RunContinuation::Continue
        );
        assert_eq!(
            decide(Some(&p), None, chat(), None, &[]),
            invalid(DenialReason::NotFound)
        );
        assert_eq!(
            decide(Some(&p), Some(personal()), None, None, &[]),
            invalid(DenialReason::NotFound)
        );
        assert_eq!(
            decide(Some(&p), Some(personal()), chat(), Some(None), &[]),
            invalid(DenialReason::NotFound)
        );
    }

    #[test]
    fn targets_outside_the_run_scope_are_concealed() {
        let p = owner();
        let in_project = || {
            Some(resource(
                ResourceKind::Conversation,
                project(ProjectRole::Editor),
                OWNER,
            ))
        };
        assert_eq!(
            decide(Some(&p), Some(personal()), in_project(), None, &[]),
            invalid(DenialReason::NotFound)
        );
        let artifact = resource(ResourceKind::Artifact, project(ProjectRole::Editor), OWNER);
        assert_eq!(
            decide(
                Some(&p),
                Some(personal()),
                Some(resource(ResourceKind::Conversation, personal(), OWNER)),
                Some(Some(artifact)),
                &[]
            ),
            invalid(DenialReason::NotFound)
        );
    }

    #[test]
    fn project_role_and_extra_target_access_are_both_required() {
        let p = owner();
        let chat = |role| Some(resource(ResourceKind::Conversation, project(role), OWNER));
        assert_eq!(
            decide(
                Some(&p),
                Some(project(ProjectRole::Editor)),
                chat(ProjectRole::Editor),
                None,
                &[]
            ),
            RunContinuation::Continue
        );
        assert_eq!(
            decide(
                Some(&p),
                Some(project(ProjectRole::Viewer)),
                chat(ProjectRole::Viewer),
                None,
                &[]
            ),
            invalid(DenialReason::Policy(PolicyReason::InsufficientRole))
        );
        let others = |access| {
            Some(Some(shared(
                resource(ResourceKind::Artifact, project(ProjectRole::Editor), OTHER),
                access,
            )))
        };
        let scope = || Some(project(ProjectRole::Editor));
        assert_eq!(
            decide(
                Some(&p),
                scope(),
                chat(ProjectRole::Editor),
                others(ResourceAccess::Write),
                &[]
            ),
            RunContinuation::Continue
        );
        assert_eq!(
            decide(
                Some(&p),
                scope(),
                chat(ProjectRole::Editor),
                others(ResourceAccess::Read),
                &[]
            ),
            invalid(DenialReason::Policy(PolicyReason::InsufficientAccess))
        );
        let unshared = resource(ResourceKind::Artifact, project(ProjectRole::Editor), OTHER);
        assert_eq!(
            decide(
                Some(&p),
                scope(),
                chat(ProjectRole::Editor),
                Some(Some(unshared)),
                &[]
            ),
            invalid(DenialReason::NotFound)
        );
    }

    #[test]
    fn capabilities_apply_to_the_run_and_a_deny_wins() {
        let chat = || Some(resource(ResourceKind::Conversation, personal(), OWNER));
        let yolo = [("runs.use_yolo", CapabilityGate::OptIn)];
        let p = owner();
        assert_eq!(
            decide(Some(&p), Some(personal()), chat(), None, &yolo),
            invalid(DenialReason::Policy(PolicyReason::CapabilityNotGranted))
        );
        let granted = Principal {
            granted_capabilities: BTreeSet::from(["runs.use_yolo".to_owned()]),
            ..owner()
        };
        assert_eq!(
            decide(Some(&granted), Some(personal()), chat(), None, &yolo),
            RunContinuation::Continue
        );
        let denied = Principal {
            denied_capabilities: BTreeSet::from(["runs.use_yolo".to_owned()]),
            ..granted
        };
        assert_eq!(
            decide(Some(&denied), Some(personal()), chat(), None, &yolo),
            invalid(DenialReason::Policy(PolicyReason::CapabilityDenied))
        );
    }

    fn limits() -> AdmissionLimits {
        AdmissionLimits {
            live_per_actor: 1,
            live_per_scope: 1,
            queued_in_instance: 1,
            queue_timeout: Duration::from_secs(1),
            round_cap: 1,
        }
    }

    fn refused<T: std::fmt::Debug>(result: Result<T, StoreError>) -> &'static str {
        match result {
            Err(StoreError::InvalidInput(field)) => field,
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[test]
    fn round_limit_is_the_request_capped_or_the_cap() {
        assert_eq!(effective_round_limit(None, 25).unwrap(), 25);
        assert_eq!(effective_round_limit(Some(1), 25).unwrap(), 1);
        assert_eq!(effective_round_limit(Some(10), 25).unwrap(), 10);
        assert_eq!(effective_round_limit(Some(25), 25).unwrap(), 25);
        assert_eq!(effective_round_limit(Some(26), 25).unwrap(), 25);
        assert_eq!(effective_round_limit(Some(i64::MAX), 1000).unwrap(), 1000);
        for bad in [0, -1, i64::MIN] {
            assert_eq!(
                refused(effective_round_limit(Some(bad), 25)),
                "round_limit",
                "{bad}"
            );
        }
    }

    #[test]
    fn limits_are_range_checked_before_any_database_work() {
        let max = AdmissionLimits {
            live_per_actor: 1000,
            live_per_scope: 10_000,
            queued_in_instance: 10_000,
            queue_timeout: Duration::from_secs(86_400),
            round_cap: 1000,
        };
        assert!(limits().validate().is_ok());
        assert!(max.validate().is_ok());
        let below = Duration::from_millis(999);
        let above = Duration::from_secs(86_400) + Duration::from_millis(1);
        for (bad, field) in [
            (
                AdmissionLimits {
                    live_per_actor: 0,
                    ..max
                },
                "live_per_actor",
            ),
            (
                AdmissionLimits {
                    live_per_actor: 1001,
                    ..max
                },
                "live_per_actor",
            ),
            (
                AdmissionLimits {
                    live_per_scope: 0,
                    ..max
                },
                "live_per_scope",
            ),
            (
                AdmissionLimits {
                    live_per_scope: 10_001,
                    ..max
                },
                "live_per_scope",
            ),
            (
                AdmissionLimits {
                    queued_in_instance: 0,
                    ..max
                },
                "queued_in_instance",
            ),
            (
                AdmissionLimits {
                    queued_in_instance: 10_001,
                    ..max
                },
                "queued_in_instance",
            ),
            (
                AdmissionLimits {
                    queue_timeout: below,
                    ..max
                },
                "queue_timeout",
            ),
            (
                AdmissionLimits {
                    queue_timeout: above,
                    ..max
                },
                "queue_timeout",
            ),
            (
                AdmissionLimits {
                    round_cap: 0,
                    ..max
                },
                "round_cap",
            ),
            (
                AdmissionLimits {
                    round_cap: 1001,
                    ..max
                },
                "round_cap",
            ),
        ] {
            assert_eq!(refused(bad.validate()), field);
        }
        let claim = |executing_per_actor, executing_per_scope| ClaimLimits {
            executing_per_actor,
            executing_per_scope,
        };
        assert!(claim(1, 1).validate().is_ok());
        assert!(claim(1024, 1024).validate().is_ok());
        for (bad, field) in [
            (claim(0, 1), "executing_per_actor"),
            (claim(1025, 1), "executing_per_actor"),
            (claim(1, 0), "executing_per_scope"),
            (claim(1, 1025), "executing_per_scope"),
        ] {
            assert_eq!(refused(bad.validate()), field);
        }
    }

    fn input(key: &str) -> RunInput<'_> {
        RunInput {
            scope: ID,
            actor: OWNER,
            conversation: ID,
            branch: ID,
            message: ID,
            key,
            format: "openmettle.synthetic-run",
            version: 1,
            input: b"",
            config: b"",
        }
    }

    fn admission<'a>(key: &'a str, capabilities: &'a [CapabilityUse<'a>]) -> RunAdmission<'a> {
        RunAdmission {
            input: input(key),
            actor_approval_id: ID,
            capabilities,
            requested_rounds: None,
            now_ms: 1,
        }
    }

    #[test]
    fn admission_requests_are_validated_before_any_database_work() {
        assert!(admission("key", &[]).validate().is_ok());
        assert_eq!(refused(admission("", &[]).validate()), "run input");
        let bad_approval = RunAdmission {
            actor_approval_id: "not-a-uuid",
            ..admission("key", &[])
        };
        assert_eq!(refused(bad_approval.validate()), "actor_approval_id");
        let capability = [CapabilityUse {
            name: "Web search",
            gate: CapabilityGate::OnByDefault,
        }];
        assert_eq!(
            refused(admission("key", &capability).validate()),
            "capability"
        );
    }

    #[test]
    fn replay_matching_compares_the_whole_request_identity() {
        let original = input("key");
        let identity = durable::run_identity(&original).unwrap();
        let replay = RunReplay {
            run_id: ID.into(),
            state: "queued".into(),
            round_limit: Some(5),
            conversation_id: ID.into(),
            branch_id: ID.into(),
            input_message_id: ID.into(),
            request_digest: durable::digest(&identity),
            request_identity: identity,
        };
        assert!(replay.matches(&original));
        assert!(!replay.matches(&RunInput {
            input: b"changed",
            ..input("key")
        }));
        assert!(!replay.matches(&RunInput {
            message: OTHER,
            ..input("key")
        }));
        assert!(!replay.matches(&input("other-key")));
        assert!(!replay.matches(&input("")));
    }

    #[test]
    fn queue_statements_repeat_the_partial_index_predicate_and_lock_order() {
        let live = non_terminal!();
        assert_eq!(LIVE_COUNTS.matches(live).count(), 3);
        assert!(LIVE_COUNTS.contains(" AND state = 'queued' LIMIT $5"));
        assert_eq!(CLAIM.matches(live).count(), 2);
        assert!(CLAIM.contains("state IN ('running', 'cancelling', 'reconciling')"));
        assert!(!CLAIM.contains("'waiting'"));
        assert!(CLAIM.contains("ORDER BY coalesce(a.n, 0), r.created_at, r.id"));
        assert!(CLAIM.contains("FOR NO KEY UPDATE OF r SKIP LOCKED"));
        assert!(CLAIM.contains("r.queue_expires_at > clock_timestamp()"));
        assert!(EXPIRE.contains(live));
        assert!(EXPIRE.contains("ORDER BY id LIMIT $1 FOR NO KEY UPDATE SKIP LOCKED"));
        assert!(EXPIRE.contains("queue_expires_at IS NULL"));
        for sql in [CANCEL_SCOPE, CANCEL_USER, EXPIRE] {
            assert!(
                sql.ends_with("RETURNING r.scope_id::text, r.id::text"),
                "{sql}"
            );
        }
    }

    #[test]
    fn terminal_payloads_are_fixed_json() {
        for (payload, json) in [
            (CANCEL_REQUESTED, r#"{"reason":"requested"}"#),
            (CANCEL_REVOKED, r#"{"reason":"revoked"}"#),
            (EXPIRED, "{}"),
            (CLAIMED, "{}"),
        ] {
            assert_eq!(payload.version, 1);
            assert_eq!(payload.bytes, json.as_bytes());
            assert!(serde_json::from_slice::<serde_json::Value>(payload.bytes).is_ok());
        }
        assert_eq!(CANCEL_REQUESTED.format, "openmettle.run-cancelled");
        assert_eq!(CANCEL_REVOKED.format, "openmettle.run-cancelled");
        assert_eq!(EXPIRED.format, "openmettle.run-expired");
        assert_eq!(CLAIMED.format, "openmettle.run-claimed");
        assert_eq!(TERMINAL_KEY, "run-terminal");
    }
}
