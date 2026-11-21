//! Worker ownership and recovery store (ADR 0033). All times come from the primary.
//! Anchor remaining durations at the instant the request was sent.
use super::{
    runs::{ClaimedRun, TERMINAL_KEY, append, is_terminal, transaction},
    store::{self, StoreError},
};
use crate::runs::{self as durable, Payload, WriteTransaction};
use sqlx::{PgConnection, Row, postgres::PgRow};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseSettings {
    /// Length of a lease, from 30 seconds to 10 minutes.
    pub lease: Duration,
    /// Allowance from first dispatch, at least two leases and at most 24 hours.
    pub execution_timeout: Duration,
}

impl LeaseSettings {
    pub fn validate(&self) -> Result<(), StoreError> {
        if !(Duration::from_secs(30)..=Duration::from_secs(600)).contains(&self.lease) {
            return Err(StoreError::InvalidInput("lease"));
        }
        if !(2 * self.lease..=Duration::from_secs(86_400)).contains(&self.execution_timeout) {
            return Err(StoreError::InvalidInput("execution_timeout"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Lease<'a> {
    pub scope_id: &'a str,
    pub run_id: &'a str,
    pub claim_token: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fence {
    /// Observe, renew, release or settle an executing run.
    Hold,
    /// Start work only while running without a cancellation request.
    Step,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecState {
    Running,
    Cancelling,
    Reconciling,
}

#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelReason {
    Requested,
    Revoked,
}

impl CancelReason {
    pub(crate) const NAMES: &[&str] = &["requested", "revoked"];

    pub(super) fn as_str(self) -> &'static str {
        Self::NAMES[self as usize]
    }

    pub(super) fn payload(self) -> &'static [u8] {
        match self {
            Self::Requested => br#"{"reason":"requested"}"#,
            Self::Revoked => br#"{"reason":"revoked"}"#,
        }
    }
}

fn cancel_reason(row: &PgRow) -> Result<Option<CancelReason>, StoreError> {
    match row.try_get("cancel_reason")? {
        None => Ok(None),
        Some("requested") => Ok(Some(CancelReason::Requested)),
        Some("revoked") => Ok(Some(CancelReason::Revoked)),
        Some(_) => Err(StoreError::InvalidInput("stored cancel reason")),
    }
}

fn exec_state(state: &str) -> Option<ExecState> {
    match state {
        "running" => Some(ExecState::Running),
        "cancelling" => Some(ExecState::Cancelling),
        "reconciling" => Some(ExecState::Reconciling),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    pub state: ExecState,
    pub cancel: Option<CancelReason>,
    pub lease_remaining: Duration,
    pub execution_remaining: Duration,
}

macro_rules! remaining_sql {
    () => {
        "(extract(epoch FROM lease_expires_at - clock_timestamp()) * 1000)::bigint AS lease_ms,
         (extract(epoch FROM execution_expires_at - clock_timestamp()) * 1000)::bigint AS execution_ms"
    };
}
pub(super) use remaining_sql;

pub(super) fn remaining(row: &PgRow, key: &str) -> Result<Duration, StoreError> {
    Ok(Duration::from_millis(
        row.try_get::<i64, _>(key)?.max(0) as u64
    ))
}

fn held(row: &PgRow, state: ExecState) -> Result<Held, StoreError> {
    Ok(Held {
        state,
        cancel: cancel_reason(row)?,
        lease_remaining: remaining(row, "lease_ms")?,
        execution_remaining: remaining(row, "execution_ms")?,
    })
}

#[derive(Debug)]
pub enum LeaseError {
    Terminal { state: String },
    StaleClaim,
    Expired,
    Stopping(Held),
    Store(StoreError),
}

impl From<StoreError> for LeaseError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

// Materialize the locked row before evaluating the clock. Time spent waiting for the lock
// must count against the lease even when the previous locker made no update.
const LOCK: &str = concat!(
    "WITH locked AS MATERIALIZED (
        SELECT state, cancel_reason, claim_token, lease_expires_at, execution_expires_at
          FROM openmettle.runs WHERE scope_id = $1::uuid AND id = $2::uuid FOR NO KEY UPDATE)
     SELECT state, cancel_reason, claim_token = $3::uuid AS owned,
            lease_expires_at > clock_timestamp() AS live, ",
    remaining_sql!(),
    " FROM locked"
);

async fn lock(c: &mut PgConnection, lease: &Lease<'_>, fence: Fence) -> Result<Held, LeaseError> {
    let row = sqlx::query(LOCK)
        .bind(lease.scope_id)
        .bind(lease.run_id)
        .bind(lease.claim_token)
        .fetch_optional(c)
        .await
        .map_err(StoreError::from)?
        .ok_or(StoreError::NotFound)?;
    let state: &str = row.try_get("state").map_err(StoreError::from)?;
    if is_terminal(state) {
        return Err(LeaseError::Terminal {
            state: state.to_owned(),
        });
    }
    if row
        .try_get::<Option<bool>, _>("owned")
        .map_err(StoreError::from)?
        != Some(true)
    {
        return Err(LeaseError::StaleClaim);
    }
    let state = exec_state(state).ok_or(LeaseError::StaleClaim)?;
    if row
        .try_get::<Option<bool>, _>("live")
        .map_err(StoreError::from)?
        != Some(true)
    {
        return Err(LeaseError::Expired);
    }
    let held = held(&row, state)?;
    if fence == Fence::Step && (state != ExecState::Running || held.cancel.is_some()) {
        return Err(LeaseError::Stopping(held));
    }
    Ok(held)
}

pub(super) async fn fenced<T>(
    c: &mut PgConnection,
    lease: &Lease<'_>,
    fence: Fence,
    body: impl AsyncFnOnce(&mut WriteTransaction<'_>, &Held) -> Result<T, StoreError>,
) -> Result<T, LeaseError> {
    store::uuid(lease.scope_id, "scope_id")?;
    store::uuid(lease.run_id, "run_id")?;
    store::uuid(lease.claim_token, "claim_token")?;
    let mut tx = store::begin(c).await?;
    let result = async {
        let c = tx.connection().map_err(StoreError::from)?;
        sqlx::query("SET LOCAL idle_in_transaction_session_timeout = '5s'")
            .execute(&mut *c)
            .await
            .map_err(StoreError::from)?;
        let held = lock(c, lease, fence).await?;
        Ok(body(&mut tx, &held).await?)
    }
    .await;
    match result {
        Ok(value) => {
            tx.commit().await.map_err(StoreError::from)?;
            Ok(value)
        }
        Err(error) => {
            tx.rollback().await.map_err(StoreError::from)?;
            Err(error)
        }
    }
}

/// Compose durable helpers for this run under its row lock. Use Step for intents and Hold
/// for observations of work already in flight. The body must only write the addressed run.
pub async fn with_lease<T>(
    c: &mut PgConnection,
    lease: &Lease<'_>,
    fence: Fence,
    body: impl AsyncFnOnce(&mut WriteTransaction<'_>, &Held) -> Result<T, durable::Error>,
) -> Result<T, LeaseError> {
    fenced(c, lease, fence, async |tx, held| {
        body(tx, held).await.map_err(|error| match error {
            durable::Error::Conflict => StoreError::Conflict("fenced write"),
            durable::Error::StaleRevision => StoreError::Conflict("stale operation revision"),
            durable::Error::Invalid => StoreError::InvalidInput("fenced write"),
            other => other.into(),
        })
    })
    .await
}

const RENEW: &str = concat!(
    "UPDATE openmettle.runs
        SET lease_expires_at = greatest(lease_expires_at,
                least(clock_timestamp() + $3::bigint * interval '1 millisecond', execution_expires_at))
      WHERE scope_id = $1::uuid AND id = $2::uuid AND lease_expires_at > clock_timestamp()
     RETURNING cancel_reason, ",
    remaining_sql!()
);

pub async fn renew_lease(
    c: &mut PgConnection,
    lease: &Lease<'_>,
    settings: &LeaseSettings,
) -> Result<Held, LeaseError> {
    settings.validate()?;
    fenced(c, lease, Fence::Hold, async |tx, current| {
        let row = sqlx::query(RENEW)
            .bind(lease.scope_id)
            .bind(lease.run_id)
            .bind(settings.lease.as_millis() as i64)
            .fetch_optional(tx.connection()?)
            .await?;
        row.as_ref().map(|row| held(row, current.state)).transpose()
    })
    .await?
    .ok_or(LeaseError::Expired)
}

/// Make the lease due immediately, retaining the claim and its execution deadline.
pub async fn release_lease(c: &mut PgConnection, lease: &Lease<'_>) -> Result<(), LeaseError> {
    fenced(c, lease, Fence::Hold, async |tx, _| {
        release_locked(tx.connection()?, lease).await
    })
    .await
}

async fn release_locked(c: &mut PgConnection, lease: &Lease<'_>) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE openmettle.runs SET lease_expires_at = least(clock_timestamp(), execution_expires_at)
          WHERE scope_id = $1::uuid AND id = $2::uuid",
    )
    .bind(lease.scope_id)
    .bind(lease.run_id)
    .execute(c)
    .await?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settle {
    Succeeded,
    Failed(FailReason),
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailReason {
    StepFailed,
    RoundLimit,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Settled {
    Terminal { state: &'static str },
    Reconciling { unresolved: u32 },
}

macro_rules! unresolved {
    () => {
        "outcome IN ('intent', 'outcome_unknown') AND capability IN ('lookup', 'non_repeatable')"
    };
}

#[derive(Debug, PartialEq, Eq)]
pub struct UnresolvedOperation {
    pub id: String,
    pub logical_key: String,
    pub target: String,
    pub capability: String,
    pub outcome: String,
    pub revision: i64,
    pub downstream_handle: Option<String>,
}

fn validate_limit(limit: u32) -> Result<(), StoreError> {
    if !(1..=1000).contains(&limit) {
        return Err(StoreError::InvalidInput("limit"));
    }
    Ok(())
}

pub async fn unresolved_operations(
    c: &mut PgConnection,
    lease: &Lease<'_>,
    limit: u32,
) -> Result<Vec<UnresolvedOperation>, LeaseError> {
    unresolved_after(c, lease, limit, None).await
}

/// Keyset pagination visits an unavailable operation only once in a reconciliation pass.
pub(crate) async fn unresolved_after(
    c: &mut PgConnection,
    lease: &Lease<'_>,
    limit: u32,
    after: Option<&str>,
) -> Result<Vec<UnresolvedOperation>, LeaseError> {
    validate_limit(limit)?;
    fenced(c, lease, Fence::Hold, async |tx, _| {
        let rows = sqlx::query(concat!(
            "SELECT id::text, logical_key, target, capability, outcome,
                revision, downstream_handle FROM openmettle.operations
                WHERE scope_id = $1::uuid AND run_id = $2::uuid AND ",
            unresolved!(),
            " AND ($4::uuid IS NULL OR id > $4::uuid) ORDER BY openmettle.operations.id LIMIT $3"
        ))
        .bind(lease.scope_id)
        .bind(lease.run_id)
        .bind(i64::from(limit))
        .bind(after)
        .fetch_all(tx.connection()?)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(UnresolvedOperation {
                    id: row.try_get("id")?,
                    logical_key: row.try_get("logical_key")?,
                    target: row.try_get("target")?,
                    capability: row.try_get("capability")?,
                    outcome: row.try_get("outcome")?,
                    revision: row.try_get("revision")?,
                    downstream_handle: row.try_get("downstream_handle")?,
                })
            })
            .collect()
    })
    .await
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Resolution {
    Succeeded,
    Failed(FailReason),
    DeadlineExceeded,
    Cancelled(CancelReason),
    Reconciling(u32),
    Interrupted(u32),
}

fn decide(
    state: ExecState,
    cancel: Option<CancelReason>,
    input: Settle,
    n: u32,
    time_to_reconcile: bool,
) -> Result<Resolution, StoreError> {
    use Resolution as R;
    if state == ExecState::Reconciling {
        return match (input, n, cancel) {
            (Settle::Stopped, 0, Some(reason)) => Ok(R::Cancelled(reason)),
            (Settle::Stopped, _, _) => Ok(R::Interrupted(n)),
            _ => Err(StoreError::InvalidInput("settle")),
        };
    }
    match (input, n, cancel) {
        (Settle::Succeeded, 0, _) => Ok(R::Succeeded),
        (Settle::Succeeded, _, _) => Err(StoreError::Conflict("unresolved operation")),
        (_, 1.., _) if time_to_reconcile => Ok(R::Reconciling(n)),
        (_, 1.., _) => Ok(R::Interrupted(n)),
        (_, 0, Some(reason)) => Ok(R::Cancelled(reason)),
        (Settle::Failed(reason), 0, None) => Ok(R::Failed(reason)),
        (Settle::Stopped, 0, None) if !time_to_reconcile => Ok(R::DeadlineExceeded),
        _ => Err(StoreError::InvalidInput("settle")),
    }
}

impl Resolution {
    fn state(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed(_) | Self::DeadlineExceeded => "failed",
            Self::Cancelled(_) => "cancelled",
            Self::Reconciling(_) => "reconciling",
            Self::Interrupted(_) => "interrupted",
        }
    }

    async fn event(self, c: &mut PgConnection, scope: &str, id: &str) -> Result<(), StoreError> {
        let count;
        let (format, bytes): (_, &[u8]) = match self {
            Self::Succeeded => ("openmettle.run-succeeded", b"{}"),
            Self::Cancelled(reason) => ("openmettle.run-cancelled", reason.payload()),
            Self::Failed(FailReason::StepFailed) => {
                ("openmettle.run-failed", br#"{"reason":"step_failed"}"#)
            }
            Self::Failed(FailReason::RoundLimit) => {
                ("openmettle.run-failed", br#"{"reason":"round_limit"}"#)
            }
            Self::DeadlineExceeded => (
                "openmettle.run-failed",
                br#"{"reason":"deadline_exceeded"}"#,
            ),
            Self::Reconciling(n) | Self::Interrupted(n) => {
                count = format!(r#"{{"unresolved":{n}}}"#);
                let format = if matches!(self, Self::Reconciling(_)) {
                    "openmettle.run-reconciling"
                } else {
                    "openmettle.run-interrupted"
                };
                (format, count.as_bytes())
            }
        };
        let key = if matches!(self, Self::Reconciling(_)) {
            "run-reconciling"
        } else {
            TERMINAL_KEY
        };
        append(
            c,
            scope,
            id,
            key,
            Payload {
                format,
                version: 1,
                bytes,
            },
        )
        .await?;
        if let Self::Cancelled(reason) = self {
            crate::telemetry::metrics::global().record_cancellation(reason);
        }
        Ok(())
    }
}

pub async fn settle(
    c: &mut PgConnection,
    lease: &Lease<'_>,
    settings: &LeaseSettings,
    input: Settle,
) -> Result<Settled, LeaseError> {
    settings.validate()?;
    fenced(c, lease, Fence::Hold, async |tx, held| {
        settle_locked(
            tx.connection()?,
            lease,
            held.state,
            held.cancel,
            settings,
            input,
        )
        .await
    })
    .await
}

const SETTLEMENT_INPUTS: &str = concat!(
    "SELECT (SELECT count(*) FROM openmettle.operations WHERE scope_id = $1::uuid AND run_id = $2::uuid AND ",
    unresolved!(),
    "), execution_expires_at > clock_timestamp() + $3::bigint * interval '1 millisecond'
         FROM openmettle.runs WHERE scope_id = $1::uuid AND id = $2::uuid"
);

/// Decide handover under the same lock that excludes new intents and cancellation.
pub(crate) async fn handoff(
    c: &mut PgConnection,
    lease: &Lease<'_>,
    settings: &LeaseSettings,
) -> Result<(), LeaseError> {
    fenced(c, lease, Fence::Hold, async |tx, held| {
        let c = tx.connection()?;
        if held.state == ExecState::Reconciling {
            return release_locked(c, lease).await;
        }
        let pending = held.cancel.is_some()
            || sqlx::query_scalar::<_, bool>(concat!(
                "SELECT EXISTS (SELECT FROM openmettle.operations
               WHERE scope_id = $1::uuid AND run_id = $2::uuid AND ",
                unresolved!(),
                ")"
            ))
            .bind(lease.scope_id)
            .bind(lease.run_id)
            .fetch_one(&mut *c)
            .await?;
        if pending {
            let settled =
                settle_locked(c, lease, held.state, held.cancel, settings, Settle::Stopped).await?;
            if matches!(settled, Settled::Terminal { .. }) {
                return Ok(());
            }
        }
        release_locked(c, lease).await
    })
    .await
}

pub(super) async fn settle_locked(
    c: &mut PgConnection,
    lease: &Lease<'_>,
    state: ExecState,
    cancel: Option<CancelReason>,
    settings: &LeaseSettings,
    input: Settle,
) -> Result<Settled, StoreError> {
    let (n, time): (i64, bool) = sqlx::query_as(SETTLEMENT_INPUTS)
        .bind(lease.scope_id)
        .bind(lease.run_id)
        .bind(settings.lease.as_millis() as i64)
        .fetch_one(&mut *c)
        .await?;
    let resolution = decide(state, cancel, input, operation_count(n)?, time)?;
    sqlx::query("UPDATE openmettle.runs SET state = $3, wait_reason = NULL WHERE scope_id = $1::uuid AND id = $2::uuid")
        .bind(lease.scope_id)
        .bind(lease.run_id)
        .bind(resolution.state())
        .execute(&mut *c)
        .await?;
    resolution.event(c, lease.scope_id, lease.run_id).await?;
    Ok(match resolution {
        Resolution::Reconciling(unresolved) => Settled::Reconciling { unresolved },
        _ => Settled::Terminal {
            state: resolution.state(),
        },
    })
}

fn operation_count(n: i64) -> Result<u32, StoreError> {
    n.try_into()
        .map_err(|_| StoreError::Conflict("unresolved operation count"))
}

#[derive(Debug, PartialEq, Eq)]
pub struct Reclaimed {
    pub run: ClaimedRun,
    pub state: ExecState,
    pub cancel: Option<CancelReason>,
}

// Include the partial index predicate verbatim.
macro_rules! lapsed {
    () => {
        "state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')
         AND state IN ('running', 'cancelling', 'reconciling')
         AND (lease_expires_at IS NULL OR lease_expires_at <= clock_timestamp())"
    };
}

const RECLAIM: &str = concat!(
    "WITH next AS (
       SELECT id, clock_timestamp() AS t FROM openmettle.runs WHERE ",
    lapsed!(),
    " AND execution_expires_at > clock_timestamp() + $1::bigint * interval '1 millisecond'
        ORDER BY lease_expires_at NULLS FIRST, id LIMIT 1 FOR NO KEY UPDATE SKIP LOCKED)
     UPDATE openmettle.runs r
        SET claim_token = gen_random_uuid(), claimed_at = next.t,
            lease_expires_at = least(next.t + $1::bigint * interval '1 millisecond', r.execution_expires_at)
       FROM next WHERE r.id = next.id
     RETURNING r.scope_id::text, r.id::text, r.claim_token::text,
               r.actor_approval_id::text, r.round_limit, r.state, r.cancel_reason, ",
    remaining_sql!()
);

pub async fn reclaim_next(
    c: &mut PgConnection,
    settings: &LeaseSettings,
) -> Result<Option<Reclaimed>, StoreError> {
    settings.validate()?;
    transaction(c, async |c| {
        let Some(row) = sqlx::query(RECLAIM)
            .bind(settings.lease.as_millis() as i64)
            .fetch_optional(&mut *c)
            .await?
        else {
            return Ok(None);
        };
        let run = ClaimedRun::from_row(&row)?;
        let state = exec_state(row.try_get("state")?)
            .ok_or(StoreError::InvalidInput("stored run state"))?;
        let cancel = cancel_reason(&row)?;
        append(
            c,
            &run.scope_id,
            &run.run_id,
            &format!("reclaim:{}", run.claim_token),
            Payload {
                format: "openmettle.run-reclaimed",
                version: 1,
                bytes: b"{}",
            },
        )
        .await?;
        Ok(Some(Reclaimed { run, state, cancel }))
    })
    .await
}

const LOCK_EXPIRED: &str = concat!(
    "SELECT id::text FROM openmettle.runs WHERE ",
    lapsed!(),
    " AND (execution_expires_at IS NULL OR execution_expires_at <= clock_timestamp())
       ORDER BY openmettle.runs.id LIMIT $1 FOR NO KEY UPDATE SKIP LOCKED"
);

const SETTLE_EXPIRED: &str = concat!(
    "WITH due AS (SELECT unnest($1::text[]::uuid[]) AS id), unresolved AS (
       SELECT o.run_id, count(*) AS n FROM openmettle.operations o JOIN due ON o.run_id = due.id
        WHERE ",
    unresolved!(),
    " GROUP BY o.run_id
     ), settled AS (
       UPDATE openmettle.runs r
          SET state = CASE WHEN coalesce(u.n, 0) > 0 THEN 'interrupted'
                           WHEN r.cancel_reason IS NOT NULL THEN 'cancelled'
                           WHEN r.state = 'reconciling' THEN 'interrupted'
                           ELSE 'failed' END,
              wait_reason = NULL
         FROM due LEFT JOIN unresolved u ON u.run_id = due.id WHERE r.id = due.id
       RETURNING r.scope_id::text, r.id, r.state, r.cancel_reason, coalesce(u.n, 0) AS n)
     SELECT scope_id, id::text, state, cancel_reason, n FROM settled ORDER BY settled.id"
);

/// Settle expired execution deadlines (including legacy NULLs). Lock the batch first, then
/// read operations in a fresh READ COMMITTED snapshot so the last holder's writes are visible.
pub async fn settle_expired(c: &mut PgConnection, limit: u32) -> Result<Vec<String>, StoreError> {
    validate_limit(limit)?;
    transaction(c, async |c| {
        let ids: Vec<String> = sqlx::query_scalar(LOCK_EXPIRED)
            .bind(i64::from(limit))
            .fetch_all(&mut *c)
            .await?;
        if ids.is_empty() {
            return Ok(ids);
        }
        let rows = sqlx::query(SETTLE_EXPIRED)
            .bind(&ids)
            .fetch_all(&mut *c)
            .await?;
        for row in rows {
            let resolution = match row.try_get("state")? {
                "interrupted" => Resolution::Interrupted(operation_count(row.try_get("n")?)?),
                "cancelled" => Resolution::Cancelled(
                    cancel_reason(&row)?.ok_or(StoreError::InvalidInput("stored cancel reason"))?,
                ),
                "failed" => Resolution::DeadlineExceeded,
                _ => return Err(StoreError::InvalidInput("expired run state")),
            };
            resolution
                .event(c, row.try_get("scope_id")?, row.try_get("id")?)
                .await?;
        }
        Ok(ids)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_settings_are_bounded_before_database_work() {
        let settings = |lease, execution| LeaseSettings {
            lease: Duration::from_millis(lease),
            execution_timeout: Duration::from_millis(execution),
        };
        for (lease, execution) in [
            (30_000, 60_000),
            (600_000, 1_200_000),
            (600_000, 86_400_000),
        ] {
            assert!(settings(lease, execution).validate().is_ok());
        }
        for (lease, execution) in [
            (29_999, 60_000),
            (600_001, 86_400_000),
            (30_001, 60_001),
            (30_000, 59_999),
            (30_000, 86_400_001),
        ] {
            assert!(settings(lease, execution).validate().is_err());
        }
        for n in [0, 1001] {
            assert!(validate_limit(n).is_err());
        }
        for n in [1, 1000] {
            assert!(validate_limit(n).is_ok());
        }
    }

    #[test]
    fn settlement_uses_the_first_matching_rule() {
        use ExecState::*;
        use Resolution as R;
        let stop = Settle::Stopped;
        let success = Settle::Succeeded;
        let failed = Settle::Failed(FailReason::StepFailed);
        let r = Some(CancelReason::Requested);
        for (state, cancel, input, n, time, expected) in [
            (Running, None, success, 0, true, R::Succeeded),
            (Cancelling, r, success, 0, false, R::Succeeded),
            (Reconciling, r, stop, 1, true, R::Interrupted(1)),
            (
                Reconciling,
                r,
                stop,
                0,
                true,
                R::Cancelled(CancelReason::Requested),
            ),
            (Reconciling, None, stop, 0, true, R::Interrupted(0)),
            (Running, None, failed, 2, true, R::Reconciling(2)),
            (Cancelling, r, stop, 1, false, R::Interrupted(1)),
            (
                Cancelling,
                r,
                failed,
                0,
                false,
                R::Cancelled(CancelReason::Requested),
            ),
            (
                Running,
                None,
                failed,
                0,
                false,
                R::Failed(FailReason::StepFailed),
            ),
            (
                Running,
                None,
                Settle::Failed(FailReason::RoundLimit),
                0,
                true,
                R::Failed(FailReason::RoundLimit),
            ),
            (Running, None, stop, 0, false, R::DeadlineExceeded),
        ] {
            assert_eq!(decide(state, cancel, input, n, time).unwrap(), expected);
        }
        for input in [success, failed] {
            assert!(matches!(
                decide(Reconciling, None, input, 1, true),
                Err(StoreError::InvalidInput("settle"))
            ));
        }
        assert!(matches!(
            decide(Cancelling, r, success, 1, true),
            Err(StoreError::Conflict("unresolved operation"))
        ));
        assert!(matches!(
            decide(Running, None, stop, 0, true),
            Err(StoreError::InvalidInput("settle"))
        ));
    }
}
