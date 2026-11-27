//! Fenced GPU capacity controller store (ADR 0042, Migration 27).
//!
//! One controller lease per managed group fences observations, grant decisions and release
//! evidence by a secret returned once on acquisition and by `controller_epoch`, against database
//! time. Reading a snapshot never reserves capacity: each decision is serialized on the group
//! row and subtracts commitments made since the cited measurement. A run-linked grant commits
//! the run's `device_reservations` slot in the same transaction (`quota_commit_device_handoff`),
//! and only confirmed release or non-allocation on every device returns its bytes and settles
//! that slot.
//!
//! The fenced writes ([`Controller::acquire`], [`Controller::renew`], [`publish`], [`resume`],
//! [`grant`] and [`reconcile`]) must run under `READ COMMITTED`; any other level fails with
//! [`Error::Invalid`] (SQLSTATE `25000`). `WriteTransaction::begin_bounded` and
//! `begin_bounded_pool` in [`crate::runs`] select it explicitly. An autocommit statement on a
//! pooled connection, [`crate::runs::WriteTransaction::begin`] and a plain `sqlx` transaction
//! inherit the role's or server's `default_transaction_isolation`, so use them only where that
//! setting is `read committed` (the PostgreSQL default). [`snapshot`] is a read and works at any
//! level: inside `REPEATABLE READ` it returns the transaction's snapshot, possibly older than
//! committed state, with `admits_bursts` evaluated on that snapshot at the current time.
//!
//! On any `Err` from a write, roll the caller's transaction back and never commit it. An error
//! PostgreSQL raised (including expiries detected after a write's last lock wait: `LeaseLost`,
//! `Fenced`, `Expired`) has already aborted the transaction, losing its earlier writes; an
//! `Invalid` the Rust API returns before sending any SQL has not. An `Ok` outcome, including
//! `Decision::Insufficient` and `Decision::Unavailable`, leaves the transaction intact.
use crate::{
    runs::is_canonical_uuid,
    telemetry::{
        self,
        metrics::{self, CapacityOperation, CapacityOutcome, CapacityStaleSurface},
    },
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sqlx::{Connection, PgConnection, Row};
use std::{
    fmt,
    time::{Duration, Instant},
};
use tracing::Instrument;

pub mod adapter;

/// All failure classes are safe to display or log.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Malformed input, a non-`READ COMMITTED` transaction, or an observation, footprint or
    /// transition the store refuses.
    Invalid,
    /// The caller does not hold the group's current controller secret, epoch and lease.
    Fenced,
    /// The run's claim is not an active `Step` lease.
    LeaseLost,
    /// Quota metering is enforced and the run holds no unused `device_reservations` slot: none
    /// was admitted, or an earlier grant already used it.
    SlotRequired,
    /// The request identity names another request, the run already holds a live grant, or its
    /// device slot is bound elsewhere.
    Conflict,
    /// The group stopped admitting bursts (its sample went stale) while the grant waited for its
    /// last lock. The decision and the caller's transaction are aborted.
    Expired,
    Database,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "capacity input refused",
            Self::Fenced => "capacity controller fenced",
            Self::LeaseLost => "run lease not active",
            Self::SlotRequired => "run device slot required",
            Self::Conflict => "capacity request conflict",
            Self::Expired => "capacity decision expired",
            Self::Database => "capacity store unavailable",
        })
    }
}
impl std::error::Error for Error {}
impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        match error.as_database_error().and_then(|e| e.code()).as_deref() {
            Some("OMC01") => Self::Fenced,
            Some("42501") => Self::LeaseLost,
            Some("OMQ04") => Self::SlotRequired,
            Some("23505") => Self::Conflict,
            Some("OMC02") => Self::Expired,
            Some("22003" | "22023" | "22P02" | "23502" | "23503" | "23514" | "25000") => {
                Self::Invalid
            }
            _ => Self::Database,
        }
    }
}

fn ids(values: &[&str]) -> Result<(), Error> {
    values
        .iter()
        .all(|v| is_canonical_uuid(v))
        .then_some(())
        .ok_or(Error::Invalid)
}

/// Locale-independent capacity profile/model name check matching `openmettle.capacity_valid_name`:
/// 1..=128 UTF-8 bytes, no leading or trailing Unicode whitespace (`str::trim()`), and no C0/C1
/// control characters (`char::is_control`).
pub(crate) fn valid_capacity_name(value: &str) -> bool {
    crate::runs::bounded(value, 128)
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn lease_ms(lease: Duration) -> Result<i32, Error> {
    i32::try_from(lease.as_millis()).map_err(|_| Error::Invalid)
}

/// The lease holder for one group. Its secret is generated here, sent once, and only its
/// SHA-256 is stored, so worker-readable rows never confer controller authority.
pub struct Controller {
    group_id: String,
    epoch: i64,
    secret: [u8; 32],
}
// Never disclose the secret through Debug.
impl fmt::Debug for Controller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Controller")
            .field("group_id", &self.group_id)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}
impl Controller {
    /// Take over an absent or expired lease with a fresh secret and a new epoch. A live lease
    /// returns [`Error::Fenced`]. The new epoch is closed to bursts until [`resume`] succeeds.
    pub async fn acquire(
        c: &mut PgConnection,
        group_id: &str,
        lease: Duration,
    ) -> Result<Self, Error> {
        ids(&[group_id])?;
        let mut secret = [0; 32];
        SystemRandom::new()
            .fill(&mut secret)
            .map_err(|_| Error::Database)?;
        let epoch =
            sqlx::query_scalar("SELECT openmettle.capacity_acquire_controller($1::uuid, $2, $3)")
                .bind(group_id)
                .bind(secret.as_slice())
                .bind(lease_ms(lease)?)
                .fetch_one(c)
                .await?;
        Ok(Self {
            group_id: group_id.to_owned(),
            epoch,
            secret,
        })
    }

    /// Extend the live lease within this epoch. After expiry or takeover, including expiry while
    /// the renewal waits for a lock, this returns [`Error::Fenced`] and leaves the deadline
    /// unchanged: acquire again for a new epoch.
    pub async fn renew(&self, c: &mut PgConnection, lease: Duration) -> Result<(), Error> {
        sqlx::query("SELECT openmettle.capacity_renew_controller($1::uuid, $2, $3, $4)")
            .bind(&self.group_id)
            .bind(self.secret.as_slice())
            .bind(self.epoch)
            .bind(lease_ms(lease)?)
            .execute(c)
            .await?;
        Ok(())
    }

    pub fn group_id(&self) -> &str {
        &self.group_id
    }

    pub fn epoch(&self) -> i64 {
        self.epoch
    }
}

/// One device row of a snapshot (ADR 0042 "Observations and fit").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeviceObservation {
    pub device_id: String,
    pub total_bytes: i64,
    pub committed_bytes: i64,
    pub actual_used_bytes: i64,
    pub reclaimable_bytes: i64,
    pub safety_headroom_bytes: i64,
    pub active_chat_floor_bytes: i64,
    /// Conservative spare capacity, clamped at zero. The controller attributes measured use to
    /// the chat floor and to commitments; the store checks only necessary bounds.
    pub grantable_bytes: i64,
}

/// A complete sample covering every configured device of the group.
pub struct Observation<'a> {
    pub revision: i64,
    /// Measurement time, microseconds since the Unix epoch on the database clock.
    pub observed_at_us: i64,
    /// Highest grant `commit_seq` whose footprint the sample counts in `committed_bytes`.
    pub commit_watermark: i64,
    pub devices: &'a [DeviceObservation],
}

/// Publish a snapshot. Returns false for a revision that is not newer than the published one:
/// a replayed or superseded sample never extends freshness.
pub async fn publish(
    c: &mut PgConnection,
    controller: &Controller,
    observation: &Observation<'_>,
) -> Result<bool, Error> {
    if observation
        .devices
        .iter()
        .any(|d| !is_canonical_uuid(&d.device_id))
    {
        return Err(Error::Invalid);
    }
    let devices = serde_json::to_string(observation.devices).map_err(|_| Error::Invalid)?;
    Ok(sqlx::query_scalar(
        "SELECT openmettle.capacity_publish_observation($1::uuid, $2, $3, $4,
             'epoch'::timestamptz + $5 * interval '1 microsecond', $6, $7::jsonb)",
    )
    .bind(&controller.group_id)
    .bind(controller.secret.as_slice())
    .bind(controller.epoch)
    .bind(observation.revision)
    .bind(observation.observed_at_us)
    .bind(observation.commit_watermark)
    .bind(devices)
    .fetch_one(c)
    .await?)
}

fn error_outcome(error: &Error) -> CapacityOutcome {
    match error {
        Error::Fenced => CapacityOutcome::Fenced,
        Error::Expired => CapacityOutcome::Expired,
        Error::Invalid | Error::LeaseLost | Error::SlotRequired | Error::Conflict => {
            CapacityOutcome::Refused
        }
        Error::Database => CapacityOutcome::Error,
    }
}

pub(crate) fn store_error_outcome(error: &Error) -> CapacityOutcome {
    error_outcome(error)
}

/// RAII guard for one `capacity.grant` lifecycle span. Ensures `operation.outcome`, the
/// `capacity.grant.completed` event, and the `openmettle.capacity.grants` counter are emitted
/// strictly once — either at the caller's post-commit `finish` boundary or with
/// [`CapacityOutcome::Error`] if the owning future is dropped mid-flight.
pub(crate) struct CapacityGrantGuard<'a> {
    span: tracing::Span,
    run_id: Option<&'a str>,
    grant_id: Option<String>,
    operation: CapacityOperation,
    started: Instant,
    metrics: &'a metrics::Metrics,
    finished: bool,
}

impl<'a> CapacityGrantGuard<'a> {
    pub(crate) fn new(
        span: tracing::Span,
        run_id: Option<&'a str>,
        grant_id: Option<&str>,
        operation: CapacityOperation,
        metrics: &'a metrics::Metrics,
    ) -> Self {
        Self {
            span,
            run_id,
            grant_id: grant_id.map(str::to_owned),
            operation,
            started: Instant::now(),
            metrics,
            finished: false,
        }
    }

    pub(crate) fn set_grant_id(&mut self, grant_id: &str) {
        self.span
            .in_scope(|| telemetry::record_capacity_span_grant_id(grant_id));
        self.grant_id = Some(grant_id.to_owned());
    }

    pub(crate) fn finish(mut self, outcome: CapacityOutcome) {
        self.record(outcome, true);
    }

    pub(crate) fn finish_span_only(mut self, outcome: CapacityOutcome) {
        self.record(outcome, false);
    }

    fn record(&mut self, outcome: CapacityOutcome, record_metric: bool) {
        if self.finished {
            return;
        }
        self.finished = true;
        if record_metric {
            self.metrics.record_capacity_grant(self.operation, outcome);
        }
        self.span.record("operation.outcome", outcome.as_str());
        telemetry::capacity_grant_completed(
            self.run_id,
            self.grant_id.as_deref(),
            self.operation,
            outcome,
            self.started.elapsed(),
        );
    }
}

impl Drop for CapacityGrantGuard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            let span = self.span.clone();
            span.in_scope(|| self.record(CapacityOutcome::Error, true));
        }
    }
}

async fn group_observation_stale(c: &mut PgConnection, group_id: &str) -> Result<bool, Error> {
    let stale = sqlx::query_scalar::<_, bool>(
        "SELECT coalesce(
             observed_at IS NOT NULL
             AND observed_at + observation_ttl_ms * interval '1 millisecond' <= clock_timestamp(),
             false
         )
           FROM openmettle.capacity_groups
          WHERE id = $1::uuid",
    )
    .bind(group_id)
    .fetch_optional(c)
    .await?
    .unwrap_or(false);
    Ok(stale)
}

/// Toggle the group's durable backend-unknown recovery fence under the controller lease.
///
/// Newly acquired epochs start with `backend_unknown = true` so bursts cannot reopen until
/// backend inventory has been reconciled. Setting `unknown = true` also clears `ready_epoch`.
pub async fn set_backend_unknown(
    c: &mut PgConnection,
    controller: &Controller,
    unknown: bool,
) -> Result<(), Error> {
    sqlx::query("SELECT openmettle.capacity_set_backend_unknown($1::uuid, $2, $3, $4)")
        .bind(&controller.group_id)
        .bind(controller.secret.as_slice())
        .bind(controller.epoch)
        .bind(unknown)
        .execute(c)
        .await?;
    Ok(())
}

pub(super) async fn resume_query(
    c: &mut PgConnection,
    controller: &Controller,
) -> Result<bool, Error> {
    sqlx::query_scalar("SELECT openmettle.capacity_resume($1::uuid, $2, $3)")
        .bind(&controller.group_id)
        .bind(controller.secret.as_slice())
        .bind(controller.epoch)
        .fetch_one(c)
        .await
        .map_err(Error::from)
}

async fn resume_with_metrics(
    c: &mut PgConnection,
    controller: &Controller,
    m: &metrics::Metrics,
) -> Result<bool, Error> {
    if c.is_in_transaction() {
        return resume_query(c, controller).await;
    }
    let span = telemetry::capacity_grant_span(None, None, CapacityOperation::Resume);
    let guard_span = span.clone();
    async {
        let guard = CapacityGrantGuard::new(guard_span, None, None, CapacityOperation::Resume, m);
        let result = resume_query(c, controller).await;
        let outcome = match &result {
            Ok(true) => CapacityOutcome::Resumed,
            Ok(false) => CapacityOutcome::Unavailable,
            Err(err) => error_outcome(err),
        };
        guard.finish(outcome);
        result
    }
    .instrument(span)
    .await
}

/// Reopen bursts in the current epoch. Returns false while the group does not admit them: the
/// epoch needs a fresh sample of its own covering every device and its chat floor, no unknown
/// allocation, and an `Allocated` (or release) attestation for every live earlier-epoch grant.
///
/// Emits `capacity.grant` telemetry only in autocommit mode (`!c.is_in_transaction()`); callers
/// composing an outer transaction own the commit boundary (use [`adapter::GroupCoordinator`]).
pub async fn resume(c: &mut PgConnection, controller: &Controller) -> Result<bool, Error> {
    resume_with_metrics(c, controller, metrics::global()).await
}

/// Bytes one grant commits on one device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceBytes {
    pub device_id: String,
    pub bytes: i64,
}

/// A grant request for an admitted, leased run.
pub struct GrantRequest<'a> {
    pub scope_id: &'a str,
    pub run_id: &'a str,
    /// The worker's active `Step` claim token for the run.
    pub claim_token: &'a str,
    /// Stable identity within the scope. A retry recovers the recorded decision.
    pub request_key: &'a str,
    pub profile: &'a str,
    /// Bytes required on each device; every device must fit on its own.
    pub footprint: &'a [DeviceBytes],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantState {
    Granted,
    Releasing,
    UnknownAllocation,
    Released,
}
impl GrantState {
    fn parse(value: &str) -> Result<Self, Error> {
        match value {
            "granted" => Ok(Self::Granted),
            "releasing" => Ok(Self::Releasing),
            "unknown_allocation" => Ok(Self::UnknownAllocation),
            "released" => Ok(Self::Released),
            _ => Err(Error::Database),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// A durable grant, new or recovered by replay, in its current state.
    Grant { grant_id: String, state: GrantState },
    /// The group admits bursts, but the footprint does not fit every required device now.
    Insufficient,
    /// The group does not admit bursts (see [`resume`]).
    Unavailable,
}

/// Decide a grant under the group fence and the run's active lease. A new grant charges its full
/// footprint and binds the run's `device_reservations` slot before the caller dispatches. If
/// the run lease, controller lease or sample expires while the decision waits for its last lock,
/// it returns `LeaseLost`, `Fenced` or `Expired`, raised by PostgreSQL: the caller's transaction,
/// including writes it made earlier, is already aborted. Roll back on any `Err`.
///
/// Emits `capacity.grant` telemetry only in autocommit mode (`!c.is_in_transaction()`) so a
/// rolled-back or dropped outer transaction can never emit durable `granted` telemetry; callers
/// composing transactions should use [`adapter::GroupCoordinator`].
pub async fn grant(
    c: &mut PgConnection,
    controller: &Controller,
    request: &GrantRequest<'_>,
) -> Result<Decision, Error> {
    if c.is_in_transaction() {
        return grant_inner(c, controller, request).await;
    }
    let span = telemetry::capacity_grant_span(Some(request.run_id), None, CapacityOperation::Grant);
    let guard_span = span.clone();
    async {
        let mut guard = CapacityGrantGuard::new(
            guard_span,
            Some(request.run_id),
            None,
            CapacityOperation::Grant,
            metrics::global(),
        );
        let result = match grant_inner(&mut *c, controller, request).await {
            Ok(Decision::Unavailable) => {
                match group_observation_stale(&mut *c, &controller.group_id).await {
                    Ok(true) => {
                        metrics::global()
                            .record_capacity_stale_observation(CapacityStaleSurface::Controller);
                        Ok(Decision::Unavailable)
                    }
                    Ok(false) => Ok(Decision::Unavailable),
                    Err(err) => Err(err),
                }
            }
            other => other,
        };
        let outcome = match &result {
            Ok(Decision::Grant { grant_id, state }) => {
                guard.set_grant_id(grant_id);
                match state {
                    GrantState::Granted => CapacityOutcome::Granted,
                    GrantState::Releasing => CapacityOutcome::Releasing,
                    GrantState::UnknownAllocation => CapacityOutcome::UnknownAllocation,
                    GrantState::Released => CapacityOutcome::Released,
                }
            }
            Ok(Decision::Insufficient) => CapacityOutcome::Insufficient,
            Ok(Decision::Unavailable) => CapacityOutcome::Unavailable,
            Err(err) => {
                if *err == Error::Expired {
                    metrics::global()
                        .record_capacity_stale_observation(CapacityStaleSurface::Controller);
                }
                error_outcome(err)
            }
        };
        guard.finish(outcome);
        result
    }
    .instrument(span)
    .await
}

async fn grant_inner(
    c: &mut PgConnection,
    controller: &Controller,
    request: &GrantRequest<'_>,
) -> Result<Decision, Error> {
    ids(&[request.scope_id, request.run_id, request.claim_token])?;
    if !crate::runs::bounded(request.request_key, 128)
        || !crate::runs::bounded(request.profile, 128)
        || request
            .footprint
            .iter()
            .any(|d| !is_canonical_uuid(&d.device_id))
    {
        return Err(Error::Invalid);
    }
    let footprint = serde_json::to_string(request.footprint).map_err(|_| Error::Invalid)?;
    let row = sqlx::query(
        "SELECT grant_ref::text, outcome FROM openmettle.capacity_grant(
             $1::uuid, $2, $3, $4::uuid, $5::uuid, $6::uuid, $7, $8, $9::jsonb)",
    )
    .bind(&controller.group_id)
    .bind(controller.secret.as_slice())
    .bind(controller.epoch)
    .bind(request.scope_id)
    .bind(request.run_id)
    .bind(request.claim_token)
    .bind(request.request_key)
    .bind(request.profile)
    .bind(footprint)
    .fetch_one(c)
    .await?;
    let outcome: String = row.try_get("outcome")?;
    Ok(
        match (
            row.try_get::<Option<String>, _>("grant_ref")?,
            outcome.as_str(),
        ) {
            (None, "insufficient") => Decision::Insufficient,
            (None, "unavailable") => Decision::Unavailable,
            (Some(grant_id), state) => Decision::Grant {
                grant_id,
                state: GrantState::parse(state)?,
            },
            _ => return Err(Error::Database),
        },
    )
}

/// Backend inventory evidence or a release trigger for one grant.
#[derive(Clone, Copy, Debug)]
pub enum Evidence<'a> {
    /// Fenced inventory shows the allocation live: attests the grant in this epoch.
    Allocated,
    /// Completion, cancellation, timeout or lease expiry. The charge remains.
    Releasing,
    /// A lost reply or unidentifiable allocation. The charge remains and the group closes until
    /// release evidence resolves it.
    UnknownAllocation,
    /// Confirmed backend release of the grant's allocation on these devices.
    Released(&'a [String]),
    /// Positive evidence that these devices never allocated the grant and, behind the adapter
    /// fence, cannot allocate it from a delayed dispatch.
    NotAllocated(&'a [String]),
}

pub(super) fn reconcile_outcome(
    result: &Result<GrantState, Error>,
    evidence: Evidence<'_>,
) -> CapacityOutcome {
    match result {
        Ok(GrantState::Granted) => CapacityOutcome::Granted,
        Ok(GrantState::Releasing) => CapacityOutcome::Releasing,
        Ok(GrantState::UnknownAllocation) => CapacityOutcome::UnknownAllocation,
        Ok(GrantState::Released) => match evidence {
            Evidence::NotAllocated(_) => CapacityOutcome::NotAllocated,
            _ => CapacityOutcome::Released,
        },
        Err(err) => error_outcome(err),
    }
}

async fn reconcile_with_metrics(
    c: &mut PgConnection,
    controller: &Controller,
    grant_id: &str,
    evidence: Evidence<'_>,
    m: &metrics::Metrics,
) -> Result<GrantState, Error> {
    if c.is_in_transaction() {
        return reconcile_inner(c, controller, grant_id, evidence).await;
    }
    let span = telemetry::capacity_grant_span(None, Some(grant_id), CapacityOperation::Reconcile);
    let guard_span = span.clone();
    async {
        let guard = CapacityGrantGuard::new(
            guard_span,
            None,
            Some(grant_id),
            CapacityOperation::Reconcile,
            m,
        );
        let result = reconcile_inner(c, controller, grant_id, evidence).await;
        let outcome = reconcile_outcome(&result, evidence);
        guard.finish(outcome);
        result
    }
    .instrument(span)
    .await
}

/// Record fenced evidence for a grant. The grant reaches `released`, and its device slot is
/// settled in the same transaction, only when every device of its footprint has confirmed. If
/// the controller lease expires while any step waits for a lock, every change rolls back and it
/// returns `Fenced`, with the caller's transaction already aborted.
///
/// Emits `capacity.grant` telemetry only in autocommit mode (`!c.is_in_transaction()`); callers
/// composing an outer transaction own the commit boundary (use [`adapter::GroupCoordinator`]).
pub async fn reconcile(
    c: &mut PgConnection,
    controller: &Controller,
    grant_id: &str,
    evidence: Evidence<'_>,
) -> Result<GrantState, Error> {
    reconcile_with_metrics(c, controller, grant_id, evidence, metrics::global()).await
}

pub(super) async fn reconcile_inner(
    c: &mut PgConnection,
    controller: &Controller,
    grant_id: &str,
    evidence: Evidence<'_>,
) -> Result<GrantState, Error> {
    ids(&[grant_id])?;
    let (kind, devices): (&str, &[String]) = match evidence {
        Evidence::Allocated => ("allocated", &[]),
        Evidence::Releasing => ("releasing", &[]),
        Evidence::UnknownAllocation => ("unknown_allocation", &[]),
        Evidence::Released(devices) => ("released", devices),
        Evidence::NotAllocated(devices) => ("not_allocated", devices),
    };
    if devices.iter().any(|d| !is_canonical_uuid(d)) {
        return Err(Error::Invalid);
    }
    let state: String = sqlx::query_scalar(
        "SELECT openmettle.capacity_reconcile($1::uuid, $2, $3, $4::uuid, $5, $6::uuid[])",
    )
    .bind(&controller.group_id)
    .bind(controller.secret.as_slice())
    .bind(controller.epoch)
    .bind(grant_id)
    .bind(kind)
    .bind(devices.to_vec())
    .fetch_one(c)
    .await?;
    GrantState::parse(&state)
}

/// The latest published snapshot of one group, read in one statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub controller_epoch: i64,
    pub observation_revision: i64,
    pub observed_at_us: Option<i64>,
    /// The same readiness predicate grant decisions apply (`capacity_admits`).
    pub admits_bursts: bool,
    /// Highest committed grant sequence; cite it as the next sample's watermark.
    pub commit_seq: i64,
    pub commit_watermark: i64,
    pub devices: Vec<DeviceObservation>,
}

/// Group summary of one snapshot revision. Sums are wide enough never to overflow.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GroupTotals {
    pub total_bytes: i128,
    pub committed_bytes: i128,
    pub actual_used_bytes: i128,
    pub reclaimable_bytes: i128,
    pub safety_headroom_bytes: i128,
    pub active_chat_floor_bytes: i128,
    pub grantable_bytes: i128,
}

impl Snapshot {
    /// Group totals for the snapshot's revision. A request constrained to particular ranks must
    /// still fit each device; the group sum never justifies a grant.
    pub fn totals(&self) -> GroupTotals {
        self.devices
            .iter()
            .fold(GroupTotals::default(), |t, d| GroupTotals {
                total_bytes: t.total_bytes + i128::from(d.total_bytes),
                committed_bytes: t.committed_bytes + i128::from(d.committed_bytes),
                actual_used_bytes: t.actual_used_bytes + i128::from(d.actual_used_bytes),
                reclaimable_bytes: t.reclaimable_bytes + i128::from(d.reclaimable_bytes),
                safety_headroom_bytes: t.safety_headroom_bytes
                    + i128::from(d.safety_headroom_bytes),
                active_chat_floor_bytes: t.active_chat_floor_bytes
                    + i128::from(d.active_chat_floor_bytes),
                grantable_bytes: t.grantable_bytes + i128::from(d.grantable_bytes),
            })
    }
}

/// Read the group's latest snapshot. Returns `None` for an unknown group. A read at any
/// isolation level: rows and `admits_bursts` come from the statement's (or, under
/// `REPEATABLE READ`, the transaction's) snapshot.
pub async fn snapshot(c: &mut PgConnection, group_id: &str) -> Result<Option<Snapshot>, Error> {
    ids(&[group_id])?;
    let rows = sqlx::query(
        "SELECT g.controller_epoch, g.observation_revision,
                (extract(epoch FROM g.observed_at) * 1000000)::bigint AS observed_at_us,
                openmettle.capacity_admits(g.id, false) AS admits,
                g.commit_seq, g.commit_watermark, o.device_id::text AS device_id,
                o.total_bytes, o.committed_bytes, o.actual_used_bytes, o.reclaimable_bytes,
                o.safety_headroom_bytes, o.active_chat_floor_bytes, o.grantable_bytes
           FROM openmettle.capacity_groups g
           LEFT JOIN openmettle.capacity_observations o
             ON o.group_id = g.id AND o.revision = g.observation_revision
          WHERE g.id = $1::uuid
          ORDER BY o.device_id",
    )
    .bind(group_id)
    .fetch_all(c)
    .await?;
    let Some(first) = rows.first() else {
        return Ok(None);
    };
    let mut snapshot = Snapshot {
        controller_epoch: first.try_get("controller_epoch")?,
        observation_revision: first.try_get("observation_revision")?,
        observed_at_us: first.try_get("observed_at_us")?,
        admits_bursts: first.try_get("admits")?,
        commit_seq: first.try_get("commit_seq")?,
        commit_watermark: first.try_get("commit_watermark")?,
        devices: Vec::with_capacity(rows.len()),
    };
    for row in &rows {
        let Some(device_id) = row.try_get::<Option<String>, _>("device_id")? else {
            continue;
        };
        snapshot.devices.push(DeviceObservation {
            device_id,
            total_bytes: row.try_get("total_bytes")?,
            committed_bytes: row.try_get("committed_bytes")?,
            actual_used_bytes: row.try_get("actual_used_bytes")?,
            reclaimable_bytes: row.try_get("reclaimable_bytes")?,
            safety_headroom_bytes: row.try_get("safety_headroom_bytes")?,
            active_chat_floor_bytes: row.try_get("active_chat_floor_bytes")?,
            grantable_bytes: row.try_get("grantable_bytes")?,
        });
    }
    Ok(Some(snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(id: &str, total: i64, grantable: i64) -> DeviceObservation {
        DeviceObservation {
            device_id: id.into(),
            total_bytes: total,
            committed_bytes: 1,
            actual_used_bytes: 2,
            reclaimable_bytes: 1,
            safety_headroom_bytes: 3,
            active_chat_floor_bytes: 4,
            grantable_bytes: grantable,
        }
    }

    #[test]
    fn totals_summarize_every_device_without_overflow() {
        let snapshot = Snapshot {
            controller_epoch: 1,
            observation_revision: 1,
            observed_at_us: Some(1),
            admits_bursts: true,
            commit_seq: 0,
            commit_watermark: 0,
            devices: vec![device("a", i64::MAX, 5), device("b", i64::MAX, 7)],
        };
        let totals = snapshot.totals();
        assert_eq!(totals.total_bytes, 2 * i128::from(i64::MAX));
        assert_eq!(totals.grantable_bytes, 12);
        assert_eq!(totals.committed_bytes, 2);
        assert_eq!(totals.actual_used_bytes, 4);
        assert_eq!(totals.reclaimable_bytes, 2);
        assert_eq!(totals.safety_headroom_bytes, 6);
        assert_eq!(totals.active_chat_floor_bytes, 8);
    }

    #[test]
    fn controller_debug_redacts_the_secret_and_states_reject_unknown_values() {
        let controller = Controller {
            group_id: "g".into(),
            epoch: 3,
            secret: [0xa5; 32],
        };
        let shown = format!("{controller:?}");
        assert!(shown.contains("epoch: 3") && !shown.contains("secret") && !shown.contains("165"));
        assert_eq!(lease_ms(Duration::from_secs(u64::MAX)), Err(Error::Invalid));
        assert_eq!(GrantState::parse("released"), Ok(GrantState::Released));
        assert_eq!(GrantState::parse("requested"), Err(Error::Database));
    }

    #[test]
    fn valid_capacity_name_rejects_unicode_whitespace_and_control_characters() {
        assert!(valid_capacity_name("synthetic-image"));
        assert!(valid_capacity_name("model v1"));
        assert!(valid_capacity_name(&"a".repeat(128)));
        assert!(!valid_capacity_name(""));
        assert!(!valid_capacity_name(&"a".repeat(129)));
        for bad in [
            " leading",
            "trailing ",
            "\tleading",
            "trailing\n",
            "\u{00a0}model",
            "model\u{00a0}",
            "\u{3000}model",
            "model\u{2028}",
            "model\tname",
            "model\u{0085}name",
            "model\u{007f}name",
            "model\u{0000}name",
        ] {
            assert!(
                !valid_capacity_name(bad),
                "expected invalid capacity name: {bad:?}"
            );
        }
    }
}
