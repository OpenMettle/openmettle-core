//! Transactional quota operations paired with gateway allocation, dispatch, authenticated
//! visibility and `ManageQuotas` scope overrides (ADR 0040).
use crate::{
    authz::gateway::{Authority, Call, Error, Reservation},
    authz::{
        self, Action, AdminChange, DenialReason, PolicyReason,
        runs::{AdmissionLimits, ClaimLimits, RunLimit},
        store::{self, AuditContext, StoreError},
    },
    runs::WriteTransaction,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Acquire, PgConnection, PgPool, Postgres, Row, Transaction};
use std::fmt;

pub(crate) async fn prepare_round(
    tx: &mut WriteTransaction<'_>,
    call: &Call<'_>,
    cost_ceiling: Option<i64>,
) -> Result<(), Error> {
    if let Authority::Lease { run, round, token } = call.authority {
        let has_actor_prefix: bool = sqlx::query_scalar(
            "SELECT to_regprocedure(
                 'openmettle.quota_lock_run_actor_prefix(uuid,uuid)'
             ) IS NOT NULL",
        )
        .fetch_one(tx.connection()?)
        .await?;
        if has_actor_prefix {
            sqlx::query("SELECT openmettle.quota_lock_run_actor_prefix($1::uuid,$2::uuid)")
                .bind(call.reservation.scope_id)
                .bind(run)
                .execute(tx.connection()?)
                .await?;
        }
        sqlx::query(
            "SELECT openmettle.quota_unwind_superseded_round($1::uuid,$2::uuid,$3::uuid,$4)",
        )
        .bind(call.reservation.scope_id)
        .bind(run)
        .bind(token)
        .bind(round)
        .execute(tx.connection()?)
        .await
        .map_err(crate::authz::gateway::map_stale_lease)?;
        let has_v26_prepare: bool = sqlx::query_scalar(
            "SELECT to_regprocedure(
                 'openmettle.quota_prepare_turn_round(uuid,uuid,uuid,bigint,bigint,boolean,boolean,boolean,boolean)'
             ) IS NOT NULL",
        )
        .fetch_one(tx.connection()?)
        .await?;
        if has_v26_prepare {
            sqlx::query(
                "SELECT openmettle.quota_prepare_turn_round(
                     $1::uuid,$2::uuid,$3::uuid,$4,$5,false,false,false,true
                 )",
            )
            .bind(call.reservation.scope_id)
            .bind(run)
            .bind(token)
            .bind(call.units)
            .bind(cost_ceiling)
            .execute(tx.connection()?)
            .await
            .map_err(crate::authz::gateway::map_stale_lease)?;
        } else {
            sqlx::query(
                "SELECT openmettle.quota_ensure_legacy_run_holds($1::uuid,$2::uuid,$3::uuid)",
            )
            .bind(call.reservation.scope_id)
            .bind(run)
            .bind(token)
            .execute(tx.connection()?)
            .await
            .map_err(crate::authz::gateway::map_stale_lease)?;
        }
    }
    Ok(())
}

struct CostLimitState {
    denomination: Option<String>,
    any_limit: bool,
    personal_limit: bool,
    min_limit: Option<i64>,
    tightest_scope_kind: Option<String>,
}

async fn cost_limit_state(
    c: &mut PgConnection,
    scope_id: &str,
    actor_user_id: &str,
) -> Result<CostLimitState, sqlx::Error> {
    let (denomination, any_limit, personal_limit, min_limit, tightest_scope_kind): (
        Option<String>,
        bool,
        bool,
        Option<i64>,
        Option<String>,
    ) = sqlx::query_as(
        "WITH stamp AS (SELECT clock_timestamp() AS now),
         tiers AS (
             SELECT id AS scope_id, kind AS scope_kind, (personal_user_id = $2::uuid) AS is_personal
               FROM openmettle.scopes
              WHERE id = $1::uuid OR personal_user_id = $2::uuid
             UNION ALL
             SELECT NULL::uuid, 'instance'::text, false
         ),
         resolved AS (
             SELECT t.scope_kind,
                    t.is_personal,
                    coalesce(
                        CASE WHEN o.revoked_at IS NULL
                              AND (o.expires_at IS NULL OR o.expires_at > (SELECT now FROM stamp))
                             THEN o.hard_limit END,
                        d.hard_limit
                    ) AS hard_limit
               FROM tiers t
               LEFT JOIN openmettle.quota_defaults d
                 ON d.scope_kind = t.scope_kind AND d.resource_kind = 'usage_cost_micros'
               LEFT JOIN openmettle.quota_overrides o
                 ON o.scope_id = t.scope_id AND o.resource_kind = 'usage_cost_micros'
         )
         SELECT (SELECT cost_denomination FROM openmettle.quota_defaults
                  WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros'),
                EXISTS (SELECT 1 FROM resolved WHERE hard_limit IS NOT NULL),
                EXISTS (SELECT 1 FROM resolved WHERE is_personal AND hard_limit IS NOT NULL),
                (SELECT min(hard_limit) FROM resolved),
                (SELECT scope_kind FROM resolved
                  WHERE hard_limit IS NOT NULL
                  ORDER BY hard_limit ASC,
                           CASE scope_kind WHEN 'personal' THEN 0 WHEN 'project' THEN 1 ELSE 2 END
                  LIMIT 1)",
    )
    .bind(scope_id)
    .bind(actor_user_id)
    .fetch_one(c)
    .await?;
    Ok(CostLimitState {
        denomination,
        any_limit,
        personal_limit,
        min_limit,
        tightest_scope_kind,
    })
}

async fn round_cost_slice(
    c: &mut PgConnection,
    scope_id: &str,
    run_id: &str,
    current_request_id: Option<&str>,
) -> Result<Option<i64>, sqlx::Error> {
    let has_slice_fn: bool = sqlx::query_scalar(
        "SELECT to_regprocedure(
             'openmettle.quota_run_round_cost_slice(uuid,uuid,uuid)'
         ) IS NOT NULL",
    )
    .fetch_one(&mut *c)
    .await?;
    if !has_slice_fn {
        return Ok(None);
    }
    sqlx::query_scalar("SELECT openmettle.quota_run_round_cost_slice($1::uuid,$2::uuid,$3::uuid)")
        .bind(scope_id)
        .bind(run_id)
        .bind(current_request_id)
        .fetch_one(&mut *c)
        .await
}

/// How a caller specifies the per-request cost bound for `cost_ceiling` / `bind_request`.
#[derive(Clone, Copy)]
pub(crate) enum CostBoundSpec {
    /// Non-catalog `gateway::hold` / `gateway::reserve`: derive slice or ceiling from configured
    /// limits when cost metering applies.
    Legacy,
    /// Catalog-driven turn round (`TurnRound`) or explicit caller bound: `Some(c)` supplies the
    /// qualified ceiling; `None` means the profile has no qualified `cost_bound` and must fail
    /// closed whenever any cost tier applies.
    Profile(Option<u128>),
}

#[allow(clippy::too_many_arguments)]
async fn resolve_cost_from_state(
    c: &mut PgConnection,
    state: &CostLimitState,
    owner: &Reservation<'_>,
    run: Option<&str>,
    current_request_id: Option<&str>,
    parent_cost_held: Option<i64>,
    enforced: bool,
    spec: CostBoundSpec,
) -> Result<Option<i64>, Error> {
    if state.any_limit {
        if !enforced && parent_cost_held.is_none() {
            return if matches!(spec, CostBoundSpec::Profile(None)) {
                Err(Error::Refused)
            } else {
                Ok(None)
            };
        }
        if state.denomination.is_none() || !state.personal_limit {
            return Err(Error::Refused);
        }
        let Some(limit) = state.min_limit.filter(|&l| l > 0) else {
            return Err(Error::Refused);
        };
        let amount = match spec {
            CostBoundSpec::Profile(Some(n)) => {
                let Ok(n) = i64::try_from(n) else {
                    return Err(Error::Refused);
                };
                if n <= 0 || n > limit {
                    return Err(Error::Refused);
                }
                if let Some(held) = parent_cost_held
                    && n > held
                {
                    return Err(Error::Refused);
                }
                n
            }
            CostBoundSpec::Profile(None) => return Err(Error::Refused),
            CostBoundSpec::Legacy => {
                let slice = if let Some(run_id) = run
                    && let Some(s) =
                        round_cost_slice(c, owner.scope_id, run_id, current_request_id).await?
                {
                    s.min(limit)
                } else {
                    limit
                };
                let slice = parent_cost_held.map_or(slice, |held| slice.min(held));
                if slice <= 0 {
                    return Err(Error::Refused);
                }
                slice
            }
        };
        Ok(Some(amount))
    } else if let Some(held) = parent_cost_held {
        let amount = match spec {
            CostBoundSpec::Profile(Some(s)) => {
                let s = i64::try_from(s).map_err(|_| Error::Refused)?;
                if s <= 0 || s > held {
                    return Err(Error::Refused);
                }
                s
            }
            CostBoundSpec::Legacy | CostBoundSpec::Profile(None) => {
                let slice = if let Some(run_id) = run {
                    round_cost_slice(c, owner.scope_id, run_id, current_request_id)
                        .await?
                        .unwrap_or(held)
                } else {
                    held
                }
                .min(held);
                if slice <= 0 {
                    return Err(Error::Refused);
                }
                slice
            }
        };
        Ok(Some(amount))
    } else {
        if matches!(spec, CostBoundSpec::Profile(Some(0))) {
            return Err(Error::Refused);
        }
        Ok(None)
    }
}

pub(crate) async fn cost_ceiling(
    tx: &mut WriteTransaction<'_>,
    owner: &Reservation<'_>,
    run: Option<&str>,
    current_request_id: Option<&str>,
    spec: CostBoundSpec,
) -> Result<Option<i64>, Error> {
    let state = cost_limit_state(tx.connection()?, owner.scope_id, owner.actor).await?;
    resolve_cost_from_state(
        tx.connection()?,
        &state,
        owner,
        run,
        current_request_id,
        None,
        true,
        spec,
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindOutcome {
    /// Request holds were bound (`enforced_at_bind` is true when `metering_enforced` was already
    /// active during binding; `cost_bound_at_bind` is true when a `usage_cost_micros` hold was
    /// bound for the request).
    Bound {
        enforced_at_bind: bool,
        cost_bound_at_bind: bool,
    },
    /// `metering_enforced` flipped `false -> true` after `quota_prepare_turn_round` skipped
    /// creating run-level parent holds; caller must roll back and retry preparation with
    /// `p_require_holds = true`.
    NeedsParentHolds,
}

pub(crate) async fn bind_request(
    tx: &mut WriteTransaction<'_>,
    call: &Call<'_>,
    id: &str,
    secret: &[u8],
    spec: CostBoundSpec,
    requires_device_slot: bool,
) -> Result<BindOutcome, Error> {
    let enforced: bool =
        sqlx::query_scalar("SELECT metering_enforced FROM openmettle.quota_enforcement WHERE id")
            .fetch_one(tx.connection()?)
            .await?;
    match call.authority {
        Authority::Session { .. } => {
            let cost = cost_ceiling(tx, &call.reservation, None, Some(id), spec).await?;
            for (resource, amount) in [
                ("usage_cost_micros", cost),
                ("usage_tokens", Some(call.units)),
            ] {
                let Some(amount) = amount else { continue };
                sqlx::query(
                    "SELECT openmettle.quota_reserve($1::uuid,$2::uuid,$3,$4,$5,NULL,$6::uuid,$7,
                    clock_timestamp()+interval '15 minutes')",
                )
                .bind(call.reservation.scope_id)
                .bind(call.reservation.actor)
                .bind(resource)
                .bind(amount)
                .bind(format!("request:{id}"))
                .bind(id)
                .bind(secret)
                .execute(tx.connection()?)
                .await?;
            }
            Ok(BindOutcome::Bound {
                enforced_at_bind: true,
                cost_bound_at_bind: cost.is_some(),
            })
        }
        Authority::Lease { run, token, .. } => {
            // Query already-charged parent holds on this run in BOTH activation states and resolve
            // cost-limit state in one atomic `clock_timestamp()` snapshot so an expiring cost limit
            // can never drop a cost child when a held cost parent exists.
            let parents: Vec<(String, i64)> = sqlx::query_as(
                "SELECT resource_kind, held_units
                   FROM openmettle.quota_reservations
                  WHERE scope_id = $1::uuid
                    AND run_id = $2::uuid
                    AND gateway_request_id IS NULL
                    AND (
                        (resource_kind IN ('usage_cost_micros', 'usage_tokens') AND state = 'held')
                        OR (resource_kind = 'device_reservations' AND state IN ('held', 'handoff_committed'))
                    )
                  ORDER BY resource_kind ASC",
            )
            .bind(call.reservation.scope_id)
            .bind(run)
            .fetch_all(tx.connection()?)
            .await?;
            let mut parent_cost_held = None;
            let mut has_token_parent = false;
            let mut has_device_parent = false;
            for (kind, held) in parents {
                match kind.as_str() {
                    "usage_cost_micros" => parent_cost_held = Some(held),
                    "usage_tokens" => has_token_parent = true,
                    "device_reservations" => has_device_parent = true,
                    _ => {}
                }
            }
            if enforced && (!has_token_parent || (requires_device_slot && !has_device_parent)) {
                return Ok(BindOutcome::NeedsParentHolds);
            }
            let state = cost_limit_state(
                tx.connection()?,
                call.reservation.scope_id,
                call.reservation.actor,
            )
            .await?;
            let cost = resolve_cost_from_state(
                tx.connection()?,
                &state,
                &call.reservation,
                Some(run),
                Some(id),
                parent_cost_held,
                enforced,
                spec,
            )
            .await?;
            if parent_cost_held.is_some() && cost.is_none() {
                return Err(Error::Refused);
            }
            if enforced && cost.is_some() && parent_cost_held.is_none() {
                return Ok(BindOutcome::NeedsParentHolds);
            }
            let tokens = (enforced || has_token_parent).then_some(call.units);
            for (resource, amount) in [("usage_cost_micros", cost), ("usage_tokens", tokens)] {
                let Some(amount) = amount else { continue };
                sqlx::query("SELECT openmettle.quota_allocate_round($1::uuid,$2,$3::uuid,$4,$5)")
                    .bind(id)
                    .bind(secret)
                    .bind(token)
                    .bind(resource)
                    .bind(amount)
                    .execute(tx.connection()?)
                    .await?;
            }
            Ok(BindOutcome::Bound {
                enforced_at_bind: enforced,
                cost_bound_at_bind: cost.is_some(),
            })
        }
    }
}

const NIL: &str = "00000000-0000-0000-0000-000000000000";
const MAX: &str = "ffffffff-ffff-ffff-ffff-ffffffffffff";

/// One fixed upper bound per pass. Timestamps travel as PostgreSQL text to preserve precision.
#[derive(Default)]
pub(crate) struct Pass {
    upper: Option<String>,
    after: Option<(String, String)>,
}
impl Pass {
    fn cursor(&self) -> (&str, &str) {
        self.after
            .as_ref()
            .map_or(("-infinity", NIL), |(at, id)| (at, id))
    }
}

pub(crate) async fn reconcile_stale_quotas(
    pool: &PgPool,
    pass: &mut Pass,
    limit: i32,
) -> Result<(), crate::runs::Error> {
    if !(1..=1000).contains(&limit) {
        return Err(crate::runs::Error::Invalid);
    }
    if pass.upper.is_none() {
        pass.upper = Some(
            sqlx::query_scalar("SELECT clock_timestamp()::text")
                .fetch_one(pool)
                .await?,
        );
    }
    let (at, id) = pass.cursor();
    let page=sqlx::query_as::<_,(String,String,bool)>("WITH page AS MATERIALIZED (
        SELECT lease_expires_at,id,run_id FROM openmettle.quota_reservations WHERE state='held'
        AND (lease_expires_at,id)>($1::text::timestamptz,$2::uuid)
        AND (lease_expires_at,id)<=($3::text::timestamptz,$4::uuid) ORDER BY lease_expires_at,id LIMIT $5)
        SELECT p.lease_expires_at::text,p.id::text,(p.run_id IS NULL OR EXISTS (SELECT FROM openmettle.runs r
        WHERE r.id=p.run_id AND r.state IN ('succeeded','failed','cancelled','interrupted')
        AND NOT EXISTS (SELECT FROM openmettle.operations o WHERE o.run_id=r.id AND o.outcome IN ('intent','outcome_unknown'))))
        FROM page p ORDER BY p.lease_expires_at,p.id")
        .bind(at).bind(id).bind(&pass.upper).bind(MAX).bind(limit).fetch_all(pool).await?;
    let count = page.len();
    for (at, id, eligible) in page {
        pass.after = Some((at, id.clone()));
        if eligible {
            let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
            sqlx::query("SELECT openmettle.quota_release_unsent($1::uuid,NULL,true)")
                .bind(&id)
                .execute(tx.connection()?)
                .await?;
            tx.commit().await?;
        }
    }
    if count < limit as usize {
        *pass = Pass::default();
    }
    Ok(())
}

/// One short transaction can unwind at most one orphan. An early return after a release
/// advances the cursor without mistaking the partially inspected page for the end of a pass.
pub(crate) async fn orphan_page(
    pool: &PgPool,
    pass: &mut Pass,
    limit: i32,
) -> Result<(bool, i32), crate::runs::Error> {
    if !(1..=1000).contains(&limit) {
        return Err(crate::runs::Error::Invalid);
    }
    if pass.upper.is_none() {
        pass.upper = Some(
            sqlx::query_scalar("SELECT (clock_timestamp()-interval '15 minutes')::text")
                .fetch_one(pool)
                .await?,
        );
    }
    let (at, id) = pass.cursor();
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    let (at,id,scanned,released):(String,String,i32,i32)=sqlx::query_as("SELECT next_created_at::text,next_id::text,
        raw_keys_scanned,released_count FROM openmettle.quota_release_orphan_gateway_requests(interval '15 minutes',
        $1::text::timestamptz,$2::uuid,$3::text::timestamptz,$4::uuid,$5)")
        .bind(at).bind(id).bind(&pass.upper).bind(MAX).bind(limit).fetch_one(tx.connection()?).await?;
    tx.commit().await?;
    let done = released == 0 && scanned < limit;
    if done {
        *pass = Pass::default();
    } else {
        pass.after = Some((at, id));
    }
    Ok((done, released))
}

/// Perform a complete bounded-key pass after old writers have drained. Each release commits separately.
pub async fn drain_gateway_orphans(pool: &PgPool) -> Result<u64, crate::runs::Error> {
    let mut pass = Pass::default();
    let mut total = 0;
    loop {
        let (done, released) = orphan_page(pool, &mut pass, 100).await?;
        total += released as u64;
        if done {
            return Ok(total);
        }
    }
}

pub(crate) async fn emit_warnings(pool: &PgPool) -> Result<(), sqlx::Error> {
    let warnings = sqlx::query_as::<_, (String, String, String, i16, i64)>(
        "SELECT * FROM openmettle.quota_take_warnings(100)",
    )
    .fetch_all(pool)
    .await?;
    for (target, scope, resource, threshold, bucket) in warnings {
        crate::telemetry::quota_warning(&target, &scope, &resource, threshold, bucket);
    }
    Ok(())
}

/// Count a bounded index page without taking row locks or changing the underlying holds.
pub(crate) async fn observe_overdue_handoffs(pool: &PgPool, limit: i32) -> Result<(), sqlx::Error> {
    let observed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM (SELECT id FROM openmettle.quota_reservations
         WHERE state='handoff_committed' AND lease_expires_at <= statement_timestamp()
         ORDER BY lease_expires_at,id LIMIT $1) AS overdue",
    )
    .bind(limit)
    .fetch_one(pool)
    .await?;
    crate::telemetry::metrics::global().record_overdue_handoffs(observed as u64);
    Ok(())
}

// --- ADR 0040 PR3: authenticated visibility and idempotent scope overrides --------------------

/// Managed quota resource kinds (Migration 0024).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum QuotaResourceKind {
    StorageBytes,
    UsageTokens,
    UsageCostMicros,
    DeviceReservations,
    LiveRunsPerActor,
    LiveRunsPerScope,
    ExecutingRunsPerActor,
    ExecutingRunsPerScope,
    RoundCap,
}

impl QuotaResourceKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "storage_bytes" => Some(Self::StorageBytes),
            "usage_tokens" => Some(Self::UsageTokens),
            "usage_cost_micros" => Some(Self::UsageCostMicros),
            "device_reservations" => Some(Self::DeviceReservations),
            "live_runs_per_actor" => Some(Self::LiveRunsPerActor),
            "live_runs_per_scope" => Some(Self::LiveRunsPerScope),
            "executing_runs_per_actor" => Some(Self::ExecutingRunsPerActor),
            "executing_runs_per_scope" => Some(Self::ExecutingRunsPerScope),
            "round_cap" => Some(Self::RoundCap),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StorageBytes => "storage_bytes",
            Self::UsageTokens => "usage_tokens",
            Self::UsageCostMicros => "usage_cost_micros",
            Self::DeviceReservations => "device_reservations",
            Self::LiveRunsPerActor => "live_runs_per_actor",
            Self::LiveRunsPerScope => "live_runs_per_scope",
            Self::ExecutingRunsPerActor => "executing_runs_per_actor",
            Self::ExecutingRunsPerScope => "executing_runs_per_scope",
            Self::RoundCap => "round_cap",
        }
    }

    pub const fn is_per_actor(self) -> bool {
        matches!(self, Self::LiveRunsPerActor | Self::ExecutingRunsPerActor)
    }

    pub const fn is_round_cap(self) -> bool {
        matches!(self, Self::RoundCap)
    }
}

/// Errors from quota summary reads and `ManageQuotas` override writes.
#[derive(Debug)]
pub enum QuotaError {
    Store(StoreError),
    /// `quota_enforcement.metering_enforced = false`: rolling-upgrade activation incomplete.
    UpgradeNotEnforced,
    /// `storage_volume_control.adoption_run_id IS NOT NULL`: storage volume adoption in progress.
    AdoptionInProgress,
    /// `usage_cost_micros` override requested while instance `cost_denomination` is unconfigured (`OMQ02`).
    CostDenominationUnconfigured,
}

impl fmt::Display for QuotaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => e.fmt(f),
            Self::UpgradeNotEnforced => f.write_str("quota metering is not yet enabled"),
            Self::AdoptionInProgress => f.write_str("storage volume adoption is in progress"),
            Self::CostDenominationUnconfigured => {
                f.write_str("cost denomination is not configured")
            }
        }
    }
}

impl std::error::Error for QuotaError {}

impl From<StoreError> for QuotaError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<sqlx::Error> for QuotaError {
    fn from(error: sqlx::Error) -> Self {
        Self::Store(StoreError::Database(error))
    }
}

impl From<crate::runs::Error> for QuotaError {
    fn from(error: crate::runs::Error) -> Self {
        Self::Store(error.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QuotaStorageSummary {
    pub limit_bytes: Option<String>,
    pub limit_source: String,
    pub override_expires_at: Option<String>,
    pub active_bytes: String,
    pub retained_bytes: String,
    pub reserved_bytes: String,
    pub charged_bytes: String,
    pub remaining_bytes: Option<String>,
    pub warn_thresholds: [i16; 2],
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QuotaUsageItem {
    pub resource_kind: String,
    pub unit: Option<String>,
    pub window_kind: String,
    pub window_start: String,
    pub window_end: Option<String>,
    pub limit: Option<String>,
    pub limit_source: String,
    pub override_expires_at: Option<String>,
    pub active_used: String,
    pub reserved_held: String,
    pub remaining: Option<String>,
    pub warn_thresholds: [i16; 2],
    pub status: String,
    pub authoritative_source: String,
    pub last_reconciled_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QuotaExecutionCounter {
    pub current: String,
    pub limit: Option<String>,
    pub limit_source: String,
    pub override_expires_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QuotaLimitProjection {
    pub limit: Option<String>,
    pub limit_source: String,
    pub override_expires_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QuotaExecutionSummary {
    pub live_runs_per_scope: QuotaExecutionCounter,
    pub executing_runs_per_scope: QuotaExecutionCounter,
    pub round_cap: QuotaLimitProjection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_runs_per_actor: Option<QuotaExecutionCounter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executing_runs_per_actor: Option<QuotaExecutionCounter>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QuotaDeviceReservationsSummary {
    pub reserved_held: String,
    pub limit: Option<String>,
    pub limit_source: String,
    pub override_expires_at: Option<String>,
    pub warn_thresholds: [i16; 2],
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QuotaDeviceCapacitySummary {
    pub active_reservations: QuotaDeviceReservationsSummary,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QuotaWarning {
    pub resource_kind: String,
    pub threshold_pct: i16,
    pub dedupe_bucket: String,
    pub triggered_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QuotaSummary {
    pub scope_id: String,
    pub scope_kind: String,
    pub observed_at: String,
    pub storage: QuotaStorageSummary,
    pub usage: Vec<QuotaUsageItem>,
    pub execution: QuotaExecutionSummary,
    pub device_capacity: QuotaDeviceCapacitySummary,
    pub warnings: Vec<QuotaWarning>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaOverride {
    pub scope_id: String,
    pub scope_kind: String,
    pub resource_kind: String,
    pub hard_limit: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub revision: String,
    pub updated_at: String,
}

fn format_timestamp_us(micros: i64) -> Result<String, QuotaError> {
    chrono::DateTime::from_timestamp_micros(micros)
        .map(|at| at.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string())
        .ok_or_else(|| {
            QuotaError::Store(StoreError::Database(sqlx::Error::Protocol(
                "timestamp out of range".into(),
            )))
        })
}

fn opt_timestamp_us(micros: Option<i64>) -> Result<Option<String>, QuotaError> {
    micros.map(format_timestamp_us).transpose()
}

fn parse_u128_text(text: &str) -> Result<u128, QuotaError> {
    text.parse::<u128>().map_err(|_| {
        QuotaError::Store(StoreError::Database(sqlx::Error::Protocol(
            "invalid wide quota counter".into(),
        )))
    })
}

fn threshold_status(limit: Option<i64>, charged: u128, warn_pct_1: i16) -> &'static str {
    let Some(limit) = limit else {
        return "unconfigured";
    };
    if limit <= 0 || charged >= limit as u128 {
        return "hard_limit";
    }
    let warn = u128::from(warn_pct_1.max(1) as u16);
    if charged.saturating_mul(100) >= (limit as u128).saturating_mul(warn) {
        "warning"
    } else {
        "ok"
    }
}

fn resolve_limit(
    override_limit: Option<i64>,
    override_expires_us: Option<i64>,
    default_limit: Option<i64>,
) -> Result<(Option<i64>, &'static str, Option<String>), QuotaError> {
    if let Some(lim) = override_limit {
        Ok((
            Some(lim),
            "override",
            opt_timestamp_us(override_expires_us)?,
        ))
    } else if let Some(lim) = default_limit {
        Ok((Some(lim), "default", None))
    } else {
        Ok((None, "unconfigured", None))
    }
}

/// Read one consistent primary-database quota summary for `scope_id`.
///
/// Callers must authorize scope visibility on the primary first. Pass `actor_user_id = Some(...)`
/// for a personal scope summary and `None` for a project scope summary so per-actor counters are
/// omitted on project summaries. Remaining capacity is computed strictly from
/// `max(0, owner_limit - owner_charged)` and never leaks instance headroom.
pub async fn read_summary(
    c: &mut PgConnection,
    scope_id: &str,
    actor_user_id: Option<&str>,
    admission: Option<AdmissionLimits>,
    claim: Option<ClaimLimits>,
) -> Result<QuotaSummary, QuotaError> {
    store::uuid(scope_id, "scope_id")?;
    if let Some(actor) = actor_user_id {
        store::uuid(actor, "actor_user_id")?;
    }
    let mut tx = c.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT set_config('statement_timeout', '3s', true)")
        .execute(&mut *tx)
        .await?;
    let result = read_summary_in_tx(&mut tx, scope_id, actor_user_id, admission, claim).await;
    match result {
        Ok(summary) => {
            tx.commit().await?;
            Ok(summary)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

/// Read one quota summary inside an already-open `REPEATABLE READ, READ ONLY` transaction so
/// authorization checks and quota reads share a single consistent database snapshot.
pub(crate) async fn read_summary_in_tx(
    tx: &mut PgConnection,
    scope_id: &str,
    actor_user_id: Option<&str>,
    admission: Option<AdmissionLimits>,
    claim: Option<ClaimLimits>,
) -> Result<QuotaSummary, QuotaError> {
    store::uuid(scope_id, "scope_id")?;
    if let Some(actor) = actor_user_id {
        store::uuid(actor, "actor_user_id")?;
    }

    let scope_row: Option<(String, i64, String)> = sqlx::query_as(
        "SELECT s.kind,
                (extract(epoch FROM t.now) * 1000000)::bigint,
                t.now::text
           FROM openmettle.scopes s
           CROSS JOIN (SELECT clock_timestamp() AS now) t
          WHERE s.id = $1::uuid",
    )
    .bind(scope_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((scope_kind, observed_us, observed_ts)) = scope_row else {
        return Err(QuotaError::Store(StoreError::NotFound));
    };
    let observed_at = format_timestamp_us(observed_us)?;
    let day_bucket_ts: String =
        sqlx::query_scalar("SELECT date_trunc('day', $1::text::timestamptz, 'UTC')::text")
            .bind(&observed_ts)
            .fetch_one(&mut *tx)
            .await?;

    // 1. Storage summary
    let s_row = sqlx::query(
        "SELECT coalesce(a.active_bytes, 0) AS active_bytes,
                coalesce(a.retained_bytes, 0) AS retained_bytes,
                coalesce(a.reserved_bytes, 0) AS reserved_bytes,
                CASE WHEN $2 = 'personal' THEN i.personal_limit_bytes ELSE i.project_limit_bytes END AS default_limit,
                coalesce(i.warn_pct_1, 80)::smallint AS warn_pct_1,
                coalesce(i.warn_pct_2, 90)::smallint AS warn_pct_2,
                coalesce(i.config_revision, 1) AS config_revision,
                CASE WHEN o.revoked_at IS NULL AND (o.expires_at IS NULL OR o.expires_at > $3::text::timestamptz)
                     THEN o.hard_limit END AS override_limit,
                CASE WHEN o.revoked_at IS NULL AND (o.expires_at IS NULL OR o.expires_at > $3::text::timestamptz)
                     THEN (extract(epoch FROM o.expires_at) * 1000000)::bigint END AS override_expires_us,
                CASE
                    WHEN o.revoked_at IS NOT NULL THEN o.revision
                    WHEN o.expires_at IS NULL OR o.expires_at > $3::text::timestamptz THEN coalesce(o.revision, 0)
                    ELSE 0
                END AS limit_revision
           FROM (VALUES (1)) AS seed(id)
           LEFT JOIN openmettle.storage_accounts a ON a.scope_id = $1::uuid
           LEFT JOIN openmettle.storage_instance i ON i.id
           LEFT JOIN openmettle.quota_overrides o
             ON o.scope_id = $1::uuid AND o.resource_kind = 'storage_bytes'",
    )
    .bind(scope_id)
    .bind(&scope_kind)
    .bind(&observed_ts)
    .fetch_one(&mut *tx)
    .await?;

    let active_bytes: i64 = s_row.try_get("active_bytes")?;
    let retained_bytes: i64 = s_row.try_get("retained_bytes")?;
    let reserved_bytes: i64 = s_row.try_get("reserved_bytes")?;
    let charged_u128 = (active_bytes as u128)
        .saturating_add(retained_bytes as u128)
        .saturating_add(reserved_bytes as u128);
    let warn1: i16 = s_row.try_get("warn_pct_1")?;
    let warn2: i16 = s_row.try_get("warn_pct_2")?;
    let (storage_limit, storage_source, storage_override_exp) = resolve_limit(
        s_row.try_get("override_limit")?,
        s_row.try_get("override_expires_us")?,
        s_row.try_get("default_limit")?,
    )?;
    let remaining_bytes =
        storage_limit.map(|lim| (lim as u128).saturating_sub(charged_u128).to_string());
    let storage = QuotaStorageSummary {
        limit_bytes: storage_limit.map(|v| v.to_string()),
        limit_source: storage_source.to_owned(),
        override_expires_at: storage_override_exp,
        active_bytes: active_bytes.to_string(),
        retained_bytes: retained_bytes.to_string(),
        reserved_bytes: reserved_bytes.to_string(),
        charged_bytes: charged_u128.to_string(),
        remaining_bytes,
        warn_thresholds: [warn1, warn2],
        status: threshold_status(storage_limit, charged_u128, warn1).to_owned(),
    };
    let mut active_warn_keys: Vec<(String, String, i64, i64)> = vec![(
        "storage_bytes".to_owned(),
        day_bucket_ts.clone(),
        s_row.try_get("limit_revision")?,
        s_row.try_get("config_revision")?,
    )];
    let mut warn_state = std::collections::BTreeMap::new();
    warn_state.insert("storage_bytes".to_owned(), (storage_limit, charged_u128));

    // 2. Metered usage budgets (usage_tokens, usage_cost_micros)
    let usage_rows = sqlx::query(
        "WITH resources(ord, resource_kind) AS (
             VALUES (1, 'usage_tokens'), (2, 'usage_cost_micros')
         ),
         denom AS (
             SELECT cost_denomination
               FROM openmettle.quota_defaults
              WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros'
         ),
         resolved AS (
             SELECT r.ord,
                    r.resource_kind,
                    (SELECT cost_denomination FROM denom) AS cost_denomination,
                    d.hard_limit AS default_limit,
                    d.window_seconds,
                    coalesce(d.warn_pct_1, 80)::smallint AS warn_pct_1,
                    coalesce(d.warn_pct_2, 90)::smallint AS warn_pct_2,
                    coalesce(d.config_revision, 1) AS config_revision,
                    CASE WHEN o.revoked_at IS NULL AND (o.expires_at IS NULL OR o.expires_at > $3::text::timestamptz)
                         THEN o.hard_limit END AS override_limit,
                    CASE WHEN o.revoked_at IS NULL AND (o.expires_at IS NULL OR o.expires_at > $3::text::timestamptz)
                         THEN (extract(epoch FROM o.expires_at) * 1000000)::bigint END AS override_expires_us,
                    CASE
                        WHEN o.revoked_at IS NOT NULL THEN o.revision
                        WHEN o.expires_at IS NULL OR o.expires_at > $3::text::timestamptz THEN coalesce(o.revision, 0)
                        ELSE 0
                    END AS limit_revision,
                    CASE WHEN d.window_seconds IS NULL THEN 'static' ELSE 'windowed' END AS window_kind,
                    CASE WHEN d.window_seconds IS NULL THEN 'epoch'::timestamptz
                         ELSE date_bin(make_interval(secs => d.window_seconds), $3::text::timestamptz, 'epoch')
                    END AS window_start,
                    CASE WHEN d.window_seconds IS NULL THEN NULL
                         ELSE date_bin(make_interval(secs => d.window_seconds), $3::text::timestamptz, 'epoch')
                              + make_interval(secs => d.window_seconds)
                    END AS window_end
               FROM resources r
               LEFT JOIN openmettle.quota_defaults d
                 ON d.scope_kind = $2 AND d.resource_kind = r.resource_kind
               LEFT JOIN openmettle.quota_overrides o
                 ON o.scope_id = $1::uuid AND o.resource_kind = r.resource_kind
         )
         SELECT res.resource_kind,
                res.cost_denomination,
                res.window_kind,
                (extract(epoch FROM res.window_start) * 1000000)::bigint AS window_start_us,
                (extract(epoch FROM res.window_end) * 1000000)::bigint AS window_end_us,
                res.default_limit,
                res.override_limit,
                res.override_expires_us,
                coalesce(b.active_used, 0)::text AS active_used,
                coalesce(b.reserved_held, 0)::text AS reserved_held,
                res.warn_pct_1,
                res.warn_pct_2,
                (SELECT (extract(epoch FROM max(rec.recorded_at)) * 1000000)::bigint
                   FROM openmettle.quota_reservation_charges c
                   JOIN openmettle.quota_reconciliations rec USING (reservation_id)
                  WHERE c.budget_id = b.id) AS last_reconciled_us,
                CASE WHEN res.window_kind = 'windowed' THEN res.window_start
                     ELSE date_trunc('day', $3::text::timestamptz, 'UTC') END::text AS dedupe_bucket_ts,
                res.limit_revision,
                res.config_revision
           FROM resolved res
           LEFT JOIN openmettle.quota_budgets b
             ON b.target_kind = 'scope'
            AND b.scope_id = $1::uuid
            AND b.resource_kind = res.resource_kind
            AND b.window_kind = res.window_kind
            AND b.window_start = res.window_start
          ORDER BY res.ord",
    )
    .bind(scope_id)
    .bind(&scope_kind)
    .bind(&observed_ts)
    .fetch_all(&mut *tx)
    .await?;

    let mut usage = Vec::with_capacity(usage_rows.len());
    for row in usage_rows {
        let resource_kind: String = row.try_get("resource_kind")?;
        let cost_denom: Option<String> = row.try_get("cost_denomination")?;
        let unit = if resource_kind == "usage_tokens" {
            Some("tokens".to_owned())
        } else {
            cost_denom.clone()
        };
        let active_used_str: String = row.try_get("active_used")?;
        let reserved_held_str: String = row.try_get("reserved_held")?;
        let active_used = parse_u128_text(&active_used_str)?;
        let reserved_held = parse_u128_text(&reserved_held_str)?;
        let charged = active_used.saturating_add(reserved_held);
        let u_warn1: i16 = row.try_get("warn_pct_1")?;
        let u_warn2: i16 = row.try_get("warn_pct_2")?;
        let (eff_limit, source, override_exp) =
            if resource_kind == "usage_cost_micros" && cost_denom.is_none() {
                (None, "unconfigured", None)
            } else {
                resolve_limit(
                    row.try_get("override_limit")?,
                    row.try_get("override_expires_us")?,
                    row.try_get("default_limit")?,
                )?
            };
        let remaining = eff_limit.map(|lim| (lim as u128).saturating_sub(charged).to_string());
        active_warn_keys.push((
            resource_kind.clone(),
            row.try_get("dedupe_bucket_ts")?,
            row.try_get("limit_revision")?,
            row.try_get("config_revision")?,
        ));
        warn_state.insert(resource_kind.clone(), (eff_limit, charged));
        usage.push(QuotaUsageItem {
            resource_kind,
            unit,
            window_kind: row.try_get("window_kind")?,
            window_start: format_timestamp_us(row.try_get("window_start_us")?)?,
            window_end: opt_timestamp_us(row.try_get("window_end_us")?)?,
            limit: eff_limit.map(|v| v.to_string()),
            limit_source: source.to_owned(),
            override_expires_at: override_exp,
            active_used: active_used_str,
            reserved_held: reserved_held_str,
            remaining,
            warn_thresholds: [u_warn1, u_warn2],
            status: threshold_status(eff_limit, charged, u_warn1).to_owned(),
            authoritative_source: "gateway".to_owned(),
            last_reconciled_at: opt_timestamp_us(row.try_get("last_reconciled_us")?)?,
        });
    }

    // 3. Device capacity (concurrent reservation slots)
    let dev_row = sqlx::query(
        "SELECT coalesce(b.reserved_held, 0)::text AS reserved_held,
                d.hard_limit AS default_limit,
                CASE WHEN o.revoked_at IS NULL AND (o.expires_at IS NULL OR o.expires_at > $3::text::timestamptz)
                     THEN o.hard_limit END AS override_limit,
                CASE WHEN o.revoked_at IS NULL AND (o.expires_at IS NULL OR o.expires_at > $3::text::timestamptz)
                     THEN (extract(epoch FROM o.expires_at) * 1000000)::bigint END AS override_expires_us,
                coalesce(d.warn_pct_1, 80)::smallint AS warn_pct_1,
                coalesce(d.warn_pct_2, 90)::smallint AS warn_pct_2,
                CASE
                    WHEN o.revoked_at IS NOT NULL THEN o.revision
                    WHEN o.expires_at IS NULL OR o.expires_at > $3::text::timestamptz THEN coalesce(o.revision, 0)
                    ELSE 0
                END AS limit_revision,
                coalesce(d.config_revision, 1) AS config_revision
           FROM (VALUES (1)) AS seed(id)
           LEFT JOIN openmettle.quota_defaults d
             ON d.scope_kind = $2 AND d.resource_kind = 'device_reservations'
           LEFT JOIN openmettle.quota_overrides o
             ON o.scope_id = $1::uuid AND o.resource_kind = 'device_reservations'
           LEFT JOIN openmettle.quota_budgets b
             ON b.target_kind = 'scope'
            AND b.scope_id = $1::uuid
            AND b.resource_kind = 'device_reservations'
            AND b.window_kind = 'concurrent'
            AND b.window_start = 'epoch'::timestamptz",
    )
    .bind(scope_id)
    .bind(&scope_kind)
    .bind(&observed_ts)
    .fetch_one(&mut *tx)
    .await?;

    let dev_held_str: String = dev_row.try_get("reserved_held")?;
    let dev_held = parse_u128_text(&dev_held_str)?;
    let d_warn1: i16 = dev_row.try_get("warn_pct_1")?;
    let d_warn2: i16 = dev_row.try_get("warn_pct_2")?;
    let (dev_limit, dev_source, dev_override_exp) = resolve_limit(
        dev_row.try_get("override_limit")?,
        dev_row.try_get("override_expires_us")?,
        dev_row.try_get("default_limit")?,
    )?;
    active_warn_keys.push((
        "device_reservations".to_owned(),
        day_bucket_ts,
        dev_row.try_get("limit_revision")?,
        dev_row.try_get("config_revision")?,
    ));
    warn_state.insert("device_reservations".to_owned(), (dev_limit, dev_held));
    let device_capacity = QuotaDeviceCapacitySummary {
        active_reservations: QuotaDeviceReservationsSummary {
            reserved_held: dev_held_str,
            limit: dev_limit.map(|v| v.to_string()),
            limit_source: dev_source.to_owned(),
            override_expires_at: dev_override_exp,
            warn_thresholds: [d_warn1, d_warn2],
            status: threshold_status(dev_limit, dev_held, d_warn1).to_owned(),
        },
    };

    // 4. Execution concurrency & round cap
    let exec_rows = sqlx::query(
        "SELECT r.resource_kind,
                d.hard_limit AS default_limit,
                CASE WHEN o.revoked_at IS NULL AND (o.expires_at IS NULL OR o.expires_at > $3::text::timestamptz)
                     THEN o.hard_limit END AS override_limit,
                CASE WHEN o.revoked_at IS NULL AND (o.expires_at IS NULL OR o.expires_at > $3::text::timestamptz)
                     THEN (extract(epoch FROM o.expires_at) * 1000000)::bigint END AS override_expires_us
           FROM (VALUES
               ('live_runs_per_scope'),
               ('executing_runs_per_scope'),
               ('round_cap'),
               ('live_runs_per_actor'),
               ('executing_runs_per_actor')
           ) AS r(resource_kind)
           LEFT JOIN openmettle.quota_defaults d
             ON d.scope_kind = $2 AND d.resource_kind = r.resource_kind
           LEFT JOIN openmettle.quota_overrides o
             ON o.scope_id = $1::uuid AND o.resource_kind = r.resource_kind",
    )
    .bind(scope_id)
    .bind(&scope_kind)
    .bind(&observed_ts)
    .fetch_all(&mut *tx)
    .await?;

    let mut exec_map = std::collections::BTreeMap::new();
    for row in exec_rows {
        let kind: String = row.try_get("resource_kind")?;
        exec_map.insert(
            kind,
            (
                row.try_get::<Option<i64>, _>("override_limit")?,
                row.try_get::<Option<i64>, _>("override_expires_us")?,
                row.try_get::<Option<i64>, _>("default_limit")?,
            ),
        );
    }

    let (scope_live, scope_exec): (i64, i64) = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM openmettle.runs
             WHERE scope_id = $1::uuid
               AND state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')),
           (SELECT count(*) FROM openmettle.runs
             WHERE scope_id = $1::uuid
               AND state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')
               AND state IN ('running', 'cancelling', 'reconciling'))",
    )
    .bind(scope_id)
    .fetch_one(&mut *tx)
    .await?;

    let resolve_exec = |kind: &str,
                        fallback: Option<i64>|
     -> Result<(Option<String>, String, Option<String>), QuotaError> {
        let (ov, ov_exp, def) = exec_map.get(kind).copied().unwrap_or((None, None, None));
        let (lim, src, exp) = resolve_limit(ov, ov_exp, def.or(fallback))?;
        Ok((lim.map(|v| v.to_string()), src.to_owned(), exp))
    };

    let (lim, src, exp) = resolve_exec(
        "live_runs_per_scope",
        admission.map(|l| i64::from(l.live_per_scope)),
    )?;
    let live_runs_per_scope = QuotaExecutionCounter {
        current: scope_live.to_string(),
        limit: lim,
        limit_source: src,
        override_expires_at: exp,
    };
    let (lim, src, exp) = resolve_exec(
        "executing_runs_per_scope",
        claim.map(|l| i64::from(l.executing_per_scope)),
    )?;
    let executing_runs_per_scope = QuotaExecutionCounter {
        current: scope_exec.to_string(),
        limit: lim,
        limit_source: src,
        override_expires_at: exp,
    };
    let (lim, src, exp) = resolve_exec("round_cap", admission.map(|l| i64::from(l.round_cap)))?;
    let round_cap = QuotaLimitProjection {
        limit: lim,
        limit_source: src,
        override_expires_at: exp,
    };

    let (live_runs_per_actor, executing_runs_per_actor) = if scope_kind == "personal"
        && let Some(actor_id) = actor_user_id
    {
        let (actor_live, actor_exec): (i64, i64) = sqlx::query_as(
            "SELECT
                   (SELECT count(*) FROM openmettle.runs
                     WHERE actor_user_id = $1::uuid
                       AND state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')),
                   (SELECT count(*) FROM openmettle.runs
                     WHERE actor_user_id = $1::uuid
                       AND state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')
                       AND state IN ('running', 'cancelling', 'reconciling'))",
        )
        .bind(actor_id)
        .fetch_one(&mut *tx)
        .await?;
        let (lim, src, exp) = resolve_exec(
            "live_runs_per_actor",
            admission.map(|l| i64::from(l.live_per_actor)),
        )?;
        let live = QuotaExecutionCounter {
            current: actor_live.to_string(),
            limit: lim,
            limit_source: src,
            override_expires_at: exp,
        };
        let (lim, src, exp) = resolve_exec(
            "executing_runs_per_actor",
            claim.map(|l| i64::from(l.executing_per_actor)),
        )?;
        let exec = QuotaExecutionCounter {
            current: actor_exec.to_string(),
            limit: lim,
            limit_source: src,
            override_expires_at: exp,
        };
        (Some(live), Some(exec))
    } else {
        (None, None)
    };

    // 5. Active deduplicated warnings for this scope only (re-armed on revision/config/bucket
    // change and validated against the current effective limit and charged usage).
    let res_kinds: Vec<&str> = active_warn_keys.iter().map(|k| k.0.as_str()).collect();
    let buckets: Vec<&str> = active_warn_keys.iter().map(|k| k.1.as_str()).collect();
    let lim_revs: Vec<i64> = active_warn_keys.iter().map(|k| k.2).collect();
    let cfg_revs: Vec<i64> = active_warn_keys.iter().map(|k| k.3).collect();

    let warn_rows = sqlx::query(
        "SELECT w.resource_kind,
                w.threshold_pct,
                (extract(epoch FROM w.dedupe_bucket) * 1000000)::bigint AS dedupe_bucket_us,
                (extract(epoch FROM w.triggered_at) * 1000000)::bigint AS triggered_at_us
           FROM openmettle.quota_warning_events w
           JOIN unnest($2::text[], $3::text[], $4::bigint[], $5::bigint[])
             AS active(resource_kind, dedupe_bucket_ts, limit_revision, config_revision)
             ON w.resource_kind = active.resource_kind
            AND w.dedupe_bucket = active.dedupe_bucket_ts::timestamptz
            AND w.limit_revision = active.limit_revision
            AND w.config_revision = active.config_revision
          WHERE w.target_kind = 'scope'
            AND w.scope_id = $1::uuid
          ORDER BY w.resource_kind, w.threshold_pct, w.dedupe_bucket",
    )
    .bind(scope_id)
    .bind(&res_kinds)
    .bind(&buckets)
    .bind(&lim_revs)
    .bind(&cfg_revs)
    .fetch_all(&mut *tx)
    .await?;

    let mut warnings = Vec::with_capacity(warn_rows.len());
    for row in warn_rows {
        let resource_kind: String = row.try_get("resource_kind")?;
        let threshold_pct: i16 = row.try_get("threshold_pct")?;
        let still_crossed = warn_state
            .get(&resource_kind)
            .and_then(|(lim, charged)| lim.map(|l| (l, *charged)))
            .is_some_and(|(lim, charged)| {
                lim > 0
                    && charged.saturating_mul(100)
                        >= (lim as u128).saturating_mul(u128::from(threshold_pct.max(1) as u16))
            });
        if !still_crossed {
            continue;
        }
        warnings.push(QuotaWarning {
            resource_kind,
            threshold_pct,
            dedupe_bucket: format_timestamp_us(row.try_get("dedupe_bucket_us")?)?,
            triggered_at: format_timestamp_us(row.try_get("triggered_at_us")?)?,
        });
    }

    Ok(QuotaSummary {
        scope_id: scope_id.to_owned(),
        scope_kind,
        observed_at,
        storage,
        usage,
        execution: QuotaExecutionSummary {
            live_runs_per_scope,
            executing_runs_per_scope,
            round_cap,
            live_runs_per_actor,
            executing_runs_per_actor,
        },
        device_capacity,
        warnings,
    })
}

async fn read_override_row(
    c: &mut PgConnection,
    scope_id: &str,
    resource: QuotaResourceKind,
) -> Result<QuotaOverride, QuotaError> {
    let row = sqlx::query(
        "SELECT scope_id::text, scope_kind, resource_kind, hard_limit,
                CASE WHEN expires_at IS NOT NULL
                     THEN to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
                END AS expires_at,
                CASE WHEN revoked_at IS NOT NULL
                     THEN to_char(revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
                END AS revoked_at,
                revision,
                to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS updated_at
           FROM openmettle.quota_overrides
          WHERE scope_id = $1::uuid AND resource_kind = $2",
    )
    .bind(scope_id)
    .bind(resource.as_str())
    .fetch_one(c)
    .await?;
    Ok(QuotaOverride {
        scope_id: row.try_get("scope_id")?,
        scope_kind: row.try_get("scope_kind")?,
        resource_kind: row.try_get("resource_kind")?,
        hard_limit: row.try_get::<i64, _>("hard_limit")?.to_string(),
        expires_at: row.try_get("expires_at")?,
        revoked_at: row.try_get("revoked_at")?,
        revision: row.try_get::<i64, _>("revision")?.to_string(),
        updated_at: row.try_get("updated_at")?,
    })
}

fn map_override_sql_error(error: sqlx::Error) -> QuotaError {
    if let sqlx::Error::Database(ref db) = error {
        match db.code().as_deref() {
            Some("OMQ02") => return QuotaError::CostDenominationUnconfigured,
            Some("OMQ03") => return QuotaError::AdoptionInProgress,
            Some("OMQ06") => return QuotaError::UpgradeNotEnforced,
            Some("P0002") => return QuotaError::Store(StoreError::NotFound),
            Some("42501") => {
                return QuotaError::Store(StoreError::Denied(DenialReason::Policy(
                    PolicyReason::NotAccountAdmin,
                )));
            }
            Some("23514") => return QuotaError::Store(StoreError::InvalidInput("quota_override")),
            _ => {}
        }
    }
    QuotaError::Store(StoreError::Database(error))
}

async fn authorize_manage_quotas_and_check_upgrade(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
) -> Result<(), QuotaError> {
    sqlx::query("SELECT id FROM openmettle.account_admin_lock WHERE id FOR UPDATE")
        .fetch_one(&mut *c)
        .await?;
    let actor = store::acting(c, ctx).await?;
    store::check(authz::authorize_admin(
        &actor,
        AdminChange {
            action: Action::ManageQuotas,
            removes_enabled_admin: false,
            enabled_account_admins: 0,
        },
    ))?;
    let (metering_enforced, overrides_enforced): (bool, bool) = sqlx::query_as(
        "SELECT metering_enforced, overrides_enforced
           FROM openmettle.quota_enforcement
          WHERE id",
    )
    .fetch_one(&mut *c)
    .await?;
    if !metering_enforced || !overrides_enforced {
        return Err(QuotaError::UpgradeNotEnforced);
    }
    // Acquire FOR SHARE on storage_volume_control so override writes serialize against adoption
    // and never overlap an active adoption run (OMQ03 -> 503 unavailable).
    sqlx::query("SELECT openmettle.storage_lock_not_adopting()")
        .execute(&mut *c)
        .await
        .map_err(map_override_sql_error)?;
    Ok(())
}

async fn check_override_idempotency(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    action: &'static str,
    scope_id: &str,
    expected_request: &Value,
) -> Result<Option<QuotaOverride>, QuotaError> {
    let existing = sqlx::query(
        "SELECT action, target_kind, target_id, reason, details::text AS details
           FROM openmettle.authorization_audit
          WHERE actor_user_id = $1::uuid AND request_key = $2",
    )
    .bind(ctx.actor_user_id)
    .bind(ctx.request_key)
    .fetch_optional(c)
    .await?;
    let Some(row) = existing else {
        return Ok(None);
    };
    let recorded_action: String = row.try_get("action")?;
    let recorded_kind: String = row.try_get("target_kind")?;
    let recorded_target: String = row.try_get("target_id")?;
    let recorded_reason: String = row.try_get("reason")?;
    let details_text: String = row.try_get("details")?;
    let details: Value = serde_json::from_str(&details_text)
        .map_err(|_| QuotaError::Store(StoreError::Conflict(store::KEY_REUSED)))?;
    let same = recorded_action == action
        && recorded_kind == "quota_scope"
        && recorded_target == scope_id
        && recorded_reason == ctx.reason
        && details.get("request") == Some(expected_request);
    if !same {
        return Err(QuotaError::Store(StoreError::Conflict(store::KEY_REUSED)));
    }
    let response = details
        .get("response")
        .cloned()
        .and_then(|v| serde_json::from_value::<QuotaOverride>(v).ok())
        .ok_or_else(|| QuotaError::Store(StoreError::Conflict(store::KEY_REUSED)))?;
    Ok(Some(response))
}

async fn validate_scope_for_resource(
    c: &mut PgConnection,
    scope_id: &str,
    resource: QuotaResourceKind,
) -> Result<String, QuotaError> {
    let scope_kind: Option<String> =
        sqlx::query_scalar("SELECT kind FROM openmettle.scopes WHERE id = $1::uuid")
            .bind(scope_id)
            .fetch_optional(c)
            .await?;
    let Some(scope_kind) = scope_kind else {
        return Err(QuotaError::Store(StoreError::NotFound));
    };
    if resource.is_per_actor() && scope_kind != "personal" {
        return Err(QuotaError::Store(StoreError::InvalidInput(
            "per_actor_scope",
        )));
    }
    Ok(scope_kind)
}

/// Create or update one scope quota override as `openmettle_api` (`Action::ManageQuotas`),
/// serialized under `account_admin_lock` and `storage_volume_control FOR SHARE` with one
/// authoritative `authorization_audit` row per write, exact idempotent replay, and conflict check.
pub async fn set_scope_override(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    scope_id: &str,
    resource: QuotaResourceKind,
    hard_limit: i64,
    expires_at: Option<&str>,
) -> Result<QuotaOverride, QuotaError> {
    store::uuid(scope_id, "scope_id")?;
    if !crate::runs::bounded(ctx.reason, 256) || hard_limit < 0 {
        return Err(QuotaError::Store(StoreError::InvalidInput(
            "quota_override",
        )));
    }
    if resource.is_round_cap() && !(1..=1000).contains(&hard_limit) {
        return Err(QuotaError::Store(StoreError::InvalidInput("round_cap")));
    }
    ctx.validate()?;
    let mut tx = store::begin(c).await?;
    let outcome = async {
        let c = tx.connection()?;
        authorize_manage_quotas_and_check_upgrade(c, ctx).await?;
        let req = json!({
            "op": "set",
            "scope_id": scope_id,
            "resource_kind": resource.as_str(),
            "hard_limit": hard_limit.to_string(),
            "expires_at": expires_at,
            "reason": ctx.reason,
        });
        if let Some(replayed) =
            check_override_idempotency(c, ctx, "quota.override.set", scope_id, &req).await?
        {
            return Ok(replayed);
        }
        validate_scope_for_resource(c, scope_id, resource).await?;
        let req_text = req.to_string();
        sqlx::query_scalar::<_, i64>(
            "SELECT openmettle.quota_upsert_scope_override(
                 $1::uuid, $2::uuid, $3, $4, $5::text::timestamptz, $6, $7, $8::jsonb
             )",
        )
        .bind(scope_id)
        .bind(ctx.actor_user_id)
        .bind(resource.as_str())
        .bind(hard_limit)
        .bind(expires_at)
        .bind(ctx.reason)
        .bind(ctx.request_key)
        .bind(&req_text)
        .fetch_one(&mut *c)
        .await
        .map_err(map_override_sql_error)?;
        read_override_row(c, scope_id, resource).await
    }
    .await;
    match outcome {
        Ok(record) => {
            tx.commit().await?;
            Ok(record)
        }
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}

/// Revoke an active scope quota override as `openmettle_api` (`Action::ManageQuotas`),
/// serialized under `account_admin_lock` and `storage_volume_control FOR SHARE` with one
/// authoritative `authorization_audit` row per write, exact idempotent replay, and conflict check.
pub async fn revoke_scope_override(
    c: &mut PgConnection,
    ctx: &AuditContext<'_>,
    scope_id: &str,
    resource: QuotaResourceKind,
) -> Result<QuotaOverride, QuotaError> {
    store::uuid(scope_id, "scope_id")?;
    if !crate::runs::bounded(ctx.reason, 256) {
        return Err(QuotaError::Store(StoreError::InvalidInput("reason")));
    }
    ctx.validate()?;
    let mut tx = store::begin(c).await?;
    let outcome = async {
        let c = tx.connection()?;
        authorize_manage_quotas_and_check_upgrade(c, ctx).await?;
        let req = json!({
            "op": "revoke",
            "scope_id": scope_id,
            "resource_kind": resource.as_str(),
            "reason": ctx.reason,
        });
        if let Some(replayed) =
            check_override_idempotency(c, ctx, "quota.override.revoke", scope_id, &req).await?
        {
            return Ok(replayed);
        }
        validate_scope_for_resource(c, scope_id, resource).await?;
        let req_text = req.to_string();
        let revoked: Option<i64> = sqlx::query_scalar(
            "SELECT openmettle.quota_revoke_scope_override(
                 $1::uuid, $2::uuid, $3, $4, $5, $6::jsonb
             )",
        )
        .bind(scope_id)
        .bind(ctx.actor_user_id)
        .bind(resource.as_str())
        .bind(ctx.reason)
        .bind(ctx.request_key)
        .bind(&req_text)
        .fetch_one(&mut *c)
        .await
        .map_err(map_override_sql_error)?;
        if revoked.is_none() {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1 FROM openmettle.quota_overrides
                      WHERE scope_id = $1::uuid AND resource_kind = $2
                 )",
            )
            .bind(scope_id)
            .bind(resource.as_str())
            .fetch_one(&mut *c)
            .await?;
            return Err(if exists {
                QuotaError::Store(StoreError::Conflict("quota override is already revoked"))
            } else {
                QuotaError::Store(StoreError::NotFound)
            });
        }
        read_override_row(c, scope_id, resource).await
    }
    .await;
    match outcome {
        Ok(record) => {
            tx.commit().await?;
            Ok(record)
        }
        Err(error) => {
            tx.rollback().await?;
            Err(error)
        }
    }
}

/// Inputs for reserving run-level gateway and metered quota holds inside `/v1/runs` admission.
pub struct RunBudgetReservation<'a> {
    pub scope_id: &'a str,
    pub scope_kind: &'static str,
    pub actor_user_id: &'a str,
    pub actor_approval_id: &'a str,
    pub run_id: &'a str,
    pub token_units: i64,
    /// Qualified per-round cost ceiling when the profile carries a `cost_bound`, or `None` when
    /// the profile is unqualified for cost metering. Multiplied by `round_limit` only when a
    /// `usage_cost_micros` limit is actually active.
    pub per_round_cost_micros: Option<u128>,
    /// Effective run round limit (`>= 1`).
    pub round_limit: i32,
    /// True when executing this profile requires one concurrent `device_reservations` slot.
    pub requires_device_slot: bool,
}

/// Reserve the run-level gateway and metered quota holds inside the `/v1/runs` admission
/// transaction (`runs -> gateway_reservations -> quota_budgets` lock order, ADR 0040).
///
/// Returns `Ok(Some(limit))` when a metered budget refuses the reservation so the caller rolls
/// back the entire submission transaction cleanly (no committed run, branch turn, or hold).
pub async fn reserve_admitted_run_budget(
    tx: &mut WriteTransaction<'_>,
    input: &RunBudgetReservation<'_>,
) -> Result<Option<RunLimit>, StoreError> {
    let mut outer = tx.take_active()?;
    let result = reserve_admitted_run_budget_inner(&mut outer, input).await;
    tx.restore(outer);
    result
}

/// Backfill missing `gateway_reservations` and/or metered `quota_reservations` parent holds
/// for an already-`queued` run on exact HTTP `Idempotency-Key` replay (e.g. a queued run
/// admitted by an `N-1` server or before migration 0024).
///
/// Runs inside a savepoint so partial writes are rolled back atomically whenever backfill is a
/// no-op, refused by quota/provisioning, or encounters a retryable `40001` serialization conflict.
/// Returns `Ok((true, None))` when at least one missing row was backfilled and the caller must
/// commit `tx`; `Ok((false, None))` when the run already has its budget rows or hit a best-effort
/// `40001` conflict (stay read-only); or `Ok((false, Some(limit)))` when backfill was refused.
pub async fn backfill_replayed_run_budget(
    tx: &mut WriteTransaction<'_>,
    input: &RunBudgetReservation<'_>,
) -> Result<(bool, Option<RunLimit>), StoreError> {
    let mut outer = tx.take_active()?;
    let result = backfill_replayed_run_budget_inner(&mut outer, input).await;
    tx.restore(outer);
    result
}

async fn backfill_replayed_run_budget_inner(
    outer: &mut Transaction<'_, Postgres>,
    input: &RunBudgetReservation<'_>,
) -> Result<(bool, Option<RunLimit>), StoreError> {
    let mut sp = outer.begin().await?;
    let outcome = backfill_replayed_run_budget_savepoint(&mut sp, input).await;
    match outcome {
        Ok((true, None)) => {
            sp.commit().await?;
            Ok((true, None))
        }
        Ok((_, refusal)) => {
            sp.rollback().await?;
            Ok((false, refusal))
        }
        Err(StoreError::Database(ref err))
            if err.as_database_error().and_then(|e| e.code()).as_deref() == Some("40001") =>
        {
            sp.rollback().await?;
            Ok((false, None))
        }
        Err(err) => {
            sp.rollback().await?;
            Err(err)
        }
    }
}

async fn backfill_replayed_run_budget_savepoint(
    outer: &mut Transaction<'_, Postgres>,
    input: &RunBudgetReservation<'_>,
) -> Result<(bool, Option<RunLimit>), StoreError> {
    let has_gateway_reservations: bool =
        sqlx::query_scalar("SELECT to_regclass('openmettle.gateway_reservations') IS NOT NULL")
            .fetch_one(&mut **outer)
            .await?;
    if !has_gateway_reservations {
        return Ok((false, None));
    }
    let has_helper: bool = sqlx::query_scalar(
        "SELECT to_regprocedure(
             'openmettle.quota_ensure_replayed_run_gateway_reservation(uuid,uuid,uuid,bigint)'
         ) IS NOT NULL",
    )
    .fetch_one(&mut **outer)
    .await?;
    let (gw_inserted, effective_token_units) = if has_helper {
        let row: Option<(String, i64, bool)> = sqlx::query_as(
            "SELECT reservation_id::text, units, inserted
               FROM openmettle.quota_ensure_replayed_run_gateway_reservation(
                    $1::uuid, $2::uuid, $3::uuid, $4
               )",
        )
        .bind(input.scope_id)
        .bind(input.run_id)
        .bind(input.actor_user_id)
        .bind(input.token_units)
        .fetch_optional(&mut **outer)
        .await?;
        let Some((_, units, inserted)) = row else {
            return Ok((false, None));
        };
        (inserted, units)
    } else {
        // Pre-0026 fallback: lock the run row in canonical order and reuse its actor_approval_id.
        let run_row: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT state, actor_approval_id::text
               FROM openmettle.runs
              WHERE scope_id = $1::uuid
                AND id = $2::uuid
                AND actor_user_id = $3::uuid
                FOR NO KEY UPDATE",
        )
        .bind(input.scope_id)
        .bind(input.run_id)
        .bind(input.actor_user_id)
        .fetch_optional(&mut **outer)
        .await?;
        let Some((state, Some(run_approval_id))) = run_row else {
            return Ok((false, None));
        };
        if state != "queued" {
            return Ok((false, None));
        }
        let mut sp = outer.begin().await?;
        let inserted = match sqlx::query(
            "INSERT INTO openmettle.gateway_reservations
                 (id, scope_id, actor_user_id, approval_id, run_id, units)
             VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $1::uuid, $5)",
        )
        .bind(input.run_id)
        .bind(input.scope_id)
        .bind(input.actor_user_id)
        .bind(&run_approval_id)
        .bind(input.token_units)
        .execute(&mut *sp)
        .await
        {
            Ok(done) => {
                sp.commit().await?;
                done.rows_affected() > 0
            }
            Err(err)
                if err.as_database_error().and_then(|e| e.code()).as_deref() == Some("23505") =>
            {
                // A legacy gateway_reservations row already exists (possibly with id <> run_id
                // or smaller stored units); roll back the savepoint and defer parent hold
                // materialization to the worker rather than charging recomputed input.token_units.
                sp.rollback().await?;
                return Ok((false, None));
            }
            Err(err) => {
                sp.rollback().await?;
                return Err(StoreError::Database(err));
            }
        };
        (inserted, input.token_units)
    };

    let has_quota_schema: bool =
        sqlx::query_scalar("SELECT to_regclass('openmettle.quota_enforcement') IS NOT NULL")
            .fetch_one(&mut **outer)
            .await?;
    let enforced = if has_quota_schema {
        sqlx::query_scalar::<_, bool>(
            "SELECT metering_enforced FROM openmettle.quota_enforcement WHERE id",
        )
        .fetch_one(&mut **outer)
        .await?
    } else {
        false
    };
    if !enforced {
        return Ok((gw_inserted, None));
    }
    let has_token_hold: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM openmettle.quota_reservations
              WHERE scope_id = $1::uuid
                AND run_id = $2::uuid
                AND gateway_request_id IS NULL
                AND resource_kind = 'usage_tokens'
         )",
    )
    .bind(input.scope_id)
    .bind(input.run_id)
    .fetch_one(&mut **outer)
    .await?;
    if has_token_hold {
        return Ok((gw_inserted, None));
    }
    let effective = RunBudgetReservation {
        token_units: effective_token_units,
        ..*input
    };
    if let Some(refusal) = reserve_metered_holds_inner(outer, &effective).await? {
        return Ok((false, Some(refusal)));
    }
    Ok((true, None))
}

async fn reserve_admitted_run_budget_inner(
    outer: &mut Transaction<'_, Postgres>,
    input: &RunBudgetReservation<'_>,
) -> Result<Option<RunLimit>, StoreError> {
    // Schema 23 adds `gateway_reservations`; schema 24 adds `quota_enforcement` / `quota_reserve`.
    // Keep the two checks separate so runs admitted on schema 23 still record `gateway_reservations`
    // and survive upgrading 23 -> 24+ cleanly.
    let has_gateway_reservations: bool =
        sqlx::query_scalar("SELECT to_regclass('openmettle.gateway_reservations') IS NOT NULL")
            .fetch_one(&mut **outer)
            .await?;
    if !has_gateway_reservations {
        return Ok(None);
    }
    sqlx::query(
        "INSERT INTO openmettle.gateway_reservations
             (id, scope_id, actor_user_id, approval_id, run_id, units)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $1::uuid, $5)",
    )
    .bind(input.run_id)
    .bind(input.scope_id)
    .bind(input.actor_user_id)
    .bind(input.actor_approval_id)
    .bind(input.token_units)
    .execute(&mut **outer)
    .await?;

    let has_quota_schema: bool =
        sqlx::query_scalar("SELECT to_regclass('openmettle.quota_enforcement') IS NOT NULL")
            .fetch_one(&mut **outer)
            .await?;
    if !has_quota_schema {
        return Ok(None);
    }
    let enforced: bool =
        sqlx::query_scalar("SELECT metering_enforced FROM openmettle.quota_enforcement WHERE id")
            .fetch_one(&mut **outer)
            .await?;
    if !enforced {
        return Ok(None);
    }

    reserve_metered_holds_inner(outer, input).await
}

async fn reserve_metered_holds_inner(
    outer: &mut Transaction<'_, Postgres>,
    input: &RunBudgetReservation<'_>,
) -> Result<Option<RunLimit>, StoreError> {
    // Canonical alphabetical resource_kind order (ADR 0040):
    // 1. device_reservations (when required by profile)
    // 2. usage_cost_micros (when any applicable cost limit is configured)
    // 3. usage_tokens (always)
    if input.requires_device_slot
        && let Some(refusal) = try_quota_reserve(
            outer,
            input.scope_id,
            input.scope_kind,
            input.actor_user_id,
            input.run_id,
            "device_reservations",
            1,
        )
        .await?
    {
        return Ok(Some(refusal));
    }

    let cost_state = cost_limit_state(outer, input.scope_id, input.actor_user_id).await?;

    if cost_state.any_limit {
        let Some(per_round_cost) = input
            .per_round_cost_micros
            .filter(|_| cost_state.denomination.is_some())
        else {
            return Ok(Some(RunLimit::QuotaUnconfigured {
                resource_kind: "usage_cost_micros",
                scope_kind: "instance",
            }));
        };
        if !cost_state.personal_limit {
            return Ok(Some(RunLimit::QuotaUnconfigured {
                resource_kind: "usage_cost_micros",
                scope_kind: "personal",
            }));
        }
        if per_round_cost == 0 {
            return Err(StoreError::InvalidInput("cost_units"));
        }
        let rounds_u32 = u32::try_from(input.round_limit)
            .ok()
            .filter(|&n| n > 0)
            .ok_or(StoreError::InvalidInput("round_limit"))?;
        let Some(cost_units) = per_round_cost
            .checked_mul(u128::from(rounds_u32))
            .and_then(|total| i64::try_from(total).ok())
        else {
            return Ok(Some(RunLimit::Quota {
                resource_kind: "usage_cost_micros",
                scope_kind: db_tier(cost_state.tightest_scope_kind.as_deref(), input.scope_kind),
            }));
        };
        if let Some(refusal) = try_quota_reserve(
            outer,
            input.scope_id,
            input.scope_kind,
            input.actor_user_id,
            input.run_id,
            "usage_cost_micros",
            cost_units,
        )
        .await?
        {
            return Ok(Some(refusal));
        }
    }

    try_quota_reserve(
        outer,
        input.scope_id,
        input.scope_kind,
        input.actor_user_id,
        input.run_id,
        "usage_tokens",
        input.token_units,
    )
    .await
}

fn db_tier(detail: Option<&str>, fallback: &'static str) -> &'static str {
    match detail {
        Some("personal") => "personal",
        Some("project") => "project",
        Some("instance") => "instance",
        _ => fallback,
    }
}

async fn try_quota_reserve(
    outer: &mut Transaction<'_, Postgres>,
    scope_id: &str,
    scope_kind: &'static str,
    actor_user_id: &str,
    run_id: &str,
    resource: &'static str,
    units: i64,
) -> Result<Option<RunLimit>, StoreError> {
    let mut sp = outer.begin().await?;
    let res = sqlx::query_scalar::<_, String>(
        "SELECT openmettle.quota_reserve(
             $1::uuid,
             $2::uuid,
             $3,
             $4,
             'run:' || $5,
             $5::uuid,
             NULL,
             NULL,
             (SELECT greatest(clock_timestamp() + interval '1 second',
                              coalesce(queue_expires_at, clock_timestamp()) + interval '60 seconds')
                FROM openmettle.runs
               WHERE id = $5::uuid)
         )::text",
    )
    .bind(scope_id)
    .bind(actor_user_id)
    .bind(resource)
    .bind(units)
    .bind(run_id)
    .fetch_one(&mut *sp)
    .await;
    match res {
        Ok(_) => {
            sp.commit().await?;
            Ok(None)
        }
        Err(err) => {
            sp.rollback().await?;
            if let sqlx::Error::Database(ref db) = err {
                let detail = db
                    .try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
                    .and_then(|pg| pg.detail());
                match db.code().as_deref() {
                    Some("OMQ01") => {
                        return Ok(Some(RunLimit::Quota {
                            resource_kind: resource,
                            scope_kind: db_tier(detail, scope_kind),
                        }));
                    }
                    Some("OMQ02") => {
                        return Ok(Some(RunLimit::QuotaUnconfigured {
                            resource_kind: resource,
                            scope_kind: "instance",
                        }));
                    }
                    Some("OMQ05") => {
                        return Ok(Some(RunLimit::QuotaUnconfigured {
                            resource_kind: resource,
                            scope_kind: db_tier(detail, "personal"),
                        }));
                    }
                    _ => {}
                }
            }
            Err(StoreError::Database(err))
        }
    }
}
