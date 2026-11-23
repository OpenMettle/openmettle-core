//! Fenced GPU capacity controller store (ADR 0042, Migration 27).
//!
//! One controller lease per managed group fences observations, grant decisions and release
//! evidence by `controller_epoch` against database time. Reading a snapshot never reserves
//! capacity: each decision is serialized on the group row and subtracts commitments made since
//! the cited measurement. A run-linked grant commits the run's `device_reservations` slot in the
//! same transaction (`quota_commit_device_handoff`), and only confirmed release or
//! non-allocation on every device returns its bytes and settles that slot.
use crate::runs::is_canonical_uuid;
use serde::Serialize;
use sqlx::{PgConnection, Row};
use std::{fmt, time::Duration};

/// All failure classes are safe to display or log.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Malformed input, or an observation, footprint or transition the store refuses.
    Invalid,
    /// The caller does not hold the group's current controller lease and epoch.
    Fenced,
    /// The run's claim is not an active `Step` lease.
    LeaseLost,
    /// The request identity names another request, or the run's device slot is bound elsewhere.
    Conflict,
    Database,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "capacity input refused",
            Self::Fenced => "capacity controller fenced",
            Self::LeaseLost => "run lease not active",
            Self::Conflict => "capacity request conflict",
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
            Some("23505") => Self::Conflict,
            Some("22003" | "22023" | "22P02" | "23502" | "23503" | "23514") => Self::Invalid,
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

/// The caller's controller identity for one group, with the epoch [`acquire`] returned.
#[derive(Clone, Copy, Debug)]
pub struct Fence<'a> {
    pub group_id: &'a str,
    pub controller_id: &'a str,
    pub epoch: i64,
}
impl Fence<'_> {
    fn validate(&self) -> Result<(), Error> {
        ids(&[self.group_id, self.controller_id])?;
        (self.epoch >= 1).then_some(()).ok_or(Error::Invalid)
    }
}

/// Renew this controller's live lease, or take over an absent or expired one with a new epoch.
/// A new epoch closes the group to bursts until [`resume`] succeeds. Use a controller ID that is
/// unique to each process start, so a restart cannot renew its predecessor's epoch.
pub async fn acquire(
    c: &mut PgConnection,
    group_id: &str,
    controller_id: &str,
    lease: Duration,
) -> Result<i64, Error> {
    ids(&[group_id, controller_id])?;
    let lease_ms = i32::try_from(lease.as_millis()).map_err(|_| Error::Invalid)?;
    Ok(
        sqlx::query_scalar("SELECT openmettle.capacity_acquire_controller($1::uuid, $2::uuid, $3)")
            .bind(group_id)
            .bind(controller_id)
            .bind(lease_ms)
            .fetch_one(c)
            .await?,
    )
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
    fence: &Fence<'_>,
    observation: &Observation<'_>,
) -> Result<bool, Error> {
    fence.validate()?;
    if observation
        .devices
        .iter()
        .any(|d| !is_canonical_uuid(&d.device_id))
    {
        return Err(Error::Invalid);
    }
    let devices = serde_json::to_string(observation.devices).map_err(|_| Error::Invalid)?;
    Ok(sqlx::query_scalar(
        "SELECT openmettle.capacity_publish_observation($1::uuid, $2::uuid, $3, $4,
             'epoch'::timestamptz + $5 * interval '1 microsecond', $6, $7::jsonb)",
    )
    .bind(fence.group_id)
    .bind(fence.controller_id)
    .bind(fence.epoch)
    .bind(observation.revision)
    .bind(observation.observed_at_us)
    .bind(observation.commit_watermark)
    .bind(devices)
    .fetch_one(c)
    .await?)
}

/// Reopen bursts in the current epoch. Returns false until the epoch has published a fresh
/// sample measured after takeover and no grant of the group is in `unknown_allocation`.
pub async fn resume(c: &mut PgConnection, fence: &Fence<'_>) -> Result<bool, Error> {
    fence.validate()?;
    Ok(
        sqlx::query_scalar("SELECT openmettle.capacity_resume($1::uuid, $2::uuid, $3)")
            .bind(fence.group_id)
            .bind(fence.controller_id)
            .bind(fence.epoch)
            .fetch_one(c)
            .await?,
    )
}

/// Bytes one grant commits on one device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
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
    /// Safe capacity cannot be established: takeover recovery, a stale sample, a missing rank or
    /// an unknown allocation keeps the group closed.
    Unavailable,
}

/// Decide a grant under the group fence and the run's active lease. A new grant charges its full
/// footprint and binds the run's `device_reservations` slot before the caller dispatches.
pub async fn grant(
    c: &mut PgConnection,
    fence: &Fence<'_>,
    request: &GrantRequest<'_>,
) -> Result<Decision, Error> {
    fence.validate()?;
    ids(&[request.scope_id, request.run_id, request.claim_token])?;
    if request
        .footprint
        .iter()
        .any(|d| !is_canonical_uuid(&d.device_id))
    {
        return Err(Error::Invalid);
    }
    let footprint = serde_json::to_string(request.footprint).map_err(|_| Error::Invalid)?;
    let row = sqlx::query(
        "SELECT grant_ref::text, outcome FROM openmettle.capacity_grant(
             $1::uuid, $2::uuid, $3, $4::uuid, $5::uuid, $6::uuid, $7, $8, $9::jsonb)",
    )
    .bind(fence.group_id)
    .bind(fence.controller_id)
    .bind(fence.epoch)
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

/// Backend evidence or a release trigger for one grant.
#[derive(Clone, Copy, Debug)]
pub enum Release<'a> {
    /// Completion, cancellation, timeout or lease expiry. The charge remains.
    Releasing,
    /// A lost reply or unidentifiable allocation. The charge remains and the group closes to bursts.
    UnknownAllocation,
    /// Confirmed backend release of the grant's allocation on these devices.
    Released(&'a [String]),
    /// Positive evidence that these devices never allocated the grant and, behind the adapter
    /// fence, cannot allocate it from a delayed dispatch.
    NotAllocated(&'a [String]),
}

/// Record a fenced release transition. The grant reaches `released`, and its device slot is
/// settled in the same transaction, only when every device of its footprint has confirmed.
pub async fn record_release(
    c: &mut PgConnection,
    fence: &Fence<'_>,
    grant_id: &str,
    release: Release<'_>,
) -> Result<GrantState, Error> {
    fence.validate()?;
    ids(&[grant_id])?;
    let (outcome, devices): (&str, &[String]) = match release {
        Release::Releasing => ("releasing", &[]),
        Release::UnknownAllocation => ("unknown_allocation", &[]),
        Release::Released(devices) => ("released", devices),
        Release::NotAllocated(devices) => ("not_allocated", devices),
    };
    if devices.iter().any(|d| !is_canonical_uuid(d)) {
        return Err(Error::Invalid);
    }
    let state: String = sqlx::query_scalar(
        "SELECT openmettle.capacity_record_release($1::uuid, $2::uuid, $3, $4::uuid, $5, $6::uuid[])",
    )
    .bind(fence.group_id)
    .bind(fence.controller_id)
    .bind(fence.epoch)
    .bind(grant_id)
    .bind(outcome)
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
    /// The current epoch has completed recovery.
    pub ready: bool,
    /// The sample is within the group's freshness TTL.
    pub fresh: bool,
    pub unknown_allocations: i64,
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
    /// Bursts are admitted only in a recovered epoch with a fresh sample and no unknown allocation.
    pub fn admits_bursts(&self) -> bool {
        self.ready && self.fresh && self.unknown_allocations == 0
    }

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

/// Read the group's latest snapshot. Returns `None` for an unknown group.
pub async fn snapshot(c: &mut PgConnection, group_id: &str) -> Result<Option<Snapshot>, Error> {
    ids(&[group_id])?;
    let rows = sqlx::query(
        "SELECT g.controller_epoch, g.observation_revision,
                (extract(epoch FROM g.observed_at) * 1000000)::bigint AS observed_at_us,
                coalesce(g.ready_epoch = g.controller_epoch, false) AS ready,
                coalesce(g.observed_at + g.observation_ttl_ms * interval '1 millisecond'
                    > clock_timestamp(), false) AS fresh,
                (SELECT count(*) FROM openmettle.capacity_grants c
                  WHERE c.group_id = g.id AND c.state = 'unknown_allocation') AS unknown,
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
        ready: first.try_get("ready")?,
        fresh: first.try_get("fresh")?,
        unknown_allocations: first.try_get("unknown")?,
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
            ready: true,
            fresh: true,
            unknown_allocations: 0,
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
        assert!(snapshot.admits_bursts());
        for closed in [
            Snapshot {
                ready: false,
                ..snapshot.clone()
            },
            Snapshot {
                fresh: false,
                ..snapshot.clone()
            },
            Snapshot {
                unknown_allocations: 1,
                ..snapshot.clone()
            },
        ] {
            assert!(!closed.admits_bursts());
        }
    }

    #[test]
    fn fences_and_states_reject_malformed_values() {
        let id = "00000000-0000-4000-8000-000000000001";
        assert_eq!(
            Fence {
                group_id: id,
                controller_id: id,
                epoch: 0
            }
            .validate(),
            Err(Error::Invalid)
        );
        assert_eq!(
            Fence {
                group_id: "not-a-uuid",
                controller_id: id,
                epoch: 1
            }
            .validate(),
            Err(Error::Invalid)
        );
        assert!(
            Fence {
                group_id: id,
                controller_id: id,
                epoch: 1
            }
            .validate()
            .is_ok()
        );
        assert_eq!(GrantState::parse("released"), Ok(GrantState::Released));
        assert_eq!(GrantState::parse("requested"), Err(Error::Database));
    }
}
