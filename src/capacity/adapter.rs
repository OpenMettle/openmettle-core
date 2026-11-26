//! Internal versioned controller/adapter contract and conservative fit math (ADR 0042, PR3).
//!
//! Every adapter envelope carries [`ADAPTER_CONTRACT_VERSION`], the managed `group_id` and the
//! controller's monotonic `controller_epoch`, and rejects unknown fields. On takeover, the
//! successor establishes its epoch with the backend before reconciling durable grants, releasing
//! any rogue or mismatched backend allocations, or resuming bursts; stale-epoch commands arriving
//! after that fence can neither allocate nor release.
//!
//! [`GroupCoordinator`] enforces commit-before-dispatch against a [`PgPool`] using bounded
//! `READ COMMITTED` transactions (`WriteTransaction::begin_bounded_pool`), serializes per-group
//! controller operations, keeps every newly prepared grant `in_flight` (blocking concurrent bursts)
//! until backend dispatch confirms or reconciles, and never discards database reconciliation
//! errors.
use super::{Controller, DeviceBytes, Error as StoreError, Evidence, GrantRequest, GrantState};
use crate::{
    runs::{self, WriteTransaction, bounded, is_canonical_uuid},
    telemetry::metrics::{
        self, CapacityOperation, CapacityOutcome, CapacityStaleSurface, CapacityWaitOutcome,
    },
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sqlx::{PgConnection, PgPool, Row};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// Wire version of the internal controller/adapter protocol.
pub const ADAPTER_CONTRACT_VERSION: &str = "openmettle.capacity-adapter/1";

/// Safe, fixed error classes returned by an adapter implementation or envelope check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterError {
    /// Envelope `version` is not [`ADAPTER_CONTRACT_VERSION`].
    UnsupportedVersion,
    /// Malformed envelope, invalid identifier, non-positive bytes/epoch, duplicate device or wrong group.
    Invalid,
    /// No controller epoch has been established yet on this backend (`establish_epoch` required first).
    Unfenced,
    /// Command `controller_epoch` does not match the backend's established epoch.
    StaleEpoch { established_epoch: i64 },
    /// Conflicting reuse of a `grant_id` or reclaim `request_key`, or delayed dispatch of a released grant.
    Conflict,
    /// Device physical capacity or reclaimable backing cannot satisfy the command.
    InsufficientCapacity,
    /// Backend transport/execution failure or ambiguous lost reply.
    Unavailable,
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => {
                f.write_str("unsupported capacity adapter contract version")
            }
            Self::Invalid => f.write_str("invalid capacity adapter message"),
            Self::Unfenced => f.write_str("capacity adapter has no established epoch"),
            Self::StaleEpoch { .. } => f.write_str("capacity adapter command epoch is stale"),
            Self::Conflict => f.write_str("capacity adapter request identity conflict"),
            Self::InsufficientCapacity => {
                f.write_str("capacity adapter has insufficient device capacity")
            }
            Self::Unavailable => f.write_str("capacity adapter unavailable"),
        }
    }
}

impl std::error::Error for AdapterError {}

/// Strict closed JSON parser for adapter envelopes: requires a JSON object with unique keys and
/// rejects unknown fields via the target type's `#[serde(deny_unknown_fields)]`.
pub fn parse_envelope<T: DeserializeOwned>(body: &[u8]) -> Result<T, AdapterError> {
    let value = crate::provider_keys::documents::unique(body).map_err(|_| AdapterError::Invalid)?;
    if !value.is_object() {
        return Err(AdapterError::Invalid);
    }
    serde_json::from_value(value).map_err(|_| AdapterError::Invalid)
}

fn check_version(version: &str) -> Result<(), AdapterError> {
    if version != ADAPTER_CONTRACT_VERSION {
        return Err(AdapterError::UnsupportedVersion);
    }
    Ok(())
}

fn check_group_and_epoch(group_id: &str, epoch: i64) -> Result<(), AdapterError> {
    if !is_canonical_uuid(group_id) || epoch < 1 {
        return Err(AdapterError::Invalid);
    }
    Ok(())
}

fn check_profile(profile: &str) -> Result<(), AdapterError> {
    if !bounded(profile, 128) || profile.trim() != profile {
        return Err(AdapterError::Invalid);
    }
    Ok(())
}

fn canonical_footprint(footprint: &[DeviceBytes]) -> Result<BTreeMap<String, i64>, AdapterError> {
    if footprint.is_empty() || footprint.len() > 64 {
        return Err(AdapterError::Invalid);
    }
    let mut map = BTreeMap::new();
    for entry in footprint {
        if !is_canonical_uuid(&entry.device_id) || entry.bytes <= 0 {
            return Err(AdapterError::Invalid);
        }
        if map.insert(entry.device_id.clone(), entry.bytes).is_some() {
            return Err(AdapterError::Invalid);
        }
    }
    Ok(map)
}

fn canonical_devices(devices: &[String]) -> Result<BTreeSet<String>, AdapterError> {
    if devices.is_empty() || devices.len() > 64 {
        return Err(AdapterError::Invalid);
    }
    let mut set = BTreeSet::new();
    for id in devices {
        if !is_canonical_uuid(id) || !set.insert(id.clone()) {
            return Err(AdapterError::Invalid);
        }
    }
    Ok(set)
}

fn map_tx_error(error: runs::Error) -> StoreError {
    match error {
        runs::Error::Database(err) => StoreError::from(err),
        runs::Error::Invalid => StoreError::Invalid,
        runs::Error::Conflict => StoreError::Conflict,
        _ => StoreError::Database,
    }
}

/// Caller-owned wait timer started when a run begins waiting for burst capacity (ADR 0028 /
/// ADR 0042). Pass to [`GroupCoordinator::dispatch_grant`] so `openmettle.capacity.wait.duration`
/// records total caller wait time rather than only the final database/adapter call.
#[derive(Clone, Copy, Debug)]
pub struct CapacityWait {
    started_at: Instant,
}

impl CapacityWait {
    pub fn start() -> Self {
        Self {
            started_at: Instant::now(),
        }
    }

    pub fn from_instant(started_at: Instant) -> Self {
        Self { started_at }
    }

    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    pub fn record(&self, outcome: CapacityWaitOutcome) {
        metrics::global().record_capacity_wait(outcome, self.elapsed());
    }

    pub fn finish(self, outcome: CapacityWaitOutcome) {
        self.record(outcome);
    }
}

/// Takeover fence sent by a successor controller before reconciling in-flight grants or resuming.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EstablishEpochRequest {
    pub version: String,
    pub group_id: String,
    pub controller_epoch: i64,
}

impl EstablishEpochRequest {
    pub fn new(controller: &Controller) -> Self {
        Self {
            version: ADAPTER_CONTRACT_VERSION.to_owned(),
            group_id: controller.group_id().to_owned(),
            controller_epoch: controller.epoch(),
        }
    }

    pub fn validate(&self) -> Result<(), AdapterError> {
        check_version(&self.version)?;
        check_group_and_epoch(&self.group_id, self.controller_epoch)
    }
}

/// One live backend allocation attested behind the adapter's established epoch fence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendAllocation {
    pub grant_id: String,
    pub profile: String,
    pub footprint: Vec<DeviceBytes>,
}

/// Fenced inventory returned by [`CapacityAdapter::establish_epoch`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EstablishEpochResponse {
    pub version: String,
    pub group_id: String,
    pub established_epoch: i64,
    pub allocations: Vec<BackendAllocation>,
}

/// Idempotent fenced grant dispatch for a grant already committed in PostgreSQL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchGrantCommand {
    pub version: String,
    pub group_id: String,
    pub controller_epoch: i64,
    pub grant_id: String,
    pub profile: String,
    pub footprint: Vec<DeviceBytes>,
}

impl DispatchGrantCommand {
    pub fn validate(&self) -> Result<BTreeMap<String, i64>, AdapterError> {
        check_version(&self.version)?;
        check_group_and_epoch(&self.group_id, self.controller_epoch)?;
        if !is_canonical_uuid(&self.grant_id) {
            return Err(AdapterError::Invalid);
        }
        check_profile(&self.profile)?;
        canonical_footprint(&self.footprint)
    }
}

/// Confirmed dispatch response from [`CapacityAdapter::dispatch_grant`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchGrantResponse {
    pub version: String,
    pub group_id: String,
    pub controller_epoch: i64,
    pub grant_id: String,
    pub replayed: bool,
}

/// Fenced elastic tail-KV reclaim request; never shrinks below the protected active-chat floor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReclaimKvCommand {
    pub version: String,
    pub group_id: String,
    pub controller_epoch: i64,
    pub request_key: String,
    pub targets: Vec<DeviceBytes>,
}

impl ReclaimKvCommand {
    pub fn validate(&self) -> Result<BTreeMap<String, i64>, AdapterError> {
        check_version(&self.version)?;
        check_group_and_epoch(&self.group_id, self.controller_epoch)?;
        if !bounded(&self.request_key, 128) || self.request_key.trim() != self.request_key {
            return Err(AdapterError::Invalid);
        }
        canonical_footprint(&self.targets)
    }
}

/// Per-device physical handback attested by [`CapacityAdapter::reclaim_kv`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceReclaimResult {
    pub device_id: String,
    pub reclaimed_bytes: i64,
}

/// Confirmed tail-KV handback evidence returned by [`CapacityAdapter::reclaim_kv`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReclaimKvResponse {
    pub version: String,
    pub group_id: String,
    pub controller_epoch: i64,
    pub request_key: String,
    pub reclaimed: Vec<DeviceReclaimResult>,
}

/// Fenced confirmed release command for one grant's devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseGrantCommand {
    pub version: String,
    pub group_id: String,
    pub controller_epoch: i64,
    pub grant_id: String,
    pub devices: Vec<String>,
}

impl ReleaseGrantCommand {
    pub fn validate(&self) -> Result<BTreeSet<String>, AdapterError> {
        check_version(&self.version)?;
        check_group_and_epoch(&self.group_id, self.controller_epoch)?;
        if !is_canonical_uuid(&self.grant_id) {
            return Err(AdapterError::Invalid);
        }
        canonical_devices(&self.devices)
    }
}

/// Per-device release attestation behind the adapter epoch fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceReleaseStatus {
    /// Physical allocation existed on this device and was released.
    Released,
    /// This device never allocated the grant and, behind the epoch fence, cannot allocate it late.
    NotAllocated,
    /// Release could not be confirmed on this device; the grant stays `unknown_allocation`.
    Unknown,
}

/// Confirmed per-device release evidence for one grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceReleaseEvidence {
    pub device_id: String,
    pub status: DeviceReleaseStatus,
}

/// Response from [`CapacityAdapter::release_grant`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseGrantResponse {
    pub version: String,
    pub group_id: String,
    pub controller_epoch: i64,
    pub grant_id: String,
    pub devices: Vec<DeviceReleaseEvidence>,
}

/// One durable non-released grant's byte commitment on one device through a snapshot's
/// `commit_watermark`, used for per-grant backing attribution when computing device observations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableGrantAllocation {
    pub grant_id: String,
    pub device_id: String,
    pub bytes: i64,
}

/// Inputs to the conservative per-device fit calculation (ADR 0042 "Observations and fit").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceFitInput {
    pub total_bytes: i64,
    pub committed_bytes: i64,
    pub actual_used_bytes: i64,
    pub reclaimable_bytes: i64,
    pub safety_headroom_bytes: i64,
    pub active_chat_floor_bytes: i64,
    /// Resident portion of `actual_used_bytes` positively attributed to `committed_bytes`.
    pub backed_committed_bytes: i64,
    /// Resident portion of `actual_used_bytes` positively attributed to `active_chat_floor_bytes`.
    pub backed_chat_floor_bytes: i64,
}

/// Attribute per-grant durable commitments against resident backend allocations on a single device.
///
/// Returns `(committed_bytes, backed_committed_bytes)` where:
/// - `committed_bytes` is the sum of durable commitments on this device, and
/// - `backed_committed_bytes = sum_g min(durable(g), resident(g))`.
///
/// Resident bytes belonging to a rogue or untracked grant never offset an unbacked durable grant.
pub fn attribute_device_commitments(
    durable_by_grant: &BTreeMap<String, i64>,
    resident_by_grant: &BTreeMap<String, i64>,
) -> Result<(i64, i64), AdapterError> {
    let mut committed = 0i128;
    let mut backed = 0i128;
    for &bytes in resident_by_grant.values() {
        if bytes < 0 {
            return Err(AdapterError::Invalid);
        }
    }
    for (grant_id, &durable_bytes) in durable_by_grant {
        if durable_bytes < 0 {
            return Err(AdapterError::Invalid);
        }
        committed += i128::from(durable_bytes);
        let resident_bytes = resident_by_grant.get(grant_id).copied().unwrap_or(0);
        backed += i128::from(durable_bytes.min(resident_bytes));
    }
    let committed = i64::try_from(committed).map_err(|_| AdapterError::Invalid)?;
    let backed = i64::try_from(backed).map_err(|_| AdapterError::Invalid)?;
    Ok((committed, backed))
}

/// Computes conservative `grantable_bytes` for one device (ADR 0042 "Observations and fit"):
///
/// Charges `actual_used_bytes` plus the unbacked portion of commitments and the uncovered portion
/// of `active_chat_floor_bytes`, subtracts those charges and `safety_headroom_bytes` from
/// `total_bytes`, and clamps spare capacity at zero. Rejects negative values, non-positive
/// `total_bytes`, `reclaimable_bytes > actual_used_bytes`, or overlapping attribution whose sum
/// exceeds `actual_used_bytes`.
pub fn compute_device_grantable_bytes(input: &DeviceFitInput) -> Result<i64, AdapterError> {
    if input.total_bytes <= 0
        || input.committed_bytes < 0
        || input.actual_used_bytes < 0
        || input.reclaimable_bytes < 0
        || input.safety_headroom_bytes < 0
        || input.active_chat_floor_bytes < 0
        || input.backed_committed_bytes < 0
        || input.backed_chat_floor_bytes < 0
        || input.reclaimable_bytes > input.actual_used_bytes
        || input.backed_committed_bytes > input.committed_bytes
        || input.backed_chat_floor_bytes > input.active_chat_floor_bytes
    {
        return Err(AdapterError::Invalid);
    }
    let attributed =
        i128::from(input.backed_committed_bytes) + i128::from(input.backed_chat_floor_bytes);
    if attributed > i128::from(input.actual_used_bytes) {
        return Err(AdapterError::Invalid);
    }
    let unbacked_committed =
        i128::from(input.committed_bytes) - i128::from(input.backed_committed_bytes);
    let uncovered_floor =
        i128::from(input.active_chat_floor_bytes) - i128::from(input.backed_chat_floor_bytes);
    let charged = i128::from(input.actual_used_bytes)
        + unbacked_committed
        + uncovered_floor
        + i128::from(input.safety_headroom_bytes);
    let spare = (i128::from(input.total_bytes) - charged).max(0);
    i64::try_from(spare).map_err(|_| AdapterError::Invalid)
}

/// Fenced adapter interface implemented by each managed device group backend.
pub trait CapacityAdapter: Send + Sync {
    fn establish_epoch(
        &self,
        request: EstablishEpochRequest,
    ) -> impl Future<Output = Result<EstablishEpochResponse, AdapterError>> + Send;

    fn dispatch_grant(
        &self,
        command: DispatchGrantCommand,
    ) -> impl Future<Output = Result<DispatchGrantResponse, AdapterError>> + Send;

    fn reclaim_kv(
        &self,
        command: ReclaimKvCommand,
    ) -> impl Future<Output = Result<ReclaimKvResponse, AdapterError>> + Send;

    fn release_grant(
        &self,
        command: ReleaseGrantCommand,
    ) -> impl Future<Output = Result<ReleaseGrantResponse, AdapterError>> + Send;
}

impl<T: CapacityAdapter> CapacityAdapter for &T {
    fn establish_epoch(
        &self,
        request: EstablishEpochRequest,
    ) -> impl Future<Output = Result<EstablishEpochResponse, AdapterError>> + Send {
        (*self).establish_epoch(request)
    }

    fn dispatch_grant(
        &self,
        command: DispatchGrantCommand,
    ) -> impl Future<Output = Result<DispatchGrantResponse, AdapterError>> + Send {
        (*self).dispatch_grant(command)
    }

    fn reclaim_kv(
        &self,
        command: ReclaimKvCommand,
    ) -> impl Future<Output = Result<ReclaimKvResponse, AdapterError>> + Send {
        (*self).reclaim_kv(command)
    }

    fn release_grant(
        &self,
        command: ReleaseGrantCommand,
    ) -> impl Future<Output = Result<ReleaseGrantResponse, AdapterError>> + Send {
        (*self).release_grant(command)
    }
}

impl<T: CapacityAdapter> CapacityAdapter for Arc<T> {
    fn establish_epoch(
        &self,
        request: EstablishEpochRequest,
    ) -> impl Future<Output = Result<EstablishEpochResponse, AdapterError>> + Send {
        self.as_ref().establish_epoch(request)
    }

    fn dispatch_grant(
        &self,
        command: DispatchGrantCommand,
    ) -> impl Future<Output = Result<DispatchGrantResponse, AdapterError>> + Send {
        self.as_ref().dispatch_grant(command)
    }

    fn reclaim_kv(
        &self,
        command: ReclaimKvCommand,
    ) -> impl Future<Output = Result<ReclaimKvResponse, AdapterError>> + Send {
        self.as_ref().reclaim_kv(command)
    }

    fn release_grant(
        &self,
        command: ReleaseGrantCommand,
    ) -> impl Future<Output = Result<ReleaseGrantResponse, AdapterError>> + Send {
        self.as_ref().release_grant(command)
    }
}

/// Initial physical state for one device in [`FencedBackend`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendDeviceConfig {
    pub device_id: String,
    pub total_bytes: i64,
    pub safety_headroom_bytes: i64,
    pub active_chat_floor_bytes: i64,
    pub backed_chat_floor_bytes: i64,
    /// Resident elastic KV tail bytes eligible for fenced reclaim (outside the chat floor).
    pub reclaimable_bytes: i64,
    /// Unattributed resident use outside controller grants and chat floor.
    pub unattributed_used_bytes: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalGrant {
    profile: String,
    footprint: BTreeMap<String, i64>,
}

#[derive(Clone, Debug)]
struct BackendDevice {
    total_bytes: i64,
    safety_headroom_bytes: i64,
    active_chat_floor_bytes: i64,
    backed_chat_floor_bytes: i64,
    reclaimable_bytes: i64,
    unattributed_used_bytes: i64,
    allocations: BTreeMap<String, i64>,
}

impl BackendDevice {
    fn allocated_bytes(&self) -> i128 {
        self.allocations.values().map(|&b| i128::from(b)).sum()
    }

    fn observation(
        &self,
        device_id: &str,
        durable_by_grant: &BTreeMap<String, i64>,
    ) -> Result<super::DeviceObservation, AdapterError> {
        let (committed, backed_committed) =
            attribute_device_commitments(durable_by_grant, &self.allocations)?;
        let actual_used = i64::try_from(
            i128::from(self.backed_chat_floor_bytes)
                + i128::from(self.reclaimable_bytes)
                + i128::from(self.unattributed_used_bytes)
                + self.allocated_bytes(),
        )
        .map_err(|_| AdapterError::Invalid)?;
        let fit = DeviceFitInput {
            total_bytes: self.total_bytes,
            committed_bytes: committed,
            actual_used_bytes: actual_used,
            reclaimable_bytes: self.reclaimable_bytes,
            safety_headroom_bytes: self.safety_headroom_bytes,
            active_chat_floor_bytes: self.active_chat_floor_bytes,
            backed_committed_bytes: backed_committed,
            backed_chat_floor_bytes: self.backed_chat_floor_bytes,
        };
        let grantable_bytes = compute_device_grantable_bytes(&fit)?;
        Ok(super::DeviceObservation {
            device_id: device_id.to_owned(),
            total_bytes: self.total_bytes,
            committed_bytes: committed,
            actual_used_bytes: actual_used,
            reclaimable_bytes: self.reclaimable_bytes,
            safety_headroom_bytes: self.safety_headroom_bytes,
            active_chat_floor_bytes: self.active_chat_floor_bytes,
            grantable_bytes,
        })
    }
}

#[derive(Default)]
struct BackendState {
    established_epoch: Option<i64>,
    devices: BTreeMap<String, BackendDevice>,
    live_grants: BTreeMap<String, CanonicalGrant>,
    /// Per-grant released devices, preserved so duplicate release is idempotent and delayed
    /// dispatch of an already-released or confirmed-non-allocated grant can never allocate.
    released_devices: BTreeMap<String, BTreeSet<String>>,
    tombstoned_grants: BTreeSet<String>,
    reclaim_history: BTreeMap<String, (BTreeMap<String, i64>, Vec<DeviceReclaimResult>)>,
    /// Deterministic fault-injection hooks for tests.
    fail_next_dispatch: Option<AdapterError>,
    unknown_release_pairs: BTreeSet<(String, String)>,
}

/// Deterministic in-process reference implementation of [`CapacityAdapter`] enforcing monotonic
/// epoch fencing, idempotent dispatch/reclaim/release and chat-floor protection.
pub struct FencedBackend {
    group_id: String,
    state: Mutex<BackendState>,
}

impl FencedBackend {
    pub fn new(
        group_id: impl Into<String>,
        devices: Vec<BackendDeviceConfig>,
    ) -> Result<Self, AdapterError> {
        let group_id = group_id.into();
        if !is_canonical_uuid(&group_id) || devices.is_empty() {
            return Err(AdapterError::Invalid);
        }
        let mut map = BTreeMap::new();
        for cfg in devices {
            if !is_canonical_uuid(&cfg.device_id)
                || cfg.total_bytes <= 0
                || cfg.safety_headroom_bytes < 0
                || cfg.active_chat_floor_bytes < 0
                || cfg.backed_chat_floor_bytes < 0
                || cfg.backed_chat_floor_bytes > cfg.active_chat_floor_bytes
                || cfg.reclaimable_bytes < 0
                || cfg.unattributed_used_bytes < 0
            {
                return Err(AdapterError::Invalid);
            }
            let device = BackendDevice {
                total_bytes: cfg.total_bytes,
                safety_headroom_bytes: cfg.safety_headroom_bytes,
                active_chat_floor_bytes: cfg.active_chat_floor_bytes,
                backed_chat_floor_bytes: cfg.backed_chat_floor_bytes,
                reclaimable_bytes: cfg.reclaimable_bytes,
                unattributed_used_bytes: cfg.unattributed_used_bytes,
                allocations: BTreeMap::new(),
            };
            // Verify initial device state produces a valid conservative fit.
            device.observation(&cfg.device_id, &BTreeMap::new())?;
            if map.insert(cfg.device_id, device).is_some() {
                return Err(AdapterError::Invalid);
            }
        }
        Ok(Self {
            group_id,
            state: Mutex::new(BackendState {
                devices: map,
                ..BackendState::default()
            }),
        })
    }

    pub fn established_epoch(&self) -> Option<i64> {
        self.state.lock().unwrap().established_epoch
    }

    /// Snapshot the backend's physical observations with zero durable commitments. When publishing
    /// to PostgreSQL alongside durable grants, use [`Self::observe_with_commitments`] with
    /// [`durable_committed_through`].
    pub fn observe(&self) -> Result<Vec<super::DeviceObservation>, AdapterError> {
        self.observe_with_commitments(&[])
    }

    /// Snapshot the backend's physical observations while attributing each durable commitment to
    /// its own `grant_id` on each device so rogue or untracked resident bytes never offset an
    /// unbacked durable commitment.
    pub fn observe_with_commitments(
        &self,
        durable_allocations: &[DurableGrantAllocation],
    ) -> Result<Vec<super::DeviceObservation>, AdapterError> {
        let state = self.state.lock().unwrap();
        let mut by_device: BTreeMap<&str, BTreeMap<String, i64>> = BTreeMap::new();
        for entry in durable_allocations {
            if !is_canonical_uuid(&entry.grant_id)
                || !is_canonical_uuid(&entry.device_id)
                || entry.bytes <= 0
                || !state.devices.contains_key(&entry.device_id)
            {
                return Err(AdapterError::Invalid);
            }
            let grants = by_device.entry(entry.device_id.as_str()).or_default();
            if grants.insert(entry.grant_id.clone(), entry.bytes).is_some() {
                return Err(AdapterError::Invalid);
            }
        }
        let empty = BTreeMap::new();
        state
            .devices
            .iter()
            .map(|(id, dev)| {
                let durable = by_device.get(id.as_str()).unwrap_or(&empty);
                dev.observation(id, durable)
            })
            .collect()
    }

    /// Inject a one-shot error for the next fenced [`CapacityAdapter::dispatch_grant`] call.
    pub fn inject_next_dispatch_error(&self, error: AdapterError) {
        self.state.lock().unwrap().fail_next_dispatch = Some(error);
    }

    /// Force release of `(grant_id, device_id)` to report [`DeviceReleaseStatus::Unknown`]
    /// until cleared via [`Self::clear_unknown_release`].
    pub fn inject_unknown_release(&self, grant_id: &str, device_id: &str) {
        self.state
            .lock()
            .unwrap()
            .unknown_release_pairs
            .insert((grant_id.to_owned(), device_id.to_owned()));
    }

    pub fn clear_unknown_release(&self, grant_id: &str, device_id: &str) {
        self.state
            .lock()
            .unwrap()
            .unknown_release_pairs
            .remove(&(grant_id.to_owned(), device_id.to_owned()));
    }

    /// Inject a resident backend-only allocation directly into device state to test takeover
    /// reconciliation of rogue allocations and per-grant backing attribution.
    pub fn inject_rogue_allocation(
        &self,
        grant_id: &str,
        profile: &str,
        footprint: &[DeviceBytes],
    ) -> Result<(), AdapterError> {
        if !is_canonical_uuid(grant_id) {
            return Err(AdapterError::Invalid);
        }
        check_profile(profile)?;
        let footprint = canonical_footprint(footprint)?;
        let mut state = self.state.lock().unwrap();
        if state.live_grants.contains_key(grant_id) {
            return Err(AdapterError::Conflict);
        }
        for device_id in footprint.keys() {
            if !state.devices.contains_key(device_id) {
                return Err(AdapterError::Invalid);
            }
        }
        for (device_id, &bytes) in &footprint {
            state
                .devices
                .get_mut(device_id)
                .unwrap()
                .allocations
                .insert(grant_id.to_owned(), bytes);
        }
        state.live_grants.insert(
            grant_id.to_owned(),
            CanonicalGrant {
                profile: profile.to_owned(),
                footprint,
            },
        );
        Ok(())
    }

    /// Inject an unexpected resident allocation on an extra rank for an existing live grant to
    /// test takeover reconciliation of footprint mismatches.
    pub fn inject_extra_rank_allocation(
        &self,
        grant_id: &str,
        device_id: &str,
        bytes: i64,
    ) -> Result<(), AdapterError> {
        if !is_canonical_uuid(grant_id) || !is_canonical_uuid(device_id) || bytes <= 0 {
            return Err(AdapterError::Invalid);
        }
        let mut state = self.state.lock().unwrap();
        if !state.devices.contains_key(device_id) || !state.live_grants.contains_key(grant_id) {
            return Err(AdapterError::Invalid);
        }
        state
            .devices
            .get_mut(device_id)
            .unwrap()
            .allocations
            .insert(grant_id.to_owned(), bytes);
        state
            .live_grants
            .get_mut(grant_id)
            .unwrap()
            .footprint
            .insert(device_id.to_owned(), bytes);
        Ok(())
    }

    fn require_epoch(state: &BackendState, epoch: i64) -> Result<(), AdapterError> {
        match state.established_epoch {
            None => Err(AdapterError::Unfenced),
            Some(established) if established != epoch => Err(AdapterError::StaleEpoch {
                established_epoch: established,
            }),
            Some(_) => Ok(()),
        }
    }
}

impl CapacityAdapter for FencedBackend {
    async fn establish_epoch(
        &self,
        request: EstablishEpochRequest,
    ) -> Result<EstablishEpochResponse, AdapterError> {
        request.validate()?;
        if request.group_id != self.group_id {
            return Err(AdapterError::Invalid);
        }
        let mut state = self.state.lock().unwrap();
        if let Some(established) = state.established_epoch
            && request.controller_epoch < established
        {
            return Err(AdapterError::StaleEpoch {
                established_epoch: established,
            });
        }
        state.established_epoch = Some(request.controller_epoch);
        let allocations = state
            .live_grants
            .iter()
            .map(|(grant_id, grant)| BackendAllocation {
                grant_id: grant_id.clone(),
                profile: grant.profile.clone(),
                footprint: grant
                    .footprint
                    .iter()
                    .map(|(device_id, &bytes)| DeviceBytes {
                        device_id: device_id.clone(),
                        bytes,
                    })
                    .collect(),
            })
            .collect();
        Ok(EstablishEpochResponse {
            version: ADAPTER_CONTRACT_VERSION.to_owned(),
            group_id: self.group_id.clone(),
            established_epoch: request.controller_epoch,
            allocations,
        })
    }

    async fn dispatch_grant(
        &self,
        command: DispatchGrantCommand,
    ) -> Result<DispatchGrantResponse, AdapterError> {
        let footprint = command.validate()?;
        if command.group_id != self.group_id {
            return Err(AdapterError::Invalid);
        }
        let mut state = self.state.lock().unwrap();
        Self::require_epoch(&state, command.controller_epoch)?;
        if let Some(err) = state.fail_next_dispatch.take() {
            return Err(err);
        }
        // Check tombstones BEFORE live_grants so a partially-released grant can never accept
        // a replayed dispatch.
        if state.tombstoned_grants.contains(&command.grant_id) {
            return Err(AdapterError::Conflict);
        }
        let canonical = CanonicalGrant {
            profile: command.profile.clone(),
            footprint: footprint.clone(),
        };
        if let Some(existing) = state.live_grants.get(&command.grant_id) {
            if *existing == canonical {
                return Ok(DispatchGrantResponse {
                    version: ADAPTER_CONTRACT_VERSION.to_owned(),
                    group_id: self.group_id.clone(),
                    controller_epoch: command.controller_epoch,
                    grant_id: command.grant_id,
                    replayed: true,
                });
            }
            return Err(AdapterError::Conflict);
        }
        let empty = BTreeMap::new();
        for (device_id, &bytes) in &footprint {
            let dev = state.devices.get(device_id).ok_or(AdapterError::Invalid)?;
            let obs = dev.observation(device_id, &empty)?;
            if bytes > obs.grantable_bytes {
                return Err(AdapterError::InsufficientCapacity);
            }
        }
        for (device_id, &bytes) in &footprint {
            let dev = state.devices.get_mut(device_id).unwrap();
            dev.allocations.insert(command.grant_id.clone(), bytes);
        }
        state
            .live_grants
            .insert(command.grant_id.clone(), canonical);
        Ok(DispatchGrantResponse {
            version: ADAPTER_CONTRACT_VERSION.to_owned(),
            group_id: self.group_id.clone(),
            controller_epoch: command.controller_epoch,
            grant_id: command.grant_id,
            replayed: false,
        })
    }

    async fn reclaim_kv(
        &self,
        command: ReclaimKvCommand,
    ) -> Result<ReclaimKvResponse, AdapterError> {
        let targets = command.validate()?;
        if command.group_id != self.group_id {
            return Err(AdapterError::Invalid);
        }
        let mut state = self.state.lock().unwrap();
        Self::require_epoch(&state, command.controller_epoch)?;
        if let Some((prev_targets, prev_reclaimed)) =
            state.reclaim_history.get(&command.request_key)
        {
            if *prev_targets == targets {
                return Ok(ReclaimKvResponse {
                    version: ADAPTER_CONTRACT_VERSION.to_owned(),
                    group_id: self.group_id.clone(),
                    controller_epoch: command.controller_epoch,
                    request_key: command.request_key,
                    reclaimed: prev_reclaimed.clone(),
                });
            }
            return Err(AdapterError::Conflict);
        }
        for device_id in targets.keys() {
            if !state.devices.contains_key(device_id) {
                return Err(AdapterError::Invalid);
            }
        }
        let mut reclaimed = Vec::with_capacity(targets.len());
        for (device_id, &want) in &targets {
            let dev = state.devices.get_mut(device_id).unwrap();
            // Only eligible tail KV is reclaimed; active_chat_floor_bytes is never touched.
            let handed_back = want.min(dev.reclaimable_bytes);
            dev.reclaimable_bytes -= handed_back;
            reclaimed.push(DeviceReclaimResult {
                device_id: device_id.clone(),
                reclaimed_bytes: handed_back,
            });
        }
        let response = ReclaimKvResponse {
            version: ADAPTER_CONTRACT_VERSION.to_owned(),
            group_id: self.group_id.clone(),
            controller_epoch: command.controller_epoch,
            request_key: command.request_key.clone(),
            reclaimed: reclaimed.clone(),
        };
        state
            .reclaim_history
            .insert(command.request_key, (targets, reclaimed));
        Ok(response)
    }

    async fn release_grant(
        &self,
        command: ReleaseGrantCommand,
    ) -> Result<ReleaseGrantResponse, AdapterError> {
        let devices = command.validate()?;
        if command.group_id != self.group_id {
            return Err(AdapterError::Invalid);
        }
        let mut state = self.state.lock().unwrap();
        Self::require_epoch(&state, command.controller_epoch)?;
        for device_id in &devices {
            if !state.devices.contains_key(device_id) {
                return Err(AdapterError::Invalid);
            }
        }
        let mut results = Vec::with_capacity(devices.len());
        for device_id in &devices {
            if state
                .unknown_release_pairs
                .contains(&(command.grant_id.clone(), device_id.clone()))
            {
                results.push(DeviceReleaseEvidence {
                    device_id: device_id.clone(),
                    status: DeviceReleaseStatus::Unknown,
                });
                continue;
            }
            let removed = state
                .devices
                .get_mut(device_id)
                .unwrap()
                .allocations
                .remove(&command.grant_id)
                .is_some();
            if removed {
                if let Some(live) = state.live_grants.get_mut(&command.grant_id) {
                    live.footprint.remove(device_id);
                }
                state
                    .released_devices
                    .entry(command.grant_id.clone())
                    .or_default()
                    .insert(device_id.clone());
                results.push(DeviceReleaseEvidence {
                    device_id: device_id.clone(),
                    status: DeviceReleaseStatus::Released,
                });
            } else if state
                .released_devices
                .get(&command.grant_id)
                .is_some_and(|set| set.contains(device_id))
            {
                if let Some(live) = state.live_grants.get_mut(&command.grant_id) {
                    live.footprint.remove(device_id);
                }
                results.push(DeviceReleaseEvidence {
                    device_id: device_id.clone(),
                    status: DeviceReleaseStatus::Released,
                });
            } else {
                results.push(DeviceReleaseEvidence {
                    device_id: device_id.clone(),
                    status: DeviceReleaseStatus::NotAllocated,
                });
            }
        }
        let still_live = state
            .live_grants
            .get(&command.grant_id)
            .is_some_and(|live| !live.footprint.is_empty());
        if !still_live {
            state.live_grants.remove(&command.grant_id);
        }
        state.tombstoned_grants.insert(command.grant_id.clone());
        Ok(ReleaseGrantResponse {
            version: ADAPTER_CONTRACT_VERSION.to_owned(),
            group_id: self.group_id.clone(),
            controller_epoch: command.controller_epoch,
            grant_id: command.grant_id,
            devices: results,
        })
    }
}

/// Combined error returned by [`GroupCoordinator`].
#[derive(Debug, PartialEq, Eq)]
pub enum CoordinatorError {
    Store(StoreError),
    Adapter(AdapterError),
}

impl From<StoreError> for CoordinatorError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<AdapterError> for CoordinatorError {
    fn from(error: AdapterError) -> Self {
        Self::Adapter(error)
    }
}

/// Summary of grants reconciled during [`GroupCoordinator::takeover_and_reconcile`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TakeoverReport {
    pub established_epoch: i64,
    pub attested: usize,
    pub released: usize,
    pub rogue_released: usize,
    pub unknown: usize,
}

/// Outcome of [`GroupCoordinator::dispatch_grant`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// Durable grant committed, dispatched to the fenced adapter, and confirmed in PostgreSQL.
    Dispatched { grant_id: String, replayed: bool },
    /// Replay matched an already-settled or dispatch-confirmed durable grant; never re-dispatched.
    Existing { grant_id: String, state: GrantState },
    /// Group admits bursts, but the footprint does not fit every required device now.
    Insufficient,
    /// Group does not admit bursts.
    Unavailable,
}

struct DurableLiveGrant {
    state: String,
    profile: String,
    footprint: BTreeMap<String, i64>,
    unreleased_devices: Vec<String>,
}

enum PreparedDispatch {
    DispatchNow { grant_id: String, is_replay: bool },
    AlreadySettled { grant_id: String, state: GrantState },
    Insufficient,
    Unavailable { observation_stale: bool },
}

struct VerifiedRelease {
    released_ids: Vec<String>,
    not_allocated_ids: Vec<String>,
    unknown_ids: Vec<String>,
}

/// Load every durable non-released `(grant_id, device_id, bytes)` allocation through
/// `commit_watermark` in a committed read-only bounded transaction so [`FencedBackend::observe_with_commitments`]
/// attributes resident bytes per grant.
pub async fn durable_committed_through(
    pool: &PgPool,
    group_id: &str,
    commit_watermark: i64,
) -> Result<Vec<DurableGrantAllocation>, StoreError> {
    if !is_canonical_uuid(group_id) || commit_watermark < 0 {
        return Err(StoreError::Invalid);
    }
    let mut tx = WriteTransaction::begin_bounded_pool(pool, true)
        .await
        .map_err(map_tx_error)?;
    let rows = sqlx::query(
        "SELECT gd.grant_id::text AS grant_id, gd.device_id::text AS device_id, gd.bytes
           FROM openmettle.capacity_grant_devices gd
           JOIN openmettle.capacity_grants c ON c.id = gd.grant_id
          WHERE gd.group_id = $1::uuid
            AND c.state <> 'released'
            AND c.commit_seq <= $2
          ORDER BY gd.grant_id, gd.device_id",
    )
    .bind(group_id)
    .bind(commit_watermark)
    .fetch_all(tx.connection().map_err(map_tx_error)?)
    .await?;
    tx.commit().await.map_err(map_tx_error)?;
    let mut allocations = Vec::with_capacity(rows.len());
    for row in rows {
        allocations.push(DurableGrantAllocation {
            grant_id: row.try_get("grant_id")?,
            device_id: row.try_get("device_id")?,
            bytes: row.try_get("bytes")?,
        });
    }
    Ok(allocations)
}

async fn load_live_grants(
    c: &mut PgConnection,
    group_id: &str,
) -> Result<Vec<(String, DurableLiveGrant)>, StoreError> {
    let rows = sqlx::query(
        "SELECT g.id::text AS grant_id, g.state, g.profile,
                gd.device_id::text AS device_id, gd.bytes,
                gd.released_at IS NOT NULL AS device_released
           FROM openmettle.capacity_grants g
           JOIN openmettle.capacity_grant_devices gd
             ON gd.group_id = g.group_id AND gd.grant_id = g.id
          WHERE g.group_id = $1::uuid AND g.state <> 'released'
          ORDER BY g.commit_seq, g.id, gd.device_id",
    )
    .bind(group_id)
    .fetch_all(c)
    .await?;
    let mut ordered: Vec<(String, DurableLiveGrant)> = Vec::new();
    for row in rows {
        let grant_id: String = row.try_get("grant_id")?;
        let device_id: String = row.try_get("device_id")?;
        let bytes: i64 = row.try_get("bytes")?;
        let device_released: bool = row.try_get("device_released")?;
        let entry = match ordered.last_mut() {
            Some((last_id, entry)) if *last_id == grant_id => entry,
            _ => {
                ordered.push((
                    grant_id,
                    DurableLiveGrant {
                        state: row.try_get("state")?,
                        profile: row.try_get("profile")?,
                        footprint: BTreeMap::new(),
                        unreleased_devices: Vec::new(),
                    },
                ));
                &mut ordered.last_mut().unwrap().1
            }
        };
        entry.footprint.insert(device_id.clone(), bytes);
        if !device_released {
            entry.unreleased_devices.push(device_id);
        }
    }
    Ok(ordered)
}

async fn prepare_dispatch_tx(
    pool: &PgPool,
    controller: &Controller,
    request: &GrantRequest<'_>,
) -> Result<PreparedDispatch, StoreError> {
    if !is_canonical_uuid(request.scope_id)
        || !is_canonical_uuid(request.run_id)
        || !is_canonical_uuid(request.claim_token)
        || request
            .footprint
            .iter()
            .any(|d| !is_canonical_uuid(&d.device_id))
    {
        return Err(StoreError::Invalid);
    }
    let footprint = serde_json::to_string(request.footprint).map_err(|_| StoreError::Invalid)?;
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false)
        .await
        .map_err(map_tx_error)?;
    let row = sqlx::query(
        "SELECT grant_ref::text, outcome, action, is_replay, observation_stale
           FROM openmettle.capacity_prepare_dispatch(
                $1::uuid, $2, $3, $4::uuid, $5::uuid, $6::uuid, $7, $8, $9::jsonb)",
    )
    .bind(controller.group_id())
    .bind(controller.secret.as_slice())
    .bind(controller.epoch())
    .bind(request.scope_id)
    .bind(request.run_id)
    .bind(request.claim_token)
    .bind(request.request_key)
    .bind(request.profile)
    .bind(footprint)
    .fetch_one(tx.connection().map_err(map_tx_error)?)
    .await?;
    tx.commit().await.map_err(map_tx_error)?;

    let grant_ref: Option<String> = row.try_get("grant_ref")?;
    let outcome: String = row.try_get("outcome")?;
    let action: String = row.try_get("action")?;
    let is_replay: bool = row.try_get("is_replay")?;
    let observation_stale: bool = row.try_get("observation_stale")?;
    match (grant_ref, outcome.as_str(), action.as_str()) {
        (None, "insufficient", "none") => Ok(PreparedDispatch::Insufficient),
        (None, "unavailable", "none") => Ok(PreparedDispatch::Unavailable { observation_stale }),
        (Some(grant_id), "granted", "dispatch_now") => Ok(PreparedDispatch::DispatchNow {
            grant_id,
            is_replay,
        }),
        (Some(grant_id), state, "already_settled") => Ok(PreparedDispatch::AlreadySettled {
            grant_id,
            state: GrantState::parse(state)?,
        }),
        _ => Err(StoreError::Database),
    }
}

async fn confirm_dispatch_tx(
    pool: &PgPool,
    controller: &Controller,
    grant_id: &str,
) -> Result<GrantState, StoreError> {
    if !is_canonical_uuid(grant_id) {
        return Err(StoreError::Invalid);
    }
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false)
        .await
        .map_err(map_tx_error)?;
    let state: String = sqlx::query_scalar(
        "SELECT openmettle.capacity_confirm_dispatch($1::uuid, $2, $3, $4::uuid)",
    )
    .bind(controller.group_id())
    .bind(controller.secret.as_slice())
    .bind(controller.epoch())
    .bind(grant_id)
    .fetch_one(tx.connection().map_err(map_tx_error)?)
    .await?;
    tx.commit().await.map_err(map_tx_error)?;
    GrantState::parse(&state)
}

async fn reconcile_tx(
    pool: &PgPool,
    controller: &Controller,
    grant_id: &str,
    evidence: Evidence<'_>,
) -> Result<GrantState, StoreError> {
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false)
        .await
        .map_err(map_tx_error)?;
    let state = super::reconcile(
        tx.connection().map_err(map_tx_error)?,
        controller,
        grant_id,
        evidence,
    )
    .await?;
    tx.commit().await.map_err(map_tx_error)?;
    Ok(state)
}

/// Pool-backed, serialized coordinator for one managed capacity group and its fenced backend
/// adapter (ADR 0042).
///
/// Every database write phase runs in its own committed `READ COMMITTED` bounded transaction
/// (`WriteTransaction::begin_bounded_pool`) before any adapter call, ensuring durable commits
/// cannot roll back after backend side effects and concurrent bursts are blocked while any
/// dispatch is `in_flight`.
pub struct GroupCoordinator<A: CapacityAdapter> {
    pool: PgPool,
    controller: Controller,
    adapter: A,
    op_lock: tokio::sync::Mutex<()>,
    unresolved_backend_unknown: AtomicBool,
}

impl<A: CapacityAdapter> GroupCoordinator<A> {
    pub fn new(pool: PgPool, controller: Controller, adapter: A) -> Self {
        Self {
            pool,
            controller,
            adapter,
            op_lock: tokio::sync::Mutex::new(()),
            unresolved_backend_unknown: AtomicBool::new(false),
        }
    }

    pub fn controller(&self) -> &Controller {
        &self.controller
    }

    pub fn adapter(&self) -> &A {
        &self.adapter
    }

    pub fn has_unresolved_backend_unknown(&self) -> bool {
        self.unresolved_backend_unknown.load(Ordering::Acquire)
    }

    async fn adapter_release_verified(
        &self,
        grant_id: &str,
        expected: &BTreeSet<String>,
    ) -> Result<VerifiedRelease, AdapterError> {
        let command = ReleaseGrantCommand {
            version: ADAPTER_CONTRACT_VERSION.to_owned(),
            group_id: self.controller.group_id().to_owned(),
            controller_epoch: self.controller.epoch(),
            grant_id: grant_id.to_owned(),
            devices: expected.iter().cloned().collect(),
        };
        let response = self.adapter.release_grant(command).await?;
        if response.version != ADAPTER_CONTRACT_VERSION
            || response.group_id != self.controller.group_id()
            || response.controller_epoch != self.controller.epoch()
            || response.grant_id != grant_id
        {
            return Err(AdapterError::Invalid);
        }
        let mut seen = BTreeSet::new();
        let mut released_ids = Vec::new();
        let mut not_allocated_ids = Vec::new();
        let mut unknown_ids = Vec::new();
        for item in response.devices {
            if !expected.contains(&item.device_id) || !seen.insert(item.device_id.clone()) {
                return Err(AdapterError::Invalid);
            }
            match item.status {
                DeviceReleaseStatus::Released => released_ids.push(item.device_id),
                DeviceReleaseStatus::NotAllocated => not_allocated_ids.push(item.device_id),
                DeviceReleaseStatus::Unknown => unknown_ids.push(item.device_id),
            }
        }
        if seen != *expected {
            return Err(AdapterError::Invalid);
        }
        Ok(VerifiedRelease {
            released_ids,
            not_allocated_ids,
            unknown_ids,
        })
    }

    async fn apply_release_for_grant(
        &self,
        grant_id: &str,
        db_unreleased: &[String],
        extra_backend: &BTreeSet<String>,
    ) -> Result<GrantState, CoordinatorError> {
        let db_set = canonical_devices(db_unreleased)?;
        let mut union = db_set.clone();
        for dev in extra_backend {
            if !is_canonical_uuid(dev) {
                return Err(CoordinatorError::Adapter(AdapterError::Invalid));
            }
            union.insert(dev.clone());
        }
        let verified = match self.adapter_release_verified(grant_id, &union).await {
            Ok(verified) => verified,
            Err(err @ (AdapterError::StaleEpoch { .. } | AdapterError::Unfenced)) => {
                return Err(CoordinatorError::Adapter(err));
            }
            Err(err) => {
                reconcile_tx(
                    &self.pool,
                    &self.controller,
                    grant_id,
                    Evidence::UnknownAllocation,
                )
                .await?;
                return Err(CoordinatorError::Adapter(err));
            }
        };

        // If any extra backend-only rank failed to confirm release, never settle the durable
        // grant or its quota slot in PostgreSQL: keep it in `unknown_allocation` so takeover can
        // retry releasing the union.
        let extra_unresolved = verified.unknown_ids.iter().any(|dev| !db_set.contains(dev));
        if extra_unresolved {
            let state = reconcile_tx(
                &self.pool,
                &self.controller,
                grant_id,
                Evidence::UnknownAllocation,
            )
            .await?;
            return Ok(state);
        }

        let db_released: Vec<String> = verified
            .released_ids
            .into_iter()
            .filter(|d| db_set.contains(d))
            .collect();
        let db_not_allocated: Vec<String> = verified
            .not_allocated_ids
            .into_iter()
            .filter(|d| db_set.contains(d))
            .collect();
        let db_has_unknown = verified.unknown_ids.iter().any(|d| db_set.contains(d));

        let mut tx = WriteTransaction::begin_bounded_pool(&self.pool, false)
            .await
            .map_err(map_tx_error)?;
        let conn = tx.connection().map_err(map_tx_error)?;
        let mut final_state = None;
        if !db_released.is_empty() {
            final_state = Some(
                super::reconcile(
                    conn,
                    &self.controller,
                    grant_id,
                    Evidence::Released(&db_released),
                )
                .await?,
            );
        }
        if !db_not_allocated.is_empty() {
            final_state = Some(
                super::reconcile(
                    conn,
                    &self.controller,
                    grant_id,
                    Evidence::NotAllocated(&db_not_allocated),
                )
                .await?,
            );
        }
        if db_has_unknown && final_state != Some(GrantState::UnknownAllocation) {
            final_state = Some(
                super::reconcile(
                    conn,
                    &self.controller,
                    grant_id,
                    Evidence::UnknownAllocation,
                )
                .await?,
            );
        }
        tx.commit().await.map_err(map_tx_error)?;
        Ok(final_state.unwrap_or(GrantState::UnknownAllocation))
    }

    /// Establish the successor controller's epoch on the adapter and reconcile both backend-only
    /// rogue allocations and every non-released durable grant in PostgreSQL (ADR 0042).
    ///
    /// If any rogue allocation or mismatched extra rank fails to confirm release, this records
    /// `has_unresolved_backend_unknown() == true` so [`Self::resume`] refuses to reopen bursts
    /// until a subsequent takeover confirms release.
    pub async fn takeover_and_reconcile(&self) -> Result<TakeoverReport, CoordinatorError> {
        let _guard = self.op_lock.lock().await;
        // Fail closed if takeover aborts partway through.
        self.unresolved_backend_unknown
            .store(true, Ordering::Release);

        let response = self
            .adapter
            .establish_epoch(EstablishEpochRequest::new(&self.controller))
            .await?;
        if response.version != ADAPTER_CONTRACT_VERSION
            || response.group_id != self.controller.group_id()
            || response.established_epoch != self.controller.epoch()
        {
            return Err(CoordinatorError::Adapter(AdapterError::Invalid));
        }
        let mut backend_live: BTreeMap<String, CanonicalGrant> = BTreeMap::new();
        for alloc in response.allocations {
            if !is_canonical_uuid(&alloc.grant_id) {
                return Err(CoordinatorError::Adapter(AdapterError::Invalid));
            }
            check_profile(&alloc.profile)?;
            let footprint = canonical_footprint(&alloc.footprint)?;
            if backend_live
                .insert(
                    alloc.grant_id,
                    CanonicalGrant {
                        profile: alloc.profile,
                        footprint,
                    },
                )
                .is_some()
            {
                return Err(CoordinatorError::Adapter(AdapterError::Invalid));
            }
        }

        let live_grants = {
            let mut tx = WriteTransaction::begin_bounded_pool(&self.pool, true)
                .await
                .map_err(map_tx_error)?;
            let grants = load_live_grants(
                tx.connection().map_err(map_tx_error)?,
                self.controller.group_id(),
            )
            .await?;
            tx.commit().await.map_err(map_tx_error)?;
            grants
        };
        let durable_ids: BTreeSet<&str> = live_grants.iter().map(|(id, _)| id.as_str()).collect();

        let mut report = TakeoverReport {
            established_epoch: response.established_epoch,
            ..TakeoverReport::default()
        };

        // 1. Release backend-only rogue allocations (absent from PostgreSQL or already marked
        //    `released` there) before reopening bursts.
        for (grant_id, alloc) in &backend_live {
            if durable_ids.contains(grant_id.as_str()) {
                continue;
            }
            let rogue_devices: BTreeSet<String> = alloc.footprint.keys().cloned().collect();
            match self
                .adapter_release_verified(grant_id, &rogue_devices)
                .await
            {
                Ok(verified) if verified.unknown_ids.is_empty() => {
                    report.rogue_released += 1;
                }
                Ok(_) | Err(AdapterError::Unavailable) => {
                    report.unknown += 1;
                }
                Err(err) => return Err(CoordinatorError::Adapter(err)),
            }
        }

        // 2. Reconcile every non-released durable grant against fenced backend inventory.
        for (grant_id, durable) in live_grants {
            let exact_match = durable.state == "granted"
                && durable.unreleased_devices.len() == durable.footprint.len()
                && backend_live.get(&grant_id).is_some_and(|live| {
                    live.profile == durable.profile && live.footprint == durable.footprint
                });
            if exact_match {
                reconcile_tx(&self.pool, &self.controller, &grant_id, Evidence::Allocated).await?;
                report.attested += 1;
                continue;
            }

            let backend_devices: BTreeSet<String> = backend_live
                .get(&grant_id)
                .map(|live| live.footprint.keys().cloned().collect())
                .unwrap_or_default();
            let db_set: BTreeSet<String> = durable.unreleased_devices.iter().cloned().collect();
            let extra_backend: BTreeSet<String> =
                backend_devices.difference(&db_set).cloned().collect();

            // A `granted` row with partial, extra-rank, or byte/profile mismatch transitions to
            // `unknown_allocation` first so bursts stay closed even if release crashes mid-way.
            if durable.state == "granted" && backend_live.contains_key(&grant_id) {
                reconcile_tx(
                    &self.pool,
                    &self.controller,
                    &grant_id,
                    Evidence::UnknownAllocation,
                )
                .await?;
            }

            match self
                .apply_release_for_grant(&grant_id, &durable.unreleased_devices, &extra_backend)
                .await
            {
                Ok(GrantState::Released) => report.released += 1,
                Ok(_) | Err(CoordinatorError::Adapter(AdapterError::Unavailable)) => {
                    report.unknown += 1;
                }
                Err(err) => return Err(err),
            }
        }

        self.unresolved_backend_unknown
            .store(report.unknown > 0, Ordering::Release);
        Ok(report)
    }

    /// Two-phase commit-before-dispatch (ADR 0042):
    ///
    /// 1. Commits the durable grant with `dispatch_state = 'in_flight'` (blocking concurrent
    ///    bursts) and binds the run's `device_reservations` slot in PostgreSQL.
    /// 2. Dispatches the grant to the fenced adapter after that commit succeeds.
    /// 3. Commits `capacity_confirm_dispatch` (`dispatch_state = 'confirmed'`) on valid adapter
    ///    acknowledgement, or reconciles the grant to `unknown_allocation` on ambiguous/failed
    ///    dispatch (leaving `in_flight` intact on `StaleEpoch`/`Unfenced`).
    ///
    /// Replaying an already-settled or dispatch-confirmed grant returns [`DispatchOutcome::Existing`]
    /// without calling the backend or recording duplicate grant/wait metrics. Retrying an
    /// unconfirmed `in_flight` grant re-verifies the run's active claim first.
    pub async fn dispatch_grant(
        &self,
        request: &GrantRequest<'_>,
        wait: &CapacityWait,
    ) -> Result<DispatchOutcome, CoordinatorError> {
        let _guard = self.op_lock.lock().await;
        let prepared = match prepare_dispatch_tx(&self.pool, &self.controller, request).await {
            Ok(prepared) => prepared,
            Err(err) => {
                if err == StoreError::Expired {
                    metrics::global()
                        .record_capacity_stale_observation(CapacityStaleSurface::Controller);
                }
                metrics::global().record_capacity_grant(
                    CapacityOperation::Grant,
                    super::store_error_outcome(&err),
                );
                wait.record(CapacityWaitOutcome::Unavailable);
                return Err(CoordinatorError::Store(err));
            }
        };

        match prepared {
            PreparedDispatch::AlreadySettled { grant_id, state } => {
                Ok(DispatchOutcome::Existing { grant_id, state })
            }
            PreparedDispatch::Insufficient => {
                metrics::global()
                    .record_capacity_grant(CapacityOperation::Grant, CapacityOutcome::Insufficient);
                wait.record(CapacityWaitOutcome::Busy);
                Ok(DispatchOutcome::Insufficient)
            }
            PreparedDispatch::Unavailable { observation_stale } => {
                if observation_stale {
                    metrics::global()
                        .record_capacity_stale_observation(CapacityStaleSurface::Controller);
                }
                metrics::global()
                    .record_capacity_grant(CapacityOperation::Grant, CapacityOutcome::Unavailable);
                wait.record(CapacityWaitOutcome::Unavailable);
                Ok(DispatchOutcome::Unavailable)
            }
            PreparedDispatch::DispatchNow {
                grant_id,
                is_replay,
            } => {
                let command = DispatchGrantCommand {
                    version: ADAPTER_CONTRACT_VERSION.to_owned(),
                    group_id: self.controller.group_id().to_owned(),
                    controller_epoch: self.controller.epoch(),
                    grant_id: grant_id.clone(),
                    profile: request.profile.to_owned(),
                    footprint: request.footprint.to_vec(),
                };
                match self.adapter.dispatch_grant(command).await {
                    Ok(resp)
                        if resp.version == ADAPTER_CONTRACT_VERSION
                            && resp.group_id == self.controller.group_id()
                            && resp.controller_epoch == self.controller.epoch()
                            && resp.grant_id == grant_id =>
                    {
                        if let Err(err) =
                            confirm_dispatch_tx(&self.pool, &self.controller, &grant_id).await
                        {
                            metrics::global().record_capacity_grant(
                                CapacityOperation::Grant,
                                super::store_error_outcome(&err),
                            );
                            wait.record(CapacityWaitOutcome::Unavailable);
                            return Err(CoordinatorError::Store(err));
                        }
                        metrics::global().record_capacity_grant(
                            CapacityOperation::Grant,
                            CapacityOutcome::Granted,
                        );
                        wait.record(CapacityWaitOutcome::Granted);
                        Ok(DispatchOutcome::Dispatched {
                            grant_id,
                            replayed: is_replay || resp.replayed,
                        })
                    }
                    Ok(_) => {
                        if let Err(err) = reconcile_tx(
                            &self.pool,
                            &self.controller,
                            &grant_id,
                            Evidence::UnknownAllocation,
                        )
                        .await
                        {
                            metrics::global().record_capacity_grant(
                                CapacityOperation::Grant,
                                super::store_error_outcome(&err),
                            );
                            wait.record(CapacityWaitOutcome::Unavailable);
                            return Err(CoordinatorError::Store(err));
                        }
                        metrics::global().record_capacity_grant(
                            CapacityOperation::Grant,
                            CapacityOutcome::UnknownAllocation,
                        );
                        wait.record(CapacityWaitOutcome::Unavailable);
                        Err(CoordinatorError::Adapter(AdapterError::Invalid))
                    }
                    Err(err @ (AdapterError::StaleEpoch { .. } | AdapterError::Unfenced)) => {
                        // Deposed or unfenced controller leaves the `in_flight` durable charge
                        // intact so bursts remain blocked until takeover reconciles it.
                        metrics::global().record_capacity_grant(
                            CapacityOperation::Grant,
                            CapacityOutcome::Fenced,
                        );
                        wait.record(CapacityWaitOutcome::Unavailable);
                        Err(CoordinatorError::Adapter(err))
                    }
                    Err(err) => {
                        if let Err(store_err) = reconcile_tx(
                            &self.pool,
                            &self.controller,
                            &grant_id,
                            Evidence::UnknownAllocation,
                        )
                        .await
                        {
                            metrics::global().record_capacity_grant(
                                CapacityOperation::Grant,
                                super::store_error_outcome(&store_err),
                            );
                            wait.record(CapacityWaitOutcome::Unavailable);
                            return Err(CoordinatorError::Store(store_err));
                        }
                        metrics::global().record_capacity_grant(
                            CapacityOperation::Grant,
                            CapacityOutcome::UnknownAllocation,
                        );
                        wait.record(CapacityWaitOutcome::Unavailable);
                        Err(CoordinatorError::Adapter(err))
                    }
                }
            }
        }
    }

    /// Request fenced elastic tail-KV handback from the adapter, strictly verifying the response
    /// device set and byte bounds, and record the reclaim outcome metric.
    pub async fn reclaim_kv(
        &self,
        request_key: &str,
        targets: &[DeviceBytes],
    ) -> Result<ReclaimKvResponse, AdapterError> {
        let _guard = self.op_lock.lock().await;
        let command = ReclaimKvCommand {
            version: ADAPTER_CONTRACT_VERSION.to_owned(),
            group_id: self.controller.group_id().to_owned(),
            controller_epoch: self.controller.epoch(),
            request_key: request_key.to_owned(),
            targets: targets.to_vec(),
        };
        let target_map = command.validate()?;
        let result = self.adapter.reclaim_kv(command).await;
        let outcome = match &result {
            Ok(resp) => {
                let valid = resp.version == ADAPTER_CONTRACT_VERSION
                    && resp.group_id == self.controller.group_id()
                    && resp.controller_epoch == self.controller.epoch()
                    && resp.request_key == request_key
                    && resp.reclaimed.len() == target_map.len()
                    && {
                        let mut seen = BTreeSet::new();
                        resp.reclaimed.iter().all(|item| {
                            target_map.get(&item.device_id).is_some_and(|&target| {
                                seen.insert(item.device_id.as_str())
                                    && item.reclaimed_bytes >= 0
                                    && item.reclaimed_bytes <= target
                            })
                        }) && seen.len() == target_map.len()
                    };
                if !valid {
                    metrics::global()
                        .record_capacity_grant(CapacityOperation::Reclaim, CapacityOutcome::Error);
                    return Err(AdapterError::Invalid);
                }
                CapacityOutcome::Released
            }
            Err(AdapterError::StaleEpoch { .. } | AdapterError::Unfenced) => {
                CapacityOutcome::Fenced
            }
            Err(AdapterError::InsufficientCapacity) => CapacityOutcome::Insufficient,
            Err(AdapterError::Unavailable) => CapacityOutcome::Unavailable,
            Err(
                AdapterError::UnsupportedVersion | AdapterError::Invalid | AdapterError::Conflict,
            ) => CapacityOutcome::Refused,
        };
        metrics::global().record_capacity_grant(CapacityOperation::Reclaim, outcome);
        result
    }

    /// Commit `releasing` in PostgreSQL, obtain confirmed per-device release evidence behind the
    /// adapter epoch fence, and settle the durable grant and its device slot only once every
    /// device has confirmed `Released` or `NotAllocated`.
    pub async fn release_grant(
        &self,
        grant_id: &str,
        devices: &[String],
    ) -> Result<GrantState, CoordinatorError> {
        let _guard = self.op_lock.lock().await;
        let current =
            reconcile_tx(&self.pool, &self.controller, grant_id, Evidence::Releasing).await?;
        if current == GrantState::Released {
            return Ok(GrantState::Released);
        }
        self.apply_release_for_grant(grant_id, devices, &BTreeSet::new())
            .await
    }

    /// Reopen bursts in PostgreSQL only when no backend-only rogue allocation remains unresolved.
    pub async fn resume(&self) -> Result<bool, StoreError> {
        let _guard = self.op_lock.lock().await;
        if self.unresolved_backend_unknown.load(Ordering::Acquire) {
            metrics::global()
                .record_capacity_grant(CapacityOperation::Resume, CapacityOutcome::Unavailable);
            return Ok(false);
        }
        let mut tx = WriteTransaction::begin_bounded_pool(&self.pool, false)
            .await
            .map_err(map_tx_error)?;
        let resumed =
            super::resume(tx.connection().map_err(map_tx_error)?, &self.controller).await?;
        tx.commit().await.map_err(map_tx_error)?;
        Ok(resumed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP: &str = "00000000-0000-4000-8000-00000000a001";
    const OTHER_GROUP: &str = "00000000-0000-4000-8000-00000000a002";
    const GPU0: &str = "00000000-0000-4000-8000-00000000a0d0";
    const GPU1: &str = "00000000-0000-4000-8000-00000000a0d1";
    const GRANT1: &str = "00000000-0000-4000-8000-00000000a101";
    const GRANT2: &str = "00000000-0000-4000-8000-00000000a102";
    const ROGUE: &str = "00000000-0000-4000-8000-00000000a199";
    const GIB: i64 = 1 << 30;

    fn backend_two_gpu() -> FencedBackend {
        FencedBackend::new(
            GROUP,
            vec![
                BackendDeviceConfig {
                    device_id: GPU0.into(),
                    total_bytes: 24 * GIB,
                    safety_headroom_bytes: GIB,
                    active_chat_floor_bytes: 16 * GIB,
                    backed_chat_floor_bytes: 16 * GIB,
                    reclaimable_bytes: 2 * GIB,
                    unattributed_used_bytes: 0,
                },
                BackendDeviceConfig {
                    device_id: GPU1.into(),
                    total_bytes: 24 * GIB,
                    safety_headroom_bytes: GIB,
                    active_chat_floor_bytes: 16 * GIB,
                    backed_chat_floor_bytes: 16 * GIB,
                    reclaimable_bytes: GIB,
                    unattributed_used_bytes: 0,
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn conservative_fit_deduplicates_only_attributed_overlap_and_protects_floor() {
        // 24 GiB total, 1 GiB headroom, 16 GiB chat floor (10 GiB resident), 4 GiB committed (1 GiB resident),
        // 2 GiB unattributed use -> actual_used = 10 + 1 + 2 = 13 GiB.
        // Charged = 13 + (4 - 1) + (16 - 10) + 1 = 23 GiB -> grantable = 1 GiB.
        let fit = DeviceFitInput {
            total_bytes: 24 * GIB,
            committed_bytes: 4 * GIB,
            actual_used_bytes: 13 * GIB,
            reclaimable_bytes: 2 * GIB,
            safety_headroom_bytes: GIB,
            active_chat_floor_bytes: 16 * GIB,
            backed_committed_bytes: GIB,
            backed_chat_floor_bytes: 10 * GIB,
        };
        assert_eq!(compute_device_grantable_bytes(&fit), Ok(GIB));

        // Clamps spare capacity at zero when charges exceed total bytes.
        let oversubscribed = DeviceFitInput {
            committed_bytes: 10 * GIB,
            ..fit
        };
        assert_eq!(compute_device_grantable_bytes(&oversubscribed), Ok(0));

        // Rejects overlapping attribution exceeding actual_used_bytes.
        let overlap = DeviceFitInput {
            backed_committed_bytes: 4 * GIB,
            backed_chat_floor_bytes: 10 * GIB,
            actual_used_bytes: 13 * GIB,
            ..fit
        };
        assert_eq!(
            compute_device_grantable_bytes(&overlap),
            Err(AdapterError::Invalid)
        );

        // Rejects reclaimable_bytes exceeding actual_used_bytes.
        let bad_reclaim = DeviceFitInput {
            reclaimable_bytes: 14 * GIB,
            ..fit
        };
        assert_eq!(
            compute_device_grantable_bytes(&bad_reclaim),
            Err(AdapterError::Invalid)
        );
    }

    #[test]
    fn per_grant_attribution_never_credits_rogue_resident_bytes_to_unbacked_durable_grants() {
        let mut durable = BTreeMap::new();
        durable.insert(GRANT1.to_owned(), 4 * GIB);
        let mut resident = BTreeMap::new();
        resident.insert(ROGUE.to_owned(), 4 * GIB);

        // GRANT1 is unbacked (0 resident) while ROGUE holds 4 GiB: backed_committed MUST be 0.
        assert_eq!(
            attribute_device_commitments(&durable, &resident),
            Ok((4 * GIB, 0))
        );

        // Partial backing of GRANT1 (2 GiB resident) plus 2 GiB rogue credits only 2 GiB.
        resident.insert(GRANT1.to_owned(), 2 * GIB);
        assert_eq!(
            attribute_device_commitments(&durable, &resident),
            Ok((4 * GIB, 2 * GIB))
        );

        // End-to-end on FencedBackend: 24 GiB total, 1 GiB headroom, 16 GiB floor, 0 reclaimable,
        // 4 GiB rogue resident on GPU0 + 4 GiB unbacked durable GRANT1 on GPU0 =>
        // actual_used = 20 GiB, unbacked_committed = 4 GiB, headroom = 1 GiB -> charged 25 -> 0 grantable.
        let backend = FencedBackend::new(
            GROUP,
            vec![BackendDeviceConfig {
                device_id: GPU0.into(),
                total_bytes: 24 * GIB,
                safety_headroom_bytes: GIB,
                active_chat_floor_bytes: 16 * GIB,
                backed_chat_floor_bytes: 16 * GIB,
                reclaimable_bytes: 0,
                unattributed_used_bytes: 0,
            }],
        )
        .unwrap();
        backend
            .inject_rogue_allocation(
                ROGUE,
                "rogue.profile",
                &[DeviceBytes {
                    device_id: GPU0.into(),
                    bytes: 4 * GIB,
                }],
            )
            .unwrap();
        let obs = backend
            .observe_with_commitments(&[DurableGrantAllocation {
                grant_id: GRANT1.into(),
                device_id: GPU0.into(),
                bytes: 4 * GIB,
            }])
            .unwrap();
        assert_eq!(obs[0].committed_bytes, 4 * GIB);
        assert_eq!(obs[0].actual_used_bytes, 20 * GIB);
        assert_eq!(obs[0].grantable_bytes, 0);
    }

    #[test]
    fn envelopes_reject_unknown_fields_and_duplicate_keys() {
        let valid = serde_json::json!({
            "version": ADAPTER_CONTRACT_VERSION,
            "group_id": GROUP,
            "controller_epoch": 2
        });
        let parsed: EstablishEpochRequest = parse_envelope(valid.to_string().as_bytes()).unwrap();
        assert_eq!(parsed.controller_epoch, 2);
        assert!(parsed.validate().is_ok());

        let unknown = serde_json::json!({
            "version": ADAPTER_CONTRACT_VERSION,
            "group_id": GROUP,
            "controller_epoch": 2,
            "extra": true
        });
        assert_eq!(
            parse_envelope::<EstablishEpochRequest>(unknown.to_string().as_bytes()),
            Err(AdapterError::Invalid)
        );
        let dup = format!(
            r#"{{"version":"{ADAPTER_CONTRACT_VERSION}","group_id":"{GROUP}","controller_epoch":1,"controller_epoch":2}}"#
        );
        assert_eq!(
            parse_envelope::<EstablishEpochRequest>(dup.as_bytes()),
            Err(AdapterError::Invalid)
        );
    }

    #[tokio::test]
    async fn fenced_backend_enforces_epoch_barrier_idempotency_and_reclaim_floor() {
        let backend = backend_two_gpu();
        let dispatch_e1 = DispatchGrantCommand {
            version: ADAPTER_CONTRACT_VERSION.into(),
            group_id: GROUP.into(),
            controller_epoch: 1,
            grant_id: GRANT1.into(),
            profile: "media.image".into(),
            footprint: vec![DeviceBytes {
                device_id: GPU0.into(),
                bytes: 4 * GIB,
            }],
        };
        // Refuses commands before establish_epoch.
        assert_eq!(
            backend.dispatch_grant(dispatch_e1.clone()).await,
            Err(AdapterError::Unfenced)
        );

        // Unsupported version is rejected.
        assert_eq!(
            backend
                .establish_epoch(EstablishEpochRequest {
                    version: "openmettle.capacity-adapter/99".into(),
                    group_id: GROUP.into(),
                    controller_epoch: 1,
                })
                .await,
            Err(AdapterError::UnsupportedVersion)
        );
        // Wrong group is rejected.
        assert_eq!(
            backend
                .establish_epoch(EstablishEpochRequest {
                    version: ADAPTER_CONTRACT_VERSION.into(),
                    group_id: OTHER_GROUP.into(),
                    controller_epoch: 1,
                })
                .await,
            Err(AdapterError::Invalid)
        );

        // Establish epoch 1 idempotently.
        let est = backend
            .establish_epoch(EstablishEpochRequest {
                version: ADAPTER_CONTRACT_VERSION.into(),
                group_id: GROUP.into(),
                controller_epoch: 1,
            })
            .await
            .unwrap();
        assert_eq!(est.established_epoch, 1);
        assert!(est.allocations.is_empty());

        // Dispatch grant 1 and replay identically -> idempotent, no double charge.
        let first = backend.dispatch_grant(dispatch_e1.clone()).await.unwrap();
        assert!(!first.replayed);
        let replay = backend.dispatch_grant(dispatch_e1.clone()).await.unwrap();
        assert!(replay.replayed);

        // Conflicting footprint under same grant_id is refused.
        let mut conflicting = dispatch_e1.clone();
        conflicting.footprint[0].bytes = 3 * GIB;
        assert_eq!(
            backend.dispatch_grant(conflicting).await,
            Err(AdapterError::Conflict)
        );

        // Reclaim tail KV idempotently without touching active_chat_floor_bytes.
        let reclaim = ReclaimKvCommand {
            version: ADAPTER_CONTRACT_VERSION.into(),
            group_id: GROUP.into(),
            controller_epoch: 1,
            request_key: "reclaim-1".into(),
            targets: vec![DeviceBytes {
                device_id: GPU0.into(),
                bytes: 5 * GIB,
            }],
        };
        let r1 = backend.reclaim_kv(reclaim.clone()).await.unwrap();
        assert_eq!(r1.reclaimed[0].reclaimed_bytes, 2 * GIB);
        let r2 = backend.reclaim_kv(reclaim.clone()).await.unwrap();
        assert_eq!(r2, r1);
        let obs = backend.observe().unwrap();
        assert_eq!(obs[0].active_chat_floor_bytes, 16 * GIB);
        assert_eq!(obs[0].reclaimable_bytes, 0);
        // 24 - 1 headroom - 16 floor - 4 grant1 = 3 GiB grantable now.
        assert_eq!(obs[0].grantable_bytes, 3 * GIB);

        // Successor controller establishes epoch 2 and sees GRANT1 live.
        let est2 = backend
            .establish_epoch(EstablishEpochRequest {
                version: ADAPTER_CONTRACT_VERSION.into(),
                group_id: GROUP.into(),
                controller_epoch: 2,
            })
            .await
            .unwrap();
        assert_eq!(est2.established_epoch, 2);
        assert_eq!(est2.allocations.len(), 1);
        assert_eq!(est2.allocations[0].grant_id, GRANT1);

        // Cross-epoch idempotent replay of reclaim_kv returns epoch 2 and cached handback.
        let r_e2 = backend
            .reclaim_kv(ReclaimKvCommand {
                controller_epoch: 2,
                ..reclaim
            })
            .await
            .unwrap();
        assert_eq!(r_e2.controller_epoch, 2);
        assert_eq!(r_e2.reclaimed, r1.reclaimed);

        // Stale epoch 1 cannot establish, dispatch, reclaim, or release after takeover.
        assert_eq!(
            backend
                .establish_epoch(EstablishEpochRequest {
                    version: ADAPTER_CONTRACT_VERSION.into(),
                    group_id: GROUP.into(),
                    controller_epoch: 1,
                })
                .await,
            Err(AdapterError::StaleEpoch {
                established_epoch: 2
            })
        );
        assert_eq!(
            backend
                .dispatch_grant(DispatchGrantCommand {
                    grant_id: GRANT2.into(),
                    ..dispatch_e1.clone()
                })
                .await,
            Err(AdapterError::StaleEpoch {
                established_epoch: 2
            })
        );
        assert_eq!(
            backend
                .release_grant(ReleaseGrantCommand {
                    version: ADAPTER_CONTRACT_VERSION.into(),
                    group_id: GROUP.into(),
                    controller_epoch: 1,
                    grant_id: GRANT1.into(),
                    devices: vec![GPU0.into()],
                })
                .await,
            Err(AdapterError::StaleEpoch {
                established_epoch: 2
            })
        );

        // Epoch 2 releases GRANT1 idempotently and confirms GRANT2 was never allocated.
        let rel1 = backend
            .release_grant(ReleaseGrantCommand {
                version: ADAPTER_CONTRACT_VERSION.into(),
                group_id: GROUP.into(),
                controller_epoch: 2,
                grant_id: GRANT1.into(),
                devices: vec![GPU0.into()],
            })
            .await
            .unwrap();
        assert_eq!(rel1.devices[0].status, DeviceReleaseStatus::Released);
        let rel1_dup = backend
            .release_grant(ReleaseGrantCommand {
                version: ADAPTER_CONTRACT_VERSION.into(),
                group_id: GROUP.into(),
                controller_epoch: 2,
                grant_id: GRANT1.into(),
                devices: vec![GPU0.into()],
            })
            .await
            .unwrap();
        assert_eq!(rel1_dup.devices[0].status, DeviceReleaseStatus::Released);

        let rel2 = backend
            .release_grant(ReleaseGrantCommand {
                version: ADAPTER_CONTRACT_VERSION.into(),
                group_id: GROUP.into(),
                controller_epoch: 2,
                grant_id: GRANT2.into(),
                devices: vec![GPU0.into()],
            })
            .await
            .unwrap();
        assert_eq!(rel2.devices[0].status, DeviceReleaseStatus::NotAllocated);

        // Delayed dispatch of tombstoned GRANT1 or GRANT2 is refused even in epoch 2.
        assert_eq!(
            backend
                .dispatch_grant(DispatchGrantCommand {
                    controller_epoch: 2,
                    ..dispatch_e1
                })
                .await,
            Err(AdapterError::Conflict)
        );
    }

    #[tokio::test]
    async fn partial_release_removes_released_device_from_inventory_and_blocks_dispatch_replay() {
        let backend = backend_two_gpu();
        backend
            .establish_epoch(EstablishEpochRequest {
                version: ADAPTER_CONTRACT_VERSION.into(),
                group_id: GROUP.into(),
                controller_epoch: 1,
            })
            .await
            .unwrap();
        let dispatch = DispatchGrantCommand {
            version: ADAPTER_CONTRACT_VERSION.into(),
            group_id: GROUP.into(),
            controller_epoch: 1,
            grant_id: GRANT1.into(),
            profile: "media.two_gpu".into(),
            footprint: vec![
                DeviceBytes {
                    device_id: GPU0.into(),
                    bytes: 3 * GIB,
                },
                DeviceBytes {
                    device_id: GPU1.into(),
                    bytes: 3 * GIB,
                },
            ],
        };
        backend.dispatch_grant(dispatch.clone()).await.unwrap();

        // GPU1 release returns Unknown while GPU0 confirms Released.
        backend.inject_unknown_release(GRANT1, GPU1);
        let rel = backend
            .release_grant(ReleaseGrantCommand {
                version: ADAPTER_CONTRACT_VERSION.into(),
                group_id: GROUP.into(),
                controller_epoch: 1,
                grant_id: GRANT1.into(),
                devices: vec![GPU0.into(), GPU1.into()],
            })
            .await
            .unwrap();
        assert_eq!(rel.devices[0].status, DeviceReleaseStatus::Released);
        assert_eq!(rel.devices[1].status, DeviceReleaseStatus::Unknown);

        // Replaying dispatch_grant on the partially-released grant MUST fail with Conflict
        // even though GPU1 is still resident.
        assert_eq!(
            backend.dispatch_grant(dispatch).await,
            Err(AdapterError::Conflict)
        );

        // establish_epoch inventory MUST report only the still-resident device (GPU1), not GPU0!
        let est2 = backend
            .establish_epoch(EstablishEpochRequest {
                version: ADAPTER_CONTRACT_VERSION.into(),
                group_id: GROUP.into(),
                controller_epoch: 2,
            })
            .await
            .unwrap();
        assert_eq!(est2.allocations.len(), 1);
        assert_eq!(est2.allocations[0].grant_id, GRANT1);
        assert_eq!(
            est2.allocations[0].footprint,
            vec![DeviceBytes {
                device_id: GPU1.into(),
                bytes: 3 * GIB,
            }]
        );
    }
}
