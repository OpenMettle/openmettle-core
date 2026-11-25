//! Internal versioned controller/adapter contract and conservative fit math (ADR 0042, PR3).
//!
//! Every adapter envelope carries [`ADAPTER_CONTRACT_VERSION`], the managed `group_id` and the
//! controller's monotonic `controller_epoch`, and rejects unknown fields. On takeover, the
//! successor establishes its epoch with the backend before reconciling durable grants or resuming
//! bursts; stale-epoch commands arriving after that fence can neither allocate nor release.
use super::{
    Controller, Decision, DeviceBytes, Error as StoreError, Evidence, GrantRequest, GrantState,
};
use crate::{
    runs::{bounded, is_canonical_uuid},
    telemetry::metrics::{self, CapacityOperation, CapacityOutcome, CapacityWaitOutcome},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sqlx::{PgConnection, Row};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    sync::Mutex,
    time::Instant,
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
        durable_committed_bytes: i64,
    ) -> Result<super::DeviceObservation, AdapterError> {
        if durable_committed_bytes < 0 {
            return Err(AdapterError::Invalid);
        }
        let backed_committed =
            i64::try_from(self.allocated_bytes()).map_err(|_| AdapterError::Invalid)?;
        let committed = durable_committed_bytes.max(backed_committed);
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
    reclaim_history: BTreeMap<String, (BTreeMap<String, i64>, ReclaimKvResponse)>,
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
            device.observation(&cfg.device_id, 0)?;
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

    /// Snapshot the backend's physical observations using only resident backend allocations as
    /// `committed_bytes`. When publishing to PostgreSQL alongside unbacked or partially-released
    /// durable grants, use [`Self::observe_with_commitments`] with [`durable_committed_through`].
    pub fn observe(&self) -> Result<Vec<super::DeviceObservation>, AdapterError> {
        self.observe_with_commitments(&BTreeMap::new())
    }

    /// Snapshot the backend's physical observations while charging every durable commitment in
    /// `durable_committed` (unbacked portions remain charged via [`compute_device_grantable_bytes`]).
    pub fn observe_with_commitments(
        &self,
        durable_committed: &BTreeMap<String, i64>,
    ) -> Result<Vec<super::DeviceObservation>, AdapterError> {
        let state = self.state.lock().unwrap();
        state
            .devices
            .iter()
            .map(|(id, dev)| dev.observation(id, durable_committed.get(id).copied().unwrap_or(0)))
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
        if state.tombstoned_grants.contains(&command.grant_id) {
            return Err(AdapterError::Conflict);
        }
        for (device_id, &bytes) in &footprint {
            let dev = state.devices.get(device_id).ok_or(AdapterError::Invalid)?;
            let obs = dev.observation(device_id, 0)?;
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
        if let Some((prev_targets, prev_response)) = state.reclaim_history.get(&command.request_key)
        {
            if *prev_targets == targets {
                return Ok(prev_response.clone());
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
            reclaimed,
        };
        state
            .reclaim_history
            .insert(command.request_key, (targets, response.clone()));
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
            .devices
            .values()
            .any(|dev| dev.allocations.contains_key(&command.grant_id));
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

/// Combined error returned by controller coordinator helpers.
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

/// Summary of grants reconciled during [`takeover_and_reconcile`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TakeoverReport {
    pub established_epoch: i64,
    pub attested: usize,
    pub released: usize,
    pub unknown: usize,
}

/// Outcome of [`dispatch_grant`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// Durable grant committed and dispatched to the fenced adapter.
    Dispatched { grant_id: String, replayed: bool },
    /// Replay matched an existing non-`granted` durable grant; never re-dispatched.
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

/// Sum durable non-released grant bytes per device through `commit_watermark` so a published
/// observation counts every still-charged commitment, including unbacked or partially-released
/// grants (ADR 0042).
pub async fn durable_committed_through(
    c: &mut PgConnection,
    group_id: &str,
    commit_watermark: i64,
) -> Result<BTreeMap<String, i64>, StoreError> {
    if !is_canonical_uuid(group_id) || commit_watermark < 0 {
        return Err(StoreError::Invalid);
    }
    let rows = sqlx::query(
        "SELECT gd.device_id::text AS device_id, coalesce(sum(gd.bytes), 0)::bigint AS committed_bytes
           FROM openmettle.capacity_grant_devices gd
           JOIN openmettle.capacity_grants c ON c.id = gd.grant_id
          WHERE gd.group_id = $1::uuid
            AND c.state <> 'released'
            AND c.commit_seq <= $2
          GROUP BY gd.device_id",
    )
    .bind(group_id)
    .bind(commit_watermark)
    .fetch_all(c)
    .await?;
    let mut totals = BTreeMap::new();
    for row in rows {
        totals.insert(row.try_get("device_id")?, row.try_get("committed_bytes")?);
    }
    Ok(totals)
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

async fn apply_release_evidence<A: CapacityAdapter>(
    c: &mut PgConnection,
    controller: &Controller,
    adapter: &A,
    grant_id: &str,
    devices: &[String],
) -> Result<GrantState, CoordinatorError> {
    let expected = canonical_devices(devices)?;
    let command = ReleaseGrantCommand {
        version: ADAPTER_CONTRACT_VERSION.to_owned(),
        group_id: controller.group_id().to_owned(),
        controller_epoch: controller.epoch(),
        grant_id: grant_id.to_owned(),
        devices: expected.iter().cloned().collect(),
    };
    let response = match adapter.release_grant(command).await {
        Ok(response) => response,
        Err(AdapterError::Unavailable) => {
            let _ = super::reconcile(c, controller, grant_id, Evidence::UnknownAllocation).await;
            return Err(CoordinatorError::Adapter(AdapterError::Unavailable));
        }
        Err(err) => return Err(CoordinatorError::Adapter(err)),
    };
    if response.version != ADAPTER_CONTRACT_VERSION
        || response.group_id != controller.group_id()
        || response.controller_epoch != controller.epoch()
        || response.grant_id != grant_id
    {
        let _ = super::reconcile(c, controller, grant_id, Evidence::UnknownAllocation).await;
        return Err(CoordinatorError::Adapter(AdapterError::Invalid));
    }
    let mut seen = BTreeSet::new();
    let mut released_ids = Vec::new();
    let mut not_allocated_ids = Vec::new();
    let mut has_unknown = false;
    for item in response.devices {
        if !expected.contains(&item.device_id) || !seen.insert(item.device_id.clone()) {
            let _ = super::reconcile(c, controller, grant_id, Evidence::UnknownAllocation).await;
            return Err(CoordinatorError::Adapter(AdapterError::Invalid));
        }
        match item.status {
            DeviceReleaseStatus::Released => released_ids.push(item.device_id),
            DeviceReleaseStatus::NotAllocated => not_allocated_ids.push(item.device_id),
            DeviceReleaseStatus::Unknown => has_unknown = true,
        }
    }
    if seen != expected {
        let _ = super::reconcile(c, controller, grant_id, Evidence::UnknownAllocation).await;
        return Err(CoordinatorError::Adapter(AdapterError::Invalid));
    }
    let mut final_state = None;
    if !released_ids.is_empty() {
        final_state = Some(
            super::reconcile(c, controller, grant_id, Evidence::Released(&released_ids)).await?,
        );
    }
    if !not_allocated_ids.is_empty() {
        final_state = Some(
            super::reconcile(
                c,
                controller,
                grant_id,
                Evidence::NotAllocated(&not_allocated_ids),
            )
            .await?,
        );
    }
    if has_unknown {
        let state = match final_state {
            Some(GrantState::UnknownAllocation) => GrantState::UnknownAllocation,
            _ => super::reconcile(c, controller, grant_id, Evidence::UnknownAllocation).await?,
        };
        return Ok(state);
    }
    Ok(final_state.unwrap_or(GrantState::UnknownAllocation))
}

/// Establish the successor controller's epoch on `adapter` and reconcile every non-released
/// durable grant in PostgreSQL against fenced backend inventory (ADR 0042).
///
/// The caller must publish a fresh observation and call [`super::resume`] afterwards; the group
/// stays closed to bursts until all unknowns are resolved and a fresh sample is published.
pub async fn takeover_and_reconcile<A: CapacityAdapter>(
    c: &mut PgConnection,
    controller: &Controller,
    adapter: &A,
) -> Result<TakeoverReport, CoordinatorError> {
    let response = adapter
        .establish_epoch(EstablishEpochRequest::new(controller))
        .await?;
    if response.version != ADAPTER_CONTRACT_VERSION
        || response.group_id != controller.group_id()
        || response.established_epoch != controller.epoch()
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
    let live_grants = load_live_grants(c, controller.group_id()).await?;
    let mut report = TakeoverReport {
        established_epoch: response.established_epoch,
        ..TakeoverReport::default()
    };
    for (grant_id, durable) in live_grants {
        if durable.state == "granted" {
            match backend_live.get(&grant_id) {
                Some(live)
                    if live.profile == durable.profile && live.footprint == durable.footprint =>
                {
                    super::reconcile(c, controller, &grant_id, Evidence::Allocated).await?;
                    report.attested += 1;
                }
                Some(_) => {
                    super::reconcile(c, controller, &grant_id, Evidence::UnknownAllocation).await?;
                    report.unknown += 1;
                }
                None => {
                    match apply_release_evidence(
                        c,
                        controller,
                        adapter,
                        &grant_id,
                        &durable.unreleased_devices,
                    )
                    .await
                    {
                        Ok(GrantState::Released) => report.released += 1,
                        Ok(_) => report.unknown += 1,
                        Err(CoordinatorError::Adapter(AdapterError::Unavailable)) => {
                            report.unknown += 1;
                        }
                        Err(err) => return Err(err),
                    }
                }
            }
        } else {
            match apply_release_evidence(
                c,
                controller,
                adapter,
                &grant_id,
                &durable.unreleased_devices,
            )
            .await
            {
                Ok(GrantState::Released) => report.released += 1,
                Ok(_) => report.unknown += 1,
                Err(CoordinatorError::Adapter(AdapterError::Unavailable)) => {
                    report.unknown += 1;
                }
                Err(err) => return Err(err),
            }
        }
    }
    Ok(report)
}

/// Commit a serialized durable grant in PostgreSQL, then dispatch it to the fenced adapter.
///
/// Must be called outside an uncommitted transaction (`READ COMMITTED` autocommit on `c`) so the
/// durable grant and quota slot handoff are committed before backend dispatch (ADR 0042).
pub async fn dispatch_grant<A: CapacityAdapter>(
    c: &mut PgConnection,
    controller: &Controller,
    adapter: &A,
    request: &GrantRequest<'_>,
) -> Result<DispatchOutcome, CoordinatorError> {
    let started = Instant::now();
    let decision = match super::grant(c, controller, request).await {
        Ok(decision) => decision,
        Err(err) => {
            metrics::global()
                .record_capacity_wait(CapacityWaitOutcome::Unavailable, started.elapsed());
            return Err(CoordinatorError::Store(err));
        }
    };
    match decision {
        Decision::Insufficient => {
            metrics::global().record_capacity_wait(CapacityWaitOutcome::Busy, started.elapsed());
            Ok(DispatchOutcome::Insufficient)
        }
        Decision::Unavailable => {
            metrics::global()
                .record_capacity_wait(CapacityWaitOutcome::Unavailable, started.elapsed());
            Ok(DispatchOutcome::Unavailable)
        }
        Decision::Grant {
            grant_id,
            state: GrantState::Granted,
        } => {
            let command = DispatchGrantCommand {
                version: ADAPTER_CONTRACT_VERSION.to_owned(),
                group_id: controller.group_id().to_owned(),
                controller_epoch: controller.epoch(),
                grant_id: grant_id.clone(),
                profile: request.profile.to_owned(),
                footprint: request.footprint.to_vec(),
            };
            match adapter.dispatch_grant(command).await {
                Ok(resp) => {
                    if resp.version != ADAPTER_CONTRACT_VERSION
                        || resp.group_id != controller.group_id()
                        || resp.controller_epoch != controller.epoch()
                        || resp.grant_id != grant_id
                    {
                        let _ =
                            super::reconcile(c, controller, &grant_id, Evidence::UnknownAllocation)
                                .await;
                        metrics::global().record_capacity_wait(
                            CapacityWaitOutcome::Unavailable,
                            started.elapsed(),
                        );
                        return Err(CoordinatorError::Adapter(AdapterError::Invalid));
                    }
                    metrics::global()
                        .record_capacity_wait(CapacityWaitOutcome::Granted, started.elapsed());
                    Ok(DispatchOutcome::Dispatched {
                        grant_id,
                        replayed: resp.replayed,
                    })
                }
                Err(err @ (AdapterError::StaleEpoch { .. } | AdapterError::Unfenced)) => {
                    // Deposed or unfenced controller leaves the durable charge intact for takeover.
                    metrics::global()
                        .record_capacity_wait(CapacityWaitOutcome::Unavailable, started.elapsed());
                    Err(CoordinatorError::Adapter(err))
                }
                Err(err) => {
                    let _ = super::reconcile(c, controller, &grant_id, Evidence::UnknownAllocation)
                        .await;
                    metrics::global()
                        .record_capacity_wait(CapacityWaitOutcome::Unavailable, started.elapsed());
                    Err(CoordinatorError::Adapter(err))
                }
            }
        }
        Decision::Grant { grant_id, state } => {
            metrics::global().record_capacity_wait(CapacityWaitOutcome::Granted, started.elapsed());
            Ok(DispatchOutcome::Existing { grant_id, state })
        }
    }
}

/// Request fenced elastic tail-KV handback from `adapter` and record the reclaim outcome metric.
pub async fn reclaim_kv<A: CapacityAdapter>(
    controller: &Controller,
    adapter: &A,
    request_key: &str,
    targets: &[DeviceBytes],
) -> Result<ReclaimKvResponse, AdapterError> {
    let command = ReclaimKvCommand {
        version: ADAPTER_CONTRACT_VERSION.to_owned(),
        group_id: controller.group_id().to_owned(),
        controller_epoch: controller.epoch(),
        request_key: request_key.to_owned(),
        targets: targets.to_vec(),
    };
    command.validate()?;
    let result = adapter.reclaim_kv(command).await;
    let outcome = match &result {
        Ok(resp) => {
            if resp.version != ADAPTER_CONTRACT_VERSION
                || resp.group_id != controller.group_id()
                || resp.controller_epoch != controller.epoch()
                || resp.request_key != request_key
                || resp.reclaimed.iter().any(|r| r.reclaimed_bytes < 0)
            {
                metrics::global()
                    .record_capacity_grant(CapacityOperation::Reclaim, CapacityOutcome::Error);
                return Err(AdapterError::Invalid);
            }
            CapacityOutcome::Released
        }
        Err(AdapterError::StaleEpoch { .. } | AdapterError::Unfenced) => CapacityOutcome::Fenced,
        Err(AdapterError::InsufficientCapacity) => CapacityOutcome::Insufficient,
        Err(AdapterError::Unavailable) => CapacityOutcome::Unavailable,
        Err(AdapterError::UnsupportedVersion | AdapterError::Invalid | AdapterError::Conflict) => {
            CapacityOutcome::Refused
        }
    };
    metrics::global().record_capacity_grant(CapacityOperation::Reclaim, outcome);
    result
}

/// Transition a grant to `releasing`, obtain confirmed per-device release evidence behind the
/// adapter epoch fence, and settle the durable grant and its device slot only once every device
/// has confirmed `Released` or `NotAllocated`.
pub async fn release_grant<A: CapacityAdapter>(
    c: &mut PgConnection,
    controller: &Controller,
    adapter: &A,
    grant_id: &str,
    devices: &[String],
) -> Result<GrantState, CoordinatorError> {
    let current = super::reconcile(c, controller, grant_id, Evidence::Releasing).await?;
    if current == GrantState::Released {
        return Ok(GrantState::Released);
    }
    apply_release_evidence(c, controller, adapter, grant_id, devices).await
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
        let r2 = backend.reclaim_kv(reclaim).await.unwrap();
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
}
