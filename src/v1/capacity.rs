//! Authenticated `/v1` capacity visibility and privileged operator inspection (ADR 0042, PR3).
//!
//! `GET /v1/capacity` projects coarse caller-authorized availability (`ready`, `busy`,
//! `queued_estimate`, `unavailable`) without reserving capacity and omits inaccessible profiles.
//! `GET /v1/admin/capacity/groups` exposes versioned per-group and per-device observations only
//! to active `account_admin` principals or active operators granted the opt-in `capacity.inspect`
//! capability. Both run in a `REPEATABLE READ, READ ONLY` transaction and read only through
//! `openmettle.capacity_profiles` and `openmettle.capacity_group_observations()`, never touching
//! `capacity_groups.controller_token_hash` or tenant `capacity_grants` rows.
use super::{
    Api, INTERNAL, INVALID, Op, Problem, Session, catalog, denied, principal, read_only_snapshot,
    reply, timestamp,
};
use crate::{
    authz::{self, CapabilityGate, PlatformPolicy, Principal, store},
    model_config::Catalog,
    telemetry::metrics::{self, CapacityStaleSurface},
};
use axum::{
    http::{StatusCode, request::Parts},
    response::Response,
};
use serde_json::{Value, json};
use sqlx::{PgConnection, Row};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProfileConfig {
    profile: String,
    group_id: String,
    per_device_bytes: i64,
    required_devices: usize,
    required_capability: Option<String>,
    capability_gate: CapabilityGate,
    estimated_wait_seconds: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservedDevice {
    device_id: String,
    total_bytes: i64,
    committed_bytes: i64,
    actual_used_bytes: i64,
    reclaimable_bytes: i64,
    safety_headroom_bytes: i64,
    active_chat_floor_bytes: i64,
    grantable_bytes: i64,
    effective_grantable_bytes: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservedGroup {
    group_id: String,
    controller_epoch: i64,
    admits_bursts: bool,
    observation_stale: bool,
    observation_revision: i64,
    observed_at_us: Option<i64>,
    devices: Vec<ObservedDevice>,
}

fn parse_capability_gate(value: &str) -> Result<CapabilityGate, Problem> {
    match value {
        "on_by_default" => Ok(CapabilityGate::OnByDefault),
        "opt_in" => Ok(CapabilityGate::OptIn),
        _ => Err(INTERNAL),
    }
}

async fn load_profiles(tx: &mut PgConnection) -> Result<Vec<ProfileConfig>, Problem> {
    let rows = sqlx::query(
        "SELECT profile, group_id::text AS group_id, per_device_bytes, required_devices,
                required_capability, capability_gate, estimated_wait_seconds
           FROM openmettle.capacity_profiles
          ORDER BY profile",
    )
    .fetch_all(tx)
    .await?;
    let mut profiles = Vec::with_capacity(rows.len());
    for row in rows {
        let required_devices: i32 = row.try_get("required_devices")?;
        let required_devices = usize::try_from(required_devices).map_err(|_| INTERNAL)?;
        let gate: String = row.try_get("capability_gate")?;
        profiles.push(ProfileConfig {
            profile: row.try_get("profile")?,
            group_id: row.try_get("group_id")?,
            per_device_bytes: row.try_get("per_device_bytes")?,
            required_devices,
            required_capability: row.try_get("required_capability")?,
            capability_gate: parse_capability_gate(&gate)?,
            estimated_wait_seconds: row.try_get("estimated_wait_seconds")?,
        });
    }
    Ok(profiles)
}

async fn load_group_observations(tx: &mut PgConnection) -> Result<Vec<ObservedGroup>, Problem> {
    let rows = sqlx::query(
        "SELECT group_id::text AS group_id, controller_epoch, admits_bursts, observation_stale,
                observation_revision, observed_at_us, device_id::text AS device_id,
                total_bytes, committed_bytes, actual_used_bytes, reclaimable_bytes,
                safety_headroom_bytes, active_chat_floor_bytes, grantable_bytes,
                effective_grantable_bytes
           FROM openmettle.capacity_group_observations()",
    )
    .fetch_all(tx)
    .await?;
    let mut groups: Vec<ObservedGroup> = Vec::new();
    for row in rows {
        let group_id: String = row.try_get("group_id")?;
        let group = match groups.last_mut() {
            Some(last) if last.group_id == group_id => last,
            _ => {
                groups.push(ObservedGroup {
                    group_id,
                    controller_epoch: row.try_get("controller_epoch")?,
                    admits_bursts: row.try_get("admits_bursts")?,
                    observation_stale: row.try_get("observation_stale")?,
                    observation_revision: row.try_get("observation_revision")?,
                    observed_at_us: row.try_get("observed_at_us")?,
                    devices: Vec::new(),
                });
                groups.last_mut().unwrap()
            }
        };
        let Some(device_id) = row.try_get::<Option<String>, _>("device_id")? else {
            continue;
        };
        group.devices.push(ObservedDevice {
            device_id,
            total_bytes: row.try_get("total_bytes")?,
            committed_bytes: row.try_get("committed_bytes")?,
            actual_used_bytes: row.try_get("actual_used_bytes")?,
            reclaimable_bytes: row.try_get("reclaimable_bytes")?,
            safety_headroom_bytes: row.try_get("safety_headroom_bytes")?,
            active_chat_floor_bytes: row.try_get("active_chat_floor_bytes")?,
            grantable_bytes: row.try_get("grantable_bytes")?,
            effective_grantable_bytes: row.try_get("effective_grantable_bytes")?,
        });
    }
    Ok(groups)
}

fn profile_authorized(
    principal: &Principal,
    platform: &PlatformPolicy,
    model_catalog: Option<&Catalog>,
    profile: &ProfileConfig,
) -> bool {
    if let Some(cap) = profile.required_capability.as_deref()
        && !authz::authorize_capability(principal, platform, cap, profile.capability_gate)
            .is_allowed()
    {
        return false;
    }
    if let Some(model_catalog) = model_catalog
        && model_catalog.model(&profile.profile).is_some()
        && !catalog::allowed(model_catalog, principal, platform, &profile.profile, None)
    {
        return false;
    }
    true
}

fn device_physically_satisfiable(device: &ObservedDevice, per_device_bytes: i64) -> bool {
    let available = i128::from(device.total_bytes)
        - i128::from(device.safety_headroom_bytes)
        - i128::from(device.active_chat_floor_bytes);
    available >= i128::from(per_device_bytes)
}

fn profile_availability(
    profile: &ProfileConfig,
    group: Option<&ObservedGroup>,
) -> (&'static str, Option<i32>) {
    let Some(group) = group else {
        return ("unavailable", None);
    };
    if !group.admits_bursts {
        return ("unavailable", None);
    }
    let ready = group
        .devices
        .iter()
        .filter(|d| d.effective_grantable_bytes >= profile.per_device_bytes)
        .count();
    if ready >= profile.required_devices {
        return ("ready", None);
    }
    let satisfiable = group
        .devices
        .iter()
        .filter(|d| device_physically_satisfiable(d, profile.per_device_bytes))
        .count();
    if satisfiable >= profile.required_devices {
        if let Some(wait) = profile.estimated_wait_seconds {
            return ("queued_estimate", Some(wait));
        }
        return ("busy", None);
    }
    ("unavailable", None)
}

fn project_user_capacity(
    principal: &Principal,
    platform: &PlatformPolicy,
    model_catalog: Option<&Catalog>,
    profiles: &[ProfileConfig],
    groups: &[ObservedGroup],
) -> (Value, usize) {
    let by_id: BTreeMap<&str, &ObservedGroup> =
        groups.iter().map(|g| (g.group_id.as_str(), g)).collect();
    let mut stale_groups = BTreeSet::new();
    let mut projected = Vec::new();
    for profile in profiles {
        if !profile_authorized(principal, platform, model_catalog, profile) {
            continue;
        }
        let group = by_id.get(profile.group_id.as_str()).copied();
        if let Some(g) = group
            && g.observation_stale
        {
            stale_groups.insert(g.group_id.as_str());
        }
        let (availability, estimated_wait_seconds) = profile_availability(profile, group);
        projected.push(json!({
            "profile": profile.profile,
            "availability": availability,
            "estimated_wait_seconds": estimated_wait_seconds,
        }));
    }
    (json!({ "profiles": projected }), stale_groups.len())
}

fn project_admin_groups(groups: &[ObservedGroup]) -> Result<(Value, usize), Problem> {
    let mut stale_count = 0usize;
    let mut projected = Vec::with_capacity(groups.len());
    for group in groups {
        if group.observation_stale {
            stale_count += 1;
        }
        let mut total_bytes = 0i128;
        let mut committed_bytes = 0i128;
        let mut actual_used_bytes = 0i128;
        let mut reclaimable_bytes = 0i128;
        let mut safety_headroom_bytes = 0i128;
        let mut active_chat_floor_bytes = 0i128;
        let mut grantable_bytes = 0i128;
        let mut effective_grantable_bytes = 0i128;
        let mut devices = Vec::with_capacity(group.devices.len());
        for d in &group.devices {
            total_bytes += i128::from(d.total_bytes);
            committed_bytes += i128::from(d.committed_bytes);
            actual_used_bytes += i128::from(d.actual_used_bytes);
            reclaimable_bytes += i128::from(d.reclaimable_bytes);
            safety_headroom_bytes += i128::from(d.safety_headroom_bytes);
            active_chat_floor_bytes += i128::from(d.active_chat_floor_bytes);
            grantable_bytes += i128::from(d.grantable_bytes);
            effective_grantable_bytes += i128::from(d.effective_grantable_bytes);
            devices.push(json!({
                "device_id": d.device_id,
                "total_bytes": d.total_bytes.to_string(),
                "committed_bytes": d.committed_bytes.to_string(),
                "actual_used_bytes": d.actual_used_bytes.to_string(),
                "reclaimable_bytes": d.reclaimable_bytes.to_string(),
                "safety_headroom_bytes": d.safety_headroom_bytes.to_string(),
                "active_chat_floor_bytes": d.active_chat_floor_bytes.to_string(),
                "grantable_bytes": d.grantable_bytes.to_string(),
                "effective_grantable_bytes": d.effective_grantable_bytes.to_string(),
            }));
        }
        let observed_at = group.observed_at_us.map(timestamp).transpose()?;
        projected.push(json!({
            "group_id": group.group_id,
            "controller_epoch": group.controller_epoch.to_string(),
            "admits_bursts": group.admits_bursts,
            "observation_revision": group.observation_revision.to_string(),
            "observed_at": observed_at,
            "totals": {
                "total_bytes": total_bytes.to_string(),
                "committed_bytes": committed_bytes.to_string(),
                "actual_used_bytes": actual_used_bytes.to_string(),
                "reclaimable_bytes": reclaimable_bytes.to_string(),
                "safety_headroom_bytes": safety_headroom_bytes.to_string(),
                "active_chat_floor_bytes": active_chat_floor_bytes.to_string(),
                "grantable_bytes": grantable_bytes.to_string(),
                "effective_grantable_bytes": effective_grantable_bytes.to_string(),
            },
            "devices": devices,
        }));
    }
    Ok((json!({ "groups": projected }), stale_count))
}

impl Api {
    pub(super) async fn capacity_operation(
        &self,
        op: Op,
        parts: &Parts,
        session: Session,
    ) -> Result<Response, Problem> {
        if parts.uri.query().is_some() {
            return Err(INVALID);
        }
        let model_catalog = parts.extensions.get::<Arc<Catalog>>().map(Arc::as_ref);
        let context = self.authenticate(&session).await?;
        match op {
            Op::GetCapacity => {
                let (body, stale_groups) = self
                    .with_connection(async |c| {
                        read_only_snapshot(c, async |tx| {
                            let p = principal(tx, &context).await?;
                            let policy = store::load_platform_capabilities(tx).await?;
                            let profiles = load_profiles(tx).await?;
                            let groups = load_group_observations(tx).await?;
                            Ok(project_user_capacity(
                                &p,
                                &policy,
                                model_catalog,
                                &profiles,
                                &groups,
                            ))
                        })
                        .await
                    })
                    .await?;
                for _ in 0..stale_groups {
                    metrics::global()
                        .record_capacity_stale_observation(CapacityStaleSurface::V1User);
                }
                Ok(reply(StatusCode::OK, body))
            }
            Op::ListAdminCapacityGroups => {
                let (body, stale_groups) = self
                    .with_connection(async |c| {
                        read_only_snapshot(c, async |tx| {
                            let p = principal(tx, &context).await?;
                            let policy = store::load_platform_capabilities(tx).await?;
                            if let authz::Decision::Deny(reason) =
                                authz::authorize_capacity_inspection(&p, &policy)
                            {
                                return Err(denied(reason));
                            }
                            let groups = load_group_observations(tx).await?;
                            project_admin_groups(&groups)
                        })
                        .await
                    })
                    .await?;
                for _ in 0..stale_groups {
                    metrics::global()
                        .record_capacity_stale_observation(CapacityStaleSurface::V1Admin);
                }
                Ok(reply(StatusCode::OK, body))
            }
            _ => Err(INTERNAL),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP_A: &str = "00000000-0000-4000-8000-00000000c101";
    const GROUP_B: &str = "00000000-0000-4000-8000-00000000c102";
    const DEV_0: &str = "00000000-0000-4000-8000-00000000d100";
    const DEV_1: &str = "00000000-0000-4000-8000-00000000d101";
    const GIB: i64 = 1 << 30;

    fn active_user() -> Principal {
        Principal {
            user_id: "00000000-0000-4000-8000-000000000001".into(),
            personal_scope_id: "00000000-0000-4000-8000-000000000002".into(),
            account_active: true,
            approval_active: true,
            provider_active: true,
            ..Principal::default()
        }
    }

    fn device(
        id: &str,
        total: i64,
        grantable: i64,
        effective: i64,
        reclaimable: i64,
    ) -> ObservedDevice {
        ObservedDevice {
            device_id: id.into(),
            total_bytes: total,
            committed_bytes: (grantable - effective).max(0),
            actual_used_bytes: 16 * GIB + reclaimable,
            reclaimable_bytes: reclaimable,
            safety_headroom_bytes: GIB,
            active_chat_floor_bytes: 16 * GIB,
            grantable_bytes: grantable,
            effective_grantable_bytes: effective,
        }
    }

    #[test]
    fn user_projection_filters_capabilities_and_maps_all_four_availability_states() {
        let mut user = active_user();
        user.denied_capabilities.insert("media.denied".into());
        let platform = PlatformPolicy::default();
        let groups = vec![
            ObservedGroup {
                group_id: GROUP_A.into(),
                controller_epoch: 3,
                admits_bursts: true,
                observation_stale: false,
                observation_revision: 5,
                observed_at_us: Some(1_795_000_000_123_456),
                devices: vec![
                    device(DEV_0, 24 * GIB, 7 * GIB, 4 * GIB, 2 * GIB),
                    device(DEV_1, 24 * GIB, 7 * GIB, 2 * GIB, 2 * GIB),
                ],
            },
            ObservedGroup {
                group_id: GROUP_B.into(),
                controller_epoch: 2,
                admits_bursts: false,
                observation_stale: true,
                observation_revision: 1,
                observed_at_us: Some(1_795_000_000_000_000),
                devices: vec![device(DEV_0, 24 * GIB, 7 * GIB, 7 * GIB, 0)],
            },
        ];
        let profiles = vec![
            ProfileConfig {
                profile: "a.ready".into(),
                group_id: GROUP_A.into(),
                per_device_bytes: 4 * GIB,
                required_devices: 1,
                required_capability: None,
                capability_gate: CapabilityGate::OnByDefault,
                estimated_wait_seconds: Some(20),
            },
            ProfileConfig {
                profile: "b.queued".into(),
                group_id: GROUP_A.into(),
                per_device_bytes: 5 * GIB,
                required_devices: 2,
                required_capability: None,
                capability_gate: CapabilityGate::OnByDefault,
                estimated_wait_seconds: Some(30),
            },
            ProfileConfig {
                profile: "c.busy".into(),
                group_id: GROUP_A.into(),
                per_device_bytes: 5 * GIB,
                required_devices: 1,
                required_capability: None,
                capability_gate: CapabilityGate::OnByDefault,
                estimated_wait_seconds: None,
            },
            ProfileConfig {
                profile: "d.too_large".into(),
                group_id: GROUP_A.into(),
                per_device_bytes: 8 * GIB, // > 24 - 1 - 16 = 7 GiB
                required_devices: 1,
                required_capability: None,
                capability_gate: CapabilityGate::OnByDefault,
                estimated_wait_seconds: Some(10),
            },
            ProfileConfig {
                profile: "e.stale".into(),
                group_id: GROUP_B.into(),
                per_device_bytes: 2 * GIB,
                required_devices: 1,
                required_capability: None,
                capability_gate: CapabilityGate::OnByDefault,
                estimated_wait_seconds: Some(10),
            },
            ProfileConfig {
                profile: "f.denied".into(),
                group_id: GROUP_A.into(),
                per_device_bytes: GIB,
                required_devices: 1,
                required_capability: Some("media.denied".into()),
                capability_gate: CapabilityGate::OnByDefault,
                estimated_wait_seconds: None,
            },
            ProfileConfig {
                profile: "g.opt_in_hidden".into(),
                group_id: GROUP_A.into(),
                per_device_bytes: GIB,
                required_devices: 1,
                required_capability: Some("media.video".into()),
                capability_gate: CapabilityGate::OptIn,
                estimated_wait_seconds: None,
            },
        ];

        let (body, stale) = project_user_capacity(&user, &platform, None, &profiles, &groups);
        assert_eq!(stale, 1);
        assert_eq!(
            body,
            json!({
                "profiles": [
                    { "profile": "a.ready", "availability": "ready", "estimated_wait_seconds": null },
                    { "profile": "b.queued", "availability": "queued_estimate", "estimated_wait_seconds": 30 },
                    { "profile": "c.busy", "availability": "busy", "estimated_wait_seconds": null },
                    { "profile": "d.too_large", "availability": "unavailable", "estimated_wait_seconds": null },
                    { "profile": "e.stale", "availability": "unavailable", "estimated_wait_seconds": null },
                ]
            })
        );
        // Never leaks group IDs, device IDs, or raw byte counts.
        let rendered = body.to_string();
        for forbidden in [GROUP_A, GROUP_B, DEV_0, DEV_1, "grantable", "total_bytes"] {
            assert!(!rendered.contains(forbidden), "{rendered}");
        }
    }

    #[test]
    fn admin_projection_sums_wide_totals_without_overflow_and_formats_timestamps() {
        let groups = vec![
            ObservedGroup {
                group_id: GROUP_A.into(),
                controller_epoch: 4,
                admits_bursts: true,
                observation_stale: false,
                observation_revision: 9,
                observed_at_us: Some(1_795_000_000_123_456),
                devices: vec![
                    ObservedDevice {
                        device_id: DEV_0.into(),
                        total_bytes: i64::MAX,
                        committed_bytes: 10,
                        actual_used_bytes: 20,
                        reclaimable_bytes: 5,
                        safety_headroom_bytes: 3,
                        active_chat_floor_bytes: 4,
                        grantable_bytes: 100,
                        effective_grantable_bytes: 80,
                    },
                    ObservedDevice {
                        device_id: DEV_1.into(),
                        total_bytes: i64::MAX,
                        committed_bytes: 15,
                        actual_used_bytes: 30,
                        reclaimable_bytes: 7,
                        safety_headroom_bytes: 3,
                        active_chat_floor_bytes: 4,
                        grantable_bytes: 200,
                        effective_grantable_bytes: 150,
                    },
                ],
            },
            ObservedGroup {
                group_id: GROUP_B.into(),
                controller_epoch: 0,
                admits_bursts: false,
                observation_stale: true,
                observation_revision: 0,
                observed_at_us: None,
                devices: vec![],
            },
        ];
        let (body, stale) = project_admin_groups(&groups).unwrap();
        assert_eq!(stale, 1);
        assert_eq!(
            body["groups"][0]["totals"]["total_bytes"],
            (2 * i128::from(i64::MAX)).to_string()
        );
        assert_eq!(
            body["groups"][0]["totals"]["effective_grantable_bytes"],
            "230"
        );
        assert_eq!(
            body["groups"][0]["observed_at"],
            "2026-11-18T11:06:40.123456Z"
        );
        assert_eq!(body["groups"][1]["observed_at"], Value::Null);
        assert_eq!(body["groups"][1]["totals"]["total_bytes"], "0");
    }
}
