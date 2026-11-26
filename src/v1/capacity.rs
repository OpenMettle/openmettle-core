//! Authenticated `/v1` capacity visibility and privileged operator inspection (ADR 0042, PR3).
//!
//! `GET /v1/capacity` projects coarse caller-authorized availability (`ready`, `busy`,
//! `queued_estimate`, `unavailable`) without reserving capacity and omits inaccessible profiles.
//! `GET /v1/admin/capacity/groups` exposes versioned per-group and per-device observations only
//! to active `account_admin` principals or active operators granted the opt-in `capacity.inspect`
//! capability (explicit user or platform denies on `capacity.inspect` always win). Both run in a
//! `REPEATABLE READ, READ ONLY` transaction and read only through `openmettle.capacity_profiles`
//! and `openmettle.capacity_group_observations()`, never touching
//! `capacity_groups.controller_token_hash` or tenant `capacity_grants` rows.
use super::{
    Api, INTERNAL, INVALID, Op, Problem, Session, UNAVAILABLE, catalog, denied, principal,
    read_only_snapshot, reply, timestamp,
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

const MAX_CAPACITY_PROFILES: usize = 256;
const MAX_CAPACITY_GROUPS: usize = 64;
const MAX_CAPACITY_DEVICES_PER_GROUP: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProfileConfig {
    profile: String,
    group_id: String,
    per_device_bytes: i64,
    required_devices: usize,
    required_capability: Option<String>,
    capability_gate: CapabilityGate,
    model_id: Option<String>,
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
                required_capability, capability_gate, model_id
           FROM openmettle.capacity_profiles
          ORDER BY profile",
    )
    .fetch_all(tx)
    .await?;
    if rows.len() > MAX_CAPACITY_PROFILES {
        return Err(UNAVAILABLE);
    }
    let mut profiles = Vec::with_capacity(rows.len());
    for row in rows {
        let required_devices: i32 = row.try_get("required_devices")?;
        let required_devices = usize::try_from(required_devices).map_err(|_| INTERNAL)?;
        let gate: String = row.try_get("capability_gate")?;
        let capability_gate = parse_capability_gate(&gate)?;
        let required_capability: Option<String> = row.try_get("required_capability")?;
        if capability_gate == CapabilityGate::OptIn && required_capability.is_none() {
            return Err(INTERNAL);
        }
        profiles.push(ProfileConfig {
            profile: row.try_get("profile")?,
            group_id: row.try_get("group_id")?,
            per_device_bytes: row.try_get("per_device_bytes")?,
            required_devices,
            required_capability,
            capability_gate,
            model_id: row.try_get("model_id")?,
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
                if groups.len() >= MAX_CAPACITY_GROUPS {
                    return Err(UNAVAILABLE);
                }
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
        if group.devices.len() >= MAX_CAPACITY_DEVICES_PER_GROUP {
            return Err(UNAVAILABLE);
        }
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

fn collect_profile_models<'a>(
    profiles: &'a [ProfileConfig],
    model_catalog: Option<&Catalog>,
) -> Vec<&'a str> {
    let Some(cat) = model_catalog else {
        return Vec::new();
    };
    let mut seen = BTreeSet::new();
    for profile in profiles {
        if let Some(model_id) = profile.model_id.as_deref()
            && cat.model(model_id).is_some()
        {
            seen.insert(model_id);
        }
    }
    seen.into_iter().collect()
}

fn profile_authorized(
    principal: &Principal,
    platform: &PlatformPolicy,
    model_catalog: Option<&Catalog>,
    family_permitted: &BTreeSet<String>,
    profile: &ProfileConfig,
) -> bool {
    if profile.capability_gate == CapabilityGate::OptIn && profile.required_capability.is_none() {
        return false;
    }
    if let Some(cap) = profile.required_capability.as_deref()
        && !authz::authorize_capability(principal, platform, cap, profile.capability_gate)
            .is_allowed()
    {
        return false;
    }
    if let Some(model_id) = profile.model_id.as_deref() {
        // Explicit model-backed profiles fail closed when no catalog is loaded, when the model
        // has been removed from the catalog, or when capability or family policy denies it.
        // Workload profiles (`model_id: None`) never inherit model restrictions by name collision.
        let Some(cat) = model_catalog else {
            return false;
        };
        if cat.model(model_id).is_none()
            || !catalog::allowed(cat, principal, platform, model_id, None)
            || !family_permitted.contains(model_id)
        {
            return false;
        }
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
        // Until per-caller stored waits exist, an occupied satisfiable profile reports `busy`
        // rather than a static operator-configured wait estimate.
        return ("busy", None);
    }
    ("unavailable", None)
}

fn project_user_capacity(
    principal: &Principal,
    platform: &PlatformPolicy,
    model_catalog: Option<&Catalog>,
    family_permitted: &BTreeSet<String>,
    profiles: &[ProfileConfig],
    groups: &[ObservedGroup],
) -> Result<(Value, usize), Problem> {
    let by_id: BTreeMap<&str, &ObservedGroup> =
        groups.iter().map(|g| (g.group_id.as_str(), g)).collect();
    let mut stale_groups = BTreeSet::new();
    let mut projected = Vec::new();
    for profile in profiles {
        if !profile_authorized(
            principal,
            platform,
            model_catalog,
            family_permitted,
            profile,
        ) {
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
    if projected.len() > MAX_CAPACITY_PROFILES {
        return Err(UNAVAILABLE);
    }
    Ok((json!({ "profiles": projected }), stale_groups.len()))
}

fn project_admin_groups(groups: &[ObservedGroup]) -> Result<(Value, usize), Problem> {
    if groups.len() > MAX_CAPACITY_GROUPS {
        return Err(UNAVAILABLE);
    }
    let mut stale_count = 0usize;
    let mut projected = Vec::with_capacity(groups.len());
    for group in groups {
        if group.devices.len() > MAX_CAPACITY_DEVICES_PER_GROUP {
            return Err(UNAVAILABLE);
        }
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
                            let family_models = collect_profile_models(&profiles, model_catalog);
                            let family_permitted = if family_models.is_empty() {
                                BTreeSet::new()
                            } else {
                                authz::gateway::family::permits_models(
                                    tx,
                                    &p.user_id,
                                    context.approval_id(),
                                    &family_models,
                                    context.observed_ms(),
                                )
                                .await?
                            };
                            project_user_capacity(
                                &p,
                                &policy,
                                model_catalog,
                                &family_permitted,
                                &profiles,
                                &groups,
                            )
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

    fn test_catalog() -> Catalog {
        Catalog::load(include_bytes!(
            "../../tests/fixtures/conversation-catalog-v1.json"
        ))
        .unwrap()
    }

    #[test]
    fn user_projection_filters_capabilities_and_reports_busy_instead_of_static_queue_estimates() {
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
                model_id: None,
            },
            ProfileConfig {
                profile: "b.occupied".into(),
                group_id: GROUP_A.into(),
                per_device_bytes: 5 * GIB,
                required_devices: 2,
                required_capability: None,
                capability_gate: CapabilityGate::OnByDefault,
                model_id: None,
            },
            ProfileConfig {
                profile: "c.busy".into(),
                group_id: GROUP_A.into(),
                per_device_bytes: 5 * GIB,
                required_devices: 1,
                required_capability: None,
                capability_gate: CapabilityGate::OnByDefault,
                model_id: None,
            },
            ProfileConfig {
                profile: "d.too_large".into(),
                group_id: GROUP_A.into(),
                per_device_bytes: 8 * GIB, // > 24 - 1 - 16 = 7 GiB
                required_devices: 1,
                required_capability: None,
                capability_gate: CapabilityGate::OnByDefault,
                model_id: None,
            },
            ProfileConfig {
                profile: "e.stale".into(),
                group_id: GROUP_B.into(),
                per_device_bytes: 2 * GIB,
                required_devices: 1,
                required_capability: None,
                capability_gate: CapabilityGate::OnByDefault,
                model_id: None,
            },
            ProfileConfig {
                profile: "f.denied".into(),
                group_id: GROUP_A.into(),
                per_device_bytes: GIB,
                required_devices: 1,
                required_capability: Some("media.denied".into()),
                capability_gate: CapabilityGate::OnByDefault,
                model_id: None,
            },
            ProfileConfig {
                profile: "g.opt_in_hidden".into(),
                group_id: GROUP_A.into(),
                per_device_bytes: GIB,
                required_devices: 1,
                required_capability: Some("media.video".into()),
                capability_gate: CapabilityGate::OptIn,
                model_id: None,
            },
        ];

        let (body, stale) =
            project_user_capacity(&user, &platform, None, &BTreeSet::new(), &profiles, &groups)
                .unwrap();
        assert_eq!(stale, 1);
        assert_eq!(
            body,
            json!({
                "profiles": [
                    { "profile": "a.ready", "availability": "ready", "estimated_wait_seconds": null },
                    { "profile": "b.occupied", "availability": "busy", "estimated_wait_seconds": null },
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
    fn model_backed_profiles_fail_closed_and_workload_profiles_ignore_name_collisions() {
        let user = active_user();
        let platform = PlatformPolicy::default();
        let cat = test_catalog();
        let groups = vec![ObservedGroup {
            group_id: GROUP_A.into(),
            controller_epoch: 1,
            admits_bursts: true,
            observation_stale: false,
            observation_revision: 1,
            observed_at_us: Some(1_795_000_000_000_000),
            devices: vec![device(DEV_0, 24 * GIB, 7 * GIB, 7 * GIB, 0)],
        }];
        let profiles = vec![
            ProfileConfig {
                profile: "model.a".into(),
                group_id: GROUP_A.into(),
                per_device_bytes: GIB,
                required_devices: 1,
                required_capability: None,
                capability_gate: CapabilityGate::OnByDefault,
                model_id: Some("a".into()),
            },
            ProfileConfig {
                profile: "model.b".into(),
                group_id: GROUP_A.into(),
                per_device_bytes: GIB,
                required_devices: 1,
                required_capability: None,
                capability_gate: CapabilityGate::OnByDefault,
                model_id: Some("b".into()),
            },
            ProfileConfig {
                profile: "model.removed".into(),
                group_id: GROUP_A.into(),
                per_device_bytes: GIB,
                required_devices: 1,
                required_capability: None,
                capability_gate: CapabilityGate::OnByDefault,
                model_id: Some("does-not-exist".into()),
            },
            // Workload profile named "b" with `model_id: None` must NOT inherit model "b"'s
            // family policy restriction via name collision.
            ProfileConfig {
                profile: "b".into(),
                group_id: GROUP_A.into(),
                per_device_bytes: GIB,
                required_devices: 1,
                required_capability: None,
                capability_gate: CapabilityGate::OnByDefault,
                model_id: None,
            },
            // Malformed opt_in without required_capability fails closed.
            ProfileConfig {
                profile: "broken.opt_in".into(),
                group_id: GROUP_A.into(),
                per_device_bytes: GIB,
                required_devices: 1,
                required_capability: None,
                capability_gate: CapabilityGate::OptIn,
                model_id: None,
            },
        ];

        // Without catalog: model_id-backed profiles fail closed; non-model workload profile stays visible.
        let (no_cat, _) =
            project_user_capacity(&user, &platform, None, &BTreeSet::new(), &profiles, &groups)
                .unwrap();
        assert_eq!(
            no_cat,
            json!({
                "profiles": [
                    { "profile": "b", "availability": "ready", "estimated_wait_seconds": null }
                ]
            })
        );

        // With catalog and family policy allowing only "a": "model.a" and workload profile "b"
        // are shown; "model.b", "model.removed", and "broken.opt_in" are omitted.
        let allowed_models: BTreeSet<String> = ["a".to_owned()].into_iter().collect();
        let (filtered, _) = project_user_capacity(
            &user,
            &platform,
            Some(&cat),
            &allowed_models,
            &profiles,
            &groups,
        )
        .unwrap();
        assert_eq!(
            filtered,
            json!({
                "profiles": [
                    { "profile": "model.a", "availability": "ready", "estimated_wait_seconds": null },
                    { "profile": "b", "availability": "ready", "estimated_wait_seconds": null }
                ]
            })
        );
    }

    #[test]
    fn projections_fail_closed_when_cardinality_ceilings_are_exceeded() {
        let user = active_user();
        let platform = PlatformPolicy::default();
        let groups = vec![ObservedGroup {
            group_id: GROUP_A.into(),
            controller_epoch: 1,
            admits_bursts: true,
            observation_stale: false,
            observation_revision: 1,
            observed_at_us: Some(1_795_000_000_000_000),
            devices: vec![device(DEV_0, 24 * GIB, 7 * GIB, 7 * GIB, 0)],
        }];
        let too_many_profiles: Vec<ProfileConfig> = (0..=MAX_CAPACITY_PROFILES)
            .map(|i| ProfileConfig {
                profile: format!("p-{i:03}"),
                group_id: GROUP_A.into(),
                per_device_bytes: GIB,
                required_devices: 1,
                required_capability: None,
                capability_gate: CapabilityGate::OnByDefault,
                model_id: None,
            })
            .collect();
        assert_eq!(
            project_user_capacity(
                &user,
                &platform,
                None,
                &BTreeSet::new(),
                &too_many_profiles,
                &groups,
            )
            .unwrap_err(),
            UNAVAILABLE
        );

        let too_many_groups: Vec<ObservedGroup> = (0..=MAX_CAPACITY_GROUPS)
            .map(|i| ObservedGroup {
                group_id: format!("00000000-0000-4000-8000-{i:012x}"),
                controller_epoch: 1,
                admits_bursts: false,
                observation_stale: false,
                observation_revision: 0,
                observed_at_us: None,
                devices: Vec::new(),
            })
            .collect();
        assert_eq!(
            project_admin_groups(&too_many_groups).unwrap_err(),
            UNAVAILABLE
        );

        let too_many_devices = vec![ObservedGroup {
            group_id: GROUP_A.into(),
            controller_epoch: 1,
            admits_bursts: true,
            observation_stale: false,
            observation_revision: 1,
            observed_at_us: Some(1_795_000_000_000_000),
            devices: (0..=MAX_CAPACITY_DEVICES_PER_GROUP)
                .map(|i| {
                    device(
                        &format!("00000000-0000-4000-8000-{i:012x}"),
                        24 * GIB,
                        7 * GIB,
                        7 * GIB,
                        0,
                    )
                })
                .collect(),
        }];
        assert_eq!(
            project_admin_groups(&too_many_devices).unwrap_err(),
            UNAVAILABLE
        );
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
