use super::{conversations::decimal, pagination::Page, *};
use crate::{
    authz::{CapabilityGate, PlatformPolicy, authorize_capability},
    model_config::{Catalog, Error, Preset, Profile, Selection},
};
use std::collections::BTreeMap;

pub(super) async fn check_project_defaults(
    c: &mut PgConnection,
    actor: &Principal,
    catalog: Option<&Catalog>,
    selection: &Selection,
) -> Result<(), StoreError> {
    if selection.model.is_none() && selection.preset.is_none() {
        return Ok(());
    }
    let catalog = catalog.ok_or(StoreError::InvalidInput("project model_config"))?;
    let policy = store::load_platform_capabilities(c).await?;
    catalog
        .resolve(selection, &Selection::default(), None, |model, preset| {
            allowed(catalog, actor, &policy, model, preset)
        })
        .map(drop)
        .map_err(|e| match e {
            Error::Unauthorized => StoreError::Denied(authz::DenialReason::Policy(
                authz::PolicyReason::CapabilityDenied,
            )),
            Error::Invalid(reason) => StoreError::InvalidInput(reason),
            Error::Provisioning => StoreError::InvalidInput("project model_config"),
        })
}

pub(super) fn allowed(
    catalog: &Catalog,
    actor: &Principal,
    policy: &PlatformPolicy,
    model: &str,
    preset: Option<&str>,
) -> bool {
    let check = |(name, gate): (&String, &CapabilityGate)| {
        authorize_capability(actor, policy, name, *gate).is_allowed()
    };
    catalog
        .model(model)
        .is_none_or(|p| p.required_capabilities.iter().all(check))
        && preset.and_then(|id| catalog.preset(id)).is_none_or(|p| {
            p.required_capabilities.iter().all(check)
                && catalog
                    .model(&p.model)
                    .is_some_and(|m| m.required_capabilities.iter().all(check))
        })
}

/// A preset cannot relax an opt-in capability on either its base or the selected target.
pub(super) fn capabilities(
    catalog: &Catalog,
    model: &str,
    preset: Option<&str>,
) -> Result<BTreeMap<String, CapabilityGate>, Problem> {
    let mut gates = catalog
        .model(model)
        .ok_or(INVALID)?
        .required_capabilities
        .clone();
    if let Some(p) = preset.and_then(|id| catalog.preset(id)) {
        for (k, v) in catalog
            .model(&p.model)
            .ok_or(INVALID)?
            .required_capabilities
            .iter()
            .chain(&p.required_capabilities)
        {
            if *v == CapabilityGate::OptIn || !gates.contains_key(k) {
                gates.insert(k.clone(), *v);
            }
        }
    }
    Ok(gates)
}

fn defaults(layer: &crate::model_config::Layer) -> Value {
    let c = &layer.controls;
    json!({
        "instructions": layer.instructions,
        "controls": {
            "temperature": c.temperature, "top_p": c.top_p, "reasoning_effort": c.reasoning_effort,
            "context_window": decimal(c.context_window), "output_reserve": decimal(c.output_reserve),
        }
    })
}

fn model(id: &str, p: &Profile) -> Value {
    json!({
        "model_id": id, "profile": p.pin, "installed": true, "authorization": true,
        "readiness": { "state": "unknown" }, "defaults": defaults(&p.defaults),
        "context_window": decimal(p.context_window), "conservative_ceiling": decimal(p.conservative_ceiling),
        "output_limit": decimal(p.output_limit), "temperature": p.temperature, "top_p": p.top_p,
        "joint_sampling": p.joint_sampling, "reasoning_efforts": p.efforts, "default_effort": p.default_effort,
        "usage_semantics": p.usage_semantics, "estimator_revision": p.estimator_revision,
        "reasoning_format": p.reasoning_format
    })
}

fn preset(id: &str, p: &Preset) -> Value {
    json!({
        "preset_id": id, "model_id": p.model, "revision": p.revision, "installed": true,
        "authorization": true, "readiness": { "state": "unknown" }, "defaults": defaults(&p.defaults)
    })
}

pub(super) async fn describe(
    c: &mut PgConnection,
    actor: &Principal,
    op: Op,
    id: Option<&str>,
    catalog: Option<&Catalog>,
    page: Option<&Page<'_>>,
) -> Result<Response, Problem> {
    let policy = store::load_platform_capabilities(c).await?;
    if let Some(id) = id {
        let catalog = catalog.ok_or(NOT_FOUND)?;
        let p = catalog
            .preset(id)
            .filter(|p| allowed(catalog, actor, &policy, &p.model, Some(id)))
            .ok_or(NOT_FOUND)?;
        return Ok(reply(StatusCode::OK, preset(id, p)));
    }
    let page = page.ok_or(INTERNAL)?;
    let revision = catalog.map_or("", Catalog::revision);
    let start = page.position::<usize>(revision)?.unwrap_or(0);
    let mut items = Vec::new();
    let mut next = None;
    if let Some(catalog) = catalog {
        // Position is in the pinned sorted catalog, before authorization filtering.
        let mut push = |i: usize, v: Value| {
            if items.len() == page.limit {
                next = Some(i);
                false
            } else {
                items.push(v);
                true
            }
        };
        if op == Op::ListModels {
            for (i, (id, p)) in catalog.models().iter().enumerate().skip(start) {
                if allowed(catalog, actor, &policy, id, None) && !push(i, model(id, p)) {
                    break;
                }
            }
        } else {
            for (i, (id, p)) in catalog.presets().iter().enumerate().skip(start) {
                if allowed(catalog, actor, &policy, &p.model, Some(id)) && !push(i, preset(id, p)) {
                    break;
                }
            }
        }
    }
    page.finish(items, revision, next)
}
