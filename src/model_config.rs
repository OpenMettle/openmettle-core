//! Versioned server-controlled catalog, deterministic configuration and admission budget (ADR 0036).
//! The catalog contains qualification data. Its IDs do not grant permission or imply readiness.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid(&'static str),
    Unauthorized,
    Provisioning,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProfilePin {
    pub provider: String,
    pub revision: String,
    pub checkpoint: String,
    pub template: String,
    pub parser: String,
    pub runtime: String,
    pub gateway: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySource {
    pub profile: ProfilePin,
    pub format: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRule {
    pub source: ReplaySource,
    pub max_tokens_per_byte: u32,
    pub fixed_tokens: u32,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Range {
    pub min: f64,
    pub max: f64,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
#[serde(default, deny_unknown_fields)]
pub struct Controls {
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub reasoning_effort: Option<String>,
    pub context_window: Option<u64>,
    pub output_reserve: Option<u64>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
#[serde(default, deny_unknown_fields)]
pub struct Layer {
    pub controls: Controls,
    pub instructions: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromptBound {
    pub fixed_tokens: u32,
    pub tokens_per_turn: u32,
    pub tokens_per_part: u32,
    pub tokens_per_byte: u32,
    pub tokens_per_attachment: Option<u32>,
}

/// Qualified per-round upper-bound pricing in configured cost-denomination micro-units (ADR 0040).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CostBound {
    #[serde(default)]
    pub fixed_micros: u64,
    pub micros_per_token: u64,
}

impl CostBound {
    /// Qualified upper-bound cost in micro-units for one round of up to `round_tokens` tokens,
    /// computed in `u128` so token-only installations without cost limits never reject valid large
    /// `cost_bound` profiles; callers enforce `i64::MAX` bounds only when a cost tier applies.
    pub fn round_ceiling(self, round_tokens: u64) -> Result<u128, Error> {
        if self.fixed_micros > i64::MAX as u64
            || self.micros_per_token > i64::MAX as u64
            || (self.fixed_micros == 0 && self.micros_per_token == 0)
        {
            return Err(Error::Invalid("cost budget"));
        }
        u128::from(round_tokens)
            .checked_mul(u128::from(self.micros_per_token))
            .and_then(|v| v.checked_add(u128::from(self.fixed_micros)))
            .filter(|&n| n > 0)
            .ok_or(Error::Invalid("cost budget"))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Deployment-qualified upper bounds for this exact profile and estimator revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_bound: Option<PromptBound>,
    /// Deployment-qualified per-round cost bound when `usage_cost_micros` metering is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_bound: Option<CostBound>,
    /// True when executing this profile requires reserving a concurrent `device_reservations` slot.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub requires_device_slot: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub required_capabilities: BTreeMap<String, crate::authz::CapabilityGate>,
    pub pin: ProfilePin,
    pub defaults: Layer,
    pub context_window: Option<u64>,
    pub conservative_ceiling: Option<u64>,
    pub output_limit: Option<u64>,
    pub temperature: Option<Range>,
    pub top_p: Option<Range>,
    pub joint_sampling: bool,
    pub efforts: BTreeSet<String>,
    pub default_effort: Option<String>,
    pub usage_semantics: String,
    pub estimator_revision: Option<String>,
    pub reasoning_format: Option<String>,
    pub replay: Vec<ReplayRule>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Preset {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub required_capabilities: BTreeMap<String, crate::authz::CapabilityGate>,
    pub revision: String,
    pub model: String,
    pub defaults: Layer,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CatalogDocument {
    version: u32,
    revision: String,
    models: BTreeMap<String, Profile>,
    presets: BTreeMap<String, Preset>,
}

pub struct Catalog(CatalogDocument);

pub(crate) fn name(s: &str) -> bool {
    crate::runs::bounded(s, 256) && !s.chars().any(char::is_control)
}

/// Convert canonical wire counts for typed decoding. Older project documents store integers.
pub(crate) fn decode_control_counts(
    controls: &mut serde_json::Map<String, serde_json::Value>,
    project_defaults: bool,
) -> Result<(), Error> {
    for key in ["context_window", "output_reserve"] {
        let Some(v) = controls.get_mut(key) else {
            continue;
        };
        if v.is_null() || (project_defaults && v.is_u64()) {
            continue;
        }
        let s = v.as_str().ok_or(Error::Invalid("control count"))?;
        let n = s
            .parse::<i64>()
            .ok()
            .filter(|n| *n >= 0 && n.to_string() == s)
            .ok_or(Error::Invalid("control count"))?;
        *v = n.into();
    }
    Ok(())
}

impl ProfilePin {
    fn valid(&self) -> bool {
        [
            &self.provider,
            &self.revision,
            &self.checkpoint,
            &self.template,
            &self.parser,
            &self.runtime,
            &self.gateway,
        ]
        .into_iter()
        .all(|s| name(s))
    }
}

impl Catalog {
    pub fn load(bytes: &[u8]) -> Result<Self, Error> {
        // Maps keep the last of two equal keys, so refuse repeats before typed decoding.
        let doc: CatalogDocument = crate::provider_keys::documents::unique(bytes)
            .and_then(serde_json::from_value)
            .map_err(|_| Error::Invalid("catalog"))?;
        if doc.version != 1 || !name(&doc.revision) {
            return Err(Error::Invalid("catalog revision"));
        }
        for (id, p) in &doc.models {
            if !name(id)
                || p.required_capabilities
                    .keys()
                    .any(|k| !crate::authz::valid_capability(k))
                || p.prompt_bound
                    .as_ref()
                    .is_some_and(|b| b.tokens_per_byte == 0 || p.estimator_revision.is_none())
                || p.cost_bound.is_some_and(|c| {
                    c.fixed_micros > i64::MAX as u64
                        || c.micros_per_token > i64::MAX as u64
                        || (c.fixed_micros == 0 && c.micros_per_token == 0)
                })
                || [p.context_window, p.output_limit, p.conservative_ceiling]
                    .into_iter()
                    .flatten()
                    .any(|n| n > i64::MAX as u64)
                || !p.pin.valid()
                || !name(&p.usage_semantics)
                || [p.context_window, p.output_limit, p.conservative_ceiling].contains(&Some(0))
                || p.estimator_revision.as_ref().is_some_and(|s| !name(s))
                || p.reasoning_format.as_ref().is_some_and(|s| !name(s))
                || p.efforts.iter().any(|s| !name(s) || s == "default")
                || p.default_effort
                    .as_ref()
                    .is_some_and(|s| !p.efforts.contains(s))
                || [p.temperature, p.top_p]
                    .into_iter()
                    .flatten()
                    .any(|r| !r.min.is_finite() || !r.max.is_finite() || r.min > r.max)
                || p.replay.iter().enumerate().any(|(i, r)| {
                    !r.source.profile.valid()
                        || !name(&r.source.format)
                        || r.max_tokens_per_byte == 0
                        || p.replay[..i].iter().any(|other| other.source == r.source)
                })
            {
                return Err(Error::Invalid("profile"));
            }
        }
        let catalog = Self(doc);
        let empty = Selection::default();
        for id in catalog.0.models.keys() {
            catalog.resolve(
                &empty,
                &Selection {
                    model: Some(id.clone()),
                    ..Default::default()
                },
                None,
                |_, _| true,
            )?;
        }
        for (id, preset) in &catalog.0.presets {
            if !name(id)
                || !name(&preset.revision)
                || preset
                    .required_capabilities
                    .keys()
                    .any(|k| !crate::authz::valid_capability(k))
            {
                return Err(Error::Invalid("preset"));
            }
            catalog.resolve(
                &empty,
                &Selection {
                    preset: Some(id.clone()),
                    ..Default::default()
                },
                None,
                |_, _| true,
            )?;
        }
        Ok(catalog)
    }

    pub(crate) fn revision(&self) -> &str {
        &self.0.revision
    }

    pub(crate) fn models(&self) -> &BTreeMap<String, Profile> {
        &self.0.models
    }

    pub(crate) fn presets(&self) -> &BTreeMap<String, Preset> {
        &self.0.presets
    }

    /// Deterministically encode a validated document for storage and subsequent reload.
    pub fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.0).expect("validated catalog")
    }

    pub fn model(&self, id: &str) -> Option<&Profile> {
        self.0.models.get(id)
    }
    pub fn preset(&self, id: &str) -> Option<&Preset> {
        self.0.presets.get(id)
    }

    /// Resolve model → preset → project → request. The caller supplies authorization for the
    /// selected model and preset from current policy. A selection never grants capabilities.
    pub fn resolve(
        &self,
        project: &Selection,
        request: &Selection,
        project_revision: Option<i64>,
        authorized: impl FnOnce(&str, Option<&str>) -> bool,
    ) -> Result<Effective, Error> {
        let preset_id = request.preset.as_ref().or(project.preset.as_ref());
        let preset = preset_id
            .map(|id| self.preset(id).ok_or(Error::Invalid("preset")))
            .transpose()?;
        // Only the model paired with the selected preset must match its base. A request
        // can switch the target model while inheriting a project's preset defaults.
        let paired_model = if request.preset.is_some() {
            request.model.as_ref()
        } else {
            project.model.as_ref()
        };
        if let (Some(id), Some(p)) = (paired_model, preset)
            && id != &p.model
        {
            return Err(Error::Invalid("preset base model"));
        }
        let model_id = request
            .model
            .as_ref()
            .or(preset.map(|p| &p.model))
            .or(project.model.as_ref())
            .ok_or(Error::Invalid("model selection"))?;
        if !authorized(model_id, preset_id.map(String::as_str)) {
            return Err(Error::Unauthorized);
        }
        let p = self.model(model_id).ok_or(Error::Invalid("model"))?;
        let inherited_model = match &project.preset {
            Some(id) => self.preset(id).map(|p| &p.model),
            None => project.model.as_ref(),
        };
        let switched = (request.model.is_some() || request.preset.is_some())
            && inherited_model.is_none_or(|id| id != model_id);
        let mut e = Effective {
            catalog_revision: self.0.revision.clone(),
            model: model_id.clone(),
            profile: p.pin.clone(),
            model_source: if request.model.is_some() {
                Source::Request
            } else if preset.is_some() {
                Source::Preset
            } else {
                Source::Project
            },
            preset_source: preset.map(|_| {
                if request.preset.is_some() {
                    Source::Request
                } else {
                    Source::Project
                }
            }),
            preset: preset_id.cloned(),
            preset_revision: preset.map(|p| p.revision.clone()),
            project_revision,
            reasoning_format: p.reasoning_format.clone(),
            context_window: Field::from_model(p.context_window),
            ceiling: Field::default(),
            output_reserve: Field::default(),
            instructions: Vec::new(),
            omissions: Vec::new(),
            temperature: Field::default(),
            top_p: Field::default(),
            reasoning_effort: Field::default(),
        };
        let layers = [
            (Source::Model, Some(&p.defaults)),
            (Source::Preset, preset.map(|p| &p.defaults)),
            (Source::Project, Some(&project.layer)),
            (Source::Request, Some(&request.layer)),
        ]
        .into_iter()
        .filter_map(|(source, layer)| Some((source, layer?)));
        for (source, layer) in layers.clone() {
            if let Some(text) = &layer.instructions {
                if text.contains('\0') {
                    return Err(Error::Invalid("instructions"));
                }
                e.instructions.push(Instruction {
                    source,
                    text: text.clone(),
                });
            }
        }
        for (source, layer) in layers.rev() {
            let drop_unsupported = switched
                && (source == Source::Project
                    || (source == Source::Preset && preset.is_some_and(|s| s.model != *model_id)));
            e.apply_controls(p, &layer.controls, source, drop_unsupported)?;
        }
        if e.ceiling.value.is_none() {
            e.ceiling = Field::from_model(p.context_window.or(p.conservative_ceiling));
        }
        // Snapshots list preset omissions before project omissions, in control order within each.
        e.omissions.sort_by_key(|o| o.source == Source::Project);
        if !p.joint_sampling && e.temperature.value.is_some() && e.top_p.value.is_some() {
            return Err(Error::Invalid("sampling combination"));
        }
        if let (Some(c), Some(r)) = (e.ceiling.value, e.output_reserve.value)
            && r > c
        {
            return Err(Error::Invalid("output reserve exceeds ceiling"));
        }
        Ok(e)
    }

    /// Resolve model → preset → project → request for run admission and preview, falling back
    /// to the first deterministic permitted catalog model when the request omits both `model` and
    /// `preset` and no project default is set or the project default is unauthorized (for example
    /// during active study hours). An explicit request `model` or `preset` never falls back.
    pub fn resolve_with_fallback(
        &self,
        project: &Selection,
        request: &Selection,
        project_revision: Option<i64>,
        mut authorized: impl FnMut(&str, Option<&str>) -> bool,
    ) -> Result<Effective, Error> {
        if request.model.is_some() || request.preset.is_some() {
            return self.resolve(project, request, project_revision, |m, p| authorized(m, p));
        }
        if project.model.is_some() || project.preset.is_some() {
            match self.resolve(project, request, project_revision, |m, p| authorized(m, p)) {
                Ok(effective) => return Ok(effective),
                Err(Error::Unauthorized) => {}
                Err(error) => return Err(error),
            }
        } else if self.0.models.is_empty() {
            return Err(Error::Invalid("model selection"));
        }
        let Some(fallback) = self
            .0
            .models
            .keys()
            .find(|id| authorized(id, None))
            .cloned()
        else {
            return Err(Error::Unauthorized);
        };
        let fallback_project = Selection {
            model: None,
            preset: None,
            layer: project.layer.clone(),
        };
        let fallback_request = Selection {
            model: Some(fallback),
            preset: None,
            layer: request.layer.clone(),
        };
        let mut effective = self.resolve(
            &fallback_project,
            &fallback_request,
            project_revision,
            |m, p| authorized(m, p),
        )?;
        effective.model_source = Source::Model;
        Ok(effective)
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq))]
#[serde(default, deny_unknown_fields)]
pub struct Selection {
    pub model: Option<String>,
    pub preset: Option<String>,
    pub layer: Layer,
}

impl Selection {
    /// Load only the typed model_config object. Instructions have their own project column.
    pub fn project(settings: &crate::authz::projects::ProjectSettings) -> Result<Self, Error> {
        Self::from_defaults(&settings.defaults, &settings.instructions)
    }

    pub(crate) fn from_defaults(
        defaults: &serde_json::Value,
        instructions: &str,
    ) -> Result<Self, Error> {
        #[derive(Default, Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct Defaults {
            model: Option<String>,
            preset: Option<String>,
            controls: Controls,
        }
        let mut typed = defaults.get("model_config").cloned();
        if let Some(v) = typed.as_mut() {
            let fields = v
                .as_object_mut()
                .ok_or(Error::Invalid("project model_config"))?;
            if let Some(controls) = fields.get_mut("controls") {
                decode_control_counts(
                    controls
                        .as_object_mut()
                        .ok_or(Error::Invalid("project model_config"))?,
                    true,
                )?;
            }
        }
        let typed: Defaults = typed
            .map(serde_json::from_value)
            .transpose()
            .map_err(|_| Error::Invalid("project model_config"))?
            .unwrap_or_default();
        if [
            &typed.model,
            &typed.preset,
            &typed.controls.reasoning_effort,
        ]
        .into_iter()
        .flatten()
        .any(|id| !name(id))
            || [typed.controls.context_window, typed.controls.output_reserve]
                .into_iter()
                .flatten()
                .any(|value| !(1..=i64::MAX as u64).contains(&value))
        {
            return Err(Error::Invalid("project model_config"));
        }
        Ok(Self {
            model: typed.model,
            preset: typed.preset,
            layer: Layer {
                controls: typed.controls,
                instructions: (!instructions.is_empty()).then(|| instructions.to_owned()),
            },
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Model,
    Preset,
    Project,
    Request,
    #[default]
    GatewayDefault,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Field<T> {
    pub value: Option<T>,
    pub source: Source,
}

impl<T> Field<T> {
    fn from_model(value: Option<T>) -> Self {
        Self {
            value,
            source: Source::Model,
        }
    }
    fn set(&mut self, value: T, source: Source) {
        self.value = Some(value);
        self.source = source;
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub source: Source,
    pub text: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Omission {
    pub source: Source,
    pub control: String,
    pub reason: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Effective {
    pub catalog_revision: String,
    pub model: String,
    pub model_source: Source,
    pub profile: ProfilePin,
    pub preset: Option<String>,
    pub preset_source: Option<Source>,
    pub preset_revision: Option<String>,
    pub project_revision: Option<i64>,
    pub reasoning_format: Option<String>,
    pub instructions: Vec<Instruction>,
    pub omissions: Vec<Omission>,
    pub temperature: Field<f64>,
    pub top_p: Field<f64>,
    pub reasoning_effort: Field<String>,
    pub context_window: Field<u64>,
    pub ceiling: Field<u64>,
    pub output_reserve: Field<u64>,
}

fn supported<T>(
    declaration: Option<T>,
    drop_unsupported: bool,
    control: &'static str,
    source: Source,
    omissions: &mut Vec<Omission>,
) -> Result<Option<T>, Error> {
    if declaration.is_none() {
        if !drop_unsupported {
            return Err(Error::Invalid(control));
        }
        omissions.push(Omission {
            source,
            control: control.into(),
            reason: "unsupported_by_target".into(),
        });
    }
    Ok(declaration)
}

impl Effective {
    fn apply_controls(
        &mut self,
        p: &Profile,
        c: &Controls,
        source: Source,
        drop_unsupported: bool,
    ) -> Result<(), Error> {
        for (control, value, range, field) in [
            (
                "temperature",
                c.temperature,
                p.temperature,
                &mut self.temperature,
            ),
            ("top_p", c.top_p, p.top_p, &mut self.top_p),
        ] {
            if field.value.is_none()
                && let Some(value) = value
                && let Some(r) = supported(
                    range,
                    drop_unsupported,
                    control,
                    source,
                    &mut self.omissions,
                )?
            {
                if !value.is_finite() || value < r.min || value > r.max {
                    return Err(Error::Invalid(control));
                }
                field.set(value, source);
            }
        }
        if self.reasoning_effort.value.is_none()
            && let Some(effort) = &c.reasoning_effort
        {
            let level = if effort == "default" {
                p.default_effort.as_ref()
            } else {
                Some(effort)
            };
            if let Some(level) = supported(
                level.filter(|s| p.efforts.contains(*s)),
                drop_unsupported,
                "reasoning_effort",
                source,
                &mut self.omissions,
            )? {
                self.reasoning_effort.set(level.clone(), source);
            }
        }
        if self.ceiling.value.is_none()
            && let Some(window) = c.context_window
            && let Some(limit) = supported(
                p.context_window.or(p.conservative_ceiling),
                drop_unsupported,
                "context_window",
                source,
                &mut self.omissions,
            )?
        {
            if window == 0 || window > limit {
                return Err(Error::Invalid("context_window"));
            }
            self.ceiling.set(window, source);
            if p.context_window.is_some() {
                self.context_window.set(window, source);
            }
        }
        if self.output_reserve.value.is_none()
            && let Some(reserve) = c.output_reserve
            && let Some(limit) = supported(
                p.output_limit,
                drop_unsupported,
                "output_reserve",
                source,
                &mut self.omissions,
            )?
        {
            if reserve == 0 || reserve > limit {
                return Err(Error::Invalid("output_reserve"));
            }
            self.output_reserve.set(reserve, source);
        }
        Ok(())
    }

    /// Subtract the sourced output reserve from the effective total ceiling.
    pub fn usable_input(&self) -> Option<u64> {
        self.ceiling.value?.checked_sub(self.output_reserve.value?)
    }
}

/// Exact, versioned provenance of the blocks a target can encode on a later call.
impl Profile {
    pub fn replay_blocks<'a>(
        &self,
        source: Option<&ReplaySource>,
        blocks: Option<&'a [serde_json::Map<String, serde_json::Value>]>,
    ) -> Option<&'a [serde_json::Map<String, serde_json::Value>]> {
        self.replay_rule(source).and(blocks)
    }

    pub fn replay_rule(&self, source: Option<&ReplaySource>) -> Option<&ReplayRule> {
        let source = source?;
        self.qualified_for(&source.profile, &source.format)
    }

    fn qualified_for(&self, profile: &ProfilePin, format: &str) -> Option<&ReplayRule> {
        self.replay
            .iter()
            .find(|rule| &rule.source.profile == profile && rule.source.format == format)
    }

    /// Qualified upper-bound cost in micro-units for one round of up to `round_tokens` tokens,
    /// or `Ok(None)` when this profile carries no qualified `cost_bound`. Computed in `u128` so
    /// token-only installations without cost limits never reject valid large `cost_bound` profiles;
    /// callers enforce `i64::MAX` bounds only when a cost tier applies.
    pub fn round_cost_ceiling(&self, round_tokens: u64) -> Result<Option<u128>, Error> {
        self.cost_bound
            .map(|cb| cb.round_ceiling(round_tokens))
            .transpose()
    }
}

pub const SNAPSHOT_FORMAT: &str = "openmettle.conversation";
pub const SNAPSHOT_VERSION: i32 = 1;
#[derive(Serialize, Deserialize)]
pub struct ConfigSnapshot {
    pub effective: Effective,
    pub required_capabilities: BTreeMap<String, crate::authz::CapabilityGate>,
    pub policy_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_bound: Option<CostBound>,
}

#[derive(Clone)]
pub struct PathTurn {
    pub message_id: String,
    pub run_id: Option<String>,
    pub profile: Option<ProfilePin>,
    pub reasoning_format: Option<String>,
    pub reasoning_bytes: u32,
    pub input_count: Option<u64>,
    pub output_count: Option<u64>,
}

impl PathTurn {
    pub(crate) fn replay_rule<'a>(&self, target: &'a Profile) -> Option<&'a ReplayRule> {
        target.qualified_for(self.profile.as_ref()?, self.reasoning_format.as_deref()?)
    }
}

/// Qualified estimate of the assembled prompt before adding structured replay. Each component
/// includes its template framing. An unavailable component leaves the overall estimate unknown.
pub struct PromptEstimate<'a> {
    pub profile: &'a ProfilePin,
    pub revision: &'a str,
    pub instructions: Option<u64>,
    pub history: Option<u64>,
    pub proposed_input: Option<u64>,
    pub tools: Option<u64>,
    pub attachments: Option<u64>,
}

pub struct Estimate {
    pub revision: String,
    pub upper_bound: u64,
}
pub struct Budget<'a> {
    pub measured: Option<&'a PathTurn>,
    pub estimated: Option<Estimate>,
    pub usable_input: Option<u64>,
}

impl Budget<'_> {
    pub fn admit(&self) -> Result<(), Error> {
        let limit = self.usable_input.ok_or(Error::Provisioning)?;
        let estimate = self.estimated.as_ref().ok_or(Error::Provisioning)?;
        if estimate.upper_bound > limit {
            return Err(Error::Invalid("context budget"));
        }
        Ok(())
    }
}

impl Catalog {
    pub(crate) fn target(&self, e: &Effective) -> Result<&Profile, Error> {
        self.model(&e.model)
            .filter(|p| p.pin == e.profile && self.0.revision == e.catalog_revision)
            .ok_or(Error::Provisioning)
    }

    /// Qualified per-round cost ceiling in micro-units for the resolved effective configuration,
    /// shared by `/v1/runs` admission and worker round dispatch (`gateway::reserve_turn_round`).
    pub fn round_cost_ceiling(&self, e: &Effective) -> Result<Option<u128>, Error> {
        let target = self.target(e)?;
        let round_tokens = e.ceiling.value.ok_or(Error::Provisioning)?;
        target.round_cost_ceiling(round_tokens)
    }

    /// The path is ordered head first and contains no siblings. Only a qualified estimator for
    /// this target can establish a bound. Historical usage never establishes capacity or cost.
    pub fn budget<'a>(
        &self,
        e: &Effective,
        path: &'a [PathTurn],
        prompt: Option<&PromptEstimate<'_>>,
    ) -> Result<Budget<'a>, Error> {
        let target = self.target(e)?;
        let measured = path
            .iter()
            .find(|t| t.run_id.is_some() && (t.input_count.is_some() || t.output_count.is_some()));
        let estimated = prompt.and_then(|p| {
            if *p.profile != target.pin || Some(p.revision) != target.estimator_revision.as_deref()
            {
                return None;
            }
            let mut count = [
                p.instructions,
                p.history,
                p.proposed_input,
                p.tools,
                p.attachments,
            ]
            .into_iter()
            .try_fold(0u64, |sum, x| sum.checked_add(x?))?;
            for turn in path.iter().filter(|t| t.reasoning_bytes > 0) {
                if let Some(rule) = turn.replay_rule(target) {
                    let cost =
                        u64::from(turn.reasoning_bytes) * u64::from(rule.max_tokens_per_byte);
                    count = count
                        .checked_add(cost)?
                        .checked_add(u64::from(rule.fixed_tokens))?;
                }
            }
            Some(Estimate {
                revision: p.revision.into(),
                upper_bound: count,
            })
        });
        Ok(Budget {
            measured,
            estimated,
            usable_input: e.usable_input(),
        })
    }
}
