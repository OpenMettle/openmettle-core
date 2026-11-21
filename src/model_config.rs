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
#[serde(default, deny_unknown_fields)]
pub struct Controls {
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub reasoning_effort: Option<String>,
    pub context_window: Option<u64>,
    pub output_reserve: Option<u64>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Layer {
    pub controls: Controls,
    pub instructions: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
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

fn name(s: &str) -> bool {
    crate::runs::bounded(s, 256) && !s.chars().any(char::is_control)
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
        let doc: CatalogDocument =
            serde_json::from_slice(bytes).map_err(|_| Error::Invalid("catalog"))?;
        if doc.version != 1 || !name(&doc.revision) {
            return Err(Error::Invalid("catalog revision"));
        }
        for (id, p) in &doc.models {
            if !name(id)
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
            if !name(id) || !name(&preset.revision) {
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
        let inherited_model = if let Some(p) = &project.preset {
            Some(
                &self
                    .preset(p)
                    .ok_or(Error::Invalid("project preset"))?
                    .model,
            )
        } else {
            project.model.as_ref()
        };
        if let (Some(id), Some(p)) = (&request.model, request.preset.as_ref().and(preset))
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
        let switched = inherited_model.is_some_and(|id| id != model_id)
            && (request.model.is_some() || request.preset.is_some());
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
            ceiling: Field::from_model(p.context_window.or(p.conservative_ceiling)),
            output_reserve: Field::default(),
            instructions: Vec::new(),
            omissions: Vec::new(),
            temperature: Field::default(),
            top_p: Field::default(),
            reasoning_effort: Field::default(),
        };
        for (source, layer) in [
            (Source::Model, Some(&p.defaults)),
            (Source::Preset, preset.map(|p| &p.defaults)),
            (Source::Project, Some(&project.layer)),
            (Source::Request, Some(&request.layer)),
        ] {
            if let Some(layer) = layer {
                let drop_unsupported = switched
                    && (source == Source::Project
                        || (source == Source::Preset
                            && preset.is_some_and(|s| s.model != *model_id)));
                e.apply(p, layer, source, drop_unsupported)?;
            }
        }
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
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Selection {
    pub model: Option<String>,
    pub preset: Option<String>,
    pub layer: Layer,
}

impl Selection {
    /// Load only the typed model_config object. Instructions have their own project column.
    pub fn project(settings: &crate::authz::projects::ProjectSettings) -> Result<Self, Error> {
        #[derive(Default, Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct Defaults {
            model: Option<String>,
            preset: Option<String>,
            controls: Controls,
        }
        let typed: Defaults = settings
            .defaults
            .get("model_config")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .map_err(|_| Error::Invalid("project model_config"))?
            .unwrap_or_default();
        Ok(Self {
            model: typed.model,
            preset: typed.preset,
            layer: Layer {
                controls: typed.controls,
                instructions: (!settings.instructions.is_empty())
                    .then(|| settings.instructions.clone()),
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
    fn apply(
        &mut self,
        p: &Profile,
        layer: &Layer,
        source: Source,
        drop_unsupported: bool,
    ) -> Result<(), Error> {
        if let Some(text) = &layer.instructions {
            if text.contains('\0') {
                return Err(Error::Invalid("instructions"));
            }
            self.instructions.push(Instruction {
                source,
                text: text.clone(),
            });
        }
        let c = &layer.controls;
        for (control, value, range, field) in [
            (
                "temperature",
                c.temperature,
                p.temperature,
                &mut self.temperature,
            ),
            ("top_p", c.top_p, p.top_p, &mut self.top_p),
        ] {
            if let Some(value) = value
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
        if let Some(effort) = &c.reasoning_effort {
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
        if let Some(window) = c.context_window
            && let Some(limit) = supported(
                self.ceiling.value,
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
        if let Some(reserve) = c.output_reserve
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
}

pub const SNAPSHOT_FORMAT: &str = "openmettle.conversation";
pub const SNAPSHOT_VERSION: i32 = 1;
#[derive(Serialize, Deserialize)]
pub struct ConfigSnapshot {
    pub effective: Effective,
    pub required_capabilities: BTreeMap<String, crate::authz::CapabilityGate>,
    pub policy_revision: String,
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
