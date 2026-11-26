//! The graph and durable run share one bounded write transaction.
use super::{catalog, conversations::decimal, *};
use crate::{
    authz::{
        branches::{
            self, Conversation, History, Operation, Part, PartContent, UserInput,
            snapshot::{Intent, Snapshots},
        },
        runs::{self as queue, Admission, AdmissionLimits, RunLimit},
    },
    model_config::{
        Budget, Catalog, ConfigSnapshot, Effective, Field, PathTurn, PromptEstimate,
        SNAPSHOT_FORMAT, SNAPSHOT_VERSION, Selection,
    },
    runs::{RunInput, WriteTransaction},
};
use serde::{Deserializer, Serialize};

#[derive(Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
enum Turn {
    Append {
        input_message_id: String,
        parts: Vec<Part>,
    },
    Edit {
        target_message_id: String,
        input_message_id: String,
        parts: Vec<Part>,
    },
    Retry {
        target_message_id: String,
    },
}

fn required_nullable<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::deserialize(d)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Proposal {
    #[serde(deserialize_with = "required_nullable")]
    expected_head_message_id: Option<String>,
    turn: Turn,
    #[serde(default)]
    selection: Selection,
    requested_rounds: Option<i64>,
}
impl Proposal {
    pub(super) fn read(body: &[u8]) -> Result<Self, Problem> {
        let proposal: Self = wire_proposal(body, false)?;
        proposal.validate()?;
        Ok(proposal)
    }

    fn operation(&self) -> Operation<'_> {
        match &self.turn {
            Turn::Append {
                input_message_id,
                parts,
            } => Operation::Append(UserInput {
                id: input_message_id,
                parts,
            }),
            Turn::Edit {
                target_message_id,
                input_message_id,
                parts,
            } => Operation::Edit {
                target: target_message_id,
                replacement: UserInput {
                    id: input_message_id,
                    parts,
                },
            },
            Turn::Retry { target_message_id } => Operation::Retry {
                target: target_message_id,
            },
        }
    }
    fn validate(&self) -> Result<(), Problem> {
        let check = |s: &str| crate::runs::uuid(s).map_err(|_| INVALID);
        if let Some(head) = &self.expected_head_message_id {
            check(head)?
        }
        if self
            .requested_rounds
            .is_some_and(|n| !(1..=i64::from(i32::MAX)).contains(&n))
        {
            return Err(INVALID);
        }
        if self
            .selection
            .layer
            .instructions
            .as_ref()
            .is_some_and(|s| s.len() > 32768 || s.contains('\0'))
        {
            return Err(INVALID);
        }
        for name in [
            &self.selection.model,
            &self.selection.preset,
            &self.selection.layer.controls.reasoning_effort,
        ]
        .into_iter()
        .flatten()
        {
            if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
                return Err(INVALID);
            }
        }
        match self.operation() {
            Operation::Append(input) => {
                check(input.id)?;
                branches::validate_parts(input.parts, true)?;
            }
            Operation::Edit {
                target,
                replacement,
            } => {
                check(target)?;
                check(replacement.id)?;
                branches::validate_parts(replacement.parts, true)?;
            }
            Operation::Retry { target } => check(target)?,
        }
        Ok(())
    }
}

// Serde also accepts positional arrays for derived structs. Check nested object shapes and
// canonical decimal counts on the wire before converting to the storage representation.
fn wire_proposal<T: DeserializeOwned>(body: &[u8], submission: bool) -> Result<T, Problem> {
    let mut value = crate::provider_keys::documents::unique(body).map_err(|_| BODY)?;
    if !value.is_object() {
        return Err(BODY);
    }
    let proposal = if submission {
        value.get_mut("proposal").ok_or(BODY)?
    } else {
        &mut value
    };
    if !proposal.is_object() || !proposal.get("turn").is_some_and(Value::is_object) {
        return Err(BODY);
    }
    if let Some(selection) = proposal.get_mut("selection") {
        if !selection.is_object() {
            return Err(BODY);
        }
        if let Some(layer) = selection.get_mut("layer") {
            if !layer.is_object() {
                return Err(BODY);
            }
            if let Some(controls) = layer.get_mut("controls") {
                let controls = controls.as_object_mut().ok_or(BODY)?;
                crate::model_config::decode_control_counts(controls, false).map_err(|_| BODY)?;
            }
        }
    }
    serde_json::from_value(value).map_err(|_| BODY)
}
#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ExecutionMode {
    #[default]
    Standard,
    Yolo,
}

// The v1 configuration remains readable by executors that only consume ConfigSnapshot.
#[derive(Serialize)]
struct AdmissionConfig<'a> {
    #[serde(flatten)]
    config: &'a ConfigSnapshot,
    execution_mode: ExecutionMode,
}

#[derive(Deserialize)]
struct StoredMode {
    // Snapshots admitted before session binding used standard execution.
    #[serde(default, deserialize_with = "string_enum")]
    execution_mode: ExecutionMode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    #[serde(default, deserialize_with = "string_enum")]
    execution_mode: ExecutionMode,
    conversation_id: String,
    branch_id: String,
    proposal: Proposal,
}
impl Request {
    pub fn read(body: &[u8]) -> Result<Self, Problem> {
        let r: Self = wire_proposal(body, true)?;
        crate::runs::uuid(&r.conversation_id)
            .and_then(|_| crate::runs::uuid(&r.branch_id))
            .map_err(|_| INVALID)?;
        r.proposal.validate()?;
        Ok(r)
    }
}

async fn resolve(
    c: &mut PgConnection,
    ctx: &sessions::Context,
    actor: &Principal,
    view: &ResourceView,
    catalog: &Catalog,
    selection: &Selection,
    now_ms: i64,
) -> Result<ConfigSnapshot, Problem> {
    let (project, rev) = if let Some(id) = &view.project_id {
        let settings = projects::load_project_settings(c, id)
            .await?
            .ok_or(NOT_FOUND)?;
        (Selection::project(&settings)?, Some(settings.revision))
    } else {
        (Selection::default(), None)
    };
    let policy = store::load_platform_capabilities(c).await?;
    let resolved = catalog.resolve(&project, selection, rev, |model, preset| {
        catalog::allowed(catalog, actor, &policy, model, preset)
    })?;
    let permitted = authz::gateway::family::permits_at(
        c,
        &actor.user_id,
        ctx.approval_id(),
        &resolved.model,
        now_ms,
    )
    .await?;
    let effective = if permitted {
        resolved
    } else if selection.model.is_some() || selection.preset.is_some() {
        return Err(crate::model_config::Error::Unauthorized.into());
    } else {
        let models: Vec<&str> = catalog.models().keys().map(String::as_str).collect();
        let family_permitted = authz::gateway::family::permits_models(
            c,
            &actor.user_id,
            ctx.approval_id(),
            &models,
            now_ms,
        )
        .await?;
        catalog.resolve_with_fallback(
            &project,
            selection,
            rev,
            |model, preset| catalog::allowed(catalog, actor, &policy, model, preset),
            |model| family_permitted.contains(model),
        )?
    };
    let required_capabilities =
        catalog::capabilities(catalog, &effective.model, effective.preset.as_deref())?;
    let cost_bound = catalog.target(&effective)?.cost_bound;
    Ok(ConfigSnapshot {
        effective,
        required_capabilities,
        policy_revision: "openmettle.authz/1".into(),
        cost_bound,
    })
}

// Only a deployment-qualified encoding bound for the selected profile can authorize admission.
// Every assembled turn, instruction and part includes its framing. No tools are proposed here.
fn budget<'a>(
    catalog: &Catalog,
    e: &Effective,
    path: &'a [PathTurn],
    history: &History,
    proposed: Option<&[Part]>,
) -> Result<Budget<'a>, Problem> {
    let profile = catalog.target(e)?;
    let estimate = profile
        .prompt_bound
        .as_ref()
        .zip(profile.estimator_revision.as_deref())
        .map(|(b, revision)| {
            let mut text = Some(u64::from(b.fixed_tokens));
            let mut attachments = Some(0u64);
            let mut charge = |bytes: usize, framing: u32| {
                text = text.and_then(|n| {
                    n.checked_add(u64::from(framing))?
                        .checked_add((bytes as u64).checked_mul(u64::from(b.tokens_per_byte))?)
                });
            };
            for i in &e.instructions {
                charge(i.text.len(), b.tokens_per_turn);
            }
            let mut part = |p: &Part| match p {
                Part::Text(s) => charge(s.len(), b.tokens_per_part),
                Part::Attachment(_) => {
                    charge(0, b.tokens_per_part);
                    attachments = attachments
                        .and_then(|n| n.checked_add(u64::from(b.tokens_per_attachment?)));
                }
            };
            for t in &history.turns {
                for p in &t.parts {
                    if let PartContent::Available(value) = &p.value {
                        part(value)
                    }
                }
            }
            if let Some(parts) = proposed {
                for p in parts {
                    part(p)
                }
            }
            let turns = history.turns.len() as u64 + u64::from(proposed.is_some());
            PromptEstimate {
                profile: &profile.pin,
                revision,
                instructions: Some(0),
                history: text
                    .and_then(|n| n.checked_add(turns.checked_mul(u64::from(b.tokens_per_turn))?)),
                proposed_input: Some(0),
                tools: Some(0),
                attachments,
            }
        });
    Ok(catalog.budget(e, path, estimate.as_ref())?)
}
fn field(f: &Field<u64>) -> Value {
    json!({"state":if f.value.is_some(){"known"}else{"unknown"},"value":decimal(f.value),"source":f.source})
}

pub(super) async fn preview(
    c: &mut PgConnection,
    call: Call<'_>,
    actor: &Principal,
    view: &ResourceView,
    branch: &str,
    catalog: Option<&Catalog>,
    proposal: &Proposal,
) -> Result<Response, Problem> {
    let chat = Conversation {
        scope: &view.scope_id,
        id: call.target,
    };
    let now = call.context.observed_ms();
    let mut history = branches::history(c, actor, chat, branch, now)
        .await?
        .ok_or(NOT_FOUND)?;
    if history.head != proposal.expected_head_message_id {
        return Err(CONFLICT);
    }
    let (target, user) = match proposal.operation() {
        Operation::Append(_) => (None, false),
        Operation::Edit { target, .. } => (Some(target), true),
        Operation::Retry { target } => (Some(target), false),
    };
    if let Some(target) = target {
        let index = history
            .turns
            .iter()
            .position(|t| t.metadata.message_id == target)
            .ok_or(NOT_FOUND)?;
        if history.turns[index].author_user_id.is_some() != user {
            return Err(INVALID);
        }
        history.turns.drain(..=index);
    }
    let proposed = match proposal.operation() {
        Operation::Append(i) | Operation::Edit { replacement: i, .. } => {
            for p in i.parts {
                if let Part::Attachment(id) = p {
                    branches::readable_revision(c, actor, chat.scope, id, now).await?
                }
            }
            Some(i.parts)
        }
        Operation::Retry { .. } => {
            let input = history
                .turns
                .first()
                .filter(|t| t.author_user_id.is_some())
                .ok_or(INVALID)?;
            if input
                .parts
                .iter()
                .any(|p| !matches!(p.value, PartContent::Available(_)))
            {
                return Err(NOT_FOUND);
            }
            None
        }
    };
    let catalog = catalog.ok_or(PROVISIONING)?;
    let config = resolve(
        c,
        call.context,
        actor,
        view,
        catalog,
        &proposal.selection,
        now,
    )
    .await?;
    let e = &config.effective;
    let path = history
        .turns
        .iter()
        .map(|t| t.metadata.clone())
        .collect::<Vec<_>>();
    let b = budget(catalog, e, &path, &history, proposed)?;
    let prompt = match b.estimated {
        Some(n) => {
            json!({"kind":"estimated","count":n.upper_bound.to_string(),"estimator_revision":n.revision})
        }
        None => json!({"kind":"unknown","count":null,"estimator_revision":null}),
    };
    let measured = b.measured.map(|turn| {
        json!({
            "message_id": turn.message_id, "run_id": turn.run_id,
            "profile_revision": turn.profile.as_ref().map(|p| &p.revision),
            "input_count": decimal(turn.input_count), "output_count": decimal(turn.output_count),
        })
    });
    let mut omissions: Vec<Value> = e.omissions.iter().map(|o| json!(o)).collect();
    for t in &history.turns {
        for p in &t.parts {
            if !matches!(p.value, PartContent::Available(_)) {
                omissions.push(json!({"source":"history","control":"attachment","reason":"unavailable","message_id":t.metadata.message_id}));
            }
        }
    }
    Ok(reply(
        StatusCode::OK,
        json!({
            "model": e.model, "model_source": e.model_source, "preset": e.preset, "preset_source": e.preset_source,
            "profile": e.profile, "catalog_revision": e.catalog_revision, "preset_revision": e.preset_revision,
            "project_revision": e.project_revision.map(|n| n.to_string()), "context_window": field(&e.context_window),
            "ceiling": field(&e.ceiling), "output_reserve": field(&e.output_reserve), "usable_input": decimal(b.usable_input),
            "usable_input_operands": ["ceiling", "output_reserve"], "temperature": e.temperature, "top_p": e.top_p,
            "reasoning_effort": e.reasoning_effort, "omissions": omissions,
            "instruction_sources": e.instructions.iter().map(|i|i.source).collect::<Vec<_>>(),
            "measured": measured, "prompt": prompt
        }),
    ))
}

pub(super) async fn submit(
    c: &mut PgConnection,
    call: Call<'_>,
    r: &Request,
    limits: &AdmissionLimits,
    catalog: Option<&Catalog>,
) -> Result<(StatusCode, String, i64), Problem> {
    let ctx = call.context;
    let actor = principal(c, ctx).await?;
    crate::restore::require_open_gate(c).await?;
    let visible = projects::read_resource(
        c,
        &actor,
        ResourceKind::Conversation,
        &r.conversation_id,
        ctx.observed_ms(),
    )
    .await?;
    let mut tx = WriteTransaction::begin_bounded(c, false).await?;
    let result = admission(&mut tx, &visible.scope_id, call, r, limits, catalog).await;
    if matches!(result, Ok((_, true, _))) {
        tx.commit().await?
    } else {
        tx.rollback().await?
    }
    let (outcome, _, verified_now_ms) = result?;
    match outcome {
        Admission::Admitted { run_id, .. } => Ok((StatusCode::CREATED, run_id, verified_now_ms)),
        Admission::Replayed { run_id, .. } => Ok((StatusCode::OK, run_id, verified_now_ms)),
        Admission::Refused(RunLimit::ActorLimit | RunLimit::ScopeLimit) => Err(problem(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "A live run limit has been reached.",
        )),
        Admission::Refused(RunLimit::QueueFull) => Err(QUEUE_FULL),
        Admission::Refused(RunLimit::Quota {
            resource_kind,
            scope_kind,
        }) => Err(quota_problem(
            StatusCode::TOO_MANY_REQUESTS,
            "quota",
            if resource_kind == "device_reservations" {
                "The device reservation quota does not allow this request."
            } else {
                "The usage budget does not allow this request."
            },
            resource_kind,
            scope_kind,
        )),
        Admission::Refused(RunLimit::QuotaUnconfigured {
            resource_kind,
            scope_kind,
        }) => Err(quota_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "provisioning",
            "Quota limits are not configured for this resource.",
            resource_kind,
            scope_kind,
        )),
    }
}
pub(super) const QUEUE_FULL: Problem = problem(
    StatusCode::SERVICE_UNAVAILABLE,
    "unavailable",
    "The run queue is full.",
);
async fn admission(
    tx: &mut WriteTransaction<'_>,
    scope: &str,
    call: Call<'_>,
    r: &Request,
    limits: &AdmissionLimits,
    catalog: Option<&Catalog>,
) -> Result<(Admission, bool, i64), Problem> {
    let c = tx.connection()?;
    crate::restore::require_open_gate(c).await?;
    let ctx = call.context;
    let (personal_owner, project_id) =
        queue::lock_scope_actor(c, scope, ctx.user_id(), ctx.approval_id()).await?;
    let mut now_ms = store::post_lock_clock_ms(c, ctx.observed_ms()).await?;
    let actor = principal_at(c, ctx, now_ms).await?;
    let view = projects::resource_view(
        c,
        &actor,
        ResourceKind::Conversation,
        &r.conversation_id,
        now_ms,
        authz::Action::RunExecute,
    )
    .await?;
    if view.scope_id != scope {
        return Err(NOT_FOUND);
    }
    let key = request_key(call.op, &r.conversation_id, call.key);
    let chat = Conversation {
        scope,
        id: &r.conversation_id,
    };
    let intent = Intent {
        source_branch_id: &r.branch_id,
        expected_head_message_id: r.proposal.expected_head_message_id.as_deref(),
        operation: r.proposal.operation(),
        selection: &r.proposal.selection,
        requested_rounds: r.proposal.requested_rounds,
    };
    let scope_kind = if view.project_id.is_some() {
        "project"
    } else {
        "personal"
    };
    let (
        branch,
        message,
        input_attachments,
        replay_approval_id,
        format,
        version,
        snapshots,
        gates,
        per_round_ceiling,
        per_round_cost_micros,
        requires_device_slot,
        selected_model,
    ) = if let Some(found) = queue::find_run(c, scope, ctx.user_id(), &key).await? {
        let (previous, config) = Snapshots::decode(&found).map_err(|_| KEY_CONFLICT)?;
        let mode: StoredMode =
            serde_json::from_slice(&found.config_snapshot).map_err(|_| KEY_CONFLICT)?;
        if mode.execution_mode != r.execution_mode || !previous.matches(&intent) {
            return Err(KEY_CONFLICT);
        }
        let pinned_cost = config.cost_bound.and_then(|cb| {
            config
                .effective
                .ceiling
                .value
                .and_then(|tokens| cb.round_ceiling(tokens).ok())
        });
        let (round_cost, device_slot) = match catalog {
            Some(cat) => match cat.target(&config.effective) {
                Ok(profile) => (
                    pinned_cost
                        .or_else(|| cat.round_cost_ceiling(&config.effective).ok().flatten()),
                    profile.requires_device_slot,
                ),
                Err(_) => (pinned_cost, false),
            },
            None => (pinned_cost, false),
        };
        (
            found.branch_id,
            found.input_message_id,
            Vec::new(),
            Some(found.actor_approval_id),
            found.snapshot_format,
            found.snapshot_version,
            Snapshots {
                input: found.input_snapshot,
                config: found.config_snapshot,
            },
            config.required_capabilities,
            config.effective.ceiling.value,
            round_cost,
            device_slot,
            Some(config.effective.model),
        )
    } else {
        let audit = AuditContext {
            now_ms,
            request_key: &key,
            ..call.audit()
        };
        let target = branches::prepare_turn(
            tx,
            &audit,
            chat,
            &r.branch_id,
            intent.expected_head_message_id,
            intent.operation,
        )
        .await?;
        let c = tx.connection()?;
        now_ms = store::post_lock_clock_ms(c, now_ms).await?;
        let actor = principal_at(c, ctx, now_ms).await?;
        let catalog = catalog.ok_or(PROVISIONING)?;
        let mut config = resolve(c, ctx, &actor, &view, catalog, intent.selection, now_ms).await?;
        if r.execution_mode == ExecutionMode::Yolo {
            config
                .required_capabilities
                .insert("runs.use_yolo".into(), authz::CapabilityGate::OptIn);
        }
        let history = branches::history(c, &actor, chat, &target.branch_id, now_ms)
            .await?
            .ok_or(NOT_FOUND)?;
        let path = history
            .turns
            .iter()
            .map(|t| t.metadata.clone())
            .collect::<Vec<_>>();
        budget(catalog, &config.effective, &path, &history, None)?.admit()?;
        let profile = catalog.target(&config.effective)?;
        let round_cost = catalog.round_cost_ceiling(&config.effective)?;
        let device_slot = profile.requires_device_slot;
        let selected_model = config.effective.model.clone();
        let mut snapshots = Snapshots::encode(&intent, &history, catalog, &config)?;
        snapshots.config = serde_json::to_vec(&AdmissionConfig {
            config: &config,
            execution_mode: r.execution_mode,
        })
        .map_err(|_| INTERNAL)?;
        (
            target.branch_id,
            target.input_message_id,
            target.attachment_revisions,
            None,
            SNAPSHOT_FORMAT.to_owned(),
            SNAPSHOT_VERSION,
            snapshots,
            config.required_capabilities,
            config.effective.ceiling.value,
            round_cost,
            device_slot,
            Some(selected_model),
        )
    };
    let caps = gates
        .iter()
        .map(|(name, gate)| queue::CapabilityUse { name, gate: *gate })
        .collect::<Vec<_>>();
    let mut admission_req = queue::RunAdmission {
        input: RunInput {
            scope,
            actor: ctx.user_id(),
            conversation: chat.id,
            branch: &branch,
            message: &message,
            key: &key,
            format: &format,
            version,
            input: &snapshots.input,
            config: &snapshots.config,
        },
        actor_approval_id: ctx.approval_id(),
        capabilities: &caps,
        requested_rounds: intent.requested_rounds,
        now_ms,
        cost_qualified: Some(per_round_cost_micros.is_some()),
    };
    let (admitted, admit_now_ms) =
        queue::admit_run_with_mode_at(tx, &admission_req, limits, ctx).await?;
    now_ms = now_ms.max(admit_now_ms);
    admission_req.now_ms = now_ms;
    let build_token_units = |round_limit: i32| -> Result<i64, Problem> {
        let per_round = per_round_ceiling.ok_or(PROVISIONING)?;
        per_round
            .checked_mul(u64::from(u32::try_from(round_limit).map_err(|_| INTERNAL)?))
            .and_then(|n| i64::try_from(n).ok())
            .filter(|&n| n > 0)
            .ok_or(INVALID)
    };
    match &admitted {
        Admission::Admitted {
            run_id,
            round_limit,
        } => {
            let token_units = build_token_units(*round_limit)?;
            let refusal = crate::quotas::reserve_admitted_run_budget(
                tx,
                &crate::quotas::RunBudgetReservation {
                    scope_id: scope,
                    scope_kind,
                    actor_user_id: ctx.user_id(),
                    actor_approval_id: ctx.approval_id(),
                    run_id,
                    token_units,
                    per_round_cost_micros,
                    round_limit: *round_limit,
                    requires_device_slot,
                },
            )
            .await?;
            let c = tx.connection()?;
            let (fresh_actor, _, _, post_reserve_ms) = queue::verify_admission_authority(
                c,
                &admission_req,
                personal_owner.as_deref(),
                project_id.as_deref(),
                Some(ctx.locator()),
                now_ms,
            )
            .await?;
            if let Some(limit) = refusal {
                return Ok((Admission::Refused(limit), false, post_reserve_ms));
            }
            for revision in &input_attachments {
                branches::readable_revision(c, &fresh_actor, scope, revision, post_reserve_ms)
                    .await?;
            }
            if let Some(model) = selected_model.as_deref()
                && !authz::gateway::family::permits_at(
                    c,
                    ctx.user_id(),
                    ctx.approval_id(),
                    model,
                    post_reserve_ms,
                )
                .await?
            {
                return Err(crate::model_config::Error::Unauthorized.into());
            }
            Ok((admitted, true, post_reserve_ms))
        }
        Admission::Replayed {
            run_id,
            state,
            round_limit,
        } if state == "queued" => {
            let effective_rounds = round_limit.unwrap_or(limits.round_cap);
            let (committed, refusal) = match build_token_units(effective_rounds) {
                Ok(token_units) => {
                    crate::quotas::backfill_replayed_run_budget(
                        tx,
                        &crate::quotas::RunBudgetReservation {
                            scope_id: scope,
                            scope_kind,
                            actor_user_id: ctx.user_id(),
                            actor_approval_id: ctx.approval_id(),
                            run_id,
                            token_units,
                            per_round_cost_micros,
                            round_limit: effective_rounds,
                            requires_device_slot,
                        },
                    )
                    .await?
                }
                Err(_) => (false, None),
            };
            let c = tx.connection()?;
            let (_, _, _, post_backfill_ms) = queue::verify_admission_authority(
                c,
                &admission_req,
                personal_owner.as_deref(),
                project_id.as_deref(),
                Some(ctx.locator()),
                now_ms,
            )
            .await?;
            let stored_approval_id = match replay_approval_id {
                Some(stored) => stored,
                None => sqlx::query_scalar::<_, Option<String>>(
                    "SELECT actor_approval_id::text
                       FROM openmettle.runs
                      WHERE scope_id = $1::uuid AND id = $2::uuid AND actor_user_id = $3::uuid",
                )
                .bind(scope)
                .bind(run_id)
                .bind(ctx.user_id())
                .fetch_optional(&mut *c)
                .await
                .map_err(Problem::from)?
                .flatten(),
            };
            let should_commit = if committed && refusal.is_none() {
                match (selected_model.as_deref(), stored_approval_id.as_deref()) {
                    (Some(model), Some(approval_id)) => {
                        authz::gateway::family::permits_at(
                            c,
                            ctx.user_id(),
                            approval_id,
                            model,
                            post_backfill_ms,
                        )
                        .await?
                    }
                    (Some(_), None) => false,
                    (None, _) => true,
                }
            } else {
                false
            };
            Ok((admitted, should_commit, post_backfill_ms))
        }
        _ => {
            let verified_ms = store::post_lock_clock_ms(tx.connection()?, now_ms).await?;
            Ok((admitted, false, verified_ms))
        }
    }
}
pub(super) async fn cancel(
    c: &mut PgConnection,
    call: Call<'_>,
) -> Result<(StatusCode, String, i64), Problem> {
    let ctx = call.context;
    let actor = principal(c, ctx).await?;
    crate::restore::require_open_gate(c).await?;
    let (scope, conversation): (String, String) = sqlx::query_as(
        "SELECT scope_id::text, conversation_id::text FROM openmettle.runs
         WHERE id=$1::uuid AND actor_user_id=$2::uuid",
    )
    .bind(call.target)
    .bind(ctx.user_id())
    .fetch_optional(&mut *c)
    .await?
    .ok_or(NOT_FOUND)?;
    projects::read_resource(
        c,
        &actor,
        ResourceKind::Conversation,
        &conversation,
        ctx.observed_ms(),
    )
    .await?;
    let result = queue::cancel_run(c, &actor, &scope, call.target).await?;
    let status = match result {
        queue::CancelOutcome::Requested { .. } => StatusCode::ACCEPTED,
        _ => StatusCode::OK,
    };
    let verified_ms = store::post_lock_clock_ms(c, ctx.observed_ms()).await?;
    Ok((status, call.target.to_owned(), verified_ms))
}
