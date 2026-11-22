//! Execute an admitted conversation turn against the deployment's qualified gateway.
use super::*;
use crate::{
    authz::{
        branches::{self, Part, WorkerPrompt},
        runs::{CapabilityUse, RunRecheckOutcome, RunRecheckRequest},
    },
    model_config::{Catalog, ConfigSnapshot, Effective},
    provider_http::inference::{
        self, Call, CallGroup, Credential, Gateway, History, Request, RunStop, Tool,
    },
};
use serde_json::{Map, Value};

/// Metered gateway dispatch settings for a leased worker turn route.
pub struct MeteredRoute {
    pub installation: String,
    pub keys: Arc<crate::provider_keys::gateway::GatewayKeys>,
    pub device_grant_id: Option<String>,
}

/// The credential owner resolves this route at dispatch for the admitted actor and scope.
pub struct Route {
    pub gateway: Arc<Gateway>,
    pub bearer: String,
    pub stream: bool,
    pub metered: Option<MeteredRoute>,
}

impl Route {
    pub fn bearer(gateway: Arc<Gateway>, bearer: String, stream: bool) -> Self {
        Self {
            gateway,
            bearer,
            stream,
            metered: None,
        }
    }

    pub fn metered(
        gateway: Arc<Gateway>,
        installation: String,
        keys: Arc<crate::provider_keys::gateway::GatewayKeys>,
        stream: bool,
    ) -> Self {
        Self {
            gateway,
            bearer: String::new(),
            stream,
            metered: Some(MeteredRoute {
                installation,
                keys,
                device_grant_id: None,
            }),
        }
    }

    pub fn with_device_grant(mut self, device_grant_id: String) -> Self {
        if let Some(metered) = &mut self.metered {
            metered.device_grant_id = Some(device_grant_id);
        }
        self
    }
}

pub trait TurnRoutes: Send + Sync + 'static {
    fn route(
        &self,
        claim: &ClaimedRun,
        actor: &str,
        model: &Effective,
    ) -> impl Future<Output = Result<Route, inference::Error>> + Send;

    /// Only server-owned declarations qualified and budgeted for this admitted run.
    fn tools(&self, _claim: &ClaimedRun) -> Vec<Tool> {
        vec![]
    }
    /// A profile-qualified upper bound for the complete prompt with server tools and their
    /// results. The admission estimate covers the original conversation without these items.
    fn tool_prompt_bound(&self, _model: &Effective, _request: &Request) -> Option<u64> {
        None
    }
    /// Bind a validated call to a reviewed version and destination. Nothing here grants dispatch.
    fn proposal(&self, _claim: &ClaimedRun, _call: &Call) -> Option<Proposal> {
        None
    }
}

pub struct TurnExecutor<R> {
    pool: PgPool,
    catalog: Arc<Catalog>,
    leases: LeaseSettings,
    routes: R,
    artifacts: Option<artifact_fs::Store>,
    effects: Option<Arc<ApprovedEffects>>,
}

pub struct FinalAnswer {
    parts: Vec<Part>,
    reasoning: Option<Vec<Map<String, Value>>>,
    input_count: Option<i64>,
    output_count: Option<i64>,
}

pub(super) async fn publish(
    c: &mut sqlx::PgConnection,
    lease: &leases::Lease<'_>,
    settings: &LeaseSettings,
    answer: FinalAnswer,
) -> Result<Settled, LeaseError> {
    let id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut *c)
        .await
        .map_err(StoreError::from)?;
    leases::settle_answer(
        c,
        lease,
        settings,
        &branches::Answer {
            id: &id,
            parts: &answer.parts,
            reasoning: answer.reasoning.as_deref(),
            input_count: answer.input_count,
            output_count: answer.output_count,
        },
    )
    .await
}

const FAILED: StepResult = StepResult::Failed(FailReason::StepFailed);
pub(crate) fn lease_step(error: LeaseError) -> StepResult {
    match error {
        LeaseError::Stopping(_) => StepResult::Stopped,
        LeaseError::Store(StoreError::Conflict("expired effect claim")) => StepResult::LeaseLost,
        LeaseError::StaleClaim | LeaseError::Expired | LeaseError::Terminal { .. } => {
            StepResult::LeaseLost
        }
        LeaseError::Store(_) => FAILED,
    }
}

impl<R: TurnRoutes> TurnExecutor<R> {
    pub fn new(pool: PgPool, catalog: Arc<Catalog>, leases: LeaseSettings, routes: R) -> Self {
        Self {
            pool,
            catalog,
            leases,
            routes,
            artifacts: None,
            effects: None,
        }
    }
    pub fn with_artifacts(mut self, store: artifact_fs::Store) -> Self {
        store.attach(&self.pool);
        self.artifacts = Some(store);
        self
    }
    pub fn with_effects(mut self, effects: Arc<ApprovedEffects>) -> Self {
        self.effects = Some(effects);
        self
    }

    async fn authority(
        &self,
        claim: &ClaimedRun,
        config: &ConfigSnapshot,
    ) -> Result<(), StepResult> {
        let caps = config
            .required_capabilities
            .iter()
            .map(|(name, gate)| CapabilityUse { name, gate: *gate })
            .collect::<Vec<_>>();
        let mut c = self.pool.acquire().await.map_err(|_| FAILED)?;
        let now_ms =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
                .fetch_one(&mut *c)
                .await
                .map_err(|_| FAILED)?;
        let check = RunRecheckRequest {
            scope_id: &claim.scope_id,
            run_id: &claim.run_id,
            actor_approval_id: &claim.actor_approval_id,
            capabilities: &caps,
            extra_target: None,
            now_ms,
        };
        match queue::recheck_leased(&mut c, &claim.lease(), &check, &self.leases).await {
            Ok(RunRecheckOutcome::Continue) => Ok(()),
            // recheck_leased has already settled. Handoff releases a reconciling
            // holder, and the Hold fence refuses an already terminal run.
            Ok(_) => Err(StepResult::Handoff),
            Err(error) => Err(lease_step(error)),
        }
    }

    /// Reserve the model round before HTTP. A replacement holder cannot reset the round budget.
    async fn next_round(&self, claim: &ClaimedRun, restarting: bool) -> Result<i64, StepResult> {
        let mut c = self.pool.acquire().await.map_err(|_| FAILED)?;
        let number = leases::with_lease(&mut c, &claim.lease(), Fence::Step, async |tx, _| {
            let (used, has_effect): (i64,bool) = sqlx::query_as("SELECT
                (SELECT count(*) FROM openmettle.run_events WHERE scope_id=$2::uuid AND run_id=$1::uuid AND format='openmettle.model-round'),
                EXISTS(SELECT FROM openmettle.operations WHERE scope_id=$2::uuid AND run_id=$1::uuid)")
                .bind(&claim.run_id).bind(&claim.scope_id).fetch_one(tx.connection()?).await?;
            if restarting && has_effect {
                // The in-memory tool transcript did not survive. Never redispatch a past effect.
                return Err(crate::runs::Error::Conflict);
            }
            let round = used + 1;
            if round <= i64::from(claim.round_limit) {
                crate::runs::append_event(tx, &claim.scope_id, &claim.run_id, &format!("model-round:{round}"),
                    Payload { format: "openmettle.model-round", version: 1, bytes: b"{}" }).await?;
            }
            Ok(round)
        }).await.map_err(lease_step)?;
        if number > i64::from(claim.round_limit) {
            Err(StepResult::Failed(FailReason::RoundLimit))
        } else {
            Ok(number)
        }
    }

    async fn tool(
        &self,
        run: &ActiveRun,
        cx: &StepContext,
        config: &ConfigSnapshot,
        call: &Call,
        prior_effects: &mut Vec<(String, Proposal)>,
    ) -> Result<String, StepResult> {
        let effects = self.effects.as_deref().ok_or(FAILED)?;
        self.authority(&run.claim, config).await?;
        let refused = || crate::mcp::ToolFault::TerminalRefusal.envelope();
        let Some(proposal) = self.routes.proposal(&run.claim, call) else {
            return Ok(refused());
        };
        if proposal.tool != call.name {
            return Ok(refused());
        }
        if proposal.tool == crate::mcp::READ_RANGE {
            let Ok(expected) = crate::mcp::Registry.proposal(
                &run.claim.scope_id,
                &proposal.logical_key,
                &call.name,
                &proposal.version,
                call.arguments.to_string().as_bytes(),
            ) else {
                return Ok(refused());
            };
            if expected.arguments() != proposal.arguments()
                || expected.destination() != proposal.destination()
            {
                return Ok(refused());
            }
        } else if proposal.arguments() != &call.arguments {
            return Ok(refused());
        }
        let intent = {
            let mut c = self.pool.acquire().await.map_err(|_| FAILED)?;
            if cx.stop.borrow().is_some() {
                return Err(StepResult::Stopped);
            }
            match approvals::record_fenced_intent(
                &mut c,
                &run.claim.lease(),
                &proposal,
                None,
                &Some(effects),
                &self.leases,
            )
            .await
            {
                Ok(intent) => intent,
                Err(LeaseError::Store(StoreError::Denied(_) | StoreError::InvalidInput(_))) => {
                    return Ok(refused());
                }
                Err(e) => return Err(lease_step(e)),
            }
        };
        let step = StepContext {
            deadline: run.execution_deadline,
            ..cx.clone()
        };
        let id = match &intent {
            IntentResult::Applied(i) => Some(i.operation_id.clone()),
            IntentResult::Replayed(id) => Some(id.clone()),
            _ => None,
        };
        match (EffectDispatch {
            pool: &self.pool,
            artifacts: self.artifacts.as_ref(),
            effects,
            settings: &self.leases,
        })
        .send(run, &proposal, intent, step)
        .await
        {
            StepResult::ToolOutput(output) => {
                if let Some(id) = id {
                    prior_effects.push((id, proposal));
                }
                Ok(output)
            }
            stopped @ (StepResult::Stopped
            | StepResult::Handoff
            | StepResult::LeaseLost
            | StepResult::Invalidated(_)
            | StepResult::Failed(_)) => Err(stopped),
            _ => Err(FAILED),
        }
    }

    async fn prepare_round(
        &self,
        claim: &ClaimedRun,
        config: &ConfigSnapshot,
        continuation: &[History],
        tools: Option<Vec<Tool>>,
    ) -> Result<(Route, Request, i64, String), StepResult> {
        self.authority(claim, config).await?;
        let prompt = {
            let mut c = self.pool.acquire().await.map_err(|_| FAILED)?;
            branches::worker_prompt(
                &mut c,
                claim,
                config,
                &self.catalog,
                self.artifacts.as_ref(),
            )
            .await
        };
        let WorkerPrompt { actor, mut history } = match prompt {
            Ok(prompt) => prompt,
            Err(StoreError::Denied(_)) => {
                // Identity or visibility can change between the fenced check and hydration.
                self.authority(claim, config).await?;
                return Err(FAILED);
            }
            Err(_) => return Err(FAILED),
        };
        let route = self
            .routes
            .route(claim, &actor, &config.effective)
            .await
            .map_err(inference::Error::step_result)?;
        history.extend_from_slice(continuation);
        let request = Request {
            history,
            parallel: None,
            tools,
            stream: route.stream,
        };
        if request.tools.is_some() {
            let bound = self
                .routes
                .tool_prompt_bound(&config.effective, &request)
                .ok_or(FAILED)?;
            if bound > config.effective.usable_input().ok_or(FAILED)? {
                return Err(FAILED);
            }
        }
        let round = self.next_round(claim, continuation.is_empty()).await?;
        self.authority(claim, config).await?;
        Ok((route, request, round, actor))
    }

    async fn execute_turn(
        &self,
        run: &ActiveRun,
        cx: StepContext,
    ) -> Result<FinalAnswer, StepResult> {
        let mut stop = cx.stop.clone();
        let config = {
            let mut c = self.pool.acquire().await.map_err(|_| FAILED)?;
            branches::worker_config(&mut c, &run.claim)
                .await
                .map_err(|_| FAILED)?
        };
        let mut continuation = Vec::new();
        let mut prior_effects: Vec<(String, Proposal)> = Vec::new();
        let mut tools = self
            .effects
            .as_ref()
            .map(|_| self.routes.tools(&run.claim))
            .filter(|t| !t.is_empty());
        loop {
            let (route, request, round, actor) = tokio::select! {
                biased;
                _ = stop.wait_for(Option::is_some) => return Err(StepResult::Stopped),
                ready = self.prepare_round(&run.claim, &config, &continuation, tools) => ready?,
            };
            // These cached tool messages will be sent to the model again on every
            // continuation. Recheck each operation immediately before exposing history.
            for (op, proposal) in &prior_effects {
                let mut c = self
                    .pool
                    .acquire()
                    .await
                    .map_err(|_| StepResult::LeaseLost)?;
                match approvals::recheck_replay_effect_authority(
                    &mut c,
                    &run.claim.lease(),
                    op,
                    proposal,
                    &self.leases,
                    &self.effects.as_deref(),
                )
                .await
                .map_err(lease_step)?
                {
                    approvals::ReplayEffect::Observed { .. } => {}
                    approvals::ReplayEffect::Invalidated(s) => {
                        return Err(StepResult::Invalidated(s));
                    }
                    _ => return Err(FAILED),
                }
            }
            let metering_enforced = {
                let mut c = self.pool.acquire().await.map_err(|_| FAILED)?;
                let has_table: bool = sqlx::query_scalar(
                    "SELECT to_regclass('openmettle.quota_enforcement') IS NOT NULL",
                )
                .fetch_one(&mut *c)
                .await
                .map_err(|_| FAILED)?;
                if has_table {
                    sqlx::query_scalar::<_, bool>(
                        "SELECT metering_enforced FROM openmettle.quota_enforcement WHERE id",
                    )
                    .fetch_one(&mut *c)
                    .await
                    .map_err(|_| FAILED)?
                } else {
                    false
                }
            };
            if metering_enforced && route.metered.is_none() {
                return Err(FAILED);
            }
            let turn = if let Some(metered) = &route.metered {
                let round_tokens = config
                    .effective
                    .ceiling
                    .value
                    .and_then(|n| i64::try_from(n).ok())
                    .filter(|&n| n > 0)
                    .ok_or(FAILED)?;
                let round_cost = self
                    .catalog
                    .round_cost_ceiling(&config.effective)
                    .map_err(|_| FAILED)?;
                let requires_device_slot = self
                    .catalog
                    .target(&config.effective)
                    .map_err(|_| FAILED)?
                    .requires_device_slot;
                let round_i32 = i32::try_from(round).map_err(|_| FAILED)?;
                let pending = crate::authz::gateway::reserve_turn_round(
                    &self.pool,
                    crate::authz::gateway::TurnRound {
                        scope_id: &run.claim.scope_id,
                        actor: &actor,
                        approval: &run.claim.actor_approval_id,
                        run_id: &run.claim.run_id,
                        round: round_i32,
                        claim_token: &run.claim.claim_token,
                        installation: &metered.installation,
                        model: &config.effective.model,
                        round_tokens,
                        round_cost,
                        requires_device_slot,
                    },
                )
                .await
                .map_err(|_| FAILED)?;
                if requires_device_slot && metering_enforced {
                    let Some(grant_id) = metered.device_grant_id.as_deref() else {
                        let _ = pending.release(&self.pool).await;
                        return Err(FAILED);
                    };
                    if crate::authz::gateway::verify_turn_device_hold(
                        &self.pool,
                        &run.claim.scope_id,
                        &run.claim.run_id,
                        grant_id,
                    )
                    .await
                    .is_err()
                    {
                        let _ = pending.release(&self.pool).await;
                        return Err(FAILED);
                    }
                }
                if cx.stop.borrow().is_some() {
                    let _ = pending.release(&self.pool).await;
                    return Err(StepResult::Stopped);
                }
                let dispatch = match pending.handoff(&self.pool, &metered.keys).await {
                    Ok(dispatch) => dispatch,
                    Err(_) => {
                        let _ = pending.release(&self.pool).await;
                        return Err(FAILED);
                    }
                };
                if requires_device_slot && metering_enforced {
                    let grant_id = metered.device_grant_id.as_deref().ok_or(FAILED)?;
                    crate::authz::gateway::commit_turn_device_handoff(
                        &self.pool,
                        &run.claim.scope_id,
                        &run.claim.run_id,
                        &run.claim.claim_token,
                        grant_id,
                    )
                    .await
                    .map_err(|_| FAILED)?;
                }
                crate::provider_http::BillableInferenceRef {
                    installation: &metered.installation,
                    route: &route.gateway,
                }
                .send(
                    dispatch,
                    &self.catalog,
                    &config.effective,
                    &request,
                    Some(RunStop::from_worker(run, cx.stop.clone())),
                    |_| async {},
                )
                .await
                .map_err(inference::Error::step_result)?
            } else {
                route
                    .gateway
                    .server(
                        &self.catalog,
                        &config.effective,
                        &request,
                        Credential::Bearer(&route.bearer),
                        RunStop::from_worker(run, cx.stop.clone()),
                        |_| async {},
                    )
                    .await
                    .map_err(inference::Error::step_result)?
            };
            tools = request.tools;
            let [answer]: [_; 1] = turn.answers.try_into().map_err(|_| FAILED)?;
            match answer.calls {
                CallGroup::Valid(calls) if calls.is_empty() => {
                    if answer.parts.is_empty() && answer.reasoning.is_none() {
                        return Err(FAILED);
                    }
                    let reasoning = answer
                        .reasoning
                        .map(|r| {
                            r.blocks
                                .into_iter()
                                .map(|v| match v {
                                    Value::Object(m) => Ok(m),
                                    _ => Err(FAILED),
                                })
                                .collect::<Result<_, _>>()
                        })
                        .transpose()?;
                    return Ok(FinalAnswer {
                        parts: answer.parts.into_iter().map(Part::Text).collect(),
                        reasoning,
                        input_count: turn.usage.as_ref().and_then(|u| u.input).map(|n| n as i64),
                        output_count: turn.usage.and_then(|u| u.output).map(|n| n as i64),
                    });
                }
                _ if round >= i64::from(run.claim.round_limit) => {
                    return Err(StepResult::Failed(FailReason::RoundLimit));
                }
                CallGroup::InvalidArguments(errors) => {
                    continuation.push(History::RejectedGroup(errors))
                }
                CallGroup::Valid(calls) => {
                    let [call] = calls.as_slice() else {
                        return Err(FAILED);
                    };
                    let output = self
                        .tool(run, &cx, &config, call, &mut prior_effects)
                        .await?;
                    let id = call.id.clone();
                    continuation.push(History::Assistant {
                        parts: answer.parts,
                        reasoning: answer.reasoning,
                        calls,
                    });
                    continuation.push(History::ToolResult { id, output });
                }
            }
        }
    }
}

impl<R: TurnRoutes> Executor for TurnExecutor<R> {
    async fn step(&self, run: &ActiveRun, cx: StepContext) -> StepResult {
        // The gateway observes stop itself. An in-flight tool keeps its runner's drain
        // window to record the downstream outcome before the lease is handed off.
        self.execute_turn(run, cx)
            .await
            .map_or_else(|r| r, StepResult::Answer)
    }
    fn can_resume_approved(&self, _: &Proposal) -> bool {
        // This executor only runs tools in a live model transcript. A bare parked
        // proposal cannot reconstruct the original call group and model context.
        false
    }

    async fn reconcile(&self, _: &UnresolvedOperation, _: StepContext) -> Option<OwnedObservation> {
        // No authoritative downstream lookup was supplied. Never repeat an uncertain effect.
        None
    }
}

#[cfg(test)]
#[path = "schema_fixture.rs"]
mod schema_fixture;
