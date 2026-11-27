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

/// Metered gateway dispatch settings for a leased worker turn route. The round's bearer is made
/// at handoff (ADR 0044), so the route carries no credential.
pub struct MeteredRoute {
    pub installation: String,
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

    pub fn metered(gateway: Arc<Gateway>, installation: String, stream: bool) -> Self {
        Self {
            gateway,
            bearer: String::new(),
            stream,
            metered: Some(MeteredRoute {
                installation,
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
    /// Server-owned declarations carrying pinned external contract versions when applicable.
    /// External MCP routes should override this via `ExternalToolContract::declared_tool`.
    fn declared_tools(&self, claim: &ClaimedRun) -> Vec<DeclaredTool> {
        self.tools(claim)
            .into_iter()
            .map(DeclaredTool::internal)
            .collect()
    }
    /// Server-owned declarations qualified for `model`, carrying pinned external contract
    /// versions when applicable. Defaults to [`Self::declared_tools`].
    fn declared_tools_for_model(
        &self,
        claim: &ClaimedRun,
        _model: &Effective,
    ) -> Vec<DeclaredTool> {
        self.declared_tools(claim)
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

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum AdvertisedDeclaration {
    Unoffered,
    Internal,
    External { version: String },
}

impl AdvertisedDeclaration {
    fn from_external_version(ext: Option<String>) -> Self {
        match ext {
            None => Self::Internal,
            Some(version) => Self::External { version },
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SavedCallGroup {
    Valid {
        round: i64,
        continuation_rounds: Vec<i64>,
        parts: Vec<String>,
        reasoning: Option<Box<SavedReasoning>>,
        calls: Vec<SavedCall>,
    },
    Rejected {
        round: i64,
        continuation_rounds: Vec<i64>,
        errors: Vec<inference::ToolError>,
    },
}

impl SavedCallGroup {
    fn is_valid_shape(&self, expected_round: i64) -> bool {
        let rounds_ok = |rounds: &[i64]| {
            !rounds.is_empty()
                && rounds.last() == Some(&expected_round)
                && rounds.iter().all(|&r| r >= 1 && r <= expected_round)
                && rounds.windows(2).all(|w| w[0] < w[1])
        };
        match self {
            Self::Valid {
                round,
                continuation_rounds,
                calls,
                ..
            } => *round == expected_round && !calls.is_empty() && rounds_ok(continuation_rounds),
            Self::Rejected {
                round,
                continuation_rounds,
                errors,
            } => *round == expected_round && !errors.is_empty() && rounds_ok(continuation_rounds),
        }
    }

    fn continuation_rounds(&self) -> &[i64] {
        match self {
            Self::Valid {
                continuation_rounds,
                ..
            }
            | Self::Rejected {
                continuation_rounds,
                ..
            } => continuation_rounds,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SavedHandoff {
    continuation_rounds: Vec<i64>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SavedReasoning {
    source: crate::model_config::ReplaySource,
    blocks: Vec<Value>,
    storage_bytes: usize,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SavedCall {
    id: String,
    name: String,
    arguments: Value,
    advertised: AdvertisedDeclaration,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SavedCallResult {
    call_id: String,
    operation_id: Option<String>,
    output: String,
}

pub struct FinalAnswer {
    parts: Vec<Part>,
    reasoning: Option<Vec<Map<String, Value>>>,
    input_count: Option<i64>,
    output_count: Option<i64>,
    stop_reason: Option<inference::StopReason>,
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
            stop_reason: answer.stop_reason.map(inference::StopReason::as_str),
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

    /// Reserve the model round before HTTP. A replacement holder cannot reset the round budget,
    /// except when a metered predecessor never reached gateway handoff for its reserved round.
    async fn next_round(
        &self,
        claim: &ClaimedRun,
        restarting: bool,
        metered: bool,
    ) -> Result<i64, StepResult> {
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
            if restarting
                && metered
                && used > 0
                && used <= i64::from(claim.round_limit)
                && let Ok(prior_round) = i32::try_from(used)
            {
                let has_recover: bool = sqlx::query_scalar(
                    "SELECT to_regprocedure(
                         'openmettle.quota_recover_unsent_turn_round(uuid,uuid,uuid,integer)'
                     ) IS NOT NULL",
                )
                .fetch_one(tx.connection()?)
                .await?;
                if has_recover {
                    let reusable: bool = sqlx::query_scalar(
                        "SELECT openmettle.quota_recover_unsent_turn_round(
                             $1::uuid, $2::uuid, $3::uuid, $4
                         )",
                    )
                    .bind(&claim.scope_id)
                    .bind(&claim.run_id)
                    .bind(&claim.claim_token)
                    .bind(prior_round)
                    .fetch_one(tx.connection()?)
                    .await?;
                    if reusable {
                        return Ok(used);
                    }
                }
            }
            let round = used + 1;
            if round <= i64::from(claim.round_limit) {
                let bytes: &[u8] = if metered {
                    br#"{"metered":true}"#
                } else {
                    b"{}"
                };
                crate::runs::append_event(
                    tx,
                    &claim.scope_id,
                    &claim.run_id,
                    &format!("model-round:{round}"),
                    Payload {
                        format: "openmettle.model-round",
                        version: 1,
                        bytes,
                    },
                )
                .await?;
            }
            Ok(round)
        }).await.map_err(lease_step)?;
        if number > i64::from(claim.round_limit) {
            Err(StepResult::Failed(FailReason::RoundLimit))
        } else {
            Ok(number)
        }
    }

    async fn persist_turn_calls(
        &self,
        run: &ActiveRun,
        round: i64,
        saved: &SavedCallGroup,
    ) -> Result<(), StepResult> {
        let bytes = serde_json::to_vec(saved).map_err(|_| FAILED)?;
        if bytes.len() > 65_536 {
            return Err(FAILED);
        }
        let mut c = self
            .pool
            .acquire()
            .await
            .map_err(|_| StepResult::LeaseLost)?;
        leases::with_lease(&mut c, &run.claim.lease(), Fence::Step, async |tx, _| {
            crate::runs::append_event(
                tx,
                &run.claim.scope_id,
                &run.claim.run_id,
                &format!("turn-calls:{round}"),
                Payload {
                    format: "openmettle.turn-calls",
                    version: 1,
                    bytes: &bytes,
                },
            )
            .await?;
            Ok(())
        })
        .await
        .map_err(lease_step)
    }

    async fn persist_turn_handoff(
        &self,
        run: &ActiveRun,
        round: i64,
        continuation_rounds: &[i64],
    ) -> Result<(), StepResult> {
        let bytes = serde_json::to_vec(&SavedHandoff {
            continuation_rounds: continuation_rounds.to_vec(),
        })
        .map_err(|_| FAILED)?;
        if bytes.len() > 65_536 {
            return Err(FAILED);
        }
        let mut c = self
            .pool
            .acquire()
            .await
            .map_err(|_| StepResult::LeaseLost)?;
        leases::with_lease(&mut c, &run.claim.lease(), Fence::Step, async |tx, _| {
            crate::runs::append_event(
                tx,
                &run.claim.scope_id,
                &run.claim.run_id,
                &format!("turn-handoff:{round}"),
                Payload {
                    format: "openmettle.turn-handoff",
                    version: 1,
                    bytes: &bytes,
                },
            )
            .await?;
            Ok(())
        })
        .await
        .map_err(lease_step)
    }

    async fn persist_turn_result(
        &self,
        run: &ActiveRun,
        round: i64,
        idx: usize,
        call_id: &str,
        operation_id: Option<&str>,
        output: &str,
    ) -> Result<(), StepResult> {
        let bytes = serde_json::to_vec(&SavedCallResult {
            call_id: call_id.to_owned(),
            operation_id: operation_id.map(str::to_owned),
            output: output.to_owned(),
        })
        .map_err(|_| FAILED)?;
        if bytes.len() > 65_536 {
            return Err(FAILED);
        }
        let mut c = self
            .pool
            .acquire()
            .await
            .map_err(|_| StepResult::LeaseLost)?;
        leases::with_lease(&mut c, &run.claim.lease(), Fence::Step, async |tx, _| {
            crate::runs::append_event(
                tx,
                &run.claim.scope_id,
                &run.claim.run_id,
                &format!("turn-result:{round}:{idx}"),
                Payload {
                    format: "openmettle.turn-result",
                    version: 1,
                    bytes: &bytes,
                },
            )
            .await?;
            Ok(())
        })
        .await
        .map_err(lease_step)
    }

    fn declared_tool_map(
        raw: &[DeclaredTool],
    ) -> Result<std::collections::BTreeMap<String, AdvertisedDeclaration>, StepResult> {
        let mut map = std::collections::BTreeMap::new();
        for dt in raw {
            let decl = AdvertisedDeclaration::from_external_version(dt.external_version.clone());
            if map.insert(dt.tool.name.clone(), decl).is_some() {
                return Err(FAILED);
            }
        }
        Ok(map)
    }

    fn proposal_matches_declaration(
        &self,
        claim: &ClaimedRun,
        effects: &ApprovedEffects,
        call: &Call,
        proposal: &Proposal,
        decl: &AdvertisedDeclaration,
    ) -> bool {
        if proposal.tool != call.name {
            return false;
        }
        match decl {
            AdvertisedDeclaration::Unoffered => false,
            AdvertisedDeclaration::Internal => {
                if proposal.tool == crate::mcp::READ_RANGE {
                    let Ok(expected) = crate::mcp::Registry.proposal(
                        &claim.scope_id,
                        &proposal.logical_key,
                        &call.name,
                        &proposal.version,
                        call.arguments.to_string().as_bytes(),
                    ) else {
                        return false;
                    };
                    expected.arguments() == proposal.arguments()
                        && expected.destination() == proposal.destination()
                } else {
                    effects
                        .adapter
                        .verify_turn_call_proposal(call, proposal, None)
                }
            }
            AdvertisedDeclaration::External { version } => {
                proposal.version == *version
                    && effects.adapter.verify_turn_call_proposal(
                        call,
                        proposal,
                        Some(version.as_str()),
                    )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn tool(
        &self,
        run: &ActiveRun,
        cx: &StepContext,
        config: &ConfigSnapshot,
        call: &Call,
        advertised: &AdvertisedDeclaration,
        prior_effects: &mut Vec<(String, Proposal)>,
        is_open_zero: bool,
    ) -> Result<(String, Option<String>), StepResult> {
        let effects = self.effects.as_deref().ok_or(FAILED)?;
        if let Some(why) = *cx.stop.borrow() {
            return Err(stopped_step(why));
        }
        self.authority(&run.claim, config).await?;
        let refused = || {
            if is_open_zero {
                Err(FAILED)
            } else {
                Ok((crate::mcp::ToolFault::TerminalRefusal.envelope(), None))
            }
        };
        if matches!(advertised, AdvertisedDeclaration::Unoffered) {
            return refused();
        }
        let Some(proposal) = self.routes.proposal(&run.claim, call) else {
            return refused();
        };
        if !self.proposal_matches_declaration(&run.claim, effects, call, &proposal, advertised) {
            return refused();
        }
        let step = StepContext {
            deadline: run.execution_deadline,
            ..cx.clone()
        };
        let preflight = effects.adapter.preflight(run, &proposal, &step).await;
        if let Some(why) = *cx.stop.borrow() {
            return Err(stopped_step(why));
        }
        match preflight {
            Ok(()) => {}
            Err(PreflightError::Transient) => {
                return if is_open_zero {
                    Err(StepResult::Handoff)
                } else {
                    Ok((crate::mcp::ToolFault::Transient.envelope(), None))
                };
            }
            Err(PreflightError::Refused) => return refused(),
            Err(PreflightError::Store(_)) => return Err(StepResult::LeaseLost),
        }
        let intent = {
            let mut c = self.pool.acquire().await.map_err(|_| FAILED)?;
            if let Some(why) = *cx.stop.borrow() {
                return Err(stopped_step(why));
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
                    return refused();
                }
                Err(e) => return Err(lease_step(e)),
            }
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
                if let Some(op_id) = &id {
                    prior_effects.push((op_id.clone(), proposal));
                }
                Ok((output, id))
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
        if request.tools.is_some() || !continuation.is_empty() {
            let bound = self
                .routes
                .tool_prompt_bound(&config.effective, &request)
                .ok_or(FAILED)?;
            if bound > config.effective.usable_input().ok_or(FAILED)? {
                return Err(FAILED);
            }
        }
        let round = self
            .next_round(claim, continuation.is_empty(), route.metered.is_some())
            .await?;
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
        let mut continuation_rounds: Vec<i64> = Vec::new();
        let mut prior_effects: Vec<(String, Proposal)> = Vec::new();
        let mut last_completed_round: i64 = 0;
        // Discover either (a) an open, proven-unsent automatic (`approval_id IS NULL`,
        // `dispatched_attempts = 0`) write intent left by a prior claim that handed off before
        // Transaction 2, or (b) an explicit fenced `turn-handoff:{used}` checkpoint written when
        // pre-round tool verification transiently handed off after a completed round.
        if let Some(effects) = self.effects.as_deref() {
            if let Some(why) = *cx.stop.borrow() {
                return Err(stopped_step(why));
            }
            let has_pending_auto = {
                let mut c = self
                    .pool
                    .acquire()
                    .await
                    .map_err(|_| StepResult::LeaseLost)?;
                approvals::pending_automatic_write(&mut c, &run.claim.lease())
                    .await
                    .map_err(|_| StepResult::LeaseLost)?
                    .is_some()
            };
            let has_turn_handoff = if has_pending_auto {
                false
            } else {
                let mut c = self
                    .pool
                    .acquire()
                    .await
                    .map_err(|_| StepResult::LeaseLost)?;
                leases::with_lease(&mut c, &run.claim.lease(), Fence::Step, async |tx, _| {
                    let conn = tx.connection()?;
                    let used: i64 = sqlx::query_scalar(
                        "SELECT count(*) FROM openmettle.run_events
                          WHERE scope_id=$1::uuid AND run_id=$2::uuid AND format='openmettle.model-round'",
                    )
                    .bind(&run.claim.scope_id)
                    .bind(&run.claim.run_id)
                    .fetch_one(&mut *conn)
                    .await?;
                    if used <= 0 {
                        return Ok(false);
                    }
                    let exists: bool = sqlx::query_scalar(
                        "SELECT EXISTS(
                             SELECT 1 FROM openmettle.run_events
                              WHERE scope_id=$1::uuid AND run_id=$2::uuid
                                AND append_key=$3
                                AND format='openmettle.turn-handoff'
                         )",
                    )
                    .bind(&run.claim.scope_id)
                    .bind(&run.claim.run_id)
                    .bind(format!("turn-handoff:{used}"))
                    .fetch_one(&mut *conn)
                    .await?;
                    Ok(exists)
                })
                .await
                .map_err(lease_step)?
            };
            if has_pending_auto || has_turn_handoff {
                let route_declared = Self::declared_tool_map(
                    &self
                        .routes
                        .declared_tools_for_model(&run.claim, &config.effective),
                )?;
                let (used, expected_rounds, saved_rounds, saved_results, ops_by_key) = {
                    let mut c = self
                        .pool
                        .acquire()
                        .await
                        .map_err(|_| StepResult::LeaseLost)?;
                    leases::with_lease(&mut c, &run.claim.lease(), Fence::Step, async |tx, _| {
                        let conn = tx.connection()?;
                        let used: i64 = sqlx::query_scalar(
                            "SELECT count(*) FROM openmettle.run_events
                              WHERE scope_id=$1::uuid AND run_id=$2::uuid AND format='openmettle.model-round'",
                        )
                        .bind(&run.claim.scope_id)
                        .bind(&run.claim.run_id)
                        .fetch_one(&mut *conn)
                        .await?;
                        if used <= 0 {
                            return Err(crate::runs::Error::Conflict);
                        }
                        let transcript_rows: Vec<(String, i64, String, Vec<u8>)> = sqlx::query_as(
                            "SELECT format, format_version::bigint, append_key, payload
                               FROM openmettle.run_events
                              WHERE scope_id=$1::uuid AND run_id=$2::uuid
                                AND format IN (
                                    'openmettle.turn-handoff',
                                    'openmettle.turn-calls',
                                    'openmettle.turn-result'
                                )",
                        )
                        .bind(&run.claim.scope_id)
                        .bind(&run.claim.run_id)
                        .fetch_all(&mut *conn)
                        .await?;
                        let mut handoff_rows: std::collections::BTreeMap<i64, SavedHandoff> =
                            std::collections::BTreeMap::new();
                        let mut saved_rounds: std::collections::BTreeMap<i64, SavedCallGroup> =
                            std::collections::BTreeMap::new();
                        let mut raw_results: Vec<(String, Vec<u8>)> = Vec::new();
                        for (format, format_version, append_key, bytes) in transcript_rows {
                            if format_version != 1 {
                                return Err(crate::runs::Error::Conflict);
                            }
                            match format.as_str() {
                                "openmettle.turn-handoff" => {
                                    let Some(r_str) = append_key.strip_prefix("turn-handoff:")
                                    else {
                                        return Err(crate::runs::Error::Conflict);
                                    };
                                    let Ok(r) = r_str.parse::<i64>() else {
                                        return Err(crate::runs::Error::Conflict);
                                    };
                                    if r < 1 || r > used || r.to_string() != r_str {
                                        return Err(crate::runs::Error::Conflict);
                                    }
                                    let ho: SavedHandoff = serde_json::from_slice(&bytes)
                                        .map_err(|_| crate::runs::Error::Conflict)?;
                                    if ho.continuation_rounds.is_empty()
                                        || ho.continuation_rounds.last() != Some(&r)
                                    {
                                        return Err(crate::runs::Error::Conflict);
                                    }
                                    if handoff_rows.insert(r, ho).is_some() {
                                        return Err(crate::runs::Error::Conflict);
                                    }
                                }
                                "openmettle.turn-calls" => {
                                    let Some(round_str) = append_key.strip_prefix("turn-calls:")
                                    else {
                                        return Err(crate::runs::Error::Conflict);
                                    };
                                    let Ok(r) = round_str.parse::<i64>() else {
                                        return Err(crate::runs::Error::Conflict);
                                    };
                                    if r < 1 || r > used || r.to_string() != round_str {
                                        return Err(crate::runs::Error::Conflict);
                                    }
                                    let saved: SavedCallGroup = serde_json::from_slice(&bytes)
                                        .map_err(|_| crate::runs::Error::Conflict)?;
                                    if !saved.is_valid_shape(r) {
                                        return Err(crate::runs::Error::Conflict);
                                    }
                                    if saved_rounds.insert(r, saved).is_some() {
                                        return Err(crate::runs::Error::Conflict);
                                    }
                                }
                                "openmettle.turn-result" => {
                                    raw_results.push((append_key, bytes));
                                }
                                _ => return Err(crate::runs::Error::Conflict),
                            }
                        }
                        if has_turn_handoff && !handoff_rows.contains_key(&used) {
                            return Err(crate::runs::Error::Conflict);
                        }
                        let Some(last_group) = saved_rounds.get(&used) else {
                            return Err(crate::runs::Error::Conflict);
                        };
                        let expected_rounds = last_group.continuation_rounds().to_vec();
                        for (&hr, ho) in &handoff_rows {
                            if saved_rounds.get(&hr).map(SavedCallGroup::continuation_rounds)
                                != Some(ho.continuation_rounds.as_slice())
                            {
                                return Err(crate::runs::Error::Conflict);
                            }
                        }
                        if expected_rounds.is_empty()
                            || expected_rounds.last() != Some(&used)
                            || !expected_rounds.iter().all(|&r| r >= 1 && r <= used)
                            || !expected_rounds.windows(2).all(|w| w[0] < w[1])
                            || !saved_rounds.keys().copied().eq(expected_rounds.iter().copied())
                        {
                            return Err(crate::runs::Error::Conflict);
                        }
                        for (idx, &r) in expected_rounds.iter().enumerate() {
                            if saved_rounds[&r].continuation_rounds() != &expected_rounds[..=idx] {
                                return Err(crate::runs::Error::Conflict);
                            }
                        }
                        let mut saved_results: std::collections::BTreeMap<
                            (i64, usize),
                            SavedCallResult,
                        > = std::collections::BTreeMap::new();
                        for (append_key, bytes) in raw_results {
                            let Some(rest) = append_key.strip_prefix("turn-result:") else {
                                return Err(crate::runs::Error::Conflict);
                            };
                            let Some((r_str, idx_str)) = rest.split_once(':') else {
                                return Err(crate::runs::Error::Conflict);
                            };
                            let (Ok(r), Ok(idx)) = (r_str.parse::<i64>(), idx_str.parse::<usize>())
                            else {
                                return Err(crate::runs::Error::Conflict);
                            };
                            if r.to_string() != r_str || idx.to_string() != idx_str {
                                return Err(crate::runs::Error::Conflict);
                            }
                            let Some(SavedCallGroup::Valid { calls, .. }) = saved_rounds.get(&r)
                            else {
                                return Err(crate::runs::Error::Conflict);
                            };
                            if idx >= calls.len() {
                                return Err(crate::runs::Error::Conflict);
                            }
                            let res: SavedCallResult = serde_json::from_slice(&bytes)
                                .map_err(|_| crate::runs::Error::Conflict)?;
                            if res.call_id != calls[idx].id {
                                return Err(crate::runs::Error::Conflict);
                            }
                            if saved_results.insert((r, idx), res).is_some() {
                                return Err(crate::runs::Error::Conflict);
                            }
                        }
                        let op_rows: Vec<(String, String, bool)> = sqlx::query_as(
                            "SELECT id::text, logical_key,
                                    coalesce(
                                        outcome = 'intent'
                                            AND dispatched_attempts = 0
                                            AND approval_id IS NULL,
                                        false
                                    )
                               FROM openmettle.operations
                              WHERE scope_id=$1::uuid AND run_id=$2::uuid",
                        )
                        .bind(&run.claim.scope_id)
                        .bind(&run.claim.run_id)
                        .fetch_all(&mut *conn)
                        .await?;
                        let mut ops_by_key: std::collections::BTreeMap<String, (String, bool)> =
                            std::collections::BTreeMap::new();
                        for (id, logical_key, is_open_zero) in op_rows {
                            ops_by_key.insert(logical_key, (id, is_open_zero));
                        }
                        Ok((
                            used,
                            expected_rounds,
                            saved_rounds,
                            saved_results,
                            ops_by_key,
                        ))
                    })
                    .await
                    .map_err(lease_step)?
                };
                let any_open_zero = ops_by_key.values().any(|(_, open)| *open);
                if has_pending_auto != any_open_zero {
                    return Err(FAILED);
                }
                let mut saved_keys = std::collections::BTreeSet::new();
                for saved in saved_rounds.values() {
                    if let SavedCallGroup::Valid { calls, .. } = saved {
                        for sc in calls {
                            let call = Call {
                                id: sc.id.clone(),
                                name: sc.name.clone(),
                                arguments: sc.arguments.clone(),
                            };
                            if let Some(p) = self.routes.proposal(&run.claim, &call)
                                && self.proposal_matches_declaration(
                                    &run.claim,
                                    effects,
                                    &call,
                                    &p,
                                    &sc.advertised,
                                )
                            {
                                saved_keys.insert(p.logical_key);
                            }
                        }
                    }
                }
                if ops_by_key.keys().any(|k| !saved_keys.contains(k)) {
                    return Err(FAILED);
                }
                let mut saved_rounds = saved_rounds;
                for &r in &expected_rounds {
                    match saved_rounds.remove(&r).ok_or(FAILED)? {
                        SavedCallGroup::Rejected { errors, .. } => {
                            if saved_results.keys().any(|(rr, _)| *rr == r) {
                                return Err(FAILED);
                            }
                            continuation.push(History::RejectedGroup(errors));
                        }
                        SavedCallGroup::Valid {
                            parts,
                            reasoning,
                            calls: saved_calls,
                            ..
                        } => {
                            let call_decls: Vec<(Call, AdvertisedDeclaration)> = saved_calls
                                .into_iter()
                                .map(|c| {
                                    (
                                        Call {
                                            id: c.id,
                                            name: c.name,
                                            arguments: c.arguments,
                                        },
                                        c.advertised,
                                    )
                                })
                                .collect();
                            let must_be_saved = r < used || !has_pending_auto;
                            let mut results = Vec::with_capacity(call_decls.len());
                            for (idx, (call, saved_decl)) in call_decls.iter().enumerate() {
                                let proposal = self.routes.proposal(&run.claim, call);
                                let op_entry = proposal
                                    .as_ref()
                                    .and_then(|p| ops_by_key.get(&p.logical_key));
                                let is_open_zero = op_entry.is_some_and(|(_, open)| *open);
                                if let Some(saved_res) = saved_results.get(&(r, idx)) {
                                    if saved_res.call_id != call.id || is_open_zero {
                                        return Err(FAILED);
                                    }
                                    match (&saved_res.operation_id, op_entry, proposal) {
                                        (Some(op_id), Some((db_id, false)), Some(prop))
                                            if op_id == db_id
                                                && self.proposal_matches_declaration(
                                                    &run.claim, effects, call, &prop, saved_decl,
                                                ) =>
                                        {
                                            prior_effects.push((op_id.clone(), prop));
                                        }
                                        (None, None, _) => {}
                                        _ => return Err(FAILED),
                                    }
                                    results.push((call.id.clone(), saved_res.output.clone()));
                                } else if must_be_saved {
                                    return Err(FAILED);
                                } else {
                                    if saved_results
                                        .range((r, idx + 1)..=(r, usize::MAX))
                                        .next()
                                        .is_some()
                                    {
                                        return Err(FAILED);
                                    }
                                    let effective_decl =
                                        if route_declared.get(&call.name) == Some(saved_decl) {
                                            saved_decl
                                        } else {
                                            &AdvertisedDeclaration::Unoffered
                                        };
                                    let (output, op_id) = self
                                        .tool(
                                            run,
                                            &cx,
                                            &config,
                                            call,
                                            effective_decl,
                                            &mut prior_effects,
                                            is_open_zero,
                                        )
                                        .await?;
                                    self.persist_turn_result(
                                        run,
                                        r,
                                        idx,
                                        &call.id,
                                        op_id.as_deref(),
                                        &output,
                                    )
                                    .await?;
                                    results.push((call.id.clone(), output));
                                }
                            }
                            let calls: Vec<Call> = call_decls.into_iter().map(|(c, _)| c).collect();
                            let reasoning = reasoning.map(|rr| inference::Reasoning {
                                source: Box::new(rr.source),
                                blocks: rr.blocks,
                                storage_bytes: rr.storage_bytes,
                            });
                            continuation.push(History::Assistant {
                                parts,
                                reasoning,
                                calls,
                            });
                            continuation.extend(
                                results
                                    .into_iter()
                                    .map(|(id, output)| History::ToolResult { id, output }),
                            );
                        }
                    }
                }
                let still_pending = {
                    let mut c = self
                        .pool
                        .acquire()
                        .await
                        .map_err(|_| StepResult::LeaseLost)?;
                    approvals::pending_automatic_write(&mut c, &run.claim.lease())
                        .await
                        .map_err(|_| StepResult::LeaseLost)?
                        .is_some()
                };
                if still_pending {
                    return Err(FAILED);
                }
                continuation_rounds = expected_rounds;
                last_completed_round = used;
            }
        }
        loop {
            let (tools, offered_declarations) = if let Some(effects) = self.effects.as_deref() {
                let raw = self
                    .routes
                    .declared_tools_for_model(&run.claim, &config.effective);
                let raw_map = Self::declared_tool_map(&raw)?;
                if raw.is_empty() {
                    (None, std::collections::BTreeMap::new())
                } else {
                    let filter_step = StepContext {
                        deadline: run.execution_deadline,
                        ..cx.clone()
                    };
                    let filtered = tokio::select! {
                        biased;
                        _ = stop.wait_for(Option::is_some) => return Err(StepResult::Stopped),
                        filtered = effects.adapter.filter_turn_tools(run, raw, &filter_step) => {
                            filtered
                        }
                    };
                    let kept = match filtered {
                        Ok(kept) => kept,
                        Err(StepResult::Handoff) => {
                            if !continuation.is_empty() && last_completed_round > 0 {
                                self.persist_turn_handoff(
                                    run,
                                    last_completed_round,
                                    &continuation_rounds,
                                )
                                .await?;
                            }
                            return Err(StepResult::Handoff);
                        }
                        Err(other) => return Err(other),
                    };
                    let mut offered = std::collections::BTreeMap::new();
                    for t in &kept {
                        let Some(decl) = raw_map.get(&t.name) else {
                            return Err(FAILED);
                        };
                        if offered.insert(t.name.clone(), decl.clone()).is_some() {
                            return Err(FAILED);
                        }
                    }
                    ((!kept.is_empty()).then_some(kept), offered)
                }
            } else {
                (None, std::collections::BTreeMap::new())
            };
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
            let turn = if let Some(metered) = &route.metered {
                let billable = crate::provider_http::BillableInferenceRef {
                    installation: &metered.installation,
                    route: &route.gateway,
                };
                // Validate and wire-encode the outbound payload BEFORE reserving or committing a
                // gateway handoff so oversized/invalid payloads never strand handoff_committed holds.
                let mut prepared = billable
                    .prepare(&self.catalog, &config.effective, &request, true)
                    .map_err(inference::Error::step_result)?;
                if let Some(snap_cb) = config.cost_bound
                    && prepared.cost_bound() != Some(snap_cb)
                {
                    return Err(FAILED);
                }
                let round_tokens = prepared.round_tokens().ok_or(FAILED)?;
                let round_cost = prepared.round_cost();
                let cost_bound = prepared.cost_bound();
                let requires_device_slot = prepared.requires_device_slot();
                const MAX_RETRYABLE_RESERVE_ATTEMPTS: u8 = 4;
                const MAX_MISSING_HOLD_HANDOFF_RETRIES: u8 = 2;
                let round_i32 = i32::try_from(round).map_err(|_| FAILED)?;
                let turn_dispatch = {
                    let mut missing_hold_retries: u8 = 0;
                    let mut retryable_attempts: u8 = 0;
                    loop {
                        let pending = match crate::authz::gateway::reserve_turn_round(
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
                                cost_bound,
                                requires_device_slot,
                            },
                        )
                        .await
                        {
                            Ok(pending) => pending,
                            Err(crate::authz::gateway::Error::Retryable)
                                if retryable_attempts < MAX_RETRYABLE_RESERVE_ATTEMPTS =>
                            {
                                if cx.stop.borrow().is_some() {
                                    return Err(StepResult::Stopped);
                                }
                                retryable_attempts += 1;
                                continue;
                            }
                            Err(_) => return Err(FAILED),
                        };
                        if cx.stop.borrow().is_some() {
                            let _ = pending.release(&self.pool).await;
                            return Err(StepResult::Stopped);
                        }
                        match pending
                            .handoff_turn(
                                &self.pool,
                                metered.device_grant_id.as_deref(),
                                &billable,
                                prepared,
                            )
                            .await
                        {
                            Ok(turn_dispatch) => break turn_dispatch,
                            Err(err)
                                if matches!(
                                    err.0,
                                    crate::authz::gateway::TurnHandoffError::MissingHold
                                ) && missing_hold_retries < MAX_MISSING_HOLD_HANDOFF_RETRIES =>
                            {
                                prepared = err.1;
                                if !matches!(pending.release(&self.pool).await, Ok(true)) {
                                    return Err(FAILED);
                                }
                                if cx.stop.borrow().is_some() {
                                    return Err(StepResult::Stopped);
                                }
                                missing_hold_retries += 1;
                            }
                            Err(_) => {
                                let _ = pending.release(&self.pool).await;
                                self.authority(&run.claim, &config).await?;
                                return Err(FAILED);
                            }
                        }
                    }
                };
                let op_id = turn_dispatch.id().to_owned();
                run_observed_inference(
                    run,
                    &op_id,
                    &cx.stop,
                    turn_dispatch.send(RunStop::from_worker(run, cx.stop.clone()), |_| async {}),
                )
                .await?
            } else {
                if cx.stop.borrow().is_some() {
                    return Err(StepResult::Stopped);
                }
                {
                    let mut c = self.pool.acquire().await.map_err(|_| FAILED)?;
                    let has_quota_schema: bool = sqlx::query_scalar(
                        "SELECT to_regclass('openmettle.quota_enforcement') IS NOT NULL",
                    )
                    .fetch_one(&mut *c)
                    .await
                    .map_err(|_| FAILED)?;
                    if has_quota_schema {
                        let has_guard: bool = sqlx::query_scalar(
                            "SELECT to_regprocedure(
                                 'openmettle.quota_authorize_unmetered_turn_round(uuid,uuid,uuid)'
                             ) IS NOT NULL",
                        )
                        .fetch_one(&mut *c)
                        .await
                        .map_err(|_| FAILED)?;
                        if !has_guard {
                            return Err(FAILED);
                        }
                        sqlx::query(
                            "SELECT openmettle.quota_authorize_unmetered_turn_round(
                                 $1::uuid, $2::uuid, $3::uuid
                             )",
                        )
                        .bind(&run.claim.scope_id)
                        .bind(&run.claim.run_id)
                        .bind(&run.claim.claim_token)
                        .execute(&mut *c)
                        .await
                        .map_err(|_| FAILED)?;
                    }
                }
                let op_id = crate::telemetry::RequestId::generate()
                    .map(|id| id.to_string())
                    .unwrap_or_default();
                run_observed_inference(
                    run,
                    &op_id,
                    &cx.stop,
                    route.gateway.server(
                        &self.catalog,
                        &config.effective,
                        &request,
                        Credential::Bearer(&route.bearer),
                        RunStop::from_worker(run, cx.stop.clone()),
                        |_| async {},
                    ),
                )
                .await?
            };
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
                        stop_reason: answer.stop_reason,
                    });
                }
                _ if round >= i64::from(run.claim.round_limit) => {
                    return Err(StepResult::Failed(FailReason::RoundLimit));
                }
                CallGroup::InvalidArguments(errors) => {
                    if self.effects.is_some() {
                        let mut next_rounds = continuation_rounds.clone();
                        next_rounds.push(round);
                        self.persist_turn_calls(
                            run,
                            round,
                            &SavedCallGroup::Rejected {
                                round,
                                continuation_rounds: next_rounds.clone(),
                                errors: errors.clone(),
                            },
                        )
                        .await?;
                        continuation_rounds = next_rounds;
                    }
                    continuation.push(History::RejectedGroup(errors));
                    last_completed_round = round;
                }
                CallGroup::Valid(calls) => {
                    if self.effects.is_some() {
                        let mut next_rounds = continuation_rounds.clone();
                        next_rounds.push(round);
                        let saved = SavedCallGroup::Valid {
                            round,
                            continuation_rounds: next_rounds.clone(),
                            parts: answer.parts.clone(),
                            reasoning: answer.reasoning.as_ref().map(|r| {
                                Box::new(SavedReasoning {
                                    source: (*r.source).clone(),
                                    blocks: r.blocks.clone(),
                                    storage_bytes: r.storage_bytes,
                                })
                            }),
                            calls: calls
                                .iter()
                                .map(|c| SavedCall {
                                    id: c.id.clone(),
                                    name: c.name.clone(),
                                    arguments: c.arguments.clone(),
                                    advertised: offered_declarations
                                        .get(&c.name)
                                        .cloned()
                                        .unwrap_or(AdvertisedDeclaration::Unoffered),
                                })
                                .collect(),
                        };
                        self.persist_turn_calls(run, round, &saved).await?;
                        continuation_rounds = next_rounds;
                    }
                    let mut results = Vec::with_capacity(calls.len());
                    for (idx, call) in calls.iter().enumerate() {
                        let adv = offered_declarations
                            .get(&call.name)
                            .unwrap_or(&AdvertisedDeclaration::Unoffered);
                        let (output, op_id) = self
                            .tool(run, &cx, &config, call, adv, &mut prior_effects, false)
                            .await?;
                        if self.effects.is_some() {
                            self.persist_turn_result(
                                run,
                                round,
                                idx,
                                &call.id,
                                op_id.as_deref(),
                                &output,
                            )
                            .await?;
                        }
                        results.push((call.id.clone(), output));
                    }
                    continuation.push(History::Assistant {
                        parts: answer.parts,
                        reasoning: answer.reasoning,
                        calls,
                    });
                    continuation.extend(
                        results
                            .into_iter()
                            .map(|(id, output)| History::ToolResult { id, output }),
                    );
                    last_completed_round = round;
                }
            }
        }
    }
}

fn inference_operation_outcome<T>(
    result: &Result<T, inference::Error>,
    stop: &watch::Receiver<Option<Stop>>,
) -> WorkerOperationOutcome {
    match result {
        Ok(_) => WorkerOperationOutcome::Ok,
        Err(inference::Error::Stopped(Stop::LeaseLost)) => WorkerOperationOutcome::LeaseLost,
        Err(inference::Error::Stopped(_)) => {
            if *stop.borrow() == Some(Stop::LeaseLost) {
                WorkerOperationOutcome::LeaseLost
            } else {
                WorkerOperationOutcome::Stopped
            }
        }
        Err(_) => WorkerOperationOutcome::Failed,
    }
}

async fn run_observed_inference<T, Fut>(
    run: &ActiveRun,
    op_id: &str,
    stop: &watch::Receiver<Option<Stop>>,
    call: Fut,
) -> Result<T, StepResult>
where
    Fut: std::future::Future<Output = Result<T, inference::Error>>,
{
    let lease_id = derive_run_lease_id(&run.claim.run_id, &run.claim.claim_token);
    let op_span = worker_operation_span(
        &run.claim.run_id,
        &lease_id,
        op_id,
        WorkerOperationKind::Inference,
    );
    let guard_span = op_span.clone();
    async {
        let guard = super::WorkerOperationGuard::new(
            guard_span,
            &run.claim.run_id,
            &lease_id,
            op_id,
            WorkerOperationKind::Inference,
            Some(stop.clone()),
        );
        let raw = call.await;
        let outcome = inference_operation_outcome(&raw, stop);
        let sent = raw.map_err(inference::Error::step_result);
        guard.finish(outcome);
        sent
    }
    .instrument(op_span)
    .await
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

    async fn reconcile(
        &self,
        run: &ActiveRun,
        operation: &UnresolvedOperation,
        cx: StepContext,
    ) -> Option<OwnedObservation> {
        let effects = self.effects.as_ref()?;
        effects
            .adapter
            .reconcile_operation(run, operation, cx)
            .await
    }
}

#[cfg(test)]
#[path = "schema_fixture.rs"]
mod schema_fixture;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model_config::Selection,
        provider_http::{
            Trust,
            fixture::{self, Ca, Reply, Server},
            inference::{Protocol, Qualification, SchemaSubset, Timeouts},
        },
        telemetry::{
            Format, Process, Verbosity,
            tests::{
                Capture,
                otlp::{Collector, attributes, finish, start_traces, text},
            },
        },
    };
    use serde_json::json;

    /// When an inference round returns normally because `RunStop` observed `Stop::LeaseLost`,
    /// `run_observed_inference` must preserve `operation.outcome = "lease_lost"` on both the
    /// exported `worker.operation` span and `worker.operation.completed` event (matching mid-flight
    /// drop semantics) while still returning `Err(StepResult::Stopped)`.
    #[tokio::test]
    async fn inference_return_on_lease_lost_records_lease_lost_outcome() {
        const RUN_ID: &str = "11111111-1111-4111-8111-1111111111aa";
        const OP_ID_LEASE: &str = "22222222-2222-4222-8222-2222222222aa";
        const OP_ID_CANCEL: &str = "22222222-2222-4222-8222-2222222222bb";
        const CLAIM_TOKEN: &str = "33333333-3333-4333-8333-3333333333aa";

        let doc: Value = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/conversation-catalog-v1.json"
        ))
        .unwrap();
        let catalog = Catalog::load(&serde_json::to_vec(&doc).unwrap()).unwrap();
        let effective = catalog
            .resolve(
                &Selection::default(),
                &serde_json::from_value(json!({"preset": "study"})).unwrap(),
                None,
                |_, _| true,
            )
            .unwrap();
        let ca = Ca::new();
        let server =
            Server::start(ca.leaf(fixture::HOST, false), |_| Reply::Stall(Vec::new())).await;
        let mut gateway = Gateway::new(
            &format!(
                "https://{}:{}/v1/chat/completions",
                fixture::HOST,
                server.port
            ),
            Trust::Bundle(&ca.pem()),
            &[],
            Qualification {
                model: effective.model.clone(),
                pin: effective.profile.clone(),
                protocol: Protocol::Chat,
                json: true,
                sse: true,
                functions: Some(SchemaSubset::Nested),
                images: false,
                parallel: true,
                usage: true,
                tool_separator_whitespace: true,
            },
            Timeouts {
                setup: Duration::from_secs(3),
                idle: Duration::from_secs(3),
                overall: Duration::from_secs(6),
            },
        )
        .unwrap();
        gateway.fixture_lookup(Arc::new(fixture::loopback));

        let lease_id = derive_run_lease_id(RUN_ID, CLAIM_TOKEN);
        let run = ActiveRun {
            claim: ClaimedRun {
                scope_id: "44444444-4444-4444-8444-4444444444aa".to_owned(),
                run_id: RUN_ID.to_owned(),
                claim_token: CLAIM_TOKEN.to_owned(),
                actor_approval_id: "55555555-5555-4555-8555-5555555555aa".to_owned(),
                round_limit: 4,
                lease_remaining: Duration::from_secs(30),
                execution_remaining: Duration::from_secs(120),
            },
            state: ExecState::Running,
            execution_deadline: Instant::now() + Duration::from_secs(120),
        };
        let request = Request {
            history: vec![History::User("synthetic prompt".into())],
            tools: None,
            parallel: None,
            stream: true,
        };

        let collector = Collector::accepting().await;
        let (tracer, exporter) = start_traces(collector.destination(), Process::Worker);
        let (capture, sub_guard) = Capture::install_traced(Format::Json, Verbosity::Debug, tracer);

        // 1. Normal return on `Stop::LeaseLost` -> `StepResult::Stopped`, outcome `"lease_lost"`.
        let (tx_lease, rx_lease) = watch::channel(Some(Stop::LeaseLost));
        let _keep_tx = tx_lease;
        let res_lease = run_observed_inference(
            &run,
            OP_ID_LEASE,
            &rx_lease,
            gateway.server(
                &catalog,
                &effective,
                &request,
                Credential::Bearer("synthetic-bearer"),
                RunStop::from_worker(&run, rx_lease.clone()),
                |_| async {},
            ),
        )
        .await;
        assert!(matches!(res_lease, Err(StepResult::Stopped)));

        // 2. Normal return on `Stop::Cancel` -> `StepResult::Stopped`, outcome `"stopped"`.
        let (tx_cancel, rx_cancel) = watch::channel(Some(Stop::Cancel));
        let _keep_tx2 = tx_cancel;
        let res_cancel = run_observed_inference(
            &run,
            OP_ID_CANCEL,
            &rx_cancel,
            gateway.server(
                &catalog,
                &effective,
                &request,
                Credential::Bearer("synthetic-bearer"),
                RunStop::from_worker(&run, rx_cancel.clone()),
                |_| async {},
            ),
        )
        .await;
        assert!(matches!(res_cancel, Err(StepResult::Stopped)));

        drop(sub_guard);
        finish(exporter).await;

        let spans: Vec<_> = collector
            .spans()
            .into_iter()
            .filter(|s| s.name == "worker.operation")
            .collect();
        assert_eq!(spans.len(), 2);

        let events = capture.events("worker.operation.completed");
        assert_eq!(events.len(), 2, "{}", capture.text());

        for (i, (expected_op, expected_outcome)) in
            [(OP_ID_LEASE, "lease_lost"), (OP_ID_CANCEL, "stopped")]
                .into_iter()
                .enumerate()
        {
            let span = &spans[i];
            assert_eq!(span.dropped_attributes_count, 0);
            let attrs = attributes(&span.attributes);
            assert_eq!(text(attrs["run_id"]), Some(RUN_ID));
            assert_eq!(text(attrs["lease_id"]), Some(lease_id.as_str()));
            assert_eq!(text(attrs["operation_id"]), Some(expected_op));
            assert_eq!(text(attrs["operation.kind"]), Some("inference"));
            assert_eq!(text(attrs["operation.outcome"]), Some(expected_outcome));

            let ev = &events[i];
            assert_eq!(ev["run_id"].as_str(), Some(RUN_ID));
            assert_eq!(ev["lease_id"].as_str(), Some(lease_id.as_str()));
            assert_eq!(ev["operation_id"].as_str(), Some(expected_op));
            assert_eq!(ev["operation.kind"].as_str(), Some("inference"));
            assert_eq!(ev["operation.outcome"].as_str(), Some(expected_outcome));
            assert!(ev["duration_us"].as_u64().is_some());
        }

        capture.assert_absent(&[CLAIM_TOKEN.as_bytes()]);
        collector.assert_absent(&[CLAIM_TOKEN.as_bytes()]);
    }
}
