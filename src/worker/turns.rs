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

/// The credential owner resolves this route at dispatch for the admitted actor and scope.
pub struct Route {
    pub gateway: Arc<Gateway>,
    pub bearer: String,
    pub stream: bool,
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
            Ok(_) => Err(StepResult::Invalidated),
            Err(LeaseError::StaleClaim | LeaseError::Expired | LeaseError::Terminal { .. }) => {
                Err(StepResult::Invalidated)
            }
            Err(_) => Err(FAILED),
        }
    }

    /// Reserve the model round before HTTP. A replacement holder cannot reset the round budget.
    async fn next_round(&self, claim: &ClaimedRun, restarting: bool) -> Result<i64, StepResult> {
        let mut c = self.pool.acquire().await.map_err(|_| FAILED)?;
        let number = leases::with_lease(&mut c, &claim.lease(), Fence::Step, async |tx, _| {
            let (used, has_effect): (i64,bool) = sqlx::query_as("SELECT
                (SELECT count(*) FROM openmettle.run_events WHERE run_id=$1::uuid AND format='openmettle.model-round'),
                EXISTS(SELECT FROM openmettle.operations WHERE run_id=$1::uuid)")
                .bind(&claim.run_id).fetch_one(tx.connection()?).await?;
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
        }).await.map_err(|_| FAILED)?;
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
    ) -> Result<String, StepResult> {
        let effects = self.effects.as_deref().ok_or(FAILED)?;
        let proposal = self.routes.proposal(&run.claim, call).ok_or(FAILED)?;
        if proposal.tool != call.name || proposal.arguments() != &call.arguments {
            return Err(FAILED);
        }
        self.authority(&run.claim, config).await?;
        let intent = {
            let mut c = self.pool.acquire().await.map_err(|_| FAILED)?;
            approvals::record_fenced_intent(
                &mut c,
                &run.claim.lease(),
                &proposal,
                None,
                &Some(effects),
                &self.leases,
            )
            .await
            .map_err(|_| FAILED)?
        };
        let IntentResult::Applied(intent) = intent else {
            // No automatic send permit (including human approval required or a replay).
            return Err(FAILED);
        };
        let op = intent.operation_id.clone();
        // This new intent carries a fresh, lease-bounded send deadline. A previous
        // model round may have outlived the initial step snapshot through renewal.
        let mut step = StepContext {
            deadline: run.execution_deadline,
            ..cx.clone()
        };
        let (bytes, deadline) = intent.start(&step).ok_or(FAILED)?;
        step.deadline = deadline;
        let result = timeout_at(deadline, effects.adapter.send(run, op.clone(), bytes, step))
            .await
            .map_err(|_| FAILED)?;
        let StepResult::ToolOutput(output) = result else {
            return Err(FAILED);
        };
        if output.len() > 65536 {
            return Err(FAILED);
        }
        let observed: bool = sqlx::query_scalar(
            "SELECT outcome='succeeded' FROM openmettle.operations
           WHERE scope_id=$1::uuid AND run_id=$2::uuid AND id=$3::uuid",
        )
        .bind(&run.claim.scope_id)
        .bind(&run.claim.run_id)
        .bind(op)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| FAILED)?;
        if observed { Ok(output) } else { Err(FAILED) }
    }

    async fn execute_turn(
        &self,
        run: &ActiveRun,
        cx: StepContext,
    ) -> Result<FinalAnswer, StepResult> {
        let mut continuation = Vec::new();
        let mut tools = self
            .effects
            .as_ref()
            .map(|_| self.routes.tools(&run.claim))
            .filter(|t| !t.is_empty());
        loop {
            let WorkerPrompt {
                actor,
                config,
                mut history,
            } = {
                let mut c = self.pool.acquire().await.map_err(|_| FAILED)?;
                branches::worker_prompt(&mut c, &run.claim, &self.catalog, self.artifacts.as_ref())
                    .await
                    .map_err(|_| FAILED)?
            };
            self.authority(&run.claim, &config).await?;
            let route = self
                .routes
                .route(&run.claim, &actor, &config.effective)
                .await
                .map_err(inference::Error::step_result)?;
            history.extend_from_slice(&continuation);
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
            let round = self.next_round(&run.claim, continuation.is_empty()).await?;
            self.authority(&run.claim, &config).await?;
            let turn = route
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
                .map_err(inference::Error::step_result)?;
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
                    let output = self.tool(run, &cx, &config, call).await?;
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
        let mut stop = cx.stop.clone();
        // The monitor renews the lease while HTTP is open. The gateway applies the hard
        // execution deadline and adapter timeouts; the watch also interrupts DB/route work.
        tokio::select! {
            biased;
            _ = stop.wait_for(Option::is_some) => StepResult::Stopped,
            answer = self.execute_turn(run, cx) => answer.map_or_else(|r|r, StepResult::Answer),
        }
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
