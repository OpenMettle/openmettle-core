//! External scoped MCP adapter, credential seam (V1-28), fault/retry engine (`PLAN-10`), and
//! destination-authorized read-only reconciliation (`Executor::reconcile`, ADR 0039 PR3).

use super::{
    ToolFault,
    contract::{ExternalRegistry, ExternalToolContract, IdempotencyCarrier},
    observe_unknown,
};
use crate::{
    artifact_fs::Store,
    authz::{
        RunContinuation,
        approvals::{self, EffectClass, EndpointKey, Proposal, Review},
        leases::{self, ExecState, Fence, LeaseError, LeaseSettings, UnresolvedOperation},
        runs::{CapabilityUse, RunRecheckRequest, recheck_decision},
        store::StoreError,
    },
    provider_http::mcp::{
        FaultKind, IdempotencyHeader, IdempotencyMeta, McpTransport, RetryAfter, ToolCallRequest,
        ToolCallSuccess, TransportFault,
    },
    worker::{
        ActiveRun, ApprovedAdapter, ApprovedEffects, EffectDispatch, OwnedObservation, StepContext,
        StepResult, Stop, start_permit, stopped_step, turns::lease_step,
    },
};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{Map, Value};
use sqlx::{PgPool, Row};
use std::{collections::BTreeMap, fmt, future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::time::{Instant, sleep_until};

/// Redacted MCP outbound credential. `Debug` never emits secret bytes.
#[derive(Clone)]
pub struct McpCredential {
    bearer: Option<String>,
}

impl McpCredential {
    pub fn bearer(token: impl Into<String>) -> Self {
        Self {
            bearer: Some(token.into()),
        }
    }

    pub fn unauthenticated() -> Self {
        Self { bearer: None }
    }

    pub fn bearer_token(&self) -> Option<&str> {
        self.bearer.as_deref()
    }
}

impl fmt::Debug for McpCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("McpCredential(..)")
    }
}

/// Server-derived lookup context for [`McpCredentialProvider`].
#[derive(Clone, Debug)]
pub struct CredentialRequest<'a> {
    pub connection_id: &'a str,
    pub account_id: &'a str,
    pub scope_id: &'a str,
    pub actor_user_id: &'a str,
}

/// Result of resolving an external MCP credential at dispatch or reconciliation.
#[derive(Debug)]
pub enum CredentialOutcome {
    Ready(McpCredential),
    /// Credential is missing, revoked, or gated (e.g. pending V1-28 vault storage).
    Unavailable,
}

/// Server-side credential lookup seam (production external storage stays gated on V1-28 `#25`).
pub trait McpCredentialProvider: Send + Sync {
    fn resolve<'a>(
        &'a self,
        request: CredentialRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = CredentialOutcome> + Send + 'a>>;
}

/// Fail-closed default credential provider while V1-28 external secret storage is unconfigured.
pub struct GatedCredentialProvider;

impl McpCredentialProvider for GatedCredentialProvider {
    fn resolve<'a>(
        &'a self,
        _request: CredentialRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = CredentialOutcome> + Send + 'a>> {
        Box::pin(async { CredentialOutcome::Unavailable })
    }
}

/// Destination context passed to [`DestinationAuthorizer::authorize_reconcile`] under `Fence::Hold`
/// strictly before any [`McpCredentialProvider`] lookup or outbound read-only reconciliation call.
#[derive(Clone, Debug)]
pub struct ReconcileTarget<'a> {
    pub scope_id: &'a str,
    pub run_id: &'a str,
    pub actor_user_id: &'a str,
    pub connection_id: &'a str,
    pub account_id: &'a str,
    pub tool_id: &'a str,
    pub tool_version: &'a str,
    pub destination: &'a str,
    pub capability: &'a str,
}

/// Live destination authorization seam checked inside `Fence::Hold` before any reconciliation
/// credential lookup or read-only lookup call.
pub trait DestinationAuthorizer: Send + Sync {
    fn authorize_reconcile<'a>(
        &'a self,
        target: ReconcileTarget<'a>,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

/// Call parameters for [`ExternalMcpAdapter::call`].
pub struct ExternalCall<'a> {
    pub key: &'a str,
    pub tool: &'a str,
    pub version: &'a str,
    pub raw_args: &'a [u8],
    pub approval: Option<&'a str>,
}

/// External MCP adapter executing reviewed contracts over [`McpTransport`] with sticky
/// send-uncertainty tracking, durable Transaction 2 retries, and authorized reconciliation.
pub struct ExternalMcpAdapter {
    pool: PgPool,
    settings: LeaseSettings,
    registry: Arc<ExternalRegistry>,
    transports: BTreeMap<String, Arc<McpTransport>>,
    credentials: Arc<dyn McpCredentialProvider>,
    reconcile_auth: Arc<dyn DestinationAuthorizer>,
    artifacts: Option<Store>,
}

impl ExternalMcpAdapter {
    pub fn new(
        pool: PgPool,
        settings: LeaseSettings,
        registry: Arc<ExternalRegistry>,
        transports: BTreeMap<String, Arc<McpTransport>>,
        credentials: Arc<dyn McpCredentialProvider>,
        reconcile_auth: Arc<dyn DestinationAuthorizer>,
    ) -> Self {
        Self {
            pool,
            settings,
            registry,
            transports,
            credentials,
            reconcile_auth,
            artifacts: None,
        }
    }

    pub fn with_artifacts(mut self, store: Store) -> Self {
        store.attach(&self.pool);
        self.artifacts = Some(store);
        self
    }

    pub fn approved_effects(self: &Arc<Self>) -> ApprovedEffects {
        ApprovedEffects {
            policy: self.registry.clone(),
            adapter: self.clone(),
        }
    }

    /// Execute a reviewed external MCP call through the two-phase effect ledger.
    ///
    /// Fails closed with zero `operations` rows when `two_phase_effect_intents_enabled = false`,
    /// the proposal violates the reviewed contract, the connection transport is unconfigured, or
    /// the credential provider reports [`CredentialOutcome::Unavailable`].
    pub async fn call(
        self: &Arc<Self>,
        run: &ActiveRun,
        step: StepContext,
        call: ExternalCall<'_>,
    ) -> StepResult {
        let ExternalCall {
            key,
            tool,
            version,
            raw_args,
            approval,
        } = call;
        let refused = || StepResult::ToolOutput(ToolFault::TerminalRefusal.envelope());
        let Some(contract) = self.registry.get(tool, version) else {
            return refused();
        };
        if !self.transports.contains_key(&contract.connection_id) {
            return refused();
        }
        let Ok(proposal) = contract.proposal(key, raw_args) else {
            return refused();
        };
        if let Some(stop) = *step.stop.borrow() {
            return stopped_step(stop);
        }
        let (two_phase_enabled, actor_user_id) = {
            let Ok(mut c) = self.pool.acquire().await else {
                return StepResult::LeaseLost;
            };
            let Ok(enabled) = approvals::two_phase_effect_intents_enabled(&mut c).await else {
                return StepResult::LeaseLost;
            };
            if !enabled {
                return refused();
            }
            let Ok(actor) = sqlx::query_scalar::<_, String>(
                "SELECT actor_user_id::text FROM openmettle.runs WHERE scope_id=$1::uuid AND id=$2::uuid",
            )
            .bind(&run.claim.scope_id)
            .bind(&run.claim.run_id)
            .fetch_one(&mut *c)
            .await
            else {
                return StepResult::LeaseLost;
            };
            (enabled, actor)
        };
        if !two_phase_enabled {
            return refused();
        }
        // Fail closed before Transaction 1 (zero `operations` rows) when credential is unavailable.
        if matches!(
            self.credentials
                .resolve(CredentialRequest {
                    connection_id: &contract.connection_id,
                    account_id: &contract.account_id,
                    scope_id: &run.claim.scope_id,
                    actor_user_id: &actor_user_id,
                })
                .await,
            CredentialOutcome::Unavailable
        ) {
            return refused();
        }
        if let Some(stop) = *step.stop.borrow() {
            return stopped_step(stop);
        }
        let intent = {
            let Ok(mut c) = self.pool.acquire().await else {
                return StepResult::LeaseLost;
            };
            match approvals::record_fenced_intent(
                &mut c,
                &run.claim.lease(),
                &proposal,
                approval,
                self.registry.as_ref(),
                &self.settings,
            )
            .await
            {
                Ok(intent) => intent,
                Err(LeaseError::Store(StoreError::Denied(_) | StoreError::InvalidInput(_))) => {
                    return refused();
                }
                Err(e) => return lease_step(e),
            }
        };
        let effects = self.approved_effects();
        EffectDispatch {
            pool: &self.pool,
            artifacts: self.artifacts.as_ref(),
            effects: &effects,
            settings: &self.settings,
        }
        .send(run, &proposal, intent, step)
        .await
    }

    /// Destination-authorized read-only reconciliation for `Executor::reconcile` (ADR 0039 PR3).
    ///
    /// - Excludes `repeatable_read` and never re-sends a write.
    /// - Proven-unsent `outcome == "intent" && dispatched_attempts == Some(0)` returns a terminal
    ///   `outcome = "failed"` observation with zero credential lookups and zero HTTP calls.
    /// - For `dispatched_attempts.is_none() || dispatched_attempts >= Some(1)`, verifies BOTH
    ///   `recheck_decision` and [`DestinationAuthorizer::authorize_reconcile`] inside `Fence::Hold`
    ///   strictly before any [`McpCredentialProvider`] lookup or read-only HTTP call.
    /// - `non_repeatable` writes and `lookup` writes lacking both `downstream_handle` and a
    ///   deterministic contract lookup return `outcome = "outcome_unknown"` with zero lookups and
    ///   zero HTTP calls.
    pub async fn reconcile_operation(
        &self,
        run: &ActiveRun,
        op: &UnresolvedOperation,
        mut step: StepContext,
    ) -> Option<OwnedObservation> {
        if op.capability == "repeatable_read"
            || !matches!(op.outcome.as_str(), "intent" | "outcome_unknown")
        {
            return None;
        }
        if op.outcome == "intent" && op.dispatched_attempts == Some(0) {
            return Some(OwnedObservation {
                key: format!("reconciled-unsent:{}", op.id),
                outcome: "failed".into(),
                handle: None,
                format: "openmettle.unsent-write".into(),
                version: 1,
                evidence: br#"{"reason":"unsent_write_intent"}"#.to_vec(),
            });
        }
        if step.stop.borrow().is_some() || Instant::now() >= step.deadline {
            return None;
        }
        let lease = run.claim.lease();
        let (proposal, review, actor_user_id, conversation_id) = {
            let mut c = self.pool.acquire().await.ok()?;
            leases::with_lease(&mut c, &lease, Fence::Hold, async |tx, held| {
                if held.state != ExecState::Reconciling {
                    return Ok(None);
                }
                let conn = tx.connection()?;
                let row = sqlx::query(
                    "SELECT r.actor_user_id::text, r.conversation_id::text, o.request, o.outcome, o.dispatched_attempts
                       FROM openmettle.runs r
                       JOIN openmettle.operations o
                         ON o.scope_id = r.scope_id AND o.run_id = r.id
                      WHERE r.scope_id = $1::uuid AND r.id = $2::uuid AND o.id = $3::uuid",
                )
                .bind(lease.scope_id)
                .bind(lease.run_id)
                .bind(&op.id)
                .fetch_optional(&mut *conn)
                .await?;
                let Some(row) = row else {
                    return Ok(None);
                };
                let actor_user_id: String = row.try_get("actor_user_id")?;
                let conversation_id: String = row.try_get("conversation_id")?;
                let bytes: Vec<u8> = row.try_get("request")?;
                let Ok((proposal, review)) = approvals::parse_effect_envelope(&bytes) else {
                    return Ok(None);
                };
                Ok(Some((proposal, review, actor_user_id, conversation_id)))
            })
            .await
            .ok()??
        };
        let contract = self.registry.get(&proposal.tool, &proposal.version);

        // Non-repeatable writes and lookup/idempotent writes without any reconcilable lookup query
        // resolve deterministically to `outcome_unknown` with zero credential lookups and zero HTTP.
        let lookup_plan = contract
            .and_then(|c| build_reconcile_lookup(c, op, &proposal, &review).map(|args| (c, args)));
        let Some((contract, (lookup_tool, lookup_args))) = lookup_plan else {
            return Some(OwnedObservation {
                key: format!("reconcile-unknown:{}", op.id),
                outcome: "outcome_unknown".into(),
                handle: op.downstream_handle.clone(),
                format: "openmettle.unresolved-write".into(),
                version: 1,
                evidence: br#"{"reason":"no_authoritative_lookup"}"#.to_vec(),
            });
        };

        // Check BOTH `recheck_decision` AND live destination read/reconcile authorization inside
        // `Fence::Hold` strictly BEFORE any `McpCredentialProvider` lookup or outbound HTTP call.
        let authorized = {
            let mut c = self.pool.acquire().await.ok()?;
            let capabilities = [CapabilityUse {
                name: &review.capability,
                gate: review.gate,
            }];
            let target = ReconcileTarget {
                scope_id: &run.claim.scope_id,
                run_id: &run.claim.run_id,
                actor_user_id: &actor_user_id,
                connection_id: &contract.connection_id,
                account_id: &contract.account_id,
                tool_id: &contract.tool_id,
                tool_version: &contract.version,
                destination: proposal.destination(),
                capability: &op.capability,
            };
            let reconcile_auth = self.reconcile_auth.clone();
            leases::with_lease(&mut c, &lease, Fence::Hold, async |tx, held| {
                if held.state != ExecState::Reconciling {
                    return Ok(false);
                }
                let conn = tx.connection()?;
                let now_ms: i64 = sqlx::query_scalar(
                    "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint",
                )
                .fetch_one(&mut *conn)
                .await?;
                let check = RunRecheckRequest {
                    scope_id: &run.claim.scope_id,
                    run_id: &run.claim.run_id,
                    actor_approval_id: &run.claim.actor_approval_id,
                    capabilities: &capabilities,
                    extra_target: None,
                    now_ms,
                };
                if !matches!(
                    recheck_decision(conn, &check, &actor_user_id, &conversation_id).await,
                    Ok(RunContinuation::Continue)
                ) {
                    return Ok(false);
                }
                Ok(reconcile_auth.authorize_reconcile(target).await)
            })
            .await
            .unwrap_or(false)
        };
        if !authorized {
            return None;
        }
        let transport = self.transports.get(&contract.connection_id)?;
        let CredentialOutcome::Ready(credential) = self
            .credentials
            .resolve(CredentialRequest {
                connection_id: &contract.connection_id,
                account_id: &contract.account_id,
                scope_id: &run.claim.scope_id,
                actor_user_id: &actor_user_id,
            })
            .await
        else {
            return None;
        };
        let req_id = format!("reconcile:{}", op.id);
        let call_deadline = step.deadline.min(Instant::now() + contract.call_timeout);
        let response = transport
            .tools_call(
                &ToolCallRequest {
                    request_id: &req_id,
                    tool_name: &lookup_tool,
                    arguments: &lookup_args,
                    bearer_token: credential.bearer_token(),
                    idempotency_header: None,
                    idempotency_meta: None,
                },
                call_deadline,
                &mut step.stop,
            )
            .await
            .ok()?;
        let reconcile_spec = contract.reconcile.as_ref()?;
        let status = extract_reconcile_status(&response, &reconcile_spec.status_field)?;
        let handle = extract_downstream_handle(&response, contract.handle_field.as_deref())
            .or_else(|| op.downstream_handle.clone());
        match status.as_str() {
            "succeeded" => Some(OwnedObservation {
                key: format!("reconciled:{}", op.id),
                outcome: "succeeded".into(),
                handle,
                format: "openmettle.reconciled-write".into(),
                version: 1,
                evidence: br#"{"status":"succeeded"}"#.to_vec(),
            }),
            "failed" | "not_found" => Some(OwnedObservation {
                key: format!("reconciled:{}", op.id),
                outcome: "failed".into(),
                handle,
                format: "openmettle.reconciled-write".into(),
                version: 1,
                evidence: br#"{"status":"failed"}"#.to_vec(),
            }),
            _ => None,
        }
    }
}

fn build_reconcile_lookup(
    contract: &ExternalToolContract,
    op: &UnresolvedOperation,
    proposal: &Proposal,
    review: &Review,
) -> Option<(String, Value)> {
    if op.capability == "non_repeatable" {
        return None;
    }
    let spec = contract.reconcile.as_ref()?;
    let mut args = Map::new();
    if let (Some(field), Some(handle)) = (&spec.handle_argument, &op.downstream_handle) {
        args.insert(field.clone(), Value::String(handle.clone()));
        return Some((spec.lookup_tool.clone(), Value::Object(args)));
    }
    if let Some(field) = &spec.deterministic_key_argument {
        let key = match &review.endpoint_key {
            EndpointKey::Supported { key, .. } => key.as_str(),
            _ => proposal.logical_key.as_str(),
        };
        args.insert(field.clone(), Value::String(key.to_owned()));
        return Some((spec.lookup_tool.clone(), Value::Object(args)));
    }
    None
}

fn extract_reconcile_status(response: &ToolCallSuccess, field: &str) -> Option<String> {
    if let Some(s) = response
        .structured
        .as_ref()
        .and_then(|v| v.as_object())
        .and_then(|m| m.get(field))
        .and_then(Value::as_str)
    {
        return Some(s.to_owned());
    }
    let parsed: Value = serde_json::from_str(&response.text).ok()?;
    parsed.as_object()?.get(field)?.as_str().map(str::to_owned)
}

fn extract_downstream_handle(response: &ToolCallSuccess, field: Option<&str>) -> Option<String> {
    let field = field?;
    let candidate = response
        .structured
        .as_ref()
        .and_then(|v| v.as_object())
        .and_then(|m| m.get(field))
        .and_then(Value::as_str)?;
    if candidate.is_empty()
        || candidate.len() > 256
        || !candidate.bytes().all(|b| b.is_ascii_graphic())
    {
        return None;
    }
    Some(candidate.to_owned())
}

impl ApprovedAdapter for ExternalMcpAdapter {
    fn send<'a>(
        &'a self,
        run: &'a ActiveRun,
        operation_id: String,
        request: Vec<u8>,
        mut step: StepContext,
    ) -> Pin<Box<dyn Future<Output = StepResult> + Send + 'a>> {
        Box::pin(async move {
            let lease = run.claim.lease();
            let Ok((proposal, review)) = approvals::parse_effect_envelope(&request) else {
                return StepResult::Failed(leases::FailReason::StepFailed);
            };
            let Some(contract) = self.registry.get(&proposal.tool, &proposal.version) else {
                return StepResult::ToolResponse(Err(ToolFault::TerminalRefusal));
            };
            let Some(transport) = self.transports.get(&contract.connection_id) else {
                return StepResult::ToolResponse(Err(ToolFault::TerminalRefusal));
            };
            let actor_user_id = {
                let Ok(mut c) = self.pool.acquire().await else {
                    return StepResult::LeaseLost;
                };
                let Ok(actor) = sqlx::query_scalar::<_, String>(
                    "SELECT actor_user_id::text FROM openmettle.runs WHERE scope_id=$1::uuid AND id=$2::uuid",
                )
                .bind(lease.scope_id)
                .bind(lease.run_id)
                .fetch_one(&mut *c)
                .await
                else {
                    return StepResult::LeaseLost;
                };
                actor
            };

            let is_read = review.class == EffectClass::Read;
            let capability = review.capability_class();
            let mut attempt: u32 = 1;
            let mut backoff_ms: u64 = 250;
            // Sticky across every attempt: once ANY request byte may have left the process,
            // `sent_uncertain` stays true so later pre-send errors or refusals never misclassify
            // an uncertain write as a known failure.
            let mut sent_uncertain = false;
            let mut prior_attempt_ambiguous = false;

            loop {
                let CredentialOutcome::Ready(credential) = self
                    .credentials
                    .resolve(CredentialRequest {
                        connection_id: &contract.connection_id,
                        account_id: &contract.account_id,
                        scope_id: lease.scope_id,
                        actor_user_id: &actor_user_id,
                    })
                    .await
                else {
                    return if !is_read && sent_uncertain {
                        observe_unknown(&self.pool, &lease, &step, &operation_id).await
                    } else {
                        StepResult::ToolResponse(Err(ToolFault::TerminalRefusal))
                    };
                };

                let (idem_header, idem_meta) =
                    idempotency_wire_fields(contract, &review.endpoint_key);
                let req_id = format!("{operation_id}:{attempt}");
                let call_deadline = step.deadline.min(Instant::now() + contract.call_timeout);
                let call_result = transport
                    .tools_call(
                        &ToolCallRequest {
                            request_id: &req_id,
                            tool_name: &contract.remote_name,
                            arguments: proposal.arguments(),
                            bearer_token: credential.bearer_token(),
                            idempotency_header: idem_header,
                            idempotency_meta: idem_meta,
                        },
                        call_deadline,
                        &mut step.stop,
                    )
                    .await;

                match call_result {
                    Ok(success) => {
                        let handle =
                            extract_downstream_handle(&success, contract.handle_field.as_deref());
                        return StepResult::ToolSuccess {
                            text: success.text,
                            handle,
                        };
                    }
                    Err(TransportFault {
                        kind: FaultKind::Stopped(why),
                        bytes_may_have_left,
                    }) => {
                        if bytes_may_have_left {
                            sent_uncertain = true;
                        }
                        if why == Stop::LeaseLost {
                            return StepResult::LeaseLost;
                        }
                        if !is_read && sent_uncertain {
                            return observe_unknown(&self.pool, &lease, &step, &operation_id).await;
                        }
                        return stopped_step(why);
                    }
                    Err(TransportFault {
                        kind: FaultKind::Semantic { is_tool_error },
                        bytes_may_have_left,
                    }) => {
                        let known_safe = is_read
                            || !bytes_may_have_left
                            || (!prior_attempt_ambiguous
                                && (!is_tool_error
                                    || contract.semantic_errors_are_side_effect_free));
                        if known_safe {
                            return StepResult::ToolResponse(Err(ToolFault::Semantic));
                        }
                        return observe_unknown(&self.pool, &lease, &step, &operation_id).await;
                    }
                    Err(TransportFault {
                        kind: FaultKind::TerminalRefusal,
                        bytes_may_have_left,
                    }) => {
                        if bytes_may_have_left {
                            sent_uncertain = true;
                        }
                        if !is_read && sent_uncertain {
                            return observe_unknown(&self.pool, &lease, &step, &operation_id).await;
                        }
                        return StepResult::ToolResponse(Err(ToolFault::TerminalRefusal));
                    }
                    Err(TransportFault {
                        kind: FaultKind::Transient(retry_after),
                        bytes_may_have_left,
                    }) => {
                        if bytes_may_have_left {
                            sent_uncertain = true;
                            prior_attempt_ambiguous = true;
                        }
                        // Determine whether another attempt is permitted by the contract.
                        let retry_allowed = match capability {
                            "repeatable_read" | "idempotent" => attempt < 3,
                            // `lookup` and `non_repeatable` writes retry ONLY proven pre-send
                            // failures and NEVER after any request byte may have left.
                            "lookup" | "non_repeatable" => !sent_uncertain && attempt < 3,
                            _ => false,
                        };
                        if !retry_allowed || retry_after == RetryAfter::TooLong {
                            if !is_read && sent_uncertain {
                                return observe_unknown(&self.pool, &lease, &step, &operation_id)
                                    .await;
                            }
                            return StepResult::ToolResponse(Err(ToolFault::Transient));
                        }
                        let delay = match retry_after {
                            RetryAfter::Seconds(secs) => Duration::from_secs(secs),
                            RetryAfter::None => full_jitter(backoff_ms),
                            RetryAfter::TooLong => unreachable!(),
                        };
                        backoff_ms = 500;
                        let wake = Instant::now() + delay;
                        if wake >= step.deadline {
                            if !is_read && sent_uncertain {
                                return observe_unknown(&self.pool, &lease, &step, &operation_id)
                                    .await;
                            }
                            return StepResult::ToolResponse(Err(ToolFault::Transient));
                        }
                        let stopped = tokio::select! {
                            biased;
                            waited = step.stop.wait_for(Option::is_some) => {
                                Some(waited.ok().and_then(|v| *v).unwrap_or(Stop::LeaseLost))
                            }
                            _ = sleep_until(wake) => None,
                        };
                        if let Some(why) = stopped {
                            if why == Stop::LeaseLost {
                                return StepResult::LeaseLost;
                            }
                            if !is_read && sent_uncertain {
                                return observe_unknown(&self.pool, &lease, &step, &operation_id)
                                    .await;
                            }
                            return stopped_step(why);
                        }

                        // Acquire a fresh Transaction 2 permit (`dispatched_attempts` increment +
                        // live `{AUTH}` + `effective_expires_us` check) before every retry send.
                        let Ok(mut c) = self.pool.acquire().await else {
                            return StepResult::LeaseLost;
                        };
                        let permit = if is_read {
                            approvals::start_replayed_read(
                                &mut c,
                                &lease,
                                &operation_id,
                                &proposal,
                                &self.settings,
                                self.registry.as_ref(),
                            )
                            .await
                        } else {
                            approvals::start_write_retry(
                                &mut c,
                                &lease,
                                &operation_id,
                                &proposal,
                                &self.settings,
                                self.registry.as_ref(),
                            )
                            .await
                        };
                        let checked = start_permit(
                            &mut c,
                            &lease,
                            (&operation_id, &proposal),
                            &self.settings,
                            self.registry.as_ref(),
                            &mut step,
                            permit,
                        )
                        .await;
                        drop(c);
                        if let Err(step_result) = checked {
                            // If a write had already sent uncertain bytes and the retry failed
                            // exhaustion or handoff (not LeaseLost/Invalidated), commit outcome_unknown.
                            if !is_read
                                && sent_uncertain
                                && matches!(step_result, StepResult::Stopped | StepResult::Handoff)
                            {
                                return observe_unknown(&self.pool, &lease, &step, &operation_id)
                                    .await;
                            }
                            return step_result;
                        }
                        attempt += 1;
                    }
                }
            }
        })
    }
}

fn idempotency_wire_fields<'a>(
    contract: &'a ExternalToolContract,
    endpoint_key: &'a EndpointKey,
) -> (Option<IdempotencyHeader<'a>>, Option<IdempotencyMeta<'a>>) {
    let (Some(idem), EndpointKey::Supported { key, .. }) = (&contract.idempotency, endpoint_key)
    else {
        return (None, None);
    };
    match &idem.carrier {
        IdempotencyCarrier::Header(name) => (
            Some(IdempotencyHeader {
                name: name.as_str(),
                value: key.as_str(),
            }),
            None,
        ),
        IdempotencyCarrier::Meta(field) => (
            None,
            Some(IdempotencyMeta {
                field: field.as_str(),
                value: key.as_str(),
            }),
        ),
        IdempotencyCarrier::None => (None, None),
    }
}

fn full_jitter(max_ms: u64) -> Duration {
    let mut bytes = [0u8; 2];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        return Duration::from_millis(max_ms);
    }
    Duration::from_millis(u64::from(u16::from_be_bytes(bytes)) % (max_ms + 1))
}
