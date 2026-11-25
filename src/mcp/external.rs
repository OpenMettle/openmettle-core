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
        DenialReason, PolicyReason, RunContinuation,
        approvals::{self, EffectClass, EffectPolicy, EndpointKey, Proposal, Review},
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
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
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
    verified_catalogs: Mutex<BTreeSet<(String, String, [u8; 32])>>,
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
            verified_catalogs: Mutex::new(BTreeSet::new()),
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

    async fn admit_pre_intent(
        &self,
        run: &ActiveRun,
        proposal: &Proposal,
        step: &StepContext,
    ) -> Result<(), StoreError> {
        const REFUSED: StoreError =
            StoreError::Denied(DenialReason::Policy(PolicyReason::CapabilityDenied));
        let Some(contract) = self.registry.get(&proposal.tool, &proposal.version) else {
            return Err(REFUSED);
        };
        let Some(transport) = self.transports.get(&contract.connection_id) else {
            return Err(REFUSED);
        };
        let Some(fingerprint) = self
            .registry
            .connection_fingerprint(&contract.connection_id)
        else {
            return Err(REFUSED);
        };
        let Ok(expected) = contract.proposal(
            &proposal.logical_key,
            proposal.arguments().to_string().as_bytes(),
        ) else {
            return Err(REFUSED);
        };
        if expected.arguments() != proposal.arguments()
            || expected.destination() != proposal.destination()
        {
            return Err(REFUSED);
        }
        if step.stop.borrow().is_some() {
            return Err(REFUSED);
        }
        let actor_user_id = {
            let mut c = self.pool.acquire().await?;
            if !approvals::two_phase_effect_intents_enabled(&mut c).await? {
                return Err(REFUSED);
            }
            sqlx::query_scalar::<_, String>(
                "SELECT actor_user_id::text FROM openmettle.runs WHERE scope_id=$1::uuid AND id=$2::uuid",
            )
            .bind(&run.claim.scope_id)
            .bind(&run.claim.run_id)
            .fetch_one(&mut *c)
            .await?
        };
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
            return Err(REFUSED);
        };
        let cache_key = (
            contract.connection_id.clone(),
            contract.account_id.clone(),
            fingerprint,
        );
        let already_verified = self
            .verified_catalogs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&cache_key);
        if !already_verified {
            let mut stop = step.stop.clone();
            let list_deadline = step.deadline.min(Instant::now() + contract.call_timeout);
            let req_id = format!("tools-list:{}", run.claim.run_id);
            let remote = transport
                .tools_list(&req_id, credential.bearer_token(), list_deadline, &mut stop)
                .await
                .map_err(|_| REFUSED)?;
            self.registry
                .verify_tools_list(&contract.connection_id, &remote)
                .map_err(|_| REFUSED)?;
            self.verified_catalogs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(cache_key);
        }
        Ok(())
    }

    /// Execute a reviewed external MCP call through the two-phase effect ledger.
    ///
    /// Fails closed with zero `operations` rows when `two_phase_effect_intents_enabled = false`,
    /// the proposal violates the reviewed contract, the connection transport is unconfigured,
    /// upstream `tools/list` drifts from the pinned contracts, or the credential provider reports
    /// [`CredentialOutcome::Unavailable`].
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
        let Ok(proposal) = contract.proposal(key, raw_args) else {
            return refused();
        };
        if let Some(stop) = *step.stop.borrow() {
            return stopped_step(stop);
        }
        let preflight = self.admit_pre_intent(run, &proposal, &step).await;
        if let Some(stop) = *step.stop.borrow() {
            return stopped_step(stop);
        }
        match preflight {
            Ok(()) => {}
            Err(StoreError::Denied(_) | StoreError::InvalidInput(_)) => return refused(),
            Err(_) => return StepResult::LeaseLost,
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
        if op.target != proposal.destination() {
            return None;
        }
        let (committed_conn, committed_acct, committed_action, _committed_resource) =
            parse_committed_destination(proposal.destination())?;
        let contract = self.registry.get(&proposal.tool, &proposal.version)?;
        if !contract_matches_committed(
            self.registry.as_ref(),
            run,
            contract,
            &proposal,
            &review,
            &committed_conn,
            &committed_acct,
            &committed_action,
        ) {
            return None;
        }

        // Non-repeatable writes and lookup/idempotent writes without any reconcilable lookup query
        // resolve deterministically to `outcome_unknown` with zero credential lookups and zero HTTP.
        let Some((lookup_tool, lookup_args)) =
            build_reconcile_lookup(contract, op, &proposal, &review)
        else {
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
        let remote_handle = extract_downstream_handle(&response, contract.handle_field.as_deref());
        let handle = match (&op.downstream_handle, remote_handle) {
            // Never overwrite an already-recorded downstream handle with a conflicting one.
            (Some(existing), Some(remote)) if remote != *existing => return None,
            (Some(existing), _) => Some(existing.clone()),
            (None, remote) => remote,
        };
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

fn parse_committed_destination(destination: &str) -> Option<(String, String, String, String)> {
    let Value::Array(items) = serde_json::from_str(destination).ok()? else {
        return None;
    };
    if items.len() != 5 || items[0].as_str() != Some("v1") {
        return None;
    }
    Some((
        items[1].as_str()?.to_owned(),
        items[2].as_str()?.to_owned(),
        items[3].as_str()?.to_owned(),
        items[4].as_str()?.to_owned(),
    ))
}

fn endpoint_key_matches(current: &EndpointKey, committed: &EndpointKey) -> bool {
    match (current, committed) {
        (EndpointKey::Unsupported, EndpointKey::Unsupported) => true,
        (
            EndpointKey::Supported {
                namespace: cn,
                field: cf,
                key: ck,
                ..
            },
            EndpointKey::Supported {
                namespace: mn,
                field: mf,
                key: mk,
                ..
            },
        ) => cn == mn && cf == mf && ck == mk,
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn contract_matches_committed(
    registry: &ExternalRegistry,
    run: &ActiveRun,
    contract: &ExternalToolContract,
    proposal: &Proposal,
    committed_review: &Review,
    committed_conn: &str,
    committed_acct: &str,
    committed_action: &str,
) -> bool {
    if contract.connection_id != committed_conn
        || contract.account_id != committed_acct
        || contract.action != committed_action
        || contract.endpoint_id != committed_review.endpoint_id
        || contract.endpoint_version != committed_review.endpoint_version
        || contract.capability != committed_review.capability
    {
        return false;
    }
    let Ok(Some(current_review)) =
        registry.review(&run.claim.scope_id, &run.claim.run_id, proposal)
    else {
        return false;
    };
    current_review.endpoint_id == committed_review.endpoint_id
        && current_review.endpoint_version == committed_review.endpoint_version
        && current_review.destination_policy == committed_review.destination_policy
        && current_review.tool_policy == committed_review.tool_policy
        && current_review.capability == committed_review.capability
        && current_review.gate == committed_review.gate
        && current_review.class == committed_review.class
        && current_review.authoritative_lookup == committed_review.authoritative_lookup
        && endpoint_key_matches(&current_review.endpoint_key, &committed_review.endpoint_key)
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

fn sanitize_tool_success(
    success: &ToolCallSuccess,
    handle_field: Option<&str>,
) -> (String, Option<String>) {
    let handle = extract_downstream_handle(success, handle_field);
    let raw_text = if let Some(text) = &success.content_text {
        text.clone()
    } else if let Some(structured) = &success.structured {
        let mut sanitized = structured.clone();
        if let (Some(field), Some(map)) = (handle_field, sanitized.as_object_mut()) {
            map.remove(field);
        }
        sanitized.sort_all_objects();
        sanitized.to_string()
    } else {
        success.text.clone()
    };
    let text = match handle.as_deref() {
        Some(h) => raw_text.replace(h, "[REDACTED]"),
        None => raw_text,
    };
    (text, handle)
}

impl ApprovedAdapter for ExternalMcpAdapter {
    fn preflight<'a>(
        &'a self,
        run: &'a ActiveRun,
        proposal: &'a Proposal,
        step: &'a StepContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + 'a>> {
        Box::pin(async move { self.admit_pre_intent(run, proposal, step).await })
    }

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
            // Whole logical tool call budget across all attempts and retry backoffs (PLAN-10).
            let logical_call_deadline = step.deadline.min(Instant::now() + contract.call_timeout);

            loop {
                let call_deadline = logical_call_deadline.min(step.deadline);
                if Instant::now() >= call_deadline {
                    return if !is_read && sent_uncertain {
                        observe_unknown(&self.pool, &lease, &step, &operation_id).await
                    } else {
                        StepResult::ToolResponse(Err(ToolFault::Transient))
                    };
                }
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
                        let (text, handle) =
                            sanitize_tool_success(&success, contract.handle_field.as_deref());
                        return StepResult::ToolSuccess { text, handle };
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
                        let effective_deadline = logical_call_deadline.min(step.deadline);
                        if wake >= effective_deadline {
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
                        if Instant::now() >= logical_call_deadline.min(step.deadline) {
                            if !is_read && sent_uncertain {
                                return observe_unknown(&self.pool, &lease, &step, &operation_id)
                                    .await;
                            }
                            return StepResult::ToolResponse(Err(ToolFault::Transient));
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
