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
        approvals::{self, EffectClass, EffectPolicy, EndpointKey, Proposal, Review},
        leases::{self, ExecState, Fence, LeaseError, LeaseSettings, UnresolvedOperation},
        runs::{CapabilityUse, RunRecheckRequest, recheck_decision},
        store::StoreError,
    },
    provider_http::{
        inference::Tool,
        mcp::{
            FaultKind, IdempotencyHeader, IdempotencyMeta, McpTransport, RetryAfter,
            ToolCallRequest, ToolCallSuccess, TransportFault,
        },
    },
    worker::{
        ActiveRun, ApprovedAdapter, ApprovedEffects, EffectDispatch, OwnedObservation,
        PreflightError, StepContext, StepResult, Stop, start_permit, stopped_step,
        turns::lease_step,
    },
};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{Map, Value};
use sqlx::{PgPool, Row};
use std::{
    collections::BTreeMap,
    fmt,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::{Instant, sleep_until, timeout_at};

/// Default freshness TTL for verified upstream `tools/list` catalog entries.
pub const DEFAULT_CATALOG_TTL: Duration = Duration::from_secs(60);

type CatalogCacheKey = (String, String, String, String, [u8; 32]);

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
    verified_catalogs: Mutex<BTreeMap<CatalogCacheKey, Instant>>,
    catalog_ttl: Duration,
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
            verified_catalogs: Mutex::new(BTreeMap::new()),
            catalog_ttl: DEFAULT_CATALOG_TTL,
        }
    }

    pub fn with_artifacts(mut self, store: Store) -> Self {
        store.attach(&self.pool);
        self.artifacts = Some(store);
        self
    }

    pub fn with_catalog_ttl(mut self, ttl: Duration) -> Self {
        self.catalog_ttl = ttl;
        self
    }

    pub fn approved_effects(self: &Arc<Self>) -> ApprovedEffects {
        ApprovedEffects {
            policy: self.registry.clone(),
            adapter: self.clone(),
        }
    }

    async fn verify_connection_catalog(
        &self,
        run: &ActiveRun,
        contract: &ExternalToolContract,
        actor_user_id: &str,
        step: &StepContext,
    ) -> Result<(), PreflightError> {
        let Some(transport) = self.transports.get(&contract.connection_id) else {
            return Err(PreflightError::Refused);
        };
        let Some(fingerprint) = self
            .registry
            .connection_fingerprint(&contract.connection_id)
        else {
            return Err(PreflightError::Refused);
        };
        let call_deadline = step.deadline.min(Instant::now() + contract.call_timeout);
        let credential = resolve_credential_bounded(
            self.credentials.as_ref(),
            CredentialRequest {
                connection_id: &contract.connection_id,
                account_id: &contract.account_id,
                scope_id: &run.claim.scope_id,
                actor_user_id,
            },
            call_deadline,
            &step.stop,
        )
        .await?;
        let cache_key: CatalogCacheKey = (
            contract.connection_id.clone(),
            contract.account_id.clone(),
            run.claim.scope_id.clone(),
            actor_user_id.to_owned(),
            fingerprint,
        );
        let fresh = {
            let guard = self
                .verified_catalogs
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            guard
                .get(&cache_key)
                .is_some_and(|at| !self.catalog_ttl.is_zero() && at.elapsed() < self.catalog_ttl)
        };
        if !fresh {
            let mut stop = step.stop.clone();
            let req_id = format!("tools-list:{}", run.claim.run_id);
            let remote = match transport
                .tools_list(&req_id, credential.bearer_token(), call_deadline, &mut stop)
                .await
            {
                Ok(remote) => remote,
                Err(fault) => {
                    self.verified_catalogs
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&cache_key);
                    return Err(match fault.kind {
                        FaultKind::Transient(_) | FaultKind::Stopped(_) => {
                            PreflightError::Transient
                        }
                        FaultKind::TerminalRefusal | FaultKind::Semantic { .. } => {
                            PreflightError::Refused
                        }
                    });
                }
            };
            if self
                .registry
                .verify_tools_list(&contract.connection_id, &remote)
                .is_err()
            {
                self.verified_catalogs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&cache_key);
                return Err(PreflightError::Refused);
            }
            let mut guard = self
                .verified_catalogs
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if guard.len() > 1024 {
                guard
                    .retain(|_, at| !self.catalog_ttl.is_zero() && at.elapsed() < self.catalog_ttl);
            }
            guard.insert(cache_key, Instant::now());
        }
        Ok(())
    }

    async fn admit_pre_intent(
        &self,
        run: &ActiveRun,
        proposal: &Proposal,
        step: &StepContext,
    ) -> Result<(), PreflightError> {
        let Some(contract) = self.registry.get(&proposal.tool, &proposal.version) else {
            return Err(PreflightError::Refused);
        };
        let Ok(expected) = contract.proposal(
            &proposal.logical_key,
            proposal.arguments().to_string().as_bytes(),
        ) else {
            return Err(PreflightError::Refused);
        };
        if expected.arguments() != proposal.arguments()
            || expected.destination() != proposal.destination()
        {
            return Err(PreflightError::Refused);
        }
        if step.stop.borrow().is_some() {
            return Err(PreflightError::Transient);
        }
        let actor_user_id = {
            let mut c = self
                .pool
                .acquire()
                .await
                .map_err(|e| PreflightError::Store(e.into()))?;
            if !approvals::two_phase_effect_intents_enabled(&mut c)
                .await
                .map_err(PreflightError::Store)?
            {
                return Err(PreflightError::Refused);
            }
            sqlx::query_scalar::<_, String>(
                "SELECT actor_user_id::text FROM openmettle.runs WHERE scope_id=$1::uuid AND id=$2::uuid",
            )
            .bind(&run.claim.scope_id)
            .bind(&run.claim.run_id)
            .fetch_one(&mut *c)
            .await
            .map_err(|e| PreflightError::Store(e.into()))?
        };
        self.verify_connection_catalog(run, contract, &actor_user_id, step)
            .await
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
            Err(PreflightError::Refused) => return refused(),
            Err(PreflightError::Transient) => {
                return StepResult::ToolOutput(ToolFault::Transient.envelope());
            }
            Err(PreflightError::Store(_)) => return StepResult::LeaseLost,
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
        // If already recorded at `outcome_unknown`, return `None` so replacement workers do not
        // collide on `reconcile-unknown:<op.id>` at a higher revision.
        let Some((lookup_tool, lookup_args)) =
            build_reconcile_lookup(contract, op, &proposal, &review)
        else {
            if op.outcome == "outcome_unknown" {
                return None;
            }
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
        let call_deadline = step.deadline.min(Instant::now() + contract.call_timeout);
        let Ok(credential) = resolve_credential_bounded(
            self.credentials.as_ref(),
            CredentialRequest {
                connection_id: &contract.connection_id,
                account_id: &contract.account_id,
                scope_id: &run.claim.scope_id,
                actor_user_id: &actor_user_id,
            },
            call_deadline,
            &step.stop,
        )
        .await
        else {
            return None;
        };
        let req_id = format!("reconcile:{}", op.id);
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
        let remote_handle =
            match extract_downstream_handle(&response, contract.handle_field.as_deref()) {
                ExtractedHandle::Absent => None,
                ExtractedHandle::Valid(h) => Some(h),
                ExtractedHandle::Malformed => return None,
            };
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

async fn resolve_credential_bounded(
    provider: &dyn McpCredentialProvider,
    request: CredentialRequest<'_>,
    deadline: Instant,
    stop: &tokio::sync::watch::Receiver<Option<Stop>>,
) -> Result<McpCredential, PreflightError> {
    if stop.borrow().is_some() || Instant::now() >= deadline {
        return Err(PreflightError::Transient);
    }
    let mut stop_rx = stop.clone();
    tokio::select! {
        biased;
        _ = stop_rx.wait_for(Option::is_some) => Err(PreflightError::Transient),
        resolved = timeout_at(deadline, provider.resolve(request)) => match resolved {
            Ok(CredentialOutcome::Ready(cred)) => Ok(cred),
            Ok(CredentialOutcome::Unavailable) => Err(PreflightError::Refused),
            Err(_) => Err(PreflightError::Transient),
        },
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
    {
        return false;
    }
    let Ok(expected) = contract.proposal(
        &proposal.logical_key,
        proposal.arguments().to_string().as_bytes(),
    ) else {
        return false;
    };
    if expected.destination() != proposal.destination()
        || expected.arguments() != proposal.arguments()
    {
        return false;
    }
    let Ok(Some(current_review)) =
        registry.review(&run.claim.scope_id, &run.claim.run_id, proposal)
    else {
        return false;
    };
    current_review == *committed_review
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

enum ExtractedHandle {
    Absent,
    Valid(String),
    Malformed,
}

fn extract_downstream_handle(response: &ToolCallSuccess, field: Option<&str>) -> ExtractedHandle {
    let Some(field) = field else {
        return ExtractedHandle::Absent;
    };
    let Some(val) = response
        .structured
        .as_ref()
        .and_then(|v| v.as_object())
        .and_then(|m| m.get(field))
    else {
        return ExtractedHandle::Absent;
    };
    let Some(candidate) = val.as_str() else {
        return ExtractedHandle::Malformed;
    };
    if candidate.is_empty()
        || candidate.len() > 256
        || !candidate.bytes().all(|b| b.is_ascii_graphic())
    {
        return ExtractedHandle::Malformed;
    }
    ExtractedHandle::Valid(candidate.to_owned())
}

fn redact_value_strings(value: &mut Value, handle: &str) {
    match value {
        Value::String(s) => {
            if s.contains(handle) {
                *s = s.replace(handle, "[REDACTED]");
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_value_strings(item, handle);
            }
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                redact_value_strings(v, handle);
            }
        }
        _ => {}
    }
}

fn sanitize_tool_success(
    success: &ToolCallSuccess,
    handle_field: Option<&str>,
) -> Result<(String, Option<String>), ToolFault> {
    let handle = match extract_downstream_handle(success, handle_field) {
        ExtractedHandle::Absent => None,
        ExtractedHandle::Valid(h) => Some(h),
        ExtractedHandle::Malformed => return Err(ToolFault::TerminalRefusal),
    };
    let text = if let Some(content) = &success.content_text {
        if handle_field.is_some()
            && let Ok(mut parsed) = serde_json::from_str::<Value>(content)
            && (parsed.is_object() || parsed.is_array())
        {
            if let (Some(field), Some(map)) = (handle_field, parsed.as_object_mut()) {
                map.remove(field);
            }
            if let Some(h) = handle.as_deref() {
                redact_value_strings(&mut parsed, h);
            }
            parsed.sort_all_objects();
            parsed.to_string()
        } else {
            match handle.as_deref() {
                Some(h) => content.replace(h, "[REDACTED]"),
                None => content.clone(),
            }
        }
    } else if let Some(structured) = &success.structured {
        let mut sanitized = structured.clone();
        if let (Some(field), Some(map)) = (handle_field, sanitized.as_object_mut()) {
            map.remove(field);
        }
        if let Some(h) = handle.as_deref() {
            redact_value_strings(&mut sanitized, h);
        }
        sanitized.sort_all_objects();
        sanitized.to_string()
    } else {
        match handle.as_deref() {
            Some(h) => success.text.replace(h, "[REDACTED]"),
            None => success.text.clone(),
        }
    };
    Ok((text, handle))
}

impl ApprovedAdapter for ExternalMcpAdapter {
    fn preflight<'a>(
        &'a self,
        run: &'a ActiveRun,
        proposal: &'a Proposal,
        step: &'a StepContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), PreflightError>> + Send + 'a>> {
        Box::pin(async move { self.admit_pre_intent(run, proposal, step).await })
    }

    fn filter_turn_tools<'a>(
        &'a self,
        run: &'a ActiveRun,
        tools: Vec<Tool>,
        step: &'a StepContext,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Tool>, StepResult>> + Send + 'a>> {
        Box::pin(async move {
            if tools.is_empty() {
                return Ok(tools);
            }
            if let Some(why) = *step.stop.borrow() {
                return Err(stopped_step(why));
            }
            let (two_phase_enabled, actor_user_id) = {
                let Ok(mut c) = self.pool.acquire().await else {
                    return Err(StepResult::LeaseLost);
                };
                let Ok(enabled) = approvals::two_phase_effect_intents_enabled(&mut c).await else {
                    return Err(StepResult::LeaseLost);
                };
                let Ok(actor) = sqlx::query_scalar::<_, String>(
                    "SELECT actor_user_id::text FROM openmettle.runs WHERE scope_id=$1::uuid AND id=$2::uuid",
                )
                .bind(&run.claim.scope_id)
                .bind(&run.claim.run_id)
                .fetch_one(&mut *c)
                .await
                else {
                    return Err(StepResult::LeaseLost);
                };
                (enabled, actor)
            };
            let mut checked: BTreeMap<(String, String), bool> = BTreeMap::new();
            let mut kept = Vec::with_capacity(tools.len());
            for tool in tools {
                let contracts = self.registry.find_by_tool_id(&tool.name);
                if contracts.is_empty() {
                    kept.push(tool);
                    continue;
                }
                if !two_phase_enabled {
                    continue;
                }
                let mut ok = true;
                for contract in contracts {
                    let conn_key = (contract.connection_id.clone(), contract.account_id.clone());
                    if let Some(&allowed) = checked.get(&conn_key) {
                        if !allowed {
                            ok = false;
                            break;
                        }
                        continue;
                    }
                    let res = self
                        .verify_connection_catalog(run, contract, &actor_user_id, step)
                        .await;
                    if let Some(why) = *step.stop.borrow() {
                        return Err(stopped_step(why));
                    }
                    match res {
                        Ok(()) => {
                            checked.insert(conn_key, true);
                        }
                        Err(PreflightError::Refused) => {
                            checked.insert(conn_key, false);
                            ok = false;
                            break;
                        }
                        Err(PreflightError::Transient) => return Err(StepResult::Handoff),
                        Err(PreflightError::Store(_)) => return Err(StepResult::LeaseLost),
                    }
                }
                if ok {
                    kept.push(tool);
                }
            }
            Ok(kept)
        })
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
                let credential = match resolve_credential_bounded(
                    self.credentials.as_ref(),
                    CredentialRequest {
                        connection_id: &contract.connection_id,
                        account_id: &contract.account_id,
                        scope_id: lease.scope_id,
                        actor_user_id: &actor_user_id,
                    },
                    call_deadline,
                    &step.stop,
                )
                .await
                {
                    Ok(cred) => cred,
                    Err(PreflightError::Refused) => {
                        return if !is_read && sent_uncertain {
                            observe_unknown(&self.pool, &lease, &step, &operation_id).await
                        } else {
                            StepResult::ToolResponse(Err(ToolFault::TerminalRefusal))
                        };
                    }
                    Err(PreflightError::Transient | PreflightError::Store(_)) => {
                        let stopped = *step.stop.borrow();
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
                        return if !is_read && sent_uncertain {
                            observe_unknown(&self.pool, &lease, &step, &operation_id).await
                        } else {
                            StepResult::ToolResponse(Err(ToolFault::Transient))
                        };
                    }
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
                        match sanitize_tool_success(&success, contract.handle_field.as_deref()) {
                            Ok((text, handle)) => return StepResult::ToolSuccess { text, handle },
                            Err(_) => {
                                if !is_read {
                                    return observe_unknown(
                                        &self.pool,
                                        &lease,
                                        &step,
                                        &operation_id,
                                    )
                                    .await;
                                }
                                return StepResult::ToolResponse(Err(ToolFault::TerminalRefusal));
                            }
                        }
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
                        // live `{AUTH}` + `effective_expires_us` check) bounded by `logical_call_deadline`.
                        enum PermitWait {
                            Stopped(Stop),
                            TimedOut,
                            Done(Result<Vec<u8>, StepResult>),
                        }
                        let permit_deadline = logical_call_deadline.min(step.deadline);
                        let mut stop_rx = step.stop.clone();
                        let permit_wait = tokio::select! {
                            biased;
                            waited = stop_rx.wait_for(Option::is_some) => {
                                PermitWait::Stopped(
                                    waited.ok().and_then(|v| *v).unwrap_or(Stop::LeaseLost),
                                )
                            }
                            timed = timeout_at(permit_deadline, async {
                                let Ok(mut c) = self.pool.acquire().await else {
                                    return Err(StepResult::LeaseLost);
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
                                start_permit(
                                    &mut c,
                                    &lease,
                                    (&operation_id, &proposal),
                                    &self.settings,
                                    self.registry.as_ref(),
                                    &mut step,
                                    permit,
                                )
                                .await
                            }) => match timed {
                                Ok(res) => PermitWait::Done(res),
                                Err(_) => PermitWait::TimedOut,
                            },
                        };
                        let checked = match permit_wait {
                            PermitWait::Stopped(why) => {
                                if why == Stop::LeaseLost {
                                    return StepResult::LeaseLost;
                                }
                                if !is_read && sent_uncertain {
                                    return observe_unknown(
                                        &self.pool,
                                        &lease,
                                        &step,
                                        &operation_id,
                                    )
                                    .await;
                                }
                                return stopped_step(why);
                            }
                            PermitWait::TimedOut => {
                                if !is_read && sent_uncertain {
                                    return observe_unknown(
                                        &self.pool,
                                        &lease,
                                        &step,
                                        &operation_id,
                                    )
                                    .await;
                                }
                                return StepResult::ToolResponse(Err(ToolFault::Transient));
                            }
                            PermitWait::Done(res) => res,
                        };
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sanitize_tool_success_redacts_json_escaped_and_short_handles_without_corrupting_json() {
        // 1. JSON-escaped handle inside structured-only response.
        let escaped_handle = "h\"quote\\1";
        let structured_escaped = ToolCallSuccess {
            text: String::new(),
            content_text: None,
            structured: Some(json!({
                "handle": escaped_handle,
                "note": format!("created {escaped_handle} ok"),
                "nested": [format!("again:{escaped_handle}")],
                "count": 1
            })),
            meta: None,
        };
        let (text, handle) = sanitize_tool_success(&structured_escaped, Some("handle")).unwrap();
        assert_eq!(handle.as_deref(), Some(escaped_handle));
        assert!(!text.contains(escaped_handle));
        assert!(!text.contains("quote"));
        let parsed: Value = serde_json::from_str(&text).expect("valid JSON");
        assert!(parsed.get("handle").is_none());
        assert_eq!(parsed["note"], "created [REDACTED] ok");
        assert_eq!(parsed["nested"][0], "again:[REDACTED]");
        assert_eq!(parsed["count"], 1);

        // 2. Short handle "1" must NOT corrupt integer JSON values like `"count": 1`.
        let structured_short = ToolCallSuccess {
            text: String::new(),
            content_text: None,
            structured: Some(json!({
                "handle": "1",
                "count": 1,
                "label": "item-1",
                "ok": true
            })),
            meta: None,
        };
        let (short_text, short_handle) =
            sanitize_tool_success(&structured_short, Some("handle")).unwrap();
        assert_eq!(short_handle.as_deref(), Some("1"));
        let parsed_short: Value = serde_json::from_str(&short_text).expect("valid JSON");
        assert!(parsed_short.get("handle").is_none());
        assert_eq!(parsed_short["count"], 1);
        assert_eq!(parsed_short["label"], "item-[REDACTED]");
        assert_eq!(parsed_short["ok"], true);

        // 3. JSON-encoded text content echoing both handle field and short handle alongside integer 1.
        let json_content = ToolCallSuccess {
            text: String::new(),
            content_text: Some(
                json!({
                    "handle": "1",
                    "count": 1,
                    "msg": "ref-1"
                })
                .to_string(),
            ),
            structured: Some(json!({"handle": "1"})),
            meta: None,
        };
        let (ctext, chandle) = sanitize_tool_success(&json_content, Some("handle")).unwrap();
        assert_eq!(chandle.as_deref(), Some("1"));
        let parsed_c: Value = serde_json::from_str(&ctext).expect("valid JSON");
        assert!(parsed_c.get("handle").is_none());
        assert_eq!(parsed_c["count"], 1);
        assert_eq!(parsed_c["msg"], "ref-[REDACTED]");

        // 4. Plain non-JSON text content echoing a handle with quotes/backslashes.
        let plain_content = ToolCallSuccess {
            text: String::new(),
            content_text: Some(format!("done {escaped_handle} end")),
            structured: Some(json!({"handle": escaped_handle})),
            meta: None,
        };
        let (ptext, phandle) = sanitize_tool_success(&plain_content, Some("handle")).unwrap();
        assert_eq!(phandle.as_deref(), Some(escaped_handle));
        assert_eq!(ptext, "done [REDACTED] end");
    }

    #[test]
    fn extract_downstream_handle_distinguishes_absent_valid_and_malformed() {
        let absent = ToolCallSuccess {
            text: "ok".into(),
            content_text: Some("ok".into()),
            structured: Some(json!({"ok": true})),
            meta: None,
        };
        assert!(matches!(
            extract_downstream_handle(&absent, Some("handle")),
            ExtractedHandle::Absent
        ));
        assert_eq!(
            sanitize_tool_success(&absent, Some("handle")).unwrap().1,
            None
        );

        let valid = ToolCallSuccess {
            text: "ok".into(),
            content_text: Some("ok".into()),
            structured: Some(json!({"handle": "op_123-abc"})),
            meta: None,
        };
        assert!(matches!(
            extract_downstream_handle(&valid, Some("handle")),
            ExtractedHandle::Valid(ref s) if s == "op_123-abc"
        ));

        let too_long = "a".repeat(257);
        for bad in [
            json!(""),
            json!("bad space"),
            json!("line\nbreak"),
            json!(too_long),
            json!(123),
            json!(null),
            json!(true),
            json!(["x"]),
        ] {
            let malformed = ToolCallSuccess {
                text: "ok".into(),
                content_text: Some("ok".into()),
                structured: Some(json!({"handle": bad})),
                meta: None,
            };
            assert!(
                matches!(
                    extract_downstream_handle(&malformed, Some("handle")),
                    ExtractedHandle::Malformed
                ),
                "expected Malformed for {bad}"
            );
            assert_eq!(
                sanitize_tool_success(&malformed, Some("handle")),
                Err(ToolFault::TerminalRefusal),
                "expected TerminalRefusal for {bad}"
            );
        }
    }
}
