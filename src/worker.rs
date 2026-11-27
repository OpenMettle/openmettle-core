//! Cooperative, fenced worker execution and scheduled maintenance (ADR 0033).
pub mod config;
pub mod turns;

use crate::{
    RunPolicy, WorkerSettings, artifact_fs,
    authz::{
        approvals::{self, EffectPolicy, IntentResult, Proposal, Review},
        leases::{
            self, ExecState, FailReason, Fence, LeaseError, LeaseSettings, Settle, Settled,
            UnresolvedOperation,
        },
        runs::{self as queue, ClaimedRun},
        store::StoreError,
    },
    runs::{Observation, Payload, record_observation},
    telemetry::{
        Sweep, WorkerOperationKind, WorkerOperationOutcome, WorkerRunOutcome, derive_run_lease_id,
        sweep_failed, worker_operation_completed, worker_operation_span, worker_run_claimed,
        worker_run_settled, worker_run_span,
    },
};
use ring::rand::{SecureRandom, SystemRandom};
use sqlx::{PgPool, Postgres, pool::PoolConnection};
use std::{
    future::Future,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{
    sync::watch,
    task::JoinSet,
    time::{Instant, sleep, sleep_until, timeout, timeout_at},
};
use tracing::Instrument;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    Cancel,
    Deadline,
    LeaseLost,
    Shutdown,
}

#[derive(Clone)]
pub struct StepContext {
    /// Apply this deadline (or an earlier adapter timeout) to every outbound call.
    pub deadline: Instant,
    pub stop: watch::Receiver<Option<Stop>>,
    pub tasks: TaskHandle,
}

#[derive(Default)]
struct ChildSet {
    tasks: JoinSet<()>,
    closed: bool,
}
type Children = Mutex<Option<ChildSet>>;

/// A weak handle cannot keep the run's tasks alive after the worker is dropped.
#[derive(Clone)]
pub struct TaskHandle(Weak<Children>);
/// Owns a step's child tasks. Closing an empty set prevents another spawn racing park.
pub struct StepTasks(Arc<Children>);
impl Default for StepTasks {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(Some(ChildSet::default()))))
    }
}
impl StepTasks {
    pub fn handle(&self) -> TaskHandle {
        TaskHandle(Arc::downgrade(&self.0))
    }
}
/// Owns the temporary closure of a drained task set while the park transaction is prepared.
pub(crate) struct ParkGuard(Option<Arc<Children>>);
impl ParkGuard {
    pub(crate) fn keep_closed(mut self) {
        self.0 = None;
    }
}
impl Drop for ParkGuard {
    fn drop(&mut self) {
        if let Some(owner) = &self.0
            && let Some(set) = owner.lock().unwrap().as_mut()
        {
            set.closed = false;
        }
    }
}
impl TaskHandle {
    pub(crate) fn close_if_drained(&self) -> Option<ParkGuard> {
        let owner = self.0.upgrade()?;
        let mut owned = owner.lock().unwrap();
        let set = owned.as_mut()?;
        while set.tasks.try_join_next().is_some() {}
        if set.closed || !set.tasks.is_empty() {
            return None;
        }
        set.closed = true;
        drop(owned);
        Some(ParkGuard(Some(owner)))
    }

    /// Returns false once the runner has closed this run's task set.
    pub fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) -> bool {
        let Some(owner) = self.0.upgrade() else {
            return false;
        };
        let mut set = owner.lock().unwrap();
        let Some(set) = set.as_mut() else {
            return false;
        };
        if set.closed {
            return false;
        }
        while set.tasks.try_join_next().is_some() {}
        set.tasks.spawn(task);
        true
    }
}

pub enum StepResult {
    /// A model answer awaiting publication under the run fence.
    Answer(turns::FinalAnswer),
    /// A known scoped tool outcome awaiting bounded observation and optional publication.
    ToolResponse(Result<String, crate::mcp::ToolFault>),
    /// A known scoped tool success carrying an optional redacted downstream handle.
    ToolSuccess {
        text: String,
        handle: Option<String>,
    },
    /// Model-visible output of an observed, reviewed tool operation.
    ToolOutput(String),
    /// A fenced authority check already invalidated the run.
    Invalidated(Settled),
    Handoff,
    LeaseLost,
    Continue,
    Finished,
    Failed(FailReason),
    Stopped,
}

pub struct ActiveRun {
    pub claim: ClaimedRun,
    pub state: ExecState,
    pub execution_deadline: Instant,
}

/// The runner supplies the run, operation ID and expected revision from its fenced read.
pub struct OwnedObservation {
    pub key: String,
    pub outcome: String,
    pub handle: Option<String>,
    pub format: String,
    pub version: i32,
    pub evidence: Vec<u8>,
}

/// Record an intent under a Step fence before dispatching an effect. Apply the context deadline
/// to each call, and use its task handle for concurrent work. An adapter that needs a particular
/// capability or another target must recheck those permissions before using them.
pub trait Executor: Send + Sync + 'static {
    fn step(&self, run: &ActiveRun, cx: StepContext) -> impl Future<Output = StepResult> + Send;
    /// A resumed approval can predate this claim. An executor that needs an unavailable
    /// continuation must reject it before the runner records an intent or sends any bytes.
    fn can_resume_approved(&self, _proposal: &Proposal) -> bool {
        true
    }
    fn reconcile(
        &self,
        run: &ActiveRun,
        operation: &UnresolvedOperation,
        cx: StepContext,
    ) -> impl Future<Output = Option<OwnedObservation>> + Send;
}

/// Outcome of [`ApprovedAdapter::preflight`] before Transaction 1 commits any operation row.
#[derive(Debug)]
pub enum PreflightError {
    /// Non-retryable policy, schema, credential-unavailable, catalog-drift, or terminal refusal.
    Refused,
    /// Temporary upstream, network, or timeout outage; caller should hand off or retry rather
    /// than terminally failing a run or its proven-unsent write.
    Transient,
    /// Database or lease-layer error.
    Store(StoreError),
}

/// Server-owned tool declaration paired with its pinned external MCP contract version, if any.
#[derive(Clone)]
pub struct DeclaredTool {
    pub tool: crate::provider_http::inference::Tool,
    pub external_version: Option<String>,
}

impl DeclaredTool {
    pub fn internal(tool: crate::provider_http::inference::Tool) -> Self {
        Self {
            tool,
            external_version: None,
        }
    }

    pub fn external(
        tool: crate::provider_http::inference::Tool,
        version: impl Into<String>,
    ) -> Self {
        Self {
            tool,
            external_version: Some(version.into()),
        }
    }
}

/// A reviewed adapter receives only committed bytes. It records observations with a Hold fence.
pub trait ApprovedAdapter: Send + Sync {
    /// Pre-intent server-side gate run strictly before `record_fenced_intent` commits any
    /// `openmettle.operations` row (rollout gates, verified upstream `tools/list` catalog, and
    /// credential availability). Defaults to `Ok(())`.
    fn preflight<'a>(
        &'a self,
        _run: &'a ActiveRun,
        _proposal: &'a Proposal,
        _step: &'a StepContext,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), PreflightError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    /// Verify that a model tool `call` maps faithfully to `proposal` under the advertised
    /// `expected_external_version` (allowing deterministic schema-default expansion on external
    /// MCP contracts while rejecting version switches and route-injected fields).
    fn verify_turn_call_proposal(
        &self,
        call: &crate::provider_http::inference::Call,
        proposal: &Proposal,
        expected_external_version: Option<&str>,
    ) -> bool {
        expected_external_version.is_none()
            && proposal.tool == call.name
            && proposal.arguments() == &call.arguments
    }

    /// Filter model-facing tool declarations before starting a turn round (e.g. verifying
    /// external MCP `tools/list` catalogs before offering those tools to the model).
    /// Defaults to returning the inner `Tool` declarations unchanged.
    fn filter_turn_tools<'a>(
        &'a self,
        _run: &'a ActiveRun,
        tools: Vec<DeclaredTool>,
        _step: &'a StepContext,
    ) -> std::pin::Pin<
        Box<
            dyn Future<Output = Result<Vec<crate::provider_http::inference::Tool>, StepResult>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move { Ok(tools.into_iter().map(|t| t.tool).collect()) })
    }

    fn send<'a>(
        &'a self,
        run: &'a ActiveRun,
        operation_id: String,
        request: Vec<u8>,
        step: StepContext,
    ) -> std::pin::Pin<Box<dyn Future<Output = StepResult> + Send + 'a>>;

    /// Destination-authorized read-only reconciliation for unresolved operations during
    /// `Executor::reconcile`. Defaults to returning `None` (fail closed without replaying).
    fn reconcile_operation<'a>(
        &'a self,
        _run: &'a ActiveRun,
        _operation: &'a UnresolvedOperation,
        _step: StepContext,
    ) -> std::pin::Pin<Box<dyn Future<Output = Option<OwnedObservation>> + Send + 'a>> {
        Box::pin(async { None })
    }
}

pub struct ApprovedEffects {
    pub policy: Arc<dyn EffectPolicy + Send + Sync>,
    pub adapter: Arc<dyn ApprovedAdapter>,
}

impl EffectPolicy for Option<&ApprovedEffects> {
    fn review(&self, scope: &str, run: &str, p: &Proposal) -> Result<Option<Review>, StoreError> {
        match self {
            Some(effects) => effects.policy.review(scope, run, p),
            None => Ok(None),
        }
    }

    fn requires_two_phase_writes(&self) -> bool {
        self.is_some_and(|effects| effects.policy.requires_two_phase_writes())
    }
}

struct Adapters<'a, E> {
    artifacts: Option<&'a artifact_fs::Store>,
    executor: &'a E,
    approved: Option<&'a ApprovedEffects>,
}

async fn connection(pool: &PgPool) -> Result<PoolConnection<Postgres>, StoreError> {
    Ok(pool.acquire().await?)
}

fn jitter(base: Duration) -> Duration {
    let mut byte = [0];
    let _ = SystemRandom::new().fill(&mut byte);
    base + base * u32::from(byte[0]) / (255 * 5)
}

async fn sweep<T, E>(work: impl Future<Output = Result<T, E>>) -> bool {
    matches!(timeout(Duration::from_secs(15), work).await, Ok(Ok(_)))
}

fn record_drift_verification<E>(
    metrics: &crate::telemetry::metrics::Metrics,
    outcome: Result<Result<artifact_fs::Drift, E>, tokio::time::error::Elapsed>,
) -> bool {
    use crate::telemetry::metrics::QuotaDriftOutcome;
    match outcome {
        Ok(Ok(report)) if report.healthy() => {
            metrics.record_quota_drift(QuotaDriftOutcome::Healthy, 1);
            true
        }
        Ok(Ok(report)) => {
            let mut recorded = false;
            for (kind, count) in [
                (QuotaDriftOutcome::StorageAccounts, report.storage_accounts),
                (QuotaDriftOutcome::Budgets, report.budgets),
                (QuotaDriftOutcome::Settlements, report.settlements),
            ] {
                if let Ok(n) = u64::try_from(count)
                    && n > 0
                {
                    metrics.record_quota_drift(kind, n);
                    recorded = true;
                }
            }
            for (kind, count) in [
                (QuotaDriftOutcome::Files, report.files),
                (QuotaDriftOutcome::Quarantined, report.quarantined),
            ] {
                if count > 0 {
                    metrics.record_quota_drift(kind, count);
                    recorded = true;
                }
            }
            if !recorded {
                metrics.record_quota_drift(QuotaDriftOutcome::Error, 1);
            }
            false
        }
        Ok(Err(_)) => {
            metrics.record_quota_drift(QuotaDriftOutcome::Error, 1);
            false
        }
        Err(_) => {
            metrics.record_quota_drift(QuotaDriftOutcome::Timeout, 1);
            false
        }
    }
}

pub(crate) async fn maintenance(
    pool: &PgPool,
    store: Option<&artifact_fs::Store>,
    period: Duration,
) {
    let mut held = crate::quotas::Pass::default();
    let mut orphans = crate::quotas::Pass::default();
    let mut unreported = crate::quotas::Pass::default();
    let verify_interval = Duration::from_secs(3600);
    let mut next_verification = Instant::now() + verify_interval;
    // Seed durable backup outcome totals from PostgreSQL before the first OTLP export so a
    // restarted worker never emits a premature `0` baseline ahead of historical failure/overdue
    // counts.
    let _ = sweep(crate::backup::observe_telemetry(pool)).await;
    loop {
        sleep(jitter(period)).await;
        let queued =
            sweep(async { queue::expire_queued(&mut *connection(pool).await?, 100).await }).await;
        let waits =
            sweep(async { approvals::expire_waits(&mut *connection(pool).await?, 100).await })
                .await;
        // Queue maintenance has one failure event per tick and a separate budget for each sweep.
        if !queued || !waits {
            sweep_failed(Sweep::Queue);
        }
        if !sweep(async { leases::settle_expired(&mut *connection(pool).await?, 100).await }).await
        {
            sweep_failed(Sweep::Execution);
        }
        let holds_ok = sweep(crate::quotas::reconcile_stale_quotas(pool, &mut held, 100)).await;
        let orphans_ok = sweep(crate::quotas::orphan_page(pool, &mut orphans, 100)).await;
        let unreported_ok = sweep(crate::quotas::sweep_unreported_gateway_requests(
            pool,
            &mut unreported,
            100,
        ))
        .await;
        let warnings_ok = sweep(crate::quotas::emit_warnings(pool)).await;
        let overdue_ok = sweep(crate::quotas::observe_overdue_handoffs(pool, 100)).await;
        let mut drift_ok = true;
        if Instant::now() >= next_verification {
            next_verification = Instant::now() + verify_interval;
            drift_ok = record_drift_verification(
                crate::telemetry::metrics::global(),
                timeout(
                    Duration::from_secs(15),
                    artifact_fs::verify_accounting_drift(pool, store),
                )
                .await,
            );
        }
        if !(holds_ok && orphans_ok && unreported_ok && warnings_ok && overdue_ok && drift_ok) {
            crate::telemetry::metrics::quota_sweep_failed();
        }
        if let Some(store) = store {
            let age = artifact_fs::UPLOAD_TIMEOUT + Duration::from_secs(300);
            // Maximum reviewed call (300 s), maximum lease drain (100 s), and 900 s grace.
            let spills = sweep(artifact_fs::reconcile_run_spills(
                pool,
                store,
                Duration::from_secs(1300),
                100,
            ))
            .await;
            let uploads = sweep(artifact_fs::reconcile_expired(pool, store, age, 100)).await;
            if !spills || !uploads {
                sweep_failed(Sweep::Uploads);
            }
            // ADR 0041 & ADR 0046: when restore gate is closed, run no purge work; when
            // maintenance is active (and restore gate is open), finish already-claimed `purging`
            // revisions and `.purge.<id>` anchors so drain completes without claiming new purges.
            let gate_state = timeout(Duration::from_secs(15), async {
                let mut conn = pool.acquire().await?;
                let restore_open = crate::restore::gate_open(&mut conn).await?;
                let maint_active = crate::backup::maintenance_active(&mut conn).await?;
                Ok::<(bool, bool), sqlx::Error>((restore_open, maint_active))
            })
            .await;
            let purged = match gate_state {
                Ok(Ok((true, false))) => sweep(artifact_fs::purge_due(pool, store, 100)).await,
                Ok(Ok((true, true))) => {
                    sweep(artifact_fs::finish_inflight_purges(pool, store, 100)).await
                }
                Ok(Ok((false, _))) => true,
                _ => false,
            };
            if !purged {
                sweep_failed(Sweep::Retention);
            }
        }
        // ADR 0046 / ADR 0028: observe completed/failed/expired backup runs and RPO overdue state.
        let _ = sweep(crate::backup::observe_telemetry(pool)).await;
    }
}

async fn claim(
    pool: &PgPool,
    policy: RunPolicy,
) -> Result<Option<(ActiveRun, Instant, bool)>, StoreError> {
    let mut c = connection(pool).await?;
    // ADR 0041 & ADR 0046: no run is claimed or reclaimed while restore is pending or maintenance is active.
    if !crate::restore::gate_open(&mut c).await?
        || crate::backup::maintenance_active(&mut c).await?
    {
        return Ok(None);
    }
    let sent = Instant::now();
    let (claim, sent, state, recovered) =
        if let Some(old) = leases::reclaim_next(&mut c, &policy.leases).await? {
            (old.run, sent, old.state, true)
        } else {
            let sent = Instant::now();
            let Some(new) = queue::claim_next(&mut c, &policy.limits, &policy.leases).await? else {
                return Ok(None);
            };
            (new, sent, ExecState::Running, false)
        };
    let execution_deadline = sent + claim.execution_remaining;
    Ok(Some((
        ActiveRun {
            claim,
            state,
            execution_deadline,
        },
        sent,
        recovered,
    )))
}

/// Run maintenance and, when slots are configured, the supplied executor. Pass half the
/// process drain budget as `run_budget`. Dropping this future also aborts the owned run tasks.
pub async fn run<E: Executor>(
    pool: &PgPool,
    store: Option<&artifact_fs::Store>,
    settings: WorkerSettings,
    executor: Arc<E>,
    shutdown: impl Future<Output = ()>,
    run_budget: Duration,
) {
    run_with_approvals(pool, store, settings, executor, None, shutdown, run_budget).await
}

/// Run the same worker with an optional reviewed adapter for resumed effects.
pub async fn run_with_approvals<E: Executor>(
    pool: &PgPool,
    store: Option<&artifact_fs::Store>,
    settings: WorkerSettings,
    executor: Arc<E>,
    approved: Option<Arc<ApprovedEffects>>,
    shutdown: impl Future<Output = ()>,
    run_budget: Duration,
) {
    let mut runs = JoinSet::new();
    let (shutdown_tx, shutdown_rx) = watch::channel(None);
    let claiming = async {
        let mut stopping = shutdown_rx.clone();
        let Some(policy) = settings.policy else {
            let _ = stopping.changed().await;
            return;
        };
        artifact_fs::configure_slots(policy.slots);
        let mut poll_at = Instant::now();
        while stopping.borrow().is_none() {
            while runs.try_join_next().is_some() {
                poll_at = Instant::now();
            }
            if runs.len() < policy.slots && Instant::now() >= poll_at {
                // Finish an in-flight claim even if shutdown arrives during its commit.
                // The new holder then observes shutdown before dispatch and hands it back.
                if let Ok(Some((active, sent, recovered))) = claim(pool, policy).await {
                    let (pool, executor, shutdown) =
                        (pool.clone(), executor.clone(), stopping.clone());
                    let approved = approved.clone();
                    let artifacts = store.cloned();
                    runs.spawn(async move {
                        run_one(
                            &pool,
                            Adapters {
                                artifacts: artifacts.as_ref(),
                                executor: executor.as_ref(),
                                approved: approved.as_deref(),
                            },
                            active,
                            sent,
                            recovered,
                            policy.leases,
                            shutdown,
                        )
                        .await
                    });
                } else {
                    poll_at = Instant::now() + jitter(settings.poll);
                }
                continue;
            }
            tokio::select! {
                _ = stopping.changed() => break,
                _ = runs.join_next(), if !runs.is_empty() => poll_at = Instant::now(),
                _ = sleep_until(poll_at), if runs.len() < policy.slots => (),
            }
        }
        while runs.join_next().await.is_some() {}
    };
    tokio::pin!(claiming);
    tokio::select! {
        biased;
        _ = shutdown => (),
        () = &mut claiming => unreachable!(),
        () = maintenance(pool, store, settings.sweep) => unreachable!(),
    }
    let until = Instant::now() + run_budget;
    shutdown_tx.send_replace(Some(until));
    let _ = timeout_at(until, claiming).await;
}

fn stop_point(
    sent: Instant,
    lease: Duration,
    execution: Duration,
    margin: Duration,
) -> (Instant, Stop) {
    let cause = if execution <= lease {
        Stop::Deadline
    } else {
        Stop::LeaseLost
    };
    (sent + lease.min(execution).saturating_sub(margin), cause)
}

/// Race the entire renewal, including connection acquisition, against the last known stop point.
async fn monitor(
    pool: &PgPool,
    run: &ActiveRun,
    settings: LeaseSettings,
    mut sent: Instant,
    deadline: &watch::Sender<(Instant, Stop)>,
) -> Stop {
    let interval = settings.lease / 3;
    let mut point = *deadline.borrow();
    let mut next = sent + interval;
    loop {
        if Instant::now() >= point.0 {
            return point.1;
        }
        let renew = async {
            sleep_until(next).await;
            let mut c = connection(pool).await?;
            sent = Instant::now();
            leases::renew_lease(&mut c, &run.claim.lease(), &settings).await
        };
        let held = tokio::select! {
            biased;
            _ = sleep_until(point.0) => return point.1,
            result = renew => match result {
                Ok(held) => held,
                Err(LeaseError::Store(_)) => {
                    next = (next + interval / 2).max(Instant::now());
                    continue;
                }
                Err(_) => return Stop::LeaseLost,
            },
        };
        if Instant::now() >= point.0 {
            return point.1;
        }
        if held.state == ExecState::Cancelling {
            return Stop::Cancel;
        }
        point = stop_point(
            sent,
            held.lease_remaining,
            held.execution_remaining,
            interval,
        );
        deadline.send_replace(point);
        next = sent + interval;
    }
}

struct RunContext {
    deadline: watch::Receiver<(Instant, Stop)>,
    stop: watch::Receiver<Option<Stop>>,
    tasks: TaskHandle,
}

impl RunContext {
    fn stopped(&self) -> Option<Stop> {
        let (at, why) = *self.deadline.borrow();
        self.stop
            .borrow()
            .or_else(|| (Instant::now() >= at).then_some(why))
    }

    fn step(&self) -> StepContext {
        StepContext {
            deadline: self.deadline.borrow().0,
            stop: self.stop.clone(),
            tasks: self.tasks.clone(),
        }
    }
}

/// RAII guard for one `worker.operation` span and its matching `worker.operation.completed`
/// structured log event. Disarmed on normal completion via [`Self::finish`]; if the enclosing
/// future is dropped mid-flight (for example when worker drain hits its deadline), `Drop`
/// records `lease_lost` or `stopped` directly on the open span handle and emits the event once.
pub(crate) struct WorkerOperationGuard {
    span: tracing::Span,
    run_id: String,
    lease_id: String,
    operation_id: String,
    kind: WorkerOperationKind,
    started: std::time::Instant,
    stop: Option<watch::Receiver<Option<Stop>>>,
    finished: bool,
}

impl WorkerOperationGuard {
    pub(crate) fn new(
        span: tracing::Span,
        run_id: &str,
        lease_id: &str,
        operation_id: &str,
        kind: WorkerOperationKind,
        stop: Option<watch::Receiver<Option<Stop>>>,
    ) -> Self {
        Self {
            span,
            run_id: run_id.to_owned(),
            lease_id: lease_id.to_owned(),
            operation_id: operation_id.to_owned(),
            kind,
            started: std::time::Instant::now(),
            stop,
            finished: false,
        }
    }

    pub(crate) fn finish(mut self, outcome: WorkerOperationOutcome) {
        self.record(outcome);
    }

    fn record(&mut self, outcome: WorkerOperationOutcome) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.span.record("operation.outcome", outcome.as_str());
        worker_operation_completed(
            &self.run_id,
            &self.lease_id,
            &self.operation_id,
            self.kind,
            outcome,
            self.started.elapsed(),
        );
    }
}

impl Drop for WorkerOperationGuard {
    fn drop(&mut self) {
        if !self.finished {
            let outcome = match self.stop.as_ref().and_then(|rx| *rx.borrow()) {
                Some(Stop::LeaseLost) => WorkerOperationOutcome::LeaseLost,
                _ => WorkerOperationOutcome::Stopped,
            };
            let span = self.span.clone();
            span.in_scope(|| self.record(outcome));
        }
    }
}

async fn reconcile_operation<E: Executor>(
    pool: &PgPool,
    run: &ActiveRun,
    op: &UnresolvedOperation,
    executor: &E,
    context: &RunContext,
    lease_id: &str,
) -> Result<Option<WorkEnd>, LeaseError> {
    let lease = run.claim.lease();
    let op_span = worker_operation_span(
        lease.run_id,
        lease_id,
        &op.id,
        WorkerOperationKind::Reconcile,
    );
    let guard_span = op_span.clone();
    async {
        let guard = WorkerOperationGuard::new(
            guard_span,
            lease.run_id,
            lease_id,
            &op.id,
            WorkerOperationKind::Reconcile,
            Some(context.stop.clone()),
        );
        let res: Result<(WorkerOperationOutcome, Option<WorkEnd>), LeaseError> = async {
            if let Some(o) = executor.reconcile(run, op, context.step()).await {
                let mut c = connection(pool).await?;
                if context.stopped() == Some(Stop::LeaseLost) {
                    Ok((
                        WorkerOperationOutcome::LeaseLost,
                        Some(WorkEnd::Stop(Stop::LeaseLost)),
                    ))
                } else {
                    leases::with_lease(&mut c, &lease, Fence::Hold, async |tx, _| {
                        record_observation(
                            tx,
                            &Observation {
                                scope: lease.scope_id,
                                run: lease.run_id,
                                operation: &op.id,
                                key: &o.key,
                                expected_revision: op.revision,
                                outcome: &o.outcome,
                                handle: o.handle.as_deref(),
                                evidence: Payload {
                                    format: &o.format,
                                    version: o.version,
                                    bytes: &o.evidence,
                                },
                            },
                        )
                        .await
                    })
                    .await?;
                    Ok((WorkerOperationOutcome::Ok, None))
                }
            } else if let Some(why) = context.stopped() {
                let outcome = if why == Stop::LeaseLost {
                    WorkerOperationOutcome::LeaseLost
                } else {
                    WorkerOperationOutcome::Stopped
                };
                Ok((outcome, Some(WorkEnd::Stop(why))))
            } else {
                Ok((WorkerOperationOutcome::Handoff, None))
            }
        }
        .await;
        match res {
            Ok((outcome, end)) => {
                guard.finish(outcome);
                Ok(end)
            }
            Err(err) => {
                let outcome = match err {
                    LeaseError::Stopping(_) => WorkerOperationOutcome::Stopped,
                    LeaseError::StaleClaim | LeaseError::Expired | LeaseError::Terminal { .. } => {
                        WorkerOperationOutcome::LeaseLost
                    }
                    LeaseError::Store(_) => WorkerOperationOutcome::Failed,
                };
                guard.finish(outcome);
                Err(err)
            }
        }
    }
    .instrument(op_span)
    .await
}

async fn reconcile<E: Executor>(
    pool: &PgPool,
    run: &ActiveRun,
    executor: &E,
    context: &RunContext,
    lease_id: &str,
) -> Result<WorkEnd, LeaseError> {
    let lease = run.claim.lease();
    let mut after = None;
    loop {
        if let Some(why) = context.stopped() {
            return Ok(WorkEnd::Stop(why));
        }
        let page =
            leases::unresolved_after(&mut *connection(pool).await?, &lease, 100, after.as_deref())
                .await?;
        for op in &page {
            if let Some(why) = context.stopped() {
                return Ok(WorkEnd::Stop(why));
            }
            if let Some(end) =
                reconcile_operation(pool, run, op, executor, context, lease_id).await?
            {
                return Ok(end);
            }
        }
        if page.len() < 100 {
            return Ok(WorkEnd::Complete(Settle::Stopped));
        }
        after = page.last().map(|op| op.id.clone());
    }
}

enum WorkEnd {
    Answer(turns::FinalAnswer),
    Complete(Settle),
    Invalidated(Settled),
    Handoff,
    Stop(Stop),
    Incomplete,
}

async fn execute<E: Executor>(
    pool: &PgPool,
    adapters: Adapters<'_, E>,
    run: &ActiveRun,
    recovered: bool,
    settings: &LeaseSettings,
    context: &RunContext,
    lease_id: &str,
) -> Result<WorkEnd, LeaseError> {
    if run.state == ExecState::Reconciling {
        return reconcile(pool, run, adapters.executor, context, lease_id).await;
    }
    if run.state == ExecState::Cancelling
        || (recovered
            && !leases::unresolved_operations(&mut *connection(pool).await?, &run.claim.lease(), 1)
                .await?
                .is_empty())
    {
        return Ok(WorkEnd::Complete(Settle::Stopped));
    }
    loop {
        if let Some(why) = context.stopped() {
            return Ok(WorkEnd::Stop(why));
        }
        if let Some(settled) =
            queue::recheck_claim(&mut *connection(pool).await?, &run.claim, settings).await?
        {
            return Ok(WorkEnd::Invalidated(settled));
        }
        if let Some(why) = context.stopped() {
            return Ok(WorkEnd::Stop(why));
        }
        let pending =
            match approvals::pending_effect(&mut *connection(pool).await?, &run.claim.lease())
                .await?
            {
                Some((id, proposal)) => Some((Some(id), proposal)),
                None if adapters.approved.is_some() => approvals::pending_automatic_write(
                    &mut *connection(pool).await?,
                    &run.claim.lease(),
                )
                .await?
                .filter(|proposal| adapters.executor.can_resume_approved(proposal))
                .map(|proposal| (None, proposal)),
                None => None,
            };
        if let Some(why) = context.stopped() {
            return Ok(WorkEnd::Stop(why));
        }
        let result = if let Some((id, proposal)) = pending {
            if !adapters.executor.can_resume_approved(&proposal) {
                return Ok(WorkEnd::Complete(Settle::Failed(FailReason::StepFailed)));
            }
            if let Some(effects) = adapters.approved {
                let preflight_step = context.step();
                let preflight = effects
                    .adapter
                    .preflight(run, &proposal, &preflight_step)
                    .await;
                if let Some(why) = context.stopped() {
                    return Ok(WorkEnd::Stop(why));
                }
                match preflight {
                    Ok(()) => {}
                    Err(PreflightError::Transient) => return Ok(WorkEnd::Handoff),
                    Err(PreflightError::Refused) => {
                        return Ok(WorkEnd::Complete(Settle::Failed(FailReason::StepFailed)));
                    }
                    Err(PreflightError::Store(err)) => return Err(err.into()),
                }
            }
            let intent = approvals::record_fenced_intent(
                &mut *connection(pool).await?,
                &run.claim.lease(),
                &proposal,
                id.as_deref(),
                &adapters.approved,
                settings,
            )
            .await?;
            match intent {
                IntentResult::Invalidated(settled) => return Ok(WorkEnd::Invalidated(settled)),
                IntentResult::ApprovalRequired => {
                    return Ok(WorkEnd::Complete(Settle::Failed(FailReason::StepFailed)));
                }
                IntentResult::Applied(_) | IntentResult::Replayed(_) => {}
            }
            let resumed = EffectDispatch {
                pool,
                artifacts: adapters.artifacts,
                effects: adapters
                    .approved
                    .ok_or(StoreError::Conflict("approval adapter"))?,
                settings,
            }
            .send(run, &proposal, intent, context.step())
            .await;
            match resumed {
                StepResult::ToolOutput(_) => StepResult::Continue,
                other => other,
            }
        } else {
            adapters.executor.step(run, context.step()).await
        };
        match result {
            StepResult::Invalidated(settled) => return Ok(WorkEnd::Invalidated(settled)),
            StepResult::Handoff => return Ok(WorkEnd::Handoff),
            StepResult::LeaseLost => return Ok(WorkEnd::Stop(Stop::LeaseLost)),
            StepResult::Answer(answer) => return Ok(WorkEnd::Answer(answer)),
            StepResult::ToolOutput(_)
            | StepResult::ToolResponse(_)
            | StepResult::ToolSuccess { .. } => {
                return Ok(WorkEnd::Complete(Settle::Failed(FailReason::StepFailed)));
            }
            StepResult::Continue => continue,
            StepResult::Finished => return Ok(WorkEnd::Complete(Settle::Succeeded)),
            StepResult::Failed(reason) => return Ok(WorkEnd::Complete(Settle::Failed(reason))),
            StepResult::Stopped => return Ok(WorkEnd::Complete(Settle::Stopped)),
        }
    }
}

fn settled_run_outcome(result: &Result<Settled, LeaseError>) -> WorkerRunOutcome {
    match result {
        Ok(Settled::Terminal { state: "succeeded" }) => WorkerRunOutcome::Succeeded,
        Ok(Settled::Terminal { state: "cancelled" }) => WorkerRunOutcome::Cancelled,
        Ok(Settled::Terminal {
            state: "interrupted",
        }) => WorkerRunOutcome::Interrupted,
        Ok(Settled::Terminal { .. }) => WorkerRunOutcome::Failed,
        Ok(Settled::Reconciling { .. }) => WorkerRunOutcome::Reconciling,
        Err(LeaseError::Expired | LeaseError::StaleClaim | LeaseError::Terminal { .. }) => {
            WorkerRunOutcome::LeaseLost
        }
        Err(_) => WorkerRunOutcome::Aborted,
    }
}

fn handoff_run_outcome(result: &Result<leases::Handoff, LeaseError>) -> WorkerRunOutcome {
    match result {
        Ok(leases::Handoff::Released) => WorkerRunOutcome::Handoff,
        Ok(leases::Handoff::Settled(settled)) => settled_run_outcome(&Ok(*settled)),
        Err(LeaseError::Expired | LeaseError::StaleClaim | LeaseError::Terminal { .. }) => {
            WorkerRunOutcome::LeaseLost
        }
        Err(_) => WorkerRunOutcome::Aborted,
    }
}

async fn run_one<E: Executor>(
    pool: &PgPool,
    adapters: Adapters<'_, E>,
    run: ActiveRun,
    sent: Instant,
    recovered: bool,
    settings: LeaseSettings,
    shutdown: watch::Receiver<Option<Instant>>,
) {
    let started = std::time::Instant::now();
    let run_id = run.claim.run_id.clone();
    let lease_id = derive_run_lease_id(&run_id, &run.claim.claim_token);
    let span = worker_run_span(&run_id, &lease_id);
    async {
        worker_run_claimed(&run_id, &lease_id);
        let outcome = run_one_inner(
            pool, adapters, run, sent, recovered, settings, shutdown, &lease_id,
        )
        .await;
        tracing::Span::current().record("run.outcome", outcome.as_str());
        worker_run_settled(&run_id, &lease_id, outcome, started.elapsed());
    }
    .instrument(span)
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn run_one_inner<E: Executor>(
    pool: &PgPool,
    adapters: Adapters<'_, E>,
    run: ActiveRun,
    sent: Instant,
    recovered: bool,
    settings: LeaseSettings,
    mut shutdown: watch::Receiver<Option<Instant>>,
    lease_id: &str,
) -> WorkerRunOutcome {
    let lease = run.claim.lease();
    let children = StepTasks::default();
    let (stop, rx) = watch::channel(None);
    let (deadline, current) = watch::channel(stop_point(
        sent,
        run.claim.lease_remaining,
        run.claim.execution_remaining,
        settings.lease / 3,
    ));
    let mut renewal = Box::pin(monitor(pool, &run, settings, sent, &deadline));
    let context = RunContext {
        deadline: current,
        stop: rx,
        tasks: children.handle(),
    };
    let mut work = Box::pin(async {
        match execute(
            pool, adapters, &run, recovered, &settings, &context, lease_id,
        )
        .await
        {
            Ok(end) => end,
            Err(LeaseError::Stopping(_)) => WorkEnd::Stop(Stop::Cancel),
            Err(_) => WorkEnd::Stop(Stop::LeaseLost),
        }
    });
    let (mut cause, finished) = tokio::select! {
        biased;
        why = &mut renewal => (Some(why), None),
        _ = shutdown.wait_for(Option::is_some) => (Some(Stop::Shutdown), None),
        end = &mut work => {
            let why = match end {
                WorkEnd::Stop(why) => Some(why),
                WorkEnd::Invalidated(_) => Some(Stop::Cancel),
                _ => context.stopped(),
            };
            (why, Some(end))
        }
    };
    let mut until = Instant::now() + settings.lease / 6;
    if let Some(shutdown_limit) = *shutdown.borrow() {
        until = until.min(shutdown_limit);
    }
    if let Some(why) = cause {
        stop.send_replace(Some(why));
    }
    let drain = async {
        let end = match finished {
            Some(end) => end,
            None => timeout_at(until, &mut work)
                .await
                .unwrap_or(WorkEnd::Incomplete),
        };
        drop(work);
        // Close spawning before aborting, including spawns racing the end of drain.
        let mut owned = children
            .0
            .lock()
            .unwrap()
            .take()
            .expect("runner owns child set")
            .tasks;
        owned.abort_all();
        let _ = timeout_at(until, async { while owned.join_next().await.is_some() {} }).await;
        end
    };
    tokio::pin!(drain);
    let end = if cause == Some(Stop::Shutdown) {
        tokio::select! {
            biased;
            why = &mut renewal => {
                cause = Some(why);
                stop.send_replace(cause);
                drain.await
            }
            end = &mut drain => end,
        }
    } else {
        drain.await
    };
    // Cancel any pending renewal and return its connection before settling.
    drop(renewal);
    if cause == Some(Stop::LeaseLost) || matches!(end, WorkEnd::Stop(Stop::LeaseLost)) {
        return WorkerRunOutcome::LeaseLost;
    }
    let Ok(mut c) = connection(pool).await else {
        return WorkerRunOutcome::Aborted;
    };
    let input = match end {
        WorkEnd::Answer(answer) if cause.is_none() => {
            match turns::publish(&mut c, &lease, &settings, answer).await {
                // Publication rolled back. Settle the rejected answer under a fresh fence.
                Err(LeaseError::Store(StoreError::InvalidInput(_) | StoreError::Denied(_))) => {
                    Settle::Failed(FailReason::StepFailed)
                }
                Ok(Settled::Reconciling { .. }) => {
                    let _ = leases::release_lease(&mut c, &lease).await;
                    return WorkerRunOutcome::Reconciling;
                }
                other => return settled_run_outcome(&other),
            }
        }
        WorkEnd::Invalidated(settled) => {
            if matches!(settled, Settled::Reconciling { .. }) {
                let _ = leases::release_lease(&mut c, &lease).await;
                return WorkerRunOutcome::Reconciling;
            }
            return WorkerRunOutcome::Invalidated;
        }
        WorkEnd::Handoff => {
            let outcome = leases::handoff(&mut c, &lease, &settings).await;
            return handoff_run_outcome(&outcome);
        }
        WorkEnd::Complete(input @ (Settle::Succeeded | Settle::Failed(_))) => input,
        WorkEnd::Complete(Settle::Stopped) if run.state == ExecState::Reconciling => {
            Settle::Stopped
        }
        _ if cause == Some(Stop::Shutdown) => {
            let outcome = leases::handoff(&mut c, &lease, &settings).await;
            return handoff_run_outcome(&outcome);
        }
        _ => Settle::Stopped,
    };
    let mut settled = leases::settle(&mut c, &lease, &settings, input).await;
    if input == Settle::Succeeded
        && matches!(settled, Err(LeaseError::Store(StoreError::Conflict(_))))
    {
        settled = leases::settle(&mut c, &lease, &settings, Settle::Stopped).await;
    }
    if matches!(settled, Ok(Settled::Reconciling { .. })) {
        let _ = leases::release_lease(&mut c, &lease).await;
    }
    settled_run_outcome(&settled)
}

/// Shared by live turns and resumed approvals. An existing write never gains a send
/// permit. A read, including its first attempt, passes through a second transaction.
pub(crate) struct EffectDispatch<'a> {
    pub pool: &'a PgPool,
    pub artifacts: Option<&'a artifact_fs::Store>,
    pub effects: &'a ApprovedEffects,
    pub settings: &'a LeaseSettings,
}

fn operation_outcome(result: &StepResult) -> WorkerOperationOutcome {
    match result {
        StepResult::Answer(_)
        | StepResult::ToolOutput(_)
        | StepResult::ToolSuccess { .. }
        | StepResult::ToolResponse(Ok(_))
        | StepResult::Continue
        | StepResult::Finished => WorkerOperationOutcome::Ok,
        StepResult::ToolResponse(Err(_)) | StepResult::Failed(_) => WorkerOperationOutcome::Failed,
        StepResult::Stopped => WorkerOperationOutcome::Stopped,
        StepResult::Handoff => WorkerOperationOutcome::Handoff,
        StepResult::LeaseLost => WorkerOperationOutcome::LeaseLost,
        StepResult::Invalidated(_) => WorkerOperationOutcome::Invalidated,
    }
}

impl EffectDispatch<'_> {
    pub async fn send(
        &self,
        run: &ActiveRun,
        proposal: &Proposal,
        intent: IntentResult,
        step: StepContext,
    ) -> StepResult {
        let fail = StepResult::Failed(FailReason::StepFailed);
        let (op, fresh) = match intent {
            IntentResult::Applied(i) => (i.operation_id.clone(), Some(i)),
            IntentResult::Replayed(id) => (id, None),
            IntentResult::Invalidated(s) => return StepResult::Invalidated(s),
            IntentResult::ApprovalRequired => return fail,
        };
        let lease_id = derive_run_lease_id(&run.claim.run_id, &run.claim.claim_token);
        let op_span =
            worker_operation_span(&run.claim.run_id, &lease_id, &op, WorkerOperationKind::Tool);
        let guard_span = op_span.clone();
        let stop_rx = step.stop.clone();
        async {
            let guard = WorkerOperationGuard::new(
                guard_span,
                &run.claim.run_id,
                &lease_id,
                &op,
                WorkerOperationKind::Tool,
                Some(stop_rx),
            );
            let result = self.send_operation(run, proposal, &op, fresh, step).await;
            guard.finish(operation_outcome(&result));
            result
        }
        .instrument(op_span)
        .await
    }

    async fn send_operation(
        &self,
        run: &ActiveRun,
        proposal: &Proposal,
        op: &str,
        fresh: Option<approvals::CommittedIntent>,
        mut step: StepContext,
    ) -> StepResult {
        let Self {
            pool,
            artifacts,
            effects,
            settings,
        } = *self;
        use approvals::ReplayEffect;
        let fail = StepResult::Failed(FailReason::StepFailed);
        let policy = Some(effects);
        let lease = run.claim.lease();
        let Ok(mut c) = pool.acquire().await else {
            return StepResult::LeaseLost;
        };
        let op_row: Result<(String, Option<i32>), _> = sqlx::query_as(
            "SELECT capability, dispatched_attempts FROM openmettle.operations
              WHERE scope_id=$1::uuid AND run_id=$2::uuid AND id=$3::uuid",
        )
        .bind(lease.scope_id)
        .bind(lease.run_id)
        .bind(op)
        .fetch_one(&mut *c)
        .await;
        let permit = match op_row {
            Err(_) => return StepResult::LeaseLost,
            Ok((cap, _)) if cap == "repeatable_read" => {
                if let Some(why) = *step.stop.borrow() {
                    return stopped_step(why);
                }
                if Instant::now() >= step.deadline {
                    return StepResult::Handoff;
                }
                approvals::start_replayed_read(&mut c, &lease, op, proposal, settings, &policy)
                    .await
            }
            // Only legacy single-phase rows (`dispatched_attempts IS NULL`, created while
            // `two_phase_effect_intents_enabled = false`) may bypass Transaction 2.
            Ok((_, None)) if fresh.is_some() => Ok(ReplayEffect::Ready(fresh.unwrap())),
            // Any unproven-sent two-phase write (`dispatched_attempts = 0`, whether freshly
            // inserted or reclaimed via `IntentResult::Replayed`), and any two-phase write with a
            // fresh first-phase permit (even if a same-claim peer already advanced attempts >= 1),
            // MUST go through Transaction 2 (`start_write_attempt`).
            Ok((_, Some(attempts))) if attempts == 0 || fresh.is_some() => {
                if let Some(why) = *step.stop.borrow() {
                    return stopped_step(why);
                }
                if Instant::now() >= step.deadline {
                    return StepResult::Handoff;
                }
                approvals::start_write_attempt(&mut c, &lease, op, proposal, settings, &policy)
                    .await
            }
            Ok(_) => {
                approvals::recheck_replay_effect_authority(
                    &mut c, &lease, op, proposal, settings, &policy,
                )
                .await
            }
        };
        let bytes = match start_permit(
            &mut c,
            &lease,
            (op, proposal),
            settings,
            &policy,
            &mut step,
            permit,
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(step) => return step,
        };
        drop(c);
        let result = match timeout_at(
            step.deadline,
            effects
                .adapter
                .send(run, op.to_owned(), bytes, step.clone()),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => return StepResult::Handoff,
        };
        let output = match result {
            StepResult::ToolSuccess { text, handle } if proposal.tool != crate::mcp::READ_RANGE => {
                let cx = artifact_fs::SpillContext {
                    pool,
                    lease,
                    proposal,
                    operation: op,
                    step: &step,
                };
                return artifact_fs::publish_bytes_with_handle(
                    &cx,
                    artifacts,
                    &text,
                    handle.as_deref(),
                    settings,
                    &policy,
                )
                .await;
            }
            StepResult::ToolSuccess { text, handle } => {
                if *step.stop.borrow() == Some(Stop::LeaseLost) {
                    return StepResult::LeaseLost;
                }
                let Ok(mut c) = pool.acquire().await else {
                    return StepResult::LeaseLost;
                };
                if let Err(e) = crate::mcp::observe_known_with_handle(
                    &mut c,
                    &lease,
                    &step,
                    op,
                    true,
                    handle.as_deref(),
                    &text,
                )
                .await
                {
                    return turns::lease_step(e);
                }
                text
            }
            StepResult::ToolResponse(Ok(text)) if proposal.tool != crate::mcp::READ_RANGE => {
                let cx = artifact_fs::SpillContext {
                    pool,
                    lease,
                    proposal,
                    operation: op,
                    step: &step,
                };
                return artifact_fs::publish_bytes(&cx, artifacts, &text, settings, &policy).await;
            }
            StepResult::ToolResponse(known) => {
                // Range pages have already been sized after JSON escaping. Known faults
                // always use a fixed inline envelope and cannot enter spill publication.
                let success = known.is_ok();
                let output = known.unwrap_or_else(crate::mcp::ToolFault::envelope);
                if *step.stop.borrow() == Some(Stop::LeaseLost) {
                    return StepResult::LeaseLost;
                }
                let Ok(mut c) = pool.acquire().await else {
                    return StepResult::LeaseLost;
                };
                if let Err(e) =
                    crate::mcp::observe_known(&mut c, &lease, &step, op, success, &output).await
                {
                    return turns::lease_step(e);
                }
                output
            }
            StepResult::ToolOutput(output) => output,
            other => return other,
        };
        if let Some(why) = *step.stop.borrow() {
            return stopped_step(why);
        }
        if Instant::now() >= step.deadline {
            return StepResult::Handoff;
        }
        let Ok(mut c) = pool.acquire().await else {
            return StepResult::LeaseLost;
        };
        match approvals::recheck_replay_effect_authority(
            &mut c, &lease, op, proposal, settings, &policy,
        )
        .await
        {
            Ok(ReplayEffect::Observed {
                output: Some(stored),
                ..
            }) => StepResult::ToolOutput(stored),
            // Preserve the output of legacy adapters with their own observation format.
            Ok(ReplayEffect::Observed {
                succeeded: true, ..
            }) if output.len() <= 65536 => StepResult::ToolOutput(output),
            Ok(ReplayEffect::Invalidated(s)) => StepResult::Invalidated(s),
            Err(e) => turns::lease_step(e),
            _ => fail,
        }
    }
}

/// If the conservative local authority clock fires, consult the primary before
/// invalidating. A second short local window hands off without starting work.
pub(crate) async fn start_permit(
    c: &mut sqlx::PgConnection,
    lease: &leases::Lease<'_>,
    effect: (&str, &Proposal),
    settings: &LeaseSettings,
    policy: &impl EffectPolicy,
    step: &mut StepContext,
    mut permit: Result<approvals::ReplayEffect, LeaseError>,
) -> Result<Vec<u8>, StepResult> {
    use approvals::{ReplayEffect, StartPermit};
    let (operation, proposal) = effect;
    let mut refreshed = false;
    loop {
        match permit {
            Ok(ReplayEffect::Ready(intent)) => match intent.start(step) {
                StartPermit::Stopped(stop) => return Err(stopped_step(stop)),
                StartPermit::LeaseMarginExhausted => return Err(StepResult::Handoff),
                StartPermit::AuthorityExpired { .. } if !refreshed => {
                    refreshed = true;
                    permit = approvals::expire_unstarted_intent(
                        c, lease, operation, proposal, settings, policy,
                    )
                    .await;
                }
                StartPermit::AuthorityExpired { .. } => return Err(StepResult::Handoff),
                StartPermit::Ready { request, deadline } => {
                    step.deadline = deadline;
                    return Ok(request);
                }
            },
            Ok(ReplayEffect::Observed {
                output: Some(output),
                ..
            }) => {
                return Err(if let Some(why) = *step.stop.borrow() {
                    stopped_step(why)
                } else if Instant::now() >= step.deadline {
                    StepResult::Handoff
                } else {
                    StepResult::ToolOutput(output)
                });
            }
            Ok(ReplayEffect::Invalidated(s)) => return Err(StepResult::Invalidated(s)),
            Ok(ReplayEffect::Handoff | ReplayEffect::Pending) => return Err(StepResult::Handoff),
            Ok(ReplayEffect::Exhausted) => return Err(StepResult::Stopped),
            Ok(_) => return Err(StepResult::Failed(FailReason::StepFailed)),
            Err(e) => return Err(turns::lease_step(e)),
        }
    }
}

pub(crate) fn stopped_step(why: Stop) -> StepResult {
    match why {
        Stop::LeaseLost => StepResult::LeaseLost,
        Stop::Shutdown => StepResult::Handoff,
        Stop::Deadline | Stop::Cancel => StepResult::Stopped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::{Process, metrics::Metrics};
    use opentelemetry_proto::tonic::{
        common::v1::any_value::Value as AnyVal,
        metrics::v1::{metric, number_data_point::Value as NumVal},
    };
    use std::collections::BTreeMap;

    fn drift_counts(store: &Metrics) -> BTreeMap<String, i64> {
        let req = store
            .encode_otlp(Process::Api, None)
            .expect("non-empty metrics");
        let mut counts = BTreeMap::new();
        for metric in &req.resource_metrics[0].scope_metrics[0].metrics {
            if metric.name != "openmettle.storage.quota.drift" {
                continue;
            }
            let Some(metric::Data::Sum(sum)) = metric.data.as_ref() else {
                panic!("expected Sum for openmettle.storage.quota.drift");
            };
            for dp in &sum.data_points {
                let outcome = dp
                    .attributes
                    .iter()
                    .find(|kv| kv.key == "outcome")
                    .and_then(|kv| kv.value.as_ref())
                    .and_then(|v| v.value.as_ref())
                    .and_then(|v| match v {
                        AnyVal::StringValue(s) => Some(s.clone()),
                        _ => None,
                    })
                    .expect("outcome attribute");
                let Some(NumVal::AsInt(value)) = dp.value else {
                    panic!("expected integer counter value");
                };
                counts.insert(outcome, value);
            }
        }
        counts
    }

    #[test]
    fn local_stop_point_is_anchored_at_send_and_execution_wins_a_tie() {
        let sent = Instant::now();
        let secs = Duration::from_secs;
        for (lease, execution, expected, cause) in [
            (30, 120, 20, Stop::LeaseLost),
            (15, 15, 5, Stop::Deadline),
            (20, 4, 0, Stop::Deadline),
            (2, 60, 0, Stop::LeaseLost),
        ] {
            assert_eq!(
                stop_point(sent, secs(lease), secs(execution), secs(10)),
                (sent + secs(expected), cause)
            );
        }
    }

    #[tokio::test]
    async fn drift_verification_records_all_eight_outcomes_accurately() {
        let store = Metrics::new();

        // Healthy report (including non-zero informational pending/unsettled fields) records `healthy: 1`.
        assert!(record_drift_verification::<()>(
            &store,
            Ok(Ok(artifact_fs::Drift {
                pending_gateway: 4,
                unsettled_payloads: 2,
                ..artifact_fs::Drift::default()
            })),
        ));
        assert_eq!(
            drift_counts(&store),
            BTreeMap::from([("healthy".to_owned(), 1)])
        );

        // Unhealthy report records each non-zero mismatch category with its observed count.
        assert!(!record_drift_verification::<()>(
            &store,
            Ok(Ok(artifact_fs::Drift {
                storage_accounts: 2,
                budgets: 3,
                settlements: 4,
                pending_gateway: 9,
                files: 5,
                quarantined: 6,
                unsettled_payloads: 7,
            })),
        ));

        // Verification error records `error: 1`.
        assert!(!record_drift_verification(&store, Ok(Err("db_error"))));

        // Defensive negative count on an unhealthy report still falls back to `error: 1`.
        assert!(!record_drift_verification::<()>(
            &store,
            Ok(Ok(artifact_fs::Drift {
                storage_accounts: -1,
                ..artifact_fs::Drift::default()
            })),
        ));

        // Real timeout records `timeout: 1`.
        let timed_out: Result<Result<artifact_fs::Drift, ()>, _> =
            timeout(Duration::from_millis(1), std::future::pending()).await;
        assert!(!record_drift_verification(&store, timed_out));

        assert_eq!(
            drift_counts(&store),
            BTreeMap::from([
                ("budgets".to_owned(), 3),
                ("error".to_owned(), 2),
                ("files".to_owned(), 5),
                ("healthy".to_owned(), 1),
                ("quarantined".to_owned(), 6),
                ("settlements".to_owned(), 4),
                ("storage_accounts".to_owned(), 2),
                ("timeout".to_owned(), 1),
            ])
        );
    }

    #[test]
    fn handoff_run_outcome_reports_committed_disposition_and_fence_errors() {
        assert_eq!(
            handoff_run_outcome(&Ok(leases::Handoff::Released)),
            WorkerRunOutcome::Handoff
        );
        assert_eq!(
            handoff_run_outcome(&Ok(leases::Handoff::Settled(Settled::Terminal {
                state: "cancelled",
            }))),
            WorkerRunOutcome::Cancelled
        );
        assert_eq!(
            handoff_run_outcome(&Ok(leases::Handoff::Settled(Settled::Reconciling {
                unresolved: 1,
            }))),
            WorkerRunOutcome::Reconciling
        );
        assert_eq!(
            handoff_run_outcome(&Err(LeaseError::StaleClaim)),
            WorkerRunOutcome::LeaseLost
        );
        assert_eq!(
            handoff_run_outcome(&Err(LeaseError::Expired)),
            WorkerRunOutcome::LeaseLost
        );
        assert_eq!(
            handoff_run_outcome(&Err(LeaseError::Terminal {
                state: "cancelled".to_owned(),
            })),
            WorkerRunOutcome::LeaseLost
        );
        assert_eq!(
            handoff_run_outcome(&Err(LeaseError::Store(StoreError::InvalidInput("x")))),
            WorkerRunOutcome::Aborted
        );
    }

    #[tokio::test]
    async fn reconcile_operation_records_outcome_and_event_when_db_connection_fails() {
        use crate::telemetry::{Format, Verbosity, tests::Capture};
        use sqlx::postgres::PgPoolOptions;

        struct FakeExecutor;
        impl Executor for FakeExecutor {
            async fn step(&self, _: &ActiveRun, _: StepContext) -> StepResult {
                StepResult::Finished
            }
            async fn reconcile(
                &self,
                _: &ActiveRun,
                _: &UnresolvedOperation,
                _: StepContext,
            ) -> Option<OwnedObservation> {
                Some(OwnedObservation {
                    key: "obs-1".to_owned(),
                    outcome: "succeeded".to_owned(),
                    handle: None,
                    format: "synthetic.obs".to_owned(),
                    version: 1,
                    evidence: b"{}".to_vec(),
                })
            }
        }

        let closed_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let db_url = format!("postgres://unused@127.0.0.1:{closed_port}/unused?sslmode=disable");
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(50))
            .connect_lazy_with(db_url.parse().unwrap());

        const RUN_ID: &str = "11111111-1111-4111-8111-111111111111";
        const OP_ID: &str = "22222222-2222-4222-8222-222222222222";
        const CLAIM_TOKEN: &str = "33333333-3333-4333-8333-333333333333";
        let lease_id = derive_run_lease_id(RUN_ID, CLAIM_TOKEN);
        let run = ActiveRun {
            claim: ClaimedRun {
                scope_id: "44444444-4444-4444-8444-444444444444".to_owned(),
                run_id: RUN_ID.to_owned(),
                claim_token: CLAIM_TOKEN.to_owned(),
                actor_approval_id: "55555555-5555-4555-8555-555555555555".to_owned(),
                round_limit: 5,
                lease_remaining: Duration::from_secs(30),
                execution_remaining: Duration::from_secs(120),
            },
            state: ExecState::Reconciling,
            execution_deadline: Instant::now() + Duration::from_secs(120),
        };
        let op = UnresolvedOperation {
            id: OP_ID.to_owned(),
            logical_key: "synthetic-key".to_owned(),
            target: "tool".to_owned(),
            capability: "cap".to_owned(),
            outcome: "outcome_unknown".to_owned(),
            revision: 0,
            downstream_handle: None,
            dispatched_attempts: Some(1),
        };
        let children = StepTasks::default();
        let (_stop_tx, stop_rx) = watch::channel(None);
        let (_dl_tx, dl_rx) =
            watch::channel((Instant::now() + Duration::from_secs(30), Stop::Deadline));
        let context = RunContext {
            deadline: dl_rx,
            stop: stop_rx,
            tasks: children.handle(),
        };

        let (capture, _guard) = Capture::install(Format::Json, Verbosity::Debug);
        let res = reconcile_operation(&pool, &run, &op, &FakeExecutor, &context, &lease_id).await;
        assert!(matches!(res, Err(LeaseError::Store(_))));

        let events = capture.events("worker.operation.completed");
        assert_eq!(events.len(), 1, "{}", capture.text());
        assert_eq!(events[0]["run_id"].as_str(), Some(RUN_ID));
        assert_eq!(events[0]["lease_id"].as_str(), Some(lease_id.as_str()));
        assert_eq!(events[0]["operation_id"].as_str(), Some(OP_ID));
        assert_eq!(events[0]["operation.kind"].as_str(), Some("reconcile"));
        assert_eq!(events[0]["operation.outcome"].as_str(), Some("failed"));
        capture.assert_absent(&[CLAIM_TOKEN.as_bytes()]);
    }

    #[tokio::test]
    async fn reconcile_operation_records_outcome_and_event_when_dropped_while_pending() {
        use crate::telemetry::{
            Format, Process, Verbosity,
            tests::{
                Capture,
                otlp::{Collector, attributes, finish, start_traces, text},
            },
        };
        use sqlx::postgres::PgPoolOptions;
        use std::sync::Arc;
        use tokio::sync::Notify;

        struct PendingExecutor(Arc<Notify>);
        impl Executor for PendingExecutor {
            async fn step(&self, _: &ActiveRun, _: StepContext) -> StepResult {
                StepResult::Finished
            }
            async fn reconcile(
                &self,
                _: &ActiveRun,
                _: &UnresolvedOperation,
                _: StepContext,
            ) -> Option<OwnedObservation> {
                self.0.notify_one();
                std::future::pending().await
            }
        }

        let closed_port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let db_url = format!("postgres://unused@127.0.0.1:{closed_port}/unused?sslmode=disable");
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(50))
            .connect_lazy_with(db_url.parse().unwrap());

        const RUN_ID: &str = "11111111-1111-4111-8111-111111111112";
        const OP_ID: &str = "22222222-2222-4222-8222-222222222223";
        const CLAIM_TOKEN: &str = "33333333-3333-4333-8333-333333333334";
        let lease_id = derive_run_lease_id(RUN_ID, CLAIM_TOKEN);
        let run = ActiveRun {
            claim: ClaimedRun {
                scope_id: "44444444-4444-4444-8444-444444444445".to_owned(),
                run_id: RUN_ID.to_owned(),
                claim_token: CLAIM_TOKEN.to_owned(),
                actor_approval_id: "55555555-5555-4555-8555-555555555556".to_owned(),
                round_limit: 5,
                lease_remaining: Duration::from_secs(30),
                execution_remaining: Duration::from_secs(120),
            },
            state: ExecState::Reconciling,
            execution_deadline: Instant::now() + Duration::from_secs(120),
        };
        let op = UnresolvedOperation {
            id: OP_ID.to_owned(),
            logical_key: "synthetic-pending-key".to_owned(),
            target: "tool".to_owned(),
            capability: "cap".to_owned(),
            outcome: "outcome_unknown".to_owned(),
            revision: 0,
            downstream_handle: None,
            dispatched_attempts: Some(1),
        };

        let collector = Collector::accepting().await;
        let (tracer, exporter) = start_traces(collector.destination(), Process::Worker);
        let (capture, sub_guard) = Capture::install_traced(Format::Json, Verbosity::Debug, tracer);

        // Case 1: dropped while pending with no lease loss -> `stopped`.
        {
            let children = StepTasks::default();
            let (_stop_tx, stop_rx) = watch::channel(None);
            let (_dl_tx, dl_rx) =
                watch::channel((Instant::now() + Duration::from_secs(30), Stop::Deadline));
            let context = RunContext {
                deadline: dl_rx,
                stop: stop_rx,
                tasks: children.handle(),
            };
            let entered = Arc::new(Notify::new());
            let exec = PendingExecutor(entered.clone());
            let mut fut = std::pin::pin!(reconcile_operation(
                &pool, &run, &op, &exec, &context, &lease_id
            ));
            tokio::select! {
                biased;
                _ = &mut fut => panic!("pending executor must not resolve"),
                _ = entered.notified() => {}
            }
        }

        // Case 2: `Stop::LeaseLost` observed before drop -> `lease_lost`.
        {
            let children = StepTasks::default();
            let (stop_tx, stop_rx) = watch::channel(None);
            let (_dl_tx, dl_rx) =
                watch::channel((Instant::now() + Duration::from_secs(30), Stop::Deadline));
            let context = RunContext {
                deadline: dl_rx,
                stop: stop_rx,
                tasks: children.handle(),
            };
            let entered = Arc::new(Notify::new());
            let exec = PendingExecutor(entered.clone());
            let mut fut = std::pin::pin!(reconcile_operation(
                &pool, &run, &op, &exec, &context, &lease_id
            ));
            tokio::select! {
                biased;
                _ = &mut fut => panic!("pending executor must not resolve"),
                _ = entered.notified() => {}
            }
            stop_tx.send(Some(Stop::LeaseLost)).unwrap();
        }

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

        for (i, expected_outcome) in ["stopped", "lease_lost"].into_iter().enumerate() {
            let span = &spans[i];
            assert_eq!(span.dropped_attributes_count, 0);
            let attrs = attributes(&span.attributes);
            assert_eq!(text(attrs["run_id"]), Some(RUN_ID));
            assert_eq!(text(attrs["lease_id"]), Some(lease_id.as_str()));
            assert_eq!(text(attrs["operation_id"]), Some(OP_ID));
            assert_eq!(text(attrs["operation.kind"]), Some("reconcile"));
            assert_eq!(text(attrs["operation.outcome"]), Some(expected_outcome));

            let ev = &events[i];
            assert_eq!(ev["run_id"].as_str(), Some(RUN_ID));
            assert_eq!(ev["lease_id"].as_str(), Some(lease_id.as_str()));
            assert_eq!(ev["operation_id"].as_str(), Some(OP_ID));
            assert_eq!(ev["operation.kind"].as_str(), Some("reconcile"));
            assert_eq!(ev["operation.outcome"].as_str(), Some(expected_outcome));
            assert!(ev["duration_us"].as_u64().is_some());
        }

        capture.assert_absent(&[CLAIM_TOKEN.as_bytes()]);
        collector.assert_absent(&[CLAIM_TOKEN.as_bytes()]);
    }
}
