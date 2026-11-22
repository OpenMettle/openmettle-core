//! Cooperative, fenced worker execution and scheduled maintenance (ADR 0033).
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
    telemetry::{Sweep, sweep_failed},
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
    /// Model-visible output of an observed, reviewed tool operation.
    ToolOutput(String),
    /// A fenced authority check already invalidated the run.
    Invalidated,
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
        operation: &UnresolvedOperation,
        cx: StepContext,
    ) -> impl Future<Output = Option<OwnedObservation>> + Send;
}

/// A reviewed adapter receives only committed bytes. It records observations with a Hold fence.
pub trait ApprovedAdapter: Send + Sync {
    fn send<'a>(
        &'a self,
        run: &'a ActiveRun,
        operation_id: String,
        request: Vec<u8>,
        step: StepContext,
    ) -> std::pin::Pin<Box<dyn Future<Output = StepResult> + Send + 'a>>;
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
}

struct Adapters<'a, E> {
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

pub(crate) async fn maintenance(
    pool: &PgPool,
    store: Option<&artifact_fs::Store>,
    period: Duration,
) {
    let mut held = crate::quotas::Pass::default();
    let mut orphans = crate::quotas::Pass::default();
    let verify_interval = Duration::from_secs(3600);
    let mut next_verification = Instant::now() + verify_interval;
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
        let warnings_ok = sweep(crate::quotas::emit_warnings(pool)).await;
        let overdue_ok = sweep(crate::quotas::observe_overdue_handoffs(pool, 100)).await;
        let mut drift_ok = true;
        if Instant::now() >= next_verification {
            next_verification = Instant::now() + verify_interval;
            drift_ok = matches!(timeout(Duration::from_secs(15),
                artifact_fs::verify_accounting_drift(pool, store)).await, Ok(Ok(report)) if report.healthy());
        }
        if !(holds_ok && orphans_ok && warnings_ok && overdue_ok && drift_ok) {
            crate::telemetry::metrics::quota_sweep_failed();
        }
        if let Some(store) = store {
            let age = artifact_fs::UPLOAD_TIMEOUT + Duration::from_secs(300);
            if !sweep(artifact_fs::reconcile_expired(pool, store, age, 100)).await {
                sweep_failed(Sweep::Uploads);
            }
            if !sweep(artifact_fs::purge_due(pool, store, 100)).await {
                sweep_failed(Sweep::Retention);
            }
        }
    }
}

async fn claim(
    pool: &PgPool,
    policy: RunPolicy,
) -> Result<Option<(ActiveRun, Instant, bool)>, StoreError> {
    let mut c = connection(pool).await?;
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
                    runs.spawn(async move {
                        run_one(
                            &pool,
                            Adapters {
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

async fn reconcile<E: Executor>(
    pool: &PgPool,
    run: &ActiveRun,
    executor: &E,
    context: &RunContext,
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
            if let Some(o) = executor.reconcile(op, context.step()).await {
                let mut c = connection(pool).await?;
                if context.stopped() == Some(Stop::LeaseLost) {
                    return Ok(WorkEnd::Stop(Stop::LeaseLost));
                }
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
            } else if let Some(why) = context.stopped() {
                return Ok(WorkEnd::Stop(why));
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
    Invalidated,
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
) -> Result<WorkEnd, LeaseError> {
    if run.state == ExecState::Reconciling {
        return reconcile(pool, run, adapters.executor, context).await;
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
        if queue::recheck_claim(&mut *connection(pool).await?, &run.claim, settings)
            .await?
            .is_some()
        {
            return Ok(WorkEnd::Invalidated);
        }
        if let Some(why) = context.stopped() {
            return Ok(WorkEnd::Stop(why));
        }
        let pending =
            approvals::pending_effect(&mut *connection(pool).await?, &run.claim.lease()).await?;
        if let Some(why) = context.stopped() {
            return Ok(WorkEnd::Stop(why));
        }
        let result = if let Some((id, proposal)) = pending {
            if !adapters.executor.can_resume_approved(&proposal) {
                return Ok(WorkEnd::Complete(Settle::Failed(FailReason::StepFailed)));
            }
            let intent = approvals::record_fenced_intent(
                &mut *connection(pool).await?,
                &run.claim.lease(),
                &proposal,
                Some(&id),
                &adapters.approved,
                settings,
            )
            .await?;
            match intent {
                IntentResult::Applied(intent) => {
                    let mut step = context.step();
                    let operation = intent.operation_id.clone();
                    let Some((request, deadline)) = intent.start(&step) else {
                        return Ok(WorkEnd::Complete(Settle::Stopped));
                    };
                    step.deadline = deadline;
                    adapters
                        .approved
                        .ok_or(StoreError::Conflict("approval adapter"))?
                        .adapter
                        .send(run, operation, request, step)
                        .await
                }
                IntentResult::Invalidated(_) => return Ok(WorkEnd::Invalidated),
                _ => return Ok(WorkEnd::Complete(Settle::Stopped)),
            }
        } else {
            adapters.executor.step(run, context.step()).await
        };
        match result {
            StepResult::Invalidated => return Ok(WorkEnd::Invalidated),
            StepResult::Answer(answer) => return Ok(WorkEnd::Answer(answer)),
            StepResult::ToolOutput(_) => {
                return Ok(WorkEnd::Complete(Settle::Failed(FailReason::StepFailed)));
            }
            StepResult::Continue => continue,
            StepResult::Finished => return Ok(WorkEnd::Complete(Settle::Succeeded)),
            StepResult::Failed(reason) => return Ok(WorkEnd::Complete(Settle::Failed(reason))),
            StepResult::Stopped => return Ok(WorkEnd::Complete(Settle::Stopped)),
        }
    }
}

async fn run_one<E: Executor>(
    pool: &PgPool,
    adapters: Adapters<'_, E>,
    run: ActiveRun,
    sent: Instant,
    recovered: bool,
    settings: LeaseSettings,
    mut shutdown: watch::Receiver<Option<Instant>>,
) {
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
        match execute(pool, adapters, &run, recovered, &settings, &context).await {
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
                WorkEnd::Invalidated => Some(Stop::Cancel),
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
        return;
    }
    let Ok(mut c) = connection(pool).await else {
        return;
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
                    return;
                }
                _ => return,
            }
        }
        WorkEnd::Invalidated => {
            let _ = leases::release_lease(&mut c, &lease).await;
            return;
        }
        WorkEnd::Complete(input @ (Settle::Succeeded | Settle::Failed(_))) => input,
        WorkEnd::Complete(Settle::Stopped) if run.state == ExecState::Reconciling => {
            Settle::Stopped
        }
        _ if cause == Some(Stop::Shutdown) => {
            let _ = leases::handoff(&mut c, &lease, &settings).await;
            return;
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
