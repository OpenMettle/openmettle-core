//! A spill holds its exclusive file lock from creation through commit. Ambiguous
//! commits leave all names intact for replay and the reservation's dedicated cleaner.
use super::*;
use crate::{
    authz::{
        approvals::Proposal,
        leases::{self, Fence, Lease, LeaseError},
    },
    mcp::{self, result::Output},
    worker::StepContext,
};
use tokio::{
    sync::Semaphore,
    time::{Instant, timeout},
};

static PERMITS: OnceLock<Arc<Semaphore>> = OnceLock::new();
pub(crate) fn configure_slots(slots: usize) {
    PERMITS.get_or_init(|| Arc::new(Semaphore::new(slots)));
}

impl Store {
    /// Verify a no-replace hard link, file fsync and both directory fsyncs before serving.
    pub fn probe_writable(&self) -> Result<(), Error> {
        let v = &self.volume;
        v.recheck()?;
        let id = crate::telemetry::RequestId::generate().ok_or(Error::Io)?;
        let name = format!(".tool-probe.{id}");
        let file = fs::File::from(at::openat(
            &v.staging,
            &name,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )?);
        let ino = file.metadata()?.ino();
        let mut linked = false;
        let result = (|| {
            file.try_lock().map_err(|_| Error::Io)?;
            file.sync_all()?;
            at::linkat(&v.staging, &name, &v.revisions, &name, AtFlags::empty())?;
            linked = true;
            if at::linkat(&v.staging, &name, &v.revisions, &name, AtFlags::empty())
                != Err(rustix::io::Errno::EXIST)
            {
                return Err(Error::Io);
            }
            v.matches(&file, &v.revisions, &name, ino)?;
            at::fsync(&v.revisions)?;
            Ok(())
        })();
        let rev = if linked {
            v.unlink(&v.revisions, &name, ino)
        } else {
            Ok(())
        };
        let stage = v.unlink(&v.staging, &name, ino);
        let sync_rev = at::fsync(&v.revisions);
        let sync_stage = at::fsync(&v.staging);
        rev?;
        stage?;
        sync_rev?;
        sync_stage?;
        result
    }
}

pub struct SpillContext<'a> {
    pub pool: &'a PgPool,
    pub lease: Lease<'a>,
    pub proposal: &'a Proposal,
    pub operation: &'a str,
    pub step: &'a StepContext,
}

impl SpillContext<'_> {
    async fn fenced<T>(
        &self,
        body: impl AsyncFnOnce(&mut WriteTransaction<'_>) -> Result<T, runs::Error>,
    ) -> Result<T, LeaseError> {
        let mut c = self
            .pool
            .acquire()
            .await
            .map_err(crate::authz::store::StoreError::from)?;
        leases::with_lease(&mut c, &self.lease, Fence::Step, async |tx, _| {
            body(tx).await
        })
        .await
    }
}

#[derive(Debug)]
enum SpillError {
    Storage,
    Quota,
    Saturated,
    Stopped,
    LeaseLost,
}
impl SpillError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Saturated => "spill_saturated",
            Self::Quota => "quota_exceeded",
            _ => "storage_io",
        }
    }
}
impl From<LeaseError> for SpillError {
    fn from(e: LeaseError) -> Self {
        match e {
            LeaseError::Stopping(_) => Self::Stopped,
            LeaseError::Store(_) => Self::Storage,
            _ => Self::LeaseLost,
        }
    }
}

async fn try_publish(
    cx: &SpillContext<'_>,
    store: &Store,
    output: &Output<'_>,
) -> Result<String, SpillError> {
    let mut stop = cx.step.stop.clone();
    let deadline = cx.step.deadline;
    tokio::select! {
        biased;
        _=stop.wait_for(Option::is_some)=>Err(SpillError::Stopped),
        _=tokio::time::sleep_until(deadline)=>Err(SpillError::Stopped),
        result=publish(cx,store,output)=>result,
    }
}

async fn publish(
    cx: &SpillContext<'_>,
    store: &Store,
    output: &Output<'_>,
) -> Result<String, SpillError> {
    let permit = PERMITS
        .get_or_init(|| Arc::new(Semaphore::new(1)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| SpillError::Saturated)?;
    let size = output.text.len() as i64;
    let expected_pin = store
        .prepare(cx.pool, false)
        .await
        .map_err(|_| SpillError::Storage)?
        .ok_or(SpillError::Storage)?;
    // Commit quota and the stage claim before creating a filesystem entry. Derive the
    // owner from the run under its Step fence, never from the caller or tool response.
    let (pin, artifact, reservation) = cx.fenced(async |tx| {
        let c = tx.connection()?;
        let (actor, artifact, attempt, pin): (String, String, String, String) = sqlx::query_as(
                "SELECT r.actor_user_id::text,gen_random_uuid()::text,gen_random_uuid()::text,openmettle.storage_lock_pinned_volume()::text
                 FROM openmettle.runs r JOIN openmettle.operations o ON o.run_id=r.id AND o.scope_id=r.scope_id
                 WHERE r.id=$1::uuid AND r.scope_id=$2::uuid AND o.id=$3::uuid AND o.logical_key=$4 AND o.revision=0 AND o.outcome='intent'")
                .bind(cx.lease.run_id).bind(cx.lease.scope_id).bind(cx.operation).bind(&cx.proposal.logical_key).fetch_one(c).await?;
        if pin != expected_pin {
            return Err(runs::Error::Conflict);
        }
        let key = format!("tool-spill:{}:{}", cx.operation, attempt);
        let reservation = match storage::reserve(
            tx,
            &ReservationInput {
                scope: cx.lease.scope_id,
                actor: &actor,
                key: &key,
                artifact: &artifact,
                max_bytes: size,
                run: Some(cx.lease.run_id),
                operation: Some(cx.operation),
            },
        )
        .await
        {
            Ok(r) => r.id,
            Err(
                runs::Error::InstanceLimit
                | runs::Error::OwnerLimit
                | runs::Error::LimitUnconfigured
                | runs::Error::InstanceLimitUnconfigured,
            ) => return Ok(None),
            Err(e) => return Err(e),
        };
        sqlx::query("UPDATE openmettle.storage_reservations SET stage_claimed=true WHERE id=$1::uuid")
            .bind(&reservation)
            .execute(tx.connection()?)
            .await?;
        Ok(Some((pin, artifact, reservation)))
    }).await?.ok_or(SpillError::Quota)?;

    // The blocking job owns the permit even if its async caller is dropped.
    let stage = {
        let store = store.clone();
        let pin = pin.clone();
        let id = reservation.clone();
        tokio::task::spawn_blocking(move || {
            store.volume.verify(&pin)?;
            let stage = store.create_stage(&id, true)?;
            stage.file.as_ref().ok_or(Error::Io)?.sync_all()?;
            Ok::<_, Error>((stage, permit))
        })
        .await
        .map_err(|_| SpillError::Storage)?
        .map_err(|_| SpillError::Storage)?
    };
    let ino = stage.0.ino;
    cx.fenced(async |tx|{
        lock_writer(tx,&reservation,Some(&pin),true,None,false).await.map_err(|_|runs::Error::Conflict)?;
        sqlx::query("UPDATE openmettle.storage_reservations SET payload_ino=$2::text::numeric WHERE id=$1::uuid")
            .bind(&reservation).bind(ino.to_string()).execute(tx.connection()?).await?;
        Ok(())
    }).await?;

    let bytes = output.text.as_bytes().to_vec();
    let step = cx.step.clone();
    let stage = tokio::task::spawn_blocking(move || {
        let (mut staged, permit) = stage;
        let file = staged.file.as_mut().ok_or(Error::Io)?;
        for chunk in bytes.chunks(65536) {
            if step.stop.borrow().is_some() || Instant::now() >= step.deadline {
                return Err(Error::Io);
            }
            file.write_all(chunk)?;
        }
        file.sync_all()?;
        staged
            .volume
            .matches(file, &staged.volume.staging, &staged.id, ino)?;
        if file.metadata()?.len() != size as u64 {
            return Err(Error::Io);
        }
        Ok((staged, permit))
    })
    .await
    .map_err(|_| SpillError::Storage)?
    .map_err(|_| SpillError::Storage)?;

    cx.fenced(async |tx| {
        lock_writer(tx, &reservation, Some(&pin), true, Some(ino), false)
            .await
            .map_err(|_| runs::Error::Conflict)?;
        sqlx::query(
            "UPDATE openmettle.storage_reservations SET publish_pending=true WHERE id=$1::uuid",
        )
        .bind(&reservation)
        .execute(tx.connection()?)
        .await?;
        Ok(())
    })
    .await?;
    let pin_copy = pin.clone();
    let step = cx.step.clone();
    let linked = tokio::task::spawn_blocking(move || {
        stage.0.volume.verify(&pin_copy)?;
        if step.stop.borrow().is_some() || Instant::now() >= step.deadline {
            return Err(Error::InProgress);
        }
        stage.0.publish()?;
        stage.0.volume.verify(&pin_copy)?;
        Ok::<_, Error>(Arc::new(stage))
    })
    .await
    .map_err(|_| SpillError::Storage)?;
    let stage = match linked {
        Ok(stage) => stage,
        Err(Error::InProgress) => return Err(SpillError::Stopped),
        Err(_) => {
            quarantine_writer(cx.pool, &reservation, ino)
                .await
                .map_err(|_| SpillError::Storage)?;
            return Err(SpillError::Storage);
        }
    };

    let mut mismatched = false;
    let encoded = cx.fenced(async |tx| {
        if cx.step.stop.borrow().is_some() || Instant::now() >= cx.step.deadline {
            return Err(runs::Error::Conflict);
        }
        lock_writer(tx, &reservation, Some(&pin), true, Some(ino), true)
            .await
            .map_err(|_| runs::Error::Conflict)?;
        let revision = storage::settle(
            tx,
            &Settlement {
                scope: cx.lease.scope_id,
                reservation: &reservation,
                size_bytes: size,
                content_digest: &output.digest,
                media_type: "text/plain; charset=utf-8",
                display_name: None,
            },
        )
        .await?;
        let encoded = output.preview(cx.proposal, cx.operation, Ok((&artifact, &revision)));
        mcp::observe(tx, &cx.lease, cx.operation, true, &encoded).await?;
        let check = stage.clone();
        let pin = pin.clone();
        let verified = timeout(
            Duration::from_secs(2),
            tokio::task::spawn_blocking(move || {
                let staged = &check.0;
                let file = staged.file.as_ref().ok_or(Error::Io)?;
                staged.volume.verify(&pin)?;
                staged
                    .volume
                    .matches(file, &staged.volume.staging, &staged.id, ino)?;
                staged
                    .volume
                    .matches(file, &staged.volume.revisions, &staged.id, ino)?;
                if file.metadata()?.len() != size as u64 {
                    return Err(Error::Io);
                }
                Ok(())
            }),
        )
        .await;
        match verified {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(_))) => {
                mismatched = true;
                return Err(runs::Error::Conflict);
            }
            _ => return Err(runs::Error::Conflict),
        }
        let live:bool=sqlx::query_scalar("SELECT state='running' AND cancel_reason IS NULL AND claim_token=$2::uuid AND
                least(lease_expires_at,execution_expires_at)>clock_timestamp() FROM openmettle.runs WHERE id=$1::uuid")
                .bind(cx.lease.run_id).bind(cx.lease.claim_token).fetch_one(tx.connection()?).await?;
        if !live || cx.step.stop.borrow().is_some() || Instant::now() >= cx.step.deadline {
            return Err(runs::Error::Conflict);
        }
        Ok(encoded)
    }).await;
    if mismatched {
        quarantine_writer(cx.pool, &reservation, ino)
            .await
            .map_err(|_| SpillError::Storage)?;
    }
    let encoded = encoded?;
    if let Ok((file, permit)) = Arc::try_unwrap(stage) {
        let volume = file.volume.clone();
        drop(file);
        let _ = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            volume.detach_staged(&reservation, ino)
        })
        .await;
    }
    Ok(encoded)
}

/// Complete a known successful normalized tool result. The revision and observation
/// commit together. Recover an uncertain acknowledgement by consulting the ledger.
pub async fn publish_bytes(
    cx: &SpillContext<'_>,
    store: Option<&Store>,
    text: &str,
    settings: &leases::LeaseSettings,
    policy: &impl crate::authz::approvals::EffectPolicy,
) -> crate::worker::StepResult {
    use crate::{
        authz::{
            approvals::{ReplayAction, ReplayEffect, check_operation},
            store::StoreError,
        },
        worker::{StepResult, turns::lease_step},
    };
    if *cx.step.stop.borrow() == Some(crate::worker::Stop::LeaseLost) {
        return StepResult::LeaseLost;
    }
    let fail = StepResult::Failed(leases::FailReason::StepFailed);
    if cx.proposal.tool == mcp::READ_RANGE {
        return fail;
    }
    let Ok(output) = Output::new(text) else {
        return fail;
    };
    let recheck = async |action| {
        let mut c = cx
            .pool
            .acquire()
            .await
            .map_err(crate::authz::store::StoreError::from)?;
        check_operation(
            &mut c,
            &cx.lease,
            cx.operation,
            cx.proposal,
            settings,
            policy,
            action,
        )
        .await
    };
    let observed = |r| match r {
        Ok(ReplayEffect::Observed {
            output: Some(output),
            ..
        }) => {
            if let Some(why) = *cx.step.stop.borrow() {
                crate::worker::stopped_step(why)
            } else {
                StepResult::ToolOutput(output)
            }
        }
        Ok(ReplayEffect::Invalidated(s)) => StepResult::Invalidated(s),
        Err(e) => lease_step(e),
        _ => StepResult::LeaseLost,
    };
    let mut fallback = output.inline();
    if fallback.is_none() {
        let error = match recheck(ReplayAction::PrepareSpill).await {
            Err(LeaseError::Stopping(_) | LeaseError::Store(StoreError::Denied(_))) => {
                Some("storage_io")
            }
            Ok(ReplayEffect::Pending)
                if cx.step.stop.borrow().is_some() || Instant::now() >= cx.step.deadline =>
            {
                Some("storage_io")
            }
            Ok(ReplayEffect::Pending) => match store {
                None => Some("store_unconfigured"),
                Some(store) => match try_publish(cx, store, &output).await {
                    Ok(_) => None,
                    Err(SpillError::LeaseLost) => return StepResult::LeaseLost,
                    Err(error) => Some(error.code()),
                },
            },
            other => return observed(other),
        };
        fallback = error.map(|code| output.preview(cx.proposal, cx.operation, Err(code)));
    }
    if *cx.step.stop.borrow() == Some(crate::worker::Stop::LeaseLost) {
        return StepResult::LeaseLost;
    }
    if let Some(s) = fallback {
        // The spill commit may already have won. The single observation key and
        // expected revision prevent a fallback from replacing the durable result.
        let write = async {
            let mut c = cx
                .pool
                .acquire()
                .await
                .map_err(crate::authz::store::StoreError::from)?;
            mcp::observe_known(&mut c, &cx.lease, cx.step, cx.operation, true, &s).await
        };
        match timeout(Duration::from_secs(2), write).await {
            Ok(Ok(())) => {}
            Ok(Err(LeaseError::Store(StoreError::Conflict(_)))) => {
                // A prior commit can have a different envelope for the same operation.
                return observed(recheck(ReplayAction::PrepareSpill).await);
            }
            Ok(Err(LeaseError::Store(StoreError::Database(_)))) => return StepResult::LeaseLost,
            Ok(Err(e)) => return lease_step(e),
            Err(_) => return StepResult::LeaseLost,
        }
    }
    if let Some(stop) = *cx.step.stop.borrow() {
        return crate::worker::stopped_step(stop);
    }
    observed(recheck(ReplayAction::Inspect).await)
}
