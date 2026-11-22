//! Bounded, resumable enumeration of staging aliases. Detaching a name never resizes its inode.
use super::*;
use rustix::fs::Dir;
use std::{
    collections::VecDeque,
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
};

type Slice = (Dir, VecDeque<OsString>, bool);

#[derive(Default)]
pub(super) enum StagingSweepState {
    #[default]
    Idle,
    Open(Dir, VecDeque<OsString>),
    InFlight(JoinHandle<std::io::Result<Slice>>),
    InvalidatedInFlight(JoinHandle<std::io::Result<Slice>>),
    DrainingEof(Dir, VecDeque<OsString>),
}

impl fmt::Debug for StagingSweepState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("staging directory sweep")
    }
}

fn read_slice(mut dir: Dir, limit: usize) -> std::io::Result<Slice> {
    let mut page = VecDeque::new();
    for _ in 0..limit {
        let Some(entry) = dir.read() else {
            return Ok((dir, page, true));
        };
        let entry = entry?;
        let name = OsStr::from_bytes(entry.file_name().to_bytes());
        if !matches!(name.to_str(), Some("." | ".." | ".openmettle-volume-id"))
            && !name.as_bytes().starts_with(b".openmettle-volume-id.tmp.")
        {
            page.push_back(name.to_owned());
        }
    }
    Ok((dir, page, false))
}

pub(super) async fn sweep(pool: &PgPool, store: &Store, limit: usize) -> Result<(), Error> {
    let mut state = store.staging_pass.lock().await;
    let pin = store.prepare(pool, false).await;
    if !matches!(&pin, Ok(Some(_))) {
        *state = match std::mem::take(&mut *state) {
            StagingSweepState::InFlight(task) | StagingSweepState::InvalidatedInFlight(task)
                if !task.is_finished() =>
            {
                StagingSweepState::InvalidatedInFlight(task)
            }
            _ => StagingSweepState::Idle,
        };
        return pin.map(|_| ());
    }
    let pin = pin?.ok_or(Error::Io)?;
    if let StagingSweepState::InvalidatedInFlight(task) = &mut *state {
        let _ = task.await;
        *state = StagingSweepState::Idle;
    }
    if matches!(*state, StagingSweepState::Idle) {
        *state = StagingSweepState::Open(Dir::read_from(&store.volume.staging)?, VecDeque::new());
    }
    if matches!(&*state,StagingSweepState::Open(_,q) if q.is_empty())
        && let StagingSweepState::Open(dir, _) = std::mem::take(&mut *state)
    {
        *state = StagingSweepState::InFlight(tokio::task::spawn_blocking(move || {
            read_slice(dir, limit.min(64))
        }));
    }
    if let StagingSweepState::InFlight(task) = &mut *state {
        let result = task.await;
        *state = StagingSweepState::Idle;
        let (dir, page, eof) = result.map_err(|_| Error::Io)??;
        *state = if eof {
            StagingSweepState::DrainingEof(dir, page)
        } else {
            StagingSweepState::Open(dir, page)
        };
    }
    let mut first_error = None;
    if let StagingSweepState::Open(dir, page) | StagingSweepState::DrainingEof(dir, page) =
        &mut *state
    {
        // Retain the directory handle until all returned names are inspected.
        let _directory = dir;
        for _ in 0..limit {
            let Some(name) = page.front() else { break };
            let result = detach_alias(pool, store, &pin, name).await;
            page.pop_front();
            if let Err(e) = result {
                first_error.get_or_insert(e);
            }
        }
    }
    if matches!(&*state,StagingSweepState::DrainingEof(_,q) if q.is_empty()) {
        *state = StagingSweepState::Idle;
    }
    first_error.map_or(Ok(()), Err)
}

async fn detach_alias(pool: &PgPool, store: &Store, pin: &str, name: &OsStr) -> Result<(), Error> {
    let v = &store.volume;
    // A non-UTF-8 name cannot represent a database UUID. Keep its original bytes for unlinkat.
    let text = name.to_str().unwrap_or("");
    let anchor = text.strip_prefix(".reclaim.");
    let id = anchor.unwrap_or(text);
    let Some(ino) = v.inode(&v.staging, name)? else {
        return Ok(());
    };
    let file = v.regular(&v.staging, name, true)?;
    match file.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => return Ok(()),
        Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
    }
    v.matches(&file, &v.staging, name, ino)?;
    let meta = file.metadata()?;
    let aged = meta
        .modified()?
        .elapsed()
        .is_ok_and(|age| age > Duration::from_secs(900));
    let mut tx = WriteTransaction::begin_bounded_pool(pool, false).await?;
    let canonical = runs::is_canonical_uuid(id);
    let row=sqlx::query("SELECT state,reclaim_state,payload_ino::text,adoption_unverified FROM openmettle.storage_reservations
        WHERE id=$1::uuid FOR UPDATE SKIP LOCKED").bind(canonical.then_some(id)).fetch_optional(tx.connection()?).await?;
    let mut clear = false;
    let serialize_orphan = match row {
        None if aged => {
            // SKIP LOCKED also returns no row for an active writer. An unlocked snapshot
            // distinguishes it from an orphan before taking the instance lock.
            if canonical
                && sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT FROM openmettle.storage_reservations WHERE id=$1::uuid)",
                )
                .bind(id)
                .fetch_one(tx.connection()?)
                .await?
            {
                return Ok(());
            }
            true
        }
        None => return Ok(()),
        Some(row) => {
            if row.get::<bool, _>("adoption_unverified") {
                return Ok(());
            }
            let state: &str = row.get("state");
            let bound = row
                .get::<Option<String>, _>("payload_ino")
                .map(|raw| raw.parse::<u64>())
                .transpose()
                .map_err(|_| Error::Io)?;
            match (state, row.get::<&str, _>("reclaim_state"), anchor.is_some()) {
                ("released", "anchor_pending_unlink", true)
                    if bound == Some(ino) && meta.len() == 0 =>
                {
                    clear = true;
                    false
                }
                ("released", "none", true) | ("settled", _, true) if aged => true,
                ("released", _, false) if bound.is_none() && meta.len() == 0 => false,
                ("settled", _, false) if bound == Some(ino) => {
                    let live = sqlx::query(
                        "SELECT FROM openmettle.artifact_revisions WHERE reservation_id=$1::uuid
                        AND state IN ('active','retained') FOR UPDATE SKIP LOCKED",
                    )
                    .bind(id)
                    .fetch_optional(tx.connection()?)
                    .await?;
                    if live.is_none() || v.inode(&v.revisions, id)? != Some(ino) {
                        return Ok(());
                    }
                    false
                }
                _ => return Ok(()),
            }
        }
    };
    reclaim::lock_pin(&mut tx, pin).await?;
    if serialize_orphan {
        sqlx::query("SELECT FROM openmettle.storage_instance WHERE id FOR NO KEY UPDATE")
            .fetch_one(tx.connection()?)
            .await?;
        let owned: bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM openmettle.storage_reservations WHERE id=$1::uuid
            AND (state='reserved' OR adoption_unverified OR NOT $2 OR reclaim_state='anchor_pending_unlink'))")
            .bind(canonical.then_some(id)).bind(anchor.is_some()).fetch_one(tx.connection()?).await?;
        if owned {
            return Ok(());
        }
    }
    v.verify(pin)?;
    v.matches(&file, &v.staging, name, ino)?;
    v.unlink(&v.staging, name, ino)?;
    drop(file);
    if clear {
        at::fsync(&v.staging)?;
        sqlx::query(
            "UPDATE openmettle.storage_reservations SET reclaim_state='none' WHERE id=$1::uuid",
        )
        .bind(id)
        .execute(tx.connection()?)
        .await?;
        tx.commit().await?;
    } else {
        tx.commit().await?;
        at::fsync(&v.staging)?;
    }
    Ok(())
}
