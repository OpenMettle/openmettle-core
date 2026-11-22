//! Filesystem artifact payloads. PostgreSQL owns reservation state and the volume pin.
//! An open regular file and a durable hard link preserve payload identity across commits.
pub mod adoption;
mod drift;
pub use drift::{Drift, verify_accounting_drift};
mod reclaim;
mod staging;
mod volume;
use crate::{
    multipart::{self, Form, Parser},
    runs::{self, WriteTransaction},
    storage::{self, ReservationInput, ReservationState, Settlement},
};
use axum::body::{Bytes, HttpBody};
use http_body_util::BodyExt;
use hyper::body::{Frame, SizeHint};
use rustix::fs::{self as at, AtFlags, Mode, OFlags};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use sqlx::Row;
use std::{
    fmt, fs,
    future::Future,
    io::{ErrorKind, Read, Seek, SeekFrom, Write},
    path::Path,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use std::{
    os::unix::fs::MetadataExt,
    sync::{Arc, OnceLock},
};
use tokio::task::JoinHandle;
use volume::Volume;

const STAGING: &str = "staging";
const REVISIONS: &str = "revisions";
/// Largest chunk one read of a payload file returns.
const READ_CHUNK: u64 = 64 * 1024;
/// Wall-clock limit for the HTTP upload. Worker cleanup adds a settlement allowance.
pub const UPLOAD_TIMEOUT: Duration = Duration::from_secs(600);
/// Largest batch one reconciliation call handles.
pub const MAX_BATCH: i64 = 1000;

/// The artifacts directory was refused. It deliberately carries no path or OS detail.
#[derive(Debug, PartialEq, Eq)]
pub struct InvalidDirectory;

#[derive(Debug)]
pub enum Error {
    /// The multipart body was refused.
    Multipart(multipart::Error),
    /// The file exceeds the reservation's byte ceiling.
    TooLarge,
    /// The caller's check refused the completed form.
    Rejected,
    /// Another request is streaming under the same reservation; it was left untouched.
    InProgress,
    /// The request body could not be read.
    Body,
    /// A filesystem operation failed.
    Io,
    /// A settled revision's payload is missing or has another size.
    Missing,
    /// A persistence helper refused or failed (ADR 0005).
    Storage(runs::Error),
}

impl From<runs::Error> for Error {
    fn from(error: runs::Error) -> Self {
        Self::Storage(error)
    }
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}
impl From<rustix::io::Errno> for Error {
    fn from(_: rustix::io::Errno) -> Self {
        Self::Io
    }
}
impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(runs::Error::Database(error))
    }
}

// Fixed text: never a path, file name, OS message or request value.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Multipart(error) => error.fmt(f),
            Self::Storage(error) => error.fmt(f),
            Self::TooLarge => f.write_str("file exceeds the reserved byte ceiling"),
            Self::Rejected => f.write_str("upload metadata was refused"),
            Self::InProgress => f.write_str("another upload holds this reservation"),
            Self::Body => f.write_str("request body could not be read"),
            Self::Io => f.write_str("artifact storage I/O failed"),
            Self::Missing => f.write_str("settled artifact payload is missing"),
        }
    }
}

/// A validated artifacts directory with its `staging` and `revisions` subdirectories.
#[derive(Clone, Debug)]
pub struct Store {
    volume: Arc<Volume>,
    pool: Arc<OnceLock<PgPool>>,
    expiry_pass: Arc<[tokio::sync::Mutex<reclaim::AnchorPass>; 4]>,
    staging_pass: Arc<tokio::sync::Mutex<staging::StagingSweepState>>,
    anchor_pass: Arc<[tokio::sync::Mutex<reclaim::AnchorPass>; 2]>,
}
impl Store {
    pub fn open(root: &Path) -> Result<Self, InvalidDirectory> {
        Self::open_volume(root, true)
    }
    /// Open an existing volume for read-only inspection without creating directories.
    pub fn open_existing(root: &Path) -> Result<Self, InvalidDirectory> {
        Self::open_volume(root, false)
    }
    fn open_volume(root: &Path, create: bool) -> Result<Self, InvalidDirectory> {
        Ok(Self {
            volume: Arc::new(Volume::open(root, create).map_err(|_| InvalidDirectory)?),
            pool: Default::default(),
            staging_pass: Default::default(),
            expiry_pass: Default::default(),
            anchor_pass: Default::default(),
        })
    }
    /// Initializes a fresh installation from the API role and verifies an existing pin.
    pub async fn initialize_api(&self, pool: &PgPool) -> Result<(), Error> {
        self.prepare(pool, true).await.map(|_| ())
    }
    pub(crate) async fn verify_startup(&self, pool: &PgPool, api: bool) -> Result<(), Error> {
        self.prepare(pool, api).await.map(|_| ())
    }
    pub(crate) fn attach(&self, pool: &PgPool) {
        self.pool.get_or_init(|| pool.clone());
    }
    // Re-read the database marker for each operation. On a pre-adoption upgrade only HTTP
    // acquisition and publication may proceed without sentinels.
    async fn prepare(&self, pool: &PgPool, bootstrap: bool) -> Result<Option<String>, Error> {
        self.attach(pool);
        self.volume.recheck()?;
        let (pin,auto,adopting,empty):(Option<String>,bool,bool,bool)=sqlx::query_as(
            "SELECT volume_id::text,bootstrap_auto_pin_allowed,adoption_run_id IS NOT NULL,
             NOT EXISTS (SELECT FROM openmettle.storage_reservations) AND NOT EXISTS (SELECT FROM openmettle.artifact_revisions)
             FROM openmettle.storage_volume_control WHERE id").fetch_one(pool).await?;
        if adopting {
            return Err(Error::Io);
        }
        if let Some(id) = pin {
            self.volume.verify(&id)?;
            return Ok(Some(id));
        }
        if auto && bootstrap && empty {
            let id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
                .fetch_one(pool)
                .await?;
            let id = self.volume.publish_identity(&id)?;
            sqlx::query("SELECT openmettle.storage_pin_volume_id($1::uuid)")
                .bind(&id)
                .execute(pool)
                .await?;
            return Ok(Some(id));
        }
        Ok(None)
    }
    async fn stage(&self, reservation: &str) -> Result<Staged, Error> {
        runs::uuid(reservation)?;
        self.volume.recheck()?;
        let f = at::openat(
            &self.volume.staging,
            reservation,
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|e| {
            if e == rustix::io::Errno::EXIST {
                Error::InProgress
            } else {
                Error::Io
            }
        })?;
        let f = fs::File::from(f);
        f.try_lock_shared().map_err(|_| Error::InProgress)?;
        let ino = f.metadata()?.ino();
        self.volume
            .matches(&f, &self.volume.staging, reservation, ino)?;
        at::fsync(&self.volume.staging)?;
        Ok(Staged {
            volume: self.volume.clone(),
            id: reservation.to_string(),
            ino,
            file: Some(f),
        })
    }
    /// Opens the published payload of a settled revision and positions it at `start`; the body
    /// streams the next `len` bytes. The file must be a regular file (not a symbolic link) of
    /// exactly `size` bytes, else [`Error::Missing`]. `start + len` must not exceed `size`.
    pub async fn read(
        &self,
        reservation: &str,
        size: i64,
        start: u64,
        len: u64,
    ) -> Result<Content, Error> {
        runs::uuid(reservation)?;
        let size = u64::try_from(size).map_err(|_| Error::Missing)?;
        if start.checked_add(len).is_none_or(|end| end > size) {
            return Err(Error::Missing);
        }
        let pool = self.pool.get().ok_or(Error::Io)?;
        let pin = self.prepare(pool, false).await?;
        let (ino, bad): (Option<String>, bool) = sqlx::query_as(
            "SELECT payload_ino::text,adoption_unverified
            FROM openmettle.storage_reservations WHERE id=$1::uuid AND state='settled'",
        )
        .bind(reservation)
        .fetch_one(pool)
        .await?;
        if bad || (pin.is_some() && ino.is_none()) {
            return Err(Error::Io);
        }
        let mut file = self
            .volume
            .regular(&self.volume.revisions, reservation, false)
            .map_err(|_| Error::Missing)?;
        file.try_lock_shared().map_err(|_| Error::Missing)?;
        let m = file.metadata()?;
        if m.len() != size {
            return Err(Error::Missing);
        }
        if ino.is_some_and(|v| v != m.ino().to_string()) {
            return Err(Error::Io);
        }
        self.volume
            .matches(&file, &self.volume.revisions, reservation, m.ino())?;
        file.seek(SeekFrom::Start(start))?;
        Ok(Content {
            file: Some(file),
            remaining: len,
            pending: None,
        })
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> std::io::Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|_| Err(ErrorKind::Other.into()))
}

struct Staged {
    id: String,
    volume: Arc<Volume>,
    ino: u64,
    file: Option<fs::File>,
}
impl Staged {
    async fn write(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        let mut file = self.file.take().ok_or(Error::Io)?;
        let file = blocking(move || {
            file.write_all(&bytes)?;
            Ok(file)
        })
        .await
        .map_err(|_| Error::Io)?;
        self.file = Some(file);
        Ok(())
    }

    /// `fsync` the file; done before the publication lock is taken.
    async fn sync(&mut self) -> Result<(), Error> {
        let file = self.file.take().ok_or(Error::Io)?;
        let file = blocking(move || file.sync_all().map(|()| file))
            .await
            .map_err(|_| Error::Io)?;
        self.file = Some(file);
        Ok(())
    }

    fn publish(&self) -> Result<(), Error> {
        let f = self.file.as_ref().ok_or(Error::Io)?;
        self.volume.recheck()?;
        self.volume
            .matches(f, &self.volume.staging, &self.id, self.ino)?;
        at::linkat(
            &self.volume.staging,
            self.id.as_str(),
            &self.volume.revisions,
            self.id.as_str(),
            AtFlags::empty(),
        )?;
        at::fsync(&self.volume.revisions)?;
        self.volume
            .matches(f, &self.volume.revisions, &self.id, self.ino)?;
        Ok(())
    }
}

/// One blocking read: the file back and the chunk it filled.
type PendingRead = JoinHandle<std::io::Result<(fs::File, Vec<u8>)>>;

/// A response body streaming a byte range of one payload file in chunks of at most 64 KiB, each
/// read on the blocking pool. Its exact size is known up front. A file that ends early yields
/// an error, which aborts the response.
pub struct Content {
    /// `None` while a read is pending.
    file: Option<fs::File>,
    remaining: u64,
    pending: Option<PendingRead>,
}

impl HttpBody for Content {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        let this = self.get_mut();
        if this.pending.is_none() {
            if this.remaining == 0 {
                return Poll::Ready(None);
            }
            let Some(mut file) = this.file.take() else {
                return Poll::Ready(Some(Err(ErrorKind::Other.into())));
            };
            // At most READ_CHUNK, so the cast cannot truncate.
            let mut chunk = vec![0; this.remaining.min(READ_CHUNK) as usize];
            this.pending = Some(tokio::task::spawn_blocking(move || {
                file.read_exact(&mut chunk)?;
                Ok((file, chunk))
            }));
        }
        let Some(pending) = this.pending.as_mut() else {
            return Poll::Ready(None);
        };
        let read = std::task::ready!(Pin::new(pending).poll(cx));
        this.pending = None;
        Poll::Ready(Some(match read {
            Ok(Ok((file, chunk))) => {
                this.file = Some(file);
                this.remaining -= chunk.len() as u64;
                Ok(Frame::data(Bytes::from(chunk)))
            }
            Ok(Err(error)) => {
                this.remaining = 0;
                Err(error)
            }
            Err(_) => {
                this.remaining = 0;
                Err(ErrorKind::Other.into())
            }
        }))
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0 && self.pending.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
}

/// Size and SHA-256 of the observed file bytes, bounded by the reservation's ceiling whether or
/// not the request declared a length.
struct Sink {
    hasher: Sha256,
    size: u64,
    max: u64,
    /// `None` when re-reading the body of an already settled reservation.
    staged: Option<Staged>,
}

impl Sink {
    async fn write(&mut self, bytes: Vec<u8>) -> Result<(), Error> {
        let size = self.size + bytes.len() as u64;
        if size > self.max {
            return Err(Error::TooLarge);
        }
        self.size = size;
        self.hasher.update(&bytes);
        match &mut self.staged {
            Some(staged) => staged.write(bytes).await,
            None => Ok(()),
        }
    }
}

/// One upload under the ADR 0005 reservation protocol. The idempotency identity is the key, the
/// scope, the actor, the artifact and `max_bytes`; the multipart boundary is not part of it, so
/// a retry may use another boundary.
pub struct Upload<'a> {
    pub scope: &'a str,
    pub actor: &'a str,
    pub key: &'a str,
    /// A new artifact's UUID or an existing artifact in `scope`.
    pub artifact: &'a str,
    /// The file's byte ceiling, charged until settlement. It must be stable across retries:
    /// never derive it from the multipart body length.
    pub max_bytes: i64,
    /// The request's `Content-Type` header value.
    pub content_type: &'a str,
}

/// A settled revision and the form it was read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stored {
    pub revision: String,
    pub reservation: String,
    pub size_bytes: i64,
    pub content_digest: [u8; 32],
    pub form: Form,
}

/// Runs storage helpers in their own transaction, committed only on success.
async fn committed<T, E: From<runs::Error>>(
    pool: &PgPool,
    step: impl AsyncFnOnce(&mut WriteTransaction<'_>) -> Result<T, E>,
) -> Result<T, E> {
    let mut connection = pool.acquire().await.map_err(runs::Error::from)?;
    let mut tx = WriteTransaction::begin(&mut connection).await?;
    match step(&mut tx).await {
        Ok(value) => {
            tx.commit().await?;
            Ok(value)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

/// Reserve, stream the multipart `body` into staging, check the completed form with `accept`,
/// publish and settle. The writer commits its claim before creating staging. Cancellation leaves
/// any file and charge for fenced recovery. Failed validation releases through the same cleaner.
///
/// An exact retry of a settled upload re-reads the body without writing, settles it as an
/// exact replay and returns the same revision with no second charge; a changed body, media type
/// or display name conflicts. A failed `settle` leaves the published file for a retry or the
/// reconciler: its commit may have succeeded.
pub async fn ingest<B>(
    pool: &PgPool,
    store: &Store,
    upload: &Upload<'_>,
    mut body: B,
    accept: impl FnOnce(&Form) -> bool,
) -> Result<Stored, Error>
where
    B: HttpBody<Data = Bytes> + Unpin,
{
    let mut parser = Parser::new(upload.content_type).map_err(Error::Multipart)?;
    let input = ReservationInput {
        scope: upload.scope,
        actor: upload.actor,
        key: upload.key,
        artifact: upload.artifact,
        max_bytes: upload.max_bytes,
        run: None,
        operation: None,
    };
    let pin = store.prepare(pool, true).await?;
    let reservation =
        committed::<_, Error>(pool, async |tx| Ok(storage::reserve(tx, &input).await?)).await?;
    let id = reservation.id;
    let staged = match reservation.state {
        ReservationState::Released => return Err(runs::Error::Conflict.into()),
        ReservationState::Settled => None,
        ReservationState::Reserved => {
            committed(pool, async |tx| {
                lock_writer(tx, &id, pin.as_deref(), false, None, false).await?;
                sqlx::query("UPDATE openmettle.storage_reservations SET stage_claimed=true WHERE id=$1::uuid")
                    .bind(&id).execute(tx.connection()?).await?;
                Ok::<_, Error>(())
            }).await?;
            if let Some(pin) = pin.as_deref() {
                store.volume.verify(pin)?;
            }
            let staged = store.stage(&id).await?;
            committed(pool, async |tx| {
                lock_writer(tx, &id, pin.as_deref(), true, None, false).await?;
                store.volume.matches(staged.file.as_ref().ok_or(Error::Io)?, &store.volume.staging, &id, staged.ino)?;
                sqlx::query("UPDATE openmettle.storage_reservations SET payload_ino=$2::text::numeric WHERE id=$1::uuid")
                    .bind(&id).bind(staged.ino.to_string()).execute(tx.connection()?).await?;
                Ok::<_, Error>(())
            }).await?;
            Some(staged)
        }
    };
    let fresh = staged.is_some();
    let mut sink = Sink {
        hasher: Sha256::new(),
        size: 0,
        max: upload.max_bytes as u64,
        staged,
    };
    let received = async {
        while let Some(frame) = body.frame().await {
            let Ok(bytes) = frame.map_err(|_| Error::Body)?.into_data() else {
                continue; // trailers carry no file bytes
            };
            let file = parser.feed(&bytes).map_err(Error::Multipart)?;
            if !file.is_empty() {
                sink.write(file).await?;
            }
        }
        let form = parser.finish().map_err(Error::Multipart)?;
        if accept(&form) {
            Ok(form)
        } else {
            Err(Error::Rejected)
        }
    }
    .await;
    let form = match received {
        Ok(form) => form,
        Err(error) if fresh => {
            drop(sink); // release the shared file lock before reclamation
            return Err(abort(pool, store, upload.scope, &id, error).await);
        }
        Err(error) => return Err(error),
    };
    let size_bytes = sink.size as i64;
    let content_digest: [u8; 32] = sink.hasher.finalize().into();
    let mut staged = sink.staged.take();
    if let Some(file) = &mut staged
        && let Err(error) = file.sync().await
    {
        drop(staged);
        return Err(abort(pool, store, upload.scope, &id, error).await);
    }
    let settlement = Settlement {
        scope: upload.scope,
        reservation: &id,
        size_bytes,
        content_digest: &content_digest,
        media_type: &form.media_type,
        display_name: form.display_name.as_deref(),
    };
    if let Some(file) = staged.as_ref() {
        committed(pool, async |tx| {
            lock_writer(tx, &id, pin.as_deref(), true, Some(file.ino), false).await?;
            store.volume.matches(
                file.file.as_ref().ok_or(Error::Io)?,
                &store.volume.staging,
                &id,
                file.ino,
            )?;
            sqlx::query(
                "UPDATE openmettle.storage_reservations SET publish_pending=true WHERE id=$1::uuid",
            )
            .bind(&id)
            .execute(tx.connection()?)
            .await?;
            Ok::<_, Error>(())
        })
        .await?;
        if let Some(pin) = &pin {
            store.volume.verify(pin)?;
        }
        if file.publish().is_err() {
            quarantine_writer(pool, &id, file.ino).await?;
            return Err(Error::Io);
        }
    }
    let revision = committed(pool, async |tx| {
        if let Some(file) = staged.as_ref() {
            lock_writer(tx, &id, pin.as_deref(), true, Some(file.ino), true).await?;
        }
        let revision = storage::settle(tx, &settlement).await?;
        if let Some(file) = staged.as_ref() {
            if let Some(pin) = &pin {
                store.volume.verify(pin)?;
            } else {
                store.volume.recheck()?;
            }
            let fd = file.file.as_ref().ok_or(Error::Io)?;
            store
                .volume
                .matches(fd, &store.volume.staging, &id, file.ino)?;
            store
                .volume
                .matches(fd, &store.volume.revisions, &id, file.ino)?;
            if fd.metadata()?.len() != size_bytes as u64 {
                return Err(Error::Io);
            }
        }
        Ok::<_, Error>(revision)
    })
    .await;
    if matches!(revision, Err(Error::Io))
        && let Some(file) = staged.as_ref()
    {
        quarantine_writer(pool, &id, file.ino).await?;
    }
    let revision = revision?;
    if let Some(file) = staged {
        let ino = file.ino;
        let _ = store.volume.detach_staged(&id, ino);
        drop(file);
    } else {
        store.read(&id, size_bytes, 0, 0).await?;
    }
    Ok(Stored {
        revision,
        reservation: id,
        size_bytes,
        content_digest,
        form,
    })
}

async fn quarantine_writer(pool: &PgPool, id: &str, ino: u64) -> Result<(), Error> {
    sqlx::query(
        "UPDATE openmettle.storage_reservations SET adoption_unverified=true,publish_pending=false
        WHERE id=$1::uuid AND payload_ino=$2::text::numeric AND publish_pending
        AND state='reserved' AND reclaim_state='none'",
    )
    .bind(id)
    .bind(ino.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

async fn lock_writer(
    tx: &mut WriteTransaction<'_>,
    id: &str,
    pin: Option<&str>,
    claimed: bool,
    ino: Option<u64>,
    pending: bool,
) -> Result<(), Error> {
    let ok: Option<bool> = sqlx::query_scalar(
        "SELECT stage_claimed=$2 AND publish_pending=$4 AND payload_ino IS NOT DISTINCT FROM $3::text::numeric
        AND NOT adoption_unverified AND reclaim_state='none' FROM openmettle.storage_reservations
        WHERE id=$1::uuid AND state='reserved' FOR UPDATE",
    )
    .bind(id)
    .bind(claimed)
    .bind(ino.map(|i| i.to_string()))
    .bind(pending)
    .fetch_optional(tx.connection()?)
    .await?;
    if ok != Some(true) {
        return Err(Error::InProgress);
    }
    let (vol, adopting): (Option<String>, bool) = sqlx::query_as(
        "SELECT volume_id::text,adoption_run_id IS NOT NULL
        FROM openmettle.storage_volume_control WHERE id",
    )
    .fetch_one(tx.connection()?)
    .await?;
    if adopting || vol.as_deref() != pin {
        return Err(Error::Io);
    }
    if let Some(expected) = pin {
        reclaim::lock_pin(tx, expected).await?;
    }
    Ok(())
}
async fn abort(pool: &PgPool, store: &Store, scope: &str, id: &str, error: Error) -> Error {
    let _ = reclaim::release(pool, store, scope, id, None).await;
    error
}
fn batch(limit: i64) -> Result<(), Error> {
    if (1..=MAX_BATCH).contains(&limit) {
        Ok(())
    } else {
        Err(runs::Error::Invalid.into())
    }
}

/// Count completed items and surface the first error after attempting the entire batch.
async fn sweep_items<T, F: Future<Output = Result<bool, Error>>>(
    candidates: Vec<T>,
    process: impl Fn(T) -> F,
) -> Result<usize, Error> {
    let mut count = 0;
    let mut first_error = None;
    for candidate in candidates {
        match process(candidate).await {
            Ok(done) => count += usize::from(done),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    first_error.map_or(Ok(count), Err)
}

pub use reclaim::{purge_due, reconcile_expired};
#[cfg(test)]
mod tests;
