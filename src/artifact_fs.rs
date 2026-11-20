//! Filesystem artifact payloads (ADR 0031) over the ADR 0005 accounting helpers. Every path is
//! `<root>/staging/<reservation>` or `<root>/revisions/<reservation>`, where the reservation is
//! the server-generated UUID that `storage::reserve` returned. No client file name, database
//! path column or other request value ever names a file.
//!
//! Publication order: write the staging file (created exclusively, mode 0600) and `fsync` it;
//! then, holding the reservation's row lock, rename it into `revisions/`, `fsync` that
//! directory and `storage::settle` in the same transaction. A failure before the rename unlinks
//! the staging file and releases the reservation. A revision file whose
//! reservation is still `reserved` (a crash or lost response between rename and settle) is
//! replaced by a retry with the same idempotency key, or removed by [`reconcile_expired`] before
//! it releases the reservation, so no uncharged payload remains.
use crate::{
    multipart::{self, Form, Parser},
    runs::{self, WriteTransaction},
    storage::{self, ReservationInput, ReservationState, Settlement},
};
use axum::body::{Bytes, HttpBody};
use http_body_util::BodyExt;
use sha2::{Digest as _, Sha256};
use sqlx::{PgPool, Row};
use std::{
    fmt, fs,
    io::{ErrorKind, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

const STAGING: &str = "staging";
const REVISIONS: &str = "revisions";
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
    staging: PathBuf,
    revisions: PathBuf,
}

impl Store {
    /// Validates `root` at startup: an absolute path to an existing directory that is not
    /// itself a symbolic link. Creates `staging` and `revisions` (mode 0700) if absent; each
    /// must then be a real, readable directory. Symbolic links above the leaf are allowed.
    pub fn open(root: &Path) -> Result<Self, InvalidDirectory> {
        let directory = |path: &Path| {
            fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir())
                && fs::read_dir(path).is_ok()
        };
        if !root.is_absolute() || !directory(root) {
            return Err(InvalidDirectory);
        }
        let store = Self {
            staging: root.join(STAGING),
            revisions: root.join(REVISIONS),
        };
        for dir in [&store.staging, &store.revisions] {
            match fs::DirBuilder::new().mode(0o700).create(dir) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                Err(_) => return Err(InvalidDirectory),
            }
            if !directory(dir) {
                return Err(InvalidDirectory);
            }
        }
        sync_dir(root).map_err(|_| InvalidDirectory)?;
        Ok(store)
    }

    fn paths(&self, reservation: &str) -> Result<(PathBuf, PathBuf), Error> {
        // Only the canonical lower-case UUID text names a file: no separator, dot or NUL.
        runs::uuid(reservation)?;
        Ok((
            self.staging.join(reservation),
            self.revisions.join(reservation),
        ))
    }

    /// Creates the staging file exclusively; an existing one means another request (or a crash
    /// awaiting reconciliation) holds the reservation.
    async fn stage(&self, reservation: &str) -> Result<Staged, Error> {
        let (path, revision) = self.paths(reservation)?;
        let open = path.clone();
        let file = blocking(move || {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(open)
        })
        .await
        .map_err(|e| match e.kind() {
            ErrorKind::AlreadyExists => Error::InProgress,
            _ => Error::Io,
        })?;
        Ok(Staged {
            path,
            revision,
            revisions: self.revisions.clone(),
            file: Some(file),
            publishing: false,
        })
    }

    /// Unlinks both payload paths of `reservation` (absent is fine) and syncs the directories.
    async fn remove(&self, reservation: &str) -> Result<(), Error> {
        let (staging, revision) = self.paths(reservation)?;
        let dirs = (self.staging.clone(), self.revisions.clone());
        blocking(move || {
            remove(&staging, &dirs.0)?;
            remove(&revision, &dirs.1)
        })
        .await
        .map_err(|_| Error::Io)
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> std::io::Result<T> + Send + 'static,
) -> std::io::Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|_| Err(ErrorKind::Other.into()))
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

fn remove(path: &Path, dir: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => sync_dir(dir),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// An exclusively created staging file. Dropping it before publication unlinks it, including
/// when the request future is cancelled mid-stream.
struct Staged {
    path: PathBuf,
    revision: PathBuf,
    revisions: PathBuf,
    /// `None` after a failed or cancelled write; the upload must then be abandoned.
    file: Option<fs::File>,
    /// Set once the rename task owns the file; it cleans up after itself on failure.
    publishing: bool,
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

    /// Rename into `revisions/` and `fsync` that directory. On failure both paths are unlinked,
    /// so the caller may release the reservation.
    async fn publish(mut self) -> Result<(), Error> {
        drop(self.file.take().ok_or(Error::Io)?);
        self.publishing = true;
        let (staging, revision, revisions) = (
            self.path.clone(),
            self.revision.clone(),
            self.revisions.clone(),
        );
        blocking(move || {
            let result = fs::rename(&staging, &revision).and_then(|()| sync_dir(&revisions));
            if result.is_err() {
                let _ = fs::remove_file(&staging);
                let _ = fs::remove_file(&revision);
            }
            result
        })
        .await
        .map_err(|_| Error::Io)
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.publishing {
            let _ = fs::remove_file(&self.path);
        }
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
/// publish and settle. Every refusal before publication unlinks the staging file and then
/// releases the reservation, except [`Error::InProgress`], which leaves the other request's
/// file and reservation alone. A cancelled future unlinks its staging file; its reservation
/// stays `reserved` for a retry or [`reconcile_expired`].
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
    let reservation =
        committed::<_, Error>(pool, async |tx| Ok(storage::reserve(tx, &input).await?)).await?;
    let id = reservation.id;
    let staged = match reservation.state {
        ReservationState::Released => return Err(runs::Error::Conflict.into()),
        ReservationState::Settled => None,
        ReservationState::Reserved => match store.stage(&id).await {
            Ok(staged) => Some(staged),
            Err(Error::InProgress) => return Err(Error::InProgress),
            Err(error) => return Err(abort(pool, upload.scope, &id, error).await),
        },
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
            drop(sink); // unlink staging before the release
            return Err(abort(pool, upload.scope, &id, error).await);
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
        return Err(abort(pool, upload.scope, &id, error).await);
    }
    let settlement = Settlement {
        scope: upload.scope,
        reservation: &id,
        size_bytes,
        content_digest: &content_digest,
        media_type: &form.media_type,
        display_name: form.display_name.as_deref(),
    };
    // The rename happens under the reservation's row lock, in the settling transaction, so it
    // never replaces the payload of a revision another request settled, or races
    // `reconcile_expired`. A reservation no longer `reserved` keeps no staging file; `settle`
    // then replays or conflicts.
    let settled = committed::<_, Error>(pool, async |tx| {
        if let Some(staged) = staged {
            let state: String = sqlx::query_scalar(
                "SELECT state FROM openmettle.storage_reservations
                  WHERE scope_id = $1::uuid AND id = $2::uuid FOR UPDATE",
            )
            .bind(upload.scope)
            .bind(&id)
            .fetch_one(tx.connection()?)
            .await?;
            if state == "reserved" {
                staged.publish().await?;
            }
        }
        Ok(storage::settle(tx, &settlement).await?)
    })
    .await;
    let revision = match settled {
        Ok(revision) => revision,
        // Only publication fails with `Io`: both paths are gone, so the release is safe.
        Err(Error::Io) => return Err(abort(pool, upload.scope, &id, Error::Io).await),
        Err(error) => return Err(error),
    };
    if !fresh {
        let (_, path) = store.paths(&id)?;
        let len = blocking(move || fs::symlink_metadata(path).map(|m| m.len()))
            .await
            .map_err(|_| Error::Missing)?;
        if len != sink.size {
            return Err(Error::Missing);
        }
    }
    Ok(Stored {
        revision,
        reservation: id,
        size_bytes,
        content_digest,
        form,
    })
}

/// Releases an unpublished reservation after its staging file is gone and returns `error`. A
/// failed release leaves the reservation for [`reconcile_expired`].
async fn abort(pool: &PgPool, scope: &str, reservation: &str, error: Error) -> Error {
    let _ = committed(pool, async |tx| {
        storage::release(tx, scope, reservation).await
    })
    .await;
    error
}

fn batch(limit: i64) -> Result<(), Error> {
    if (1..=MAX_BATCH).contains(&limit) {
        Ok(())
    } else {
        Err(runs::Error::Invalid.into())
    }
}

/// Releases up to `limit` upload reservations (no run link) still `reserved` more than
/// `older_than` after creation, oldest first. Under the reservation's row lock it unlinks any
/// `staging/` or `revisions/` file first, so no uncharged payload remains. `older_than` must
/// exceed the longest upload plus settlement; an upload still running past it would lose its
/// reservation. Returns the number released. Works as `openmettle_api` or
/// `openmettle_worker`.
pub async fn reconcile_expired(
    pool: &PgPool,
    store: &Store,
    older_than: Duration,
    limit: i64,
) -> Result<usize, Error> {
    batch(limit)?;
    let age = i64::try_from(older_than.as_millis()).map_err(|_| runs::Error::Invalid)?;
    let candidates: Vec<(String, String)> = sqlx::query_as(
        "SELECT scope_id::text, id::text FROM openmettle.storage_reservations
          WHERE state = 'reserved' AND run_id IS NULL
            AND created_at < now() - $1 * interval '1 millisecond'
          ORDER BY created_at LIMIT $2",
    )
    .bind(age)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let mut released = 0;
    for (scope, reservation) in candidates {
        let done = committed(pool, async |tx| {
            let state: Option<String> = sqlx::query_scalar(
                "SELECT state FROM openmettle.storage_reservations
                  WHERE scope_id = $1::uuid AND id = $2::uuid FOR UPDATE",
            )
            .bind(&scope)
            .bind(&reservation)
            .fetch_optional(tx.connection()?)
            .await?;
            if state.as_deref() != Some("reserved") {
                return Ok::<_, Error>(false);
            }
            store.remove(&reservation).await?;
            storage::release(tx, &scope, &reservation).await?;
            Ok(true)
        })
        .await?;
        released += usize::from(done);
    }
    Ok(released)
}

/// Purges up to `limit` revisions: expired `retained` ones are claimed with `begin_purge`, and
/// claims left by an earlier crash are resumed. Each payload `revisions/<reservation>` is
/// unlinked, then `confirm_purge` stops charging it. `openmettle_worker` only (ADR 0005 column
/// grants). Returns the number confirmed.
pub async fn purge_due(pool: &PgPool, store: &Store, limit: i64) -> Result<usize, Error> {
    batch(limit)?;
    let due = sqlx::query(
        "SELECT scope_id::text, id::text, reservation_id::text FROM openmettle.artifact_revisions
          WHERE (state = 'retained' AND purge_after <= now()) OR state = 'purging'
          ORDER BY purge_after LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let mut purged = 0;
    for row in due {
        let (scope, revision, reservation): (String, String, String) =
            (row.try_get(0)?, row.try_get(1)?, row.try_get(2)?);
        // A claim must be committed before its confirmation (ADR 0005). A revision restored
        // since the scan is no longer eligible and is skipped.
        match committed(pool, async |tx| {
            storage::begin_purge(tx, &scope, &revision).await
        })
        .await
        {
            Ok(()) => {}
            Err(runs::Error::NotEligible) => continue,
            Err(error) => return Err(error.into()),
        }
        let (_, path) = store.paths(&reservation)?;
        let dir = store.revisions.clone();
        blocking(move || remove(&path, &dir))
            .await
            .map_err(|_| Error::Io)?;
        committed::<_, runs::Error>(pool, async |tx| {
            storage::confirm_purge(tx, &scope, &revision).await
        })
        .await?;
        purged += 1;
    }
    Ok(purged)
}

#[cfg(test)]
mod tests;
