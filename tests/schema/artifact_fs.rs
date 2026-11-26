//! ADR 0031: migration 17 and the filesystem artifact engine over isolated PostgreSQL 18 and a
//! per-test temporary directory. Every value is synthetic.
use super::storage::{
    account, assert_totals, configure_limits as configure, new_uuid, retention_grace,
};
use super::*;
use crate::auth_config_support::Dir;
use axum::body::{Bytes, HttpBody};
use hyper::body::Frame;
use openmettle_core::{
    artifact_fs::{self, MAX_BATCH, Store, Stored, Upload},
    multipart,
    storage::{self, ReservationInput, Settlement},
};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    collections::VecDeque,
    fs,
    path::PathBuf,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

/// A request body delivered in the given chunks; `Err` is a client read failure.
struct Chunks(VecDeque<Result<Vec<u8>, ()>>);

impl HttpBody for Chunks {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
        Poll::Ready(self.get_mut().0.pop_front().map(|chunk| {
            chunk
                .map(|bytes| Frame::data(Bytes::from(bytes)))
                .map_err(|()| std::io::Error::other("synthetic"))
        }))
    }
}

/// A failure case: key, body, the caller's verdict and the expected error.
type Case = (&'static str, Chunks, bool, fn(&artifact_fs::Error) -> bool);

fn chunked(body: &[u8], size: usize) -> Chunks {
    Chunks(body.chunks(size).map(|c| Ok(c.to_vec())).collect())
}

struct Part<'a> {
    name: &'a str,
    filename: Option<&'a str>,
    media: &'a str,
    body: &'a [u8],
}

fn file<'a>(filename: Option<&'a str>, body: &'a [u8]) -> Part<'a> {
    Part {
        name: "file",
        filename,
        media: "text/plain",
        body,
    }
}

const METADATA: Part<'static> = Part {
    name: "metadata",
    filename: None,
    media: "application/json",
    body: b"{}",
};

fn form(boundary: &str, parts: &[Part<'_>], close: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        let filename = part
            .filename
            .map(|f| format!("; filename=\"{f}\""))
            .unwrap_or_default();
        out.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{}\"{filename}\r\n\
                 Content-Type: {}\r\n\r\n",
                part.name, part.media
            )
            .as_bytes(),
        );
        out.extend_from_slice(part.body);
        out.extend_from_slice(b"\r\n");
    }
    if close {
        out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    }
    out
}

pub(super) async fn pool(db: &TestDb, role: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .connect(&db.url(role))
        .await
        .unwrap()
}

pub(super) struct Fixture {
    pub(super) db: TestDb,
    pub(super) c: Context,
    pub(super) api: PgPool,
    pub(super) store: Store,
    pub(super) root: PathBuf,
    _dir: Dir,
}

impl Fixture {
    pub(super) async fn new() -> Self {
        let db = TestDb::migrated().await;
        configure(&db, Some(10_000), Some(10_000), Some(10_000)).await;
        // Removed revisions become due after one second.
        retention_grace(&db, 1).await;
        let c = Context::new(&db).await;
        let api = pool(&db, API).await;
        let dir = Dir::new();
        let root = PathBuf::from(dir.path("artifacts"));
        fs::create_dir(&root).unwrap();
        let store = Store::open(&root).unwrap();
        store.initialize_api(&api).await.unwrap();
        Self {
            db,
            c,
            api,
            store,
            root,
            _dir: dir,
        }
    }

    async fn upload(
        &self,
        key: &str,
        artifact: &str,
        max: i64,
        boundary: &str,
        body: Chunks,
        accept: bool,
    ) -> Result<Stored, artifact_fs::Error> {
        let content_type = format!("multipart/form-data; boundary={boundary}");
        let upload = Upload {
            scope: &self.c.scope,
            actor: &self.c.actor,
            key,
            artifact,
            max_bytes: max,
            content_type: &content_type,
        };
        artifact_fs::ingest(&self.api, &self.store, &upload, body, |form| {
            accept && form.metadata == b"{}"
        })
        .await
    }

    pub(super) async fn payload(&self, key: &str, body: &[u8]) -> Stored {
        let doc = new_uuid(&self.db).await;
        let form = form("x", &[METADATA, file(None, body)], true);
        self.upload(key, &doc, 100, "x", chunked(&form, 16), true)
            .await
            .unwrap()
    }

    pub(super) fn files(&self, sub: &str) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.root.join(sub))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n != ".openmettle-volume-id")
            .collect();
        names.sort();
        names
    }

    async fn state(&self, key: &str) -> Option<String> {
        sqlx::query_scalar(
            "SELECT state FROM openmettle.storage_reservations
              WHERE scope_id = $1::uuid AND idempotency_key = $2",
        )
        .bind(&self.c.scope)
        .bind(key)
        .fetch_optional(&mut self.db.admin().await)
        .await
        .unwrap()
    }

    pub(super) async fn reserve(&self, key: &str, artifact: &str, max: i64) -> String {
        let mut cn = connect(&self.db.0, API).await;
        let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
        let reservation = storage::reserve(
            &mut tx,
            &ReservationInput {
                scope: &self.c.scope,
                actor: &self.c.actor,
                key,
                artifact,
                max_bytes: max,
                run: None,
                operation: None,
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        reservation.id
    }
}

async fn insert_legacy_revision(
    api: &mut PgConnection,
    c: &Context,
    doc: &str,
) -> (String, String, Vec<u8>) {
    let mut tx = api.begin().await.unwrap();
    sqlx::query("INSERT INTO openmettle.storage_accounts(scope_id) VALUES($1::uuid)")
        .bind(&c.scope)
        .execute(&mut *tx)
        .await
        .unwrap();
    let reserved:String=sqlx::query_scalar("INSERT INTO openmettle.storage_reservations
        (scope_id,actor_user_id,idempotency_key,artifact_id,max_bytes,request_identity,request_digest)
        VALUES($1::uuid,$2::uuid,'v16',$3::uuid,10,'legacy',sha256('legacy'::bytea)) RETURNING id::text")
        .bind(&c.scope).bind(&c.actor).bind(doc).fetch_one(&mut *tx).await.unwrap();
    sqlx::query("UPDATE openmettle.storage_accounts SET reserved_bytes=10 WHERE scope_id=$1::uuid")
        .bind(&c.scope)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE openmettle.storage_instance SET reserved_bytes=10")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let digest = Sha256::digest(b"v16").to_vec();
    sqlx::query(
        "INSERT INTO openmettle.artifacts (id, scope_id, scope_kind, owner_user_id)
         VALUES ($1::uuid, $2::uuid, 'personal', $3::uuid)",
    )
    .bind(doc)
    .bind(&c.scope)
    .bind(&c.actor)
    .execute(&mut *api)
    .await
    .unwrap();
    let old: String = sqlx::query_scalar(
        "INSERT INTO openmettle.artifact_revisions (scope_id, artifact_id, revision, reservation_id,
             size_bytes, content_digest, media_type, created_by_user_id)
         VALUES ($1::uuid, $2::uuid, 1, $3::uuid, 3, $4, 'text/plain', $5::uuid) RETURNING id::text",
    )
    .bind(&c.scope)
    .bind(doc)
    .bind(&reserved)
    .bind(&digest)
    .bind(&c.actor)
    .fetch_one(&mut *api)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.storage_reservations SET state = 'settled', settled_bytes = 3,
             closed_at = now() WHERE id = $1::uuid",
    )
    .bind(&reserved)
    .execute(&mut *api)
    .await
    .unwrap();
    (old, reserved, digest)
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn migration_17_adds_a_bounded_immutable_display_name() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..16]).await.unwrap();
    configure(&db, Some(10_000), Some(10_000), Some(10_000)).await;
    let c = Context::new(&db).await;
    let doc = new_uuid(&db).await;
    // A version-16 revision, written with the version-4 column grants as a released binary does.
    let mut api = connect(&db.0, API).await;
    let (old, reserved, digest) = insert_legacy_revision(&mut api, &c, &doc).await;
    // The display-name column does not exist yet.
    assert_eq!(
        sqlstate(
            sqlx::query("SELECT display_name FROM openmettle.artifact_revisions")
                .fetch_all(&mut api)
                .await
        ),
        "42703"
    );
    drop(api);
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(db.history().await, all_versions());

    let mut api = connect(&db.0, API).await;
    let name: Option<String> = sqlx::query_scalar(
        "SELECT display_name FROM openmettle.artifact_revisions WHERE id = $1::uuid",
    )
    .bind(&old)
    .fetch_one(&mut api)
    .await
    .unwrap();
    assert_eq!(name, None);
    // The pre-17 revision replays exactly without a name; adding one conflicts.
    let replay = async |display_name: Option<&str>| {
        let mut cn = connect(&db.0, WORKER).await;
        let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
        let result = storage::settle(
            &mut tx,
            &Settlement {
                scope: &c.scope,
                reservation: &reserved,
                size_bytes: 3,
                content_digest: &digest,
                media_type: "text/plain",
                display_name,
            },
        )
        .await;
        tx.commit().await.unwrap();
        result
    };
    assert_eq!(replay(None).await.unwrap(), old);
    assert!(matches!(
        replay(Some("v16.txt")).await,
        Err(Error::Conflict)
    ));
    // The database bound: 1 to 255 characters, no control or surrounding white space.
    let insert = async |role: &str, revision: i64, name: &str| {
        let mut cn = connect(&db.0, role).await;
        let key = format!("name-{revision}");
        let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
        let reservation = storage::reserve(
            &mut tx,
            &ReservationInput {
                scope: &c.scope,
                actor: &c.actor,
                key: &key,
                artifact: &doc,
                max_bytes: 1,
                run: None,
                operation: None,
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        sqlx::query(
            "INSERT INTO openmettle.artifact_revisions (scope_id, artifact_id, revision,
                 reservation_id, size_bytes, content_digest, media_type, display_name,
                 created_by_user_id)
             VALUES ($1::uuid, $2::uuid, $3, $4::uuid, 0, $5, 'text/plain', $6, $7::uuid)",
        )
        .bind(&c.scope)
        .bind(&doc)
        .bind(revision)
        .bind(&reservation.id)
        .bind(&digest)
        .bind(name)
        .bind(&c.actor)
        .execute(&mut cn)
        .await
    };
    let long = "é".repeat(256);
    for (revision, name) in [
        (10, ""),
        (11, " leading"),
        (12, "trailing\t"),
        (13, "line\nbreak"),
        (14, "bell\u{7}"),
        (15, long.as_str()),
    ] {
        assert_eq!(
            sqlstate(insert(API, revision, name).await),
            "23514",
            "{name:?}"
        );
    }
    insert(API, 20, &"é".repeat(255)).await.unwrap();
    insert(WORKER, 21, "Report (final).pdf").await.unwrap();
    // Display names are immutable for both application roles.
    for role in [API, WORKER] {
        assert_eq!(
            sqlstate(
                sqlx::query("UPDATE openmettle.artifact_revisions SET display_name = 'x'")
                    .execute(&mut connect(&db.0, role).await)
                    .await
            ),
            "42501"
        );
    }
    // The boundary check reports any privilege beyond the version-17 contract.
    let mut owner = connect(&db.0, OWNER).await;
    owner
        .execute("GRANT UPDATE (display_name) ON openmettle.artifact_revisions TO openmettle_api")
        .await
        .unwrap();
    refused_with(
        &settings,
        MIGRATIONS,
        "openmettle_api has UPDATE on openmettle.artifact_revisions.display_name",
    )
    .await;
    owner
        .execute(
            "REVOKE UPDATE (display_name) ON openmettle.artifact_revisions FROM openmettle_api",
        )
        .await
        .unwrap();
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn ingest_publishes_once_and_replays_exactly() {
    let f = Fixture::new().await;
    let doc = new_uuid(&f.db).await;
    let content = b"synthetic artifact body\r\n--not-a-boundary\r\n";
    let first = form(
        "first",
        &[METADATA, file(Some("dir/Notes v1.txt"), content)],
        true,
    );
    let stored = f
        .upload("a", &doc, 1000, "first", chunked(&first, 1), true)
        .await
        .unwrap();
    assert_eq!(stored.size_bytes, content.len() as i64);
    assert_eq!(
        stored.content_digest.as_slice(),
        Sha256::digest(content).as_slice()
    );
    assert_eq!(stored.form.display_name.as_deref(), Some("Notes v1.txt"));
    assert_eq!(stored.form.media_type, "text/plain");
    assert!(f.files("staging").is_empty());
    assert_eq!(f.files("revisions"), [stored.reservation.as_str()]);
    assert_eq!(
        fs::read(f.root.join("revisions").join(&stored.reservation)).unwrap(),
        content
    );
    let row: (Option<String>, String, i64) = sqlx::query_as(
        "SELECT display_name, media_type, size_bytes FROM openmettle.artifact_revisions
          WHERE id = $1::uuid",
    )
    .bind(&stored.revision)
    .fetch_one(&mut f.db.admin().await)
    .await
    .unwrap();
    assert_eq!(
        row,
        (
            Some("Notes v1.txt".into()),
            "text/plain".into(),
            content.len() as i64
        )
    );
    assert_eq!(account(&f.db, &f.c.scope).await, (row.2, 0, 0));

    // A retry after a lost response, with another boundary, part order and chunking, returns
    // the same revision without a second file or charge.
    let retry = form(
        "second-boundary",
        &[file(Some("dir/Notes v1.txt"), content), METADATA],
        true,
    );
    let replayed = f
        .upload("a", &doc, 1000, "second-boundary", chunked(&retry, 7), true)
        .await
        .unwrap();
    assert_eq!(replayed, stored);
    assert_eq!(account(&f.db, &f.c.scope).await, (row.2, 0, 0));
    assert_eq!(f.files("revisions"), [stored.reservation.as_str()]);
    // A changed body or display name under the same key conflicts and changes nothing.
    for body in [
        form(
            "b",
            &[METADATA, file(Some("dir/Notes v1.txt"), b"other")],
            true,
        ),
        form("b", &[METADATA, file(Some("Notes v2.txt"), content)], true),
        form("b", &[METADATA, file(None, content)], true),
    ] {
        assert!(matches!(
            f.upload("a", &doc, 1000, "b", chunked(&body, 64), true)
                .await,
            Err(artifact_fs::Error::Storage(Error::Conflict))
        ));
    }
    // A changed byte ceiling is another request under the same key.
    assert!(matches!(
        f.upload("a", &doc, 999, "second-boundary", chunked(&retry, 64), true)
            .await,
        Err(artifact_fs::Error::Storage(Error::Conflict))
    ));
    assert_eq!(
        fs::read(f.root.join("revisions").join(&stored.reservation)).unwrap(),
        content
    );
    // A missing settled payload is reported, never recreated.
    fs::rename(
        f.root.join("revisions").join(&stored.reservation),
        f.root.join("moved"),
    )
    .unwrap();
    assert!(matches!(
        f.upload(
            "a",
            &doc,
            1000,
            "second-boundary",
            chunked(&retry, 64),
            true
        )
        .await,
        Err(artifact_fs::Error::Missing)
    ));
    // A symlink to a payload of the right size is not the settled payload either.
    std::os::unix::fs::symlink(
        f.root.join("moved"),
        f.root.join("revisions").join(&stored.reservation),
    )
    .unwrap();
    assert!(matches!(
        f.upload(
            "a",
            &doc,
            1000,
            "second-boundary",
            chunked(&retry, 64),
            true
        )
        .await,
        Err(artifact_fs::Error::Missing)
    ));
    fs::remove_file(f.root.join("revisions").join(&stored.reservation)).unwrap();
    fs::rename(
        f.root.join("moved"),
        f.root.join("revisions").join(&stored.reservation),
    )
    .unwrap();
    // A second revision of the same artifact is its own payload and charge.
    let second = form("c", &[file(None, b"v2"), METADATA], true);
    let v2 = f
        .upload("b", &doc, 1000, "c", chunked(&second, 3), true)
        .await
        .unwrap();
    assert_ne!(v2.reservation, stored.reservation);
    assert_eq!(v2.form.display_name, None);
    assert_eq!(f.files("revisions").len(), 2);
    assert_eq!(account(&f.db, &f.c.scope).await, (row.2 + 2, 0, 0));
    assert_totals(&f.db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn ingest_failures_unlink_staging_and_release_the_reservation() {
    let f = Fixture::new().await;
    let doc = new_uuid(&f.db).await;
    let ok = |body: &[u8]| form("x", &[METADATA, file(None, body)], true);
    let truncated = form("x", &[METADATA, file(None, b"partial")], false);
    let mut failing: VecDeque<Result<Vec<u8>, ()>> = ok(b"payload")
        .chunks(5)
        .take(8)
        .map(|c| Ok(c.to_vec()))
        .collect();
    failing.push_back(Err(()));
    let cases: Vec<Case> = vec![
        ("too-large", chunked(&ok(&[b'z'; 101]), 1), true, |e| {
            matches!(e, artifact_fs::Error::TooLarge)
        }),
        ("truncated", chunked(&truncated, 3), true, |e| {
            matches!(
                e,
                artifact_fs::Error::Multipart(multipart::Error::Truncated)
            )
        }),
        (
            "duplicate",
            chunked(
                &form("x", &[METADATA, file(None, b"a"), file(None, b"b")], true),
                2,
            ),
            true,
            |e| {
                matches!(
                    e,
                    artifact_fs::Error::Multipart(multipart::Error::DuplicatePart)
                )
            },
        ),
        (
            "unknown",
            chunked(
                &form(
                    "x",
                    &[
                        file(None, b"a"),
                        Part {
                            name: "extra",
                            filename: None,
                            media: "text/plain",
                            body: b"x",
                        },
                    ],
                    true,
                ),
                2,
            ),
            true,
            |e| {
                matches!(
                    e,
                    artifact_fs::Error::Multipart(multipart::Error::UnknownPart)
                )
            },
        ),
        (
            "name",
            chunked(&form("x", &[METADATA, file(Some(" x"), b"a")], true), 4),
            true,
            |e| {
                matches!(
                    e,
                    artifact_fs::Error::Multipart(multipart::Error::DisplayName)
                )
            },
        ),
        ("rejected", chunked(&ok(b"payload"), 4), false, |e| {
            matches!(e, artifact_fs::Error::Rejected)
        }),
        ("body", Chunks(failing), true, |e| {
            matches!(e, artifact_fs::Error::Body)
        }),
    ];
    for (key, body, accept, expected) in cases {
        let error = f
            .upload(key, &doc, 100, "x", body, accept)
            .await
            .unwrap_err();
        assert!(expected(&error), "{key}: {error:?}");
        assert_eq!(f.state(key).await.as_deref(), Some("released"), "{key}");
        assert!(f.files("staging").is_empty(), "{key}");
        assert!(f.files("revisions").is_empty(), "{key}");
        // The released key is spent: a retry conflicts and writes nothing.
        assert!(matches!(
            f.upload(key, &doc, 100, "x", chunked(&ok(b"y"), 64), true)
                .await,
            Err(artifact_fs::Error::Storage(Error::Conflict))
        ));
    }
    // A refused Content-Type reserves nothing.
    let upload = Upload {
        scope: &f.c.scope,
        actor: &f.c.actor,
        key: "content-type",
        artifact: &doc,
        max_bytes: 100,
        content_type: "application/json",
    };
    assert!(matches!(
        artifact_fs::ingest(&f.api, &f.store, &upload, chunked(b"{}", 2), |_| true).await,
        Err(artifact_fs::Error::Multipart(multipart::Error::ContentType))
    ));
    assert_eq!(f.state("content-type").await, None);
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 0, 0));
    assert_totals(&f.db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn concurrent_and_crashed_uploads_are_reconciled_without_uncharged_files() {
    let f = Fixture::new().await;
    let doc = new_uuid(&f.db).await;
    let body = form("x", &[METADATA, file(None, b"payload")], true);
    // Another request (or a crash) holds the staging file: the upload leaves it and the
    // reservation alone.
    let held = f.reserve("held", &doc, 100).await;
    fs::write(f.root.join("staging").join(&held), b"other request").unwrap();
    assert!(matches!(
        f.upload("held", &doc, 100, "x", chunked(&body, 8), true)
            .await,
        Err(artifact_fs::Error::InProgress)
    ));
    assert_eq!(f.state("held").await.as_deref(), Some("reserved"));
    assert_eq!(f.files("staging"), [held.as_str()]);
    // A crash after the rename but before settle leaves a revision file under a reservation.
    let renamed = f.reserve("renamed", &doc, 100).await;
    fs::write(f.root.join("revisions").join(&renamed), b"unsettled").unwrap();
    use std::os::unix::fs::MetadataExt;
    for (id, dir) in [(&held, "staging"), (&renamed, "revisions")] {
        let ino = fs::metadata(f.root.join(dir).join(id)).unwrap().ino();
        sqlx::query("UPDATE openmettle.storage_reservations SET stage_claimed=true,payload_ino=$2::text::numeric WHERE id=$1::uuid")
            .bind(id).bind(ino.to_string()).execute(&mut f.db.admin().await).await.unwrap();
    }
    // A recent reservation is not touched.
    let recent = |older_than| artifact_fs::reconcile_expired(&f.api, &f.store, older_than, 10);
    assert_eq!(recent(Duration::from_secs(3600)).await.unwrap(), 0);
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 0, 200));
    assert!(matches!(
        artifact_fs::reconcile_expired(&f.api, &f.store, Duration::ZERO, 0).await,
        Err(artifact_fs::Error::Storage(Error::Invalid))
    ));
    f.db.admin()
        .await
        .execute(
            "UPDATE openmettle.storage_reservations SET created_at=now()-interval '901 seconds',
        lease_expires_at=now()-interval '1 second' WHERE state='reserved'",
        )
        .await
        .unwrap();
    // Bounded batches, oldest first.
    assert_eq!(recent(Duration::ZERO).await.unwrap(), 2);
    assert_eq!(f.state("held").await.as_deref(), Some("released"));
    assert_eq!(f.state("renamed").await.as_deref(), Some("released"));
    assert!(f.files("staging").is_empty() && f.files("revisions").is_empty());
    assert_eq!(recent(Duration::ZERO).await.unwrap(), 0);
    // A foreign revision is never overwritten, even if the caller retries with the same key.
    let retried = f.reserve("retried", &doc, 100).await;
    fs::write(f.root.join("revisions").join(&retried), b"stale").unwrap();
    assert!(
        f.upload("retried", &doc, 100, "x", chunked(&body, 8), true)
            .await
            .is_err()
    );
    assert_eq!(
        fs::read(f.root.join("revisions").join(&retried)).unwrap(),
        b"stale"
    );
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 0, 100));
    assert_totals(&f.db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn expired_reservations_skip_locks_and_continue_after_an_unlink_error() {
    let f = Fixture::new().await;
    let doc = new_uuid(&f.db).await;
    let locked = f.reserve("locked", &doc, 100).await;
    let broken = f.reserve("broken", &doc, 100).await;
    f.reserve("healthy", &doc, 100).await;
    let bad_path = f.root.join("staging").join(&broken);
    fs::create_dir(&bad_path).unwrap();
    f.db.admin()
        .await
        .execute(
            "UPDATE openmettle.storage_reservations SET created_at=now()-interval '901 seconds',
        lease_expires_at=now()-interval '1 second' WHERE state='reserved'",
        )
        .await
        .unwrap();

    let mut conn = f.db.admin().await;
    let mut lock = WriteTransaction::begin(&mut conn).await.unwrap();
    sqlx::query("SELECT FROM openmettle.storage_reservations WHERE id = $1::uuid FOR UPDATE")
        .bind(locked)
        .execute(lock.connection().unwrap())
        .await
        .unwrap();
    let sweep = || artifact_fs::reconcile_expired(&f.api, &f.store, Duration::ZERO, 10);
    let result = tokio::time::timeout(Duration::from_secs(5), sweep())
        .await
        .unwrap();
    assert!(matches!(result, Err(artifact_fs::Error::Io)));
    assert_eq!(f.state("healthy").await.as_deref(), Some("released"));
    assert_eq!(f.state("broken").await.as_deref(), Some("reserved"));
    fs::remove_dir(bad_path).unwrap();
    // An unexpected non-regular leaf requires owner verification even after the path disappears.
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT adoption_unverified FROM openmettle.storage_reservations WHERE id=$1::uuid"
        )
        .bind(broken)
        .fetch_one(&mut f.db.admin().await)
        .await
        .unwrap()
    );
    assert_eq!(sweep().await.unwrap(), 0);
    assert_eq!(f.state("locked").await.as_deref(), Some("reserved"));
    lock.rollback().await.unwrap();
    assert_eq!(sweep().await.unwrap(), 1);
    assert_totals(&f.db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn purge_unlinks_the_payload_before_confirming() {
    let f = Fixture::new().await;
    let doc = new_uuid(&f.db).await;
    let body = form("x", &[METADATA, file(Some("old.txt"), b"retained")], true);
    let stored = f
        .upload("p", &doc, 100, "x", chunked(&body, 16), true)
        .await
        .unwrap();
    let worker = pool(&f.db, WORKER).await;
    let payload = f.root.join("revisions").join(&stored.reservation);
    assert!(matches!(
        artifact_fs::purge_due(&worker, &f.store, MAX_BATCH + 1).await,
        Err(artifact_fs::Error::Storage(Error::Invalid))
    ));
    // Active and not yet expired revisions are not purged.
    assert_eq!(
        artifact_fs::purge_due(&worker, &f.store, 10).await.unwrap(),
        0
    );
    let mut cn = connect(&f.db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
    storage::retain_revision(&mut tx, &f.c.scope, &stored.revision)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        artifact_fs::purge_due(&worker, &f.store, 10).await.unwrap(),
        0
    );
    assert!(payload.exists());
    tokio::time::sleep(Duration::from_millis(1200)).await;
    // The API holds no purge grants.
    assert!(artifact_fs::purge_due(&f.api, &f.store, 10).await.is_err());
    assert!(payload.exists());
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 8, 0));
    assert_eq!(
        artifact_fs::purge_due(&worker, &f.store, 10).await.unwrap(),
        1
    );
    assert!(!payload.exists());
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 0, 0));
    assert_eq!(
        artifact_fs::purge_due(&worker, &f.store, 10).await.unwrap(),
        0
    );
    let state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.artifact_revisions WHERE id = $1::uuid")
            .bind(&stored.revision)
            .fetch_one(&mut f.db.admin().await)
            .await
            .unwrap();
    assert_eq!(state, "purged");
    assert_eq!(journaled(&f.db).await, [stored.revision]);
    assert_totals(&f.db).await;
}

/// Revisions in the deletion journal, in journal order.
async fn journaled(db: &TestDb) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT entity_id::text FROM openmettle.deletion_journal ORDER BY journal_seq",
    )
    .fetch_all(&mut db.admin().await)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn purge_resumes_after_worker_death_at_each_stage_without_double_release() {
    let f = Fixture::new().await;
    retention_grace(&f.db, 0).await;
    let body = form("x", &[METADATA, file(None, b"payload")], true);
    let revisions = f.root.join("revisions");
    let mut api = connect(&f.db.0, API).await;
    let mut cn = connect(&f.db.0, WORKER).await;
    let mut stored = Vec::new();
    // Each worker died after a different stage: after its claim committed, after Stage A
    // anchored, truncated and unlinked the payload, and after confirmation but before Stage C.
    for (stage, key) in ["claimed", "unlinked", "confirmed"].into_iter().enumerate() {
        let doc = new_uuid(&f.db).await;
        let s = f
            .upload(key, &doc, 100, "x", chunked(&body, 16), true)
            .await
            .unwrap();
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        storage::retain_revision(&mut tx, &f.c.scope, &s.revision)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
        storage::begin_purge(&mut tx, &f.c.scope, &s.revision)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        if stage > 0 {
            let payload = revisions.join(&s.reservation);
            let anchor = revisions.join(format!(".purge.{}", s.reservation));
            fs::hard_link(&payload, &anchor).unwrap();
            fs::OpenOptions::new()
                .write(true)
                .open(&anchor)
                .unwrap()
                .set_len(0)
                .unwrap();
            fs::remove_file(&payload).unwrap();
        }
        if stage > 1 {
            let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
            storage::confirm_purge(&mut tx, &f.c.scope, &s.revision)
                .await
                .unwrap();
            tx.commit().await.unwrap();
        }
        stored.push(s);
    }
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 14, 0));
    assert_eq!(journaled(&f.db).await, [stored[2].revision.clone()]);
    assert_totals(&f.db).await;

    let worker = pool(&f.db, WORKER).await;
    assert_eq!(
        artifact_fs::purge_due(&worker, &f.store, 10).await.unwrap(),
        2
    );
    assert!(
        f.files("revisions").is_empty(),
        "{:?}",
        f.files("revisions")
    );
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 0, 0));
    assert_eq!(
        artifact_fs::purge_due(&worker, &f.store, 10).await.unwrap(),
        0
    );
    let mut recorded = journaled(&f.db).await;
    recorded.sort();
    let mut expected: Vec<String> = stored.iter().map(|s| s.revision.clone()).collect();
    expected.sort();
    assert_eq!(recorded, expected);
    let left: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.artifact_revisions WHERE state <> 'purged' OR purge_stage <> 'none'",
    )
    .fetch_one(&mut f.db.admin().await)
    .await
    .unwrap();
    assert_eq!(left, 0);
    assert_totals(&f.db).await;
}

fn sweep_process(f: &Fixture, artifacts: bool) -> Process {
    let mut cmd = binary("worker");
    cmd.env("OPENMETTLE_WORKER_BIND", address())
        .env("OPENMETTLE_WORKER_DATABASE_URL", f.db.url(WORKER))
        .env("OPENMETTLE_WORKER_SWEEP_MS", "1000");
    if artifacts {
        cmd.env("OPENMETTLE_WORKER_ARTIFACTS_DIR", &f.root);
    }
    Process(cmd.spawn().unwrap())
}

async fn expired_runs(f: &Fixture, tx: &mut WriteTransaction<'_>, prefix: &str) -> [String; 2] {
    let queued = runs::create_run(tx, &f.c.input(&format!("{prefix}-queue")))
        .await
        .unwrap();
    let running = runs::create_run(tx, &f.c.input(&format!("{prefix}-running")))
        .await
        .unwrap();
    // Legacy queued and executing rows with NULL deadlines are both due (ADR 0033).
    sqlx::query("UPDATE openmettle.runs SET state = 'running' WHERE id = $1::uuid")
        .bind(&running)
        .execute(tx.connection().unwrap())
        .await
        .unwrap();
    [queued, running]
}

async fn assert_swept(f: &Fixture, ids: &[String; 2]) {
    tokio::time::timeout(Duration::from_secs(10), async {
        for (id, expected) in ids
            .iter()
            .zip(["openmettle.run-expired", "openmettle.run-failed"])
        {
            loop {
                let events = crate::authz_runs::terminal_events(&f.db, id).await;
                if let Some((format, _)) = events.first() {
                    assert_eq!(events.len(), 1);
                    assert_eq!(format, expected);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn worker_purges_unlocked_revisions_and_sweeps_runs_while_a_revision_stays_locked() {
    let f = Fixture::new().await;
    let body = form("x", &[METADATA, file(None, b"payload")], true);
    let mut revisions = Vec::new();
    let mut api = connect(&f.db.0, API).await;
    for key in ["locked", "healthy"] {
        let doc = new_uuid(&f.db).await;
        let stored = f
            .upload(key, &doc, 100, "x", chunked(&body, 16), true)
            .await
            .unwrap();
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        storage::retain_revision(&mut tx, &f.c.scope, &stored.revision)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        revisions.push(stored);
    }
    let mut conn = f.db.admin().await;
    let mut lock = WriteTransaction::begin(&mut conn).await.unwrap();
    sqlx::query("SELECT FROM openmettle.artifact_revisions WHERE id = $1::uuid FOR UPDATE")
        .bind(&revisions[0].revision)
        .execute(lock.connection().unwrap())
        .await
        .unwrap();

    let mut process = sweep_process(&f, true);
    tokio::time::timeout(Duration::from_secs(10), async {
        while account(&f.db, &f.c.scope).await != (0, 7, 0)
            || f.files("revisions") != [revisions[0].reservation.as_str()]
        {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the later revision was not purged");
    assert_eq!(f.files("revisions"), [revisions[0].reservation.as_str()]);
    // These deadlines arrived after the first purge. The next maintenance tick must run
    // both deadline sweeps even though the oldest revision is still locked.
    let mut owner = f.db.admin().await;
    let mut seed = WriteTransaction::begin(&mut owner).await.unwrap();
    let ids = expired_runs(&f, &mut seed, "during-purge").await;
    seed.commit().await.unwrap();
    assert_swept(&f, &ids).await;

    assert!(stop_process(&mut process, "-TERM", "artifact_fs worker shutdown").success());
    let logs = read_string_bounded(
        process.0.stderr.take().unwrap(),
        PIPE_DRAIN_TIMEOUT,
        "stderr",
        "artifact_fs worker stderr",
    );
    assert!(
        logs.lines()
            .any(|line| line.contains("worker.sweep.failed") && line.contains("purge_due"))
    );
    lock.rollback().await.unwrap();
    assert_eq!(
        artifact_fs::purge_due(&pool(&f.db, WORKER).await, &f.store, 10)
            .await
            .unwrap(),
        1
    );
    assert_totals(&f.db).await;
}

/// A retained revision that is due once its one-second grace elapses.
async fn due(f: &Fixture, key: &str) -> Stored {
    let s = f.payload(key, key.as_bytes()).await;
    let mut api = connect(&f.db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    storage::retain_revision(&mut tx, &f.c.scope, &s.revision)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    s
}

async fn wait_until(what: &str, mut done: impl AsyncFnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !done().await {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect(what);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn worker_binary_purges_only_while_the_restore_gate_is_open() {
    let f = Fixture::new().await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let origin_us: i64 = sqlx::query_scalar(
        "SELECT (extract(epoch FROM coverage_started_at) * 1000000)::bigint
           FROM openmettle.deletion_journal_head WHERE id",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    sqlx::query(
        "SELECT openmettle.restore_gate_lock($1, 0, decode(repeat('00', 32), 'hex'), true)",
    )
    .bind(origin_us)
    .execute(&mut owner)
    .await
    .unwrap();
    let s = due(&f, "gated").await;
    let mut seed = WriteTransaction::begin(&mut owner).await.unwrap();
    let ids = expired_runs(&f, &mut seed, "gated").await;
    seed.commit().await.unwrap();
    let mut process = sweep_process(&f, true);
    // Maintenance ticks run (the run deadlines are swept) but skip the purge sweep.
    assert_swept(&f, &ids).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(f.files("revisions"), [s.reservation.as_str()]);
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 5, 0));
    sqlx::query(
        "SELECT openmettle.restore_gate_open(c.restore_run_id, c.volume_claim_token, $1, 0, decode(repeat('00', 32), 'hex'))
           FROM openmettle.restore_claim_volume_phase($1, 0, decode(repeat('00', 32), 'hex')) AS c",
    )
    .bind(origin_us)
    .execute(&mut owner)
    .await
    .unwrap();
    wait_until(
        "the revision was not purged after the gate opened",
        async || account(&f.db, &f.c.scope).await == (0, 0, 0) && f.files("revisions").is_empty(),
    )
    .await;
    assert!(stop_process(&mut process, "-TERM", "restore-gated worker shutdown").success());
    let logs = read_string_bounded(
        process.0.stderr.take().unwrap(),
        PIPE_DRAIN_TIMEOUT,
        "stderr",
        "restore-gated worker stderr",
    );
    // A closed gate is a deferral, not a sweep failure.
    assert!(!logs.contains("worker.sweep.failed"), "{logs}");
    assert_eq!(journaled(&f.db).await, [s.revision]);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_worker_killed_inside_a_scheduled_purge_is_resumed_and_releases_once() {
    let f = Fixture::new().await;
    let s = due(&f, "killed").await;
    let anchor = format!(".purge.{}", s.reservation);
    // Holding the instance counters stops the scheduled purge in its confirmation, after Stage A
    // anchored, truncated and unlinked the payload.
    let mut owner = f.db.admin().await;
    let mut lock = WriteTransaction::begin(&mut owner).await.unwrap();
    lock.connection()
        .unwrap()
        .execute("LOCK openmettle.storage_instance IN EXCLUSIVE MODE")
        .await
        .unwrap();
    let mut process = sweep_process(&f, true);
    wait_until("the purge did not reach its confirmation", async || {
        let waiting: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT FROM pg_stat_activity p JOIN pg_locks l ON l.pid = p.pid
              WHERE p.datname = current_database() AND p.usename = 'openmettle_worker'
                AND NOT l.granted AND l.relation = 'openmettle.storage_instance'::regclass)",
        )
        .fetch_one(&mut f.db.admin().await)
        .await
        .unwrap();
        waiting && f.files("revisions") == [anchor.as_str()]
    })
    .await;
    let _ = stop_process(&mut process, "-KILL", "killed purge worker");
    lock.rollback().await.unwrap();
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 6, 0));
    assert!(journaled(&f.db).await.is_empty());
    let mut replacement = sweep_process(&f, true);
    wait_until("the replacement did not finish the purge", async || {
        account(&f.db, &f.c.scope).await == (0, 0, 0) && f.files("revisions").is_empty()
    })
    .await;
    assert!(stop_process(&mut replacement, "-TERM", "replacement purge worker").success());
    assert_eq!(journaled(&f.db).await, [s.revision]);
    assert_totals(&f.db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn worker_binary_sweeps_with_and_without_payloads_and_recovers_after_signals() {
    use std::os::unix::{fs::MetadataExt, process::ExitStatusExt};
    let f = Fixture::new().await;
    let doc = new_uuid(&f.db).await;
    let old = f.reserve("abandoned", &doc, 100).await;
    let staged = f.root.join("staging").join(&old);
    fs::write(&staged, b"partial").unwrap();
    sqlx::query(
        "UPDATE openmettle.storage_reservations SET created_at = now() - interval '901 seconds',lease_expires_at=now()-interval '1 second',
        stage_claimed=true,payload_ino=$2::text::numeric WHERE id = $1::uuid",
    )
    .bind(&old)
    .bind(fs::metadata(&staged).unwrap().ino().to_string())
    .execute(&mut f.db.admin().await)
    .await
    .unwrap();
    let body = form("x", &[METADATA, file(None, b"retained")], true);
    let stored = f
        .upload("retained", &doc, 100, "x", chunked(&body, 16), true)
        .await
        .unwrap();
    let payload = f.root.join("revisions").join(&stored.reservation);
    let mut c = connect(&f.db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    storage::retain_revision(&mut tx, &f.c.scope, &stored.revision)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // Both signals hit a real sweep blocked on this fixture's table lock. The replacement
    // must settle the queued work once, including a batch left behind by SIGKILL.
    let mut owner = f.db.admin().await;
    let mut seed = WriteTransaction::begin(&mut owner).await.unwrap();
    let mut ids = expired_runs(&f, &mut seed, "first").await;
    seed.commit().await.unwrap();
    for (artifacts, sig) in [(false, "-TERM"), (true, "-KILL")] {
        let mut process = sweep_process(&f, artifacts);
        assert_swept(&f, &ids).await;
        if artifacts {
            tokio::time::timeout(Duration::from_secs(8), async {
                while account(&f.db, &f.c.scope).await != (0, 0, 0) {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .unwrap();
        }
        assert_eq!(staged.exists(), !artifacts);
        assert_eq!(payload.exists(), !artifacts);
        let mut lock = WriteTransaction::begin(&mut owner).await.unwrap();
        lock.connection()
            .unwrap()
            .execute("LOCK openmettle.runs IN ACCESS EXCLUSIVE MODE")
            .await
            .unwrap();
        ids = expired_runs(&f, &mut lock, sig).await;
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS (
                        SELECT FROM pg_stat_activity p JOIN pg_locks l ON l.pid = p.pid
                        WHERE p.datname = current_database() AND p.usename = 'openmettle_worker'
                          AND p.wait_event_type = 'Lock' AND NOT l.granted
                          AND l.relation = 'openmettle.runs'::regclass)",
                )
                .fetch_one(&mut f.db.admin().await)
                .await
                .unwrap();
                if waiting {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        signal(&process.0, sig);
        lock.commit().await.unwrap();
        let status = wait_exit(
            &mut process.0,
            &format!("artifact_fs worker ({sig}, artifacts={artifacts})"),
        );
        if artifacts {
            assert_eq!(status.signal(), Some(9));
        } else {
            assert_eq!(status.code(), Some(0));
        }
    }
    let mut replacement = sweep_process(&f, true);
    assert_swept(&f, &ids).await;
    assert!(
        stop_process(
            &mut replacement,
            "-TERM",
            "artifact_fs replacement worker shutdown",
        )
        .success()
    );
    assert_eq!(f.state("abandoned").await.as_deref(), Some("released"));
    assert_totals(&f.db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn adoption_detects_cross_reservation_alias_and_preserves_its_owner() {
    use artifact_fs::adoption::{Options, adopt};
    let f = Fixture::new().await;
    let doc = new_uuid(&f.db).await;
    let body = form("x", &[METADATA, file(None, b"original")], true);
    let stored = f
        .upload("B", &doc, 100, "x", chunked(&body, 8), true)
        .await
        .unwrap();
    let other = f.reserve("A", &doc, 100).await;
    let published = f.root.join("revisions").join(&stored.reservation);
    let staged = f.root.join("staging").join(&other);
    fs::hard_link(&published, &staged).unwrap();
    let opts = Options {
        root: &f.root,
        replace: None,
        expected_fs: None,
        expected_directory: None,
        confirm_absent: false,
    };
    let mut owner = connect(&f.db.0, OWNER).await;
    for _ in 0..2 {
        assert_eq!(
            adopt(&mut owner, &opts).await.unwrap_err().0,
            "cross_reservation_inode_alias"
        );
        let state:(bool,bool)=sqlx::query_as("SELECT adoption_unverified,payload_ino IS NULL FROM openmettle.storage_reservations WHERE id=$1::uuid")
            .bind(&other).fetch_one(&mut owner).await.unwrap();
        assert_eq!(state, (true, true));
        assert_eq!(fs::read(&published).unwrap(), b"original");
    }
    fs::remove_file(&staged).unwrap();
    fs::write(&staged, b"replacement").unwrap();
    adopt(&mut owner, &opts).await.unwrap();
    let state:(bool,bool)=sqlx::query_as("SELECT adoption_unverified,payload_ino IS NOT NULL FROM openmettle.storage_reservations WHERE id=$1::uuid")
        .bind(&other).fetch_one(&mut owner).await.unwrap();
    assert_eq!(state, (false, true));
    let report = artifact_fs::verify_accounting_drift(&pool(&f.db, WORKER).await, Some(&f.store))
        .await
        .unwrap();
    assert!(report.healthy(), "{report:?}");
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn generic_expiry_leaves_operation_bound_tool_spills_charged() {
    let f = Fixture::new().await;
    let run = f.c.run(&f.db, "cleanup-ownership").await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let op: String = sqlx::query_scalar(
        "INSERT INTO openmettle.operations(scope_id,run_id,logical_key,target,capability,format,
             format_version,request,request_identity,request_digest,outcome,revision,
             observation_format,observation_version,evidence)
         VALUES ($1::uuid,$2::uuid,'spill-fixture','fixture','lookup','v1',1,'q','i',
             sha256('i'),'succeeded',1,'v1',1,'done') RETURNING id::text",
    )
    .bind(&f.c.scope)
    .bind(&run)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let doc = new_uuid(&f.db).await;
    let mut api = connect(&f.db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let mut input = ReservationInput {
        scope: &f.c.scope,
        actor: &f.c.actor,
        key: "tool-spill:fixture",
        artifact: &doc,
        max_bytes: 100,
        run: Some(&run),
        operation: Some(&op),
    };
    let spill = storage::reserve(&mut tx, &input).await.unwrap();
    input.key = "ordinary-operation";
    storage::reserve(&mut tx, &input).await.unwrap();
    tx.commit().await.unwrap();
    let unbind = sqlx::query(
        "UPDATE openmettle.storage_reservations SET operation_id=NULL WHERE id=$1::uuid",
    )
    .bind(&spill.id)
    .execute(&mut owner)
    .await;
    assert_eq!(sqlstate(unbind), "23514");
    sqlx::query("UPDATE openmettle.runs SET state='succeeded' WHERE id=$1::uuid")
        .bind(&run)
        .execute(&mut owner)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE openmettle.storage_reservations SET created_at=now()-interval '2 hours',
        lease_expires_at=now()-interval '1 hour' WHERE run_id=$1::uuid",
    )
    .bind(&run)
    .execute(&mut owner)
    .await
    .unwrap();
    let path = f.root.join("staging").join(&spill.id);
    fs::write(&path, b"reserved spill bytes").unwrap();
    let worker = pool(&f.db, WORKER).await;
    assert_eq!(
        artifact_fs::reconcile_expired(&worker, &f.store, Duration::ZERO, 10)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        f.state("ordinary-operation").await.as_deref(),
        Some("released")
    );
    assert_eq!(
        f.state("tool-spill:fixture").await.as_deref(),
        Some("reserved")
    );
    assert_eq!(fs::read(path).unwrap(), b"reserved spill bytes");
    assert_totals(&f.db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn expired_unbound_empty_staging_requires_exclusive_lock_before_inode_binding() {
    use std::os::unix::fs::MetadataExt;
    let f = Fixture::new().await;
    let doc = new_uuid(&f.db).await;
    let id = f.reserve("before-bind", &doc, 100).await;
    let path = f.root.join("staging").join(&id);
    let file = fs::File::create_new(&path).unwrap();
    file.try_lock_shared().unwrap();
    let ino = file.metadata().unwrap().ino();
    let mut owner = connect(&f.db.0, OWNER).await;
    sqlx::query("UPDATE openmettle.storage_reservations SET stage_claimed=true,created_at=now()-interval '901 seconds',
        lease_expires_at=now()-interval '1 second' WHERE id=$1::uuid").bind(&id).execute(&mut owner).await.unwrap();
    let w = pool(&f.db, WORKER).await;
    let sweep = || artifact_fs::reconcile_expired(&w, &f.store, Duration::from_secs(900), 10);
    assert!(matches!(sweep().await, Err(artifact_fs::Error::InProgress)));
    assert_eq!(fs::metadata(&path).unwrap().ino(), ino);
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT payload_ino IS NULL FROM openmettle.storage_reservations WHERE id=$1::uuid"
        )
        .bind(&id)
        .fetch_one(&mut owner)
        .await
        .unwrap()
    );
    drop(file);
    sqlx::query("UPDATE openmettle.storage_reservations SET reclaim_lease_until=clock_timestamp() WHERE id=$1::uuid")
        .bind(&id).execute(&mut owner).await.unwrap();
    assert_eq!(sweep().await.unwrap(), 1);
    let state:(String,String,String)=sqlx::query_as("SELECT state,reclaim_state,payload_ino::text FROM openmettle.storage_reservations WHERE id=$1::uuid")
        .bind(&id).fetch_one(&mut owner).await.unwrap();
    assert_eq!(state, ("released".into(), "none".into(), ino.to_string()));
    assert!(f.files("staging").is_empty());
    assert_totals(&f.db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn adoption_clears_detached_pending_anchors_even_after_inode_reuse() {
    use artifact_fs::adoption::{Options, adopt};
    use std::os::unix::fs::MetadataExt;

    let f = Fixture::new().await;
    let doc = new_uuid(&f.db).await;
    let body = form("x", &[METADATA, file(None, b"surviving revision")], true);
    let upload = |key| f.upload(key, &doc, 100, "x", chunked(&body, 8), true);
    let current = upload("current").await.unwrap();
    let old = upload("purged").await.unwrap();
    let released = f.reserve("released", &doc, 100).await;
    let mut api = connect(&f.db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    storage::release(&mut tx, &f.c.scope, &released)
        .await
        .unwrap();
    storage::retain_revision(&mut tx, &f.c.scope, &old.revision)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let worker = pool(&f.db, WORKER).await;
    assert_eq!(
        artifact_fs::purge_due(&worker, &f.store, 8).await.unwrap(),
        1
    );
    let live = f.root.join("revisions").join(&current.reservation);
    let ino = fs::metadata(&live).unwrap().ino().to_string();

    // Reproduce the crash after the last unlink, then reuse that historical inode.
    let mut owner = connect(&f.db.0, OWNER).await;
    sqlx::query("UPDATE openmettle.storage_reservations SET stage_claimed=true,payload_ino=$3::text::numeric,
        reclaim_state=CASE WHEN id=$1::uuid THEN 'anchor_pending_unlink' ELSE reclaim_state END
        WHERE id IN ($1::uuid,$2::uuid)").bind(&released).bind(&old.reservation).bind(&ino).execute(&mut owner).await.unwrap();
    sqlx::query("UPDATE openmettle.artifact_revisions SET purge_stage='anchor_pending_unlink' WHERE id=$1::uuid")
        .bind(&old.revision).execute(&mut owner).await.unwrap();
    adopt(
        &mut owner,
        &Options {
            root: &f.root,
            replace: None,
            expected_fs: None,
            expected_directory: None,
            confirm_absent: false,
        },
    )
    .await
    .unwrap();
    let stages: (String, String) = sqlx::query_as(
        "SELECT reclaim_state,purge_stage FROM openmettle.storage_reservations s
        CROSS JOIN openmettle.artifact_revisions r WHERE s.id=$1::uuid AND r.id=$2::uuid",
    )
    .bind(&released)
    .bind(&old.revision)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(stages, ("none".into(), "none".into()));
    assert_eq!(fs::read(live).unwrap(), b"surviving revision");
    assert_totals(&f.db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn reclaim_recovers_each_durable_anchor_boundary_without_truncating_replacement_names() {
    use std::os::unix::fs::MetadataExt;
    let f = Fixture::new().await;
    let doc = new_uuid(&f.db).await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let worker = pool(&f.db, WORKER).await;
    for (step, staged, published) in [
        ("claiming", true, true),
        ("claiming", false, true),
        ("claiming", false, false),
        ("truncated", false, false),
    ] {
        let key = format!("{step}-{staged}-{published}");
        let id = f.reserve(&key, &doc, 10).await;
        let anchor = f.root.join("staging").join(format!(".reclaim.{id}"));
        let visible = f.root.join("staging").join(&id);
        let revision = f.root.join("revisions").join(&id);
        let file = fs::File::create_new(&anchor).unwrap();
        let ino = file.metadata().unwrap().ino().to_string();
        if staged {
            fs::hard_link(&anchor, &visible).unwrap();
        }
        if published {
            fs::hard_link(&anchor, &revision).unwrap();
        }
        if step == "truncated" {
            fs::write(&visible, b"foreign").unwrap();
        }
        sqlx::query("UPDATE openmettle.storage_reservations SET stage_claimed=true,payload_ino=$2::text::numeric,
            reclaim_state=$3,reclaim_claim_token=gen_random_uuid(),reclaim_lease_until=clock_timestamp(),
            created_at=clock_timestamp()-interval '2 hours',lease_expires_at=clock_timestamp()-interval '1 hour'
            WHERE id=$1::uuid").bind(&id).bind(ino).bind(step).execute(&mut owner).await.unwrap();
        assert_eq!(
            artifact_fs::reconcile_expired(&worker, &f.store, Duration::from_secs(900), 10)
                .await
                .unwrap(),
            1
        );
        assert!(!anchor.exists() && !revision.exists());
        if step == "truncated" {
            assert_eq!(fs::read(&visible).unwrap(), b"foreign");
        } else {
            assert!(!visible.exists());
        }
        assert_eq!(f.state(&key).await.as_deref(), Some("released"));
        assert_totals(&f.db).await;
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn admin_cli_adopts_populated_upgrade_only_after_verifying_the_original_payload() {
    use std::os::unix::fs::MetadataExt;
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
    configure(&db, Some(1000), Some(1000), Some(1000)).await;
    let c = Context::new(&db).await;
    let doc = new_uuid(&db).await;
    let mut api = connect(&db.0, API).await;
    let (_, reserved, _) = insert_legacy_revision(&mut api, &c, &doc).await;
    let mut owner = connect(&db.0, OWNER).await;
    for sql in [
        "UPDATE openmettle.storage_accounts SET active_bytes=3,reserved_bytes=0",
        "UPDATE openmettle.storage_instance SET active_bytes=3,reserved_bytes=0",
    ] {
        owner.execute(sql).await.unwrap();
    }
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    // An operator must be able to diagnose a pinned ledger missing its inode bindings.
    let mut pin = owner.begin().await.unwrap();
    sqlx::query(
        "UPDATE openmettle.storage_volume_control SET volume_id=gen_random_uuid() WHERE id",
    )
    .execute(&mut *pin)
    .await
    .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT storage_mismatches FROM openmettle.quota_verify_accounting_drift()"
        )
        .fetch_one(&mut *pin)
        .await
        .unwrap(),
        1
    );
    pin.rollback().await.unwrap();
    let dir = Dir::new();
    let root = dir.path("original");
    let root = std::path::Path::new(&root);
    fs::create_dir_all(root.join("revisions")).unwrap();
    fs::create_dir(root.join("staging")).unwrap();
    let payload = root.join("revisions").join(&reserved);
    fs::write(&payload, b"bad").unwrap();
    let admin = |args: &[&str]| {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_openmettle-admin"));
        cmd.env("OPENMETTLE_ADMIN_DATABASE_URL", db.url(OWNER))
            .args(args);
        run_cli(&mut cmd, &format!("openmettle-admin {args:?}"))
    };
    let path = root.to_str().unwrap();
    let failed = admin(&["storage", "adopt", path]);
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("size_or_digest_mismatch"));
    assert!(!root.join(".openmettle-volume-id").exists());
    let untouched:bool = sqlx::query_scalar("SELECT volume_id IS NULL AND adoption_run_id IS NULL
        AND NOT bootstrap_auto_pin_allowed AND NOT EXISTS (SELECT FROM openmettle.storage_reservations WHERE payload_ino IS NOT NULL)
        FROM openmettle.storage_volume_control").fetch_one(&mut owner).await.unwrap();
    assert!(untouched);
    fs::write(&payload, b"v16").unwrap();
    for args in [
        vec!["storage", "adopt", path],
        vec!["quota", "drain-orphans"],
        vec!["quota", "activate"],
        vec!["quota", "verify", path],
    ] {
        let result = admin(&args);
        assert!(
            result.status.success(),
            "command {args:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let ino: String = sqlx::query_scalar(
        "SELECT payload_ino::text FROM openmettle.storage_reservations WHERE id=$1::uuid",
    )
    .bind(&reserved)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(ino, fs::metadata(payload).unwrap().ino().to_string());
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn initial_adoption_blocks_new_storage_reservations_before_a_volume_is_pinned() {
    let db = TestDb::migrated().await;
    configure(&db, Some(1000), Some(1000), Some(1000)).await;
    let c = Context::new(&db).await;
    let mut owner = connect(&db.0, OWNER).await;
    let doc = new_uuid(&db).await;
    let mut api = connect(&db.0, API).await;
    let input = ReservationInput {
        scope: &c.scope,
        actor: &c.actor,
        key: "fenced",
        artifact: &doc,
        max_bytes: 15,
        run: None,
        operation: None,
    };
    owner
        .execute("UPDATE openmettle.storage_volume_control SET adoption_run_id=gen_random_uuid()")
        .await
        .unwrap();
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let err = storage::reserve(&mut tx, &input).await.unwrap_err();
    assert!(
        matches!(err, Error::Database(sqlx::Error::Database(e)) if e.code().as_deref()==Some("OMQ03"))
    );
    tx.rollback().await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM openmettle.storage_reservations")
            .fetch_one(&mut owner)
            .await
            .unwrap(),
        0
    );
    owner
        .execute("UPDATE openmettle.storage_volume_control SET adoption_run_id=NULL")
        .await
        .unwrap();
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    storage::reserve(&mut tx, &input).await.unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn purge_advances_past_a_busy_payload_and_refuses_a_foreign_revision_alias() {
    use std::os::unix::fs::MetadataExt;
    let f = Fixture::new().await;
    let worker = pool(&f.db, WORKER).await;
    let mut api = connect(&f.db.0, API).await;
    let mut owner = connect(&f.db.0, OWNER).await;
    let body = form("x", &[METADATA, file(None, b"payload")], true);
    let mut paths = Vec::new();
    for (index, key) in ["busy", "due"].into_iter().enumerate() {
        let doc = new_uuid(&f.db).await;
        let stored = f
            .upload(key, &doc, 100, "x", chunked(&body, 16), true)
            .await
            .unwrap();
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        storage::retain_revision(&mut tx, &f.c.scope, &stored.revision)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        sqlx::query(
            "UPDATE openmettle.artifact_revisions SET retained_at=now()-interval '1 day',
            purge_after=now()-interval '1 hour'+$2*interval '1 minute' WHERE id=$1::uuid",
        )
        .bind(&stored.revision)
        .bind(index as f64)
        .execute(&mut owner)
        .await
        .unwrap();
        paths.push(f.root.join("revisions").join(stored.reservation));
    }
    let busy = fs::File::open(&paths[0]).unwrap();
    busy.try_lock_shared().unwrap();
    assert!(matches!(
        artifact_fs::purge_due(&worker, &f.store, 1).await,
        Err(artifact_fs::Error::InProgress)
    ));
    assert_eq!(
        artifact_fs::purge_due(&worker, &f.store, 1).await.unwrap(),
        1
    );
    assert!(!paths[1].exists());
    let ino = busy.metadata().unwrap().ino();
    drop(busy);
    let id = paths[0].file_name().unwrap().to_str().unwrap();
    let anchor = paths[0].with_file_name(format!(".purge.{id}"));
    fs::rename(&paths[0], &anchor).unwrap();
    fs::write(&paths[0], b"foreign").unwrap();
    assert_ne!(fs::metadata(&paths[0]).unwrap().ino(), ino);
    assert!(artifact_fs::purge_due(&worker, &f.store, 1).await.is_err());
    assert_eq!(fs::read(&paths[0]).unwrap(), b"foreign");
    assert_eq!(fs::read(anchor).unwrap(), b"payload");
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 7, 0));
    // Only the purged revision is journaled; the refused one keeps its charge and no record.
    assert_eq!(journaled(&f.db).await.len(), 1);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn drift_counts_an_unbound_revision_and_a_nonregular_orphan() {
    let f = Fixture::new().await;
    let doc = new_uuid(&f.db).await;
    let id = f.reserve("unbound", &doc, 10).await;
    fs::write(f.root.join("revisions").join(id), b"x").unwrap();
    let orphan = new_uuid(&f.db).await;
    std::os::unix::fs::symlink("missing", f.root.join("staging").join(orphan)).unwrap();
    let report = artifact_fs::verify_accounting_drift(&pool(&f.db, WORKER).await, Some(&f.store))
        .await
        .unwrap();
    assert_eq!(report.files, 2);
    assert_eq!(report.unsettled_payloads, 0);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn reclaim_rechecks_a_publication_alias_created_after_its_initial_probe() {
    use std::os::unix::fs::MetadataExt;
    let f = Fixture::new().await;
    let doc = new_uuid(&f.db).await;
    let id = f.reserve("publishing", &doc, 10).await;
    let staged = f.root.join("staging").join(&id);
    let revision = f.root.join("revisions").join(&id);
    fs::write(&staged, b"payload").unwrap();
    let mut owner = connect(&f.db.0, OWNER).await;
    sqlx::query("UPDATE openmettle.storage_reservations SET stage_claimed=true,payload_ino=$2::text::numeric,
        created_at=now()-interval '2 hours',lease_expires_at=now()-interval '1 hour' WHERE id=$1::uuid")
        .bind(&id).bind(fs::metadata(&staged).unwrap().ino().to_string()).execute(&mut owner).await.unwrap();
    // Stop the cleaner at renewal, after it selected the staging name but before it can truncate.
    owner
        .execute(
            "CREATE FUNCTION openmettle.test_pause_renew() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN PERFORM pg_advisory_xact_lock(47121); RETURN NEW; END $$;
        CREATE TRIGGER pause_renew BEFORE UPDATE ON openmettle.storage_reservations
        FOR EACH ROW WHEN (OLD.reclaim_state='claiming' AND NEW.reclaim_state='claiming')
        EXECUTE FUNCTION openmettle.test_pause_renew()",
        )
        .await
        .unwrap();
    let mut barrier = owner.begin().await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid() FROM pg_advisory_xact_lock(47121)")
        .fetch_one(&mut *barrier)
        .await
        .unwrap();
    let worker = pool(&f.db, WORKER).await;
    let sweep = artifact_fs::reconcile_expired(&worker, &f.store, Duration::ZERO, 10);
    let publish = async {
        wait_for_blocked_peer(&f.db, pid).await;
        fs::hard_link(&staged, &revision).unwrap();
        barrier.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(sweep, publish);
    assert_eq!(result.unwrap(), 1);
    assert!(!revision.exists() && !staged.exists());
    assert_eq!(f.state("publishing").await.as_deref(), Some("released"));
    assert_totals(&f.db).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn staging_sweep_drains_aged_orphans_and_skips_a_locked_reservation() {
    use std::time::SystemTime;
    let f = Fixture::new().await;
    let dir = f.root.join("staging");
    let doc = new_uuid(&f.db).await;
    let id = f.reserve("locked-stage", &doc, 10).await;
    let aged = SystemTime::now() - Duration::from_secs(1800);
    for name in [&id[..], "orphan-a", "orphan-b"] {
        let file = fs::File::create_new(dir.join(name)).unwrap();
        file.set_modified(aged).unwrap();
    }
    std::os::unix::fs::symlink("missing", dir.join("malformed")).unwrap();
    let mut owner = connect(&f.db.0, OWNER).await;
    let mut lock = owner.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.storage_reservations WHERE id=$1::uuid FOR UPDATE")
        .bind(&id)
        .execute(&mut *lock)
        .await
        .unwrap();
    let worker = pool(&f.db, WORKER).await;
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        artifact_fs::reconcile_expired(&worker, &f.store, Duration::from_secs(900), 50),
    )
    .await
    .expect("sweep blocked on an active writer");
    assert!(result.is_err(), "the nonregular entry must be reported");
    assert!(!dir.join("orphan-a").exists() && !dir.join("orphan-b").exists());
    assert!(dir.join(id).is_file());
    lock.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn locked_adoption_discards_a_transient_pre_scan_digest_mismatch() {
    use artifact_fs::adoption::{Options, adopt};
    let f = Fixture::new().await;
    let doc = new_uuid(&f.db).await;
    let body = form("x", &[METADATA, file(None, b"original")], true);
    let stored = f
        .upload("repair", &doc, 100, "x", chunked(&body, 16), true)
        .await
        .unwrap();
    let path = f.root.join("revisions").join(&stored.reservation);
    fs::write(&path, b"incomplete").unwrap();
    let mut owner = connect(&f.db.0, OWNER).await;
    let mut fixture = f.db.admin().await;
    let mut barrier = fixture.begin().await.unwrap();
    let pid: i32 = sqlx::query_scalar(
        "SELECT pg_backend_pid() FROM openmettle.artifact_revisions
        WHERE id=$1::uuid FOR UPDATE",
    )
    .bind(&stored.revision)
    .fetch_one(&mut *barrier)
    .await
    .unwrap();
    let opts = Options {
        root: &f.root,
        replace: None,
        expected_fs: None,
        expected_directory: None,
        confirm_absent: false,
    };
    let repair = async {
        wait_for_blocked_peer(&f.db, pid).await;
        // Preserve the pinned inode and restore its contents between the two inventories.
        fs::write(&path, b"original").unwrap();
        barrier.commit().await.unwrap();
    };
    let (result, ()) = tokio::join!(adopt(&mut owner, &opts), repair);
    result.unwrap();
    assert_eq!(fs::read(path).unwrap(), b"original");
}

#[path = "artifact_rebind.rs"]
mod rebind;
