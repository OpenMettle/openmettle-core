//! ADR 0031: migration 17 and the filesystem artifact engine over isolated PostgreSQL 18 and a
//! per-test temporary directory. Every value is synthetic.
use super::storage::{account, assert_totals, configure, new_uuid};
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

async fn pool(db: &TestDb, role: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .connect(&db.url(role))
        .await
        .unwrap()
}

struct Fixture {
    db: TestDb,
    c: Context,
    api: PgPool,
    store: Store,
    root: PathBuf,
    _dir: Dir,
}

impl Fixture {
    async fn new() -> Self {
        let db = TestDb::migrated().await;
        configure(&db, Some(10_000), Some(10_000), Some(10_000)).await;
        let c = Context::new(&db).await;
        let api = pool(&db, API).await;
        let dir = Dir::new();
        let root = PathBuf::from(dir.path("artifacts"));
        fs::create_dir(&root).unwrap();
        let store = Store::open(&root).unwrap();
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

    fn files(&self, sub: &str) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.root.join(sub))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
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

    async fn reserve(&self, key: &str, artifact: &str, max: i64) -> String {
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
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let reserved = storage::reserve(
        &mut tx,
        &ReservationInput {
            scope: &c.scope,
            actor: &c.actor,
            key: "v16",
            artifact: &doc,
            max_bytes: 10,
            run: None,
            operation: None,
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let digest = Sha256::digest(b"v16").to_vec();
    sqlx::query(
        "INSERT INTO openmettle.artifacts (id, scope_id, scope_kind, owner_user_id)
         VALUES ($1::uuid, $2::uuid, 'personal', $3::uuid)",
    )
    .bind(&doc)
    .bind(&c.scope)
    .bind(&c.actor)
    .execute(&mut api)
    .await
    .unwrap();
    let old: String = sqlx::query_scalar(
        "INSERT INTO openmettle.artifact_revisions (scope_id, artifact_id, revision, reservation_id,
             size_bytes, content_digest, media_type, created_by_user_id)
         VALUES ($1::uuid, $2::uuid, 1, $3::uuid, 3, $4, 'text/plain', $5::uuid) RETURNING id::text",
    )
    .bind(&c.scope)
    .bind(&doc)
    .bind(&reserved.id)
    .bind(&digest)
    .bind(&c.actor)
    .fetch_one(&mut api)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.storage_reservations SET state = 'settled', settled_bytes = 3,
             closed_at = now() WHERE id = $1::uuid",
    )
    .bind(&reserved.id)
    .execute(&mut api)
    .await
    .unwrap();
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
                reservation: &reserved.id,
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
    // A recent reservation is not touched.
    let recent = |older_than| artifact_fs::reconcile_expired(&f.api, &f.store, older_than, 10);
    assert_eq!(recent(Duration::from_secs(3600)).await.unwrap(), 0);
    assert_eq!(account(&f.db, &f.c.scope).await, (0, 0, 200));
    assert!(matches!(
        artifact_fs::reconcile_expired(&f.api, &f.store, Duration::ZERO, 0).await,
        Err(artifact_fs::Error::Storage(Error::Invalid))
    ));
    // Bounded batches, oldest first.
    assert_eq!(recent(Duration::ZERO).await.unwrap(), 2);
    assert_eq!(f.state("held").await.as_deref(), Some("released"));
    assert_eq!(f.state("renamed").await.as_deref(), Some("released"));
    assert!(f.files("staging").is_empty() && f.files("revisions").is_empty());
    assert_eq!(recent(Duration::ZERO).await.unwrap(), 0);
    // A retry of a crashed upload whose reservation is still reserved replaces the leftover.
    let retried = f.reserve("retried", &doc, 100).await;
    fs::write(f.root.join("revisions").join(&retried), b"stale").unwrap();
    let stored = f
        .upload("retried", &doc, 100, "x", chunked(&body, 8), true)
        .await
        .unwrap();
    assert_eq!(stored.reservation, retried);
    assert_eq!(
        fs::read(f.root.join("revisions").join(&retried)).unwrap(),
        b"payload"
    );
    assert_eq!(account(&f.db, &f.c.scope).await, (7, 0, 0));
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
    assert_eq!(sweep().await.unwrap(), 1);
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
    storage::retain_revision(&mut tx, &f.c.scope, &stored.revision, 1)
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
        storage::retain_revision(&mut tx, &f.c.scope, &stored.revision, 1)
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
        while account(&f.db, &f.c.scope).await != (0, 7, 0) {
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

    signal(&process.0, "-TERM");
    assert!(process.0.wait().unwrap().success());
    let mut logs = String::new();
    process
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut logs)
        .unwrap();
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

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn worker_binary_sweeps_with_and_without_payloads_and_recovers_after_signals() {
    use std::os::unix::process::ExitStatusExt;
    let f = Fixture::new().await;
    let doc = new_uuid(&f.db).await;
    let old = f.reserve("abandoned", &doc, 100).await;
    let staged = f.root.join("staging").join(&old);
    fs::write(&staged, b"partial").unwrap();
    sqlx::query("UPDATE openmettle.storage_reservations SET created_at = now() - interval '901 seconds' WHERE id = $1::uuid")
        .bind(&old).execute(&mut f.db.admin().await).await.unwrap();
    let body = form("x", &[METADATA, file(None, b"retained")], true);
    let stored = f
        .upload("retained", &doc, 100, "x", chunked(&body, 16), true)
        .await
        .unwrap();
    let payload = f.root.join("revisions").join(&stored.reservation);
    let mut c = connect(&f.db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    storage::retain_revision(&mut tx, &f.c.scope, &stored.revision, 1)
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
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS (SELECT FROM pg_stat_activity WHERE datname = current_database() AND usename = 'openmettle_worker' AND wait_event_type = 'Lock' AND query LIKE '%WITH due AS MATERIALIZED%')")
                    .fetch_one(&mut f.db.admin().await).await.unwrap();
                if waiting { break }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }).await.unwrap();
        signal(&process.0, sig);
        lock.commit().await.unwrap();
        let status = process.0.wait().unwrap();
        if artifacts {
            assert_eq!(status.signal(), Some(9));
        } else {
            assert_eq!(status.code(), Some(0));
        }
    }
    let mut replacement = sweep_process(&f, true);
    assert_swept(&f, &ids).await;
    signal(&replacement.0, "-TERM");
    assert!(replacement.0.wait().unwrap().success());
    assert_eq!(f.state("abandoned").await.as_deref(), Some("released"));
    assert_totals(&f.db).await;
}
