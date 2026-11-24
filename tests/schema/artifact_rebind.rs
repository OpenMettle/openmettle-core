//! ADR 0040 amendment (24 Nov 2026): the owner-run rebind after a file-copy restore. Each test
//! copies a populated artifact tree with a real tool, so every inode number changes, and
//! drives the `openmettle-admin` binary against the copy. Every value is synthetic.
use super::*;
use http_body_util::BodyExt;
use std::{
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Command, Output},
};

fn run(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// Copy the artifact tree with a real tool. `None` when the tool is not installed.
fn copy_tree(tool: &str, from: &Path, dir: &Dir) -> Option<PathBuf> {
    let to = PathBuf::from(dir.path("restored"));
    match tool {
        "cp" => {
            run(Command::new("cp").arg("-a").arg(from).arg(&to));
        }
        "tar" => {
            let archive = dir.path("volume.tar");
            run(Command::new("tar")
                .arg("-C")
                .arg(from)
                .args(["-cf", &archive, "."]));
            fs::create_dir(&to).unwrap();
            run(Command::new("tar")
                .arg("-C")
                .arg(&to)
                .args(["-xpf", &archive]));
        }
        _ => {
            if Command::new("restic").arg("version").output().is_err() {
                return None;
            }
            let repository = dir.path("repository");
            let restic = |args: &[&str]| {
                let mut command = Command::new("restic");
                command
                    .env("RESTIC_PASSWORD", "synthetic")
                    .args(["--no-cache", "-r", &repository])
                    .args(args);
                run(&mut command);
            };
            restic(&["init"]);
            restic(&["backup", from.to_str().unwrap()]);
            let target = dir.path("restic-target");
            restic(&["restore", "latest", "--target", &target]);
            // restic restores the absolute source path below its target.
            let restored = Path::new(&target).join(from.strip_prefix("/").unwrap());
            fs::rename(restored, &to).unwrap();
        }
    }
    Some(to)
}

fn admin(db: &TestDb, role: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_openmettle-admin"))
        .env("OPENMETTLE_ADMIN_DATABASE_URL", db.url(role))
        .args(args)
        .output()
        .unwrap()
}

fn rebind(db: &TestDb, root: &Path, extra: &[&str]) -> (bool, String, String) {
    let mut args = vec!["storage", "rebind", root.to_str().unwrap()];
    args.extend_from_slice(extra);
    let output = admin(db, OWNER, &args);
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn ino(path: impl AsRef<Path>) -> String {
    fs::metadata(path).unwrap().ino().to_string()
}

async fn bound(db: &TestDb, reservation: &str) -> String {
    sqlx::query_scalar(
        "SELECT payload_ino::text FROM openmettle.storage_reservations WHERE id=$1::uuid",
    )
    .bind(reservation)
    .fetch_one(&mut db.admin().await)
    .await
    .unwrap()
}

async fn barrier(db: &TestDb) -> Option<String> {
    sqlx::query_scalar("SELECT adoption_run_id::text FROM openmettle.storage_volume_control")
        .fetch_one(&mut db.admin().await)
        .await
        .unwrap()
}

async fn read(
    store: &Store,
    s: &Stored,
    start: u64,
    len: u64,
) -> Result<Vec<u8>, artifact_fs::Error> {
    let content = store.read(&s.reservation, s.size_bytes, start, len).await?;
    Ok(content.collect().await.unwrap().to_bytes().to_vec())
}

impl Fixture {
    async fn stored(&self, key: &str, body: &[u8]) -> Stored {
        let doc = new_uuid(&self.db).await;
        let body = form("x", &[METADATA, file(None, body)], true);
        self.upload(key, &doc, 100, "x", chunked(&body, 16), true)
            .await
            .unwrap()
    }

    async fn retain(&self, s: &Stored) {
        let mut api = connect(&self.db.0, API).await;
        let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
        storage::retain_revision(&mut tx, &self.c.scope, &s.revision)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    /// An upload whose writer died: a claimed reservation bound to its staging file, and,
    /// when `published`, already linked under its revision name but never settled.
    async fn crashed(&self, key: &str, body: &[u8], published: bool) -> String {
        let doc = new_uuid(&self.db).await;
        let id = self.reserve(key, &doc, 100).await;
        let staged = self.root.join("staging").join(&id);
        fs::write(&staged, body).unwrap();
        if published {
            fs::hard_link(&staged, self.root.join("revisions").join(&id)).unwrap();
        }
        sqlx::query(
            "UPDATE openmettle.storage_reservations SET stage_claimed=true,
             payload_ino=$2::text::numeric,publish_pending=$3 WHERE id=$1::uuid",
        )
        .bind(&id)
        .bind(ino(&staged))
        .bind(published)
        .execute(&mut self.db.admin().await)
        .await
        .unwrap();
        id
    }

    /// Claim a retained, due revision for purge without touching its payload.
    async fn claim_purge(&self, s: &Stored) {
        let mut cn = connect(&self.db.0, WORKER).await;
        let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
        storage::begin_purge(&mut tx, &self.c.scope, &s.revision)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    async fn expire_reservations(&self) {
        self.db
            .admin()
            .await
            .execute(
                "UPDATE openmettle.storage_reservations SET created_at=now()-interval '901 seconds',
                 lease_expires_at=now()-interval '1 second' WHERE state='reserved'",
            )
            .await
            .unwrap();
    }
}

async fn reservation_row(db: &TestDb, id: &str) -> (String, bool, bool, i64) {
    sqlx::query_as(
        "SELECT s.state,s.publish_pending,s.adoption_unverified,
         (SELECT count(*) FROM openmettle.artifact_revisions r WHERE r.reservation_id=s.id)
         FROM openmettle.storage_reservations s WHERE s.id=$1::uuid",
    )
    .bind(id)
    .fetch_one(&mut db.admin().await)
    .await
    .unwrap()
}

/// The writer's own settlement of an emptied upload is refused.
async fn assert_cannot_settle(f: &Fixture, reservation: &str, body: &[u8]) {
    let mut api = connect(&f.db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let digest = Sha256::digest(body);
    assert!(matches!(
        storage::settle(
            &mut tx,
            &Settlement {
                scope: &f.c.scope,
                reservation,
                size_bytes: body.len() as i64,
                content_digest: &digest,
                media_type: "text/plain",
                display_name: None,
            },
        )
        .await,
        Err(Error::Conflict)
    ));
}

async fn revision_state(db: &TestDb, s: &Stored) -> String {
    sqlx::query_scalar("SELECT state FROM openmettle.artifact_revisions WHERE id=$1::uuid")
        .bind(&s.revision)
        .fetch_one(&mut db.admin().await)
        .await
        .unwrap()
}

/// Every state a recovery point can hold, copied with `tool` and rebound.
async fn recovers(tool: &str) {
    let f = Fixture::new().await;
    retention_grace(&f.db, 0).await;
    let worker = pool(&f.db, WORKER).await;

    // A released reservation whose reclaim anchor was never unlinked.
    let anchor = f.crashed("anchor", b"", false).await;
    f.expire_reservations().await;
    assert_eq!(
        artifact_fs::reconcile_expired(&worker, &f.store, Duration::ZERO, 10)
            .await
            .unwrap(),
        1
    );
    let reclaim = format!(".reclaim.{anchor}");
    fs::write(f.root.join("staging").join(&reclaim), b"").unwrap();
    sqlx::query(
        "UPDATE openmettle.storage_reservations SET reclaim_state='anchor_pending_unlink',
         payload_ino=$2::text::numeric WHERE id=$1::uuid",
    )
    .bind(&anchor)
    .bind(ino(f.root.join("staging").join(&reclaim)))
    .execute(&mut connect(&f.db.0, OWNER).await)
    .await
    .unwrap();

    // Two active revisions, one retained and due, and one whose purge truncated and
    // anchored the payload before the worker died.
    let first = f.stored("first", b"first payload").await;
    let second = f.stored("second", b"the second, longer payload").await;
    let retained = f.stored("retained", b"retained payload").await;
    f.retain(&retained).await;
    let truncated = f.stored("truncated", b"purging payload").await;
    f.retain(&truncated).await;
    f.claim_purge(&truncated).await;
    let purge = format!(".purge.{}", truncated.reservation);
    let payload = f.root.join("revisions").join(&truncated.reservation);
    fs::hard_link(&payload, f.root.join("revisions").join(&purge)).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&payload)
        .unwrap()
        .set_len(0)
        .unwrap();
    fs::remove_file(&payload).unwrap();

    // Uploads that were never acknowledged: one in flight, one published but not settled.
    let held = f.crashed("held", b"partial upload", false).await;
    let published = f.crashed("published", b"unsettled payload", true).await;
    let before = account(&f.db, &f.c.scope).await;

    let dir = Dir::new();
    let Some(root) = copy_tree(tool, &f.root, &dir) else {
        eprintln!("{tool} is not installed; the {tool} restore was not exercised");
        return;
    };
    let staging = root.join("staging");
    let revisions = root.join("revisions");
    // The copy carries the volume identity and every byte, under new inode numbers.
    let store = Store::open(&root).unwrap();
    assert!(matches!(
        store.initialize_api(&f.api).await,
        Err(artifact_fs::Error::Io)
    ));
    for s in [&first, &second, &retained] {
        assert_ne!(
            ino(revisions.join(&s.reservation)),
            bound(&f.db, &s.reservation).await
        );
        assert!(matches!(
            read(&store, s, 0, s.size_bytes as u64).await,
            Err(artifact_fs::Error::Io)
        ));
    }
    assert_eq!(
        ino(staging.join(&published)),
        ino(revisions.join(&published)),
        "{tool} did not preserve the hard link between the two names of one upload"
    );
    let path = root.to_str().unwrap();
    // The read-only check an operator may reach for first is refused too, and says why.
    let early = admin(&f.db, OWNER, &["quota", "verify", path]);
    assert!(!early.status.success());
    let early = String::from_utf8_lossy(&early.stderr).into_owned();
    assert!(early.contains("storage rebind"), "{early}");

    let (ok, out, err) = rebind(&f.db, &root, &[]);
    assert!(ok, "{out}{err}");
    assert_eq!(
        out.trim(),
        "rebound 7, emptied 2, unchanged 0, quarantined 0, failed 0"
    );
    assert_eq!(barrier(&f.db).await, None);

    // Settled payloads are bound to the copied files and read back byte for byte.
    for (s, body) in [
        (&first, &b"first payload"[..]),
        (&second, b"the second, longer payload"),
        (&retained, b"retained payload"),
    ] {
        assert_eq!(
            bound(&f.db, &s.reservation).await,
            ino(revisions.join(&s.reservation))
        );
        assert_eq!(read(&store, s, 0, body.len() as u64).await.unwrap(), body);
        assert_eq!(read(&store, s, 4, 5).await.unwrap(), &body[4..9]);
    }
    assert_eq!(
        bound(&f.db, &truncated.reservation).await,
        ino(revisions.join(&purge))
    );
    assert_eq!(bound(&f.db, &anchor).await, ino(staging.join(&reclaim)));

    // Nothing unsettled was acknowledged: both uploads are emptied, still reserved and
    // charged, and the writer's own settlement is refused.
    for id in [&held, &published] {
        assert_eq!(
            reservation_row(&f.db, id).await,
            ("reserved".into(), false, false, 0)
        );
        assert_eq!(fs::metadata(staging.join(id)).unwrap().len(), 0);
        assert_eq!(bound(&f.db, id).await, ino(staging.join(id)));
    }
    assert_eq!(fs::metadata(revisions.join(&published)).unwrap().len(), 0);
    assert_eq!(account(&f.db, &f.c.scope).await, before);
    assert_cannot_settle(&f, &published, b"unsettled payload").await;

    // The required post-restore check passes, and the reconciler and the purge finish
    // every state under their normal rules.
    let verified = admin(&f.db, OWNER, &["quota", "verify", path]);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stdout)
    );
    f.expire_reservations().await;
    assert_eq!(
        artifact_fs::reconcile_expired(&worker, &store, Duration::ZERO, 10)
            .await
            .unwrap(),
        2
    );
    for id in [&held, &published] {
        assert_eq!(reservation_row(&f.db, id).await.0, "released");
    }
    assert_eq!(
        artifact_fs::purge_due(&worker, &store, 10).await.unwrap(),
        2
    );
    let mut recorded = journaled(&f.db).await;
    recorded.sort();
    let mut expected = vec![retained.revision.clone(), truncated.revision.clone()];
    expected.sort();
    assert_eq!(recorded, expected);
    let mut left: Vec<String> = fs::read_dir(&revisions)
        .unwrap()
        .chain(fs::read_dir(&staging).unwrap())
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n != ".openmettle-volume-id")
        .collect();
    left.sort();
    let mut live = vec![first.reservation.clone(), second.reservation.clone()];
    live.sort();
    assert_eq!(left, live);
    assert!(
        admin(&f.db, OWNER, &["quota", "verify", path])
            .status
            .success()
    );
    assert_totals(&f.db).await;

    // A second run finds every payload bound and writes nothing.
    let (ok, out, _) = rebind(&f.db, &root, &[]);
    assert!(ok);
    assert_eq!(
        out.trim(),
        "rebound 0, emptied 0, unchanged 2, quarantined 0, failed 0"
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn rebind_recovers_a_cp_a_copy() {
    recovers("cp").await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn rebind_recovers_a_tar_round_trip() {
    recovers("tar").await;
}

/// Runs only where the `restic` binary is installed.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn rebind_recovers_a_restic_restore() {
    recovers("restic").await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn rebind_keeps_the_volume_closed_until_every_payload_verifies() {
    let f = Fixture::new().await;
    let good = f.stored("good", b"intact payload").await;
    let corrupt = f.stored("corrupt", b"original bytes").await;
    let missing = f.stored("missing", b"lost in the copy").await;
    let dir = Dir::new();
    let root = copy_tree("cp", &f.root, &dir).unwrap();
    let revisions = root.join("revisions");
    // Same length, other bytes; and a payload the copy never carried.
    fs::write(revisions.join(&corrupt.reservation), b"replaced bytes").unwrap();
    fs::remove_file(revisions.join(&missing.reservation)).unwrap();
    let stale = [
        bound(&f.db, &corrupt.reservation).await,
        bound(&f.db, &missing.reservation).await,
    ];

    let (ok, out, err) = rebind(&f.db, &root, &[]);
    assert!(!ok);
    assert!(out.contains("rebound 1, emptied 0, unchanged 0, quarantined 0, failed 2"));
    assert!(out.contains(&format!(
        "failed {}: size_or_digest_mismatch",
        corrupt.reservation
    )));
    assert!(out.contains(&format!("failed {}: missing revision", missing.reservation)));
    // The verified payload is kept; the others are untouched; the volume stays closed.
    let held = barrier(&f.db).await.unwrap();
    assert!(
        err.contains(&format!("--replace-adoption-run {held}")),
        "{err}"
    );
    assert_eq!(
        bound(&f.db, &good.reservation).await,
        ino(revisions.join(&good.reservation))
    );
    assert_eq!(bound(&f.db, &corrupt.reservation).await, stale[0]);
    assert_eq!(bound(&f.db, &missing.reservation).await, stale[1]);
    let store = Store::open(&root).unwrap();
    assert!(matches!(
        store.initialize_api(&f.api).await,
        Err(artifact_fs::Error::Io)
    ));
    assert!(matches!(
        read(&store, &good, 0, 14).await,
        Err(artifact_fs::Error::Io)
    ));

    // Only the run that names the held barrier may continue, and a refused run changes nothing.
    let (ok, _, err) = rebind(&f.db, &root, &[]);
    assert!(!ok);
    assert!(err.contains("adoption ownership mismatch"), "{err}");
    assert_eq!(barrier(&f.db).await.as_deref(), Some(held.as_str()));

    // Adoption cannot take the barrier away either: its refusal hands it back.
    let adopt = admin(
        &f.db,
        OWNER,
        &[
            "storage",
            "adopt",
            root.to_str().unwrap(),
            "--replace-adoption-run",
            &held,
        ],
    );
    assert!(!adopt.status.success());
    // Adoption is not behind the store's copy check: it inspected the copied files itself.
    let refusal = String::from_utf8_lossy(&adopt.stderr).into_owned();
    assert!(
        refusal.contains("OMQ03: intra_reservation_inode_mismatch")
            || refusal.contains("OMQ03: missing revision"),
        "{refusal}"
    );
    assert_eq!(barrier(&f.db).await.as_deref(), Some(held.as_str()));

    // Repairing one payload is not enough.
    fs::write(revisions.join(&corrupt.reservation), b"original bytes").unwrap();
    let (ok, out, err) = rebind(&f.db, &root, &["--replace-adoption-run", &held]);
    assert!(!ok);
    assert!(out.contains("rebound 1, emptied 0, unchanged 1, quarantined 0, failed 1"));
    let held = barrier(&f.db).await.unwrap();
    assert!(
        err.contains(&format!("--replace-adoption-run {held}")),
        "{err}"
    );

    fs::write(revisions.join(&missing.reservation), b"lost in the copy").unwrap();
    let (ok, out, err) = rebind(&f.db, &root, &["--replace-adoption-run", &held]);
    assert!(ok, "{out}{err}");
    assert!(out.contains("rebound 1, emptied 0, unchanged 2, quarantined 0, failed 0"));
    assert_eq!(barrier(&f.db).await, None);
    store.initialize_api(&f.api).await.unwrap();
    for (s, body) in [
        (&good, &b"intact payload"[..]),
        (&corrupt, b"original bytes"),
        (&missing, b"lost in the copy"),
    ] {
        assert_eq!(read(&store, s, 0, body.len() as u64).await.unwrap(), body);
    }
    let path = root.to_str().unwrap();
    assert!(
        admin(&f.db, OWNER, &["quota", "verify", path])
            .status
            .success()
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn rebind_on_a_volume_that_was_not_copied_keeps_settled_payloads_and_empties_uploads() {
    let f = Fixture::new().await;
    let settled = f.stored("settled", b"settled payload").await;
    let held = f.crashed("held", b"partial upload", false).await;
    let published = f.crashed("published", b"unsettled payload", true).await;
    let staging = f.root.join("staging");
    let payload = f.root.join("revisions").join(&settled.reservation);
    let ids = [&settled.reservation, &held, &published];
    let mut inodes = Vec::new();
    for id in ids {
        inodes.push(bound(&f.db, id).await);
    }

    // Every runtime role stays write-once.
    for role in [API, WORKER] {
        let refused = sqlx::query(
            "UPDATE openmettle.storage_reservations SET payload_ino=payload_ino+1 WHERE id=$1::uuid",
        )
        .bind(&held)
        .execute(&mut connect(&f.db.0, role).await)
        .await
        .unwrap_err();
        assert_eq!(
            refused.as_database_error().unwrap().code().as_deref(),
            Some("OMQ03")
        );
    }

    // A refused run changes neither a row nor a file, and hands the barrier back.
    let untouched = async || {
        assert_eq!(barrier(&f.db).await, None);
        for (id, inode) in ids.iter().zip(&inodes) {
            assert_eq!(&bound(&f.db, id).await, inode);
        }
        assert_eq!(fs::read(staging.join(&held)).unwrap(), b"partial upload");
        assert_eq!(
            fs::read(staging.join(&published)).unwrap(),
            b"unsettled payload"
        );
        assert!(reservation_row(&f.db, &published).await.1);
    };
    let path = f.root.to_str().unwrap();
    let refused = |output: Output, reason: &str| {
        assert!(!output.status.success());
        let err = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(err.contains(reason), "{err}");
        assert!(err.contains("nothing was changed"), "{err}");
    };
    refused(
        admin(&f.db, API, &["storage", "rebind", path]),
        "owner login required",
    );
    untouched().await;
    // Another process still streams a payload.
    let reader = fs::File::open(&payload).unwrap();
    reader.lock_shared().unwrap();
    refused(
        admin(&f.db, OWNER, &["storage", "rebind", path]),
        "reservation in use",
    );
    drop(reader);
    untouched().await;
    // A volume that was never adopted or pinned belongs to `storage adopt`.
    let mut owner = connect(&f.db.0, OWNER).await;
    let pin: String = sqlx::query_scalar(
        "UPDATE openmettle.storage_volume_control o SET volume_id=NULL FROM
         openmettle.storage_volume_control p WHERE o.id AND p.id RETURNING p.volume_id::text",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    refused(
        admin(&f.db, OWNER, &["storage", "rebind", path]),
        "volume is not pinned",
    );
    sqlx::query("UPDATE openmettle.storage_volume_control SET volume_id=$1::uuid WHERE id")
        .bind(&pin)
        .execute(&mut owner)
        .await
        .unwrap();
    untouched().await;
    let unknown = admin(&f.db, OWNER, &["storage", "rebind", path, "--unknown"]);
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("unknown rebind option"));
    untouched().await;

    // Rebind is a post-restore command. An inode number that still matches is no evidence:
    // the settled payload is verified and kept, and every interrupted upload is emptied.
    let (ok, out, err) = rebind(&f.db, &f.root, &[]);
    assert!(ok, "{out}{err}");
    assert_eq!(
        out.trim(),
        "rebound 0, emptied 2, unchanged 3, quarantined 0, failed 0"
    );
    assert_eq!(barrier(&f.db).await, None);
    for (id, inode) in ids.iter().zip(&inodes) {
        assert_eq!(&bound(&f.db, id).await, inode);
    }
    assert_eq!(fs::read(&payload).unwrap(), b"settled payload");
    for id in [&held, &published] {
        assert_eq!(fs::metadata(staging.join(id)).unwrap().len(), 0);
        assert_eq!(
            reservation_row(&f.db, id).await,
            ("reserved".into(), false, false, 0)
        );
    }
    assert_cannot_settle(&f, &published, b"unsettled payload").await;
    let (ok, out, _) = rebind(&f.db, &f.root, &[]);
    assert!(ok);
    assert_eq!(
        out.trim(),
        "rebound 0, emptied 0, unchanged 3, quarantined 0, failed 0"
    );
}

/// Make the ledger carry the copied file's inode number, as a copy onto a fresh filesystem
/// can do by chance.
async fn carry_copied_inode(db: &TestDb, reservation: &str, copied: &Path) {
    sqlx::query(
        "UPDATE openmettle.storage_reservations SET payload_ino=$2::text::numeric WHERE id=$1::uuid",
    )
    .bind(reservation)
    .bind(ino(copied))
    .execute(&mut db.admin().await)
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn rebind_takes_no_evidence_from_an_equal_inode_number() {
    let f = Fixture::new().await;
    retention_grace(&f.db, 0).await;
    let purging = f.stored("purging", b"purging payload").await;
    f.retain(&purging).await;
    f.claim_purge(&purging).await;
    let published = f.crashed("published", b"unsettled payload", true).await;
    let dir = Dir::new();
    let root = copy_tree("cp", &f.root, &dir).unwrap();
    let payload = root.join("revisions").join(&purging.reservation);
    let staged = root.join("staging").join(&published);
    // The copied payload has other bytes of the same length under the number the ledger holds.
    fs::write(&payload, b"damaged payload").unwrap();
    carry_copied_inode(&f.db, &purging.reservation, &payload).await;
    carry_copied_inode(&f.db, &published, &staged).await;

    let (ok, out, _) = rebind(&f.db, &root, &[]);
    assert!(!ok, "{out}");
    assert!(
        out.contains("rebound 0, emptied 1, unchanged 1, quarantined 0, failed 1"),
        "{out}"
    );
    assert!(out.contains(&format!(
        "failed {}: size_or_digest_mismatch",
        purging.reservation
    )));
    // The damaged payload is neither accepted nor purged, and the volume stays closed.
    let held = barrier(&f.db).await.unwrap();
    assert_eq!(fs::read(&payload).unwrap(), b"damaged payload");
    assert_eq!(revision_state(&f.db, &purging).await, "purging");
    // The unsettled upload is emptied although its number matched, and cannot be settled.
    assert_eq!(fs::metadata(&staged).unwrap().len(), 0);
    assert_eq!(
        reservation_row(&f.db, &published).await,
        ("reserved".into(), false, false, 0)
    );
    assert_cannot_settle(&f, &published, b"unsettled payload").await;

    fs::write(&payload, b"purging payload").unwrap();
    let (ok, out, err) = rebind(&f.db, &root, &["--replace-adoption-run", &held]);
    assert!(ok, "{out}{err}");
    assert_eq!(
        out.trim(),
        "rebound 0, emptied 0, unchanged 2, quarantined 0, failed 0"
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn rebind_keeps_the_barrier_when_it_fails_after_emptying_an_upload() {
    let f = Fixture::new().await;
    let held = f.crashed("held", b"partial upload", false).await;
    let dir = Dir::new();
    let root = copy_tree("cp", &f.root, &dir).unwrap();
    let staged = root.join("staging").join(&held);
    // The ledger write fails after the file was emptied.
    let mut admin_db = f.db.admin().await;
    for sql in [
        "CREATE FUNCTION openmettle.synthetic_refusal() RETURNS trigger LANGUAGE plpgsql
         AS $$ BEGIN RAISE EXCEPTION 'synthetic'; END $$",
        "CREATE TRIGGER synthetic_refusal BEFORE UPDATE OF payload_ino
         ON openmettle.storage_reservations FOR EACH ROW
         EXECUTE FUNCTION openmettle.synthetic_refusal()",
    ] {
        admin_db.execute(sql).await.unwrap();
    }
    let stale = bound(&f.db, &held).await;

    let (ok, _, err) = rebind(&f.db, &root, &[]);
    assert!(!ok);
    assert_eq!(fs::metadata(&staged).unwrap().len(), 0);
    assert_eq!(bound(&f.db, &held).await, stale);
    // A file was modified, so the volume stays closed and the run names its recovery value.
    let kept = barrier(&f.db).await.expect("the barrier was released");
    assert!(
        err.contains(&format!("--replace-adoption-run {kept}")),
        "{err}"
    );
    assert!(!err.contains("nothing was changed"), "{err}");

    admin_db
        .execute("DROP TRIGGER synthetic_refusal ON openmettle.storage_reservations")
        .await
        .unwrap();
    let (ok, out, err) = rebind(&f.db, &root, &["--replace-adoption-run", &kept]);
    assert!(ok, "{out}{err}");
    assert_eq!(
        out.trim(),
        "rebound 1, emptied 0, unchanged 0, quarantined 0, failed 0"
    );
    assert_eq!(barrier(&f.db).await, None);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn rebind_reports_a_layout_the_lifecycle_does_not_allow() {
    let f = Fixture::new().await;
    retention_grace(&f.db, 0).await;
    let purging = f.stored("purging", b"purging payload").await;
    f.retain(&purging).await;
    f.claim_purge(&purging).await;
    let dir = Dir::new();
    let root = copy_tree("cp", &f.root, &dir).unwrap();
    let payload = root.join("revisions").join(&purging.reservation);
    // A purge needs the published file or its anchor; an empty staging file is neither.
    fs::remove_file(&payload).unwrap();
    fs::write(root.join("staging").join(&purging.reservation), b"").unwrap();
    let stale = bound(&f.db, &purging.reservation).await;

    let (ok, out, _) = rebind(&f.db, &root, &[]);
    assert!(!ok, "{out}");
    assert!(
        out.contains(&format!("failed {}: missing revision", purging.reservation)),
        "{out}"
    );
    assert!(barrier(&f.db).await.is_some());
    assert_eq!(bound(&f.db, &purging.reservation).await, stale);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn rebind_keeps_the_barrier_for_a_file_mismatch_not_for_quarantine_or_accounting_drift() {
    let f = Fixture::new().await;
    let live = f.stored("live", b"live payload").await;
    // States the system tolerated before the backup: a quarantined reservation and a ledger
    // total that does not add up.
    let quarantined = f.crashed("quarantined", b"quarantined upload", false).await;
    let mut owner = connect(&f.db.0, OWNER).await;
    sqlx::query(
        "UPDATE openmettle.storage_reservations SET adoption_unverified=true WHERE id=$1::uuid",
    )
    .bind(&quarantined)
    .execute(&mut owner)
    .await
    .unwrap();
    owner
        .execute("UPDATE openmettle.storage_instance SET reserved_bytes=reserved_bytes+1")
        .await
        .unwrap();
    let dir = Dir::new();
    let root = copy_tree("cp", &f.root, &dir).unwrap();
    let staged = root.join("staging").join(&quarantined);
    let stale = bound(&f.db, &quarantined).await;
    // A file no reservation owns: every row verifies, and the volume still has a file
    // mismatch, which is rebind's to refuse.
    let orphan = root.join("revisions").join(new_uuid(&f.db).await);
    fs::write(&orphan, b"orphan").unwrap();

    let (ok, out, err) = rebind(&f.db, &root, &[]);
    assert!(!ok, "{out}");
    assert!(
        out.contains("rebound 1, emptied 0, unchanged 0, quarantined 1, failed 0"),
        "{out}"
    );
    assert!(out.contains("file mismatches 1"), "{out}");
    let kept = barrier(&f.db).await.expect("the barrier was released");
    assert!(
        err.contains(&format!("--replace-adoption-run {kept}")),
        "{err}"
    );
    // The verified row is kept.
    assert_eq!(
        bound(&f.db, &live.reservation).await,
        ino(root.join("revisions").join(&live.reservation))
    );

    // Without the file mismatch the volume opens. The quarantine and the accounting drift
    // are reported, left exactly as they were, and do not fail the run.
    fs::remove_file(&orphan).unwrap();
    let (ok, out, err) = rebind(&f.db, &root, &["--replace-adoption-run", &kept]);
    assert!(ok, "{out}{err}");
    assert!(
        out.contains("rebound 0, emptied 0, unchanged 1, quarantined 1, failed 0"),
        "{out}"
    );
    assert!(
        out.contains(&format!("quarantined {quarantined}: left unchanged")),
        "{out}"
    );
    assert!(
        out.contains("storage mismatches 1,") && out.contains("file mismatches 0, quarantined 1"),
        "{out}"
    );
    assert_eq!(barrier(&f.db).await, None);
    assert_eq!(fs::read(&staged).unwrap(), b"quarantined upload");
    assert_eq!(bound(&f.db, &quarantined).await, stale);
    assert_eq!(
        reservation_row(&f.db, &quarantined).await,
        ("reserved".into(), false, true, 0)
    );
    // The store serves the volume, and the drift check stays unhealthy for the same reasons
    // as before the backup.
    let store = Store::open(&root).unwrap();
    store.initialize_api(&f.api).await.unwrap();
    assert_eq!(read(&store, &live, 0, 12).await.unwrap(), b"live payload");
    let path = root.to_str().unwrap();
    assert!(
        !admin(&f.db, OWNER, &["quota", "verify", path])
            .status
            .success()
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn rebind_reports_a_payload_it_cannot_open_as_a_row_failure() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new().await;
    let open = f.stored("open", b"readable payload").await;
    let closed = f.stored("closed", b"restored with a wrong mode").await;
    let dir = Dir::new();
    let root = copy_tree("cp", &f.root, &dir).unwrap();
    let payload = root.join("revisions").join(&closed.reservation);
    let mode = |mode| fs::set_permissions(&payload, fs::Permissions::from_mode(mode)).unwrap();
    mode(0o000);
    if fs::OpenOptions::new().read(true).open(&payload).is_ok() {
        eprintln!("running as root: an inaccessible payload cannot be simulated; not exercised");
        return;
    }

    let (ok, out, _) = rebind(&f.db, &root, &[]);
    assert!(!ok, "{out}");
    assert!(
        out.contains("rebound 1, emptied 0, unchanged 0, quarantined 0, failed 1"),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "failed {}: payload is not accessible",
            closed.reservation
        )),
        "{out}"
    );
    assert_eq!(
        bound(&f.db, &open.reservation).await,
        ino(root.join("revisions").join(&open.reservation))
    );
    let kept = barrier(&f.db).await.unwrap();

    mode(0o600);
    let (ok, out, err) = rebind(&f.db, &root, &["--replace-adoption-run", &kept]);
    assert!(ok, "{out}{err}");
    assert_eq!(barrier(&f.db).await, None);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn rebind_holds_a_bounded_number_of_descriptors() {
    let f = Fixture::new().await;
    for n in 0..80 {
        f.crashed(&format!("held-{n}"), b"partial upload", false)
            .await;
    }
    let dir = Dir::new();
    let root = copy_tree("cp", &f.root, &dir).unwrap();
    // More interrupted uploads than the process may hold open files.
    let output = Command::new("sh")
        .args(["-c", "ulimit -n 64 && exec \"$@\"", "sh"])
        .arg(env!("CARGO_BIN_EXE_openmettle-admin"))
        .env("OPENMETTLE_ADMIN_DATABASE_URL", f.db.url(OWNER))
        .args(["storage", "rebind", root.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "rebound 80, emptied 80, unchanged 0, quarantined 0, failed 0"
    );
    assert_eq!(barrier(&f.db).await, None);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_store_does_no_artifact_work_on_a_copied_volume_until_the_copy_check_passes() {
    let f = Fixture::new().await;
    retention_grace(&f.db, 0).await;
    let _live = f.stored("live", b"live payload").await;
    let retained = f.stored("retained", b"retained payload").await;
    f.retain(&retained).await;
    let held = f.crashed("held", b"partial upload", false).await;
    f.expire_reservations().await;
    let dir = Dir::new();
    let root = copy_tree("cp", &f.root, &dir).unwrap();
    // A process whose start-up check could not complete (a database timeout) holds a store
    // that was never verified. Its first sweeps must not touch the ledger.
    let store = Store::open(&root).unwrap();
    let worker = pool(&f.db, WORKER).await;
    for _ in 0..2 {
        assert!(matches!(
            artifact_fs::reconcile_expired(&worker, &store, Duration::ZERO, 10).await,
            Err(artifact_fs::Error::Io)
        ));
        assert!(matches!(
            artifact_fs::purge_due(&worker, &store, 10).await,
            Err(artifact_fs::Error::Io)
        ));
        assert_eq!(
            reservation_row(&f.db, &held).await,
            ("reserved".into(), false, false, 0)
        );
        assert_eq!(revision_state(&f.db, &retained).await, "retained");
    }

    let (ok, out, err) = rebind(&f.db, &root, &[]);
    assert!(ok, "{out}{err}");
    // The same store now passes the check on its next operation and works normally.
    assert_eq!(
        artifact_fs::reconcile_expired(&worker, &store, Duration::ZERO, 10)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        artifact_fs::purge_due(&worker, &store, 10).await.unwrap(),
        1
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn rebind_never_empties_a_file_that_another_name_shares() {
    let f = Fixture::new().await;
    let settled = f.stored("settled", b"settled payload").await;
    let alias = f.crashed("alias", b"aliased upload", false).await;
    let foreign = f.crashed("foreign", b"linked elsewhere", false).await;
    let split = f.crashed("split", b"split upload", true).await;
    let dir = Dir::new();
    let root = copy_tree("cp", &f.root, &dir).unwrap();
    let staging = root.join("staging");
    let revisions = root.join("revisions");
    // The staging name of one upload is a hard link to another reservation's payload.
    fs::remove_file(staging.join(&alias)).unwrap();
    fs::hard_link(revisions.join(&settled.reservation), staging.join(&alias)).unwrap();
    // A payload with a link outside the names its reservation owns.
    fs::hard_link(staging.join(&foreign), root.join("kept-elsewhere")).unwrap();
    // A copy that did not preserve hard links: two names, two files.
    fs::remove_file(revisions.join(&split)).unwrap();
    fs::write(revisions.join(&split), b"split upload").unwrap();

    let (ok, out, _) = rebind(&f.db, &root, &[]);
    assert!(!ok);
    assert!(
        out.contains("rebound 0, emptied 0, unchanged 0, quarantined 0, failed 4"),
        "{out}"
    );
    for (id, reason) in [
        (&settled.reservation, "cross_reservation_inode_alias"),
        (&alias, "cross_reservation_inode_alias"),
        (&foreign, "foreign hard link"),
        (&split, "intra_reservation_inode_mismatch"),
    ] {
        assert!(out.contains(&format!("failed {id}: {reason}")), "{out}");
    }
    assert!(barrier(&f.db).await.is_some());
    assert_eq!(
        fs::read(revisions.join(&settled.reservation)).unwrap(),
        b"settled payload"
    );
    assert_eq!(
        fs::read(root.join("kept-elsewhere")).unwrap(),
        b"linked elsewhere"
    );
    assert_eq!(fs::read(staging.join(&split)).unwrap(), b"split upload");
    assert_eq!(fs::read(revisions.join(&split)).unwrap(), b"split upload");
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_worker_refuses_a_copied_volume_until_rebind_has_run() {
    let f = Fixture::new().await;
    retention_grace(&f.db, 0).await;
    let live = f.stored("live", b"live payload").await;
    let retained = f.stored("retained", b"retained payload").await;
    f.retain(&retained).await;
    let held = f.crashed("held", b"partial upload", false).await;
    f.expire_reservations().await;
    let dir = Dir::new();
    let root = copy_tree("cp", &f.root, &dir).unwrap();
    let worker = |root: &Path| {
        let mut command = binary("worker");
        command
            .env("OPENMETTLE_WORKER_BIND", address())
            .env("OPENMETTLE_WORKER_DATABASE_URL", f.db.url(WORKER))
            .env("OPENMETTLE_WORKER_SWEEP_MS", "1000")
            .env("OPENMETTLE_WORKER_ARTIFACTS_DIR", root);
        Process(command.spawn().unwrap())
    };
    // Started before rebind, the worker exits instead of sweeping: its reconciler would
    // quarantine the crashed upload and its purge would claim the retained revision.
    let mut early = worker(&root);
    let status = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = early.0.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the worker started on a copied volume");
    assert_eq!(status.code(), Some(78));
    let mut refusal = String::new();
    std::io::Read::read_to_string(early.0.stderr.as_mut().unwrap(), &mut refusal).unwrap();
    assert!(refusal.contains("invalid ARTIFACTS_DIR"), "{refusal}");
    assert!(
        refusal.contains("openmettle-admin storage rebind"),
        "{refusal}"
    );
    assert_eq!(
        reservation_row(&f.db, &held).await,
        ("reserved".into(), false, false, 0)
    );
    assert_eq!(revision_state(&f.db, &retained).await, "retained");

    let (ok, out, err) = rebind(&f.db, &root, &[]);
    assert!(ok, "{out}{err}");
    // A reservation quarantined for an unrelated reason names no published payload and does
    // not keep a healthy store from starting.
    let quarantined = f.crashed("quarantined", b"unrelated", false).await;
    sqlx::query(
        "UPDATE openmettle.storage_reservations SET adoption_unverified=true WHERE id=$1::uuid",
    )
    .bind(&quarantined)
    .execute(&mut f.db.admin().await)
    .await
    .unwrap();
    let started = worker(&root);
    tokio::time::timeout(Duration::from_secs(15), async {
        while reservation_row(&f.db, &held).await.0 != "released"
            || revision_state(&f.db, &retained).await != "purged"
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the worker did not sweep the rebound volume");
    let mut started = started;
    signal(&started.0, "-TERM");
    assert!(started.0.wait().unwrap().success());
    let store = Store::open(&root).unwrap();
    store.initialize_api(&f.api).await.unwrap();
    assert_eq!(read(&store, &live, 0, 12).await.unwrap(), b"live payload");
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn the_copy_check_does_not_pass_on_a_probe_that_failed() {
    let f = Fixture::new().await;
    let live = f.stored("live", b"live payload").await;
    let payload = f.root.join("revisions").join(&live.reservation);
    let aside = f.root.join("aside");
    // The one sampled payload cannot be probed: its name is not a regular file.
    fs::rename(&payload, &aside).unwrap();
    std::os::unix::fs::symlink("missing", &payload).unwrap();
    let store = Store::open(&f.root).unwrap();
    assert!(matches!(
        store.initialize_api(&f.api).await,
        Err(artifact_fs::Error::Io)
    ));
    assert!(!store.awaits_rebind());
    // The failed probe decided nothing: a copy under the name is still detected.
    fs::remove_file(&payload).unwrap();
    fs::copy(&aside, &payload).unwrap();
    assert!(matches!(
        store.initialize_api(&f.api).await,
        Err(artifact_fs::Error::Io)
    ));
    assert!(store.awaits_rebind());
    fs::rename(&aside, &payload).unwrap();
    store.initialize_api(&f.api).await.unwrap();
    assert!(!store.awaits_rebind());
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn rebind_warns_about_an_unbound_staged_file_and_leaves_it_to_the_reconciler() {
    let f = Fixture::new().await;
    let _live = f.stored("live", b"live payload").await;
    // A reservation that never recorded an inode, with bytes under its staging name.
    let doc = new_uuid(&f.db).await;
    let unbound = f.reserve("unbound", &doc, 100).await;
    fs::write(f.root.join("staging").join(&unbound), b"never bound").unwrap();
    let dir = Dir::new();
    let root = copy_tree("cp", &f.root, &dir).unwrap();
    let staged = root.join("staging").join(&unbound);

    let (ok, out, err) = rebind(&f.db, &root, &[]);
    assert!(ok, "{out}{err}");
    assert!(
        out.contains("rebound 1, emptied 0, unchanged 0, quarantined 0, failed 0"),
        "{out}"
    );
    assert!(
        out.contains(&format!(
            "warning {unbound}: unbound reservation with a staged file; left unchanged, the reconciler will quarantine it"
        )),
        "{out}"
    );
    assert_eq!(barrier(&f.db).await, None);
    assert_eq!(fs::read(&staged).unwrap(), b"never bound");
    let recorded: Option<String> = sqlx::query_scalar(
        "SELECT payload_ino::text FROM openmettle.storage_reservations WHERE id=$1::uuid",
    )
    .bind(&unbound)
    .fetch_one(&mut f.db.admin().await)
    .await
    .unwrap();
    assert_eq!(recorded, None);

    // The running system's own answer: the reconciler quarantines it and touches no byte.
    f.expire_reservations().await;
    let store = Store::open(&root).unwrap();
    let worker = pool(&f.db, WORKER).await;
    assert!(matches!(
        artifact_fs::reconcile_expired(&worker, &store, Duration::ZERO, 10).await,
        Err(artifact_fs::Error::Io)
    ));
    assert_eq!(
        reservation_row(&f.db, &unbound).await,
        ("reserved".into(), false, true, 0)
    );
    assert_eq!(fs::read(&staged).unwrap(), b"never bound");
}

/// Fail every commit that updated `table`, after the statements themselves succeeded.
async fn fail_commits_on(db: &TestDb, table: &str) {
    let mut admin_db = db.admin().await;
    for sql in [
        "CREATE FUNCTION openmettle.synthetic_refusal() RETURNS trigger LANGUAGE plpgsql
         AS $$ BEGIN RAISE EXCEPTION 'synthetic'; END $$"
            .to_owned(),
        format!(
            "CREATE CONSTRAINT TRIGGER synthetic_commit AFTER UPDATE ON openmettle.{table}
             DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
             EXECUTE FUNCTION openmettle.synthetic_refusal()"
        ),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(&mut admin_db)
            .await
            .unwrap();
    }
}

const READ_BARRIER: &str = "SELECT adoption_run_id FROM openmettle.storage_volume_control";

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn rebind_does_not_claim_a_barrier_state_after_a_failed_acquisition_commit() {
    let f = Fixture::new().await;
    let _live = f.stored("live", b"live payload").await;
    fail_commits_on(&f.db, "storage_volume_control").await;

    let (ok, _, err) = rebind(&f.db, &f.root, &[]);
    assert!(!ok);
    assert!(err.contains("OMQ03: commit outcome unknown"), "{err}");
    assert!(err.contains(READ_BARRIER), "{err}");
    assert!(!err.contains("nothing was changed"), "{err}");
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn rebind_does_not_claim_a_barrier_state_after_a_failed_final_commit() {
    let f = Fixture::new().await;
    let held = f.crashed("held", b"partial upload", false).await;
    let dir = Dir::new();
    let root = copy_tree("cp", &f.root, &dir).unwrap();
    fail_commits_on(&f.db, "storage_reservations").await;

    let (ok, _, err) = rebind(&f.db, &root, &[]);
    assert!(!ok);
    // The upload is emptied and the commit's outcome is not known to the command. It names
    // the value it used and how to read the real one, and promises neither state.
    assert_eq!(
        fs::metadata(root.join("staging").join(&held))
            .unwrap()
            .len(),
        0
    );
    let attempted = barrier(&f.db).await.unwrap();
    assert!(err.contains("OMQ03: commit outcome unknown"), "{err}");
    assert!(err.contains(&attempted), "{err}");
    assert!(err.contains(READ_BARRIER), "{err}");
    assert!(!err.contains("the volume stays closed"), "{err}");

    f.db.admin()
        .await
        .execute("DROP TRIGGER synthetic_commit ON openmettle.storage_reservations")
        .await
        .unwrap();
    let (ok, out, err) = rebind(&f.db, &root, &["--replace-adoption-run", &attempted]);
    assert!(ok, "{out}{err}");
    assert_eq!(barrier(&f.db).await, None);
}
