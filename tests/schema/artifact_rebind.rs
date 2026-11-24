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
    let mut cn = connect(&f.db.0, WORKER).await;
    let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
    storage::begin_purge(&mut tx, &f.c.scope, &truncated.revision)
        .await
        .unwrap();
    tx.commit().await.unwrap();
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
    store.initialize_api(&f.api).await.unwrap();
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
    assert!(
        !admin(&f.db, OWNER, &["quota", "verify", path])
            .status
            .success()
    );

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
    let mut api = connect(&f.db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let digest = Sha256::digest(b"unsettled payload");
    assert!(matches!(
        storage::settle(
            &mut tx,
            &Settlement {
                scope: &f.c.scope,
                reservation: &published,
                size_bytes: 17,
                content_digest: &digest,
                media_type: "text/plain",
                display_name: None,
            },
        )
        .await,
        Err(Error::Conflict)
    ));
    drop(tx);

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
async fn rebind_changes_nothing_on_the_original_volume_and_refuses_without_changes() {
    let f = Fixture::new().await;
    let settled = f.stored("settled", b"settled payload").await;
    let held = f.crashed("held", b"partial upload", false).await;
    let staged = f.root.join("staging").join(&held);
    let payload = f.root.join("revisions").join(&settled.reservation);
    let inodes = [
        bound(&f.db, &settled.reservation).await,
        bound(&f.db, &held).await,
    ];

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

    let unchanged = async |f: &Fixture| {
        assert_eq!(barrier(&f.db).await, None);
        assert_eq!(bound(&f.db, &settled.reservation).await, inodes[0]);
        assert_eq!(bound(&f.db, &held).await, inodes[1]);
        assert_eq!(fs::read(&staged).unwrap(), b"partial upload");
        assert_eq!(fs::read(&payload).unwrap(), b"settled payload");
    };
    // A volume that was not copied: the payload is verified, nothing is written, and an
    // in-flight upload whose file still matches is left to the reconciler with its bytes.
    for _ in 0..2 {
        let (ok, out, err) = rebind(&f.db, &f.root, &[]);
        assert!(ok, "{out}{err}");
        assert_eq!(
            out.trim(),
            "rebound 0, emptied 0, unchanged 2, quarantined 0, failed 0"
        );
        unchanged(&f).await;
    }

    let path = f.root.to_str().unwrap();
    let refused = |output: Output, reason: &str| {
        assert!(!output.status.success());
        let err = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(err.contains(reason), "{err}");
    };
    refused(
        admin(&f.db, API, &["storage", "rebind", path]),
        "owner login required",
    );
    unchanged(&f).await;
    // Another process still streams a payload.
    let reader = fs::File::open(&payload).unwrap();
    reader.lock_shared().unwrap();
    refused(
        admin(&f.db, OWNER, &["storage", "rebind", path]),
        "reservation in use",
    );
    drop(reader);
    unchanged(&f).await;
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
    unchanged(&f).await;
    refused(
        admin(&f.db, OWNER, &["storage", "rebind", path, "--unknown"]),
        "unknown rebind option",
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
