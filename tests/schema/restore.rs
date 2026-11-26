//! ADR 0041 PR2b: the restore reconciliation gate, deletion journal export/replay, pinned
//! checkpoints, exclusive volume-phase leasing, unsettled upload scrub, audited coverage-gap
//! break-glass, and `storage rebind` integration on PostgreSQL 18. A restore is simulated inside
//! PostgreSQL: `CREATE DATABASE ... TEMPLATE live` copies the live database's committed state
//! once no session is connected to it, and that copy is the backup. The live database then purges
//! more revisions; "restoring" means pointing the owner, the worker and the store at the copy.
//! For file-copy restore coverage, `tar` copies the volume so every inode changes. No backup
//! tool, dump, WAL archive or volume snapshot is exercised. Identities and payloads are synthetic.
use super::artifact_fs::{Fixture, pool};
use super::retention::{Step, assert_chain, step};
use super::storage::{
    account, assert_totals, code, configure, input, new_uuid, reserve, retention_grace, settle,
};
use super::*;
use crate::auth_config_support::Dir;
use openmettle_core::{
    artifact_fs::{self, Store},
    restore::{self, Export, GENESIS},
};
use sqlx::PgPool;
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

/// The backup: a copy of `db`'s committed state. No session may be connected to `db`. A copy
/// does not carry database-level privileges, so they are restored as migrations 1, 18 and 23 set
/// them, as a real restore must also do.
async fn backup(db: &TestDb) -> TestDb {
    let copy = TestDb::with_options(false, &format!("TEMPLATE {}", db.0)).await;
    let roles = "openmettle_api, openmettle_worker, openmettle_issuance, openmettle_gateway";
    for sql in [
        format!("REVOKE ALL ON DATABASE {} FROM PUBLIC", copy.0),
        format!("GRANT CONNECT ON DATABASE {} TO {roles}", copy.0),
    ] {
        copy.admin()
            .await
            .execute(AssertSqlSafe(sql))
            .await
            .unwrap();
    }
    copy
}

fn cli(db: &TestDb, args: &[&str]) -> (bool, String, String) {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_openmettle-admin"));
    cmd.env("OPENMETTLE_ADMIN_DATABASE_URL", db.url(OWNER))
        .args(args);
    let out = run_cli(&mut cmd, &format!("openmettle-admin {args:?}"));
    let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
    (out.status.success(), text(out.stdout), text(out.stderr))
}

async fn sleep_past_grace() {
    tokio::time::sleep(Duration::from_millis(1100)).await;
}

async fn pid(c: &mut PgConnection) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(c)
        .await
        .unwrap()
}

async fn origin_of(db: &TestDb) -> i64 {
    sqlx::query_scalar(
        "SELECT (extract(epoch FROM coverage_started_at) * 1000000)::bigint
           FROM openmettle.deletion_journal_head WHERE id",
    )
    .fetch_one(&mut db.admin().await)
    .await
    .unwrap()
}

async fn lifecycle_origin_of(db: &TestDb) -> Option<i64> {
    sqlx::query_scalar(
        "SELECT (extract(epoch FROM lifecycle_coverage_started_at) * 1000000)::bigint
           FROM openmettle.deletion_journal_head WHERE id",
    )
    .fetch_one(&mut db.admin().await)
    .await
    .unwrap()
}

async fn state(db: &TestDb, rev: &str) -> (String, Option<String>) {
    sqlx::query_as(
        "SELECT state, purge_after::text FROM openmettle.artifact_revisions WHERE id = $1::uuid",
    )
    .bind(rev)
    .fetch_one(&mut db.admin().await)
    .await
    .unwrap()
}

/// Every journal row as text, in order.
async fn journal(db: &TestDb) -> Vec<String> {
    sqlx::query_scalar("SELECT j::text FROM openmettle.deletion_journal j ORDER BY journal_seq")
        .fetch_all(&mut db.admin().await)
        .await
        .unwrap()
}

async fn gate(db: &TestDb) -> (bool, Option<i64>, Option<i64>, Option<String>, bool) {
    sqlx::query_as(
        "SELECT open, snapshot_journal_seq, required_journal_seq,
                encode(required_chain_digest, 'hex'), coverage_complete
           FROM openmettle.restore_reconciliation_gate",
    )
    .fetch_one(&mut db.admin().await)
    .await
    .unwrap()
}

async fn restore_run_id_of(db: &TestDb) -> Option<String> {
    sqlx::query_scalar("SELECT restore_run_id::text FROM openmettle.restore_reconciliation_gate")
        .fetch_one(&mut db.admin().await)
        .await
        .unwrap()
}

fn sqlstate_of(error: restore::Error) -> String {
    match error {
        restore::Error::Database(sqlx::Error::Database(e)) => {
            e.code().unwrap_or_default().into_owned()
        }
        other => panic!("expected a database refusal, got {other:?}"),
    }
}

/// The volume phase as `openmettle-admin` runs it, with a store for the restored database.
async fn replay(owner: &PgPool, store: &Store, text: &str) -> Result<(), restore::Error> {
    let export = Export::parse(text)?;
    restore::apply(owner, &export).await?;
    restore::finish(owner, Some(store), &export).await
}

fn reseal(lines: &[String]) -> String {
    let body: String = lines.iter().map(|l| format!("{l}\n")).collect();
    let sum: String = Sha256::digest(body.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{body}sha256 {sum}\n")
}

/// Copy an artifact tree via `tar`, giving every file a fresh inode while preserving hard links.
fn tar_copy(from: &Path, dir: &Dir, name: &str) -> PathBuf {
    let archive = dir.path(&format!("{name}.tar"));
    let to = PathBuf::from(dir.path(name));
    let mut create = std::process::Command::new("tar");
    create.arg("-C").arg(from).args(["-cf", &archive, "."]);
    let out = run_cli(&mut create, "tar create artifact copy");
    assert!(out.status.success(), "{}", stderr(&out));
    fs::create_dir(&to).unwrap();
    let mut extract = std::process::Command::new("tar");
    extract.arg("-C").arg(&to).args(["-xpf", &archive]);
    let out = run_cli(&mut extract, "tar extract artifact copy");
    assert!(out.status.success(), "{}", stderr(&out));
    to
}

/// An unsettled upload captured mid-publication: bound `staging/<id>` hard-linked to
/// `revisions/<id>` with `publish_pending = true` and secret bytes on disk.
async fn seed_unsettled_upload(f: &Fixture, key: &str, body: &[u8], published: bool) -> String {
    let doc = new_uuid(&f.db).await;
    let id = f.reserve(key, &doc, 100).await;
    let staged = f.root.join("staging").join(&id);
    fs::write(&staged, body).unwrap();
    if published {
        fs::hard_link(&staged, f.root.join("revisions").join(&id)).unwrap();
    }
    let ino = fs::metadata(&staged).unwrap().ino().to_string();
    sqlx::query(
        "UPDATE openmettle.storage_reservations
            SET stage_claimed = true, payload_ino = $2::text::numeric, publish_pending = $3
          WHERE id = $1::uuid",
    )
    .bind(&id)
    .bind(&ino)
    .bind(published)
    .execute(&mut f.db.admin().await)
    .await
    .unwrap();
    id
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn replay_after_restoring_an_older_backup_purges_once_and_keeps_every_deadline() {
    let f = Fixture::new().await;
    let worker = pool(&f.db, WORKER).await;
    let mut stored = Vec::new();
    for key in ["early", "due", "removed", "kept", "live"] {
        stored.push(f.payload(key, key.as_bytes()).await);
    }
    let ids: Vec<String> = stored.iter().map(|s| s.revision.clone()).collect();
    let [early, due, removed, kept, live] = &ids[..] else {
        unreachable!()
    };
    let at = async |db: &TestDb, rev: &str, s: Step| step(&db.0, &f.c.scope, rev, s).await.unwrap();
    // Before the backup: one revision purged and journaled, one with a one-day deadline, one due.
    at(&f.db, early, Step::Retain).await;
    retention_grace(&f.db, 86_400).await;
    at(&f.db, kept, Step::Retain).await;
    retention_grace(&f.db, 1).await;
    sleep_past_grace().await;
    assert_eq!(
        artifact_fs::purge_due(&worker, &f.store, 10).await.unwrap(),
        1
    );
    at(&f.db, due, Step::Retain).await;
    sleep_past_grace().await;
    let kept_deadline = state(&f.db, kept).await;
    worker.close().await;
    f.api.close().await;
    let restored = backup(&f.db).await;

    // After the backup the live database purges the due revision and a newly removed one. Only
    // the database moves: the directory keeps the payloads it held at the backup point.
    for s in [Step::Claim, Step::Confirm] {
        at(&f.db, due, s).await;
    }
    at(&f.db, removed, Step::Retain).await;
    sleep_past_grace().await;
    for s in [Step::Claim, Step::Confirm] {
        at(&f.db, removed, s).await;
    }
    let dir = Dir::new();
    let file = dir.path("journal.export");
    let (ok, out, err) = cli(&f.db, &["journal", "export", &file]);
    assert!(ok, "{err}");
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let text = fs::read_to_string(&file).unwrap();
    let export = Export::parse(&text).unwrap();
    let lc_origin = export.lifecycle_origin_us.unwrap();
    assert!(
        out.starts_with(&format!(
            "watermark {} 7 {} ",
            export.origin_us, export.digest
        )),
        "{out}"
    );
    assert!(
        out.contains(&format!("\nlifecycle_origin {lc_origin}\n")),
        "{out}"
    );
    assert!(
        !cli(&f.db, &["journal", "export", &file]).0,
        "overwrote an export"
    );

    // The restored copy still has the gate open, as it was when the backup was taken.
    let owner = pool(&restored, OWNER).await;
    assert_eq!(gate(&restored).await, (true, None, None, None, true));
    let origin_str = export.origin_us.to_string();
    let lc_origin_str = lc_origin.to_string();
    let (ok, out, err) = cli(
        &restored,
        &[
            "restore",
            "lock",
            "--required-origin",
            &origin_str,
            "--required-lifecycle-origin",
            &lc_origin_str,
            "--required-seq",
            "7",
            "--required-digest",
            &export.digest,
            "--export-complete",
        ],
    );
    assert!(ok, "{err}");
    let run_id = restore_run_id_of(&restored).await.unwrap();
    assert_eq!(
        out,
        format!(
            "restore gate closed: restore_run {run_id}, origin {}, lifecycle_origin {lc_origin}, snapshot 4, required 7, coverage_complete true\n",
            export.origin_us
        )
    );
    // While it is closed no application role can claim or confirm a purge.
    let refused = step(&restored.0, &f.c.scope, due, Step::Claim).await;
    assert_eq!(code(&refused.unwrap_err()), "OMR02");
    assert_eq!(state(&restored, due).await.0, "retained");

    // A replay that stops after its database phase (openmettle-admin dies) moved both revisions
    // to 'purging' under their original deadlines; the gate refuses to open with payloads left.
    assert_eq!(restore::apply(&owner, &export).await.unwrap(), 3);
    for rev in [due, removed] {
        let (s, deadline) = state(&restored, rev).await;
        assert_eq!(
            (s.as_str(), deadline),
            ("purging", state(&f.db, rev).await.1)
        );
    }
    assert_eq!(account(&restored, &f.c.scope).await, (4, 14, 0));
    let (claim_run, claim_token): (String, String) = sqlx::query_as(
        "SELECT restore_run_id::text, volume_claim_token::text
           FROM openmettle.restore_claim_volume_phase($1, $2, decode($3, 'hex'), $4)",
    )
    .bind(export.origin_us)
    .bind(export.seq)
    .bind(&export.digest)
    .bind(export.lifecycle_origin_us)
    .fetch_one(&owner)
    .await
    .unwrap();
    let open = sqlx::query(
        "SELECT openmettle.restore_gate_open(
                    $1::uuid,
                    $2::uuid,
                    $3,
                    $4,
                    decode($5, 'hex'),
                    (SELECT volume_id FROM openmettle.storage_volume_control WHERE id),
                    $6
                )",
    )
    .bind(&claim_run)
    .bind(&claim_token)
    .bind(export.origin_us)
    .bind(export.seq)
    .bind(&export.digest)
    .bind(export.lifecycle_origin_us)
    .execute(&owner)
    .await;
    assert_eq!(sqlstate(open), "OMR05");
    sqlx::query("SELECT openmettle.restore_release_volume_phase($1::uuid, $2::uuid)")
        .bind(&claim_run)
        .bind(&claim_token)
        .execute(&owner)
        .await
        .unwrap();
    let (ok, _, err) = cli(&restored, &["restore", "replay", &file]);
    assert!(!ok && err.contains("pass its artifact root"), "{err}");

    // The rerun removes the resurrected payloads, releases their bytes once and opens the gate.
    let root = f.root.to_str().unwrap();
    let (ok, out, err) = cli(&restored, &["restore", "replay", &file, root]);
    assert!(ok, "{err}");
    assert_eq!(out, "replayed 0 records through 7; restore gate open\n");
    let mut left = vec![stored[3].reservation.clone(), stored[4].reservation.clone()];
    left.sort();
    assert_eq!(f.files("revisions"), left);
    assert_eq!(account(&restored, &f.c.scope).await, (4, 4, 0));
    assert_eq!(account(&f.db, &f.c.scope).await, (4, 4, 0));
    for rev in [early, due, removed] {
        assert_eq!(state(&restored, rev).await, state(&f.db, rev).await);
    }
    assert_eq!(state(&restored, kept).await, kept_deadline);
    assert_eq!(state(&restored, live).await.0, "active");
    assert_eq!(journal(&restored).await, journal(&f.db).await);
    assert_chain(&restored).await;
    assert_totals(&restored).await;
    assert_eq!(
        gate(&restored).await,
        (true, Some(4), Some(7), Some(export.digest), true)
    );
    assert_eq!(restore_run_id_of(&restored).await, None);
    let (ok, _, err) = cli(&restored, &["restore", "replay", &file, root]);
    assert!(!ok && err.contains("OMR02"), "{err}");
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn replay_fails_closed_on_damaged_tampered_lagging_and_stale_exports() {
    let f = Fixture::new().await;
    let worker = pool(&f.db, WORKER).await;
    let live_owner = pool(&f.db, OWNER).await;
    let mut stored = Vec::new();
    for key in ["first", "second", "third", "other"] {
        stored.push(f.payload(key, key.as_bytes()).await);
    }
    let ids: Vec<String> = stored.iter().map(|s| s.revision.clone()).collect();
    let [first, second, third, other] = &ids[..] else {
        unreachable!()
    };
    let at = async |rev: &str, s: Step| step(&f.db.0, &f.c.scope, rev, s).await.unwrap();
    let before = restore::export(&live_owner).await.unwrap();
    at(first, Step::Retain).await;
    sleep_past_grace().await;
    assert_eq!(
        artifact_fs::purge_due(&worker, &f.store, 10).await.unwrap(),
        1
    );
    at(second, Step::Retain).await;
    at(third, Step::Retain).await;
    sleep_past_grace().await;
    for p in [&worker, &live_owner, &f.api] {
        p.close().await;
    }
    let restored = backup(&f.db).await;
    let forged_backup = backup(&f.db).await;
    for s in [Step::Claim, Step::Confirm] {
        at(second, s).await;
    }
    let stale = restore::export(&pool(&f.db, OWNER).await).await.unwrap();
    let stale_parsed = Export::parse(&stale).unwrap();
    for s in [Step::Claim, Step::Confirm] {
        at(third, s).await;
    }
    let full = restore::export(&pool(&f.db, OWNER).await).await.unwrap();
    let full_parsed = Export::parse(&full).unwrap();
    let origin = full_parsed.origin_us;
    let lc_origin = full_parsed.lifecycle_origin_us;

    let owner = pool(&restored, OWNER).await;
    let store = Store::open_existing(&f.root).unwrap();
    // Replay needs a closed gate.
    assert_eq!(
        sqlstate_of(replay(&owner, &store, &full).await.unwrap_err()),
        "OMR02"
    );
    // Asserting complete coverage (`--export-complete`) for a watermark below the restored head
    // (`0 < 1`) fails closed with OMR04.
    assert_eq!(
        sqlstate_of(
            restore::lock(&owner, origin, lc_origin, 0, GENESIS, true, None, true)
                .await
                .unwrap_err()
        ),
        "OMR04"
    );
    // Closing with seq 0 (below snapshot 4) WITHOUT `--export-complete` raises requirement to the
    // snapshot head with `coverage_complete = false`; an export older than the restored database
    // fails at restore_verify_export with OMR04.
    let locked = restore::lock(&owner, origin, lc_origin, 0, GENESIS, false, None, true)
        .await
        .unwrap();
    assert_eq!(
        (
            locked.snapshot_seq,
            locked.required_seq,
            locked.coverage_complete
        ),
        (4, 4, false)
    );
    assert_eq!(
        sqlstate_of(replay(&owner, &store, &before).await.unwrap_err()),
        "OMR04"
    );
    // Re-locking without --replace-restore-run fails with OMR02.
    assert_eq!(
        sqlstate_of(
            restore::lock(
                &owner,
                origin,
                lc_origin,
                6,
                &full_parsed.digest,
                true,
                None,
                true
            )
            .await
            .unwrap_err()
        ),
        "OMR02"
    );
    // Updating the same restore with matching restore_run_id raises the requirement, never lowers
    // it, refuses `--export-complete` for a watermark below the locked requirement with OMR04,
    // records intermediate checkpoints without lowering required_seq, and refuses conflicting
    // digests at any pinned sequence with OMR03.
    let raised = restore::lock(
        &owner,
        origin,
        lc_origin,
        6,
        &full_parsed.digest,
        true,
        Some(&locked.restore_run_id),
        false,
    )
    .await
    .unwrap();
    assert_eq!(raised.restore_run_id, locked.restore_run_id);
    assert_eq!(
        (
            raised.snapshot_seq,
            raised.required_seq,
            raised.coverage_complete
        ),
        (4, 6, true)
    );
    assert_eq!(
        sqlstate_of(
            restore::lock(
                &owner,
                origin,
                lc_origin,
                5,
                &stale_parsed.digest,
                true,
                Some(&locked.restore_run_id),
                false,
            )
            .await
            .unwrap_err()
        ),
        "OMR04"
    );
    let kept_lock = restore::lock(
        &owner,
        origin,
        lc_origin,
        5,
        &stale_parsed.digest,
        false,
        Some(&locked.restore_run_id),
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        (
            kept_lock.snapshot_seq,
            kept_lock.required_seq,
            kept_lock.coverage_complete
        ),
        (4, 6, true)
    );
    assert_eq!(
        sqlstate_of(
            restore::lock(
                &owner,
                origin,
                lc_origin,
                5,
                &"bb".repeat(32),
                false,
                Some(&locked.restore_run_id),
                false,
            )
            .await
            .unwrap_err()
        ),
        "OMR03"
    );
    assert_eq!(
        sqlstate_of(
            restore::lock(
                &owner,
                origin,
                lc_origin,
                6,
                &"aa".repeat(32),
                true,
                Some(&locked.restore_run_id),
                false,
            )
            .await
            .unwrap_err()
        ),
        "OMR03"
    );
    let unchanged = async || {
        assert_eq!(
            gate(&restored).await,
            (
                false,
                Some(4),
                Some(6),
                Some(full_parsed.digest.clone()),
                true
            )
        );
        assert_eq!(journal(&restored).await.len(), 4);
        for rev in [second, third] {
            assert_eq!(state(&restored, rev).await.0, "retained");
        }
    };

    // Export lines: [0]=header, [1]=origin, [2]=lifecycle_origin, [3..=8]=rec1..rec6, [9]=watermark, [10]=sha256.
    let lines: Vec<&str> = full.lines().collect();
    let edit = |index: usize, field: usize| -> Vec<String> {
        let mut out: Vec<String> = lines[..lines.len() - 1]
            .iter()
            .map(|l| (*l).to_owned())
            .collect();
        let mut fields: Vec<String> = out[index].split(' ').map(str::to_owned).collect();
        fields[field] = (fields[field].parse::<i64>().unwrap() + 1).to_string();
        out[index] = fields.join(" ");
        out
    };
    let pick = |indices: &[usize]| {
        indices
            .iter()
            .map(|&i| lines[i].to_owned())
            .collect::<Vec<_>>()
    };
    // Damaged, truncated, gapped and reordered exports are refused before the database is read.
    for (text, why) in [
        (
            full.replacen(
                " artifact_revision.purged ",
                " artifact_revision.purgex ",
                1,
            ),
            "checksum mismatch",
        ),
        (
            pick(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
                .iter()
                .map(|l| format!("{l}\n"))
                .collect(),
            "missing checksum",
        ),
        (
            reseal(&pick(&[0, 1, 2, 3, 4, 5, 6, 8, 9])),
            "records out of sequence",
        ),
        (
            reseal(&pick(&[0, 1, 2, 3, 4, 5, 6, 8, 7, 9])),
            "records out of sequence",
        ),
    ] {
        assert!(
            matches!(Export::parse(&text), Err(restore::Error::Export(w)) if w == why),
            "{why}"
        );
    }
    // A record altered after the restored head breaks the chain; one at or below it differs from
    // the restored record. Either refusal rolls the whole replay back.
    for altered in [edit(8, 6), edit(4, 6)] {
        assert_eq!(
            sqlstate_of(replay(&owner, &store, &reseal(&altered)).await.unwrap_err()),
            "OMR03"
        );
        unchanged().await;
    }
    // A stale export (seq 5 < locked required 6) fails in restore_verify_export BEFORE any row
    // is written, leaving the restored DB completely untouched.
    assert_eq!(
        sqlstate_of(replay(&owner, &store, &stale).await.unwrap_err()),
        "OMR04"
    );
    unchanged().await;

    // A forged record extending the chain with a matching locked watermark (7, forged) but a
    // mismatched content_digest for `other` fails in deletion_journal_replay with OMR03 and rolls
    // back the whole transaction.
    let (scope, digest): (String, String) = sqlx::query_as(
        "SELECT scope_id::text, encode(chain_digest, 'hex')
           FROM openmettle.deletion_journal WHERE journal_seq = 6",
    )
    .fetch_one(&mut f.db.admin().await)
    .await
    .unwrap();
    let forged_owner = pool(&forged_backup, OWNER).await;
    let forged: String = sqlx::query_scalar(
        "SELECT encode(openmettle.deletion_journal_digest(decode($1, 'hex'), ROW(7, 'epoch'::timestamptz,
                'artifact_revision.purged', $2::uuid, $3::uuid, 'epoch'::timestamptz, 'epoch'::timestamptz,
                sha256('forged'), NULL, NULL, NULL)::openmettle.deletion_journal), 'hex')",
    )
    .bind(&digest)
    .bind(other)
    .bind(&scope)
    .fetch_one(&forged_owner)
    .await
    .unwrap();
    let mut extended = pick(&[0, 1, 2, 3, 4, 5, 6, 7, 8]);
    let content: String = Sha256::digest(b"forged")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    extended.push(format!(
        "7 0 artifact_revision.purged {other} {scope} 0 0 {content} - {forged}"
    ));
    extended.push(format!("watermark {origin} 7 {forged} 0"));
    restore::lock(
        &forged_owner,
        origin,
        lc_origin,
        7,
        &forged,
        true,
        None,
        true,
    )
    .await
    .unwrap();
    assert_eq!(
        sqlstate_of(
            replay(&forged_owner, &store, &reseal(&extended))
                .await
                .unwrap_err()
        ),
        "OMR03"
    );
    assert_eq!(journal(&forged_backup).await.len(), 4);
    assert_eq!(state(&forged_backup, other).await.0, "active");

    // An active adoption/rebind barrier blocks finish with OMQ03 without opening the gate (and
    // releases its volume-phase lease cleanly on error so the next attempt runs immediately).
    sqlx::query("UPDATE openmettle.storage_volume_control SET adoption_run_id = gen_random_uuid()")
        .execute(&owner)
        .await
        .unwrap();
    assert_eq!(
        sqlstate_of(replay(&owner, &store, &full).await.unwrap_err()),
        "OMQ03"
    );
    assert!(!gate(&restored).await.0);
    sqlx::query("UPDATE openmettle.storage_volume_control SET adoption_run_id = NULL")
        .execute(&owner)
        .await
        .unwrap();

    // A ledger that disagrees with the volume keeps the gate closed until it is repaired.
    let skew = "UPDATE openmettle.storage_accounts SET active_bytes = active_bytes + $1";
    sqlx::query(skew).bind(1i64).execute(&owner).await.unwrap();
    let drift = replay(&owner, &store, &full).await;
    assert!(matches!(drift, Err(restore::Error::Drift)), "{drift:?}");
    assert_eq!(state(&restored, second).await.0, "purged");
    assert_eq!(state(&restored, third).await.0, "purged");
    assert!(!gate(&restored).await.0);
    sqlx::query(skew).bind(-1i64).execute(&owner).await.unwrap();
    replay(&owner, &store, &full).await.unwrap();
    assert_eq!(
        gate(&restored).await,
        (true, Some(4), Some(6), Some(full_parsed.digest), true)
    );
    assert_eq!(journal(&restored).await, journal(&f.db).await);
    assert_eq!(account(&restored, &f.c.scope).await, (5, 0, 0));
    assert_totals(&restored).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn the_gate_waits_for_purges_in_flight_and_only_the_owner_moves_it() {
    let f = Fixture::new().await;
    let origin = origin_of(&f.db).await;
    let lc_origin = lifecycle_origin_of(&f.db).await;
    let a = f.payload("a", b"a").await.revision;
    let b = f.payload("b", b"bb").await.revision;
    for rev in [&a, &b] {
        step(&f.db.0, &f.c.scope, rev, Step::Retain).await.unwrap();
    }
    sleep_past_grace().await;
    for rev in [&a, &b] {
        step(&f.db.0, &f.c.scope, rev, Step::Claim).await.unwrap();
    }
    let owner = pool(&f.db, OWNER).await;
    // Closing waits for a confirmation in flight, and its snapshot includes the record that
    // confirmation appends at commit.
    let mut worker = connect(&f.db.0, WORKER).await;
    let holder = pid(&mut worker).await;
    let mut tx = WriteTransaction::begin(&mut worker).await.unwrap();
    openmettle_core::storage::confirm_purge(&mut tx, &f.c.scope, &a)
        .await
        .unwrap();
    let locking = tokio::spawn({
        let owner = owner.clone();
        async move {
            restore::lock(&owner, origin, lc_origin, 0, GENESIS, false, None, true)
                .await
                .unwrap()
        }
    });
    wait_for_blocked_peer(&f.db, holder).await;
    tx.commit().await.unwrap();
    let locked = locking.await.unwrap();
    assert_eq!(
        (
            locked.snapshot_seq,
            locked.required_seq,
            locked.coverage_complete
        ),
        (3, 3, false)
    );
    // Complete coverage at head seq 3 before opening the gate, then close again while another
    // confirmation waits.
    sqlx::query(
        "SELECT openmettle.restore_gate_lock($1, h.journal_seq, h.chain_digest, true, $2::uuid, false, $3)
           FROM openmettle.deletion_journal_head h",
    )
    .bind(origin)
    .bind(&locked.restore_run_id)
    .bind(lc_origin)
    .execute(&owner)
    .await
    .unwrap();
    sqlx::query(
        "SELECT openmettle.restore_gate_open(
                    c.restore_run_id,
                    c.volume_claim_token,
                    $1,
                    h.journal_seq,
                    h.chain_digest,
                    (SELECT volume_id FROM openmettle.storage_volume_control WHERE id),
                    $2
                )
           FROM openmettle.deletion_journal_head h
          CROSS JOIN LATERAL openmettle.restore_claim_volume_phase($1, h.journal_seq, h.chain_digest, $2) c",
    )
    .bind(origin)
    .bind(lc_origin)
    .execute(&owner)
    .await
    .unwrap();
    let mut closer = connect(&f.db.0, OWNER).await;
    let holder = pid(&mut closer).await;
    let mut close = closer.begin().await.unwrap();
    sqlx::query(
        "SELECT openmettle.restore_gate_lock($1, 0, decode(repeat('00', 32), 'hex'), false, NULL, true, $2)",
    )
    .bind(origin)
    .bind(lc_origin)
    .execute(&mut *close)
    .await
    .unwrap();
    let confirming = tokio::spawn({
        let (db, scope, b) = (f.db.0.clone(), f.c.scope.clone(), b.clone());
        async move { step(&db, &scope, &b, Step::Confirm).await }
    });
    wait_for_blocked_peer(&f.db, holder).await;
    close.commit().await.unwrap();
    assert_eq!(code(&confirming.await.unwrap().unwrap_err()), "OMR02");
    assert_eq!(state(&f.db, &b).await.0, "purging");
    assert_eq!(journal(&f.db).await.len(), 3);

    // Every owner gate/replay/checkpoint/volume-phase/break-glass function requires READ COMMITTED.
    for sql in [
        "SELECT openmettle.restore_gate_lock(0, 0, decode(repeat('00', 32), 'hex'), true)",
        "SELECT openmettle.restore_verify_export(0, 0, decode(repeat('00', 32), 'hex'))",
        "SELECT openmettle.restore_verify_checkpoints()",
        "SELECT openmettle.restore_claim_volume_phase(0, 0, decode(repeat('00', 32), 'hex'))",
        "SELECT openmettle.restore_renew_volume_phase(gen_random_uuid(), gen_random_uuid())",
        "SELECT openmettle.restore_assert_volume_phase(gen_random_uuid(), gen_random_uuid())",
        "SELECT openmettle.restore_release_volume_phase(gen_random_uuid(), gen_random_uuid())",
        "SELECT openmettle.restore_gate_open(gen_random_uuid(), gen_random_uuid(), 0, 0, decode(repeat('00', 32), 'hex'), NULL::uuid)",
        "SELECT openmettle.deletion_journal_replay(1, 0, '', NULL, NULL, 0, 0, NULL, NULL, NULL)",
        "SELECT openmettle.restore_accept_coverage_gap(gen_random_uuid(), gen_random_uuid(), 'k', 'r')",
    ] {
        let mut c = owner.begin().await.unwrap();
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *c)
            .await
            .unwrap();
        assert_eq!(
            sqlstate(sqlx::query(sql).execute(&mut *c).await),
            "25000",
            "{sql}"
        );
    }
    // Only the owner may call owner migration-41 functions or mutate the gate; only the worker may
    // SELECT from restore_reconciliation_gate or call restore_gate_lock_open().
    for role in [API, WORKER, ISSUANCE, crate::pg::GATEWAY] {
        let mut c = connect(&f.db.0, role).await;
        for sql in [
            "UPDATE openmettle.restore_reconciliation_gate SET open = true",
            "DELETE FROM openmettle.restore_reconciliation_gate",
            "TRUNCATE openmettle.restore_reconciliation_gate",
            "SELECT openmettle.restore_gate_lock(0, 0, decode(repeat('00', 32), 'hex'), true)",
            "SELECT openmettle.restore_verify_export(0, 0, decode(repeat('00', 32), 'hex'))",
            "SELECT openmettle.restore_verify_checkpoints()",
            "SELECT openmettle.restore_claim_volume_phase(0, 0, decode(repeat('00', 32), 'hex'))",
            "SELECT openmettle.restore_renew_volume_phase(gen_random_uuid(), gen_random_uuid())",
            "SELECT openmettle.restore_assert_volume_phase(gen_random_uuid(), gen_random_uuid())",
            "SELECT openmettle.restore_release_volume_phase(gen_random_uuid(), gen_random_uuid())",
            "SELECT openmettle.restore_gate_open(gen_random_uuid(), gen_random_uuid(), 0, 0, decode(repeat('00', 32), 'hex'), NULL::uuid)",
            "SELECT openmettle.deletion_journal_replay(1, 0, '', NULL, NULL, 0, 0, NULL, NULL, NULL)",
            "SELECT openmettle.deletion_journal_digest(NULL, NULL)",
            "SELECT openmettle.restore_accept_coverage_gap(gen_random_uuid(), gen_random_uuid(), 'k', 'r')",
        ] {
            let result = sqlx::query(sql).execute(&mut c).await;
            assert_eq!(sqlstate(result), "42501", "{role}: {sql}");
        }
        let read = restore::gate_open(&mut c).await;
        let lock_open: Result<bool, sqlx::Error> =
            sqlx::query_scalar("SELECT openmettle.restore_gate_lock_open()")
                .fetch_one(&mut c)
                .await;
        if role == WORKER {
            assert!(!read.unwrap());
            assert!(!lock_open.unwrap());
        } else if role == API {
            assert_eq!(sqlstate(read), "42501", "{role}");
            assert!(!lock_open.unwrap());
        } else {
            assert_eq!(sqlstate(read), "42501", "{role}");
            assert_eq!(sqlstate(lock_open), "42501", "{role}");
        }
    }

    // P2 #10 regression: `openmettle_api` cannot insert `restore.accept_coverage_gap` or
    // `restore_gate` into `authorization_audit`, and even `openmettle_owner` cannot decouple them.
    let mut api = connect(&f.db.0, API).await;
    let fake_user = new_uuid(&f.db).await;
    let api_insert = sqlx::query(
        "INSERT INTO openmettle.authorization_audit
            (actor_user_id, action, target_kind, target_id, request_key, reason, details)
         VALUES ($1::uuid, 'restore.accept_coverage_gap', 'restore_gate', 'instance',
                 'api-forged', 'forged', '{}'::jsonb)",
    )
    .bind(&fake_user)
    .execute(&mut api)
    .await;
    assert_eq!(sqlstate(api_insert), "23514");
    let api_op_col = sqlx::query(
        "INSERT INTO openmettle.authorization_audit
            (actor_kind, operator_id, action, target_kind, target_id, request_key, reason, details)
         VALUES ('operator', $1::uuid, 'restore.accept_coverage_gap', 'restore_gate', 'instance',
                 'api-op', 'forged', '{}'::jsonb)",
    )
    .bind(&fake_user)
    .execute(&mut api)
    .await;
    assert_eq!(sqlstate(api_op_col), "42501");
    let mismatched_owner = sqlx::query(
        "INSERT INTO openmettle.authorization_audit
            (actor_kind, operator_id, action, target_kind, target_id, request_key, reason, details)
         VALUES ('operator', $1::uuid, 'restore.accept_coverage_gap', 'user', 'instance',
                 'owner-mismatch', 'bad', '{}'::jsonb)",
    )
    .bind(&fake_user)
    .execute(&owner)
    .await;
    assert_eq!(sqlstate(mismatched_owner), "23514");
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn a_schema_28_journal_and_backup_replay_after_the_upgrade_to_41() {
    let live = TestDb::new().await;
    let settings = live.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..28]).await.unwrap();
    configure(&live, Some(1000), Some(1000), Some(1000)).await;
    retention_grace(&live, 0).await;
    let c = Context::new(&live).await;
    let purge = async |key: &str| {
        let doc = new_uuid(&live).await;
        let r = reserve(&live, API, &input(&c.scope, &c.actor, key, &doc, 10))
            .await
            .unwrap();
        let rev = settle(&live, &c.scope, &r.id, 10, key.as_bytes(), "text/plain")
            .await
            .unwrap();
        for s in [Step::Retain, Step::Claim, Step::Confirm] {
            step(&live.0, &c.scope, &rev, s).await.unwrap();
        }
    };
    let restored = backup(&live).await;
    purge("first").await;
    purge("second").await;
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    // The upgrade keeps the journal as migration 28 wrote it and leaves the gate open.
    assert_eq!(journal(&live).await.len(), 2);
    assert_eq!(gate(&live).await, (true, None, None, None, true));
    purge("third").await;
    // One chain across the upgrade: migration 41 appends with migration 28's encoding.
    assert_chain(&live).await;
    let export = Export::parse(&restore::export(&pool(&live, OWNER).await).await.unwrap()).unwrap();

    // A backup taken at schema 28 preserves migration 28's installed_on timestamp in
    // _sqlx_migrations, so migrating it to 42 produces the exact same coverage_started_at origin
    // as the live primary, while receiving a newer lifecycle_coverage_started_at (since pre-42
    // disassociations were not journaled): `--export-complete` fails closed with OMR04 and opening
    // requires an audited operator `restore.accept_coverage_gap`.
    tokio::time::sleep(Duration::from_millis(20)).await;
    migrate::apply(&restored.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    let owner = pool(&restored, OWNER).await;
    assert_eq!(gate(&restored).await, (true, None, None, None, true));
    // Even a record the restored journal lacks is refused while the gate is open.
    let open = restore::apply(&owner, &export).await;
    assert_eq!(sqlstate_of(open.unwrap_err()), "OMR02");
    assert_eq!(
        sqlstate_of(
            restore::lock(
                &owner,
                export.origin_us,
                export.lifecycle_origin_us,
                export.seq,
                &export.digest,
                true,
                None,
                true,
            )
            .await
            .unwrap_err()
        ),
        "OMR04"
    );
    let locked = restore::lock(
        &owner,
        export.origin_us,
        export.lifecycle_origin_us,
        export.seq,
        &export.digest,
        false,
        None,
        true,
    )
    .await
    .unwrap();
    assert_eq!(
        (
            locked.snapshot_seq,
            locked.required_seq,
            locked.coverage_complete
        ),
        (0, 4, false)
    );
    // Records written by migrations 28 and 42 all verify against migration 42's encoding.
    assert_eq!(restore::apply(&owner, &export).await.unwrap(), 4);
    // Opening without break-glass coverage-gap acceptance fails closed with OMR04.
    let blocked_open = sqlx::query(
        "SELECT openmettle.restore_gate_open(
                    c.restore_run_id,
                    c.volume_claim_token,
                    $1,
                    $2,
                    decode($3, 'hex'),
                    (SELECT volume_id FROM openmettle.storage_volume_control WHERE id),
                    $4
                )
           FROM openmettle.restore_claim_volume_phase($1, $2, decode($3, 'hex'), $4) c",
    )
    .bind(export.origin_us)
    .bind(export.seq)
    .bind(&export.digest)
    .bind(export.lifecycle_origin_us)
    .execute(&owner)
    .await;
    assert_eq!(sqlstate(blocked_open), "OMR04");
    let operator = new_uuid(&restored).await;
    assert!(
        restore::accept_coverage_gap(
            &owner,
            &locked.restore_run_id,
            &operator,
            "pre42-schema28-gap",
            "schema-28 backup predates migration 42 lifecycle journaling",
        )
        .await
        .unwrap()
    );
    // No purged revision exists in the backup, so once break-glass is recorded the gate opens.
    sqlx::query(
        "SELECT openmettle.restore_gate_open(
                    c.restore_run_id,
                    c.volume_claim_token,
                    $1,
                    $2,
                    decode($3, 'hex'),
                    (SELECT volume_id FROM openmettle.storage_volume_control WHERE id),
                    $4
                )
           FROM openmettle.restore_claim_volume_phase($1, $2, decode($3, 'hex'), $4) c",
    )
    .bind(export.origin_us)
    .bind(export.seq)
    .bind(&export.digest)
    .bind(export.lifecycle_origin_us)
    .execute(&owner)
    .await
    .unwrap();
    assert_eq!(journal(&restored).await, journal(&live).await);
    assert_chain(&restored).await;
}

/// P1 #1 (original) & P1 #2 (Review #1): an export or lock from a second independent installation
/// (at seq 0 or seq 1) is rejected BEFORE `deletion_journal_replay` writes anything, and
/// `restore_gate_lock` authenticates `--required-origin` immediately.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn export_from_second_independent_installation_is_rejected_before_apply_commits() {
    let a = Fixture::new().await;
    let b = Fixture::new().await;
    let a_empty_export =
        Export::parse(&restore::export(&pool(&a.db, OWNER).await).await.unwrap()).unwrap();
    let b_empty_export =
        Export::parse(&restore::export(&pool(&b.db, OWNER).await).await.unwrap()).unwrap();
    assert_ne!(
        a_empty_export.origin_us, b_empty_export.origin_us,
        "independent installations must have distinct coverage_started_at origins"
    );

    // Retain and purge one revision on installation A and one on installation B so both reach
    // seq = 2 with distinct digests D_A and D_B. Capture A's backup at seq = 0 (before retain).
    let a_rev = a.payload("inst-a", b"secret-a").await.revision;
    let b_rev = b.payload("inst-b", b"secret-b").await.revision;
    a.api.close().await;
    let a_backup = backup(&a.db).await;
    for (f, rev) in [(&a, &a_rev), (&b, &b_rev)] {
        step(&f.db.0, &f.c.scope, rev, Step::Retain).await.unwrap();
    }
    sleep_past_grace().await;
    for (f, rev) in [(&a, &a_rev), (&b, &b_rev)] {
        for s in [Step::Claim, Step::Confirm] {
            step(&f.db.0, &f.c.scope, rev, s).await.unwrap();
        }
    }
    let exp_a = Export::parse(&restore::export(&pool(&a.db, OWNER).await).await.unwrap()).unwrap();
    let exp_b = Export::parse(&restore::export(&pool(&b.db, OWNER).await).await.unwrap()).unwrap();
    assert_eq!((exp_a.seq, exp_b.seq), (2, 2));
    assert_ne!(exp_a.digest, exp_b.digest);

    // Case 0: Locking backup A with installation B's origin fails IMMEDIATELY in restore_gate_lock
    // with OMR04.
    let owner_a = pool(&a_backup, OWNER).await;
    assert_eq!(
        sqlstate_of(
            restore::lock(
                &owner_a,
                exp_b.origin_us,
                exp_b.lifecycle_origin_us,
                0,
                GENESIS,
                true,
                None,
                true
            )
            .await
            .unwrap_err()
        ),
        "OMR04"
    );

    // Case 1: Backup A locked at (O_A, 0, GENESIS) rejects installation B's empty export (same seq
    // 0 and same GENESIS digest, different origin) with OMR04.
    let lock_a = restore::lock(
        &owner_a,
        exp_a.origin_us,
        exp_a.lifecycle_origin_us,
        0,
        GENESIS,
        true,
        None,
        true,
    )
    .await
    .unwrap();
    assert_eq!(
        sqlstate_of(restore::apply(&owner_a, &b_empty_export).await.unwrap_err()),
        "OMR04"
    );
    // Case 2: Backup A locked at (O_A, 0, GENESIS) rejects installation B's seq=2 export with
    // OMR04 (sequence mismatch) and writes zero rows.
    assert_eq!(
        sqlstate_of(restore::apply(&owner_a, &exp_b).await.unwrap_err()),
        "OMR04"
    );
    assert!(journal(&a_backup).await.is_empty());

    // Case 3: Backup A locked at A's legitimate watermark (O_A, 2, D_A) rejects installation B's
    // seq=2 export (same seq 2, wrong digest D_B) with OMR03 before writing a single row.
    restore::lock(
        &owner_a,
        exp_a.origin_us,
        exp_a.lifecycle_origin_us,
        2,
        &exp_a.digest,
        true,
        Some(&lock_a.restore_run_id),
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        sqlstate_of(restore::apply(&owner_a, &exp_b).await.unwrap_err()),
        "OMR03"
    );
    assert!(journal(&a_backup).await.is_empty());
    assert_eq!(state(&a_backup, &a_rev).await.0, "active");

    // Case 4: Locking the live A DB (at head seq=2, D_A) with B's digest D_B fails in
    // restore_gate_lock itself with OMR03.
    let live_a_owner = pool(&a.db, OWNER).await;
    assert_eq!(
        sqlstate_of(
            restore::lock(
                &live_a_owner,
                exp_a.origin_us,
                exp_a.lifecycle_origin_us,
                2,
                &exp_b.digest,
                true,
                None,
                true
            )
            .await
            .unwrap_err()
        ),
        "OMR03"
    );

    // Legitimate replay of A's own export succeeds and opens the gate.
    assert_eq!(restore::apply(&owner_a, &exp_a).await.unwrap(), 2);
    restore::finish(&owner_a, Some(&a.store), &exp_a)
        .await
        .unwrap();
    assert!(gate(&a_backup).await.0);
}

/// P1 #2a + Review #1 P1 #2 regression: a backup taken at schema <= 27 migrated through 28..41
/// gets a fresh `coverage_started_at` timestamp and fails closed with OMR04 IMMEDIATELY at
/// `restore lock` (even at `seq = 0`, preventing a self-export from opening the gate).
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn schema_27_backup_migrated_to_41_fails_closed_on_origin_mismatch() {
    let live = TestDb::new().await;
    let settings = live.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..27]).await.unwrap();
    configure(&live, Some(1000), Some(1000), Some(1000)).await;
    let c = Context::new(&live).await;
    let doc = new_uuid(&live).await;
    let r = reserve(&live, API, &input(&c.scope, &c.actor, "pre28", &doc, 10))
        .await
        .unwrap();
    let rev = settle(&live, &c.scope, &r.id, 10, b"pre28-data", "text/plain")
        .await
        .unwrap();
    // Take the backup at schema 27 (before migration 28 existed).
    let pre28_backup = backup(&live).await;

    // Upgrade the live primary to latest (41), record its seq = 0 watermark, then purge and export.
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    let live_empty =
        Export::parse(&restore::export(&pool(&live, OWNER).await).await.unwrap()).unwrap();
    retention_grace(&live, 0).await;
    for s in [Step::Retain, Step::Claim, Step::Confirm] {
        step(&live.0, &c.scope, &rev, s).await.unwrap();
    }
    let live_export =
        Export::parse(&restore::export(&pool(&live, OWNER).await).await.unwrap()).unwrap();

    // Ensure a clock tick before migrating the schema-27 backup through 28..41.
    tokio::time::sleep(Duration::from_millis(20)).await;
    migrate::apply(&pre28_backup.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    let owner = pool(&pre28_backup, OWNER).await;
    // Even at seq = 0 (where the migrated backup could generate its own syntactically valid empty
    // export), locking with the primary's independently recorded `--required-origin` fails closed
    // immediately with OMR04!
    assert_eq!(
        sqlstate_of(
            restore::lock(
                &owner,
                live_empty.origin_us,
                live_empty.lifecycle_origin_us,
                0,
                GENESIS,
                true,
                None,
                true
            )
            .await
            .unwrap_err()
        ),
        "OMR04"
    );
    // And locking with the live post-purge watermark likewise fails closed with OMR04.
    assert_eq!(
        sqlstate_of(
            restore::lock(
                &owner,
                live_export.origin_us,
                live_export.lifecycle_origin_us,
                live_export.seq,
                &live_export.digest,
                true,
                None,
                true,
            )
            .await
            .unwrap_err()
        ),
        "OMR04"
    );
    assert!(journal(&pre28_backup).await.is_empty());
}

/// P1 #2b + Review #1 P1 #1 regression: omitting `--export-complete` leaves
/// `coverage_complete = false` and blocks gate opening with `OMR04` until an audited `'operator'`
/// break-glass `accept-coverage-gap` bound to `--restore-run` is recorded; AND restoring a backup
/// captured while an earlier restore gate was ALREADY CLOSED with `coverage_complete = true`
/// requires `--replace-restore-run --new-restore` and NEVER inherits `coverage_complete = true`.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn incomplete_coverage_and_closed_gate_backup_require_fresh_restore_run_and_break_glass() {
    let f = Fixture::new().await;
    let rev = f.payload("partial", b"partial-bytes").await.revision;
    step(&f.db.0, &f.c.scope, &rev, Step::Retain).await.unwrap();
    sleep_past_grace().await;
    f.api.close().await;
    let restored = backup(&f.db).await;

    for s in [Step::Claim, Step::Confirm] {
        step(&f.db.0, &f.c.scope, &rev, s).await.unwrap();
    }
    let dir = Dir::new();
    let file = dir.path("partial.export");
    let (ok, _, err) = cli(&f.db, &["journal", "export", &file]);
    assert!(ok, "{err}");
    let export = Export::parse(&fs::read_to_string(&file).unwrap()).unwrap();
    let origin_str = export.origin_us.to_string();
    let lc_origin = export.lifecycle_origin_us.unwrap();
    let lc_origin_str = lc_origin.to_string();

    // --- Part A: Lock WITHOUT `--export-complete` -> coverage_complete = false ---
    let (ok, out, err) = cli(
        &restored,
        &[
            "restore",
            "lock",
            "--required-origin",
            &origin_str,
            "--required-lifecycle-origin",
            &lc_origin_str,
            "--required-seq",
            "2",
            "--required-digest",
            &export.digest,
        ],
    );
    assert!(ok, "{err}");
    let run_id = restore_run_id_of(&restored).await.unwrap();
    assert_eq!(
        out,
        format!(
            "restore gate closed: restore_run {run_id}, origin {}, lifecycle_origin {lc_origin}, snapshot 1, required 2, coverage_complete false\n",
            export.origin_us
        )
    );
    assert_eq!(
        gate(&restored).await,
        (false, Some(1), Some(2), Some(export.digest.clone()), false)
    );

    // Replay purges the exported record but refuses to open the gate with OMR04 because coverage
    // is incomplete (and releases its volume-phase lease cleanly on error).
    let root = f.root.to_str().unwrap();
    let (ok, _, err) = cli(&restored, &["restore", "replay", &file, root]);
    assert!(!ok && err.contains("OMR04"), "{err}");
    assert!(!gate(&restored).await.0);
    assert_eq!(state(&restored, &rev).await.0, "purged");

    // Break-glass with a wrong `--restore-run` UUID fails with OMR02.
    let operator = new_uuid(&restored).await;
    let other_operator = new_uuid(&restored).await;
    let wrong_run = new_uuid(&restored).await;
    let (ok, _, err) = cli(
        &restored,
        &[
            "restore",
            "accept-coverage-gap",
            "--restore-run",
            &wrong_run,
            "--operator-id",
            &operator,
            "--request-key",
            "inc-wrong",
            "--reason",
            "wrong restore run",
        ],
    );
    assert!(!ok && err.contains("OMR02"), "{err}");

    // Operator runs audited break-glass accept-coverage-gap bound to the active restore_run_id.
    let (ok, out, err) = cli(
        &restored,
        &[
            "restore",
            "accept-coverage-gap",
            "--restore-run",
            &run_id,
            "--operator-id",
            &operator,
            "--request-key",
            "inc-42",
            "--reason",
            "primary storage unrecoverable after seq 1",
        ],
    );
    assert!(ok, "{err}");
    assert_eq!(out, "applied restore.accept_coverage_gap\n");

    // Verify the `'operator'` audit row recorded restore_run_id, origin, watermark, and reason.
    let audit: (String, String, String, String, String, String) = sqlx::query_as(
        "SELECT actor_kind, operator_id::text, action, target_kind, reason, details::text
           FROM openmettle.authorization_audit
          WHERE action = 'restore.accept_coverage_gap' AND request_key = 'inc-42'",
    )
    .fetch_one(&mut restored.admin().await)
    .await
    .unwrap();
    let details: serde_json::Value = serde_json::from_str(&audit.5).unwrap();
    assert_eq!(audit.0, "operator");
    assert_eq!(audit.1, operator);
    assert_eq!(audit.2, "restore.accept_coverage_gap");
    assert_eq!(audit.3, "restore_gate");
    assert_eq!(audit.4, "primary storage unrecoverable after seq 1");
    assert_eq!(details["restore_run_id"], run_id);
    assert_eq!(details["required_origin_us"], export.origin_us);
    assert_eq!(details["snapshot_journal_seq"], 1);
    assert_eq!(details["required_journal_seq"], 2);
    assert_eq!(details["required_chain_digest"], export.digest);

    // Exact replay is idempotent and writes no duplicate audit row.
    let (ok, out, err) = cli(
        &restored,
        &[
            "restore",
            "accept-coverage-gap",
            "--restore-run",
            &run_id,
            "--operator-id",
            &operator,
            "--request-key",
            "inc-42",
            "--reason",
            "primary storage unrecoverable after seq 1",
        ],
    );
    assert!(ok, "{err}");
    assert_eq!(out, "replayed restore.accept_coverage_gap\n");
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.authorization_audit
          WHERE action = 'restore.accept_coverage_gap'",
    )
    .fetch_one(&mut restored.admin().await)
    .await
    .unwrap();
    assert_eq!(count, 1);

    // Same request_key with a different reason or different operator_id fails with 23505.
    let (ok, _, err) = cli(
        &restored,
        &[
            "restore",
            "accept-coverage-gap",
            "--restore-run",
            &run_id,
            "--operator-id",
            &operator,
            "--request-key",
            "inc-42",
            "--reason",
            "different reason",
        ],
    );
    assert!(!ok && err.contains("23505"), "{err}");
    let (ok, _, err) = cli(
        &restored,
        &[
            "restore",
            "accept-coverage-gap",
            "--restore-run",
            &run_id,
            "--operator-id",
            &other_operator,
            "--request-key",
            "inc-42",
            "--reason",
            "primary storage unrecoverable after seq 1",
        ],
    );
    assert!(!ok && err.contains("23505"), "{err}");

    // --- Part B (Review #1 P1 #1): Backup taken WHILE gate is closed with coverage_complete = true ---
    // At this moment `restored` has `open = false`, `restore_run_id = run_id`, and
    // `coverage_complete = true`. Simulate restoring a backup taken right now.
    let closed_gate_backup = backup(&restored).await;
    // Plain `restore lock` without `--replace-restore-run` fails with OMR02.
    let (ok, _, err) = cli(
        &closed_gate_backup,
        &[
            "restore",
            "lock",
            "--required-origin",
            &origin_str,
            "--required-seq",
            "2",
            "--required-digest",
            &export.digest,
        ],
    );
    assert!(!ok && err.contains("OMR02"), "{err}");
    // Starting a fresh restore over the closed-gate backup with `--replace-restore-run` AND
    // `--new-restore` (omitting `--export-complete`) mints a brand-new `restore_run_id` and sets
    // `coverage_complete = false` — NEVER inheriting `true` from the backup!
    let (ok, _, err) = cli(
        &closed_gate_backup,
        &[
            "restore",
            "lock",
            "--required-origin",
            &origin_str,
            "--required-lifecycle-origin",
            &lc_origin_str,
            "--required-seq",
            "2",
            "--required-digest",
            &export.digest,
            "--replace-restore-run",
            &run_id,
            "--new-restore",
        ],
    );
    assert!(ok, "{err}");
    let fresh_run_id = restore_run_id_of(&closed_gate_backup).await.unwrap();
    assert_ne!(fresh_run_id, run_id);
    assert!(!gate(&closed_gate_backup).await.4);
    // Replay on `closed_gate_backup` stays blocked with OMR04 until break-glass under fresh_run_id.
    let (ok, _, err) = cli(&closed_gate_backup, &["restore", "replay", &file, root]);
    assert!(!ok && err.contains("OMR04"), "{err}");
    assert!(!gate(&closed_gate_backup).await.0);

    // Back on `restored` (where `coverage_complete = true`): restore replay succeeds and opens gate.
    let (ok, out, err) = cli(&restored, &["restore", "replay", &file, root]);
    assert!(ok, "{err}");
    assert_eq!(out, "replayed 0 records through 2; restore gate open\n");
    assert!(gate(&restored).await.0);

    // Break-glass on an already-open gate fails with OMR02.
    let (ok, _, err) = cli(
        &restored,
        &[
            "restore",
            "accept-coverage-gap",
            "--restore-run",
            &run_id,
            "--operator-id",
            &operator,
            "--request-key",
            "inc-43",
            "--reason",
            "gate already open",
        ],
    );
    assert!(!ok && err.contains("OMR02"), "{err}");
}

/// Review #1 P1 #3 regression: raising `required_journal_seq` from `(1, D_A)` to `(2, D_B)` retains
/// `(1, D_A)` in `checkpoints`; replaying a divergent history `(1, D_X) -> (2, D_B)` fails in
/// `restore_verify_checkpoints()` with `OMR03` and rolls back the entire `apply` transaction.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn raising_required_seq_retains_pinned_checkpoints_and_rejects_divergent_prefix() {
    let f = Fixture::new().await;
    let rev_a = f.payload("branch-a", b"aaa").await.revision;
    let rev_b = f.payload("branch-b", b"bbb").await.revision;
    for rev in [&rev_a, &rev_b] {
        step(&f.db.0, &f.c.scope, rev, Step::Retain).await.unwrap();
    }
    sleep_past_grace().await;
    f.api.close().await;

    // Three clones from the same seq-0 origin:
    // - branch1 purges rev_a -> seq 1 has digest D_A
    // - branch2 purges rev_b then rev_a -> seq 1 has digest D_X (!= D_A), seq 2 has digest D_B
    // - target is restored at seq 0, locked at (1, D_A) then raised to (2, D_B)
    let branch1 = backup(&f.db).await;
    let branch2 = backup(&f.db).await;
    let target = backup(&f.db).await;

    for s in [Step::Claim, Step::Confirm] {
        step(&branch1.0, &f.c.scope, &rev_a, s).await.unwrap();
    }
    let exp1 =
        Export::parse(&restore::export(&pool(&branch1, OWNER).await).await.unwrap()).unwrap();

    for rev in [&rev_b, &rev_a] {
        for s in [Step::Claim, Step::Confirm] {
            step(&branch2.0, &f.c.scope, rev, s).await.unwrap();
        }
    }
    let exp2 =
        Export::parse(&restore::export(&pool(&branch2, OWNER).await).await.unwrap()).unwrap();
    assert_eq!(exp1.origin_us, exp2.origin_us);
    assert_eq!((exp1.seq, exp2.seq), (3, 4));

    let owner = pool(&target, OWNER).await;
    let lock1 = restore::lock(
        &owner,
        exp1.origin_us,
        exp1.lifecycle_origin_us,
        3,
        &exp1.digest,
        false,
        None,
        true,
    )
    .await
    .unwrap();
    let lock2 = restore::lock(
        &owner,
        exp2.origin_us,
        exp2.lifecycle_origin_us,
        4,
        &exp2.digest,
        true,
        Some(&lock1.restore_run_id),
        false,
    )
    .await
    .unwrap();
    assert_eq!(lock2.restore_run_id, lock1.restore_run_id);

    // Replaying branch2's divergent export passes restore_verify_export (matches seq 4, D_B),
    // replays records 3 and 4, and then FAILS in restore_verify_checkpoints() with OMR03 because
    // checkpoint (3, D_A) disagrees with branch2's seq 3! The entire transaction rolls back.
    assert_eq!(
        sqlstate_of(restore::apply(&owner, &exp2).await.unwrap_err()),
        "OMR03"
    );
    assert_eq!(journal(&target).await.len(), 2);
    assert_eq!(state(&target, &rev_a).await.0, "retained");
    assert_eq!(state(&target, &rev_b).await.0, "retained");
    assert!(!gate(&target).await.0);
}

/// Review #1 P1 #5 & P1 #6 regression:
/// 1. An active `volume_claim_token` lease serializes `finish` against concurrent `finish`,
///    `apply`, and `lock` (`OMR02`), and a stale `(restore_run_id, claim_token)` fails with `OMR02`
///    and performs ZERO filesystem mutations after the gate moves or opens.
/// 2. `purge_one` / `purge_journaled` refuses a foreign hard link on a resurrected revision
///    strictly BEFORE `set_len(0)`, leaving the foreign link's bytes intact.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn volume_phase_lease_fences_concurrent_ops_and_purge_refuses_foreign_hard_link() {
    let f = Fixture::new().await;
    let rev = f.payload("linked", b"keep-foreign-bytes").await;
    step(&f.db.0, &f.c.scope, &rev.revision, Step::Retain)
        .await
        .unwrap();
    sleep_past_grace().await;
    f.api.close().await;
    let restored = backup(&f.db).await;

    for s in [Step::Claim, Step::Confirm] {
        step(&f.db.0, &f.c.scope, &rev.revision, s).await.unwrap();
    }
    let exp_text = restore::export(&pool(&f.db, OWNER).await).await.unwrap();
    let export = Export::parse(&exp_text).unwrap();

    let owner = pool(&restored, OWNER).await;
    let locked = restore::lock(
        &owner,
        export.origin_us,
        export.lifecycle_origin_us,
        export.seq,
        &export.digest,
        true,
        None,
        true,
    )
    .await
    .unwrap();
    assert_eq!(restore::apply(&owner, &export).await.unwrap(), 1);

    // Part A (P1 #5): Claim the volume-phase lease manually to simulate an active `finish`.
    let (lease_run, lease_token): (String, String) = sqlx::query_as(
        "SELECT restore_run_id::text, volume_claim_token::text
           FROM openmettle.restore_claim_volume_phase($1, $2, decode($3, 'hex'), $4)",
    )
    .bind(export.origin_us)
    .bind(export.seq)
    .bind(&export.digest)
    .bind(export.lifecycle_origin_us)
    .fetch_one(&owner)
    .await
    .unwrap();
    assert_eq!(lease_run, locked.restore_run_id);

    // While the lease is active, concurrent `finish`, `apply`, and `lock` all fail with OMR02.
    assert_eq!(
        sqlstate_of(
            restore::finish(&owner, Some(&f.store), &export)
                .await
                .unwrap_err()
        ),
        "OMR02"
    );
    assert_eq!(
        sqlstate_of(restore::apply(&owner, &export).await.unwrap_err()),
        "OMR02"
    );
    assert_eq!(
        sqlstate_of(
            restore::lock(
                &owner,
                export.origin_us,
                export.lifecycle_origin_us,
                export.seq,
                &export.digest,
                true,
                Some(&locked.restore_run_id),
                false,
            )
            .await
            .unwrap_err()
        ),
        "OMR02"
    );
    // Calling purge_journaled or scrub_unsettled_on_restore with a wrong/stale claim token fails
    // with OMR02 and touches ZERO bytes on disk.
    let stale_token = new_uuid(&restored).await;
    let payload_path = f.root.join("revisions").join(&rev.reservation);
    assert_eq!(
        sqlstate_of(
            artifact_fs::purge_journaled(&owner, &f.store, &lease_run, &stale_token)
                .await
                .unwrap_err()
                .into()
        ),
        "OMR02"
    );
    assert_eq!(
        sqlstate_of(
            artifact_fs::scrub_unsettled_on_restore(&owner, &f.store, &lease_run, &stale_token)
                .await
                .unwrap_err()
                .into()
        ),
        "OMR02"
    );
    assert_eq!(fs::read(&payload_path).unwrap(), b"keep-foreign-bytes");

    // Release the manual lease so `restore::finish` can run.
    sqlx::query("SELECT openmettle.restore_release_volume_phase($1::uuid, $2::uuid)")
        .bind(&lease_run)
        .bind(&lease_token)
        .execute(&owner)
        .await
        .unwrap();

    // Part B (P1 #6): Create a foreign hard link on the resurrected revision's payload.
    let foreign_alias = f.root.join("revisions").join("foreign-alias");
    fs::hard_link(&payload_path, &foreign_alias).unwrap();
    let err = restore::finish(&owner, Some(&f.store), &export)
        .await
        .unwrap_err();
    assert!(
        matches!(err, restore::Error::Storage(artifact_fs::Error::Io)),
        "{err:?}"
    );
    assert!(!gate(&restored).await.0);
    // Refusal happened strictly BEFORE set_len(0): both links retain the full original bytes.
    assert_eq!(fs::read(&foreign_alias).unwrap(), b"keep-foreign-bytes");
    assert_eq!(fs::read(&payload_path).unwrap(), b"keep-foreign-bytes");

    // Remove the foreign link; now `restore::finish` succeeds and opens the gate.
    fs::remove_file(&foreign_alias).unwrap();
    restore::finish(&owner, Some(&f.store), &export)
        .await
        .unwrap();
    assert!(gate(&restored).await.0);
    assert!(!payload_path.exists());
    // After gate opens, reusing the old `(lease_run, lease_token)` still fails with OMR02.
    assert_eq!(
        sqlstate_of(
            artifact_fs::scrub_unsettled_on_restore(&owner, &f.store, &lease_run, &lease_token)
                .await
                .unwrap_err()
                .into()
        ),
        "OMR02"
    );
}

/// P1 #3 + Review #1 P2 #7 & P2 #8 regression:
/// - An unsettled mid-publication upload (`publish_pending = true`, hard-linked under
///   `revisions/<id>` and `staging/<id>` with secret bytes) is scrubbed on BOTH in-place snapshot
///   restore and `tar` file-copy restore (failing closed with `REBIND_FIRST` if `storage rebind`
///   is skipped).
/// - Mid-reclaim rows (`reclaim_state = 'claiming'` with published bytes and `'truncated'` with
///   empty `.reclaim.<id>`) are scrubbed cleanly so drift passes and the gate opens, and a worker
///   then releases the truncated reservation cleanly.
/// - An all-zero reservation UUID (`00000000-0000-0000-0000-000000000000`) is never skipped by
///   keyset pagination in `scrub_unsettled_on_restore` or `drift::verify_volume`.
/// - Foreign hard links, quarantined non-zero staging, and unbound non-zero staging fail closed.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn unsettled_mid_publication_mid_reclaim_and_all_zero_uuid_are_scrubbed_on_restore() {
    let f = Fixture::new().await;
    let settled = f.payload("live-doc", b"keep-me").await;
    let mid_pub = seed_unsettled_upload(&f, "mid-pub", b"secret-unsettled", true).await;
    let staged_only = seed_unsettled_upload(&f, "staged-only", b"secret-staged", false).await;

    // P2 #7: seed a `reclaim_state = 'claiming'` reservation with a live published link and bytes,
    // plus a `reclaim_state = 'truncated'` reservation with an empty `.reclaim.<id>` anchor.
    let claiming_id = seed_unsettled_upload(&f, "mid-claiming", b"secret-claiming", true).await;
    sqlx::query(
        "UPDATE openmettle.storage_reservations
            SET reclaim_state = 'claiming',
                reclaim_claim_token = gen_random_uuid(),
                reclaim_lease_until = clock_timestamp() + interval '60 seconds',
                created_at = clock_timestamp() - interval '2 hours',
                lease_expires_at = clock_timestamp() - interval '1 hour'
          WHERE id = $1::uuid",
    )
    .bind(&claiming_id)
    .execute(&mut f.db.admin().await)
    .await
    .unwrap();

    let trunc_doc = new_uuid(&f.db).await;
    let truncated_id = f.reserve("mid-truncated", &trunc_doc, 100).await;
    let trunc_anchor = f
        .root
        .join("staging")
        .join(format!(".reclaim.{truncated_id}"));
    let trunc_file = fs::File::create_new(&trunc_anchor).unwrap();
    let trunc_ino = trunc_file.metadata().unwrap().ino().to_string();
    drop(trunc_file);
    sqlx::query(
        "UPDATE openmettle.storage_reservations
            SET stage_claimed = true,
                payload_ino = $2::text::numeric,
                publish_pending = false,
                reclaim_state = 'truncated',
                reclaim_claim_token = gen_random_uuid(),
                reclaim_lease_until = clock_timestamp() + interval '60 seconds',
                created_at = clock_timestamp() - interval '2 hours',
                lease_expires_at = clock_timestamp() - interval '1 hour'
          WHERE id = $1::uuid",
    )
    .bind(&truncated_id)
    .bind(&trunc_ino)
    .execute(&mut f.db.admin().await)
    .await
    .unwrap();

    // P2 #8: seed an unsettled reservation with the all-zero UUID `00000000-...`.
    let zero_id = "00000000-0000-0000-0000-000000000000";
    let zero_doc = new_uuid(&f.db).await;
    let zero_staged = f.root.join("staging").join(zero_id);
    let zero_rev = f.root.join("revisions").join(zero_id);
    fs::write(&zero_staged, b"secret-zero-uuid").unwrap();
    fs::hard_link(&zero_staged, &zero_rev).unwrap();
    let zero_ino = fs::metadata(&zero_staged).unwrap().ino().to_string();
    let mut admin = f.db.admin().await;
    let mut ztx = admin.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO openmettle.storage_reservations
            (id, scope_id, actor_user_id, idempotency_key, artifact_id, max_bytes,
             request_identity, request_digest, stage_claimed, payload_ino, publish_pending)
         VALUES ($1::uuid, $2::uuid, $3::uuid, 'zero-uuid', $4::uuid, 100,
                 'zero-uuid', sha256('zero-uuid'::bytea), true, $5::text::numeric, true)",
    )
    .bind(zero_id)
    .bind(&f.c.scope)
    .bind(&f.c.actor)
    .bind(&zero_doc)
    .bind(&zero_ino)
    .execute(&mut *ztx)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.storage_accounts SET reserved_bytes = reserved_bytes + 100 WHERE scope_id = $1::uuid",
    )
    .bind(&f.c.scope)
    .execute(&mut *ztx)
    .await
    .unwrap();
    sqlx::query("UPDATE openmettle.storage_instance SET reserved_bytes = reserved_bytes + 100")
        .execute(&mut *ztx)
        .await
        .unwrap();
    ztx.commit().await.unwrap();
    drop(admin);

    f.api.close().await;

    let db_tar = backup(&f.db).await;
    let db_inplace = backup(&f.db).await;
    let db_fail = backup(&f.db).await;

    let dir = Dir::new();
    let tar_root = tar_copy(&f.root, &dir, "tar-volume");
    let fail_root = tar_copy(&f.root, &dir, "fail-volume");
    let export_file = dir.path("empty.export");
    let (ok, _, err) = cli(&f.db, &["journal", "export", &export_file]);
    assert!(ok, "{err}");
    let export = Export::parse(&fs::read_to_string(&export_file).unwrap()).unwrap();
    let origin_str = export.origin_us.to_string();
    let lc_origin_str = export.lifecycle_origin_us.unwrap().to_string();

    // --- Part A: tar file-copy restore (new inodes) ---
    let (ok, _, err) = cli(
        &db_tar,
        &[
            "restore",
            "lock",
            "--required-origin",
            &origin_str,
            "--required-lifecycle-origin",
            &lc_origin_str,
            "--required-seq",
            "0",
            "--required-digest",
            GENESIS,
            "--export-complete",
        ],
    );
    assert!(ok, "{err}");
    // Skipping `storage rebind` fails closed with REBIND_FIRST and leaves the gate closed.
    let (ok, _, err) = cli(
        &db_tar,
        &[
            "restore",
            "replay",
            &export_file,
            tar_root.to_str().unwrap(),
        ],
    );
    assert!(
        !ok && err.contains("run `openmettle-admin storage rebind` first"),
        "{err}"
    );
    assert!(!gate(&db_tar).await.0);

    let (ok, _, err) = cli(&db_tar, &["storage", "rebind", tar_root.to_str().unwrap()]);
    assert!(ok, "{err}");
    let (ok, _, err) = cli(
        &db_tar,
        &[
            "restore",
            "replay",
            &export_file,
            tar_root.to_str().unwrap(),
        ],
    );
    assert!(ok, "{err}");
    assert!(gate(&db_tar).await.0);
    assert!(!tar_root.join("revisions").join(&mid_pub).exists());
    assert!(!tar_root.join("revisions").join(zero_id).exists());
    assert!(!tar_root.join("revisions").join(&claiming_id).exists());
    assert!(!tar_root.join("staging").join(&claiming_id).exists());
    assert_eq!(
        fs::metadata(
            tar_root
                .join("staging")
                .join(format!(".reclaim.{claiming_id}"))
        )
        .unwrap()
        .len(),
        0
    );
    assert_eq!(
        fs::metadata(tar_root.join("staging").join(&mid_pub))
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        fs::metadata(tar_root.join("staging").join(zero_id))
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        fs::read(tar_root.join("revisions").join(&settled.reservation)).unwrap(),
        b"keep-me"
    );

    // --- Part B: in-place snapshot restore (inodes unchanged, no rebind needed) ---
    let (ok, _, err) = cli(
        &db_inplace,
        &[
            "restore",
            "lock",
            "--required-origin",
            &origin_str,
            "--required-lifecycle-origin",
            &lc_origin_str,
            "--required-seq",
            "0",
            "--required-digest",
            GENESIS,
            "--export-complete",
        ],
    );
    assert!(ok, "{err}");
    let (ok, _, err) = cli(
        &db_inplace,
        &["restore", "replay", &export_file, f.root.to_str().unwrap()],
    );
    assert!(ok, "{err}");
    assert!(gate(&db_inplace).await.0);
    assert!(!f.root.join("revisions").join(&mid_pub).exists());
    assert!(!f.root.join("revisions").join(zero_id).exists());
    assert!(!f.root.join("revisions").join(&claiming_id).exists());
    assert!(!f.root.join("staging").join(&claiming_id).exists());
    assert_eq!(
        fs::metadata(
            f.root
                .join("staging")
                .join(format!(".reclaim.{claiming_id}"))
        )
        .unwrap()
        .len(),
        0
    );
    assert_eq!(
        fs::metadata(f.root.join("staging").join(zero_id))
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        fs::metadata(f.root.join("staging").join(&mid_pub))
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        fs::metadata(f.root.join("staging").join(&staged_only))
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        fs::read(f.root.join("revisions").join(&settled.reservation)).unwrap(),
        b"keep-me"
    );
    for id in [&mid_pub, zero_id, &claiming_id, &truncated_id] {
        let pending: bool = sqlx::query_scalar(
            "SELECT publish_pending FROM openmettle.storage_reservations WHERE id = $1::uuid",
        )
        .bind(id)
        .fetch_one(&mut db_inplace.admin().await)
        .await
        .unwrap();
        assert!(!pending, "{id}");
    }
    let claim_state: String = sqlx::query_scalar(
        "SELECT reclaim_state FROM openmettle.storage_reservations WHERE id = $1::uuid",
    )
    .bind(&claiming_id)
    .fetch_one(&mut db_inplace.admin().await)
    .await
    .unwrap();
    assert_eq!(claim_state, "truncated");
    // Now that the gate is open, worker expiry releases both mid-reclaim rows and the legacy
    // all-zero reservation cleanly.
    let worker = pool(&db_inplace, WORKER).await;
    assert_eq!(
        artifact_fs::reconcile_expired(&worker, &f.store, Duration::ZERO, 10)
            .await
            .unwrap(),
        3
    );
    assert!(!f.root.join("staging").join(zero_id).exists());
    assert!(
        !f.root
            .join("staging")
            .join(format!(".reclaim.{claiming_id}"))
            .exists()
    );
    assert!(
        !f.root
            .join("staging")
            .join(format!(".reclaim.{truncated_id}"))
            .exists()
    );
    assert_totals(&db_inplace).await;

    // --- Part C: fail-closed checks on foreign hard link, quarantined, and unbound non-zero staging ---
    let (ok, _, err) = cli(
        &db_fail,
        &["storage", "rebind", fail_root.to_str().unwrap()],
    );
    assert!(ok, "{err}");
    let (ok, _, err) = cli(
        &db_fail,
        &[
            "restore",
            "lock",
            "--required-origin",
            &origin_str,
            "--required-lifecycle-origin",
            &lc_origin_str,
            "--required-seq",
            "0",
            "--required-digest",
            GENESIS,
            "--export-complete",
        ],
    );
    assert!(ok, "{err}");
    // 1. Foreign hard link on an unsettled upload's inode keeps the gate closed and preserves bytes.
    let foreign_link = fail_root.join("staging").join("foreign-alias");
    fs::write(fail_root.join("staging").join(&staged_only), b"do-not-wipe").unwrap();
    fs::hard_link(fail_root.join("staging").join(&staged_only), &foreign_link).unwrap();
    let (ok, _, err) = cli(
        &db_fail,
        &[
            "restore",
            "replay",
            &export_file,
            fail_root.to_str().unwrap(),
        ],
    );
    assert!(!ok, "foreign hard link should fail closed: {err}");
    assert!(!gate(&db_fail).await.0);
    assert_eq!(fs::read(&foreign_link).unwrap(), b"do-not-wipe");
    fs::remove_file(&foreign_link).unwrap();

    // 2. Quarantined row with non-zero staged bytes fails closed and keeps the gate shut.
    sqlx::query(
        "UPDATE openmettle.storage_reservations SET adoption_unverified = true WHERE id = $1::uuid",
    )
    .bind(&staged_only)
    .execute(&mut db_fail.admin().await)
    .await
    .unwrap();
    let (ok, _, err) = cli(
        &db_fail,
        &[
            "restore",
            "replay",
            &export_file,
            fail_root.to_str().unwrap(),
        ],
    );
    assert!(
        !ok,
        "quarantined non-zero staging should fail closed: {err}"
    );
    assert!(!gate(&db_fail).await.0);

    // 3. Unbound row (`payload_ino IS NULL`) with non-zero staged bytes fails closed.
    sqlx::query(
        "UPDATE openmettle.storage_reservations
            SET adoption_unverified = false, payload_ino = NULL
          WHERE id = $1::uuid",
    )
    .bind(&staged_only)
    .execute(&mut db_fail.admin().await)
    .await
    .unwrap();
    let (ok, _, err) = cli(
        &db_fail,
        &[
            "restore",
            "replay",
            &export_file,
            fail_root.to_str().unwrap(),
        ],
    );
    assert!(!ok, "unbound non-zero staging should fail closed: {err}");
    assert!(!gate(&db_fail).await.0);
}

/// P2 #4 regression: a mutable retention hold present at backup time and released before purge on
/// the primary is stripped during replay so the resurrected revision purges and the gate opens.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn replay_strips_resurrected_mutable_retention_holds() {
    let f = Fixture::new().await;
    let rev = f.payload("held", b"held-bytes").await.revision;
    step(&f.db.0, &f.c.scope, &rev, Step::Retain).await.unwrap();
    // Place a mutable hold before taking the backup.
    sqlx::query(
        "INSERT INTO openmettle.artifact_retention_holds (scope_id, artifact_revision_id)
         VALUES ($1::uuid, $2::uuid)",
    )
    .bind(&f.c.scope)
    .bind(&rev)
    .execute(&mut f.db.admin().await)
    .await
    .unwrap();
    sleep_past_grace().await;
    f.api.close().await;
    let restored = backup(&f.db).await;

    // On primary: release the hold, claim and confirm the purge, and export.
    sqlx::query(
        "DELETE FROM openmettle.artifact_retention_holds
          WHERE scope_id = $1::uuid AND artifact_revision_id = $2::uuid",
    )
    .bind(&f.c.scope)
    .bind(&rev)
    .execute(&mut f.db.admin().await)
    .await
    .unwrap();
    for s in [Step::Claim, Step::Confirm] {
        step(&f.db.0, &f.c.scope, &rev, s).await.unwrap();
    }
    let export_text = restore::export(&pool(&f.db, OWNER).await).await.unwrap();
    let export = Export::parse(&export_text).unwrap();

    // Confirm the restored DB indeed has the resurrected hold row.
    let holds_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.artifact_retention_holds WHERE artifact_revision_id = $1::uuid",
    )
    .bind(&rev)
    .fetch_one(&mut restored.admin().await)
    .await
    .unwrap();
    assert_eq!(holds_before, 1);

    let owner = pool(&restored, OWNER).await;
    restore::lock(
        &owner,
        export.origin_us,
        export.lifecycle_origin_us,
        export.seq,
        &export.digest,
        true,
        None,
        true,
    )
    .await
    .unwrap();
    replay(&owner, &f.store, &export_text).await.unwrap();
    let holds_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.artifact_retention_holds WHERE artifact_revision_id = $1::uuid",
    )
    .bind(&rev)
    .fetch_one(&mut restored.admin().await)
    .await
    .unwrap();
    assert_eq!(holds_after, 0);
    assert_eq!(state(&restored, &rev).await.0, "purged");
    assert!(f.files("revisions").is_empty());
    assert!(gate(&restored).await.0);
    assert_totals(&restored).await;
}

/// P2 #5 + Review #1 P2 #9 regression: replaying a journal record stamped with `policy_revision`
/// advances `retention_policy.revision` strictly past it (`max_imported + 1`) so BOTH an immediate
/// post-restore removal (before any policy edit) AND a later `retention_set_grace` call never
/// reuse a replayed policy revision number.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn replay_advances_retention_policy_revision_so_future_removals_and_edits_never_collide() {
    let f = Fixture::new().await;
    let mut owner = connect(&f.db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let admin =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    authz_store::make_admin(&mut owner, &admin).await;
    // Allow grace_seconds in [0, 86400] so admin policy edits can bump revision cleanly.
    sqlx::query(
        "UPDATE openmettle.retention_policy SET min_grace_seconds = 0, max_grace_seconds = 86400",
    )
    .execute(&mut owner)
    .await
    .unwrap();
    let initial_rev: i64 =
        sqlx::query_scalar("SELECT revision FROM openmettle.retention_policy WHERE id")
            .fetch_one(&mut owner)
            .await
            .unwrap();
    let rev = f.payload("policy-rev", b"policy-bytes").await.revision;
    let post_rev = f.payload("post-restore", b"post-bytes").await.revision;
    drop(owner);
    f.api.close().await;
    let restored = backup(&f.db).await;

    // On live primary: bump retention_policy.revision by 4 audited edits, retain and purge `rev`.
    let mut live_api = connect(&f.db.0, API).await;
    let mut bumped = initial_rev;
    for i in 1..=4 {
        bumped = sqlx::query_scalar(
            "SELECT openmettle.retention_set_grace($1::uuid, $2::uuid, $3, 'bump', $4)",
        )
        .bind(&admin.user)
        .bind(&admin.approval)
        .bind(if i == 4 { 0i32 } else { i })
        .bind(format!("bump-{i}"))
        .fetch_one(&mut live_api)
        .await
        .unwrap();
    }
    assert_eq!(bumped, initial_rev + 4);
    for s in [Step::Retain, Step::Claim, Step::Confirm] {
        step(&f.db.0, &f.c.scope, &rev, s).await.unwrap();
    }
    let export_text = restore::export(&pool(&f.db, OWNER).await).await.unwrap();
    let export = Export::parse(&export_text).unwrap();

    // Replay onto the older backup (which still had initial_rev).
    let restored_owner = pool(&restored, OWNER).await;
    restore::lock(
        &restored_owner,
        export.origin_us,
        export.lifecycle_origin_us,
        export.seq,
        &export.digest,
        true,
        None,
        true,
    )
    .await
    .unwrap();
    replay(&restored_owner, &f.store, &export_text)
        .await
        .unwrap();

    // Active policy revision is now strictly greater than `bumped` (`bumped + 1`).
    let after_replay: i64 =
        sqlx::query_scalar("SELECT revision FROM openmettle.retention_policy WHERE id")
            .fetch_one(&restored_owner)
            .await
            .unwrap();
    assert_eq!(after_replay, bumped + 1);

    // Retaining a revision IMMEDIATELY after restore (before any policy edit) stamps `bumped + 1`,
    // never colliding with the replayed `bumped` policy revision.
    step(&restored.0, &f.c.scope, &post_rev, Step::Retain)
        .await
        .unwrap();
    let stamped: i64 = sqlx::query_scalar(
        "SELECT retention_policy_revision FROM openmettle.artifact_revisions WHERE id = $1::uuid",
    )
    .bind(&post_rev)
    .fetch_one(&restored_owner)
    .await
    .unwrap();
    assert_eq!(stamped, bumped + 1);

    // Next post-restore retention_set_grace must return bumped + 2.
    let next_rev: i64 = sqlx::query_scalar(
        "SELECT openmettle.retention_set_grace($1::uuid, $2::uuid, 60, 'post-restore', 'post-1')",
    )
    .bind(&admin.user)
    .bind(&admin.approval)
    .fetch_one(&mut connect(&restored.0, API).await)
    .await
    .unwrap();
    assert_eq!(next_rev, bumped + 2);
}

/// CI raw-SQL harness regression (#12): applying every migration SQL directly as `openmettle_owner`
/// without `openmettle._sqlx_migrations` (as `tests/kubernetes/qualify.py` does) succeeds cleanly
/// and initializes both `deletion_journal_head.coverage_started_at` and
/// `restore_reconciliation_gate`.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn raw_sql_migration_41_succeeds_without_sqlx_migrations_table() {
    let db = TestDb::new().await;
    let mut owner = connect(&db.0, OWNER).await;
    sqlx::query("CREATE SCHEMA openmettle")
        .execute(&mut owner)
        .await
        .unwrap();
    for migration in MIGRATIONS {
        let mut tx = owner.begin().await.unwrap();
        sqlx::query("SET LOCAL search_path = pg_catalog, pg_temp")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::raw_sql(migration.sql)
            .execute(&mut *tx)
            .await
            .unwrap_or_else(|e| panic!("raw migration {} failed: {e}", migration.version));
        tx.commit().await.unwrap();
    }
    let has_sqlx_table: bool =
        sqlx::query_scalar("SELECT to_regclass('openmettle._sqlx_migrations') IS NOT NULL")
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert!(!has_sqlx_table);
    let has_origin: bool = sqlx::query_scalar(
        "SELECT coverage_started_at IS NOT NULL FROM openmettle.deletion_journal_head WHERE id",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert!(has_origin);
    assert_eq!(gate(&db).await, (true, None, None, None, true));
}

/// Review #2 P1 #3 regression: `purge_journaled`, `scrub_unsettled_on_restore`, and
/// `verify_volume_with_lease` (inside `restore::finish`) renew the restore volume-phase lease
/// across paginated reservations and directory batches so large healthy volumes never outlive the
/// 300-second lease.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn drift_verification_renews_volume_phase_lease_across_large_volume() {
    let f = Fixture::new().await;
    let owner = pool(&f.db, OWNER).await;
    let purged_rev = f.payload("to-purge", b"purge-me").await.revision;
    step(&f.db.0, &f.c.scope, &purged_rev, Step::Retain)
        .await
        .unwrap();
    sleep_past_grace().await;
    let _unsettled = seed_unsettled_upload(&f, "to-scrub", b"scrub-me", true).await;

    // Seed 115 additional bound 0-byte settled revisions + files in `revisions/` so drift
    // verification spans >1 page of 100 reservations AND >100 directory entries.
    let mut admin = f.db.admin().await;
    let mut seed_tx = admin.begin().await.unwrap();
    for i in 0..115usize {
        let res_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut *seed_tx)
            .await
            .unwrap();
        let art_id: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&mut *seed_tx)
            .await
            .unwrap();
        let file_path = f.root.join("revisions").join(&res_id);
        let file = fs::File::create_new(&file_path).unwrap();
        let ino = file.metadata().unwrap().ino().to_string();
        drop(file);
        sqlx::query(
            "INSERT INTO openmettle.storage_reservations
                (id, scope_id, actor_user_id, idempotency_key, artifact_id, max_bytes,
                 request_identity, request_digest, state, settled_bytes, closed_at,
                 stage_claimed, payload_ino, publish_pending)
             VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5::uuid, 1,
                     $4::bytea, sha256($4::bytea), 'settled', 0, clock_timestamp(),
                     true, $6::text::numeric, false)",
        )
        .bind(&res_id)
        .bind(&f.c.scope)
        .bind(&f.c.actor)
        .bind(format!("bulk-empty-{i}"))
        .bind(&art_id)
        .bind(&ino)
        .execute(&mut *seed_tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.artifacts (id, scope_id, scope_kind, owner_user_id, last_revision)
             VALUES ($1::uuid, $2::uuid, (SELECT kind FROM openmettle.scopes WHERE id = $2::uuid), $3::uuid, 1)",
        )
        .bind(&art_id)
        .bind(&f.c.scope)
        .bind(&f.c.actor)
        .execute(&mut *seed_tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO openmettle.artifact_revisions
                (scope_id, artifact_id, revision, reservation_id, size_bytes,
                 content_digest, media_type, created_by_user_id, state)
             VALUES ($1::uuid, $2::uuid, 1, $3::uuid, 0, sha256(''::bytea),
                     'application/octet-stream', $4::uuid, 'active')",
        )
        .bind(&f.c.scope)
        .bind(&art_id)
        .bind(&res_id)
        .bind(&f.c.actor)
        .execute(&mut *seed_tx)
        .await
        .unwrap();
    }
    seed_tx.commit().await.unwrap();
    drop(admin);
    owner.close().await;
    f.api.close().await;

    let restored = backup(&f.db).await;
    for s in [Step::Claim, Step::Confirm] {
        step(&f.db.0, &f.c.scope, &purged_rev, s).await.unwrap();
    }
    let export = Export::parse(&restore::export(&pool(&f.db, OWNER).await).await.unwrap()).unwrap();
    let owner = pool(&restored, OWNER).await;
    restore::lock(
        &owner,
        export.origin_us,
        export.lifecycle_origin_us,
        export.seq,
        &export.digest,
        true,
        None,
        true,
    )
    .await
    .unwrap();
    assert_eq!(restore::apply(&owner, &export).await.unwrap(), 1);

    // Part A: Shorten a claimed lease to +5s; verify both `purge_journaled` and
    // `scrub_unsettled_on_restore` extend `volume_lease_until` by >200s.
    let (run_id, token): (String, String) = sqlx::query_as(
        "SELECT restore_run_id::text, volume_claim_token::text
           FROM openmettle.restore_claim_volume_phase($1, $2, decode($3, 'hex'), $4)",
    )
    .bind(export.origin_us)
    .bind(export.seq)
    .bind(&export.digest)
    .bind(export.lifecycle_origin_us)
    .fetch_one(&owner)
    .await
    .unwrap();

    sqlx::query(
        "UPDATE openmettle.restore_reconciliation_gate
            SET volume_lease_until = clock_timestamp() + interval '5 seconds'
          WHERE id",
    )
    .execute(&owner)
    .await
    .unwrap();
    assert_eq!(
        artifact_fs::purge_journaled(&owner, &f.store, &run_id, &token)
            .await
            .unwrap(),
        1
    );
    let extended_purge: bool = sqlx::query_scalar(
        "SELECT volume_lease_until > clock_timestamp() + interval '200 seconds'
           FROM openmettle.restore_reconciliation_gate WHERE id",
    )
    .fetch_one(&owner)
    .await
    .unwrap();
    assert!(
        extended_purge,
        "purge_journaled must renew the volume lease"
    );

    sqlx::query(
        "UPDATE openmettle.restore_reconciliation_gate
            SET volume_lease_until = clock_timestamp() + interval '5 seconds'
          WHERE id",
    )
    .execute(&owner)
    .await
    .unwrap();
    assert_eq!(
        artifact_fs::scrub_unsettled_on_restore(&owner, &f.store, &run_id, &token)
            .await
            .unwrap(),
        1
    );
    let extended_scrub: bool = sqlx::query_scalar(
        "SELECT volume_lease_until > clock_timestamp() + interval '200 seconds'
           FROM openmettle.restore_reconciliation_gate WHERE id",
    )
    .fetch_one(&owner)
    .await
    .unwrap();
    assert!(
        extended_scrub,
        "scrub_unsettled_on_restore must renew the volume lease"
    );

    sqlx::query("SELECT openmettle.restore_release_volume_phase($1::uuid, $2::uuid)")
        .bind(&run_id)
        .bind(&token)
        .execute(&owner)
        .await
        .unwrap();

    // Part B: Instrument `volume_lease_until` updates on the disposable test DB and exercise an
    // ACTUAL lease-window crossing during storage-enabled `verify_volume_on`: hold an
    // `ACCESS EXCLUSIVE` lock on `storage_accounts` so `ledgers(&mut tx_pin)` blocks on Conn 1
    // while `with_volume_phase_heartbeat` renews on Conn 2 every 60 ms across a shortened 250 ms
    // lease window (~450 ms total hold).
    let mut adm = restored.admin().await;
    sqlx::raw_sql(
        "CREATE TABLE public._lease_renew_log (id serial PRIMARY KEY);
         CREATE FUNCTION public._record_lease_renew() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
         BEGIN
             IF NEW.volume_lease_until IS NOT NULL
                AND OLD.volume_lease_until IS NOT NULL
                AND NEW.volume_claim_token = OLD.volume_claim_token THEN
                 INSERT INTO public._lease_renew_log DEFAULT VALUES;
             END IF;
             RETURN NEW;
         END
         $$;
         CREATE TRIGGER _track_lease_renew
             AFTER UPDATE OF volume_lease_until ON openmettle.restore_reconciliation_gate
             FOR EACH ROW EXECUTE FUNCTION public._record_lease_renew();",
    )
    .execute(&mut adm)
    .await
    .unwrap();

    let mut blocker = connect(&restored.0, OWNER).await;
    let blocker_pid = pid(&mut blocker).await;
    let mut blocker_tx = blocker.begin().await.unwrap();
    sqlx::query("LOCK TABLE openmettle.storage_accounts IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker_tx)
        .await
        .unwrap();

    let finishing = tokio::spawn({
        let owner = owner.clone();
        let store = f.store.clone();
        let export = export.clone();
        async move {
            restore::finish_with_heartbeat(&owner, Some(&store), &export, Duration::from_millis(60))
                .await
        }
    });
    wait_for_blocked_peer(&restored, blocker_pid).await;

    // Shorten the active lease to +250 ms AFTER the upfront renewal has already run and Conn 1
    // is blocked inside `ledgers(&mut tx_pin)`.
    sqlx::query(
        "UPDATE openmettle.restore_reconciliation_gate
            SET volume_lease_until = clock_timestamp() + interval '250 milliseconds'
          WHERE id",
    )
    .execute(&mut adm)
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(320)).await;
    let still_extended: bool = sqlx::query_scalar(
        "SELECT volume_lease_until > clock_timestamp() + interval '200 seconds'
           FROM openmettle.restore_reconciliation_gate WHERE id",
    )
    .fetch_one(&mut adm)
    .await
    .unwrap();
    assert!(
        still_extended,
        "mid-verification heartbeat must extend volume_lease_until while ledgers query is blocked"
    );
    let mut rival = connect(&restored.0, OWNER).await;
    let rival_claim = sqlx::query(
        "SELECT * FROM openmettle.restore_claim_volume_phase($1, $2, decode($3, 'hex'), $4)",
    )
    .bind(export.origin_us)
    .bind(export.seq)
    .bind(&export.digest)
    .bind(export.lifecycle_origin_us)
    .execute(&mut rival)
    .await;
    assert_eq!(sqlstate(rival_claim), "OMR02");
    tokio::time::sleep(Duration::from_millis(130)).await;
    blocker_tx.commit().await.unwrap();
    finishing.await.unwrap().unwrap();
    assert!(gate(&restored).await.0);

    let renewals: i64 = sqlx::query_scalar("SELECT count(*) FROM public._lease_renew_log")
        .fetch_one(&mut adm)
        .await
        .unwrap();
    assert!(
        renewals >= 10,
        "expected >= 10 lease renewals across heartbeat-driven verification, got {renewals}"
    );

    // Part C: Exercise an ACTUAL lease-window crossing on the storage-disabled (`store = None`,
    // `verify_ledgers_on`) path too.
    let disabled_db = TestDb::migrated().await;
    let disabled_owner = pool(&disabled_db, OWNER).await;
    let disabled_export = Export::parse(&restore::export(&disabled_owner).await.unwrap()).unwrap();
    restore::lock(
        &disabled_owner,
        disabled_export.origin_us,
        disabled_export.lifecycle_origin_us,
        0,
        GENESIS,
        true,
        None,
        true,
    )
    .await
    .unwrap();

    let mut dis_blocker = connect(&disabled_db.0, OWNER).await;
    let dis_blocker_pid = pid(&mut dis_blocker).await;
    let mut dis_blocker_tx = dis_blocker.begin().await.unwrap();
    sqlx::query("LOCK TABLE openmettle.storage_accounts IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *dis_blocker_tx)
        .await
        .unwrap();

    let dis_finishing = tokio::spawn({
        let owner = disabled_owner.clone();
        let export = disabled_export.clone();
        async move {
            restore::finish_with_heartbeat(&owner, None, &export, Duration::from_millis(60)).await
        }
    });
    wait_for_blocked_peer(&disabled_db, dis_blocker_pid).await;

    let mut dis_adm = disabled_db.admin().await;
    sqlx::query(
        "UPDATE openmettle.restore_reconciliation_gate
            SET volume_lease_until = clock_timestamp() + interval '250 milliseconds'
          WHERE id",
    )
    .execute(&mut dis_adm)
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(320)).await;
    let dis_extended: bool = sqlx::query_scalar(
        "SELECT volume_lease_until > clock_timestamp() + interval '200 seconds'
           FROM openmettle.restore_reconciliation_gate WHERE id",
    )
    .fetch_one(&mut dis_adm)
    .await
    .unwrap();
    assert!(
        dis_extended,
        "storage-disabled heartbeat must extend volume_lease_until while verify_ledgers_on blocks"
    );
    let mut dis_rival = connect(&disabled_db.0, OWNER).await;
    let dis_rival_claim = sqlx::query(
        "SELECT * FROM openmettle.restore_claim_volume_phase($1, 0, decode(repeat('00', 32), 'hex'), $2)",
    )
    .bind(disabled_export.origin_us)
    .bind(disabled_export.lifecycle_origin_us)
    .execute(&mut dis_rival)
    .await;
    assert_eq!(sqlstate(dis_rival_claim), "OMR02");
    tokio::time::sleep(Duration::from_millis(130)).await;
    dis_blocker_tx.commit().await.unwrap();
    dis_finishing.await.unwrap().unwrap();
    assert!(gate(&disabled_db).await.0);
}

/// Review #2 P1 #4 regression: `restore_gate_open` verifies `storage_volume_control.volume_id`
/// against `p_expected_volume_id` and rejects an active `adoption_run_id` (`OMQ03`), and
/// `restore::finish`'s `tx_pin` (`storage_volume_control FOR SHARE`) serializes with concurrent
/// `storage rebind`/`adopt` (`FOR UPDATE`) without blocking Connection 2's `restore_gate_open`.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn restore_gate_open_checks_volume_pin_and_serializes_with_rebind() {
    let f = Fixture::new().await;
    let owner = pool(&f.db, OWNER).await;
    let origin = origin_of(&f.db).await;
    let lc_origin = lifecycle_origin_of(&f.db).await;
    let true_vol: String = sqlx::query_scalar(
        "SELECT volume_id::text FROM openmettle.storage_volume_control WHERE id",
    )
    .fetch_one(&owner)
    .await
    .unwrap();
    let wrong_vol = new_uuid(&f.db).await;
    restore::lock(&owner, origin, lc_origin, 0, GENESIS, true, None, true)
        .await
        .unwrap();
    let (run_id, token): (String, String) = sqlx::query_as(
        "SELECT restore_run_id::text, volume_claim_token::text
           FROM openmettle.restore_claim_volume_phase($1, 0, decode(repeat('00', 32), 'hex'), $2)",
    )
    .bind(origin)
    .bind(lc_origin)
    .fetch_one(&owner)
    .await
    .unwrap();

    // 1. Mismatched volume_id -> OMQ03.
    let bad_vol = sqlx::query(
        "SELECT openmettle.restore_gate_open($1::uuid, $2::uuid, $3, 0, decode(repeat('00', 32), 'hex'), $4::uuid, $5)",
    )
    .bind(&run_id)
    .bind(&token)
    .bind(origin)
    .bind(&wrong_vol)
    .bind(lc_origin)
    .execute(&owner)
    .await;
    assert_eq!(sqlstate(bad_vol), "OMQ03");
    assert!(!gate(&f.db).await.0);

    // 2. NULL expected volume_id when a volume IS pinned -> OMQ03.
    let null_vol = sqlx::query(
        "SELECT openmettle.restore_gate_open($1::uuid, $2::uuid, $3, 0, decode(repeat('00', 32), 'hex'), NULL::uuid, $4)",
    )
    .bind(&run_id)
    .bind(&token)
    .bind(origin)
    .bind(lc_origin)
    .execute(&owner)
    .await;
    assert_eq!(sqlstate(null_vol), "OMQ03");
    assert!(!gate(&f.db).await.0);

    // 3. Active adoption/rebind barrier with matching volume_id -> OMQ03.
    sqlx::query("UPDATE openmettle.storage_volume_control SET adoption_run_id = gen_random_uuid()")
        .execute(&owner)
        .await
        .unwrap();
    let adopting = sqlx::query(
        "SELECT openmettle.restore_gate_open($1::uuid, $2::uuid, $3, 0, decode(repeat('00', 32), 'hex'), $4::uuid, $5)",
    )
    .bind(&run_id)
    .bind(&token)
    .bind(origin)
    .bind(&true_vol)
    .bind(lc_origin)
    .execute(&owner)
    .await;
    assert_eq!(sqlstate(adopting), "OMQ03");
    assert!(!gate(&f.db).await.0);
    sqlx::query("UPDATE openmettle.storage_volume_control SET adoption_run_id = NULL")
        .execute(&owner)
        .await
        .unwrap();

    // 4. Three-connection serialization check: Conn 1 (`tx_pin`) holds `storage_volume_control
    //    FOR SHARE`, Conn 3 (concurrent `storage rebind` / `adopt`) blocks on `FOR UPDATE`, and
    //    Conn 2 (`open_tx`) executes `restore_gate_open` cleanly WITHOUT deadlocking. Committing
    //    `tx_pin` FIRST keeps `rebind` blocked on `open_tx`'s share lock and keeps the gate closed
    //    until `open_tx` commits SECOND.
    let mut conn1 = connect(&f.db.0, OWNER).await;
    let pid1 = pid(&mut conn1).await;
    let mut tx_pin = conn1.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.storage_volume_control WHERE id FOR SHARE")
        .execute(&mut *tx_pin)
        .await
        .unwrap();

    let rebind = tokio::spawn({
        let db_name = f.db.0.clone();
        async move {
            let mut conn3 = connect(&db_name, OWNER).await;
            let mut tx3 = conn3.begin().await.unwrap();
            sqlx::query("SELECT FROM openmettle.storage_volume_control WHERE id FOR UPDATE")
                .execute(&mut *tx3)
                .await
                .unwrap();
            tx3.commit().await.unwrap();
        }
    });
    wait_for_blocked_peer(&f.db, pid1).await;

    let mut open_tx = owner.begin().await.unwrap();
    sqlx::query(
        "SELECT openmettle.restore_gate_open($1::uuid, $2::uuid, $3, 0, decode(repeat('00', 32), 'hex'), $4::uuid, $5)",
    )
    .bind(&run_id)
    .bind(&token)
    .bind(origin)
    .bind(&true_vol)
    .bind(lc_origin)
    .execute(&mut *open_tx)
    .await
    .unwrap();
    tx_pin.commit().await.unwrap();
    assert!(!gate(&f.db).await.0);
    assert!(
        !rebind.is_finished(),
        "rebind must remain blocked on open_tx's share lock after tx_pin commits"
    );
    open_tx.commit().await.unwrap();
    assert!(gate(&f.db).await.0);
    tokio::time::timeout(Duration::from_secs(5), rebind)
        .await
        .expect("rebind should unblock once open_tx commits")
        .unwrap();

    // 4b. Review #3 P1 #4 regression: if `tx_pin`'s PostgreSQL backend is terminated after
    //     verification and before `tx_pin.commit()`, committing `tx_pin` FIRST fails, `open_tx`
    //     rolls back on drop, and `restore_reconciliation_gate.open` remains `false`.
    restore::lock(&owner, origin, lc_origin, 0, GENESIS, true, None, true)
        .await
        .unwrap();
    let (run_id2, token2): (String, String) = sqlx::query_as(
        "SELECT restore_run_id::text, volume_claim_token::text
           FROM openmettle.restore_claim_volume_phase($1, 0, decode(repeat('00', 32), 'hex'), $2)",
    )
    .bind(origin)
    .bind(lc_origin)
    .fetch_one(&owner)
    .await
    .unwrap();
    let mut dead_conn = connect(&f.db.0, OWNER).await;
    let dead_pid = pid(&mut dead_conn).await;
    let mut dead_tx_pin = dead_conn.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.storage_volume_control WHERE id FOR SHARE")
        .execute(&mut *dead_tx_pin)
        .await
        .unwrap();
    let mut open_tx_aborted = owner.begin().await.unwrap();
    sqlx::query(
        "SELECT openmettle.restore_gate_open($1::uuid, $2::uuid, $3, 0, decode(repeat('00', 32), 'hex'), $4::uuid, $5)",
    )
    .bind(&run_id2)
    .bind(&token2)
    .bind(origin)
    .bind(&true_vol)
    .bind(lc_origin)
    .execute(&mut *open_tx_aborted)
    .await
    .unwrap();
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(dead_pid)
        .fetch_one(&mut f.db.admin().await)
        .await
        .unwrap();
    assert!(terminated);
    assert!(
        dead_tx_pin.commit().await.is_err(),
        "terminated tx_pin backend must fail commit"
    );
    drop(open_tx_aborted);
    assert!(
        !gate(&f.db).await.0,
        "rolling back open_tx after tx_pin commit failure must leave gate closed"
    );

    // 5. Storage-disabled deployment (`store = None`) opens cleanly with `p_expected_volume_id = NULL`.
    let disabled_db = TestDb::migrated().await;
    let disabled_owner = pool(&disabled_db, OWNER).await;
    let disabled_export = Export::parse(&restore::export(&disabled_owner).await.unwrap()).unwrap();
    restore::lock(
        &disabled_owner,
        disabled_export.origin_us,
        disabled_export.lifecycle_origin_us,
        0,
        GENESIS,
        true,
        None,
        true,
    )
    .await
    .unwrap();
    restore::finish(&disabled_owner, None, &disabled_export)
        .await
        .unwrap();
    assert!(gate(&disabled_db).await.0);
}

/// Review #2 P2 #5 regression: live `purge_due` holds `restore_reconciliation_gate FOR SHARE`
/// (via `restore_gate_lock_open()`) in both Tx 1 and Stage A across filesystem mutations, so an
/// already-`'purging'` revision waits on a concurrent `restore_gate_lock`, returns `0` once the
/// gate closes, and performs zero filesystem mutations.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn live_purge_stage_a_holds_restore_gate_share_lock_and_stops_when_closed() {
    let f = Fixture::new().await;
    let worker = pool(&f.db, WORKER).await;
    let owner = pool(&f.db, OWNER).await;
    let origin = origin_of(&f.db).await;
    let lc_origin = lifecycle_origin_of(&f.db).await;
    let p = f
        .payload("already-purging", b"do-not-touch-while-closed")
        .await;
    step(&f.db.0, &f.c.scope, &p.revision, Step::Retain)
        .await
        .unwrap();
    sleep_past_grace().await;
    step(&f.db.0, &f.c.scope, &p.revision, Step::Claim)
        .await
        .unwrap();
    assert_eq!(state(&f.db, &p.revision).await.0, "purging");

    // Hold an uncommitted `restore_gate_lock` so `purge_due` reaches `restore_gate_lock_open()`
    // and blocks on the gate row. Once `restore_gate_lock` commits, `purge_due` sees `false`,
    // rolls back cleanly, returns 0, and leaves the payload intact on disk.
    let (p_head_seq, p_head_digest): (i64, String) = sqlx::query_as(
        "SELECT journal_seq, encode(chain_digest, 'hex') FROM openmettle.deletion_journal_head WHERE id",
    )
    .fetch_one(&owner)
    .await
    .unwrap();
    let mut closer = connect(&f.db.0, OWNER).await;
    let holder = pid(&mut closer).await;
    let mut close_tx = closer.begin().await.unwrap();
    sqlx::query(
        "SELECT openmettle.restore_gate_lock($1, $2, decode($3, 'hex'), true, NULL, true, $4)",
    )
    .bind(origin)
    .bind(p_head_seq)
    .bind(&p_head_digest)
    .bind(lc_origin)
    .execute(&mut *close_tx)
    .await
    .unwrap();

    let purging = tokio::spawn({
        let worker = worker.clone();
        let store = f.store.clone();
        async move { artifact_fs::purge_due(&worker, &store, 10).await }
    });
    wait_for_blocked_peer(&f.db, holder).await;
    close_tx.commit().await.unwrap();
    assert_eq!(purging.await.unwrap().unwrap(), 0);
    assert_eq!(state(&f.db, &p.revision).await.0, "purging");
    let payload_path = f.root.join("revisions").join(&p.reservation);
    assert_eq!(
        fs::read(&payload_path).unwrap(),
        b"do-not-touch-while-closed"
    );

    // Repeated live `purge_due` while gate remains closed also returns 0 with zero disk writes.
    assert_eq!(
        artifact_fs::purge_due(&worker, &f.store, 10).await.unwrap(),
        0
    );
    assert_eq!(
        fs::read(&payload_path).unwrap(),
        b"do-not-touch-while-closed"
    );

    // Once the gate opens again, live `purge_due` completes the purge cleanly.
    sqlx::query(
        "SELECT openmettle.restore_gate_open(
                    c.restore_run_id,
                    c.volume_claim_token,
                    $1,
                    $2,
                    decode($3, 'hex'),
                    (SELECT volume_id FROM openmettle.storage_volume_control WHERE id),
                    $4
                )
           FROM openmettle.restore_claim_volume_phase($1, $2, decode($3, 'hex'), $4) c",
    )
    .bind(origin)
    .bind(p_head_seq)
    .bind(&p_head_digest)
    .bind(lc_origin)
    .execute(&owner)
    .await
    .unwrap();
    assert_eq!(
        artifact_fs::purge_due(&worker, &f.store, 10).await.unwrap(),
        1
    );
    assert_eq!(state(&f.db, &p.revision).await.0, "purged");
    assert!(!payload_path.exists());

    // Review #3 P2 #5 regression: live `detach` for a `state = 'purged',
    // purge_stage = 'anchor_pending_unlink'` revision also calls `restore_gate_lock_open()`
    // before `lock_pin`, leaving `.purge.<reservation>` intact while the gate is closed and
    // serializing with `restore_gate_lock` while open.
    let pa = f.payload("anchor-gated", b"anchor-payload").await;
    step(&f.db.0, &f.c.scope, &pa.revision, Step::Retain)
        .await
        .unwrap();
    sleep_past_grace().await;
    for s in [Step::Claim, Step::Confirm] {
        step(&f.db.0, &f.c.scope, &pa.revision, s).await.unwrap();
    }
    let pa_rev_path = f.root.join("revisions").join(&pa.reservation);
    let pa_anchor_path = f
        .root
        .join("revisions")
        .join(format!(".purge.{}", pa.reservation));
    fs::OpenOptions::new()
        .write(true)
        .open(&pa_rev_path)
        .unwrap()
        .set_len(0)
        .unwrap();
    fs::rename(&pa_rev_path, &pa_anchor_path).unwrap();
    let purge_stage = async |rev: &str| -> String {
        sqlx::query_scalar(
            "SELECT purge_stage FROM openmettle.artifact_revisions WHERE id = $1::uuid",
        )
        .bind(rev)
        .fetch_one(&mut f.db.admin().await)
        .await
        .unwrap()
    };
    assert_eq!(purge_stage(&pa.revision).await, "anchor_pending_unlink");

    let (head_seq, head_digest): (i64, String) = sqlx::query_as(
        "SELECT journal_seq, encode(chain_digest, 'hex') FROM openmettle.deletion_journal_head WHERE id",
    )
    .fetch_one(&owner)
    .await
    .unwrap();
    restore::lock(
        &owner,
        origin,
        lc_origin,
        head_seq,
        &head_digest,
        true,
        None,
        true,
    )
    .await
    .unwrap();
    assert_eq!(
        artifact_fs::purge_due(&worker, &f.store, 10).await.unwrap(),
        0
    );
    assert!(
        pa_anchor_path.exists(),
        "live detach must not unlink .purge.<res> while restore gate is closed"
    );
    assert_eq!(purge_stage(&pa.revision).await, "anchor_pending_unlink");

    // Reopen the gate, pause live `detach` on `storage_volume_control FOR SHARE` right after it
    // acquires `restore_gate_lock_open()` (`FOR SHARE`), and verify `restore_gate_lock` blocks on
    // the live `detach` transaction until `detach` finishes and commits.
    sqlx::query(
        "SELECT openmettle.restore_gate_open(
                    c.restore_run_id,
                    c.volume_claim_token,
                    $1,
                    $2,
                    decode($3, 'hex'),
                    (SELECT volume_id FROM openmettle.storage_volume_control WHERE id),
                    $4
                )
           FROM openmettle.restore_claim_volume_phase($1, $2, decode($3, 'hex'), $4) c",
    )
    .bind(origin)
    .bind(head_seq)
    .bind(&head_digest)
    .bind(lc_origin)
    .execute(&owner)
    .await
    .unwrap();

    let mut vol_conn = connect(&f.db.0, OWNER).await;
    let vol_holder = pid(&mut vol_conn).await;
    let mut vol_tx = vol_conn.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.storage_volume_control WHERE id FOR UPDATE")
        .execute(&mut *vol_tx)
        .await
        .unwrap();

    let detaching = tokio::spawn({
        let worker = worker.clone();
        let store = f.store.clone();
        async move { artifact_fs::purge_due(&worker, &store, 10).await }
    });
    let detach_pid = waiter_on(&f.db, vol_holder).await;

    let relocking = tokio::spawn({
        let owner = owner.clone();
        let head_digest = head_digest.clone();
        async move {
            restore::lock(
                &owner,
                origin,
                lc_origin,
                head_seq,
                &head_digest,
                true,
                None,
                true,
            )
            .await
        }
    });
    wait_for_blocked_peer(&f.db, detach_pid).await;

    vol_tx.rollback().await.unwrap();
    assert_eq!(detaching.await.unwrap().unwrap(), 0);
    relocking.await.unwrap().unwrap();
    assert!(!pa_anchor_path.exists());
    assert_eq!(purge_stage(&pa.revision).await, "none");
    assert!(!gate(&f.db).await.0);
}

/// Review #2 P2 #6 regression: an unrelated file (distinct inode) at `staging/<reservation_id>`
/// must not block purging the bound revision inode in `revisions/<reservation_id>` and must be
/// left untouched on disk.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn purge_leaves_unrelated_staging_inode_untouched_while_refusing_foreign_hard_link() {
    let f = Fixture::new().await;
    let worker = pool(&f.db, WORKER).await;
    let p = f.payload("staging-sibling", b"revision-payload").await;
    step(&f.db.0, &f.c.scope, &p.revision, Step::Retain)
        .await
        .unwrap();
    sleep_past_grace().await;

    let rev_path = f.root.join("revisions").join(&p.reservation);
    let staging_path = f.root.join("staging").join(&p.reservation);
    fs::write(&staging_path, b"unrelated-staging-file").unwrap();
    assert_ne!(
        fs::metadata(&staging_path).unwrap().ino(),
        fs::metadata(&rev_path).unwrap().ino()
    );

    assert_eq!(
        artifact_fs::purge_due(&worker, &f.store, 10).await.unwrap(),
        1
    );
    assert_eq!(state(&f.db, &p.revision).await.0, "purged");
    assert!(!rev_path.exists());
    assert_eq!(fs::read(&staging_path).unwrap(), b"unrelated-staging-file");
}

/// Review #2 P2 #7 regression: transactions spanning synchronous filesystem I/O (`purge_journaled`,
/// `scrub_unsettled_on_restore`, and `restore::finish`'s `tx_pin`) set `SET LOCAL
/// idle_in_transaction_session_timeout = '300s'`, so a strict database/session default
/// (`10ms`) cannot drop the fencing locks prematurely.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn fs_io_transactions_override_short_session_idle_in_transaction_timeout() {
    let f = Fixture::new().await;
    let p = f
        .payload("idle-timeout-purge", b"purge-payload")
        .await
        .revision;
    step(&f.db.0, &f.c.scope, &p, Step::Retain).await.unwrap();
    sleep_past_grace().await;
    let _u = seed_unsettled_upload(&f, "idle-timeout-scrub", b"scrub-payload", true).await;
    f.api.close().await;

    let restored = backup(&f.db).await;
    for s in [Step::Claim, Step::Confirm] {
        step(&f.db.0, &f.c.scope, &p, s).await.unwrap();
    }
    let export = Export::parse(&restore::export(&pool(&f.db, OWNER).await).await.unwrap()).unwrap();

    // Configure an aggressively short database-level idle-in-transaction timeout (10 ms) before
    // opening the owner pool so every connection starts with `idle_in_transaction_session_timeout = 10ms`.
    restored
        .admin()
        .await
        .execute(AssertSqlSafe(format!(
            "ALTER DATABASE {} SET idle_in_transaction_session_timeout = '10ms'",
            restored.0
        )))
        .await
        .unwrap();
    let short_owner = pool(&restored, OWNER).await;
    let configured: String = sqlx::query_scalar("SHOW idle_in_transaction_session_timeout")
        .fetch_one(&short_owner)
        .await
        .unwrap();
    assert_eq!(configured, "10ms");

    restore::lock(
        &short_owner,
        export.origin_us,
        export.lifecycle_origin_us,
        export.seq,
        &export.digest,
        true,
        None,
        true,
    )
    .await
    .unwrap();
    assert_eq!(restore::apply(&short_owner, &export).await.unwrap(), 1);
    restore::finish(&short_owner, Some(&f.store), &export)
        .await
        .unwrap();
    assert!(gate(&restored).await.0);
    assert_eq!(state(&restored, &p).await.0, "purged");
}

/// Review #4 P2 #1 regression: `verify_volume_on` runs `SELECT 1` on `tx_pin` at elapsed-time
/// checkpoints during synchronous per-row and directory-entry scans, keeping Backend 1 non-idle
/// across a scan longer than `idle_in_transaction_session_timeout` with zero `by_id` fallbacks.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn verify_volume_keepalive_prevents_idle_in_transaction_timeout_during_slow_fs_scan() {
    let f = Fixture::new().await;
    for i in 0..8usize {
        f.payload(&format!("keepalive-{i}"), b"ok").await;
    }
    // Add skipped `.openmettle-volume-id.tmp.*` entries so the directory-entry scan loop also
    // runs >250 ms synchronously without issuing `by_id` SQL queries.
    for i in 0..10usize {
        let tmp = f
            .root
            .join("revisions")
            .join(format!(".openmettle-volume-id.tmp.{i:032x}"));
        fs::write(&tmp, b"").unwrap();
    }
    let pin: String = sqlx::query_scalar(
        "SELECT volume_id::text FROM openmettle.storage_volume_control WHERE id",
    )
    .fetch_one(&mut f.db.admin().await)
    .await
    .unwrap();

    // Negative control: with `yield_interval = None` (no `SELECT 1` keepalive), a 35 ms/item
    // synchronous FS scan (~600+ ms total) exceeds the 250 ms `idle_in_transaction_session_timeout`
    // and PostgreSQL terminates the transaction.
    let mut conn_no_keepalive = connect(&f.db.0, OWNER).await;
    let mut tx_no_keepalive = conn_no_keepalive.begin().await.unwrap();
    sqlx::query("SET LOCAL idle_in_transaction_session_timeout = '250ms'")
        .execute(&mut *tx_no_keepalive)
        .await
        .unwrap();
    let failed = artifact_fs::verify_volume_for_test(
        &mut tx_no_keepalive,
        &f.store,
        &pin,
        None,
        Some(Duration::from_millis(35)),
    )
    .await;
    let commit_after_fail = if failed.is_ok() {
        tx_no_keepalive.commit().await.err()
    } else {
        None
    };
    assert!(
        failed.is_err() || commit_after_fail.is_some(),
        "expected 250ms idle_in_transaction_session_timeout to abort slow scan without keepalive"
    );

    // Positive check: with `yield_interval = Some(40ms)`, `SELECT 1` runs every ~70 ms during both
    // the row scan and the directory scan (>600 ms total), keeping `tx_pin` alive and healthy.
    let mut conn_keepalive = connect(&f.db.0, OWNER).await;
    let mut tx_keepalive = conn_keepalive.begin().await.unwrap();
    sqlx::query("SET LOCAL idle_in_transaction_session_timeout = '250ms'")
        .execute(&mut *tx_keepalive)
        .await
        .unwrap();
    let started = Instant::now();
    let drift = artifact_fs::verify_volume_for_test(
        &mut tx_keepalive,
        &f.store,
        &pin,
        Some(Duration::from_millis(40)),
        Some(Duration::from_millis(35)),
    )
    .await
    .unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(400),
        "expected scan to span >400 ms, took {:?}",
        started.elapsed()
    );
    assert!(drift.healthy() && drift.unsettled_payloads == 0);
    tx_keepalive.commit().await.unwrap();
}

/// Review #4 P2 #2 regression: if heartbeat renewal fails (`OMR02`) while `tx_pin` is blocked in
/// `verify_ledgers_on`, `with_volume_phase_heartbeat` cancels Backend 1's query and `finish`
/// synchronously rolls back `tx_pin` BEFORE returning so `storage_volume_control FOR SHARE` is
/// already released even while the external table lock remains held.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn heartbeat_renewal_failure_cancels_tx_pin_and_releases_volume_lock_synchronously() {
    let db = TestDb::migrated().await;
    let owner = pool(&db, OWNER).await;
    let export = Export::parse(&restore::export(&owner).await.unwrap()).unwrap();
    restore::lock(
        &owner,
        export.origin_us,
        export.lifecycle_origin_us,
        0,
        GENESIS,
        true,
        None,
        true,
    )
    .await
    .unwrap();

    let mut blocker = connect(&db.0, OWNER).await;
    let blocker_pid = pid(&mut blocker).await;
    let mut blocker_tx = blocker.begin().await.unwrap();
    sqlx::query("LOCK TABLE openmettle.storage_accounts IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker_tx)
        .await
        .unwrap();

    let finishing = tokio::spawn({
        let owner = owner.clone();
        let export = export.clone();
        async move {
            restore::finish_with_heartbeat(&owner, None, &export, Duration::from_millis(60)).await
        }
    });
    wait_for_blocked_peer(&db, blocker_pid).await;

    // Confirm `tx_pin` is actively holding `storage_volume_control FOR SHARE` right now.
    let mut probe = connect(&db.0, OWNER).await;
    let mut probe_tx = probe.begin().await.unwrap();
    let blocked_rebind = sqlx::query(
        "SELECT volume_id FROM openmettle.storage_volume_control WHERE id FOR UPDATE NOWAIT",
    )
    .execute(&mut *probe_tx)
    .await;
    assert_eq!(sqlstate(blocked_rebind), "55P03");
    probe_tx.rollback().await.unwrap();

    // Expire the volume-phase lease on an external connection so the next 60 ms heartbeat tick
    // fails with `OMR02`.
    sqlx::query(
        "UPDATE openmettle.restore_reconciliation_gate
            SET volume_lease_until = clock_timestamp() - interval '1 second'
          WHERE id",
    )
    .execute(&mut db.admin().await)
    .await
    .unwrap();

    let err = tokio::time::timeout(Duration::from_secs(5), finishing)
        .await
        .expect("finish_with_heartbeat must abort promptly on heartbeat failure")
        .unwrap()
        .unwrap_err();
    assert_eq!(sqlstate_of(err), "OMR02");

    // IMMEDIATELY — while `blocker_tx` STILL holds `ACCESS EXCLUSIVE` on `storage_accounts` —
    // `storage_volume_control FOR UPDATE NOWAIT` must succeed without waiting!
    let mut rebind_probe_tx = probe.begin().await.unwrap();
    let vol: Option<String> = sqlx::query_scalar(
        "SELECT volume_id::text FROM openmettle.storage_volume_control WHERE id FOR UPDATE NOWAIT",
    )
    .fetch_one(&mut *rebind_probe_tx)
    .await
    .expect("tx_pin must have released storage_volume_control FOR SHARE before finish returned");
    assert!(vol.is_none());
    rebind_probe_tx.rollback().await.unwrap();
    assert!(!gate(&db).await.0);

    blocker_tx.rollback().await.unwrap();

    // Review #5 P2 regression: if `pool.close()` begins while `tx_pin` is blocked on
    // `storage_accounts`, pool-independent cancellation via `pool.connect_options()` aborts
    // Backend 1 promptly (well under 5 s), rolls back `tx_pin` synchronously, lets `pool.close()`
    // finish promptly, and releases `storage_volume_control FOR SHARE` while `storage_accounts`
    // remains locked.
    let closing_pool = pool(&db, OWNER).await;
    let mut blocker2 = connect(&db.0, OWNER).await;
    let blocker2_pid = pid(&mut blocker2).await;
    let mut blocker2_tx = blocker2.begin().await.unwrap();
    sqlx::query("LOCK TABLE openmettle.storage_accounts IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker2_tx)
        .await
        .unwrap();

    let finishing2 = tokio::spawn({
        let closing_pool = closing_pool.clone();
        let export = export.clone();
        async move {
            restore::finish_with_heartbeat(&closing_pool, None, &export, Duration::from_secs(60))
                .await
        }
    });
    wait_for_blocked_peer(&db, blocker2_pid).await;

    let mut probe2_tx = probe.begin().await.unwrap();
    let blocked_rebind2 = sqlx::query(
        "SELECT volume_id FROM openmettle.storage_volume_control WHERE id FOR UPDATE NOWAIT",
    )
    .execute(&mut *probe2_tx)
    .await;
    assert_eq!(sqlstate(blocked_rebind2), "55P03");
    probe2_tx.rollback().await.unwrap();

    let close_started = Instant::now();
    let closing = tokio::spawn({
        let closing_pool = closing_pool.clone();
        async move {
            closing_pool.close().await;
        }
    });

    let err2 = tokio::time::timeout(Duration::from_secs(3), finishing2)
        .await
        .expect("finish_with_heartbeat must abort promptly on pool.close()")
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(err2, restore::Error::Database(sqlx::Error::PoolClosed)),
        "expected PoolClosed error on pool.close(), got {err2:?}"
    );
    tokio::time::timeout(Duration::from_secs(3), closing)
        .await
        .expect("pool.close() must complete promptly after tx_pin rolls back")
        .unwrap();
    assert!(
        close_started.elapsed() < Duration::from_secs(3),
        "pool.close() cleanup should not hit 5 s timeouts, took {:?}",
        close_started.elapsed()
    );

    // BEFORE releasing `blocker2_tx`, `storage_volume_control FOR UPDATE NOWAIT` must succeed!
    let mut rebind_probe2_tx = probe.begin().await.unwrap();
    let vol2: Option<String> = sqlx::query_scalar(
        "SELECT volume_id::text FROM openmettle.storage_volume_control WHERE id FOR UPDATE NOWAIT",
    )
    .fetch_one(&mut *rebind_probe2_tx)
    .await
    .expect("tx_pin must release storage_volume_control FOR SHARE before pool.close() returns");
    assert!(vol2.is_none());
    rebind_probe2_tx.rollback().await.unwrap();
    assert!(!gate(&db).await.0);

    blocker2_tx.rollback().await.unwrap();
}

/// ADR 0041 PR3: replaying an exported deletion journal over an older backup preserves every
/// disassociated revision's original deadline (without restarting the grace window), re-applies
/// admin deadline adjustments and pre-expiry restores (including repeated retain -> restore
/// cycles), reconciles storage counters identically, and purges terminal purged revisions once.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn replay_preserves_disassociated_deadlines_admin_adjustments_and_pre_expiry_restores() {
    let f = Fixture::new().await;
    let mut live_owner = connect(&f.db.0, OWNER).await;
    authz_store::providers(&mut live_owner).await;
    let admin = authz_store::account(
        &mut live_owner,
        authz_store::PROVIDER,
        true,
        authz_store::FUTURE,
    )
    .await;
    authz_store::make_admin(&mut live_owner, &admin).await;
    sqlx::query(
        "UPDATE openmettle.retention_policy
            SET min_grace_seconds = 0, max_grace_seconds = 31536000, grace_seconds = 3600
          WHERE id",
    )
    .execute(&mut live_owner)
    .await
    .unwrap();

    let kept_active = f.payload("kept-active", b"kept-active").await;
    let disassociated = f.payload("disassociated", b"disassociated-bytes").await;
    let adjusted = f.payload("adjusted", b"adjusted-bytes").await;
    let restored_rev = f.payload("restored-rev", b"restored-bytes").await;
    let purged_rev = f.payload("purged-rev", b"purged-bytes").await;
    drop(live_owner);
    f.api.close().await;

    // Backup while all 5 revisions are active and deletion_journal is at seq 0.
    let restored = backup(&f.db).await;

    // 1. Disassociate two revisions under the 3600s grace window.
    step(&f.db.0, &f.c.scope, &disassociated.revision, Step::Retain)
        .await
        .unwrap();
    step(&f.db.0, &f.c.scope, &adjusted.revision, Step::Retain)
        .await
        .unwrap();

    // 2. Audited policy update to 120s and explicit deadline adjustment on retained revisions.
    let mut live_api = connect(&f.db.0, API).await;
    let rev_120: i64 = sqlx::query_scalar(
        "SELECT openmettle.retention_set_grace($1::uuid, $2::uuid, 120, 'shorten', 'pr3-120')",
    )
    .bind(&admin.user)
    .bind(&admin.approval)
    .fetch_one(&mut live_api)
    .await
    .unwrap();
    let (affected_revs, affected_bytes, applied_rev): (i64, i64, i64) = sqlx::query_as(
        "SELECT affected_revisions, affected_bytes, policy_revision
           FROM openmettle.retention_apply_deadlines($1::uuid, $2::uuid, $3, 120, $4::uuid, 'apply-120', 'pr3-apply-120')",
    )
    .bind(&admin.user)
    .bind(&admin.approval)
    .bind(rev_120)
    .bind(&f.c.scope)
    .fetch_one(&mut live_api)
    .await
    .unwrap();
    assert_eq!(affected_revs, 2);
    assert_eq!(
        affected_bytes,
        (b"disassociated-bytes".len() + b"adjusted-bytes".len()) as i64
    );
    assert_eq!(applied_rev, rev_120);

    // 3. Retain and pre-expiry restore `restored_rev` TWICE (verifying non-unique lifecycle rows).
    for _ in 0..2 {
        step(&f.db.0, &f.c.scope, &restored_rev.revision, Step::Retain)
            .await
            .unwrap();
        step(&f.db.0, &f.c.scope, &restored_rev.revision, Step::Restore)
            .await
            .unwrap();
    }

    // 4. Set grace to 0, retain and purge `purged_rev` so all 4 event kinds appear in one chain.
    let rev_zero: i64 = sqlx::query_scalar(
        "SELECT openmettle.retention_set_grace($1::uuid, $2::uuid, 0, 'zero', 'pr3-zero')",
    )
    .bind(&admin.user)
    .bind(&admin.approval)
    .fetch_one(&mut live_api)
    .await
    .unwrap();
    for s in [Step::Retain, Step::Claim, Step::Confirm] {
        step(&f.db.0, &f.c.scope, &purged_rev.revision, s)
            .await
            .unwrap();
    }
    drop(live_api);

    // Wait so any accidental grace-window restart on replay would visibly shift timestamps.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_chain(&f.db).await;

    let dir = Dir::new();
    let file = dir.path("lifecycle.export");
    let (ok, _, err) = cli(&f.db, &["journal", "export", &file]);
    assert!(ok, "{err}");
    let text = fs::read_to_string(&file).unwrap();
    let export = Export::parse(&text).unwrap();
    // 2 retained + 2 deadline_adjusted + 2*(retained+restored) + 1 retained + 1 purged = 10 records.
    assert_eq!(export.seq, 10);

    // Lock and replay over the older backup.
    let origin_str = export.origin_us.to_string();
    let lc_origin_str = export.lifecycle_origin_us.unwrap().to_string();
    let seq_str = export.seq.to_string();
    let (ok, _, err) = cli(
        &restored,
        &[
            "restore",
            "lock",
            "--required-origin",
            &origin_str,
            "--required-lifecycle-origin",
            &lc_origin_str,
            "--required-seq",
            &seq_str,
            "--required-digest",
            &export.digest,
            "--export-complete",
        ],
    );
    assert!(ok, "{err}");
    let root = f.root.to_str().unwrap();
    let (ok, out, err) = cli(&restored, &["restore", "replay", &file, root]);
    assert!(ok, "{err}");
    assert_eq!(out, "replayed 10 records through 10; restore gate open\n");
    assert!(gate(&restored).await.0);

    // Verify exact revision states, timestamps, policy revisions, storage counters, and payloads.
    let detail =
        async |db: &TestDb, rev: &str| -> (String, Option<String>, Option<String>, Option<i64>) {
            sqlx::query_as(
                "SELECT state, retained_at::text, purge_after::text, retention_policy_revision
               FROM openmettle.artifact_revisions WHERE id = $1::uuid",
            )
            .bind(rev)
            .fetch_one(&mut db.admin().await)
            .await
            .unwrap()
        };
    for rev in [
        &kept_active.revision,
        &disassociated.revision,
        &adjusted.revision,
        &restored_rev.revision,
        &purged_rev.revision,
    ] {
        assert_eq!(
            detail(&restored, rev).await,
            detail(&f.db, rev).await,
            "{rev}"
        );
    }
    assert_eq!(
        detail(&restored, &disassociated.revision).await.0,
        "retained"
    );
    assert_eq!(detail(&restored, &adjusted.revision).await.0, "retained");
    assert_eq!(detail(&restored, &restored_rev.revision).await.0, "active");
    assert_eq!(detail(&restored, &purged_rev.revision).await.0, "purged");
    assert_eq!(detail(&restored, &kept_active.revision).await.0, "active");

    assert_eq!(
        account(&restored, &f.c.scope).await,
        account(&f.db, &f.c.scope).await
    );
    assert_eq!(journal(&restored).await, journal(&f.db).await);
    assert_chain(&restored).await;
    assert_totals(&restored).await;
    assert!(
        !f.root
            .join("revisions")
            .join(&purged_rev.reservation)
            .exists()
    );
    assert_eq!(
        fs::read(f.root.join("revisions").join(&restored_rev.reservation)).unwrap(),
        b"restored-bytes"
    );
    let post_policy_rev: i64 =
        sqlx::query_scalar("SELECT revision FROM openmettle.retention_policy WHERE id")
            .fetch_one(&mut restored.admin().await)
            .await
            .unwrap();
    assert!(
        post_policy_rev > rev_zero,
        "expected policy revision > {rev_zero}, got {post_policy_rev}"
    );
}

/// Review #1 P1 #1 regression: a schema-41 backup predating migration 42's lifecycle journaling
/// cannot assert `--export-complete` (`OMR04`) and cannot open the gate without an audited
/// `'operator'` `restore.accept_coverage_gap` row, even when `coverage_started_at` matches.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn schema_41_backup_with_untracked_disassociation_fails_complete_and_requires_gap_acceptance()
{
    let live = TestDb::new().await;
    let settings = live.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..41]).await.unwrap();
    configure(&live, Some(1000), Some(1000), Some(1000)).await;
    retention_grace(&live, 3600).await;
    let c = Context::new(&live).await;
    let doc = new_uuid(&live).await;
    // On schema 41, openmettle_api lacks EXECUTE on restore_gate_lock_open() and fails closed
    // (P1 #3); seed the pre-42 revision and disassociation as OWNER to simulate a pre-42 workload.
    assert!(
        reserve(
            &live,
            API,
            &input(&c.scope, &c.actor, "pre42-api-refused", &doc, 10)
        )
        .await
        .is_err()
    );
    let r = reserve(&live, OWNER, &input(&c.scope, &c.actor, "pre42", &doc, 10))
        .await
        .unwrap();
    let mut live_owner = connect(&live.0, OWNER).await;
    crate::mark_storage_payload_published(&mut live_owner, &r.id).await;
    let mut settle_tx = WriteTransaction::begin(&mut live_owner).await.unwrap();
    let digest = Sha256::digest(b"pre42-data").to_vec();
    let rev = openmettle_core::storage::settle(
        &mut settle_tx,
        &openmettle_core::storage::Settlement {
            scope: &c.scope,
            reservation: &r.id,
            size_bytes: 10,
            content_digest: &digest,
            media_type: "text/plain",
            display_name: None,
        },
    )
    .await
    .unwrap();
    settle_tx.commit().await.unwrap();
    live_owner.close().await.unwrap();
    // Capture backup at schema 41 while revision is still active.
    let pre42_backup = backup(&live).await;

    // Disassociate on schema 41 (NOT journaled before migration 42), then upgrade live to 42.
    let mut live_owner = connect(&live.0, OWNER).await;
    let mut retain_tx = WriteTransaction::begin(&mut live_owner).await.unwrap();
    openmettle_core::storage::retain_revision(&mut retain_tx, &c.scope, &rev)
        .await
        .unwrap();
    retain_tx.commit().await.unwrap();
    live_owner.close().await.unwrap();
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert!(journal(&live).await.is_empty());
    let export = Export::parse(&restore::export(&pool(&live, OWNER).await).await.unwrap()).unwrap();
    assert!(export.lifecycle_origin_us.is_some());

    // Migrate the schema-41 backup to 42 after a clock tick: same coverage_started_at, distinct
    // lifecycle_coverage_started_at.
    tokio::time::sleep(Duration::from_millis(20)).await;
    migrate::apply(&pre42_backup.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    assert_eq!(origin_of(&pre42_backup).await, export.origin_us);
    assert_ne!(
        lifecycle_origin_of(&pre42_backup).await,
        export.lifecycle_origin_us
    );

    let owner = pool(&pre42_backup, OWNER).await;
    // Asserting complete coverage on a pre-42 backup fails closed with OMR04.
    assert_eq!(
        sqlstate_of(
            restore::lock(
                &owner,
                export.origin_us,
                export.lifecycle_origin_us,
                export.seq,
                &export.digest,
                true,
                None,
                true,
            )
            .await
            .unwrap_err()
        ),
        "OMR04"
    );
    // Locking with coverage_complete = false succeeds and replay completes the DB phase, but
    // opening the gate stays blocked with OMR04 until audited restore.accept_coverage_gap runs.
    let locked = restore::lock(
        &owner,
        export.origin_us,
        export.lifecycle_origin_us,
        export.seq,
        &export.digest,
        false,
        None,
        true,
    )
    .await
    .unwrap();
    assert_eq!(restore::apply(&owner, &export).await.unwrap(), 0);
    let open_without_gap = sqlx::query(
        "SELECT openmettle.restore_gate_open(
                    c.restore_run_id,
                    c.volume_claim_token,
                    $1,
                    $2,
                    decode($3, 'hex'),
                    (SELECT volume_id FROM openmettle.storage_volume_control WHERE id),
                    $4
                )
           FROM openmettle.restore_claim_volume_phase($1, $2, decode($3, 'hex'), $4) c",
    )
    .bind(export.origin_us)
    .bind(export.seq)
    .bind(&export.digest)
    .bind(export.lifecycle_origin_us)
    .execute(&owner)
    .await;
    assert_eq!(sqlstate(open_without_gap), "OMR04");
    assert!(!gate(&pre42_backup).await.0);

    // Even if coverage_complete were manually flipped true without an operator audit row,
    // restore_gate_open still refuses with OMR04 because lifecycle_origin differs.
    sqlx::query(
        "UPDATE openmettle.restore_reconciliation_gate SET coverage_complete = true WHERE id",
    )
    .execute(&owner)
    .await
    .unwrap();
    let open_without_audit = sqlx::query(
        "SELECT openmettle.restore_gate_open(
                    c.restore_run_id,
                    c.volume_claim_token,
                    $1,
                    $2,
                    decode($3, 'hex'),
                    (SELECT volume_id FROM openmettle.storage_volume_control WHERE id),
                    $4
                )
           FROM openmettle.restore_claim_volume_phase($1, $2, decode($3, 'hex'), $4) c",
    )
    .bind(export.origin_us)
    .bind(export.seq)
    .bind(&export.digest)
    .bind(export.lifecycle_origin_us)
    .execute(&owner)
    .await;
    assert_eq!(sqlstate(open_without_audit), "OMR04");
    assert!(!gate(&pre42_backup).await.0);

    // Recording audited restore.accept_coverage_gap lets restore_gate_open succeed.
    sqlx::query(
        "UPDATE openmettle.restore_reconciliation_gate SET coverage_complete = false WHERE id",
    )
    .execute(&owner)
    .await
    .unwrap();
    let operator = new_uuid(&pre42_backup).await;
    assert!(
        restore::accept_coverage_gap(
            &owner,
            &locked.restore_run_id,
            &operator,
            "pre42-schema41-gap",
            "schema-41 backup audited for untracked pre-42 disassociations",
        )
        .await
        .unwrap()
    );
    sqlx::query(
        "SELECT openmettle.restore_gate_open(
                    c.restore_run_id,
                    c.volume_claim_token,
                    $1,
                    $2,
                    decode($3, 'hex'),
                    (SELECT volume_id FROM openmettle.storage_volume_control WHERE id),
                    $4
                )
           FROM openmettle.restore_claim_volume_phase($1, $2, decode($3, 'hex'), $4) c",
    )
    .bind(export.origin_us)
    .bind(export.seq)
    .bind(&export.digest)
    .bind(export.lifecycle_origin_us)
    .execute(&owner)
    .await
    .unwrap();
    assert!(gate(&pre42_backup).await.0);
}

/// Review #1 P1 #2 regression: setting `openmettle.replaying_deletion_journal = 'on'` in an
/// `openmettle_api` session before calling `SECURITY DEFINER` `retention_apply_deadlines`, OR in
/// an `openmettle_owner` session while the restore gate is open, MUST NOT suppress lifecycle
/// journal appends or deadline stamping.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn api_session_replay_guc_cannot_suppress_lifecycle_journal_on_deadline_adjustments() {
    let f = Fixture::new().await;
    let mut owner = connect(&f.db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let admin =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, authz_store::FUTURE).await;
    authz_store::make_admin(&mut owner, &admin).await;
    sqlx::query(
        "UPDATE openmettle.retention_policy
            SET min_grace_seconds = 0, max_grace_seconds = 86400, grace_seconds = 3600
          WHERE id",
    )
    .execute(&mut owner)
    .await
    .unwrap();

    let rev1 = f.payload("guc-api", b"guc-api-bytes").await.revision;
    let rev2 = f.payload("guc-owner", b"guc-owner-bytes").await.revision;
    step(&f.db.0, &f.c.scope, &rev1, Step::Retain)
        .await
        .unwrap();
    assert_eq!(journal(&f.db).await.len(), 1);

    let mut api = connect(&f.db.0, API).await;
    sqlx::query("SET openmettle.replaying_deletion_journal = 'on'")
        .execute(&mut api)
        .await
        .unwrap();
    let policy_rev: i64 =
        sqlx::query_scalar("SELECT revision FROM openmettle.retention_policy WHERE id")
            .fetch_one(&mut owner)
            .await
            .unwrap();
    let (affected, _, _): (i64, i64, i64) = sqlx::query_as(
        "SELECT affected_revisions, affected_bytes, policy_revision
           FROM openmettle.retention_apply_deadlines(
               $1::uuid, $2::uuid, $3, 120, $4::uuid, 'guc-check', 'guc-apply-1'
           )",
    )
    .bind(&admin.user)
    .bind(&admin.approval)
    .bind(policy_rev)
    .bind(&f.c.scope)
    .fetch_one(&mut api)
    .await
    .unwrap();
    assert_eq!(affected, 1);
    let kinds: Vec<String> = sqlx::query_scalar(
        "SELECT event_kind FROM openmettle.deletion_journal ORDER BY journal_seq",
    )
    .fetch_all(&mut owner)
    .await
    .unwrap();
    assert_eq!(
        kinds,
        vec![
            "artifact_revision.retained",
            "artifact_revision.deadline_adjusted"
        ]
    );

    // Even as openmettle_owner while the restore gate is OPEN, setting the replay GUC must not
    // suppress either deadline stamping or lifecycle journal appends.
    sqlx::query("SET openmettle.replaying_deletion_journal = 'on'")
        .execute(&mut owner)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE openmettle.artifact_revisions
            SET state = 'retained', retained_at = NULL, purge_after = NULL,
                retention_policy_revision = NULL
          WHERE id = $1::uuid",
    )
    .bind(&rev2)
    .execute(&mut owner)
    .await
    .unwrap();
    let (st, deadline) = state(&f.db, &rev2).await;
    assert_eq!(st, "retained");
    assert!(deadline.is_some());
    assert_eq!(journal(&f.db).await.len(), 3);
    assert_chain(&f.db).await;
}

/// Review #1 P1 #3 regression: on a schema-41 database (where `restore_reconciliation_gate` exists
/// but migration 42 has not yet granted `EXECUTE` on `restore_gate_lock_open()` to `openmettle_api`),
/// `openmettle_api` storage operations fail closed instead of treating the gate as open.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn lock_open_gate_fails_closed_for_api_role_on_schema_41() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..41]).await.unwrap();
    configure(&db, Some(1000), Some(1000), Some(1000)).await;
    let c = Context::new(&db).await;
    let origin = origin_of(&db).await;

    // Close the restore gate on schema 41 using migration 41's 6-arg restore_gate_lock.
    let mut owner = connect(&db.0, OWNER).await;
    sqlx::query(
        "SELECT openmettle.restore_gate_lock($1, 0, decode(repeat('00', 32), 'hex'), true)",
    )
    .bind(origin)
    .execute(&mut owner)
    .await
    .unwrap();
    drop(owner);

    // As openmettle_api on schema 41, reserve() calls restore::lock_open_gate and MUST fail closed
    // with 42501 instead of silently returning Ok(true).
    let doc = new_uuid(&db).await;
    let err = reserve(&db, API, &input(&c.scope, &c.actor, "s41-closed", &doc, 10))
        .await
        .unwrap_err();
    assert_eq!(code(&err), "42501");

    // After applying migration 42 while the gate is still closed, reserve() fails closed with
    // Protocol("restore reconciliation pending").
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    let err_42 = reserve(&db, API, &input(&c.scope, &c.actor, "s42-closed", &doc, 10))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err_42,
            openmettle_core::runs::Error::Database(sqlx::Error::Protocol(_))
        ),
        "expected closed-gate Protocol refusal on schema 42, got {err_42:?}"
    );
}

/// Review #1 P1 #4 deterministic mid-stream cutoff regression: `Store::read_gated_for_test`
/// verifies `restore::lock_open_gate` before each 64 KiB chunk, aborts immediately once the gate
/// closes after chunk 1, and drops the payload `File` so an exclusive `try_lock` succeeds at once.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn gated_download_stream_aborts_mid_stream_and_releases_lock_when_gate_closes() {
    use http_body_util::BodyExt;

    let f = Fixture::new().await;
    configure(&f.db, Some(1_000_000), Some(1_000_000), Some(1_000_000)).await;
    let payload = vec![b'X'; 192 * 1024];
    let stored = f.payload_sized("large-dl", &payload, 256 * 1024).await;
    let api_pool = pool(&f.db, API).await;
    let mut conn = api_pool.acquire().await.unwrap();
    let mut content = f
        .store
        .read_gated_for_test(
            &mut conn,
            api_pool.clone(),
            &stored.reservation,
            payload.len() as i64,
            0,
            payload.len() as u64,
        )
        .await
        .unwrap();
    drop(conn);

    // Chunk 1 succeeds while the gate is open, and payload file currently holds LOCK_SH.
    let first = content.frame().await.unwrap().unwrap().into_data().unwrap();
    assert_eq!(first.len(), 64 * 1024);
    let rev_path = f.root.join("revisions").join(&stored.reservation);
    let probe = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&rev_path)
        .unwrap();
    assert!(
        probe.try_lock().is_err(),
        "active gated download must hold LOCK_SH while streaming"
    );

    // Close the restore gate mid-stream.
    let owner = pool(&f.db, OWNER).await;
    let origin = origin_of(&f.db).await;
    let lc_origin = lifecycle_origin_of(&f.db).await;
    restore::lock(&owner, origin, lc_origin, 0, GENESIS, true, None, true)
        .await
        .unwrap();

    // Chunk 2 immediately fails closed with "restore reconciliation pending" and drops LOCK_SH.
    let second = content.frame().await.unwrap().unwrap_err();
    assert!(
        second
            .to_string()
            .contains("restore reconciliation pending"),
        "{second}"
    );
    probe
        .try_lock()
        .expect("mid-stream gate cutoff must release LOCK_SH immediately");
}

/// Review #1 P1 #6 regression: a closed restore gate rejects settled upload retries in
/// `storage::settle` AND fences an in-flight upload's publish (`linkat` into `revisions/`) against
/// `restore_gate_lock`.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn closed_gate_rejects_settled_upload_replay_and_fences_in_flight_publish() {
    use axum::body::{Bytes, HttpBody};
    use hyper::body::Frame;
    use std::{
        convert::Infallible,
        pin::Pin,
        task::{Context as TaskContext, Poll},
    };
    use tokio::sync::mpsc;

    struct ChannelBody(mpsc::Receiver<Bytes>);
    impl HttpBody for ChannelBody {
        type Data = Bytes;
        type Error = Infallible;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            self.0
                .poll_recv(cx)
                .map(|item| item.map(|b| Ok(Frame::data(b))))
        }
    }

    let f = Fixture::new().await;
    let stored = f.payload("settled-replay", b"already-settled").await;
    let owner = pool(&f.db, OWNER).await;
    let origin = origin_of(&f.db).await;
    let lc_origin = lifecycle_origin_of(&f.db).await;

    // Part A: close gate and verify exact storage::settle replay on an already-settled reservation
    // fails closed with restore reconciliation pending.
    restore::lock(&owner, origin, lc_origin, 0, GENESIS, true, None, true)
        .await
        .unwrap();
    let mut api = connect(&f.db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut api).await.unwrap();
    let err = openmettle_core::storage::settle(
        &mut tx,
        &openmettle_core::storage::Settlement {
            scope: &f.c.scope,
            reservation: &stored.reservation,
            size_bytes: stored.size_bytes,
            content_digest: &stored.content_digest,
            media_type: "application/octet-stream",
            display_name: None,
        },
    )
    .await
    .unwrap_err();
    tx.rollback().await.unwrap();
    assert!(
        matches!(
            err,
            openmettle_core::runs::Error::Database(sqlx::Error::Protocol(_))
        ),
        "expected closed-gate refusal on settled upload replay, got {err:?}"
    );

    // Reopen gate for Part B.
    sqlx::query(
        "SELECT openmettle.restore_gate_open(
                    c.restore_run_id,
                    c.volume_claim_token,
                    $1,
                    0,
                    decode(repeat('00', 32), 'hex'),
                    (SELECT volume_id FROM openmettle.storage_volume_control WHERE id),
                    $2
                )
           FROM openmettle.restore_claim_volume_phase($1, 0, decode(repeat('00', 32), 'hex'), $2) c",
    )
    .bind(origin)
    .bind(lc_origin)
    .execute(&owner)
    .await
    .unwrap();

    // Part B: start an upload body that pauses mid-stream AFTER reservation + staging are created,
    // hold an uncommitted `restore_gate_lock`, finish sending the body so `ingest` reaches its
    // fenced publish transaction and blocks on `restore_reconciliation_gate`, then commit the gate
    // close and confirm `ingest` fails closed WITHOUT creating `revisions/<reservation_id>`.
    let (tx_body, rx_body) = mpsc::channel::<Bytes>(4);
    let boundary = "fence-publish-boundary";
    let head = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhello-"
    );
    let tail = format!(
        "world\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n{{}}\r\n--{boundary}--\r\n"
    );
    tx_body.send(Bytes::from(head)).await.unwrap();

    let doc = new_uuid(&f.db).await;
    let body = ChannelBody(rx_body);
    let ingest_task = tokio::spawn({
        let api_pool = f.api.clone();
        let store = f.store.clone();
        let scope = f.c.scope.clone();
        let actor = f.c.actor.clone();
        let doc = doc.clone();
        async move {
            let upload = openmettle_core::artifact_fs::Upload {
                scope: &scope,
                actor: &actor,
                key: "fenced-publish-key",
                artifact: &doc,
                max_bytes: 1024,
                content_type: &format!("multipart/form-data; boundary={boundary}"),
            };
            artifact_fs::ingest(&api_pool, &store, &upload, body, |_| true).await
        }
    });

    // Wait until reservation + payload_ino are committed by ingest.
    let res_id: String = loop {
        let found: Option<String> = sqlx::query_scalar(
            "SELECT id::text FROM openmettle.storage_reservations
              WHERE idempotency_key = 'fenced-publish-key' AND payload_ino IS NOT NULL",
        )
        .fetch_optional(&owner)
        .await
        .unwrap();
        if let Some(id) = found {
            break id;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };

    // Hold uncommitted restore_gate_lock, then finish the body so ingest enters its publish tx and
    // blocks on restore_reconciliation_gate FOR SHARE before file.publish().
    let mut closer = connect(&f.db.0, OWNER).await;
    let holder = pid(&mut closer).await;
    let mut close_tx = closer.begin().await.unwrap();
    sqlx::query(
        "SELECT openmettle.restore_gate_lock($1, 0, decode(repeat('00', 32), 'hex'), true, NULL, true, $2)",
    )
    .bind(origin)
    .bind(lc_origin)
    .execute(&mut *close_tx)
    .await
    .unwrap();

    tx_body.send(Bytes::from(tail)).await.unwrap();
    drop(tx_body);
    wait_for_blocked_peer(&f.db, holder).await;

    close_tx.commit().await.unwrap();
    let err = ingest_task.await.unwrap().unwrap_err();
    assert!(
        matches!(
            err,
            artifact_fs::Error::Storage(openmettle_core::runs::Error::Database(
                sqlx::Error::Protocol(_)
            ))
        ),
        "expected closed-gate Protocol error on fenced publish, got {err:?}"
    );
    assert!(
        !f.root.join("revisions").join(&res_id).exists(),
        "fenced publish must never link revisions/<res> after restore_gate_lock closes the gate"
    );
}

/// Review #1 P1 #8 regression: flushing `artifact_revisions_lifecycle_journal` via
/// `SET CONSTRAINTS ... IMMEDIATE` strictly before post-write authority rechecks ensures that if
/// an actor's approval expires while waiting on `deletion_journal_head FOR UPDATE`, both
/// `retention_apply_deadlines` AND `projects::delete_artifact_revision` roll back cleanly with
/// zero mutated revisions, zero audit rows, and zero appended journal rows.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn contended_deletion_journal_head_enforces_approval_expiry_before_commit() {
    let f = Fixture::new().await;
    let mut owner = connect(&f.db.0, OWNER).await;
    authz_store::providers(&mut owner).await;
    let now_ms: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut owner)
            .await
            .unwrap();
    let admin =
        authz_store::account(&mut owner, authz_store::PROVIDER, true, now_ms + 60_000).await;
    authz_store::make_admin(&mut owner, &admin).await;
    sqlx::query(
        "UPDATE openmettle.retention_policy
            SET min_grace_seconds = 0, max_grace_seconds = 86400, grace_seconds = 3600
          WHERE id",
    )
    .execute(&mut owner)
    .await
    .unwrap();

    // Seed one retained revision for retention_apply_deadlines and one active revision owned by
    // `admin` for projects::delete_artifact_revision.
    let rev_adj = f.payload("p1-8-adj", b"adj-bytes").await.revision;
    step(&f.db.0, &f.c.scope, &rev_adj, Step::Retain)
        .await
        .unwrap();
    let admin_scope: String = sqlx::query_scalar(
        "SELECT id::text FROM openmettle.scopes WHERE personal_user_id = $1::uuid",
    )
    .bind(&admin.user)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    let admin_art = new_uuid(&f.db).await;
    let admin_res = reserve(
        &f.db,
        API,
        &input(&admin_scope, &admin.user, "p1-8-del-res", &admin_art, 10),
    )
    .await
    .unwrap();
    let rev_del = settle(
        &f.db,
        &admin_scope,
        &admin_res.id,
        5,
        b"hello",
        "text/plain",
    )
    .await
    .unwrap();
    let policy_rev: i64 =
        sqlx::query_scalar("SELECT revision FROM openmettle.retention_policy WHERE id")
            .fetch_one(&mut owner)
            .await
            .unwrap();
    let journal_before = journal(&f.db).await.len();

    // --- Part A: retention_apply_deadlines blocks on deletion_journal_head until approval expires ---
    let cur_ms: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut owner)
            .await
            .unwrap();
    sqlx::query(
        "UPDATE openmettle.local_identity_approvals SET expires_ms = $2 WHERE id = $1::uuid",
    )
    .bind(&admin.approval)
    .bind(cur_ms + 500)
    .execute(&mut owner)
    .await
    .unwrap();

    let mut head_holder = connect(&f.db.0, OWNER).await;
    let holder_pid = pid(&mut head_holder).await;
    let mut head_tx = head_holder.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.deletion_journal_head WHERE id FOR UPDATE")
        .execute(&mut *head_tx)
        .await
        .unwrap();

    let apply_task = tokio::spawn({
        let db_name = f.db.0.clone();
        let user = admin.user.clone();
        let approval = admin.approval.clone();
        let scope = f.c.scope.clone();
        async move {
            let mut api = connect(&db_name, API).await;
            sqlx::query(
                "SELECT * FROM openmettle.retention_apply_deadlines(
                     $1::uuid, $2::uuid, $3, 120, $4::uuid, 'expiry-race', 'p1-8-apply-key'
                 )",
            )
            .bind(&user)
            .bind(&approval)
            .bind(policy_rev)
            .bind(&scope)
            .execute(&mut api)
            .await
        }
    });
    wait_for_blocked_peer(&f.db, holder_pid).await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    head_tx.commit().await.unwrap();

    let apply_res = apply_task.await.unwrap();
    assert_eq!(sqlstate(apply_res), "42501");
    assert_eq!(journal(&f.db).await.len(), journal_before);
    let audit_apply: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.authorization_audit WHERE request_key = 'p1-8-apply-key'",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(audit_apply, 0);

    // --- Part B: projects::delete_artifact_revision blocks on deletion_journal_head until approval expires ---
    let cur_ms2: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&mut owner)
            .await
            .unwrap();
    sqlx::query(
        "UPDATE openmettle.local_identity_approvals SET expires_ms = $2 WHERE id = $1::uuid",
    )
    .bind(&admin.approval)
    .bind(cur_ms2 + 500)
    .execute(&mut owner)
    .await
    .unwrap();

    let mut head_tx2 = head_holder.begin().await.unwrap();
    sqlx::query("SELECT FROM openmettle.deletion_journal_head WHERE id FOR UPDATE")
        .execute(&mut *head_tx2)
        .await
        .unwrap();

    let del_task = tokio::spawn({
        let db_name = f.db.0.clone();
        let user = admin.user.clone();
        let approval = admin.approval.clone();
        let art = admin_art.clone();
        let rev = rev_del.clone();
        async move {
            let mut api = connect(&db_name, API).await;
            let ctx = openmettle_core::authz::store::AuditContext {
                actor_user_id: &user,
                actor_approval_id: &approval,
                now_ms: cur_ms2,
                request_key: "p1-8-del-key",
                reason: "deleteArtifactRevision",
            };
            openmettle_core::authz::projects::delete_artifact_revision(&mut api, &ctx, &art, &rev)
                .await
        }
    });
    wait_for_blocked_peer(&f.db, holder_pid).await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    head_tx2.commit().await.unwrap();

    let del_res = del_task.await.unwrap();
    assert!(
        matches!(
            del_res,
            Err(openmettle_core::authz::store::StoreError::Denied(
                openmettle_core::authz::DenialReason::InactivePrincipal
            ))
        ),
        "expected InactivePrincipal on post-journal-flush expiry, got {del_res:?}"
    );
    assert_eq!(state(&f.db, &rev_del).await.0, "active");
    assert_eq!(journal(&f.db).await.len(), journal_before);
    let audit_del: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.authorization_audit WHERE request_key = 'p1-8-del-key'",
    )
    .fetch_one(&mut owner)
    .await
    .unwrap();
    assert_eq!(audit_del, 0);
}
