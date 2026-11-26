//! ADR 0041 PR2b: the restore reconciliation gate, deletion journal export/replay, unsettled
//! upload scrub, audited coverage-gap break-glass, and `storage rebind` integration on PostgreSQL
//! 18. A restore is simulated inside PostgreSQL: `CREATE DATABASE ... TEMPLATE live` copies the
//! live database's committed state once no session is connected to it, and that copy is the
//! backup. The live database then purges more revisions; "restoring" means pointing the owner,
//! the worker and the store at the copy. For file-copy restore coverage, `tar` copies the volume
//! so every inode changes. No backup tool, dump, WAL archive or volume snapshot is exercised.
//! Identities and payloads are synthetic.
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
    os::unix::fs::MetadataExt,
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
    let text = fs::read_to_string(&file).unwrap();
    let export = Export::parse(&text).unwrap();
    assert!(
        out.starts_with(&format!("watermark 3 {} ", export.digest)),
        "{out}"
    );
    assert!(
        !cli(&f.db, &["journal", "export", &file]).0,
        "overwrote an export"
    );

    // The restored copy still has the gate open, as it was when the backup was taken.
    let owner = pool(&restored, OWNER).await;
    assert_eq!(gate(&restored).await, (true, None, None, None, true));
    let (ok, out, err) = cli(
        &restored,
        &[
            "restore",
            "lock",
            "--required-seq",
            "3",
            "--required-digest",
            &export.digest,
            "--export-complete",
        ],
    );
    assert!(ok, "{err}");
    assert_eq!(
        out,
        "restore gate closed: snapshot 1, required 3, coverage_complete true\n"
    );
    // While it is closed no application role can claim or confirm a purge.
    let refused = step(&restored.0, &f.c.scope, due, Step::Claim).await;
    assert_eq!(code(&refused.unwrap_err()), "OMR02");
    assert_eq!(state(&restored, due).await.0, "retained");

    // A replay that stops after its database phase (openmettle-admin dies) moved both revisions
    // to 'purging' under their original deadlines; the gate refuses to open with payloads left.
    assert_eq!(restore::apply(&owner, &export).await.unwrap(), 2);
    for rev in [due, removed] {
        let (s, deadline) = state(&restored, rev).await;
        assert_eq!(
            (s.as_str(), deadline),
            ("purging", state(&f.db, rev).await.1)
        );
    }
    assert_eq!(account(&restored, &f.c.scope).await, (4, 14, 0));
    let open = sqlx::query("SELECT openmettle.restore_gate_open($1, decode($2, 'hex'))")
        .bind(export.seq)
        .bind(&export.digest)
        .execute(&owner)
        .await;
    assert_eq!(sqlstate(open), "OMR05");
    let (ok, _, err) = cli(&restored, &["restore", "replay", &file]);
    assert!(!ok && err.contains("pass its artifact root"), "{err}");

    // The rerun removes the resurrected payloads, releases their bytes once and opens the gate.
    let root = f.root.to_str().unwrap();
    let (ok, out, err) = cli(&restored, &["restore", "replay", &file, root]);
    assert!(ok, "{err}");
    assert_eq!(out, "replayed 0 records through 3; restore gate open\n");
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
        (true, Some(1), Some(3), Some(export.digest), true)
    );
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

    let owner = pool(&restored, OWNER).await;
    let store = Store::open_existing(&f.root).unwrap();
    // Replay needs a closed gate.
    assert_eq!(
        sqlstate_of(replay(&owner, &store, &full).await.unwrap_err()),
        "OMR02"
    );
    // Closed with seq 0 (below snapshot 1), the lock raises requirement to the snapshot head; an
    // export older than the restored database fails at restore_verify_export with OMR04.
    assert_eq!(
        restore::lock(&owner, 0, GENESIS, true).await.unwrap(),
        (1, 1, true)
    );
    assert_eq!(
        sqlstate_of(replay(&owner, &store, &before).await.unwrap_err()),
        "OMR04"
    );
    // Re-locking raises the requirement, never lowers it, refuses partial watermarks between
    // head and required, and refuses conflicting digests at the same sequence.
    assert_eq!(
        restore::lock(&owner, 3, &full_parsed.digest, true)
            .await
            .unwrap(),
        (1, 3, true)
    );
    assert_eq!(
        restore::lock(&owner, 0, GENESIS, true).await.unwrap(),
        (1, 3, true)
    );
    assert_eq!(
        sqlstate_of(
            restore::lock(&owner, 2, &stale_parsed.digest, true)
                .await
                .unwrap_err()
        ),
        "OMR04"
    );
    assert_eq!(
        sqlstate_of(
            restore::lock(&owner, 3, &"aa".repeat(32), true)
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
                Some(1),
                Some(3),
                Some(full_parsed.digest.clone()),
                true
            )
        );
        assert_eq!(journal(&restored).await.len(), 1);
        for rev in [second, third] {
            assert_eq!(state(&restored, rev).await.0, "retained");
        }
    };

    // Export lines: [0]=header, [1]=origin, [2]=rec1, [3]=rec2, [4]=rec3, [5]=watermark, [6]=sha256.
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
            pick(&[0, 1, 2, 3, 4, 5])
                .iter()
                .map(|l| format!("{l}\n"))
                .collect(),
            "missing checksum",
        ),
        (reseal(&pick(&[0, 1, 2, 4, 5])), "records out of sequence"),
        (
            reseal(&pick(&[0, 1, 2, 4, 3, 5])),
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
    for altered in [edit(4, 6), edit(2, 6)] {
        assert_eq!(
            sqlstate_of(replay(&owner, &store, &reseal(&altered)).await.unwrap_err()),
            "OMR03"
        );
        unchanged().await;
    }
    // A stale export (seq 2 < locked required 3) fails in restore_verify_export BEFORE any row
    // is written, leaving the restored DB completely untouched.
    assert_eq!(
        sqlstate_of(replay(&owner, &store, &stale).await.unwrap_err()),
        "OMR04"
    );
    unchanged().await;

    // A forged record extending the chain with a matching locked watermark (4, forged) but a
    // mismatched content_digest for `other` fails in deletion_journal_replay with OMR03 and rolls
    // back the whole transaction.
    let (scope, digest): (String, String) = sqlx::query_as(
        "SELECT scope_id::text, encode(chain_digest, 'hex')
           FROM openmettle.deletion_journal WHERE journal_seq = 3",
    )
    .fetch_one(&mut f.db.admin().await)
    .await
    .unwrap();
    let forged_owner = pool(&forged_backup, OWNER).await;
    let forged: String = sqlx::query_scalar(
        "SELECT encode(openmettle.deletion_journal_digest(decode($1, 'hex'), ROW(4, 'epoch'::timestamptz,
                'artifact_revision.purged', $2::uuid, $3::uuid, 'epoch'::timestamptz, 'epoch'::timestamptz,
                sha256('forged'), NULL, NULL)::openmettle.deletion_journal), 'hex')",
    )
    .bind(&digest)
    .bind(other)
    .bind(&scope)
    .fetch_one(&forged_owner)
    .await
    .unwrap();
    let mut extended = pick(&[0, 1, 2, 3, 4]);
    let content: String = Sha256::digest(b"forged")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    extended.push(format!(
        "4 0 artifact_revision.purged {other} {scope} 0 0 {content} - {forged}"
    ));
    extended.push(format!("watermark 4 {forged} 0"));
    restore::lock(&forged_owner, 4, &forged, true)
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
    assert_eq!(journal(&forged_backup).await.len(), 1);
    assert_eq!(state(&forged_backup, other).await.0, "active");

    // An active adoption/rebind barrier blocks finish with OMQ03 without opening the gate.
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
        (true, Some(1), Some(3), Some(full_parsed.digest), true)
    );
    assert_eq!(journal(&restored).await, journal(&f.db).await);
    assert_eq!(account(&restored, &f.c.scope).await, (5, 0, 0));
    assert_totals(&restored).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn the_gate_waits_for_purges_in_flight_and_only_the_owner_moves_it() {
    let f = Fixture::new().await;
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
        async move { restore::lock(&owner, 0, GENESIS, true).await.unwrap() }
    });
    wait_for_blocked_peer(&f.db, holder).await;
    tx.commit().await.unwrap();
    assert_eq!(locking.await.unwrap(), (1, 1, true));
    // A confirmation that reaches the gate while it is being closed waits, then fails closed.
    sqlx::query(
        "SELECT openmettle.restore_gate_open(journal_seq, chain_digest)
           FROM openmettle.deletion_journal_head",
    )
    .execute(&owner)
    .await
    .unwrap();
    let mut closer = connect(&f.db.0, OWNER).await;
    let holder = pid(&mut closer).await;
    let mut close = closer.begin().await.unwrap();
    sqlx::query("SELECT openmettle.restore_gate_lock(0, decode(repeat('00', 32), 'hex'), true)")
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
    assert_eq!(journal(&f.db).await.len(), 1);

    // Every owner gate/replay/break-glass function requires READ COMMITTED.
    for sql in [
        "SELECT openmettle.restore_gate_lock(0, decode(repeat('00', 32), 'hex'), true)",
        "SELECT openmettle.restore_verify_export(0, 0, decode(repeat('00', 32), 'hex'))",
        "SELECT openmettle.restore_gate_open(0, NULL)",
        "SELECT openmettle.deletion_journal_replay(1, 0, '', NULL, NULL, 0, 0, NULL, NULL, NULL)",
        "SELECT openmettle.restore_accept_coverage_gap(gen_random_uuid(), 'k', 'r')",
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
    // Only the owner may call migration 41's functions or mutate the gate; only the worker may
    // SELECT from restore_reconciliation_gate.
    for role in [API, WORKER, ISSUANCE, crate::pg::GATEWAY] {
        let mut c = connect(&f.db.0, role).await;
        for sql in [
            "UPDATE openmettle.restore_reconciliation_gate SET open = true",
            "DELETE FROM openmettle.restore_reconciliation_gate",
            "TRUNCATE openmettle.restore_reconciliation_gate",
            "SELECT openmettle.restore_gate_lock(0, decode(repeat('00', 32), 'hex'), true)",
            "SELECT openmettle.restore_verify_export(0, 0, decode(repeat('00', 32), 'hex'))",
            "SELECT openmettle.restore_gate_open(0, NULL)",
            "SELECT openmettle.deletion_journal_replay(1, 0, '', NULL, NULL, 0, 0, NULL, NULL, NULL)",
            "SELECT openmettle.deletion_journal_digest(NULL, NULL)",
            "SELECT openmettle.restore_accept_coverage_gap(gen_random_uuid(), 'k', 'r')",
        ] {
            let result = sqlx::query(sql).execute(&mut c).await;
            assert_eq!(sqlstate(result), "42501", "{role}: {sql}");
        }
        let read = restore::gate_open(&mut c).await;
        if role == WORKER {
            assert!(!read.unwrap());
        } else {
            assert_eq!(sqlstate(read), "42501", "{role}");
        }
    }
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
    // _sqlx_migrations, so migrating it to 41 produces the exact same coverage_started_at origin
    // as the live primary.
    migrate::apply(&restored.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    let owner = pool(&restored, OWNER).await;
    assert_eq!(gate(&restored).await, (true, None, None, None, true));
    // Even a record the restored journal lacks is refused while the gate is open.
    let open = restore::apply(&owner, &export).await;
    assert_eq!(sqlstate_of(open.unwrap_err()), "OMR02");
    assert_eq!(
        restore::lock(&owner, export.seq, &export.digest, true)
            .await
            .unwrap(),
        (0, 3, true)
    );
    // Records written by migrations 28 and 41 all verify against migration 41's encoding.
    assert_eq!(restore::apply(&owner, &export).await.unwrap(), 3);
    // No purged revision exists in the backup, so nothing is left to purge.
    sqlx::query("SELECT openmettle.restore_gate_open($1, decode($2, 'hex'))")
        .bind(export.seq)
        .bind(&export.digest)
        .execute(&owner)
        .await
        .unwrap();
    assert_eq!(journal(&restored).await, journal(&live).await);
    assert_chain(&restored).await;
}

/// P1 #1 regression: an export from a second independent installation (same sequence 0 or 1, or
/// different chain digest) is rejected BEFORE deletion_journal_replay writes anything.
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

    // Purge one revision on installation A and one on installation B so both reach seq = 1 with
    // distinct digests D_A and D_B.
    let a_rev = a.payload("inst-a", b"secret-a").await.revision;
    let b_rev = b.payload("inst-b", b"secret-b").await.revision;
    for (f, rev) in [(&a, &a_rev), (&b, &b_rev)] {
        step(&f.db.0, &f.c.scope, rev, Step::Retain).await.unwrap();
    }
    sleep_past_grace().await;
    a.api.close().await;
    let a_backup = backup(&a.db).await;
    for (f, rev) in [(&a, &a_rev), (&b, &b_rev)] {
        for s in [Step::Claim, Step::Confirm] {
            step(&f.db.0, &f.c.scope, rev, s).await.unwrap();
        }
    }
    let exp_a = Export::parse(&restore::export(&pool(&a.db, OWNER).await).await.unwrap()).unwrap();
    let exp_b = Export::parse(&restore::export(&pool(&b.db, OWNER).await).await.unwrap()).unwrap();
    assert_eq!((exp_a.seq, exp_b.seq), (1, 1));
    assert_ne!(exp_a.digest, exp_b.digest);

    // Case 1: Backup A locked at (0, GENESIS) rejects installation B's empty export (same seq 0
    // and same GENESIS digest, different origin) with OMR04.
    let owner_a = pool(&a_backup, OWNER).await;
    restore::lock(&owner_a, 0, GENESIS, true).await.unwrap();
    assert_eq!(
        sqlstate_of(restore::apply(&owner_a, &b_empty_export).await.unwrap_err()),
        "OMR04"
    );
    // Case 2: Backup A locked at (0, GENESIS) rejects installation B's seq=1 export with OMR04
    // (sequence mismatch) and writes zero rows.
    assert_eq!(
        sqlstate_of(restore::apply(&owner_a, &exp_b).await.unwrap_err()),
        "OMR04"
    );
    assert!(journal(&a_backup).await.is_empty());

    // Case 3: Backup A locked at A's legitimate watermark (1, D_A) rejects installation B's seq=1
    // export (same seq 1, wrong digest D_B) with OMR03 before writing a single row.
    restore::lock(&owner_a, 1, &exp_a.digest, true)
        .await
        .unwrap();
    assert_eq!(
        sqlstate_of(restore::apply(&owner_a, &exp_b).await.unwrap_err()),
        "OMR03"
    );
    assert!(journal(&a_backup).await.is_empty());
    assert_eq!(state(&a_backup, &a_rev).await.0, "retained");

    // Case 4: Locking the live A DB (at head seq=1, D_A) with B's digest D_B fails in
    // restore_gate_lock itself with OMR03.
    let live_a_owner = pool(&a.db, OWNER).await;
    assert_eq!(
        sqlstate_of(
            restore::lock(&live_a_owner, 1, &exp_b.digest, true)
                .await
                .unwrap_err()
        ),
        "OMR03"
    );

    // Legitimate replay of A's own export succeeds and opens the gate.
    assert_eq!(restore::apply(&owner_a, &exp_a).await.unwrap(), 1);
    restore::finish(&owner_a, Some(&a.store), &exp_a)
        .await
        .unwrap();
    assert!(gate(&a_backup).await.0);
}

/// P1 #2a regression: a backup taken at schema <= 27 (before deletion_journal existed) migrated
/// through 28..41 gets a fresh migration-28 `installed_on` timestamp and fails closed with OMR04
/// when replaying the primary's export.
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

    // Upgrade the live primary to latest (41), purge the revision, and export its journal.
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    retention_grace(&live, 0).await;
    for s in [Step::Retain, Step::Claim, Step::Confirm] {
        step(&live.0, &c.scope, &rev, s).await.unwrap();
    }
    let live_export =
        Export::parse(&restore::export(&pool(&live, OWNER).await).await.unwrap()).unwrap();

    // Ensure at least a small clock tick before migrating the schema-27 backup through 28..41.
    tokio::time::sleep(Duration::from_millis(20)).await;
    migrate::apply(&pre28_backup.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    let owner = pool(&pre28_backup, OWNER).await;
    restore::lock(&owner, live_export.seq, &live_export.digest, true)
        .await
        .unwrap();
    // Replay fails closed with OMR04 on origin mismatch; zero rows written, gate stays closed.
    assert_eq!(
        sqlstate_of(restore::apply(&owner, &live_export).await.unwrap_err()),
        "OMR04"
    );
    assert!(journal(&pre28_backup).await.is_empty());
    assert!(!gate(&pre28_backup).await.0);
}

/// P1 #2b regression: omitting `--export-complete` leaves `coverage_complete = false` and blocks
/// gate opening with `OMR04` until an audited `'operator'` break-glass `accept-coverage-gap` is
/// recorded (idempotent on exact replay, `23505` on mismatched parameters, `OMR02` when open).
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn incomplete_coverage_requires_audited_accept_coverage_gap_break_glass() {
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

    // Lock WITHOUT `--export-complete` -> coverage_complete = false.
    let (ok, out, err) = cli(
        &restored,
        &[
            "restore",
            "lock",
            "--required-seq",
            "1",
            "--required-digest",
            &export.digest,
        ],
    );
    assert!(ok, "{err}");
    assert_eq!(
        out,
        "restore gate closed: snapshot 0, required 1, coverage_complete false\n"
    );
    assert_eq!(
        gate(&restored).await,
        (false, Some(0), Some(1), Some(export.digest.clone()), false)
    );

    // Replay purges the exported record but refuses to open the gate with OMR04 because coverage
    // is incomplete.
    let root = f.root.to_str().unwrap();
    let (ok, _, err) = cli(&restored, &["restore", "replay", &file, root]);
    assert!(!ok && err.contains("OMR04"), "{err}");
    assert!(!gate(&restored).await.0);
    assert_eq!(state(&restored, &rev).await.0, "purged");

    // Operator runs audited break-glass accept-coverage-gap.
    let operator = new_uuid(&restored).await;
    let other_operator = new_uuid(&restored).await;
    let (ok, out, err) = cli(
        &restored,
        &[
            "restore",
            "accept-coverage-gap",
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

    // Verify the `'operator'` audit row recorded the pinned watermark and reason.
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
    assert_eq!(details["snapshot_journal_seq"], 0);
    assert_eq!(details["required_journal_seq"], 1);
    assert_eq!(details["required_chain_digest"], export.digest);

    // Exact replay is idempotent and writes no duplicate audit row.
    let (ok, out, err) = cli(
        &restored,
        &[
            "restore",
            "accept-coverage-gap",
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
            "--operator-id",
            &other_operator,
            "--request-key",
            "inc-42",
            "--reason",
            "primary storage unrecoverable after seq 1",
        ],
    );
    assert!(!ok && err.contains("23505"), "{err}");

    // Now restore replay succeeds and opens the gate.
    let (ok, out, err) = cli(&restored, &["restore", "replay", &file, root]);
    assert!(ok, "{err}");
    assert_eq!(out, "replayed 0 records through 1; restore gate open\n");
    assert!(gate(&restored).await.0);

    // Break-glass on an already-open gate fails with OMR02.
    let (ok, _, err) = cli(
        &restored,
        &[
            "restore",
            "accept-coverage-gap",
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

/// P1 #3 regression: an unsettled mid-publication upload (`publish_pending = true`, hard-linked
/// under `revisions/<id>` and `staging/<id>` with secret bytes) cannot survive either an in-place
/// snapshot restore OR a `tar` file-copy restore; skipping `storage rebind` on a `tar` copy fails
/// closed with `REBIND_FIRST`; and foreign hard links / quarantined / unbound non-zero staging
/// fail closed keeping the gate shut.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn unsettled_mid_publication_upload_is_scrubbed_on_in_place_and_tar_copy_restore() {
    let f = Fixture::new().await;
    let settled = f.payload("live-doc", b"keep-me").await;
    let mid_pub = seed_unsettled_upload(&f, "mid-pub", b"secret-unsettled", true).await;
    let staged_only = seed_unsettled_upload(&f, "staged-only", b"secret-staged", false).await;
    f.api.close().await;

    // Take three independent DB backups at this exact moment: one for tar-copy restore, one for
    // in-place snapshot restore, and one for fail-closed edge cases.
    let db_tar = backup(&f.db).await;
    let db_inplace = backup(&f.db).await;
    let db_fail = backup(&f.db).await;

    let dir = Dir::new();
    let tar_root = tar_copy(&f.root, &dir, "tar-volume");
    let fail_root = tar_copy(&f.root, &dir, "fail-volume");
    let export_file = dir.path("empty.export");
    let (ok, _, err) = cli(&f.db, &["journal", "export", &export_file]);
    assert!(ok, "{err}");

    // --- Part A: tar file-copy restore (new inodes) ---
    let (ok, _, err) = cli(
        &db_tar,
        &[
            "restore",
            "lock",
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

    // Run `storage rebind`, then `restore replay`: rebind empties unsettled uploads (leaving empty
    // `revisions/<mid_pub>`), and `restore replay` unlinks `revisions/<mid_pub>`, verifies
    // `unsettled_payloads == 0`, and opens the gate while preserving the settled payload.
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
    assert_eq!(
        fs::metadata(tar_root.join("staging").join(&mid_pub))
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        fs::metadata(tar_root.join("staging").join(&staged_only))
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        fs::read(tar_root.join("revisions").join(&settled.reservation)).unwrap(),
        b"keep-me"
    );
    let pending: bool = sqlx::query_scalar(
        "SELECT publish_pending FROM openmettle.storage_reservations WHERE id = $1::uuid",
    )
    .bind(&mid_pub)
    .fetch_one(&mut db_tar.admin().await)
    .await
    .unwrap();
    assert!(!pending);

    // --- Part B: in-place snapshot restore (inodes unchanged, no rebind needed) ---
    let (ok, _, err) = cli(
        &db_inplace,
        &[
            "restore",
            "lock",
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
    let pending: bool = sqlx::query_scalar(
        "SELECT publish_pending FROM openmettle.storage_reservations WHERE id = $1::uuid",
    )
    .bind(&mid_pub)
    .fetch_one(&mut db_inplace.admin().await)
    .await
    .unwrap();
    assert!(!pending);

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
    restore::lock(&owner, export.seq, &export.digest, true)
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

/// P2 #5 regression: replaying a journal record stamped with a higher `policy_revision` advances
/// `retention_policy.revision` so post-restore `retention_set_grace` calls never reuse a replayed
/// policy revision number.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn replay_advances_retention_policy_revision_so_future_edits_never_collide() {
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
    restore::lock(&restored_owner, export.seq, &export.digest, true)
        .await
        .unwrap();
    replay(&restored_owner, &f.store, &export_text)
        .await
        .unwrap();

    let after_replay: i64 =
        sqlx::query_scalar("SELECT revision FROM openmettle.retention_policy WHERE id")
            .fetch_one(&restored_owner)
            .await
            .unwrap();
    assert_eq!(after_replay, bumped);

    // Next post-restore retention_set_grace must return bumped + 1 (not initial_rev + 1).
    let next_rev: i64 = sqlx::query_scalar(
        "SELECT openmettle.retention_set_grace($1::uuid, $2::uuid, 60, 'post-restore', 'post-1')",
    )
    .bind(&admin.user)
    .bind(&admin.approval)
    .fetch_one(&mut connect(&restored.0, API).await)
    .await
    .unwrap();
    assert_eq!(next_rev, bumped + 1);
}
