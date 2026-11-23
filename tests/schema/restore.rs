//! ADR 0041 PR2b: the restore reconciliation gate and deletion journal export and replay on
//! PostgreSQL 18. A restore is simulated inside PostgreSQL: `CREATE DATABASE … TEMPLATE live`
//! copies the live database's committed state once no session is connected to it, and that copy
//! is the backup. The live database then purges more revisions; "restoring" means pointing the
//! owner, the worker and the store at the copy. The payload directory is left as it was at the
//! backup point, so it stands for a volume restored to the same recovery point. No backup tool,
//! dump, WAL archive or volume snapshot is exercised. Identities and payloads are synthetic.
use super::artifact_fs::{Fixture, pool};
use super::retention::{Step, assert_chain, pid, step};
use super::storage::{
    account, assert_totals, code, configure, input, new_uuid, reserve, retention_grace, settle,
};
use super::*;
use openmettle_core::{
    artifact_fs::{self, Store},
    restore::{self, Export},
    storage,
};
use sqlx::PgPool;
use std::fs;

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
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_openmettle-admin"))
        .env("OPENMETTLE_ADMIN_DATABASE_URL", db.url(OWNER))
        .args(args)
        .output()
        .unwrap();
    let text = |b: Vec<u8>| String::from_utf8(b).unwrap();
    (out.status.success(), text(out.stdout), text(out.stderr))
}

async fn sleep_past_grace() {
    tokio::time::sleep(Duration::from_millis(1100)).await;
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

async fn gate(db: &TestDb) -> (bool, Option<i64>, Option<i64>) {
    sqlx::query_as(
        "SELECT open, snapshot_journal_seq, required_journal_seq
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

/// The volume phase as openmettle-admin runs it, with a store for the restored database.
async fn replay(owner: &PgPool, store: &Store, text: &str) -> Result<(), restore::Error> {
    let export = Export::parse(text)?;
    restore::apply(owner, &export).await?;
    restore::finish(owner, Some(store), &export).await
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
    let dir = crate::auth_config_support::Dir::new();
    let file = dir.path("journal.export");
    let (ok, out, err) = cli(&f.db, &["journal", "export", &file]);
    assert!(ok, "{err}");
    assert!(out.starts_with("watermark 3 "), "{out}");
    assert!(
        !cli(&f.db, &["journal", "export", &file]).0,
        "overwrote an export"
    );

    // The restored copy still has the gate open, as it was when the backup was taken.
    let owner = pool(&restored, OWNER).await;
    assert_eq!(gate(&restored).await, (true, None, None));
    let (ok, out, err) = cli(&restored, &["restore", "lock", "--required-seq", "3"]);
    assert!(ok, "{err}");
    assert_eq!(out, "restore gate closed: snapshot 1, required 3\n");
    // While it is closed no application role can claim or confirm a purge.
    let refused = step(&restored.0, &f.c.scope, due, Step::Claim).await;
    assert_eq!(code(&refused.unwrap_err()), "OMR02");
    assert_eq!(state(&restored, due).await.0, "retained");

    // A replay that stops after its database phase (openmettle-admin dies) moved both revisions
    // to 'purging' under their original deadlines; the gate refuses to open with payloads left.
    let text = fs::read_to_string(&file).unwrap();
    let export = Export::parse(&text).unwrap();
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
    assert_eq!(gate(&restored).await, (true, Some(1), Some(3)));
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
    for s in [Step::Claim, Step::Confirm] {
        at(second, s).await;
    }
    let stale = restore::export(&pool(&f.db, OWNER).await).await.unwrap();
    for s in [Step::Claim, Step::Confirm] {
        at(third, s).await;
    }
    let full = restore::export(&pool(&f.db, OWNER).await).await.unwrap();

    let owner = pool(&restored, OWNER).await;
    let store = Store::open_existing(&f.root).unwrap();
    // Replay needs a closed gate.
    assert_eq!(
        sqlstate_of(replay(&owner, &store, &full).await.unwrap_err()),
        "OMR02"
    );
    // Closed with no requirement beyond the snapshot, an export older than the restored database
    // still lags it.
    assert_eq!(restore::lock(&owner, 0).await.unwrap(), (1, 1));
    assert_eq!(
        sqlstate_of(replay(&owner, &store, &before).await.unwrap_err()),
        "OMR04"
    );
    // Closing it again keeps the snapshot and raises the requirement, but never lowers it.
    assert_eq!(restore::lock(&owner, 3).await.unwrap(), (1, 3));
    assert_eq!(restore::lock(&owner, 0).await.unwrap(), (1, 3));
    let unchanged = async || {
        assert_eq!(gate(&restored).await, (false, Some(1), Some(3)));
        assert_eq!(journal(&restored).await.len(), 1);
        for rev in [second, third] {
            assert_eq!(state(&restored, rev).await.0, "retained");
        }
    };

    let lines: Vec<&str> = full.lines().collect();
    let reseal = |lines: &[String]| {
        let body: String = lines.iter().map(|l| format!("{l}\n")).collect();
        let sum: String = Sha256::digest(body.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("{body}sha256 {sum}\n")
    };
    let edit = |index: usize, field: usize| -> Vec<String> {
        let mut out: Vec<String> = lines[..lines.len() - 1]
            .iter()
            .map(|l| l.to_string())
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
            pick(&[0, 1, 2, 3, 4])
                .iter()
                .map(|l| format!("{l}\n"))
                .collect(),
            "missing checksum",
        ),
        (reseal(&pick(&[0, 1, 3, 4])), "records out of sequence"),
        (reseal(&pick(&[0, 1, 3, 2, 4])), "records out of sequence"),
    ] {
        assert!(
            matches!(Export::parse(&text), Err(restore::Error::Export(w)) if w == why),
            "{why}"
        );
    }
    // A record altered after the restored head breaks the chain; one at or below it differs from
    // the restored record. Either refusal rolls the whole replay back.
    for altered in [edit(3, 6), edit(1, 6)] {
        assert_eq!(
            sqlstate_of(replay(&owner, &store, &reseal(&altered)).await.unwrap_err()),
            "OMR03"
        );
        unchanged().await;
    }
    // A forged record that extends the chain correctly but names a revision whose content it does
    // not match.
    let (scope, digest): (String, String) = sqlx::query_as(
        "SELECT scope_id::text, encode(chain_digest, 'hex') FROM openmettle.deletion_journal WHERE journal_seq = 3",
    )
    .fetch_one(&mut f.db.admin().await)
    .await
    .unwrap();
    let forged: String = sqlx::query_scalar(
        "SELECT encode(openmettle.deletion_journal_digest(decode($1, 'hex'), ROW(4, 'epoch'::timestamptz,
                'artifact_revision.purged', $2::uuid, $3::uuid, 'epoch'::timestamptz, 'epoch'::timestamptz,
                sha256('forged'), NULL, NULL)::openmettle.deletion_journal), 'hex')",
    )
    .bind(&digest)
    .bind(other)
    .bind(&scope)
    .fetch_one(&owner)
    .await
    .unwrap();
    let mut extended = pick(&[0, 1, 2, 3]);
    let content: String = Sha256::digest(b"forged")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    extended.push(format!(
        "4 0 artifact_revision.purged {other} {scope} 0 0 {content} - {forged}"
    ));
    extended.push(format!("watermark 4 {forged} 0"));
    assert_eq!(
        sqlstate_of(
            replay(&owner, &store, &reseal(&extended))
                .await
                .unwrap_err()
        ),
        "OMR03"
    );
    unchanged().await;
    assert_eq!(state(&restored, other).await.0, "active");
    // An export older than the required watermark: its record is replayed and purged, and the
    // gate stays closed.
    assert_eq!(
        sqlstate_of(replay(&owner, &store, &stale).await.unwrap_err()),
        "OMR04"
    );
    assert_eq!(state(&restored, second).await.0, "purged");
    // Closing it again keeps the restored snapshot although replay advanced the head.
    assert_eq!(restore::lock(&owner, 0).await.unwrap(), (1, 3));
    // A ledger that disagrees with the volume keeps the gate closed until it is repaired.
    let skew = "UPDATE openmettle.storage_accounts SET active_bytes = active_bytes + $1";
    sqlx::query(skew).bind(1i64).execute(&owner).await.unwrap();
    let drift = replay(&owner, &store, &full).await;
    assert!(matches!(drift, Err(restore::Error::Drift)), "{drift:?}");
    assert_eq!(state(&restored, third).await.0, "purged");
    assert!(!gate(&restored).await.0);
    sqlx::query(skew).bind(-1i64).execute(&owner).await.unwrap();
    replay(&owner, &store, &full).await.unwrap();
    assert_eq!(gate(&restored).await, (true, Some(1), Some(3)));
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
    storage::confirm_purge(&mut tx, &f.c.scope, &a)
        .await
        .unwrap();
    let locking = tokio::spawn({
        let owner = owner.clone();
        async move { restore::lock(&owner, 0).await.unwrap() }
    });
    wait_for_blocked_peer(&f.db, holder).await;
    tx.commit().await.unwrap();
    assert_eq!(locking.await.unwrap(), (1, 1));
    // A confirmation that reaches the gate while it is being closed waits, then fails closed.
    sqlx::query(
        "SELECT openmettle.restore_gate_open(journal_seq, chain_digest) FROM openmettle.deletion_journal_head",
    )
    .execute(&owner)
    .await
    .unwrap();
    let mut closer = connect(&f.db.0, OWNER).await;
    let holder = pid(&mut closer).await;
    let mut close = closer.begin().await.unwrap();
    sqlx::query("SELECT openmettle.restore_gate_lock(0)")
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
    // Gate and replay changes are owner-only and need READ COMMITTED; only the worker reads it.
    for sql in [
        "SELECT openmettle.restore_gate_lock(0)",
        "SELECT openmettle.restore_gate_open(0, NULL)",
        "SELECT openmettle.deletion_journal_replay(1, 0, '', NULL, NULL, 0, 0, NULL, NULL, NULL)",
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
    for role in [API, WORKER, ISSUANCE, crate::pg::GATEWAY] {
        let mut c = connect(&f.db.0, role).await;
        for sql in [
            "UPDATE openmettle.restore_reconciliation_gate SET open = true",
            "DELETE FROM openmettle.restore_reconciliation_gate",
            "TRUNCATE openmettle.restore_reconciliation_gate",
            "SELECT openmettle.restore_gate_lock(0)",
            "SELECT openmettle.restore_gate_open(0, NULL)",
            "SELECT openmettle.deletion_journal_replay(1, 0, '', NULL, NULL, 0, 0, NULL, NULL, NULL)",
            "SELECT openmettle.deletion_journal_digest(NULL, NULL)",
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
async fn a_schema_28_journal_and_backup_replay_after_the_upgrade_to_29() {
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
    assert_eq!(gate(&live).await, (true, None, None));
    purge("third").await;
    // One chain across the upgrade: migration 29 appends with migration 28's encoding.
    assert_chain(&live).await;
    let export = Export::parse(&restore::export(&pool(&live, OWNER).await).await.unwrap()).unwrap();

    // A backup taken at schema 28 is migrated first and, like any restore, closed explicitly.
    migrate::apply(&restored.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();
    let owner = pool(&restored, OWNER).await;
    assert_eq!(gate(&restored).await, (true, None, None));
    // Even a record the restored journal lacks is refused while the gate is open.
    let open = restore::apply(&owner, &export).await;
    assert_eq!(sqlstate_of(open.unwrap_err()), "OMR02");
    assert_eq!(restore::lock(&owner, export.seq).await.unwrap(), (0, 3));
    // Records written by migrations 28 and 29 all verify against migration 29's encoding.
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
