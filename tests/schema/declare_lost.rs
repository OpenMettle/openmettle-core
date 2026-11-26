//! Issue #154 (ADR 0040 / ADR 0041 amendment, migration 44): owner-only `storage declare-lost`
//! for unrecoverable artifact payloads after a restore, role boundaries, deletion-journal
//! propagation across subsequent restores, and `/v1` `410 payload_lost` / conversation safety.
use super::artifact_fs::{Fixture, pool};
use super::retention::{Step, step};
use super::storage::{account as storage_account, retention_grace};
use super::*;
use crate::authz_http::{
    Api, As, GIB, browser, file_part, form, limits, metadata_part, refused, success,
};
use crate::authz_store::{FUTURE, PROVIDER, account, ctx, providers};
use crate::{auth_config_support::Dir, ca::Ca, consumer};
use openmettle_core::{
    WorkerSettings,
    artifact_fs::{self, Store},
    authz::{
        Grantee, ResourceAccess, ResourceKind,
        branches::{self, Conversation, PartContent},
        leases::LeaseSettings,
        projects,
        runs::ClaimedRun,
    },
    model_config::Catalog,
    provider_http::inference,
    restore::{self, Export},
    worker::{
        self,
        turns::{Route, TurnExecutor, TurnRoutes},
    },
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const OPERATOR_1: &str = "11111111-1111-4111-8111-111111111111";
const OPERATOR_2: &str = "22222222-2222-4222-8222-222222222222";

fn admin_as(db: &TestDb, role: &str, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_openmettle-admin"));
    cmd.env("OPENMETTLE_ADMIN_DATABASE_URL", db.url(role))
        .args(args);
    run_cli(&mut cmd, &format!("openmettle-admin ({role}) {args:?}"))
}

fn cli(db: &TestDb, args: &[&str]) -> (bool, String, String) {
    let out = admin_as(db, OWNER, args);
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn declare_lost_cli(
    db: &TestDb,
    role: &str,
    root: &Path,
    revision: &str,
    operator_id: &str,
    request_key: &str,
    reason: &str,
) -> (bool, String, String) {
    let out = admin_as(
        db,
        role,
        &[
            "storage",
            "declare-lost",
            root.to_str().unwrap(),
            "--revision",
            revision,
            "--operator-id",
            operator_id,
            "--request-key",
            request_key,
            "--reason",
            reason,
        ],
    );
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn tar_copy(from: &Path, dir: &Dir, name: &str) -> PathBuf {
    let archive = dir.path(&format!("{name}.tar"));
    let to = PathBuf::from(dir.path(name));
    let mut create = Command::new("tar");
    create.arg("-C").arg(from).args(["-cf", &archive, "."]);
    let out = run_cli(&mut create, "tar create copy");
    assert!(out.status.success(), "{}", stderr(&out));
    fs::create_dir(&to).unwrap();
    let mut extract = Command::new("tar");
    extract.arg("-C").arg(&to).args(["-xpf", &archive]);
    let out = run_cli(&mut extract, "tar extract copy");
    assert!(out.status.success(), "{}", stderr(&out));
    to
}

async fn backup_db(db: &TestDb) -> TestDb {
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

async fn barrier_of(db: &TestDb) -> Option<String> {
    sqlx::query_scalar("SELECT adoption_run_id::text FROM openmettle.storage_volume_control")
        .fetch_one(&mut db.admin().await)
        .await
        .unwrap()
}

async fn gate_open_of(db: &TestDb) -> bool {
    sqlx::query_scalar("SELECT open FROM openmettle.restore_reconciliation_gate WHERE id")
        .fetch_one(&mut db.admin().await)
        .await
        .unwrap()
}

async fn revision_row(
    db: &TestDb,
    rev: &str,
) -> (String, bool, Option<String>, Option<String>, String) {
    sqlx::query_as(
        "SELECT state, lost_at IS NOT NULL, retained_at::text, purge_after::text, purge_stage
           FROM openmettle.artifact_revisions
          WHERE id = $1::uuid",
    )
    .bind(rev)
    .fetch_one(&mut db.admin().await)
    .await
    .unwrap()
}

async fn instance_totals(db: &TestDb) -> (i64, i64, i64) {
    sqlx::query_as(
        "SELECT active_bytes, retained_bytes, reserved_bytes FROM openmettle.storage_instance",
    )
    .fetch_one(&mut db.admin().await)
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn declare_lost_refuses_live_volume_intact_purging_foreign_link_locked_and_non_owners() {
    let f = Fixture::new().await;
    let active_intact = f.payload("intact", b"intact-payload").await;
    let active_corrupt = f.payload("corrupt", b"corrupt-payload").await;
    let purging_empty = f.payload("p-empty", b"purging-empty").await;
    let foreign_linked = f.payload("foreign", b"foreign-link-bytes").await;
    let locked_corrupt = f.payload("locked", b"locked-corrupt").await;

    retention_grace(&f.db, 0).await;
    step(&f.db.0, &f.c.scope, &purging_empty.revision, Step::Retain)
        .await
        .unwrap();
    step(&f.db.0, &f.c.scope, &purging_empty.revision, Step::Claim)
        .await
        .unwrap();

    // 1. Live open volume (no adoption barrier, gate open) must refuse even when corrupted.
    fs::write(
        f.root.join("revisions").join(&active_corrupt.reservation),
        b"corrupted!",
    )
    .unwrap();
    let (ok, _, err) = declare_lost_cli(
        &f.db,
        OWNER,
        &f.root,
        &active_corrupt.revision,
        OPERATOR_1,
        "live-refused",
        "attempt on live volume",
    );
    assert!(!ok);
    assert!(err.contains("live and open"), "{err}");

    // 2. Non-owner roles must have zero privilege to call CLI, SQL function, or direct UPDATE.
    for role in [API, WORKER, ISSUANCE, "openmettle_gateway"] {
        let (ok, _, err) = declare_lost_cli(
            &f.db,
            role,
            &f.root,
            &active_corrupt.revision,
            OPERATOR_1,
            &format!("role-{role}"),
            "non-owner attempt",
        );
        assert!(!ok, "role {role} unexpectedly succeeded");
        assert!(
            err.contains("owner login required") || err.contains("owner connection failed"),
            "{role}: {err}"
        );

        let mut cn = connect(&f.db.0, role).await;
        let res = sqlx::query(
            "SELECT * FROM openmettle.storage_declare_payload_lost($1::uuid, $2::uuid, $3, $4)",
        )
        .bind(&active_corrupt.revision)
        .bind(OPERATOR_1)
        .bind(format!("sql-{role}"))
        .bind("direct sql attempt")
        .execute(&mut cn)
        .await;
        assert_eq!(sqlstate(res), "42501", "role {role} must get 42501");
    }
    for role in [API, WORKER] {
        let mut cn = connect(&f.db.0, role).await;
        let res = sqlx::query(
            "UPDATE openmettle.artifact_revisions SET state = 'lost' WHERE id = $1::uuid",
        )
        .bind(&active_corrupt.revision)
        .execute(&mut cn)
        .await;
        assert_eq!(
            sqlstate(res),
            "42501",
            "direct UPDATE state='lost' by {role} must fail with 42501"
        );
    }

    // 3. Closed restore gate whose journal has NOT caught up to required_journal_seq must refuse.
    let export_text = restore::export(&pool(&f.db, OWNER).await).await.unwrap();
    let export = Export::parse(&export_text).unwrap();
    let next_seq = export.seq + 1;
    let dummy_digest = "ab".repeat(32);
    sqlx::query(
        "SELECT openmettle.restore_gate_lock($1, $2, decode($3, 'hex'), false, NULL, true, $4, decode($5, 'hex'), $6)",
    )
    .bind(export.origin_us)
    .bind(next_seq)
    .bind(&dummy_digest)
    .bind(export.lifecycle_origin_us)
    .bind(export.lifecycle_baseline_digest.as_deref())
    .bind(export.connection_origin_us)
    .execute(&mut connect(&f.db.0, OWNER).await)
    .await
    .unwrap();
    let (ok, _, err) = declare_lost_cli(
        &f.db,
        OWNER,
        &f.root,
        &active_corrupt.revision,
        OPERATOR_1,
        "behind-journal",
        "before journal replay",
    );
    assert!(!ok);
    assert!(
        err.contains("replay the deletion journal before declaring payloads lost"),
        "{err}"
    );
    // Reset gate back to open for barrier-based disk checks.
    sqlx::query(
        "UPDATE openmettle.restore_reconciliation_gate
            SET open = true, opened_at = clock_timestamp(), restore_run_id = NULL,
                required_origin_us = NULL, snapshot_lifecycle_origin_us = NULL,
                snapshot_lifecycle_baseline_digest = NULL, required_lifecycle_origin_us = NULL,
                required_lifecycle_baseline_digest = NULL, replayed_lifecycle_baseline_digest = NULL,
                snapshot_connection_origin_us = NULL, required_connection_origin_us = NULL,
                connection_gap_reconciled = false, checkpoints = '[]'::jsonb,
                volume_claim_token = NULL, volume_lease_until = NULL
          WHERE id",
    )
    .execute(&mut f.db.admin().await)
    .await
    .unwrap();

    // 4. Copy volume, damage target files, truncate purging_empty, link foreign file, run rebind
    //    (which fails on damaged files and holds adoption_run_id).
    let dir = Dir::new();
    let copy = tar_copy(&f.root, &dir, "copy");
    fs::write(copy.join("revisions").join(&purging_empty.reservation), b"").unwrap();
    fs::write(
        copy.join("revisions").join(&foreign_linked.reservation),
        b"bad",
    )
    .unwrap();
    let foreign_path = copy.join("external-hardlink");
    fs::hard_link(
        copy.join("revisions").join(&foreign_linked.reservation),
        &foreign_path,
    )
    .unwrap();
    fs::write(
        copy.join("revisions").join(&locked_corrupt.reservation),
        b"bad-locked",
    )
    .unwrap();

    let (ok, _, _) = cli(&f.db, &["storage", "rebind", copy.to_str().unwrap()]);
    assert!(!ok, "rebind must stay closed while damaged payloads exist");
    assert!(barrier_of(&f.db).await.is_some());

    // Intact payload is refused.
    let (ok, _, err) = declare_lost_cli(
        &f.db,
        OWNER,
        &copy,
        &active_intact.revision,
        OPERATOR_1,
        "intact-refused",
        "mistakenly targeting intact payload",
    );
    assert!(!ok);
    assert!(err.contains("payload verifies intact"), "{err}");
    assert_eq!(
        revision_row(&f.db, &active_intact.revision).await.0,
        "active"
    );
    assert_eq!(
        fs::read(copy.join("revisions").join(&active_intact.reservation)).unwrap(),
        b"intact-payload"
    );

    // Already-truncated purging payload accepted by rebind is refused.
    let (ok, _, err) = declare_lost_cli(
        &f.db,
        OWNER,
        &copy,
        &purging_empty.revision,
        OPERATOR_1,
        "purging-empty-refused",
        "purging already truncated",
    );
    assert!(!ok);
    assert!(
        err.contains("already acceptable to storage rebind"),
        "{err}"
    );
    assert_eq!(
        revision_row(&f.db, &purging_empty.revision).await.0,
        "purging"
    );

    // Foreign hard link is refused and external link left intact.
    let (ok, _, err) = declare_lost_cli(
        &f.db,
        OWNER,
        &copy,
        &foreign_linked.revision,
        OPERATOR_1,
        "foreign-refused",
        "corrupt but externally linked",
    );
    assert!(!ok);
    assert!(err.contains("foreign hard link"), "{err}");
    assert_eq!(fs::read(&foreign_path).unwrap(), b"bad");
    assert_eq!(
        revision_row(&f.db, &foreign_linked.revision).await.0,
        "active"
    );

    // Locked file (another process holds LOCK_EX) is refused.
    let lock_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(copy.join("revisions").join(&locked_corrupt.reservation))
        .unwrap();
    lock_file.try_lock().unwrap();
    let (ok, _, err) = declare_lost_cli(
        &f.db,
        OWNER,
        &copy,
        &locked_corrupt.revision,
        OPERATOR_1,
        "locked-refused",
        "file currently locked",
    );
    assert!(!ok);
    assert!(err.contains("reservation in use"), "{err}");
    assert_eq!(
        revision_row(&f.db, &locked_corrupt.revision).await.0,
        "active"
    );
    drop(lock_file);

    // Unknown revision UUID is refused cleanly.
    let (ok, _, err) = declare_lost_cli(
        &f.db,
        OWNER,
        &copy,
        "99999999-9999-4999-8999-999999999999",
        OPERATOR_1,
        "missing-row",
        "unknown revision",
    );
    assert!(!ok);
    assert!(err.contains("artifact revision not found"), "{err}");
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn declare_lost_handles_active_retained_with_hold_and_purging_then_rebind_and_gate_open_succeed()
 {
    let f = Fixture::new().await;
    let worker = pool(&f.db, WORKER).await;
    let intact = f.payload("intact", b"intact-0123456789").await;
    let missing_active = f.payload("miss-act", b"missing-active-bytes").await;
    let corrupt_retained = f.payload("corr-ret", b"corrupt-retained-123").await;
    let corrupt_purging = f.payload("corr-prg", b"corrupt-purging-4567").await;
    let already_purged = f.payload("purged", b"purged-before-backup").await;

    retention_grace(&f.db, 0).await;
    step(&f.db.0, &f.c.scope, &already_purged.revision, Step::Retain)
        .await
        .unwrap();
    assert_eq!(
        artifact_fs::purge_due(&worker, &f.store, 10).await.unwrap(),
        1
    );
    step(
        &f.db.0,
        &f.c.scope,
        &corrupt_retained.revision,
        Step::Retain,
    )
    .await
    .unwrap();
    // Place an operator retention hold on corrupt_retained; declare-lost must clear it.
    sqlx::query(
        "INSERT INTO openmettle.artifact_retention_holds (scope_id, artifact_revision_id)
         VALUES ($1::uuid, $2::uuid)",
    )
    .bind(&f.c.scope)
    .bind(&corrupt_retained.revision)
    .execute(&mut f.db.admin().await)
    .await
    .unwrap();
    step(&f.db.0, &f.c.scope, &corrupt_purging.revision, Step::Retain)
        .await
        .unwrap();
    step(&f.db.0, &f.c.scope, &corrupt_purging.revision, Step::Claim)
        .await
        .unwrap();

    // Export deletion journal before restore.
    let dir = Dir::new();
    let export_path = dir.path("journal.export");
    let (ok, _, err) = cli(&f.db, &["journal", "export", &export_path]);
    assert!(ok, "{err}");
    let export_text = fs::read_to_string(&export_path).unwrap();
    let export = Export::parse(&export_text).unwrap();
    let pre_seq = export.seq;

    let copy = tar_copy(&f.root, &dir, "restored");
    // Simulate unrecoverable data loss on the copied volume:
    fs::remove_file(copy.join("revisions").join(&missing_active.reservation)).unwrap();
    fs::write(
        copy.join("revisions").join(&corrupt_retained.reservation),
        b"corrupt!",
    )
    .unwrap();
    fs::write(
        copy.join("revisions").join(&corrupt_purging.reservation),
        b"corrupt-purging!",
    )
    .unwrap();

    // Close restore gate at the exported watermark (head is already at pre_seq).
    let mut lock_args = vec![
        "restore".to_owned(),
        "lock".to_owned(),
        "--required-origin".to_owned(),
        export.origin_us.to_string(),
        "--required-lifecycle-origin".to_owned(),
        export.lifecycle_origin_us.unwrap().to_string(),
        "--required-lifecycle-baseline-digest".to_owned(),
        export.lifecycle_baseline_digest.clone().unwrap(),
        "--required-seq".to_owned(),
        export.seq.to_string(),
        "--required-digest".to_owned(),
        export.digest.clone(),
        "--export-complete".to_owned(),
    ];
    if let Some(co) = export.connection_origin_us {
        lock_args.push("--required-connection-origin".to_owned());
        lock_args.push(co.to_string());
    }
    let lock_refs: Vec<&str> = lock_args.iter().map(String::as_str).collect();
    let (ok, _, err) = cli(&f.db, &lock_refs);
    assert!(ok, "{err}");
    assert!(!gate_open_of(&f.db).await);

    // First rebind fails on the 3 damaged settled revisions and holds adoption_run_id.
    let (ok, out, _) = cli(&f.db, &["storage", "rebind", copy.to_str().unwrap()]);
    assert!(!ok, "{out}");
    assert!(out.contains("failed 3"), "{out}");
    let held_barrier = barrier_of(&f.db).await.expect("barrier must be held");

    let before_acct = storage_account(&f.db, &f.c.scope).await;
    let before_inst = instance_totals(&f.db).await;

    // Declare all 3 unrecoverable payloads lost.
    for (rev, key, reason, expect_unlinked) in [
        (&missing_active, "lost-k1", "missing from backup media", 0),
        (
            &corrupt_retained,
            "lost-k2",
            "bitrot on retained backup copy",
            1,
        ),
        (
            &corrupt_purging,
            "lost-k3",
            "bitrot on purging backup copy",
            1,
        ),
    ] {
        let (ok, out, err) =
            declare_lost_cli(&f.db, OWNER, &copy, &rev.revision, OPERATOR_1, key, reason);
        assert!(ok, "{out}{err}");
        assert!(
            out.contains("applied storage.declare_payload_lost"),
            "{out}"
        );
        assert!(
            out.contains(&format!("unlinked={expect_unlinked}")),
            "{out}"
        );
        assert!(
            !copy.join("revisions").join(&rev.reservation).exists(),
            "leftover corrupt file should be unlinked"
        );
    }

    // Verify accounting decremented exactly once.
    let after_acct = storage_account(&f.db, &f.c.scope).await;
    let after_inst = instance_totals(&f.db).await;
    assert_eq!(after_acct.0, before_acct.0 - missing_active.size_bytes);
    assert_eq!(
        after_acct.1,
        before_acct.1 - corrupt_retained.size_bytes - corrupt_purging.size_bytes
    );
    assert_eq!(after_inst.0, before_inst.0 - missing_active.size_bytes);
    assert_eq!(
        after_inst.1,
        before_inst.1 - corrupt_retained.size_bytes - corrupt_purging.size_bytes
    );

    // Retention hold on corrupt_retained was removed.
    let holds: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.artifact_retention_holds WHERE artifact_revision_id = $1::uuid",
    )
    .bind(&corrupt_retained.revision)
    .fetch_one(&mut f.db.admin().await)
    .await
    .unwrap();
    assert_eq!(holds, 0);

    // Revision metadata: lost_at populated, retained timestamps preserved where present.
    let r_act = revision_row(&f.db, &missing_active.revision).await;
    assert_eq!(
        (
            r_act.0.as_str(),
            r_act.1,
            r_act.2,
            r_act.3,
            r_act.4.as_str()
        ),
        ("lost", true, None, None, "none")
    );
    let r_ret = revision_row(&f.db, &corrupt_retained.revision).await;
    assert_eq!(r_ret.0, "lost");
    assert!(r_ret.1 && r_ret.2.is_some() && r_ret.3.is_some());
    let r_prg = revision_row(&f.db, &corrupt_purging.revision).await;
    assert_eq!(r_prg.0, "lost");
    assert!(r_prg.1 && r_prg.2.is_some() && r_prg.3.is_some());

    // Idempotent retry on exact same request_key succeeds without changing accounting or journal.
    let (ok, out, err) = declare_lost_cli(
        &f.db,
        OWNER,
        &copy,
        &missing_active.revision,
        OPERATOR_1,
        "lost-k1",
        "missing from backup media",
    );
    assert!(ok, "{out}{err}");
    assert!(
        out.contains("replayed storage.declare_payload_lost"),
        "{out}"
    );
    assert_eq!(storage_account(&f.db, &f.c.scope).await, after_acct);

    // Reusing request_key with different reason, revision, or operator conflicts (23505).
    for (rev, op, reason) in [
        (
            missing_active.revision.as_str(),
            OPERATOR_1,
            "different reason",
        ),
        (
            intact.revision.as_str(),
            OPERATOR_1,
            "missing from backup media",
        ),
        (
            missing_active.revision.as_str(),
            OPERATOR_2,
            "missing from backup media",
        ),
    ] {
        let (ok, _, err) = declare_lost_cli(&f.db, OWNER, &copy, rev, op, "lost-k1", reason);
        assert!(!ok);
        assert!(
            err.contains("request key already used with different parameters"),
            "{err}"
        );
    }

    // Fresh request_key on already-lost or already-purged revision is refused.
    let (ok, _, err) = declare_lost_cli(
        &f.db,
        OWNER,
        &copy,
        &missing_active.revision,
        OPERATOR_1,
        "lost-k-new",
        "second declaration",
    );
    assert!(!ok);
    assert!(err.contains("already declared lost"), "{err}");

    let (ok, _, err) = declare_lost_cli(
        &f.db,
        OWNER,
        &copy,
        &already_purged.revision,
        OPERATOR_1,
        "lost-k-purged",
        "target is purged",
    );
    assert!(!ok);
    assert!(err.contains("purged"), "{err}");

    // Deletion journal advanced by 3 'artifact_revision.lost' entries.
    let head_seq: i64 =
        sqlx::query_scalar("SELECT journal_seq FROM openmettle.deletion_journal_head WHERE id")
            .fetch_one(&mut f.db.admin().await)
            .await
            .unwrap();
    assert_eq!(head_seq, pre_seq + 3);

    // Resume storage rebind with held barrier -> succeeds and clears adoption_run_id.
    let (ok, out, err) = cli(
        &f.db,
        &[
            "storage",
            "rebind",
            copy.to_str().unwrap(),
            "--replace-adoption-run",
            &held_barrier,
        ],
    );
    assert!(ok, "{out}{err}");
    assert!(out.contains("failed 0"), "{out}");
    assert_eq!(barrier_of(&f.db).await, None);

    // Original export file still completes `restore replay` and opens the gate despite the
    // verified post-replay lost tail beyond required_journal_seq.
    let (ok, out, err) = cli(
        &f.db,
        &["restore", "replay", &export_path, copy.to_str().unwrap()],
    );
    assert!(ok, "{out}{err}");
    assert!(out.contains("restore gate open"), "{out}");
    assert!(gate_open_of(&f.db).await);

    // Final quota verify reports zero accounting or file drift.
    let (ok, out, err) = cli(&f.db, &["quota", "verify", copy.to_str().unwrap()]);
    assert!(ok, "{out}{err}");
    assert!(
        out.contains("storage mismatches 0") && out.contains("file mismatches 0"),
        "{out}"
    );
    let _ = intact;
    worker.close().await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn second_restore_replays_lost_journal_onto_older_backup_and_cleans_obsolete_file() {
    let f = Fixture::new().await;
    let keep = f.payload("keep", b"kept-alive-bytes").await;
    let lost_act = f.payload("lost-act", b"will-be-declared-lost-01").await;
    let lost_ret = f.payload("lost-ret", b"will-be-lost-ret02").await;

    retention_grace(&f.db, 86_400).await;
    step(&f.db.0, &f.c.scope, &lost_ret.revision, Step::Retain)
        .await
        .unwrap();

    // Snapshot an older backup BEFORE the payloads were declared lost (both files intact on disk).
    let dir = Dir::new();
    let older_vol_a = tar_copy(&f.root, &dir, "older-vol-a");
    let older_vol_b = tar_copy(&f.root, &dir, "older-vol-b");
    f.api.close().await;
    let older_db_a = backup_db(&f.db).await;
    let older_db_b = backup_db(&f.db).await;

    // On the live instance, declare both payloads lost after simulating a damaged volume copy.
    let live_copy = tar_copy(&f.root, &dir, "live-damaged");
    fs::remove_file(live_copy.join("revisions").join(&lost_act.reservation)).unwrap();
    fs::write(
        live_copy.join("revisions").join(&lost_ret.reservation),
        b"bad",
    )
    .unwrap();
    let (ok, _, _) = cli(&f.db, &["storage", "rebind", live_copy.to_str().unwrap()]);
    assert!(!ok);
    let b = barrier_of(&f.db).await.unwrap();
    for (rev, key) in [(&lost_act, "exp-lost-1"), (&lost_ret, "exp-lost-2")] {
        let (ok, out, err) = declare_lost_cli(
            &f.db,
            OWNER,
            &live_copy,
            &rev.revision,
            OPERATOR_1,
            key,
            "lost on live",
        );
        assert!(ok, "{out}{err}");
    }
    let (ok, out, err) = cli(
        &f.db,
        &[
            "storage",
            "rebind",
            live_copy.to_str().unwrap(),
            "--replace-adoption-run",
            &b,
        ],
    );
    assert!(ok, "{out}{err}");

    let export_path = dir.path("after-loss.export");
    let (ok, _, err) = cli(&f.db, &["journal", "export", &export_path]);
    assert!(ok, "{err}");
    let export_text = fs::read_to_string(&export_path).unwrap();
    let export = Export::parse(&export_text).unwrap();
    assert_eq!(
        export_text
            .lines()
            .filter(|line| line.contains(" artifact_revision.lost "))
            .count(),
        2
    );

    let lock_for = |db: &TestDb| {
        let mut args = vec![
            "restore".to_owned(),
            "lock".to_owned(),
            "--required-origin".to_owned(),
            export.origin_us.to_string(),
            "--required-lifecycle-origin".to_owned(),
            export.lifecycle_origin_us.unwrap().to_string(),
            "--required-lifecycle-baseline-digest".to_owned(),
            export.lifecycle_baseline_digest.clone().unwrap(),
            "--required-seq".to_owned(),
            export.seq.to_string(),
            "--required-digest".to_owned(),
            export.digest.clone(),
            "--export-complete".to_owned(),
        ];
        if let Some(co) = export.connection_origin_us {
            args.push("--required-connection-origin".to_owned());
            args.push(co.to_string());
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        cli(db, &refs)
    };

    // Path A (standard order): restore lock -> storage rebind -> restore replay.
    // Rebind succeeds on older_vol_a (files still present), then restore replay replays
    // artifact_revision.lost, releases accounting, cleans obsolete files, and opens gate.
    let (ok, _, err) = lock_for(&older_db_a);
    assert!(ok, "{err}");
    let (ok, out, err) = cli(
        &older_db_a,
        &["storage", "rebind", older_vol_a.to_str().unwrap()],
    );
    assert!(ok, "{out}{err}");
    let (ok, out, err) = cli(
        &older_db_a,
        &[
            "restore",
            "replay",
            &export_path,
            older_vol_a.to_str().unwrap(),
        ],
    );
    assert!(ok, "{out}{err}");
    assert!(gate_open_of(&older_db_a).await);
    assert_eq!(
        revision_row(&older_db_a, &lost_act.revision).await.0,
        "lost"
    );
    assert_eq!(
        revision_row(&older_db_a, &lost_ret.revision).await.0,
        "lost"
    );
    assert!(
        !older_vol_a
            .join("revisions")
            .join(&lost_act.reservation)
            .exists()
    );
    assert!(
        !older_vol_a
            .join("revisions")
            .join(&lost_ret.reservation)
            .exists()
    );
    assert!(
        older_vol_a
            .join("revisions")
            .join(&keep.reservation)
            .exists()
    );
    assert_eq!(
        storage_account(&older_db_a, &f.c.scope).await,
        (keep.size_bytes, 0, 0)
    );
    let (ok, out, err) = cli(
        &older_db_a,
        &["quota", "verify", older_vol_a.to_str().unwrap()],
    );
    assert!(ok, "{out}{err}");

    // Path B (DB apply before rebind): restore lock -> restore::apply -> storage rebind -> restore replay.
    // Verifies `storage rebind` itself cleans leftover files for settled+lost reservations.
    let (ok, _, err) = lock_for(&older_db_b);
    assert!(ok, "{err}");
    let owner_b = pool(&older_db_b, OWNER).await;
    restore::apply(&owner_b, &export).await.unwrap();
    owner_b.close().await;
    assert_eq!(
        revision_row(&older_db_b, &lost_act.revision).await.0,
        "lost"
    );
    assert!(
        older_vol_b
            .join("revisions")
            .join(&lost_act.reservation)
            .exists()
    );
    let (ok, out, err) = cli(
        &older_db_b,
        &["storage", "rebind", older_vol_b.to_str().unwrap()],
    );
    assert!(ok, "{out}{err}");
    assert!(
        !older_vol_b
            .join("revisions")
            .join(&lost_act.reservation)
            .exists()
    );
    assert!(
        !older_vol_b
            .join("revisions")
            .join(&lost_ret.reservation)
            .exists()
    );
    let (ok, out, err) = cli(
        &older_db_b,
        &[
            "restore",
            "replay",
            &export_path,
            older_vol_b.to_str().unwrap(),
        ],
    );
    assert!(ok, "{out}{err}");
    let (ok, out, err) = cli(
        &older_db_b,
        &["quota", "verify", older_vol_b.to_str().unwrap()],
    );
    assert!(ok, "{out}{err}");
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn v1_api_surfaces_lost_metadata_returns_410_conceals_unauthorized_and_keeps_conversations_safe()
 {
    let db = TestDb::migrated().await;
    limits(&db, Some(GIB), Some(GIB)).await;
    let mut owner = connect(&db.0, OWNER).await;
    providers(&mut owner).await;
    let alice = account(&mut owner, PROVIDER, true, FUTURE).await;
    let bob = account(&mut owner, PROVIDER, true, FUTURE).await;
    let outsider = account(&mut owner, PROVIDER, true, FUTURE).await;
    for scope_kind in ["instance", "personal", "project"] {
        sqlx::query(
            "INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, hard_limit)
             VALUES ($1, 'usage_tokens', 100000)",
        )
        .bind(scope_kind)
        .execute(&mut owner)
        .await
        .unwrap();
    }

    let dir = Dir::new();
    fs::create_dir(dir.path("artifacts")).unwrap();
    let mut doc = auth_config_support::document_v2_native(&dir, &Ca::new().pem());
    doc["cursor_keys"] = auth_config_support::cursor_keys(&dir);
    let mut catalog: Value =
        serde_json::from_slice(include_bytes!("../fixtures/conversation-catalog-v1.json")).unwrap();
    catalog["models"]["a"]["prompt_bound"] = json!({
        "fixed_tokens": 4,
        "tokens_per_turn": 4,
        "tokens_per_part": 2,
        "tokens_per_byte": 1,
        "tokens_per_attachment": 10
    });
    doc["catalog_file"] = json!(dir.write("catalog.json", &serde_json::to_vec(&catalog).unwrap()));
    doc["admission_limits"] = json!({
        "live_per_actor": 4,
        "live_per_scope": 8,
        "queued_in_instance": 32,
        "queue_timeout_seconds": 300,
        "round_cap": 10
    });
    let api = Api::configured(&db, dir, doc.clone(), 4);
    let alice_cookie = browser(&db, &alice, 1).await;
    let bob_cookie = browser(&db, &bob, 2).await;
    let outsider_cookie = browser(&db, &outsider, 3).await;
    let alice_b = As::Browser(&alice_cookie);
    let bob_b = As::Browser(&bob_cookie);
    let outsider_b = As::Browser(&outsider_cookie);

    // Alice uploads rev1 (to be declared lost) and rev2 (stays active) on the same artifact.
    let body1 = form(
        "bnd1",
        &[
            metadata_part("{}"),
            file_part(Some("first.txt"), "text/plain", "first-revision-bytes"),
        ],
        true,
    );
    let r1 = success(api.upload(alice_b, "/v1/artifacts", "up-1", &body1), 201);
    let art_id = r1["artifact_id"].as_str().unwrap().to_owned();
    let rev1_id = r1["revision_id"].as_str().unwrap().to_owned();

    let body2 = form(
        "bnd2",
        &[
            metadata_part("{}"),
            file_part(Some("second.txt"), "text/plain", "second-revision-bytes"),
        ],
        true,
    );
    let r2 = success(
        api.upload(
            alice_b,
            &format!("/v1/artifacts/{art_id}/revisions"),
            "up-2",
            &body2,
        ),
        201,
    );
    let rev2_id = r2["revision_id"].as_str().unwrap().to_owned();

    // Share the artifact read-only with Bob; Outsider has no share.
    let mut api_cn = connect(&db.0, API).await;
    projects::share_resource(
        &mut api_cn,
        &ctx(&alice, "share-bob"),
        ResourceKind::Artifact,
        &art_id,
        &Grantee::User(bob.user.clone()),
        ResourceAccess::Read,
    )
    .await
    .unwrap();

    // Create a conversation and attach rev1 to a user message before loss.
    let conv = success(
        api.call(
            alice_b,
            "POST",
            "/v1/conversations",
            Some("conv-1"),
            Some(&json!({})),
        ),
        201,
    );
    let conv_id = conv["conversation_id"].as_str().unwrap().to_owned();
    let branch_id = conv["branch_id"].as_str().unwrap().to_owned();
    let scope_id = conv["scope_id"].as_str().unwrap().to_owned();
    let run1 = success(
        api.call(
            alice_b,
            "POST",
            "/v1/runs",
            Some("run-with-att"),
            Some(&json!({
                "conversation_id": conv_id,
                "branch_id": branch_id,
                "proposal": {
                    "expected_head_message_id": null,
                    "turn": {
                        "mode": "append",
                        "input_message_id": "00000000-0000-4000-8000-000000001541",
                        "parts": [
                            {"text": "hello with attachment"},
                            {"attachment": rev1_id}
                        ]
                    },
                    "selection": {
                        "model": "a",
                        "layer": {"controls": {"context_window": "450", "output_reserve": "100"}}
                    },
                    "requested_rounds": 1
                }
            })),
        ),
        201,
    );
    let run1_id = run1["run_id"].as_str().unwrap().to_owned();

    // Stop API, remove rev1's file, declare rev1 lost, finish rebind, restart API.
    let dir = api.kill();
    let artifacts_root = PathBuf::from(dir.path("artifacts"));
    let res1_id: String = sqlx::query_scalar(
        "SELECT reservation_id::text FROM openmettle.artifact_revisions WHERE id = $1::uuid",
    )
    .bind(&rev1_id)
    .fetch_one(&mut owner)
    .await
    .unwrap();
    fs::remove_file(artifacts_root.join("revisions").join(&res1_id)).unwrap();
    let (ok, _, _) = cli(
        &db,
        &["storage", "rebind", artifacts_root.to_str().unwrap()],
    );
    assert!(!ok);
    let held = barrier_of(&db).await.unwrap();
    let (ok, out, err) = declare_lost_cli(
        &db,
        OWNER,
        &artifacts_root,
        &rev1_id,
        OPERATOR_1,
        "v1-lost-1",
        "payload lost after restore",
    );
    assert!(ok, "{out}{err}");
    let (ok, out, err) = cli(
        &db,
        &[
            "storage",
            "rebind",
            artifacts_root.to_str().unwrap(),
            "--replace-adoption-run",
            &held,
        ],
    );
    assert!(ok, "{out}{err}");
    let api = Api::configured(&db, dir, doc, 4);

    // 1. Authorized owner and reader see state="lost" and lost_at on metadata, and 410 payload_lost on content.
    let rev1_path = format!("/v1/artifacts/{art_id}/revisions/{rev1_id}");
    let rev1_content = format!("{rev1_path}/content");
    for caller in [alice_b, bob_b] {
        let meta = success(api.call(caller, "GET", &rev1_path, None, None), 200);
        let decoded = consumer::decode_revision(&meta).unwrap();
        assert_eq!(decoded.state, consumer::RevisionState::Lost);
        assert!(!decoded.state.downloadable());
        assert!(decoded.lost_at.is_some());

        let (status, _, body) = api.download(caller, "GET", &rev1_content, None);
        assert_eq!(status, 410, "{body}");
        let problem_json: Value = serde_json::from_str(&body).unwrap();
        let problem = consumer::decode_problem(&problem_json).unwrap();
        assert_eq!(problem.category, consumer::Category::PayloadLost);
        assert_eq!(problem_json["code"], "payload_lost");

        let (head_status, _, head_body) = api.download(caller, "HEAD", &rev1_content, None);
        assert_eq!(head_status, 410);
        assert!(head_body.is_empty());
    }

    // 2. Unauthorized outsider still gets concealed 404 not_found (never 410).
    refused(
        api.call(outsider_b, "GET", &rev1_path, None, None),
        404,
        "not_found",
    );
    let (status, _, body) = api.download(outsider_b, "GET", &rev1_content, None);
    assert_eq!(status, 404, "{body}");
    let out_problem: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(out_problem["code"], "not_found");

    // 3. Revision delete and restore on 'lost' return 409 conflict; artifact delete retains rev2 cleanly.
    refused(
        api.call(alice_b, "DELETE", &rev1_path, Some("del-lost"), None),
        409,
        "conflict",
    );
    refused(
        api.call(
            alice_b,
            "POST",
            &format!("{rev1_path}/restore"),
            Some("rest-lost"),
            None,
        ),
        409,
        "conflict",
    );
    success(
        api.call(
            alice_b,
            "DELETE",
            &format!("/v1/artifacts/{art_id}"),
            Some("del-art"),
            None,
        ),
        204,
    );
    assert_eq!(revision_row(&db, &rev1_id).await.0, "lost");
    assert_eq!(revision_row(&db, &rev2_id).await.0, "retained");

    // 4. Listing conversation messages with the lost attachment returns 200 (no 500) and decodes cleanly.
    let msgs = success(
        api.call(
            alice_b,
            "GET",
            &format!("/v1/conversations/{conv_id}/branches/{branch_id}/messages"),
            None,
            None,
        ),
        200,
    );
    consumer::decode_conversation_operation("listMessages", &msgs).unwrap();
    assert_eq!(msgs["items"].as_array().unwrap().len(), 1);
    let parts = msgs["items"][0]["parts"].as_array().unwrap();
    assert_eq!(
        parts.len(),
        1,
        "unavailable lost attachment should be omitted cleanly"
    );
    assert_eq!(parts[0]["kind"], "text");

    // 5. Attaching a lost revision to a new conversation run is refused cleanly (non-500).
    let conv2 = success(
        api.call(
            alice_b,
            "POST",
            "/v1/conversations",
            Some("conv-2"),
            Some(&json!({})),
        ),
        201,
    );
    let conv2_id = conv2["conversation_id"].as_str().unwrap();
    let branch2_id = conv2["branch_id"].as_str().unwrap();
    refused(
        api.call(
            alice_b,
            "POST",
            "/v1/runs",
            Some("attach-lost"),
            Some(&json!({
                "conversation_id": conv2_id,
                "branch_id": branch2_id,
                "proposal": {
                    "expected_head_message_id": null,
                    "turn": {
                        "mode": "append",
                        "input_message_id": "00000000-0000-4000-8000-000000001542",
                        "parts": [
                            {"text": "try lost attachment"},
                            {"attachment": rev1_id}
                        ]
                    },
                    "selection": {
                        "model": "a",
                        "layer": {"controls": {"context_window": "450", "output_reserve": "100"}}
                    },
                    "requested_rounds": 1
                }
            })),
        ),
        404,
        "not_found",
    );

    // 6. Branch history & real worker turn execution: rev1 surfaces as UnavailableAttachment,
    //    and the worker fails the previously-admitted run cleanly without dispatching inference.
    let alice_principal = authz_store::principal(&db, &alice).await;
    let hist = branches::history(
        &mut api_cn,
        &alice_principal,
        Conversation {
            scope: &scope_id,
            id: &conv_id,
        },
        &branch_id,
        FUTURE - 1000,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        hist.turns[0].parts[1].value,
        PartContent::UnavailableAttachment
    ));

    struct PanicRoutes;
    impl TurnRoutes for PanicRoutes {
        async fn route(
            &self,
            _claim: &ClaimedRun,
            _actor: &str,
            _model: &openmettle_core::model_config::Effective,
        ) -> Result<Route, inference::Error> {
            panic!("worker must fail a lost input attachment before routing inference")
        }
    }
    let parsed_catalog = Catalog::load(&serde_json::to_vec(&catalog).unwrap()).unwrap();
    let worker_pool = pool(&db, WORKER).await;
    let store = Store::open(&artifacts_root).unwrap();
    let settings = WorkerSettings::parse(Duration::from_secs(1), |key| {
        Ok(match key {
            "RUN_SLOTS" | "EXECUTING_PER_ACTOR" | "EXECUTING_PER_SCOPE" => Some("1"),
            "LEASE_MS" => Some("30000"),
            "EXECUTION_TIMEOUT_MS" => Some("180000"),
            "POLL_MS" => Some("100"),
            _ => None,
        }
        .map(str::to_owned))
    })
    .unwrap();
    let leases = LeaseSettings {
        lease: Duration::from_secs(30),
        execution_timeout: Duration::from_secs(180),
    };
    let exec = Arc::new(
        TurnExecutor::new(
            worker_pool.clone(),
            Arc::new(parsed_catalog),
            leases,
            PanicRoutes,
        )
        .with_artifacts(store),
    );
    let db_name = db.0.clone();
    let run1_check = run1_id.clone();
    tokio::time::timeout(
        Duration::from_secs(15),
        worker::run(
            &worker_pool,
            None,
            settings,
            exec,
            async move {
                let mut obs = connect(&db_name, OWNER).await;
                loop {
                    let st: String =
                        sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
                            .bind(&run1_check)
                            .fetch_one(&mut obs)
                            .await
                            .unwrap();
                    if st == "failed" {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            },
            Duration::from_secs(1),
        ),
    )
    .await
    .expect("worker did not fail the lost-attachment run cleanly");
    let final_run_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.runs WHERE id = $1::uuid")
            .bind(&run1_id)
            .fetch_one(&mut owner)
            .await
            .unwrap();
    assert_eq!(final_run_state, "failed");
    worker_pool.close().await;
}

/// Review #1 P1 #1 regression: an intact payload paired with a stale `.purge.<id>` hard link
/// causes `rebind::classify` to fail with a layout error, yet `storage declare-lost` MUST still
/// verify SHA-256 independently, refuse the declaration, and leave both files and DB untouched.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn declare_lost_refuses_intact_payload_with_stale_purge_anchor_leaving_files_and_db_untouched()
 {
    let f = Fixture::new().await;
    let payload = b"intact-active-with-stale-purge-anchor";
    let intact = f.payload("intact-anchor", payload).await;

    let dir = Dir::new();
    let copy = tar_copy(&f.root, &dir, "copy-stale-anchor");
    let rev_path = copy.join("revisions").join(&intact.reservation);
    let purge_path = copy
        .join("revisions")
        .join(format!(".purge.{}", intact.reservation));
    fs::hard_link(&rev_path, &purge_path).unwrap();

    let (ok, out, _) = cli(&f.db, &["storage", "rebind", copy.to_str().unwrap()]);
    assert!(!ok, "rebind must refuse unexpected purge anchor: {out}");
    assert!(out.contains("unexpected purge anchor"), "{out}");
    assert!(barrier_of(&f.db).await.is_some());

    let before_acct = storage_account(&f.db, &f.c.scope).await;
    let before_inst = instance_totals(&f.db).await;
    let before_seq: i64 =
        sqlx::query_scalar("SELECT journal_seq FROM openmettle.deletion_journal_head WHERE id")
            .fetch_one(&mut f.db.admin().await)
            .await
            .unwrap();

    let (ok, _, err) = declare_lost_cli(
        &f.db,
        OWNER,
        &copy,
        &intact.revision,
        OPERATOR_1,
        "p1-1-stale-anchor",
        "must not unlink intact payload with stray purge anchor",
    );
    assert!(!ok);
    assert!(err.contains("payload verifies intact"), "{err}");
    assert_eq!(fs::read(&rev_path).unwrap(), payload);
    assert_eq!(fs::read(&purge_path).unwrap(), payload);
    assert_eq!(revision_row(&f.db, &intact.revision).await.0, "active");
    assert!(!revision_row(&f.db, &intact.revision).await.1);
    assert_eq!(storage_account(&f.db, &f.c.scope).await, before_acct);
    assert_eq!(instance_totals(&f.db).await, before_inst);
    let after_seq: i64 =
        sqlx::query_scalar("SELECT journal_seq FROM openmettle.deletion_journal_head WHERE id")
            .fetch_one(&mut f.db.admin().await)
            .await
            .unwrap();
    assert_eq!(after_seq, before_seq);
}

/// Review #1 P1 #2 regression: when `storage rebind` fails on a missing payload and holds
/// `adoption_run_id` while `restore_reconciliation_gate` is closed behind a post-backup journal
/// export, `openmettle-admin restore replay --db-only FILE` catches up the DB journal under the
/// held barrier so `storage declare-lost`, resumed `storage rebind`, and final `restore replay`
/// succeed with zero drift.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn restore_replay_db_only_catches_up_under_held_rebind_barrier_then_declare_lost_and_gate_open_succeed()
 {
    let f = Fixture::new().await;
    let missing = f.payload("miss-a", b"missing-on-restored-copy").await;
    let retained_after = f.payload("ret-b", b"retained-after-backup-123").await;
    retention_grace(&f.db, 86_400).await;

    let dir = Dir::new();
    let copy = tar_copy(&f.root, &dir, "restored-p1-2");
    f.api.close().await;
    let restored_db = backup_db(&f.db).await;

    // Post-backup lifecycle transition (`active` -> `retained`) creates a journal record whose
    // replay adjusts `active_bytes`/`retained_bytes` and locks `storage_volume_control`.
    step(&f.db.0, &f.c.scope, &retained_after.revision, Step::Retain)
        .await
        .unwrap();
    let export_path = dir.path("p1-2.export");
    let (ok, _, err) = cli(&f.db, &["journal", "export", &export_path]);
    assert!(ok, "{err}");
    let export = Export::parse(&fs::read_to_string(&export_path).unwrap()).unwrap();
    assert!(export.seq >= 1);

    // Simulate missing file for `missing` on the restored volume copy.
    fs::remove_file(copy.join("revisions").join(&missing.reservation)).unwrap();

    // 1. Lock restore gate on restored_db at the post-backup watermark.
    let mut lock_args = vec![
        "restore".to_owned(),
        "lock".to_owned(),
        "--required-origin".to_owned(),
        export.origin_us.to_string(),
        "--required-lifecycle-origin".to_owned(),
        export.lifecycle_origin_us.unwrap().to_string(),
        "--required-lifecycle-baseline-digest".to_owned(),
        export.lifecycle_baseline_digest.clone().unwrap(),
        "--required-seq".to_owned(),
        export.seq.to_string(),
        "--required-digest".to_owned(),
        export.digest.clone(),
        "--export-complete".to_owned(),
    ];
    if let Some(co) = export.connection_origin_us {
        lock_args.push("--required-connection-origin".to_owned());
        lock_args.push(co.to_string());
    }
    let lock_refs: Vec<&str> = lock_args.iter().map(String::as_str).collect();
    let (ok, _, err) = cli(&restored_db, &lock_refs);
    assert!(ok, "{err}");
    assert!(!gate_open_of(&restored_db).await);

    // 2. First `storage rebind` fails on `missing` and holds `adoption_run_id`.
    let (ok, out, _) = cli(&restored_db, &["storage", "rebind", copy.to_str().unwrap()]);
    assert!(!ok, "{out}");
    assert!(out.contains("failed 1"), "{out}");
    let held_barrier = barrier_of(&restored_db)
        .await
        .expect("rebind barrier must be held");

    // 3. `storage declare-lost` refuses while journal is still behind `required_journal_seq`.
    let (ok, _, err) = declare_lost_cli(
        &restored_db,
        OWNER,
        &copy,
        &missing.revision,
        OPERATOR_1,
        "p1-2-too-early",
        "before db-only replay",
    );
    assert!(!ok);
    assert!(
        err.contains("replay the deletion journal before declaring payloads lost"),
        "{err}"
    );

    // 4. `restore replay --db-only FILE` succeeds even while `adoption_run_id` is held, catches up
    //    the journal (`retained_after` -> `retained`), and keeps the gate and barrier closed.
    let (ok, out, err) = cli(
        &restored_db,
        &["restore", "replay", "--db-only", &export_path],
    );
    assert!(ok, "{out}{err}");
    assert!(
        out.contains("database journal caught up (restore gate remains closed)"),
        "{out}"
    );
    assert!(!gate_open_of(&restored_db).await);
    assert_eq!(
        barrier_of(&restored_db).await.as_deref(),
        Some(held_barrier.as_str())
    );
    assert_eq!(
        revision_row(&restored_db, &retained_after.revision).await.0,
        "retained"
    );

    // 5. Now `storage declare-lost` succeeds, resumed `storage rebind` clears the barrier, and full
    //    `restore replay` opens the gate with zero accounting or file drift.
    let (ok, out, err) = declare_lost_cli(
        &restored_db,
        OWNER,
        &copy,
        &missing.revision,
        OPERATOR_1,
        "p1-2-lost",
        "payload missing from recovery copy after db-only replay",
    );
    assert!(ok, "{out}{err}");
    assert!(
        out.contains("applied storage.declare_payload_lost"),
        "{out}"
    );

    let (ok, out, err) = cli(
        &restored_db,
        &[
            "storage",
            "rebind",
            copy.to_str().unwrap(),
            "--replace-adoption-run",
            &held_barrier,
        ],
    );
    assert!(ok, "{out}{err}");
    assert_eq!(barrier_of(&restored_db).await, None);

    let (ok, out, err) = cli(
        &restored_db,
        &["restore", "replay", &export_path, copy.to_str().unwrap()],
    );
    assert!(ok, "{out}{err}");
    assert!(out.contains("restore gate open"), "{out}");
    assert!(gate_open_of(&restored_db).await);

    let (ok, out, err) = cli(&restored_db, &["quota", "verify", copy.to_str().unwrap()]);
    assert!(ok, "{out}{err}");
    assert!(
        out.contains("storage mismatches 0") && out.contains("file mismatches 0"),
        "{out}"
    );
    assert_eq!(
        storage_account(&restored_db, &f.c.scope).await,
        (0, retained_after.size_bytes, 0)
    );
}

/// Review #1 P1 #3 regression:
/// 1. Replaying an `artifact_revision.purged` commitment leaves the revision `'purging'`;
///    `storage declare-lost` (both CLI and SQL) MUST refuse it rather than creating a conflicting
///    `artifact_revision.lost` commitment.
/// 2. `storage rebind` completes already-journaled purges whose files are missing or corrupt on a
///    copied volume (transitioning to `'purged'`, unlinking corrupt bytes, and decrementing
///    `retained_bytes` once), allowing `restore replay` to open the gate with zero drift.
/// 3. On an in-place snapshot restore (`purge_journaled`), an already-journaled purge whose files
///    are absent on disk also completes cleanly so `restore replay` opens the gate with zero drift.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn already_journaled_purge_refuses_declare_lost_and_completes_via_rebind_and_snapshot_restore()
 {
    let f = Fixture::new().await;
    let keep = f.payload("keep", b"kept-alive-bytes").await;
    let purged_missing = f.payload("p-miss", b"purged-and-missing-file").await;
    let purged_corrupt = f.payload("p-corr", b"purged-and-corrupt-file").await;
    retention_grace(&f.db, 0).await;

    let dir = Dir::new();
    let copy_vol = tar_copy(&f.root, &dir, "copy-p1-3");
    f.api.close().await;
    let copy_db = backup_db(&f.db).await;
    let snap_db = backup_db(&f.db).await;

    // Purge both revisions on the live DB (recording `artifact_revision.purged` commitments) while
    // keeping `f.root`'s original inodes intact for the snapshot-restore sub-test.
    for rev in [&purged_missing, &purged_corrupt] {
        for s in [Step::Retain, Step::Claim, Step::Confirm] {
            step(&f.db.0, &f.c.scope, &rev.revision, s).await.unwrap();
        }
    }
    let export_path = dir.path("p1-3.export");
    let (ok, _, err) = cli(&f.db, &["journal", "export", &export_path]);
    assert!(ok, "{err}");
    let export = Export::parse(&fs::read_to_string(&export_path).unwrap()).unwrap();

    let lock_for = |db: &TestDb| {
        let mut args = vec![
            "restore".to_owned(),
            "lock".to_owned(),
            "--required-origin".to_owned(),
            export.origin_us.to_string(),
            "--required-lifecycle-origin".to_owned(),
            export.lifecycle_origin_us.unwrap().to_string(),
            "--required-lifecycle-baseline-digest".to_owned(),
            export.lifecycle_baseline_digest.clone().unwrap(),
            "--required-seq".to_owned(),
            export.seq.to_string(),
            "--required-digest".to_owned(),
            export.digest.clone(),
            "--export-complete".to_owned(),
        ];
        if let Some(co) = export.connection_origin_us {
            args.push("--required-connection-origin".to_owned());
            args.push(co.to_string());
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        cli(db, &refs)
    };

    // --- Sub-test A: file-copy restore with missing + corrupt files for journaled purges ---
    fs::remove_file(copy_vol.join("revisions").join(&purged_missing.reservation)).unwrap();
    fs::write(
        copy_vol.join("revisions").join(&purged_corrupt.reservation),
        b"corrupt!",
    )
    .unwrap();

    let (ok, _, err) = lock_for(&copy_db);
    assert!(ok, "{err}");
    let (ok, out, err) = cli(&copy_db, &["restore", "replay", "--db-only", &export_path]);
    assert!(ok, "{out}{err}");
    assert_eq!(
        revision_row(&copy_db, &purged_missing.revision).await.0,
        "purging"
    );
    assert_eq!(
        revision_row(&copy_db, &purged_corrupt.revision).await.0,
        "purging"
    );

    // `storage declare-lost` refuses both revisions because they already carry terminal
    // `artifact_revision.purged` commitments in `deletion_journal`.
    for (rev, key) in [
        (&purged_missing, "p1-3-miss"),
        (&purged_corrupt, "p1-3-corr"),
    ] {
        let (ok, _, err) = declare_lost_cli(
            &copy_db,
            OWNER,
            &copy_vol,
            &rev.revision,
            OPERATOR_1,
            key,
            "should refuse already-journaled purge",
        );
        assert!(!ok);
        assert!(err.contains("terminal purge commitment"), "{err}");

        let res = sqlx::query(
            "SELECT * FROM openmettle.storage_declare_payload_lost($1::uuid, $2::uuid, $3, $4)",
        )
        .bind(&rev.revision)
        .bind(OPERATOR_1)
        .bind(format!("sql-{key}"))
        .bind("direct sql attempt on journaled purge")
        .execute(&mut connect(&copy_db.0, OWNER).await)
        .await;
        assert_eq!(sqlstate(res), "OMQ03");
    }
    let lost_journal_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM openmettle.deletion_journal WHERE event_kind = 'artifact_revision.lost'",
    )
    .fetch_one(&mut copy_db.admin().await)
    .await
    .unwrap();
    assert_eq!(lost_journal_rows, 0);

    // `storage rebind` completes both already-journaled purges cleanly, removes corrupt bytes,
    // decrements `retained_bytes` once, and releases the barrier.
    let (ok, out, err) = cli(&copy_db, &["storage", "rebind", copy_vol.to_str().unwrap()]);
    assert!(ok, "{out}{err}");
    assert!(out.contains("failed 0"), "{out}");
    assert_eq!(barrier_of(&copy_db).await, None);
    assert_eq!(
        revision_row(&copy_db, &purged_missing.revision).await.0,
        "purged"
    );
    assert_eq!(
        revision_row(&copy_db, &purged_corrupt.revision).await.0,
        "purged"
    );
    assert!(
        !copy_vol
            .join("revisions")
            .join(&purged_corrupt.reservation)
            .exists()
    );
    assert_eq!(
        storage_account(&copy_db, &f.c.scope).await,
        (keep.size_bytes, 0, 0)
    );

    // Full `restore replay` opens the gate and `quota verify` reports zero drift.
    let (ok, out, err) = cli(
        &copy_db,
        &[
            "restore",
            "replay",
            &export_path,
            copy_vol.to_str().unwrap(),
        ],
    );
    assert!(ok, "{out}{err}");
    assert!(gate_open_of(&copy_db).await);
    let (ok, out, err) = cli(&copy_db, &["quota", "verify", copy_vol.to_str().unwrap()]);
    assert!(ok, "{out}{err}");
    assert!(
        out.contains("storage mismatches 0") && out.contains("file mismatches 0"),
        "{out}"
    );

    // --- Sub-test B: in-place snapshot restore where one journaled purge file is missing ---
    fs::remove_file(f.root.join("revisions").join(&purged_missing.reservation)).unwrap();
    let (ok, _, err) = lock_for(&snap_db);
    assert!(ok, "{err}");
    let (ok, out, err) = cli(
        &snap_db,
        &["restore", "replay", &export_path, f.root.to_str().unwrap()],
    );
    assert!(ok, "{out}{err}");
    assert!(out.contains("restore gate open"), "{out}");
    assert!(gate_open_of(&snap_db).await);
    assert_eq!(
        revision_row(&snap_db, &purged_missing.revision).await.0,
        "purged"
    );
    assert_eq!(
        revision_row(&snap_db, &purged_corrupt.revision).await.0,
        "purged"
    );
    assert!(
        !f.root
            .join("revisions")
            .join(&purged_corrupt.reservation)
            .exists()
    );
    assert_eq!(
        storage_account(&snap_db, &f.c.scope).await,
        (keep.size_bytes, 0, 0)
    );
    let (ok, out, err) = cli(&snap_db, &["quota", "verify", f.root.to_str().unwrap()]);
    assert!(ok, "{out}{err}");
    assert!(
        out.contains("storage mismatches 0") && out.contains("file mismatches 0"),
        "{out}"
    );
}

/// Review #1 P2 #6 regression: on a split `purging` layout (corrupt `revisions/<id>` + separate-
/// inode empty `.purge.<id>`), `storage declare-lost` commits durable `'lost'` DB state BEFORE
/// unlinking files so an interruption leaving `.purge.<id>` on disk recovers cleanly on either an
/// idempotent `--request-key` retry OR a resumed `storage rebind`.
#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn declare_lost_split_purging_layout_recovers_leftover_anchor_on_retry_or_rebind() {
    let f = Fixture::new().await;
    let split_retry = f.payload("split-retry", b"split-purging-retry-bytes").await;
    let split_rebind = f
        .payload("split-rebind", b"split-purging-rebind-bytes")
        .await;
    retention_grace(&f.db, 0).await;
    for rev in [&split_retry, &split_rebind] {
        step(&f.db.0, &f.c.scope, &rev.revision, Step::Retain)
            .await
            .unwrap();
        step(&f.db.0, &f.c.scope, &rev.revision, Step::Claim)
            .await
            .unwrap();
    }

    let dir = Dir::new();
    let copy = tar_copy(&f.root, &dir, "copy-split-p2-6");
    for rev in [&split_retry, &split_rebind] {
        fs::write(copy.join("revisions").join(&rev.reservation), b"corrupt!").unwrap();
        fs::write(
            copy.join("revisions")
                .join(format!(".purge.{}", rev.reservation)),
            b"",
        )
        .unwrap();
    }

    let (ok, out, _) = cli(&f.db, &["storage", "rebind", copy.to_str().unwrap()]);
    assert!(!ok, "{out}");
    assert!(out.contains("intra_reservation_inode_mismatch"), "{out}");
    let held_barrier = barrier_of(&f.db).await.unwrap();

    // 1. Declare both split-purging revisions lost.
    for (rev, key) in [(&split_retry, "p2-6-retry"), (&split_rebind, "p2-6-rebind")] {
        let (ok, out, err) = declare_lost_cli(
            &f.db,
            OWNER,
            &copy,
            &rev.revision,
            OPERATOR_1,
            key,
            "split purging payload corrupt",
        );
        assert!(ok, "{out}{err}");
        assert!(out.contains("unlinked=2"), "{out}");
        assert_eq!(revision_row(&f.db, &rev.revision).await.0, "lost");
    }

    let acct_after_lost = storage_account(&f.db, &f.c.scope).await;
    let seq_after_lost: i64 =
        sqlx::query_scalar("SELECT journal_seq FROM openmettle.deletion_journal_head WHERE id")
            .fetch_one(&mut f.db.admin().await)
            .await
            .unwrap();

    // 2. Simulate post-commit interruption leaving `.purge.<id>` on disk for `split_retry`, and
    //    verify exact `--request-key` retry cleans the leftover anchor idempotently.
    let retry_anchor = copy
        .join("revisions")
        .join(format!(".purge.{}", split_retry.reservation));
    fs::write(&retry_anchor, b"").unwrap();
    let (ok, out, err) = declare_lost_cli(
        &f.db,
        OWNER,
        &copy,
        &split_retry.revision,
        OPERATOR_1,
        "p2-6-retry",
        "split purging payload corrupt",
    );
    assert!(ok, "{out}{err}");
    assert!(
        out.contains("replayed storage.declare_payload_lost") && out.contains("unlinked=1"),
        "{out}"
    );
    assert!(!retry_anchor.exists());
    assert_eq!(storage_account(&f.db, &f.c.scope).await, acct_after_lost);
    let seq_after_retry: i64 =
        sqlx::query_scalar("SELECT journal_seq FROM openmettle.deletion_journal_head WHERE id")
            .fetch_one(&mut f.db.admin().await)
            .await
            .unwrap();
    assert_eq!(seq_after_retry, seq_after_lost);

    // 3. Simulate post-commit interruption leaving `.purge.<id>` on disk for `split_rebind`, and
    //    verify resumed `storage rebind` cleans the leftover anchor and passes drift checks.
    let rebind_anchor = copy
        .join("revisions")
        .join(format!(".purge.{}", split_rebind.reservation));
    fs::write(&rebind_anchor, b"").unwrap();
    let (ok, out, err) = cli(
        &f.db,
        &[
            "storage",
            "rebind",
            copy.to_str().unwrap(),
            "--replace-adoption-run",
            &held_barrier,
        ],
    );
    assert!(ok, "{out}{err}");
    assert!(out.contains("failed 0"), "{out}");
    assert!(!rebind_anchor.exists());
    assert_eq!(barrier_of(&f.db).await, None);
    let (ok, out, err) = cli(&f.db, &["quota", "verify", copy.to_str().unwrap()]);
    assert!(ok, "{out}{err}");
    assert!(
        out.contains("storage mismatches 0") && out.contains("file mismatches 0"),
        "{out}"
    );
}
