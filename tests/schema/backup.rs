//! V1-30 (ADR 0046, migration 45, issue #27): maintenance-window coordinated backup capture,
//! admission closing and drain, role boundaries, fail-closed drain timeout & explicit maintenance
//! recovery, AEAD verify/tamper/unpack + full PostgreSQL & artifact volume restore round-trip,
//! GFS retention pruning (7 daily / 4 weekly / 3 monthly), and `openmettle.backup.runs` worker
//! telemetry observation. Every value is synthetic.

use super::authz_http::{Api, As, browser, file_part, form, metadata_part};
use super::authz_runs::personal_of;
use super::authz_store::{Account, FUTURE, PROVIDER, account, ctx, make_admin, providers};
use super::*;
use openmettle_core::{
    artifact_fs::{self, Store},
    authz::{
        leases::{self, LeaseSettings},
        runs::{self as run_queue, ClaimLimits},
        store::WriteOutcome,
    },
    backup::{
        self, BackupError, BackupManifest, CaptureOptions, CliPgDumpRunner, DEFAULT_LEASE_SECONDS,
        GATEWAY_CONSISTENCY_MODE, GraphitiManifest, GraphitiMode, PgDumpRunner,
        REBUILDABLE_INDEXES,
        archive::{BackupMeta, GfsPolicy},
        crypto::BackupKeyRing,
    },
    runs::{self, RunInput, WriteTransaction},
    storage::{self, ReservationInput, Settlement},
    telemetry::metrics::{BackupRunOutcome, Metrics},
    vault::{self, AuthorizeConnectionInput, CreateConnectionInput, VaultKeyRing},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    fs,
    io::Write as IoWrite,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output, Stdio},
    time::Duration,
};

const OPERATOR_1: &str = "11111111-1111-4111-8111-111111111111";
const OPERATOR_2: &str = "22222222-2222-4222-8222-222222222222";

async fn pool(db: &TestDb, role: &str) -> PgPool {
    PgPoolOptions::new()
        .max_connections(4)
        .connect(&db.url(role))
        .await
        .unwrap()
}

async fn configure_limits(
    db: &TestDb,
    budget: Option<i64>,
    personal: Option<i64>,
    project: Option<i64>,
) {
    sqlx::query(
        "UPDATE openmettle.storage_instance
            SET instance_budget_bytes = $1,
                personal_limit_bytes = $2,
                project_limit_bytes = $3",
    )
    .bind(budget)
    .bind(personal)
    .bind(project)
    .execute(&mut db.admin().await)
    .await
    .unwrap();
}

async fn retention_grace(db: &TestDb, seconds: i32) {
    sqlx::query(
        "UPDATE openmettle.retention_policy
            SET min_grace_seconds = least(min_grace_seconds, $1),
                max_grace_seconds = greatest(max_grace_seconds, $1),
                grace_seconds = $1
          WHERE id",
    )
    .bind(seconds)
    .execute(&mut db.admin().await)
    .await
    .unwrap();
}

async fn new_uuid(db: &TestDb) -> String {
    sqlx::query_scalar("SELECT gen_random_uuid()::text")
        .fetch_one(&mut db.admin().await)
        .await
        .unwrap()
}

async fn retain_revision(db: &TestDb, scope: &str, rev: &str) {
    let mut c = connect(&db.0, API).await;
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    storage::retain_revision(&mut tx, scope, rev).await.unwrap();
    tx.commit().await.unwrap();
}

fn admin_as(db: &TestDb, role: &str, args: &[&str], extra_env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_openmettle-admin"));
    scrub_env(&mut cmd);
    cmd.env("OPENMETTLE_ADMIN_DATABASE_URL", db.url(role))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    run_cli(&mut cmd, &format!("openmettle-admin ({role}) {args:?}"))
}

fn admin_cli(db: &TestDb, args: &[&str]) -> (bool, String, String) {
    let out = admin_as(db, OWNER, args, &[]);
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn write_keyring_json(
    dir: &auth_config_support::Dir,
    prefix: &str,
    active_key_id: &str,
    keys: &[(&str, [u8; 32])],
) -> PathBuf {
    let key_dir = PathBuf::from(dir.path(&format!("{prefix}-keys")));
    fs::create_dir_all(&key_dir).unwrap();
    fs::set_permissions(&key_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let mut entries = Vec::new();
    for (id, bytes) in keys {
        let key_path = key_dir.join(format!("{prefix}-{id}.key"));
        fs::write(&key_path, bytes).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        entries.push(json!({ "id": id, "file": key_path.to_str().unwrap() }));
    }
    let cfg_path = key_dir.join(format!("{prefix}-keyring.json"));
    fs::write(
        &cfg_path,
        json!({
            "version": 1,
            "active_key_id": active_key_id,
            "keys": entries,
        })
        .to_string(),
    )
    .unwrap();
    fs::set_permissions(&cfg_path, fs::Permissions::from_mode(0o600)).unwrap();
    cfg_path
}

fn tool_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

struct SyntheticPgDumpRunner;
impl PgDumpRunner for SyntheticPgDumpRunner {
    fn dump(&self, _database_url: &str, writer: &mut dyn IoWrite) -> Result<u64, BackupError> {
        let payload = b"PGDMP-SYNTHETIC-TEST-ARCHIVE-V1";
        writer.write_all(payload)?;
        Ok(payload.len() as u64)
    }
}

async fn seed_user(db: &TestDb) -> (Account, String, String) {
    let mut owner = db.admin().await;
    providers(&mut owner).await;
    let user = account(&mut owner, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner, &user).await;
    drop(owner);
    let session = browser(db, &user, 1).await;
    let personal = personal_of(db, &user).await;
    (user, session, personal)
}

async fn seed_queued_personal_run(db: &TestDb, scope: &str, user: &Account, key: &str) -> String {
    let mut c = connect(&db.0, API).await;
    let conv = conversation(&mut c, scope, "personal", &user.user)
        .await
        .unwrap();
    let msg = message(&mut c, scope, &conv, None).await.unwrap();
    let branch: String = sqlx::query_scalar(
        "INSERT INTO openmettle.conversation_branches (scope_id, conversation_id)
         VALUES ($1::uuid, $2::uuid)
         RETURNING id::text",
    )
    .bind(scope)
    .bind(&conv)
    .fetch_one(&mut c)
    .await
    .unwrap();
    let mut tx = WriteTransaction::begin(&mut c).await.unwrap();
    let run_id = runs::create_run(
        &mut tx,
        &RunInput {
            scope,
            actor: &user.user,
            conversation: &conv,
            branch: &branch,
            message: &msg,
            key,
            format: "openmettle.synthetic-run",
            version: 1,
            input: b"synthetic input",
            config: b"{}",
        },
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    sqlx::query(
        "UPDATE openmettle.runs
            SET queue_expires_at = clock_timestamp() + interval '10 minutes',
                actor_approval_id = $2::uuid,
                round_limit = 4
          WHERE id = $1::uuid",
    )
    .bind(&run_id)
    .bind(&user.approval)
    .execute(&mut db.admin().await)
    .await
    .unwrap();
    run_id
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn maintenance_window_closes_mutations_keeps_reads_probes_and_in_flight_settlement_open_and_enforces_role_boundaries()
 {
    let db = TestDb::migrated().await;
    configure_limits(&db, Some(100_000), Some(100_000), Some(100_000)).await;
    retention_grace(&db, 0).await;

    let (user, session, personal_scope) = seed_user(&db).await;

    let dir = auth_config_support::Dir::new();
    let artifact_root = PathBuf::from(dir.path("artifacts"));
    fs::create_dir(&artifact_root).unwrap();
    let store = Store::open(&artifact_root).unwrap();
    let api_pool = pool(&db, API).await;
    store.initialize_api(&api_pool).await.unwrap();

    // Adopt the artifact volume so pinned-volume checks exercise the real production path.
    let (ok, _, err) = admin_cli(
        &db,
        &[
            "storage",
            "adopt",
            artifact_root.to_str().unwrap(),
            "--confirm-no-on-disk-payloads",
        ],
    );
    assert!(ok, "storage adopt failed: {err}");

    let api = Api::start_in(&db, dir);

    // Seed baseline project, conversation, queued run, and an in-flight upload reservation before
    // maintenance.
    let (status, proj) = api.call(
        As::Browser(&session),
        "POST",
        "/v1/projects",
        Some("proj-pre-maint"),
        Some(&json!({ "name": "Backup Gate Project" })),
    );
    assert_eq!(status, 201, "{proj}");
    let project_id = proj["project_id"]
        .as_str()
        .or_else(|| proj["id"].as_str())
        .unwrap()
        .to_owned();

    let (status, conv) = api.call(
        As::Browser(&session),
        "POST",
        "/v1/conversations",
        Some("conv-pre-maint"),
        Some(&json!({})),
    );
    assert_eq!(status, 201, "{conv}");

    let queued_run_id =
        seed_queued_personal_run(&db, &personal_scope, &user, "queued-before-maint").await;

    let inflight_artifact = new_uuid(&db).await;
    let inflight_reservation = {
        let mut cn = connect(&db.0, API).await;
        let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
        let res = storage::reserve(
            &mut tx,
            &ReservationInput {
                scope: &personal_scope,
                actor: &user.user,
                key: "inflight-before-maint",
                artifact: &inflight_artifact,
                max_bytes: 128,
                run: None,
                operation: None,
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        res.id
    };
    let inflight_payload = b"in-flight-upload-bytes";
    let inflight_digest: [u8; 32] = Sha256::digest(inflight_payload).into();
    let rev_path = artifact_root.join("revisions").join(&inflight_reservation);
    fs::write(&rev_path, inflight_payload).unwrap();
    fs::set_permissions(&rev_path, fs::Permissions::from_mode(0o600)).unwrap();
    let inflight_ino = std::os::unix::fs::MetadataExt::ino(&fs::metadata(&rev_path).unwrap());
    sqlx::query(
        "UPDATE openmettle.storage_reservations
            SET stage_claimed = true, publish_pending = true, payload_ino = $1
          WHERE id = $2::uuid",
    )
    .bind(inflight_ino as i64)
    .bind(&inflight_reservation)
    .execute(&mut db.admin().await)
    .await
    .unwrap();

    // 1. Verify runtime roles have ZERO direct table privileges on backup tables and ZERO
    //    execute privileges on owner backup functions.
    for role in [API, WORKER, ISSUANCE, "openmettle_gateway"] {
        let mut cn = connect(&db.0, role).await;
        for sql in [
            "SELECT * FROM openmettle.backup_maintenance_gate",
            "SELECT * FROM openmettle.backup_runs",
            "SELECT openmettle.backup_enter_maintenance('11111111-1111-4111-8111-111111111111'::uuid, 'rk', 'bad')",
            "SELECT openmettle.backup_release_maintenance('11111111-1111-4111-8111-111111111111'::uuid, 'rk', 'bad', false)",
            "SELECT openmettle.backup_arm_rpo('11111111-1111-4111-8111-111111111111'::uuid, 'rk', 'bad', 86400)",
        ] {
            let err = sqlx::query(sql).execute(&mut cn).await.unwrap_err();
            let code = err
                .as_database_error()
                .and_then(|d| d.code())
                .unwrap_or_default();
            assert_eq!(
                code, "42501",
                "role {role} unexpectedly allowed `{sql}`: {err}"
            );
        }
        // `backup_maintenance_is_active()` is permitted for all four runtime roles.
        let active: bool = sqlx::query_scalar("SELECT openmettle.backup_maintenance_is_active()")
            .fetch_one(&mut cn)
            .await
            .unwrap();
        assert!(!active);

        // `openmettle-admin backup status` must fail for non-owner roles.
        let out = admin_as(&db, role, &["backup", "status"], &[]);
        assert!(
            !out.status.success(),
            "role {role} should fail backup status"
        );
    }

    // `backup_observe_telemetry()` is restricted to openmettle_worker; `backup_maintenance_lock_open()`
    // is denied to openmettle_gateway.
    {
        let mut api_cn = connect(&db.0, API).await;
        let err = sqlx::query("SELECT * FROM openmettle.backup_observe_telemetry()")
            .execute(&mut api_cn)
            .await
            .unwrap_err();
        assert_eq!(
            err.as_database_error().unwrap().code().as_deref(),
            Some("42501")
        );

        let mut gw_cn = connect(&db.0, "openmettle_gateway").await;
        let err = sqlx::query("SELECT openmettle.backup_maintenance_lock_open()")
            .execute(&mut gw_cn)
            .await
            .unwrap_err();
        assert_eq!(
            err.as_database_error().unwrap().code().as_deref(),
            Some("42501")
        );
    }

    // 2. Enter maintenance via CLI (and check exact idempotent replay).
    let enter_args = [
        "backup",
        "enter-maintenance",
        "--operator-id",
        OPERATOR_1,
        "--request-key",
        "enter-maint-1",
        "--reason",
        "scheduled maintenance test",
    ];
    let (ok, out, err) = admin_cli(&db, &enter_args);
    assert!(ok, "enter-maintenance failed: {err}");
    assert!(out.contains("applied backup.maintenance_entered"), "{out}");

    let (ok, out, err) = admin_cli(&db, &enter_args);
    assert!(ok, "enter-maintenance replay failed: {err}");
    assert!(out.contains("replayed backup.maintenance_entered"), "{out}");

    // 3. Health & readiness probes and `/v1` reads remain OPEN during maintenance.
    assert!(
        http_status(api.bind(), "/healthz")
            .unwrap_or_default()
            .contains("200")
    );
    assert!(
        http_status(api.bind(), "/readyz")
            .unwrap_or_default()
            .contains("200")
    );
    let (status, _) = api.call(As::Browser(&session), "GET", "/v1/capabilities", None, None);
    assert_eq!(status, 200);
    let (status, _) = api.call(
        As::Browser(&session),
        "GET",
        &format!("/v1/projects/{project_id}"),
        None,
        None,
    );
    assert_eq!(status, 200);
    let (status, _) = api.call(
        As::Browser(&session),
        "GET",
        "/v1/conversations",
        None,
        None,
    );
    assert_eq!(status, 200);
    let (status, _) = api.call(
        As::Browser(&session),
        "GET",
        "/v1/admin/retention/status",
        None,
        None,
    );
    assert_eq!(status, 200);

    // 4. Mutating `/v1` operations fail closed with `503 unavailable`.
    for (method, path, key, body) in [
        (
            "POST",
            "/v1/projects",
            "maint-proj",
            json!({ "name": "Blocked Project" }),
        ),
        ("POST", "/v1/conversations", "maint-conv", json!({})),
        (
            "POST",
            "/v1/connections",
            "maint-conn",
            json!({
                "provider_kind": "github",
                "account_id": "acct-blocked",
                "origin": "https://api.example.test",
                "allowed_scopes": ["repo:read"]
            }),
        ),
        (
            "PUT",
            "/v1/admin/retention/policy",
            "maint-ret",
            json!({ "grace_seconds": 3600, "reason": "blocked during maintenance" }),
        ),
    ] {
        let (status, problem) =
            api.call(As::Browser(&session), method, path, Some(key), Some(&body));
        assert_eq!(status, 503, "{method} {path} -> {problem}");
        assert_eq!(
            problem["code"], "unavailable",
            "{method} {path} -> {problem}"
        );
    }

    // Artifact upload is refused with 503 before staging bytes.
    let body = form(
        "maint-boundary",
        &[
            metadata_part("{}"),
            file_part(Some("blocked.txt"), "text/plain", "blocked"),
        ],
        true,
    );
    let (status, problem) = api.upload(As::Browser(&session), "/v1/artifacts", "maint-up", &body);
    assert_eq!(status, 503, "{problem}");
    assert_eq!(problem["code"], "unavailable", "{problem}");

    // `openmettle_issuance` maintenance lock fails closed (SQLSTATE OMM01 -> Ok(false)).
    {
        let mut iss_cn = connect(&db.0, ISSUANCE).await;
        let mut tx = iss_cn.begin().await.unwrap();
        assert!(!backup::lock_open_maintenance(&mut tx).await.unwrap());
        tx.rollback().await.unwrap();
    }

    // 5. Worker claiming/reclaiming pauses cleanly (`Ok(None)`) during maintenance, and
    //    already-reserved in-flight uploads CAN still settle!
    let claim_limits = ClaimLimits {
        executing_per_actor: 4,
        executing_per_scope: 4,
    };
    let lease_settings = LeaseSettings {
        lease: Duration::from_secs(30),
        execution_timeout: Duration::from_secs(120),
    };
    let mut worker_cn = connect(&db.0, WORKER).await;
    let claimed = run_queue::claim_next(&mut worker_cn, &claim_limits, &lease_settings)
        .await
        .unwrap();
    assert!(
        claimed.is_none(),
        "worker must not claim queued runs in maintenance"
    );
    let reclaimed = leases::reclaim_next(&mut worker_cn, &lease_settings)
        .await
        .unwrap();
    assert!(
        reclaimed.is_none(),
        "worker must not reclaim runs in maintenance"
    );

    // Already-reserved upload settles cleanly while maintenance is active.
    {
        let mut cn = connect(&db.0, API).await;
        let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
        let rev_id = storage::settle(
            &mut tx,
            &Settlement {
                scope: &personal_scope,
                reservation: &inflight_reservation,
                size_bytes: inflight_payload.len() as i64,
                content_digest: &inflight_digest,
                media_type: "text/plain",
                display_name: Some("inflight.txt"),
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert!(!rev_id.is_empty());
    }

    // 6. Release maintenance explicitly and verify admission & worker claim reopen immediately.
    let (ok, out, err) = admin_cli(
        &db,
        &[
            "backup",
            "release-maintenance",
            "--operator-id",
            OPERATOR_1,
            "--request-key",
            "release-maint-1",
            "--reason",
            "finished maintenance check",
        ],
    );
    assert!(ok, "release-maintenance failed: {err}");
    assert!(out.contains("applied backup.maintenance_released"), "{out}");

    let (status, reopened) = api.call(
        As::Browser(&session),
        "POST",
        "/v1/projects",
        Some("proj-post-maint"),
        Some(&json!({ "name": "Post Maintenance Project" })),
    );
    assert_eq!(status, 201, "{reopened}");

    let claimed_after = run_queue::claim_next(&mut worker_cn, &claim_limits, &lease_settings)
        .await
        .unwrap();
    assert_eq!(
        claimed_after.as_ref().map(|c| c.run_id.as_str()),
        Some(queued_run_id.as_str())
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn drain_timeout_fails_closed_and_requires_explicit_maintenance_recovery() {
    let db = TestDb::migrated().await;
    configure_limits(&db, Some(100_000), Some(100_000), Some(100_000)).await;
    let (user, _, personal_scope) = seed_user(&db).await;

    let owner_pool = pool(&db, OWNER).await;
    let active_run_id =
        seed_queued_personal_run(&db, &personal_scope, &user, "active-drain-run").await;
    let mut worker_cn = connect(&db.0, WORKER).await;
    let claimed = run_queue::claim_next(
        &mut worker_cn,
        &ClaimLimits {
            executing_per_actor: 4,
            executing_per_scope: 4,
        },
        &LeaseSettings {
            lease: Duration::from_secs(300),
            execution_timeout: Duration::from_secs(600),
        },
    )
    .await
    .unwrap()
    .expect("queued run must be claimed");
    assert_eq!(claimed.run_id, active_run_id);

    let dir = auth_config_support::Dir::new();
    let dest_root = PathBuf::from(dir.path("dest"));
    fs::create_dir(&dest_root).unwrap();
    let keyring_path = write_keyring_json(&dir, "bk", "bk-timeout", &[("bk-timeout", [0x33; 32])]);
    let keyring = BackupKeyRing::load_from_config(&keyring_path).unwrap();

    // Capture must fail closed on DrainTimeout, clean up staging, and keep maintenance active.
    let err = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: db.url(OWNER),
            destination_root: dest_root.clone(),
            destination_domain: "offhost-test".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "drain-timeout-req".to_owned(),
            reason: "drain timeout test".to_owned(),
            drain_timeout: Duration::from_millis(250),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: Some(GfsPolicy::default()),
            release_on_success: true,
            allow_local_test_paths: true,
        },
        &SyntheticPgDumpRunner,
    )
    .await
    .unwrap_err();

    match err {
        BackupError::DrainTimeout(counts) => {
            assert_eq!(counts.active_runs, 1);
        }
        other => panic!("expected DrainTimeout, got {other:?}"),
    }

    // Destination root must contain zero staging or published directories.
    let entries: Vec<_> = fs::read_dir(&dest_root).unwrap().collect();
    assert!(entries.is_empty(), "partial artifacts leaked: {entries:?}");

    let status = backup::status(&owner_pool).await.unwrap();
    assert!(
        status.maintenance_active,
        "maintenance_active must stay true after capture failure"
    );
    assert_eq!(status.latest_run_state.as_deref(), Some("failed"));
    assert_eq!(
        status.latest_run_failure_code.as_deref(),
        Some("drain_timeout")
    );
    assert!(status.last_succeeded_run_id.is_none());

    // Simulate a live leased capture run and prove release refuses without --abort-active-run
    // (OMB02) and succeeds with --abort-active-run (marking run incomplete).
    let (live_run_id,): (String,) = sqlx::query_as(
        "SELECT backup_run_id::text FROM openmettle.backup_start_capture(
            $1::uuid, 'live-lease-req', 'live lease check', 'offhost-test', 300
         )",
    )
    .bind(OPERATOR_1)
    .fetch_one(&owner_pool)
    .await
    .unwrap();

    let (ok, _, err_out) = admin_cli(
        &db,
        &[
            "backup",
            "release-maintenance",
            "--operator-id",
            OPERATOR_2,
            "--request-key",
            "release-without-abort",
            "--reason",
            "should refuse live lease",
        ],
    );
    assert!(!ok, "release without --abort-active-run must fail");
    assert!(err_out.contains("OMB02"), "{err_out}");

    let (ok, out, err_out) = admin_cli(
        &db,
        &[
            "backup",
            "release-maintenance",
            "--operator-id",
            OPERATOR_2,
            "--request-key",
            "release-with-abort",
            "--reason",
            "operator confirmed backup process exited",
            "--abort-active-run",
        ],
    );
    assert!(ok, "release with --abort-active-run failed: {err_out}");
    assert!(out.contains(&live_run_id), "{out}");

    let st_after = backup::status(&owner_pool).await.unwrap();
    assert!(!st_after.maintenance_active);
    let aborted_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.backup_runs WHERE id = $1::uuid")
            .bind(&live_run_id)
            .fetch_one(&owner_pool)
            .await
            .unwrap();
    assert_eq!(aborted_state, "incomplete");
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn full_coordinated_capture_verify_tamper_unpack_and_pg_restore_round_trip() {
    let db = TestDb::migrated().await;
    configure_limits(&db, Some(1_000_000), Some(1_000_000), Some(1_000_000)).await;
    retention_grace(&db, 0).await;

    let (user, _, personal_scope) = seed_user(&db).await;
    let owner_pool = pool(&db, OWNER).await;
    let api_pool = pool(&db, API).await;
    let worker_pool = pool(&db, WORKER).await;

    let dir = auth_config_support::Dir::new();
    let artifact_root = PathBuf::from(dir.path("artifacts"));
    fs::create_dir(&artifact_root).unwrap();
    let store = Store::open(&artifact_root).unwrap();
    store.initialize_api(&api_pool).await.unwrap();
    let (ok, _, err) = admin_cli(
        &db,
        &[
            "storage",
            "adopt",
            artifact_root.to_str().unwrap(),
            "--confirm-no-on-disk-payloads",
        ],
    );
    assert!(ok, "storage adopt failed: {err}");

    // Seed 2 active revisions, 1 retained revision, and 1 purged revision (creating a real
    // deletion_journal watermark with journal_seq >= 1).
    let mut seeded_revs = Vec::new();
    for (idx, payload) in [
        (0, b"active-payload-alpha-001".as_slice()),
        (1, b"active-payload-beta-002".as_slice()),
        (2, b"retained-payload-gamma-003".as_slice()),
        (3, b"purged-payload-delta-004".as_slice()),
    ] {
        let art_id = new_uuid(&db).await;
        let res_id = {
            let mut cn = connect(&db.0, API).await;
            let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
            let r = storage::reserve(
                &mut tx,
                &ReservationInput {
                    scope: &personal_scope,
                    actor: &user.user,
                    key: &format!("seed-art-{idx}"),
                    artifact: &art_id,
                    max_bytes: 1024,
                    run: None,
                    operation: None,
                },
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
            r.id
        };
        let path = artifact_root.join("revisions").join(&res_id);
        fs::write(&path, payload).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let ino = std::os::unix::fs::MetadataExt::ino(&fs::metadata(&path).unwrap());
        sqlx::query(
            "UPDATE openmettle.storage_reservations
                SET stage_claimed = true, publish_pending = true, payload_ino = $1
              WHERE id = $2::uuid",
        )
        .bind(ino as i64)
        .bind(&res_id)
        .execute(&owner_pool)
        .await
        .unwrap();
        let digest: [u8; 32] = Sha256::digest(payload).into();
        let rev_id = {
            let mut cn = connect(&db.0, API).await;
            let mut tx = WriteTransaction::begin(&mut cn).await.unwrap();
            let rev = storage::settle(
                &mut tx,
                &Settlement {
                    scope: &personal_scope,
                    reservation: &res_id,
                    size_bytes: payload.len() as i64,
                    content_digest: &digest,
                    media_type: "text/plain",
                    display_name: Some("seed.txt"),
                },
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
            rev
        };
        seeded_revs.push((rev_id, res_id, payload.to_vec()));
    }

    // Move rev[2] to retained, and purge rev[3] through worker purge_due so deletion_journal advances.
    retain_revision(&db, &personal_scope, &seeded_revs[2].0).await;
    retain_revision(&db, &personal_scope, &seeded_revs[3].0).await;
    sqlx::query(
        "UPDATE openmettle.artifact_revisions
            SET purge_after = retained_at + interval '7 days'
          WHERE id = $1::uuid",
    )
    .bind(&seeded_revs[2].0)
    .execute(&owner_pool)
    .await
    .unwrap();
    let purged = artifact_fs::purge_due(&worker_pool, &store, 10)
        .await
        .unwrap();
    assert_eq!(purged, 1);

    // Seed an authorized external connection encrypted under VaultKeyRing ("vault-k1") so
    // vault_required_key_ids is populated in manifest.json.enc and config/vault-key-inventory.json.
    let vault_ring = VaultKeyRing::new(
        "vault-k1".to_owned(),
        vec![("vault-k1".to_owned(), [0x77; 32])],
    )
    .unwrap();
    let scopes = vec!["repo:read".to_owned()];
    let mut api_cn = connect(&db.0, API).await;
    let create_ctx = ctx(&user, "conn-create-1");
    let created_outcome = vault::create_connection(
        &mut api_cn,
        &create_ctx,
        &CreateConnectionInput {
            scope_id: &personal_scope,
            provider_kind: "github",
            account_id: "acct-vault-1",
            origin: "https://api.example.test",
            allowed_scopes: &scopes,
        },
    )
    .await
    .unwrap();
    let connection_id = match created_outcome {
        WriteOutcome::Applied { target_id } | WriteOutcome::Replayed { target_id } => target_id,
    };
    let auth_ctx = ctx(&user, "conn-auth-1");
    vault::authorize_connection(
        &mut api_cn,
        &auth_ctx,
        &vault_ring,
        &connection_id,
        &AuthorizeConnectionInput {
            access_token: "synthetic-access-token",
            refresh_token: Some("synthetic-refresh-token"),
            granted_scopes: &scopes,
            expires_at: Some("2028-01-01T00:00:00Z"),
        },
    )
    .await
    .unwrap();

    // Prepare separate backup keyring, synthetic non-secret config, and synthetic Neo4j dump.
    let backup_keyring_path =
        write_keyring_json(&dir, "bk", "bk-2026-11", &[("bk-2026-11", [0x44; 32])]);
    let backup_keyring = BackupKeyRing::load_from_config(&backup_keyring_path).unwrap();
    let cfg_path = PathBuf::from(dir.write(
        "catalog.json",
        br#"{"version":1,"models":[{"id":"synthetic-model"}]}"#,
    ));
    let neo4j_dump_bytes = b"NEO4J-OFFLINE-DUMP-SYNTHETIC-PAYLOAD-0123456789";
    let neo4j_path = PathBuf::from(dir.write("graphiti.dump", neo4j_dump_bytes));
    let dest_root = PathBuf::from(dir.path("backups"));
    fs::create_dir(&dest_root).unwrap();

    let has_pg_dump = tool_available("pg_dump");
    let has_pg_restore = tool_available("pg_restore");
    let cli_runner = CliPgDumpRunner::default();
    let synth_runner = SyntheticPgDumpRunner;
    let runner: &dyn PgDumpRunner = if has_pg_dump {
        &cli_runner
    } else {
        &synth_runner
    };

    let capture_report = backup::capture_with_runner(
        &owner_pool,
        &backup_keyring,
        &CaptureOptions {
            database_url: db.url(OWNER),
            destination_root: dest_root.clone(),
            destination_domain: "offhost-nas-test".to_owned(),
            artifact_root: Some(artifact_root.clone()),
            operator_id: OPERATOR_1.to_owned(),
            request_key: "full-capture-1".to_owned(),
            reason: "full round-trip capture test".to_owned(),
            drain_timeout: Duration::from_secs(10),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::OfflineDump(neo4j_path.clone()),
            config_files: vec![("catalog.json".to_owned(), cfg_path.clone())],
            prune_policy: Some(GfsPolicy::default()),
            release_on_success: true,
            allow_local_test_paths: true,
        },
        runner,
    )
    .await
    .unwrap();

    assert!(capture_report.released_maintenance);
    assert!(capture_report.journal_seq >= 1);
    assert!(capture_report.backup_dir.is_dir());

    // Verify backup via CLI.
    let (ok, out, err) = admin_cli(
        &db,
        &[
            "backup",
            "verify",
            "--backup-dir",
            capture_report.backup_dir.to_str().unwrap(),
            "--backup-keys-config",
            backup_keyring_path.to_str().unwrap(),
        ],
    );
    assert!(ok, "backup verify failed: {err}");
    assert!(out.contains("backup.verified"), "{out}");
    assert!(out.contains("artifact_revisions=3"), "{out}");

    // Tamper & truncation checks must fail closed.
    let tamper_dir = PathBuf::from(dir.path("tampered"));
    fs::create_dir(&tamper_dir).unwrap();
    for entry in fs::read_dir(&capture_report.backup_dir).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), tamper_dir.join(entry.file_name())).unwrap();
    }
    let mut art_enc = fs::read(tamper_dir.join("artifacts.bin.enc")).unwrap();
    let flip_idx = art_enc.len() - 5;
    art_enc[flip_idx] ^= 0x80;
    fs::write(tamper_dir.join("artifacts.bin.enc"), &art_enc).unwrap();
    assert!(backup::verify_backup(&tamper_dir, &backup_keyring).is_err());

    // Restore artifacts.bin.enc and truncate pg.dump.enc.
    fs::copy(
        capture_report.backup_dir.join("artifacts.bin.enc"),
        tamper_dir.join("artifacts.bin.enc"),
    )
    .unwrap();
    let pg_enc = fs::read(tamper_dir.join("pg.dump.enc")).unwrap();
    fs::write(tamper_dir.join("pg.dump.enc"), &pg_enc[..pg_enc.len() - 3]).unwrap();
    assert!(backup::verify_backup(&tamper_dir, &backup_keyring).is_err());

    // Unpack via CLI into fresh 0700 directory.
    let unpack_dir = PathBuf::from(dir.path("unpacked"));
    let (ok, out, err) = admin_cli(
        &db,
        &[
            "backup",
            "unpack",
            "--backup-dir",
            capture_report.backup_dir.to_str().unwrap(),
            "--output-dir",
            unpack_dir.to_str().unwrap(),
            "--backup-keys-config",
            backup_keyring_path.to_str().unwrap(),
        ],
    );
    assert!(ok, "backup unpack failed: {err}");
    assert!(out.contains("backup.unpacked"), "{out}");
    assert!(out.contains("neo4j_dump=true"), "{out}");
    assert_eq!(
        fs::metadata(&unpack_dir).unwrap().permissions().mode() & 0o777,
        0o700
    );

    let manifest: BackupManifest =
        serde_json::from_slice(&fs::read(unpack_dir.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest.gateway_consistency_mode, GATEWAY_CONSISTENCY_MODE);
    assert_eq!(
        manifest.rebuildable_indexes,
        REBUILDABLE_INDEXES
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>()
    );
    assert_eq!(manifest.vault_required_key_ids, vec!["vault-k1".to_owned()]);
    assert!(matches!(
        manifest.graphiti_neo4j,
        GraphitiManifest::OfflineDump { .. }
    ));
    assert_eq!(manifest.artifact_volume.revision_count, 3);
    assert_eq!(
        fs::read(unpack_dir.join("neo4j.dump")).unwrap(),
        neo4j_dump_bytes
    );
    assert_eq!(
        fs::read(unpack_dir.join("config/catalog.json")).unwrap(),
        fs::read(&cfg_path).unwrap()
    );
    let gw_doc: Value =
        serde_json::from_slice(&fs::read(unpack_dir.join("gateway-entitlements.json")).unwrap())
            .unwrap();
    assert_eq!(gw_doc["consistency_mode"], GATEWAY_CONSISTENCY_MODE);

    // End-to-end pg_restore -> openmettle-migrate boundary verify -> restore lock ->
    // storage rebind -> restore replay -> quota verify -> backup release-maintenance.
    if has_pg_dump && has_pg_restore {
        let restored = TestDb::with_options(false, "").await;
        for sql in [
            "REVOKE ALL ON SCHEMA public FROM PUBLIC".to_owned(),
            format!("REVOKE ALL ON DATABASE {} FROM PUBLIC", restored.0),
            format!(
                "GRANT CONNECT ON DATABASE {} TO openmettle_api, openmettle_worker, openmettle_issuance, openmettle_gateway",
                restored.0
            ),
        ] {
            restored
                .admin()
                .await
                .execute(AssertSqlSafe(sql))
                .await
                .unwrap();
        }

        let restore_out = run_cli(
            Command::new("pg_restore")
                .args(["--no-owner", "--exit-on-error", "--dbname"])
                .arg(restored.url(OWNER))
                .arg(unpack_dir.join("pg.dump"))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
            "pg_restore into fresh database",
        );
        assert!(
            restore_out.status.success(),
            "pg_restore failed: {}",
            stderr(&restore_out)
        );

        // openmettle-migrate verifies role boundaries & ownership on the restored schema.
        let mig_out = run_cli(
            &mut migrate_command(&restored.url(OWNER), &[]),
            "migrate verify",
        );
        assert!(
            mig_out.status.success(),
            "migrate verification after pg_restore failed: {}",
            stderr(&mig_out)
        );

        // Because pg.dump was taken inside maintenance, restored DB starts with maintenance active.
        let restored_pool = pool(&restored, OWNER).await;
        let restored_status = backup::status(&restored_pool).await.unwrap();
        assert!(restored_status.maintenance_active);

        // Lock restore gate with exact watermark from manifest.json.
        let mut lock_args: Vec<String> = vec![
            "restore".into(),
            "lock".into(),
            "--required-origin".into(),
            manifest.deletion_journal.origin_us.to_string(),
            "--required-seq".into(),
            manifest.deletion_journal.journal_seq.to_string(),
            "--required-digest".into(),
            manifest.deletion_journal.chain_digest.clone(),
            "--export-complete".into(),
        ];
        if let (Some(lo), Some(lb)) = (
            manifest.deletion_journal.lifecycle_origin_us,
            manifest.deletion_journal.lifecycle_baseline_digest.as_ref(),
        ) {
            lock_args.push("--required-lifecycle-origin".into());
            lock_args.push(lo.to_string());
            lock_args.push("--required-lifecycle-baseline-digest".into());
            lock_args.push(lb.clone());
        }
        if let Some(co) = manifest.deletion_journal.connection_origin_us {
            lock_args.push("--required-connection-origin".into());
            lock_args.push(co.to_string());
        }
        let lock_refs: Vec<&str> = lock_args.iter().map(String::as_str).collect();
        let (ok, _, err) = admin_cli(&restored, &lock_refs);
        assert!(ok, "restore lock failed: {err}");

        let restored_artifacts = unpack_dir.join("artifacts");
        let (ok, _, err) = admin_cli(
            &restored,
            &["storage", "rebind", restored_artifacts.to_str().unwrap()],
        );
        assert!(ok, "storage rebind failed: {err}");

        let (ok, _, err) = admin_cli(
            &restored,
            &[
                "restore",
                "replay",
                unpack_dir.join("deletion-journal.bin").to_str().unwrap(),
                restored_artifacts.to_str().unwrap(),
            ],
        );
        assert!(ok, "restore replay failed: {err}");

        let (ok, _, err) = admin_cli(
            &restored,
            &["quota", "verify", restored_artifacts.to_str().unwrap()],
        );
        assert!(ok, "quota verify failed: {err}");

        let (ok, _, err) = admin_cli(
            &restored,
            &[
                "backup",
                "release-maintenance",
                "--operator-id",
                OPERATOR_1,
                "--request-key",
                "post-restore-release",
                "--reason",
                "completed full restore verification",
                "--abort-active-run",
            ],
        );
        assert!(ok, "post-restore release-maintenance failed: {err}");
        assert!(
            !backup::status(&restored_pool)
                .await
                .unwrap()
                .maintenance_active
        );

        // Verify restored DB rows and artifact payload bytes match source.
        let restored_conn_key: String = sqlx::query_scalar(
            "SELECT encryption_key_id FROM openmettle.external_connections WHERE id = $1::uuid",
        )
        .bind(&connection_id)
        .fetch_one(&restored_pool)
        .await
        .unwrap();
        assert_eq!(restored_conn_key, "vault-k1");

        for (_, res_id, expected_bytes) in &seeded_revs[..3] {
            let actual = fs::read(restored_artifacts.join("revisions").join(res_id)).unwrap();
            assert_eq!(&actual, expected_bytes);
        }
        // Purged revision 3 must not exist on disk.
        assert!(
            !restored_artifacts
                .join("revisions")
                .join(&seeded_revs[3].1)
                .exists()
        );
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn gfs_retention_prunes_7_daily_4_weekly_3_monthly_and_preserves_incomplete_and_foreign_dirs()
{
    let db = TestDb::migrated().await;
    let dir = auth_config_support::Dir::new();
    let dest = PathBuf::from(dir.path("gfs-dest"));
    fs::create_dir(&dest).unwrap();

    // Create 19 completed sets spanning 5 calendar months, 7 ISO weeks, and 10 consecutive days.
    let timestamps = [
        "2026-07-15T02:00:00Z", // old month 1 -> prune
        "2026-08-15T02:00:00Z", // old month 2 -> prune
        "2026-09-10T02:00:00Z", // Sep early -> prune
        "2026-09-28T02:00:00Z", // monthly #3 (Sep newest) -> keep
        "2026-10-05T02:00:00Z", // Oct early -> prune
        "2026-10-19T02:00:00Z", // Oct mid -> prune
        "2026-10-26T02:00:00Z", // monthly #2 (Oct newest) -> keep
        "2026-11-01T02:00:00Z", // W44 -> prune (5th week back)
        "2026-11-08T02:00:00Z", // weekly #4 (W45) -> keep
        "2026-11-15T02:00:00Z", // weekly #3 (W46) -> keep
        "2026-11-18T02:00:00Z", // older than 7 daily, W47 older than 11-22 -> prune
        "2026-11-19T02:00:00Z", // older than 7 daily -> prune
        "2026-11-20T02:00:00Z", // daily #7 -> keep
        "2026-11-21T02:00:00Z", // daily #6 -> keep
        "2026-11-22T02:00:00Z", // daily #5 + weekly #2 (W47) -> keep
        "2026-11-23T02:00:00Z", // daily #4 -> keep
        "2026-11-24T02:00:00Z", // daily #3 -> keep
        "2026-11-25T02:00:00Z", // daily #2 -> keep
        "2026-11-26T02:00:00Z", // daily #1 + weekly #1 (W48) + monthly #1 (Nov) -> keep
    ];
    let mut created_dirs = Vec::new();
    for (idx, ts) in timestamps.iter().enumerate() {
        let run_id = format!("00000000-0000-4000-8000-{idx:012}");
        let name = format!("backup-{idx:02}-{run_id}");
        let bdir = dest.join(&name);
        fs::create_dir(&bdir).unwrap();
        let meta = BackupMeta {
            format: backup::META_FORMAT.to_owned(),
            backup_run_id: run_id,
            completed_at: (*ts).to_owned(),
            destination_domain: "offhost-gfs".to_owned(),
            encryption_key_id: "bk-1".to_owned(),
            manifest_ciphertext_sha256: "a".repeat(64),
            bundle_digest: "b".repeat(64),
            state: "complete".to_owned(),
        };
        fs::write(
            bdir.join("backup-meta.json"),
            serde_json::to_vec(&meta).unwrap(),
        )
        .unwrap();
        created_dirs.push(((*ts).to_owned(), bdir));
    }

    // Add staging, incomplete, and foreign directories that MUST stay untouched.
    let staging = dest.join(".staging.11111111-1111-4111-8111-111111111111");
    let incomplete = dest.join("backup-incomplete-1");
    let foreign = dest.join("operator-notes");
    fs::create_dir(&staging).unwrap();
    fs::create_dir(&incomplete).unwrap();
    fs::write(
        incomplete.join("backup-meta.json"),
        br#"{"state":"in_progress"}"#,
    )
    .unwrap();
    fs::create_dir(&foreign).unwrap();

    // Dry-run reports deletions without removing anything.
    let (ok, out, err) = admin_cli(
        &db,
        &[
            "backup",
            "prune",
            "--destination-root",
            dest.to_str().unwrap(),
            "--keep-daily",
            "7",
            "--keep-weekly",
            "4",
            "--keep-monthly",
            "3",
            "--dry-run",
        ],
    );
    assert!(ok, "prune dry-run failed: {err}");
    assert!(out.contains("dry_run=true"), "{out}");
    assert!(out.contains("kept=11"), "{out}");
    assert!(out.contains("pruned=8"), "{out}");
    assert!(created_dirs.iter().all(|(_, p)| p.exists()));

    // Actual prune removes only the 8 expired completed backups.
    let (ok, out, err) = admin_cli(
        &db,
        &[
            "backup",
            "prune",
            "--destination-root",
            dest.to_str().unwrap(),
            "--keep-daily",
            "7",
            "--keep-weekly",
            "4",
            "--keep-monthly",
            "3",
        ],
    );
    assert!(ok, "prune failed: {err}");
    assert!(out.contains("dry_run=false"), "{out}");
    assert!(out.contains("kept=11"), "{out}");
    assert!(out.contains("pruned=8"), "{out}");

    assert!(staging.exists());
    assert!(incomplete.exists());
    assert!(foreign.exists());
    let expected_kept: std::collections::BTreeSet<&str> = [
        "2026-09-28T02:00:00Z",
        "2026-10-26T02:00:00Z",
        "2026-11-08T02:00:00Z",
        "2026-11-15T02:00:00Z",
        "2026-11-20T02:00:00Z",
        "2026-11-21T02:00:00Z",
        "2026-11-22T02:00:00Z",
        "2026-11-23T02:00:00Z",
        "2026-11-24T02:00:00Z",
        "2026-11-25T02:00:00Z",
        "2026-11-26T02:00:00Z",
    ]
    .into_iter()
    .collect();
    for (ts, path) in &created_dirs {
        assert_eq!(
            path.exists(),
            expected_kept.contains(ts.as_str()),
            "mismatch for {ts}"
        );
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn worker_observe_telemetry_records_succeeded_failed_expired_incomplete_and_rpo_overdue() {
    let db = TestDb::migrated().await;
    let owner_pool = pool(&db, OWNER).await;
    let worker_pool = pool(&db, WORKER).await;
    let metrics = Metrics::new();

    // 1. Fresh unarmed DB emits zero outcomes (no spurious overdue before RPO is armed).
    let obs0 = backup::observe_telemetry_into(&worker_pool, &metrics)
        .await
        .unwrap();
    assert_eq!(obs0, backup::ObservedTelemetry::default());

    // 2. Run one succeeded capture and one failed capture, then observe exactly once.
    let dir = auth_config_support::Dir::new();
    let dest = PathBuf::from(dir.path("dest"));
    fs::create_dir(&dest).unwrap();
    let keyring_path = write_keyring_json(&dir, "bk", "bk-tel", &[("bk-tel", [0x66; 32])]);
    let keyring = BackupKeyRing::load_from_config(&keyring_path).unwrap();

    backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: db.url(OWNER),
            destination_root: dest.clone(),
            destination_domain: "offhost-tel".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "tel-ok-1".to_owned(),
            reason: "telemetry succeeded run".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            allow_local_test_paths: true,
        },
        &SyntheticPgDumpRunner,
    )
    .await
    .unwrap();

    // Create a failed run directly via owner SQL functions.
    let (failed_id,): (String,) = sqlx::query_as(
        "SELECT backup_run_id::text FROM openmettle.backup_start_capture(
            $1::uuid, 'tel-fail-1', 'telemetry failed run', 'offhost-tel', 300
         )",
    )
    .bind(OPERATOR_1)
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    sqlx::query(
        "SELECT openmettle.backup_fail_capture($1::uuid, 'pg_dump_failed', 'simulated failure')",
    )
    .bind(&failed_id)
    .execute(&owner_pool)
    .await
    .unwrap();
    backup::release_maintenance(
        &owner_pool,
        OPERATOR_1,
        "tel-rel-1",
        "release after fail",
        false,
    )
    .await
    .unwrap();

    let obs1 = backup::observe_telemetry_into(&worker_pool, &metrics)
        .await
        .unwrap();
    assert_eq!(obs1.succeeded, 1);
    assert_eq!(obs1.failed, 1);
    assert_eq!(obs1.incomplete, 0);
    assert_eq!(obs1.overdue, 0);
    assert_eq!(metrics.backup_run_count(BackupRunOutcome::Succeeded), 1);
    assert_eq!(metrics.backup_run_count(BackupRunOutcome::Failed), 1);

    // Exact-once observation: second sweep returns all zeros.
    let obs2 = backup::observe_telemetry_into(&worker_pool, &metrics)
        .await
        .unwrap();
    assert_eq!(obs2, backup::ObservedTelemetry::default());

    // 3. Simulate a crashed backup run whose lease expired -> worker marks it `incomplete` and
    //    KEEPS maintenance_active = true!
    let (abandoned_id,): (String,) = sqlx::query_as(
        "SELECT backup_run_id::text FROM openmettle.backup_start_capture(
            $1::uuid, 'tel-abandoned-1', 'crashed backup run', 'offhost-tel', 300
         )",
    )
    .bind(OPERATOR_1)
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.backup_runs
            SET lease_until = clock_timestamp() - interval '10 seconds'
          WHERE id = $1::uuid",
    )
    .bind(&abandoned_id)
    .execute(&owner_pool)
    .await
    .unwrap();

    let obs3 = backup::observe_telemetry_into(&worker_pool, &metrics)
        .await
        .unwrap();
    assert_eq!(obs3.incomplete, 1);
    assert_eq!(metrics.backup_run_count(BackupRunOutcome::Incomplete), 1);
    assert!(
        backup::status(&owner_pool)
            .await
            .unwrap()
            .maintenance_active,
        "expired backup lease must leave maintenance_active = true for explicit recovery"
    );
    let abandoned_state: String =
        sqlx::query_scalar("SELECT state FROM openmettle.backup_runs WHERE id = $1::uuid")
            .bind(&abandoned_id)
            .fetch_one(&owner_pool)
            .await
            .unwrap();
    assert_eq!(abandoned_state, "incomplete");

    backup::release_maintenance(
        &owner_pool,
        OPERATOR_1,
        "tel-rel-2",
        "release after incomplete expiry",
        false,
    )
    .await
    .unwrap();

    // 4. Arm 3600s RPO on a fresh DB and backdate armed timestamp past RPO ->
    //    emits overdue=1 once, throttles hourly, then emits overdue=1 again after 61 minutes.
    let db_overdue = TestDb::migrated().await;
    let overdue_owner = pool(&db_overdue, OWNER).await;
    let overdue_worker = pool(&db_overdue, WORKER).await;
    backup::arm_rpo(
        &overdue_owner,
        OPERATOR_1,
        "arm-overdue-1",
        "arm 1h rpo",
        3600,
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.backup_maintenance_gate
            SET rpo_tracking_armed_at = clock_timestamp() - interval '2 hours'
          WHERE id",
    )
    .execute(&overdue_owner)
    .await
    .unwrap();

    let obs4 = backup::observe_telemetry_into(&overdue_worker, &metrics)
        .await
        .unwrap();
    assert_eq!(obs4.overdue, 1);
    assert_eq!(metrics.backup_run_count(BackupRunOutcome::Overdue), 1);

    // Throttled within 1 hour.
    let obs5 = backup::observe_telemetry_into(&overdue_worker, &metrics)
        .await
        .unwrap();
    assert_eq!(obs5.overdue, 0);

    // Fires again once 1 hour passes.
    sqlx::query(
        "UPDATE openmettle.backup_maintenance_gate
            SET last_overdue_observed_at = clock_timestamp() - interval '61 minutes'
          WHERE id",
    )
    .execute(&overdue_owner)
    .await
    .unwrap();
    let obs6 = backup::observe_telemetry_into(&overdue_worker, &metrics)
        .await
        .unwrap();
    assert_eq!(obs6.overdue, 1);
    assert_eq!(metrics.backup_run_count(BackupRunOutcome::Overdue), 2);
}
