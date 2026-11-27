//! V1-30 (ADR 0046, migration 45, issue #27): maintenance-window coordinated backup capture,
//! admission closing and drain, role boundaries, fail-closed drain timeout & explicit maintenance
//! recovery, AEAD verify/tamper/unpack + full PostgreSQL & artifact volume restore round-trip,
//! GFS retention pruning (7 daily / 4 weekly / 3 monthly), and `openmettle.backup.runs` worker
//! telemetry observation. Every value is synthetic.

use super::authz_http::{Api, As, browser, file_part, form, metadata_part};
use super::authz_runs::{framed_digest, personal_of};
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
        self, ArtifactVolumeManifest, BackupError, BackupManifest, CHROMA_REBUILDABLE_INDEX,
        CaptureOptions, ChromaManifest, ChromaMode, CliPgDumpRunner, ComponentManifest,
        DEFAULT_LEASE_SECONDS, DumpCancel, GATEWAY_CONSISTENCY_MODE, GraphitiManifest,
        GraphitiMode, JournalWatermarkManifest, MANIFEST_FORMAT, META_FORMAT, PgDumpRunner,
        REBUILDABLE_INDEXES,
        archive::{BackupMeta, GfsPolicy},
        crypto::{BackupKeyRing, StreamEncryptor},
    },
    runs::{self, RunInput, WriteTransaction},
    storage::{self, ReservationInput, Settlement},
    telemetry::{
        Process,
        metrics::{BackupRunOutcome, Metrics},
    },
    vault::{self, AuthorizeConnectionInput, CreateConnectionInput, VaultKeyRing},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write as IoWrite,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::Arc,
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

fn pg_tool_major_version(name: &str) -> Option<u32> {
    let out = Command::new(name)
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for token in text.split_whitespace() {
        let digits: String = token.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty()
            && let Ok(major) = digits.parse::<u32>()
        {
            return Some(major);
        }
    }
    None
}

enum PgRestoreMode {
    Local,
    Docker { container: String },
}

/// Resolve PostgreSQL >= 18 `pg_dump` and `pg_restore`:
/// 1. Prefer host `pg_dump`/`pg_restore` when both report major version >= 18.
/// 2. Otherwise, when `POSTGRES_CONTAINER` is set (as in GitHub Actions `Rust runtime`, where the
///    Ubuntu runner carries `pg_dump` 16.x alongside a `postgres:18.1` service container), generate
///    a `0700` `docker exec` wrapper script so tests exercise real PG 18.1 `pg_dump --snapshot`
///    and `pg_restore`.
fn resolve_pg18_tools(
    dir: &auth_config_support::Dir,
) -> Option<(Arc<dyn PgDumpRunner>, PgRestoreMode)> {
    let local_dump = pg_tool_major_version("pg_dump").is_some_and(|v| v >= 18);
    let local_restore = pg_tool_major_version("pg_restore").is_some_and(|v| v >= 18);
    if local_dump && local_restore {
        return Some((Arc::new(CliPgDumpRunner::default()), PgRestoreMode::Local));
    }
    let container = std::env::var("POSTGRES_CONTAINER").ok()?;
    if container.is_empty() {
        return None;
    }
    let wrapper = PathBuf::from(dir.path("pg_dump_18.sh"));
    // Rewrite `--port <mapped>` -> `--port 5432` and `--host localhost` -> `--host 127.0.0.1`
    // inside the container, and feed the host PGPASSFILE (with host:port rewritten to *:*) over
    // stdin into a 0600 temp file inside the container so zero passwords appear in argv or env.
    let posix_script = format!(
        "#!/bin/sh\nset -eu\n\
         CONTAINER='{container}'\n\
         COUNT=$#\n\
         I=0\n\
         while [ \"$I\" -lt \"$COUNT\" ]; do\n\
             ARG=\"$1\"\n\
             shift\n\
             I=$((I + 1))\n\
             case \"$ARG\" in\n\
                 --port=*)\n\
                     set -- \"$@\" --port=5432\n\
                     ;;\n\
                 --port)\n\
                     if [ \"$I\" -lt \"$COUNT\" ]; then\n\
                         shift\n\
                         I=$((I + 1))\n\
                     fi\n\
                     set -- \"$@\" --port=5432\n\
                     ;;\n\
                 --host=*)\n\
                     set -- \"$@\" --host=127.0.0.1\n\
                     ;;\n\
                 --host)\n\
                     if [ \"$I\" -lt \"$COUNT\" ]; then\n\
                         shift\n\
                         I=$((I + 1))\n\
                     fi\n\
                     set -- \"$@\" --host=127.0.0.1\n\
                     ;;\n\
                 *)\n\
                     set -- \"$@\" \"$ARG\"\n\
                     ;;\n\
             esac\n\
         done\n\
         if [ -n \"${{PGPASSFILE:-}}\" ] && [ -f \"$PGPASSFILE\" ]; then\n\
             sed -E 's/^[^:]*:[^:]*:/\\*:\\*:/' \"$PGPASSFILE\" | docker exec -i \\\n\
                 -e \"PGSSLMODE=${{PGSSLMODE:-disable}}\" \\\n\
                 -e \"PGGSSENCMODE=${{PGGSSENCMODE:-disable}}\" \\\n\
                 \"$CONTAINER\" sh -eu -c \\\n\
                 'f=$(mktemp); chmod 600 \"$f\"; trap \"rm -f \\\"$f\\\"\" EXIT; cat > \"$f\"; PGPASSFILE=\"$f\" pg_dump \"$@\" </dev/null' \\\n\
                 _ \"$@\"\n\
         else\n\
             docker exec -e \"PGSSLMODE=${{PGSSLMODE:-disable}}\" -e \"PGGSSENCMODE=${{PGGSSENCMODE:-disable}}\" \"$CONTAINER\" pg_dump \"$@\"\n\
         fi\n"
    );
    fs::write(&wrapper, posix_script).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    Some((
        Arc::new(CliPgDumpRunner::with_program(wrapper)),
        PgRestoreMode::Docker { container },
    ))
}

fn run_pg_restore(mode: &PgRestoreMode, restored: &TestDb, dump_path: &Path) -> Output {
    let dump_len = fs::metadata(dump_path)
        .expect("unpacked pg.dump must exist")
        .len();
    assert!(
        dump_len > 100,
        "unpacked pg.dump unexpectedly small ({dump_len} bytes)"
    );
    let dump_file = fs::File::open(dump_path).unwrap();
    let (mut cmd, label) = match mode {
        PgRestoreMode::Local => {
            let mut cmd = Command::new("pg_restore");
            cmd.args([
                "--format=custom",
                "--no-owner",
                "--exit-on-error",
                "--dbname",
            ])
            .arg(restored.url(OWNER));
            (cmd, "pg_restore into fresh database")
        }
        PgRestoreMode::Docker { container } => {
            let parsed = backup::parse_validated_pg_uri(&restored.url(OWNER)).unwrap();
            let mut cmd = Command::new("docker");
            cmd.args(["exec", "-i", "-e", "PGSSLMODE=disable"]);
            if let Some(pw) = parsed.password.as_deref() {
                cmd.arg("-e").arg(format!("PGPASSWORD={pw}"));
            }
            cmd.arg(container).args([
                "pg_restore",
                "--format=custom",
                "--no-owner",
                "--exit-on-error",
                "--host",
                "127.0.0.1",
                "--port",
                "5432",
                "--username",
                OWNER,
                "--dbname",
                &restored.0,
            ]);
            (cmd, "docker exec pg_restore into fresh database")
        }
    };
    cmd.stdin(Stdio::from(dump_file))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd
        .spawn()
        .unwrap_or_else(|err| panic!("failed to spawn process for {label}: {err}"));
    wait_output(Process(child), label)
}

struct SyntheticPgDumpRunner;
impl PgDumpRunner for SyntheticPgDumpRunner {
    fn dump(
        &self,
        _database_url: &str,
        snapshot_id: Option<&str>,
        _cancel: &DumpCancel,
        writer: &mut dyn IoWrite,
    ) -> Result<u64, BackupError> {
        assert!(
            snapshot_id.is_some_and(|s| !s.is_empty()),
            "coordinated backup capture must export and supply a PostgreSQL snapshot ID"
        );
        let payload = b"PGDMP-SYNTHETIC-TEST-ARCHIVE-V1";
        writer.write_all(payload)?;
        Ok(payload.len() as u64)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Create a genuine cryptographically verifiable backup directory on disk (with `OMBKUP01`
/// component `.enc` files, `manifest.json.enc`, and `backup-meta.json`) for GFS pruning tests.
fn write_verified_backup_set(
    dest: &Path,
    keyring: &BackupKeyRing,
    installation_id: &str,
    destination_domain: &str,
    completed_at: &str,
    idx: usize,
) -> PathBuf {
    let run_id = format!("00000000-0000-4000-8000-{idx:012}");
    let dir_name = format!("backup-{idx:02}-{run_id}");
    let bdir = dest.join(&dir_name);
    fs::create_dir(&bdir).unwrap();
    fs::set_permissions(&bdir, fs::Permissions::from_mode(0o700)).unwrap();

    let mut components = BTreeMap::new();
    for (file_name, role, body) in [
        ("pg.dump.enc", "pg_dump", b"PGDMP-SYNTH".as_slice()),
        (
            "gateway-entitlements.json.enc",
            "gateway_entitlements",
            b"{}".as_slice(),
        ),
        (
            "deletion-journal.bin.enc",
            "deletion_journal",
            b"journal".as_slice(),
        ),
        (
            "artifacts.bin.enc",
            "artifacts",
            b"OMART01\0\0\0".as_slice(),
        ),
        ("config.json.enc", "config", b"{}".as_slice()),
    ] {
        let mut f = fs::File::create(bdir.join(file_name)).unwrap();
        let mut enc = StreamEncryptor::start(keyring, &run_id, role, &mut f).unwrap();
        enc.write_all(body).unwrap();
        let stats = enc.finish().unwrap();
        components.insert(
            file_name.to_owned(),
            ComponentManifest {
                role: role.to_owned(),
                plaintext_bytes: stats.plaintext_bytes,
                plaintext_sha256: hex_encode(&stats.plaintext_sha256),
                ciphertext_bytes: stats.ciphertext_bytes,
                ciphertext_sha256: hex_encode(&stats.ciphertext_sha256),
            },
        );
    }

    let bundle_digest_for = |manifest_ct: &str| -> String {
        let mut parts: Vec<&[u8]> = Vec::new();
        for (name, comp) in &components {
            parts.push(name.as_bytes());
            parts.push(comp.ciphertext_sha256.as_bytes());
        }
        parts.push(manifest_ct.as_bytes());
        hex_encode(&framed_digest(b"openmettle.backup.bundle/1\0", &parts))
    };

    let manifest = BackupManifest {
        format: MANIFEST_FORMAT.to_owned(),
        installation_id: installation_id.to_owned(),
        backup_run_id: run_id.clone(),
        quiesced_at: completed_at.to_owned(),
        completed_at: completed_at.to_owned(),
        schema_version: 45,
        crate_version: env!("CARGO_PKG_VERSION").to_owned(),
        destination_domain: destination_domain.to_owned(),
        rpo_target_seconds: 86_400,
        encryption_key_id: keyring.active_key_id().to_owned(),
        bundle_digest: bundle_digest_for(""),
        components: components.clone(),
        deletion_journal: JournalWatermarkManifest {
            origin_us: 1,
            journal_seq: 0,
            chain_digest: openmettle_core::restore::GENESIS.to_owned(),
            lifecycle_origin_us: None,
            lifecycle_baseline_digest: None,
            connection_origin_us: None,
        },
        artifact_volume: ArtifactVolumeManifest {
            volume_id: None,
            revision_count: 0,
            payload_bytes: 0,
        },
        vault_required_key_ids: Vec::new(),
        gateway_consistency_mode: GATEWAY_CONSISTENCY_MODE.to_owned(),
        graphiti_neo4j: GraphitiManifest::NotProvisioned,
        chroma: ChromaManifest::NotProvisioned,
        rebuildable_indexes: REBUILDABLE_INDEXES
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    let mut mf = fs::File::create(bdir.join("manifest.json.enc")).unwrap();
    let mut menc = StreamEncryptor::start(keyring, &run_id, "manifest", &mut mf).unwrap();
    menc.write_all(&manifest_bytes).unwrap();
    let mstats = menc.finish().unwrap();
    let manifest_ct_hex = hex_encode(&mstats.ciphertext_sha256);

    let meta = BackupMeta {
        format: META_FORMAT.to_owned(),
        installation_id: installation_id.to_owned(),
        backup_run_id: run_id,
        completed_at: completed_at.to_owned(),
        destination_domain: destination_domain.to_owned(),
        encryption_key_id: keyring.active_key_id().to_owned(),
        manifest_ciphertext_sha256: manifest_ct_hex.clone(),
        bundle_digest: bundle_digest_for(&manifest_ct_hex),
        state: "complete".to_owned(),
    };
    fs::write(
        bdir.join("backup-meta.json"),
        serde_json::to_vec_pretty(&meta).unwrap(),
    )
    .unwrap();
    bdir
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
            format: "openmettle.conversation",
            version: 1,
            input: b"synthetic input",
            config: br#"{"effective":{"model":"synthetic-model"}}"#,
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
            "SELECT * FROM openmettle.backup_rpo_telemetry_state",
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
        // `backup_maintenance_is_active()` is granted ONLY to `openmettle_api` and
        // `openmettle_worker`; `openmettle_issuance` and `openmettle_gateway` receive zero new
        // privileges from migration 45.
        if matches!(role, API | WORKER) {
            let active: bool =
                sqlx::query_scalar("SELECT openmettle.backup_maintenance_is_active()")
                    .fetch_one(&mut cn)
                    .await
                    .unwrap();
            assert!(!active);
        } else {
            for fn_sql in [
                "SELECT openmettle.backup_maintenance_is_active()",
                "SELECT openmettle.backup_maintenance_lock_open()",
            ] {
                let err = sqlx::query(fn_sql).execute(&mut cn).await.unwrap_err();
                assert_eq!(
                    err.as_database_error().unwrap().code().as_deref(),
                    Some("42501"),
                    "role {role} must have zero EXECUTE privilege on `{fn_sql}`"
                );
            }
        }

        // `openmettle-admin backup status` must fail for non-owner roles.
        let out = admin_as(&db, role, &["backup", "status"], &[]);
        assert!(
            !out.status.success(),
            "role {role} should fail backup status"
        );
    }

    // `backup_observe_telemetry()` is restricted to openmettle_worker.
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

    // `openmettle_issuance` session minting fails closed via the BEFORE INSERT trigger
    // `enforce_local_sessions_maintenance_gate` (SQLSTATE OMM01) with zero extra role grants.
    {
        let (provider_id, identity_id): (String, String) = sqlx::query_as(
            "SELECT provider_id::text, identity_id::text
               FROM openmettle.local_identity_approvals
              WHERE id = $1::uuid",
        )
        .bind(&user.approval)
        .fetch_one(&mut db.admin().await)
        .await
        .unwrap();
        let mut iss_cn = connect(&db.0, ISSUANCE).await;
        let mut tx = iss_cn.begin().await.unwrap();
        let err = sqlx::query(
            "INSERT INTO openmettle.local_sessions
                (id, secret_hash, login_id, provider_id, identity_id, approval_id, user_id,
                 issued_client, issued_epoch, issued_revision, provider_generation,
                 approval_generation, user_generation, created_ms, expires_ms)
             VALUES
                ('maint-blocked-session', $1, 'maint-login', $2::uuid, $3::uuid, $4::uuid,
                 $5::uuid, 'browser', 1, 1, 1, 1, 1, 1, 2)",
        )
        .bind([0x11u8; 32].as_slice())
        .bind(&provider_id)
        .bind(&identity_id)
        .bind(&user.approval)
        .bind(&user.user)
        .execute(&mut *tx)
        .await
        .unwrap_err();
        assert_eq!(
            err.as_database_error().unwrap().code().as_deref(),
            Some("OMM01"),
            "session issuance insert must be fenced by maintenance trigger: {err}"
        );
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
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: Some(GfsPolicy::default()),
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        Arc::new(SyntheticPgDumpRunner),
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

    let pg18_tools = resolve_pg18_tools(&dir);
    if std::env::var("POSTGRES_CONTAINER").is_ok() {
        assert!(
            pg18_tools.is_some(),
            "POSTGRES_CONTAINER is set; real PG 18.1 pg_dump/pg_restore wrapper must be active"
        );
    }
    let runner: Arc<dyn PgDumpRunner> = match &pg18_tools {
        Some((r, _)) => Arc::clone(r),
        None => Arc::new(SyntheticPgDumpRunner),
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
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: vec![("catalog.json".to_owned(), cfg_path.clone())],
            prune_policy: Some(GfsPolicy::default()),
            release_on_success: true,
            pg_dump_bin: None,
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

    // End-to-end pg_restore -> openmettle-migrate boundary & global default ACL verify ->
    // restore lock -> storage rebind -> restore replay -> quota verify -> backup release-maintenance.
    if let Some((_, restore_mode)) = &pg18_tools {
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

        let restore_out = run_pg_restore(restore_mode, &restored, &unpack_dir.join("pg.dump"));
        assert!(
            restore_out.status.success(),
            "pg_restore failed: {}",
            stderr(&restore_out)
        );

        // openmettle-migrate verifies role boundaries & ownership and reapplies global owner
        // default function ACLs (`defaclnamespace = 0`, P2 #6).
        let mig_out = run_cli(
            &mut migrate_command(&restored.url(OWNER), &[]),
            "migrate verify",
        );
        assert!(
            mig_out.status.success(),
            "migrate verification after pg_restore failed: {}",
            stderr(&mig_out)
        );

        let restored_pool = pool(&restored, OWNER).await;
        // Verify global (defaclnamespace = 0) default function ACL exists for openmettle_owner
        // with PUBLIC EXECUTE revoked (restored by openmettle-migrate after pg_restore).
        let (has_global_fn_acl, public_granted): (bool, bool) = sqlx::query_as(
            "SELECT
                EXISTS (
                    SELECT 1 FROM pg_default_acl d
                    JOIN pg_roles r ON r.oid = d.defaclrole
                    WHERE r.rolname = 'openmettle_owner'
                      AND d.defaclnamespace = 0
                      AND d.defaclobjtype = 'f'
                ),
                EXISTS (
                    SELECT 1 FROM pg_default_acl d
                    JOIN pg_roles r ON r.oid = d.defaclrole,
                         aclexplode(d.defaclacl) a
                    WHERE r.rolname = 'openmettle_owner'
                      AND d.defaclnamespace = 0
                      AND d.defaclobjtype = 'f'
                      AND a.grantee = 0
                )",
        )
        .fetch_one(&restored_pool)
        .await
        .unwrap();
        assert!(
            has_global_fn_acl && !public_granted,
            "post-restore openmettle-migrate must restore global owner default function ACL without PUBLIC execute"
        );

        // Because pg.dump was taken inside maintenance, restored DB starts with maintenance active.
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
    let keyring_path = write_keyring_json(&dir, "bk", "bk-1", &[("bk-1", [0x51; 32])]);
    let keyring = BackupKeyRing::load_from_config(&keyring_path).unwrap();
    let inst_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    // Create 19 cryptographically verified completed sets spanning 5 calendar months, 7 ISO weeks,
    // and 10 consecutive days.
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
        let bdir = write_verified_backup_set(&dest, &keyring, inst_id, "offhost-gfs", ts, idx);
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
            "--backup-keys-config",
            keyring_path.to_str().unwrap(),
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
    assert!(out.contains("skipped_unverified=1"), "{out}");
    assert!(created_dirs.iter().all(|(_, p)| p.exists()));

    // Actual prune removes only the 8 expired completed backups.
    let (ok, out, err) = admin_cli(
        &db,
        &[
            "backup",
            "prune",
            "--destination-root",
            dest.to_str().unwrap(),
            "--backup-keys-config",
            keyring_path.to_str().unwrap(),
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
    assert!(out.contains("skipped_unverified=1"), "{out}");

    assert!(staging.exists());
    assert!(incomplete.exists());
    assert!(foreign.exists());
    let expected_kept: BTreeSet<&str> = [
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

    // 2. Run one succeeded capture and one failed capture, then observe durable cumulative totals.
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
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        Arc::new(SyntheticPgDumpRunner),
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

    // Second sweep returns the same durable cumulative totals without double-counting `metrics`.
    let obs2 = backup::observe_telemetry_into(&worker_pool, &metrics)
        .await
        .unwrap();
    assert_eq!(obs2, obs1);
    assert_eq!(metrics.backup_run_count(BackupRunOutcome::Succeeded), 1);
    assert_eq!(metrics.backup_run_count(BackupRunOutcome::Failed), 1);

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

    // P2 #9: Simulated worker restart (brand-new Metrics registry) immediately recovers all
    // durable cumulative counts via fetch_max without losing failures or incompletes.
    let restarted_metrics = Metrics::new();
    backup::observe_telemetry_into(&worker_pool, &restarted_metrics)
        .await
        .unwrap();
    assert_eq!(
        restarted_metrics.backup_run_count(BackupRunOutcome::Succeeded),
        1
    );
    assert_eq!(
        restarted_metrics.backup_run_count(BackupRunOutcome::Failed),
        1
    );
    assert_eq!(
        restarted_metrics.backup_run_count(BackupRunOutcome::Incomplete),
        1
    );

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
    //    emits overdue=1 once, throttles hourly, then advances to 2 after 61 minutes (durable
    //    across worker restarts).
    drop(owner_pool);
    drop(worker_pool);
    drop(db);
    let db_overdue = TestDb::migrated().await;
    let overdue_owner = pool(&db_overdue, OWNER).await;
    let overdue_worker = pool(&db_overdue, WORKER).await;
    let overdue_metrics = Metrics::new();
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

    let obs4 = backup::observe_telemetry_into(&overdue_worker, &overdue_metrics)
        .await
        .unwrap();
    assert_eq!(obs4.overdue, 1);
    assert_eq!(
        overdue_metrics.backup_run_count(BackupRunOutcome::Overdue),
        1
    );

    // Throttled within 1 hour: cumulative total remains 1.
    let obs5 = backup::observe_telemetry_into(&overdue_worker, &overdue_metrics)
        .await
        .unwrap();
    assert_eq!(obs5.overdue, 1);
    assert_eq!(
        overdue_metrics.backup_run_count(BackupRunOutcome::Overdue),
        1
    );

    // Advances to 2 once 1 hour passes.
    sqlx::query(
        "UPDATE openmettle.backup_rpo_telemetry_state
            SET last_overdue_observed_at = clock_timestamp() - interval '61 minutes'
          WHERE id",
    )
    .execute(&overdue_owner)
    .await
    .unwrap();
    let obs6 = backup::observe_telemetry_into(&overdue_worker, &overdue_metrics)
        .await
        .unwrap();
    assert_eq!(obs6.overdue, 2);
    assert_eq!(
        overdue_metrics.backup_run_count(BackupRunOutcome::Overdue),
        2
    );

    // Fresh worker after restart observes durable overdue=2 immediately.
    let restarted_overdue = Metrics::new();
    backup::observe_telemetry_into(&overdue_worker, &restarted_overdue)
        .await
        .unwrap();
    assert_eq!(
        restarted_overdue.backup_run_count(BackupRunOutcome::Overdue),
        2
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn released_gateway_requests_do_not_block_drain_and_superseded_final_reports_do_not_double_count()
 {
    // Upgrade from schema 23 so `quota_enforcement.metering_enforced` stays false while testing
    // gateway request drain & superseded final usage report aggregation directly.
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(10));
    migrate::apply(&settings, &MIGRATIONS[..23]).await.unwrap();
    let mut owner_cn = connect(&db.0, OWNER).await;
    providers(&mut owner_cn).await;
    let user = account(&mut owner_cn, PROVIDER, true, FUTURE).await;
    make_admin(&mut owner_cn, &user).await;
    let personal_scope = personal_of(&db, &user).await;
    drop(owner_cn);
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    let owner_pool = pool(&db, OWNER).await;

    // Seed a run-owned gateway_reservation + one released gateway_requests row (`state='released'`,
    // `settled_final=false`) via `openmettle.gateway_release(...)`, AND one handed_off row settled
    // via two final usage reports (revision 0 superseded by final revision 1).
    let run_id = seed_queued_personal_run(&db, &personal_scope, &user, "gw-drain-test-run").await;
    let gw_res = new_uuid(&db).await;
    let req_released = new_uuid(&db).await;
    let req_settled = new_uuid(&db).await;
    let installation = new_uuid(&db).await;
    let report_source = installation.clone();
    let dispatch_secret = [0x42u8; 32];

    sqlx::query(
        "INSERT INTO openmettle.gateway_reservations
            (id, scope_id, actor_user_id, approval_id, run_id, units)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, 1000)",
    )
    .bind(&gw_res)
    .bind(&personal_scope)
    .bind(&user.user)
    .bind(&user.approval)
    .bind(&run_id)
    .execute(&owner_pool)
    .await
    .unwrap();

    // Reserve round 1 as `openmettle_worker` (per gateway_allocate trigger) and release it via the
    // real worker `gateway_release` path -> leaves `state = 'released', settled_final = false`.
    // Must NOT block drain!
    let mut worker_cn = connect(&db.0, WORKER).await;
    sqlx::query(
        "INSERT INTO openmettle.gateway_requests
            (id, reservation_id, scope_id, actor_user_id, approval_id, run_id, round,
             installation, model, units, dispatch_hash)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6::uuid, 1,
                 $7::uuid, 'synthetic-model', 100, sha256($8))",
    )
    .bind(&req_released)
    .bind(&gw_res)
    .bind(&personal_scope)
    .bind(&user.user)
    .bind(&user.approval)
    .bind(&run_id)
    .bind(&installation)
    .bind(dispatch_secret.as_slice())
    .execute(&mut worker_cn)
    .await
    .unwrap();
    let released_ok: bool = sqlx::query_scalar("SELECT openmettle.gateway_release($1::uuid, $2)")
        .bind(&req_released)
        .bind(dispatch_secret.as_slice())
        .fetch_one(&mut worker_cn)
        .await
        .unwrap();
    assert!(released_ok);

    // Settled request (round 2): insert as `openmettle_worker`, mark handed_off as owner, then
    // settle with revision 0 final report superseded by revision 1 final report.
    sqlx::query(
        "INSERT INTO openmettle.gateway_requests
            (id, reservation_id, scope_id, actor_user_id, approval_id, run_id, round,
             installation, model, units, dispatch_hash)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6::uuid, 2,
                 $7::uuid, 'synthetic-model', 500, sha256('settled'))",
    )
    .bind(&req_settled)
    .bind(&gw_res)
    .bind(&personal_scope)
    .bind(&user.user)
    .bind(&user.approval)
    .bind(&run_id)
    .bind(&installation)
    .execute(&mut worker_cn)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.gateway_requests
            SET state = 'handed_off',
                report_source = $2::uuid,
                bearer_hash = sha256('bearer'),
                claim_hash = sha256('claim'),
                dispatched_at = clock_timestamp()
          WHERE id = $1::uuid",
    )
    .bind(&req_settled)
    .bind(&report_source)
    .execute(&owner_pool)
    .await
    .unwrap();

    let report_id = new_uuid(&db).await;
    // Revision 0 (initial final report: 100 prompt, 50 completion, 10 separate reasoning -> 160).
    sqlx::query(
        "INSERT INTO openmettle.gateway_usage_reports
            (request_id, source, report_id, revision, final,
             prompt_tokens, completion_tokens, reasoning_tokens, reasoning_included)
         VALUES ($1::uuid, $2::uuid, $3::uuid, 0, true, 100, 50, 10, false)",
    )
    .bind(&req_settled)
    .bind(&report_source)
    .bind(&report_id)
    .execute(&owner_pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO openmettle.gateway_settlements
            (request_id, revision, final, measured, outstanding)
         VALUES ($1::uuid, 0, true, 160, 0)",
    )
    .bind(&req_settled)
    .execute(&owner_pool)
    .await
    .unwrap();

    // Revision 1 (correcting final report: 120 prompt, 60 completion, 15 separate reasoning -> 195).
    sqlx::query(
        "INSERT INTO openmettle.gateway_usage_reports
            (request_id, source, report_id, revision, final,
             prompt_tokens, completion_tokens, reasoning_tokens, reasoning_included)
         VALUES ($1::uuid, $2::uuid, $3::uuid, 1, true, 120, 60, 15, false)",
    )
    .bind(&req_settled)
    .bind(&report_source)
    .bind(&report_id)
    .execute(&owner_pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.gateway_settlements
            SET revision = 1, measured = 195
          WHERE request_id = $1::uuid",
    )
    .bind(&req_settled)
    .execute(&owner_pool)
    .await
    .unwrap();

    // Drain counts MUST report zero unsettled gateway requests.
    let counts = backup::poll_drain_counts(&owner_pool).await.unwrap();
    assert_eq!(counts.unsettled_gateway_requests, 0);
    assert!(counts.is_quiesced(), "{counts:?}");

    let dir = auth_config_support::Dir::new();
    let dest = PathBuf::from(dir.path("gw-dest"));
    fs::create_dir(&dest).unwrap();
    let keyring_path = write_keyring_json(&dir, "bk", "bk-gw", &[("bk-gw", [0x61; 32])]);
    let keyring = BackupKeyRing::load_from_config(&keyring_path).unwrap();

    let report = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: db.url(OWNER),
            destination_root: dest,
            destination_domain: "offhost-gw".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "gw-capture-1".to_owned(),
            reason: "gateway drain and summary regression".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        Arc::new(SyntheticPgDumpRunner),
    )
    .await
    .unwrap();

    let unpack_dir = PathBuf::from(dir.path("gw-unpacked"));
    backup::unpack_backup(&report.backup_dir, &unpack_dir, &keyring).unwrap();
    let gw: Value =
        serde_json::from_slice(&fs::read(unpack_dir.join("gateway-entitlements.json")).unwrap())
            .unwrap();
    let summary = &gw["gateway_usage_summary"];
    assert_eq!(summary["settled_requests"], 1);
    assert_eq!(summary["unsettled_requests"], 0);
    assert_eq!(summary["total_measured_units"], "195");
    assert_eq!(summary["total_prompt_tokens"], "120");
    assert_eq!(summary["total_completion_tokens"], "60");
    assert_eq!(summary["total_reasoning_tokens"], "15");
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn commit_before_marker_idempotent_retry_inherited_maintenance_and_preflight_guards() {
    let db = TestDb::migrated().await;
    let owner_pool = pool(&db, OWNER).await;
    let dir = auth_config_support::Dir::new();
    let dest = PathBuf::from(dir.path("dest"));
    fs::create_dir(&dest).unwrap();
    let keyring_path = write_keyring_json(&dir, "bk", "bk-own", &[("bk-own", [0x71; 32])]);
    let keyring = BackupKeyRing::load_from_config(&keyring_path).unwrap();

    // P1 #7: Reserved config filename (`vault-key-inventory.json`) fails preflight BEFORE entering
    // maintenance.
    let dummy_cfg = PathBuf::from(dir.write("ok.json", br#"{"ok":true}"#));
    let reserved_err = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: db.url(OWNER),
            destination_root: dest.clone(),
            destination_domain: "offhost-own".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "reserved-cfg-fail".to_owned(),
            reason: "should fail preflight".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: vec![("vault-key-inventory.json".to_owned(), dummy_cfg)],
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        Arc::new(SyntheticPgDumpRunner),
    )
    .await
    .unwrap_err();
    assert!(matches!(reserved_err, BackupError::Archive(_)));
    assert!(
        !backup::status(&owner_pool)
            .await
            .unwrap()
            .maintenance_active
    );

    // P1 #7: Neo4j dump mutated/truncated mid-capture fails closed and publishes nothing.
    let neo4j_path = PathBuf::from(dir.write("graphiti-live.dump", b"INITIAL-NEO4J-DUMP-BYTES"));
    struct MutatingNeo4jRunner(PathBuf);
    impl PgDumpRunner for MutatingNeo4jRunner {
        fn dump(
            &self,
            _database_url: &str,
            _snapshot_id: Option<&str>,
            _cancel: &DumpCancel,
            writer: &mut dyn IoWrite,
        ) -> Result<u64, BackupError> {
            // Mutate/truncate the held Neo4j dump file in-place before step 6e reads it.
            let f = fs::OpenOptions::new().write(true).open(&self.0)?;
            f.set_len(4)?;
            let payload = b"PGDMP-SYNTH";
            writer.write_all(payload)?;
            Ok(payload.len() as u64)
        }
    }
    let mutated_err = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: db.url(OWNER),
            destination_root: dest.clone(),
            destination_domain: "offhost-own".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "mutated-neo4j-fail".to_owned(),
            reason: "neo4j mutated during capture".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::OfflineDump(neo4j_path.clone()),
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        Arc::new(MutatingNeo4jRunner(neo4j_path)),
    )
    .await
    .unwrap_err();
    assert!(matches!(mutated_err, BackupError::Integrity(_)));
    assert!(fs::read_dir(&dest).unwrap().next().is_none());
    // Failure kept maintenance active!
    assert!(
        backup::status(&owner_pool)
            .await
            .unwrap()
            .maintenance_active
    );

    // P1 #6: Subsequent capture with `--release-on-success` on an INHERITED maintenance window
    // (still active from the failed capture above) succeeds on its backup set while keeping
    // `maintenance_active = true` (`released_maintenance == false`).
    let inherited_opts = CaptureOptions {
        database_url: db.url(OWNER),
        destination_root: dest.clone(),
        destination_domain: "offhost-own".to_owned(),
        artifact_root: None,
        operator_id: OPERATOR_1.to_owned(),
        request_key: "inherited-maint-capture".to_owned(),
        reason: "retry capture inside existing maintenance".to_owned(),
        drain_timeout: Duration::from_secs(5),
        lease_seconds: DEFAULT_LEASE_SECONDS,
        require_separate_device: false,
        graphiti_mode: GraphitiMode::NotProvisioned,
        chroma_mode: ChromaMode::NotProvisioned,
        config_files: Vec::new(),
        prune_policy: None,
        release_on_success: true,
        pg_dump_bin: None,
        allow_local_test_paths: true,
    };
    let rep1 = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &inherited_opts,
        Arc::new(SyntheticPgDumpRunner),
    )
    .await
    .unwrap();
    assert!(
        !rep1.released_maintenance,
        "capture must not release an inherited maintenance window"
    );
    assert!(
        backup::status(&owner_pool)
            .await
            .unwrap()
            .maintenance_active
    );

    // P1 #3: Simulate a crash right after PostgreSQL committed `backup_complete_capture` and
    // before `backup-meta.json` + atomic rename: move `final_dir` back to `.staging.<run_id>` and
    // delete `backup-meta.json`. Re-running with the EXACT same `request_key` must idempotently
    // restore `backup-meta.json`, rename into `final_dir`, and pass verification.
    let staging_dir = dest.join(format!(".staging.{}", rep1.backup_run_id));
    fs::rename(&rep1.backup_dir, &staging_dir).unwrap();
    fs::remove_file(staging_dir.join("backup-meta.json")).unwrap();
    assert!(!rep1.backup_dir.exists());

    let rep1_retry = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &inherited_opts,
        Arc::new(SyntheticPgDumpRunner),
    )
    .await
    .unwrap();
    assert_eq!(rep1_retry.backup_run_id, rep1.backup_run_id);
    assert_eq!(rep1_retry.bundle_digest, rep1.bundle_digest);
    assert_eq!(rep1_retry.backup_dir, rep1.backup_dir);
    assert!(!staging_dir.exists());
    assert!(rep1.backup_dir.is_dir());
    backup::verify_backup(&rep1.backup_dir, &keyring).unwrap();
    assert!(
        !rep1_retry.released_maintenance,
        "idempotent retry of inherited-window capture still preserves operator maintenance"
    );
    assert!(
        backup::status(&owner_pool)
            .await
            .unwrap()
            .maintenance_active
    );

    // Explicit release clears maintenance, and a fresh capture that OPENS maintenance DOES release
    // when `--release-on-success` is set.
    backup::release_maintenance(
        &owner_pool,
        OPERATOR_1,
        "explicit-release-after-inherited",
        "operator verified recovery",
        false,
    )
    .await
    .unwrap();
    assert!(
        !backup::status(&owner_pool)
            .await
            .unwrap()
            .maintenance_active
    );

    let rep2 = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: db.url(OWNER),
            destination_root: dest,
            destination_domain: "offhost-own".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "owned-maint-capture".to_owned(),
            reason: "fresh self-owned capture".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        Arc::new(SyntheticPgDumpRunner),
    )
    .await
    .unwrap();
    assert!(rep2.released_maintenance);
    assert!(
        !backup::status(&owner_pool)
            .await
            .unwrap()
            .maintenance_active
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn verified_gfs_pruning_ignores_corrupt_newer_sets_and_isolates_installations() {
    let dir = auth_config_support::Dir::new();
    let dest = PathBuf::from(dir.path("verified-gfs"));
    fs::create_dir(&dest).unwrap();
    let keyring_path = write_keyring_json(&dir, "bk", "bk-vgfs", &[("bk-vgfs", [0x81; 32])]);
    let keyring = BackupKeyRing::load_from_config(&keyring_path).unwrap();

    let inst_a = "11111111-1111-4111-8111-111111111111";
    let inst_b = "22222222-2222-4222-8222-222222222222";

    let valid_old =
        write_verified_backup_set(&dest, &keyring, inst_a, "nas", "2026-11-25T02:00:00Z", 1);
    let valid_today =
        write_verified_backup_set(&dest, &keyring, inst_a, "nas", "2026-11-26T02:00:00Z", 2);
    let corrupt_missing_pg =
        write_verified_backup_set(&dest, &keyring, inst_a, "nas", "2026-11-26T14:00:00Z", 3);
    fs::remove_file(corrupt_missing_pg.join("pg.dump.enc")).unwrap();

    let corrupt_manifest =
        write_verified_backup_set(&dest, &keyring, inst_a, "nas", "2026-11-26T18:00:00Z", 4);
    let mut mf = fs::read(corrupt_manifest.join("manifest.json.enc")).unwrap();
    let last = mf.len() - 1;
    mf[last] ^= 0xff;
    fs::write(corrupt_manifest.join("manifest.json.enc"), mf).unwrap();

    // Much older backup from a SECOND installation in the same destination root.
    let inst_b_old =
        write_verified_backup_set(&dest, &keyring, inst_b, "nas", "2026-06-01T02:00:00Z", 5);

    let report = backup::prune(
        &dest,
        &keyring,
        GfsPolicy {
            keep_daily: 1,
            keep_weekly: 1,
            keep_monthly: 1,
        },
        false,
    )
    .unwrap();

    assert_eq!(report.skipped_unverified.len(), 2, "{report:?}");
    assert!(
        corrupt_missing_pg.exists(),
        "unverified set must never be deleted by prune"
    );
    assert!(
        corrupt_manifest.exists(),
        "corrupt manifest set must never be deleted by prune"
    );
    assert!(
        valid_today.exists(),
        "corrupt newer same-day sets must NOT cause older valid backup to be pruned"
    );
    assert!(
        !valid_old.exists(),
        "older superseded valid backup in same week/month should be pruned"
    );
    assert!(
        inst_b_old.exists(),
        "second installation's backup must never be pruned by first installation's sets"
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn maintenance_finishes_inflight_purges_without_claiming_new_ones_and_fences_native_token() {
    let db = TestDb::migrated().await;
    configure_limits(&db, Some(100_000), Some(100_000), Some(100_000)).await;
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

    // Seed two retained revisions both past purge_after:
    // - rev 0: already in-flight `state = 'purging'` (simulated mid-purge when maintenance entered)
    // - rev 1: still `state = 'retained'` due for purge (must NOT be claimed during maintenance!)
    let mut revs = Vec::new();
    for (idx, payload) in [
        (0, b"inflight-purge-bytes-0".as_slice()),
        (1, b"retained-unclaimed-bytes-1".as_slice()),
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
                    key: &format!("purge-maint-{idx}"),
                    artifact: &art_id,
                    max_bytes: 512,
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
                    display_name: Some("purge.txt"),
                },
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
            rev
        };
        retain_revision(&db, &personal_scope, &rev_id).await;
        revs.push((rev_id, res_id));
    }

    // Advance rev 0 into `state = 'purging'` (simulating an in-flight worker purge when
    // maintenance enters).
    sqlx::query(
        "UPDATE openmettle.artifact_revisions
            SET state = 'purging',
                purging_at = greatest(clock_timestamp(), purge_after)
          WHERE id = $1::uuid",
    )
    .bind(&revs[0].0)
    .execute(&owner_pool)
    .await
    .unwrap();

    // Start API binary to verify `/auth/native/token` fencing (P2 #4).
    let api = Api::start_in(&db, dir);

    // Seed a pending `native_handoffs` row with `sealed IS NOT NULL` to prove maintenance does not
    // consume it.
    let native_bearer = super::authz_http::native(&db, &user, 7).await;
    let native_session_id = native_bearer.split('.').next().unwrap().to_owned();
    sqlx::query(
        "UPDATE openmettle.native_handoffs
            SET sealed = $2
          WHERE session_id = $1",
    )
    .bind(&native_session_id)
    .bind([0xabu8; 103].as_slice())
    .execute(&owner_pool)
    .await
    .unwrap();

    // Enter maintenance.
    backup::enter_maintenance(
        &owner_pool,
        OPERATOR_1,
        "maint-p2-3-4",
        "test p2-3 and p2-4",
    )
    .await
    .unwrap();

    // P2 #3: Drain sees 1 active purge; finish_inflight_purges drains rev 0 -> 'purged' while
    // leaving rev 1 untouched in 'retained'.
    assert_eq!(
        backup::poll_drain_counts(&owner_pool)
            .await
            .unwrap()
            .active_purges,
        1
    );
    let finished = artifact_fs::finish_inflight_purges(&worker_pool, &store, 10)
        .await
        .unwrap();
    assert_eq!(finished, 1);
    assert_eq!(
        backup::poll_drain_counts(&owner_pool)
            .await
            .unwrap()
            .active_purges,
        0
    );
    let state0: String =
        sqlx::query_scalar("SELECT state FROM openmettle.artifact_revisions WHERE id = $1::uuid")
            .bind(&revs[0].0)
            .fetch_one(&owner_pool)
            .await
            .unwrap();
    let state1: String =
        sqlx::query_scalar("SELECT state FROM openmettle.artifact_revisions WHERE id = $1::uuid")
            .bind(&revs[1].0)
            .fetch_one(&owner_pool)
            .await
            .unwrap();
    assert_eq!(state0, "purged");
    assert_eq!(state1, "retained");

    // P2 #4: POST /auth/native/token returns 503 during maintenance without consuming handoff.
    // Use canonical base64url (URL_SAFE_NO_PAD of [0xbb; 32]) so request parsing reaches
    // `sessions::native::claim()` rather than failing token syntax validation.
    let token_body = json!({
        "grant_type": "authorization_code",
        "iss": "https://app.example.test",
        "client_id": "openmettle-desktop",
        "redirect_uri": "https://app.example.test/native/complete",
        "code": "u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s",
        "code_verifier": "ccccccccccccccccccccccccccccccccccccccccccc",
    })
    .to_string();
    let raw_req = format!(
        "POST /auth/native/token HTTP/1.1\r\nhost: app.example.test\r\n\
         content-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        token_body.len(),
        token_body
    );
    let (status_maint, _, _) = api.raw(&raw_req);
    assert_eq!(
        status_maint, 503,
        "POST /auth/native/token must fail closed with 503 during maintenance"
    );
    let still_sealed: bool = sqlx::query_scalar(
        "SELECT sealed IS NOT NULL FROM openmettle.native_handoffs WHERE session_id = $1",
    )
    .bind(native_session_id)
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    assert!(
        still_sealed,
        "maintenance refusal must not consume native_handoffs.sealed"
    );

    // Release maintenance: POST /auth/native/token passes the maintenance fence (reaches normal
    // code lookup -> 403 for unknown code, NOT 503).
    backup::release_maintenance(
        &owner_pool,
        OPERATOR_1,
        "rel-p2-3-4",
        "done p2-3 and p2-4",
        false,
    )
    .await
    .unwrap();
    let (status_open, _, _) = api.raw(&raw_req);
    assert_eq!(status_open, 403);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn staged_publishing_retry_without_sources_non_counting_telemetry_rpo_and_abort() {
    let db = TestDb::migrated().await;
    let owner_pool = pool(&db, OWNER).await;
    let worker_pool = pool(&db, WORKER).await;
    let dir = auth_config_support::Dir::new();
    let dest = PathBuf::from(dir.path("dest-publishing"));
    fs::create_dir(&dest).unwrap();
    let keyring_path = write_keyring_json(&dir, "bk", "bk-pub", &[("bk-pub", [0x92; 32])]);
    let keyring = BackupKeyRing::load_from_config(&keyring_path).unwrap();

    // Helper to stage a valid encrypted `.staging.<run_id>` directory and commit
    // `openmettle.backup_stage_publication(...)` (`capturing -> publishing`) directly.
    async fn stage_run(
        owner_pool: &PgPool,
        dest: &Path,
        keyring: &BackupKeyRing,
        req_key: &str,
        reason: &str,
    ) -> (String, String, PathBuf, PathBuf) {
        let (run_id, _rpo, installation_id): (String, i32, String) = sqlx::query_as(
            "SELECT backup_run_id::text, rpo_target_seconds, installation_id::text
               FROM openmettle.backup_start_capture($1::uuid, $2, $3, 'offhost-pub', 300)",
        )
        .bind(OPERATOR_1)
        .bind(req_key)
        .bind(reason)
        .fetch_one(owner_pool)
        .await
        .unwrap();

        let quiesced_at: String = sqlx::query_scalar(
            "SELECT to_char(quiesced_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
               FROM openmettle.backup_mark_quiesced($1::uuid, clock_timestamp(), 300)",
        )
        .bind(&run_id)
        .fetch_one(owner_pool)
        .await
        .unwrap();

        let staging_dir = dest.join(format!(".staging.{run_id}"));
        fs::create_dir(&staging_dir).unwrap();
        fs::set_permissions(&staging_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let mut components = BTreeMap::new();
        for (file_name, role, body) in [
            ("pg.dump.enc", "pg_dump", b"PGDMP-STAGED".as_slice()),
            (
                "gateway-entitlements.json.enc",
                "gateway_entitlements",
                b"{}".as_slice(),
            ),
            (
                "deletion-journal.bin.enc",
                "deletion_journal",
                b"version 1\n".as_slice(),
            ),
            ("artifacts.bin.enc", "artifacts", b"OMART01\0\0\0".as_slice()),
            (
                "config.json.enc",
                "config",
                br#"{"format":"openmettle-backup-config/v1","vault_required_key_ids":[],"files":[]}"#
                    .as_slice(),
            ),
        ] {
            let mut out = fs::File::create(staging_dir.join(file_name)).unwrap();
            let mut enc = StreamEncryptor::start(keyring, &run_id, role, &mut out).unwrap();
            enc.write_all(body).unwrap();
            let stats = enc.finish().unwrap();
            components.insert(
                file_name.to_owned(),
                ComponentManifest {
                    role: role.to_owned(),
                    plaintext_bytes: stats.plaintext_bytes,
                    plaintext_sha256: hex_encode(&stats.plaintext_sha256),
                    ciphertext_bytes: stats.ciphertext_bytes,
                    ciphertext_sha256: hex_encode(&stats.ciphertext_sha256),
                },
            );
        }

        let mut parts: Vec<&[u8]> = Vec::new();
        for (file_name, comp) in &components {
            parts.push(file_name.as_bytes());
            parts.push(comp.ciphertext_sha256.as_bytes());
        }
        parts.push(b"");
        let pre_bundle = hex_encode(&framed_digest(b"openmettle.backup.bundle/1\0", &parts));

        let completed_at = "2026-11-26T03:00:00Z".to_owned();
        let manifest = BackupManifest {
            format: MANIFEST_FORMAT.to_owned(),
            installation_id: installation_id.clone(),
            backup_run_id: run_id.clone(),
            quiesced_at,
            completed_at: completed_at.clone(),
            schema_version: 45,
            crate_version: env!("CARGO_PKG_VERSION").to_owned(),
            destination_domain: "offhost-pub".to_owned(),
            rpo_target_seconds: 86_400,
            encryption_key_id: keyring.active_key_id().to_owned(),
            bundle_digest: pre_bundle,
            components: components.clone(),
            deletion_journal: JournalWatermarkManifest {
                origin_us: 1,
                journal_seq: 0,
                chain_digest: openmettle_core::restore::GENESIS.to_owned(),
                lifecycle_origin_us: None,
                lifecycle_baseline_digest: None,
                connection_origin_us: None,
            },
            artifact_volume: ArtifactVolumeManifest {
                volume_id: None,
                revision_count: 0,
                payload_bytes: 0,
            },
            vault_required_key_ids: Vec::new(),
            gateway_consistency_mode: GATEWAY_CONSISTENCY_MODE.to_owned(),
            graphiti_neo4j: GraphitiManifest::NotProvisioned,
            chroma: ChromaManifest::NotProvisioned,
            rebuildable_indexes: REBUILDABLE_INDEXES
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        let mut mf = fs::File::create(staging_dir.join("manifest.json.enc")).unwrap();
        let mut menc = StreamEncryptor::start(keyring, &run_id, "manifest", &mut mf).unwrap();
        menc.write_all(&manifest_bytes).unwrap();
        let mstats = menc.finish().unwrap();
        let mct_hex = hex_encode(&mstats.ciphertext_sha256);

        let mut fparts: Vec<&[u8]> = Vec::new();
        for (file_name, comp) in &components {
            fparts.push(file_name.as_bytes());
            fparts.push(comp.ciphertext_sha256.as_bytes());
        }
        fparts.push(mct_hex.as_bytes());
        let final_bundle_bytes = framed_digest(b"openmettle.backup.bundle/1\0", &fparts);
        let final_bundle_hex = hex_encode(&final_bundle_bytes);
        let final_dir_name = format!("backup-20261126T030000Z-{run_id}");
        let final_dir = dest.join(&final_dir_name);
        let summary_text = json!({
            "format": MANIFEST_FORMAT,
            "installation_id": installation_id,
            "completed_at": completed_at,
            "manifest_ciphertext_sha256": mct_hex,
            "schema_version": 45,
            "crate_version": env!("CARGO_PKG_VERSION"),
            "destination_domain": "offhost-pub",
            "reason": reason,
            "encryption_key_id": keyring.active_key_id(),
            "artifact_revision_count": 0,
            "artifact_payload_bytes": 0,
            "vault_required_key_ids": [],
            "rebuildable_indexes": REBUILDABLE_INDEXES,
            "backup_dir_name": final_dir_name,
        })
        .to_string();

        sqlx::query(
            "SELECT openmettle.backup_stage_publication(
                $1::uuid, $2, $3, $4, 1, 0, $5, NULL, NULL, NULL, $6::jsonb
            )",
        )
        .bind(&run_id)
        .bind(keyring.active_key_id())
        .bind(final_bundle_bytes.as_slice())
        .bind(mstats.plaintext_sha256.as_slice())
        .bind([0u8; 32].as_slice())
        .bind(&summary_text)
        .execute(owner_pool)
        .await
        .unwrap();

        (run_id, final_bundle_hex, staging_dir, final_dir)
    }

    // 1. Stage run 1 in `publishing`.
    let (run1, bundle1, staging1, final1) = stage_run(
        &owner_pool,
        &dest,
        &keyring,
        "pub-retry-key-1",
        "publish retry test",
    )
    .await;

    let st = backup::status(&owner_pool).await.unwrap();
    assert!(st.maintenance_active);
    assert_eq!(st.latest_run_id.as_deref(), Some(run1.as_str()));
    assert_eq!(st.latest_run_state.as_deref(), Some("publishing"));
    assert!(st.last_succeeded_run_id.is_none());
    assert!(st.last_succeeded_at.is_none());

    // 2. P1 #3: `publishing` must NOT count as `succeeded`, must NOT expire as `incomplete`, and
    //    must NOT reset the 24h RPO overdue clock.
    sqlx::query(
        "UPDATE openmettle.backup_maintenance_gate
            SET rpo_tracking_armed_at = clock_timestamp() - interval '25 hours'
          WHERE id",
    )
    .execute(&owner_pool)
    .await
    .unwrap();
    let metrics = Metrics::new();
    let obs = backup::observe_telemetry_into(&worker_pool, &metrics)
        .await
        .unwrap();
    assert_eq!(obs.succeeded, 0);
    assert_eq!(obs.failed, 0);
    assert_eq!(obs.incomplete, 0);
    assert_eq!(
        obs.overdue, 1,
        "unpublished `publishing` run must not reset the 24h RPO clock"
    );

    // 3. Releasing maintenance without `--abort-active-run` refuses a `publishing` run with OMB02.
    let err = backup::release_maintenance(
        &owner_pool,
        OPERATOR_1,
        "rel-refuse-pub",
        "should refuse publishing",
        false,
    )
    .await
    .unwrap_err();
    match err {
        BackupError::Database(sqlx::Error::Database(d)) => {
            assert_eq!(d.code().as_deref(), Some("OMB02"));
        }
        other => panic!("expected OMB02 refusal for publishing run, got {other:?}"),
    }

    // 4. P2 #1: Simulate a crash mid-write leaving corrupt/partial `backup-meta.json` and
    //    `backup-meta.json.tmp` in `.staging.<run_id>`, AND pass nonexistent `--neo4j-dump` and
    //    `--config-file` paths plus a panicking PgDumpRunner. Exact-key retry must finalize
    //    without touching source files or re-dumping.
    fs::write(staging1.join("backup-meta.json.tmp"), b"{truncated").unwrap();
    fs::write(staging1.join("backup-meta.json"), b"{corrupt").unwrap();

    struct PanicPgDumpRunner;
    impl PgDumpRunner for PanicPgDumpRunner {
        fn dump(
            &self,
            _database_url: &str,
            _snapshot_id: Option<&str>,
            _cancel: &DumpCancel,
            _writer: &mut dyn IoWrite,
        ) -> Result<u64, BackupError> {
            panic!("publishing retry must not re-run pg_dump");
        }
    }

    let retry_report = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: db.url(OWNER),
            destination_root: dest.clone(),
            destination_domain: "offhost-pub".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "pub-retry-key-1".to_owned(),
            reason: "publish retry test".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::OfflineDump(PathBuf::from(dir.path("deleted-neo4j.dump"))),
            chroma_mode: ChromaMode::Archive(PathBuf::from(dir.path("deleted-chroma.tar"))),
            config_files: vec![(
                "missing.json".to_owned(),
                PathBuf::from(dir.path("deleted-config.json")),
            )],
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        Arc::new(PanicPgDumpRunner),
    )
    .await
    .unwrap();
    assert_eq!(retry_report.backup_run_id, run1);
    assert_eq!(retry_report.bundle_digest, bundle1);
    assert_eq!(retry_report.backup_dir, final1);
    assert!(retry_report.released_maintenance);
    assert!(!staging1.exists());
    assert!(final1.is_dir());
    backup::verify_backup(&final1, &keyring).unwrap();

    let obs_after = backup::observe_telemetry_into(&worker_pool, &metrics)
        .await
        .unwrap();
    assert_eq!(obs_after.succeeded, 1);
    let st_after = backup::status(&owner_pool).await.unwrap();
    assert!(!st_after.maintenance_active);
    assert_eq!(
        st_after.last_succeeded_run_id.as_deref(),
        Some(run1.as_str())
    );

    // 5. Explicit abort of a `publishing` run via `--abort-active-run` transitions it to
    //    `incomplete` with `failure_code = 'publication_aborted'`.
    let (run2, _, _, _) = stage_run(
        &owner_pool,
        &dest,
        &keyring,
        "pub-abort-key-2",
        "publish abort test",
    )
    .await;
    let (released, aborted) = backup::release_maintenance(
        &owner_pool,
        OPERATOR_1,
        "rel-abort-pub-2",
        "aborting unrecoverable publication",
        true,
    )
    .await
    .unwrap();
    assert!(released);
    assert_eq!(aborted.as_deref(), Some(run2.as_str()));
    let (state2, failure2): (String, Option<String>) = sqlx::query_as(
        "SELECT state, failure_code FROM openmettle.backup_runs WHERE id = $1::uuid",
    )
    .bind(&run2)
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    assert_eq!(state2, "incomplete");
    assert_eq!(failure2.as_deref(), Some("publication_aborted"));
    let obs_final = backup::observe_telemetry_into(&worker_pool, &metrics)
        .await
        .unwrap();
    assert_eq!(obs_final.incomplete, 1);

    // 6. P1 #1: Retry when `final_dir` ALREADY exists on disk (simulating a crash right after
    //    `rename(staging_dir, final_dir)` before `fsync_dir(dest_root)` + `confirm_publication`)
    //    verifies + syncs `final_dir`/`dest_root` and confirms `publishing -> succeeded`.
    let (run3, bundle3, staging3, final3) = stage_run(
        &owner_pool,
        &dest,
        &keyring,
        "pub-retry-final-exists-3",
        "publish retry final exists",
    )
    .await;
    let run3_summary_text: String = sqlx::query_scalar(
        "SELECT manifest_summary::text FROM openmettle.backup_runs WHERE id = $1::uuid",
    )
    .bind(&run3)
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    let run3_summary: Value = serde_json::from_str(&run3_summary_text).unwrap();
    let run3_meta = BackupMeta {
        format: META_FORMAT.to_owned(),
        installation_id: run3_summary["installation_id"].as_str().unwrap().to_owned(),
        backup_run_id: run3.clone(),
        completed_at: run3_summary["completed_at"].as_str().unwrap().to_owned(),
        destination_domain: "offhost-pub".to_owned(),
        encryption_key_id: keyring.active_key_id().to_owned(),
        manifest_ciphertext_sha256: run3_summary["manifest_ciphertext_sha256"]
            .as_str()
            .unwrap()
            .to_owned(),
        bundle_digest: bundle3.clone(),
        state: "complete".to_owned(),
    };
    fs::write(
        staging3.join("backup-meta.json"),
        serde_json::to_vec_pretty(&run3_meta).unwrap(),
    )
    .unwrap();
    fs::rename(&staging3, &final3).unwrap();
    assert!(!staging3.exists() && final3.is_dir());

    let retry3 = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: db.url(OWNER),
            destination_root: dest.clone(),
            destination_domain: "offhost-pub".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "pub-retry-final-exists-3".to_owned(),
            reason: "publish retry final exists".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        Arc::new(PanicPgDumpRunner),
    )
    .await
    .unwrap();
    assert_eq!(retry3.backup_run_id, run3);
    assert_eq!(retry3.backup_dir, final3);
    assert!(retry3.released_maintenance);
    let state3: String =
        sqlx::query_scalar("SELECT state FROM openmettle.backup_runs WHERE id = $1::uuid")
            .bind(&run3)
            .fetch_one(&owner_pool)
            .await
            .unwrap();
    assert_eq!(state3, "succeeded");
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn confirming_old_publishing_run_anchors_rpo_to_quiesced_at_not_completed_at() {
    let db = TestDb::migrated().await;
    let owner_pool = pool(&db, OWNER).await;
    let worker_pool = pool(&db, WORKER).await;
    let run_id = new_uuid(&db).await;

    // Insert a staged `publishing` run whose captured recovery point (`quiesced_at`) is 25 hours
    // old (past the default 86400s RPO target), and bind it to the active maintenance gate.
    sqlx::query(
        "INSERT INTO openmettle.backup_runs
            (id, request_key, operator_id, state, started_at, lease_until, quiesced_at,
             completed_at, destination_domain, encryption_key_id, bundle_digest, manifest_digest,
             journal_origin_us, journal_seq, journal_chain_digest, failure_code,
             opened_maintenance, manifest_summary)
         VALUES
            ($1::uuid, 'old-quiesced-pub-1', $2::uuid, 'publishing',
             clock_timestamp() - interval '26 hours', NULL,
             clock_timestamp() - interval '25 hours', NULL,
             'offhost-rpo', 'bk-old', $3, $3, 1, 0, $3, NULL, true, '{}'::jsonb)",
    )
    .bind(&run_id)
    .bind(OPERATOR_1)
    .bind([0x55u8; 32].as_slice())
    .execute(&owner_pool)
    .await
    .unwrap();

    sqlx::query(
        "UPDATE openmettle.backup_maintenance_gate
            SET maintenance_active = true,
                backup_run_id = $1::uuid,
                entered_at = clock_timestamp() - interval '26 hours',
                entered_by_operator_id = $2::uuid,
                reason = 'delayed confirmation rpo test',
                quiesced_at = clock_timestamp() - interval '25 hours',
                rpo_tracking_armed_at = clock_timestamp() - interval '26 hours',
                updated_at = clock_timestamp()
          WHERE id",
    )
    .bind(&run_id)
    .bind(OPERATOR_1)
    .execute(&owner_pool)
    .await
    .unwrap();

    // Confirming publication NOW sets `completed_at = clock_timestamp()`, while `quiesced_at`
    // remains 25 hours ago.
    let mut tx = owner_pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("SELECT openmettle.backup_confirm_publication($1::uuid, 'late confirmation')")
        .bind(&run_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    // RPO overdue evaluation MUST anchor to `quiesced_at` (25h old), NOT `completed_at` (now),
    // so `overdue` increments to 1 even though `succeeded` is 1.
    let metrics = Metrics::new();
    let obs = backup::observe_telemetry_into(&worker_pool, &metrics)
        .await
        .unwrap();
    assert_eq!(obs.succeeded, 1);
    assert_eq!(
        obs.overdue, 1,
        "confirming a 25h-old publishing snapshot must NOT reset the 24h RPO clock"
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn worker_restart_with_historical_failure_never_emits_zero_before_seeding() {
    let db = TestDb::migrated().await;
    let owner_pool = pool(&db, OWNER).await;
    let worker_pool = pool(&db, WORKER).await;

    // Seed one durable historical failed backup run in PostgreSQL.
    let (run_id,): (String,) = sqlx::query_as(
        "SELECT backup_run_id::text
           FROM openmettle.backup_start_capture(
               $1::uuid, 'hist-fail-1', 'historical failure test', 'offhost-hist', 300
           )",
    )
    .bind(OPERATOR_1)
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    sqlx::query(
        "SELECT openmettle.backup_fail_capture($1::uuid, 'io_error', 'synthetic io error')",
    )
    .bind(&run_id)
    .execute(&owner_pool)
    .await
    .unwrap();

    // Fresh Metrics store simulates a restarted worker process before its startup DB seed runs.
    let fresh_metrics = Metrics::new();
    let instance_id = "33333333-4444-4555-8666-777777777777";
    let pre = fresh_metrics
        .encode_otlp(Process::Worker, Some(instance_id))
        .expect("worker emits non-backup baseline metrics before seeding");
    assert!(
        !pre.resource_metrics[0].scope_metrics[0]
            .metrics
            .iter()
            .any(|m| m.name == "openmettle.backup.runs"),
        "restarted worker must not emit 0 for openmettle.backup.runs prior to DB seeding"
    );

    // Startup telemetry seed populates durable PostgreSQL counts and enables emission atomically.
    let observed = backup::observe_telemetry_into(&worker_pool, &fresh_metrics)
        .await
        .unwrap();
    assert_eq!(observed.failed, 1);
    assert_eq!(fresh_metrics.backup_run_count(BackupRunOutcome::Failed), 1);

    let post = fresh_metrics
        .encode_otlp(Process::Worker, Some(instance_id))
        .expect("seeded worker emits openmettle.backup.runs");
    let backup_metric = post.resource_metrics[0].scope_metrics[0]
        .metrics
        .iter()
        .find(|m| m.name == "openmettle.backup.runs")
        .expect("seeded worker must emit openmettle.backup.runs");
    match backup_metric.data.as_ref().unwrap() {
        opentelemetry_proto::tonic::metrics::v1::metric::Data::Sum(sum) => {
            assert_eq!(sum.data_points.len(), BackupRunOutcome::ALL.len());
            let failed_dp = sum
                .data_points
                .iter()
                .find(|dp| {
                    dp.attributes.iter().any(|kv| {
                        kv.key == "outcome"
                            && matches!(
                                kv.value.as_ref().and_then(|v| v.value.as_ref()),
                                Some(
                                    opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(s)
                                ) if s == "failed"
                            )
                    })
                })
                .expect("failed data point missing");
            assert!(
                matches!(
                    failed_dp.value,
                    Some(
                        opentelemetry_proto::tonic::metrics::v1::number_data_point::Value::AsInt(1)
                    )
                ),
                "first emitted failed sample on restart must be 1 (never 0 -> 1), got {:?}",
                failed_dp.value
            );
        }
        other => panic!("expected Sum metric for openmettle.backup.runs, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn audit_request_key_collision_blocked_during_inflight_capture() {
    let db = TestDb::migrated().await;
    let owner_pool = pool(&db, OWNER).await;

    // Start capture 1 and confirm `backup.capture_started` immediately reserves `(operator, key)`
    // in `authorization_audit`.
    let (run1,): (String,) = sqlx::query_as(
        "SELECT backup_run_id::text
           FROM openmettle.backup_start_capture(
               $1::uuid, 'inflight-shared-key', 'capture collision check', 'offhost-audit', 300
           )",
    )
    .bind(OPERATOR_1)
    .fetch_one(&owner_pool)
    .await
    .unwrap();

    let started_row: (String, String, String) = sqlx::query_as(
        "SELECT action, target_kind, target_id
           FROM openmettle.authorization_audit
          WHERE actor_kind = 'operator'
            AND operator_id = $1::uuid
            AND request_key = 'inflight-shared-key'",
    )
    .bind(OPERATOR_1)
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    assert_eq!(
        started_row,
        (
            "backup.capture_started".to_owned(),
            "backup_run".to_owned(),
            run1.clone()
        )
    );

    // While run 1 is still draining/capturing, reusing the exact same `(operator, request_key)`
    // across `arm_rpo`, `enter_maintenance`, or `release_maintenance` MUST be rejected (`23505`).
    for err in [
        backup::arm_rpo(
            &owner_pool,
            OPERATOR_1,
            "inflight-shared-key",
            "collide arm-rpo",
            86_400,
        )
        .await
        .unwrap_err(),
        backup::enter_maintenance(
            &owner_pool,
            OPERATOR_1,
            "inflight-shared-key",
            "collide enter",
        )
        .await
        .unwrap_err(),
        backup::release_maintenance(
            &owner_pool,
            OPERATOR_1,
            "inflight-shared-key",
            "collide release",
            false,
        )
        .await
        .unwrap_err(),
    ] {
        match err {
            BackupError::Database(sqlx::Error::Database(db_err)) => {
                assert_eq!(db_err.code().as_deref(), Some("23505"), "{db_err}");
            }
            other => panic!("expected SQLSTATE 23505 collision rejection, got {other:?}"),
        }
    }

    // Also verify another operator cannot collide with `backup_runs.request_key` via `arm_rpo`.
    let other_op_err = backup::arm_rpo(
        &owner_pool,
        OPERATOR_2,
        "inflight-shared-key",
        "cross-operator arm-rpo collision",
        86_400,
    )
    .await
    .unwrap_err();
    match other_op_err {
        BackupError::Database(sqlx::Error::Database(db_err)) => {
            assert_eq!(db_err.code().as_deref(), Some("23505"), "{db_err}");
        }
        other => panic!("expected SQLSTATE 23505 for cross-operator collision, got {other:?}"),
    }

    // Reserved `sys.backup:` audit namespace MUST be rejected for every caller-supplied key
    // across backup functions (`22023`) AND non-backup operator audit rows (`23514` table CHECK)
    // so nothing can ever pre-occupy `sys.backup:capture_succeeded:<run_id>` or
    // `sys.backup:capture_release:<run_id>`!
    let reserved_key = format!("sys.backup:capture_succeeded:{run1}");
    for err in [
        backup::arm_rpo(
            &owner_pool,
            OPERATOR_1,
            &reserved_key,
            "try reserved namespace arm-rpo",
            86_400,
        )
        .await
        .unwrap_err(),
        backup::enter_maintenance(
            &owner_pool,
            OPERATOR_1,
            &reserved_key,
            "try reserved namespace enter",
        )
        .await
        .unwrap_err(),
        backup::release_maintenance(
            &owner_pool,
            OPERATOR_1,
            &reserved_key,
            "try reserved namespace release",
            false,
        )
        .await
        .unwrap_err(),
    ] {
        match err {
            BackupError::Database(sqlx::Error::Database(db_err)) => {
                assert_eq!(db_err.code().as_deref(), Some("22023"), "{db_err}");
            }
            other => panic!("expected SQLSTATE 22023 for sys.backup: key, got {other:?}"),
        }
    }
    let direct_non_backup_err = sqlx::query(
        "INSERT INTO openmettle.authorization_audit
            (actor_kind, actor_user_id, operator_id, action, target_kind, target_id,
             request_key, reason, details)
         VALUES
            ('operator', NULL, $1::uuid, 'restore.accept_coverage_gap', 'restore_gate',
             'instance', $2, 'attempt to spoof sys.backup namespace', '{}'::jsonb)",
    )
    .bind(OPERATOR_1)
    .bind(&reserved_key)
    .execute(&owner_pool)
    .await
    .unwrap_err();
    let db_err = direct_non_backup_err.as_database_error().unwrap();
    assert_eq!(
        db_err.code().as_deref(),
        Some("23514"),
        "table CHECK must forbid sys.backup: prefix on non-backup audit actions: {db_err:?}"
    );
    assert_eq!(
        db_err.constraint(),
        Some("authorization_audit_sys_backup_namespace_check"),
        "expected authorization_audit_sys_backup_namespace_check violation, got {db_err:?}"
    );

    // Complete run 1 through quiesce -> stage -> confirm -> auto-release; confirmation MUST
    // succeed and write distinct `sys.backup:capture_succeeded:<run_id>` and
    // `sys.backup:capture_release:<run_id>` audit keys preserving `capture_request_key`.
    sqlx::query("SELECT * FROM openmettle.backup_mark_quiesced($1::uuid, clock_timestamp(), 300)")
        .bind(&run1)
        .execute(&owner_pool)
        .await
        .unwrap();
    sqlx::query(
        "SELECT openmettle.backup_stage_publication(
            $1::uuid, 'k1', $2, $2, 1, 0, $2, NULL, NULL, NULL, '{}'::jsonb
        )",
    )
    .bind(&run1)
    .bind([0x44u8; 32].as_slice())
    .execute(&owner_pool)
    .await
    .unwrap();
    sqlx::query("SELECT openmettle.backup_confirm_publication($1::uuid, 'confirmed cleanly')")
        .bind(&run1)
        .execute(&owner_pool)
        .await
        .unwrap();

    let succeeded_details: String = sqlx::query_scalar(
        "SELECT details::text
           FROM openmettle.authorization_audit
          WHERE actor_kind = 'operator'
            AND operator_id = $1::uuid
            AND action = 'backup.capture_succeeded'
            AND request_key = $2",
    )
    .bind(OPERATOR_1)
    .bind(format!("sys.backup:capture_succeeded:{run1}"))
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    let succeeded_json: Value = serde_json::from_str(&succeeded_details).unwrap();
    assert_eq!(succeeded_json["capture_request_key"], "inflight-shared-key");

    let auto_released: bool = sqlx::query_scalar(
        "SELECT openmettle.backup_release_capture_maintenance($1::uuid, $2::uuid, 'auto release')",
    )
    .bind(&run1)
    .bind(OPERATOR_1)
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    assert!(auto_released);
    // Calling auto-release a second time is idempotent (`false`) via `sys.backup:capture_release:<run_id>`.
    let auto_released_again: bool = sqlx::query_scalar(
        "SELECT openmettle.backup_release_capture_maintenance($1::uuid, $2::uuid, 'auto release')",
    )
    .bind(&run1)
    .bind(OPERATOR_1)
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    assert!(!auto_released_again);

    let release_audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM openmettle.authorization_audit
          WHERE actor_kind = 'operator'
            AND operator_id = $1::uuid
            AND action = 'backup.maintenance_released'
            AND request_key = $2",
    )
    .bind(OPERATOR_1)
    .bind(format!("sys.backup:capture_release:{run1}"))
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    assert_eq!(release_audit_count, 1);

    // Start a second run and fail it; verify distinct `sys.backup:capture_failed:<run_id>` audit key.
    let (run2,): (String,) = sqlx::query_as(
        "SELECT backup_run_id::text
           FROM openmettle.backup_start_capture(
               $1::uuid, 'inflight-fail-key', 'fail audit key check', 'offhost-audit', 300
           )",
    )
    .bind(OPERATOR_1)
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    sqlx::query("SELECT openmettle.backup_fail_capture($1::uuid, 'io_error', 'synthetic fail')")
        .bind(&run2)
        .execute(&owner_pool)
        .await
        .unwrap();
    let failed_details: String = sqlx::query_scalar(
        "SELECT details::text
           FROM openmettle.authorization_audit
          WHERE actor_kind = 'operator'
            AND operator_id = $1::uuid
            AND action = 'backup.capture_failed'
            AND request_key = $2",
    )
    .bind(OPERATOR_1)
    .bind(format!("sys.backup:capture_failed:{run2}"))
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    let failed_json: Value = serde_json::from_str(&failed_details).unwrap();
    assert_eq!(failed_json["capture_request_key"], "inflight-fail-key");
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn quiesced_at_anchors_to_exported_snapshot_timestamp_and_rejects_out_of_bounds() {
    let db = TestDb::migrated().await;
    let owner_pool = pool(&db, OWNER).await;

    let (run1,): (String,) = sqlx::query_as(
        "SELECT backup_run_id::text
           FROM openmettle.backup_start_capture(
               $1::uuid, 'snap-ts-bounds-1', 'quiesce bounds test', 'offhost-ts', 300
           )",
    )
    .bind(OPERATOR_1)
    .fetch_one(&owner_pool)
    .await
    .unwrap();

    // Future (> now + 5s) and far-past (< entered_at - 5s) timestamps are rejected with 22023.
    for q in [
        "SELECT * FROM openmettle.backup_mark_quiesced($1::uuid, clock_timestamp() + interval '30 seconds', 300)",
        "SELECT * FROM openmettle.backup_mark_quiesced($1::uuid, clock_timestamp() - interval '30 seconds', 300)",
    ] {
        let err = sqlx::query(q)
            .bind(&run1)
            .execute(&owner_pool)
            .await
            .unwrap_err();
        assert_eq!(
            err.as_database_error().unwrap().code().as_deref(),
            Some("22023"),
            "out-of-bounds snapshot timestamp must raise 22023: {err}"
        );
    }

    // Valid snapshot timestamp strictly between started_at and now() is preserved accurately.
    tokio::time::sleep(Duration::from_millis(25)).await;
    let snap_ts: String = sqlx::query_scalar(
        "SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')",
    )
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(120)).await;

    let returned_ts: String = sqlx::query_scalar(
        "SELECT to_char(quiesced_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
           FROM openmettle.backup_mark_quiesced($1::uuid, $2::timestamptz, 300)",
    )
    .bind(&run1)
    .bind(&snap_ts)
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    assert_eq!(
        returned_ts, snap_ts,
        "backup_mark_quiesced must record the exact exported snapshot timestamp"
    );

    let (run_q, gate_q): (String, String) = sqlx::query_as(
        "SELECT to_char(r.quiesced_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                to_char(g.quiesced_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
           FROM openmettle.backup_runs r
           JOIN openmettle.backup_maintenance_gate g ON g.id
          WHERE r.id = $1::uuid",
    )
    .bind(&run1)
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    assert_eq!(run_q, snap_ts);
    assert_eq!(gate_q, snap_ts);

    // End-to-end capture: verify manifest.quiesced_at matches backup_runs.quiesced_at and precedes
    // completed_at when pg_dump takes measurable time.
    backup::release_maintenance(
        &owner_pool,
        OPERATOR_1,
        "snap-ts-release-1",
        "clear bounds test",
        true,
    )
    .await
    .unwrap();

    struct SlowSyntheticPgDump;
    impl PgDumpRunner for SlowSyntheticPgDump {
        fn dump(
            &self,
            _database_url: &str,
            _snapshot_id: Option<&str>,
            _cancel: &DumpCancel,
            writer: &mut dyn IoWrite,
        ) -> Result<u64, BackupError> {
            std::thread::sleep(Duration::from_millis(120));
            let payload = b"PGDMP-SLOW-SYNTHETIC";
            writer.write_all(payload)?;
            Ok(payload.len() as u64)
        }
    }

    let dir = auth_config_support::Dir::new();
    let dest = PathBuf::from(dir.path("dest-ts"));
    fs::create_dir(&dest).unwrap();
    let keyring_path = write_keyring_json(&dir, "bk", "bk-ts", &[("bk-ts", [0x88; 32])]);
    let keyring = BackupKeyRing::load_from_config(&keyring_path).unwrap();

    let rep = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: db.url(OWNER),
            destination_root: dest,
            destination_domain: "offhost-ts".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "snap-ts-e2e-1".to_owned(),
            reason: "snapshot timestamp capture".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        Arc::new(SlowSyntheticPgDump),
    )
    .await
    .unwrap();

    let manifest = backup::verify_backup(&rep.backup_dir, &keyring).unwrap();
    let (db_quiesced, db_order_ok): (String, bool) = sqlx::query_as(
        "SELECT to_char(quiesced_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                (started_at <= quiesced_at AND quiesced_at < completed_at)
           FROM openmettle.backup_runs
          WHERE id = $1::uuid",
    )
    .bind(&rep.backup_run_id)
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    assert_eq!(manifest.quiesced_at, db_quiesced);
    assert!(
        db_order_ok,
        "expected started_at <= quiesced_at < completed_at"
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn chroma_modes_not_provisioned_archive_and_qualified_rebuild_and_retry_with_prune() {
    let db = TestDb::migrated().await;
    let owner_pool = pool(&db, OWNER).await;
    let dir = auth_config_support::Dir::new();
    let dest = PathBuf::from(dir.path("dest-chroma"));
    fs::create_dir(&dest).unwrap();
    let keyring_path = write_keyring_json(&dir, "bk", "bk-ch", &[("bk-ch", [0x99; 32])]);
    let keyring = BackupKeyRing::load_from_config(&keyring_path).unwrap();

    // 1. Invalid qualification_ref fails preflight BEFORE entering maintenance.
    let bad_qual = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: db.url(OWNER),
            destination_root: dest.clone(),
            destination_domain: "offhost-chroma".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "chroma-bad-qual".to_owned(),
            reason: "invalid qual ref".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::QualifiedRebuild {
                qualification_ref: "bad\nref".to_owned(),
            },
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        Arc::new(SyntheticPgDumpRunner),
    )
    .await
    .unwrap_err();
    assert!(matches!(bad_qual, BackupError::Invalid(_)));
    assert!(
        !backup::status(&owner_pool)
            .await
            .unwrap()
            .maintenance_active
    );

    // 2. ChromaMode::NotProvisioned excludes `chroma_vector_embeddings` from rebuildable_indexes.
    let rep_np = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: db.url(OWNER),
            destination_root: dest.clone(),
            destination_domain: "offhost-chroma".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "chroma-np-1".to_owned(),
            reason: "chroma not provisioned".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        Arc::new(SyntheticPgDumpRunner),
    )
    .await
    .unwrap();
    let unpack_np = PathBuf::from(dir.path("unpack-np"));
    let u_np = backup::unpack_backup(&rep_np.backup_dir, &unpack_np, &keyring).unwrap();
    assert_eq!(u_np.manifest.chroma, ChromaManifest::NotProvisioned);
    assert!(
        !u_np
            .manifest
            .rebuildable_indexes
            .iter()
            .any(|s| s == CHROMA_REBUILDABLE_INDEX)
    );
    assert!(!u_np.has_chroma_archive);
    assert!(!unpack_np.join("chroma.archive").exists());

    // 3. ChromaMode::Archive encrypts `chroma.archive.enc`, unpacks `chroma.archive`, detects
    //    tamper, and still excludes `chroma_vector_embeddings` from rebuildable_indexes.
    let chroma_bytes = b"SYNTHETIC-CHROMA-TAR-ARCHIVE-BYTES-0123456789";
    let chroma_path = PathBuf::from(dir.write("chroma.tar", chroma_bytes));
    let rep_arch = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: db.url(OWNER),
            destination_root: dest.clone(),
            destination_domain: "offhost-chroma".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "chroma-arch-1".to_owned(),
            reason: "chroma archive mode".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::Archive(chroma_path),
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        Arc::new(SyntheticPgDumpRunner),
    )
    .await
    .unwrap();
    let unpack_arch = PathBuf::from(dir.path("unpack-arch"));
    let u_arch = backup::unpack_backup(&rep_arch.backup_dir, &unpack_arch, &keyring).unwrap();
    assert!(matches!(
        u_arch.manifest.chroma,
        ChromaManifest::Archive {
            ref component,
            plaintext_bytes,
            ..
        } if component == "chroma.archive.enc" && plaintext_bytes == chroma_bytes.len() as u64
    ));
    assert!(
        !u_arch
            .manifest
            .rebuildable_indexes
            .iter()
            .any(|s| s == CHROMA_REBUILDABLE_INDEX)
    );
    assert!(u_arch.has_chroma_archive);
    assert_eq!(
        fs::read(unpack_arch.join("chroma.archive")).unwrap(),
        chroma_bytes
    );

    // Tampering `chroma.archive.enc` must fail `verify_backup`.
    let tamper_dir = PathBuf::from(dir.path("tamper-chroma"));
    fs::create_dir(&tamper_dir).unwrap();
    for entry in fs::read_dir(&rep_arch.backup_dir).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), tamper_dir.join(entry.file_name())).unwrap();
    }
    let mut enc = fs::read(tamper_dir.join("chroma.archive.enc")).unwrap();
    let idx = enc.len() - 4;
    enc[idx] ^= 0x01;
    fs::write(tamper_dir.join("chroma.archive.enc"), &enc).unwrap();
    assert!(backup::verify_backup(&tamper_dir, &keyring).is_err());

    // 4. ChromaMode::QualifiedRebuild records qualification_ref and includes
    //    `chroma_vector_embeddings` in rebuildable_indexes.
    let rep_qual = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: db.url(OWNER),
            destination_root: dest.clone(),
            destination_domain: "offhost-chroma".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "chroma-qual-1".to_owned(),
            reason: "chroma qualified rebuild".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::QualifiedRebuild {
                qualification_ref: "V1-30-CHROMA-QUAL-2026-11".to_owned(),
            },
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        Arc::new(SyntheticPgDumpRunner),
    )
    .await
    .unwrap();
    let m_qual = backup::verify_backup(&rep_qual.backup_dir, &keyring).unwrap();
    assert_eq!(
        m_qual.chroma,
        ChromaManifest::QualifiedRebuild {
            qualification_ref: "V1-30-CHROMA-QUAL-2026-11".to_owned(),
        }
    );
    assert!(
        m_qual
            .rebuildable_indexes
            .iter()
            .any(|s| s == CHROMA_REBUILDABLE_INDEX)
    );
    assert!(!m_qual.components.contains_key("chroma.archive.enc"));

    // 5. Exact-key retry of `rep_qual` with `prune_policy: Some(1,1,1)` and
    //    `release_on_success: true` prunes the two older same-day sets (`rep_np` and `rep_arch`).
    let retry_with_prune = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: db.url(OWNER),
            destination_root: dest.clone(),
            destination_domain: "offhost-chroma".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "chroma-qual-1".to_owned(),
            reason: "chroma qualified rebuild".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::QualifiedRebuild {
                qualification_ref: "V1-30-CHROMA-QUAL-2026-11".to_owned(),
            },
            config_files: Vec::new(),
            prune_policy: Some(GfsPolicy {
                keep_daily: 1,
                keep_weekly: 1,
                keep_monthly: 1,
            }),
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        Arc::new(SyntheticPgDumpRunner),
    )
    .await
    .unwrap();
    let pruned = retry_with_prune
        .pruned
        .expect("exact-key retry must execute prune_policy when provided");
    assert_eq!(pruned.kept.len(), 1);
    assert_eq!(pruned.pruned.len(), 2, "pruned={pruned:?}");
    assert!(rep_qual.backup_dir.is_dir());
    assert!(!rep_np.backup_dir.exists());
    assert!(!rep_arch.backup_dir.exists());
}

mod tls_proxy_helpers {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::pin::Pin;
    use std::sync::{Arc, RwLock, atomic::AtomicUsize};
    use std::task::Poll;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::{TcpListener, TcpStream};

    const PG_SSL_REQ: [u8; 8] = [0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];

    pub fn pem_cert(der: &[u8]) -> Vec<u8> {
        let body = STANDARD.encode(der);
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in body.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).unwrap());
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out.into_bytes()
    }

    pub fn make_ca(
        cn: &str,
    ) -> (
        rcgen::Issuer<'static, rcgen::KeyPair>,
        CertificateDer<'static>,
    ) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let der = params.self_signed(&key).unwrap().der().clone();
        (rcgen::Issuer::new(params, key), der)
    }

    pub fn make_server_config(
        issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
        ca_der: &CertificateDer<'static>,
        san: &str,
        shared_sessions: Option<Arc<dyn rustls::server::StoresServerSessions>>,
        shared_ticketer: Option<Arc<dyn rustls::server::ProducesTickets>>,
    ) -> Arc<rustls::ServerConfig> {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![san.to_owned()]).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, issuer).unwrap();
        let chain = vec![cert.der().clone(), ca_der.clone()];
        let priv_key: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(key.serialize_der()).into();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, priv_key)
            .unwrap();
        if let Some(sessions) = shared_sessions {
            cfg.session_storage = sessions;
        }
        if let Some(ticketer) = shared_ticketer {
            cfg.ticketer = ticketer;
            cfg.send_tls13_tickets = 2;
        }
        Arc::new(cfg)
    }

    async fn read_exact_tcp(stream: &TcpStream, mut buf: &mut [u8]) -> std::io::Result<()> {
        while !buf.is_empty() {
            stream.readable().await?;
            match stream.try_read(buf) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "eof",
                    ));
                }
                Ok(n) => buf = &mut buf[n..],
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    async fn write_all_tcp(stream: &TcpStream, mut buf: &[u8]) -> std::io::Result<()> {
        while !buf.is_empty() {
            stream.writable().await?;
            match stream.try_write(buf) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "write zero",
                    ));
                }
                Ok(n) => buf = &buf[n..],
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    async fn forward_duplex<
        A: AsyncRead + AsyncWrite + Unpin,
        B: AsyncRead + AsyncWrite + Unpin,
    >(
        mut a: A,
        mut b: B,
    ) {
        let mut a_to_b = vec![0u8; 16 * 1024];
        let (mut a_pos, mut a_len, mut a_eof, mut b_flush, mut b_shut) =
            (0usize, 0usize, false, false, false);
        let mut b_to_a = vec![0u8; 16 * 1024];
        let (mut b_pos, mut b_len, mut b_eof, mut a_flush, mut a_shut) =
            (0usize, 0usize, false, false, false);
        let _ = std::future::poll_fn(|cx| {
            loop {
                let mut prog = false;
                if a_pos < a_len {
                    match Pin::new(&mut b).poll_write(cx, &a_to_b[a_pos..a_len]) {
                        Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => return Poll::Ready(()),
                        Poll::Ready(Ok(n)) => {
                            a_pos += n;
                            b_flush = true;
                            if a_pos == a_len {
                                a_pos = 0;
                                a_len = 0;
                            }
                            prog = true;
                        }
                        Poll::Pending => {}
                    }
                } else if b_flush {
                    match Pin::new(&mut b).poll_flush(cx) {
                        Poll::Ready(Ok(())) => {
                            b_flush = false;
                            prog = true;
                        }
                        Poll::Ready(Err(_)) => return Poll::Ready(()),
                        Poll::Pending => {}
                    }
                } else if !a_eof {
                    let mut rb = ReadBuf::new(&mut a_to_b);
                    match Pin::new(&mut a).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                a_eof = true;
                            } else {
                                a_len = n;
                                a_pos = 0;
                            }
                            prog = true;
                        }
                        Poll::Ready(Err(_)) => return Poll::Ready(()),
                        Poll::Pending => {}
                    }
                } else if !b_shut {
                    match Pin::new(&mut b).poll_shutdown(cx) {
                        Poll::Ready(Ok(())) => {
                            b_shut = true;
                            prog = true;
                        }
                        Poll::Ready(Err(_)) => return Poll::Ready(()),
                        Poll::Pending => {}
                    }
                }
                if b_pos < b_len {
                    match Pin::new(&mut a).poll_write(cx, &b_to_a[b_pos..b_len]) {
                        Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => return Poll::Ready(()),
                        Poll::Ready(Ok(n)) => {
                            b_pos += n;
                            a_flush = true;
                            if b_pos == b_len {
                                b_pos = 0;
                                b_len = 0;
                            }
                            prog = true;
                        }
                        Poll::Pending => {}
                    }
                } else if a_flush {
                    match Pin::new(&mut a).poll_flush(cx) {
                        Poll::Ready(Ok(())) => {
                            a_flush = false;
                            prog = true;
                        }
                        Poll::Ready(Err(_)) => return Poll::Ready(()),
                        Poll::Pending => {}
                    }
                } else if !b_eof {
                    let mut rb = ReadBuf::new(&mut b_to_a);
                    match Pin::new(&mut b).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                b_eof = true;
                            } else {
                                b_len = n;
                                b_pos = 0;
                            }
                            prog = true;
                        }
                        Poll::Ready(Err(_)) => return Poll::Ready(()),
                        Poll::Pending => {}
                    }
                } else if !a_shut {
                    match Pin::new(&mut a).poll_shutdown(cx) {
                        Poll::Ready(Ok(())) => {
                            a_shut = true;
                            prog = true;
                        }
                        Poll::Ready(Err(_)) => return Poll::Ready(()),
                        Poll::Pending => {}
                    }
                }
                if a_shut && b_shut {
                    return Poll::Ready(());
                }
                if !prog {
                    return Poll::Pending;
                }
            }
        })
        .await;
    }

    pub async fn spawn_pg_tls_proxy(
        upstream_host: String,
        upstream_port: u16,
        server_cfg: Arc<RwLock<Arc<rustls::ServerConfig>>>,
        post_accept_connections: Arc<AtomicUsize>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let cfg = Arc::clone(&server_cfg.read().unwrap());
                let acc = tokio_rustls::TlsAcceptor::from(cfg);
                let up_host = upstream_host.clone();
                let accepted_count = Arc::clone(&post_accept_connections);
                tokio::spawn(async move {
                    let mut req = [0u8; 8];
                    if read_exact_tcp(&client, &mut req).await.is_err() || req != PG_SSL_REQ {
                        return;
                    }
                    if write_all_tcp(&client, b"S").await.is_err() {
                        return;
                    }
                    let Ok(tls_stream) = acc.accept(client).await else {
                        return;
                    };
                    accepted_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let Ok(upstream) = TcpStream::connect((up_host.as_str(), upstream_port)).await
                    else {
                        return;
                    };
                    forward_duplex(tls_stream, upstream).await;
                });
            }
        });
        (port, handle)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn tls_strict_sslrootcert_preflight_and_home_isolation_with_real_pg_dump() {
    use tls_proxy_helpers::{make_ca, make_server_config, pem_cert, spawn_pg_tls_proxy};

    let shared_sessions: Arc<dyn rustls::server::StoresServerSessions> =
        rustls::server::ServerSessionMemoryCache::new(256);
    let shared_ticketer: Arc<dyn rustls::server::ProducesTickets> =
        rustls::crypto::ring::Ticketer::new().unwrap();
    let make_resumable_srv = |issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
                              ca_der: &rustls::pki_types::CertificateDer<'static>,
                              san: &str| {
        make_server_config(
            issuer,
            ca_der,
            san,
            Some(Arc::clone(&shared_sessions)),
            Some(Arc::clone(&shared_ticketer)),
        )
    };

    let db = TestDb::migrated().await;
    let base_url = db.url(OWNER);
    let base_cfg = backup::parse_validated_pg_uri(&base_url).unwrap();
    if base_cfg.host.starts_with('/') {
        // TCP proxy requires a TCP PostgreSQL upstream.
        return;
    }

    let dir = auth_config_support::Dir::new();
    let dest = PathBuf::from(dir.path("dest-tls"));
    fs::create_dir(&dest).unwrap();
    let keyring_path = write_keyring_json(&dir, "bk", "bk-tls", &[("bk-tls", [0xaa; 32])]);
    let keyring = BackupKeyRing::load_from_config(&keyring_path).unwrap();

    let (ca_server, ca_server_der) = make_ca("OpenMettle PG18 Test CA");
    let (ca_other, ca_other_der) = make_ca("OpenMettle Unrelated CA");
    let ca_server_path =
        PathBuf::from(dir.write("ca-server.pem", &pem_cert(ca_server_der.as_ref())));
    let ca_other_path = PathBuf::from(dir.write("ca-other.pem", &pem_cert(ca_other_der.as_ref())));
    fs::set_permissions(&ca_server_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&ca_other_path, fs::Permissions::from_mode(0o600)).unwrap();

    let proxy_ip_cfg = Arc::new(std::sync::RwLock::new(make_resumable_srv(
        &ca_server,
        &ca_server_der,
        "127.0.0.1",
    )));
    let proxy_ip_accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (proxy_ip_port, proxy_ip_handle) = spawn_pg_tls_proxy(
        base_cfg.host.clone(),
        base_cfg.port,
        Arc::clone(&proxy_ip_cfg),
        Arc::clone(&proxy_ip_accepted),
    )
    .await;
    let proxy_dns_cfg = Arc::new(std::sync::RwLock::new(make_resumable_srv(
        &ca_server,
        &ca_server_der,
        "other.example.test",
    )));
    let proxy_dns_accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (proxy_dns_port, proxy_dns_handle) = spawn_pg_tls_proxy(
        base_cfg.host.clone(),
        base_cfg.port,
        proxy_dns_cfg,
        proxy_dns_accepted,
    )
    .await;

    let build_proxy_url = |port: u16, query: &str| -> String {
        match base_cfg.password.as_deref() {
            Some(pw) => format!(
                "postgres://{}:{}@127.0.0.1:{port}/{}?{query}",
                base_cfg.username, pw, base_cfg.database
            ),
            None => format!(
                "postgres://{}@127.0.0.1:{port}/{}?{query}",
                base_cfg.username, base_cfg.database
            ),
        }
    };

    let owner_pool = pool(&db, OWNER).await;
    let has_local_pg18 = pg_tool_major_version("pg_dump").is_some_and(|v| v >= 18);
    let make_runner = || -> Arc<dyn PgDumpRunner> {
        if has_local_pg18 {
            Arc::new(CliPgDumpRunner::default())
        } else {
            Arc::new(SyntheticPgDumpRunner)
        }
    };

    // 1. Wrong `sslrootcert` (`ca_other`) fails preflight BEFORE entering maintenance.
    let bad_ca_url = build_proxy_url(
        proxy_ip_port,
        &format!("sslmode=verify-ca&sslrootcert={}", ca_other_path.display()),
    );
    let err = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: bad_ca_url,
            destination_root: dest.clone(),
            destination_domain: "offhost-tls".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "tls-wrong-ca-1".to_owned(),
            reason: "wrong ca preflight test".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        make_runner(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, BackupError::PgDump(_)), "{err:?}");
    assert!(
        !backup::status(&owner_pool)
            .await
            .unwrap()
            .maintenance_active
    );

    // 2. `verify-full` against mismatched SAN (`other.example.test`) fails preflight BEFORE
    //    entering maintenance.
    let mismatch_full_url = build_proxy_url(
        proxy_dns_port,
        &format!(
            "sslmode=verify-full&sslrootcert={}",
            ca_server_path.display()
        ),
    );
    let err = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: mismatch_full_url,
            destination_root: dest.clone(),
            destination_domain: "offhost-tls".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "tls-mismatch-full-1".to_owned(),
            reason: "verify-full san mismatch test".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        make_runner(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, BackupError::PgDump(_)), "{err:?}");
    assert!(
        !backup::status(&owner_pool)
            .await
            .unwrap()
            .maintenance_active
    );

    // 3. `verify-ca` against mismatched SAN with matching `ca_server` succeeds over real TLS
    //    via `ValidatedPgPool` (and real `pg_dump` 18 when available).
    let verify_ca_url = build_proxy_url(
        proxy_dns_port,
        &format!("sslmode=verify-ca&sslrootcert={}", ca_server_path.display()),
    );
    let verify_ca_cfg = backup::parse_validated_pg_uri(&verify_ca_url).unwrap();
    let tls_pool_ca = backup::connect_validated_pool(&verify_ca_cfg, 4)
        .await
        .unwrap();
    let rep_ca = backup::capture_with_runner(
        tls_pool_ca.pool(),
        &keyring,
        &CaptureOptions {
            database_url: verify_ca_url,
            destination_root: dest.clone(),
            destination_domain: "offhost-tls".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "tls-verify-ca-ok-1".to_owned(),
            reason: "verify-ca tls capture".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        make_runner(),
    )
    .await
    .unwrap();
    backup::verify_backup(&rep_ca.backup_dir, &keyring).unwrap();
    tls_pool_ca.close().await;

    // 4. `verify-full` against matching `127.0.0.1` IP SAN + `ca_server` succeeds over real TLS
    //    via ONE reused `ValidatedPgPool(2)` (`capture_validated_with_runner`), and refuses a
    //    mismatched `database_url`.
    let verify_full_url = build_proxy_url(
        proxy_ip_port,
        &format!(
            "sslmode=verify-full&sslrootcert={}",
            ca_server_path.display()
        ),
    );
    let verify_full_cfg = backup::parse_validated_pg_uri(&verify_full_url).unwrap();
    let tls_pool_full = backup::connect_validated_pool(&verify_full_cfg, 2)
        .await
        .unwrap();
    let mismatch_pool_err = backup::capture_validated_with_runner(
        &tls_pool_full,
        &keyring,
        &CaptureOptions {
            database_url: build_proxy_url(
                proxy_dns_port,
                &format!("sslmode=verify-ca&sslrootcert={}", ca_server_path.display()),
            ),
            destination_root: dest.clone(),
            destination_domain: "offhost-tls".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "tls-validated-mismatch-1".to_owned(),
            reason: "mismatched validated pool url".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        make_runner(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(mismatch_pool_err, BackupError::PgDump(_)),
        "{mismatch_pool_err:?}"
    );
    let rep_full = backup::capture_validated_with_runner(
        &tls_pool_full,
        &keyring,
        &CaptureOptions {
            database_url: verify_full_url,
            destination_root: dest.clone(),
            destination_domain: "offhost-tls".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "tls-verify-full-ok-1".to_owned(),
            reason: "verify-full tls capture".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        make_runner(),
    )
    .await
    .unwrap();
    backup::verify_backup(&rep_full.backup_dir, &keyring).unwrap();
    tls_pool_full.close().await;

    // 5. Poisoned `$HOME/.postgresql/root.crt` (holding `ca_other`) + `sslmode=require`:
    //    Both SQLx (`ValidatedPgPool`) AND real `pg_dump` 18 (isolated by `CliPgDumpRunner`'s
    //    ephemeral PG env) succeed over TLS even though unisolated `pg_dump` with that `HOME` fails!
    let poisoned_home = PathBuf::from(dir.path("poisoned-home"));
    let dot_pg = poisoned_home.join(".postgresql");
    fs::create_dir_all(&dot_pg).unwrap();
    fs::set_permissions(&dot_pg, fs::Permissions::from_mode(0o700)).unwrap();
    fs::copy(&ca_other_path, dot_pg.join("root.crt")).unwrap();
    fs::set_permissions(dot_pg.join("root.crt"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(dot_pg.join("postgresql.crt"), b"INVALID-CLIENT-CERT").unwrap();
    fs::set_permissions(
        dot_pg.join("postgresql.crt"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let require_url = build_proxy_url(proxy_ip_port, "sslmode=require");
    let require_cfg = backup::parse_validated_pg_uri(&require_url).unwrap();
    let tls_pool_req = backup::connect_validated_pool(&require_cfg, 4)
        .await
        .unwrap();

    let require_runner: Arc<dyn PgDumpRunner> = if has_local_pg18 {
        // Negative control: unisolated `pg_dump` with `HOME=poisoned_home` and `PGSSLMODE=require`
        // MUST fail because libpq loads `$HOME/.postgresql/root.crt` (`ca_other`)!
        let mut raw_cmd = Command::new("pg_dump");
        raw_cmd
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", &poisoned_home)
            .env("PGSSLMODE", "require")
            .args([
                "--format=custom",
                "--schema=openmettle",
                "--no-owner",
                "--host=127.0.0.1",
                &format!("--port={proxy_ip_port}"),
                &format!("--username={}", base_cfg.username),
                &format!("--dbname={}", base_cfg.database),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if let Ok(ld) = std::env::var("LD_LIBRARY_PATH") {
            raw_cmd.env("LD_LIBRARY_PATH", ld);
        }
        if let Some(pw) = base_cfg.password.as_deref() {
            raw_cmd.env("PGPASSWORD", pw);
        }
        let raw_out = tokio::task::spawn_blocking(move || raw_cmd.output().unwrap())
            .await
            .unwrap();
        let raw_stderr = String::from_utf8_lossy(&raw_out.stderr);
        assert!(
            !raw_out.status.success(),
            "negative control failed: unisolated pg_dump with poisoned $HOME/.postgresql/root.crt unexpectedly succeeded"
        );
        assert!(
            raw_stderr.to_ascii_lowercase().contains("ssl")
                || raw_stderr.to_ascii_lowercase().contains("cert"),
            "negative control failed for unexpected non-TLS reason: {raw_stderr}"
        );

        let home_wrapper = PathBuf::from(dir.path("pg_dump_poisoned_home.sh"));
        fs::write(
            &home_wrapper,
            format!(
                "#!/bin/sh\nset -eu\nexport HOME='{}'\nexec pg_dump \"$@\"\n",
                poisoned_home.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&home_wrapper, fs::Permissions::from_mode(0o700)).unwrap();
        Arc::new(CliPgDumpRunner::with_program(home_wrapper))
    } else {
        Arc::new(SyntheticPgDumpRunner)
    };

    let rep_req = backup::capture_with_runner(
        tls_pool_req.pool(),
        &keyring,
        &CaptureOptions {
            database_url: require_url,
            destination_root: dest,
            destination_domain: "offhost-tls".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "tls-require-home-isolated-1".to_owned(),
            reason: "sslmode=require ignores poisoned HOME".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        require_runner,
    )
    .await
    .unwrap();
    backup::verify_backup(&rep_req.backup_dir, &keyring).unwrap();
    tls_pool_req.close().await;

    // 6. Mid-pool certificate rotation / reconnect fail-closed proof with preserved server TLS
    //    session cache & TLS 1.3 ticket keys:
    //    Open `ValidatedPgPool` (`max_connections=1`) against `ca_server`, verify `SELECT
    //    pg_backend_pid()`, pause 50ms so TLS 1.3 NewSessionTicket frames arrive, atomically
    //    rotate the proxy server certificate to `ca_other` while keeping the SAME session cache
    //    and ticketer, terminate the first pooled backend so SQLx must reconnect through
    //    `StrictTlsTunnel`, and prove the reconnect performs full cert verification (never PSK
    //    resumption) and fails closed with zero accepted post-rotation handshakes!
    let rotate_pool = backup::connect_validated_pool(&verify_full_cfg, 1)
        .await
        .unwrap();
    let first_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(rotate_pool.pool())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    *proxy_ip_cfg.write().unwrap() = make_resumable_srv(&ca_other, &ca_other_der, "127.0.0.1");
    proxy_ip_accepted.store(0, std::sync::atomic::Ordering::SeqCst);
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(first_pid)
        .fetch_one(&owner_pool)
        .await
        .unwrap();
    assert!(terminated);
    // First query may observe the dead connection or immediately dial; a second query is
    // guaranteed to dial a new connection through `StrictTlsTunnel` against the rotated cert.
    for _ in 0..2 {
        let res = sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(rotate_pool.pool())
            .await;
        assert!(
            res.is_err(),
            "ValidatedPgPool must reject reconnecting to a rotated cert outside sslrootcert"
        );
    }
    assert_eq!(
        proxy_ip_accepted.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "rotated untrusted TLS server must never complete a TLS handshake or receive StartupMessage"
    );
    rotate_pool.close().await;

    proxy_ip_handle.abort();
    proxy_dns_handle.abort();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn unix_socket_pgpass_auth_and_external_archive_key_custody_guards() {
    let db = TestDb::migrated().await;
    let owner_pool = pool(&db, OWNER).await;
    let dir = auth_config_support::Dir::new();
    let dest = PathBuf::from(dir.path("dest-custody"));
    fs::create_dir(&dest).unwrap();
    let keyring_path = write_keyring_json(&dir, "bk", "bk-cust", &[("bk-cust", [0xbc; 32])]);
    let keyring = BackupKeyRing::load_from_config(&keyring_path).unwrap();
    let backup_key_file = keyring_path.parent().unwrap().join("bk-bk-cust.key");
    assert!(backup_key_file.is_file());

    // 1. Both `--neo4j-dump` and `--chroma-archive` refuse backup key custody files BEFORE
    //    entering maintenance.
    let err_neo4j = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: db.url(OWNER),
            destination_root: dest.clone(),
            destination_domain: "offhost-cust".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "custody-neo4j-reject".to_owned(),
            reason: "reject key file as neo4j dump".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::OfflineDump(backup_key_file.clone()),
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        Arc::new(SyntheticPgDumpRunner),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err_neo4j, BackupError::Invalid(_)),
        "{err_neo4j:?}"
    );
    assert!(
        !backup::status(&owner_pool)
            .await
            .unwrap()
            .maintenance_active
    );

    let err_chroma = backup::capture_with_runner(
        &owner_pool,
        &keyring,
        &CaptureOptions {
            database_url: db.url(OWNER),
            destination_root: dest,
            destination_domain: "offhost-cust".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "custody-chroma-reject".to_owned(),
            reason: "reject key file as chroma archive".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::Archive(backup_key_file),
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        Arc::new(SyntheticPgDumpRunner),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err_chroma, BackupError::Invalid(_)),
        "{err_chroma:?}"
    );
    assert!(
        !backup::status(&owner_pool)
            .await
            .unwrap()
            .maintenance_active
    );

    // 2. When PostgreSQL's Unix socket directory is locally reachable alongside real `pg_dump` 18,
    //    verify `CliPgDumpRunner` authenticates cleanly using the dual-entry `PGPASSFILE`
    //    (socket directory + `localhost`) over the Unix socket.
    if pg_tool_major_version("pg_dump").is_some_and(|v| v >= 18) {
        let mut admin_cn = db.admin().await;
        let (sock_dirs, pg_port): (String, String) = sqlx::query_as(
            "SELECT current_setting('unix_socket_directories'), current_setting('port')",
        )
        .fetch_one(&mut admin_cn)
        .await
        .unwrap();
        let local_requires_password: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM pg_catalog.pg_hba_file_rules
                  WHERE type = 'local'
                    AND auth_method IN ('scram-sha-256', 'md5', 'password')
             )",
        )
        .fetch_one(&mut admin_cn)
        .await
        .unwrap_or(false);
        drop(admin_cn);
        let port: u16 = pg_port.parse().unwrap();
        let reachable_dir = sock_dirs
            .split(',')
            .map(str::trim)
            .find(|d| !d.is_empty() && Path::new(d).join(format!(".s.PGSQL.{port}")).exists());
        if std::env::var_os("OPENMETTLE_REQUIRE_UNIX_SOCKET_PGPASS_TEST").is_some() {
            assert!(
                reachable_dir.is_some(),
                "expected reachable PostgreSQL Unix socket in {sock_dirs} for port {port}"
            );
            assert!(
                local_requires_password,
                "expected local Unix socket SCRAM/password auth when OPENMETTLE_REQUIRE_UNIX_SOCKET_PGPASS_TEST is set"
            );
        }
        if let Some(sock_dir) = reachable_dir {
            let base_cfg = backup::parse_validated_pg_uri(&db.url(OWNER)).unwrap();
            let make_sock_url = |socket_dir: &str| -> String {
                let encoded = socket_dir.replace('/', "%2F");
                match base_cfg.password.as_deref() {
                    Some(pw) => format!(
                        "postgres://{}:{}@{encoded}:{port}/{}?sslmode=disable",
                        base_cfg.username, pw, base_cfg.database
                    ),
                    None => format!(
                        "postgres://{}@{encoded}:{port}/{}?sslmode=disable",
                        base_cfg.username, base_cfg.database
                    ),
                }
            };
            let run_raw_pg_dump = |host_arg: &str, pgpass_path: &Path| -> std::process::Output {
                let mut raw = Command::new("pg_dump");
                raw.env_clear()
                    .env("PATH", std::env::var("PATH").unwrap_or_default())
                    .env("PGPASSFILE", pgpass_path)
                    .env("PGSSLMODE", "disable")
                    .env("PGGSSENCMODE", "disable")
                    .args([
                        "--format=custom",
                        "--schema=openmettle",
                        "--no-owner",
                        &format!("--host={host_arg}"),
                        &format!("--port={port}"),
                        &format!("--username={}", base_cfg.username),
                        &format!("--dbname={}", base_cfg.database),
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::piped());
                if let Ok(ld) = std::env::var("LD_LIBRARY_PATH") {
                    raw.env("LD_LIBRARY_PATH", ld);
                }
                raw.output().unwrap()
            };

            // Probe `localhost:`-only PGPASSFILE first: on libpq's compiled-in default socket
            // directory (e.g. `/var/run/postgresql` on Debian/Ubuntu), libpq rewrites the host
            // lookup to `localhost`, so `localhost:`-only succeeds and `socket-only.pgpass` fails.
            // On custom non-default socket directories, libpq matches `{sock_dir}:` literally.
            let mut localhost_only_pgpass: Option<PathBuf> = None;
            if local_requires_password && let Some(pw) = base_cfg.password.as_deref() {
                let lh_pgpass = PathBuf::from(
                    dir.write(
                        "localhost-only.pgpass",
                        format!(
                            "localhost:{port}:{}:{}:{pw}\n",
                            base_cfg.database, base_cfg.username
                        )
                        .as_bytes(),
                    ),
                );
                fs::set_permissions(&lh_pgpass, fs::Permissions::from_mode(0o600)).unwrap();
                let localhost_only_ok = run_raw_pg_dump(sock_dir, &lh_pgpass).status.success();
                if std::env::var_os("OPENMETTLE_REQUIRE_UNIX_SOCKET_PGPASS_TEST").is_some() {
                    assert!(
                        localhost_only_ok,
                        "expected localhost-only PGPASSFILE to authenticate on libpq default socket dir {sock_dir}"
                    );
                }
                if localhost_only_ok {
                    let bad_pgpass = PathBuf::from(
                        dir.write(
                            "socket-only.pgpass",
                            format!(
                                "{sock_dir}:{port}:{}:{}:{pw}\n",
                                base_cfg.database, base_cfg.username
                            )
                            .as_bytes(),
                        ),
                    );
                    fs::set_permissions(&bad_pgpass, fs::Permissions::from_mode(0o600)).unwrap();
                    let raw_out = run_raw_pg_dump(sock_dir, &bad_pgpass);
                    assert!(
                        !raw_out.status.success(),
                        "negative control failed: socket-only PGPASSFILE without localhost entry unexpectedly authenticated on libpq default socket dir {sock_dir}"
                    );
                }
                localhost_only_pgpass = Some(lh_pgpass);
            }

            // Dual-entry `CliPgDumpRunner` MUST succeed on `sock_dir`.
            let runner = CliPgDumpRunner::default();
            let mut dump_bytes = Vec::new();
            let written = runner
                .dump(
                    &make_sock_url(sock_dir),
                    None,
                    &DumpCancel::new(),
                    &mut dump_bytes,
                )
                .unwrap();
            assert!(
                written > 100,
                "unexpectedly small Unix socket pg_dump: {written}"
            );
            assert!(
                dump_bytes.starts_with(b"PGDMP"),
                "expected PostgreSQL custom-format PGDMP header"
            );

            // Also test a custom non-default socket path (short symlink to `sock_dir`) where
            // libpq does NOT rewrite to `localhost` and instead requires the literal socket path
            // line in `PGPASSFILE`.
            struct UnlinkGuard(PathBuf);
            impl Drop for UnlinkGuard {
                fn drop(&mut self) {
                    let _ = fs::remove_file(&self.0);
                }
            }
            let custom_sock = PathBuf::from(format!(
                "/tmp/om-csock-{}-{}",
                std::process::id(),
                new_uuid(&db).await.split('-').next().unwrap_or("0")
            ));
            let _ = fs::remove_file(&custom_sock);
            std::os::unix::fs::symlink(sock_dir, &custom_sock).unwrap();
            let _custom_guard = UnlinkGuard(custom_sock.clone());
            let custom_sock_str = custom_sock.to_str().unwrap();

            if let Some(lh_pgpass) = &localhost_only_pgpass {
                let custom_lh_out = run_raw_pg_dump(custom_sock_str, lh_pgpass);
                assert!(
                    !custom_lh_out.status.success(),
                    "negative control failed: localhost-only PGPASSFILE unexpectedly authenticated on custom non-default socket path {custom_sock_str}"
                );
            }
            let mut custom_dump = Vec::new();
            let custom_written = runner
                .dump(
                    &make_sock_url(custom_sock_str),
                    None,
                    &DumpCancel::new(),
                    &mut custom_dump,
                )
                .unwrap();
            assert!(
                custom_written > 100 && custom_dump.starts_with(b"PGDMP"),
                "CliPgDumpRunner must succeed on custom non-default Unix socket path {custom_sock_str}"
            );
        }
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn populated_upgrade_from_44_preserves_historical_sys_backup_audit_rows_and_blocks_new_ones()
{
    let db = TestDb::new().await;
    migrate::apply(&db.settings(Duration::from_secs(10)), &MIGRATIONS[..44])
        .await
        .unwrap();

    // Insert historical pre-45 operator audit rows whose `request_key` starts with `sys.backup:`.
    let owner_pre = pool(&db, OWNER).await;
    sqlx::query(
        "INSERT INTO openmettle.authorization_audit
            (actor_kind, actor_user_id, operator_id, action, target_kind, target_id,
             request_key, reason, details)
         VALUES
            ('operator', NULL, $1::uuid, 'restore.accept_coverage_gap', 'restore_gate',
             'instance', 'sys.backup:historical-gap-1', 'pre-45 historical gap', '{}'::jsonb),
            ('operator', NULL, $1::uuid, 'storage.declare_payload_lost', 'artifact_revision',
             '33333333-3333-4333-8333-333333333333', 'sys.backup:historical-lost-1',
             'pre-45 historical lost payload', '{}'::jsonb)",
    )
    .bind(OPERATOR_1)
    .execute(&owner_pre)
    .await
    .unwrap();
    owner_pre.close().await;

    // Upgrade 44 -> 45 (including `src/boundaries.sql`) must succeed without rolling back.
    migrate::apply(&db.settings(Duration::from_secs(10)), MIGRATIONS)
        .await
        .unwrap();

    let owner_pool = pool(&db, OWNER).await;
    let preserved: i64 = sqlx::query_scalar(
        "SELECT count(*)
           FROM openmettle.authorization_audit
          WHERE request_key IN ('sys.backup:historical-gap-1', 'sys.backup:historical-lost-1')",
    )
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    assert_eq!(
        preserved, 2,
        "pre-45 historical sys.backup:* audit rows must be preserved across 44 -> 45 upgrade"
    );

    // Post-45: new non-internal inserts using `sys.backup:%` MUST be rejected by the NOT VALID
    // CHECK constraint `authorization_audit_sys_backup_namespace_check` (SQLSTATE 23514).
    let err = sqlx::query(
        "INSERT INTO openmettle.authorization_audit
            (actor_kind, actor_user_id, operator_id, action, target_kind, target_id,
             request_key, reason, details)
         VALUES
            ('operator', NULL, $1::uuid, 'restore.accept_coverage_gap', 'restore_gate',
             'instance', 'sys.backup:post45-forged', 'must fail post-45', '{}'::jsonb)",
    )
    .bind(OPERATOR_1)
    .execute(&owner_pool)
    .await
    .unwrap_err();
    let db_err = err.as_database_error().unwrap();
    assert_eq!(
        db_err.code().as_deref(),
        Some("23514"),
        "post-45 non-internal sys.backup:* insert must fail CHECK constraint: {db_err:?}"
    );
    assert_eq!(
        db_err.constraint(),
        Some("authorization_audit_sys_backup_namespace_check"),
        "expected authorization_audit_sys_backup_namespace_check violation, got {db_err:?}"
    );

    // Normal post-45 backup capture start & release still succeed cleanly.
    let mut tx = owner_pool.begin().await.unwrap();
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await
        .unwrap();
    let run_id: String = sqlx::query_scalar(
        "SELECT backup_run_id::text
           FROM openmettle.backup_start_capture($1::uuid, 'post45-ok-1', 'upgrade ok', 'offhost-upg', 300)",
    )
    .bind(OPERATOR_1)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(!run_id.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "isolated PostgreSQL 18 required"]
async fn validated_pool_capture_fits_owner_connection_limit_three_over_verify_full() {
    use tls_proxy_helpers::{make_ca, make_server_config, pem_cert, spawn_pg_tls_proxy};

    let db = TestDb::migrated_exclusive().await;
    let base_url = db.url(OWNER);
    let base_cfg = backup::parse_validated_pg_uri(&base_url).unwrap();
    if base_cfg.host.starts_with('/') {
        return;
    }
    let _restore = Restore(&["ALTER ROLE openmettle_owner CONNECTION LIMIT -1"]);
    db.wait_no_migration_session().await;
    sqlx::query("ALTER ROLE openmettle_owner CONNECTION LIMIT 3")
        .execute(&mut db.admin().await)
        .await
        .unwrap();

    let (ca_issuer, ca_der) = make_ca("OpenMettle Lim3 CA");
    let srv_cfg = Arc::new(std::sync::RwLock::new(make_server_config(
        &ca_issuer,
        &ca_der,
        "127.0.0.1",
        None,
        None,
    )));
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (proxy_port, proxy_handle) =
        spawn_pg_tls_proxy(base_cfg.host.clone(), base_cfg.port, srv_cfg, accepted).await;

    let dir = auth_config_support::Dir::new();
    let dest = PathBuf::from(dir.path("dest-lim3"));
    fs::create_dir(&dest).unwrap();
    let keyring_path = write_keyring_json(&dir, "bk", "bk-lim3", &[("bk-lim3", [0xcd; 32])]);
    let keyring = BackupKeyRing::load_from_config(&keyring_path).unwrap();

    let ca_path = PathBuf::from(dir.write("ca-lim3.pem", &pem_cert(ca_der.as_ref())));
    fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o600)).unwrap();

    let verify_full_url = match base_cfg.password.as_deref() {
        Some(pw) => format!(
            "postgres://{}:{}@127.0.0.1:{proxy_port}/{}?sslmode=verify-full&sslrootcert={}",
            base_cfg.username,
            pw,
            base_cfg.database,
            ca_path.display()
        ),
        None => format!(
            "postgres://{}@127.0.0.1:{proxy_port}/{}?sslmode=verify-full&sslrootcert={}",
            base_cfg.username,
            base_cfg.database,
            ca_path.display()
        ),
    };
    let cfg = backup::parse_validated_pg_uri(&verify_full_url).unwrap();
    let validated_pool = backup::connect_validated_pool(&cfg, 2).await.unwrap();
    let runner: Arc<dyn PgDumpRunner> = if pg_tool_major_version("pg_dump").is_some_and(|v| v >= 18)
    {
        Arc::new(CliPgDumpRunner::default())
    } else {
        Arc::new(SyntheticPgDumpRunner)
    };

    let report = backup::capture_validated_with_runner(
        &validated_pool,
        &keyring,
        &CaptureOptions {
            database_url: verify_full_url,
            destination_root: dest,
            destination_domain: "offhost-lim3".to_owned(),
            artifact_root: None,
            operator_id: OPERATOR_1.to_owned(),
            request_key: "lim3-verify-full-1".to_owned(),
            reason: "connection limit 3 verify-full capture".to_owned(),
            drain_timeout: Duration::from_secs(5),
            lease_seconds: DEFAULT_LEASE_SECONDS,
            require_separate_device: false,
            graphiti_mode: GraphitiMode::NotProvisioned,
            chroma_mode: ChromaMode::NotProvisioned,
            config_files: Vec::new(),
            prune_policy: None,
            release_on_success: true,
            pg_dump_bin: None,
            allow_local_test_paths: true,
        },
        runner,
    )
    .await
    .unwrap();
    backup::verify_backup(&report.backup_dir, &keyring).unwrap();
    assert!(report.released_maintenance);

    validated_pool.close().await;
    proxy_handle.abort();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 required"]
async fn worker_observe_telemetry_advances_overdue_and_expires_leases_under_held_for_share_gate_lock()
 {
    let db = TestDb::migrated().await;
    let owner_pool = pool(&db, OWNER).await;
    let api_pool = pool(&db, API).await;
    let worker_pool = pool(&db, WORKER).await;
    let metrics = Metrics::new();

    // 1. Arm RPO and backdate it past 3600s so the next telemetry observation is overdue, while
    //    keeping `maintenance_active = false` so `openmettle_api` can acquire `FOR SHARE` on
    //    `backup_maintenance_gate`.
    backup::arm_rpo(
        &owner_pool,
        OPERATOR_1,
        "arm-for-share-1",
        "arm rpo under active traffic",
        3600,
    )
    .await
    .unwrap();
    sqlx::query(
        "UPDATE openmettle.backup_maintenance_gate
            SET rpo_tracking_armed_at = clock_timestamp() - interval '2 hours'
          WHERE id",
    )
    .execute(&owner_pool)
    .await
    .unwrap();

    // 2. Seed an expired `draining` row directly in `backup_runs` (representing a crashed capture
    //    whose lease lapsed).
    let stale_run_id = new_uuid(&db).await;
    sqlx::query(
        "INSERT INTO openmettle.backup_runs
            (id, request_key, operator_id, state, started_at, lease_until, destination_domain,
             opened_maintenance)
         VALUES
            ($1::uuid, 'stale-under-share-1', $2::uuid, 'draining',
             clock_timestamp() - interval '10 minutes',
             clock_timestamp() - interval '1 minute',
             'offhost-share', false)",
    )
    .bind(&stale_run_id)
    .bind(OPERATOR_1)
    .execute(&owner_pool)
    .await
    .unwrap();

    // 3. Hold an open `openmettle_api` transaction with `FOR SHARE` on `backup_maintenance_gate`.
    let mut api_tx = api_pool.begin().await.unwrap();
    sqlx::query("SELECT openmettle.backup_maintenance_lock_open()")
        .execute(&mut *api_tx)
        .await
        .unwrap();

    // 4. `backup_observe_telemetry()` must neither block nor skip under the held `FOR SHARE` lock:
    //    it must expire the stale lease AND increment `overdue_count`.
    let obs = tokio::time::timeout(
        Duration::from_secs(5),
        backup::observe_telemetry_into(&worker_pool, &metrics),
    )
    .await
    .expect("backup_observe_telemetry must not block on runtime FOR SHARE lock")
    .unwrap();
    assert_eq!(obs.overdue, 1, "overdue_count must advance under FOR SHARE");
    assert_eq!(
        obs.incomplete, 1,
        "stale draining lease must expire to incomplete under FOR SHARE"
    );

    let (state, failure_code): (String, Option<String>) = sqlx::query_as(
        "SELECT state, failure_code FROM openmettle.backup_runs WHERE id = $1::uuid",
    )
    .bind(&stale_run_id)
    .fetch_one(&owner_pool)
    .await
    .unwrap();
    assert_eq!(state, "incomplete");
    assert_eq!(failure_code.as_deref(), Some("lease_expired"));

    let st = backup::status(&owner_pool).await.unwrap();
    assert!(
        st.last_overdue_observed_at.is_some(),
        "backup::status must surface last_overdue_observed_at from backup_rpo_telemetry_state"
    );

    api_tx.rollback().await.unwrap();
}
