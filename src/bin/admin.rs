//! Owner-operated offline maintenance.
use openmettle_core::{
    artifact_fs::{
        adoption::{self, Options},
        lost, rebind,
    },
    authz::{
        gateway::family,
        store::{StoreError, WriteOutcome},
    },
    backup::{
        self, CaptureOptions, ChromaMode, DEFAULT_DRAIN_TIMEOUT_SECS, DEFAULT_LEASE_SECONDS,
        GraphitiMode, archive::GfsPolicy, crypto::BackupKeyRing,
    },
    restore, vault,
};
use sqlx::{Connection, PgConnection, PgPool};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

const REBIND_FIRST: &str = "the artifact volume was restored by file copy and is not rebound; run `openmettle-admin storage rebind` first";

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("openmettle-admin: {msg}");
            ExitCode::FAILURE
        }
    }
}

async fn pool(connections: u32) -> Result<PgPool, &'static str> {
    let url = env::var("OPENMETTLE_ADMIN_DATABASE_URL")
        .map_err(|_| "OPENMETTLE_ADMIN_DATABASE_URL is required")?;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(connections)
        .connect(&url)
        .await
        .map_err(|_| "database connection failed")
}

async fn validated_backup_pool(
    connections: u32,
) -> Result<(String, backup::ValidatedPgPool), &'static str> {
    let url = env::var("OPENMETTLE_ADMIN_DATABASE_URL")
        .map_err(|_| "OPENMETTLE_ADMIN_DATABASE_URL is required")?;
    let pg_cfg = backup::parse_validated_pg_uri(&url).map_err(|err| {
        eprintln!("backup: {err}");
        "OPENMETTLE_ADMIN_DATABASE_URL is invalid or contains unsupported parameters"
    })?;
    let db = backup::connect_validated_pool(&pg_cfg, connections)
        .await
        .map_err(|err| {
            eprintln!("backup: {err}");
            match err {
                backup::BackupError::PgDump(_) => "PostgreSQL TLS or URL validation failed",
                _ => "database connection failed",
            }
        })?;
    Ok((url, db))
}

/// Reports a journal or restore step's failure by kind and SQLSTATE only, never record contents
/// or digests, and returns the step's own message.
fn failed(step: &'static str) -> impl FnOnce(restore::Error) -> &'static str {
    move |e| {
        match e {
            restore::Error::Export(why) => eprintln!("{step}: invalid export: {why}"),
            restore::Error::Invalid(why) => eprintln!("{step}: invalid argument: {why}"),
            restore::Error::Database(sqlx::Error::Database(d)) => {
                eprintln!("{step}: SQLSTATE {}", d.code().unwrap_or_default())
            }
            restore::Error::Drift => eprintln!("{step}: accounting drift detected"),
            restore::Error::ArtifactRootRequired => {
                eprintln!("{step}: the volume is pinned; pass its artifact root")
            }
            restore::Error::RebindRequired => return REBIND_FIRST,
            _ => eprintln!("{step}: database or volume failure"),
        }
        match step {
            "journal export" => "journal export failed",
            "restore lock" => "restore lock failed; the gate state is unchanged",
            "restore accept-coverage-gap" => {
                "restore accept-coverage-gap failed; the gate state is unchanged"
            }
            _ => "restore replay failed; the restore gate was not opened",
        }
    }
}

struct RestoreLockArgs {
    origin_us: i64,
    lifecycle_origin_us: Option<i64>,
    lifecycle_baseline_digest: Option<String>,
    connection_origin_us: Option<i64>,
    required_seq: i64,
    required_digest: String,
    export_complete: bool,
    replace_restore_run: Option<String>,
    new_restore: bool,
}

fn parse_restore_lock_args(args: &[String]) -> Result<RestoreLockArgs, &'static str> {
    let usage = "usage: openmettle-admin restore lock --required-origin ORIGIN_US [--required-lifecycle-origin ORIGIN_US] [--required-lifecycle-baseline-digest HEX] [--required-connection-origin ORIGIN_US] --required-seq N --required-digest HEX [--export-complete] [--replace-restore-run UUID] [--new-restore]";
    let mut origin_us = None;
    let mut lifecycle_origin_us = None;
    let mut lifecycle_baseline_digest = None;
    let mut connection_origin_us = None;
    let mut required_seq = None;
    let mut required_digest = None;
    let mut export_complete = false;
    let mut replace_restore_run = None;
    let mut new_restore_flag = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--required-origin" => {
                if origin_us.is_some() {
                    return Err("duplicate --required-origin");
                }
                i += 1;
                let raw = args.get(i).ok_or("missing --required-origin value")?;
                origin_us = Some(raw.parse().map_err(|_| "invalid origin")?);
            }
            "--required-lifecycle-origin" => {
                if lifecycle_origin_us.is_some() {
                    return Err("duplicate --required-lifecycle-origin");
                }
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or("missing --required-lifecycle-origin value")?;
                lifecycle_origin_us = Some(raw.parse().map_err(|_| "invalid lifecycle origin")?);
            }
            "--required-lifecycle-baseline-digest" => {
                if lifecycle_baseline_digest.is_some() {
                    return Err("duplicate --required-lifecycle-baseline-digest");
                }
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or("missing --required-lifecycle-baseline-digest value")?;
                if !restore::is_valid_digest(raw) {
                    return Err("invalid lifecycle baseline digest");
                }
                lifecycle_baseline_digest = Some(raw.clone());
            }
            "--required-connection-origin" => {
                if connection_origin_us.is_some() {
                    return Err("duplicate --required-connection-origin");
                }
                i += 1;
                let raw = args
                    .get(i)
                    .ok_or("missing --required-connection-origin value")?;
                connection_origin_us = Some(raw.parse().map_err(|_| "invalid connection origin")?);
            }
            "--required-seq" => {
                if required_seq.is_some() {
                    return Err("duplicate --required-seq");
                }
                i += 1;
                let raw = args.get(i).ok_or("missing --required-seq value")?;
                let seq: i64 = raw.parse().map_err(|_| "invalid sequence")?;
                if seq < 0 {
                    return Err("invalid sequence");
                }
                required_seq = Some(seq);
            }
            "--required-digest" => {
                if required_digest.is_some() {
                    return Err("duplicate --required-digest");
                }
                i += 1;
                let raw = args.get(i).ok_or("missing --required-digest value")?;
                if !restore::is_valid_digest(raw) {
                    return Err("invalid chain digest");
                }
                required_digest = Some(raw.clone());
            }
            "--export-complete" => {
                if export_complete {
                    return Err("duplicate --export-complete");
                }
                export_complete = true;
            }
            "--replace-restore-run" => {
                if replace_restore_run.is_some() {
                    return Err("duplicate --replace-restore-run");
                }
                i += 1;
                replace_restore_run = Some(
                    args.get(i)
                        .ok_or("missing --replace-restore-run value")?
                        .clone(),
                );
            }
            "--new-restore" => {
                if new_restore_flag {
                    return Err("duplicate --new-restore");
                }
                new_restore_flag = true;
            }
            _ => return Err("unknown restore lock option"),
        }
        i += 1;
    }
    if new_restore_flag && replace_restore_run.is_none() {
        return Err("--new-restore requires --replace-restore-run");
    }
    if lifecycle_origin_us.is_some() != lifecycle_baseline_digest.is_some() {
        return Err(
            "--required-lifecycle-origin and --required-lifecycle-baseline-digest must be supplied together",
        );
    }
    let origin_us = origin_us.ok_or(usage)?;
    let required_seq = required_seq.ok_or(usage)?;
    let required_digest = required_digest.ok_or(usage)?;
    let new_restore = replace_restore_run.is_none() || new_restore_flag;
    Ok(RestoreLockArgs {
        origin_us,
        lifecycle_origin_us,
        lifecycle_baseline_digest,
        connection_origin_us,
        required_seq,
        required_digest,
        export_complete,
        replace_restore_run,
        new_restore,
    })
}

fn parse_accept_gap_args(
    args: &[String],
) -> Result<(String, String, String, String), &'static str> {
    let mut restore_run_id = None;
    let mut operator_id = None;
    let mut request_key = None;
    let mut reason = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--restore-run" => {
                if restore_run_id.is_some() {
                    return Err("duplicate --restore-run");
                }
                i += 1;
                restore_run_id = Some(args.get(i).ok_or("missing --restore-run value")?.clone());
            }
            "--operator-id" => {
                if operator_id.is_some() {
                    return Err("duplicate --operator-id");
                }
                i += 1;
                operator_id = Some(args.get(i).ok_or("missing --operator-id value")?.clone());
            }
            "--request-key" => {
                if request_key.is_some() {
                    return Err("duplicate --request-key");
                }
                i += 1;
                request_key = Some(args.get(i).ok_or("missing --request-key value")?.clone());
            }
            "--reason" => {
                if reason.is_some() {
                    return Err("duplicate --reason");
                }
                i += 1;
                reason = Some(args.get(i).ok_or("missing --reason value")?.clone());
            }
            _ => return Err("unknown restore accept-coverage-gap option"),
        }
        i += 1;
    }
    let usage = "usage: openmettle-admin restore accept-coverage-gap --restore-run UUID --operator-id UUID --request-key KEY --reason REASON";
    Ok((
        restore_run_id.ok_or(usage)?,
        operator_id.ok_or(usage)?,
        request_key.ok_or(usage)?,
        reason.ok_or(usage)?,
    ))
}

struct RestoreReplayArgs {
    file: String,
    root: Option<String>,
    db_only: bool,
}

fn parse_restore_replay_args(args: &[String]) -> Result<RestoreReplayArgs, &'static str> {
    let usage = "usage: openmettle-admin restore replay [--db-only] FILE [ROOT]";
    let mut db_only = false;
    let mut positional: Vec<String> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--db-only" => {
                if db_only {
                    return Err("duplicate --db-only");
                }
                db_only = true;
            }
            s if s.starts_with('-') => return Err("unknown restore replay option"),
            _ => positional.push(arg.clone()),
        }
    }
    if db_only {
        if positional.len() != 1 {
            return Err("usage: openmettle-admin restore replay --db-only FILE");
        }
        return Ok(RestoreReplayArgs {
            file: positional.remove(0),
            root: None,
            db_only: true,
        });
    }
    match positional.len() {
        1 => Ok(RestoreReplayArgs {
            file: positional.remove(0),
            root: None,
            db_only: false,
        }),
        2 => {
            let root = positional.pop();
            let file = positional.remove(0);
            Ok(RestoreReplayArgs {
                file,
                root,
                db_only: false,
            })
        }
        _ => Err(usage),
    }
}

/// ADR 0041: `journal export FILE`,
/// `restore lock --required-origin ORIGIN_US --required-seq N --required-digest HEX [--export-complete] [--replace-restore-run UUID] [--new-restore]`,
/// `restore accept-coverage-gap --restore-run UUID --operator-id UUID --request-key KEY --reason REASON`,
/// `restore replay [--db-only] FILE [ROOT]`.
async fn journal(
    command: (Option<String>, Option<String>),
    args: &[String],
) -> Result<(), &'static str> {
    match (command.0.as_deref(), command.1.as_deref()) {
        (Some("journal"), Some("export")) => {
            let [file] = args else {
                return Err("usage: openmettle-admin journal export FILE");
            };
            let text = restore::export(&pool(1).await?)
                .await
                .map_err(failed("journal export"))?;
            // Never overwrite an earlier export, and sync both the file and its parent directory
            // before acknowledging the watermark.
            let path = Path::new(file);
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            opts.open(path)
                .and_then(|mut f| {
                    std::io::Write::write_all(&mut f, text.as_bytes())?;
                    f.sync_all()?;
                    fs::File::open(parent)?.sync_all()
                })
                .map_err(|_| "export file could not be created")?;
            println!("{}", text.lines().rev().nth(1).unwrap_or_default());
            if let Some(lc) = text
                .lines()
                .nth(2)
                .filter(|line| line.starts_with("lifecycle_origin "))
            {
                println!("{lc}");
            }
            if let Some(lb) = text
                .lines()
                .nth(3)
                .filter(|line| line.starts_with("lifecycle_baseline "))
            {
                println!("{lb}");
            }
            if let Some(co) = text
                .lines()
                .find(|line| line.starts_with("connection_origin "))
            {
                println!("{co}");
            }
        }
        (Some("restore"), Some("lock")) => {
            let lock_args = parse_restore_lock_args(args)?;
            let locked = restore::lock_gate_with_connection_origin(
                &pool(1).await?,
                &restore::GateLockRequest {
                    origin_us: lock_args.origin_us,
                    lifecycle_origin_us: lock_args.lifecycle_origin_us,
                    lifecycle_baseline_digest: lock_args.lifecycle_baseline_digest.as_deref(),
                    required_seq: lock_args.required_seq,
                    required_digest: &lock_args.required_digest,
                    coverage_complete: lock_args.export_complete,
                    replace_restore_run: lock_args.replace_restore_run.as_deref(),
                    new_restore: lock_args.new_restore,
                },
                lock_args.connection_origin_us,
            )
            .await
            .map_err(failed("restore lock"))?;
            let conn_suffix = locked
                .connection_origin_us
                .map_or_else(String::new, |co| format!(", connection_origin {co}"));
            match (
                locked.lifecycle_origin_us,
                locked.lifecycle_baseline_digest.as_deref(),
            ) {
                (Some(lc), Some(lb)) => println!(
                    "restore gate closed: restore_run {}, origin {}, lifecycle_origin {}, lifecycle_baseline {}{conn_suffix}, snapshot {}, required {}, coverage_complete {}",
                    locked.restore_run_id,
                    locked.origin_us,
                    lc,
                    lb,
                    locked.snapshot_seq,
                    locked.required_seq,
                    locked.coverage_complete
                ),
                (Some(lc), None) => println!(
                    "restore gate closed: restore_run {}, origin {}, lifecycle_origin {}{conn_suffix}, snapshot {}, required {}, coverage_complete {}",
                    locked.restore_run_id,
                    locked.origin_us,
                    lc,
                    locked.snapshot_seq,
                    locked.required_seq,
                    locked.coverage_complete
                ),
                (None, _) => println!(
                    "restore gate closed: restore_run {}, origin {}{conn_suffix}, snapshot {}, required {}, coverage_complete {}",
                    locked.restore_run_id,
                    locked.origin_us,
                    locked.snapshot_seq,
                    locked.required_seq,
                    locked.coverage_complete
                ),
            }
        }
        (Some("restore"), Some("accept-coverage-gap")) => {
            let (restore_run_id, operator_id, request_key, reason) = parse_accept_gap_args(args)?;
            let applied = restore::accept_coverage_gap(
                &pool(1).await?,
                &restore_run_id,
                &operator_id,
                &request_key,
                &reason,
            )
            .await
            .map_err(failed("restore accept-coverage-gap"))?;
            if applied {
                println!("applied restore.accept_coverage_gap");
            } else {
                println!("replayed restore.accept_coverage_gap");
            }
        }
        (Some("restore"), Some("replay")) => {
            let replay_args = parse_restore_replay_args(args)?;
            let text =
                fs::read_to_string(&replay_args.file).map_err(|_| "export file unreadable")?;
            let export = restore::Export::parse(&text).map_err(failed("restore replay"))?;
            if replay_args.db_only {
                let pool = pool(1).await?;
                let applied = restore::apply(&pool, &export)
                    .await
                    .map_err(failed("restore replay"))?;
                println!(
                    "replayed {applied} records through {}; database journal caught up (restore gate remains closed)",
                    export.seq
                );
                return Ok(());
            }
            let store = replay_args
                .root
                .as_deref()
                .map(|root| openmettle_core::artifact_fs::Store::open_existing(Path::new(root)))
                .transpose()
                .map_err(|_| "volume unavailable")?;
            let pool = pool(2).await?;
            if let Some(store) = store.as_ref() {
                let mut conn = pool
                    .acquire()
                    .await
                    .map_err(|e| failed("restore replay")(e.into()))?;
                let open = restore::gate_open(&mut conn)
                    .await
                    .map_err(|e| failed("restore replay")(e.into()))?;
                drop(conn);
                if !open {
                    restore::check_rebind(&pool, store)
                        .await
                        .map_err(failed("restore replay"))?;
                }
            }
            let applied = restore::apply(&pool, &export)
                .await
                .map_err(failed("restore replay"))?;
            restore::finish(&pool, store.as_ref(), &export)
                .await
                .map_err(failed("restore replay"))?;
            println!(
                "replayed {applied} records through {}; restore gate open",
                export.seq
            );
        }
        _ => {
            return Err(
                "usage: openmettle-admin journal export FILE | restore lock --required-origin ORIGIN_US [--required-lifecycle-origin ORIGIN_US] [--required-lifecycle-baseline-digest HEX] --required-seq N --required-digest HEX [--export-complete] [--replace-restore-run UUID] [--new-restore] | restore accept-coverage-gap --restore-run UUID --operator-id UUID --request-key KEY --reason REASON | restore replay [--db-only] FILE [ROOT]",
            );
        }
    }
    Ok(())
}

async fn run() -> Result<(), &'static str> {
    let mut args = env::args().skip(1);
    let command = (args.next(), args.next());
    if matches!(command.0.as_deref(), Some("journal" | "restore")) {
        return journal(command, &args.collect::<Vec<_>>()).await;
    }
    if command.0.as_deref() == Some("vault") {
        return vault_command(command.1.as_deref(), &args.collect::<Vec<_>>()).await;
    }
    if command.0.as_deref() == Some("backup") {
        return backup_command(command.1.as_deref(), &args.collect::<Vec<_>>()).await;
    }
    if command.0.as_deref() == Some("family") {
        let mut family_args = Vec::new();
        if let Some(sub) = command.1 {
            family_args.push(sub);
        }
        family_args.extend(args);
        let parsed = family::parse_admin_args(&family_args)?;
        let url = env::var("OPENMETTLE_ADMIN_DATABASE_URL")
            .map_err(|_| "OPENMETTLE_ADMIN_DATABASE_URL is required")?;
        let mut c = PgConnection::connect(&url)
            .await
            .map_err(|_| "owner connection failed")?;
        let (action, outcome) = family::execute_admin_command(&mut c, &parsed)
            .await
            .map_err(|err| match err {
                StoreError::InvalidInput("zone") => "unknown family policy timezone",
                StoreError::InvalidInput(_) => "invalid family policy input",
                StoreError::NotFound => "family policy target not found",
                StoreError::Conflict(msg) => msg,
                StoreError::Denied(_) => "family policy write denied",
                StoreError::Database(_) => "family policy write failed",
            })?;
        match outcome {
            WriteOutcome::Applied { target_id } => println!("applied {action} {target_id}"),
            WriteOutcome::Replayed { target_id } => println!("replayed {action} {target_id}"),
        }
        return Ok(());
    }
    if command.0.as_deref() == Some("runtime") {
        if args.next().is_some() || command.1.as_deref() != Some("activate-two-phase-intents") {
            return Err("usage: openmettle-admin runtime activate-two-phase-intents");
        }
        let url = env::var("OPENMETTLE_ADMIN_DATABASE_URL")
            .map_err(|_| "OPENMETTLE_ADMIN_DATABASE_URL is required")?;
        let mut c = PgConnection::connect(&url)
            .await
            .map_err(|_| "owner connection failed")?;
        let updated = sqlx::query(
            "UPDATE openmettle.runtime_feature_gates
                SET two_phase_effect_intents_enabled = true
              WHERE id AND NOT two_phase_effect_intents_enabled",
        )
        .execute(&mut c)
        .await
        .map_err(|_| "runtime feature gate activation failed")?
        .rows_affected();
        if updated > 0 {
            println!("activated two_phase_effect_intents_enabled");
        } else {
            println!("two_phase_effect_intents_enabled already active");
        }
        return Ok(());
    }
    if command.0.as_deref() == Some("quota") {
        let artifact_root = args.next();
        if args.next().is_some()
            || (artifact_root.is_some() && command.1.as_deref() != Some("verify"))
        {
            return Err("unexpected quota command argument");
        }
        let pool = pool(1).await?;
        match command.1.as_deref() {
            Some("drain-orphans") => {
                let released = openmettle_core::quotas::drain_gateway_orphans(&pool)
                    .await
                    .map_err(|_| "orphan sweep failed")?;
                println!("released {released} orphan gateway requests");
            }
            Some("verify") => {
                let store = artifact_root
                    .as_deref()
                    .map(|root| openmettle_core::artifact_fs::Store::open_existing(Path::new(root)))
                    .transpose()
                    .map_err(|_| "volume unavailable")?;
                let report =
                    openmettle_core::artifact_fs::verify_accounting_drift(&pool, store.as_ref())
                        .await
                        .map_err(|_| {
                            if store.as_ref().is_some_and(|store| store.awaits_rebind()) {
                                REBIND_FIRST
                            } else {
                                "volume or ledger verification failed"
                            }
                        })?;
                print_drift(&report);
                if !report.healthy() {
                    return Err("accounting drift detected");
                }
            }
            Some("activate") => {
                sqlx::query(
                    "UPDATE openmettle.quota_enforcement
                        SET metering_enforced = true,
                            metering_enforced_at = coalesce(metering_enforced_at, clock_timestamp()),
                            overrides_enforced = true,
                            overrides_enforced_at = coalesce(overrides_enforced_at, clock_timestamp())
                      WHERE id AND (NOT metering_enforced OR NOT overrides_enforced)",
                )
                .execute(&pool)
                .await
                .map_err(|_| "metering activation failed")?;
            }
            _ => {
                return Err(
                    "usage: openmettle-admin quota drain-orphans | activate | verify [ROOT]",
                );
            }
        }
        return Ok(());
    }
    let rebinding = command.1.as_deref() == Some("rebind");
    let declaring_lost = command.1.as_deref() == Some("declare-lost");
    if command.0.as_deref() != Some("storage")
        || (command.1.as_deref() != Some("adopt") && !rebinding && !declaring_lost)
    {
        return Err(
            "usage: openmettle-admin storage adopt ROOT [--replace-adoption-run UUID] [--expected-fs-uuid UUID --expected-revisions-inode DEV:INO] [--confirm-no-on-disk-payloads] | storage rebind ROOT [--replace-adoption-run UUID] | storage declare-lost ROOT --revision UUID --operator-id UUID --request-key KEY --reason REASON | vault status | vault rotate --vault-keys PATH --operator-id UUID --request-key KEY --reason REASON [--batch-size N] | backup status | backup enter-maintenance ... | backup release-maintenance ... | backup arm-rpo ... | backup capture ... | backup verify ... | backup unpack ... | backup prune ...",
        );
    }
    let root = args.next().ok_or("missing artifact directory")?;
    if declaring_lost {
        let parsed = parse_declare_lost_args(&args.collect::<Vec<_>>())?;
        return declare_lost_payload(Path::new(&root), &parsed).await;
    }
    if rebinding {
        let replace = match (args.next().as_deref(), args.next(), args.next()) {
            (None, ..) => None,
            (Some("--replace-adoption-run"), Some(run), None) => Some(run),
            _ => return Err("unknown rebind option"),
        };
        return rebind_volume(Path::new(&root), replace.as_deref()).await;
    }
    let mut replace = None;
    let mut expected_fs = None;
    let mut expected_directory = None;
    let mut confirm_absent = false;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--replace-adoption-run" => replace = Some(args.next().ok_or("missing adoption UUID")?),
            "--expected-fs-uuid" => {
                expected_fs = Some(args.next().ok_or("missing filesystem UUID")?)
            }
            "--expected-revisions-inode" => {
                let value = args.next().ok_or("missing device:inode")?;
                let (dev, ino) = value.split_once(':').ok_or("invalid device:inode")?;
                expected_directory = Some((
                    dev.parse().map_err(|_| "invalid device")?,
                    ino.parse().map_err(|_| "invalid inode")?,
                ));
            }
            "--confirm-no-on-disk-payloads" => confirm_absent = true,
            _ => return Err("unknown adoption option"),
        }
    }
    let url = env::var("OPENMETTLE_ADMIN_DATABASE_URL")
        .map_err(|_| "OPENMETTLE_ADMIN_DATABASE_URL is required")?;
    let mut c = PgConnection::connect(&url)
        .await
        .map_err(|_| "owner connection failed")?;
    adoption::adopt(
        &mut c,
        &Options {
            root: Path::new(&root),
            replace: replace.as_deref(),
            expected_fs: expected_fs.as_deref(),
            expected_directory,
            confirm_absent,
        },
    )
    .await
    .map_err(|failure| {
        eprintln!("OMQ03: {}", failure.0);
        "storage adoption failed"
    })
}

/// Rebind a copied artifact volume after a restore (ADR 0040, amendment of 24 November 2026).
async fn rebind_volume(root: &Path, replace: Option<&str>) -> Result<(), &'static str> {
    let url = env::var("OPENMETTLE_ADMIN_DATABASE_URL")
        .map_err(|_| "OPENMETTLE_ADMIN_DATABASE_URL is required")?;
    let mut c = PgConnection::connect(&url)
        .await
        .map_err(|_| "owner connection failed")?;
    let report = match rebind::rebind(&mut c, &rebind::Options { root, replace }).await {
        Ok(report) => report,
        Err(stopped) => {
            eprintln!("OMQ03: {}", stopped.reason);
            return Err(match stopped.barrier {
                rebind::Barrier::AsFound => "storage rebind refused; nothing was changed",
                rebind::Barrier::Held(run) => {
                    eprintln!(
                        "the volume stays closed and uploads may already be emptied; re-run with --replace-adoption-run {run}"
                    );
                    "storage rebind incomplete"
                }
                rebind::Barrier::Unknown(run) => {
                    eprintln!(
                        "this run used the barrier value {run}; whether the volume is closed under it is not known"
                    );
                    eprintln!(
                        "read the current value before the next command: SELECT adoption_run_id FROM openmettle.storage_volume_control;"
                    );
                    "storage rebind interrupted"
                }
            });
        }
    };
    println!(
        "rebound {}, emptied {}, unchanged {}, quarantined {}, failed {}",
        report.rebound,
        report.emptied,
        report.unchanged,
        report.quarantined.len(),
        report.failures.len()
    );
    for (reservation, reason) in &report.failures {
        println!("failed {reservation}: {reason}");
    }
    for reservation in &report.quarantined {
        println!("quarantined {reservation}: left unchanged");
    }
    for reservation in &report.unbound_staged {
        println!(
            "warning {reservation}: unbound reservation with a staged file; left unchanged, the reconciler will quarantine it"
        );
    }
    let drift = report.drift.as_ref().filter(|drift| !drift.healthy());
    if let Some(drift) = drift {
        print_drift(drift);
    }
    if report.complete() {
        if drift.is_some() {
            println!(
                "rebind did not change the quarantined reservations or the accounting drift reported above"
            );
        }
        return Ok(());
    }
    eprintln!(
        "the volume stays closed; resolve what is reported and re-run with --replace-adoption-run {}",
        report.run
    );
    Err("storage rebind incomplete")
}

fn print_drift(report: &openmettle_core::artifact_fs::Drift) {
    println!(
        "storage mismatches {}, budget mismatches {}, settlement mismatches {}, pending gateway {}, file mismatches {}, quarantined {}, unsettled payloads {}",
        report.storage_accounts,
        report.budgets,
        report.settlements,
        report.pending_gateway,
        report.files,
        report.quarantined,
        report.unsettled_payloads
    );
}

struct DeclareLostArgs {
    revision: String,
    operator_id: String,
    request_key: String,
    reason: String,
}

fn parse_declare_lost_args(args: &[String]) -> Result<DeclareLostArgs, &'static str> {
    let usage = "usage: openmettle-admin storage declare-lost ROOT --revision UUID --operator-id UUID --request-key KEY --reason REASON";
    let mut revision = None;
    let mut operator_id = None;
    let mut request_key = None;
    let mut reason = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--revision" => {
                if revision.is_some() {
                    return Err("duplicate --revision");
                }
                i += 1;
                revision = Some(args.get(i).ok_or("missing --revision value")?.clone());
            }
            "--operator-id" => {
                if operator_id.is_some() {
                    return Err("duplicate --operator-id");
                }
                i += 1;
                operator_id = Some(args.get(i).ok_or("missing --operator-id value")?.clone());
            }
            "--request-key" => {
                if request_key.is_some() {
                    return Err("duplicate --request-key");
                }
                i += 1;
                request_key = Some(args.get(i).ok_or("missing --request-key value")?.clone());
            }
            "--reason" => {
                if reason.is_some() {
                    return Err("duplicate --reason");
                }
                i += 1;
                reason = Some(args.get(i).ok_or("missing --reason value")?.clone());
            }
            _ => return Err("unknown declare-lost option"),
        }
        i += 1;
    }
    Ok(DeclareLostArgs {
        revision: revision.ok_or(usage)?,
        operator_id: operator_id.ok_or(usage)?,
        request_key: request_key.ok_or(usage)?,
        reason: reason.ok_or(usage)?,
    })
}

async fn declare_lost_payload(root: &Path, parsed: &DeclareLostArgs) -> Result<(), &'static str> {
    let url = env::var("OPENMETTLE_ADMIN_DATABASE_URL")
        .map_err(|_| "OPENMETTLE_ADMIN_DATABASE_URL is required")?;
    let mut c = PgConnection::connect(&url)
        .await
        .map_err(|_| "owner connection failed")?;
    let outcome = lost::declare_lost(
        &mut c,
        &lost::Options {
            root,
            revision: &parsed.revision,
            operator_id: &parsed.operator_id,
            request_key: &parsed.request_key,
            reason: &parsed.reason,
        },
    )
    .await
    .map_err(|failure| {
        eprintln!("storage declare-lost: {}", failure.0);
        "storage declare-lost refused"
    })?;
    let verb = if outcome.applied {
        "applied"
    } else {
        "replayed"
    };
    println!(
        "{verb} storage.declare_payload_lost revision={} reservation={} previous_state={} journal_seq={} unlinked={}",
        outcome.revision_id,
        outcome.reservation_id,
        outcome.previous_state,
        outcome.journal_seq,
        outcome.unlinked_files
    );
    Ok(())
}

struct VaultRotateArgs {
    vault_keys: String,
    operator_id: String,
    request_key: String,
    reason: String,
    batch_size: usize,
}

fn parse_vault_rotate_args(args: &[String]) -> Result<VaultRotateArgs, &'static str> {
    let usage = "usage: openmettle-admin vault rotate --vault-keys PATH --operator-id UUID --request-key KEY --reason REASON [--batch-size N]";
    let mut vault_keys = None;
    let mut operator_id = None;
    let mut request_key = None;
    let mut reason = None;
    let mut batch_size = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--vault-keys" => {
                if vault_keys.is_some() {
                    return Err("duplicate --vault-keys");
                }
                i += 1;
                vault_keys = Some(args.get(i).ok_or("missing --vault-keys value")?.clone());
            }
            "--operator-id" => {
                if operator_id.is_some() {
                    return Err("duplicate --operator-id");
                }
                i += 1;
                operator_id = Some(args.get(i).ok_or("missing --operator-id value")?.clone());
            }
            "--request-key" => {
                if request_key.is_some() {
                    return Err("duplicate --request-key");
                }
                i += 1;
                request_key = Some(args.get(i).ok_or("missing --request-key value")?.clone());
            }
            "--reason" => {
                if reason.is_some() {
                    return Err("duplicate --reason");
                }
                i += 1;
                reason = Some(args.get(i).ok_or("missing --reason value")?.clone());
            }
            "--batch-size" => {
                if batch_size.is_some() {
                    return Err("duplicate --batch-size");
                }
                i += 1;
                let raw = args.get(i).ok_or("missing --batch-size value")?;
                let parsed: usize = raw.parse().map_err(|_| "invalid --batch-size")?;
                if !(1..=1000).contains(&parsed) {
                    return Err("invalid --batch-size");
                }
                batch_size = Some(parsed);
            }
            _ => return Err("unknown vault rotate option"),
        }
        i += 1;
    }
    Ok(VaultRotateArgs {
        vault_keys: vault_keys.ok_or(usage)?,
        operator_id: operator_id.ok_or(usage)?,
        request_key: request_key.ok_or(usage)?,
        reason: reason.ok_or(usage)?,
        batch_size: batch_size.unwrap_or(100),
    })
}

async fn vault_command(sub: Option<&str>, args: &[String]) -> Result<(), &'static str> {
    match sub {
        Some("status") => {
            if !args.is_empty() {
                return Err("usage: openmettle-admin vault status");
            }
            let report = vault::vault_status(&pool(1).await?)
                .await
                .map_err(|_| "vault status failed")?;
            println!(
                "connections {}, encrypted {}",
                report.total_connections, report.total_encrypted
            );
            for (state, count) in &report.by_state {
                println!("state {state} {count}");
            }
            for (key_id, count) in &report.by_key_id {
                println!("key_id {key_id} {count}");
            }
            Ok(())
        }
        Some("rotate") => {
            let parsed = parse_vault_rotate_args(args)?;
            let keyring = vault::VaultKeyRing::load_from_config(Path::new(&parsed.vault_keys))
                .map_err(|err| match err {
                    vault::VaultError::Configuration(msg) => msg,
                    _ => "vault keyring configuration invalid",
                })?;
            let report = vault::vault_rotate(
                &pool(2).await?,
                &keyring,
                &parsed.operator_id,
                &parsed.request_key,
                &parsed.reason,
                parsed.batch_size,
            )
            .await
            .map_err(|err| match err {
                vault::VaultError::UnknownKey => {
                    "vault rotation refused: stored key version missing from keyring"
                }
                vault::VaultError::Store(StoreError::Conflict(msg)) => msg,
                vault::VaultError::Store(StoreError::InvalidInput(_)) => {
                    "invalid vault rotation argument"
                }
                _ => "vault rotation failed",
            })?;
            if report.replayed {
                println!(
                    "replayed vault.rotated target_key_id={} rotated={} skipped={} deferred_active_refresh={}",
                    report.target_key_id,
                    report.rotated_rows,
                    report.skipped_rows,
                    report.deferred_active_refresh
                );
            } else {
                println!(
                    "applied vault.rotated target_key_id={} rotated={} skipped={} deferred_active_refresh={}",
                    report.target_key_id,
                    report.rotated_rows,
                    report.skipped_rows,
                    report.deferred_active_refresh
                );
            }
            if !report.replayed && (report.skipped_rows > 0 || report.deferred_active_refresh > 0) {
                return Err(
                    "vault rotation incomplete: authorized rows remain on older key versions (active refresh claims deferred); retry with the same --request-key",
                );
            }
            Ok(())
        }
        _ => Err(
            "usage: openmettle-admin vault status | vault rotate --vault-keys PATH --operator-id UUID --request-key KEY --reason REASON [--batch-size N]",
        ),
    }
}

struct BackupAuditArgs {
    operator_id: String,
    request_key: String,
    reason: String,
    abort_active_run: bool,
    rpo_seconds: Option<i32>,
}

fn parse_backup_audit_args(
    args: &[String],
    allow_abort: bool,
    allow_rpo: bool,
    usage: &'static str,
) -> Result<BackupAuditArgs, &'static str> {
    let mut operator_id = None;
    let mut request_key = None;
    let mut reason = None;
    let mut abort_active_run = false;
    let mut rpo_seconds = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--operator-id" => {
                if operator_id.is_some() {
                    return Err("duplicate --operator-id");
                }
                i += 1;
                operator_id = Some(args.get(i).ok_or("missing --operator-id value")?.clone());
            }
            "--request-key" => {
                if request_key.is_some() {
                    return Err("duplicate --request-key");
                }
                i += 1;
                request_key = Some(args.get(i).ok_or("missing --request-key value")?.clone());
            }
            "--reason" => {
                if reason.is_some() {
                    return Err("duplicate --reason");
                }
                i += 1;
                reason = Some(args.get(i).ok_or("missing --reason value")?.clone());
            }
            "--abort-active-run" if allow_abort => {
                if abort_active_run {
                    return Err("duplicate --abort-active-run");
                }
                abort_active_run = true;
            }
            "--rpo-seconds" if allow_rpo => {
                if rpo_seconds.is_some() {
                    return Err("duplicate --rpo-seconds");
                }
                i += 1;
                let raw = args.get(i).ok_or("missing --rpo-seconds value")?;
                let parsed: i32 = raw.parse().map_err(|_| "invalid --rpo-seconds")?;
                if !(3600..=604_800).contains(&parsed) {
                    return Err("invalid --rpo-seconds");
                }
                rpo_seconds = Some(parsed);
            }
            _ => return Err("unknown backup option"),
        }
        i += 1;
    }
    Ok(BackupAuditArgs {
        operator_id: operator_id.ok_or(usage)?,
        request_key: request_key.ok_or(usage)?,
        reason: reason.ok_or(usage)?,
        abort_active_run,
        rpo_seconds,
    })
}

struct BackupCaptureArgs {
    destination_root: PathBuf,
    destination_domain: String,
    backup_keys_config: Option<PathBuf>,
    artifact_root: Option<PathBuf>,
    operator_id: String,
    request_key: String,
    reason: String,
    drain_timeout_secs: u64,
    require_separate_device: bool,
    graphiti_mode: GraphitiMode,
    chroma_mode: ChromaMode,
    config_files: Vec<(String, PathBuf)>,
    keep_daily: usize,
    keep_weekly: usize,
    keep_monthly: usize,
    no_prune: bool,
    release_on_success: bool,
    pg_dump_bin: Option<PathBuf>,
}

fn parse_backup_capture_args(args: &[String]) -> Result<BackupCaptureArgs, &'static str> {
    let usage = "usage: openmettle-admin backup capture --destination-root PATH --destination-domain DOMAIN [--backup-keys-config PATH] [--artifact-root PATH] --operator-id UUID --request-key KEY --reason REASON [--drain-timeout-secs N] [--require-separate-device] [--graphiti-mode not-provisioned|offline-dump] [--neo4j-dump PATH] [--chroma-mode not-provisioned|archive|qualified-rebuild] [--chroma-archive PATH] [--chroma-qualification-ref REF] [--config-file NAME=PATH]... [--keep-daily N] [--keep-weekly N] [--keep-monthly N] [--no-prune] [--release-on-success] [--pg-dump-bin PATH]";
    let defaults = GfsPolicy::default();
    let mut destination_root = None;
    let mut destination_domain = None;
    let mut backup_keys_config = None;
    let mut artifact_root = None;
    let mut operator_id = None;
    let mut request_key = None;
    let mut reason = None;
    let mut drain_timeout_secs = None;
    let mut require_separate_device = false;
    let mut graphiti_mode_raw: Option<String> = None;
    let mut neo4j_dump: Option<PathBuf> = None;
    let mut chroma_mode_raw: Option<String> = None;
    let mut chroma_archive: Option<PathBuf> = None;
    let mut chroma_qualification_ref: Option<String> = None;
    let mut config_files: Vec<(String, PathBuf)> = Vec::new();
    let mut keep_daily = None;
    let mut keep_weekly = None;
    let mut keep_monthly = None;
    let mut no_prune = false;
    let mut release_on_success = false;
    let mut pg_dump_bin: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--destination-root" => {
                if destination_root.is_some() {
                    return Err("duplicate --destination-root");
                }
                i += 1;
                destination_root = Some(PathBuf::from(
                    args.get(i).ok_or("missing --destination-root value")?,
                ));
            }
            "--destination-domain" => {
                if destination_domain.is_some() {
                    return Err("duplicate --destination-domain");
                }
                i += 1;
                destination_domain = Some(
                    args.get(i)
                        .ok_or("missing --destination-domain value")?
                        .clone(),
                );
            }
            "--backup-keys-config" => {
                if backup_keys_config.is_some() {
                    return Err("duplicate --backup-keys-config");
                }
                i += 1;
                backup_keys_config = Some(PathBuf::from(
                    args.get(i).ok_or("missing --backup-keys-config value")?,
                ));
            }
            "--artifact-root" => {
                if artifact_root.is_some() {
                    return Err("duplicate --artifact-root");
                }
                i += 1;
                artifact_root = Some(PathBuf::from(
                    args.get(i).ok_or("missing --artifact-root value")?,
                ));
            }
            "--operator-id" => {
                if operator_id.is_some() {
                    return Err("duplicate --operator-id");
                }
                i += 1;
                operator_id = Some(args.get(i).ok_or("missing --operator-id value")?.clone());
            }
            "--request-key" => {
                if request_key.is_some() {
                    return Err("duplicate --request-key");
                }
                i += 1;
                request_key = Some(args.get(i).ok_or("missing --request-key value")?.clone());
            }
            "--reason" => {
                if reason.is_some() {
                    return Err("duplicate --reason");
                }
                i += 1;
                reason = Some(args.get(i).ok_or("missing --reason value")?.clone());
            }
            "--drain-timeout-secs" => {
                if drain_timeout_secs.is_some() {
                    return Err("duplicate --drain-timeout-secs");
                }
                i += 1;
                let raw = args.get(i).ok_or("missing --drain-timeout-secs value")?;
                let secs: u64 = raw.parse().map_err(|_| "invalid --drain-timeout-secs")?;
                if secs == 0 || secs > 86_400 {
                    return Err("invalid --drain-timeout-secs");
                }
                drain_timeout_secs = Some(secs);
            }
            "--require-separate-device" => {
                if require_separate_device {
                    return Err("duplicate --require-separate-device");
                }
                require_separate_device = true;
            }
            "--graphiti-mode" => {
                if graphiti_mode_raw.is_some() {
                    return Err("duplicate --graphiti-mode");
                }
                i += 1;
                graphiti_mode_raw =
                    Some(args.get(i).ok_or("missing --graphiti-mode value")?.clone());
            }
            "--neo4j-dump" => {
                if neo4j_dump.is_some() {
                    return Err("duplicate --neo4j-dump");
                }
                i += 1;
                neo4j_dump = Some(PathBuf::from(
                    args.get(i).ok_or("missing --neo4j-dump value")?,
                ));
            }
            "--chroma-mode" => {
                if chroma_mode_raw.is_some() {
                    return Err("duplicate --chroma-mode");
                }
                i += 1;
                chroma_mode_raw = Some(args.get(i).ok_or("missing --chroma-mode value")?.clone());
            }
            "--chroma-archive" => {
                if chroma_archive.is_some() {
                    return Err("duplicate --chroma-archive");
                }
                i += 1;
                chroma_archive = Some(PathBuf::from(
                    args.get(i).ok_or("missing --chroma-archive value")?,
                ));
            }
            "--chroma-qualification-ref" => {
                if chroma_qualification_ref.is_some() {
                    return Err("duplicate --chroma-qualification-ref");
                }
                i += 1;
                chroma_qualification_ref = Some(
                    args.get(i)
                        .ok_or("missing --chroma-qualification-ref value")?
                        .clone(),
                );
            }
            "--config-file" => {
                i += 1;
                let raw = args.get(i).ok_or("missing --config-file value")?;
                let (name, path) = raw
                    .split_once('=')
                    .ok_or("--config-file must be formatted as NAME=PATH")?;
                if name.is_empty() || path.is_empty() {
                    return Err("--config-file must be formatted as NAME=PATH");
                }
                config_files.push((name.to_owned(), PathBuf::from(path)));
            }
            "--keep-daily" => {
                if keep_daily.is_some() {
                    return Err("duplicate --keep-daily");
                }
                i += 1;
                keep_daily = Some(
                    args.get(i)
                        .ok_or("missing --keep-daily value")?
                        .parse()
                        .map_err(|_| "invalid --keep-daily")?,
                );
            }
            "--keep-weekly" => {
                if keep_weekly.is_some() {
                    return Err("duplicate --keep-weekly");
                }
                i += 1;
                keep_weekly = Some(
                    args.get(i)
                        .ok_or("missing --keep-weekly value")?
                        .parse()
                        .map_err(|_| "invalid --keep-weekly")?,
                );
            }
            "--keep-monthly" => {
                if keep_monthly.is_some() {
                    return Err("duplicate --keep-monthly");
                }
                i += 1;
                keep_monthly = Some(
                    args.get(i)
                        .ok_or("missing --keep-monthly value")?
                        .parse()
                        .map_err(|_| "invalid --keep-monthly")?,
                );
            }
            "--no-prune" => {
                if no_prune {
                    return Err("duplicate --no-prune");
                }
                no_prune = true;
            }
            "--release-on-success" => {
                if release_on_success {
                    return Err("duplicate --release-on-success");
                }
                release_on_success = true;
            }
            "--pg-dump-bin" => {
                if pg_dump_bin.is_some() {
                    return Err("duplicate --pg-dump-bin");
                }
                i += 1;
                let raw = args.get(i).ok_or("missing --pg-dump-bin value")?;
                if raw.is_empty() {
                    return Err("--pg-dump-bin must not be empty");
                }
                pg_dump_bin = Some(PathBuf::from(raw));
            }
            _ => return Err("unknown backup capture option"),
        }
        i += 1;
    }

    let graphiti_mode = match graphiti_mode_raw.as_deref().unwrap_or("not-provisioned") {
        "not-provisioned" => {
            if neo4j_dump.is_some() {
                return Err("--neo4j-dump requires --graphiti-mode offline-dump");
            }
            GraphitiMode::NotProvisioned
        }
        "offline-dump" => {
            let path =
                neo4j_dump.ok_or("--graphiti-mode offline-dump requires --neo4j-dump PATH")?;
            GraphitiMode::OfflineDump(path)
        }
        _ => return Err("--graphiti-mode must be not-provisioned or offline-dump"),
    };

    let chroma_mode = match chroma_mode_raw.as_deref().unwrap_or("not-provisioned") {
        "not-provisioned" => {
            if chroma_archive.is_some() {
                return Err("--chroma-archive requires --chroma-mode archive");
            }
            if chroma_qualification_ref.is_some() {
                return Err("--chroma-qualification-ref requires --chroma-mode qualified-rebuild");
            }
            ChromaMode::NotProvisioned
        }
        "archive" => {
            if chroma_qualification_ref.is_some() {
                return Err("--chroma-qualification-ref requires --chroma-mode qualified-rebuild");
            }
            let path =
                chroma_archive.ok_or("--chroma-mode archive requires --chroma-archive PATH")?;
            ChromaMode::Archive(path)
        }
        "qualified-rebuild" => {
            if chroma_archive.is_some() {
                return Err("--chroma-archive requires --chroma-mode archive");
            }
            let qualification_ref = chroma_qualification_ref
                .ok_or("--chroma-mode qualified-rebuild requires --chroma-qualification-ref REF")?;
            backup::validate_chroma_qualification_ref(&qualification_ref)
                .map_err(|_| "invalid --chroma-qualification-ref")?;
            ChromaMode::QualifiedRebuild { qualification_ref }
        }
        _ => return Err("--chroma-mode must be not-provisioned, archive, or qualified-rebuild"),
    };

    Ok(BackupCaptureArgs {
        destination_root: destination_root.ok_or(usage)?,
        destination_domain: destination_domain.ok_or(usage)?,
        backup_keys_config,
        artifact_root,
        operator_id: operator_id.ok_or(usage)?,
        request_key: request_key.ok_or(usage)?,
        reason: reason.ok_or(usage)?,
        drain_timeout_secs: drain_timeout_secs.unwrap_or(DEFAULT_DRAIN_TIMEOUT_SECS),
        require_separate_device,
        graphiti_mode,
        chroma_mode,
        config_files,
        keep_daily: keep_daily.unwrap_or(defaults.keep_daily),
        keep_weekly: keep_weekly.unwrap_or(defaults.keep_weekly),
        keep_monthly: keep_monthly.unwrap_or(defaults.keep_monthly),
        no_prune,
        release_on_success,
        pg_dump_bin,
    })
}

struct BackupVerifyUnpackArgs {
    backup_dir: PathBuf,
    output_dir: Option<PathBuf>,
    backup_keys_config: Option<PathBuf>,
}

fn parse_backup_verify_unpack_args(
    args: &[String],
    require_output_dir: bool,
) -> Result<BackupVerifyUnpackArgs, &'static str> {
    let usage = if require_output_dir {
        "usage: openmettle-admin backup unpack --backup-dir PATH --output-dir PATH [--backup-keys-config PATH]"
    } else {
        "usage: openmettle-admin backup verify --backup-dir PATH [--backup-keys-config PATH]"
    };
    let mut backup_dir = None;
    let mut output_dir = None;
    let mut backup_keys_config = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--backup-dir" => {
                if backup_dir.is_some() {
                    return Err("duplicate --backup-dir");
                }
                i += 1;
                backup_dir = Some(PathBuf::from(
                    args.get(i).ok_or("missing --backup-dir value")?,
                ));
            }
            "--output-dir" if require_output_dir => {
                if output_dir.is_some() {
                    return Err("duplicate --output-dir");
                }
                i += 1;
                output_dir = Some(PathBuf::from(
                    args.get(i).ok_or("missing --output-dir value")?,
                ));
            }
            "--backup-keys-config" => {
                if backup_keys_config.is_some() {
                    return Err("duplicate --backup-keys-config");
                }
                i += 1;
                backup_keys_config = Some(PathBuf::from(
                    args.get(i).ok_or("missing --backup-keys-config value")?,
                ));
            }
            _ => return Err("unknown backup option"),
        }
        i += 1;
    }
    Ok(BackupVerifyUnpackArgs {
        backup_dir: backup_dir.ok_or(usage)?,
        output_dir: if require_output_dir {
            Some(output_dir.ok_or(usage)?)
        } else {
            None
        },
        backup_keys_config,
    })
}

struct BackupPruneArgs {
    destination_root: PathBuf,
    backup_keys_config: Option<PathBuf>,
    policy: GfsPolicy,
    dry_run: bool,
}

fn parse_backup_prune_args(args: &[String]) -> Result<BackupPruneArgs, &'static str> {
    let usage = "usage: openmettle-admin backup prune --destination-root PATH [--backup-keys-config PATH] [--keep-daily N] [--keep-weekly N] [--keep-monthly N] [--dry-run]";
    let defaults = GfsPolicy::default();
    let mut destination_root = None;
    let mut backup_keys_config = None;
    let mut keep_daily = None;
    let mut keep_weekly = None;
    let mut keep_monthly = None;
    let mut dry_run = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--destination-root" => {
                if destination_root.is_some() {
                    return Err("duplicate --destination-root");
                }
                i += 1;
                destination_root = Some(PathBuf::from(
                    args.get(i).ok_or("missing --destination-root value")?,
                ));
            }
            "--backup-keys-config" => {
                if backup_keys_config.is_some() {
                    return Err("duplicate --backup-keys-config");
                }
                i += 1;
                backup_keys_config = Some(PathBuf::from(
                    args.get(i).ok_or("missing --backup-keys-config value")?,
                ));
            }
            "--keep-daily" => {
                if keep_daily.is_some() {
                    return Err("duplicate --keep-daily");
                }
                i += 1;
                keep_daily = Some(
                    args.get(i)
                        .ok_or("missing --keep-daily value")?
                        .parse()
                        .map_err(|_| "invalid --keep-daily")?,
                );
            }
            "--keep-weekly" => {
                if keep_weekly.is_some() {
                    return Err("duplicate --keep-weekly");
                }
                i += 1;
                keep_weekly = Some(
                    args.get(i)
                        .ok_or("missing --keep-weekly value")?
                        .parse()
                        .map_err(|_| "invalid --keep-weekly")?,
                );
            }
            "--keep-monthly" => {
                if keep_monthly.is_some() {
                    return Err("duplicate --keep-monthly");
                }
                i += 1;
                keep_monthly = Some(
                    args.get(i)
                        .ok_or("missing --keep-monthly value")?
                        .parse()
                        .map_err(|_| "invalid --keep-monthly")?,
                );
            }
            "--dry-run" => {
                if dry_run {
                    return Err("duplicate --dry-run");
                }
                dry_run = true;
            }
            _ => return Err("unknown backup prune option"),
        }
        i += 1;
    }
    let policy = GfsPolicy {
        keep_daily: keep_daily.unwrap_or(defaults.keep_daily),
        keep_weekly: keep_weekly.unwrap_or(defaults.keep_weekly),
        keep_monthly: keep_monthly.unwrap_or(defaults.keep_monthly),
    };
    policy
        .validate()
        .map_err(|_| "invalid GFS retention policy")?;
    Ok(BackupPruneArgs {
        destination_root: destination_root.ok_or(usage)?,
        backup_keys_config,
        policy,
        dry_run,
    })
}

fn load_backup_keyring(explicit: Option<&Path>) -> Result<BackupKeyRing, &'static str> {
    let path = match explicit {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from(env::var("OPENMETTLE_ADMIN_BACKUP_KEYS_CONFIG").map_err(
            |_| "--backup-keys-config or OPENMETTLE_ADMIN_BACKUP_KEYS_CONFIG is required",
        )?),
    };
    BackupKeyRing::load_from_config(&path).map_err(|err| {
        eprintln!("backup keys: {err}");
        "backup keyring configuration invalid"
    })
}

fn report_backup_error(step: &'static str) -> impl FnOnce(backup::BackupError) -> &'static str {
    move |err| {
        eprintln!("{step}: {err}");
        match step {
            "backup status" => "backup status failed",
            "backup enter-maintenance" => "backup enter-maintenance failed",
            "backup release-maintenance" => "backup release-maintenance failed",
            "backup arm-rpo" => "backup arm-rpo failed",
            "backup capture" => "backup capture failed",
            "backup verify" => "backup verification failed",
            "backup unpack" => "backup unpack failed",
            _ => "backup prune failed",
        }
    }
}

async fn backup_command(sub: Option<&str>, args: &[String]) -> Result<(), &'static str> {
    match sub {
        Some("status") => {
            if !args.is_empty() {
                return Err("usage: openmettle-admin backup status");
            }
            let (_url, db) = validated_backup_pool(1).await?;
            let res = backup::status(db.pool())
                .await
                .map_err(report_backup_error("backup status"));
            db.close().await;
            let st = res?;
            println!(
                "{}",
                serde_json::to_string_pretty(&st).map_err(|_| "backup status encode failed")?
            );
            Ok(())
        }
        Some("enter-maintenance") => {
            let parsed = parse_backup_audit_args(
                args,
                false,
                false,
                "usage: openmettle-admin backup enter-maintenance --operator-id UUID --request-key KEY --reason REASON",
            )?;
            let (_url, db) = validated_backup_pool(1).await?;
            let res = backup::enter_maintenance(
                db.pool(),
                &parsed.operator_id,
                &parsed.request_key,
                &parsed.reason,
            )
            .await
            .map_err(report_backup_error("backup enter-maintenance"));
            db.close().await;
            let (entered, entered_at) = res?;
            println!(
                "{} backup.maintenance_entered entered_at={}",
                if entered { "applied" } else { "replayed" },
                entered_at.as_deref().unwrap_or("none")
            );
            Ok(())
        }
        Some("release-maintenance") => {
            let parsed = parse_backup_audit_args(
                args,
                true,
                false,
                "usage: openmettle-admin backup release-maintenance --operator-id UUID --request-key KEY --reason REASON [--abort-active-run]",
            )?;
            let (_url, db) = validated_backup_pool(1).await?;
            let res = backup::release_maintenance(
                db.pool(),
                &parsed.operator_id,
                &parsed.request_key,
                &parsed.reason,
                parsed.abort_active_run,
            )
            .await
            .map_err(report_backup_error("backup release-maintenance"));
            db.close().await;
            let (released, aborted) = res?;
            println!(
                "{} backup.maintenance_released aborted_run_id={}",
                if released { "applied" } else { "replayed" },
                aborted.as_deref().unwrap_or("none")
            );
            Ok(())
        }
        Some("arm-rpo") => {
            let parsed = parse_backup_audit_args(
                args,
                false,
                true,
                "usage: openmettle-admin backup arm-rpo --operator-id UUID --request-key KEY --reason REASON [--rpo-seconds 86400]",
            )?;
            let rpo_seconds = parsed.rpo_seconds.unwrap_or(86_400);
            let (_url, db) = validated_backup_pool(1).await?;
            let res = backup::arm_rpo(
                db.pool(),
                &parsed.operator_id,
                &parsed.request_key,
                &parsed.reason,
                rpo_seconds,
            )
            .await
            .map_err(report_backup_error("backup arm-rpo"));
            db.close().await;
            let (target, armed_at) = res?;
            println!("applied backup.rpo_armed rpo_target_seconds={target} armed_at={armed_at}");
            Ok(())
        }
        Some("capture") => {
            let parsed = parse_backup_capture_args(args)?;
            let keyring = load_backup_keyring(parsed.backup_keys_config.as_deref())?;
            let (url, db) = validated_backup_pool(4).await?;
            let prune_policy = if parsed.no_prune {
                None
            } else {
                Some(GfsPolicy {
                    keep_daily: parsed.keep_daily,
                    keep_weekly: parsed.keep_weekly,
                    keep_monthly: parsed.keep_monthly,
                })
            };
            let pg_dump_bin = match parsed.pg_dump_bin {
                Some(path) => Some(path),
                None => match env::var("OPENMETTLE_PG_DUMP_BIN") {
                    Ok(raw) if !raw.is_empty() => Some(PathBuf::from(raw)),
                    Ok(_) => {
                        db.close().await;
                        return Err("OPENMETTLE_PG_DUMP_BIN must not be empty");
                    }
                    Err(_) => None,
                },
            };
            let res = backup::capture(
                db.pool(),
                &keyring,
                &CaptureOptions {
                    database_url: url,
                    destination_root: parsed.destination_root,
                    destination_domain: parsed.destination_domain,
                    artifact_root: parsed.artifact_root,
                    operator_id: parsed.operator_id,
                    request_key: parsed.request_key,
                    reason: parsed.reason,
                    drain_timeout: Duration::from_secs(parsed.drain_timeout_secs),
                    lease_seconds: DEFAULT_LEASE_SECONDS,
                    require_separate_device: parsed.require_separate_device,
                    graphiti_mode: parsed.graphiti_mode,
                    chroma_mode: parsed.chroma_mode,
                    config_files: parsed.config_files,
                    prune_policy,
                    release_on_success: parsed.release_on_success,
                    pg_dump_bin,
                    allow_local_test_paths: false,
                },
            )
            .await
            .map_err(report_backup_error("backup capture"));
            db.close().await;
            let report = res?;
            println!(
                "backup.capture_succeeded run_id={} dir={} key_id={} bundle_digest={} journal_seq={} pruned={} skipped_unverified={} maintenance_released={}",
                report.backup_run_id,
                report.backup_dir.display(),
                report.encryption_key_id,
                report.bundle_digest,
                report.journal_seq,
                report.pruned.as_ref().map_or(0, |p| p.pruned.len()),
                report
                    .pruned
                    .as_ref()
                    .map_or(0, |p| p.skipped_unverified.len()),
                report.released_maintenance
            );
            Ok(())
        }
        Some("verify") => {
            let parsed = parse_backup_verify_unpack_args(args, false)?;
            let keyring = load_backup_keyring(parsed.backup_keys_config.as_deref())?;
            let manifest = backup::verify_backup(&parsed.backup_dir, &keyring)
                .map_err(report_backup_error("backup verify"))?;
            println!(
                "backup.verified run_id={} schema={} key_id={} components={} journal_seq={} artifact_revisions={}",
                manifest.backup_run_id,
                manifest.schema_version,
                manifest.encryption_key_id,
                manifest.components.len(),
                manifest.deletion_journal.journal_seq,
                manifest.artifact_volume.revision_count
            );
            Ok(())
        }
        Some("unpack") => {
            let parsed = parse_backup_verify_unpack_args(args, true)?;
            let keyring = load_backup_keyring(parsed.backup_keys_config.as_deref())?;
            let report = backup::unpack_backup(
                &parsed.backup_dir,
                parsed.output_dir.as_deref().unwrap(),
                &keyring,
            )
            .map_err(report_backup_error("backup unpack"))?;
            println!(
                "backup.unpacked run_id={} output={} artifact_revisions={} config_files={} neo4j_dump={} chroma_archive={}",
                report.manifest.backup_run_id,
                report.output_dir.display(),
                report.artifact_summary.revision_count,
                report.config_files_written,
                report.has_neo4j_dump,
                report.has_chroma_archive
            );
            Ok(())
        }
        Some("prune") => {
            let parsed = parse_backup_prune_args(args)?;
            let keyring = load_backup_keyring(parsed.backup_keys_config.as_deref())?;
            let report = backup::prune(
                &parsed.destination_root,
                &keyring,
                parsed.policy,
                parsed.dry_run,
            )
            .map_err(report_backup_error("backup prune"))?;
            println!(
                "backup.pruned dry_run={} kept={} pruned={} skipped_unverified={}",
                parsed.dry_run,
                report.kept.len(),
                report.pruned.len(),
                report.skipped_unverified.len()
            );
            Ok(())
        }
        _ => Err(
            "usage: openmettle-admin backup status | enter-maintenance ... | release-maintenance ... | arm-rpo ... | capture ... | verify ... | unpack ... | prune ...",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ChromaMode, GraphitiMode, parse_backup_audit_args, parse_backup_capture_args,
        parse_backup_prune_args, parse_backup_verify_unpack_args, parse_declare_lost_args,
        parse_restore_lock_args, parse_restore_replay_args,
    };
    use openmettle_core::restore::GENESIS;
    use std::path::PathBuf;

    fn vecs(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn restore_lock_requires_paired_lifecycle_origin_and_baseline_digest() {
        let origin_only = vecs(&[
            "--required-origin",
            "100",
            "--required-lifecycle-origin",
            "200",
            "--required-seq",
            "0",
            "--required-digest",
            GENESIS,
        ]);
        assert_eq!(
            parse_restore_lock_args(&origin_only).err(),
            Some(
                "--required-lifecycle-origin and --required-lifecycle-baseline-digest must be supplied together"
            )
        );

        let digest_only = vecs(&[
            "--required-origin",
            "100",
            "--required-lifecycle-baseline-digest",
            GENESIS,
            "--required-seq",
            "0",
            "--required-digest",
            GENESIS,
        ]);
        assert_eq!(
            parse_restore_lock_args(&digest_only).err(),
            Some(
                "--required-lifecycle-origin and --required-lifecycle-baseline-digest must be supplied together"
            )
        );

        let paired = vecs(&[
            "--required-origin",
            "100",
            "--required-lifecycle-origin",
            "200",
            "--required-lifecycle-baseline-digest",
            GENESIS,
            "--required-seq",
            "0",
            "--required-digest",
            GENESIS,
        ]);
        let parsed = parse_restore_lock_args(&paired).unwrap();
        assert_eq!(parsed.lifecycle_origin_us, Some(200));
        assert_eq!(parsed.lifecycle_baseline_digest.as_deref(), Some(GENESIS));

        let neither = vecs(&[
            "--required-origin",
            "100",
            "--required-seq",
            "0",
            "--required-digest",
            GENESIS,
        ]);
        let parsed = parse_restore_lock_args(&neither).unwrap();
        assert_eq!(parsed.lifecycle_origin_us, None);
        assert_eq!(parsed.lifecycle_baseline_digest, None);
    }

    #[test]
    fn declare_lost_requires_all_four_audited_flags() {
        let valid = vecs(&[
            "--revision",
            "11111111-1111-4111-8111-111111111111",
            "--operator-id",
            "22222222-2222-4222-8222-222222222222",
            "--request-key",
            "lost-req-1",
            "--reason",
            "unrecoverable disk corruption after restore",
        ]);
        let parsed = parse_declare_lost_args(&valid).unwrap();
        assert_eq!(parsed.revision, "11111111-1111-4111-8111-111111111111");
        assert_eq!(parsed.operator_id, "22222222-2222-4222-8222-222222222222");
        assert_eq!(parsed.request_key, "lost-req-1");
        assert_eq!(parsed.reason, "unrecoverable disk corruption after restore");

        assert!(parse_declare_lost_args(&valid[..6]).is_err());
        assert_eq!(
            parse_declare_lost_args(&vecs(&["--unknown", "x"])).err(),
            Some("unknown declare-lost option")
        );
        assert_eq!(
            parse_declare_lost_args(&vecs(&["--revision", "a", "--revision", "b"])).err(),
            Some("duplicate --revision")
        );
    }

    #[test]
    fn restore_replay_parses_db_only_and_rejects_root_combination() {
        let db_only = parse_restore_replay_args(&vecs(&["--db-only", "export.txt"])).unwrap();
        assert!(db_only.db_only);
        assert_eq!(db_only.file, "export.txt");
        assert_eq!(db_only.root, None);

        let full = parse_restore_replay_args(&vecs(&["export.txt", "/var/artifacts"])).unwrap();
        assert!(!full.db_only);
        assert_eq!(full.file, "export.txt");
        assert_eq!(full.root.as_deref(), Some("/var/artifacts"));

        assert!(parse_restore_replay_args(&vecs(&["--db-only", "export.txt", "/root"])).is_err());
        assert_eq!(
            parse_restore_replay_args(&vecs(&["--db-only", "--db-only", "export.txt"])).err(),
            Some("duplicate --db-only")
        );
        assert_eq!(
            parse_restore_replay_args(&vecs(&["--unknown", "export.txt"])).err(),
            Some("unknown restore replay option")
        );
    }

    #[test]
    fn backup_capture_parses_options_and_enforces_graphiti_and_config_rules() {
        let parsed = parse_backup_capture_args(&vecs(&[
            "--destination-root",
            "/mnt/offhost-backups/openmettle",
            "--destination-domain",
            "nas-primary-rack2",
            "--backup-keys-config",
            "/etc/openmettle/backup-keys.json",
            "--artifact-root",
            "/var/lib/openmettle/artifacts",
            "--operator-id",
            "11111111-1111-4111-8111-111111111111",
            "--request-key",
            "nightly-2026-11-26",
            "--reason",
            "scheduled nightly backup",
            "--drain-timeout-secs",
            "180",
            "--require-separate-device",
            "--graphiti-mode",
            "offline-dump",
            "--neo4j-dump",
            "/var/backups/neo4j/graphiti.dump",
            "--config-file",
            "catalog.json=/etc/openmettle/catalog.json",
            "--config-file",
            "inference.json=/etc/openmettle/inference.json",
            "--keep-daily",
            "7",
            "--keep-weekly",
            "4",
            "--keep-monthly",
            "3",
            "--release-on-success",
            "--pg-dump-bin",
            "/usr/lib/postgresql/18/bin/pg_dump",
        ]))
        .unwrap();
        assert_eq!(
            parsed.destination_root,
            PathBuf::from("/mnt/offhost-backups/openmettle")
        );
        assert_eq!(parsed.destination_domain, "nas-primary-rack2");
        assert_eq!(parsed.drain_timeout_secs, 180);
        assert!(parsed.require_separate_device);
        assert_eq!(
            parsed.graphiti_mode,
            GraphitiMode::OfflineDump(PathBuf::from("/var/backups/neo4j/graphiti.dump"))
        );
        assert_eq!(parsed.config_files.len(), 2);
        assert!(parsed.release_on_success);
        assert!(!parsed.no_prune);
        assert_eq!(
            parsed.pg_dump_bin,
            Some(PathBuf::from("/usr/lib/postgresql/18/bin/pg_dump"))
        );
        assert_eq!(parsed.chroma_mode, ChromaMode::NotProvisioned);

        let chroma_archived = parse_backup_capture_args(&vecs(&[
            "--destination-root",
            "/mnt/backups",
            "--destination-domain",
            "offhost",
            "--operator-id",
            "11111111-1111-4111-8111-111111111111",
            "--request-key",
            "k1",
            "--reason",
            "r1",
            "--chroma-mode",
            "archive",
            "--chroma-archive",
            "/var/backups/chroma/chroma.tar",
        ]))
        .unwrap();
        assert_eq!(
            chroma_archived.chroma_mode,
            ChromaMode::Archive(PathBuf::from("/var/backups/chroma/chroma.tar"))
        );

        let chroma_qualified = parse_backup_capture_args(&vecs(&[
            "--destination-root",
            "/mnt/backups",
            "--destination-domain",
            "offhost",
            "--operator-id",
            "11111111-1111-4111-8111-111111111111",
            "--request-key",
            "k1",
            "--reason",
            "r1",
            "--chroma-mode",
            "qualified-rebuild",
            "--chroma-qualification-ref",
            "QUAL-CHROMA-2026-11",
        ]))
        .unwrap();
        assert_eq!(
            chroma_qualified.chroma_mode,
            ChromaMode::QualifiedRebuild {
                qualification_ref: "QUAL-CHROMA-2026-11".to_owned(),
            }
        );

        for (extra, expected_err) in [
            (
                vec!["--chroma-mode", "archive"],
                "--chroma-mode archive requires --chroma-archive PATH",
            ),
            (
                vec!["--chroma-archive", "/var/backups/chroma.tar"],
                "--chroma-archive requires --chroma-mode archive",
            ),
            (
                vec!["--chroma-mode", "qualified-rebuild"],
                "--chroma-mode qualified-rebuild requires --chroma-qualification-ref REF",
            ),
            (
                vec!["--chroma-qualification-ref", "QUAL-1"],
                "--chroma-qualification-ref requires --chroma-mode qualified-rebuild",
            ),
            (
                vec![
                    "--chroma-mode",
                    "archive",
                    "--chroma-archive",
                    "/var/backups/chroma.tar",
                    "--chroma-qualification-ref",
                    "QUAL-1",
                ],
                "--chroma-qualification-ref requires --chroma-mode qualified-rebuild",
            ),
            (
                vec![
                    "--chroma-mode",
                    "qualified-rebuild",
                    "--chroma-qualification-ref",
                    "QUAL-1",
                    "--chroma-archive",
                    "/var/backups/chroma.tar",
                ],
                "--chroma-archive requires --chroma-mode archive",
            ),
            (
                vec!["--chroma-mode", "bogus"],
                "--chroma-mode must be not-provisioned, archive, or qualified-rebuild",
            ),
        ] {
            let mut argv = vecs(&[
                "--destination-root",
                "/mnt/backups",
                "--destination-domain",
                "offhost",
                "--operator-id",
                "11111111-1111-4111-8111-111111111111",
                "--request-key",
                "k1",
                "--reason",
                "r1",
            ]);
            argv.extend(vecs(&extra));
            assert_eq!(parse_backup_capture_args(&argv).err(), Some(expected_err));
        }

        // offline-dump without --neo4j-dump is refused.
        assert_eq!(
            parse_backup_capture_args(&vecs(&[
                "--destination-root",
                "/mnt/backups",
                "--destination-domain",
                "offhost",
                "--operator-id",
                "11111111-1111-4111-8111-111111111111",
                "--request-key",
                "k1",
                "--reason",
                "r1",
                "--graphiti-mode",
                "offline-dump",
            ]))
            .err(),
            Some("--graphiti-mode offline-dump requires --neo4j-dump PATH")
        );

        // --neo4j-dump without offline-dump is refused.
        assert_eq!(
            parse_backup_capture_args(&vecs(&[
                "--destination-root",
                "/mnt/backups",
                "--destination-domain",
                "offhost",
                "--operator-id",
                "11111111-1111-4111-8111-111111111111",
                "--request-key",
                "k1",
                "--reason",
                "r1",
                "--neo4j-dump",
                "/var/backups/neo4j.dump",
            ]))
            .err(),
            Some("--neo4j-dump requires --graphiti-mode offline-dump")
        );

        // Malformed --config-file is refused.
        assert_eq!(
            parse_backup_capture_args(&vecs(&[
                "--destination-root",
                "/mnt/backups",
                "--destination-domain",
                "offhost",
                "--operator-id",
                "11111111-1111-4111-8111-111111111111",
                "--request-key",
                "k1",
                "--reason",
                "r1",
                "--config-file",
                "missing-equals",
            ]))
            .err(),
            Some("--config-file must be formatted as NAME=PATH")
        );
    }

    #[test]
    fn backup_audit_verify_unpack_and_prune_parsers_validate_flags() {
        let rel = parse_backup_audit_args(
            &vecs(&[
                "--operator-id",
                "11111111-1111-4111-8111-111111111111",
                "--request-key",
                "rel-1",
                "--reason",
                "recover stuck maintenance",
                "--abort-active-run",
            ]),
            true,
            false,
            "usage",
        )
        .unwrap();
        assert!(rel.abort_active_run);

        let rpo = parse_backup_audit_args(
            &vecs(&[
                "--operator-id",
                "11111111-1111-4111-8111-111111111111",
                "--request-key",
                "arm-1",
                "--reason",
                "arm nightly 24h RPO",
                "--rpo-seconds",
                "86400",
            ]),
            false,
            true,
            "usage",
        )
        .unwrap();
        assert_eq!(rpo.rpo_seconds, Some(86_400));

        assert_eq!(
            parse_backup_audit_args(&vecs(&["--rpo-seconds", "60"]), false, true, "usage").err(),
            Some("invalid --rpo-seconds")
        );

        let verify = parse_backup_verify_unpack_args(
            &vecs(&["--backup-dir", "/mnt/backups/backup-1"]),
            false,
        )
        .unwrap();
        assert_eq!(verify.backup_dir, PathBuf::from("/mnt/backups/backup-1"));
        assert!(verify.output_dir.is_none());

        assert!(
            parse_backup_verify_unpack_args(
                &vecs(&["--backup-dir", "/mnt/backups/backup-1"]),
                true,
            )
            .is_err()
        );

        let prune = parse_backup_prune_args(&vecs(&[
            "--destination-root",
            "/mnt/backups",
            "--backup-keys-config",
            "/etc/openmettle/backup-keys.json",
            "--keep-daily",
            "7",
            "--keep-weekly",
            "4",
            "--keep-monthly",
            "3",
            "--dry-run",
        ]))
        .unwrap();
        assert!(prune.dry_run);
        assert_eq!(
            prune.backup_keys_config,
            Some(PathBuf::from("/etc/openmettle/backup-keys.json"))
        );
        assert_eq!(prune.policy.keep_daily, 7);
        assert_eq!(prune.policy.keep_weekly, 4);
        assert_eq!(prune.policy.keep_monthly, 3);
    }
}
