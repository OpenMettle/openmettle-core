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
    restore, vault,
};
use sqlx::{Connection, PgConnection, PgPool};
use std::{env, fs, path::Path, process::ExitCode};

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

/// ADR 0041: `journal export FILE`,
/// `restore lock --required-origin ORIGIN_US --required-seq N --required-digest HEX [--export-complete] [--replace-restore-run UUID] [--new-restore]`,
/// `restore accept-coverage-gap --restore-run UUID --operator-id UUID --request-key KEY --reason REASON`,
/// `restore replay FILE [ROOT]`.
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
        (Some("restore"), Some("replay")) if matches!(args.len(), 1 | 2) => {
            let file = &args[0];
            let store = args
                .get(1)
                .map(|root| openmettle_core::artifact_fs::Store::open_existing(Path::new(root)))
                .transpose()
                .map_err(|_| "volume unavailable")?;
            let text = fs::read_to_string(file).map_err(|_| "export file unreadable")?;
            let export = restore::Export::parse(&text).map_err(failed("restore replay"))?;
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
                "usage: openmettle-admin journal export FILE | restore lock --required-origin ORIGIN_US [--required-lifecycle-origin ORIGIN_US] [--required-lifecycle-baseline-digest HEX] --required-seq N --required-digest HEX [--export-complete] [--replace-restore-run UUID] [--new-restore] | restore accept-coverage-gap --restore-run UUID --operator-id UUID --request-key KEY --reason REASON | restore replay FILE [ROOT]",
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
            "usage: openmettle-admin storage adopt ROOT [--replace-adoption-run UUID] [--expected-fs-uuid UUID --expected-revisions-inode DEV:INO] [--confirm-no-on-disk-payloads] | storage rebind ROOT [--replace-adoption-run UUID] | storage declare-lost ROOT --revision UUID --operator-id UUID --request-key KEY --reason REASON | vault status | vault rotate --vault-keys PATH --operator-id UUID --request-key KEY --reason REASON [--batch-size N]",
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

#[cfg(test)]
mod tests {
    use super::{parse_declare_lost_args, parse_restore_lock_args};
    use openmettle_core::restore::GENESIS;

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
}
