//! Owner-operated offline maintenance.
use openmettle_core::{
    artifact_fs::{
        adoption::{self, Options},
        rebind,
    },
    authz::{
        gateway::family,
        store::{StoreError, WriteOutcome},
    },
    restore,
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
    required_seq: i64,
    required_digest: String,
    export_complete: bool,
    replace_restore_run: Option<String>,
    new_restore: bool,
}

fn parse_restore_lock_args(args: &[String]) -> Result<RestoreLockArgs, &'static str> {
    let usage = "usage: openmettle-admin restore lock --required-origin ORIGIN_US [--required-lifecycle-origin ORIGIN_US] --required-seq N --required-digest HEX [--export-complete] [--replace-restore-run UUID] [--new-restore]";
    let mut origin_us = None;
    let mut lifecycle_origin_us = None;
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
    let origin_us = origin_us.ok_or(usage)?;
    let required_seq = required_seq.ok_or(usage)?;
    let required_digest = required_digest.ok_or(usage)?;
    let new_restore = replace_restore_run.is_none() || new_restore_flag;
    Ok(RestoreLockArgs {
        origin_us,
        lifecycle_origin_us,
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
        }
        (Some("restore"), Some("lock")) => {
            let lock_args = parse_restore_lock_args(args)?;
            let locked = restore::lock(
                &pool(1).await?,
                lock_args.origin_us,
                lock_args.lifecycle_origin_us,
                lock_args.required_seq,
                &lock_args.required_digest,
                lock_args.export_complete,
                lock_args.replace_restore_run.as_deref(),
                lock_args.new_restore,
            )
            .await
            .map_err(failed("restore lock"))?;
            match locked.lifecycle_origin_us {
                Some(lc) => println!(
                    "restore gate closed: restore_run {}, origin {}, lifecycle_origin {}, snapshot {}, required {}, coverage_complete {}",
                    locked.restore_run_id,
                    locked.origin_us,
                    lc,
                    locked.snapshot_seq,
                    locked.required_seq,
                    locked.coverage_complete
                ),
                None => println!(
                    "restore gate closed: restore_run {}, origin {}, snapshot {}, required {}, coverage_complete {}",
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
                "usage: openmettle-admin journal export FILE | restore lock --required-origin ORIGIN_US [--required-lifecycle-origin ORIGIN_US] --required-seq N --required-digest HEX [--export-complete] [--replace-restore-run UUID] [--new-restore] | restore accept-coverage-gap --restore-run UUID --operator-id UUID --request-key KEY --reason REASON | restore replay FILE [ROOT]",
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
    if command.0.as_deref() != Some("storage")
        || (command.1.as_deref() != Some("adopt") && !rebinding)
    {
        return Err(
            "usage: openmettle-admin storage adopt ROOT [--replace-adoption-run UUID] [--expected-fs-uuid UUID --expected-revisions-inode DEV:INO] [--confirm-no-on-disk-payloads] | storage rebind ROOT [--replace-adoption-run UUID]",
        );
    }
    let root = args.next().ok_or("missing artifact directory")?;
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
