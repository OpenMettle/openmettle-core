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
};
use sqlx::{Connection, PgConnection};
use std::{env, path::Path, process::ExitCode};

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
async fn run() -> Result<(), &'static str> {
    let mut args = env::args().skip(1);
    let command = (args.next(), args.next());
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
        let url = env::var("OPENMETTLE_ADMIN_DATABASE_URL")
            .map_err(|_| "OPENMETTLE_ADMIN_DATABASE_URL is required")?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .map_err(|_| "database connection failed")?;
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
