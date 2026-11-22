//! Owner-operated offline maintenance.
use openmettle_core::artifact_fs::adoption::{self, Options};
use sqlx::{Connection, PgConnection};
use std::{env, path::Path, process::ExitCode};

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
                        .map_err(|_| "volume or ledger verification failed")?;
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
                if !report.healthy() {
                    return Err("accounting drift detected");
                }
            }
            Some("activate") => {
                sqlx::query(
                    "UPDATE openmettle.quota_enforcement SET metering_enforced=true,
                    metering_enforced_at=clock_timestamp() WHERE id AND NOT metering_enforced",
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
    if command.0.as_deref() != Some("storage") || command.1.as_deref() != Some("adopt") {
        return Err(
            "usage: openmettle-admin storage adopt ROOT [--replace-adoption-run UUID] [--expected-fs-uuid UUID --expected-revisions-inode DEV:INO] [--confirm-no-on-disk-payloads]",
        );
    }
    let root = args.next().ok_or("missing artifact directory")?;
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
