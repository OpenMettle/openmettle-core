//! Owner-operated offline maintenance.
use openmettle_core::{
    artifact_fs::adoption::{self, Options},
    restore,
};
use sqlx::{Connection, PgConnection, PgPool};
use std::{env, fs, path::Path, process::ExitCode};

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

/// Reports a journal or restore step's failure by kind and SQLSTATE only, never record contents,
/// and returns the step's own message.
fn failed(step: &'static str) -> impl FnOnce(restore::Error) -> &'static str {
    move |e| {
        match e {
            restore::Error::Export(why) => eprintln!("{step}: invalid export: {why}"),
            restore::Error::Database(sqlx::Error::Database(d)) => {
                eprintln!("{step}: SQLSTATE {}", d.code().unwrap_or_default())
            }
            restore::Error::Drift => eprintln!("{step}: accounting drift detected"),
            restore::Error::ArtifactRootRequired => {
                eprintln!("{step}: the volume is pinned; pass its artifact root")
            }
            _ => eprintln!("{step}: database or volume failure"),
        }
        match step {
            "journal export" => "journal export failed",
            "restore lock" => "restore lock failed; the gate state is unchanged",
            _ => "restore replay failed; the restore gate was not opened",
        }
    }
}

/// ADR 0041: `journal export FILE`, `restore lock --required-seq N`, `restore replay FILE [ROOT]`.
async fn journal(
    command: (Option<String>, Option<String>),
    args: &[String],
) -> Result<(), &'static str> {
    match (command.0.as_deref(), command.1.as_deref(), args) {
        (Some("journal"), Some("export"), [file]) => {
            let text = restore::export(&pool(1).await?)
                .await
                .map_err(failed("journal export"))?;
            // Never overwrite an earlier export.
            fs::File::create_new(file)
                .and_then(|mut f| {
                    std::io::Write::write_all(&mut f, text.as_bytes()).and(f.sync_all())
                })
                .map_err(|_| "export file could not be created")?;
            println!("{}", text.lines().rev().nth(1).unwrap_or_default());
        }
        (Some("restore"), Some("lock"), [flag, n]) if flag == "--required-seq" => {
            let required = n.parse().map_err(|_| "invalid sequence")?;
            let (snapshot, required) = restore::lock(&pool(1).await?, required)
                .await
                .map_err(failed("restore lock"))?;
            println!("restore gate closed: snapshot {snapshot}, required {required}");
        }
        (Some("restore"), Some("replay"), [file, root @ ..]) if root.len() <= 1 => {
            let store = root
                .first()
                .map(|root| openmettle_core::artifact_fs::Store::open_existing(Path::new(root)))
                .transpose()
                .map_err(|_| "volume unavailable")?;
            let text = fs::read_to_string(file).map_err(|_| "export file unreadable")?;
            let export = restore::Export::parse(&text).map_err(failed("restore replay"))?;
            let pool = pool(2).await?;
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
                "usage: openmettle-admin journal export FILE | restore lock --required-seq N | restore replay FILE [ROOT]",
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
