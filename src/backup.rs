//! V1-30 maintenance-window coordinated backup capture, AEAD archive verification/unpacking,
//! GFS retention pruning, and `openmettle.backup.runs` worker telemetry observation (ADR 0046).

pub mod archive;
pub mod crypto;

use crate::{
    artifact_fs::{self, Store},
    authz::{projects::hex, store::StoreError},
    restore::{self, Export},
    runs,
    telemetry::metrics::{BackupRunOutcome, Metrics},
};
use archive::{
    ArchiveError, ArtifactArchiveSummary, BackupMeta, BundledConfigFile, GfsPolicy, PruneReport,
    SettledArtifactRecord, create_dir_0700, fsync_dir, load_non_secret_config_files,
    open_new_file_0600, prune_destination, unpack_artifact_archive, validate_destination_root,
    write_artifact_archive, write_file_0600,
};
use chrono::{DateTime, Utc};
use crypto::{BackupKeyRing, CryptoError, EncryptedStats, StreamEncryptor};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool, Postgres, Row, Transaction};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::{self, Cursor, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub const MANIFEST_FORMAT: &str = "openmettle-backup-manifest/v1";
pub const META_FORMAT: &str = "openmettle-backup-meta/v1";
pub const GATEWAY_CONSISTENCY_MODE: &str = "postgresql_authoritative_adr_0044";
pub const REBUILDABLE_INDEXES: [&str; 3] = [
    "postgresql_secondary_indexes",
    "chroma_vector_embeddings",
    "derived_search_and_fulltext_indexes",
];
pub const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 300;
pub const DEFAULT_LEASE_SECONDS: i32 = 300;
const DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(100);
const LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(60);

// --- runtime maintenance gate & worker telemetry helpers --------------------------------------

/// Whether the maintenance-window backup gate is active. Pre-45 schemas have no gate table and
/// return `false` so rolling upgrades stay live before migration 45 runs.
pub async fn maintenance_active(c: &mut PgConnection) -> Result<bool, sqlx::Error> {
    let has_table: bool =
        sqlx::query_scalar("SELECT to_regclass('openmettle.backup_maintenance_gate') IS NOT NULL")
            .fetch_one(&mut *c)
            .await?;
    if !has_table {
        return Ok(false);
    }
    sqlx::query_scalar("SELECT openmettle.backup_maintenance_is_active()")
        .fetch_one(c)
        .await
}

/// Acquire `FOR SHARE` on `openmettle.backup_maintenance_gate` inside the caller's transaction
/// via `openmettle.backup_maintenance_lock_open()`. Returns `Ok(true)` when open (or on pre-45
/// schemas), `Ok(false)` when SQLSTATE `OMM01` indicates maintenance is active.
pub async fn lock_open_maintenance(c: &mut PgConnection) -> Result<bool, sqlx::Error> {
    let has_table: bool =
        sqlx::query_scalar("SELECT to_regclass('openmettle.backup_maintenance_gate') IS NOT NULL")
            .fetch_one(&mut *c)
            .await?;
    if !has_table {
        return Ok(true);
    }
    match sqlx::query("SELECT openmettle.backup_maintenance_lock_open()")
        .execute(c)
        .await
    {
        Ok(_) => Ok(true),
        Err(sqlx::Error::Database(ref db)) if db.code().as_deref() == Some("OMM01") => Ok(false),
        Err(err) => Err(err),
    }
}

/// Enforce an open maintenance window inside a runtime write transaction, returning a database
/// error that maps cleanly to `/v1` `503 unavailable`.
pub async fn require_open_maintenance(c: &mut PgConnection) -> Result<(), StoreError> {
    if !lock_open_maintenance(c).await? {
        return Err(StoreError::Database(sqlx::Error::Protocol(
            "service is in maintenance window".into(),
        )));
    }
    Ok(())
}

/// Counts observed by one `openmettle.backup_observe_telemetry()` worker sweep.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObservedTelemetry {
    pub succeeded: u64,
    pub failed: u64,
    pub incomplete: u64,
    pub overdue: u64,
}

/// Poll `openmettle.backup_observe_telemetry()` as `openmettle_worker` and record observed
/// outcomes onto the process-global telemetry registry (`openmettle.backup.runs`).
pub async fn observe_telemetry(pool: &PgPool) -> Result<ObservedTelemetry, sqlx::Error> {
    observe_telemetry_into(pool, crate::telemetry::metrics::global()).await
}

/// Same as [`observe_telemetry`], recording into the supplied [`Metrics`] registry (for isolated
/// integration tests).
pub async fn observe_telemetry_into(
    pool: &PgPool,
    metrics: &Metrics,
) -> Result<ObservedTelemetry, sqlx::Error> {
    let mut c = pool.acquire().await?;
    let has_fn: bool = sqlx::query_scalar(
        "SELECT to_regprocedure('openmettle.backup_observe_telemetry()') IS NOT NULL",
    )
    .fetch_one(&mut *c)
    .await?;
    if !has_fn {
        return Ok(ObservedTelemetry::default());
    }
    let (s, f, i, o): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT succeeded_count, failed_count, incomplete_count, overdue_count
           FROM openmettle.backup_observe_telemetry()",
    )
    .fetch_one(&mut *c)
    .await?;
    let observed = ObservedTelemetry {
        succeeded: u64::try_from(s).unwrap_or(0),
        failed: u64::try_from(f).unwrap_or(0),
        incomplete: u64::try_from(i).unwrap_or(0),
        overdue: u64::try_from(o).unwrap_or(0),
    };
    metrics.record_backup_run(BackupRunOutcome::Succeeded, observed.succeeded);
    metrics.record_backup_run(BackupRunOutcome::Failed, observed.failed);
    metrics.record_backup_run(BackupRunOutcome::Incomplete, observed.incomplete);
    metrics.record_backup_run(BackupRunOutcome::Overdue, observed.overdue);
    Ok(observed)
}

// --- errors & shared types --------------------------------------------------------------------

/// Active in-flight work counts observed during maintenance drain polling.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainCounts {
    pub active_runs: i64,
    pub active_reservations: i64,
    pub active_purges: i64,
    pub unsettled_gateway_requests: i64,
    pub active_connection_refreshes: i64,
    pub unconfirmed_capacity_grants: i64,
}

impl DrainCounts {
    pub fn is_quiesced(self) -> bool {
        self.active_runs == 0
            && self.active_reservations == 0
            && self.active_purges == 0
            && self.unsettled_gateway_requests == 0
            && self.active_connection_refreshes == 0
            && self.unconfirmed_capacity_grants == 0
    }
}

/// Redacted backup error. Never prints database URLs, passwords, or key bytes.
#[derive(Debug)]
pub enum BackupError {
    Invalid(&'static str),
    Crypto(CryptoError),
    Archive(ArchiveError),
    Database(sqlx::Error),
    Restore(restore::Error),
    Storage(artifact_fs::Error),
    DrainTimeout(DrainCounts),
    DriftDetected,
    GateNotReady(&'static str),
    PgDump(&'static str),
    Integrity(&'static str),
    Io(io::Error),
}

impl BackupError {
    /// Closed redacted ASCII failure code stored in `openmettle.backup_runs.failure_code`.
    pub fn failure_code(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid_argument",
            Self::Crypto(_) => "crypto_error",
            Self::Archive(_) => "archive_error",
            Self::Database(_) => "database_error",
            Self::Restore(_) => "journal_export_error",
            Self::Storage(_) => "storage_error",
            Self::DrainTimeout(_) => "drain_timeout",
            Self::DriftDetected => "drift_detected",
            Self::GateNotReady(_) => "gate_not_ready",
            Self::PgDump(_) => "pg_dump_failed",
            Self::Integrity(_) => "integrity_failed",
            Self::Io(_) => "io_error",
        }
    }
}

impl fmt::Display for BackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(msg) => f.write_str(msg),
            Self::Crypto(e) => write!(f, "backup cryptography error: {e}"),
            Self::Archive(e) => write!(f, "backup archive error: {e}"),
            Self::Database(sqlx::Error::Database(d)) => {
                write!(
                    f,
                    "backup database refusal (SQLSTATE {})",
                    d.code().unwrap_or_default()
                )
            }
            Self::Database(_) => f.write_str("backup database error"),
            Self::Restore(_) => f.write_str("backup deletion-journal export error"),
            Self::Storage(_) => f.write_str("backup artifact volume error"),
            Self::DrainTimeout(c) => write!(
                f,
                "maintenance drain timeout (runs={}, reservations={}, purges={}, gateway={}, refreshes={}, capacity={})",
                c.active_runs,
                c.active_reservations,
                c.active_purges,
                c.unsettled_gateway_requests,
                c.active_connection_refreshes,
                c.unconfirmed_capacity_grants
            ),
            Self::DriftDetected => {
                f.write_str("accounting or filesystem drift detected; refusing to capture backup")
            }
            Self::GateNotReady(msg) => f.write_str(msg),
            Self::PgDump(msg) => write!(f, "pg_dump failed: {msg}"),
            Self::Integrity(msg) => write!(f, "backup integrity verification failed: {msg}"),
            Self::Io(_) => f.write_str("backup I/O error"),
        }
    }
}

impl std::error::Error for BackupError {}

impl From<CryptoError> for BackupError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}
impl From<ArchiveError> for BackupError {
    fn from(e: ArchiveError) -> Self {
        Self::Archive(e)
    }
}
impl From<sqlx::Error> for BackupError {
    fn from(e: sqlx::Error) -> Self {
        Self::Database(e)
    }
}
impl From<restore::Error> for BackupError {
    fn from(e: restore::Error) -> Self {
        Self::Restore(e)
    }
}
impl From<artifact_fs::Error> for BackupError {
    fn from(e: artifact_fs::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<io::Error> for BackupError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

// --- pluggable PgDumpRunner & real CLI runner -------------------------------------------------

/// Pluggable PostgreSQL logical dump runner so production runs real `pg_dump --format=custom`
/// while deterministic tests can inject synthetic or scripted dump runners.
pub trait PgDumpRunner: Send + Sync {
    fn dump(&self, database_url: &str, writer: &mut dyn Write) -> Result<u64, BackupError>;
}

/// Real `pg_dump` CLI runner using `--format=custom --schema=openmettle --no-owner` (preserving
/// bounded role `GRANT`/`REVOKE` ACLs on `openmettle` schema objects without touching `public`)
/// and an ephemeral `0600` `PGPASSFILE` (never exposing credentials on the command line or in
/// `PGPASSWORD`).
#[derive(Clone, Debug)]
pub struct CliPgDumpRunner {
    program: PathBuf,
}

impl Default for CliPgDumpRunner {
    fn default() -> Self {
        Self {
            program: PathBuf::from("pg_dump"),
        }
    }
}

impl CliPgDumpRunner {
    pub fn with_program(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ParsedPgUri {
    host: Option<String>,
    port: Option<u16>,
    database: Option<String>,
    username: Option<String>,
    password: Option<String>,
    sslmode: Option<String>,
}

fn percent_decode(input: &str) -> Result<String, BackupError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(BackupError::PgDump(
                    "malformed percent-encoding in database URL",
                ));
            }
            let hex_val = |b: u8| -> Result<u8, BackupError> {
                match b {
                    b'0'..=b'9' => Ok(b - b'0'),
                    b'a'..=b'f' => Ok(b - b'a' + 10),
                    b'A'..=b'F' => Ok(b - b'A' + 10),
                    _ => Err(BackupError::PgDump(
                        "malformed percent-encoding in database URL",
                    )),
                }
            };
            out.push((hex_val(bytes[i + 1])? << 4) | hex_val(bytes[i + 2])?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| BackupError::PgDump("non-UTF-8 database URL component"))
}

fn parse_pg_uri(url: &str) -> Result<ParsedPgUri, BackupError> {
    let rest = url
        .strip_prefix("postgresql://")
        .or_else(|| url.strip_prefix("postgres://"))
        .ok_or(BackupError::PgDump("invalid PostgreSQL URL scheme"))?;
    let (before_query, query) = match rest.split_once('?') {
        Some((a, b)) => (a, Some(b)),
        None => (rest, None),
    };
    let (authority, path) = match before_query.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (before_query, None),
    };
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };

    let mut out = ParsedPgUri::default();
    if let Some(u) = userinfo {
        match u.split_once(':') {
            Some((user, pass)) => {
                if !user.is_empty() {
                    out.username = Some(percent_decode(user)?);
                }
                out.password = Some(percent_decode(pass)?);
            }
            None => {
                if !u.is_empty() {
                    out.username = Some(percent_decode(u)?);
                }
            }
        }
    }

    if !hostport.is_empty() {
        if let Some(after_open) = hostport.strip_prefix('[') {
            let (host, tail) = after_open
                .split_once(']')
                .ok_or(BackupError::PgDump("unclosed IPv6 host in database URL"))?;
            if !host.is_empty() {
                out.host = Some(host.to_owned());
            }
            if let Some(port_str) = tail.strip_prefix(':') {
                out.port = Some(
                    port_str
                        .parse()
                        .map_err(|_| BackupError::PgDump("invalid port in database URL"))?,
                );
            }
        } else if let Some((host, port_str)) = hostport.rsplit_once(':') {
            if !host.is_empty() {
                out.host = Some(percent_decode(host)?);
            }
            if !port_str.is_empty() {
                out.port = Some(
                    port_str
                        .parse()
                        .map_err(|_| BackupError::PgDump("invalid port in database URL"))?,
                );
            }
        } else {
            out.host = Some(percent_decode(hostport)?);
        }
    }

    if let Some(p) = path
        && !p.is_empty()
    {
        out.database = Some(percent_decode(p)?);
    }

    if let Some(q) = query {
        for pair in q.split('&').filter(|s| !s.is_empty()) {
            let Some((k, v)) = pair.split_once('=') else {
                continue;
            };
            let v = percent_decode(v)?;
            match k {
                "host" if !v.is_empty() => out.host = Some(v),
                "port" if !v.is_empty() => {
                    out.port = Some(
                        v.parse()
                            .map_err(|_| BackupError::PgDump("invalid query port"))?,
                    );
                }
                "dbname" if !v.is_empty() => out.database = Some(v),
                "user" if !v.is_empty() => out.username = Some(v),
                "password" => out.password = Some(v),
                "sslmode" if !v.is_empty() => out.sslmode = Some(v),
                _ => {}
            }
        }
    }

    Ok(out)
}

fn escape_pgpass(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    for ch in field.chars() {
        if matches!(ch, '\\' | ':') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

struct EphemeralPgPass {
    dir: PathBuf,
    file: PathBuf,
}

impl EphemeralPgPass {
    fn create(parsed: &ParsedPgUri) -> Result<Self, BackupError> {
        let mut rnd = [0u8; 16];
        SystemRandom::new()
            .fill(&mut rnd)
            .map_err(|_| BackupError::Crypto(CryptoError::Random))?;
        let dir = std::env::temp_dir().join(format!("om-pgpass-{}", hex(&rnd)));
        create_dir_0700(&dir)?;
        let file = dir.join("pgpass");
        let host = parsed
            .host
            .as_deref()
            .map_or_else(|| "*".to_owned(), escape_pgpass);
        let port = parsed
            .port
            .map_or_else(|| "*".to_owned(), |p| p.to_string());
        let db = parsed
            .database
            .as_deref()
            .map_or_else(|| "*".to_owned(), escape_pgpass);
        let user = parsed
            .username
            .as_deref()
            .map_or_else(|| "*".to_owned(), escape_pgpass);
        let pass = parsed
            .password
            .as_deref()
            .map_or_else(String::new, escape_pgpass);
        let line = format!("{host}:{port}:{db}:{user}:{pass}\n");
        if let Err(err) = write_file_0600(&file, line.as_bytes()) {
            let _ = fs::remove_dir_all(&dir);
            return Err(err.into());
        }
        Ok(Self { dir, file })
    }
}

impl Drop for EphemeralPgPass {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.file);
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl PgDumpRunner for CliPgDumpRunner {
    fn dump(&self, database_url: &str, writer: &mut dyn Write) -> Result<u64, BackupError> {
        let parsed = parse_pg_uri(database_url)?;
        let pgpass = if parsed.password.is_some() {
            Some(EphemeralPgPass::create(&parsed)?)
        } else {
            None
        };

        let mut cmd = Command::new(&self.program);
        cmd.args(["--format=custom", "--schema=openmettle", "--no-owner"]);
        if let Some(host) = &parsed.host {
            cmd.arg("--host").arg(host);
        }
        if let Some(port) = parsed.port {
            cmd.arg("--port").arg(port.to_string());
        }
        if let Some(user) = &parsed.username {
            cmd.arg("--username").arg(user);
        }
        if let Some(db) = &parsed.database {
            cmd.arg("--dbname").arg(db);
        }
        cmd.env_remove("PGPASSWORD");
        if let Some(pass) = &pgpass {
            cmd.env("PGPASSFILE", &pass.file);
        }
        if let Some(sslmode) = &parsed.sslmode {
            cmd.env("PGSSLMODE", sslmode);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|_| BackupError::PgDump("failed to spawn pg_dump"))?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or(BackupError::PgDump("pg_dump stdout unavailable"))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or(BackupError::PgDump("pg_dump stderr unavailable"))?;

        // Drain stderr on a helper thread so a noisy stderr cannot deadlock stdout streaming.
        let stderr_handle = std::thread::spawn(move || {
            let mut sink = Vec::new();
            let _ = stderr.by_ref().take(4096).read_to_end(&mut sink);
            let _ = io::copy(&mut stderr, &mut io::sink());
        });

        let mut buf = vec![0u8; crypto::CHUNK_SIZE];
        let mut total: u64 = 0;
        let copy_result: Result<(), BackupError> = loop {
            match stdout.read(&mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    if let Err(e) = writer.write_all(&buf[..n]) {
                        break Err(e.into());
                    }
                    total = match total.checked_add(n as u64) {
                        Some(v) => v,
                        None => break Err(BackupError::PgDump("dump size overflow")),
                    };
                }
                Err(e) => break Err(e.into()),
            }
        };

        let status = child.wait();
        let _ = stderr_handle.join();
        drop(pgpass);

        copy_result?;
        let status = status.map_err(|_| BackupError::PgDump("failed waiting for pg_dump"))?;
        if !status.success() {
            return Err(BackupError::PgDump("pg_dump exited with non-zero status"));
        }
        if total == 0 {
            return Err(BackupError::PgDump("pg_dump produced empty output"));
        }
        Ok(total)
    }
}

// --- Graphiti / Neo4j & manifest structures ---------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraphitiMode {
    NotProvisioned,
    OfflineDump(PathBuf),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComponentManifest {
    pub role: String,
    pub plaintext_bytes: u64,
    pub plaintext_sha256: String,
    pub ciphertext_bytes: u64,
    pub ciphertext_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct JournalWatermarkManifest {
    pub origin_us: i64,
    pub journal_seq: i64,
    pub chain_digest: String,
    pub lifecycle_origin_us: Option<i64>,
    pub lifecycle_baseline_digest: Option<String>,
    pub connection_origin_us: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactVolumeManifest {
    pub volume_id: Option<String>,
    pub revision_count: u64,
    pub payload_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GraphitiManifest {
    NotProvisioned,
    OfflineDump {
        component: String,
        plaintext_bytes: u64,
        plaintext_sha256: String,
    },
}

/// Decrypted authoritative backup manifest (`manifest.json.enc`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupManifest {
    pub format: String,
    pub backup_run_id: String,
    pub quiesced_at: String,
    pub completed_at: String,
    pub schema_version: i64,
    pub crate_version: String,
    pub destination_domain: String,
    pub rpo_target_seconds: i32,
    pub encryption_key_id: String,
    pub bundle_digest: String,
    pub components: BTreeMap<String, ComponentManifest>,
    pub deletion_journal: JournalWatermarkManifest,
    pub artifact_volume: ArtifactVolumeManifest,
    pub vault_required_key_ids: Vec<String>,
    pub gateway_consistency_mode: String,
    pub graphiti_neo4j: GraphitiManifest,
    pub rebuildable_indexes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ConfigBundle {
    format: String,
    vault_required_key_ids: Vec<String>,
    files: Vec<BundledConfigFile>,
}

// --- owner DB coordination helpers ------------------------------------------------------------

async fn read_committed(pool: &PgPool) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BackupStatus {
    pub maintenance_active: bool,
    pub active_backup_run_id: Option<String>,
    pub entered_at: Option<String>,
    pub quiesced_at: Option<String>,
    pub reason: Option<String>,
    pub rpo_target_seconds: i32,
    pub rpo_tracking_armed_at: Option<String>,
    pub last_overdue_observed_at: Option<String>,
    pub last_succeeded_run_id: Option<String>,
    pub last_succeeded_at: Option<String>,
    pub latest_run_id: Option<String>,
    pub latest_run_state: Option<String>,
    pub latest_run_failure_code: Option<String>,
    pub latest_run_completed_at: Option<String>,
}

pub async fn status(pool: &PgPool) -> Result<BackupStatus, BackupError> {
    let row = sqlx::query(
        "SELECT maintenance_active,
                backup_run_id::text,
                to_char(entered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                to_char(quiesced_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                reason,
                rpo_target_seconds,
                to_char(rpo_tracking_armed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                to_char(last_overdue_observed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
           FROM openmettle.backup_maintenance_gate
          WHERE id",
    )
    .fetch_one(pool)
    .await?;

    let last_succeeded: Option<(String, String)> = sqlx::query_as(
        "SELECT id::text,
                to_char(completed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
           FROM openmettle.backup_runs
          WHERE state = 'succeeded'
          ORDER BY completed_at DESC, id DESC
          LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;

    let latest: Option<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT id::text,
                state,
                failure_code,
                to_char(completed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
           FROM openmettle.backup_runs
          ORDER BY started_at DESC, id DESC
          LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;

    Ok(BackupStatus {
        maintenance_active: row.try_get(0)?,
        active_backup_run_id: row.try_get(1)?,
        entered_at: row.try_get(2)?,
        quiesced_at: row.try_get(3)?,
        reason: row.try_get(4)?,
        rpo_target_seconds: row.try_get(5)?,
        rpo_tracking_armed_at: row.try_get(6)?,
        last_overdue_observed_at: row.try_get(7)?,
        last_succeeded_run_id: last_succeeded.as_ref().map(|(id, _)| id.clone()),
        last_succeeded_at: last_succeeded.map(|(_, at)| at),
        latest_run_id: latest.as_ref().map(|r| r.0.clone()),
        latest_run_state: latest.as_ref().map(|r| r.1.clone()),
        latest_run_failure_code: latest.as_ref().and_then(|r| r.2.clone()),
        latest_run_completed_at: latest.and_then(|r| r.3),
    })
}

pub async fn enter_maintenance(
    pool: &PgPool,
    operator_id: &str,
    request_key: &str,
    reason: &str,
) -> Result<(bool, Option<String>), BackupError> {
    runs::uuid(operator_id).map_err(|_| BackupError::Invalid("invalid --operator-id UUID"))?;
    let mut tx = read_committed(pool).await?;
    let (entered, entered_at): (bool, Option<String>) = sqlx::query_as(
        "SELECT entered,
                to_char(entered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
           FROM openmettle.backup_enter_maintenance($1::uuid, $2, $3)",
    )
    .bind(operator_id)
    .bind(request_key)
    .bind(reason)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((entered, entered_at))
}

pub async fn release_maintenance(
    pool: &PgPool,
    operator_id: &str,
    request_key: &str,
    reason: &str,
    abort_active_run: bool,
) -> Result<(bool, Option<String>), BackupError> {
    runs::uuid(operator_id).map_err(|_| BackupError::Invalid("invalid --operator-id UUID"))?;
    let mut tx = read_committed(pool).await?;
    let (released, aborted_run_id): (bool, Option<String>) = sqlx::query_as(
        "SELECT released, aborted_run_id::text
           FROM openmettle.backup_release_maintenance($1::uuid, $2, $3, $4)",
    )
    .bind(operator_id)
    .bind(request_key)
    .bind(reason)
    .bind(abort_active_run)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((released, aborted_run_id))
}

pub async fn arm_rpo(
    pool: &PgPool,
    operator_id: &str,
    request_key: &str,
    reason: &str,
    rpo_seconds: i32,
) -> Result<(i32, String), BackupError> {
    runs::uuid(operator_id).map_err(|_| BackupError::Invalid("invalid --operator-id UUID"))?;
    if !(3600..=604_800).contains(&rpo_seconds) {
        return Err(BackupError::Invalid(
            "--rpo-seconds must be between 3600 and 604800",
        ));
    }
    let mut tx = read_committed(pool).await?;
    let (target, armed_at): (i32, String) = sqlx::query_as(
        "SELECT rpo_target_seconds,
                to_char(rpo_tracking_armed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
           FROM openmettle.backup_arm_rpo($1::uuid, $2, $3, $4)",
    )
    .bind(operator_id)
    .bind(request_key)
    .bind(reason)
    .bind(rpo_seconds)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((target, armed_at))
}

async fn start_capture(
    pool: &PgPool,
    operator_id: &str,
    request_key: &str,
    reason: &str,
    destination_domain: &str,
    lease_seconds: i32,
) -> Result<(String, i32), BackupError> {
    let mut tx = read_committed(pool).await?;
    let (run_id, rpo_target_seconds): (String, i32) = sqlx::query_as(
        "SELECT backup_run_id::text, rpo_target_seconds
           FROM openmettle.backup_start_capture($1::uuid, $2, $3, $4, $5)",
    )
    .bind(operator_id)
    .bind(request_key)
    .bind(reason)
    .bind(destination_domain)
    .bind(lease_seconds)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((run_id, rpo_target_seconds))
}

async fn renew_lease(pool: &PgPool, run_id: &str, lease_seconds: i32) -> Result<(), BackupError> {
    let mut tx = read_committed(pool).await?;
    sqlx::query("SELECT openmettle.backup_renew_lease($1::uuid, $2)")
        .bind(run_id)
        .bind(lease_seconds)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

async fn mark_quiesced(
    pool: &PgPool,
    run_id: &str,
    lease_seconds: i32,
) -> Result<String, BackupError> {
    let mut tx = read_committed(pool).await?;
    let quiesced_at: String = sqlx::query_scalar(
        "SELECT to_char(quiesced_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
           FROM openmettle.backup_mark_quiesced($1::uuid, $2)",
    )
    .bind(run_id)
    .bind(lease_seconds)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(quiesced_at)
}

async fn fail_capture(pool: &PgPool, run_id: &str, failure_code: &str, reason: &str) {
    if let Ok(mut tx) = read_committed(pool).await {
        let res = sqlx::query("SELECT openmettle.backup_fail_capture($1::uuid, $2, $3)")
            .bind(run_id)
            .bind(failure_code)
            .bind(reason)
            .execute(&mut *tx)
            .await;
        if res.is_ok() {
            let _ = tx.commit().await;
        }
    }
}

pub async fn poll_drain_counts(pool: &PgPool) -> Result<DrainCounts, BackupError> {
    let row = sqlx::query(
        "SELECT
           (SELECT count(*) FROM openmettle.runs
             WHERE state IN ('running', 'cancelling', 'reconciling')
                OR (lease_expires_at IS NOT NULL AND lease_expires_at > clock_timestamp())),
           (SELECT count(*) FROM openmettle.storage_reservations
             WHERE state = 'reserved' OR reclaim_state <> 'none'),
           (SELECT count(*) FROM openmettle.artifact_revisions
             WHERE state = 'purging' OR purge_stage <> 'none'),
           (SELECT count(*) FROM openmettle.gateway_requests
             WHERE NOT settled_final),
           (SELECT count(*) FROM openmettle.external_connections
             WHERE refresh_lease_until IS NOT NULL AND refresh_lease_until > clock_timestamp()),
           (SELECT count(*) FROM openmettle.capacity_grants
             WHERE dispatch_state <> 'confirmed')",
    )
    .fetch_one(pool)
    .await?;
    Ok(DrainCounts {
        active_runs: row.try_get(0)?,
        active_reservations: row.try_get(1)?,
        active_purges: row.try_get(2)?,
        unsettled_gateway_requests: row.try_get(3)?,
        active_connection_refreshes: row.try_get(4)?,
        unconfirmed_capacity_grants: row.try_get(5)?,
    })
}

async fn export_gateway_entitlements_json(pool: &PgPool) -> Result<Vec<u8>, BackupError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *tx)
        .await?;

    let defaults: Vec<String> = sqlx::query_scalar(
        "SELECT to_jsonb(d)::text FROM openmettle.quota_defaults d
          ORDER BY d.scope_kind, d.resource_kind",
    )
    .fetch_all(&mut *tx)
    .await?;
    let overrides: Vec<String> = sqlx::query_scalar(
        "SELECT to_jsonb(o)::text FROM openmettle.quota_overrides o
          WHERE o.revoked_at IS NULL
          ORDER BY o.scope_id, o.resource_kind",
    )
    .fetch_all(&mut *tx)
    .await?;
    let budgets: Vec<String> = sqlx::query_scalar(
        "SELECT to_jsonb(b)::text FROM openmettle.quota_budgets b
          ORDER BY b.target_kind, b.scope_id NULLS FIRST, b.resource_kind, b.window_kind, b.window_start",
    )
    .fetch_all(&mut *tx)
    .await?;
    let family_policies: Vec<String> = sqlx::query_scalar(
        "SELECT to_jsonb(p)::text FROM openmettle.family_policies p ORDER BY p.id",
    )
    .fetch_all(&mut *tx)
    .await?;
    let family_models: Vec<String> = sqlx::query_scalar(
        "SELECT to_jsonb(m)::text FROM openmettle.family_policy_models m
          ORDER BY m.policy_id, m.rule_kind, m.model",
    )
    .fetch_all(&mut *tx)
    .await?;
    let gw_summary = sqlx::query(
        "SELECT
           (SELECT count(*) FROM openmettle.gateway_requests WHERE settled_final),
           (SELECT count(*) FROM openmettle.gateway_requests WHERE NOT settled_final),
           (SELECT coalesce(sum(measured), 0)::text FROM openmettle.gateway_settlements WHERE final),
           (SELECT coalesce(sum(prompt_tokens), 0)::text FROM openmettle.gateway_usage_reports WHERE final),
           (SELECT coalesce(sum(completion_tokens), 0)::text FROM openmettle.gateway_usage_reports WHERE final),
           (SELECT coalesce(sum(reasoning_tokens), 0)::text FROM openmettle.gateway_usage_reports WHERE final)",
    )
    .fetch_one(&mut *tx)
    .await?;
    let settled_requests: i64 = gw_summary.try_get(0)?;
    let unsettled_requests: i64 = gw_summary.try_get(1)?;
    let total_measured_units: String = gw_summary.try_get(2)?;
    let total_prompt_tokens: String = gw_summary.try_get(3)?;
    let total_completion_tokens: String = gw_summary.try_get(4)?;
    let total_reasoning_tokens: String = gw_summary.try_get(5)?;
    tx.commit().await?;

    let parse_vec = |items: Vec<String>| -> Result<Vec<Value>, BackupError> {
        items
            .into_iter()
            .map(|s| {
                serde_json::from_str(&s).map_err(|_| BackupError::Integrity("invalid JSON row"))
            })
            .collect()
    };

    let doc = json!({
        "format": "openmettle-gateway-entitlements/v1",
        "consistency_mode": GATEWAY_CONSISTENCY_MODE,
        "quota_defaults": parse_vec(defaults)?,
        "quota_overrides": parse_vec(overrides)?,
        "quota_budgets": parse_vec(budgets)?,
        "family_policies": parse_vec(family_policies)?,
        "family_policy_models": parse_vec(family_models)?,
        "gateway_usage_summary": {
            "settled_requests": settled_requests,
            "unsettled_requests": unsettled_requests,
            "total_measured_units": total_measured_units,
            "total_prompt_tokens": total_prompt_tokens,
            "total_completion_tokens": total_completion_tokens,
            "total_reasoning_tokens": total_reasoning_tokens,
        }
    });
    serde_json::to_vec_pretty(&doc)
        .map_err(|_| BackupError::Integrity("gateway JSON encode failed"))
}

async fn load_vault_required_key_ids(pool: &PgPool) -> Result<Vec<String>, BackupError> {
    let conn_keys: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT encryption_key_id
           FROM openmettle.external_connections
          WHERE encryption_key_id IS NOT NULL
          ORDER BY encryption_key_id",
    )
    .fetch_all(pool)
    .await?;
    let mac_keys: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT details->>'mac_key_id'
           FROM openmettle.authorization_audit
          WHERE action = 'connection.authorized'
            AND details ? 'mac_key_id'
            AND details->>'mac_key_id' IS NOT NULL
          ORDER BY 1",
    )
    .fetch_all(pool)
    .await?;
    let mut set = BTreeSet::new();
    for k in conn_keys.into_iter().chain(mac_keys) {
        if !k.is_empty() {
            set.insert(k);
        }
    }
    Ok(set.into_iter().collect())
}

async fn load_settled_artifact_records(
    pool: &PgPool,
) -> Result<(Option<String>, Vec<SettledArtifactRecord>), BackupError> {
    let (volume_id, adoption_run_id): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT volume_id::text, adoption_run_id::text
           FROM openmettle.storage_volume_control
          WHERE id",
    )
    .fetch_one(pool)
    .await?;
    if adoption_run_id.is_some() {
        return Err(BackupError::GateNotReady(
            "storage adoption or rebind barrier is active",
        ));
    }

    let rows = sqlx::query(
        "SELECT r.id::text, r.reservation_id::text, r.state, r.size_bytes,
                r.content_digest, s.payload_ino::text
           FROM openmettle.artifact_revisions r
           JOIN openmettle.storage_reservations s
             ON s.scope_id = r.scope_id AND s.id = r.reservation_id
          WHERE r.state IN ('active', 'retained', 'purging')
          ORDER BY r.reservation_id",
    )
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let digest_bytes: Vec<u8> = row.try_get(4)?;
        let content_digest: [u8; 32] = digest_bytes
            .try_into()
            .map_err(|_| BackupError::Integrity("artifact revision digest is not 32 bytes"))?;
        let ino_str: Option<String> = row.try_get(5)?;
        let payload_ino = ino_str
            .map(|s| s.parse::<u64>())
            .transpose()
            .map_err(|_| BackupError::Integrity("invalid payload_ino in storage_reservations"))?;
        out.push(SettledArtifactRecord {
            revision_id: row.try_get(0)?,
            reservation_id: row.try_get(1)?,
            state: row.try_get(2)?,
            size_bytes: row.try_get(3)?,
            content_digest,
            payload_ino,
        });
    }
    Ok((volume_id, out))
}

fn compute_bundle_digest(
    components: &BTreeMap<String, ComponentManifest>,
    manifest_ct_sha256: &str,
) -> [u8; 32] {
    let mut parts: Vec<&[u8]> = Vec::with_capacity(components.len() * 2 + 1);
    for (file_name, comp) in components {
        parts.push(file_name.as_bytes());
        parts.push(comp.ciphertext_sha256.as_bytes());
    }
    parts.push(manifest_ct_sha256.as_bytes());
    Sha256::digest(runs::identity(b"openmettle.backup.bundle/1\0", &parts)).into()
}

fn component_manifest(role: &str, stats: &EncryptedStats) -> ComponentManifest {
    ComponentManifest {
        role: role.to_owned(),
        plaintext_bytes: stats.plaintext_bytes,
        plaintext_sha256: hex(&stats.plaintext_sha256),
        ciphertext_bytes: stats.ciphertext_bytes,
        ciphertext_sha256: hex(&stats.ciphertext_sha256),
    }
}

fn encrypt_bytes_to_file(
    keyring: &BackupKeyRing,
    run_id: &str,
    role: &str,
    plaintext: &[u8],
    dest_path: &Path,
) -> Result<EncryptedStats, BackupError> {
    let mut file = open_new_file_0600(dest_path)?;
    let stats = keyring.encrypt_stream(run_id, role, &mut Cursor::new(plaintext), &mut file)?;
    file.sync_all()?;
    Ok(stats)
}

fn decode_hex_32(s: &str) -> Result<[u8; 32], BackupError> {
    if !restore::is_valid_digest(s) {
        return Err(BackupError::Integrity("invalid 32-byte hex digest"));
    }
    let nibble = |b: u8| match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => unreachable!(),
    };
    let mut out = [0u8; 32];
    for (idx, chunk) in s.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[idx] = (nibble(chunk[0]) << 4) | nibble(chunk[1]);
    }
    Ok(out)
}

// --- coordinated backup capture pipeline ------------------------------------------------------

/// Options for [`capture_with_runner`].
pub struct CaptureOptions {
    pub database_url: String,
    pub destination_root: PathBuf,
    pub destination_domain: String,
    pub artifact_root: Option<PathBuf>,
    pub operator_id: String,
    pub request_key: String,
    pub reason: String,
    pub drain_timeout: Duration,
    pub lease_seconds: i32,
    pub require_separate_device: bool,
    pub graphiti_mode: GraphitiMode,
    pub config_files: Vec<(String, PathBuf)>,
    pub prune_policy: Option<GfsPolicy>,
    pub release_on_success: bool,
    /// Must stay `false` in `openmettle-admin`. Set `true` only in isolated integration tests
    /// running inside temporary directories.
    pub allow_local_test_paths: bool,
}

#[derive(Clone, Debug)]
pub struct CaptureReport {
    pub backup_run_id: String,
    pub backup_dir: PathBuf,
    pub encryption_key_id: String,
    pub bundle_digest: String,
    pub manifest_digest: String,
    pub journal_seq: i64,
    pub pruned: Option<PruneReport>,
    pub released_maintenance: bool,
}

fn validate_destination_domain(domain: &str) -> Result<(), BackupError> {
    if domain.is_empty()
        || domain.len() > 128
        || domain.trim() != domain
        || !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'))
    {
        return Err(BackupError::Invalid("invalid --destination-domain"));
    }
    Ok(())
}

/// Run the full coordinated maintenance-window backup capture using the default real `pg_dump`
/// CLI runner (`CliPgDumpRunner`).
pub async fn capture(
    pool: &PgPool,
    keyring: &BackupKeyRing,
    opts: &CaptureOptions,
) -> Result<CaptureReport, BackupError> {
    capture_with_runner(pool, keyring, opts, &CliPgDumpRunner::default()).await
}

/// Run the full coordinated maintenance-window backup capture with a pluggable [`PgDumpRunner`].
/// On any failure after entering maintenance, partial staging files are removed, `backup_runs`
/// transitions to `failed`, and `backup_maintenance_gate.maintenance_active` stays `true` for
/// explicit operator recovery.
pub async fn capture_with_runner(
    pool: &PgPool,
    keyring: &BackupKeyRing,
    opts: &CaptureOptions,
    pg_dump: &dyn PgDumpRunner,
) -> Result<CaptureReport, BackupError> {
    // 1. Validate arguments, destination isolation, non-secret configs, and Neo4j dump before
    //    touching the database maintenance window.
    runs::uuid(&opts.operator_id)
        .map_err(|_| BackupError::Invalid("invalid --operator-id UUID"))?;
    validate_destination_domain(&opts.destination_domain)?;
    if !(30..=3600).contains(&opts.lease_seconds) {
        return Err(BackupError::Invalid(
            "lease seconds must be between 30 and 3600",
        ));
    }
    if let Some(policy) = opts.prune_policy {
        policy.validate()?;
    }
    let dest_root = validate_destination_root(
        &opts.destination_root,
        opts.artifact_root.as_deref(),
        keyring.paths(),
        opts.require_separate_device,
        opts.allow_local_test_paths,
    )?;
    let bundled_configs = load_non_secret_config_files(&opts.config_files, keyring.paths())?;
    if let GraphitiMode::OfflineDump(ref neo4j_path) = opts.graphiti_mode {
        if !neo4j_path.is_absolute() {
            return Err(BackupError::Invalid("--neo4j-dump path must be absolute"));
        }
        let meta = fs::metadata(neo4j_path)
            .map_err(|_| BackupError::Invalid("--neo4j-dump file unreadable"))?;
        if !meta.is_file() || meta.len() == 0 {
            return Err(BackupError::Invalid(
                "--neo4j-dump must be a non-empty regular file",
            ));
        }
    }

    // 2. Enter maintenance and allocate a leased `draining` backup_runs row.
    let (run_id, rpo_target_seconds) = start_capture(
        pool,
        &opts.operator_id,
        &opts.request_key,
        &opts.reason,
        &opts.destination_domain,
        opts.lease_seconds,
    )
    .await?;

    let staging_dir = dest_root.join(format!(".staging.{run_id}"));
    let outcome = capture_body(
        pool,
        keyring,
        opts,
        pg_dump,
        &dest_root,
        &staging_dir,
        &run_id,
        rpo_target_seconds,
        bundled_configs,
    )
    .await;

    match outcome {
        Ok(report) => {
            crate::telemetry::metrics::global().record_backup_run(BackupRunOutcome::Succeeded, 1);
            Ok(report)
        }
        Err(err) => {
            let _ = fs::remove_dir_all(&staging_dir);
            let fail_reason = format!("backup capture failed ({})", err.failure_code());
            fail_capture(pool, &run_id, err.failure_code(), &fail_reason).await;
            crate::telemetry::metrics::global().record_backup_run(BackupRunOutcome::Failed, 1);
            Err(err)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn capture_body(
    pool: &PgPool,
    keyring: &BackupKeyRing,
    opts: &CaptureOptions,
    pg_dump: &dyn PgDumpRunner,
    dest_root: &Path,
    staging_dir: &Path,
    run_id: &str,
    rpo_target_seconds: i32,
    bundled_configs: Vec<BundledConfigFile>,
) -> Result<CaptureReport, BackupError> {
    // 3. Poll drain loop until all active in-flight work settles or drain_timeout expires.
    let deadline = Instant::now() + opts.drain_timeout;
    let mut last_renew = Instant::now();
    loop {
        let counts = poll_drain_counts(pool).await?;
        if counts.is_quiesced() {
            break;
        }
        if Instant::now() >= deadline {
            return Err(BackupError::DrainTimeout(counts));
        }
        if last_renew.elapsed() >= LEASE_RENEW_INTERVAL {
            renew_lease(pool, run_id, opts.lease_seconds).await?;
            last_renew = Instant::now();
        }
        tokio::time::sleep(DRAIN_POLL_INTERVAL).await;
    }

    // 4. Verify restore_reconciliation_gate is open, no adoption barrier, and accounting drift
    //    is healthy before marking quiesced.
    {
        let mut conn = pool.acquire().await?;
        if !restore::gate_open(&mut conn).await? {
            return Err(BackupError::GateNotReady(
                "restore_reconciliation_gate is closed",
            ));
        }
    }
    let (pinned_volume_id, settled_records) = load_settled_artifact_records(pool).await?;
    if pinned_volume_id.is_some() && opts.artifact_root.is_none() {
        return Err(BackupError::Invalid(
            "--artifact-root is required when the artifact storage volume is pinned",
        ));
    }
    let store = opts
        .artifact_root
        .as_deref()
        .map(Store::open_existing)
        .transpose()
        .map_err(|_| BackupError::Invalid("--artifact-root could not be opened"))?;
    let drift = artifact_fs::verify_accounting_drift(pool, store.as_ref()).await?;
    if !drift.healthy() {
        return Err(BackupError::DriftDetected);
    }

    let quiesced_at = mark_quiesced(pool, run_id, opts.lease_seconds).await?;

    // 5. Capture and stream-encrypt all recovery-set components into staging directory.
    create_dir_0700(staging_dir)?;
    let mut components: BTreeMap<String, ComponentManifest> = BTreeMap::new();

    // 5a. PostgreSQL logical custom dump (`pg.dump.enc`).
    let pg_dump_path = staging_dir.join("pg.dump.enc");
    let pg_stats = {
        let mut out_file = open_new_file_0600(&pg_dump_path)?;
        let mut enc = StreamEncryptor::start(keyring, run_id, "pg_dump", &mut out_file)?;
        pg_dump.dump(&opts.database_url, &mut enc)?;
        let stats = enc.finish()?;
        out_file.sync_all()?;
        stats
    };
    components.insert(
        "pg.dump.enc".to_owned(),
        component_manifest("pg_dump", &pg_stats),
    );
    renew_lease(pool, run_id, opts.lease_seconds).await?;

    // 5b. Authoritative PostgreSQL gateway entitlements & usage snapshot (`gateway-entitlements.json.enc`).
    let gw_bytes = export_gateway_entitlements_json(pool).await?;
    let gw_stats = encrypt_bytes_to_file(
        keyring,
        run_id,
        "gateway_entitlements",
        &gw_bytes,
        &staging_dir.join("gateway-entitlements.json.enc"),
    )?;
    components.insert(
        "gateway-entitlements.json.enc".to_owned(),
        component_manifest("gateway_entitlements", &gw_stats),
    );

    // 5c. Deletion journal export (`deletion-journal.bin.enc`).
    let journal_text = restore::export(pool).await?;
    let parsed_export = Export::parse(&journal_text)?;
    let journal_stats = encrypt_bytes_to_file(
        keyring,
        run_id,
        "deletion_journal",
        journal_text.as_bytes(),
        &staging_dir.join("deletion-journal.bin.enc"),
    )?;
    components.insert(
        "deletion-journal.bin.enc".to_owned(),
        component_manifest("deletion_journal", &journal_stats),
    );

    // 5d. Generic PVC POSIX artifact archive (`artifacts.bin.enc`), live SHA-256 verified.
    let artifacts_path = staging_dir.join("artifacts.bin.enc");
    let (artifact_summary, artifact_stats) = {
        let mut out_file = open_new_file_0600(&artifacts_path)?;
        let mut enc = StreamEncryptor::start(keyring, run_id, "artifacts", &mut out_file)?;
        let summary = write_artifact_archive(
            opts.artifact_root.as_deref(),
            pinned_volume_id.as_deref(),
            &settled_records,
            &mut enc,
        )?;
        let stats = enc.finish()?;
        out_file.sync_all()?;
        (summary, stats)
    };
    components.insert(
        "artifacts.bin.enc".to_owned(),
        component_manifest("artifacts", &artifact_stats),
    );
    renew_lease(pool, run_id, opts.lease_seconds).await?;

    // 5e. Optional Graphiti / Neo4j offline dump (`neo4j.dump.enc`).
    let graphiti_manifest = match &opts.graphiti_mode {
        GraphitiMode::NotProvisioned => GraphitiManifest::NotProvisioned,
        GraphitiMode::OfflineDump(neo4j_path) => {
            let mut src = fs::File::open(neo4j_path)?;
            let mut out = open_new_file_0600(&staging_dir.join("neo4j.dump.enc"))?;
            let stats = keyring.encrypt_stream(run_id, "neo4j_dump", &mut src, &mut out)?;
            out.sync_all()?;
            let comp = component_manifest("neo4j_dump", &stats);
            let gm = GraphitiManifest::OfflineDump {
                component: "neo4j.dump.enc".to_owned(),
                plaintext_bytes: comp.plaintext_bytes,
                plaintext_sha256: comp.plaintext_sha256.clone(),
            };
            components.insert("neo4j.dump.enc".to_owned(), comp);
            gm
        }
    };

    // 5f. Non-secret config files + required vault key-ID inventory (`config.json.enc`).
    let vault_required_key_ids = load_vault_required_key_ids(pool).await?;
    let config_bundle = ConfigBundle {
        format: "openmettle-backup-config/v1".to_owned(),
        vault_required_key_ids: vault_required_key_ids.clone(),
        files: bundled_configs,
    };
    let config_bytes = serde_json::to_vec_pretty(&config_bundle)
        .map_err(|_| BackupError::Integrity("config bundle serialization failed"))?;
    let config_stats = encrypt_bytes_to_file(
        keyring,
        run_id,
        "config",
        &config_bytes,
        &staging_dir.join("config.json.enc"),
    )?;
    components.insert(
        "config.json.enc".to_owned(),
        component_manifest("config", &config_stats),
    );

    // 5g. Build and encrypt manifest (`manifest.json.enc`), then write unencrypted non-secret
    //     routing header (`backup-meta.json`).
    let schema_version: i64 = sqlx::query_scalar(
        "SELECT coalesce(max(version), 0) FROM openmettle._sqlx_migrations WHERE success",
    )
    .fetch_one(pool)
    .await?;
    let completed_at_str: String = sqlx::query_scalar(
        "SELECT to_char(greatest(clock_timestamp(), $1::timestamptz) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')",
    )
    .bind(&quiesced_at)
    .fetch_one(pool)
    .await?;
    let completed_dt: DateTime<Utc> = DateTime::parse_from_rfc3339(&completed_at_str)
        .map_err(|_| BackupError::Integrity("invalid completed_at timestamp"))?
        .with_timezone(&Utc);

    // Placeholder bundle_digest is replaced with the deterministic commitment over all
    // component ciphertext digests (manifest ciphertext digest is stored in backup-meta.json and
    // committed into backup_runs.bundle_digest).
    let pre_manifest_bundle_hex = hex(&compute_bundle_digest(&components, ""));
    let manifest = BackupManifest {
        format: MANIFEST_FORMAT.to_owned(),
        backup_run_id: run_id.to_owned(),
        quiesced_at: quiesced_at.clone(),
        completed_at: completed_at_str.clone(),
        schema_version,
        crate_version: env!("CARGO_PKG_VERSION").to_owned(),
        destination_domain: opts.destination_domain.clone(),
        rpo_target_seconds,
        encryption_key_id: keyring.active_key_id().to_owned(),
        bundle_digest: pre_manifest_bundle_hex,
        components: components.clone(),
        deletion_journal: JournalWatermarkManifest {
            origin_us: parsed_export.origin_us,
            journal_seq: parsed_export.seq,
            chain_digest: parsed_export.digest.clone(),
            lifecycle_origin_us: parsed_export.lifecycle_origin_us,
            lifecycle_baseline_digest: parsed_export.lifecycle_baseline_digest.clone(),
            connection_origin_us: parsed_export.connection_origin_us,
        },
        artifact_volume: ArtifactVolumeManifest {
            volume_id: artifact_summary.volume_id.clone(),
            revision_count: artifact_summary.revision_count,
            payload_bytes: artifact_summary.payload_bytes,
        },
        vault_required_key_ids: vault_required_key_ids.clone(),
        gateway_consistency_mode: GATEWAY_CONSISTENCY_MODE.to_owned(),
        graphiti_neo4j: graphiti_manifest,
        rebuildable_indexes: REBUILDABLE_INDEXES
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|_| BackupError::Integrity("manifest serialization failed"))?;
    let manifest_stats = encrypt_bytes_to_file(
        keyring,
        run_id,
        "manifest",
        &manifest_bytes,
        &staging_dir.join("manifest.json.enc"),
    )?;
    let manifest_ct_hex = hex(&manifest_stats.ciphertext_sha256);
    let final_bundle_digest = compute_bundle_digest(&components, &manifest_ct_hex);
    let final_bundle_hex = hex(&final_bundle_digest);
    let manifest_digest_hex = hex(&manifest_stats.plaintext_sha256);

    let meta = BackupMeta {
        format: META_FORMAT.to_owned(),
        backup_run_id: run_id.to_owned(),
        completed_at: completed_at_str,
        destination_domain: opts.destination_domain.clone(),
        encryption_key_id: keyring.active_key_id().to_owned(),
        manifest_ciphertext_sha256: manifest_ct_hex,
        bundle_digest: final_bundle_hex.clone(),
        state: "complete".to_owned(),
    };
    let meta_bytes = serde_json::to_vec_pretty(&meta)
        .map_err(|_| BackupError::Integrity("backup-meta serialization failed"))?;
    write_file_0600(&staging_dir.join("backup-meta.json"), &meta_bytes)?;

    // 6. fsync staging directory, atomically rename into final backup directory, fsync destination
    //    root, then commit `backup_runs.state = 'succeeded'` (re-checking maintenance ownership).
    fsync_dir(staging_dir)?;
    let final_dir_name = format!("backup-{}-{run_id}", completed_dt.format("%Y%m%dT%H%M%SZ"));
    let final_dir = dest_root.join(&final_dir_name);
    fs::rename(staging_dir, &final_dir)?;
    fsync_dir(dest_root)?;

    let journal_chain_bytes = decode_hex_32(&parsed_export.digest)?;
    let lifecycle_baseline_bytes = parsed_export
        .lifecycle_baseline_digest
        .as_deref()
        .map(decode_hex_32)
        .transpose()?;
    let summary_json = json!({
        "format": MANIFEST_FORMAT,
        "schema_version": schema_version,
        "crate_version": env!("CARGO_PKG_VERSION"),
        "destination_domain": opts.destination_domain,
        "encryption_key_id": keyring.active_key_id(),
        "artifact_revision_count": artifact_summary.revision_count,
        "artifact_payload_bytes": artifact_summary.payload_bytes,
        "vault_required_key_ids": vault_required_key_ids,
        "rebuildable_indexes": REBUILDABLE_INDEXES,
        "backup_dir_name": final_dir_name,
    });
    let summary_text = summary_json.to_string();

    let mut tx = read_committed(pool).await?;
    sqlx::query(
        "SELECT openmettle.backup_complete_capture(
            $1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12
        )",
    )
    .bind(run_id)
    .bind(keyring.active_key_id())
    .bind(final_bundle_digest.as_slice())
    .bind(manifest_stats.plaintext_sha256.as_slice())
    .bind(parsed_export.origin_us)
    .bind(parsed_export.seq)
    .bind(journal_chain_bytes.as_slice())
    .bind(parsed_export.lifecycle_origin_us)
    .bind(lifecycle_baseline_bytes.as_ref().map(<[u8; 32]>::as_slice))
    .bind(parsed_export.connection_origin_us)
    .bind(&summary_text)
    .bind(&opts.reason)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    // 7. Run GFS retention pruning if enabled, then optionally release maintenance in its own
    //    audited transaction.
    let pruned = match opts.prune_policy {
        Some(policy) => Some(prune_destination(dest_root, policy, false)?),
        None => None,
    };

    let released_maintenance = if opts.release_on_success {
        let release_key = hex(&Sha256::digest(
            format!("backup.capture.release:{}", opts.request_key).as_bytes(),
        ));
        let (released, _) =
            release_maintenance(pool, &opts.operator_id, &release_key, &opts.reason, false).await?;
        released
    } else {
        false
    };

    Ok(CaptureReport {
        backup_run_id: run_id.to_owned(),
        backup_dir: final_dir,
        encryption_key_id: keyring.active_key_id().to_owned(),
        bundle_digest: final_bundle_hex,
        manifest_digest: manifest_digest_hex,
        journal_seq: parsed_export.seq,
        pruned,
        released_maintenance,
    })
}

// --- verify, unpack, and prune ----------------------------------------------------------------

/// Decrypt and cryptographically verify `backup-meta.json`, `manifest.json.enc`, and every
/// component `.enc` file's AEAD tags, plaintext SHA-256, ciphertext SHA-256, byte lengths, and
/// aggregate `bundle_digest`.
pub fn verify_backup(
    backup_dir: &Path,
    keyring: &BackupKeyRing,
) -> Result<BackupManifest, BackupError> {
    let (meta, manifest) = load_and_verify_manifest(backup_dir, keyring)?;
    for (file_name, expected) in &manifest.components {
        let path = backup_dir.join(file_name);
        let mut src = fs::File::open(&path)
            .map_err(|_| BackupError::Integrity("manifest component file missing"))?;
        let stats = keyring.decrypt_stream(
            &manifest.backup_run_id,
            &expected.role,
            Some(&manifest.encryption_key_id),
            &mut src,
            &mut io::sink(),
        )?;
        verify_component_stats(expected, &stats)?;
    }
    let expected_bundle = hex(&compute_bundle_digest(
        &manifest.components,
        &meta.manifest_ciphertext_sha256,
    ));
    if meta.bundle_digest != expected_bundle {
        return Err(BackupError::Integrity("bundle digest mismatch"));
    }
    Ok(manifest)
}

#[derive(Clone, Debug)]
pub struct UnpackReport {
    pub manifest: BackupManifest,
    pub output_dir: PathBuf,
    pub artifact_summary: ArtifactArchiveSummary,
    pub config_files_written: usize,
    pub has_neo4j_dump: bool,
}

/// Decrypt, verify, and unpack a backup set into a new `0700` `output_dir` (`0600` files),
/// reconstructing `pg.dump`, `gateway-entitlements.json`, `deletion-journal.bin`, `artifacts/`
/// (with `revisions/`, `staging/`, and `.openmettle-volume-id` sentinels), `config/`, optional
/// `neo4j.dump`, and plaintext `manifest.json`.
pub fn unpack_backup(
    backup_dir: &Path,
    output_dir: &Path,
    keyring: &BackupKeyRing,
) -> Result<UnpackReport, BackupError> {
    if !output_dir.is_absolute() {
        return Err(BackupError::Invalid("--output-dir must be absolute"));
    }
    if output_dir.exists() {
        return Err(BackupError::Invalid("--output-dir must not already exist"));
    }

    let (meta, manifest) = load_and_verify_manifest(backup_dir, keyring)?;
    let expected_bundle = hex(&compute_bundle_digest(
        &manifest.components,
        &meta.manifest_ciphertext_sha256,
    ));
    if meta.bundle_digest != expected_bundle {
        return Err(BackupError::Integrity("bundle digest mismatch"));
    }

    create_dir_0700(output_dir)?;
    let unpack_result = (|| -> Result<UnpackReport, BackupError> {
        let decrypt_to_file = |comp_name: &str, out_name: &str| -> Result<(), BackupError> {
            let expected = manifest
                .components
                .get(comp_name)
                .ok_or(BackupError::Integrity(
                    "required component missing from manifest",
                ))?;
            let mut src = fs::File::open(backup_dir.join(comp_name))
                .map_err(|_| BackupError::Integrity("encrypted component file missing"))?;
            let mut dst = open_new_file_0600(&output_dir.join(out_name))?;
            let stats = keyring.decrypt_stream(
                &manifest.backup_run_id,
                &expected.role,
                Some(&manifest.encryption_key_id),
                &mut src,
                &mut dst,
            )?;
            verify_component_stats(expected, &stats)?;
            dst.sync_all()?;
            Ok(())
        };

        decrypt_to_file("pg.dump.enc", "pg.dump")?;
        decrypt_to_file("gateway-entitlements.json.enc", "gateway-entitlements.json")?;
        decrypt_to_file("deletion-journal.bin.enc", "deletion-journal.bin")?;

        // Decrypt artifacts.bin.enc via a bounded temporary plaintext stream in output_dir or
        // streaming directly into unpack_artifact_archive via a temp file unlinked immediately.
        let artifact_expected =
            manifest
                .components
                .get("artifacts.bin.enc")
                .ok_or(BackupError::Integrity(
                    "artifacts.bin.enc missing from manifest",
                ))?;
        let tmp_artifacts = output_dir.join(".artifacts.bin.tmp");
        let artifact_summary = {
            let mut src = fs::File::open(backup_dir.join("artifacts.bin.enc"))
                .map_err(|_| BackupError::Integrity("artifacts.bin.enc missing"))?;
            let mut tmp = open_new_file_0600(&tmp_artifacts)?;
            let stats = keyring.decrypt_stream(
                &manifest.backup_run_id,
                &artifact_expected.role,
                Some(&manifest.encryption_key_id),
                &mut src,
                &mut tmp,
            )?;
            verify_component_stats(artifact_expected, &stats)?;
            drop(tmp);
            let mut reader = fs::File::open(&tmp_artifacts)?;
            let summary = unpack_artifact_archive(&mut reader, &output_dir.join("artifacts"))?;
            let _ = fs::remove_file(&tmp_artifacts);
            summary
        };

        // Decrypt config.json.enc and materialize config/<name> + vault-key-inventory.json.
        let config_expected =
            manifest
                .components
                .get("config.json.enc")
                .ok_or(BackupError::Integrity(
                    "config.json.enc missing from manifest",
                ))?;
        let mut config_plain = Vec::new();
        {
            let mut src = fs::File::open(backup_dir.join("config.json.enc"))
                .map_err(|_| BackupError::Integrity("config.json.enc missing"))?;
            let stats = keyring.decrypt_stream(
                &manifest.backup_run_id,
                &config_expected.role,
                Some(&manifest.encryption_key_id),
                &mut src,
                &mut config_plain,
            )?;
            verify_component_stats(config_expected, &stats)?;
        }
        let config_bundle: ConfigBundle = serde_json::from_slice(&config_plain)
            .map_err(|_| BackupError::Integrity("invalid config.json payload"))?;
        let config_dir = output_dir.join("config");
        create_dir_0700(&config_dir)?;
        for cf in &config_bundle.files {
            if cf.name.contains('/') || cf.name.contains('\\') || cf.name == ".." || cf.name == "."
            {
                return Err(BackupError::Integrity("unsafe config filename in bundle"));
            }
            let computed = hex(&Sha256::digest(cf.content_utf8.as_bytes()));
            if computed != cf.sha256 || cf.content_utf8.len() as u64 != cf.size_bytes {
                return Err(BackupError::Integrity("config file digest mismatch"));
            }
            write_file_0600(&config_dir.join(&cf.name), cf.content_utf8.as_bytes())?;
        }
        let vault_inv = serde_json::to_vec_pretty(&json!({
            "vault_required_key_ids": config_bundle.vault_required_key_ids,
        }))
        .map_err(|_| BackupError::Integrity("vault inventory encode failed"))?;
        write_file_0600(&config_dir.join("vault-key-inventory.json"), &vault_inv)?;
        fsync_dir(&config_dir)?;

        let has_neo4j_dump = if manifest.components.contains_key("neo4j.dump.enc") {
            decrypt_to_file("neo4j.dump.enc", "neo4j.dump")?;
            true
        } else {
            false
        };

        let manifest_json = serde_json::to_vec_pretty(&manifest)
            .map_err(|_| BackupError::Integrity("manifest JSON encode failed"))?;
        write_file_0600(&output_dir.join("manifest.json"), &manifest_json)?;
        fs::set_permissions(output_dir, fs::Permissions::from_mode(0o700))?;
        fsync_dir(output_dir)?;

        Ok(UnpackReport {
            manifest,
            output_dir: output_dir.to_path_buf(),
            artifact_summary,
            config_files_written: config_bundle.files.len(),
            has_neo4j_dump,
        })
    })();

    if unpack_result.is_err() {
        let _ = fs::remove_dir_all(output_dir);
    }
    unpack_result
}

fn load_and_verify_manifest(
    backup_dir: &Path,
    keyring: &BackupKeyRing,
) -> Result<(BackupMeta, BackupManifest), BackupError> {
    if !backup_dir.is_absolute() || !backup_dir.is_dir() {
        return Err(BackupError::Invalid(
            "--backup-dir must be an existing absolute directory",
        ));
    }
    let meta_bytes = fs::read(backup_dir.join("backup-meta.json"))
        .map_err(|_| BackupError::Integrity("backup-meta.json missing"))?;
    let meta: BackupMeta = serde_json::from_slice(&meta_bytes)
        .map_err(|_| BackupError::Integrity("backup-meta.json malformed"))?;
    if meta.format != META_FORMAT || meta.state != "complete" {
        return Err(BackupError::Integrity("backup-meta.json is not complete"));
    }
    runs::uuid(&meta.backup_run_id)
        .map_err(|_| BackupError::Integrity("invalid backup_run_id in backup-meta.json"))?;

    let mut manifest_plain = Vec::new();
    let mut manifest_file = fs::File::open(backup_dir.join("manifest.json.enc"))
        .map_err(|_| BackupError::Integrity("manifest.json.enc missing"))?;
    let stats = keyring.decrypt_stream(
        &meta.backup_run_id,
        "manifest",
        Some(&meta.encryption_key_id),
        &mut manifest_file,
        &mut manifest_plain,
    )?;
    if hex(&stats.ciphertext_sha256) != meta.manifest_ciphertext_sha256 {
        return Err(BackupError::Integrity(
            "manifest ciphertext SHA-256 mismatch",
        ));
    }

    let manifest: BackupManifest = serde_json::from_slice(&manifest_plain)
        .map_err(|_| BackupError::Integrity("manifest.json malformed"))?;
    if manifest.format != MANIFEST_FORMAT
        || manifest.backup_run_id != meta.backup_run_id
        || manifest.encryption_key_id != meta.encryption_key_id
    {
        return Err(BackupError::Integrity(
            "manifest identity disagrees with backup-meta.json",
        ));
    }
    let expected_pre_bundle = hex(&compute_bundle_digest(&manifest.components, ""));
    if manifest.bundle_digest != expected_pre_bundle {
        return Err(BackupError::Integrity(
            "manifest component bundle digest mismatch",
        ));
    }
    Ok((meta, manifest))
}

fn verify_component_stats(
    expected: &ComponentManifest,
    actual: &crypto::DecryptedStats,
) -> Result<(), BackupError> {
    if actual.plaintext_bytes != expected.plaintext_bytes
        || hex(&actual.plaintext_sha256) != expected.plaintext_sha256
        || actual.ciphertext_bytes != expected.ciphertext_bytes
        || hex(&actual.ciphertext_sha256) != expected.ciphertext_sha256
    {
        return Err(BackupError::Integrity(
            "component digest or byte length disagrees with manifest",
        ));
    }
    Ok(())
}

/// Apply GFS retention pruning to `destination_root`.
pub fn prune(
    destination_root: &Path,
    policy: GfsPolicy,
    dry_run: bool,
) -> Result<PruneReport, BackupError> {
    Ok(prune_destination(destination_root, policy, dry_run)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pg_uri_handles_percent_encoding_ipv6_and_query_params() {
        let p = parse_pg_uri(
            "postgresql://openmettle_owner:s%3Aec%5Cret@127.0.0.1:55447/om_db?sslmode=require",
        )
        .unwrap();
        assert_eq!(p.username.as_deref(), Some("openmettle_owner"));
        assert_eq!(p.password.as_deref(), Some("s:ec\\ret"));
        assert_eq!(p.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(p.port, Some(55447));
        assert_eq!(p.database.as_deref(), Some("om_db"));
        assert_eq!(p.sslmode.as_deref(), Some("require"));
        assert_eq!(escape_pgpass("s:ec\\ret"), r"s\:ec\\ret");

        let v6 = parse_pg_uri("postgres://user:pw@[::1]:5432/db").unwrap();
        assert_eq!(v6.host.as_deref(), Some("::1"));
        assert_eq!(v6.port, Some(5432));
    }

    #[test]
    fn cli_pg_dump_runner_passes_zero_password_in_argv_and_cleans_0600_pgpass() {
        let dir = std::env::temp_dir().join(format!("om-pgdump-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let script = dir.join("fake-pg-dump.sh");
        let observed = dir.join("observed.txt");
        let body = format!(
            "#!/bin/sh\nset -eu\n\
             printf 'ARGS=%s\\n' \"$*\" > \"{}\"\n\
             printf 'PGPASSFILE=%s\\n' \"${{PGPASSFILE:-}}\" >> \"{}\"\n\
             printf 'PGPASSWORD=%s\\n' \"${{PGPASSWORD:-}}\" >> \"{}\"\n\
             printf 'CONTENT=%s\\n' \"$(cat \"$PGPASSFILE\")\" >> \"{}\"\n\
             printf 'PGDMP-SYNTHETIC-PAYLOAD'\n",
            observed.display(),
            observed.display(),
            observed.display(),
            observed.display(),
        );
        fs::write(&script, body).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();

        let runner = CliPgDumpRunner::with_program(&script);
        let mut out = Vec::new();
        let written = runner
            .dump(
                "postgres://openmettle_owner:supersecret:pw@127.0.0.1:55447/openmettle?sslmode=disable",
                &mut out,
            )
            .unwrap();
        assert_eq!(out, b"PGDMP-SYNTHETIC-PAYLOAD");
        assert_eq!(written, b"PGDMP-SYNTHETIC-PAYLOAD".len() as u64);

        let obs = fs::read_to_string(&observed).unwrap();
        let args_line = obs.lines().find(|l| l.starts_with("ARGS=")).unwrap();
        assert!(args_line.contains("--format=custom"));
        assert!(args_line.contains("--schema=openmettle"));
        assert!(args_line.contains("--no-owner"));
        assert!(!args_line.contains("--no-acl"));
        assert!(
            !args_line.contains("supersecret"),
            "password leaked to argv: {args_line}"
        );

        let pgpass_line = obs
            .lines()
            .find(|l| l.starts_with("PGPASSFILE="))
            .unwrap()
            .strip_prefix("PGPASSFILE=")
            .unwrap();
        assert!(!pgpass_line.is_empty());
        // Ephemeral PGPASSFILE must be deleted on return.
        assert!(!Path::new(pgpass_line).exists());
        assert!(obs.contains("PGPASSWORD=\n"));
        assert!(
            obs.contains(r"CONTENT=127.0.0.1:55447:openmettle:openmettle_owner:supersecret\:pw")
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
