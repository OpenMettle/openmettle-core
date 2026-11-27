//! V1-30 maintenance-window coordinated backup capture, AEAD archive verification/unpacking,
//! GFS retention pruning, and `openmettle.backup.runs` worker telemetry observation (ADR 0046).

pub mod archive;
pub mod crypto;

use crate::{
    artifact_fs::{self, Store},
    authz::{projects::hex, store::StoreError},
    restore::{self, Export},
    runs,
    telemetry::metrics::Metrics,
};
use archive::{
    ArchiveError, ArtifactArchiveSummary, BackupMeta, BundledConfigFile, GfsPolicy,
    MAX_BACKUP_META_BYTES, PruneReport, SettledArtifactRecord, collect_protected_key_inodes,
    create_dir_0700, fsync_dir, fsync_regular_file_nofollow, load_non_secret_config_files,
    open_new_file_0600, open_regular_nofollow, prune_destination_with_verifier,
    read_regular_bounded_nofollow, unpack_artifact_archive, validate_destination_root,
    write_artifact_archive, write_file_0600,
};
use chrono::{DateTime, Utc};
use crypto::{BackupKeyRing, CryptoError, EncryptedStats, StreamEncryptor};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore,
    SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{
    PgConnection, PgPool, Postgres, Row, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    ops::Deref,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpStream, UnixListener},
    task::JoinSet,
};

pub const MANIFEST_FORMAT: &str = "openmettle-backup-manifest/v1";
pub const META_FORMAT: &str = "openmettle-backup-meta/v1";
pub const GATEWAY_CONSISTENCY_MODE: &str = "postgresql_authoritative_adr_0044";
pub const BASE_REBUILDABLE_INDEXES: [&str; 2] = [
    "postgresql_secondary_indexes",
    "derived_search_and_fulltext_indexes",
];
pub const CHROMA_REBUILDABLE_INDEX: &str = "chroma_vector_embeddings";
pub const REBUILDABLE_INDEXES: [&str; 2] = BASE_REBUILDABLE_INDEXES;
pub const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 300;
pub const DEFAULT_LEASE_SECONDS: i32 = 300;
const DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(100);
const SNAPSHOT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const TLS_PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_TLS_PEM_BYTES: usize = 1024 * 1024;
const PG_SSL_REQUEST: [u8; 8] = [0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
const REQUIRED_COMPONENTS: [&str; 5] = [
    "artifacts.bin.enc",
    "config.json.enc",
    "deletion-journal.bin.enc",
    "gateway-entitlements.json.enc",
    "pg.dump.enc",
];

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

/// Durable cumulative outcome totals returned by `openmettle.backup_observe_telemetry()`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObservedTelemetry {
    pub succeeded: u64,
    pub failed: u64,
    pub incomplete: u64,
    pub overdue: u64,
}

/// Poll `openmettle.backup_observe_telemetry()` as `openmettle_worker` and monotonically
/// synchronize durable cumulative totals into the process-global `openmettle.backup.runs`
/// counters.
pub async fn observe_telemetry(pool: &PgPool) -> Result<ObservedTelemetry, sqlx::Error> {
    observe_telemetry_into(pool, crate::telemetry::metrics::global()).await
}

/// Same as [`observe_telemetry`], synchronizing into the supplied [`Metrics`] registry (for
/// isolated integration tests).
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
    metrics.sync_backup_run_totals(
        observed.succeeded,
        observed.failed,
        observed.incomplete,
        observed.overdue,
    );
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
    CommitOutcomeUnknown,
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
            Self::CommitOutcomeUnknown => "commit_outcome_unknown",
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
            Self::CommitOutcomeUnknown => f.write_str(
                "backup publication commit outcome unknown; staging preserved for exact-request-key retry",
            ),
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

// --- strict PostgreSQL URL validation & pluggable PgDumpRunner --------------------------------

/// Validated PostgreSQL connection parameters shared identically between `sqlx` and `pg_dump`
/// so unknown, duplicate, `hostaddr`, or multi-host connection parameters fail closed before
/// entering maintenance and neither client inherits conflicting ambient `PG*` defaults.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedPgConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: Option<String>,
    pub sslmode: String,
    pub sslrootcert: Option<String>,
    pub sslcert: Option<String>,
    pub sslkey: Option<String>,
    pub application_name: Option<String>,
}

impl fmt::Debug for ValidatedPgConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidatedPgConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("sslmode", &self.sslmode)
            .field("sslrootcert", &self.sslrootcert)
            .field("sslcert", &self.sslcert)
            .field("sslkey", &self.sslkey)
            .field("application_name", &self.application_name)
            .finish()
    }
}

impl ValidatedPgConfig {
    fn parsed_ssl_mode(&self) -> Result<PgSslMode, BackupError> {
        match self.sslmode.as_str() {
            "prefer" => Ok(PgSslMode::Prefer),
            "disable" => Ok(PgSslMode::Disable),
            "allow" => Err(BackupError::PgDump(
                "sslmode=allow is not supported; use disable, prefer, require, verify-ca, or verify-full",
            )),
            "require" => Ok(PgSslMode::Require),
            "verify-ca" => Ok(PgSslMode::VerifyCa),
            "verify-full" => Ok(PgSslMode::VerifyFull),
            _ => Err(BackupError::PgDump("invalid sslmode in database URL")),
        }
    }

    /// Enforce identical TLS certificate verification semantics between `sqlx-postgres` 0.9.0
    /// and `libpq` (`pg_dump`).
    fn validate_tls_parity(&self) -> Result<PgSslMode, BackupError> {
        let ssl_mode = self.parsed_ssl_mode()?;
        if let Some(ca) = self.sslrootcert.as_deref()
            && ca.eq_ignore_ascii_case("system")
        {
            return Err(BackupError::PgDump(
                "sslrootcert=system is not supported; pass an explicit CA file path",
            ));
        }
        if self.sslcert.is_some() != self.sslkey.is_some() {
            return Err(BackupError::PgDump(
                "sslcert and sslkey must be supplied together",
            ));
        }
        for path in [
            self.sslrootcert.as_deref(),
            self.sslcert.as_deref(),
            self.sslkey.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if path.is_empty() || !Path::new(path).is_absolute() {
                return Err(BackupError::PgDump(
                    "TLS certificate paths in database URL must be non-empty absolute paths",
                ));
            }
        }
        if self.host.starts_with('/')
            && matches!(
                self.sslmode.as_str(),
                "require" | "verify-ca" | "verify-full"
            )
        {
            return Err(BackupError::PgDump(
                "TLS-required sslmode cannot be used with a Unix domain socket host",
            ));
        }
        let has_any_cert =
            self.sslrootcert.is_some() || self.sslcert.is_some() || self.sslkey.is_some();
        match self.sslmode.as_str() {
            "disable" if has_any_cert => {
                return Err(BackupError::PgDump(
                    "TLS certificate parameters cannot be combined with sslmode=disable",
                ));
            }
            "prefer" if self.sslrootcert.is_some() => {
                return Err(BackupError::PgDump(
                    "sslrootcert cannot be combined with sslmode=prefer; use verify-ca or verify-full",
                ));
            }
            "require" if self.sslrootcert.is_some() => {
                return Err(BackupError::PgDump(
                    "sslrootcert cannot be combined with sslmode=require; use verify-ca or verify-full",
                ));
            }
            "verify-ca" | "verify-full" if self.sslrootcert.is_none() => {
                return Err(BackupError::PgDump(
                    "sslmode=verify-ca and verify-full require an explicit sslrootcert CA file path",
                ));
            }
            _ => {}
        }
        Ok(ssl_mode)
    }

    fn check_ambient_pg_env(&self) -> Result<(), BackupError> {
        if std::env::var_os("PGOPTIONS").is_some() {
            return Err(BackupError::PgDump(
                "ambient PGOPTIONS environment variable is not supported for backup capture",
            ));
        }
        if self.password.is_none() && std::env::var_os("PGPASSWORD").is_some() {
            return Err(BackupError::PgDump(
                "ambient PGPASSWORD environment variable conflicts with database URL without password",
            ));
        }
        if self.sslrootcert.is_none() && std::env::var_os("PGSSLROOTCERT").is_some() {
            return Err(BackupError::PgDump(
                "ambient PGSSLROOTCERT environment variable conflicts with database URL without sslrootcert",
            ));
        }
        if self.sslcert.is_none() && std::env::var_os("PGSSLCERT").is_some() {
            return Err(BackupError::PgDump(
                "ambient PGSSLCERT environment variable conflicts with database URL without sslcert",
            ));
        }
        if self.sslkey.is_none() && std::env::var_os("PGSSLKEY").is_some() {
            return Err(BackupError::PgDump(
                "ambient PGSSLKEY environment variable conflicts with database URL without sslkey",
            ));
        }
        if self.application_name.is_none() && std::env::var_os("PGAPPNAME").is_some() {
            return Err(BackupError::PgDump(
                "ambient PGAPPNAME environment variable conflicts with database URL without application_name",
            ));
        }
        Ok(())
    }

    /// Build `sqlx::postgres::PgConnectOptions` via `PgConnectOptions::new_without_pgpass()`
    /// with every endpoint and TLS parameter set explicitly from `self`, matching the exact
    /// values passed to `pg_dump`. Fails closed if any ambient optional `PG*` env var that
    /// `new_without_pgpass()` reads would diverge from the scrubbed `pg_dump` environment.
    pub fn to_sqlx_options(&self) -> Result<PgConnectOptions, BackupError> {
        let ssl_mode = self.validate_tls_parity()?;
        self.check_ambient_pg_env()?;

        let mut opts = PgConnectOptions::new_without_pgpass()
            .port(self.port)
            .username(&self.username)
            .database(&self.database)
            .ssl_mode(ssl_mode);
        if self.host.starts_with('/') {
            opts = opts.socket(&self.host);
        } else {
            opts = opts.host(&self.host);
        }
        if let Some(password) = &self.password {
            opts = opts.password(password);
        }
        if let Some(ca) = &self.sslrootcert {
            opts = opts.ssl_root_cert(ca);
        }
        if let Some(cert) = &self.sslcert {
            opts = opts.ssl_client_cert(cert);
        }
        if let Some(key) = &self.sslkey {
            opts = opts.ssl_client_key(key);
        }
        if let Some(app) = &self.application_name {
            opts = opts.application_name(app);
        }
        Ok(opts)
    }
}

fn contains_ctrl_or_nul(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7f)
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

/// Strictly parse a PostgreSQL URI against a closed allow-list (`host`, `port`, `dbname`, `user`,
/// `password`, `sslmode`, `sslrootcert`, `sslcert`, `sslkey`, `application_name`), requiring
/// explicit non-empty `host`, `user`, and `dbname`, defaulting `port` to `5432` and `sslmode` to
/// `"prefer"`, and rejecting `hostaddr`, multi-host URIs, fragments, duplicate or unknown query
/// parameters, invalid `sslmode`/`port`, and control characters.
pub fn parse_validated_pg_uri(url: &str) -> Result<ValidatedPgConfig, BackupError> {
    if url.contains('#') {
        return Err(BackupError::PgDump(
            "fragments are not permitted in database URL",
        ));
    }
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

    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut database: Option<String> = None;
    let mut username: Option<String> = None;
    let mut password: Option<String> = None;
    let mut sslmode: Option<String> = None;
    let mut sslrootcert: Option<String> = None;
    let mut sslcert: Option<String> = None;
    let mut sslkey: Option<String> = None;
    let mut application_name: Option<String> = None;

    if let Some(u) = userinfo {
        match u.split_once(':') {
            Some((user, pass)) => {
                if !user.is_empty() {
                    let decoded = percent_decode(user)?;
                    if contains_ctrl_or_nul(&decoded) {
                        return Err(BackupError::PgDump("invalid control character in username"));
                    }
                    username = Some(decoded);
                }
                let decoded_pw = percent_decode(pass)?;
                if contains_ctrl_or_nul(&decoded_pw) {
                    return Err(BackupError::PgDump("invalid control character in password"));
                }
                password = Some(decoded_pw);
            }
            None => {
                if !u.is_empty() {
                    let decoded = percent_decode(u)?;
                    if contains_ctrl_or_nul(&decoded) {
                        return Err(BackupError::PgDump("invalid control character in username"));
                    }
                    username = Some(decoded);
                }
            }
        }
    }

    if !hostport.is_empty() {
        if hostport.contains(',') {
            return Err(BackupError::PgDump(
                "multi-host PostgreSQL URLs are not supported",
            ));
        }
        if let Some(after_open) = hostport.strip_prefix('[') {
            let (parsed_host, tail) = after_open
                .split_once(']')
                .ok_or(BackupError::PgDump("unclosed IPv6 host in database URL"))?;
            if parsed_host.is_empty()
                || parsed_host.contains('[')
                || parsed_host.contains(']')
                || parsed_host.contains(',')
            {
                return Err(BackupError::PgDump("invalid IPv6 host in database URL"));
            }
            if contains_ctrl_or_nul(parsed_host) {
                return Err(BackupError::PgDump("invalid control character in host"));
            }
            host = Some(parsed_host.to_owned());
            if !tail.is_empty() {
                let port_str = tail
                    .strip_prefix(':')
                    .ok_or(BackupError::PgDump("invalid host/port in database URL"))?;
                let p: u16 = port_str
                    .parse()
                    .map_err(|_| BackupError::PgDump("invalid port in database URL"))?;
                if p == 0 {
                    return Err(BackupError::PgDump("invalid port in database URL"));
                }
                port = Some(p);
            }
        } else if let Some((parsed_host, port_str)) = hostport.rsplit_once(':') {
            if parsed_host.contains(':') {
                return Err(BackupError::PgDump("unbracketed IPv6 host in database URL"));
            }
            if !parsed_host.is_empty() {
                let decoded = percent_decode(parsed_host)?;
                if decoded.contains(',') || contains_ctrl_or_nul(&decoded) {
                    return Err(BackupError::PgDump("invalid host in database URL"));
                }
                host = Some(decoded);
            }
            if !port_str.is_empty() {
                let p: u16 = port_str
                    .parse()
                    .map_err(|_| BackupError::PgDump("invalid port in database URL"))?;
                if p == 0 {
                    return Err(BackupError::PgDump("invalid port in database URL"));
                }
                port = Some(p);
            }
        } else {
            let decoded = percent_decode(hostport)?;
            if decoded.contains(',') || contains_ctrl_or_nul(&decoded) {
                return Err(BackupError::PgDump("invalid host in database URL"));
            }
            host = Some(decoded);
        }
    }

    if let Some(p) = path
        && !p.is_empty()
    {
        if p.contains('/') {
            return Err(BackupError::PgDump("invalid database path in URL"));
        }
        let decoded = percent_decode(p)?;
        if contains_ctrl_or_nul(&decoded) {
            return Err(BackupError::PgDump(
                "invalid control character in database name",
            ));
        }
        database = Some(decoded);
    }

    if let Some(q) = query {
        let mut seen_keys = BTreeSet::new();
        for pair in q.split('&').filter(|s| !s.is_empty()) {
            let Some((k, v)) = pair.split_once('=') else {
                return Err(BackupError::PgDump(
                    "malformed query parameter in database URL",
                ));
            };
            if !seen_keys.insert(k) {
                return Err(BackupError::PgDump(
                    "duplicate query parameter in database URL",
                ));
            }
            let v = percent_decode(v)?;
            if contains_ctrl_or_nul(&v) {
                return Err(BackupError::PgDump(
                    "invalid control character in database URL parameter",
                ));
            }
            if k != "password" && v.is_empty() {
                return Err(BackupError::PgDump(
                    "empty query parameter value in database URL",
                ));
            }
            match k {
                "host" => {
                    if v.contains(',') {
                        return Err(BackupError::PgDump(
                            "multi-host PostgreSQL URLs are not supported",
                        ));
                    }
                    host = Some(v);
                }
                "hostaddr" => {
                    return Err(BackupError::PgDump(
                        "hostaddr URI parameter is not supported; specify a resolvable host or IP in the URI",
                    ));
                }
                "port" => {
                    if v.contains(',') {
                        return Err(BackupError::PgDump(
                            "multi-host PostgreSQL URLs are not supported",
                        ));
                    }
                    let p: u16 = v
                        .parse()
                        .map_err(|_| BackupError::PgDump("invalid query port"))?;
                    if p == 0 {
                        return Err(BackupError::PgDump("invalid query port"));
                    }
                    port = Some(p);
                }
                "dbname" => database = Some(v),
                "user" => username = Some(v),
                "password" => password = Some(v),
                "sslmode" => {
                    if v == "allow" {
                        return Err(BackupError::PgDump(
                            "sslmode=allow is not supported; use disable, prefer, require, verify-ca, or verify-full",
                        ));
                    }
                    if !matches!(
                        v.as_str(),
                        "disable" | "prefer" | "require" | "verify-ca" | "verify-full"
                    ) {
                        return Err(BackupError::PgDump("invalid sslmode in database URL"));
                    }
                    sslmode = Some(v);
                }
                "sslrootcert" => sslrootcert = Some(v),
                "sslcert" => sslcert = Some(v),
                "sslkey" => sslkey = Some(v),
                "application_name" => application_name = Some(v),
                _ => {
                    return Err(BackupError::PgDump(
                        "unsupported query parameter in database URL",
                    ));
                }
            }
        }
    }

    let host = host.filter(|h| !h.is_empty()).ok_or(BackupError::PgDump(
        "database URL requires an explicit host",
    ))?;
    let username = username
        .filter(|u| !u.is_empty())
        .ok_or(BackupError::PgDump(
            "database URL requires an explicit username",
        ))?;
    let database = database
        .filter(|d| !d.is_empty())
        .ok_or(BackupError::PgDump(
            "database URL requires an explicit database name",
        ))?;
    // Refuse libpq conninfo/URI expansion in `dbname` (and embedded slashes from `%2F` or
    // `?dbname=...`) so `pg_dump --dbname=<db>` can never override validated endpoint/TLS flags.
    if database.contains('=') {
        return Err(BackupError::PgDump(
            "database name must not contain '=' (conninfo expansion refused)",
        ));
    }
    if database.contains('/') {
        return Err(BackupError::PgDump("database name must not contain '/'"));
    }
    let lower_db = database.to_ascii_lowercase();
    if lower_db.starts_with("postgres://") || lower_db.starts_with("postgresql://") {
        return Err(BackupError::PgDump(
            "database name must not be a PostgreSQL URI",
        ));
    }
    let cfg = ValidatedPgConfig {
        host,
        port: port.unwrap_or(5432),
        database,
        username,
        password,
        sslmode: sslmode.unwrap_or_else(|| "prefer".to_owned()),
        sslrootcert,
        sslcert,
        sslkey,
        application_name,
    };
    cfg.validate_tls_parity()?;
    Ok(cfg)
}

#[derive(Debug)]
struct VerifyCaOnlyVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for VerifyCaOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(verified) => Ok(verified),
            Err(TlsError::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            Err(err) => Err(err),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn parse_pem_certs(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>, BackupError> {
    let mut out = Vec::new();
    for item in CertificateDer::pem_slice_iter(bytes) {
        let cert = item.map_err(|_| BackupError::PgDump("invalid PEM certificate file"))?;
        out.push(cert);
    }
    if out.is_empty() {
        return Err(BackupError::PgDump(
            "PEM certificate file contains no certificates",
        ));
    }
    Ok(out)
}

async fn write_all_tcp(stream: &TcpStream, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        stream.writable().await?;
        match stream.try_write(buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "unexpected EOF writing PostgreSQL SSLRequest",
                ));
            }
            Ok(n) => buf = &buf[n..],
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

async fn read_exact_tcp(stream: &TcpStream, mut buf: &mut [u8]) -> io::Result<()> {
    while !buf.is_empty() {
        stream.readable().await?;
        match stream.try_read(buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF reading PostgreSQL SSLRequest reply",
                ));
            }
            Ok(n) => buf = &mut buf[n..],
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn build_strict_tls_client(
    cfg: &ValidatedPgConfig,
) -> Result<(Arc<ClientConfig>, ServerName<'static>), BackupError> {
    let ca_path = cfg.sslrootcert.as_deref().ok_or(BackupError::PgDump(
        "sslmode=verify-ca and verify-full require an explicit sslrootcert CA file path",
    ))?;
    let ca_bytes = read_regular_bounded_nofollow(Path::new(ca_path), MAX_TLS_PEM_BYTES)
        .map_err(|_| BackupError::PgDump("failed to read sslrootcert CA PEM file"))?;
    let ca_certs = parse_pem_certs(&ca_bytes)?;
    let mut root_store = RootCertStore::empty();
    for cert in ca_certs {
        root_store
            .add(cert)
            .map_err(|_| BackupError::PgDump("invalid CA certificate in sslrootcert"))?;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|_| BackupError::PgDump("failed to initialize TLS client configuration"))?;
    let webpki_verifier =
        WebPkiServerVerifier::builder_with_provider(Arc::new(root_store), provider)
            .build()
            .map_err(|_| BackupError::PgDump("failed to build strict sslrootcert verifier"))?;
    let with_verifier = match cfg.sslmode.as_str() {
        "verify-full" => builder
            .dangerous()
            .with_custom_certificate_verifier(webpki_verifier),
        "verify-ca" => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(VerifyCaOnlyVerifier {
                inner: webpki_verifier,
            })),
        _ => unreachable!(),
    };
    let mut tls_config = match (cfg.sslcert.as_deref(), cfg.sslkey.as_deref()) {
        (Some(cert_path), Some(key_path)) => {
            let cert_bytes = read_regular_bounded_nofollow(Path::new(cert_path), MAX_TLS_PEM_BYTES)
                .map_err(|_| BackupError::PgDump("failed to read sslcert PEM file"))?;
            let certs = parse_pem_certs(&cert_bytes)?;
            let key_bytes = read_regular_bounded_nofollow(Path::new(key_path), MAX_TLS_PEM_BYTES)
                .map_err(|_| BackupError::PgDump("failed to read sslkey PEM file"))?;
            let key = PrivateKeyDer::from_pem_slice(&key_bytes)
                .map_err(|_| BackupError::PgDump("invalid sslkey PEM file"))?;
            with_verifier
                .with_client_auth_cert(certs, key)
                .map_err(|_| BackupError::PgDump("invalid sslcert/sslkey pair"))?
        }
        (None, None) => with_verifier.with_no_client_auth(),
        _ => {
            return Err(BackupError::PgDump(
                "sslcert and sslkey must be supplied together",
            ));
        }
    };
    // Disable TLS 1.2 session-ID and TLS 1.3 PSK ticket resumption so every reconnect performs
    // a full handshake and strictly re-verifies the peer certificate against `sslrootcert`.
    tls_config.resumption = rustls::client::Resumption::disabled();

    let server_name = match cfg.sslmode.as_str() {
        "verify-full" => ServerName::try_from(cfg.host.clone()).map_err(|_| {
            BackupError::PgDump("invalid database host for sslmode=verify-full verification")
        })?,
        _ => ServerName::try_from(cfg.host.clone()).unwrap_or_else(|_| {
            ServerName::try_from("postgres.invalid".to_owned()).expect("valid static DNS name")
        }),
    };

    Ok((Arc::new(tls_config), server_name))
}

async fn connect_strict_pg_tls(
    host: &str,
    port: u16,
    tls_config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, BackupError> {
    let host = host.to_owned();
    tokio::time::timeout(TLS_PREFLIGHT_TIMEOUT, async move {
        let tcp = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|_| BackupError::PgDump("PostgreSQL TLS connection failed"))?;
        write_all_tcp(&tcp, &PG_SSL_REQUEST)
            .await
            .map_err(|_| BackupError::PgDump("PostgreSQL TLS SSLRequest failed"))?;
        let mut reply = [0u8; 1];
        read_exact_tcp(&tcp, &mut reply)
            .await
            .map_err(|_| BackupError::PgDump("PostgreSQL TLS SSLRequest reply failed"))?;
        if reply[0] != b'S' {
            return Err(BackupError::PgDump(
                "PostgreSQL server declined TLS during strict sslrootcert verification",
            ));
        }
        let connector = tokio_rustls::TlsConnector::from(tls_config);
        connector.connect(server_name, tcp).await.map_err(|_| {
            BackupError::PgDump(
                "PostgreSQL TLS server certificate failed strict sslrootcert verification",
            )
        })
    })
    .await
    .map_err(|_| BackupError::PgDump("PostgreSQL TLS handshake timed out"))?
}

async fn forward_duplex<A, B>(mut a: A, mut b: B)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut a_to_b = vec![0u8; 16 * 1024];
    let mut a_pos = 0usize;
    let mut a_len = 0usize;
    let mut a_eof = false;
    let mut b_needs_flush = false;
    let mut b_shutdown = false;

    let mut b_to_a = vec![0u8; 16 * 1024];
    let mut b_pos = 0usize;
    let mut b_len = 0usize;
    let mut b_eof = false;
    let mut a_needs_flush = false;
    let mut a_shutdown = false;

    let _ = std::future::poll_fn(|cx| {
        loop {
            let mut progressed = false;

            if a_pos < a_len {
                match Pin::new(&mut b).poll_write(cx, &a_to_b[a_pos..a_len]) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(()),
                    Poll::Ready(Ok(n)) => {
                        a_pos += n;
                        b_needs_flush = true;
                        if a_pos == a_len {
                            a_pos = 0;
                            a_len = 0;
                        }
                        progressed = true;
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(()),
                    Poll::Pending => {}
                }
            } else if b_needs_flush {
                match Pin::new(&mut b).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        b_needs_flush = false;
                        progressed = true;
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
                        progressed = true;
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(()),
                    Poll::Pending => {}
                }
            } else if !b_shutdown {
                match Pin::new(&mut b).poll_shutdown(cx) {
                    Poll::Ready(Ok(())) => {
                        b_shutdown = true;
                        progressed = true;
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(()),
                    Poll::Pending => {}
                }
            }

            if b_pos < b_len {
                match Pin::new(&mut a).poll_write(cx, &b_to_a[b_pos..b_len]) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(()),
                    Poll::Ready(Ok(n)) => {
                        b_pos += n;
                        a_needs_flush = true;
                        if b_pos == b_len {
                            b_pos = 0;
                            b_len = 0;
                        }
                        progressed = true;
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(()),
                    Poll::Pending => {}
                }
            } else if a_needs_flush {
                match Pin::new(&mut a).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {
                        a_needs_flush = false;
                        progressed = true;
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
                        progressed = true;
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(()),
                    Poll::Pending => {}
                }
            } else if !a_shutdown {
                match Pin::new(&mut a).poll_shutdown(cx) {
                    Poll::Ready(Ok(())) => {
                        a_shutdown = true;
                        progressed = true;
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(()),
                    Poll::Pending => {}
                }
            }

            if a_shutdown && b_shutdown {
                return Poll::Ready(());
            }
            if !progressed {
                return Poll::Pending;
            }
        }
    })
    .await;
}

/// Process-private Unix-socket -> TLS tunnel stored in an exclusive owner-only `0700` directory
/// (`0600` socket + `SO_PEERCRED`/`LOCAL_PEERCRED` UID verification on every `accept`), enforcing
/// strict `sslrootcert`-only `rustls` verification (with TLS session resumption disabled) on EVERY
/// PostgreSQL connection and pool reconnect before reading a single byte (e.g., `StartupMessage`
/// or credentials) from SQLx.
struct StrictTlsTunnel {
    socket_dir: PathBuf,
    accept_task: tokio::task::JoinHandle<()>,
}

const STRICT_TLS_TUNNEL_PORT: u16 = 5432;

impl StrictTlsTunnel {
    async fn start(
        remote_host: String,
        remote_port: u16,
        tls_config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
    ) -> Result<Self, BackupError> {
        let temp_dir = std::env::temp_dir();
        let base_dir = if temp_dir.as_os_str().len() <= 55 {
            temp_dir
        } else {
            PathBuf::from("/tmp")
        };
        let mut rnd = [0u8; 8];
        SystemRandom::new()
            .fill(&mut rnd)
            .map_err(|_| BackupError::Crypto(CryptoError::Random))?;
        let socket_dir = base_dir.join(format!("om-pgtls-{}", hex(&rnd)));
        create_dir_0700(&socket_dir)?;

        let expected_uid = match fs::metadata(&socket_dir) {
            Ok(meta) => meta.uid(),
            Err(_) => {
                let _ = fs::remove_dir_all(&socket_dir);
                return Err(BackupError::PgDump(
                    "failed to inspect local strict-TLS tunnel directory",
                ));
            }
        };
        let sock_path = socket_dir.join(format!(".s.PGSQL.{STRICT_TLS_TUNNEL_PORT}"));
        let listener = match UnixListener::bind(&sock_path) {
            Ok(l) => l,
            Err(_) => {
                let _ = fs::remove_dir_all(&socket_dir);
                return Err(BackupError::PgDump(
                    "failed to bind local strict-TLS Unix socket tunnel",
                ));
            }
        };
        if fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o600)).is_err() {
            drop(listener);
            let _ = fs::remove_dir_all(&socket_dir);
            return Err(BackupError::PgDump(
                "failed to restrict local strict-TLS Unix socket permissions",
            ));
        }

        let accept_task = tokio::spawn(async move {
            let mut active: JoinSet<()> = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((local_unix, _)) = accepted else {
                            break;
                        };
                        if !local_unix.peer_cred().is_ok_and(|c| c.uid() == expected_uid) {
                            drop(local_unix);
                            continue;
                        }
                        let host = remote_host.clone();
                        let cfg = Arc::clone(&tls_config);
                        let name = server_name.clone();
                        active.spawn(async move {
                            // Verify remote TLS strictly against `sslrootcert` BEFORE reading a
                            // single byte from SQLx so zero credentials or SQL leave the process
                            // if a failover/cert rotation presents an untrusted certificate.
                            let Ok(remote_tls) =
                                connect_strict_pg_tls(&host, remote_port, cfg, name).await
                            else {
                                drop(local_unix);
                                return;
                            };
                            forward_duplex(local_unix, remote_tls).await;
                        });
                    }
                    Some(_) = active.join_next(), if !active.is_empty() => {}
                }
            }
        });
        Ok(Self {
            socket_dir,
            accept_task,
        })
    }
}

impl Drop for StrictTlsTunnel {
    fn drop(&mut self) {
        self.accept_task.abort();
        let _ = fs::remove_dir_all(&self.socket_dir);
    }
}

/// A validated PostgreSQL pool whose `sslmode=verify-ca` and `sslmode=verify-full` connections
/// (including every pool reconnect) are routed through [`StrictTlsTunnel`] enforcing strict
/// `sslrootcert`-only verification (zero host native or WebPKI fallback roots, TLS session
/// resumption disabled) over an owner-only Unix domain socket.
pub struct ValidatedPgPool {
    pool: PgPool,
    cfg: ValidatedPgConfig,
    _tunnel: Option<StrictTlsTunnel>,
}

impl ValidatedPgPool {
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn config(&self) -> &ValidatedPgConfig {
        &self.cfg
    }

    pub async fn close(self) {
        self.pool.close().await;
        drop(self._tunnel);
    }
}

impl Deref for ValidatedPgPool {
    type Target = PgPool;

    fn deref(&self) -> &Self::Target {
        &self.pool
    }
}

/// Open a [`ValidatedPgPool`] enforcing identical endpoint and TLS trust semantics to `libpq`
/// (`pg_dump`) across initial connect and every subsequent pool reconnect.
pub async fn connect_validated_pool(
    cfg: &ValidatedPgConfig,
    max_connections: u32,
) -> Result<ValidatedPgPool, BackupError> {
    cfg.validate_tls_parity()?;
    cfg.check_ambient_pg_env()?;
    if !matches!(cfg.sslmode.as_str(), "verify-ca" | "verify-full") {
        let opts = cfg.to_sqlx_options()?;
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect_with(opts)
            .await?;
        return Ok(ValidatedPgPool {
            pool,
            cfg: cfg.clone(),
            _tunnel: None,
        });
    }

    let (tls_config, server_name) = build_strict_tls_client(cfg)?;
    // Verify immediately before starting the tunnel/pool so cert errors surface cleanly as
    // `BackupError::PgDump(...)` instead of a generic pool-connect EOF.
    let probe = connect_strict_pg_tls(
        &cfg.host,
        cfg.port,
        Arc::clone(&tls_config),
        server_name.clone(),
    )
    .await?;
    drop(probe);

    let tunnel =
        StrictTlsTunnel::start(cfg.host.clone(), cfg.port, tls_config, server_name).await?;
    let mut local_opts = PgConnectOptions::new_without_pgpass()
        .socket(&tunnel.socket_dir)
        .port(STRICT_TLS_TUNNEL_PORT)
        .username(&cfg.username)
        .database(&cfg.database)
        .ssl_mode(PgSslMode::Disable);
    if let Some(password) = &cfg.password {
        local_opts = local_opts.password(password);
    }
    if let Some(app) = &cfg.application_name {
        local_opts = local_opts.application_name(app);
    }

    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect_with(local_opts)
        .await?;
    Ok(ValidatedPgPool {
        pool,
        cfg: cfg.clone(),
        _tunnel: Some(tunnel),
    })
}

/// Strictly verify PostgreSQL server TLS trust against ONLY `cfg.sslrootcert` (zero system or
/// WebPKI fallback roots) before opening any SQLx pool or closing admission.
pub async fn verify_pg_tls_preflight(cfg: &ValidatedPgConfig) -> Result<(), BackupError> {
    cfg.validate_tls_parity()?;
    if !matches!(cfg.sslmode.as_str(), "verify-ca" | "verify-full") {
        return Ok(());
    }
    let (tls_config, server_name) = build_strict_tls_client(cfg)?;
    let tls_stream = connect_strict_pg_tls(&cfg.host, cfg.port, tls_config, server_name).await?;
    drop(tls_stream);
    Ok(())
}

/// Cooperative cancellation handle shared between the async capture supervisor and blocking
/// `pg_dump` or streaming tasks. Calling [`DumpCancel::cancel`] marks the token cancelled and
/// sends `SIGKILL` to any registered child process so a stalled `pg_dump` exits and is reaped
/// immediately before staging cleanup.
#[derive(Clone, Default)]
pub struct DumpCancel {
    cancelled: Arc<AtomicBool>,
    child: Arc<Mutex<Option<Child>>>,
}

impl DumpCancel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        let mut guard = self.child.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(child) = guard.as_mut() {
            let _ = child.kill();
        }
    }

    fn register_child(&self, mut child: Child) {
        let mut guard = self.child.lock().unwrap_or_else(|e| e.into_inner());
        if self.cancelled.load(Ordering::Acquire) {
            let _ = child.kill();
        }
        *guard = Some(child);
    }

    /// Keep the child handle reachable inside `self.child` until `try_wait()` reaps it so a
    /// `cancel()` arriving after `stdout` EOF can still send `SIGKILL` to a hanging child.
    fn wait_and_reap(&self, kill_now: bool) -> io::Result<std::process::ExitStatus> {
        let mut killed = false;
        loop {
            {
                let mut guard = self.child.lock().unwrap_or_else(|e| e.into_inner());
                let Some(child) = guard.as_mut() else {
                    return Err(io::Error::other("pg_dump child handle missing"));
                };
                if !killed && (kill_now || self.cancelled.load(Ordering::Acquire)) {
                    let _ = child.kill();
                    killed = true;
                }
                if let Some(status) = child.try_wait()? {
                    *guard = None;
                    return Ok(status);
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Pluggable PostgreSQL logical dump runner so production runs real
/// `pg_dump --format=custom --schema=openmettle --no-owner [--snapshot=<id>]` while deterministic
/// tests can inject synthetic or scripted dump runners.
pub trait PgDumpRunner: Send + Sync {
    fn dump(
        &self,
        database_url: &str,
        snapshot_id: Option<&str>,
        cancel: &DumpCancel,
        writer: &mut dyn Write,
    ) -> Result<u64, BackupError>;
}

/// Real `pg_dump` CLI runner using `--format=custom --schema=openmettle --no-owner` (preserving
/// bounded role `GRANT`/`REVOKE` ACLs on `openmettle` schema objects without touching `public`),
/// synchronized to the exported `REPEATABLE READ` snapshot when supplied, scrubbing all inherited
/// `PG*` environment variables, and passing credentials solely via an ephemeral `0600`
/// `PGPASSFILE` unlinked on drop.
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

fn valid_snapshot_id(snap: &str) -> bool {
    !snap.is_empty()
        && snap.len() <= 128
        && snap
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

struct EphemeralPgEnv {
    dir: PathBuf,
    pgpass_file: PathBuf,
}

impl EphemeralPgEnv {
    fn create(parsed: &ValidatedPgConfig) -> Result<Self, BackupError> {
        let mut rnd = [0u8; 16];
        SystemRandom::new()
            .fill(&mut rnd)
            .map_err(|_| BackupError::Crypto(CryptoError::Random))?;
        let dir = std::env::temp_dir().join(format!("om-pgenv-{}", hex(&rnd)));
        create_dir_0700(&dir)?;
        let pgpass_file = if let Some(password) = parsed.password.as_deref() {
            let file = dir.join("pgpass");
            let host = escape_pgpass(&parsed.host);
            let port = parsed.port.to_string();
            let db = escape_pgpass(&parsed.database);
            let user = escape_pgpass(&parsed.username);
            let pass = escape_pgpass(password);
            let mut content = format!("{host}:{port}:{db}:{user}:{pass}\n");
            if parsed.host.starts_with('/') {
                // `libpq` maps its compiled-in default Unix socket directory to `localhost` when
                // consulting `PGPASSFILE`.
                content.push_str(&format!("localhost:{port}:{db}:{user}:{pass}\n"));
            }
            if let Err(err) = write_file_0600(&file, content.as_bytes()) {
                let _ = fs::remove_dir_all(&dir);
                return Err(err.into());
            }
            file
        } else {
            dir.join("nonexistent-pgpass")
        };
        Ok(Self { dir, pgpass_file })
    }

    fn nonexistent_path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for EphemeralPgEnv {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.pgpass_file);
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl PgDumpRunner for CliPgDumpRunner {
    fn dump(
        &self,
        database_url: &str,
        snapshot_id: Option<&str>,
        cancel: &DumpCancel,
        writer: &mut dyn Write,
    ) -> Result<u64, BackupError> {
        if cancel.is_cancelled() {
            return Err(BackupError::GateNotReady("backup capture cancelled"));
        }
        let parsed = parse_validated_pg_uri(database_url)?;
        if let Some(snap) = snapshot_id
            && !valid_snapshot_id(snap)
        {
            return Err(BackupError::PgDump("invalid PostgreSQL snapshot ID"));
        }
        let pg_env = EphemeralPgEnv::create(&parsed)?;

        let mut cmd = Command::new(&self.program);
        // Scrub every inherited libpq PG* variable so only explicitly validated URL settings
        // reach pg_dump.
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("PG") {
                cmd.env_remove(&key);
            }
        }

        cmd.args(["--format=custom", "--schema=openmettle", "--no-owner"]);
        if let Some(snap) = snapshot_id {
            cmd.arg(format!("--snapshot={snap}"));
        }
        cmd.arg(format!("--host={}", parsed.host));
        cmd.arg(format!("--port={}", parsed.port));
        cmd.arg(format!("--username={}", parsed.username));
        cmd.arg(format!("--dbname={}", parsed.database));
        cmd.env("PGSSLMODE", &parsed.sslmode);
        cmd.env("PGGSSENCMODE", "disable");
        // Pin every libpq home-directory fallback path into the ephemeral 0700 directory so
        // libpq never consults $HOME/.postgresql/{root.crt,postgresql.crt,postgresql.key,root.crl},
        // $HOME/.pgpass, or $HOME/.pg_service.conf.
        cmd.env("PGPASSFILE", &pg_env.pgpass_file);
        match parsed.sslrootcert.as_deref() {
            Some(ca) => cmd.env("PGSSLROOTCERT", ca),
            None => cmd.env(
                "PGSSLROOTCERT",
                pg_env.nonexistent_path("nonexistent-root.crt"),
            ),
        };
        match parsed.sslcert.as_deref() {
            Some(cert) => cmd.env("PGSSLCERT", cert),
            None => cmd.env(
                "PGSSLCERT",
                pg_env.nonexistent_path("nonexistent-client.crt"),
            ),
        };
        match parsed.sslkey.as_deref() {
            Some(key) => cmd.env("PGSSLKEY", key),
            None => cmd.env(
                "PGSSLKEY",
                pg_env.nonexistent_path("nonexistent-client.key"),
            ),
        };
        cmd.env("PGSSLCRL", pg_env.nonexistent_path("nonexistent-root.crl"));
        cmd.env("PGSSLCRLDIR", pg_env.nonexistent_path("nonexistent-crldir"));
        cmd.env(
            "PGSERVICEFILE",
            pg_env.nonexistent_path("nonexistent-pg_service.conf"),
        );
        if let Some(app) = &parsed.application_name {
            cmd.env("PGAPPNAME", app);
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
        cancel.register_child(child);

        // Drain stderr on a helper thread so a noisy stderr cannot deadlock stdout streaming.
        let stderr_handle = std::thread::spawn(move || {
            let mut sink = Vec::new();
            let _ = stderr.by_ref().take(4096).read_to_end(&mut sink);
            let _ = io::copy(&mut stderr, &mut io::sink());
        });

        let mut buf = vec![0u8; crypto::CHUNK_SIZE];
        let mut total: u64 = 0;
        let copy_result: Result<(), BackupError> = loop {
            if cancel.is_cancelled() {
                break Err(BackupError::GateNotReady("backup capture cancelled"));
            }
            match stdout.read(&mut buf) {
                Ok(0) => {
                    if cancel.is_cancelled() {
                        break Err(BackupError::GateNotReady("backup capture cancelled"));
                    }
                    break Ok(());
                }
                Ok(n) => {
                    if cancel.is_cancelled() {
                        break Err(BackupError::GateNotReady("backup capture cancelled"));
                    }
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

        // Always close the stdout read pipe, keep the child reachable in `cancel` while reaping
        // (killing immediately on error or cancellation), then join stderr and unlink pg_env.
        drop(stdout);
        let status = cancel.wait_and_reap(copy_result.is_err() || cancel.is_cancelled());
        let _ = stderr_handle.join();
        drop(pg_env);

        copy_result?;
        if cancel.is_cancelled() {
            return Err(BackupError::GateNotReady("backup capture cancelled"));
        }
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

/// Write adapter that aborts blocking streaming steps promptly when cancellation is signaled.
/// Uses `io::ErrorKind::Other` (never `Interrupted`) so `Write::write_all` aborts immediately
/// instead of spinning in a retry loop.
struct CancelCheckingWriter<'a, W: Write> {
    inner: &'a mut W,
    cancel: DumpCancel,
}

impl<W: Write> Write for CancelCheckingWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.cancel.is_cancelled() {
            return Err(io::Error::other("backup capture cancelled"));
        }
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.cancel.is_cancelled() {
            return Err(io::Error::other("backup capture cancelled"));
        }
        self.inner.flush()
    }
}

// --- Graphiti / Neo4j, Chroma, and manifest structures ----------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraphitiMode {
    NotProvisioned,
    OfflineDump(PathBuf),
}

/// Explicit backup disposition for Chroma vector embeddings. Chroma is never assumed rebuildable
/// without an operator-supplied qualification reference (`QualifiedRebuild`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ChromaMode {
    #[default]
    NotProvisioned,
    Archive(PathBuf),
    QualifiedRebuild {
        qualification_ref: String,
    },
}

struct ExternalFileErrors {
    not_absolute: &'static str,
    unreadable: &'static str,
    empty: &'static str,
    protected_key: &'static str,
    changed: &'static str,
}

const NEO4J_DUMP_ERRORS: ExternalFileErrors = ExternalFileErrors {
    not_absolute: "--neo4j-dump path must be absolute",
    unreadable: "--neo4j-dump must be a readable non-symlink regular file",
    empty: "--neo4j-dump must be a non-empty regular file",
    protected_key: "--neo4j-dump refuses vault or backup key custody files",
    changed: "--neo4j-dump changed or was truncated during backup capture",
};

const CHROMA_ARCHIVE_ERRORS: ExternalFileErrors = ExternalFileErrors {
    not_absolute: "--chroma-archive path must be absolute",
    unreadable: "--chroma-archive must be a readable non-symlink regular file",
    empty: "--chroma-archive must be a non-empty regular file",
    protected_key: "--chroma-archive refuses vault or backup key custody files",
    changed: "--chroma-archive changed or was truncated during backup capture",
};

struct OpenedExternalFile {
    file: fs::File,
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    errors: &'static ExternalFileErrors,
}

impl OpenedExternalFile {
    fn open(
        path: &Path,
        protected_inodes: &BTreeSet<(u64, u64)>,
        errors: &'static ExternalFileErrors,
    ) -> Result<Self, BackupError> {
        if !path.is_absolute() {
            return Err(BackupError::Invalid(errors.not_absolute));
        }
        let file =
            open_regular_nofollow(path).map_err(|_| BackupError::Invalid(errors.unreadable))?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.len() == 0 {
            return Err(BackupError::Invalid(errors.empty));
        }
        if protected_inodes.contains(&(meta.dev(), meta.ino())) {
            return Err(BackupError::Invalid(errors.protected_key));
        }
        Ok(Self {
            file,
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            mtime: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            errors,
        })
    }

    fn verify_unchanged(&self, read_bytes: u64) -> Result<(), BackupError> {
        let meta = self.file.metadata()?;
        if read_bytes != self.len
            || read_bytes == 0
            || !meta.is_file()
            || meta.dev() != self.dev
            || meta.ino() != self.ino
            || meta.len() != self.len
            || meta.mtime() != self.mtime
            || meta.mtime_nsec() != self.mtime_nsec
        {
            return Err(BackupError::Integrity(self.errors.changed));
        }
        Ok(())
    }
}

pub fn validate_chroma_qualification_ref(reference: &str) -> Result<(), BackupError> {
    if reference.is_empty()
        || reference.len() > 256
        || reference.trim() != reference
        || !reference.bytes().all(|b| (0x20..=0x7e).contains(&b))
    {
        return Err(BackupError::Invalid("invalid --chroma-qualification-ref"));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ChromaManifest {
    NotProvisioned,
    Archive {
        component: String,
        plaintext_bytes: u64,
        plaintext_sha256: String,
    },
    QualifiedRebuild {
        qualification_ref: String,
    },
}

/// Canonical rebuildable-index inventory for a backup manifest. `chroma_vector_embeddings` is
/// listed ONLY when Chroma rebuildability has been explicitly qualified via
/// [`ChromaManifest::QualifiedRebuild`].
pub fn rebuildable_indexes_for(chroma: &ChromaManifest) -> Vec<String> {
    let mut indexes: Vec<String> = BASE_REBUILDABLE_INDEXES
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    if matches!(chroma, ChromaManifest::QualifiedRebuild { .. }) {
        indexes.push(CHROMA_REBUILDABLE_INDEX.to_owned());
    }
    indexes
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
    pub installation_id: String,
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
    pub chroma: ChromaManifest,
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
    pub installation_id: String,
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
        "SELECT g.installation_id::text,
                g.maintenance_active,
                g.backup_run_id::text,
                to_char(g.entered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                to_char(g.quiesced_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                g.reason,
                g.rpo_target_seconds,
                to_char(g.rpo_tracking_armed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'),
                to_char(t.last_overdue_observed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
           FROM openmettle.backup_maintenance_gate g
           JOIN openmettle.backup_rpo_telemetry_state t ON t.id = g.id
          WHERE g.id",
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
        installation_id: row.try_get(0)?,
        maintenance_active: row.try_get(1)?,
        active_backup_run_id: row.try_get(2)?,
        entered_at: row.try_get(3)?,
        quiesced_at: row.try_get(4)?,
        reason: row.try_get(5)?,
        rpo_target_seconds: row.try_get(6)?,
        rpo_tracking_armed_at: row.try_get(7)?,
        last_overdue_observed_at: row.try_get(8)?,
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

async fn release_capture_maintenance(
    pool: &PgPool,
    run_id: &str,
    operator_id: &str,
    reason: &str,
) -> Result<bool, BackupError> {
    let mut tx = read_committed(pool).await?;
    let released: bool = sqlx::query_scalar(
        "SELECT openmettle.backup_release_capture_maintenance($1::uuid, $2::uuid, $3)",
    )
    .bind(run_id)
    .bind(operator_id)
    .bind(reason)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(released)
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

struct StartedCapture {
    run_id: String,
    rpo_target_seconds: i32,
    installation_id: String,
}

async fn start_capture(
    pool: &PgPool,
    operator_id: &str,
    request_key: &str,
    reason: &str,
    destination_domain: &str,
    lease_seconds: i32,
) -> Result<StartedCapture, BackupError> {
    let mut tx = read_committed(pool).await?;
    let (run_id, rpo_target_seconds, installation_id): (String, i32, String) = sqlx::query_as(
        "SELECT backup_run_id::text, rpo_target_seconds, installation_id::text
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
    Ok(StartedCapture {
        run_id,
        rpo_target_seconds,
        installation_id,
    })
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
    snapshot_quiesced_at: &str,
    lease_seconds: i32,
) -> Result<String, BackupError> {
    let mut tx = read_committed(pool).await?;
    let quiesced_at: String = sqlx::query_scalar(
        "SELECT to_char(quiesced_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')
           FROM openmettle.backup_mark_quiesced($1::uuid, $2::timestamptz, $3)",
    )
    .bind(run_id)
    .bind(snapshot_quiesced_at)
    .bind(lease_seconds)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(quiesced_at)
}

async fn confirm_publication(pool: &PgPool, run_id: &str, reason: &str) -> Result<(), BackupError> {
    let mut tx = read_committed(pool).await?;
    sqlx::query("SELECT openmettle.backup_confirm_publication($1::uuid, $2)")
        .bind(run_id)
        .bind(reason)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
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

/// Independent background lease-renewal heartbeat for long-running capture steps (`pg_dump`,
/// artifact volume streaming, Neo4j encryption) so leases stay fresh across the entire capture.
struct LeaseHeartbeat {
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
    lease_lost: Arc<AtomicBool>,
}

impl LeaseHeartbeat {
    fn spawn(pool: PgPool, run_id: String, lease_seconds: i32) -> Self {
        let lease_lost = Arc::new(AtomicBool::new(false));
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        let hb_lost = Arc::clone(&lease_lost);
        let renew_every = Duration::from_secs(((lease_seconds as u64) / 3).clamp(1, 60));
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(renew_every);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await; // consume immediate first tick
            loop {
                tokio::select! {
                    _ = &mut stop_rx => break,
                    _ = ticker.tick() => {
                        if renew_lease(&pool, &run_id, lease_seconds).await.is_err() {
                            hb_lost.store(true, Ordering::Release);
                            break;
                        }
                    }
                }
            }
        });
        Self {
            stop_tx: Some(stop_tx),
            task: Some(task),
            lease_lost,
        }
    }

    fn lost_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.lease_lost)
    }

    fn is_lost(&self) -> bool {
        self.lease_lost.load(Ordering::Acquire)
    }

    async fn stop(mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for LeaseHeartbeat {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Run a blocking capture step (`pg_dump`, artifact archive, companion file encryption/fsync) on
/// the blocking pool while sending lightweight `SELECT 1` keepalives on `snap_tx` (protecting
/// against `idle_in_transaction_session_timeout`) and monitoring `lease_lost`. On cancellation,
/// signals [`DumpCancel`] (sending `SIGKILL` to any running `pg_dump` child) and awaits the
/// blocking handle so the child is reaped and file descriptors are closed before staging cleanup.
async fn run_blocking_with_keepalive<T, F>(
    snap_tx: &mut Transaction<'static, Postgres>,
    lease_lost: &AtomicBool,
    work: F,
) -> Result<T, BackupError>
where
    T: Send + 'static,
    F: FnOnce(DumpCancel) -> Result<T, BackupError> + Send + 'static,
{
    let cancel = DumpCancel::new();
    let cancel_bg = cancel.clone();
    let mut handle = tokio::task::spawn_blocking(move || work(cancel_bg));
    let mut keepalive = tokio::time::interval(SNAPSHOT_KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    keepalive.tick().await; // consume immediate first tick
    let mut cancel_poll = tokio::time::interval(Duration::from_millis(100));
    cancel_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    cancel_poll.tick().await;
    loop {
        tokio::select! {
            res = &mut handle => {
                let task_res = res.map_err(|_| BackupError::PgDump("backup worker task failed"))?;
                if lease_lost.load(Ordering::Acquire) {
                    return Err(BackupError::GateNotReady("backup capture lease lost"));
                }
                if cancel.is_cancelled() {
                    return Err(BackupError::GateNotReady("backup capture cancelled"));
                }
                return task_res;
            }
            _ = keepalive.tick() => {
                if let Err(err) = sqlx::query("SELECT 1").execute(&mut **snap_tx).await {
                    cancel.cancel();
                    let _ = (&mut handle).await;
                    return Err(err.into());
                }
            }
            _ = cancel_poll.tick() => {
                if lease_lost.load(Ordering::Acquire) {
                    cancel.cancel();
                    let _ = (&mut handle).await;
                    return Err(BackupError::GateNotReady("backup capture lease lost"));
                }
            }
        }
    }
}

/// Run a post-snapshot blocking I/O step (Neo4j/config/manifest encryption, `fsync_dir`) off the
/// Tokio executor thread so `LeaseHeartbeat` is never starved on slow destinations.
async fn run_blocking_with_lease_check<T, F>(
    lease_lost: &AtomicBool,
    work: F,
) -> Result<T, BackupError>
where
    T: Send + 'static,
    F: FnOnce(DumpCancel) -> Result<T, BackupError> + Send + 'static,
{
    let cancel = DumpCancel::new();
    let cancel_bg = cancel.clone();
    let mut handle = tokio::task::spawn_blocking(move || work(cancel_bg));
    let mut cancel_poll = tokio::time::interval(Duration::from_millis(100));
    cancel_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    cancel_poll.tick().await;
    loop {
        tokio::select! {
            res = &mut handle => {
                let task_res = res.map_err(|_| BackupError::PgDump("backup worker task failed"))?;
                if lease_lost.load(Ordering::Acquire) {
                    return Err(BackupError::GateNotReady("backup capture lease lost"));
                }
                if cancel.is_cancelled() {
                    return Err(BackupError::GateNotReady("backup capture cancelled"));
                }
                return task_res;
            }
            _ = cancel_poll.tick() => {
                if lease_lost.load(Ordering::Acquire) {
                    cancel.cancel();
                    let _ = (&mut handle).await;
                    return Err(BackupError::GateNotReady("backup capture lease lost"));
                }
            }
        }
    }
}

pub async fn poll_drain_counts(pool: &PgPool) -> Result<DrainCounts, BackupError> {
    let mut c = pool.acquire().await?;
    poll_drain_counts_conn(&mut c).await
}

/// Poll in-flight drain counts inside a short `READ COMMITTED` transaction whose pool acquisition,
/// `lock_timeout`, and `statement_timeout` are all bounded by the remaining `drain_timeout`
/// deadline so settings never leak to pooled connections and stalled DDL/queries map cleanly to
/// [`BackupError::DrainTimeout`].
async fn poll_drain_counts_bounded(
    pool: &PgPool,
    deadline: Instant,
    tokio_deadline: tokio::time::Instant,
    fallback_counts: DrainCounts,
) -> Result<DrainCounts, BackupError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(BackupError::DrainTimeout(fallback_counts));
    }
    let remaining_ms = u64::try_from(remaining.as_millis())
        .unwrap_or(u64::MAX)
        .max(1);
    let timeout_arg = format!("{remaining_ms}ms");

    let fut = async {
        let mut tx = read_committed(pool).await?;
        sqlx::query("SELECT pg_catalog.set_config('lock_timeout', $1, true)")
            .bind(&timeout_arg)
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT pg_catalog.set_config('statement_timeout', $1, true)")
            .bind(&timeout_arg)
            .execute(&mut *tx)
            .await?;
        let counts = poll_drain_counts_conn(&mut tx).await;
        match counts {
            Ok(c) => {
                tx.commit().await?;
                Ok(c)
            }
            Err(err) => {
                let _ = tx.rollback().await;
                Err(err)
            }
        }
    };

    match tokio::time::timeout_at(tokio_deadline, fut).await {
        Ok(Ok(counts)) => Ok(counts),
        Err(_) => Err(BackupError::DrainTimeout(fallback_counts)),
        Ok(Err(BackupError::Database(e))) if is_lock_timeout(&e) || is_statement_timeout(&e) => {
            Err(BackupError::DrainTimeout(fallback_counts))
        }
        Ok(Err(err)) => Err(err),
    }
}

async fn poll_drain_counts_conn(c: &mut PgConnection) -> Result<DrainCounts, BackupError> {
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
             WHERE state = 'reserved' OR (state = 'handed_off' AND NOT settled_final)),
           (SELECT count(*) FROM openmettle.external_connections
             WHERE refresh_lease_until IS NOT NULL AND refresh_lease_until > clock_timestamp()),
           (SELECT count(*) FROM openmettle.capacity_grants
             WHERE dispatch_state <> 'confirmed')",
    )
    .fetch_one(c)
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

async fn export_gateway_entitlements_json_conn(
    c: &mut PgConnection,
) -> Result<Vec<u8>, BackupError> {
    let defaults: Vec<String> = sqlx::query_scalar(
        "SELECT to_jsonb(d)::text FROM openmettle.quota_defaults d
          ORDER BY d.scope_kind, d.resource_kind",
    )
    .fetch_all(&mut *c)
    .await?;
    let overrides: Vec<String> = sqlx::query_scalar(
        "SELECT to_jsonb(o)::text FROM openmettle.quota_overrides o
          WHERE o.revoked_at IS NULL
          ORDER BY o.scope_id, o.resource_kind",
    )
    .fetch_all(&mut *c)
    .await?;
    let budgets: Vec<String> = sqlx::query_scalar(
        "SELECT to_jsonb(b)::text FROM openmettle.quota_budgets b
          ORDER BY b.target_kind, b.scope_id NULLS FIRST, b.resource_kind, b.window_kind, b.window_start",
    )
    .fetch_all(&mut *c)
    .await?;
    let family_policies: Vec<String> = sqlx::query_scalar(
        "SELECT to_jsonb(p)::text FROM openmettle.family_policies p ORDER BY p.id",
    )
    .fetch_all(&mut *c)
    .await?;
    let family_models: Vec<String> = sqlx::query_scalar(
        "SELECT to_jsonb(m)::text FROM openmettle.family_policy_models m
          ORDER BY m.policy_id, m.rule_kind, m.model",
    )
    .fetch_all(&mut *c)
    .await?;
    let gw_summary = sqlx::query(
        "SELECT
           (SELECT count(*) FROM openmettle.gateway_requests WHERE settled_final),
           (SELECT count(*) FROM openmettle.gateway_requests
             WHERE state = 'reserved' OR (state = 'handed_off' AND NOT settled_final)),
           (SELECT coalesce(sum(s.measured), 0)::text
              FROM openmettle.gateway_settlements s
             WHERE s.final),
           (SELECT coalesce(sum(r.prompt_tokens), 0)::text
              FROM openmettle.gateway_settlements s
              JOIN openmettle.gateway_usage_reports r
                ON r.request_id = s.request_id AND r.revision = s.revision
             WHERE s.final),
           (SELECT coalesce(sum(r.completion_tokens), 0)::text
              FROM openmettle.gateway_settlements s
              JOIN openmettle.gateway_usage_reports r
                ON r.request_id = s.request_id AND r.revision = s.revision
             WHERE s.final),
           (SELECT coalesce(sum(r.reasoning_tokens), 0)::text
              FROM openmettle.gateway_settlements s
              JOIN openmettle.gateway_usage_reports r
                ON r.request_id = s.request_id AND r.revision = s.revision
             WHERE s.final)",
    )
    .fetch_one(&mut *c)
    .await?;
    let settled_requests: i64 = gw_summary.try_get(0)?;
    let unsettled_requests: i64 = gw_summary.try_get(1)?;
    let total_measured_units: String = gw_summary.try_get(2)?;
    let total_prompt_tokens: String = gw_summary.try_get(3)?;
    let total_completion_tokens: String = gw_summary.try_get(4)?;
    let total_reasoning_tokens: String = gw_summary.try_get(5)?;

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

async fn load_vault_required_key_ids_conn(
    c: &mut PgConnection,
) -> Result<Vec<String>, BackupError> {
    let conn_keys: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT encryption_key_id
           FROM openmettle.external_connections
          WHERE encryption_key_id IS NOT NULL
          ORDER BY encryption_key_id",
    )
    .fetch_all(&mut *c)
    .await?;
    let mac_keys: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT details->>'mac_key_id'
           FROM openmettle.authorization_audit
          WHERE action = 'connection.authorized'
            AND details ? 'mac_key_id'
            AND details->>'mac_key_id' IS NOT NULL
          ORDER BY 1",
    )
    .fetch_all(&mut *c)
    .await?;
    let mut set = BTreeSet::new();
    for k in conn_keys.into_iter().chain(mac_keys) {
        if !k.is_empty() {
            set.insert(k);
        }
    }
    Ok(set.into_iter().collect())
}

async fn load_settled_artifact_records_conn(
    c: &mut PgConnection,
) -> Result<Vec<SettledArtifactRecord>, BackupError> {
    let rows = sqlx::query(
        "SELECT r.id::text, r.reservation_id::text, r.state, r.size_bytes,
                r.content_digest, s.payload_ino::text
           FROM openmettle.artifact_revisions r
           JOIN openmettle.storage_reservations s
             ON s.scope_id = r.scope_id AND s.id = r.reservation_id
          WHERE r.state IN ('active', 'retained', 'purging')
          ORDER BY r.reservation_id",
    )
    .fetch_all(c)
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
    Ok(out)
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

/// Options for [`capture`] and [`capture_with_runner`].
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
    pub chroma_mode: ChromaMode,
    pub config_files: Vec<(String, PathBuf)>,
    pub prune_policy: Option<GfsPolicy>,
    pub release_on_success: bool,
    /// Optional explicit `pg_dump` executable path (defaults to `"pg_dump"`).
    pub pg_dump_bin: Option<PathBuf>,
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

fn valid_backup_dir_name(name: &str, run_id: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && name != "."
        && name != ".."
        && name.starts_with("backup-")
        && name.ends_with(&format!("-{run_id}"))
}

fn default_pg_dump_runner(opts: &CaptureOptions) -> Result<Arc<dyn PgDumpRunner>, BackupError> {
    let runner = match &opts.pg_dump_bin {
        Some(bin) => {
            if bin.as_os_str().is_empty() {
                return Err(BackupError::Invalid("--pg-dump-bin must not be empty"));
            }
            CliPgDumpRunner::with_program(bin.clone())
        }
        None => CliPgDumpRunner::default(),
    };
    Ok(Arc::new(runner))
}

/// Run the full coordinated maintenance-window backup capture using the default real `pg_dump`
/// CLI runner (`CliPgDumpRunner`, honoring `opts.pg_dump_bin`).
pub async fn capture(
    pool: &PgPool,
    keyring: &BackupKeyRing,
    opts: &CaptureOptions,
) -> Result<CaptureReport, BackupError> {
    capture_with_runner(pool, keyring, opts, default_pg_dump_runner(opts)?).await
}

/// Run the full coordinated maintenance-window backup capture reusing a pre-validated
/// [`ValidatedPgPool`] directly (zero second pool opened, fitting cleanly inside a 3-connection
/// `openmettle_owner` limit alongside `pg_dump`) and using the default real `pg_dump` CLI runner.
pub async fn capture_validated(
    pool: &ValidatedPgPool,
    keyring: &BackupKeyRing,
    opts: &CaptureOptions,
) -> Result<CaptureReport, BackupError> {
    capture_validated_with_runner(pool, keyring, opts, default_pg_dump_runner(opts)?).await
}

/// Run the full coordinated maintenance-window backup capture reusing a pre-validated
/// [`ValidatedPgPool`] with a pluggable [`PgDumpRunner`]. Fails closed if the pool's validated
/// PostgreSQL configuration disagrees with `opts.database_url`.
pub async fn capture_validated_with_runner(
    pool: &ValidatedPgPool,
    keyring: &BackupKeyRing,
    opts: &CaptureOptions,
    pg_dump: Arc<dyn PgDumpRunner>,
) -> Result<CaptureReport, BackupError> {
    capture_inner(pool.pool(), Some(&pool.cfg), keyring, opts, pg_dump).await
}

enum CaptureFailure {
    /// Failed before PostgreSQL committed `backup_stage_publication` (or confirmed via a `FOR
    /// SHARE` read that publication did not commit): safe to delete staging and record
    /// `backup_fail_capture`.
    BeforeCommit(BackupError),
    /// Failed after PostgreSQL committed `backup_stage_publication` (or after an ambiguous stage
    /// commit whose DB state could not be read): preserve staging for exact-request-key retry and
    /// do not attempt to mark the run failed.
    PreserveStaging(BackupError),
}

/// Verify a published `final_dir` against `expected_meta` and `keyring`, then durably `fsync`
/// `final_dir/backup-meta.json`, `final_dir`, and `dest_root` before `confirm_publication`.
fn verify_and_sync_published_dir_blocking(
    dest_root: &Path,
    final_dir: &Path,
    expected_meta: &BackupMeta,
    keyring: &BackupKeyRing,
) -> Result<(), BackupError> {
    let (disk_meta, _) = load_and_verify_manifest(final_dir, keyring)?;
    if &disk_meta != expected_meta || !verify_backup_dir_for_prune(final_dir, &disk_meta, keyring) {
        return Err(BackupError::Integrity(
            "published backup directory disagrees with committed backup_runs record",
        ));
    }
    fsync_regular_file_nofollow(&final_dir.join("backup-meta.json"))?;
    fsync_dir(final_dir)?;
    fsync_dir(dest_root)?;
    Ok(())
}

/// Atomically publish `backup-meta.json` inside `staging_dir` using a CSPRNG-unique exclusive
/// `0600` temp file in `dest_root` (so concurrent exact-key publishers can never truncate each
/// other's marker inode and zero `.tmp` files ever enter `staging_dir` or `final_dir`), rename
/// `staging_dir -> final_dir`, handle concurrent publisher races by falling through to verifying
/// `final_dir`, and finish with full cryptographic verification + `fsync` of `backup-meta.json`,
/// `final_dir`, and `dest_root`.
fn publish_staged_dir_blocking(
    dest_root: &Path,
    staging_dir: &Path,
    final_dir: &Path,
    expected_meta: &BackupMeta,
    keyring: &BackupKeyRing,
) -> Result<(), BackupError> {
    let meta_bytes = serde_json::to_vec_pretty(expected_meta)
        .map_err(|_| BackupError::Integrity("backup-meta serialization failed"))?;
    let mut rnd = [0u8; 16];
    SystemRandom::new()
        .fill(&mut rnd)
        .map_err(|_| BackupError::Crypto(CryptoError::Random))?;
    let tmp_path = dest_root.join(format!(
        ".meta.{}.{}.tmp",
        expected_meta.backup_run_id,
        hex(&rnd)
    ));
    if let Err(err) = write_file_0600(&tmp_path, &meta_bytes) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err.into());
    }

    let meta_path = staging_dir.join("backup-meta.json");
    if let Err(err) = fs::rename(&tmp_path, &meta_path) {
        let _ = fs::remove_file(&tmp_path);
        if final_dir.exists() {
            return verify_and_sync_published_dir_blocking(
                dest_root,
                final_dir,
                expected_meta,
                keyring,
            );
        }
        return Err(err.into());
    }

    if let Err(err) = fsync_dir(staging_dir) {
        if final_dir.exists() {
            return verify_and_sync_published_dir_blocking(
                dest_root,
                final_dir,
                expected_meta,
                keyring,
            );
        }
        return Err(err.into());
    }

    if let Err(err) = fs::rename(staging_dir, final_dir) {
        if final_dir.exists() {
            return verify_and_sync_published_dir_blocking(
                dest_root,
                final_dir,
                expected_meta,
                keyring,
            );
        }
        return Err(err.into());
    }

    verify_and_sync_published_dir_blocking(dest_root, final_dir, expected_meta, keyring)
}

/// If an earlier invocation with the exact same `request_key`, `operator_id`, `destination_domain`,
/// and `reason` already reached `state IN ('publishing', 'succeeded')` in PostgreSQL before a crash
/// or destination error during marker write, rename, confirmation, pruning, or release,
/// idempotently verify and finalize publication on disk WITHOUT reopening `--neo4j-dump` or
/// `--config-file`.
async fn try_finalize_staged_or_succeeded_retry(
    pool: &PgPool,
    keyring: &BackupKeyRing,
    opts: &CaptureOptions,
    dest_root: &Path,
) -> Result<Option<CaptureReport>, BackupError> {
    let mut tx = read_committed(pool).await?;
    let row = sqlx::query(
        "SELECT id::text, operator_id::text, destination_domain, state,
                encryption_key_id, encode(bundle_digest, 'hex'), encode(manifest_digest, 'hex'),
                journal_seq, manifest_summary::text
           FROM openmettle.backup_runs
          WHERE request_key = $1
            FOR SHARE",
    )
    .bind(&opts.request_key)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let existing_run_id: String = row.try_get(0)?;
    let existing_operator: String = row.try_get(1)?;
    let existing_domain: String = row.try_get(2)?;
    let state: String = row.try_get(3)?;
    if !matches!(state.as_str(), "publishing" | "succeeded")
        || existing_operator != opts.operator_id
        || existing_domain != opts.destination_domain
    {
        return Ok(None);
    }

    let encryption_key_id: String = row
        .try_get::<Option<String>, _>(4)?
        .ok_or(BackupError::Integrity("committed run missing key_id"))?;
    let bundle_digest: String =
        row.try_get::<Option<String>, _>(5)?
            .ok_or(BackupError::Integrity(
                "committed run missing bundle_digest",
            ))?;
    let manifest_digest: String =
        row.try_get::<Option<String>, _>(6)?
            .ok_or(BackupError::Integrity(
                "committed run missing manifest_digest",
            ))?;
    let journal_seq: i64 = row
        .try_get::<Option<i64>, _>(7)?
        .ok_or(BackupError::Integrity("committed run missing journal_seq"))?;
    let summary_text: String = row.try_get(8)?;
    let summary: Value = serde_json::from_str(&summary_text)
        .map_err(|_| BackupError::Integrity("committed run summary malformed"))?;
    if summary.get("reason").and_then(Value::as_str) != Some(opts.reason.as_str()) {
        return Ok(None);
    }

    let installation_id = summary
        .get("installation_id")
        .and_then(Value::as_str)
        .ok_or(BackupError::Integrity(
            "committed run summary missing installation_id",
        ))?
        .to_owned();
    let completed_at = summary
        .get("completed_at")
        .and_then(Value::as_str)
        .ok_or(BackupError::Integrity(
            "committed run summary missing completed_at",
        ))?
        .to_owned();
    let manifest_ct_hex = summary
        .get("manifest_ciphertext_sha256")
        .and_then(Value::as_str)
        .ok_or(BackupError::Integrity(
            "committed run summary missing manifest_ciphertext_sha256",
        ))?
        .to_owned();
    let final_dir_name = summary
        .get("backup_dir_name")
        .and_then(Value::as_str)
        .ok_or(BackupError::Integrity(
            "committed run summary missing backup_dir_name",
        ))?
        .to_owned();
    if !valid_backup_dir_name(&final_dir_name, &existing_run_id) {
        return Err(BackupError::Integrity(
            "committed run summary contains invalid backup_dir_name",
        ));
    }

    let expected_meta = BackupMeta {
        format: META_FORMAT.to_owned(),
        installation_id: installation_id.clone(),
        backup_run_id: existing_run_id.clone(),
        completed_at,
        destination_domain: existing_domain,
        encryption_key_id: encryption_key_id.clone(),
        manifest_ciphertext_sha256: manifest_ct_hex,
        bundle_digest: bundle_digest.clone(),
        state: "complete".to_owned(),
    };

    let staging_dir = dest_root.join(format!(".staging.{existing_run_id}"));
    let final_dir = dest_root.join(&final_dir_name);

    {
        let dest_root_bg = dest_root.to_path_buf();
        let staging_dir_bg = staging_dir.clone();
        let final_dir_bg = final_dir.clone();
        let expected_meta_bg = expected_meta.clone();
        let keyring_bg = keyring.clone();
        tokio::task::spawn_blocking(move || -> Result<(), BackupError> {
            if final_dir_bg.exists() {
                verify_and_sync_published_dir_blocking(
                    &dest_root_bg,
                    &final_dir_bg,
                    &expected_meta_bg,
                    &keyring_bg,
                )?;
            } else if staging_dir_bg.is_dir() {
                match verify_staged_dir_against_meta(
                    &staging_dir_bg,
                    &expected_meta_bg,
                    &keyring_bg,
                ) {
                    Ok(()) => {
                        publish_staged_dir_blocking(
                            &dest_root_bg,
                            &staging_dir_bg,
                            &final_dir_bg,
                            &expected_meta_bg,
                            &keyring_bg,
                        )?;
                    }
                    Err(_) if final_dir_bg.exists() => {
                        verify_and_sync_published_dir_blocking(
                            &dest_root_bg,
                            &final_dir_bg,
                            &expected_meta_bg,
                            &keyring_bg,
                        )?;
                    }
                    Err(err) => return Err(err),
                }
            } else if final_dir_bg.is_dir() {
                verify_and_sync_published_dir_blocking(
                    &dest_root_bg,
                    &final_dir_bg,
                    &expected_meta_bg,
                    &keyring_bg,
                )?;
            } else {
                return Err(BackupError::Integrity(
                    "committed backup set missing both staging and final directories on retry",
                ));
            }
            Ok(())
        })
        .await
        .map_err(|_| BackupError::PgDump("retry publication task failed"))??;
    }

    // Confirm publication (`publishing -> succeeded`; idempotent when already `succeeded`).
    confirm_publication(pool, &existing_run_id, &opts.reason).await?;

    let pruned = match opts.prune_policy {
        Some(policy) => {
            let dest_root_bg = dest_root.to_path_buf();
            let inst_bg = installation_id.clone();
            let dom_bg = opts.destination_domain.clone();
            let keyring_bg = keyring.clone();
            let report = tokio::task::spawn_blocking(move || {
                prune_destination_with_verifier(
                    &dest_root_bg,
                    policy,
                    Some((inst_bg.as_str(), dom_bg.as_str())),
                    false,
                    |dir, m| verify_backup_dir_for_prune(dir, m, &keyring_bg),
                )
            })
            .await
            .map_err(|_| BackupError::PgDump("prune task failed"))??;
            Some(report)
        }
        None => None,
    };

    let released_maintenance = if opts.release_on_success {
        release_capture_maintenance(pool, &existing_run_id, &opts.operator_id, &opts.reason).await?
    } else {
        false
    };

    Ok(Some(CaptureReport {
        backup_run_id: existing_run_id,
        backup_dir: final_dir,
        encryption_key_id,
        bundle_digest,
        manifest_digest,
        journal_seq,
        pruned,
        released_maintenance,
    }))
}

/// Run the full coordinated maintenance-window backup capture with a pluggable [`PgDumpRunner`].
/// On any failure confirmed before PostgreSQL stages publication (`backup_stage_publication`),
/// partial staging files are removed, `backup_runs` transitions to `failed`, and
/// `backup_maintenance_gate.maintenance_active` stays `true` for explicit operator recovery.
pub async fn capture_with_runner(
    pool: &PgPool,
    keyring: &BackupKeyRing,
    opts: &CaptureOptions,
    pg_dump: Arc<dyn PgDumpRunner>,
) -> Result<CaptureReport, BackupError> {
    capture_inner(pool, None, keyring, opts, pg_dump).await
}

async fn capture_inner(
    pool: &PgPool,
    already_validated: Option<&ValidatedPgConfig>,
    keyring: &BackupKeyRing,
    opts: &CaptureOptions,
    pg_dump: Arc<dyn PgDumpRunner>,
) -> Result<CaptureReport, BackupError> {
    // 1. Validate arguments, database URL allow-list + SQLx/TLS parity, and destination isolation
    //    BEFORE touching the database maintenance window or external source files.
    runs::uuid(&opts.operator_id)
        .map_err(|_| BackupError::Invalid("invalid --operator-id UUID"))?;
    validate_destination_domain(&opts.destination_domain)?;
    if let ChromaMode::QualifiedRebuild { qualification_ref } = &opts.chroma_mode {
        validate_chroma_qualification_ref(qualification_ref)?;
    }
    let validated_pg = parse_validated_pg_uri(&opts.database_url)?;
    let _ = validated_pg.to_sqlx_options()?;
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

    // Reuse an already-validated `ValidatedPgPool` directly when its configuration matches
    // `opts.database_url` (zero second pool opened, staying within 2 SQLx + 1 pg_dump sessions).
    // For legacy callers passing a raw `&PgPool` with `verify-ca` / `verify-full`, open an
    // internal `ValidatedPgPool` (`max_connections = 2`) to enforce strict `sslrootcert`-only
    // verification across every connection and reconnect.
    let strict_pool = match already_validated {
        Some(pool_cfg) => {
            if pool_cfg != &validated_pg {
                return Err(BackupError::PgDump(
                    "validated PostgreSQL pool configuration disagrees with capture database URL",
                ));
            }
            None
        }
        None if matches!(validated_pg.sslmode.as_str(), "verify-ca" | "verify-full") => {
            Some(connect_validated_pool(&validated_pg, 2).await?)
        }
        None => None,
    };
    let active_pool = strict_pool.as_ref().map_or(pool, ValidatedPgPool::pool);

    let result = async {
        // 2. Check for an existing `publishing` or `succeeded` run for this exact request_key
        //    BEFORE opening `--neo4j-dump`, `--chroma-archive`, or `--config-file`, so retrying an
        //    interrupted publication works even after source files have moved or changed.
        if let Some(report) =
            try_finalize_staged_or_succeeded_retry(active_pool, keyring, opts, &dest_root).await?
        {
            return Ok(report);
        }

        // 3. Validate non-secret config files and optional external archives (including backup and
        //    vault key-custody inode checks) BEFORE entering maintenance.
        let protected_key_inodes = collect_protected_key_inodes(keyring.paths())?;
        let bundled_configs = load_non_secret_config_files(&opts.config_files, keyring.paths())?;
        let opened_neo4j = match &opts.graphiti_mode {
            GraphitiMode::NotProvisioned => None,
            GraphitiMode::OfflineDump(neo4j_path) => Some(OpenedExternalFile::open(
                neo4j_path,
                &protected_key_inodes,
                &NEO4J_DUMP_ERRORS,
            )?),
        };
        let opened_chroma = match &opts.chroma_mode {
            ChromaMode::Archive(chroma_path) => Some(OpenedExternalFile::open(
                chroma_path,
                &protected_key_inodes,
                &CHROMA_ARCHIVE_ERRORS,
            )?),
            ChromaMode::NotProvisioned | ChromaMode::QualifiedRebuild { .. } => None,
        };

        // 4. Enter maintenance (or inherit an existing maintenance window) and allocate a leased
        //    `draining` backup_runs row.
        let started = start_capture(
            active_pool,
            &opts.operator_id,
            &opts.request_key,
            &opts.reason,
            &opts.destination_domain,
            opts.lease_seconds,
        )
        .await?;

        let staging_dir = dest_root.join(format!(".staging.{}", started.run_id));
        let outcome = capture_body(
            active_pool,
            keyring,
            opts,
            pg_dump,
            &dest_root,
            &staging_dir,
            &started,
            bundled_configs,
            opened_neo4j,
            opened_chroma,
        )
        .await;

        match outcome {
            Ok(report) => Ok(report),
            Err(CaptureFailure::BeforeCommit(err)) => {
                let staging_cleanup = staging_dir.clone();
                let _ =
                    tokio::task::spawn_blocking(move || fs::remove_dir_all(&staging_cleanup)).await;
                let fail_reason = format!("backup capture failed ({})", err.failure_code());
                fail_capture(
                    active_pool,
                    &started.run_id,
                    err.failure_code(),
                    &fail_reason,
                )
                .await;
                Err(err)
            }
            Err(CaptureFailure::PreserveStaging(err)) => Err(err),
        }
    }
    .await;

    if let Some(sp) = strict_pool {
        sp.close().await;
    }
    result
}

fn is_serialization_failure(err: &sqlx::Error) -> bool {
    matches!(
        err,
        sqlx::Error::Database(db) if db.code().as_deref() == Some("40001")
    )
}

fn is_lock_timeout(err: &sqlx::Error) -> bool {
    matches!(
        err,
        sqlx::Error::Database(db) if db.code().as_deref() == Some("55P03")
    )
}

fn is_statement_timeout(err: &sqlx::Error) -> bool {
    matches!(
        err,
        sqlx::Error::Database(db) if db.code().as_deref() == Some("57014")
    )
}

async fn encrypt_external_file(
    mut opened: OpenedExternalFile,
    out_path: PathBuf,
    role: &'static str,
    keyring: &BackupKeyRing,
    run_id: &str,
    lease_lost: &AtomicBool,
) -> Result<EncryptedStats, CaptureFailure> {
    let keyring_bg = keyring.clone();
    let run_id_bg = run_id.to_owned();
    run_blocking_with_lease_check(lease_lost, move |cancel| {
        opened.file.seek(SeekFrom::Start(0))?;
        let mut out = open_new_file_0600(&out_path)?;
        let mut enc = StreamEncryptor::start(&keyring_bg, &run_id_bg, role, &mut out)?;
        let mut buf = vec![0u8; crypto::CHUNK_SIZE];
        {
            let mut guarded = CancelCheckingWriter {
                inner: &mut enc,
                cancel,
            };
            loop {
                let n = opened.file.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                guarded.write_all(&buf[..n])?;
            }
        }
        let stats = enc.finish()?;
        out.sync_all()?;
        opened.verify_unchanged(stats.plaintext_bytes)?;
        Ok(stats)
    })
    .await
    .map_err(CaptureFailure::BeforeCommit)
}

#[allow(clippy::too_many_arguments)]
async fn capture_body(
    pool: &PgPool,
    keyring: &BackupKeyRing,
    opts: &CaptureOptions,
    pg_dump: Arc<dyn PgDumpRunner>,
    dest_root: &Path,
    staging_dir: &Path,
    started: &StartedCapture,
    bundled_configs: Vec<BundledConfigFile>,
    opened_neo4j: Option<OpenedExternalFile>,
    opened_chroma: Option<OpenedExternalFile>,
) -> Result<CaptureReport, CaptureFailure> {
    let run_id = &started.run_id;
    let installation_id = &started.installation_id;
    let rpo_target_seconds = started.rpo_target_seconds;

    let heartbeat = LeaseHeartbeat::spawn(pool.clone(), run_id.clone(), opts.lease_seconds);
    let lease_lost = heartbeat.lost_flag();

    // 5. Poll drain loop and acquire one exported REPEATABLE READ snapshot holding bounded
    //    `FOR SHARE` locks on `restore_reconciliation_gate` and `storage_volume_control`.
    let deadline = Instant::now() + opts.drain_timeout;
    let tokio_deadline = tokio::time::Instant::from_std(deadline);
    let mut last_counts = DrainCounts::default();
    let (mut snap_tx, snapshot_id, snapshot_ts, pinned_volume_id) = loop {
        if heartbeat.is_lost() {
            return Err(CaptureFailure::BeforeCommit(BackupError::GateNotReady(
                "backup capture lease lost during drain",
            )));
        }
        let counts = poll_drain_counts_bounded(pool, deadline, tokio_deadline, last_counts)
            .await
            .map_err(CaptureFailure::BeforeCommit)?;
        last_counts = counts;
        if !counts.is_quiesced() {
            if Instant::now() >= deadline {
                return Err(CaptureFailure::BeforeCommit(BackupError::DrainTimeout(
                    counts,
                )));
            }
            tokio::time::sleep(DRAIN_POLL_INTERVAL).await;
            continue;
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(CaptureFailure::BeforeCommit(BackupError::DrainTimeout(
                counts,
            )));
        }
        let remaining_ms = u64::try_from(remaining.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let timeout_arg = format!("{remaining_ms}ms");

        let (mut tx, snap_id, snap_ts) = match tokio::time::timeout_at(tokio_deadline, async {
            let mut tx = pool.begin().await?;
            sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                .execute(&mut *tx)
                .await?;
            sqlx::query("SET LOCAL idle_in_transaction_session_timeout = '300s'")
                .execute(&mut *tx)
                .await?;
            // Bound snapshot export, FOR SHARE waits, and quiesce verification by the remaining
            // drain deadline via PostgreSQL lock_timeout + statement_timeout and Tokio timeout_at.
            sqlx::query("SELECT pg_catalog.set_config('lock_timeout', $1, true)")
                .bind(&timeout_arg)
                .execute(&mut *tx)
                .await?;
            sqlx::query("SELECT pg_catalog.set_config('statement_timeout', $1, true)")
                .bind(&timeout_arg)
                .execute(&mut *tx)
                .await?;
            let (snap_id, snap_ts): (String, String) = sqlx::query_as(
                "SELECT pg_catalog.pg_export_snapshot(),
                        to_char(
                            pg_catalog.transaction_timestamp() AT TIME ZONE 'UTC',
                            'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'
                        )",
            )
            .fetch_one(&mut *tx)
            .await?;
            Ok::<_, sqlx::Error>((tx, snap_id, snap_ts))
        })
        .await
        {
            Ok(Ok(v)) => v,
            Err(_) => {
                return Err(CaptureFailure::BeforeCommit(BackupError::DrainTimeout(
                    counts,
                )));
            }
            Ok(Err(e)) if is_lock_timeout(&e) || is_statement_timeout(&e) => {
                return Err(CaptureFailure::BeforeCommit(BackupError::DrainTimeout(
                    counts,
                )));
            }
            Ok(Err(e)) => return Err(CaptureFailure::BeforeCommit(e.into())),
        };

        // Lock restore_reconciliation_gate and storage_volume_control FOR SHARE inside the
        // exported snapshot transaction so neither restore lock nor storage adoption/rebind can
        // race with snapshot verification, pg_dump, journal export, or artifact streaming.
        let gate_open: bool = match tokio::time::timeout_at(
            tokio_deadline,
            sqlx::query_scalar::<_, bool>(
                "SELECT open FROM openmettle.restore_reconciliation_gate WHERE id FOR SHARE",
            )
            .fetch_one(&mut *tx),
        )
        .await
        {
            Ok(Ok(v)) => v,
            Err(_) => {
                let _ = tx.rollback().await;
                return Err(CaptureFailure::BeforeCommit(BackupError::DrainTimeout(
                    counts,
                )));
            }
            Ok(Err(e)) if is_lock_timeout(&e) || is_statement_timeout(&e) => {
                let _ = tx.rollback().await;
                return Err(CaptureFailure::BeforeCommit(BackupError::DrainTimeout(
                    counts,
                )));
            }
            Ok(Err(e)) if is_serialization_failure(&e) => {
                let _ = tx.rollback().await;
                if Instant::now() >= deadline {
                    return Err(CaptureFailure::BeforeCommit(BackupError::GateNotReady(
                        "restore_reconciliation_gate changed concurrently during quiesce",
                    )));
                }
                tokio::time::sleep(DRAIN_POLL_INTERVAL).await;
                continue;
            }
            Ok(Err(e)) => return Err(CaptureFailure::BeforeCommit(e.into())),
        };
        if !gate_open {
            let _ = tx.rollback().await;
            return Err(CaptureFailure::BeforeCommit(BackupError::GateNotReady(
                "restore_reconciliation_gate is closed",
            )));
        }

        let remaining_vol = deadline.saturating_duration_since(Instant::now());
        if remaining_vol.is_zero() {
            let _ = tx.rollback().await;
            return Err(CaptureFailure::BeforeCommit(BackupError::DrainTimeout(
                counts,
            )));
        }
        let remaining_vol_ms = u64::try_from(remaining_vol.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let vol_timeout_arg = format!("{remaining_vol_ms}ms");
        match tokio::time::timeout_at(tokio_deadline, async {
            sqlx::query("SELECT pg_catalog.set_config('lock_timeout', $1, true)")
                .bind(&vol_timeout_arg)
                .execute(&mut *tx)
                .await?;
            sqlx::query("SELECT pg_catalog.set_config('statement_timeout', $1, true)")
                .bind(&vol_timeout_arg)
                .execute(&mut *tx)
                .await?;
            Ok::<_, sqlx::Error>(())
        })
        .await
        {
            Ok(Ok(())) => {}
            Err(_) => {
                let _ = tx.rollback().await;
                return Err(CaptureFailure::BeforeCommit(BackupError::DrainTimeout(
                    counts,
                )));
            }
            Ok(Err(e)) if is_lock_timeout(&e) || is_statement_timeout(&e) => {
                let _ = tx.rollback().await;
                return Err(CaptureFailure::BeforeCommit(BackupError::DrainTimeout(
                    counts,
                )));
            }
            Ok(Err(e)) => return Err(CaptureFailure::BeforeCommit(e.into())),
        }

        let (vol_id, adoption_run_id): (Option<String>, Option<String>) =
            match tokio::time::timeout_at(
                tokio_deadline,
                sqlx::query_as::<_, (Option<String>, Option<String>)>(
                    "SELECT volume_id::text, adoption_run_id::text
                       FROM openmettle.storage_volume_control
                      WHERE id
                        FOR SHARE",
                )
                .fetch_one(&mut *tx),
            )
            .await
            {
                Ok(Ok(v)) => v,
                Err(_) => {
                    let _ = tx.rollback().await;
                    return Err(CaptureFailure::BeforeCommit(BackupError::DrainTimeout(
                        counts,
                    )));
                }
                Ok(Err(e)) if is_lock_timeout(&e) || is_statement_timeout(&e) => {
                    let _ = tx.rollback().await;
                    return Err(CaptureFailure::BeforeCommit(BackupError::DrainTimeout(
                        counts,
                    )));
                }
                Ok(Err(e)) if is_serialization_failure(&e) => {
                    let _ = tx.rollback().await;
                    if Instant::now() >= deadline {
                        return Err(CaptureFailure::BeforeCommit(BackupError::GateNotReady(
                            "storage_volume_control changed concurrently during quiesce",
                        )));
                    }
                    tokio::time::sleep(DRAIN_POLL_INTERVAL).await;
                    continue;
                }
                Ok(Err(e)) => return Err(CaptureFailure::BeforeCommit(e.into())),
            };
        if adoption_run_id.is_some() {
            let _ = tx.rollback().await;
            return Err(CaptureFailure::BeforeCommit(BackupError::GateNotReady(
                "storage adoption or rebind barrier is active",
            )));
        }

        // Keep lock_timeout and statement_timeout bounded to the remaining drain budget while
        // verifying quiescence inside the exported snapshot BEFORE clearing both timeouts.
        let remaining_snap = deadline.saturating_duration_since(Instant::now());
        if remaining_snap.is_zero() {
            let _ = tx.rollback().await;
            return Err(CaptureFailure::BeforeCommit(BackupError::DrainTimeout(
                counts,
            )));
        }
        let remaining_snap_ms = u64::try_from(remaining_snap.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let snap_timeout_arg = format!("{remaining_snap_ms}ms");
        let snap_counts = match tokio::time::timeout_at(tokio_deadline, async {
            sqlx::query("SELECT pg_catalog.set_config('lock_timeout', $1, true)")
                .bind(&snap_timeout_arg)
                .execute(&mut *tx)
                .await?;
            sqlx::query("SELECT pg_catalog.set_config('statement_timeout', $1, true)")
                .bind(&snap_timeout_arg)
                .execute(&mut *tx)
                .await?;
            poll_drain_counts_conn(&mut tx).await
        })
        .await
        {
            Ok(Ok(v)) => v,
            Err(_) => {
                let _ = tx.rollback().await;
                return Err(CaptureFailure::BeforeCommit(BackupError::DrainTimeout(
                    counts,
                )));
            }
            Ok(Err(BackupError::Database(e)))
                if is_lock_timeout(&e) || is_statement_timeout(&e) =>
            {
                let _ = tx.rollback().await;
                return Err(CaptureFailure::BeforeCommit(BackupError::DrainTimeout(
                    counts,
                )));
            }
            Ok(Err(e)) => {
                let _ = tx.rollback().await;
                return Err(CaptureFailure::BeforeCommit(e));
            }
        };
        last_counts = snap_counts;
        if !snap_counts.is_quiesced() {
            let _ = tx.rollback().await;
            if Instant::now() >= deadline {
                return Err(CaptureFailure::BeforeCommit(BackupError::DrainTimeout(
                    snap_counts,
                )));
            }
            tokio::time::sleep(DRAIN_POLL_INTERVAL).await;
            continue;
        }

        // Clear drain timeouts now that both quiesce barriers are held and quiescence is verified.
        sqlx::query("SELECT pg_catalog.set_config('lock_timeout', '0', true)")
            .execute(&mut *tx)
            .await
            .map_err(|e| CaptureFailure::BeforeCommit(e.into()))?;
        sqlx::query("SELECT pg_catalog.set_config('statement_timeout', '0', true)")
            .execute(&mut *tx)
            .await
            .map_err(|e| CaptureFailure::BeforeCommit(e.into()))?;

        break (tx, snap_id, snap_ts, vol_id);
    };

    // 6. Verify accounting and filesystem drift inside the exact exported snapshot BEFORE marking
    //    the backup run `capturing`.
    if pinned_volume_id.is_some() && opts.artifact_root.is_none() {
        let _ = snap_tx.rollback().await;
        return Err(CaptureFailure::BeforeCommit(BackupError::Invalid(
            "--artifact-root is required when the artifact storage volume is pinned",
        )));
    }
    let store = opts
        .artifact_root
        .as_deref()
        .map(Store::open_existing)
        .transpose()
        .map_err(|_| {
            CaptureFailure::BeforeCommit(BackupError::Invalid(
                "--artifact-root could not be opened",
            ))
        })?;
    let drift = match store.as_ref() {
        Some(store) => {
            let pin = store
                .prepare_pin_on(&mut snap_tx)
                .await
                .map_err(|e| CaptureFailure::BeforeCommit(e.into()))?
                .ok_or_else(|| {
                    CaptureFailure::BeforeCommit(BackupError::Storage(artifact_fs::Error::Io))
                })?;
            artifact_fs::verify_volume_on(&mut snap_tx, store, &pin, Duration::from_secs(15))
                .await
                .map_err(|e| CaptureFailure::BeforeCommit(e.into()))?
        }
        None => {
            let report = artifact_fs::verify_ledgers_on(&mut snap_tx)
                .await
                .map_err(|e| CaptureFailure::BeforeCommit(e.into()))?;
            let disabled: bool = sqlx::query_scalar(
                "SELECT volume_id IS NULL AND adoption_run_id IS NULL
                    AND NOT EXISTS (SELECT FROM openmettle.storage_reservations)
                    AND NOT EXISTS (SELECT FROM openmettle.artifact_revisions)
                   FROM openmettle.storage_volume_control
                  WHERE id",
            )
            .fetch_one(&mut *snap_tx)
            .await
            .map_err(|e| CaptureFailure::BeforeCommit(e.into()))?;
            if !disabled {
                let _ = snap_tx.rollback().await;
                return Err(CaptureFailure::BeforeCommit(BackupError::Storage(
                    artifact_fs::Error::Io,
                )));
            }
            report
        }
    };
    if !drift.healthy() {
        let _ = snap_tx.rollback().await;
        return Err(CaptureFailure::BeforeCommit(BackupError::DriftDetected));
    }

    let settled_records = load_settled_artifact_records_conn(&mut snap_tx)
        .await
        .map_err(CaptureFailure::BeforeCommit)?;

    let quiesced_at = mark_quiesced(pool, run_id, &snapshot_ts, opts.lease_seconds)
        .await
        .map_err(CaptureFailure::BeforeCommit)?;

    // 7. Capture and stream-encrypt all recovery-set components into `.staging.<run_id>` from
    //    the single exported snapshot, routing all blocking disk/process I/O onto `spawn_blocking`
    //    so `LeaseHeartbeat` and snapshot keepalives are never starved.
    {
        let staging_dir_bg = staging_dir.to_path_buf();
        run_blocking_with_keepalive(&mut snap_tx, &lease_lost, move |_cancel| {
            create_dir_0700(&staging_dir_bg)?;
            Ok(())
        })
        .await
        .map_err(CaptureFailure::BeforeCommit)?;
    }
    let mut components: BTreeMap<String, ComponentManifest> = BTreeMap::new();

    // 7a. PostgreSQL logical custom dump (`pg.dump.enc`) synchronized to `snapshot_id`.
    let pg_stats = {
        let pg_dump_path = staging_dir.join("pg.dump.enc");
        let keyring_bg = keyring.clone();
        let run_id_bg = run_id.clone();
        let db_url_bg = opts.database_url.clone();
        let snap_id_bg = snapshot_id.clone();
        let runner_bg = Arc::clone(&pg_dump);
        run_blocking_with_keepalive(&mut snap_tx, &lease_lost, move |cancel| {
            let mut out_file = open_new_file_0600(&pg_dump_path)?;
            let mut enc =
                StreamEncryptor::start(&keyring_bg, &run_id_bg, "pg_dump", &mut out_file)?;
            {
                let mut guarded = CancelCheckingWriter {
                    inner: &mut enc,
                    cancel: cancel.clone(),
                };
                runner_bg.dump(&db_url_bg, Some(&snap_id_bg), &cancel, &mut guarded)?;
            }
            let stats = enc.finish()?;
            out_file.sync_all()?;
            Ok(stats)
        })
        .await
        .map_err(CaptureFailure::BeforeCommit)?
    };
    components.insert(
        "pg.dump.enc".to_owned(),
        component_manifest("pg_dump", &pg_stats),
    );

    // 7b. Authoritative PostgreSQL gateway entitlements & usage snapshot (`gateway-entitlements.json.enc`).
    let gw_bytes = export_gateway_entitlements_json_conn(&mut snap_tx)
        .await
        .map_err(CaptureFailure::BeforeCommit)?;
    let gw_stats = {
        let gw_path = staging_dir.join("gateway-entitlements.json.enc");
        let keyring_bg = keyring.clone();
        let run_id_bg = run_id.clone();
        run_blocking_with_keepalive(&mut snap_tx, &lease_lost, move |_cancel| {
            encrypt_bytes_to_file(
                &keyring_bg,
                &run_id_bg,
                "gateway_entitlements",
                &gw_bytes,
                &gw_path,
            )
        })
        .await
        .map_err(CaptureFailure::BeforeCommit)?
    };
    components.insert(
        "gateway-entitlements.json.enc".to_owned(),
        component_manifest("gateway_entitlements", &gw_stats),
    );

    // 7c. Deletion journal export (`deletion-journal.bin.enc`) from the same exported snapshot.
    let journal_text = restore::export_conn(&mut snap_tx)
        .await
        .map_err(|e| CaptureFailure::BeforeCommit(e.into()))?;
    let parsed_export =
        Export::parse(&journal_text).map_err(|e| CaptureFailure::BeforeCommit(e.into()))?;
    let journal_stats = {
        let journal_path = staging_dir.join("deletion-journal.bin.enc");
        let keyring_bg = keyring.clone();
        let run_id_bg = run_id.clone();
        let journal_bytes = journal_text.into_bytes();
        run_blocking_with_keepalive(&mut snap_tx, &lease_lost, move |_cancel| {
            encrypt_bytes_to_file(
                &keyring_bg,
                &run_id_bg,
                "deletion_journal",
                &journal_bytes,
                &journal_path,
            )
        })
        .await
        .map_err(CaptureFailure::BeforeCommit)?
    };
    components.insert(
        "deletion-journal.bin.enc".to_owned(),
        component_manifest("deletion_journal", &journal_stats),
    );

    // 7d. Generic PVC POSIX artifact archive (`artifacts.bin.enc`), live SHA-256 verified while
    //     `snap_tx` still holds `FOR SHARE` on `restore_reconciliation_gate` & `storage_volume_control`.
    let (artifact_summary, artifact_stats) = {
        let artifacts_path = staging_dir.join("artifacts.bin.enc");
        let keyring_bg = keyring.clone();
        let run_id_bg = run_id.clone();
        let art_root_bg = opts.artifact_root.clone();
        let vol_id_bg = pinned_volume_id.clone();
        run_blocking_with_keepalive(&mut snap_tx, &lease_lost, move |cancel| {
            let mut out_file = open_new_file_0600(&artifacts_path)?;
            let mut enc =
                StreamEncryptor::start(&keyring_bg, &run_id_bg, "artifacts", &mut out_file)?;
            let summary = {
                let mut guarded = CancelCheckingWriter {
                    inner: &mut enc,
                    cancel,
                };
                write_artifact_archive(
                    art_root_bg.as_deref(),
                    vol_id_bg.as_deref(),
                    &settled_records,
                    &mut guarded,
                )?
            };
            let stats = enc.finish()?;
            out_file.sync_all()?;
            Ok((summary, stats))
        })
        .await
        .map_err(CaptureFailure::BeforeCommit)?
    };
    components.insert(
        "artifacts.bin.enc".to_owned(),
        component_manifest("artifacts", &artifact_stats),
    );

    // Collect remaining snapshot-consistent metadata from `snap_tx` and release snapshot.
    let vault_required_key_ids = load_vault_required_key_ids_conn(&mut snap_tx)
        .await
        .map_err(CaptureFailure::BeforeCommit)?;
    let schema_version: i64 = sqlx::query_scalar(
        "SELECT coalesce(max(version), 0) FROM openmettle._sqlx_migrations WHERE success",
    )
    .fetch_one(&mut *snap_tx)
    .await
    .map_err(|e| CaptureFailure::BeforeCommit(e.into()))?;
    snap_tx
        .commit()
        .await
        .map_err(|e| CaptureFailure::BeforeCommit(e.into()))?;

    // 7e. Optional Graphiti / Neo4j offline dump (`neo4j.dump.enc`) and optional Chroma archive
    //     (`chroma.archive.enc`) from preflight-opened descriptors, verified unchanged across
    //     encryption.
    let graphiti_manifest = match opened_neo4j {
        None => GraphitiManifest::NotProvisioned,
        Some(neo4j) => {
            let stats = encrypt_external_file(
                neo4j,
                staging_dir.join("neo4j.dump.enc"),
                "neo4j_dump",
                keyring,
                run_id,
                &lease_lost,
            )
            .await?;
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
    let chroma_manifest = match (&opts.chroma_mode, opened_chroma) {
        (ChromaMode::NotProvisioned, None) => ChromaManifest::NotProvisioned,
        (ChromaMode::Archive(_), Some(chroma)) => {
            let stats = encrypt_external_file(
                chroma,
                staging_dir.join("chroma.archive.enc"),
                "chroma_archive",
                keyring,
                run_id,
                &lease_lost,
            )
            .await?;
            let comp = component_manifest("chroma_archive", &stats);
            let cm = ChromaManifest::Archive {
                component: "chroma.archive.enc".to_owned(),
                plaintext_bytes: comp.plaintext_bytes,
                plaintext_sha256: comp.plaintext_sha256.clone(),
            };
            components.insert("chroma.archive.enc".to_owned(), comp);
            cm
        }
        (ChromaMode::QualifiedRebuild { qualification_ref }, None) => {
            ChromaManifest::QualifiedRebuild {
                qualification_ref: qualification_ref.clone(),
            }
        }
        _ => {
            return Err(CaptureFailure::BeforeCommit(BackupError::Invalid(
                "inconsistent chroma backup mode state",
            )));
        }
    };
    let rebuildable_indexes = rebuildable_indexes_for(&chroma_manifest);

    // 7f. Non-secret config files + required vault key-ID inventory (`config.json.enc`).
    let config_bundle = ConfigBundle {
        format: "openmettle-backup-config/v1".to_owned(),
        vault_required_key_ids: vault_required_key_ids.clone(),
        files: bundled_configs,
    };
    let config_bytes = serde_json::to_vec_pretty(&config_bundle).map_err(|_| {
        CaptureFailure::BeforeCommit(BackupError::Integrity("config bundle serialization failed"))
    })?;
    let config_stats = {
        let config_path = staging_dir.join("config.json.enc");
        let keyring_bg = keyring.clone();
        let run_id_bg = run_id.clone();
        run_blocking_with_lease_check(&lease_lost, move |_cancel| {
            encrypt_bytes_to_file(
                &keyring_bg,
                &run_id_bg,
                "config",
                &config_bytes,
                &config_path,
            )
        })
        .await
        .map_err(CaptureFailure::BeforeCommit)?
    };
    components.insert(
        "config.json.enc".to_owned(),
        component_manifest("config", &config_stats),
    );

    // 7g. Build and encrypt manifest (`manifest.json.enc`) and `fsync` BOTH `staging_dir` and
    //     `dest_root` BEFORE staging publication in PostgreSQL (`capturing -> publishing`) so
    //     `.staging.<run_id>`'s directory entry is durable on disk before DB commit.
    let completed_at_str: String = sqlx::query_scalar(
        "SELECT to_char(greatest(clock_timestamp(), $1::timestamptz) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')",
    )
    .bind(&quiesced_at)
    .fetch_one(pool)
    .await
    .map_err(|e| CaptureFailure::BeforeCommit(e.into()))?;
    let completed_dt: DateTime<Utc> = DateTime::parse_from_rfc3339(&completed_at_str)
        .map_err(|_| {
            CaptureFailure::BeforeCommit(BackupError::Integrity("invalid completed_at timestamp"))
        })?
        .with_timezone(&Utc);

    let pre_manifest_bundle_hex = hex(&compute_bundle_digest(&components, ""));
    let manifest = BackupManifest {
        format: MANIFEST_FORMAT.to_owned(),
        installation_id: installation_id.clone(),
        backup_run_id: run_id.clone(),
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
        chroma: chroma_manifest,
        rebuildable_indexes: rebuildable_indexes.clone(),
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|_| {
        CaptureFailure::BeforeCommit(BackupError::Integrity("manifest serialization failed"))
    })?;
    let manifest_stats = {
        let manifest_path = staging_dir.join("manifest.json.enc");
        let staging_dir_bg = staging_dir.to_path_buf();
        let dest_root_bg = dest_root.to_path_buf();
        let keyring_bg = keyring.clone();
        let run_id_bg = run_id.clone();
        run_blocking_with_lease_check(&lease_lost, move |_cancel| {
            let stats = encrypt_bytes_to_file(
                &keyring_bg,
                &run_id_bg,
                "manifest",
                &manifest_bytes,
                &manifest_path,
            )?;
            fsync_dir(&staging_dir_bg)?;
            fsync_dir(&dest_root_bg)?;
            Ok(stats)
        })
        .await
        .map_err(CaptureFailure::BeforeCommit)?
    };

    let manifest_ct_hex = hex(&manifest_stats.ciphertext_sha256);
    let final_bundle_digest = compute_bundle_digest(&components, &manifest_ct_hex);
    let final_bundle_hex = hex(&final_bundle_digest);
    let manifest_digest_hex = hex(&manifest_stats.plaintext_sha256);
    let final_dir_name = format!("backup-{}-{run_id}", completed_dt.format("%Y%m%dT%H%M%SZ"));
    let final_dir = dest_root.join(&final_dir_name);

    // Stop the background lease heartbeat cleanly before staging publication so no concurrent
    // renewal races with `backup_stage_publication`.
    let lost_before_commit = heartbeat.is_lost();
    heartbeat.stop().await;
    if lost_before_commit {
        return Err(CaptureFailure::BeforeCommit(BackupError::GateNotReady(
            "backup capture lease lost before staging publication",
        )));
    }

    // 8. Stage publication (`capturing -> publishing`) in PostgreSQL FIRST. `publishing` does NOT
    //    increment `succeeded` telemetry or reset the RPO clock until step 10 confirms publication.
    let journal_chain_bytes =
        decode_hex_32(&parsed_export.digest).map_err(CaptureFailure::BeforeCommit)?;
    let lifecycle_baseline_bytes = parsed_export
        .lifecycle_baseline_digest
        .as_deref()
        .map(decode_hex_32)
        .transpose()
        .map_err(CaptureFailure::BeforeCommit)?;
    let summary_json = json!({
        "format": MANIFEST_FORMAT,
        "installation_id": installation_id,
        "completed_at": completed_at_str,
        "manifest_ciphertext_sha256": manifest_ct_hex,
        "schema_version": schema_version,
        "crate_version": env!("CARGO_PKG_VERSION"),
        "destination_domain": opts.destination_domain,
        "reason": opts.reason,
        "encryption_key_id": keyring.active_key_id(),
        "artifact_revision_count": artifact_summary.revision_count,
        "artifact_payload_bytes": artifact_summary.payload_bytes,
        "vault_required_key_ids": vault_required_key_ids,
        "rebuildable_indexes": rebuildable_indexes,
        "backup_dir_name": final_dir_name,
    });
    let summary_text = summary_json.to_string();

    // Step A: open READ COMMITTED transaction and execute `backup_stage_publication`. Any error
    // BEFORE `commit()` definitely rolled back (safe to remove staging and record `failed`).
    let mut stage_tx = read_committed(pool)
        .await
        .map_err(|e| CaptureFailure::BeforeCommit(e.into()))?;
    if let Err(exec_err) = sqlx::query(
        "SELECT openmettle.backup_stage_publication(
            $1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb
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
    .execute(&mut *stage_tx)
    .await
    {
        let _ = stage_tx.rollback().await;
        return Err(CaptureFailure::BeforeCommit(exec_err.into()));
    }

    // Step B: commit. On ANY `tx.commit().await` error (including `sqlx::Error::Database` such as
    // SQLSTATE `08007` `transaction_resolution_unknown` or `08006` `connection_failure`), ALWAYS
    // run a locking `FOR SHARE` probe in a fresh `READ COMMITTED` transaction before deciding
    // whether publication staged, rolled back, or remains uncertain.
    if let Err(commit_err) = stage_tx.commit().await {
        let probe: Result<Option<(String, Option<String>)>, sqlx::Error> = async {
            let mut probe_tx = read_committed(pool).await?;
            let row = sqlx::query_as::<_, (String, Option<String>)>(
                "SELECT state, encode(bundle_digest, 'hex')
                   FROM openmettle.backup_runs
                  WHERE id = $1::uuid
                    FOR SHARE",
            )
            .bind(run_id)
            .fetch_optional(&mut *probe_tx)
            .await?;
            probe_tx.commit().await?;
            Ok(row)
        }
        .await;
        match probe {
            Ok(Some((state, Some(db_bundle))))
                if matches!(state.as_str(), "publishing" | "succeeded")
                    && db_bundle == final_bundle_hex =>
            {
                // Staged publication actually landed in PostgreSQL; proceed to publish on disk.
            }
            Ok(Some(_)) => {
                // Locking read proved row remained capturing/failed/incomplete (not committed).
                return Err(CaptureFailure::BeforeCommit(commit_err.into()));
            }
            Ok(None) | Err(_) => {
                // Database unreachable / commit outcome genuinely uncertain: preserve staging and do
                // NOT call `fail_capture`.
                return Err(CaptureFailure::PreserveStaging(
                    BackupError::CommitOutcomeUnknown,
                ));
            }
        }
    }

    // 9. PostgreSQL staged `publishing`: atomically publish `backup-meta.json` via CSPRNG-unique
    //    temp file in `dest_root` + rename, rename `.staging.<run_id>` -> `backup-*`, verify the
    //    published directory, and `fsync` `backup-meta.json`, `final_dir`, and `dest_root`.
    let meta = BackupMeta {
        format: META_FORMAT.to_owned(),
        installation_id: installation_id.clone(),
        backup_run_id: run_id.clone(),
        completed_at: completed_at_str,
        destination_domain: opts.destination_domain.clone(),
        encryption_key_id: keyring.active_key_id().to_owned(),
        manifest_ciphertext_sha256: manifest_ct_hex,
        bundle_digest: final_bundle_hex.clone(),
        state: "complete".to_owned(),
    };
    {
        let dest_root_bg = dest_root.to_path_buf();
        let staging_dir_bg = staging_dir.to_path_buf();
        let final_dir_bg = final_dir.clone();
        let meta_bg = meta.clone();
        let keyring_bg = keyring.clone();
        tokio::task::spawn_blocking(move || {
            publish_staged_dir_blocking(
                &dest_root_bg,
                &staging_dir_bg,
                &final_dir_bg,
                &meta_bg,
                &keyring_bg,
            )
        })
        .await
        .map_err(|_| CaptureFailure::PreserveStaging(BackupError::PgDump("publish task failed")))?
        .map_err(CaptureFailure::PreserveStaging)?;
    }

    // 10. Confirm publication (`publishing -> succeeded`) in PostgreSQL now that the published
    //     backup directory is durable on disk.
    confirm_publication(pool, run_id, &opts.reason)
        .await
        .map_err(CaptureFailure::PreserveStaging)?;

    // 11. Run verified GFS retention pruning on the blocking pool scoped to this
    //     `(installation_id, destination_domain)`, then optionally release maintenance strictly if
    //     this capture run opened the window.
    let pruned = match opts.prune_policy {
        Some(policy) => {
            let dest_root_bg = dest_root.to_path_buf();
            let inst_bg = installation_id.clone();
            let dom_bg = opts.destination_domain.clone();
            let keyring_bg = keyring.clone();
            let report = tokio::task::spawn_blocking(move || {
                prune_destination_with_verifier(
                    &dest_root_bg,
                    policy,
                    Some((inst_bg.as_str(), dom_bg.as_str())),
                    false,
                    |dir, m| verify_backup_dir_for_prune(dir, m, &keyring_bg),
                )
            })
            .await
            .map_err(|_| CaptureFailure::PreserveStaging(BackupError::PgDump("prune task failed")))?
            .map_err(|e| CaptureFailure::PreserveStaging(e.into()))?;
            Some(report)
        }
        None => None,
    };

    let released_maintenance = if opts.release_on_success {
        release_capture_maintenance(pool, run_id, &opts.operator_id, &opts.reason)
            .await
            .map_err(CaptureFailure::PreserveStaging)?
    } else {
        false
    };

    Ok(CaptureReport {
        backup_run_id: run_id.clone(),
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
        let mut src = open_regular_nofollow(&path)
            .map_err(|_| BackupError::Integrity("manifest component file missing or invalid"))?;
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
    pub has_chroma_archive: bool,
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
            let mut src = open_regular_nofollow(&backup_dir.join(comp_name))
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

        // Decrypt artifacts.bin.enc via a temporary plaintext stream in output_dir unlinked right
        // after unpacking.
        let artifact_expected =
            manifest
                .components
                .get("artifacts.bin.enc")
                .ok_or(BackupError::Integrity(
                    "artifacts.bin.enc missing from manifest",
                ))?;
        let tmp_artifacts = output_dir.join(".artifacts.bin.tmp");
        let artifact_summary = {
            let mut src = open_regular_nofollow(&backup_dir.join("artifacts.bin.enc"))
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
            let mut src = open_regular_nofollow(&backup_dir.join("config.json.enc"))
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
            if cf.name.contains('/')
                || cf.name.contains('\\')
                || cf.name == ".."
                || cf.name == "."
                || cf.name.eq_ignore_ascii_case("vault-key-inventory.json")
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
        let has_chroma_archive = if manifest.components.contains_key("chroma.archive.enc") {
            decrypt_to_file("chroma.archive.enc", "chroma.archive")?;
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
            has_chroma_archive,
        })
    })();

    if unpack_result.is_err() {
        let _ = fs::remove_dir_all(output_dir);
    }
    unpack_result
}

fn decrypt_and_validate_manifest_file(
    dir: &Path,
    meta: &BackupMeta,
    keyring: &BackupKeyRing,
) -> Result<BackupManifest, BackupError> {
    if meta.format != META_FORMAT || meta.state != "complete" {
        return Err(BackupError::Integrity("backup-meta.json is not complete"));
    }
    runs::uuid(&meta.installation_id)
        .map_err(|_| BackupError::Integrity("invalid installation_id in backup-meta.json"))?;
    runs::uuid(&meta.backup_run_id)
        .map_err(|_| BackupError::Integrity("invalid backup_run_id in backup-meta.json"))?;

    let mut manifest_plain = Vec::new();
    let mut manifest_file = open_regular_nofollow(&dir.join("manifest.json.enc"))
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
        || manifest.installation_id != meta.installation_id
        || manifest.backup_run_id != meta.backup_run_id
        || manifest.destination_domain != meta.destination_domain
        || manifest.completed_at != meta.completed_at
        || manifest.encryption_key_id != meta.encryption_key_id
    {
        return Err(BackupError::Integrity(
            "manifest identity disagrees with backup-meta.json",
        ));
    }
    for file_name in manifest.components.keys() {
        if file_name.is_empty()
            || file_name.contains('/')
            || file_name.contains('\\')
            || file_name == "."
            || file_name == ".."
        {
            return Err(BackupError::Integrity(
                "manifest contains invalid component file name",
            ));
        }
    }
    for req in REQUIRED_COMPONENTS {
        if !manifest.components.contains_key(req) {
            return Err(BackupError::Integrity(
                "manifest missing required backup component",
            ));
        }
    }
    match &manifest.graphiti_neo4j {
        GraphitiManifest::NotProvisioned => {
            if manifest.components.contains_key("neo4j.dump.enc") {
                return Err(BackupError::Integrity(
                    "manifest declares graphiti_neo4j not_provisioned but includes neo4j.dump.enc",
                ));
            }
        }
        GraphitiManifest::OfflineDump {
            component,
            plaintext_bytes,
            plaintext_sha256,
        } => {
            let Some(comp) = manifest.components.get("neo4j.dump.enc") else {
                return Err(BackupError::Integrity(
                    "manifest declares graphiti offline_dump without neo4j.dump.enc component",
                ));
            };
            if component != "neo4j.dump.enc"
                || comp.role != "neo4j_dump"
                || comp.plaintext_bytes != *plaintext_bytes
                || &comp.plaintext_sha256 != plaintext_sha256
            {
                return Err(BackupError::Integrity(
                    "manifest graphiti_neo4j metadata disagrees with neo4j.dump.enc component",
                ));
            }
        }
    }
    match &manifest.chroma {
        ChromaManifest::NotProvisioned => {
            if manifest.components.contains_key("chroma.archive.enc") {
                return Err(BackupError::Integrity(
                    "manifest declares chroma not_provisioned but includes chroma.archive.enc",
                ));
            }
        }
        ChromaManifest::Archive {
            component,
            plaintext_bytes,
            plaintext_sha256,
        } => {
            let Some(comp) = manifest.components.get("chroma.archive.enc") else {
                return Err(BackupError::Integrity(
                    "manifest declares chroma archive without chroma.archive.enc component",
                ));
            };
            if component != "chroma.archive.enc"
                || comp.role != "chroma_archive"
                || comp.plaintext_bytes != *plaintext_bytes
                || &comp.plaintext_sha256 != plaintext_sha256
            {
                return Err(BackupError::Integrity(
                    "manifest chroma metadata disagrees with chroma.archive.enc component",
                ));
            }
        }
        ChromaManifest::QualifiedRebuild { qualification_ref } => {
            if manifest.components.contains_key("chroma.archive.enc")
                || validate_chroma_qualification_ref(qualification_ref).is_err()
            {
                return Err(BackupError::Integrity(
                    "manifest chroma qualified_rebuild metadata is invalid",
                ));
            }
        }
    }
    if manifest.rebuildable_indexes != rebuildable_indexes_for(&manifest.chroma) {
        return Err(BackupError::Integrity(
            "manifest rebuildable_indexes disagrees with chroma disposition",
        ));
    }
    let expected_pre_bundle = hex(&compute_bundle_digest(&manifest.components, ""));
    if manifest.bundle_digest != expected_pre_bundle {
        return Err(BackupError::Integrity(
            "manifest component bundle digest mismatch",
        ));
    }
    Ok(manifest)
}

fn load_and_verify_manifest(
    backup_dir: &Path,
    keyring: &BackupKeyRing,
) -> Result<(BackupMeta, BackupManifest), BackupError> {
    if !backup_dir.is_absolute() {
        return Err(BackupError::Invalid(
            "--backup-dir must be an existing absolute directory",
        ));
    }
    let sym = fs::symlink_metadata(backup_dir)
        .map_err(|_| BackupError::Invalid("--backup-dir must be an existing absolute directory"))?;
    if sym.file_type().is_symlink() || !sym.is_dir() {
        return Err(BackupError::Invalid(
            "--backup-dir must be an existing non-symlink directory",
        ));
    }
    let meta_bytes =
        read_regular_bounded_nofollow(&backup_dir.join("backup-meta.json"), MAX_BACKUP_META_BYTES)
            .map_err(|_| BackupError::Integrity("backup-meta.json missing"))?;
    let meta: BackupMeta = serde_json::from_slice(&meta_bytes)
        .map_err(|_| BackupError::Integrity("backup-meta.json malformed"))?;
    let manifest = decrypt_and_validate_manifest_file(backup_dir, &meta, keyring)?;
    Ok((meta, manifest))
}

fn verify_component_ciphertext_files(
    dir: &Path,
    manifest: &BackupManifest,
    meta: &BackupMeta,
) -> Result<(), BackupError> {
    let expected_bundle = hex(&compute_bundle_digest(
        &manifest.components,
        &meta.manifest_ciphertext_sha256,
    ));
    if meta.bundle_digest != expected_bundle {
        return Err(BackupError::Integrity("bundle digest mismatch"));
    }
    let mut buf = vec![0u8; crypto::CHUNK_SIZE];
    for (file_name, expected) in &manifest.components {
        let mut src = open_regular_nofollow(&dir.join(file_name))
            .map_err(|_| BackupError::Integrity("component ciphertext missing"))?;
        let file_len = src.metadata()?.len();
        if file_len != expected.ciphertext_bytes {
            return Err(BackupError::Integrity("component ciphertext size mismatch"));
        }
        let mut hasher = Sha256::new();
        let mut total: u64 = 0;
        loop {
            let n = src.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            total = total
                .checked_add(n as u64)
                .ok_or(BackupError::Integrity("component size overflow"))?;
        }
        if total != expected.ciphertext_bytes
            || hex(&hasher.finalize()) != expected.ciphertext_sha256
        {
            return Err(BackupError::Integrity(
                "component ciphertext SHA-256 mismatch",
            ));
        }
    }
    Ok(())
}

fn verify_staged_dir_against_meta(
    staging_dir: &Path,
    expected_meta: &BackupMeta,
    keyring: &BackupKeyRing,
) -> Result<(), BackupError> {
    let manifest = decrypt_and_validate_manifest_file(staging_dir, expected_meta, keyring)?;
    verify_component_ciphertext_files(staging_dir, &manifest, expected_meta)
}

/// Cryptographic and structural verification callback used by GFS retention pruning so an
/// incomplete, corrupt, or forged `backup-*` directory can never occupy a retention bucket or
/// supersede an older valid backup.
fn verify_backup_dir_for_prune(
    backup_dir: &Path,
    meta: &BackupMeta,
    keyring: &BackupKeyRing,
) -> bool {
    let Ok((loaded_meta, manifest)) = load_and_verify_manifest(backup_dir, keyring) else {
        return false;
    };
    if &loaded_meta != meta {
        return false;
    }
    verify_component_ciphertext_files(backup_dir, &manifest, meta).is_ok()
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

/// Apply verified GFS retention pruning to `destination_root`, grouping sets per
/// `(installation_id, destination_domain)` and excluding any unverified `backup-*` directory
/// without deleting it.
pub fn prune(
    destination_root: &Path,
    keyring: &BackupKeyRing,
    policy: GfsPolicy,
    dry_run: bool,
) -> Result<PruneReport, BackupError> {
    Ok(prune_destination_with_verifier(
        destination_root,
        policy,
        None,
        dry_run,
        |dir, meta| verify_backup_dir_for_prune(dir, meta, keyring),
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, UnixStream};

    #[test]
    fn parse_validated_pg_uri_handles_allowed_fields_and_rejects_hostaddr_or_missing_parts() {
        let p = parse_validated_pg_uri(
            "postgresql://openmettle_owner:s%3Aec%5Cret@db.example.test:55447/om_db?sslmode=verify-full&sslrootcert=/etc/ca.pem&sslcert=/etc/client.pem&sslkey=/etc/client.key&application_name=om-backup",
        )
        .unwrap();
        assert_eq!(p.username, "openmettle_owner");
        assert_eq!(p.password.as_deref(), Some("s:ec\\ret"));
        assert_eq!(p.host, "db.example.test");
        assert_eq!(p.port, 55447);
        assert_eq!(p.database, "om_db");
        assert_eq!(p.sslmode, "verify-full");
        assert_eq!(p.sslrootcert.as_deref(), Some("/etc/ca.pem"));
        assert_eq!(p.sslcert.as_deref(), Some("/etc/client.pem"));
        assert_eq!(p.sslkey.as_deref(), Some("/etc/client.key"));
        assert_eq!(p.application_name.as_deref(), Some("om-backup"));
        assert!(p.to_sqlx_options().is_ok());
        assert_eq!(escape_pgpass("s:ec\\ret"), r"s\:ec\\ret");
        // Debug redacts password.
        assert!(!format!("{p:?}").contains("s:ec\\ret"));

        let v6 = parse_validated_pg_uri("postgres://user:pw@[::1]/db").unwrap();
        assert_eq!(v6.host, "::1");
        assert_eq!(v6.port, 5432);
        assert_eq!(v6.sslmode, "prefer");

        // Accepted: sslmode=require without sslrootcert, sslmode=verify-ca with explicit CA.
        let req =
            parse_validated_pg_uri("postgres://u:p@db.example.test/db?sslmode=require").unwrap();
        assert_eq!(req.sslmode, "require");
        assert!(req.to_sqlx_options().is_ok());

        // Rejected: hostaddr, missing host/user/db, dbname conninfo/URI expansion or `%2F`,
        // TLS parity violations (allow, sslrootcert=system, disable+certs, prefer/require+sslrootcert,
        // verify-ca/verify-full without sslrootcert), unknown query params, multi-host, duplicate
        // params, invalid sslmode, malformed query pair, fragment, newline in password.
        for bad in [
            "postgres://u:p@db.example.test:5432/db?hostaddr=127.0.0.1",
            "postgres://u:p@127.0.0.1:5432/db?hostaddr=not-an-ip",
            "postgres://127.0.0.1:5432/db",
            "postgres://u:p@127.0.0.1:5432/",
            "postgres://u:p@/db",
            "postgres://u:p@127.0.0.1:5432/db?dbname=host=evil.invalid%20dbname=x",
            "postgres://u:p@127.0.0.1:5432/a%3Db",
            "postgres://u:p@127.0.0.1:5432/db?dbname=postgres://evil/db",
            "postgres://u:p@127.0.0.1:5432/db?dbname=POSTGRESQL://evil/db",
            "postgres://u:p@127.0.0.1:5432/a%2Fb",
            "postgres://u:p@127.0.0.1:5432/db?sslmode=allow",
            "postgres://u:p@127.0.0.1:5432/db?sslmode=verify-full&sslrootcert=system",
            "postgres://u:p@127.0.0.1:5432/db?sslmode=disable&sslrootcert=/etc/ca.pem",
            "postgres://u:p@127.0.0.1:5432/db?sslmode=disable&sslcert=/etc/c.pem",
            "postgres://u:p@127.0.0.1:5432/db?sslmode=disable&sslkey=/etc/c.key",
            "postgres://u:p@127.0.0.1:5432/db?sslmode=prefer&sslrootcert=/etc/ca.pem",
            "postgres://u:p@127.0.0.1:5432/db?sslmode=require&sslrootcert=/etc/ca.pem",
            "postgres://u:p@127.0.0.1:5432/db?sslmode=verify-ca",
            "postgres://u:p@127.0.0.1:5432/db?sslmode=verify-full",
            "postgres://u:p@127.0.0.1:5432/db?sslmode=verify-full&sslrootcert=relative/ca.pem",
            "postgres://u:p@127.0.0.1:5432/db?sslmode=verify-full&sslrootcert=/etc/ca.pem&sslcert=/etc/c.pem",
            "postgres://u:p@127.0.0.1:5432/db?sslmode=verify-full&sslrootcert=/etc/ca.pem&sslkey=/etc/c.key",
            "postgres://u:p@127.0.0.1:5432/db?sslmode=require&sslcert=/etc/c.pem",
            "postgres://u:p@127.0.0.1:5432/db?sslmode=require&sslcert=rel.pem&sslkey=/etc/c.key",
            "postgres://u:p@%2Fvar%2Frun%2Fpostgresql/db?sslmode=require",
            "postgres://u:p@%2Fvar%2Frun%2Fpostgresql/db?sslmode=verify-ca&sslrootcert=/etc/ca.pem",
            "postgres://u:p@%2Fvar%2Frun%2Fpostgresql/db?sslmode=verify-full&sslrootcert=/etc/ca.pem",
            "postgres://u:p@127.0.0.1:5432/db?channel_binding=require",
            "postgres://u:p@127.0.0.1:5432/db?options=-c%20search_path=public",
            "postgres://u:p@host1:5432,host2:5432/db",
            "postgres://u:p@127.0.0.1:5432/db?host=a,b",
            "postgres://u:p@127.0.0.1:5432/db?sslmode=bogus",
            "postgres://u:p@127.0.0.1:5432/db?sslmode=require&sslmode=disable",
            "postgres://u:p@127.0.0.1:5432/db?sslmode",
            "postgres://u:p@127.0.0.1:5432/db#frag",
            "postgres://u:bad%0Apw@127.0.0.1:5432/db",
        ] {
            assert!(
                parse_validated_pg_uri(bad).is_err(),
                "expected URI to be rejected: {bad}"
            );
        }
    }

    #[test]
    fn pg_uri_ignores_ambient_pgport_and_pg_env_in_both_sqlx_and_pg_dump() {
        if std::env::var_os("OPENMETTLE_TEST_PGPORT_CHILD").is_some() {
            let uri = "postgres://openmettle_owner:pw@db.example.test/om_db";
            let cfg = parse_validated_pg_uri(uri).unwrap();
            assert_eq!(cfg.port, 5432);
            assert_eq!(cfg.sslmode, "prefer");
            let opts = cfg.to_sqlx_options().unwrap();
            assert_eq!(opts.get_host(), "db.example.test");
            assert_eq!(opts.get_port(), 5432);
            assert_eq!(opts.get_username(), "openmettle_owner");
            assert_eq!(opts.get_database(), Some("om_db"));
            assert!(matches!(opts.get_ssl_mode(), PgSslMode::Prefer));

            // Verify CliPgDumpRunner also passes explicit port 5432 / sslmode prefer and scrubs PG*.
            let mut rnd = [0u8; 4];
            SystemRandom::new().fill(&mut rnd).unwrap();
            let dir = std::env::temp_dir().join(format!(
                "om-pgport-child-{}-{:02x}{:02x}{:02x}{:02x}",
                std::process::id(),
                rnd[0],
                rnd[1],
                rnd[2],
                rnd[3]
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let script = dir.join("fake-pg-dump.sh");
            let observed = dir.join("observed.txt");
            let body = format!(
                "#!/bin/sh\nset -eu\n\
                 printf 'ARGS=%s\\n' \"$*\" > \"{}\"\n\
                 printf 'PGPORT=%s\\n' \"${{PGPORT:-}}\" >> \"{}\"\n\
                 printf 'PGHOST=%s\\n' \"${{PGHOST:-}}\" >> \"{}\"\n\
                 printf 'PGSSLMODE=%s\\n' \"${{PGSSLMODE:-}}\" >> \"{}\"\n\
                 printf 'OK'\n",
                observed.display(),
                observed.display(),
                observed.display(),
                observed.display(),
            );
            fs::write(&script, body).unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();

            let runner = CliPgDumpRunner::with_program(&script);
            let mut out = Vec::new();
            runner
                .dump(uri, None, &DumpCancel::new(), &mut out)
                .unwrap();
            let obs = fs::read_to_string(&observed).unwrap();
            assert!(
                obs.contains(
                    "--host=db.example.test --port=5432 --username=openmettle_owner --dbname=om_db"
                ),
                "unexpected argv: {obs}"
            );
            assert!(obs.contains("PGPORT=\n"), "PGPORT leaked: {obs}");
            assert!(obs.contains("PGHOST=\n"), "PGHOST leaked: {obs}");
            assert!(obs.contains("PGSSLMODE=prefer\n"), "PGSSLMODE wrong: {obs}");

            // Ambient PGOPTIONS / PGSSLROOTCERT without matching URI setting must fail closed.
            let _ = fs::remove_dir_all(&dir);
            return;
        }

        // Re-exec this single unit test with hostile ambient PG* variables (zero unsafe code).
        let exe = std::env::current_exe().unwrap();
        let out = Command::new(&exe)
            .args([
                "--exact",
                "backup::tests::pg_uri_ignores_ambient_pgport_and_pg_env_in_both_sqlx_and_pg_dump",
            ])
            .env("OPENMETTLE_TEST_PGPORT_CHILD", "1")
            .env("PGPORT", "55439")
            .env("PGHOST", "wrong.invalid")
            .env("PGHOSTADDR", "127.0.0.2")
            .env("PGUSER", "wrong_user")
            .env("PGDATABASE", "wrong_db")
            .env("PGSSLMODE", "disable")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "PGPORT isolation subprocess failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[test]
    fn cli_pg_dump_runner_passes_snapshot_tls_env_zero_password_in_argv_and_kills_on_write_error() {
        let mut rnd = [0u8; 4];
        SystemRandom::new().fill(&mut rnd).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "om-pgdump-test-{}-{:02x}{:02x}{:02x}{:02x}",
            std::process::id(),
            rnd[0],
            rnd[1],
            rnd[2],
            rnd[3],
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let script = dir.join("fake-pg-dump.sh");
        let observed = dir.join("observed.txt");
        let body = format!(
            "#!/bin/sh\nset -eu\n\
             printf 'ARGS=%s\\n' \"$*\" > \"{}\"\n\
             printf 'PGPASSFILE=%s\\n' \"${{PGPASSFILE:-}}\" >> \"{}\"\n\
             printf 'PGPASSWORD=%s\\n' \"${{PGPASSWORD:-}}\" >> \"{}\"\n\
             printf 'PGSSLMODE=%s\\n' \"${{PGSSLMODE:-}}\" >> \"{}\"\n\
             printf 'PGGSSENCMODE=%s\\n' \"${{PGGSSENCMODE:-}}\" >> \"{}\"\n\
             printf 'PGSSLROOTCERT=%s\\n' \"${{PGSSLROOTCERT:-}}\" >> \"{}\"\n\
             printf 'PGAPPNAME=%s\\n' \"${{PGAPPNAME:-}}\" >> \"{}\"\n\
             printf 'CONTENT=%s\\n' \"$(tr '\\n' '|' < \"$PGPASSFILE\")\" >> \"{}\"\n\
             printf 'PGDMP-SYNTHETIC-PAYLOAD'\n",
            observed.display(),
            observed.display(),
            observed.display(),
            observed.display(),
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
                "postgres://openmettle_owner:supersecret:pw@db.example.test:55447/openmettle?sslmode=verify-ca&sslrootcert=/etc/ca.pem&application_name=om-backup",
                Some("00000003-00000010-1"),
                &DumpCancel::new(),
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
        assert!(args_line.contains("--snapshot=00000003-00000010-1"));
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
        assert!(!Path::new(pgpass_line).exists());
        assert!(obs.contains("PGPASSWORD=\n"));
        assert!(obs.contains("PGSSLMODE=verify-ca\n"));
        assert!(obs.contains("PGGSSENCMODE=disable\n"));
        assert!(obs.contains("PGSSLROOTCERT=/etc/ca.pem\n"));
        assert!(obs.contains("PGAPPNAME=om-backup\n"));
        assert!(
            obs.contains(
                r"CONTENT=db.example.test:55447:openmettle:openmettle_owner:supersecret\:pw|"
            ),
            "unexpected pgpass content: {obs}"
        );

        // Verify a noisy producer does not deadlock when the writer fails early (child is killed).
        let noisy = dir.join("noisy-pg-dump.sh");
        fs::write(
            &noisy,
            "#!/bin/sh\nwhile true; do printf '0123456789abcdef0123456789abcdef'; done\n",
        )
        .unwrap();
        fs::set_permissions(&noisy, fs::Permissions::from_mode(0o700)).unwrap();

        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "disk full"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let noisy_runner = CliPgDumpRunner::with_program(&noisy);
        let started = Instant::now();
        let err = noisy_runner
            .dump(
                "postgres://openmettle_owner:pw@127.0.0.1:55447/openmettle?sslmode=disable",
                None,
                &DumpCancel::new(),
                &mut FailingWriter,
            )
            .unwrap_err();
        assert!(matches!(err, BackupError::Io(_)));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "pg_dump write error stalled instead of killing child"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_pg_dump_runner_cancel_kills_and_reaps_stalled_child_promptly() {
        let mut rnd = [0u8; 4];
        SystemRandom::new().fill(&mut rnd).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "om-pgdump-cancel-{}-{:02x}{:02x}{:02x}{:02x}",
            std::process::id(),
            rnd[0],
            rnd[1],
            rnd[2],
            rnd[3],
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let pid_file = dir.join("child.pid");
        let pid_tmp = dir.join("child.pid.tmp");
        let pgpass_record = dir.join("pgpass.path");
        let pgpass_tmp = dir.join("pgpass.path.tmp");
        let stalled = dir.join("stalled-pg-dump.sh");
        let body = format!(
            "#!/bin/sh\nset -eu\n\
             printf '%s' \"${{PGPASSFILE:-}}\" > \"{}\"\n\
             mv \"{}\" \"{}\"\n\
             printf '%s' \"$$\" > \"{}\"\n\
             mv \"{}\" \"{}\"\n\
             exec sleep 60\n",
            pgpass_tmp.display(),
            pgpass_tmp.display(),
            pgpass_record.display(),
            pid_tmp.display(),
            pid_tmp.display(),
            pid_file.display(),
        );
        fs::write(&stalled, body).unwrap();
        fs::set_permissions(&stalled, fs::Permissions::from_mode(0o700)).unwrap();

        let cancel = DumpCancel::new();
        let cancel_trigger = cancel.clone();
        let pid_wait = pid_file.clone();
        let trigger_thread = std::thread::spawn(move || {
            for _ in 0..200 {
                if fs::read_to_string(&pid_wait)
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            cancel_trigger.cancel();
        });

        let started = Instant::now();
        let runner = CliPgDumpRunner::with_program(&stalled);
        let mut out = Vec::new();
        let err = runner
            .dump(
                "postgres://openmettle_owner:pw@127.0.0.1:55447/openmettle?sslmode=disable",
                None,
                &cancel,
                &mut out,
            )
            .unwrap_err();
        trigger_thread.join().unwrap();
        assert!(
            matches!(err, BackupError::GateNotReady(_)),
            "expected GateNotReady cancellation error, got {err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "stalled pg_dump cancellation took too long: {:?}",
            started.elapsed()
        );

        let pgpass_path = fs::read_to_string(&pgpass_record).unwrap();
        assert!(
            !pgpass_path.is_empty() && !Path::new(&pgpass_path).exists(),
            "PGPASSFILE must be unlinked after cancellation"
        );
        let pid = fs::read_to_string(&pid_file).unwrap();
        assert!(!pid.is_empty());
        let alive = Command::new("kill")
            .args(["-0", pid.trim()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(
            !alive,
            "stalled pg_dump child PID {pid} must be killed and reaped before dump() returns"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cancel_checking_writer_aborts_write_all_immediately_on_cancel() {
        let cancel = DumpCancel::new();
        cancel.cancel();
        let mut sink = Vec::new();
        let mut writer = CancelCheckingWriter {
            inner: &mut sink,
            cancel,
        };
        let err = writer.write_all(b"should-abort-immediately").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        let flush_err = writer.flush().unwrap_err();
        assert_eq!(flush_err.kind(), io::ErrorKind::Other);
        assert!(sink.is_empty());
    }

    #[test]
    fn cli_pg_dump_runner_cancel_kills_and_reaps_child_hanging_after_stdout_eof() {
        let mut rnd = [0u8; 4];
        SystemRandom::new().fill(&mut rnd).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "om-pgdump-eof-hang-{}-{:02x}{:02x}{:02x}{:02x}",
            std::process::id(),
            rnd[0],
            rnd[1],
            rnd[2],
            rnd[3],
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let pid_file = dir.join("child.pid");
        let pgpass_record = dir.join("pgpass.path");
        let post_eof_marker = dir.join("closed.flag");
        let hang_after_eof = dir.join("eof-hang-pg-dump.sh");
        let body = format!(
            "#!/bin/sh\nset -eu\n\
             printf '%s' \"$$\" > \"{}\"\n\
             printf '%s' \"${{PGPASSFILE:-}}\" > \"{}\"\n\
             printf 'PGDMP-BEFORE-EOF'\n\
             exec 1>&-\n\
             printf 'closed' > \"{}\"\n\
             exec sleep 30\n",
            pid_file.display(),
            pgpass_record.display(),
            post_eof_marker.display(),
        );
        fs::write(&hang_after_eof, body).unwrap();
        fs::set_permissions(&hang_after_eof, fs::Permissions::from_mode(0o700)).unwrap();

        let cancel = DumpCancel::new();
        let cancel_trigger = cancel.clone();
        let marker_wait = post_eof_marker.clone();
        let trigger_thread = std::thread::spawn(move || {
            for _ in 0..200 {
                if marker_wait.exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            // Give the reader loop a moment to observe EOF and enter `wait_and_reap`.
            std::thread::sleep(Duration::from_millis(50));
            cancel_trigger.cancel();
        });

        let started = Instant::now();
        let runner = CliPgDumpRunner::with_program(&hang_after_eof);
        let mut out = Vec::new();
        let err = runner
            .dump(
                "postgres://openmettle_owner:pw@127.0.0.1:55447/openmettle?sslmode=disable",
                None,
                &cancel,
                &mut out,
            )
            .unwrap_err();
        trigger_thread.join().unwrap();

        assert_eq!(out, b"PGDMP-BEFORE-EOF");
        assert!(
            matches!(err, BackupError::GateNotReady(_)),
            "expected GateNotReady after post-EOF cancellation, got {err:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "post-EOF hanging pg_dump cancellation took too long: {:?}",
            started.elapsed()
        );
        let pgpass_path = fs::read_to_string(&pgpass_record).unwrap();
        assert!(!pgpass_path.is_empty() && !Path::new(&pgpass_path).exists());
        let pid = fs::read_to_string(&pid_file).unwrap();
        let alive = Command::new("kill")
            .args(["-0", pid.trim()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(
            !alive,
            "post-EOF hanging pg_dump PID {pid} must be killed and reaped"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn publish_staged_dir_handles_concurrent_publishers_without_stray_tmp_or_truncation() {
        let mut rnd = [0u8; 4];
        SystemRandom::new().fill(&mut rnd).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "om-pub-race-{}-{:02x}{:02x}{:02x}{:02x}",
            std::process::id(),
            rnd[0],
            rnd[1],
            rnd[2],
            rnd[3],
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let key_dir = dir.join("keys");
        create_dir_0700(&key_dir).unwrap();
        let key_file = key_dir.join("k1.key");
        write_file_0600(&key_file, &[0x42u8; 32]).unwrap();
        let cfg_file = key_dir.join("keyring.json");
        write_file_0600(
            &cfg_file,
            json!({
                "version": 1,
                "active_key_id": "k1",
                "keys": [{ "id": "k1", "file": key_file.to_str().unwrap() }]
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let keyring = BackupKeyRing::load_from_config(&cfg_file).unwrap();

        let dest_root = dir.join("dest");
        create_dir_0700(&dest_root).unwrap();
        let run_id = "11111111-2222-4333-8444-555555555555";
        let inst_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        let staging_dir = dest_root.join(format!(".staging.{run_id}"));
        create_dir_0700(&staging_dir).unwrap();

        let mut components = BTreeMap::new();
        for (file_name, role, body) in [
            ("pg.dump.enc", "pg_dump", b"PGDMP".as_slice()),
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
            let stats =
                encrypt_bytes_to_file(&keyring, run_id, role, body, &staging_dir.join(file_name))
                    .unwrap();
            components.insert(file_name.to_owned(), component_manifest(role, &stats));
        }

        let completed_at = "2026-11-27T01:00:00Z".to_owned();
        let manifest = BackupManifest {
            format: MANIFEST_FORMAT.to_owned(),
            installation_id: inst_id.to_owned(),
            backup_run_id: run_id.to_owned(),
            quiesced_at: completed_at.clone(),
            completed_at: completed_at.clone(),
            schema_version: 45,
            crate_version: env!("CARGO_PKG_VERSION").to_owned(),
            destination_domain: "offhost-race".to_owned(),
            rpo_target_seconds: 86_400,
            encryption_key_id: "k1".to_owned(),
            bundle_digest: hex(&compute_bundle_digest(&components, "")),
            components: components.clone(),
            deletion_journal: JournalWatermarkManifest {
                origin_us: 1,
                journal_seq: 0,
                chain_digest: restore::GENESIS.to_owned(),
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
            rebuildable_indexes: rebuildable_indexes_for(&ChromaManifest::NotProvisioned),
        };
        let manifest_stats = encrypt_bytes_to_file(
            &keyring,
            run_id,
            "manifest",
            &serde_json::to_vec_pretty(&manifest).unwrap(),
            &staging_dir.join("manifest.json.enc"),
        )
        .unwrap();
        let mct_hex = hex(&manifest_stats.ciphertext_sha256);
        let expected_meta = BackupMeta {
            format: META_FORMAT.to_owned(),
            installation_id: inst_id.to_owned(),
            backup_run_id: run_id.to_owned(),
            completed_at,
            destination_domain: "offhost-race".to_owned(),
            encryption_key_id: "k1".to_owned(),
            manifest_ciphertext_sha256: mct_hex.clone(),
            bundle_digest: hex(&compute_bundle_digest(&components, &mct_hex)),
            state: "complete".to_owned(),
        };
        let final_dir = dest_root.join(format!("backup-20261127T010000Z-{run_id}"));

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let b = Arc::clone(&barrier);
            let dr = dest_root.clone();
            let sd = staging_dir.clone();
            let fd = final_dir.clone();
            let em = expected_meta.clone();
            let kr = keyring.clone();
            handles.push(std::thread::spawn(move || {
                b.wait();
                publish_staged_dir_blocking(&dr, &sd, &fd, &em, &kr)
            }));
        }
        for h in handles {
            h.join().unwrap().unwrap();
        }
        assert!(!staging_dir.exists());
        assert!(final_dir.is_dir());
        verify_backup(&final_dir, &keyring).unwrap();
        // Zero stray `.tmp` files remain in `dest_root` or `final_dir`.
        for entry in fs::read_dir(&dest_root).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(!name.ends_with(".tmp"), "stray tmp in dest_root: {name}");
        }
        for entry in fs::read_dir(&final_dir).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(!name.ends_with(".tmp"), "stray tmp in final_dir: {name}");
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_pg_dump_runner_isolates_home_libpq_defaults_when_optional_fields_omitted() {
        let mut rnd = [0u8; 4];
        SystemRandom::new().fill(&mut rnd).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "om-pgenv-home-{}-{:02x}{:02x}{:02x}{:02x}",
            std::process::id(),
            rnd[0],
            rnd[1],
            rnd[2],
            rnd[3],
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let script = dir.join("fake-pg-dump.sh");
        let observed = dir.join("observed.txt");
        let body = format!(
            "#!/bin/sh\nset -eu\n\
             printf 'PGPASSFILE=%s\\n' \"${{PGPASSFILE:-}}\" > \"{}\"\n\
             printf 'PGSSLROOTCERT=%s\\n' \"${{PGSSLROOTCERT:-}}\" >> \"{}\"\n\
             printf 'PGSSLCERT=%s\\n' \"${{PGSSLCERT:-}}\" >> \"{}\"\n\
             printf 'PGSSLKEY=%s\\n' \"${{PGSSLKEY:-}}\" >> \"{}\"\n\
             printf 'PGSSLCRL=%s\\n' \"${{PGSSLCRL:-}}\" >> \"{}\"\n\
             printf 'PGSSLCRLDIR=%s\\n' \"${{PGSSLCRLDIR:-}}\" >> \"{}\"\n\
             printf 'PGSERVICEFILE=%s\\n' \"${{PGSERVICEFILE:-}}\" >> \"{}\"\n\
             printf 'PGGSSENCMODE=%s\\n' \"${{PGGSSENCMODE:-}}\" >> \"{}\"\n\
             printf 'OK'\n",
            observed.display(),
            observed.display(),
            observed.display(),
            observed.display(),
            observed.display(),
            observed.display(),
            observed.display(),
            observed.display(),
        );
        fs::write(&script, body).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();

        let runner = CliPgDumpRunner::with_program(&script);
        let mut out = Vec::new();
        runner
            .dump(
                "postgres://openmettle_owner@db.example.test:5432/openmettle?sslmode=require",
                None,
                &DumpCancel::new(),
                &mut out,
            )
            .unwrap();
        let obs = fs::read_to_string(&observed).unwrap();
        assert!(obs.contains("PGGSSENCMODE=disable\n"), "{obs}");
        let mut parent_dirs = BTreeSet::new();
        for key in [
            "PGPASSFILE",
            "PGSSLROOTCERT",
            "PGSSLCERT",
            "PGSSLKEY",
            "PGSSLCRL",
            "PGSSLCRLDIR",
            "PGSERVICEFILE",
        ] {
            let val = obs
                .lines()
                .find_map(|l| l.strip_prefix(&format!("{key}=")))
                .unwrap_or("");
            assert!(
                !val.is_empty(),
                "{key} must be explicitly pinned to isolate libpq from $HOME defaults: {obs}"
            );
            assert!(
                !Path::new(val).exists(),
                "{key} path must not exist after dump: {val}"
            );
            parent_dirs.insert(Path::new(val).parent().unwrap().to_path_buf());
        }
        assert_eq!(parent_dirs.len(), 1);
        assert!(
            !parent_dirs.into_iter().next().unwrap().exists(),
            "ephemeral pg env directory must be removed on drop"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn chroma_qualification_ref_and_rebuildable_indexes_enforce_gate() {
        assert!(validate_chroma_qualification_ref("ADR-0046-chroma-rebuild-2026-11").is_ok());
        assert!(validate_chroma_qualification_ref("").is_err());
        assert!(validate_chroma_qualification_ref(" leading").is_err());
        assert!(validate_chroma_qualification_ref("bad\nref").is_err());
        assert!(validate_chroma_qualification_ref(&"a".repeat(257)).is_err());

        let not_prov = rebuildable_indexes_for(&ChromaManifest::NotProvisioned);
        assert!(!not_prov.iter().any(|s| s == CHROMA_REBUILDABLE_INDEX));
        let archived = rebuildable_indexes_for(&ChromaManifest::Archive {
            component: "chroma.archive.enc".to_owned(),
            plaintext_bytes: 12,
            plaintext_sha256: "a".repeat(64),
        });
        assert!(!archived.iter().any(|s| s == CHROMA_REBUILDABLE_INDEX));
        let qualified = rebuildable_indexes_for(&ChromaManifest::QualifiedRebuild {
            qualification_ref: "qual-ref-1".to_owned(),
        });
        assert!(qualified.iter().any(|s| s == CHROMA_REBUILDABLE_INDEX));
    }

    #[tokio::test]
    async fn verify_pg_tls_preflight_enforces_strict_sslrootcert_hostname_expiry_and_mtls() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use rustls::pki_types::PrivatePkcs8KeyDer;
        use tokio::net::TcpListener;

        fn pem_block(label: &str, der: &[u8]) -> Vec<u8> {
            let body = STANDARD.encode(der);
            let mut out = format!("-----BEGIN {label}-----\n");
            for line in body.as_bytes().chunks(64) {
                out.push_str(std::str::from_utf8(line).unwrap());
                out.push('\n');
            }
            out.push_str(&format!("-----END {label}-----\n"));
            out.into_bytes()
        }

        fn make_ca(
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

        fn make_leaf(
            issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
            ca_der: &CertificateDer<'static>,
            san: &str,
            eku: rcgen::ExtendedKeyUsagePurpose,
            expired: bool,
        ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(vec![san.to_owned()]).unwrap();
            params.extended_key_usages = vec![eku];
            if expired {
                params.not_before = rcgen::date_time_ymd(2000, 1, 1);
                params.not_after = rcgen::date_time_ymd(2001, 1, 1);
            }
            let cert = params.signed_by(&key, issuer).unwrap();
            (
                vec![cert.der().clone(), ca_der.clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
        }

        async fn spawn_pg_tls_stub(
            server_config: Option<Arc<rustls::ServerConfig>>,
        ) -> (u16, tokio::task::JoinHandle<()>) {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let handle = tokio::spawn(async move {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let mut req = [0u8; 8];
                if read_exact_tcp(&tcp, &mut req).await.is_err() || req != PG_SSL_REQUEST {
                    return;
                }
                match server_config {
                    None => {
                        let _ = write_all_tcp(&tcp, b"N").await;
                    }
                    Some(cfg) => {
                        if write_all_tcp(&tcp, b"S").await.is_err() {
                            return;
                        }
                        let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
                        let _ = acceptor.accept(tcp).await;
                    }
                }
            });
            (port, handle)
        }

        let mut rnd = [0u8; 4];
        SystemRandom::new().fill(&mut rnd).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "om-tls-preflight-{}-{:02x}{:02x}{:02x}{:02x}",
            std::process::id(),
            rnd[0],
            rnd[1],
            rnd[2],
            rnd[3],
        ));
        let _ = fs::remove_dir_all(&dir);
        create_dir_0700(&dir).unwrap();

        let (ca_server, ca_server_der) = make_ca("OpenMettle Test PG Server CA");
        let (ca_other, ca_other_der) = make_ca("OpenMettle Test Unrelated CA");
        let ca_server_path = dir.join("ca-server.pem");
        let ca_other_path = dir.join("ca-other.pem");
        write_file_0600(
            &ca_server_path,
            &pem_block("CERTIFICATE", ca_server_der.as_ref()),
        )
        .unwrap();
        write_file_0600(
            &ca_other_path,
            &pem_block("CERTIFICATE", ca_other_der.as_ref()),
        )
        .unwrap();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let build_server =
            |chain: Vec<CertificateDer<'static>>,
             key: PrivateKeyDer<'static>,
             require_client_ca: Option<CertificateDer<'static>>| {
                let b = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
                    .with_safe_default_protocol_versions()
                    .unwrap();
                let cfg = match require_client_ca {
                    None => b
                        .with_no_client_auth()
                        .with_single_cert(chain, key)
                        .unwrap(),
                    Some(client_ca) => {
                        let mut roots = RootCertStore::empty();
                        roots.add(client_ca).unwrap();
                        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                            Arc::new(roots),
                            Arc::clone(&provider),
                        )
                        .build()
                        .unwrap();
                        b.with_client_cert_verifier(verifier)
                            .with_single_cert(chain, key)
                            .unwrap()
                    }
                };
                Arc::new(cfg)
            };

        // 1. verify-full succeeds with matching 127.0.0.1 IP SAN and ca_server.
        let (chain_ip, key_ip) = make_leaf(
            &ca_server,
            &ca_server_der,
            "127.0.0.1",
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            false,
        );
        let (port, h) = spawn_pg_tls_stub(Some(build_server(chain_ip, key_ip, None))).await;
        let cfg = parse_validated_pg_uri(&format!(
            "postgres://u:p@127.0.0.1:{port}/db?sslmode=verify-full&sslrootcert={}",
            ca_server_path.display()
        ))
        .unwrap();
        verify_pg_tls_preflight(&cfg).await.unwrap();
        let _ = h.await;

        // 2. verify-full rejects mismatched SAN (`other.example.test`), while verify-ca accepts it.
        let (chain_other_san, key_other_san) = make_leaf(
            &ca_server,
            &ca_server_der,
            "other.example.test",
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            false,
        );
        let srv_other_san = build_server(chain_other_san, key_other_san, None);
        let (port, h) = spawn_pg_tls_stub(Some(Arc::clone(&srv_other_san))).await;
        let cfg_full = parse_validated_pg_uri(&format!(
            "postgres://u:p@127.0.0.1:{port}/db?sslmode=verify-full&sslrootcert={}",
            ca_server_path.display()
        ))
        .unwrap();
        assert!(verify_pg_tls_preflight(&cfg_full).await.is_err());
        let _ = h.await;

        let (port, h) = spawn_pg_tls_stub(Some(srv_other_san)).await;
        let cfg_ca = parse_validated_pg_uri(&format!(
            "postgres://u:p@127.0.0.1:{port}/db?sslmode=verify-ca&sslrootcert={}",
            ca_server_path.display()
        ))
        .unwrap();
        verify_pg_tls_preflight(&cfg_ca).await.unwrap();
        let _ = h.await;

        // 3. verify-ca still rejects expired certificates even from the trusted CA.
        let (chain_exp, key_exp) = make_leaf(
            &ca_server,
            &ca_server_der,
            "other.example.test",
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            true,
        );
        let (port, h) = spawn_pg_tls_stub(Some(build_server(chain_exp, key_exp, None))).await;
        let cfg_exp = parse_validated_pg_uri(&format!(
            "postgres://u:p@127.0.0.1:{port}/db?sslmode=verify-ca&sslrootcert={}",
            ca_server_path.display()
        ))
        .unwrap();
        assert!(verify_pg_tls_preflight(&cfg_exp).await.is_err());
        let _ = h.await;

        // 4. Both verify-ca and verify-full reject a server signed by ca_server when sslrootcert
        //    only trusts ca_other.
        let (chain_ip2, key_ip2) = make_leaf(
            &ca_server,
            &ca_server_der,
            "127.0.0.1",
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            false,
        );
        let (port, h) = spawn_pg_tls_stub(Some(build_server(chain_ip2, key_ip2, None))).await;
        let cfg_wrong_ca = parse_validated_pg_uri(&format!(
            "postgres://u:p@127.0.0.1:{port}/db?sslmode=verify-ca&sslrootcert={}",
            ca_other_path.display()
        ))
        .unwrap();
        assert!(verify_pg_tls_preflight(&cfg_wrong_ca).await.is_err());
        let _ = h.await;

        // 5. Server declining SSL (`N`) fails preflight.
        let (port, h) = spawn_pg_tls_stub(None).await;
        let cfg_decline = parse_validated_pg_uri(&format!(
            "postgres://u:p@127.0.0.1:{port}/db?sslmode=verify-ca&sslrootcert={}",
            ca_server_path.display()
        ))
        .unwrap();
        assert!(verify_pg_tls_preflight(&cfg_decline).await.is_err());
        let _ = h.await;

        // 6. Mutual TLS (`sslcert` + `sslkey`) succeeds against a server requiring a client cert.
        let (chain_mtls, key_mtls) = make_leaf(
            &ca_server,
            &ca_server_der,
            "127.0.0.1",
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            false,
        );
        let (client_chain, client_key) = make_leaf(
            &ca_other,
            &ca_other_der,
            "openmettle_owner",
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            false,
        );
        let client_cert_path = dir.join("client.pem");
        let client_key_path = dir.join("client.key");
        let mut client_pem = Vec::new();
        for c in &client_chain {
            client_pem.extend_from_slice(&pem_block("CERTIFICATE", c.as_ref()));
        }
        write_file_0600(&client_cert_path, &client_pem).unwrap();
        write_file_0600(
            &client_key_path,
            &pem_block("PRIVATE KEY", client_key.secret_der()),
        )
        .unwrap();
        let (port, h) = spawn_pg_tls_stub(Some(build_server(
            chain_mtls,
            key_mtls,
            Some(ca_other_der.clone()),
        )))
        .await;
        let cfg_mtls = parse_validated_pg_uri(&format!(
            "postgres://u:p@127.0.0.1:{port}/db?sslmode=verify-full&sslrootcert={}&sslcert={}&sslkey={}",
            ca_server_path.display(),
            client_cert_path.display(),
            client_key_path.display(),
        ))
        .unwrap();
        verify_pg_tls_preflight(&cfg_mtls).await.unwrap();
        let _ = h.await;

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_pg_dump_runner_writes_localhost_pgpass_entry_for_unix_socket_hosts() {
        let mut rnd = [0u8; 4];
        SystemRandom::new().fill(&mut rnd).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "om-pgpass-sock-{}-{:02x}{:02x}{:02x}{:02x}",
            std::process::id(),
            rnd[0],
            rnd[1],
            rnd[2],
            rnd[3],
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let script = dir.join("fake-pg-dump.sh");
        let observed = dir.join("pgpass-observed.txt");
        let body = format!(
            "#!/bin/sh\nset -eu\ncp \"$PGPASSFILE\" \"{}\"\nprintf 'PGDMP'\n",
            observed.display(),
        );
        fs::write(&script, body).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();

        let runner = CliPgDumpRunner::with_program(&script);
        let mut out = Vec::new();
        runner
            .dump(
                "postgres://openmettle_owner:s%3Aecret@%2Fvar%2Frun%2Fpostgresql:5432/openmettle?sslmode=disable",
                None,
                &DumpCancel::new(),
                &mut out,
            )
            .unwrap();
        let content = fs::read_to_string(&observed).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(
            lines,
            vec![
                r"/var/run/postgresql:5432:openmettle:openmettle_owner:s\:ecret",
                r"localhost:5432:openmettle:openmettle_owner:s\:ecret",
            ],
            "Unix socket host PGPASSFILE must contain both socket-dir and localhost lines: {content}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn external_archives_refuse_backup_and_vault_key_custody_inodes() {
        if std::env::var_os("OPENMETTLE_TEST_EXT_KEY_CHILD").is_some() {
            let dir = PathBuf::from(std::env::var("OPENMETTLE_TEST_EXT_KEY_DIR").unwrap());
            let backup_cfg = dir.join("backup-keyring.json");
            let backup_key = dir.join("backup-k1.key");
            let vault_cfg = dir.join("vault-keyring.json");
            let vault_key = dir.join("vault-k1.key");
            let binary_archive = dir.join("valid-binary.dump");

            let keyring = BackupKeyRing::load_from_config(&backup_cfg).unwrap();
            let protected = collect_protected_key_inodes(keyring.paths()).unwrap();

            // Binary (non-UTF-8) archive outside key custody succeeds for both Neo4j and Chroma.
            assert!(
                OpenedExternalFile::open(&binary_archive, &protected, &NEO4J_DUMP_ERRORS).is_ok()
            );
            assert!(
                OpenedExternalFile::open(&binary_archive, &protected, &CHROMA_ARCHIVE_ERRORS)
                    .is_ok()
            );

            // Backup key, backup keyring config, vault key, and vault keyring config are ALL
            // rejected for both `--neo4j-dump` and `--chroma-archive`.
            for forbidden in [&backup_key, &backup_cfg, &vault_key, &vault_cfg] {
                assert!(
                    matches!(
                        OpenedExternalFile::open(forbidden, &protected, &NEO4J_DUMP_ERRORS),
                        Err(BackupError::Invalid(msg)) if msg.contains("key custody")
                    ),
                    "expected --neo4j-dump to refuse {}",
                    forbidden.display()
                );
                assert!(
                    matches!(
                        OpenedExternalFile::open(forbidden, &protected, &CHROMA_ARCHIVE_ERRORS),
                        Err(BackupError::Invalid(msg)) if msg.contains("key custody")
                    ),
                    "expected --chroma-archive to refuse {}",
                    forbidden.display()
                );
            }

            // Atomically rotate the backup key file via `rename` (creating a brand-new inode)
            // while retaining a hard link to the pre-rotation inode. Re-collecting protected inodes
            // must refuse BOTH the pre-rotation hard link and the newly rotated key file.
            let old_key_hardlink = dir.join("old-backup-key-hardlink.bin");
            fs::hard_link(&backup_key, &old_key_hardlink).unwrap();
            let rotated_tmp = dir.join("backup-k1.key.rotated.tmp");
            write_file_0600(&rotated_tmp, &[0x33u8; 32]).unwrap();
            fs::rename(&rotated_tmp, &backup_key).unwrap();

            let protected_after_rotate = collect_protected_key_inodes(keyring.paths()).unwrap();
            for forbidden in [&old_key_hardlink, &backup_key] {
                assert!(
                    matches!(
                        OpenedExternalFile::open(
                            forbidden,
                            &protected_after_rotate,
                            &NEO4J_DUMP_ERRORS
                        ),
                        Err(BackupError::Invalid(msg)) if msg.contains("key custody")
                    ),
                    "expected --neo4j-dump to refuse rotated/hardlinked key {}",
                    forbidden.display()
                );
                assert!(
                    matches!(
                        OpenedExternalFile::open(
                            forbidden,
                            &protected_after_rotate,
                            &CHROMA_ARCHIVE_ERRORS
                        ),
                        Err(BackupError::Invalid(msg)) if msg.contains("key custody")
                    ),
                    "expected --chroma-archive to refuse rotated/hardlinked key {}",
                    forbidden.display()
                );
                assert!(
                    load_non_secret_config_files(
                        &[("leak.txt".to_owned(), forbidden.clone())],
                        keyring.paths()
                    )
                    .is_err(),
                    "expected --config-file to refuse rotated/hardlinked key {}",
                    forbidden.display()
                );
            }
            return;
        }

        let mut rnd = [0u8; 4];
        SystemRandom::new().fill(&mut rnd).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "om-ext-key-custody-{}-{:02x}{:02x}{:02x}{:02x}",
            std::process::id(),
            rnd[0],
            rnd[1],
            rnd[2],
            rnd[3],
        ));
        let _ = fs::remove_dir_all(&dir);
        create_dir_0700(&dir).unwrap();

        let backup_key = dir.join("backup-k1.key");
        let backup_cfg = dir.join("backup-keyring.json");
        let vault_key = dir.join("vault-k1.key");
        let vault_cfg = dir.join("vault-keyring.json");
        let binary_archive = dir.join("valid-binary.dump");

        write_file_0600(&backup_key, &[0x11u8; 32]).unwrap();
        write_file_0600(
            &backup_cfg,
            json!({
                "version": 1,
                "active_key_id": "bk1",
                "keys": [{ "id": "bk1", "file": backup_key.to_str().unwrap() }]
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        write_file_0600(&vault_key, &[0x22u8; 32]).unwrap();
        write_file_0600(
            &vault_cfg,
            json!({
                "version": 1,
                "active_key_id": "vk1",
                "keys": [{ "id": "vk1", "file": vault_key.to_str().unwrap() }]
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        // Deliberately non-UTF-8 binary payload.
        write_file_0600(&binary_archive, &[0xff, 0xfe, 0x00, 0x01, 0x80, 0x99]).unwrap();

        let exe = std::env::current_exe().unwrap();
        let out = Command::new(&exe)
            .args([
                "--exact",
                "backup::tests::external_archives_refuse_backup_and_vault_key_custody_inodes",
            ])
            .env("OPENMETTLE_TEST_EXT_KEY_CHILD", "1")
            .env("OPENMETTLE_TEST_EXT_KEY_DIR", &dir)
            .env("OPENMETTLE_ADMIN_VAULT_KEYS_CONFIG", &vault_cfg)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "external archive key custody subprocess failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn strict_tls_tunnel_blocks_forwarding_bytes_after_cert_rotation() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use rustls::pki_types::PrivatePkcs8KeyDer;
        use std::os::unix::fs::FileTypeExt;
        use std::sync::{RwLock, atomic::AtomicUsize};

        async fn write_all_stream<S: AsyncWrite + Unpin>(
            stream: &mut S,
            mut buf: &[u8],
        ) -> io::Result<()> {
            while !buf.is_empty() {
                let n =
                    std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_write(cx, buf)).await?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero"));
                }
                buf = &buf[n..];
            }
            std::future::poll_fn(|cx| Pin::new(&mut *stream).poll_flush(cx)).await
        }

        async fn read_exact_stream<S: AsyncRead + Unpin>(
            stream: &mut S,
            mut buf: &mut [u8],
        ) -> io::Result<()> {
            while !buf.is_empty() {
                let n = std::future::poll_fn(|cx| {
                    let mut rb = ReadBuf::new(buf);
                    match Pin::new(&mut *stream).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                        Poll::Pending => Poll::Pending,
                    }
                })
                .await?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof"));
                }
                buf = &mut buf[n..];
            }
            Ok(())
        }

        fn pem_cert(der: &[u8]) -> Vec<u8> {
            let body = STANDARD.encode(der);
            let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
            for line in body.as_bytes().chunks(64) {
                out.push_str(std::str::from_utf8(line).unwrap());
                out.push('\n');
            }
            out.push_str("-----END CERTIFICATE-----\n");
            out.into_bytes()
        }

        fn make_ca(
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

        let shared_sessions: Arc<dyn rustls::server::StoresServerSessions> =
            rustls::server::ServerSessionMemoryCache::new(256);
        let shared_ticketer: Arc<dyn rustls::server::ProducesTickets> =
            rustls::crypto::ring::Ticketer::new().unwrap();

        let make_srv = |issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
                        ca_der: &CertificateDer<'static>| {
            let key = rcgen::KeyPair::generate().unwrap();
            let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
            let cert = params.signed_by(&key, issuer).unwrap();
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone(), ca_der.clone()],
                    PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
                )
                .unwrap();
            cfg.session_storage = Arc::clone(&shared_sessions);
            cfg.ticketer = Arc::clone(&shared_ticketer);
            cfg.send_tls13_tickets = 2;
            Arc::new(cfg)
        };

        let mut rnd = [0u8; 4];
        SystemRandom::new().fill(&mut rnd).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "om-tls-tunnel-{}-{:02x}{:02x}{:02x}{:02x}",
            std::process::id(),
            rnd[0],
            rnd[1],
            rnd[2],
            rnd[3],
        ));
        let _ = fs::remove_dir_all(&dir);
        create_dir_0700(&dir).unwrap();

        let (ca_good, ca_good_der) = make_ca("Tunnel Good CA");
        let (ca_bad, ca_bad_der) = make_ca("Tunnel Rotated Untrusted CA");
        let ca_good_path = dir.join("ca-good.pem");
        write_file_0600(&ca_good_path, &pem_cert(ca_good_der.as_ref())).unwrap();

        let active_cfg = Arc::new(RwLock::new(make_srv(&ca_good, &ca_good_der)));
        let forwarded_bytes = Arc::new(AtomicUsize::new(0));

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let remote_port = listener.local_addr().unwrap().port();
        let cfg_srv = Arc::clone(&active_cfg);
        let bytes_srv = Arc::clone(&forwarded_bytes);
        let server_task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let cfg = Arc::clone(&cfg_srv.read().unwrap());
                let bytes = Arc::clone(&bytes_srv);
                tokio::spawn(async move {
                    let mut req = [0u8; 8];
                    if read_exact_tcp(&tcp, &mut req).await.is_err() || req != PG_SSL_REQUEST {
                        return;
                    }
                    if write_all_tcp(&tcp, b"S").await.is_err() {
                        return;
                    }
                    let Ok(mut tls) = tokio_rustls::TlsAcceptor::from(cfg).accept(tcp).await else {
                        return;
                    };
                    let mut buf = [0u8; 128];
                    let n = std::future::poll_fn(|cx| {
                        let mut rb = ReadBuf::new(&mut buf);
                        match Pin::new(&mut tls).poll_read(cx, &mut rb) {
                            Poll::Ready(Ok(())) => Poll::Ready(rb.filled().len()),
                            Poll::Ready(Err(_)) => Poll::Ready(0),
                            Poll::Pending => Poll::Pending,
                        }
                    })
                    .await;
                    bytes.fetch_add(n, Ordering::SeqCst);
                    if n > 0 {
                        let _ = std::future::poll_fn(|cx| {
                            Pin::new(&mut tls).poll_write(cx, b"ECHO-OK")
                        })
                        .await;
                        let _ = std::future::poll_fn(|cx| Pin::new(&mut tls).poll_flush(cx)).await;
                        // Keep TLS stream open briefly so post-handshake TLS 1.3 NewSessionTicket
                        // frames flush cleanly before client drops.
                        tokio::time::sleep(Duration::from_millis(80)).await;
                    }
                });
            }
        });

        let pg_cfg = parse_validated_pg_uri(&format!(
            "postgres://u:p@127.0.0.1:{remote_port}/db?sslmode=verify-full&sslrootcert={}",
            ca_good_path.display()
        ))
        .unwrap();
        let (tls_cfg, server_name) = build_strict_tls_client(&pg_cfg).unwrap();
        let tunnel =
            StrictTlsTunnel::start("127.0.0.1".to_owned(), remote_port, tls_cfg, server_name)
                .await
                .unwrap();

        // Verify strict owner-only Unix domain socket isolation (`0700` dir, `0600` socket).
        let socket_dir = tunnel.socket_dir.clone();
        let sock_path = socket_dir.join(format!(".s.PGSQL.{STRICT_TLS_TUNNEL_PORT}"));
        let dir_meta = fs::metadata(&socket_dir).unwrap();
        assert!(dir_meta.is_dir());
        assert_eq!(dir_meta.permissions().mode() & 0o777, 0o700);
        let sock_meta = fs::metadata(&sock_path).unwrap();
        assert!(sock_meta.file_type().is_socket());
        assert_eq!(sock_meta.permissions().mode() & 0o777, 0o600);

        // First connection against trusted `ca_good` forwards traffic cleanly.
        let mut c1 = UnixStream::connect(&sock_path).await.unwrap();
        write_all_stream(&mut c1, b"STARTUP-1").await.unwrap();
        let mut resp = [0u8; 7];
        read_exact_stream(&mut c1, &mut resp).await.unwrap();
        assert_eq!(&resp, b"ECHO-OK");
        // Allow server TLS 1.3 NewSessionTicket messages to arrive before disconnecting.
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(c1);

        // Rotate server to untrusted `ca_bad` while retaining identical session cache & ticketer.
        *active_cfg.write().unwrap() = make_srv(&ca_bad, &ca_bad_der);
        forwarded_bytes.store(0, Ordering::SeqCst);

        // Second connection through the SAME tunnel must not resume via PSK/session-ID and must
        // close before forwarding any bytes.
        let mut c2 = UnixStream::connect(&sock_path).await.unwrap();
        let _ = write_all_stream(&mut c2, b"SECRET-STARTUP-MUST-NOT-LEAK").await;
        let mut probe = [0u8; 1];
        let read_res = read_exact_stream(&mut c2, &mut probe).await;
        assert!(
            read_res.is_err(),
            "tunnel must close connection when rotated cert is outside sslrootcert even with shared ticket keys"
        );
        assert_eq!(
            forwarded_bytes.load(Ordering::SeqCst),
            0,
            "zero bytes may reach an untrusted rotated server"
        );

        drop(tunnel);
        assert!(
            !socket_dir.exists(),
            "StrictTlsTunnel must unlink its 0700 socket directory on Drop"
        );
        server_task.abort();
        let _ = fs::remove_dir_all(&dir);
    }
}
