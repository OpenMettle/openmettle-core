//! One-shot schema migration process (ADR 0003). API and worker processes never call this.
use crate::telemetry::{self, MigrationFailure, Process, Signal};
use sqlx::{
    ConnectOptions, Connection, Executor, PgConnection, SqlSafeStr, postgres::PgConnectOptions,
};
use sqlx_core::migrate::{Migrate, MigrateError, Migration, MigrationType, Migrator};
use std::{borrow::Cow, fmt, time::Duration};

/// Schema that owns every OpenMettle object, including migration history.
pub const SCHEMA: &str = "openmettle";
/// Migration history table, kept inside the owned schema rather than `public`.
pub const HISTORY_TABLE: &str = "openmettle._sqlx_migrations";
/// Reported as `application_name` so operators can identify migration sessions.
pub const APPLICATION_NAME: &str = "openmettle-migrate";
/// Read-only role, privilege and ownership check run before SQLx bootstrap and after migrating.
const BOUNDARIES: &str = include_str!("boundaries.sql");

/// An embedded forward-only migration. Released migrations are immutable: their checksum is
/// recorded in the history table and any later edit is refused.
#[derive(Clone, Copy)]
pub struct Source {
    pub version: i64,
    pub description: &'static str,
    pub sql: &'static str,
}

/// The release's ordered migration set.
pub const MIGRATIONS: &[Source] = &[
    Source {
        version: 1,
        description: "identity and ownership scopes",
        sql: include_str!("../migrations/0001_identity_and_scopes.sql"),
    },
    Source {
        version: 2,
        description: "conversations and messages",
        sql: include_str!("../migrations/0002_conversations_and_messages.sql"),
    },
    Source {
        version: 3,
        description: "runs events and operations",
        sql: include_str!("../migrations/0003_runs_events_operations.sql"),
    },
    Source {
        version: 4,
        description: "artifacts storage accounting",
        sql: include_str!("../migrations/0004_artifacts_storage_accounting.sql"),
    },
    Source {
        version: 5,
        description: "grant persistence",
        sql: include_str!("../migrations/0005_grant_persistence.sql"),
    },
    Source {
        version: 6,
        description: "protected login transactions",
        sql: include_str!("../migrations/0006_login_transactions.sql"),
    },
    Source {
        version: 7,
        description: "login provider authority",
        sql: include_str!("../migrations/0007_login_provider_authority.sql"),
    },
    Source {
        version: 8,
        description: "local identity approval and sessions",
        sql: include_str!("../migrations/0008_local_identity_sessions.sql"),
    },
    Source {
        version: 9,
        description: "login admission limit",
        sql: include_str!("../migrations/0009_login_admission.sql"),
    },
    Source {
        version: 10,
        description: "audited provider recovery",
        sql: include_str!("../migrations/0010_provider_recoveries.sql"),
    },
    Source {
        version: 11,
        description: "approved project membership observations",
        sql: include_str!("../migrations/0011_membership_observations.sql"),
    },
    Source {
        version: 12,
        description: "home first-account invitations",
        sql: include_str!("../migrations/0012_home_invitations.sql"),
    },
    Source {
        version: 13,
        description: "home invitation codes",
        sql: include_str!("../migrations/0013_home_invitation_codes.sql"),
    },
    Source {
        version: 14,
        description: "native sign-in handoffs",
        sql: include_str!("../migrations/0014_native_handoffs.sql"),
    },
    Source {
        version: 15,
        description: "authorization and private projects",
        sql: include_str!("../migrations/0015_authorization_and_projects.sql"),
    },
    Source {
        version: 16,
        description: "group and project grantees",
        sql: include_str!("../migrations/0016_grant_group_grantees.sql"),
    },
    Source {
        version: 17,
        description: "artifact revision display name",
        sql: include_str!("../migrations/0017_artifact_revision_display_name.sql"),
    },
    Source {
        version: 18,
        description: "session issuance role",
        sql: include_str!("../migrations/0018_session_issuance_role.sql"),
    },
    Source {
        version: 19,
        description: "run admission and queue",
        sql: include_str!("../migrations/0019_run_admission_and_queue.sql"),
    },
    Source {
        version: 20,
        description: "worker leases and deadlines",
        sql: include_str!("../migrations/0020_worker_leases_and_deadlines.sql"),
    },
    Source {
        version: 21,
        description: "conversation branch graph",
        sql: include_str!("../migrations/0021_conversation_branch_graph.sql"),
    },
];

/// Connection and deadline settings for one migration run.
pub struct Settings {
    pub database: PgConnectOptions,
    pub connect_timeout: Duration,
    pub lock_timeout: Duration,
    pub statement_timeout: Duration,
}

impl Settings {
    /// Connection settings, then telemetry settings, under the same prefix. The API's
    /// issuance credential is refused first: the migrator never reads it (ADR 0030).
    fn load() -> Result<(Self, telemetry::Settings), &'static str> {
        crate::refuse_issuance_url()?;
        let get = |key: &str| crate::env_var("OPENMETTLE_MIGRATE", key);
        Ok((Self::parse(get)?, telemetry::Settings::parse(get)?))
    }

    fn parse(
        get: impl Fn(&str) -> Result<Option<String>, &'static str>,
    ) -> Result<Self, &'static str> {
        let url = get("DATABASE_URL")?.ok_or("DATABASE_URL is required")?;
        let database =
            crate::database_url(&url, "invalid DATABASE_URL scheme", "invalid DATABASE_URL")?;
        let millis = |key, default: u64, max| {
            crate::bounded_positive(get(key)?, default, max).map(Duration::from_millis)
        };
        Ok(Self {
            database,
            connect_timeout: millis("CONNECT_TIMEOUT_MS", 5_000, 60_000)?,
            lock_timeout: millis("LOCK_TIMEOUT_MS", 15_000, 600_000)?,
            statement_timeout: millis("STATEMENT_TIMEOUT_MS", 300_000, 3_600_000)?,
        })
    }
}

/// Migration failure. `Display` never includes connection details, SQL text or row values.
#[derive(Debug)]
pub enum Failure {
    Invalid(&'static str),
    ConnectTimeout,
    Connect(sqlx::Error),
    /// The boundary check or a session reset could not run.
    Check(sqlx::Error),
    /// Provisioned roles, privileges or ownership violate the contract; nothing was changed.
    Refused(Vec<String>),
    /// Migrations committed, but the result violates the privilege contract.
    Violated(Vec<String>),
    Migrate(MigrateError),
}

fn describe(error: &sqlx::Error) -> String {
    match error {
        sqlx::Error::Database(e) => format!("SQLSTATE {}", e.code().unwrap_or_default()),
        sqlx::Error::Io(_) => "I/O error".into(),
        sqlx::Error::Tls(_) => "TLS error".into(),
        _ => "protocol or driver error".into(),
    }
}

impl Failure {
    /// The telemetry class; the CLI line keeps the detail.
    fn class(&self) -> MigrationFailure {
        match self {
            Self::Invalid(_) => MigrationFailure::Invalid,
            Self::ConnectTimeout => MigrationFailure::ConnectTimeout,
            Self::Connect(_) => MigrationFailure::Connect,
            Self::Check(_) => MigrationFailure::Check,
            Self::Refused(_) => MigrationFailure::Refused,
            Self::Violated(_) => MigrationFailure::Violated,
            Self::Migrate(_) => MigrationFailure::Migrate,
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid migration set: {message}"),
            Self::ConnectTimeout => f.write_str("database connection deadline exceeded"),
            Self::Connect(e) => write!(f, "database connection failed ({})", describe(e)),
            Self::Check(e) => write!(f, "database boundary check failed ({})", describe(e)),
            Self::Refused(violations) => write!(
                f,
                "database boundary check refused to migrate: {}",
                violations.join("; ")
            ),
            Self::Violated(violations) => write!(
                f,
                "migrated schema violates the privilege contract: {}",
                violations.join("; ")
            ),
            Self::Migrate(e) => match e {
                MigrateError::ExecuteMigration(e, version) => {
                    write!(f, "migration {version} failed ({})", describe(e))
                }
                MigrateError::Execute(e) => {
                    write!(f, "migration control statement failed ({})", describe(e))
                }
                MigrateError::VersionMismatch(version) => write!(
                    f,
                    "applied migration {version} differs from this release (checksum mismatch)"
                ),
                MigrateError::VersionMissing(version) => write!(
                    f,
                    "database has migration {version}, which this release does not contain"
                ),
                MigrateError::Dirty(version) => {
                    write!(f, "migration {version} is recorded as partially applied")
                }
                _ => f.write_str("migration failed"),
            },
        }
    }
}

const TRANSACTION_CONTROL: &[&str] = &[
    "ABORT",
    "BEGIN",
    "COMMIT",
    "END",
    "PREPARE",
    "RELEASE",
    "ROLLBACK",
    "SAVEPOINT",
    "START",
];

fn skip_quoted(sql: &[u8], start: usize, quote: u8, escapes: bool) -> Result<usize, &'static str> {
    let mut i = start + 1;
    while i < sql.len() {
        if escapes && sql[i] == b'\\' {
            i += 2;
        } else if sql[i] == quote {
            if sql.get(i + 1) == Some(&quote) {
                i += 2;
            } else {
                return Ok(i + 1);
            }
        } else {
            i += 1;
        }
    }
    Err("unterminated quoted text")
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte >= 0x80
}

/// PostgreSQL's scanner whitespace (scan.l `space`), which includes vertical tab.
fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

/// Each migration commits atomically with its history row, so top-level transaction control
/// (which would commit part of a migration early) is refused before connecting. PostgreSQL
/// itself rejects statements that cannot run inside a transaction block, such as
/// `CREATE INDEX CONCURRENTLY` or `VACUUM`. This lexical check fails closed: SQL-standard
/// `BEGIN ATOMIC` bodies are refused; use dollar-quoted bodies instead. The check models
/// `standard_conforming_strings = on`, which `apply` sets before every migration. Adjacent
/// string literals (including newline/comment continuations) are refused; use one literal.
pub fn check_transactional(sql: &str) -> Result<(), &'static str> {
    const REFUSED: &str = "transaction control statements are not permitted in migrations";
    if sql.trim_start().starts_with("-- no-transaction") {
        return Err("non-transactional migrations are not permitted");
    }
    let b = sql.as_bytes();
    let mut i = 0;
    let mut statement_start = true;
    let mut previous_string = false;
    while i < b.len() {
        let c = b[i];
        if c == b'-' && b.get(i + 1) == Some(&b'-') {
            // PostgreSQL ends a `--` comment at either LF or CR (scan.l `newline`).
            while i < b.len() && !matches!(b[i], b'\n' | b'\r') {
                i += 1;
            }
            continue;
        }
        if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let mut depth = 1;
            i += 2;
            while depth > 0 {
                if i + 1 >= b.len() {
                    return Err("unterminated comment");
                }
                if b[i] == b'/' && b[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && b[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        if c == b';' {
            previous_string = false;
            statement_start = true;
            i += 1;
            continue;
        }
        if is_space(c) {
            i += 1;
            continue;
        }
        // PostgreSQL retains E-string escape mode across string continuations. Refuse
        // adjacent literals instead of trying to duplicate that contextual lexer rule.
        if previous_string && c == b'\'' {
            return Err("adjacent string literals are not permitted in migrations");
        }
        previous_string = false;
        let first = std::mem::replace(&mut statement_start, false);
        if is_word(c) {
            let start = i;
            while i < b.len() && (is_word(b[i]) || b[i] == b'$') {
                i += 1;
            }
            if first
                && TRANSACTION_CONTROL
                    .iter()
                    .any(|word| sql[start..i].eq_ignore_ascii_case(word))
            {
                return Err(REFUSED);
            }
            continue;
        }
        match c {
            b'\'' => {
                // An escape string is a standalone E/e prefix; `time'\'` is a typed literal
                // whose standard string ends at the second quote.
                let escapes = i > 0
                    && matches!(b[i - 1], b'E' | b'e')
                    && (i == 1 || !(is_word(b[i - 2]) || b[i - 2] == b'$'));
                i = skip_quoted(b, i, b'\'', escapes)?;
                previous_string = true;
            }
            b'"' => i = skip_quoted(b, i, b'"', false)?,
            b'$' => {
                let mut end = i + 1;
                if end < b.len() && !b[end].is_ascii_digit() {
                    while end < b.len() && is_word(b[end]) {
                        end += 1;
                    }
                }
                if end < b.len() && b[end] == b'$' && !b.get(i + 1).is_some_and(u8::is_ascii_digit)
                {
                    let tag = &sql[i..=end];
                    let body = end + 1;
                    let close = sql[body..]
                        .find(tag)
                        .ok_or("unterminated dollar-quoted text")?;
                    i = body + close + tag.len();
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    Ok(())
}

/// Validates a migration set and builds a locking, transactional migrator for it.
pub fn migrator(sources: &[Source]) -> Result<Migrator, Failure> {
    if sources.is_empty() {
        return Err(Failure::Invalid("no migrations"));
    }
    let mut migrations = Vec::with_capacity(sources.len());
    for (index, source) in sources.iter().enumerate() {
        if usize::try_from(source.version).ok() != Some(index + 1) {
            return Err(Failure::Invalid(
                "versions must be contiguous and start at 1",
            ));
        }
        if source.description.trim().is_empty() {
            return Err(Failure::Invalid("description required"));
        }
        check_transactional(source.sql).map_err(Failure::Invalid)?;
        migrations.push(Migration::new(
            source.version,
            Cow::Borrowed(source.description),
            MigrationType::Simple,
            source.sql.into_sql_str(),
            false,
        ));
    }
    let mut migrator = Migrator::with_migrations(migrations);
    migrator.dangerous_set_table_name(HISTORY_TABLE);
    migrator.create_schema(SCHEMA);
    migrator.set_locking(true).set_ignore_missing(false);
    Ok(migrator)
}

/// Applies `sources` over one dedicated, non-pooled connection, then ends that session on every
/// outcome. SQLx holds a session-level advisory lock while migrating and does not release it
/// when a migration fails; ending the session releases it. Deadlines are server-side session
/// settings, so lock waits and statements stop even if this process stalls.
pub async fn apply(settings: &Settings, sources: &[Source]) -> Result<(), Failure> {
    let migrator = migrator(sources)?;
    let millis = |d: Duration| format!("{}ms", d.as_millis());
    let options = settings
        .database
        .clone()
        .disable_statement_logging()
        .application_name(APPLICATION_NAME)
        .options([
            ("lock_timeout", millis(settings.lock_timeout)),
            ("statement_timeout", millis(settings.statement_timeout)),
            // Ends the server session soon after this client disappears, even mid-wait.
            ("client_connection_check_interval", "1000ms".to_owned()),
            // Migrations must schema-qualify OpenMettle objects.
            ("search_path", "pg_catalog,pg_temp".to_owned()),
            // The transaction-control check models conforming strings; pin it over any
            // database or role default.
            ("standard_conforming_strings", "on".to_owned()),
        ]);
    let mut connection = tokio::time::timeout(
        settings.connect_timeout,
        PgConnection::connect_with(&options),
    )
    .await
    .map_err(|_| Failure::ConnectTimeout)?
    .map_err(Failure::Connect)?;
    let result = migrate_within_boundaries(&migrator, &mut connection).await;
    // Dropping the connection on timeout also closes the socket.
    let _ = tokio::time::timeout(settings.connect_timeout, connection.close()).await;
    result
}

/// Returns boundary violations; empty when provisioning matches the contract.
async fn boundary_violations(connection: &mut PgConnection) -> Result<Vec<String>, sqlx::Error> {
    let history: bool =
        sqlx::query_scalar("SELECT to_regclass('openmettle._sqlx_migrations') IS NOT NULL")
            .fetch_one(&mut *connection)
            .await?;
    // Explicit grants are allowed per version only after that version has applied.
    let applied: i64 = if history {
        sqlx::query_scalar(
            "SELECT coalesce(max(version), 0) FROM openmettle._sqlx_migrations WHERE success",
        )
        .fetch_one(&mut *connection)
        .await?
    } else {
        0
    };
    sqlx::query_scalar(BOUNDARIES)
        .bind(applied)
        .fetch_all(connection)
        .await
}

async fn migrate_within_boundaries(
    migrator: &Migrator,
    connection: &mut PgConnection,
) -> Result<(), Failure> {
    // Hold the same session-level advisory lock across boundary snapshots and all versions.
    // SQLx run_to locks reentrantly and releases its own acquisition; closing our dedicated
    // connection releases this outer acquisition on success, error or cancellation.
    connection.lock().await.map_err(Failure::Migrate)?;
    // Refuse before SQLx creates the schema or history table, on every run.
    let violations = boundary_violations(connection)
        .await
        .map_err(Failure::Check)?;
    if !violations.is_empty() {
        return Err(Failure::Refused(violations));
    }
    // One version at a time, restoring the startup session settings first, so a setting
    // changed by one migration (for example standard_conforming_strings) cannot change how
    // PostgreSQL scans the next one.
    for version in migrator.iter().map(|m| m.version) {
        connection
            .execute("RESET ALL")
            .await
            .map_err(Failure::Check)?;
        migrator
            .run_to(version, &mut *connection)
            .await
            .map_err(Failure::Migrate)?;
    }
    connection
        .execute("RESET ALL")
        .await
        .map_err(Failure::Check)?;
    let violations = boundary_violations(connection)
        .await
        .map_err(Failure::Check)?;
    if violations.is_empty() {
        Ok(())
    } else {
        Err(Failure::Violated(violations))
    }
}

/// Entry point for `openmettle-migrate`: 0 success, 78 invalid configuration, 1 failure.
///
/// The result lines are the command's operator output and are kept as they were: the stdout
/// success line and the `migration error:` stderr line, whose detail names a category,
/// version, SQLSTATE or role and object names (ADR 0003). Telemetry events add only the
/// lifecycle and the failure class.
pub async fn run() -> u8 {
    let (settings, telemetry_settings) = match Settings::load() {
        Ok(settings) => settings,
        Err(message) => {
            eprintln!("configuration error: {message}");
            return 78;
        }
    };
    let telemetry = match telemetry::install(telemetry_settings, Process::Migrate, None) {
        Ok(telemetry) => telemetry,
        Err(unavailable) => {
            eprintln!("runtime error: {}", unavailable.message());
            return 1;
        }
    };
    let code = migrate(&settings).await;
    // Bounded: a stalled stderr loses the final lines, not the exit.
    telemetry.flush(telemetry::FLUSH_LIMIT);
    code
}

async fn migrate(settings: &Settings) -> u8 {
    telemetry::migration_started();
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut terminate), Ok(mut interrupt)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        telemetry::migration_failed(MigrationFailure::SignalRegistration);
        return 1;
    };
    // A signal drops the migration future and its connection; PostgreSQL rolls back the
    // open transaction and releases the session lock.
    tokio::select! {
        result = apply(settings, MIGRATIONS) => match result {
            Ok(()) => {
                println!("schema is at migration {}", MIGRATIONS.len());
                telemetry::migration_completed(MIGRATIONS.len());
                0
            }
            Err(failure) => {
                eprintln!("migration error: {failure}");
                telemetry::migration_failed(failure.class());
                1
            }
        },
        _ = terminate.recv() => {
            telemetry::migration_interrupted(Signal::Terminate);
            1
        }
        _ = interrupt.recv() => {
            telemetry::migration_interrupted(Signal::Interrupt);
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_migrations_are_valid() {
        let migrator = migrator(MIGRATIONS).unwrap();
        assert_eq!(migrator.iter().count(), MIGRATIONS.len());
        assert!(migrator.iter().all(|m| !m.no_tx));
    }

    #[test]
    fn refuses_top_level_transaction_control() {
        for sql in [
            "COMMIT;",
            "create table a (id int); commit; create table b (id int);",
            "BEGIN; CREATE TABLE a (id int);",
            "SELECT 1;\n  End",
            "ROLLBACK",
            "abort;",
            "START TRANSACTION",
            "SAVEPOINT s",
            "RELEASE SAVEPOINT s",
            "PREPARE TRANSACTION 'x'",
            "COMMIT PREPARED 'x'",
            "/* a */ -- b\n COMMIT",
            "-- no-transaction\nCREATE INDEX CONCURRENTLY i ON t (c);",
            "CREATE FUNCTION f() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 1; END;",
            // PostgreSQL ends `--` comments at CR as well as LF.
            "CREATE TABLE openmettle.probe (id int); -- comment\rCOMMIT;\nSELECT 1/0;",
            // Vertical tab is scanner whitespace.
            "SELECT 1;\x0bCOMMIT",
            // A typed literal is a standard string: the backslash does not escape the quote.
            "SELECT time'\\'; COMMIT; --'",
            "SELECT 1 AS x, e'\\''; COMMIT; --'",
        ] {
            assert!(check_transactional(sql).is_err(), "accepted: {sql}");
        }
    }

    #[test]
    fn refuses_string_continuations() {
        for separator in ["\n", "\r\n", " -- continuation\n", " /* continuation */\n"] {
            let sql = format!(
                "CREATE TABLE openmettle.probe (id int); SELECT E''{separator}'\\''; COMMIT; --';\nSELECT 1 / 0;"
            );
            assert!(check_transactional(&sql).is_err(), "accepted: {sql}");
        }
        assert!(check_transactional("SELECT 'one'\n 'two'").is_err());
        assert_eq!(check_transactional("SELECT E'one' || 'two'"), Ok(()));
    }

    #[test]
    fn accepts_transaction_words_inside_bodies_strings_and_identifiers() {
        for sql in [
            "DO $$ BEGIN RAISE NOTICE 'x'; END $$;",
            "DO $body$ BEGIN COMMIT; END $body$;",
            "SELECT 'commit; rollback';",
            "SELECT E'it\\'s; COMMIT';",
            "SELECT 1 AS \"x; COMMIT\";",
            "-- COMMIT\nSELECT 1; /* ; ROLLBACK /* nested */ */ SELECT 2;",
            "CREATE TABLE t (begin_at int, commit_id int); SELECT begin_at FROM t;",
            "SELECT $1::int;",
            "SELECT E'\\'; COMMIT; --';",
            "SELECT 1; e'\\'; COMMIT'",
            "-- comment\r\nSELECT 1;",
        ] {
            assert_eq!(check_transactional(sql), Ok(()), "{sql}");
        }
        assert!(check_transactional("SELECT 'open").is_err());
        assert!(check_transactional("DO $$ BEGIN").is_err());
    }

    #[test]
    fn refuses_invalid_migration_sets() {
        let source = |version, sql| Source {
            version,
            description: "x",
            sql,
        };
        assert!(migrator(&[]).is_err());
        assert!(migrator(&[source(2, "SELECT 1")]).is_err());
        assert!(migrator(&[source(1, "SELECT 1"), source(3, "SELECT 1")]).is_err());
        assert!(migrator(&[source(1, "SELECT 1; COMMIT")]).is_err());
    }

    /// Each failure keeps its own `error.type`, so swapping two classes fails here.
    #[test]
    fn failures_map_to_their_own_telemetry_class() {
        let cases = [
            (Failure::Invalid("x"), MigrationFailure::Invalid),
            (Failure::ConnectTimeout, MigrationFailure::ConnectTimeout),
            (
                Failure::Connect(sqlx::Error::PoolTimedOut),
                MigrationFailure::Connect,
            ),
            (
                Failure::Check(sqlx::Error::PoolClosed),
                MigrationFailure::Check,
            ),
            (Failure::Refused(vec![]), MigrationFailure::Refused),
            (Failure::Violated(vec![]), MigrationFailure::Violated),
            (
                Failure::Migrate(MigrateError::VersionMissing(1)),
                MigrationFailure::Migrate,
            ),
        ];
        for (failure, class) in &cases {
            assert_eq!(failure.class(), *class, "{failure:?}");
        }
        // Every class but signal registration, which precedes any `Failure`, is reachable.
        let classes: std::collections::BTreeSet<_> =
            cases.iter().map(|(_, c)| format!("{c:?}")).collect();
        assert_eq!(classes.len(), cases.len());
        assert!(!classes.contains("SignalRegistration"));
    }

    #[test]
    fn configuration_is_bounded() {
        let parse = |pairs: &[(&str, &str)]| {
            let pairs: Vec<(String, String)> = pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            Settings::parse(move |key| {
                Ok(pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()))
            })
        };
        let url = ("DATABASE_URL", "postgres://localhost/test");
        let settings = parse(&[url]).unwrap();
        assert_eq!(settings.lock_timeout, Duration::from_secs(15));
        assert!(parse(&[]).is_err());
        assert!(parse(&[("DATABASE_URL", "mysql://localhost/test")]).is_err());
        for key in [
            "CONNECT_TIMEOUT_MS",
            "LOCK_TIMEOUT_MS",
            "STATEMENT_TIMEOUT_MS",
        ] {
            assert!(parse(&[url, (key, "0")]).is_err());
            assert!(parse(&[url, (key, "3600001")]).is_err());
            assert!(parse(&[url, (key, "x")]).is_err());
        }
    }
}
