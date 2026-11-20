//! Migration, ownership and role-boundary tests. Ignored tests need TEST_DATABASE_URL for an
//! isolated, disposable PostgreSQL 18 service with a superuser fixture account. They create
//! synthetic cluster roles (`openmettle_*`, test-only password) and one database per test.
#[path = "support/env.rs"]
mod env_support;
use env_support::scrub_env;
use openmettle_core::migrate::{self, Failure, MIGRATIONS, Settings, Source};
use sqlx::{AssertSqlSafe, Connection, Executor, PgConnection, Row, postgres::PgConnectOptions};
use sqlx_core::migrate::{Migrate, MigrateError};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const OWNER: &str = "openmettle_owner";
const API: &str = "openmettle_api";
const WORKER: &str = "openmettle_worker";
const CAPPED: &str = "openmettle_fixture_capped";
/// Synthetic test-only credential for disposable fixture roles; never a deployment value.
const PASSWORD: &str = "fixture-only-password";

// --- process helpers ------------------------------------------------------------------------

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn binary(name: &str) -> Command {
    let mut command = Command::new(match name {
        "migrate" => env!("CARGO_BIN_EXE_openmettle-migrate"),
        "api" => env!("CARGO_BIN_EXE_openmettle-api"),
        _ => env!("CARGO_BIN_EXE_openmettle-worker"),
    });
    scrub_env(&mut command);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command
}

fn migrate_command(url: &str, extra: &[(&str, &str)]) -> Command {
    let mut command = binary("migrate");
    command.env("OPENMETTLE_MIGRATE_DATABASE_URL", url);
    for (key, value) in extra {
        command.env(format!("OPENMETTLE_MIGRATE_{key}"), value);
    }
    command
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn address() -> String {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}

fn http_status(address: &str, path: &str) -> Option<String> {
    let mut stream =
        TcpStream::connect_timeout(&address.parse().unwrap(), Duration::from_millis(300)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    response.lines().next().map(str::to_owned)
}

fn start_service(worker: bool, url: &str) -> (Process, String) {
    let prefix = if worker {
        "OPENMETTLE_WORKER"
    } else {
        "OPENMETTLE_API"
    };
    let bind = address();
    let child = binary(if worker { "worker" } else { "api" })
        .env(format!("{prefix}_BIND"), &bind)
        .env(format!("{prefix}_DATABASE_URL"), url)
        .env(format!("{prefix}_DB_TIMEOUT_MS"), "1000")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    (Process(child), bind)
}

fn wait_ready(process: &mut Process, bind: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(process.0.try_wait().unwrap().is_none(), "process exited");
        if http_status(bind, "/readyz").is_some_and(|s| s.starts_with("HTTP/1.1 200")) {
            return;
        }
        assert!(Instant::now() < deadline, "readiness deadline");
        thread::sleep(Duration::from_millis(50));
    }
}

fn signal(child: &Child, signal: &str) {
    assert!(
        Command::new("kill")
            .args([signal, &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
}

// --- database fixture -------------------------------------------------------------------------

/// Every embedded migration version, in order: the expected history after a full apply.
fn all_versions() -> Vec<i64> {
    MIGRATIONS.iter().map(|m| m.version).collect()
}

/// The expected history after applying migrations 1 through `last`.
fn versions_through(last: i64) -> Vec<i64> {
    (1..=last).collect()
}

fn admin_options() -> PgConnectOptions {
    std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL required")
        .parse()
        .expect("valid TEST_DATABASE_URL")
}

fn role_options(database: &str, role: &str) -> PgConnectOptions {
    admin_options()
        .database(database)
        .username(role)
        .password(PASSWORD)
}

fn role_url(database: &str, role: &str) -> String {
    let admin = admin_options();
    format!(
        "postgres://{role}:{PASSWORD}@{}:{}/{database}?sslmode=disable",
        admin.get_host(),
        admin.get_port()
    )
}

async fn admin(database: Option<&str>) -> PgConnection {
    let mut options = admin_options();
    if let Some(database) = database {
        options = options.database(database);
    }
    PgConnection::connect_with(&options).await.unwrap()
}

async fn connect(database: &str, role: &str) -> PgConnection {
    PgConnection::connect_with(&role_options(database, role))
        .await
        .unwrap()
}

/// Creates the synthetic cluster roles once; serialized across concurrent tests.
async fn ensure_roles(admin: &mut PgConnection) {
    admin
        .execute("SELECT pg_advisory_lock(720202)")
        .await
        .unwrap();
    for role in [OWNER, API, WORKER, CAPPED] {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = $1)")
                .bind(role)
                .fetch_one(&mut *admin)
                .await
                .unwrap();
        if !exists {
            let limit = if role == CAPPED { 2 } else { -1 };
            admin
                .execute(AssertSqlSafe(format!(
                    "CREATE ROLE {role} LOGIN PASSWORD '{PASSWORD}' CONNECTION LIMIT {limit}"
                )))
                .await
                .unwrap();
        }
    }
    admin
        .execute(AssertSqlSafe(format!("GRANT {API} TO {CAPPED}")))
        .await
        .unwrap();
    admin
        .execute("SELECT pg_advisory_unlock(720202)")
        .await
        .unwrap();
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// Advisory key serializing tests that change cluster-wide fixture roles: every test database
/// holds it shared; a test that alters role memberships or attributes holds it exclusively.
const ROLE_STATE_LOCK: i64 = 720203;

/// Runs statements as the fixture superuser on a blocking thread; used for cleanup in `Drop`.
fn admin_blocking(database: Option<String>, statements: Vec<String>) {
    let _ = thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let mut options = admin_options();
                if let Some(database) = &database {
                    options = options.database(database);
                }
                if let Ok(mut admin) = PgConnection::connect_with(&options).await {
                    for statement in statements {
                        let _ = admin.execute(AssertSqlSafe(statement)).await;
                    }
                }
            })
    })
    .join();
}

/// Restores cluster role state when dropped, including after a failed assertion.
struct Restore(&'static [&'static str]);
impl Drop for Restore {
    fn drop(&mut self) {
        admin_blocking(None, self.0.iter().map(|s| s.to_string()).collect());
    }
}

/// A fresh database owned by openmettle_owner, dropped when the test ends.
struct TestDb(String, #[allow(dead_code)] PgConnection);
impl TestDb {
    async fn new() -> Self {
        Self::create("SELECT pg_advisory_lock_shared($1)", "").await
    }
    /// For tests that change cluster-wide role state; excludes all other test databases.
    async fn exclusive() -> Self {
        Self::create("SELECT pg_advisory_lock($1)", "").await
    }
    async fn create(lock: &'static str, options: &'static str) -> Self {
        let mut admin = admin(None).await;
        ensure_roles(&mut admin).await;
        sqlx::query(lock)
            .bind(ROLE_STATE_LOCK)
            .execute(&mut admin)
            .await
            .unwrap();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let name = format!(
            "om_schema_{}_{}_{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        admin
            .execute(AssertSqlSafe(format!(
                "CREATE DATABASE {name} OWNER {OWNER} {options}"
            )))
            .await
            .unwrap();
        // `admin` keeps the role-state lock for the database's lifetime.
        Self(name, admin)
    }
    async fn schema_exists(&self) -> bool {
        sqlx::query_scalar("SELECT to_regnamespace('openmettle') IS NOT NULL")
            .fetch_one(&mut self.admin().await)
            .await
            .unwrap()
    }
    fn url(&self, role: &str) -> String {
        role_url(&self.0, role)
    }
    fn settings(&self, lock_timeout: Duration) -> Settings {
        Settings {
            database: role_options(&self.0, OWNER),
            connect_timeout: Duration::from_secs(5),
            lock_timeout,
            statement_timeout: Duration::from_secs(30),
        }
    }
    async fn migrated() -> Self {
        let db = Self::new().await;
        migrate::apply(&db.settings(Duration::from_secs(10)), MIGRATIONS)
            .await
            .unwrap();
        db
    }
    async fn admin(&self) -> PgConnection {
        admin(Some(&self.0)).await
    }
    /// Explicit synthetic outstanding-login limit (ADR 0014) for tests that need a successful
    /// login begin. Fresh migrations keep NULL, which refuses every initiation.
    async fn admit(&self, limit: i32) {
        sqlx::query("UPDATE openmettle.login_admission SET outstanding_limit=$1,changed_by='fixture-owner',change_reason='synthetic test limit',changed_at=clock_timestamp() WHERE id")
            .bind(limit)
            .execute(&mut connect(&self.0, OWNER).await)
            .await
            .unwrap();
    }
    async fn history(&self) -> Vec<i64> {
        sqlx::query_scalar(
            "SELECT version FROM openmettle._sqlx_migrations WHERE success ORDER BY version",
        )
        .fetch_all(&mut self.admin().await)
        .await
        .unwrap()
    }
    async fn exists(&self, relation: &str) -> bool {
        sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(relation)
            .fetch_one(&mut self.admin().await)
            .await
            .unwrap()
    }
    /// Waits until no migration session or advisory lock remains in this database.
    async fn wait_no_migration_session(&self) {
        let mut admin = self.admin().await;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let (sessions, locks): (i64, i64) = sqlx::query_as(
                "SELECT
                   (SELECT count(*) FROM pg_stat_activity
                    WHERE datname = $1 AND application_name = $2),
                   (SELECT count(*) FROM pg_locks l JOIN pg_database d ON d.oid = l.database
                    WHERE d.datname = $1 AND l.locktype = 'advisory')",
            )
            .bind(&self.0)
            .bind(migrate::APPLICATION_NAME)
            .fetch_one(&mut admin)
            .await
            .unwrap();
            if sessions == 0 && locks == 0 {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "migration session or lock remained: {sessions} sessions, {locks} locks"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
impl Drop for TestDb {
    fn drop(&mut self) {
        admin_blocking(
            None,
            vec![format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.0)],
        );
    }
}

fn sqlstate<T: std::fmt::Debug>(result: Result<T, sqlx::Error>) -> String {
    match result {
        Err(sqlx::Error::Database(e)) => e.code().unwrap_or_default().into_owned(),
        other => panic!("expected a database error, got {other:?}"),
    }
}

async fn expect_state(connection: &mut PgConnection, sql: &str, code: &str) {
    let result = connection.execute(AssertSqlSafe(sql.to_owned())).await;
    assert_eq!(sqlstate(result), code, "{sql}");
}

async fn new_user(connection: &mut PgConnection) -> String {
    sqlx::query_scalar("INSERT INTO openmettle.users DEFAULT VALUES RETURNING id::text")
        .fetch_one(connection)
        .await
        .unwrap()
}

async fn personal_scope(connection: &mut PgConnection, user: &str) -> String {
    sqlx::query_scalar(
        "INSERT INTO openmettle.scopes (kind, personal_user_id)
         VALUES ('personal', $1::uuid) RETURNING id::text",
    )
    .bind(user)
    .fetch_one(connection)
    .await
    .unwrap()
}

/// Returns (project id, scope id); both rows are inserted in one transaction.
async fn project(connection: &mut PgConnection, creator: &str) -> (String, String) {
    let row = sqlx::query(
        "WITH ids AS (SELECT gen_random_uuid() AS project, gen_random_uuid() AS scope),
         s AS (INSERT INTO openmettle.scopes (id, kind, project_id)
               SELECT scope, 'project', project FROM ids),
         p AS (INSERT INTO openmettle.projects (id, scope_id, created_by_user_id)
               SELECT project, scope, $1::uuid FROM ids)
         SELECT project::text, scope::text FROM ids",
    )
    .bind(creator)
    .fetch_one(connection)
    .await
    .unwrap();
    (row.get(0), row.get(1))
}

async fn conversation(
    connection: &mut PgConnection,
    scope: &str,
    kind: &str,
    owner: &str,
) -> Result<String, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO openmettle.conversations (scope_id, scope_kind, owner_user_id)
         VALUES ($1::uuid, $2, $3::uuid) RETURNING id::text",
    )
    .bind(scope)
    .bind(kind)
    .bind(owner)
    .fetch_one(connection)
    .await
}

async fn message(
    connection: &mut PgConnection,
    scope: &str,
    conversation: &str,
    parent: Option<&str>,
) -> Result<String, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO openmettle.messages (scope_id, conversation_id, parent_message_id)
         VALUES ($1::uuid, $2::uuid, $3::uuid) RETURNING id::text",
    )
    .bind(scope)
    .bind(conversation)
    .bind(parent)
    .fetch_one(connection)
    .await
}

async fn snapshot(connection: &mut PgConnection, tables: &[&str]) -> Vec<String> {
    let mut rows = Vec::new();
    for table in tables {
        let mut table_rows: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT (to_jsonb(t) - 'session_generation' - 'lock_guard')::text FROM openmettle.{table} t ORDER BY id"
        )))
        .fetch_all(&mut *connection)
        .await
        .unwrap();
        rows.push(format!("{table}: {}", table_rows.len()));
        rows.append(&mut table_rows);
    }
    rows
}

/// A migration run refused for exactly this one boundary violation.
async fn refused_with(settings: &Settings, sources: &[Source], violation: &str) {
    match migrate::apply(settings, sources).await {
        Err(Failure::Refused(violations)) => assert_eq!(violations, [violation]),
        other => panic!("expected the boundary check to refuse, got {other:?}"),
    }
}

// --- tests without PostgreSQL ------------------------------------------------------------------

/// The single pin for every released migration: any edit to a shipped migration must fail here.
#[test]
fn released_migration_sources_match_their_pinned_hashes() {
    use sha2::{Digest, Sha256};
    migrate::migrator(MIGRATIONS)
        .expect("all embedded migrations must pass the transactional scanner");
    let expected = [
        "1672dd9259a2c9670fef4fac324af8a4fdf9b35fd9eabd421bd9f023571137bd",
        "b1bf6e677a74226d258292dc6d987158a5d81fe2fa0ba00d4e3ed1afdd0a4e5c",
        "1744f1ca3e4ef146e151e2c622dd7d19d02b295281db1c819d747970807111c1",
        "6c4a1794d1c132739fdaf1b48706e8b2884ef51e903f0f2a979837919a8f53f3",
        "3130bf356a92c08f08d9ec65e49bd4ae04c41dd82ebab2ee4e313427fa423680",
        "6ebaec059411b63e6b787ca7bb72de9e152809174c462c48a2173bdf7b10e078",
        "42e5ef4abffbbd6023f6e65a954a6f6ebedbdbcf46439f28f64e61260280842d",
        "9a77a03a838fa058ad3919ed8db5e483619755cc4a96959240202d6c35b3939a",
        "f73f2f41d56136d90deb49aac87ef835b96f50dea416871ec86cab61dd0b3c76",
        "91b95d8146362a47c78ebf96de7b9f2e81f625b99ac880ddb1f427c3f5652f57",
        "887728e24ebf829d4644b6f47937c37149862ab7a7d8069c278827141f9d7a84",
        "b71bee740d4a71320f26f3392ce2be0962f599d8c032383cb14fc11bf32b1763",
        "58312aca4b72100dd460f5cccfca9688154e83f4662268358834f75f8f49e7bd",
        "e02d6df9824120c788991dd4ec84dc5f5bd1069d780549c25ac5f2cd7e6efc4a",
        "b4203f2bf76cf54ec21882c40a41a312233c9be37a4631949f28e566b32dd118",
        "425c1d0aa9d3cf7d1910cab8f2ec55d3a5c8de24a169c181b5febeedc84f7c91",
    ];
    assert_eq!(MIGRATIONS.len(), expected.len());
    assert_eq!(all_versions(), versions_through(MIGRATIONS.len() as i64));
    for (migration, hash) in MIGRATIONS.iter().zip(expected) {
        assert_eq!(
            format!("{:x}", Sha256::digest(migration.sql.as_bytes())),
            hash,
            "migration {}",
            migration.version
        );
    }
}

#[test]
fn migrate_rejects_invalid_config_without_disclosing_values() {
    for (key, value) in [
        ("DATABASE_URL", "invalid://user:synthetic-secret@host/db"),
        ("CONNECT_TIMEOUT_MS", "synthetic-secret"),
        ("LOCK_TIMEOUT_MS", "0"),
        ("STATEMENT_TIMEOUT_MS", "3600001"),
        // ADR 0024: telemetry settings share the prefix and the exit code.
        ("LOG_FORMAT", "synthetic-secret"),
        ("LOG_LEVEL", "trace"),
    ] {
        let output = migrate_command("postgres://localhost/test", &[(key, value)])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(78), "{key}");
        // One fixed line written before telemetry exists: no event, no value.
        let text = stderr(&output);
        assert!(text.starts_with("configuration error: ") && text.lines().count() == 1);
        assert!(!text.contains("synthetic-secret"));
    }
    let output = binary("migrate").output().unwrap();
    assert_eq!(output.status.code(), Some(78));
}

#[test]
fn migrate_connection_deadline_exits_one_without_disclosing_url() {
    // A listener that never speaks PostgreSQL.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!(
        "postgres://fixture:synthetic-secret@{}/fixture?sslmode=disable",
        silent.local_addr().unwrap()
    );
    let began = Instant::now();
    let output = migrate_command(&url, &[("CONNECT_TIMEOUT_MS", "300")])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(began.elapsed() < Duration::from_secs(5));
    let text = stderr(&output);
    assert!(text.contains("deadline"), "{text}");
    assert!(!text.contains("synthetic-secret") && !text.contains("fixture"));
}

/// The JSON telemetry lines on stderr, as (event, level, error.type or signal) triples, and
/// the other lines as they are.
fn split_events(text: &str) -> (Vec<(String, String, String)>, Vec<&str>) {
    let mut events = Vec::new();
    let mut others = Vec::new();
    for line in text.lines() {
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(event) => {
                assert_eq!(event["role"], "migrate", "{line}");
                let detail = event.get("error.type").or(event.get("signal"));
                events.push((
                    event["event"].as_str().unwrap().to_owned(),
                    event["level"].as_str().unwrap().to_owned(),
                    detail.map_or(String::new(), |d| d.as_str().unwrap().to_owned()),
                ));
            }
            Err(_) => others.push(line),
        }
    }
    (events, others)
}

/// ADR 0024 through the binary: a failed run reports its `migrate::Failure` class beside the
/// unchanged operator line, for a deadline and for a refused connection.
#[test]
fn migrate_failures_report_their_class_through_the_binary() {
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let refused = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    for (address, class, line) in [
        (
            silent.local_addr().unwrap(),
            "ConnectTimeout",
            "migration error: database connection deadline exceeded",
        ),
        (
            refused,
            "Connect",
            "migration error: database connection failed (I/O error)",
        ),
    ] {
        let url = format!("postgres://fixture:synthetic-secret@{address}/fixture?sslmode=disable");
        let output = migrate_command(&url, &[("CONNECT_TIMEOUT_MS", "300")])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let text = stderr(&output);
        assert!(!text.contains("synthetic-secret"), "{text}");
        let (events, others) = split_events(&text);
        assert_eq!(others, [line], "{text}");
        let expected = [
            ("migration.started", "INFO", ""),
            ("migration.failed", "ERROR", class),
        ];
        let events: Vec<_> = events
            .iter()
            .map(|(e, l, d)| (e.as_str(), l.as_str(), d.as_str()))
            .collect();
        assert_eq!(events, expected, "{text}");
    }
}

/// ADR 0024: an interrupted run exits 1 and says so at `LOG_LEVEL=error`, in both formats.
#[test]
fn interrupted_migrator_reports_at_error_level() {
    for (format, signal_name, flag) in [("json", "SIGTERM", "-TERM"), ("text", "SIGINT", "-INT")] {
        // A listener that never speaks PostgreSQL holds the run inside its connection attempt.
        let silent = TcpListener::bind("127.0.0.1:0").unwrap();
        silent.set_nonblocking(true).unwrap();
        let url = format!(
            "postgres://fixture:synthetic-secret@{}/fixture?sslmode=disable",
            silent.local_addr().unwrap()
        );
        let mut child = Process(
            migrate_command(
                &url,
                &[
                    ("CONNECT_TIMEOUT_MS", "60000"),
                    ("LOG_LEVEL", "error"),
                    ("LOG_FORMAT", format),
                ],
            )
            .spawn()
            .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        let _connection = loop {
            match silent.accept() {
                Ok(connection) => break connection,
                Err(_) => {
                    assert!(Instant::now() < deadline, "migrator never connected");
                    thread::sleep(Duration::from_millis(10));
                }
            }
        };
        signal(&child.0, flag);
        let began = Instant::now();
        let status = child.0.wait().unwrap();
        assert!(began.elapsed() < Duration::from_secs(5));
        assert_eq!(status.code(), Some(1));
        let (mut stdout, mut text) = (String::new(), String::new());
        let pipes = (child.0.stdout.take(), child.0.stderr.take());
        pipes.0.unwrap().read_to_string(&mut stdout).unwrap();
        pipes.1.unwrap().read_to_string(&mut text).unwrap();
        assert!(stdout.is_empty());
        assert!(!text.contains("synthetic-secret"), "{text}");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1, "{text}");
        if format == "json" {
            let (events, _) = split_events(&text);
            assert_eq!(
                events,
                [(
                    "migration.interrupted".to_owned(),
                    "ERROR".to_owned(),
                    signal_name.to_owned()
                )]
            );
        } else {
            assert!(
                lines[0].ends_with(&format!(
                    " ERROR event=\"migration.interrupted\" role=\"migrate\" signal=\"{signal_name}\""
                )),
                "{text}"
            );
        }
    }
}

// --- PostgreSQL tests ----------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn fresh_install_is_idempotent_and_owned() {
    let db = TestDb::new().await;
    let output = migrate_command(&db.url(OWNER), &[]).output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(db.history().await, all_versions());

    let mut admin = db.admin().await;
    let recorded: Vec<Vec<u8>> =
        sqlx::query_scalar("SELECT checksum FROM openmettle._sqlx_migrations ORDER BY version")
            .fetch_all(&mut admin)
            .await
            .unwrap();
    let expected: Vec<Vec<u8>> = migrate::migrator(MIGRATIONS)
        .unwrap()
        .iter()
        .map(|m| m.checksum.to_vec())
        .collect();
    assert_eq!(recorded, expected);
    let installed: Vec<String> = sqlx::query_scalar(
        "SELECT installed_on::text FROM openmettle._sqlx_migrations ORDER BY version",
    )
    .fetch_all(&mut admin)
    .await
    .unwrap();

    let rerun = migrate_command(&db.url(OWNER), &[]).output().unwrap();
    assert_eq!(rerun.status.code(), Some(0), "{}", stderr(&rerun));
    let reinstalled: Vec<String> = sqlx::query_scalar(
        "SELECT installed_on::text FROM openmettle._sqlx_migrations ORDER BY version",
    )
    .fetch_all(&mut admin)
    .await
    .unwrap();
    assert_eq!(installed, reinstalled);

    // Every object, including history, is in the owned schema and owned by the migration role.
    let (foreign_owned, in_public, schema_owner): (i64, i64, String) = sqlx::query_as(
        "SELECT
           (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'openmettle' AND pg_get_userbyid(c.relowner) <> 'openmettle_owner'),
           (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'),
           (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'openmettle')",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert_eq!(
        (foreign_owned, in_public, schema_owner.as_str()),
        (0, 0, OWNER)
    );
    db.wait_no_migration_session().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn populated_upgrade_preserves_identity_and_ownership() {
    let db = TestDb::new().await;
    migrate::apply(&db.settings(Duration::from_secs(10)), &MIGRATIONS[..1])
        .await
        .unwrap();
    assert_eq!(db.history().await, [1]);
    assert!(!db.exists("openmettle.conversations").await);

    let mut api = connect(&db.0, API).await;
    let alice = new_user(&mut api).await;
    let bob = new_user(&mut api).await;
    for (user, subject) in [(&alice, "alice"), (&bob, "bob")] {
        sqlx::query(
            "INSERT INTO openmettle.user_identities (user_id, issuer, subject)
             VALUES ($1::uuid, 'https://issuer.example.test', $2)",
        )
        .bind(user)
        .bind(subject)
        .execute(&mut api)
        .await
        .unwrap();
    }
    let alice_scope = personal_scope(&mut api, &alice).await;
    personal_scope(&mut api, &bob).await;
    let (_, project_scope) = project(&mut api, &alice).await;
    let tables = ["users", "user_identities", "scopes", "projects"];
    let before = snapshot(&mut api, &tables).await;
    drop(api);

    let output = migrate_command(&db.url(OWNER), &[]).output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(db.history().await, all_versions());

    let mut api = connect(&db.0, API).await;
    assert_eq!(snapshot(&mut api, &tables).await, before);
    // Pre-existing identifiers remain valid ownership targets after the upgrade.
    let personal = conversation(&mut api, &alice_scope, "personal", &alice)
        .await
        .unwrap();
    let root = message(&mut api, &alice_scope, &personal, None)
        .await
        .unwrap();
    message(&mut api, &alice_scope, &personal, Some(&root))
        .await
        .unwrap();
    conversation(&mut api, &project_scope, "project", &bob)
        .await
        .unwrap();
    assert_eq!(
        sqlstate(conversation(&mut api, &alice_scope, "personal", &bob).await),
        "23503"
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn concurrent_migrators_apply_each_version_once() {
    let db = TestDb::new().await;
    let children: Vec<Child> = (0..4)
        .map(|_| migrate_command(&db.url(OWNER), &[]).spawn().unwrap())
        .collect();
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    }
    let rows: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT version, count(*) FROM openmettle._sqlx_migrations GROUP BY version ORDER BY version",
    )
    .fetch_all(&mut db.admin().await)
    .await
    .unwrap();
    assert_eq!(
        rows,
        MIGRATIONS
            .iter()
            .map(|m| (m.version, 1))
            .collect::<Vec<_>>()
    );
    db.wait_no_migration_session().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn held_lock_times_out_and_is_released_for_retry() {
    let db = TestDb::new().await;
    // Hold the same session advisory lock the migrator uses.
    let mut holder = connect(&db.0, OWNER).await;
    holder.lock().await.unwrap();

    let began = Instant::now();
    let output = migrate_command(
        &db.url(OWNER),
        &[
            ("LOCK_TIMEOUT_MS", "300"),
            ("STATEMENT_TIMEOUT_MS", "60000"),
        ],
    )
    .output()
    .unwrap();
    // lock_not_available (not the 60 s statement timeout) proves lock_timeout bounds the wait.
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("SQLSTATE 55P03"),
        "{}",
        stderr(&output)
    );
    assert!(began.elapsed() < Duration::from_secs(10));
    assert!(!db.exists("openmettle._sqlx_migrations").await);

    holder.unlock().await.unwrap();
    holder.close().await.unwrap();
    db.wait_no_migration_session().await;
    let retry = migrate_command(&db.url(OWNER), &[("LOCK_TIMEOUT_MS", "1000")])
        .output()
        .unwrap();
    assert_eq!(retry.status.code(), Some(0), "{}", stderr(&retry));
    assert_eq!(db.history().await, all_versions());
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn interrupted_or_killed_migrator_leaves_no_session() {
    let db = TestDb::new().await;
    let mut holder = connect(&db.0, OWNER).await;
    holder.lock().await.unwrap();
    for kill in ["-TERM", "-KILL"] {
        let mut child = migrate_command(&db.url(OWNER), &[("LOCK_TIMEOUT_MS", "60000")])
            .spawn()
            .unwrap();
        // Wait until the migrator's backend is blocked on the advisory lock.
        let mut admin = db.admin().await;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity
                 WHERE datname = $1 AND application_name = $2 AND wait_event_type = 'Lock'",
            )
            .bind(&db.0)
            .bind(migrate::APPLICATION_NAME)
            .fetch_one(&mut admin)
            .await
            .unwrap();
            if waiting == 1 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "migrator never waited on the lock"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        signal(&child, kill);
        let status = child.wait().unwrap();
        if kill == "-TERM" {
            assert_eq!(status.code(), Some(1));
        }
        // The server ends the orphaned session; only the holder's lock remains.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let (sessions, locks): (i64, i64) = sqlx::query_as(
                "SELECT
                   (SELECT count(*) FROM pg_stat_activity
                    WHERE datname = $1 AND application_name = $2),
                   (SELECT count(*) FROM pg_locks l JOIN pg_database d ON d.oid = l.database
                    WHERE d.datname = $1 AND l.locktype = 'advisory')",
            )
            .bind(&db.0)
            .bind(migrate::APPLICATION_NAME)
            .fetch_one(&mut admin)
            .await
            .unwrap();
            if sessions == 0 && locks == 1 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{kill}: {sessions} sessions, {locks} locks"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    holder.unlock().await.unwrap();
    holder.close().await.unwrap();
    let output = migrate_command(&db.url(OWNER), &[("LOCK_TIMEOUT_MS", "1000")])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn killed_migrator_holding_the_lock_mid_migration_rolls_back() {
    let db = TestDb::new().await;
    migrate::apply(&db.settings(Duration::from_secs(10)), &MIGRATIONS[..1])
        .await
        .unwrap();
    // Migration 2's foreign key to users waits behind this lock, after it has written catalog
    // rows in its transaction and while it holds the migration advisory lock.
    let mut blocker = db.admin().await;
    blocker.execute("BEGIN").await.unwrap();
    blocker
        .execute("LOCK TABLE openmettle.users IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let mut admin = db.admin().await;
    for kill in ["-TERM", "-KILL"] {
        let mut child = migrate_command(
            &db.url(OWNER),
            &[
                ("LOCK_TIMEOUT_MS", "60000"),
                ("STATEMENT_TIMEOUT_MS", "60000"),
            ],
        )
        .spawn()
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let state: Option<(bool, bool)> = sqlx::query_as(
                "SELECT a.backend_xid IS NOT NULL,
                        EXISTS (SELECT FROM pg_locks AS l
                                WHERE l.pid = a.pid AND l.locktype = 'advisory' AND l.granted)
                 FROM pg_stat_activity AS a
                 WHERE a.datname = $1 AND a.application_name = $2
                   AND a.wait_event_type = 'Lock'",
            )
            .bind(&db.0)
            .bind(migrate::APPLICATION_NAME)
            .fetch_optional(&mut admin)
            .await
            .unwrap();
            // Uncommitted migration writes plus the held migration lock.
            if state == Some((true, true)) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "migrator never blocked inside migration 2 holding the lock: {state:?}"
            );
            assert!(child.try_wait().unwrap().is_none(), "migrator exited early");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        signal(&child, kill);
        let status = child.wait().unwrap();
        if kill == "-TERM" {
            assert_eq!(status.code(), Some(1));
        }
        // PostgreSQL ends the session, rolls back migration 2 and releases the lock.
        db.wait_no_migration_session().await;
        assert!(!db.exists("openmettle.conversations").await, "{kill}");
        assert_eq!(db.history().await, [1], "{kill}");
    }
    blocker.execute("ROLLBACK").await.unwrap();
    let output = migrate_command(&db.url(OWNER), &[("LOCK_TIMEOUT_MS", "1000")])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(db.history().await, all_versions());
}

/// Custom sets start with the real migration 1 so the post-migration boundary check sees the
/// contract's database and schema privileges.
const PROBE_TWO: Source = Source {
    version: 2,
    description: "probe two",
    sql: "CREATE TABLE openmettle.probe_two (id int)",
};

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn failed_migration_rolls_back_and_immediate_retry_succeeds() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(1));
    let failing = [
        MIGRATIONS[0],
        Source {
            sql: "CREATE TABLE openmettle.probe_two (id int); SELECT 1 / 0;",
            ..PROBE_TWO
        },
    ];
    match migrate::apply(&settings, &failing).await {
        Err(Failure::Migrate(MigrateError::ExecuteMigration(_, 2))) => {}
        other => panic!("unexpected result: {other:?}"),
    }
    assert_eq!(db.history().await, [1]);
    assert!(db.exists("openmettle.users").await);
    assert!(!db.exists("openmettle.probe_two").await);
    // No live lock or session survives; the retry needs the lock within one second.
    db.wait_no_migration_session().await;
    let fixed = [MIGRATIONS[0], PROBE_TWO];
    migrate::apply(&settings, &fixed).await.unwrap();
    assert_eq!(db.history().await, [1, 2]);

    // statement_timeout bounds a long migration and records nothing.
    let mut slow_settings = db.settings(Duration::from_secs(1));
    slow_settings.statement_timeout = Duration::from_millis(200);
    let slow = [
        fixed[0],
        fixed[1],
        Source {
            version: 3,
            description: "slow",
            sql: "CREATE TABLE openmettle.probe_three (id int); SELECT pg_sleep(5);",
        },
    ];
    let failure = migrate::apply(&slow_settings, &slow).await.unwrap_err();
    assert!(failure.to_string().contains("SQLSTATE 57014"), "{failure}");
    assert_eq!(db.history().await, [1, 2]);
    assert!(!db.exists("openmettle.probe_three").await);
    db.wait_no_migration_session().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn nontransactional_migrations_are_refused() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(1));
    // Early COMMIT would split a migration from its history row: refused before connecting.
    // PostgreSQL ends a `--` comment at CR, so the second COMMIT is real SQL too.
    for sql in [
        "CREATE TABLE openmettle.p (id int); COMMIT; CREATE TABLE openmettle.q (id int);",
        "CREATE TABLE openmettle.probe (id int); -- comment\rCOMMIT;\nSELECT 1/0;",
        "CREATE TABLE openmettle.probe (id int); SELECT E''\n'\\''; COMMIT; --';\nSELECT 1/0;",
        "CREATE TABLE openmettle.probe (id int); SELECT E'' -- continuation\n'\\''; COMMIT; --';\nSELECT 1/0;",
    ] {
        let committing = [Source {
            version: 1,
            description: "split",
            sql,
        }];
        assert!(matches!(
            migrate::apply(&settings, &committing).await,
            Err(Failure::Invalid(_))
        ));
        assert!(!db.schema_exists().await, "{sql:?}");
    }
    // Operations PostgreSQL cannot run in a transaction fail inside the migration transaction.
    let concurrent = [Source {
        version: 1,
        description: "concurrent index",
        sql: "CREATE TABLE openmettle.p (id int); CREATE INDEX CONCURRENTLY p_idx ON openmettle.p (id);",
    }];
    let failure = migrate::apply(&settings, &concurrent).await.unwrap_err();
    assert!(failure.to_string().contains("SQLSTATE 25001"), "{failure}");
    assert!(db.history().await.is_empty());
    assert!(!db.exists("openmettle.p").await);

    // A session setting committed by one migration must not change how the next is scanned.
    // With standard_conforming_strings off, PostgreSQL would read `'\''` as a closed string and
    // run the COMMIT that the check (and a reset session) treat as string content.
    let lexing = [
        Source {
            version: 1,
            description: "conforming strings off",
            sql: "SET standard_conforming_strings = off",
        },
        Source {
            version: 2,
            description: "hidden commit",
            sql: "CREATE TABLE openmettle.probe (id int); SELECT '\\''; COMMIT; --'; SELECT 1 / 0;",
        },
    ];
    match migrate::apply(&settings, &lexing).await {
        Err(Failure::Migrate(MigrateError::ExecuteMigration(_, 2))) => {}
        other => panic!("unexpected result: {other:?}"),
    }
    assert_eq!(db.history().await, [1]);
    assert!(!db.exists("openmettle.probe").await);
    db.wait_no_migration_session().await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn checksum_drift_and_newer_database_are_refused() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(1));
    let third = Source {
        version: 3,
        description: "probe three",
        sql: "CREATE TABLE openmettle.probe_three (id int)",
    };
    migrate::apply(&settings, &[MIGRATIONS[0], PROBE_TWO])
        .await
        .unwrap();
    let edited = Source {
        sql: "CREATE TABLE openmettle.probe_two (id bigint)",
        ..PROBE_TWO
    };
    match migrate::apply(&settings, &[MIGRATIONS[0], edited, third]).await {
        Err(Failure::Migrate(MigrateError::VersionMismatch(2))) => {}
        other => panic!("unexpected result: {other:?}"),
    }
    assert_eq!(db.history().await, [1, 2]);
    assert!(!db.exists("openmettle.probe_three").await);

    // Before version 3 exists, the release binary detects the different version-2 source.
    let output = migrate_command(&db.url(OWNER), &[]).output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("checksum mismatch"),
        "{}",
        stderr(&output)
    );
    assert!(!stderr(&output).contains(PASSWORD));

    // Use authentic current migrations, then one contiguous future version. Keep this
    // distinct from checksum drift so both refusal reasons are exercised independently.
    drop(db);
    let future_db = TestDb::migrated().await;
    let future_settings = future_db.settings(Duration::from_secs(1));
    let next_version = MIGRATIONS.last().unwrap().version + 1;
    let mut future = MIGRATIONS.to_vec();
    future.push(Source {
        version: next_version,
        description: "future probe",
        sql: "CREATE TABLE openmettle.future_probe (id int)",
    });
    migrate::apply(&future_settings, &future).await.unwrap();
    match migrate::apply(&future_settings, MIGRATIONS).await {
        Err(Failure::Migrate(MigrateError::VersionMissing(v))) if v == next_version => {}
        other => panic!("unexpected result: {other:?}"),
    }
    let before = future_db.history().await;
    let output = migrate_command(&future_db.url(OWNER), &[])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains(&format!(
            "database has migration {next_version}, which this release does not contain"
        )),
        "{}",
        stderr(&output)
    );
    assert!(!stderr(&output).contains(PASSWORD));
    assert_eq!(future_db.history().await, before);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn wrong_login_is_refused_before_bootstrap_and_owner_retry_succeeds() {
    let db = TestDb::new().await;
    // The superuser fixture stands in for any login other than openmettle_owner.
    let mut wrong = db.settings(Duration::from_secs(1));
    wrong.database = admin_options().database(&db.0);
    for settings in [
        wrong,
        Settings {
            database: role_options(&db.0, API),
            ..db.settings(Duration::from_secs(1))
        },
    ] {
        let failure = migrate::apply(&settings, MIGRATIONS).await.unwrap_err();
        assert!(
            matches!(failure, Failure::Refused(_))
                && failure
                    .to_string()
                    .contains("migrations must log in as openmettle_owner"),
            "{failure}"
        );
        // Nothing was bootstrapped, so the owner is not blocked by foreign-owned objects.
        assert!(!db.schema_exists().await);
    }
    db.wait_no_migration_session().await;
    let output = migrate_command(&db.url(OWNER), &[("LOCK_TIMEOUT_MS", "1000")])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(db.history().await, all_versions());

    // Later runs check identity as well.
    let mut wrong = db.settings(Duration::from_secs(1));
    wrong.database = admin_options().database(&db.0);
    assert!(matches!(
        migrate::apply(&wrong, MIGRATIONS).await,
        Err(Failure::Refused(_))
    ));
}

/// Statements that restore every role change made by the membership test.
const ROLE_RESTORE: &[&str] = &[
    "REVOKE pg_write_all_data FROM openmettle_api",
    "REVOKE pg_read_all_data FROM openmettle_worker",
    "DROP ROLE IF EXISTS openmettle_fixture_group",
    "REVOKE pg_write_all_data FROM openmettle_fixture_capped",
    "REVOKE openmettle_worker FROM openmettle_fixture_capped",
    "REVOKE openmettle_owner FROM openmettle_fixture_capped",
    "REVOKE pg_read_server_files FROM openmettle_owner",
    "ALTER ROLE openmettle_api NOBYPASSRLS",
];

async fn restore_roles(admin: &mut PgConnection) {
    for statement in ROLE_RESTORE {
        admin.execute(*statement).await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn unsafe_role_memberships_and_attributes_are_refused() {
    let db = TestDb::exclusive().await;
    let _restore = Restore(ROLE_RESTORE);
    let mut admin = admin(None).await;
    restore_roles(&mut admin).await;
    let settings = db.settings(Duration::from_secs(1));
    let cases: &[(&[&str], &str)] = &[
        (
            &["GRANT pg_write_all_data TO openmettle_api"],
            "role openmettle_api must not be a member of pg_write_all_data",
        ),
        // Not inherited, but assumable with SET ROLE.
        (
            &["GRANT pg_read_all_data TO openmettle_worker WITH INHERIT FALSE, SET TRUE"],
            "role openmettle_worker must not be a member of pg_read_all_data",
        ),
        // Indirect, through an intermediate group.
        (
            &[
                "CREATE ROLE openmettle_fixture_group NOLOGIN",
                "GRANT pg_write_all_data TO openmettle_fixture_group",
                "GRANT openmettle_fixture_group TO openmettle_api",
            ],
            "role openmettle_api must not be a member of openmettle_fixture_group",
        ),
        // A login role that holds the API privileges must not carry other privileges.
        (
            &["GRANT pg_write_all_data TO openmettle_fixture_capped WITH INHERIT FALSE"],
            "role openmettle_fixture_capped, a member of an application role, must not be a member of pg_write_all_data",
        ),
        (
            &["GRANT openmettle_worker TO openmettle_fixture_capped"],
            "role openmettle_fixture_capped has both API and worker privileges",
        ),
        (
            &["GRANT openmettle_owner TO openmettle_fixture_capped"],
            "role openmettle_fixture_capped, a member of an application role, must not be a member of openmettle_owner",
        ),
        (
            &["GRANT pg_read_server_files TO openmettle_owner"],
            "role openmettle_owner must not be a member of pg_read_server_files",
        ),
        (
            &["ALTER ROLE openmettle_api BYPASSRLS"],
            "role openmettle_api must not be superuser or hold CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS",
        ),
    ];
    for (setup, expected) in cases {
        for statement in *setup {
            admin.execute(*statement).await.unwrap();
        }
        let failure = migrate::apply(&settings, MIGRATIONS).await.unwrap_err();
        assert!(
            matches!(failure, Failure::Refused(_)) && failure.to_string().contains(expected),
            "expected {expected:?}, got {failure}"
        );
        assert!(!db.schema_exists().await, "{expected}");
        restore_roles(&mut admin).await;
    }
    migrate::apply(&settings, MIGRATIONS).await.unwrap();

    // The same boundary holds on later runs against a populated schema.
    admin
        .execute("GRANT pg_write_all_data TO openmettle_api WITH INHERIT FALSE")
        .await
        .unwrap();
    let failure = migrate::apply(&settings, MIGRATIONS).await.unwrap_err();
    assert!(
        failure.to_string().contains("pg_write_all_data"),
        "{failure}"
    );
    restore_roles(&mut admin).await;
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn unsafe_privileges_defaults_and_ownership_are_refused() {
    let db = TestDb::new().await;
    let settings = db.settings(Duration::from_secs(1));
    let name = db.0.clone();
    let fixture = admin_options().get_username().to_owned();
    let mut admin = db.admin().await;
    let fresh: Vec<(Vec<String>, Vec<String>, &str)> = vec![
        (
            vec!["ALTER DEFAULT PRIVILEGES FOR ROLE openmettle_owner GRANT ALL ON TABLES TO openmettle_api".into()],
            vec!["ALTER DEFAULT PRIVILEGES FOR ROLE openmettle_owner REVOKE ALL ON TABLES FROM openmettle_api".into()],
            "default privileges of openmettle_owner grant DELETE on new tables to openmettle_api",
        ),
        (
            vec!["ALTER DEFAULT PRIVILEGES FOR ROLE openmettle_owner IN SCHEMA public GRANT SELECT ON TABLES TO PUBLIC".into()],
            vec!["ALTER DEFAULT PRIVILEGES FOR ROLE openmettle_owner IN SCHEMA public REVOKE SELECT ON TABLES FROM PUBLIC".into()],
            "default privileges of openmettle_owner in schema public grant SELECT on new tables to PUBLIC",
        ),
        (
            vec!["ALTER DEFAULT PRIVILEGES FOR ROLE openmettle_owner GRANT CREATE ON SCHEMAS TO openmettle_worker".into()],
            vec!["ALTER DEFAULT PRIVILEGES FOR ROLE openmettle_owner REVOKE CREATE ON SCHEMAS FROM openmettle_worker".into()],
            "default privileges of openmettle_owner grant CREATE on new schemas to openmettle_worker",
        ),
        (
            vec![format!("GRANT CREATE, TEMPORARY ON DATABASE {name} TO openmettle_api")],
            vec![format!("REVOKE CREATE, TEMPORARY ON DATABASE {name} FROM openmettle_api")],
            "openmettle_api has CREATE on the database",
        ),
        (
            vec![format!("GRANT CREATE ON DATABASE {name} TO PUBLIC")],
            vec![format!("REVOKE CREATE ON DATABASE {name} FROM PUBLIC")],
            "PUBLIC has CREATE on the database",
        ),
        (
            vec!["GRANT CREATE ON SCHEMA public TO openmettle_worker".into()],
            vec!["REVOKE CREATE ON SCHEMA public FROM openmettle_worker".into()],
            "openmettle_worker has CREATE on schema public",
        ),
        (
            vec![
                "CREATE TABLE public.intruder (id int)".into(),
                "ALTER TABLE public.intruder OWNER TO openmettle_api".into(),
            ],
            vec!["DROP TABLE public.intruder".into()],
            "openmettle_api owns public.intruder",
        ),
        (
            vec!["CREATE SCHEMA intruder AUTHORIZATION openmettle_worker".into()],
            vec!["DROP SCHEMA intruder".into()],
            "openmettle_worker owns schema intruder",
        ),
        (
            vec![format!("ALTER DATABASE {name} OWNER TO {fixture}")],
            vec![format!("ALTER DATABASE {name} OWNER TO openmettle_owner")],
            "the database must be owned by openmettle_owner",
        ),
    ];
    for (setup, restore, expected) in &fresh {
        for statement in setup {
            admin
                .execute(AssertSqlSafe(statement.clone()))
                .await
                .unwrap();
        }
        let failure = migrate::apply(&settings, MIGRATIONS).await.unwrap_err();
        assert!(
            matches!(failure, Failure::Refused(_)) && failure.to_string().contains(expected),
            "expected {expected:?}, got {failure}"
        );
        assert!(!db.schema_exists().await, "{expected}");
        for statement in restore {
            admin
                .execute(AssertSqlSafe(statement.clone()))
                .await
                .unwrap();
        }
    }
    migrate::apply(&settings, MIGRATIONS).await.unwrap();

    // Grants added after installation are refused on the next run.
    let rerun: Vec<(String, String, &str)> = vec![
        (
            "GRANT SELECT ON openmettle.user_identities TO openmettle_api WITH GRANT OPTION".into(),
            "REVOKE GRANT OPTION FOR SELECT ON openmettle.user_identities FROM openmettle_api".into(),
            "openmettle_api has grant option for SELECT on openmettle.user_identities",
        ),
        (
            format!("GRANT CONNECT ON DATABASE {name} TO openmettle_fixture_capped WITH GRANT OPTION"),
            format!("REVOKE GRANT OPTION FOR CONNECT ON DATABASE {name} FROM openmettle_fixture_capped"),
            "openmettle_fixture_capped has grant option for CONNECT on the database",
        ),
        (
            "GRANT USAGE ON SCHEMA openmettle TO openmettle_worker WITH GRANT OPTION".into(),
            "REVOKE GRANT OPTION FOR USAGE ON SCHEMA openmettle FROM openmettle_worker".into(),
            "openmettle_worker has grant option for USAGE on schema openmettle",
        ),
        (
            "GRANT UPDATE (disabled_at) ON openmettle.users TO openmettle_api WITH GRANT OPTION".into(),
            "REVOKE GRANT OPTION FOR UPDATE (disabled_at) ON openmettle.users FROM openmettle_api".into(),
            "openmettle_api has grant option for UPDATE on openmettle.users.disabled_at",
        ),
        (
            "GRANT DELETE ON openmettle.users TO openmettle_api".into(),
            "REVOKE DELETE ON openmettle.users FROM openmettle_api".into(),
            "openmettle_api has DELETE on openmettle.users",
        ),
        (
            "GRANT SELECT ON openmettle._sqlx_migrations TO openmettle_worker".into(),
            "REVOKE SELECT ON openmettle._sqlx_migrations FROM openmettle_worker".into(),
            "openmettle_worker has SELECT on openmettle._sqlx_migrations",
        ),
        (
            "GRANT UPDATE (id) ON openmettle.users TO openmettle_api".into(),
            "REVOKE UPDATE (id) ON openmettle.users FROM openmettle_api".into(),
            "openmettle_api has UPDATE on openmettle.users.id",
        ),
        (
            "GRANT SELECT ON openmettle.messages TO PUBLIC".into(),
            "REVOKE SELECT ON openmettle.messages FROM PUBLIC".into(),
            "PUBLIC has SELECT on openmettle.messages",
        ),
        (
            format!("GRANT CONNECT ON DATABASE {name} TO PUBLIC"),
            format!("REVOKE CONNECT ON DATABASE {name} FROM PUBLIC"),
            "PUBLIC has CONNECT on the database",
        ),
        (
            format!("GRANT TEMPORARY ON DATABASE {name} TO openmettle_worker"),
            format!("REVOKE TEMPORARY ON DATABASE {name} FROM openmettle_worker"),
            "openmettle_worker has TEMPORARY on the database",
        ),
        (
            "GRANT INSERT ON openmettle.user_identities TO openmettle_fixture_capped".into(),
            "REVOKE INSERT ON openmettle.user_identities FROM openmettle_fixture_capped".into(),
            "openmettle_fixture_capped has INSERT on openmettle.user_identities",
        ),
        (
            "GRANT USAGE ON SCHEMA public TO openmettle_api".into(),
            "REVOKE USAGE ON SCHEMA public FROM openmettle_api".into(),
            "openmettle_api has USAGE on schema public",
        ),
        (
            "ALTER DEFAULT PRIVILEGES FOR ROLE openmettle_owner IN SCHEMA openmettle GRANT SELECT ON TABLES TO openmettle_worker".into(),
            "ALTER DEFAULT PRIVILEGES FOR ROLE openmettle_owner IN SCHEMA openmettle REVOKE SELECT ON TABLES FROM openmettle_worker".into(),
            "default privileges of openmettle_owner in schema openmettle grant SELECT on new tables to openmettle_worker",
        ),
    ];
    for (grant, revoke, expected) in &rerun {
        admin.execute(AssertSqlSafe(grant.clone())).await.unwrap();
        let failure = migrate::apply(&settings, MIGRATIONS).await.unwrap_err();
        assert!(
            matches!(failure, Failure::Refused(_)) && failure.to_string().contains(expected),
            "expected {expected:?}, got {failure}"
        );
        admin.execute(AssertSqlSafe(revoke.clone())).await.unwrap();
    }
    migrate::apply(&settings, MIGRATIONS).await.unwrap();
    assert_eq!(db.history().await, all_versions());

    // A migration that grants beyond the contract is reported after it commits.
    let mut overgrant = MIGRATIONS.to_vec();
    overgrant.push(Source {
        version: MIGRATIONS.last().unwrap().version + 1,
        description: "over-grant",
        sql: "GRANT DELETE ON openmettle.messages TO openmettle_worker",
    });
    let failure = migrate::apply(&settings, &overgrant).await.unwrap_err();
    assert!(
        matches!(failure, Failure::Violated(_))
            && failure
                .to_string()
                .contains("openmettle_worker has DELETE on openmettle.messages"),
        "{failure}"
    );
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn application_roles_are_bounded() {
    let db = TestDb::migrated().await;
    let tables = [
        "users",
        "user_identities",
        "scopes",
        "projects",
        "conversations",
        "messages",
        "_sqlx_migrations",
    ];
    let privileges = [
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "TRUNCATE",
        "REFERENCES",
        "TRIGGER",
    ];
    // Declared matrix: anything not listed must be denied.
    let allowed = |role: &str, table: &str, privilege: &str| -> bool {
        match (role, table) {
            (
                API,
                "users" | "user_identities" | "scopes" | "projects" | "conversations" | "messages",
            ) => {
                matches!(privilege, "SELECT" | "INSERT")
            }
            (WORKER, "users" | "user_identities" | "scopes" | "projects" | "conversations") => {
                privilege == "SELECT"
            }
            (WORKER, "messages") => matches!(privilege, "SELECT" | "INSERT"),
            _ => false,
        }
    };
    let mut admin = db.admin().await;
    for role in [API, WORKER] {
        for table in tables {
            for privilege in privileges {
                let granted: bool = sqlx::query_scalar("SELECT has_table_privilege($1, $2, $3)")
                    .bind(role)
                    .bind(format!("openmettle.{table}"))
                    .bind(privilege)
                    .fetch_one(&mut admin)
                    .await
                    .unwrap();
                assert_eq!(
                    granted,
                    allowed(role, table, privilege),
                    "{role} {privilege} {table}"
                );
            }
        }
        let row = sqlx::query(
            "SELECT has_column_privilege($1, 'openmettle.users', 'disabled_at', 'UPDATE'),
                    has_schema_privilege($1, 'openmettle', 'USAGE'),
                    has_schema_privilege($1, 'openmettle', 'CREATE'),
                    has_schema_privilege($1, 'public', 'USAGE'),
                    has_schema_privilege($1, 'public', 'CREATE'),
                    has_database_privilege($1, current_database(), 'CONNECT'),
                    has_database_privilege($1, current_database(), 'TEMP'),
                    has_database_privilege($1, current_database(), 'CREATE'),
                    pg_has_role($1, 'openmettle_owner', 'MEMBER')",
        )
        .bind(role)
        .fetch_one(&mut admin)
        .await
        .unwrap();
        let observed: Vec<bool> = (0..9).map(|i| row.get(i)).collect();
        let column_update = role == API;
        assert_eq!(
            observed,
            [
                column_update,
                true,
                false,
                false,
                false,
                true,
                false,
                false,
                false
            ],
            "{role}"
        );
    }
    // PUBLIC (any other login) cannot connect or create temporary tables.
    let public: (bool, bool) = sqlx::query_as(
        "SELECT has_database_privilege('public', current_database(), 'CONNECT'),
                has_database_privilege('public', current_database(), 'TEMP')",
    )
    .fetch_one(&mut admin)
    .await
    .unwrap();
    assert_eq!(public, (false, false));

    // Actual denied operations for both application roles.
    for role in [API, WORKER] {
        let mut connection = connect(&db.0, role).await;
        for sql in [
            "CREATE TABLE openmettle.intruder (id int)",
            "CREATE TABLE public.intruder (id int)",
            "CREATE TEMP TABLE intruder (id int)",
            "CREATE SCHEMA intruder",
            "ALTER TABLE openmettle.users ADD COLUMN intruder int",
            "DROP TABLE openmettle.messages",
            "TRUNCATE openmettle.users",
            "TRUNCATE openmettle.messages",
            "DELETE FROM openmettle.users",
            "DELETE FROM openmettle.messages",
            "UPDATE openmettle.scopes SET kind = 'project'",
            "UPDATE openmettle.conversations SET owner_user_id = owner_user_id",
            "SELECT * FROM openmettle._sqlx_migrations",
            "INSERT INTO openmettle._sqlx_migrations VALUES (99, 'x', now(), true, '\\x00', 0)",
            "UPDATE openmettle._sqlx_migrations SET checksum = '\\x00'",
            "DELETE FROM openmettle._sqlx_migrations",
            "SET ROLE openmettle_owner",
            "SET SESSION AUTHORIZATION openmettle_owner",
        ] {
            expect_state(&mut connection, sql, "42501").await;
        }
    }
    let mut worker = connect(&db.0, WORKER).await;
    for sql in [
        "INSERT INTO openmettle.users DEFAULT VALUES",
        "UPDATE openmettle.users SET disabled_at = now()",
        // From migration 15 the worker reads identities for its recheck, but never writes them.
        "UPDATE openmettle.user_identities SET subject = subject",
        "INSERT INTO openmettle.user_identities (user_id, issuer, subject) \
         SELECT id, 'https://issuer.example.test', 'worker' FROM openmettle.users",
        "INSERT INTO openmettle.scopes (kind, project_id) VALUES ('project', gen_random_uuid())",
        "INSERT INTO openmettle.conversations (scope_id, scope_kind, owner_user_id) \
         VALUES (gen_random_uuid(), 'personal', gen_random_uuid())",
    ] {
        expect_state(&mut worker, sql, "42501").await;
    }
    // Granted operations work: the API admits a user; the worker appends a message.
    let mut api = connect(&db.0, API).await;
    let user = new_user(&mut api).await;
    let scope = personal_scope(&mut api, &user).await;
    let chat = conversation(&mut api, &scope, "personal", &user)
        .await
        .unwrap();
    message(&mut worker, &scope, &chat, None).await.unwrap();
    sqlx::query("UPDATE openmettle.users SET disabled_at = now() WHERE id = $1::uuid")
        .bind(&user)
        .execute(&mut api)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn ownership_constraints_reject_cross_scope_references() {
    let db = TestDb::migrated().await;
    let mut api = connect(&db.0, API).await;
    let alice = new_user(&mut api).await;
    let bob = new_user(&mut api).await;
    let alice_scope = personal_scope(&mut api, &alice).await;
    let bob_scope = personal_scope(&mut api, &bob).await;
    let (project_id, project_scope) = project(&mut api, &alice).await;

    // Personal scope relationships.
    expect_state(
        &mut api,
        &format!(
            "INSERT INTO openmettle.scopes (kind, personal_user_id) VALUES ('personal', '{alice}')"
        ),
        "23505",
    )
    .await;
    let carol = new_user(&mut api).await;
    expect_state(
        &mut api,
        &format!(
            "INSERT INTO openmettle.scopes (kind, personal_user_id, project_id) \
             VALUES ('personal', '{carol}', '{project_id}')"
        ),
        "23514",
    )
    .await;
    expect_state(
        &mut api,
        "INSERT INTO openmettle.scopes (kind) VALUES ('team')",
        "23514",
    )
    .await;
    // Project scope relationships are checked at commit (deferred, bidirectional).
    expect_state(
        &mut api,
        "INSERT INTO openmettle.scopes (kind, project_id) VALUES ('project', gen_random_uuid())",
        "23503",
    )
    .await;
    expect_state(
        &mut api,
        &format!(
            "INSERT INTO openmettle.projects (scope_id, created_by_user_id) VALUES ('{alice_scope}', '{alice}')"
        ),
        "23503",
    )
    .await;
    expect_state(
        &mut api,
        &format!(
            "INSERT INTO openmettle.projects (scope_id, created_by_user_id) VALUES ('{project_scope}', '{alice}')"
        ),
        "23505",
    )
    .await;

    // A personal conversation cannot name another owner or misstate its scope kind.
    assert_eq!(
        sqlstate(conversation(&mut api, &alice_scope, "personal", &bob).await),
        "23503"
    );
    assert_eq!(
        sqlstate(conversation(&mut api, &alice_scope, "project", &alice).await),
        "23503"
    );
    assert_eq!(
        sqlstate(conversation(&mut api, &project_scope, "personal", &alice).await),
        "23503"
    );
    let alice_chat = conversation(&mut api, &alice_scope, "personal", &alice)
        .await
        .unwrap();
    let bob_chat = conversation(&mut api, &bob_scope, "personal", &bob)
        .await
        .unwrap();
    // A project conversation records its private owner; membership is not modelled here.
    let project_chat = conversation(&mut api, &project_scope, "project", &bob)
        .await
        .unwrap();

    // Messages stay in their conversation's scope and parent conversation.
    let root = message(&mut api, &alice_scope, &alice_chat, None)
        .await
        .unwrap();
    let bob_root = message(&mut api, &bob_scope, &bob_chat, None)
        .await
        .unwrap();
    assert_eq!(
        sqlstate(message(&mut api, &bob_scope, &alice_chat, None).await),
        "23503"
    );
    assert_eq!(
        sqlstate(message(&mut api, &project_scope, &alice_chat, Some(&root)).await),
        "23503"
    );
    assert_eq!(
        sqlstate(message(&mut api, &alice_scope, &alice_chat, Some(&bob_root)).await),
        "23503"
    );
    assert_eq!(
        sqlstate(message(&mut api, &project_scope, &project_chat, Some(&root)).await),
        "23503"
    );
    expect_state(
        &mut api,
        &format!(
            "INSERT INTO openmettle.messages (id, scope_id, conversation_id, parent_message_id) \
             SELECT m, '{alice_scope}', '{alice_chat}', m FROM gen_random_uuid() m"
        ),
        "23514",
    )
    .await;
    let child = message(&mut api, &alice_scope, &alice_chat, Some(&root))
        .await
        .unwrap();
    message(&mut api, &alice_scope, &alice_chat, Some(&child))
        .await
        .unwrap();
    message(&mut api, &project_scope, &project_chat, None)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn concurrent_identity_admission_has_one_winner() {
    let db = TestDb::migrated().await;
    let contenders = 8;
    let barrier = Arc::new(tokio::sync::Barrier::new(contenders));
    let mut tasks = Vec::new();
    for _ in 0..contenders {
        let barrier = barrier.clone();
        let options = role_options(&db.0, API);
        tasks.push(tokio::spawn(async move {
            let mut connection = PgConnection::connect_with(&options).await.unwrap();
            barrier.wait().await;
            // One admission transaction: account plus issuer/subject mapping.
            let result: Result<(), sqlx::Error> = async {
                let mut tx = connection.begin().await?;
                let user = new_user(&mut tx).await;
                sqlx::query(
                    "INSERT INTO openmettle.user_identities (user_id, issuer, subject)
                     VALUES ($1::uuid, 'https://issuer.example.test', 'same-subject')",
                )
                .bind(user)
                .execute(&mut *tx)
                .await?;
                tx.commit().await
            }
            .await;
            result.map_err(|e| sqlstate::<()>(Err(e)))
        }));
    }
    let mut outcomes = Vec::new();
    for task in tasks {
        outcomes.push(task.await.unwrap());
    }
    assert_eq!(
        outcomes.iter().filter(|o| o.is_ok()).count(),
        1,
        "{outcomes:?}"
    );
    assert!(
        outcomes
            .iter()
            .all(|o| o.as_ref().err().is_none_or(|code| code == "23505"))
    );
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM openmettle.users),
                (SELECT count(*) FROM openmettle.user_identities)",
    )
    .fetch_one(&mut db.admin().await)
    .await
    .unwrap();
    assert_eq!(counts, (1, 1), "losing admissions leave no orphan account");
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn role_connection_limit_caps_sessions() {
    let db = TestDb::migrated().await;
    // Test-only role: CONNECTION LIMIT 2, member of openmettle_api.
    let mut first = connect(&db.0, CAPPED).await;
    let _second = connect(&db.0, CAPPED).await;
    let third = PgConnection::connect_with(&role_options(&db.0, CAPPED)).await;
    assert_eq!(sqlstate(third), "53300");
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM openmettle.users")
        .fetch_one(&mut first)
        .await
        .unwrap();
    assert_eq!(users, 0);
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to an isolated PostgreSQL test service"]
async fn runtime_readiness_with_bounded_roles_never_migrates() {
    let db = TestDb::new().await;
    // Before migration the default database grants still allow CONNECT.
    let (mut api, bind) = start_service(false, &db.url(API));
    wait_ready(&mut api, &bind);
    drop(api);
    let schema: Option<String> = sqlx::query_scalar("SELECT to_regnamespace('openmettle')::text")
        .fetch_one(&mut db.admin().await)
        .await
        .unwrap();
    assert_eq!(schema, None, "the API must not create schema");

    let output = migrate_command(&db.url(OWNER), &[]).output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let (mut api, api_bind) = start_service(false, &db.url(API));
    let (mut worker, worker_bind) = start_service(true, &db.url(WORKER));
    wait_ready(&mut api, &api_bind);
    wait_ready(&mut worker, &worker_bind);
    for (process, worker) in [(&mut worker, true), (&mut api, false)] {
        signal(&process.0, "-TERM");
        let status = process.0.wait().unwrap();
        assert!(status.success(), "worker={worker}");
    }
    assert_eq!(db.history().await, all_versions());
}

#[path = "schema/durable.rs"]
mod durable;

#[path = "schema/sessions.rs"]
mod sessions;

#[path = "schema/authz_store.rs"]
mod authz_store;

#[path = "schema/authz_projects.rs"]
mod authz_projects;
