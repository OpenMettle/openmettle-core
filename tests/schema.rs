//! Migration, ownership and role-boundary tests. Ignored tests need TEST_DATABASE_URL for an
//! isolated, disposable PostgreSQL 18 service with a superuser fixture account. They create
//! synthetic cluster roles (`openmettle_*`, test-only password) and one database per test.
#[path = "support/env.rs"]
mod env_support;
use env_support::scrub_env;
#[path = "support/pg.rs"]
mod pg;
use openmettle_core::migrate::{self, Failure, MIGRATIONS, Settings, Source};
use pg::{
    API, CAPPED, ISSUANCE, OWNER, PASSWORD, WORKER, admin, admin_blocking, admin_options, connect,
    role_options, role_url,
};
use sqlx::{AssertSqlSafe, Connection, Executor, PgConnection, Row};
use sqlx_core::migrate::{Migrate, MigrateError};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Child, Command, Output, Stdio},
    sync::{Arc, atomic::Ordering},
    thread,
    time::{Duration, Instant},
};

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

/// Restores cluster role state when dropped, including after a failed assertion.
struct Restore(&'static [&'static str]);
impl Drop for Restore {
    fn drop(&mut self) {
        admin_blocking(None, self.0.iter().map(|s| s.to_string()).collect());
    }
}

/// A fresh database owned by openmettle_owner, dropped when the test ends.
struct TestDb(String, #[allow(dead_code)] pg::DisposableDb);
impl TestDb {
    async fn new() -> Self {
        Self::with_options(false, "").await
    }
    /// For tests that change cluster-wide role state; excludes all other test databases.
    async fn exclusive() -> Self {
        Self::with_options(true, "").await
    }
    async fn create(lock: &'static str, options: &'static str) -> Self {
        let exclusive = match lock {
            "SELECT pg_advisory_lock($1)" => true,
            "SELECT pg_advisory_lock_shared($1)" => false,
            other => panic!("unexpected role-state lock query: {other}"),
        };
        Self::with_options(exclusive, options).await
    }
    async fn with_options(exclusive: bool, options: &str) -> Self {
        let db = pg::DisposableDb::create("om_schema", exclusive, true, options).await;
        Self(db.name().to_owned(), db)
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

/// Wait for the operation under test to reach a lock held by the fixture.
async fn wait_for_blocked_peer(db: &TestDb, holder: i32) {
    let mut observer = db.admin().await;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database()
                    AND $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(holder)
            .fetch_one(&mut observer)
            .await
            .unwrap();
            if waiting {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("expected a peer to wait on the fixture lock");
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

// Model the publisher's committed inode binding and publication fence in ledger-only tests.
async fn mark_storage_payload_published(c: &mut PgConnection, id: &str) {
    sqlx::query("UPDATE openmettle.storage_reservations SET stage_claimed=true,
        payload_ino=coalesce(payload_ino,abs(hashtextextended(id::text,0)::numeric)+1),publish_pending=true
        WHERE id=$1::uuid AND state='reserved' AND NOT adoption_unverified AND reclaim_state='none'")
        .bind(id).execute(c).await.unwrap();
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

// --- declarative additive-schema registry -----------------------------------------------------

/// Expected JSON value of an additive column on rows that existed before the migration adding it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ColumnDefault {
    Null,
    Bool(bool),
    Int(i64),
    Str(&'static str),
    /// Non-null value assigned dynamically at upgrade time (for example `clock_timestamp()`).
    AnyNonNull,
}

impl ColumnDefault {
    fn matches(self, value: &serde_json::Value) -> bool {
        match self {
            Self::Null => value.is_null(),
            Self::Bool(expected) => value.as_bool() == Some(expected),
            Self::Int(expected) => value.as_i64() == Some(expected),
            Self::Str(expected) => value.as_str() == Some(expected),
            Self::AnyNonNull => !value.is_null(),
        }
    }

    fn describe(self) -> String {
        match self {
            Self::Null => "null".to_owned(),
            Self::Bool(v) => v.to_string(),
            Self::Int(v) => v.to_string(),
            Self::Str(v) => format!("{v:?}"),
            Self::AnyNonNull => "a non-null value".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AdditiveColumn {
    since: i64,
    table: &'static str,
    column: &'static str,
    default: ColumnDefault,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AdditiveTable {
    since: i64,
    table: &'static str,
    /// Optional singleton seed row inserted by the migration, as JSON text.
    seed_row: Option<&'static str>,
}

const SINGLETON_LOCK_SEED: &str = r#"{"id": true, "lock_guard": false}"#;

/// Single declarative registry of every column added to an existing table by migrations after
/// the early schema baselines, ordered by `since` migration version. Adding entries here
/// automatically updates every historical upgrade test (`v1`–`v18`).
const ADDITIVE_COLUMNS: &[AdditiveColumn] = &[
    AdditiveColumn {
        since: 8,
        table: "login_providers",
        column: "lock_guard",
        default: ColumnDefault::Bool(false),
    },
    AdditiveColumn {
        since: 8,
        table: "login_providers",
        column: "access_generation",
        default: ColumnDefault::Int(0),
    },
    AdditiveColumn {
        since: 8,
        table: "login_providers",
        column: "changed_at",
        default: ColumnDefault::AnyNonNull,
    },
    AdditiveColumn {
        since: 8,
        table: "login_providers",
        column: "changed_by",
        default: ColumnDefault::Str("migration-8"),
    },
    AdditiveColumn {
        since: 8,
        table: "login_providers",
        column: "change_reason",
        default: ColumnDefault::Str("initial session authority"),
    },
    AdditiveColumn {
        since: 8,
        table: "users",
        column: "session_generation",
        default: ColumnDefault::Int(0),
    },
    AdditiveColumn {
        since: 8,
        table: "login_transactions",
        column: "session_issued",
        default: ColumnDefault::Bool(false),
    },
    AdditiveColumn {
        since: 13,
        table: "home_invitations",
        column: "code_hash",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 16,
        table: "grant_assignments",
        column: "grantee_kind",
        default: ColumnDefault::Str("user"),
    },
    AdditiveColumn {
        since: 16,
        table: "grant_assignments",
        column: "grantee_local_group_id",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 16,
        table: "grant_assignments",
        column: "grantee_oidc_group_id",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 16,
        table: "projects",
        column: "lock_guard",
        default: ColumnDefault::Bool(false),
    },
    AdditiveColumn {
        since: 17,
        table: "artifact_revisions",
        column: "display_name",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 18,
        table: "users",
        column: "lock_guard",
        default: ColumnDefault::Bool(false),
    },
    AdditiveColumn {
        since: 18,
        table: "grant_mapping_rules",
        column: "lock_guard",
        default: ColumnDefault::Bool(false),
    },
    AdditiveColumn {
        since: 19,
        table: "runs",
        column: "actor_approval_id",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 19,
        table: "runs",
        column: "round_limit",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 19,
        table: "runs",
        column: "queue_expires_at",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 19,
        table: "runs",
        column: "claim_token",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 19,
        table: "runs",
        column: "claimed_at",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 20,
        table: "runs",
        column: "lease_expires_at",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 20,
        table: "runs",
        column: "execution_expires_at",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 20,
        table: "runs",
        column: "cancel_reason",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 22,
        table: "runs",
        column: "execution_mode",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 22,
        table: "runs",
        column: "originating_session_id",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 22,
        table: "runs",
        column: "admission_evidence",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 22,
        table: "runs",
        column: "approval_wait_id",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 22,
        table: "operations",
        column: "approval_id",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 22,
        table: "operations",
        column: "approval_decision",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 24,
        table: "storage_instance",
        column: "warn_pct_1",
        default: ColumnDefault::Int(80),
    },
    AdditiveColumn {
        since: 24,
        table: "storage_instance",
        column: "warn_pct_2",
        default: ColumnDefault::Int(90),
    },
    AdditiveColumn {
        since: 24,
        table: "storage_instance",
        column: "config_revision",
        default: ColumnDefault::Int(1),
    },
    AdditiveColumn {
        since: 24,
        table: "storage_reservations",
        column: "lease_expires_at",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 24,
        table: "storage_reservations",
        column: "adoption_unverified",
        default: ColumnDefault::Bool(false),
    },
    AdditiveColumn {
        since: 24,
        table: "storage_reservations",
        column: "stage_claimed",
        default: ColumnDefault::Bool(false),
    },
    AdditiveColumn {
        since: 24,
        table: "storage_reservations",
        column: "payload_ino",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 24,
        table: "storage_reservations",
        column: "publish_pending",
        default: ColumnDefault::Bool(false),
    },
    AdditiveColumn {
        since: 24,
        table: "storage_reservations",
        column: "reclaim_state",
        default: ColumnDefault::Str("none"),
    },
    AdditiveColumn {
        since: 24,
        table: "storage_reservations",
        column: "reclaim_claim_token",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 24,
        table: "storage_reservations",
        column: "reclaim_lease_until",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 24,
        table: "artifact_revisions",
        column: "purge_stage",
        default: ColumnDefault::Str("none"),
    },
    AdditiveColumn {
        since: 25,
        table: "operations",
        column: "dispatched_attempts",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 25,
        table: "operations",
        column: "effective_expires_us",
        default: ColumnDefault::Null,
    },
    AdditiveColumn {
        since: 26,
        table: "quota_enforcement",
        column: "overrides_enforced",
        default: ColumnDefault::Bool(false),
    },
    AdditiveColumn {
        since: 26,
        table: "quota_enforcement",
        column: "overrides_enforced_at",
        default: ColumnDefault::Null,
    },
];

/// Single declarative registry of every table added after migration 14, ordered by `since`
/// migration version, along with any singleton seed row inserted by its migration.
const ADDITIVE_TABLES: &[AdditiveTable] = &[
    AdditiveTable {
        since: 15,
        table: "account_admin_lock",
        seed_row: Some(SINGLETON_LOCK_SEED),
    },
    AdditiveTable {
        since: 15,
        table: "account_admins",
        seed_row: None,
    },
    AdditiveTable {
        since: 15,
        table: "authorization_audit",
        seed_row: None,
    },
    AdditiveTable {
        since: 15,
        table: "local_group_memberships",
        seed_row: None,
    },
    AdditiveTable {
        since: 15,
        table: "local_groups",
        seed_row: None,
    },
    AdditiveTable {
        since: 15,
        table: "platform_capability_denies",
        seed_row: None,
    },
    AdditiveTable {
        since: 15,
        table: "project_settings",
        seed_row: None,
    },
    AdditiveTable {
        since: 15,
        table: "user_capability_denies",
        seed_row: None,
    },
    AdditiveTable {
        since: 15,
        table: "user_capability_grants",
        seed_row: None,
    },
    AdditiveTable {
        since: 19,
        table: "run_dispatch_lock",
        seed_row: Some(SINGLETON_LOCK_SEED),
    },
    AdditiveTable {
        since: 21,
        table: "branch_heads",
        seed_row: None,
    },
    AdditiveTable {
        since: 21,
        table: "message_parts",
        seed_row: None,
    },
    AdditiveTable {
        since: 21,
        table: "message_turns",
        seed_row: None,
    },
    AdditiveTable {
        since: 22,
        table: "run_approvals",
        seed_row: None,
    },
    AdditiveTable {
        since: 22,
        table: "run_approval_decisions",
        seed_row: None,
    },
    AdditiveTable {
        since: 23,
        table: "gateway_bindings",
        seed_row: None,
    },
    AdditiveTable {
        since: 23,
        table: "gateway_nonces",
        seed_row: None,
    },
    AdditiveTable {
        since: 23,
        table: "gateway_generations",
        seed_row: None,
    },
    AdditiveTable {
        since: 23,
        table: "gateway_policy",
        seed_row: None,
    },
    AdditiveTable {
        since: 23,
        table: "gateway_intents",
        seed_row: None,
    },
    AdditiveTable {
        since: 23,
        table: "gateway_audit",
        seed_row: None,
    },
    AdditiveTable {
        since: 23,
        table: "gateway_reservations",
        seed_row: None,
    },
    AdditiveTable {
        since: 23,
        table: "gateway_requests",
        seed_row: None,
    },
    AdditiveTable {
        since: 23,
        table: "gateway_usage_reports",
        seed_row: None,
    },
    AdditiveTable {
        since: 23,
        table: "gateway_settlements",
        seed_row: None,
    },
    AdditiveTable {
        since: 24,
        table: "storage_volume_control",
        seed_row: Some(
            r#"{"id":true,"volume_id":null,"bootstrap_auto_pin_allowed":false,"adoption_run_id":null}"#,
        ),
    },
    AdditiveTable {
        since: 24,
        table: "quota_accepted_gateway_reports",
        seed_row: None,
    },
    AdditiveTable {
        since: 24,
        table: "quota_defaults",
        seed_row: Some(
            r#"{"scope_kind":"instance","resource_kind":"usage_cost_micros","hard_limit":null,"window_seconds":null,"cost_denomination":null,"warn_pct_1":80,"warn_pct_2":90,"config_revision":1}"#,
        ),
    },
    AdditiveTable {
        since: 24,
        table: "quota_cost_unit_lock",
        seed_row: Some(r#"{"id":true}"#),
    },
    AdditiveTable {
        since: 24,
        table: "quota_enforcement",
        seed_row: Some(
            r#"{"id":true,"metering_enforced":false,"metering_enforced_at":null,"overrides_enforced":false,"overrides_enforced_at":null}"#,
        ),
    },
    AdditiveTable {
        since: 24,
        table: "quota_gateway_handoffs",
        seed_row: None,
    },
    AdditiveTable {
        since: 24,
        table: "quota_overrides",
        seed_row: None,
    },
    AdditiveTable {
        since: 24,
        table: "quota_budgets",
        seed_row: None,
    },
    AdditiveTable {
        since: 24,
        table: "quota_reservations",
        seed_row: None,
    },
    AdditiveTable {
        since: 24,
        table: "quota_reservation_charges",
        seed_row: None,
    },
    AdditiveTable {
        since: 24,
        table: "quota_reconciliations",
        seed_row: None,
    },
    AdditiveTable {
        since: 24,
        table: "quota_warning_events",
        seed_row: None,
    },
    AdditiveTable {
        since: 27,
        table: "capacity_groups",
        seed_row: None,
    },
    AdditiveTable {
        since: 27,
        table: "capacity_devices",
        seed_row: None,
    },
    AdditiveTable {
        since: 27,
        table: "capacity_observations",
        seed_row: None,
    },
    AdditiveTable {
        since: 27,
        table: "capacity_grants",
        seed_row: None,
    },
    AdditiveTable {
        since: 27,
        table: "capacity_grant_devices",
        seed_row: None,
    },
];

fn additive_columns_since(base_version: i64) -> impl Iterator<Item = &'static AdditiveColumn> {
    ADDITIVE_COLUMNS
        .iter()
        .filter(move |entry| entry.since > base_version)
}

fn expected_added_tables_since(base_version: i64) -> impl Iterator<Item = &'static AdditiveTable> {
    assert!(
        base_version >= 14,
        "ADDITIVE_TABLES tracks tables added after migration 14"
    );
    ADDITIVE_TABLES
        .iter()
        .filter(move |entry| entry.since > base_version)
}

fn canonical_json(raw: &str) -> String {
    serde_json::from_str::<serde_json::Value>(raw)
        .unwrap_or_else(|error| panic!("invalid JSON ({error}): {raw}"))
        .to_string()
}

/// Normalizes one JSON row from `table` to the schema at `base_version`: strips every column
/// added after `base_version` and asserts each present stripped column holds its declared
/// pre-existing-row default.
fn normalize_upgraded_row(table: &str, base_version: i64, raw: &str) -> Result<String, String> {
    let mut value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|error| format!("{table}: invalid row JSON ({error}): {raw}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| format!("{table}: expected JSON object row, got {raw}"))?;
    for entry in additive_columns_since(base_version).filter(|entry| entry.table == table) {
        if let Some(found) = object.remove(entry.column)
            && !entry.default.matches(&found)
        {
            return Err(format!(
                "{table}.{} (migration {}): expected {}, got {found}",
                entry.column,
                entry.since,
                entry.default.describe()
            ));
        }
    }
    Ok(value.to_string())
}

fn normalize_upgraded_rows(
    table: &str,
    base_version: i64,
    rows: &BTreeSet<String>,
) -> BTreeSet<String> {
    rows.iter()
        .map(|row| {
            normalize_upgraded_row(table, base_version, row)
                .unwrap_or_else(|error| panic!("{error}"))
        })
        .collect()
}

async fn snapshot_tables(
    connection: &mut PgConnection,
    tables: &[&str],
    base_version: i64,
    require_nonempty: bool,
) -> Vec<String> {
    let mut rows = Vec::new();
    for table in tables {
        let raw_rows: Vec<String> = sqlx::query_scalar(AssertSqlSafe(format!(
            "SELECT to_jsonb(t)::text FROM openmettle.{table} t"
        )))
        .fetch_all(&mut *connection)
        .await
        .unwrap();
        if require_nonempty {
            assert!(
                !raw_rows.is_empty(),
                "upgrade fixture must populate {table}"
            );
        }
        let mut normalized: Vec<String> = raw_rows
            .iter()
            .map(|row| {
                normalize_upgraded_row(table, base_version, row)
                    .unwrap_or_else(|error| panic!("{error}"))
            })
            .collect();
        normalized.sort();
        rows.push(format!("{table}: {}", normalized.len()));
        rows.extend(normalized);
    }
    rows
}

/// Rows written before an upgrade from `base_version`, unchanged by it. Columns added after
/// `base_version` are stripped after asserting each holds its declared pre-existing-row default.
async fn snapshot_at(
    connection: &mut PgConnection,
    tables: &[&str],
    base_version: i64,
) -> Vec<String> {
    snapshot_tables(connection, tables, base_version, false).await
}

/// Same as `snapshot_at`, additionally asserting each listed table is populated by the fixture.
async fn snapshot_nonempty_at(
    connection: &mut PgConnection,
    tables: &[&str],
    base_version: i64,
) -> Vec<String> {
    snapshot_tables(connection, tables, base_version, true).await
}

/// Convenience wrapper for the early (`v1`–`v3`) baseline upgrade tests, before any additive
/// columns existed (the first additive columns arrive in migration 8).
async fn snapshot(connection: &mut PgConnection, tables: &[&str]) -> Vec<String> {
    snapshot_at(connection, tables, 3).await
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
        "6b2363d7267c088f75999b697fee05f74f88ee4a572be688558b03e9fe27d35c",
        "26a9aff24fdead77748763b8e73ecf834faddfcfa5b0c3b70eebc5dd624000db",
        "93686928e8f33f08c340f6dbe6348727a1f9abb4c44c0e68061d10578d181e59",
        "a4a226cb408141a41dfb7e174646d7027af6d34c34020d6ba8401aa6dfad7116",
        "47ee7ed667d0f65034e4b9ea8315f66807ae8ed5a4428f3afc1763d205c8bc00",
        "e9221570f5187a4fc2d666d3724d8646d6d4236d3cb7997538e80ec10355be57",
        "275b395fab0a1e90fc6f9a3039d008adc138294af0cb0da9cb944df87b26ec1c",
        "a6ea85d09af2c2aa7d267499623a46a3922e695b79bdf585cd8e2164d68e5d9a",
        "814d7832603fdb9752e55259c1c44b6815228ae5fb128b54ed5becf9fed508d7",
        "dad89ccf522802b8c572ec8947fdfede32e569a5e26004ecb593edf50c96711f",
        "858eb86f8ee09074114d6a50c16d7c713612d4be39242106fc2d6e2443c474cd",
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

/// Plain non-DB check that the declarative additive-schema registry stays ordered, unique,
/// in sync with the embedded migration SQL, strips post-baseline columns holding their
/// declared defaults, and rejects doctored non-default values.
#[test]
fn additive_schema_registry_normalizes_and_validates_defaults() {
    let valid_ident = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    let versions: BTreeSet<i64> = all_versions().into_iter().collect();

    // Registry ordering, identifiers, uniqueness and seed JSON validity.
    let mut prev_col_version = 0;
    let mut seen_columns = BTreeSet::new();
    for entry in ADDITIVE_COLUMNS {
        assert!(
            entry.since >= prev_col_version,
            "ADDITIVE_COLUMNS must be sorted by `since`: {entry:?}"
        );
        prev_col_version = entry.since;
        assert!(
            versions.contains(&entry.since),
            "unknown version: {entry:?}"
        );
        assert!(valid_ident(entry.table), "invalid table: {entry:?}");
        assert!(valid_ident(entry.column), "invalid column: {entry:?}");
        assert!(
            seen_columns.insert((entry.table, entry.column)),
            "duplicate additive column: {entry:?}"
        );
    }

    let mut prev_table_version = 14;
    let mut seen_tables = BTreeSet::new();
    for entry in ADDITIVE_TABLES {
        assert!(
            entry.since >= prev_table_version && entry.since > 14,
            "ADDITIVE_TABLES must be sorted and after migration 14: {entry:?}"
        );
        prev_table_version = entry.since;
        assert!(
            versions.contains(&entry.since),
            "unknown version: {entry:?}"
        );
        assert!(valid_ident(entry.table), "invalid table: {entry:?}");
        assert!(
            seen_tables.insert(entry.table),
            "duplicate additive table: {entry:?}"
        );
        if let Some(seed) = entry.seed_row {
            let parsed: serde_json::Value = serde_json::from_str(seed).unwrap();
            assert!(parsed.is_object(), "seed row must be a JSON object: {seed}");
        }
    }

    // Cross-check the registry 1-to-1 against every ADD COLUMN and post-v14 CREATE TABLE in
    // the embedded migration SQL so future additive migrations cannot drift from the registry.
    let mut sql_columns = BTreeSet::new();
    let mut sql_tables = BTreeSet::new();
    for migration in MIGRATIONS {
        let stripped: String = migration
            .sql
            .lines()
            .map(|line| line.split("--").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        for stmt in stripped.split(';') {
            let tokens: Vec<&str> = stmt.split_whitespace().collect();
            if tokens.len() >= 3
                && tokens[0].eq_ignore_ascii_case("ALTER")
                && tokens[1].eq_ignore_ascii_case("TABLE")
                && let Some(table) = tokens[2].strip_prefix("openmettle.")
            {
                let table = table.trim_end_matches('(');
                for window in tokens.windows(3) {
                    if window[0].eq_ignore_ascii_case("ADD")
                        && window[1].eq_ignore_ascii_case("COLUMN")
                    {
                        sql_columns.insert((
                            migration.version,
                            table.to_owned(),
                            window[2].trim_end_matches(',').to_owned(),
                        ));
                    }
                }
            }
            if migration.version > 14
                && tokens.len() >= 3
                && tokens[0].eq_ignore_ascii_case("CREATE")
                && tokens[1].eq_ignore_ascii_case("TABLE")
                && let Some(table) = tokens[2].strip_prefix("openmettle.")
            {
                sql_tables.insert((migration.version, table.trim_end_matches('(').to_owned()));
            }
        }
    }
    let registered_columns: BTreeSet<(i64, String, String)> = ADDITIVE_COLUMNS
        .iter()
        .map(|e| (e.since, e.table.to_owned(), e.column.to_owned()))
        .collect();
    assert_eq!(registered_columns, sql_columns);
    let registered_tables: BTreeSet<(i64, String)> = ADDITIVE_TABLES
        .iter()
        .map(|e| (e.since, e.table.to_owned()))
        .collect();
    assert_eq!(registered_tables, sql_tables);

    // `expected_added_tables_since` filters accurately and preserves singleton lock seeds.
    let after_14: Vec<(&str, Option<&str>)> = expected_added_tables_since(14)
        .map(|e| (e.table, e.seed_row))
        .collect();
    assert_eq!(after_14.len(), 42);
    assert!(after_14.contains(&("account_admin_lock", Some(SINGLETON_LOCK_SEED))));
    assert!(after_14.contains(&("run_dispatch_lock", Some(SINGLETON_LOCK_SEED))));
    let after_18: Vec<(&str, Option<&str>)> = expected_added_tables_since(18)
        .map(|e| (e.table, e.seed_row))
        .collect();
    assert_eq!(
        after_18,
        vec![
            ("run_dispatch_lock", Some(SINGLETON_LOCK_SEED)),
            ("branch_heads", None),
            ("message_parts", None),
            ("message_turns", None),
            ("run_approvals", None),
            ("run_approval_decisions", None),
            ("gateway_bindings", None),
            ("gateway_nonces", None),
            ("gateway_generations", None),
            ("gateway_policy", None),
            ("gateway_intents", None),
            ("gateway_audit", None),
            ("gateway_reservations", None),
            ("gateway_requests", None),
            ("gateway_usage_reports", None),
            ("gateway_settlements", None),
            (
                "storage_volume_control",
                Some(
                    r#"{"id":true,"volume_id":null,"bootstrap_auto_pin_allowed":false,"adoption_run_id":null}"#
                )
            ),
            ("quota_accepted_gateway_reports", None),
            (
                "quota_defaults",
                Some(
                    r#"{"scope_kind":"instance","resource_kind":"usage_cost_micros","hard_limit":null,"window_seconds":null,"cost_denomination":null,"warn_pct_1":80,"warn_pct_2":90,"config_revision":1}"#
                )
            ),
            ("quota_cost_unit_lock", Some(r#"{"id":true}"#)),
            (
                "quota_enforcement",
                Some(
                    r#"{"id":true,"metering_enforced":false,"metering_enforced_at":null,"overrides_enforced":false,"overrides_enforced_at":null}"#
                )
            ),
            ("quota_gateway_handoffs", None),
            ("quota_overrides", None),
            ("quota_budgets", None),
            ("quota_reservations", None),
            ("quota_reservation_charges", None),
            ("quota_reconciliations", None),
            ("quota_warning_events", None),
            ("capacity_groups", None),
            ("capacity_devices", None),
            ("capacity_observations", None),
            ("capacity_grants", None),
            ("capacity_grant_devices", None),
        ]
    );

    // `normalize_upgraded_row` strips only columns added after `base_version` when they hold
    // their declared defaults, leaving columns already present at `base_version` intact.
    let pre_19_run = r#"{"id":"r1","state":"queued"}"#;
    let upgraded_run = r#"{
        "id": "r1",
        "state": "queued",
        "actor_approval_id": null,
        "round_limit": null,
        "queue_expires_at": null,
        "claim_token": null,
        "claimed_at": null
    }"#;
    assert_eq!(
        normalize_upgraded_row("runs", 18, upgraded_run).unwrap(),
        pre_19_run
    );
    assert_eq!(
        normalize_upgraded_row("runs", 18, pre_19_run).unwrap(),
        pre_19_run
    );

    let upgraded_user_v7 = r#"{"id":"u1","session_generation":0,"lock_guard":false}"#;
    assert_eq!(
        normalize_upgraded_row("users", 7, upgraded_user_v7).unwrap(),
        r#"{"id":"u1"}"#
    );
    // At base_version 8, `session_generation` already existed and must NOT be stripped.
    let upgraded_user_v8 = r#"{"id":"u1","session_generation":1,"lock_guard":false}"#;
    assert_eq!(
        normalize_upgraded_row("users", 8, upgraded_user_v8).unwrap(),
        r#"{"id":"u1","session_generation":1}"#
    );

    let upgraded_grant = r#"{
        "id": "g1",
        "grantee_kind": "user",
        "grantee_local_group_id": null,
        "grantee_oidc_group_id": null
    }"#;
    assert_eq!(
        normalize_upgraded_row("grant_assignments", 14, upgraded_grant).unwrap(),
        r#"{"id":"g1"}"#
    );

    let upgraded_provider = r#"{
        "id": "p1",
        "lock_guard": false,
        "access_generation": 0,
        "changed_at": "2026-01-01T00:00:00Z",
        "changed_by": "migration-8",
        "change_reason": "initial session authority"
    }"#;
    assert_eq!(
        normalize_upgraded_row("login_providers", 7, upgraded_provider).unwrap(),
        r#"{"id":"p1"}"#
    );

    // Doctored non-default values on stripped columns must be rejected with clear diagnostics.
    for (table, base, row, expected_column) in [
        (
            "runs",
            18,
            r#"{"id":"r1","round_limit":10}"#,
            "runs.round_limit",
        ),
        (
            "users",
            14,
            r#"{"id":"u1","lock_guard":true}"#,
            "users.lock_guard",
        ),
        (
            "users",
            7,
            r#"{"id":"u1","session_generation":1}"#,
            "users.session_generation",
        ),
        (
            "grant_assignments",
            14,
            r#"{"id":"g1","grantee_kind":"project"}"#,
            "grant_assignments.grantee_kind",
        ),
        (
            "login_providers",
            7,
            r#"{"id":"p1","changed_at":null}"#,
            "login_providers.changed_at",
        ),
    ] {
        let error = normalize_upgraded_row(table, base, row).unwrap_err();
        assert!(
            error.contains(expected_column),
            "expected error naming {expected_column}, got: {error}"
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
    // ADR 0030: the API's issuance credential is refused while present, whatever its value,
    // before any other setting is read and without echoing it.
    use std::os::unix::ffi::OsStrExt;
    for value in [
        std::ffi::OsStr::new("postgres://openmettle_issuance:synthetic-secret@host/db"),
        std::ffi::OsStr::new(""),
        std::ffi::OsStr::from_bytes(b"synthetic-secret-\xff"),
    ] {
        let output = migrate_command("invalid://synthetic-secret", &[])
            .env("OPENMETTLE_API_ISSUANCE_DATABASE_URL", value)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(78), "{value:?}");
        assert_eq!(
            stderr(&output),
            "configuration error: OPENMETTLE_API_ISSUANCE_DATABASE_URL is refused outside the API\n"
        );
    }
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
    let before = snapshot_at(&mut api, &tables, 1).await;
    drop(api);

    let output = migrate_command(&db.url(OWNER), &[]).output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert_eq!(db.history().await, all_versions());

    let mut api = connect(&db.0, API).await;
    assert_eq!(snapshot_at(&mut api, &tables, 1).await, before);
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
            "role openmettle_fixture_capped reaches more than one of openmettle_api, openmettle_issuance, openmettle_worker and openmettle_gateway",
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
            // ADR 0030: issuance reads identities and scopes; its writes are column grants.
            (ISSUANCE, "users" | "user_identities" | "scopes") => privilege == "SELECT",
            _ => false,
        }
    };
    let mut admin = db.admin().await;
    for role in [API, ISSUANCE, WORKER] {
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

    // Actual denied operations for every application role.
    for role in [API, ISSUANCE, WORKER] {
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

#[path = "schema/issuance.rs"]
mod issuance;

#[path = "schema/authz_store.rs"]
mod authz_store;

#[path = "schema/authz_projects.rs"]
mod authz_projects;

#[path = "schema/authz_runs.rs"]
mod authz_runs;

#[path = "schema/authz_http.rs"]
mod authz_http;

#[path = "schema/run_admission.rs"]
mod run_admission;

#[path = "schema/worker_leases.rs"]
mod worker_leases;

// Fixtures of the mounted-API tests in `authz_http`: synthetic auth settings, the transport
// fixture's synthetic CA (its leaf certificates are not needed) and the independent contract
// consumer, of which these tests decode a subset.
#[path = "auth_config_support/mod.rs"]
mod auth_config_support;
#[allow(dead_code)]
#[path = "provider_http_support/ca.rs"]
mod ca;
#[allow(dead_code)]
#[path = "contract/consumer.rs"]
mod consumer;

#[path = "schema/branches.rs"]
mod branches;

#[path = "schema/approvals.rs"]
mod approvals;

#[path = "schema/gateway.rs"]
mod gateway;

#[path = "schema/quotas.rs"]
mod quotas;

#[path = "schema/capacity.rs"]
mod capacity;
