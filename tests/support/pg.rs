//! Shared disposable PostgreSQL 18 cluster, role and database harness for tests.
//! Tests using this module require `TEST_DATABASE_URL` pointing to an isolated, disposable
//! PostgreSQL 18 service with a superuser fixture account. Never point it at a shared or
//! workstation server.
use sqlx::{AssertSqlSafe, Connection, Executor, PgConnection, postgres::PgConnectOptions};
use std::{
    sync::atomic::{AtomicU32, Ordering},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) const OWNER: &str = "openmettle_owner";
pub(crate) const API: &str = "openmettle_api";
/// Session issuance (ADR 0030); required from migration 18.
pub(crate) const ISSUANCE: &str = "openmettle_issuance";
pub(crate) const WORKER: &str = "openmettle_worker";
/// Synthetic test-only role with a low connection limit, member of `openmettle_api`.
pub(crate) const CAPPED: &str = "openmettle_fixture_capped";
/// Synthetic test-only credential for disposable fixture roles; never a deployment value.
pub(crate) const PASSWORD: &str = "fixture-only-password";

/// Cluster-wide advisory key serializing one-time fixture role creation.
pub(crate) const ROLE_LOCK: i64 = 720202;
/// Cluster-wide advisory key serializing tests that change cluster-wide fixture roles: every
/// test database holds it shared; a test that alters role memberships or attributes holds it
/// exclusively.
pub(crate) const ROLE_STATE_LOCK: i64 = 720203;

static COUNTER: AtomicU32 = AtomicU32::new(0);

pub(crate) fn admin_options() -> PgConnectOptions {
    std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL required")
        .parse()
        .expect("valid TEST_DATABASE_URL")
}

pub(crate) fn role_options(database: &str, role: &str) -> PgConnectOptions {
    admin_options()
        .database(database)
        .username(role)
        .password(PASSWORD)
}

#[allow(dead_code)]
pub(crate) fn role_url(database: &str, role: &str) -> String {
    let admin = admin_options();
    format!(
        "postgres://{role}:{PASSWORD}@{}:{}/{database}?sslmode=disable",
        admin.get_host(),
        admin.get_port()
    )
}

pub(crate) async fn admin(database: Option<&str>) -> PgConnection {
    let mut options = admin_options();
    if let Some(database) = database {
        options = options.database(database);
    }
    PgConnection::connect_with(&options).await.unwrap()
}

#[allow(dead_code)]
pub(crate) async fn connect(database: &str, role: &str) -> PgConnection {
    PgConnection::connect_with(&role_options(database, role))
        .await
        .unwrap()
}

async fn ensure_role(admin: &mut PgConnection, role: &str, limit: i32) {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = $1)")
            .bind(role)
            .fetch_one(&mut *admin)
            .await
            .unwrap();
    if !exists {
        admin
            .execute(AssertSqlSafe(format!(
                "CREATE ROLE {role} LOGIN PASSWORD '{PASSWORD}' CONNECTION LIMIT {limit}"
            )))
            .await
            .unwrap();
    }
}

/// Creates the synthetic cluster roles once; serialized across concurrent tests.
pub(crate) async fn ensure_roles(admin: &mut PgConnection, with_capped: bool) {
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(ROLE_LOCK)
        .execute(&mut *admin)
        .await
        .unwrap();
    for role in [OWNER, API, ISSUANCE, WORKER] {
        ensure_role(admin, role, -1).await;
    }
    if with_capped {
        ensure_role(admin, CAPPED, 2).await;
        admin
            .execute(AssertSqlSafe(format!("GRANT {API} TO {CAPPED}")))
            .await
            .unwrap();
    }
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(ROLE_LOCK)
        .execute(&mut *admin)
        .await
        .unwrap();
}

/// Runs statements as the fixture superuser on a blocking thread; used for cleanup in `Drop`.
pub(crate) fn admin_blocking(database: Option<String>, statements: Vec<String>) {
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

/// A fresh disposable database owned by `openmettle_owner`, dropped with `FORCE` when dropped.
/// Its administrative connection holds the cluster-wide `ROLE_STATE_LOCK` for its lifetime.
pub(crate) struct DisposableDb {
    name: String,
    _admin: PgConnection,
}

impl DisposableDb {
    pub(crate) async fn create(
        prefix: &str,
        exclusive_roles: bool,
        with_capped: bool,
        options: &str,
    ) -> Self {
        let mut admin = admin(None).await;
        ensure_roles(&mut admin, with_capped).await;
        let lock = if exclusive_roles {
            "SELECT pg_advisory_lock($1)"
        } else {
            "SELECT pg_advisory_lock_shared($1)"
        };
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
            "{prefix}_{}_{}_{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        admin
            .execute(AssertSqlSafe(format!(
                "CREATE DATABASE {name} OWNER {OWNER} {options}"
            )))
            .await
            .unwrap();
        Self {
            name,
            _admin: admin,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    #[allow(dead_code)]
    pub(crate) fn options(&self, role: &str) -> PgConnectOptions {
        role_options(&self.name, role)
    }

    #[allow(dead_code)]
    pub(crate) fn url(&self, role: &str) -> String {
        role_url(&self.name, role)
    }

    #[allow(dead_code)]
    pub(crate) async fn connect(&self, role: &str) -> PgConnection {
        connect(&self.name, role).await
    }
}

impl Drop for DisposableDb {
    fn drop(&mut self) {
        admin_blocking(
            None,
            vec![format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.name
            )],
        );
    }
}
