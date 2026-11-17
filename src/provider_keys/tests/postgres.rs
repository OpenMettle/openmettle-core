//! Managed login against the durable provider authority (ADR 0012). These tests need
//! TEST_DATABASE_URL for an isolated, disposable PostgreSQL 18 service with a superuser fixture
//! account, as in the schema suite. They create synthetic `openmettle_*` roles (test-only
//! password) and one database per test. Never point them at a shared or workstation server.
//! Providers are in-memory TLS fixtures; no real identity provider is contacted.
use super::*;
use crate::{
    login::{Callback, KeyRing, Started},
    migrate,
};
use sqlx::{AssertSqlSafe, Connection, Executor, PgConnection, postgres::PgConnectOptions};

const OWNER: &str = "openmettle_owner";
const API: &str = "openmettle_api";
const WORKER: &str = "openmettle_worker";
/// Synthetic test-only credential shared with the schema suite; never a deployment value.
const PASSWORD: &str = "fixture-only-password";
// The schema suite's role-creation and role-state advisory keys.
const ROLE_LOCK: i64 = 720202;
const ROLE_STATE_LOCK: i64 = 720203;

// Documented operator protocol (ADR 0012): lock the stable provider row, append, confirm the
// new row is the latest for the provider, then commit (or roll back if it is not).
const PROTOCOL: &str = "BEGIN; SET LOCAL lock_timeout = '2s'; \
    SET LOCAL statement_timeout = '5s'; SET LOCAL synchronous_commit = on";
const LOCK: &str = "SELECT id FROM openmettle.login_providers WHERE id = $1::uuid FOR UPDATE";
const APPEND: &str = "INSERT INTO openmettle.login_provider_revisions (provider_id, revision) \
    VALUES ($1::uuid, $2) RETURNING epoch";
const CURRENT: &str = "SELECT NOT EXISTS (SELECT FROM openmettle.login_provider_revisions \
    WHERE provider_id = $1::uuid AND epoch > $2)";
async fn is_current(owner: &mut PgConnection, epoch: i64) -> bool {
    sqlx::query_scalar(CURRENT)
        .bind(signing::ID)
        .bind(epoch)
        .fetch_one(owner)
        .await
        .unwrap()
}

fn admin_options() -> PgConnectOptions {
    std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL required")
        .parse()
        .expect("valid TEST_DATABASE_URL")
}

struct Db {
    name: String,
    // Holds the shared role-state lock for the database's lifetime.
    _admin: PgConnection,
}
impl Db {
    async fn new() -> Self {
        let mut admin = PgConnection::connect_with(&admin_options()).await.unwrap();
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(ROLE_LOCK)
            .execute(&mut admin)
            .await
            .unwrap();
        for role in [OWNER, API, WORKER] {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = $1)")
                    .bind(role)
                    .fetch_one(&mut admin)
                    .await
                    .unwrap();
            if !exists {
                admin
                    .execute(AssertSqlSafe(format!(
                        "CREATE ROLE {role} LOGIN PASSWORD '{PASSWORD}'"
                    )))
                    .await
                    .unwrap();
            }
        }
        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(ROLE_LOCK)
            .execute(&mut admin)
            .await
            .unwrap();
        sqlx::query("SELECT pg_advisory_lock_shared($1)")
            .bind(ROLE_STATE_LOCK)
            .execute(&mut admin)
            .await
            .unwrap();
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "om_authority_{}_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        );
        admin
            .execute(AssertSqlSafe(format!(
                "CREATE DATABASE {name} OWNER {OWNER}"
            )))
            .await
            .unwrap();
        let db = Self {
            name,
            _admin: admin,
        };
        migrate::apply(
            &migrate::Settings {
                database: db.options(OWNER),
                connect_timeout: Duration::from_secs(5),
                lock_timeout: Duration::from_secs(10),
                statement_timeout: Duration::from_secs(30),
            },
            migrate::MIGRATIONS,
        )
        .await
        .unwrap();
        db
    }
    fn options(&self, role: &str) -> PgConnectOptions {
        admin_options()
            .database(&self.name)
            .username(role)
            .password(PASSWORD)
    }
    async fn connect(&self, role: &str) -> PgConnection {
        PgConnection::connect_with(&self.options(role))
            .await
            .unwrap()
    }
}
impl Drop for Db {
    fn drop(&mut self) {
        let statement = format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name);
        let _ = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    if let Ok(mut admin) = PgConnection::connect_with(&admin_options()).await {
                        let _ = admin.execute(AssertSqlSafe(statement)).await;
                    }
                })
        })
        .join();
    }
}

/// Registers the provider identity and its first revision in one protocol transaction.
async fn add_provider(owner: &mut PgConnection, issuer: &str, client: &str, revision: &str) {
    owner.execute(PROTOCOL).await.unwrap();
    sqlx::query(
        "INSERT INTO openmettle.login_providers (id, issuer, client_id) VALUES ($1::uuid, $2, $3)",
    )
    .bind(signing::ID)
    .bind(issuer)
    .bind(client)
    .execute(&mut *owner)
    .await
    .unwrap();
    sqlx::query(APPEND)
        .bind(signing::ID)
        .bind(revision)
        .execute(&mut *owner)
        .await
        .unwrap();
    owner.execute("COMMIT").await.unwrap();
}
/// Opens a protocol transaction holding the provider lock with an appended, uncommitted row.
async fn open_write(owner: &mut PgConnection, revision: Option<&str>) -> i64 {
    owner.execute(PROTOCOL).await.unwrap();
    let locked = sqlx::query(LOCK)
        .bind(signing::ID)
        .fetch_optional(&mut *owner)
        .await
        .unwrap();
    assert!(
        locked.is_some(),
        "protocol requires the stable provider row"
    );
    let epoch = sqlx::query_scalar(APPEND)
        .bind(signing::ID)
        .bind(revision)
        .fetch_one(&mut *owner)
        .await
        .unwrap();
    assert!(
        is_current(owner, epoch).await,
        "protocol rolls back a non-latest epoch"
    );
    epoch
}
async fn write(owner: &mut PgConnection, revision: Option<&str>) -> i64 {
    let epoch = open_write(owner, revision).await;
    owner.execute("COMMIT").await.unwrap();
    epoch
}

fn keys() -> KeyRing {
    KeyRing::new(vec![("active".into(), [7; 32])]).unwrap()
}
fn locator(started: &Started) -> String {
    started.state.expose().split_once('.').unwrap().0.to_owned()
}
fn callback(started: &Started) -> Callback<'_> {
    Callback {
        state: started.state.expose(),
        caller_binding: started.caller_binding.expose(),
        issuer: signing::ISSUER,
        callback: signing::CALLBACK,
        code: "synthetic-code",
    }
}

struct Flow {
    h: Harness,
    db: Db,
    api: PgConnection,
    owner: PgConnection,
}
impl Flow {
    async fn new() -> Self {
        Self::with(Harness::new().await).await
    }
    async fn with(h: Harness) -> Self {
        let db = Db::new().await;
        let api = db.connect(API).await;
        let mut owner = db.connect(OWNER).await;
        add_provider(&mut owner, signing::ISSUER, signing::CLIENT, "v1").await;
        Self { h, db, api, owner }
    }
    async fn begin(&mut self, p: &ManagedProvider) -> Started {
        p.begin(&mut self.api, &keys(), Duration::from_secs(300))
            .await
            .unwrap()
    }
    /// The fixture provider issues an ID token for this login's nonce and checks its challenge.
    fn arm(&self, started: &Started) {
        let url = openidconnect::url::Url::parse(started.authorization_url.expose()).unwrap();
        let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
        let mut s = self.h.script.lock().unwrap();
        s.challenge = Some(params["code_challenge"].clone());
        s.token = signing::signed(
            &params["nonce"],
            signing::ISSUER,
            signing::CLIENT,
            1799999990,
        );
    }
    async fn consume(
        &mut self,
        p: &ManagedProvider,
        started: &Started,
    ) -> Result<login::ExchangePermit, login::Error> {
        p.consume(&mut self.api, &keys(), callback(started)).await
    }
    async fn exchanged(&mut self, p: &ManagedProvider) -> (Started, ExchangedIdentity) {
        let started = self.begin(p).await;
        self.arm(&started);
        let permit = self.consume(p, &started).await.unwrap();
        let exchanged = permit
            .exchange_with_keys(p, &auth::Policy::default())
            .await
            .unwrap();
        (started, exchanged)
    }
    async fn consumed(&mut self, started: &Started) -> bool {
        sqlx::query_scalar("SELECT consumed FROM openmettle.login_transactions WHERE id = $1")
            .bind(locator(started))
            .fetch_one(&mut self.api)
            .await
            .unwrap()
    }
    async fn rows(&mut self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM openmettle.login_transactions")
            .fetch_one(&mut self.api)
            .await
            .unwrap()
    }
    /// A new process: new manager and registration history, identical configuration.
    fn restart(&self) -> (ProviderManager, ManagedProvider) {
        let manager = ProviderManager::new(policy());
        let clock = self.h.manager.inner.clock.lock().unwrap().clone();
        *manager.inner.clock.lock().unwrap() = clock;
        // A different registration history must not change the persisted binding.
        let p = manager
            .register(Harness::config(&self.h.server, &self.h.ca, "v2"))
            .unwrap();
        manager.retire(&p).unwrap();
        let p = manager
            .register(Harness::config(&self.h.server, &self.h.ca, "v1"))
            .unwrap();
        assert!(p.generation > 1);
        (manager, p)
    }
    fn pause(&self, point: &'static str) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let reached = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        *self.h.manager.inner.pause.lock().unwrap() =
            Some((point, reached.clone(), resume.clone()));
        (reached, resume)
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 (TEST_DATABASE_URL) required"]
async fn managed_login_round_trip_survives_restart_and_identical_reload() {
    let mut f = Flow::new().await;
    let p = f.h.provider.clone();
    let (started, exchanged) = f.exchanged(&p).await;
    assert!(f.consumed(&started).await);
    let identity = p.release(&mut f.api, exchanged).await.unwrap();
    assert_eq!(identity.subject(), "synthetic-subject");
    assert_eq!(identity.provider_config_id(), signing::ID);
    {
        let heads = f.h.server.heads.lock().unwrap();
        assert_eq!(heads.iter().filter(|s| s.starts_with("POST")).count(), 1);
    }
    // Begin here; finish in a "restarted" process with a different registration history.
    let started = f.begin(&p).await;
    let (_manager, restarted) = f.restart();
    // An identical reload in the original process is a no-op and also keeps the login valid.
    let same =
        f.h.manager
            .register(Harness::config(&f.h.server, &f.h.ca, "v1"))
            .unwrap();
    assert_eq!(same.generation, p.generation);
    f.arm(&started);
    let permit = f.consume(&restarted, &started).await.unwrap();
    let exchanged = permit
        .exchange_with_keys(&restarted, &auth::Policy::default())
        .await
        .unwrap();
    // Sealed results are bound to the releasing process handle.
    let foreign = f.exchanged(&p).await.1;
    assert_eq!(
        restarted.release(&mut f.api, foreign).await.unwrap_err(),
        login::Error::Rejected
    );
    let identity = restarted.release(&mut f.api, exchanged).await.unwrap();
    assert_eq!(identity.subject(), "synthetic-subject");
    // A consumed transaction never yields a second permit.
    assert_eq!(
        f.consume(&p, &started).await.unwrap_err(),
        login::Error::Rejected
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 (TEST_DATABASE_URL) required"]
async fn begin_requires_committed_matching_authority() {
    let h = Harness::new().await;
    let db = Db::new().await;
    let mut api = db.connect(API).await;
    let mut owner = db.connect(OWNER).await;
    let p = h.provider.clone();
    let refused = async |api: &mut PgConnection, why: &str| {
        assert_eq!(
            p.begin(api, &keys(), Duration::from_secs(60))
                .await
                .unwrap_err(),
            login::Error::Rejected,
            "{why}"
        );
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM openmettle.login_transactions")
            .fetch_one(&mut *api)
            .await
            .unwrap();
        assert_eq!(rows, 0, "{why}");
    };
    refused(&mut api, "no provider row").await;
    owner.execute(PROTOCOL).await.unwrap();
    sqlx::query("INSERT INTO openmettle.login_providers (id, issuer, client_id) VALUES ($1::uuid, 'https://other.example.test', $2)")
        .bind(signing::ID).bind(signing::CLIENT).execute(&mut owner).await.unwrap();
    owner.execute("COMMIT").await.unwrap();
    refused(&mut api, "no revision row").await;
    write(&mut owner, Some("v1")).await;
    refused(&mut api, "issuer differs").await;
    // Direct identity edits are outside the protocol; used here only to isolate each check.
    sqlx::query("UPDATE openmettle.login_providers SET issuer = $1, client_id = 'other-client'")
        .bind(signing::ISSUER)
        .execute(&mut owner)
        .await
        .unwrap();
    refused(&mut api, "client differs").await;
    sqlx::query("UPDATE openmettle.login_providers SET client_id = $1")
        .bind(signing::CLIENT)
        .execute(&mut owner)
        .await
        .unwrap();
    write(&mut owner, None).await;
    refused(&mut api, "retired").await;
    write(&mut owner, Some("v2")).await;
    refused(&mut api, "revision differs").await;
    // An uncommitted reactivation is invisible; a rolled-back one never becomes current.
    open_write(&mut owner, Some("v1")).await;
    refused(&mut api, "uncommitted").await;
    owner.execute("ROLLBACK").await.unwrap();
    refused(&mut api, "rolled back").await;
    write(&mut owner, Some("v1")).await;
    p.begin(&mut api, &keys(), Duration::from_secs(60))
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 (TEST_DATABASE_URL) required"]
async fn epoch_changes_and_simulated_restore_deny_pending_logins() {
    let mut f = Flow::new().await;
    let p = f.h.provider.clone();
    // Same revision appended again: a new epoch invalidates the pending login everywhere.
    let pending = f.begin(&p).await;
    write(&mut f.owner, Some("v1")).await;
    f.arm(&pending);
    assert_eq!(
        f.consume(&p, &pending).await.unwrap_err(),
        login::Error::Rejected
    );
    let (_manager, restarted) = f.restart();
    assert_eq!(
        f.consume(&restarted, &pending).await.unwrap_err(),
        login::Error::Rejected
    );
    assert!(!f.consumed(&pending).await, "rejection must not consume");
    // Retire then restore identical configuration: removed logins never revive.
    let pending = f.begin(&p).await;
    write(&mut f.owner, None).await;
    assert_eq!(
        f.consume(&p, &pending).await.unwrap_err(),
        login::Error::Rejected
    );
    write(&mut f.owner, Some("v1")).await;
    f.arm(&pending);
    assert_eq!(
        f.consume(&restarted, &pending).await.unwrap_err(),
        login::Error::Rejected
    );
    assert!(!f.consumed(&pending).await);
    // Simulated restore drill, not backup qualification: the restored database holds a pending
    // login; before reopening, the operator appends the current revision for every provider and
    // rotates the ADR 0009 active key. The old key is kept so only the epoch causes denial.
    let restored = f.begin(&p).await;
    write(&mut f.owner, Some("v1")).await;
    let rotated = KeyRing::new(vec![
        ("rotated".into(), [8; 32]),
        ("active".into(), [7; 32]),
    ])
    .unwrap();
    f.arm(&restored);
    assert_eq!(
        restarted
            .consume(&mut f.api, &rotated, callback(&restored))
            .await
            .unwrap_err(),
        login::Error::Rejected
    );
    assert!(!f.consumed(&restored).await);
    // New logins after reopening work with the rotated key.
    let fresh = restarted
        .begin(&mut f.api, &rotated, Duration::from_secs(60))
        .await
        .unwrap();
    f.arm(&fresh);
    let permit = restarted
        .consume(&mut f.api, &rotated, callback(&fresh))
        .await
        .unwrap();
    let exchanged = permit
        .exchange_with_keys(&restarted, &auth::Policy::default())
        .await
        .unwrap();
    restarted.release(&mut f.api, exchanged).await.unwrap();
    assert_eq!(f.rows().await, 4);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 (TEST_DATABASE_URL) required"]
async fn release_linearizes_at_the_authority_read_snapshot() {
    let mut f = Flow::new().await;
    let p = f.h.provider.clone();
    // 1. Retirement committed before the release snapshot refuses.
    let (_, exchanged) = f.exchanged(&p).await;
    let (reached, resume) = f.pause("before-authority");
    let mut owner = f.db.connect(OWNER).await;
    let control = async {
        reached.notified().await;
        write(&mut owner, None).await;
        resume.notify_one();
    };
    let (result, ()) = tokio::join!(p.release(&mut f.api, exchanged), control);
    assert_eq!(result.unwrap_err(), login::Error::Rejected);
    write(&mut f.owner, Some("v1")).await;
    // 2. A retirement committed after the snapshot, while release has not yet returned, is
    // ordered after this release. This is the documented boundary, not a stronger guarantee.
    let (_, exchanged) = f.exchanged(&p).await;
    let (reached, resume) = f.pause("after-authority");
    let control = async {
        reached.notified().await;
        write(&mut owner, None).await;
        resume.notify_one();
    };
    let (result, ()) = tokio::join!(p.release(&mut f.api, exchanged), control);
    assert_eq!(result.unwrap().subject(), "synthetic-subject");
    // The next authority read observes it.
    assert_eq!(
        p.begin(&mut f.api, &keys(), Duration::from_secs(60))
            .await
            .unwrap_err(),
        login::Error::Rejected
    );
    write(&mut f.owner, Some("v1")).await;
    *f.h.manager.inner.pause.lock().unwrap() = None;
    // 3. An uncommitted writer neither blocks nor affects a plain read; its commit refuses the
    // next release, and a rolled-back writer leaves authority unchanged.
    let (_, first) = f.exchanged(&p).await;
    let (_, second) = f.exchanged(&p).await;
    let (_, third) = f.exchanged(&p).await;
    open_write(&mut owner, None).await;
    p.release(&mut f.api, first).await.unwrap();
    owner.execute("ROLLBACK").await.unwrap();
    p.release(&mut f.api, second).await.unwrap();
    open_write(&mut owner, None).await;
    owner.execute("COMMIT").await.unwrap();
    assert_eq!(
        p.release(&mut f.api, third).await.unwrap_err(),
        login::Error::Rejected
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 (TEST_DATABASE_URL) required"]
async fn in_flight_post_cannot_release_after_retirement() {
    let mut f = Flow::new().await;
    let p = f.h.provider.clone();
    let started = f.begin(&p).await;
    f.arm(&started);
    let permit = f.consume(&p, &started).await.unwrap();
    f.h.script.lock().unwrap().mode = "gate-post";
    let gate = f.h.script.lock().unwrap().gate.clone();
    let policy = auth::Policy::default();
    let mut owner = f.db.connect(OWNER).await;
    let control = async {
        f.h.entered(3).await;
        // The POST is already dispatched; durable retirement commits while it is in flight.
        write(&mut owner, None).await;
        gate.notify_one();
    };
    let (exchanged, ()) = tokio::join!(permit.exchange_with_keys(&p, &policy), control);
    let exchanged = exchanged.unwrap();
    f.h.script.lock().unwrap().mode = "ok";
    assert_eq!(
        p.release(&mut f.api, exchanged).await.unwrap_err(),
        login::Error::Rejected
    );
    assert_eq!(f.h.count(), 3);
    assert!(f.consumed(&started).await);
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 (TEST_DATABASE_URL) required"]
async fn release_owns_a_bounded_root_read_and_rechecks_time() {
    let mut p = policy();
    p.deadline = Duration::from_millis(1500);
    let mut f = Flow::with(Harness::with_policy(p).await).await;
    f.h.script.lock().unwrap().cache = "max-age=1000".into();
    f.h.script.lock().unwrap().metadata_cache = "max-age=1000".into();
    let provider = f.h.provider.clone();
    // A caller's open transaction/snapshot is never joined.
    let (_, exchanged) = f.exchanged(&provider).await;
    // Use SQLx's transaction API so its depth guard can observe the caller's transaction.
    // Manual transaction-control SQL is unsupported (ADR 0004).
    let mut outer = Connection::begin(&mut f.api).await.unwrap();
    assert!(outer.is_in_transaction());
    assert_eq!(
        provider.release(&mut outer, exchanged).await.unwrap_err(),
        login::Error::Rejected
    );
    assert!(outer.is_in_transaction());
    outer.rollback().await.unwrap();
    // The original exchange deadline survives into release.
    let (_, exchanged) = f.exchanged(&provider).await;
    tokio::time::sleep(Duration::from_millis(1600)).await;
    assert_eq!(
        provider.release(&mut f.api, exchanged).await.unwrap_err(),
        login::Error::Exchange
    );
    // A timeout may cancel the read mid-protocol. As for every ADR 0009 helper, the caller
    // discards a connection whose cleanup is uncertain and uses a fresh one.
    f.api = f.db.connect(API).await;
    let (_, exchanged) = f.exchanged(&provider).await;
    provider.release(&mut f.api, exchanged).await.unwrap();
    // Token time is rechecked after the authority read: expiry while waiting refuses.
    let (_, exchanged) = f.exchanged(&provider).await;
    let (reached, resume) = f.pause("after-authority");
    let control = async {
        reached.notified().await;
        f.h.advance(301);
        resume.notify_one();
    };
    let (result, ()) = tokio::join!(provider.release(&mut f.api, exchanged), control);
    assert_eq!(result.unwrap_err(), login::Error::Verification);
    assert!(!f.api.is_in_transaction());
}

#[tokio::test]
#[ignore = "isolated PostgreSQL 18 (TEST_DATABASE_URL) required"]
async fn operator_writers_serialize_in_commit_order() {
    let h = Harness::new().await;
    let db = Db::new().await;
    let mut api = db.connect(API).await;
    let mut admin = PgConnection::connect_with(&admin_options().database(&db.name))
        .await
        .unwrap();
    let mut first = db.connect(OWNER).await;
    let mut second = db.connect(OWNER).await;
    add_provider(&mut first, signing::ISSUER, signing::CLIENT, "v1").await;
    for (held, waiting, active) in [(None, Some("v1"), true), (Some("v1"), None, false)] {
        let held_epoch = open_write(&mut first, held).await;
        let blocked = async {
            second.execute(PROTOCOL).await.unwrap();
            sqlx::query(LOCK)
                .bind(signing::ID)
                .fetch_one(&mut second)
                .await
                .unwrap();
            let epoch: i64 = sqlx::query_scalar(APPEND)
                .bind(signing::ID)
                .bind(waiting)
                .fetch_one(&mut second)
                .await
                .unwrap();
            assert!(is_current(&mut second, epoch).await);
            second.execute("COMMIT").await.unwrap();
            epoch
        };
        let control = async {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let waiting: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM pg_stat_activity
                     WHERE datname = current_database() AND wait_event_type = 'Lock'",
                )
                .fetch_one(&mut admin)
                .await
                .unwrap();
                if waiting == 1 {
                    break;
                }
                assert!(Instant::now() < deadline, "second writer never waited");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            first.execute("COMMIT").await.unwrap();
        };
        let (waiting_epoch, ()) = tokio::join!(blocked, control);
        // The waiter allocates only after the holder commits: epoch order is commit order.
        assert!(waiting_epoch > held_epoch);
        let result = h
            .provider
            .begin(&mut api, &keys(), Duration::from_secs(60))
            .await;
        assert_eq!(result.is_ok(), active);
    }
    // A bounded writer gives up instead of waiting indefinitely; nothing is appended.
    let before: i64 =
        sqlx::query_scalar("SELECT max(epoch) FROM openmettle.login_provider_revisions")
            .fetch_one(&mut admin)
            .await
            .unwrap();
    open_write(&mut first, Some("v1")).await;
    second.execute(PROTOCOL).await.unwrap();
    second
        .execute("SET LOCAL lock_timeout = '100ms'")
        .await
        .unwrap();
    let timed_out = sqlx::query(LOCK)
        .bind(signing::ID)
        .fetch_one(&mut second)
        .await;
    assert!(
        matches!(timed_out, Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("55P03"))
    );
    second.execute("ROLLBACK").await.unwrap();
    first.execute("ROLLBACK").await.unwrap();
    let after: i64 =
        sqlx::query_scalar("SELECT max(epoch) FROM openmettle.login_provider_revisions")
            .fetch_one(&mut admin)
            .await
            .unwrap();
    assert_eq!(after, before);
    // Explicit epochs are refused unless the owner deliberately overrides the identity.
    let explicit = sqlx::query("INSERT INTO openmettle.login_provider_revisions (epoch, provider_id, revision) VALUES (999999, $1::uuid, 'v1')")
        .bind(signing::ID)
        .execute(&mut first)
        .await;
    assert!(
        matches!(explicit, Err(sqlx::Error::Database(e)) if e.code().as_deref() == Some("428C9"))
    );
    // If a row ever lies ahead of the allocator (a deliberate owner override, or restored data
    // whose sequence state is behind), the protocol's current-row check refuses to commit a
    // non-latest append instead of silently leaving older authority current.
    sqlx::query("INSERT INTO openmettle.login_provider_revisions (epoch, provider_id, revision) OVERRIDING SYSTEM VALUE VALUES (1000000, $1::uuid, 'v1')")
        .bind(signing::ID)
        .execute(&mut first)
        .await
        .unwrap();
    first.execute(PROTOCOL).await.unwrap();
    sqlx::query(LOCK)
        .bind(signing::ID)
        .fetch_one(&mut first)
        .await
        .unwrap();
    let behind: i64 = sqlx::query_scalar(APPEND)
        .bind(signing::ID)
        .bind(None::<&str>)
        .fetch_one(&mut first)
        .await
        .unwrap();
    assert!(!is_current(&mut first, behind).await);
    first.execute("ROLLBACK").await.unwrap();
    h.provider
        .begin(&mut api, &keys(), Duration::from_secs(60))
        .await
        .unwrap();
    // Documented repair: advance the allocator past every row, then append normally.
    first
        .execute("SELECT setval('openmettle.login_provider_revisions_epoch_seq', (SELECT max(epoch) FROM openmettle.login_provider_revisions))")
        .await
        .unwrap();
    assert!(write(&mut first, None).await > 1000000);
    assert!(
        h.provider
            .begin(&mut api, &keys(), Duration::from_secs(60))
            .await
            .is_err()
    );
}

mod sessions;
