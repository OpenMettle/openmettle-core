//! Shared runtime, persistence and authenticated application routes. By default the API
//! serves only `/healthz` and `/readyz`. A version-2 `OPENMETTLE_API_AUTH_CONFIG` mounts
//! browser sign-in, optional native sign-in, and the authenticated `/v1` routes.
//! Artifact payloads require `OPENMETTLE_API_ARTIFACTS_DIR` (ADR 0031). Run snapshots
//! and replayable event streams require cursor keys in the auth document (ADR 0034).
pub mod artifact_fs;
pub mod auth;
pub mod auth_config;
pub mod authz;
pub mod browser_auth;
pub mod capabilities;
pub mod grants;
pub mod invitation;
pub mod login;
pub mod mcp;
pub mod membership;
pub mod migrate;
pub mod model_config;
pub mod multipart;
pub mod provider_http;
pub mod provider_keys;
pub mod quotas;
pub mod runs;
pub mod sessions;
pub mod storage;
pub mod telemetry;
pub mod v1;
pub mod worker;

use axum::{Router, extract::State, http::StatusCode, routing::get};
use browser_auth::{
    BrowserAuth, handoff::LoginHandoff, native::NativeAuth, router::router_with_sessions,
};
use sqlx::{
    ConnectOptions, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use telemetry::{Process, ProcessFailure, Signal};

#[derive(Clone, Copy)]
pub enum Role {
    Api,
    Worker,
}

/// Validated ADR 0033 settings. The library runner can accept a run policy with an executor.
#[derive(Clone, Copy, Debug)]
pub struct WorkerSettings {
    sweep: Duration,
    poll: Duration,
    policy: Option<RunPolicy>,
}

#[derive(Clone, Copy, Debug)]
struct RunPolicy {
    slots: usize,
    leases: authz::leases::LeaseSettings,
    limits: authz::runs::ClaimLimits,
}

const WORKER_KEYS: [&str; 7] = [
    "SWEEP_MS",
    "POLL_MS",
    "RUN_SLOTS",
    "LEASE_MS",
    "EXECUTION_TIMEOUT_MS",
    "EXECUTING_PER_ACTOR",
    "EXECUTING_PER_SCOPE",
];

impl WorkerSettings {
    /// Read unprefixed worker keys from the supplied configuration source.
    pub fn parse(
        db_timeout: Duration,
        get: impl Fn(&str) -> Result<Option<String>, &'static str>,
    ) -> Result<Self, &'static str> {
        let number = |key, min, max| -> Result<Option<u32>, &'static str> {
            get(key)?
                .map(|s| {
                    s.parse()
                        .ok()
                        .filter(|n| (min..=max).contains(n))
                        .ok_or(key)
                })
                .transpose()
        };
        let [sweep, poll, slots, lease, execution, actor, scope] = WORKER_KEYS;
        let millis = |n: u32| Duration::from_millis(n.into());
        let sweep = millis(number(sweep, 1000, 3_600_000)?.unwrap_or(60_000));
        let poll = millis(number(poll, 100, 60_000)?.unwrap_or(1000));
        let policy = match (
            number(slots, 1, 256)?,
            number(lease, 30_000, 600_000)?,
            number(execution, 60_000, 86_400_000)?,
            number(actor, 1, 1024)?,
            number(scope, 1, 1024)?,
        ) {
            (None, None, None, None, None) => None,
            (None, ..) => return Err("lease and claim settings require RUN_SLOTS"),
            (Some(slots), Some(lease), Some(execution), Some(actor), Some(scope)) => {
                let leases = authz::leases::LeaseSettings {
                    lease: millis(lease),
                    execution_timeout: millis(execution),
                };
                if leases.lease / 6 < db_timeout {
                    return Err("LEASE_MS must cover six DB_TIMEOUT_MS");
                }
                if leases.validate().is_err() {
                    return Err("EXECUTION_TIMEOUT_MS must cover two leases");
                }
                Some(RunPolicy {
                    slots: slots as usize,
                    leases,
                    limits: authz::runs::ClaimLimits {
                        executing_per_actor: actor,
                        executing_per_scope: scope,
                    },
                })
            }
            _ => return Err("RUN_SLOTS requires lease and claim settings"),
        };
        Ok(Self {
            sweep,
            poll,
            policy,
        })
    }
}

struct Config {
    worker: Option<WorkerSettings>,
    bind: SocketAddr,
    database: PgConnectOptions,
    connections: u32,
    database_timeout: Duration,
    shutdown_timeout: Duration,
    telemetry: telemetry::Settings,
    /// `OTLP_TRACES_ENDPOINT` and its companions (ADR 0026); `None` leaves export off.
    otlp: Option<telemetry::otlp::Settings>,
    /// `OPENMETTLE_API_AUTH_CONFIG`: the browser, and optionally native, sign-in settings
    /// document to mount (ADRs 0025 and 0029). Always `None` for the worker, which never
    /// reads the key.
    auth_config: Option<PathBuf>,
    /// `ISSUANCE_DATABASE_URL` and `ISSUANCE_DB_MAX_CONNECTIONS` (ADR 0030): the session
    /// issuance pool's connection and size. Set exactly when `auth_config` is.
    issuance: Option<(PgConnectOptions, u32)>,
    /// `ARTIFACTS_DIR` (ADR 0031): the artifact payload directory, validated with
    /// [`artifact_fs::Store::open`] before telemetry starts. `None` leaves artifact file I/O
    /// disabled.
    artifacts_dir: Option<PathBuf>,
}

/// ADR 0030: the API's issuance credential, mounted into the API container only.
pub(crate) const ISSUANCE_URL: &str = "OPENMETTLE_API_ISSUANCE_DATABASE_URL";

/// The worker and the migrator never read [`ISSUANCE_URL`] and refuse to start while it is
/// present, whatever its value, so a misplaced Secret is noticed instead of ignored.
pub(crate) fn refuse_issuance_url() -> Result<(), &'static str> {
    match std::env::var_os(ISSUANCE_URL) {
        Some(_) => Err("OPENMETTLE_API_ISSUANCE_DATABASE_URL is refused outside the API"),
        None => Ok(()),
    }
}

/// Reads `{prefix}_{key}` from the process environment, refusing non-UTF-8 values.
pub(crate) fn env_var(prefix: &str, key: &str) -> Result<Option<String>, &'static str> {
    match std::env::var(format!("{prefix}_{key}")) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err("configuration must be UTF-8"),
    }
}

/// Parses an optional positive integer in `1..=max` with fixed, value-free refusals.
pub(crate) fn bounded_positive<T>(
    raw: Option<String>,
    default: T,
    max: T,
) -> Result<T, &'static str>
where
    T: std::str::FromStr + PartialOrd + Default,
{
    let value = match raw {
        Some(value) => value.parse().map_err(|_| "invalid numeric configuration")?,
        None => default,
    };
    if value <= T::default() || value > max {
        return Err("configuration outside allowed range");
    }
    Ok(value)
}

/// A `postgres://` or `postgresql://` URL, parsed with statement logging off (ADR 0002).
/// The refusals name the key alone, never the value.
pub(crate) fn database_url(
    url: &str,
    scheme: &'static str,
    invalid: &'static str,
) -> Result<PgConnectOptions, &'static str> {
    if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) {
        return Err(scheme);
    }
    Ok(url
        .parse::<PgConnectOptions>()
        .map_err(|_| invalid)?
        .disable_statement_logging())
}

impl Config {
    fn load(role: Role) -> Result<Self, &'static str> {
        let prefix = match role {
            Role::Api => "OPENMETTLE_API",
            Role::Worker => {
                refuse_issuance_url()?;
                "OPENMETTLE_WORKER"
            }
        };
        let mut config = Self::parse(role, |key| env_var(prefix, key))?;
        match role {
            Role::Api => {
                if WORKER_KEYS.iter().any(|key| {
                    ["OPENMETTLE_WORKER", prefix]
                        .iter()
                        .any(|p| std::env::var_os(format!("{p}_{key}")).is_some())
                }) {
                    return Err("worker scheduling settings are refused on the API");
                }
            }
            Role::Worker => {
                let settings =
                    WorkerSettings::parse(config.database_timeout, |key| env_var(prefix, key))?;
                if settings.policy.is_some() {
                    return Err("RUN_SLOTS requires a worker executor");
                }
                config.worker = Some(settings);
            }
        }
        Ok(config)
    }

    fn parse(
        role: Role,
        get: impl Fn(&str) -> Result<Option<String>, &'static str>,
    ) -> Result<Self, &'static str> {
        let port = match role {
            Role::Api => 8080,
            Role::Worker => 8081,
        };
        let bind = get("BIND")?
            .unwrap_or_else(|| format!("127.0.0.1:{port}"))
            .parse()
            .map_err(|_| "invalid BIND")?;
        let url = get("DATABASE_URL")?.ok_or("DATABASE_URL is required")?;
        let database = database_url(&url, "invalid DATABASE_URL scheme", "invalid DATABASE_URL")?;
        let number = |key, default: u32, max| bounded_positive(get(key)?, default, max);
        let connections = number("DB_MAX_CONNECTIONS", 4, 64)?;
        let database_timeout = Duration::from_millis(number("DB_TIMEOUT_MS", 2000, 30000)?.into());
        let shutdown_timeout =
            Duration::from_millis(number("SHUTDOWN_TIMEOUT_MS", 5000, 60000)?.into());
        let telemetry = telemetry::Settings::parse(&get)?;
        let otlp = telemetry::otlp::Settings::parse(&get)?;
        // Both processes; a set value is never treated as unset.
        let artifacts_dir = get("ARTIFACTS_DIR")?.map(PathBuf::from);
        if artifacts_dir
            .as_deref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err("invalid ARTIFACTS_DIR");
        }
        // Read last, and by the API alone. Unset serves the operational routes only. A set
        // value is never treated as unset: empty or relative is refused, as the loader would.
        let auth_config = match role {
            Role::Api => get("AUTH_CONFIG")?.map(PathBuf::from),
            Role::Worker => None,
        };
        if auth_config
            .as_deref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err("invalid AUTH_CONFIG");
        }
        // ADR 0030: the API's issuance pool exists exactly when sign-in is mounted, under a
        // different resolved user than the primary pool, including users filled from `PG*`
        // defaults. Read after `AUTH_CONFIG`, and by the API alone.
        let issuance = match role {
            Role::Worker => None,
            Role::Api => match (get("ISSUANCE_DATABASE_URL")?, &auth_config) {
                (Some(_), None) => return Err("ISSUANCE_DATABASE_URL requires AUTH_CONFIG"),
                (None, Some(_)) => {
                    return Err("ISSUANCE_DATABASE_URL is required with AUTH_CONFIG");
                }
                (None, None) => match get("ISSUANCE_DB_MAX_CONNECTIONS")? {
                    Some(_) => {
                        return Err("ISSUANCE_DB_MAX_CONNECTIONS requires ISSUANCE_DATABASE_URL");
                    }
                    None => None,
                },
                (Some(url), Some(_)) => {
                    let issuance = database_url(
                        &url,
                        "invalid ISSUANCE_DATABASE_URL scheme",
                        "invalid ISSUANCE_DATABASE_URL",
                    )?;
                    if issuance.get_username() == database.get_username() {
                        return Err("ISSUANCE_DATABASE_URL must use a different user");
                    }
                    Some((issuance, number("ISSUANCE_DB_MAX_CONNECTIONS", 2, 64)?))
                }
            },
        };
        Ok(Self {
            worker: None,
            bind,
            database,
            connections,
            database_timeout,
            shutdown_timeout,
            telemetry,
            otlp,
            auth_config,
            issuance,
            artifacts_dir,
        })
    }
}

/// Served operational routes; `telemetry::observe` adds request IDs when serving.
fn routes(health: Health) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/readyz", get(ready))
        .with_state(health)
}

/// Every route the process serves (ADR 0025): the operational routes, and for an API given
/// `AUTH_CONFIG` the browser sign-in routes of that version-2 document, over the same primary
/// pool (ADR 0016) and a lazy issuance pool for session issuance alone (ADR 0030). A `native` profile in it adds the five native routes over the same
/// service, so one provider manager and one pool serve both (ADR 0029). The authenticated
/// `/v1` routes are mounted beside them and accept a session from either channel (ADR 0027
/// PR4b). Loading reads local files only; no provider, DNS name or database is contacted, and
/// the lazy pools stay unconnected. Readiness is unchanged and checks the primary pool only:
/// an unusable issuance pool refuses sign-in completion alone.
///
/// The settings checks refused `/healthz`, `/readyz` and every `/v1` path as browser and
/// native paths, and every browser path as a native path, and the constructors repeat them,
/// so no merge can shadow a route or panic. The issuance pool, when built, is returned beside
/// the router so `serve` can close it within the drain deadline. `artifacts` is the store
/// `run` opened from `ARTIFACTS_DIR`; without it the `/v1` payload operations answer
/// `503 provisioning` (ADR 0031).
fn app(
    config: &Config,
    pool: &PgPool,
    artifacts: Option<artifact_fs::Store>,
) -> Result<(Router, Option<PgPool>), auth_config::Error> {
    let operational = routes(Health {
        pool: pool.clone(),
        timeout: config.database_timeout,
    });
    // `Config::parse` sets both or neither.
    let (Some(path), Some((issuance, connections))) = (&config.auth_config, &config.issuance)
    else {
        return Ok((operational, None));
    };
    let (mut settings, profile) = auth_config::load_browser(path)?;
    let catalog = settings.catalog.take();
    let admission_limits = settings.admission_limits;
    let cursor_keys = settings.cursor_keys.take();
    let native = settings.native().cloned();
    let issuance = lazy_pool(issuance, *connections, config.database_timeout);
    let service = Arc::new(BrowserAuth::new(settings, pool.clone(), issuance.clone()));
    let handoff = LoginHandoff::new(service.clone(), profile.handoff())
        .map_err(auth_config::Error::BrowserHandoff)?;
    let sign_in = router_with_sessions(handoff, profile.router(), profile.sessions())
        .map_err(auth_config::Error::BrowserRouter)?;
    let mut app = operational.merge(sign_in);
    let mut bearer = None;
    if let Some(native) = native {
        let auth = NativeAuth::checked(service.clone(), native.settings(), native.rate())
            .map_err(auth_config::Error::Native)?;
        let auth = Arc::new(auth);
        // The rate was accepted just above; a refusal here is that check's category.
        let routes = auth
            .router_shared(native.rate())
            .map_err(|_| auth_config::Error::Native(browser_auth::native::SettingsError::Rate))?;
        app = app.merge(routes);
        bearer = Some(auth);
    }
    let origin = profile.handoff().origin;
    let mut v1 = v1::router(service, bearer, origin, pool.clone(), artifacts);
    if let Some(catalog) = catalog {
        v1 = v1.layer(axum::Extension(Arc::new(catalog)));
    }
    if let Some(limits) = admission_limits {
        v1 = v1.layer(axum::Extension(limits));
    }
    if let Some(keys) = cursor_keys {
        v1 = v1.layer(axum::Extension(Arc::new(keys)));
    }
    Ok((app.merge(v1), Some(issuance)))
}

#[derive(Clone)]
struct Health {
    pool: PgPool,
    timeout: Duration,
}

async fn ready(State(state): State<Health>) -> (StatusCode, &'static str) {
    let started = std::time::Instant::now();
    let (status, body, outcome) = match tokio::time::timeout(
        state.timeout,
        sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&state.pool),
    )
    .await
    {
        Ok(Ok(1)) => (
            StatusCode::OK,
            "ready\n",
            telemetry::metrics::ReadinessOutcome::Ok,
        ),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "not ready\n",
            telemetry::metrics::ReadinessOutcome::Timeout,
        ),
        Ok(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "not ready\n",
            telemetry::metrics::ReadinessOutcome::Error,
        ),
    };
    telemetry::metrics::global().record_db_readiness(outcome, started.elapsed());
    (status, body)
}

/// Runs a serving process on a two-worker Tokio runtime and returns its exit code. The
/// runtime is then shut down without waiting for blocking tasks: an abandoned operating-system
/// DNS lookup (ADRs 0010, 0026) cannot be cancelled and must not hold the exit after `run`
/// has finished within `SHUTDOWN_TIMEOUT_MS`.
pub fn run_blocking(role: Role) -> u8 {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("runtime error: async runtime could not start");
            return 1;
        }
    };
    let code = runtime.block_on(run(role));
    runtime.shutdown_background();
    code
}

pub async fn run(role: Role) -> u8 {
    let process = match role {
        Role::Api => Process::Api,
        Role::Worker => Process::Worker,
    };
    // Configuration errors precede telemetry, whose own settings may be the invalid ones:
    // they stay one fixed stderr line that names a key or category, never a value.
    let config = match Config::load(role) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("configuration error: {message}");
            return 78;
        }
    };
    // The OTLP CA file is read here, so a refusal is the same kind of fixed line (ADR 0026).
    let export = match config.otlp.as_ref().map(telemetry::otlp::Destination::load) {
        None => None,
        Some(Ok(destination)) => Some(destination),
        Some(Err(message)) => {
            eprintln!("configuration error: {message}");
            return 78;
        }
    };
    // The artifacts directory must exist as a real directory with usable subdirectories. It
    // is opened once; the API's `/v1` routes use this store.
    let artifacts = match config
        .artifacts_dir
        .as_deref()
        .map(artifact_fs::Store::open)
    {
        None => None,
        Some(Ok(store)) => Some(store),
        Some(Err(_)) => {
            eprintln!("configuration error: invalid ARTIFACTS_DIR");
            return 78;
        }
    };
    // The same holds for the browser sign-in settings: refused before telemetry is installed
    // or the listener opens, with the offline check's fixed category line (ADRs 0015, 0025).
    let pool = pool(&config);
    if let Some(store) = &artifacts {
        if matches!(role, Role::Worker) && store.probe_writable().is_err() {
            eprintln!("configuration error: invalid ARTIFACTS_DIR");
            return 78;
        }
        store.attach(&pool);
        // Liveness is available during DB outages. Each operation rechecks the pin before use.
        if let Ok(Err(artifact_fs::Error::Io | artifact_fs::Error::Missing)) = tokio::time::timeout(
            config.database_timeout,
            store.verify_startup(&pool, matches!(role, Role::Api)),
        )
        .await
        {
            eprintln!("configuration error: invalid ARTIFACTS_DIR");
            return 78;
        }
    }
    let (app, issuance) = match app(&config, &pool, artifacts.clone()) {
        Ok(built) => built,
        Err(error) => {
            eprintln!("auth configuration error: {error}");
            return 78;
        }
    };
    let telemetry = match telemetry::install(config.telemetry, process, export) {
        Ok(telemetry) => telemetry,
        Err(unavailable) => {
            eprintln!("runtime error: {}", unavailable.message());
            return 1;
        }
    };
    let (drain, flush) = shutdown_budget(config.shutdown_timeout);
    let code = match serve(
        config.bind,
        app,
        pool,
        issuance,
        process,
        drain,
        config.worker.map(|settings| (settings, artifacts)),
    )
    .await
    {
        Ok(()) => {
            telemetry::process_stopped(process);
            0
        }
        Err(failure) => {
            telemetry::process_failed(process, failure);
            1
        }
    };
    // Bounded: a stalled stderr or collector loses the final lines or spans, not the exit.
    telemetry.stop(flush).await;
    code
}

/// Splits `SHUTDOWN_TIMEOUT_MS` so the whole stop fits it: the final telemetry flush gets a
/// tenth, at most `telemetry::FLUSH_LIMIT`, and draining gets the rest. The flush slice also
/// covers stopping a configured OTLP exporter.
fn shutdown_budget(timeout: Duration) -> (Duration, Duration) {
    let flush = (timeout / 10).min(telemetry::FLUSH_LIMIT);
    (timeout - flush, flush)
}

fn pool(config: &Config) -> PgPool {
    lazy_pool(
        &config.database,
        config.connections,
        config.database_timeout,
    )
}

/// Connects on first use; acquisition waits at most `DB_TIMEOUT_MS`.
fn lazy_pool(options: &PgConnectOptions, connections: u32, timeout: Duration) -> PgPool {
    PgPoolOptions::new()
        .max_connections(connections)
        .acquire_timeout(timeout)
        .connect_lazy_with(options.clone())
}

async fn serve(
    bind: SocketAddr,
    app: Router,
    pool: PgPool,
    issuance: Option<PgPool>,
    process: Process,
    drain: Duration,
    worker: Option<(WorkerSettings, Option<artifact_fs::Store>)>,
) -> Result<(), ProcessFailure> {
    // Install signal handlers before opening the listener.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| ProcessFailure::SignalRegistration)?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| ProcessFailure::SignalRegistration)?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|_| ProcessFailure::Bind)?;
    // After every route is added, so the sign-in routes are observed like the probes.
    let (stream_stop, stopping) = tokio::sync::watch::channel(false);
    let app = telemetry::observe(app.layer(axum::Extension(stopping)));
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = axum::serve(listener, app).with_graceful_shutdown(async {
        let _ = stop_rx.await;
    });
    let server = std::future::IntoFuture::into_future(server);
    tokio::pin!(server);
    telemetry::process_started(process);
    // Dropping maintenance at the signal stops polling and rolls back in-flight transactions.
    let http_budget = if worker.is_some() {
        drain - drain / 2
    } else {
        drain
    };
    let signal = tokio::select! {
        _ = async {
            if let Some((settings, store)) = worker {
                worker::maintenance(&pool, store.as_ref(), settings.sweep).await;
            }
            std::future::pending::<()>().await
        } => unreachable!(),
        result = &mut server => return result.map_err(|_| ProcessFailure::Server),
        _ = terminate.recv() => Signal::Terminate,
        _ = interrupt.recv() => Signal::Interrupt,
    };
    telemetry::process_stopping(process, signal);
    stream_stop.send_replace(true);
    let _ = stop_tx.send(());
    tokio::time::timeout(http_budget, async {
        server.await.map_err(|_| ProcessFailure::Shutdown)?;
        // Both pools close within the deadline, so idle connections end cleanly before the
        // runtime is shut down.
        if let Some(issuance) = &issuance {
            tokio::join!(pool.close(), issuance.close());
        } else {
            pool.close().await;
        }
        Ok(())
    })
    .await
    .map_err(|_| ProcessFailure::ShutdownDeadline)?
}

#[cfg(test)]
#[path = "../tests/support/response_barrier.rs"]
pub(crate) mod response_barrier;

#[cfg(test)]
mod tests;
