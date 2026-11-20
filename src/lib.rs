//! Shared operational contract and persistence primitives; no domain APIs or worker queue yet.
//! The API can also mount the browser sign-in routes, off by default (ADR 0025).
pub mod auth;
pub mod auth_config;
pub mod authz;
pub mod browser_auth;
pub mod capabilities;
pub mod grants;
pub mod invitation;
pub mod login;
pub mod membership;
pub mod migrate;
pub mod provider_http;
pub mod provider_keys;
pub mod runs;
pub mod sessions;
pub mod storage;
pub mod telemetry;

use axum::{Router, extract::State, http::StatusCode, routing::get};
use browser_auth::{BrowserAuth, handoff::LoginHandoff, router::router_with_sessions};
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

struct Config {
    bind: SocketAddr,
    database: PgConnectOptions,
    connections: u32,
    database_timeout: Duration,
    shutdown_timeout: Duration,
    telemetry: telemetry::Settings,
    /// `OTLP_TRACES_ENDPOINT` and its companions (ADR 0026); `None` leaves export off.
    otlp: Option<telemetry::otlp::Settings>,
    /// `OPENMETTLE_API_AUTH_CONFIG`: the browser sign-in settings document to mount
    /// (ADR 0025). Always `None` for the worker, which never reads the key.
    auth_config: Option<PathBuf>,
}

impl Config {
    fn load(role: Role) -> Result<Self, &'static str> {
        let prefix = match role {
            Role::Api => "OPENMETTLE_API",
            Role::Worker => "OPENMETTLE_WORKER",
        };
        Self::parse(role, |key| match std::env::var(format!("{prefix}_{key}")) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => Err("configuration must be UTF-8"),
        })
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
        if !(url.starts_with("postgres://") || url.starts_with("postgresql://")) {
            return Err("invalid DATABASE_URL scheme");
        }
        let database = url
            .parse::<PgConnectOptions>()
            .map_err(|_| "invalid DATABASE_URL")?
            .disable_statement_logging();
        let number = |key, default, max| -> Result<u32, &'static str> {
            let value = match get(key)? {
                Some(value) => value.parse().map_err(|_| "invalid numeric configuration")?,
                None => default,
            };
            if value == 0 || value > max {
                return Err("configuration outside allowed range");
            }
            Ok(value)
        };
        let connections = number("DB_MAX_CONNECTIONS", 4, 64)?;
        let database_timeout = Duration::from_millis(number("DB_TIMEOUT_MS", 2000, 30000)?.into());
        let shutdown_timeout =
            Duration::from_millis(number("SHUTDOWN_TIMEOUT_MS", 5000, 60000)?.into());
        let telemetry = telemetry::Settings::parse(&get)?;
        let otlp = telemetry::otlp::Settings::parse(&get)?;
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
        Ok(Self {
            bind,
            database,
            connections,
            database_timeout,
            shutdown_timeout,
            telemetry,
            otlp,
            auth_config,
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
/// pool (ADR 0016). Loading reads local files only; no provider, DNS name or database is
/// contacted, and the lazy pool stays unconnected. Readiness is unchanged and database-only.
///
/// The settings check refused `/healthz` and `/readyz` as sign-in paths, and the two
/// constructors repeat it, so the merge cannot shadow a probe or panic.
fn app(config: &Config, pool: &PgPool) -> Result<Router, auth_config::Error> {
    let operational = routes(Health {
        pool: pool.clone(),
        timeout: config.database_timeout,
    });
    let Some(path) = &config.auth_config else {
        return Ok(operational);
    };
    let (settings, profile) = auth_config::load_browser(path)?;
    let service = Arc::new(BrowserAuth::new(settings, pool.clone()));
    let handoff = LoginHandoff::new(service, profile.handoff())
        .map_err(auth_config::Error::BrowserHandoff)?;
    let sign_in = router_with_sessions(handoff, profile.router(), profile.sessions())
        .map_err(auth_config::Error::BrowserRouter)?;
    Ok(operational.merge(sign_in))
}

#[derive(Clone)]
struct Health {
    pool: PgPool,
    timeout: Duration,
}

async fn ready(State(state): State<Health>) -> (StatusCode, &'static str) {
    match tokio::time::timeout(
        state.timeout,
        sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&state.pool),
    )
    .await
    {
        Ok(Ok(1)) => (StatusCode::OK, "ready\n"),
        _ => (StatusCode::SERVICE_UNAVAILABLE, "not ready\n"),
    }
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
    // The same holds for the browser sign-in settings: refused before telemetry is installed
    // or the listener opens, with the offline check's fixed category line (ADRs 0015, 0025).
    let pool = pool(&config);
    let app = match app(&config, &pool) {
        Ok(app) => app,
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
    let code = match serve(config.bind, app, pool, process, drain).await {
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
    PgPoolOptions::new()
        .max_connections(config.connections)
        .acquire_timeout(config.database_timeout)
        .connect_lazy_with(config.database.clone())
}

async fn serve(
    bind: SocketAddr,
    app: Router,
    pool: PgPool,
    process: Process,
    drain: Duration,
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
    let app = telemetry::observe(app);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = axum::serve(listener, app).with_graceful_shutdown(async {
        let _ = stop_rx.await;
    });
    let server = std::future::IntoFuture::into_future(server);
    tokio::pin!(server);
    telemetry::process_started(process);
    let signal = tokio::select! {
        result = &mut server => return result.map_err(|_| ProcessFailure::Server),
        _ = terminate.recv() => Signal::Terminate,
        _ = interrupt.recv() => Signal::Interrupt,
    };
    telemetry::process_stopping(process, signal);
    let _ = stop_tx.send(());
    tokio::time::timeout(drain, async {
        server.await.map_err(|_| ProcessFailure::Shutdown)?;
        pool.close().await;
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
