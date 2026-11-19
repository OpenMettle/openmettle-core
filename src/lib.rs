//! Shared operational contract and persistence primitives; no domain APIs or worker queue yet.
pub mod auth;
pub mod auth_config;
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

use axum::{Router, extract::State, http::StatusCode, routing::get};
use sqlx::{
    ConnectOptions, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use std::{net::SocketAddr, time::Duration};

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
}

impl Config {
    fn load(role: Role) -> Result<Self, &'static str> {
        let (prefix, port) = match role {
            Role::Api => ("OPENMETTLE_API", 8080),
            Role::Worker => ("OPENMETTLE_WORKER", 8081),
        };
        Self::parse(port, |key| match std::env::var(format!("{prefix}_{key}")) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => Err("configuration must be UTF-8"),
        })
    }

    fn parse(
        port: u16,
        get: impl Fn(&str) -> Result<Option<String>, &'static str>,
    ) -> Result<Self, &'static str> {
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
        Ok(Self {
            bind,
            database,
            connections: number("DB_MAX_CONNECTIONS", 4, 64)?,
            database_timeout: Duration::from_millis(number("DB_TIMEOUT_MS", 2000, 30000)?.into()),
            shutdown_timeout: Duration::from_millis(
                number("SHUTDOWN_TIMEOUT_MS", 5000, 60000)?.into(),
            ),
        })
    }
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

pub async fn run(role: Role) -> u8 {
    let config = match Config::load(role) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("configuration error: {message}");
            return 78;
        }
    };
    match serve(config).await {
        Ok(()) => 0,
        Err(message) => {
            eprintln!("runtime error: {message}");
            1
        }
    }
}

async fn serve(config: Config) -> Result<(), &'static str> {
    // Install signal handlers before opening the listener.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "cannot register SIGTERM")?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|_| "cannot register SIGINT")?;
    let pool = PgPoolOptions::new()
        .max_connections(config.connections)
        .acquire_timeout(config.database_timeout)
        .connect_lazy_with(config.database);
    let listener = tokio::net::TcpListener::bind(config.bind)
        .await
        .map_err(|_| "cannot bind listener")?;
    let app = Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/readyz", get(ready))
        .with_state(Health {
            pool: pool.clone(),
            timeout: config.database_timeout,
        });
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let server = axum::serve(listener, app).with_graceful_shutdown(async {
        let _ = stop_rx.await;
    });
    let server = std::future::IntoFuture::into_future(server);
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => return result.map_err(|_| "HTTP server failed"),
        _ = terminate.recv() => {},
        _ = interrupt.recv() => {},
    }
    let _ = stop_tx.send(());
    tokio::time::timeout(config.shutdown_timeout, async {
        server.await.map_err(|_| "HTTP shutdown failed")?;
        pool.close().await;
        Ok(())
    })
    .await
    .map_err(|_| "shutdown deadline exceeded")?
}

#[cfg(test)]
#[path = "../tests/support/response_barrier.rs"]
pub(crate) mod response_barrier;
