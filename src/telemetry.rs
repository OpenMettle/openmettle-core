//! Process telemetry (ADR 0024): structured stderr logs behind a default-deny callsite guard.
//!
//! This module is the only place that emits. Each event comes from a typed constructor below:
//! identifiers are server-generated UUIDs and every other value is an enum, a duration or a
//! count. No constructor accepts free text, a request target, a header, a body, a
//! configuration value or an error's `Display` or `Debug` output.
//!
//! [`Guard`] sits in front of the only sink. It refuses every callsite whose target is not
//! exactly [`TARGET`] or which declares a field outside [`FIELDS`], so third-party
//! instrumentation (sqlx, hyper, rustls and anything else using `tracing`) and formatted
//! messages (a `message` field) never reach the output. No `log` bridge is installed, so
//! crates that log through `log` are not collected either.
//!
//! In production the sink is a bounded queue in front of one writer thread ([`sink`]), so a
//! stalled stderr drops and counts lines instead of blocking the emitting thread.
use axum::{
    Router,
    extract::{MatchedPath, Request},
    http::Method as HttpMethod,
    middleware::Next,
    response::Response,
};
use std::time::{Duration, Instant};
use tracing::{
    Level, Metadata, Subscriber,
    field::{DisplayValue, display},
    subscriber::Interest,
};
use tracing_subscriber::{
    Layer, Registry,
    filter::LevelFilter,
    fmt::{self, MakeWriter},
    layer::{Context, Filter, SubscriberExt},
};

mod sink;

/// The one target the guard admits. Every constructor names it explicitly.
pub const TARGET: &str = "openmettle_core::telemetry";

/// The only field names the guard admits. A `message` field, which every formatted event
/// carries, is deliberately absent.
pub const FIELDS: &[&str] = &[
    "event",
    "role",
    "signal",
    "request_id",
    "http.route",
    "http.request.method",
    "http.response.status_code",
    "duration_us",
    "error.type",
    "schema_version",
    "dropped_lines",
];

/// Log line encoding, from `LOG_FORMAT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Json,
    Text,
}

/// Most verbose level written, from `LOG_LEVEL`. `trace` is not offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verbosity {
    Error,
    Warn,
    Info,
    Debug,
}

impl Verbosity {
    fn level(self) -> Level {
        match self {
            Self::Error => Level::ERROR,
            Self::Warn => Level::WARN,
            Self::Info => Level::INFO,
            Self::Debug => Level::DEBUG,
        }
    }
}

/// Telemetry settings read under each process's existing configuration prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub format: Format,
    pub verbosity: Verbosity,
}

impl Settings {
    /// Reads `LOG_FORMAT` (`json` default, or `text`) and `LOG_LEVEL` (`info` default, or
    /// `error`, `warn` or `debug`). Values are matched exactly; an error names the key, never
    /// the value.
    pub fn parse(
        get: impl Fn(&str) -> Result<Option<String>, &'static str>,
    ) -> Result<Self, &'static str> {
        let format = match get("LOG_FORMAT")?.as_deref() {
            None | Some("json") => Format::Json,
            Some("text") => Format::Text,
            Some(_) => return Err("invalid LOG_FORMAT"),
        };
        let verbosity = match get("LOG_LEVEL")?.as_deref() {
            None | Some("info") => Verbosity::Info,
            Some("error") => Verbosity::Error,
            Some("warn") => Verbosity::Warn,
            Some("debug") => Verbosity::Debug,
            Some(_) => return Err("invalid LOG_LEVEL"),
        };
        Ok(Self { format, verbosity })
    }
}

/// Default-deny callsite guard in front of the sink. Its decision depends only on static
/// callsite metadata, so it is cached per callsite; `enabled` repeats it because another
/// dispatcher's interest can make a callsite `sometimes`.
pub struct Guard {
    max: Level,
}

impl Guard {
    fn admits(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == TARGET
            && *metadata.level() <= self.max
            && metadata.fields().iter().all(|f| FIELDS.contains(&f.name()))
    }
}

impl<S> Filter<S> for Guard {
    fn enabled(&self, metadata: &Metadata<'_>, _: &Context<'_, S>) -> bool {
        self.admits(metadata)
    }
    fn callsite_enabled(&self, metadata: &'static Metadata<'static>) -> Interest {
        if self.admits(metadata) {
            Interest::always()
        } else {
            Interest::never()
        }
    }
    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::from_level(self.max))
    }
}

/// The production subscriber stack over `writer`: one formatting layer behind [`Guard`].
/// Production passes stderr; tests pass a capture.
pub fn subscriber<W>(settings: Settings, writer: W) -> impl Subscriber + Send + Sync + 'static
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    let layer: Box<dyn Layer<Registry> + Send + Sync> = match settings.format {
        Format::Json => fmt::layer()
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_span_list(false)
            .with_target(false)
            .with_writer(writer)
            .boxed(),
        Format::Text => fmt::layer().with_target(false).with_writer(writer).boxed(),
    };
    let guard = Guard {
        max: settings.verbosity.level(),
    };
    Registry::default().with(layer.with_filter(guard))
}

/// Telemetry could not be installed; the process exits 1 with this fixed line.
#[derive(Debug)]
pub enum Unavailable {
    /// Another global subscriber was already installed; this process cannot vouch for its
    /// sink.
    AlreadyInstalled,
    /// The stderr writer thread could not be started.
    Writer,
}

impl Unavailable {
    pub fn message(&self) -> &'static str {
        match self {
            Self::AlreadyInstalled => "telemetry subscriber already installed",
            Self::Writer => "telemetry writer could not start",
        }
    }
}

/// The longest wait for queued lines at exit or after a panic, when stderr is not keeping up.
pub const FLUSH_LIMIT: Duration = Duration::from_millis(250);

/// The installed sink, kept by the process to flush before it exits.
pub struct Installed(sink::Queue);

impl Installed {
    /// Waits at most `limit` for every line emitted so far to be written. Returns whether it
    /// was; exit never waits longer.
    pub fn flush(&self, limit: Duration) -> bool {
        self.0.flush(limit)
    }
}

/// Installs the production stack for the rest of the process: the guarded formatter over a
/// bounded queue to a stderr writer thread, and a panic hook that writes only
/// `process.panicked` for `role`.
pub fn install(settings: Settings, role: Process) -> Result<Installed, Unavailable> {
    let queue = sink::Queue::spawn(std::io::stderr(), sink::CAPACITY, settings)
        .map_err(|_| Unavailable::Writer)?;
    tracing::subscriber::set_global_default(subscriber(settings, queue.clone()))
        .map_err(|_| Unavailable::AlreadyInstalled)?;
    let hook = queue.clone();
    // Replaces the default hook, which writes the payload and location. Unwinding or abort
    // then proceeds as without a hook.
    std::panic::set_hook(Box::new(move |_| {
        process_panicked(role);
        hook.flush(FLUSH_LIMIT);
    }));
    Ok(Installed(queue))
}

/// A server-generated UUIDv4 for one request. It is never read from a client header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestId([u8; 16]);

impl RequestId {
    /// `None` only if the operating system's random source fails.
    pub fn generate() -> Option<Self> {
        use ring::rand::{SecureRandom, SystemRandom};
        let mut bytes = [0; 16];
        SystemRandom::new().fill(&mut bytes).ok()?;
        bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
        bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 9562 variant
        Some(Self(bytes))
    }
}

/// Canonical lowercase hyphenated form.
impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// A process role; `service.name` will be `openmettle-{role}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Process {
    Api,
    Worker,
    Migrate,
}

impl Process {
    fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::Worker => "worker",
            Self::Migrate => "migrate",
        }
    }
}

/// A shutdown or interruption signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    Terminate,
    Interrupt,
}

impl Signal {
    fn as_str(self) -> &'static str {
        match self {
            Self::Terminate => "SIGTERM",
            Self::Interrupt => "SIGINT",
        }
    }
}

/// Why a serving process stopped with exit code 1. Recorded as `error.type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessFailure {
    SignalRegistration,
    Bind,
    Server,
    Shutdown,
    ShutdownDeadline,
}

impl ProcessFailure {
    fn as_str(self) -> &'static str {
        match self {
            Self::SignalRegistration => "SignalRegistration",
            Self::Bind => "Bind",
            Self::Server => "Server",
            Self::Shutdown => "Shutdown",
            Self::ShutdownDeadline => "ShutdownDeadline",
        }
    }
}

/// Why a migration run failed. Recorded as `error.type`; the CLI line keeps its own detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MigrationFailure {
    SignalRegistration,
    Invalid,
    ConnectTimeout,
    Connect,
    Check,
    Refused,
    Violated,
    Migrate,
}

impl MigrationFailure {
    fn as_str(self) -> &'static str {
        match self {
            Self::SignalRegistration => "SignalRegistration",
            Self::Invalid => "Invalid",
            Self::ConnectTimeout => "ConnectTimeout",
            Self::Connect => "Connect",
            Self::Check => "Check",
            Self::Refused => "Refused",
            Self::Violated => "Violated",
            Self::Migrate => "Migrate",
        }
    }
}

/// A closed request-method set; anything else is `_OTHER`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Delete,
    Patch,
    Options,
    Other,
}

impl Method {
    fn of(method: &HttpMethod) -> Self {
        match *method {
            HttpMethod::GET => Self::Get,
            HttpMethod::HEAD => Self::Head,
            HttpMethod::POST => Self::Post,
            HttpMethod::PUT => Self::Put,
            HttpMethod::DELETE => Self::Delete,
            HttpMethod::PATCH => Self::Patch,
            HttpMethod::OPTIONS => Self::Options,
            _ => Self::Other,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Options => "OPTIONS",
            Self::Other => "_OTHER",
        }
    }
}

/// The matched route template, registered by the server, or `unmatched`. Never the request
/// target, so a path parameter, query or fragment cannot be recorded.
struct Route(Option<MatchedPath>);

impl Route {
    fn as_str(&self) -> &str {
        self.0.as_ref().map_or("unmatched", MatchedPath::as_str)
    }
}

/// Adds request-ID middleware to every route of `router` and to its fallback. Apply it after
/// all routes are added.
pub fn observe<S: Clone + Send + Sync + 'static>(router: Router<S>) -> Router<S> {
    router.layer(axum::middleware::from_fn(request))
}

/// Assigns a fresh [`RequestId`] (also placed in request extensions for handlers) and records
/// the route template, method, status and duration when the response head is ready.
async fn request(mut request: Request, next: Next) -> Response {
    let started = Instant::now();
    let id = RequestId::generate();
    if let Some(id) = id {
        request.extensions_mut().insert(id);
    }
    let route = Route(request.extensions().get::<MatchedPath>().cloned());
    let method = Method::of(request.method());
    let response = next.run(request).await;
    request_completed(
        id,
        &route,
        method,
        response.status().as_u16(),
        started.elapsed(),
    );
    response
}

fn micros(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}

/// `debug` for an answered request, `warn` for a server error.
fn request_completed(
    id: Option<RequestId>,
    route: &Route,
    method: Method,
    status: u16,
    elapsed: Duration,
) {
    let id: Option<DisplayValue<RequestId>> = id.map(display);
    let route = route.as_str();
    let method = method.as_str();
    let duration = micros(elapsed);
    macro_rules! emit {
        ($level:expr) => {
            tracing::event!(
                target: TARGET,
                $level,
                event = "http.request.completed",
                request_id = id,
                http.route = route,
                http.request.method = method,
                http.response.status_code = status,
                duration_us = duration,
            )
        };
    }
    if status >= 500 {
        emit!(Level::WARN)
    } else {
        emit!(Level::DEBUG)
    }
}

/// The listener is bound and the process is serving.
pub fn process_started(role: Process) {
    tracing::info!(target: TARGET, event = "process.started", role = role.as_str());
}

/// A shutdown signal arrived; draining begins.
pub fn process_stopping(role: Process, signal: Signal) {
    tracing::info!(
        target: TARGET,
        event = "process.stopping",
        role = role.as_str(),
        signal = signal.as_str(),
    );
}

/// Draining finished within the shutdown deadline.
pub fn process_stopped(role: Process) {
    tracing::info!(target: TARGET, event = "process.stopped", role = role.as_str());
}

/// The process is exiting with a runtime failure.
pub fn process_failed(role: Process, failure: ProcessFailure) {
    tracing::error!(
        target: TARGET,
        event = "process.failed",
        role = role.as_str(),
        "error.type" = failure.as_str(),
    );
}

/// A thread panicked. Nothing from the panic (payload, message or location) is recorded.
pub fn process_panicked(role: Process) {
    tracing::error!(target: TARGET, event = "process.panicked", role = role.as_str());
}

/// The stderr writer dropped `count` lines since its last report, because the queue was full
/// or a write failed. `error`, so every configured level shows it.
fn lines_dropped(count: u64) {
    tracing::error!(target: TARGET, event = "telemetry.dropped", dropped_lines = count);
}

/// A migration run is starting.
pub fn migration_started() {
    tracing::info!(
        target: TARGET,
        event = "migration.started",
        role = Process::Migrate.as_str(),
    );
}

/// The schema is at `schema_version`.
pub fn migration_completed(schema_version: usize) {
    tracing::info!(
        target: TARGET,
        event = "migration.completed",
        role = Process::Migrate.as_str(),
        schema_version = schema_version as u64,
    );
}

/// A migration run failed; nothing partial remains (ADR 0003).
pub fn migration_failed(failure: MigrationFailure) {
    tracing::error!(
        target: TARGET,
        event = "migration.failed",
        role = Process::Migrate.as_str(),
        "error.type" = failure.as_str(),
    );
}

/// A signal ended the run, which exits 1; PostgreSQL rolls back the open transaction.
/// `error`, so a failed run is never silent at any configured level.
pub fn migration_interrupted(signal: Signal) {
    tracing::error!(
        target: TARGET,
        event = "migration.interrupted",
        role = Process::Migrate.as_str(),
        signal = signal.as_str(),
    );
}

#[cfg(test)]
pub(crate) mod tests;
