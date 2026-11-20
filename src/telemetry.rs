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
//!
//! The stderr guard admits events only. When OTLP export is configured ([`otlp`], ADR 0026),
//! a second layer behind [`SpanGuard`] admits spans only: this crate's request span, with
//! [`SPAN_FIELDS`]. Third-party spans and every event stay invisible to it.
use axum::{
    Router,
    extract::{MatchedPath, Request},
    http::Method as HttpMethod,
    middleware::Next,
    response::Response,
};
use opentelemetry_sdk::trace::SdkTracer;
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

pub mod metrics;
pub mod otlp;
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
    "dropped_spans",
    "dropped_metric_exports",
];

/// The only field names [`SpanGuard`] admits: the request span's. `otel.kind` is consumed by
/// the bridge as the span kind and is not exported as an attribute.
pub const SPAN_FIELDS: &[&str] = &[
    "otel.kind",
    "request_id",
    "http.route",
    "http.request.method",
    "http.response.status_code",
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

/// Admits only callsites on [`TARGET`], at or below `max`, whose every field is in `fields`.
fn allowed(metadata: &Metadata<'_>, max: Level, fields: &[&str]) -> bool {
    metadata.target() == TARGET
        && *metadata.level() <= max
        && metadata.fields().iter().all(|f| fields.contains(&f.name()))
}

/// Default-deny callsite guard in front of the stderr sink: events only, with [`FIELDS`]. Its
/// decision depends only on static callsite metadata, so it is cached per callsite; `enabled`
/// repeats it because another dispatcher's interest can make a callsite `sometimes`.
pub struct Guard {
    max: Level,
}

impl Guard {
    fn admits(&self, metadata: &Metadata<'_>) -> bool {
        metadata.is_event() && allowed(metadata, self.max, FIELDS)
    }
    fn hint(&self) -> LevelFilter {
        LevelFilter::from_level(self.max)
    }
}

/// Default-deny callsite guard in front of the OTLP span layer: spans only, with
/// [`SPAN_FIELDS`], at `info` or below whatever `LOG_LEVEL` is. Events, including every log
/// event, never become span events.
pub struct SpanGuard;

impl SpanGuard {
    fn admits(&self, metadata: &Metadata<'_>) -> bool {
        metadata.is_span() && allowed(metadata, Level::INFO, SPAN_FIELDS)
    }
    fn hint(&self) -> LevelFilter {
        LevelFilter::INFO
    }
}

/// Both guards decide from static callsite metadata alone.
macro_rules! callsite_filter {
    ($guard:ty) => {
        impl<S> Filter<S> for $guard {
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
                Some(self.hint())
            }
        }
    };
}
callsite_filter!(Guard);
callsite_filter!(SpanGuard);

/// The production subscriber stack over `writer`: one formatting layer behind [`Guard`].
/// Production passes stderr; tests pass a capture.
pub fn subscriber<W>(settings: Settings, writer: W) -> impl Subscriber + Send + Sync + 'static
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    stack(settings, writer, None)
}

/// [`subscriber`], plus the OTLP span layer behind [`SpanGuard`] when `tracer` is given. The
/// bridge records no source location, thread, target, level or busy/idle timing, maps no
/// error field, and never activates an OpenTelemetry context.
pub(crate) fn stack<W>(
    settings: Settings,
    writer: W,
    tracer: Option<SdkTracer>,
) -> Box<dyn Subscriber + Send + Sync + 'static>
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
    let logs = Registry::default().with(layer.with_filter(guard));
    // Two concrete stacks rather than an optional layer: an absent `Option` layer reports
    // interest in every callsite, which would enable the request span with export off.
    let Some(tracer) = tracer else {
        return Box::new(logs);
    };
    let spans = tracing_opentelemetry::layer()
        .with_tracer(tracer)
        .with_location(false)
        .with_threads(false)
        .with_target(false)
        .with_level(false)
        .with_tracked_inactivity(false)
        .with_context_activation(false)
        .with_error_fields_to_exceptions(false)
        .with_error_records_to_exceptions(false)
        .with_error_events_to_exceptions(false)
        .with_error_events_to_status(false)
        .with_filter(SpanGuard);
    Box::new(logs.with(spans))
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

/// The installed sink, and the OTLP exporter if one was configured, kept by the process to
/// stop them before it exits.
pub struct Installed {
    queue: sink::Queue,
    exporter: Option<otlp::Exporter>,
}

impl Installed {
    /// Waits at most `limit` for every line emitted so far to be written. Returns whether it
    /// was; exit never waits longer.
    pub fn flush(&self, limit: Duration) -> bool {
        self.queue.flush(limit)
    }

    /// Stops everything within `budget`. A configured exporter gets at most half of it to
    /// send queued spans and is then cancelled, closing any connection; the stderr flush gets
    /// the rest, before the same deadline. Without an exporter this is [`Self::flush`].
    pub async fn stop(self, budget: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + budget;
        if let Some(exporter) = self.exporter {
            exporter.stop(deadline - budget / 2).await;
        }
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        self.queue.flush(left)
    }
}

/// Installs the production stack for the rest of the process: the guarded formatter over a
/// bounded queue to a stderr writer thread, and a panic hook that writes only
/// `process.panicked` for `role`. With `export`, the OTLP exporter is started on the current
/// Tokio runtime and its span layer joins the stack; without it nothing OTLP-related exists.
pub fn install(
    settings: Settings,
    role: Process,
    export: Option<otlp::Destination>,
) -> Result<Installed, Unavailable> {
    let queue = sink::Queue::spawn(std::io::stderr(), sink::CAPACITY, settings)
        .map_err(|_| Unavailable::Writer)?;
    let (tracer, exporter) = match export {
        Some(destination) => {
            let (tracer, exporter) = otlp::start(destination, role);
            (tracer, Some(exporter))
        }
        None => (None, None),
    };
    tracing::subscriber::set_global_default(stack(settings, queue.clone(), tracer))
        .map_err(|_| Unavailable::AlreadyInstalled)?;
    let hook = queue.clone();
    // Replaces the default hook, which writes the payload and location. Unwinding or abort
    // then proceeds as without a hook.
    std::panic::set_hook(Box::new(move |_| {
        process_panicked(role);
        hook.flush(FLUSH_LIMIT);
    }));
    Ok(Installed { queue, exporter })
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
    pub const ALL: &'static [Self] = &[
        Self::Get,
        Self::Head,
        Self::Post,
        Self::Put,
        Self::Delete,
        Self::Patch,
        Self::Options,
        Self::Other,
    ];
    pub const NAMES: &'static [&'static str] = &[
        "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "_OTHER",
    ];

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
    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self.index()]
    }
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Get => 0,
            Self::Head => 1,
            Self::Post => 2,
            Self::Put => 3,
            Self::Delete => 4,
            Self::Patch => 5,
            Self::Options => 6,
            Self::Other => 7,
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
    /// The liveness and readiness probes, which produce no span.
    fn is_probe(&self) -> bool {
        matches!(self.as_str(), "/healthz" | "/readyz")
    }
}

/// Adds request-ID middleware to every route of `router` and to its fallback. Apply it after
/// all routes are added.
pub fn observe<S: Clone + Send + Sync + 'static>(router: Router<S>) -> Router<S> {
    router.layer(axum::middleware::from_fn(request))
}

/// Assigns a fresh [`RequestId`] (also placed in request extensions for handlers) and records
/// the route template, method, status and duration when the response head is ready. Every
/// route except the probes also gets a request span, which only the OTLP layer can see.
async fn request(mut request: Request, next: Next) -> Response {
    let started = Instant::now();
    let id = RequestId::generate();
    if let Some(id) = id {
        request.extensions_mut().insert(id);
    }
    let route = Route(request.extensions().get::<MatchedPath>().cloned());
    let method = Method::of(request.method());
    let span = (!route.is_probe()).then(|| request_span(id, &route, method));
    let response = next.run(request).await;
    let status = response.status().as_u16();
    let elapsed = started.elapsed();
    if let Some(span) = &span {
        // As i64: the bridge has no u64 visitor and would export the code as a string.
        span.record("http.response.status_code", i64::from(status));
    }
    metrics::global().record_http(
        method,
        metrics::RouteClass::of(route.as_str()),
        metrics::StatusClass::of(status),
        elapsed,
    );
    request_completed(id, &route, method, status, elapsed);
    response
}

/// A root server span, never entered and never parented: an inbound `traceparent` or
/// `tracestate` is not read, so every request starts a new trace. It ends when dropped,
/// after the response head is ready. Disabled, and almost free, unless OTLP is configured.
fn request_span(id: Option<RequestId>, route: &Route, method: Method) -> tracing::Span {
    let id: Option<DisplayValue<RequestId>> = id.map(display);
    tracing::info_span!(
        target: TARGET,
        parent: None,
        "http.server.request",
        otel.kind = "server",
        request_id = id,
        http.route = route.as_str(),
        http.request.method = method.as_str(),
        http.response.status_code = tracing::field::Empty,
    )
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
    metrics::global().record_dropped(metrics::DroppedSignal::LogLines, count);
    tracing::error!(target: TARGET, event = "telemetry.dropped", dropped_lines = count);
}

/// The OTLP exporter dropped `count` spans since its last report, because the queue was full
/// or a batch was not delivered. At most once per export cycle, to stderr only.
fn spans_dropped(count: u64) {
    metrics::global().record_dropped(metrics::DroppedSignal::TraceSpans, count);
    tracing::error!(target: TARGET, event = "telemetry.dropped", dropped_spans = count);
}

/// The OTLP metrics exporter dropped `count` export cycles since its last report. At most
/// once per export cycle, to stderr only.
fn metric_exports_dropped(count: u64) {
    tracing::error!(
        target: TARGET,
        event = "telemetry.dropped",
        dropped_metric_exports = count
    );
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
