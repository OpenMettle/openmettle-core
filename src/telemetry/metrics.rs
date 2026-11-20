//! Bounded, statically typed operational metrics and OTLP protobuf encoding (ADR 0028).
//!
//! Every label dimension is a closed Rust enum with no free-text or identifier values, so
//! series cardinality is fixed at compile time and cannot grow with users, scopes, runs or
//! request IDs. Recording uses wait-free `AtomicU64` counters and fixed-bucket histograms.
use super::{Method, Process, TARGET};
use opentelemetry_proto::tonic::{
    collector::metrics::v1::ExportMetricsServiceRequest,
    common::v1::{AnyValue, InstrumentationScope, KeyValue, any_value},
    metrics::v1::{
        AggregationTemporality, Histogram, HistogramDataPoint, Metric, NumberDataPoint,
        ResourceMetrics, ScopeMetrics, Sum, metric, number_data_point,
    },
    resource::v1::Resource,
};
use std::{
    sync::{
        LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Upper bounds in seconds for every duration histogram in telemetry contract v1.
pub const DURATION_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
const BUCKET_SLOTS: usize = DURATION_BUCKETS.len() + 1;

/// Closed HTTP route bucket for metrics. Keeps cardinality fixed even as new routes land and
/// guarantees no raw path segment or parameter can enter a metric label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteClass {
    Healthz,
    Readyz,
    Auth,
    V1,
    Unmatched,
}

impl RouteClass {
    pub const ALL: &'static [Self] = &[
        Self::Healthz,
        Self::Readyz,
        Self::Auth,
        Self::V1,
        Self::Unmatched,
    ];
    pub const NAMES: &'static [&'static str] = &["healthz", "readyz", "auth", "v1", "unmatched"];

    /// Classifies a matched Axum route template (never an unmatched raw target).
    pub fn of(route: &str) -> Self {
        match route {
            "/healthz" => Self::Healthz,
            "/readyz" => Self::Readyz,
            r if r.starts_with("/v1/") || r == "/v1" => Self::V1,
            "unmatched" => Self::Unmatched,
            // Browser sign-in / session / logout routes mounted by ADR 0025.
            _ => Self::Auth,
        }
    }

    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self.index()]
    }

    const fn index(self) -> usize {
        match self {
            Self::Healthz => 0,
            Self::Readyz => 1,
            Self::Auth => 2,
            Self::V1 => 3,
            Self::Unmatched => 4,
        }
    }
}

/// Closed HTTP status class for metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusClass {
    S2xx,
    S3xx,
    S4xx,
    S5xx,
    Other,
}

impl StatusClass {
    pub const ALL: &'static [Self] = &[Self::S2xx, Self::S3xx, Self::S4xx, Self::S5xx, Self::Other];
    pub const NAMES: &'static [&'static str] = &["2xx", "3xx", "4xx", "5xx", "other"];

    pub const fn of(status: u16) -> Self {
        match status {
            200..=299 => Self::S2xx,
            300..=399 => Self::S3xx,
            400..=499 => Self::S4xx,
            500..=599 => Self::S5xx,
            _ => Self::Other,
        }
    }

    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self.index()]
    }

    const fn index(self) -> usize {
        match self {
            Self::S2xx => 0,
            Self::S3xx => 1,
            Self::S4xx => 2,
            Self::S5xx => 3,
            Self::Other => 4,
        }
    }
}

/// Closed outcome set for database readiness checks (`/readyz`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadinessOutcome {
    Ok,
    Timeout,
    Error,
}

impl ReadinessOutcome {
    pub const ALL: &'static [Self] = &[Self::Ok, Self::Timeout, Self::Error];
    pub const NAMES: &'static [&'static str] = &["ok", "timeout", "error"];

    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self.index()]
    }

    const fn index(self) -> usize {
        match self {
            Self::Ok => 0,
            Self::Timeout => 1,
            Self::Error => 2,
        }
    }
}

/// Closed outbound provider HTTP operation set (ADR 0010 / 0011).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderOperation {
    Discovery,
    Jwks,
    Token,
}

impl ProviderOperation {
    pub const ALL: &'static [Self] = &[Self::Discovery, Self::Jwks, Self::Token];
    pub const NAMES: &'static [&'static str] = &["discovery", "jwks", "token"];

    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self.index()]
    }

    const fn index(self) -> usize {
        match self {
            Self::Discovery => 0,
            Self::Jwks => 1,
            Self::Token => 2,
        }
    }
}

/// Closed outcome set for outbound provider HTTP calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderOutcome {
    Ok,
    HttpError,
    Timeout,
    Transport,
    Refused,
    BodyLimit,
}

impl ProviderOutcome {
    pub const ALL: &'static [Self] = &[
        Self::Ok,
        Self::HttpError,
        Self::Timeout,
        Self::Transport,
        Self::Refused,
        Self::BodyLimit,
    ];
    pub const NAMES: &'static [&'static str] = &[
        "ok",
        "http_error",
        "timeout",
        "transport",
        "refused",
        "body_limit",
    ];

    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self.index()]
    }

    const fn index(self) -> usize {
        match self {
            Self::Ok => 0,
            Self::HttpError => 1,
            Self::Timeout => 2,
            Self::Transport => 3,
            Self::Refused => 4,
            Self::BodyLimit => 5,
        }
    }
}

/// Closed artifact storage accounting operation set (ADR 0005).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageOperation {
    Reserve,
    Settle,
    Release,
    Retain,
    Restore,
    BeginPurge,
    ConfirmPurge,
}

impl StorageOperation {
    pub const ALL: &'static [Self] = &[
        Self::Reserve,
        Self::Settle,
        Self::Release,
        Self::Retain,
        Self::Restore,
        Self::BeginPurge,
        Self::ConfirmPurge,
    ];
    pub const NAMES: &'static [&'static str] = &[
        "reserve",
        "settle",
        "release",
        "retain",
        "restore",
        "begin_purge",
        "confirm_purge",
    ];

    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self.index()]
    }

    const fn index(self) -> usize {
        match self {
            Self::Reserve => 0,
            Self::Settle => 1,
            Self::Release => 2,
            Self::Retain => 3,
            Self::Restore => 4,
            Self::BeginPurge => 5,
            Self::ConfirmPurge => 6,
        }
    }
}

/// Closed artifact storage accounting outcome set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageOutcome {
    Ok,
    QuotaRefused,
    Conflict,
    NotFound,
    Invalid,
    Error,
}

impl StorageOutcome {
    pub const ALL: &'static [Self] = &[
        Self::Ok,
        Self::QuotaRefused,
        Self::Conflict,
        Self::NotFound,
        Self::Invalid,
        Self::Error,
    ];
    pub const NAMES: &'static [&'static str] = &[
        "ok",
        "quota_refused",
        "conflict",
        "not_found",
        "invalid",
        "error",
    ];

    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self.index()]
    }

    const fn index(self) -> usize {
        match self {
            Self::Ok => 0,
            Self::QuotaRefused => 1,
            Self::Conflict => 2,
            Self::NotFound => 3,
            Self::Invalid => 4,
            Self::Error => 5,
        }
    }
}

/// Closed signal kind for telemetry self-drop accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DroppedSignal {
    LogLines,
    TraceSpans,
    MetricExports,
}

impl DroppedSignal {
    pub const ALL: &'static [Self] = &[Self::LogLines, Self::TraceSpans, Self::MetricExports];
    pub const NAMES: &'static [&'static str] = &["log_lines", "trace_spans", "metric_exports"];

    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self.index()]
    }

    const fn index(self) -> usize {
        match self {
            Self::LogLines => 0,
            Self::TraceSpans => 1,
            Self::MetricExports => 2,
        }
    }
}

/// Instrument kind recorded in telemetry contract v1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstrumentKind {
    Counter,
    Histogram,
}

impl InstrumentKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Histogram => "histogram",
        }
    }
}

/// One closed label dimension on a metric.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LabelDescriptor {
    pub name: &'static str,
    pub values: &'static [&'static str],
}

/// Authoritative Rust descriptor for one v1 metric, checked bijectively against
/// `contracts/telemetry/v1.json`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MetricDescriptor {
    pub name: &'static str,
    pub prometheus_name: &'static str,
    pub kind: InstrumentKind,
    pub unit: &'static str,
    pub description: &'static str,
    pub labels: &'static [LabelDescriptor],
    pub buckets: Option<&'static [f64]>,
}

impl MetricDescriptor {
    /// Exact upper bound on the number of series this metric can ever produce.
    pub const fn max_series(&self) -> usize {
        let mut total = 1usize;
        let mut i = 0;
        while i < self.labels.len() {
            total *= self.labels[i].values.len();
            i += 1;
        }
        total
    }
}

/// Complete list of v1 metrics emitted by `openmettle-core`.
pub const DESCRIPTORS: &[MetricDescriptor] = &[
    MetricDescriptor {
        name: "openmettle.http.server.requests",
        prometheus_name: "openmettle_http_server_requests_total",
        kind: InstrumentKind::Counter,
        unit: "{request}",
        description: "Completed HTTP requests handled by the serving process.",
        labels: &[
            LabelDescriptor {
                name: "http.request.method",
                values: Method::NAMES,
            },
            LabelDescriptor {
                name: "http.route",
                values: RouteClass::NAMES,
            },
            LabelDescriptor {
                name: "http.response.status_class",
                values: StatusClass::NAMES,
            },
        ],
        buckets: None,
    },
    MetricDescriptor {
        name: "openmettle.http.server.request.duration",
        prometheus_name: "openmettle_http_server_request_duration_seconds",
        kind: InstrumentKind::Histogram,
        unit: "s",
        description: "End-to-end HTTP request handling duration.",
        labels: &[
            LabelDescriptor {
                name: "http.route",
                values: RouteClass::NAMES,
            },
            LabelDescriptor {
                name: "http.response.status_class",
                values: StatusClass::NAMES,
            },
        ],
        buckets: Some(&DURATION_BUCKETS),
    },
    MetricDescriptor {
        name: "openmettle.db.readiness.checks",
        prometheus_name: "openmettle_db_readiness_checks_total",
        kind: InstrumentKind::Counter,
        unit: "{check}",
        description: "Database readiness probe checks executed by /readyz.",
        labels: &[LabelDescriptor {
            name: "outcome",
            values: ReadinessOutcome::NAMES,
        }],
        buckets: None,
    },
    MetricDescriptor {
        name: "openmettle.db.readiness.duration",
        prometheus_name: "openmettle_db_readiness_duration_seconds",
        kind: InstrumentKind::Histogram,
        unit: "s",
        description: "Database readiness probe latency.",
        labels: &[LabelDescriptor {
            name: "outcome",
            values: ReadinessOutcome::NAMES,
        }],
        buckets: Some(&DURATION_BUCKETS),
    },
    MetricDescriptor {
        name: "openmettle.provider.http.requests",
        prometheus_name: "openmettle_provider_http_requests_total",
        kind: InstrumentKind::Counter,
        unit: "{request}",
        description: "Outbound identity provider HTTP requests over the ADR 0010 transport.",
        labels: &[
            LabelDescriptor {
                name: "operation",
                values: ProviderOperation::NAMES,
            },
            LabelDescriptor {
                name: "outcome",
                values: ProviderOutcome::NAMES,
            },
        ],
        buckets: None,
    },
    MetricDescriptor {
        name: "openmettle.provider.http.duration",
        prometheus_name: "openmettle_provider_http_duration_seconds",
        kind: InstrumentKind::Histogram,
        unit: "s",
        description: "Outbound identity provider HTTP request latency.",
        labels: &[
            LabelDescriptor {
                name: "operation",
                values: ProviderOperation::NAMES,
            },
            LabelDescriptor {
                name: "outcome",
                values: ProviderOutcome::NAMES,
            },
        ],
        buckets: Some(&DURATION_BUCKETS),
    },
    MetricDescriptor {
        name: "openmettle.storage.operations",
        prometheus_name: "openmettle_storage_operations_total",
        kind: InstrumentKind::Counter,
        unit: "{operation}",
        description: "Artifact storage accounting and lifecycle operations.",
        labels: &[
            LabelDescriptor {
                name: "operation",
                values: StorageOperation::NAMES,
            },
            LabelDescriptor {
                name: "outcome",
                values: StorageOutcome::NAMES,
            },
        ],
        buckets: None,
    },
    MetricDescriptor {
        name: "openmettle.telemetry.dropped",
        prometheus_name: "openmettle_telemetry_dropped_total",
        kind: InstrumentKind::Counter,
        unit: "{item}",
        description: "Telemetry items dropped due to queue saturation or exporter failure.",
        labels: &[LabelDescriptor {
            name: "signal",
            values: DroppedSignal::NAMES,
        }],
        buckets: None,
    },
];

/// Sum of `max_series()` across all v1 metrics.
pub const fn max_total_series() -> usize {
    let mut total = 0usize;
    let mut i = 0;
    while i < DESCRIPTORS.len() {
        total += DESCRIPTORS[i].max_series();
        i += 1;
    }
    total
}

const HTTP_REQ_SLOTS: usize =
    Method::NAMES.len() * RouteClass::NAMES.len() * StatusClass::NAMES.len();
const HTTP_DUR_SLOTS: usize = RouteClass::NAMES.len() * StatusClass::NAMES.len();
const DB_SLOTS: usize = ReadinessOutcome::NAMES.len();
const PROVIDER_SLOTS: usize = ProviderOperation::NAMES.len() * ProviderOutcome::NAMES.len();
const STORAGE_SLOTS: usize = StorageOperation::NAMES.len() * StorageOutcome::NAMES.len();
const DROPPED_SLOTS: usize = DroppedSignal::NAMES.len();

struct HistogramSlot {
    buckets: [AtomicU64; BUCKET_SLOTS],
    sum_us: AtomicU64,
}

impl HistogramSlot {
    fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            sum_us: AtomicU64::new(0),
        }
    }

    fn observe(&self, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        let bucket = DURATION_BUCKETS
            .iter()
            .position(|&bound| secs <= bound)
            .unwrap_or(DURATION_BUCKETS.len());
        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
        let us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.sum_us.fetch_add(us, Ordering::Relaxed);
    }

    /// Reads bucket counts first and derives `count` as their sum so OTLP's invariant
    /// `count == sum(bucket_counts)` always holds even under concurrent writers.
    fn snapshot(&self) -> (u64, f64, Vec<u64>) {
        let mut counts = Vec::with_capacity(BUCKET_SLOTS);
        let mut total = 0u64;
        for bucket in &self.buckets {
            let value = bucket.load(Ordering::Relaxed);
            total = total.saturating_add(value);
            counts.push(value);
        }
        let sum_secs = self.sum_us.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        (total, sum_secs, counts)
    }
}

/// Fixed-size wait-free metrics store for one process (or isolated test).
pub struct Metrics {
    start_time_unix_nano: u64,
    http_requests: Box<[AtomicU64; HTTP_REQ_SLOTS]>,
    http_duration: Box<[HistogramSlot; HTTP_DUR_SLOTS]>,
    db_readiness_checks: [AtomicU64; DB_SLOTS],
    db_readiness_duration: [HistogramSlot; DB_SLOTS],
    provider_requests: [AtomicU64; PROVIDER_SLOTS],
    provider_duration: [HistogramSlot; PROVIDER_SLOTS],
    storage_operations: [AtomicU64; STORAGE_SLOTS],
    telemetry_dropped: [AtomicU64; DROPPED_SLOTS],
}

static GLOBAL: LazyLock<Metrics> = LazyLock::new(Metrics::new);

/// Process-wide metrics store used by serving middleware and instrumentation hooks.
pub fn global() -> &'static Metrics {
    &GLOBAL
}

fn unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            start_time_unix_nano: unix_nanos(),
            http_requests: Box::new(std::array::from_fn(|_| AtomicU64::new(0))),
            http_duration: Box::new(std::array::from_fn(|_| HistogramSlot::new())),
            db_readiness_checks: std::array::from_fn(|_| AtomicU64::new(0)),
            db_readiness_duration: std::array::from_fn(|_| HistogramSlot::new()),
            provider_requests: std::array::from_fn(|_| AtomicU64::new(0)),
            provider_duration: std::array::from_fn(|_| HistogramSlot::new()),
            storage_operations: std::array::from_fn(|_| AtomicU64::new(0)),
            telemetry_dropped: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    pub fn record_http(
        &self,
        method: Method,
        route: RouteClass,
        status: StatusClass,
        elapsed: Duration,
    ) {
        let req_idx = (method.index() * RouteClass::NAMES.len() + route.index())
            * StatusClass::NAMES.len()
            + status.index();
        self.http_requests[req_idx].fetch_add(1, Ordering::Relaxed);
        let dur_idx = route.index() * StatusClass::NAMES.len() + status.index();
        self.http_duration[dur_idx].observe(elapsed);
    }

    pub fn record_db_readiness(&self, outcome: ReadinessOutcome, elapsed: Duration) {
        let idx = outcome.index();
        self.db_readiness_checks[idx].fetch_add(1, Ordering::Relaxed);
        self.db_readiness_duration[idx].observe(elapsed);
    }

    pub fn record_provider_http(
        &self,
        operation: ProviderOperation,
        outcome: ProviderOutcome,
        elapsed: Duration,
    ) {
        let idx = operation.index() * ProviderOutcome::NAMES.len() + outcome.index();
        self.provider_requests[idx].fetch_add(1, Ordering::Relaxed);
        self.provider_duration[idx].observe(elapsed);
    }

    pub fn record_storage(&self, operation: StorageOperation, outcome: StorageOutcome) {
        let idx = operation.index() * StorageOutcome::NAMES.len() + outcome.index();
        self.storage_operations[idx].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dropped(&self, signal: DroppedSignal, count: u64) {
        if count > 0 {
            self.telemetry_dropped[signal.index()].fetch_add(count, Ordering::Relaxed);
        }
    }

    pub fn dropped_count(&self, signal: DroppedSignal) -> u64 {
        self.telemetry_dropped[signal.index()].load(Ordering::Relaxed)
    }

    /// Encodes every non-zero cumulative metric series as an OTLP `ExportMetricsServiceRequest`.
    /// Returns `None` when nothing has been recorded yet so idle processes send no empty batch.
    pub fn encode_otlp(&self, role: Process) -> Option<ExportMetricsServiceRequest> {
        let now = unix_nanos().max(self.start_time_unix_nano);
        let start = self.start_time_unix_nano;
        let mut metrics = Vec::with_capacity(DESCRIPTORS.len());

        // 0: openmettle.http.server.requests
        let mut points = Vec::new();
        for &method in Method::ALL {
            for &route in RouteClass::ALL {
                for &status in StatusClass::ALL {
                    let idx = (method.index() * RouteClass::NAMES.len() + route.index())
                        * StatusClass::NAMES.len()
                        + status.index();
                    let value = self.http_requests[idx].load(Ordering::Relaxed);
                    if value > 0 {
                        points.push(counter_point(
                            start,
                            now,
                            value,
                            &[
                                ("http.request.method", method.as_str()),
                                ("http.route", route.as_str()),
                                ("http.response.status_class", status.as_str()),
                            ],
                        ));
                    }
                }
            }
        }
        push_counter(&mut metrics, &DESCRIPTORS[0], points);

        // 1: openmettle.http.server.request.duration
        let mut hpoints = Vec::new();
        for &route in RouteClass::ALL {
            for &status in StatusClass::ALL {
                let idx = route.index() * StatusClass::NAMES.len() + status.index();
                let (count, sum, buckets) = self.http_duration[idx].snapshot();
                if count > 0 {
                    hpoints.push(histogram_point(
                        start,
                        now,
                        count,
                        sum,
                        buckets,
                        &[
                            ("http.route", route.as_str()),
                            ("http.response.status_class", status.as_str()),
                        ],
                    ));
                }
            }
        }
        push_histogram(&mut metrics, &DESCRIPTORS[1], hpoints);

        // 2 & 3: openmettle.db.readiness.{checks,duration}
        let mut db_points = Vec::new();
        let mut db_hpoints = Vec::new();
        for &outcome in ReadinessOutcome::ALL {
            let idx = outcome.index();
            let value = self.db_readiness_checks[idx].load(Ordering::Relaxed);
            if value > 0 {
                db_points.push(counter_point(
                    start,
                    now,
                    value,
                    &[("outcome", outcome.as_str())],
                ));
            }
            let (count, sum, buckets) = self.db_readiness_duration[idx].snapshot();
            if count > 0 {
                db_hpoints.push(histogram_point(
                    start,
                    now,
                    count,
                    sum,
                    buckets,
                    &[("outcome", outcome.as_str())],
                ));
            }
        }
        push_counter(&mut metrics, &DESCRIPTORS[2], db_points);
        push_histogram(&mut metrics, &DESCRIPTORS[3], db_hpoints);

        // 4 & 5: openmettle.provider.http.{requests,duration}
        let mut prov_points = Vec::new();
        let mut prov_hpoints = Vec::new();
        for &op in ProviderOperation::ALL {
            for &outcome in ProviderOutcome::ALL {
                let idx = op.index() * ProviderOutcome::NAMES.len() + outcome.index();
                let value = self.provider_requests[idx].load(Ordering::Relaxed);
                if value > 0 {
                    prov_points.push(counter_point(
                        start,
                        now,
                        value,
                        &[("operation", op.as_str()), ("outcome", outcome.as_str())],
                    ));
                }
                let (count, sum, buckets) = self.provider_duration[idx].snapshot();
                if count > 0 {
                    prov_hpoints.push(histogram_point(
                        start,
                        now,
                        count,
                        sum,
                        buckets,
                        &[("operation", op.as_str()), ("outcome", outcome.as_str())],
                    ));
                }
            }
        }
        push_counter(&mut metrics, &DESCRIPTORS[4], prov_points);
        push_histogram(&mut metrics, &DESCRIPTORS[5], prov_hpoints);

        // 6: openmettle.storage.operations
        let mut storage_points = Vec::new();
        for &op in StorageOperation::ALL {
            for &outcome in StorageOutcome::ALL {
                let idx = op.index() * StorageOutcome::NAMES.len() + outcome.index();
                let value = self.storage_operations[idx].load(Ordering::Relaxed);
                if value > 0 {
                    storage_points.push(counter_point(
                        start,
                        now,
                        value,
                        &[("operation", op.as_str()), ("outcome", outcome.as_str())],
                    ));
                }
            }
        }
        push_counter(&mut metrics, &DESCRIPTORS[6], storage_points);

        // 7: openmettle.telemetry.dropped
        let mut drop_points = Vec::new();
        for &signal in DroppedSignal::ALL {
            let value = self.telemetry_dropped[signal.index()].load(Ordering::Relaxed);
            if value > 0 {
                drop_points.push(counter_point(
                    start,
                    now,
                    value,
                    &[("signal", signal.as_str())],
                ));
            }
        }
        push_counter(&mut metrics, &DESCRIPTORS[7], drop_points);

        if metrics.is_empty() {
            return None;
        }
        Some(ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(Resource {
                    attributes: vec![kv("service.name", &format!("openmettle-{}", role.as_str()))],
                    dropped_attributes_count: 0,
                    entity_refs: Vec::new(),
                }),
                scope_metrics: vec![ScopeMetrics {
                    scope: Some(InstrumentationScope {
                        name: TARGET.to_owned(),
                        version: "1.0.0".to_owned(),
                        attributes: Vec::new(),
                        dropped_attributes_count: 0,
                    }),
                    metrics,
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        })
    }
}

fn kv(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_owned(),
        key_strindex: 0,
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.to_owned())),
        }),
    }
}

fn attrs(pairs: &[(&str, &str)]) -> Vec<KeyValue> {
    pairs.iter().map(|&(k, v)| kv(k, v)).collect()
}

fn counter_point(start: u64, now: u64, value: u64, labels: &[(&str, &str)]) -> NumberDataPoint {
    NumberDataPoint {
        attributes: attrs(labels),
        start_time_unix_nano: start,
        time_unix_nano: now,
        exemplars: Vec::new(),
        flags: 0,
        value: Some(number_data_point::Value::AsInt(
            i64::try_from(value).unwrap_or(i64::MAX),
        )),
    }
}

fn histogram_point(
    start: u64,
    now: u64,
    count: u64,
    sum: f64,
    bucket_counts: Vec<u64>,
    labels: &[(&str, &str)],
) -> HistogramDataPoint {
    HistogramDataPoint {
        attributes: attrs(labels),
        start_time_unix_nano: start,
        time_unix_nano: now,
        count,
        sum: Some(sum),
        bucket_counts,
        explicit_bounds: DURATION_BUCKETS.to_vec(),
        exemplars: Vec::new(),
        flags: 0,
        min: None,
        max: None,
    }
}

fn push_counter(
    out: &mut Vec<Metric>,
    descriptor: &MetricDescriptor,
    data_points: Vec<NumberDataPoint>,
) {
    if data_points.is_empty() {
        return;
    }
    out.push(Metric {
        name: descriptor.name.to_owned(),
        description: descriptor.description.to_owned(),
        unit: descriptor.unit.to_owned(),
        metadata: Vec::new(),
        data: Some(metric::Data::Sum(Sum {
            data_points,
            aggregation_temporality: AggregationTemporality::Cumulative as i32,
            is_monotonic: true,
        })),
    });
}

fn push_histogram(
    out: &mut Vec<Metric>,
    descriptor: &MetricDescriptor,
    data_points: Vec<HistogramDataPoint>,
) {
    if data_points.is_empty() {
        return;
    }
    out.push(Metric {
        name: descriptor.name.to_owned(),
        description: descriptor.description.to_owned(),
        unit: descriptor.unit.to_owned(),
        metadata: Vec::new(),
        data: Some(metric::Data::Histogram(Histogram {
            data_points,
            aggregation_temporality: AggregationTemporality::Cumulative as i32,
        })),
    });
}
