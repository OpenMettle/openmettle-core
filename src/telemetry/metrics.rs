//! Bounded, statically typed operational metrics and OTLP protobuf encoding (ADR 0028).
//!
//! Every label dimension is a closed Rust enum with no free-text or identifier values, so
//! series cardinality is fixed at compile time and cannot grow with users, scopes, runs or
//! request IDs. Recording uses wait-free `AtomicU64` counters and fixed-bucket histograms.
use super::{Method, Process, TARGET};
use crate::authz::leases::CancelReason;
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
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Contract version carried on `InstrumentationScope.version` and checked against
/// `contracts/telemetry/v1.json`.
pub const CONTRACT_VERSION: &str = "1.0.0";

/// Process-wide or test-isolated handle to a [`Metrics`] store.
#[derive(Clone)]
pub(crate) enum MetricsSource {
    Global(&'static Metrics),
    #[cfg(test)]
    Owned(std::sync::Arc<Metrics>),
}

impl MetricsSource {
    pub(crate) fn as_ref(&self) -> &Metrics {
        match self {
            Self::Global(m) => m,
            #[cfg(test)]
            Self::Owned(m) => m,
        }
    }
}

/// Upper bounds in seconds for every duration histogram in telemetry contract v1.
pub const DURATION_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
const BUCKET_SLOTS: usize = DURATION_BUCKETS.len() + 1;

/// Closed HTTP route bucket for metrics. Keeps cardinality fixed even as new routes land and
/// guarantees no raw path segment or parameter can enter a metric label.
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteClass {
    Healthz,
    Readyz,
    Auth,
    V1,
    Other,
    Unmatched,
}

impl RouteClass {
    pub const ALL: &'static [Self] = &[
        Self::Healthz,
        Self::Readyz,
        Self::Auth,
        Self::V1,
        Self::Other,
        Self::Unmatched,
    ];
    pub const NAMES: &'static [&'static str] =
        &["healthz", "readyz", "auth", "v1", "other", "unmatched"];

    /// Classifies a matched Axum route template (never an unmatched raw target).
    pub fn of(route: &str) -> Self {
        match route {
            "/healthz" => Self::Healthz,
            "/readyz" => Self::Readyz,
            r if r == "/auth" || r.starts_with("/auth/") => Self::Auth,
            r if r == "/v1" || r.starts_with("/v1/") => Self::V1,
            "unmatched" => Self::Unmatched,
            _ => Self::Other,
        }
    }

    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self.index()]
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Closed HTTP status class for metrics.
#[repr(usize)]
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
        self as usize
    }
}

/// Closed outcome set for database readiness checks (`/readyz`).
#[repr(usize)]
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
        self as usize
    }
}

/// Closed outbound provider HTTP operation set (ADR 0010 / 0011).
#[repr(usize)]
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
        self as usize
    }
}

/// Closed outcome set for outbound provider HTTP calls.
#[repr(usize)]
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
        self as usize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayStep {
    Readiness,
    Principal,
    Budget,
    Policy,
    Key,
    Revoke,
    Usage,
}
impl GatewayStep {
    pub const ALL: [Self; 7] = [
        Self::Readiness,
        Self::Principal,
        Self::Budget,
        Self::Policy,
        Self::Key,
        Self::Revoke,
        Self::Usage,
    ];
    pub const NAMES: [&str; 7] = [
        "readiness",
        "principal",
        "budget",
        "policy",
        "key",
        "revoke",
        "usage",
    ];
    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self as usize]
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatewayCause {
    Policy,
    ServiceAuth,
    Transport,
    Timeout,
    Protocol,
    Protection,
    Unknown,
}
impl GatewayCause {
    pub const ALL: [Self; 7] = [
        Self::Policy,
        Self::ServiceAuth,
        Self::Transport,
        Self::Timeout,
        Self::Protocol,
        Self::Protection,
        Self::Unknown,
    ];
    pub const NAMES: [&str; 7] = [
        "policy",
        "service_auth",
        "transport",
        "timeout",
        "protocol",
        "protection",
        "unknown",
    ];
    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self as usize]
    }
}

const LAG: [&str; 3] = ["under_minute", "under_hour", "hour_or_more"];

/// Closed artifact storage accounting operation set (ADR 0005).
#[repr(usize)]
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
        self as usize
    }
}

/// Closed artifact storage accounting outcome set.
#[repr(usize)]
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
        self as usize
    }
}

/// Closed signal kind for telemetry self-drop accounting.
#[repr(usize)]
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
        self as usize
    }
}

/// Closed capacity controller operation class (ADR 0042).
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityOperation {
    Grant,
    Reconcile,
    Reclaim,
    Resume,
}

impl CapacityOperation {
    pub const ALL: &'static [Self] = &[Self::Grant, Self::Reconcile, Self::Reclaim, Self::Resume];
    pub const NAMES: &'static [&'static str] = &["grant", "reconcile", "reclaim", "resume"];

    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self.index()]
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Closed capacity controller decision/reconciliation outcome (ADR 0042).
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityOutcome {
    Granted,
    Insufficient,
    Unavailable,
    Released,
    NotAllocated,
    Releasing,
    UnknownAllocation,
    Resumed,
    Fenced,
    Expired,
    Refused,
    Error,
}

impl CapacityOutcome {
    pub const ALL: &'static [Self] = &[
        Self::Granted,
        Self::Insufficient,
        Self::Unavailable,
        Self::Released,
        Self::NotAllocated,
        Self::Releasing,
        Self::UnknownAllocation,
        Self::Resumed,
        Self::Fenced,
        Self::Expired,
        Self::Refused,
        Self::Error,
    ];
    pub const NAMES: &'static [&'static str] = &[
        "granted",
        "insufficient",
        "unavailable",
        "released",
        "not_allocated",
        "releasing",
        "unknown_allocation",
        "resumed",
        "fenced",
        "expired",
        "refused",
        "error",
    ];

    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self.index()]
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Closed surface reporting a stale capacity observation past its TTL (ADR 0042).
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityStaleSurface {
    Controller,
    V1User,
    V1Admin,
}

impl CapacityStaleSurface {
    pub const ALL: &'static [Self] = &[Self::Controller, Self::V1User, Self::V1Admin];
    pub const NAMES: &'static [&'static str] = &["controller", "v1_user", "v1_admin"];

    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self.index()]
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Closed outcome set for capacity wait duration observations (ADR 0042).
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityWaitOutcome {
    Granted,
    Busy,
    Unavailable,
    Timeout,
    Cancelled,
}

impl CapacityWaitOutcome {
    pub const ALL: &'static [Self] = &[
        Self::Granted,
        Self::Busy,
        Self::Unavailable,
        Self::Timeout,
        Self::Cancelled,
    ];
    pub const NAMES: &'static [&'static str] =
        &["granted", "busy", "unavailable", "timeout", "cancelled"];

    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self.index()]
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Closed outcome set for periodic storage and quota accounting drift verification (ADR 0040).
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotaDriftOutcome {
    Healthy,
    StorageAccounts,
    Budgets,
    Settlements,
    Files,
    Quarantined,
    Error,
    Timeout,
}

impl QuotaDriftOutcome {
    pub const ALL: &'static [Self] = &[
        Self::Healthy,
        Self::StorageAccounts,
        Self::Budgets,
        Self::Settlements,
        Self::Files,
        Self::Quarantined,
        Self::Error,
        Self::Timeout,
    ];
    pub const NAMES: &'static [&'static str] = &[
        "healthy",
        "storage_accounts",
        "budgets",
        "settlements",
        "files",
        "quarantined",
        "error",
        "timeout",
    ];

    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self.index()]
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Closed outcome set for coordinated maintenance-window backups and RPO checks (ADR 0046).
#[repr(usize)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupRunOutcome {
    Succeeded,
    Failed,
    Incomplete,
    Overdue,
}

impl BackupRunOutcome {
    pub const ALL: &'static [Self] = &[
        Self::Succeeded,
        Self::Failed,
        Self::Incomplete,
        Self::Overdue,
    ];
    pub const NAMES: &'static [&'static str] = &["succeeded", "failed", "incomplete", "overdue"];

    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self.index()]
    }

    const fn index(self) -> usize {
        self as usize
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
    /// Exact upper bound on the number of OTLP data-point streams this metric can ever produce.
    pub const fn max_series(&self) -> usize {
        let mut total = 1usize;
        let mut i = 0;
        while i < self.labels.len() {
            total *= self.labels[i].values.len();
            i += 1;
        }
        total
    }

    /// Exact upper bound on the number of Prometheus series this metric expands to per process
    /// (counters are 1:1; each histogram stream expands to `buckets.len() + 1` `_bucket`
    /// series plus `_sum` and `_count`).
    pub const fn max_prometheus_series(&self) -> usize {
        match self.buckets {
            Some(buckets) => self.max_series() * (buckets.len() + 3),
            None => self.max_series(),
        }
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
                name: "openmettle.route_class",
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
                name: "openmettle.route_class",
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
        description: "Artifact storage accounting and lifecycle helper attempts (including retries before transaction commit).",
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
    MetricDescriptor {
        name: "openmettle.runs.cancellations",
        prometheus_name: "openmettle_runs_cancellations_total",
        kind: InstrumentKind::Counter,
        unit: "{run}",
        description: "Terminal cancellation events appended by store helpers before transaction commit.",
        labels: &[LabelDescriptor {
            name: "reason",
            values: CancelReason::NAMES,
        }],
        buckets: None,
    },
    MetricDescriptor {
        name: "openmettle.quota.overdue.handoffs",
        prometheus_name: "openmettle_quota_overdue_handoffs_total",
        kind: InstrumentKind::Counter,
        unit: "{observation}",
        description: "Overdue committed quota handoffs observed in bounded worker sweeps.",
        labels: &[],
        buckets: None,
    },
    MetricDescriptor {
        name: "openmettle.gateway.failures",
        prometheus_name: "openmettle_gateway_failures_total",
        kind: InstrumentKind::Counter,
        unit: "{failure}",
        description: "Gateway failures by operation step and cause.",
        labels: &[
            LabelDescriptor {
                name: "step",
                values: &GatewayStep::NAMES,
            },
            LabelDescriptor {
                name: "cause",
                values: &GatewayCause::NAMES,
            },
        ],
        buckets: None,
    },
    MetricDescriptor {
        name: "openmettle.gateway.backfill.age",
        prometheus_name: "openmettle_gateway_backfill_age_total",
        kind: InstrumentKind::Counter,
        unit: "{observation}",
        description: "Age of unresolved handoffs observed during backfill.",
        labels: &[LabelDescriptor {
            name: "lag",
            values: &LAG,
        }],
        buckets: None,
    },
    MetricDescriptor {
        name: "openmettle.capacity.grants",
        prometheus_name: "openmettle_capacity_grants_total",
        kind: InstrumentKind::Counter,
        unit: "{decision}",
        description: "Capacity controller grant, reconciliation, reclaim and resume outcomes.",
        labels: &[
            LabelDescriptor {
                name: "operation",
                values: CapacityOperation::NAMES,
            },
            LabelDescriptor {
                name: "outcome",
                values: CapacityOutcome::NAMES,
            },
        ],
        buckets: None,
    },
    MetricDescriptor {
        name: "openmettle.capacity.observations.stale",
        prometheus_name: "openmettle_capacity_observations_stale_total",
        kind: InstrumentKind::Counter,
        unit: "{observation}",
        description: "Stale capacity observations encountered past their configured freshness TTL.",
        labels: &[LabelDescriptor {
            name: "surface",
            values: CapacityStaleSurface::NAMES,
        }],
        buckets: None,
    },
    MetricDescriptor {
        name: "openmettle.capacity.wait.duration",
        prometheus_name: "openmettle_capacity_wait_duration_seconds",
        kind: InstrumentKind::Histogram,
        unit: "s",
        description: "Capacity wait duration measured separately from workload execution.",
        labels: &[LabelDescriptor {
            name: "outcome",
            values: CapacityWaitOutcome::NAMES,
        }],
        buckets: Some(&DURATION_BUCKETS),
    },
    MetricDescriptor {
        name: "openmettle.storage.quota.drift",
        prometheus_name: "openmettle_storage_quota_drift_total",
        kind: InstrumentKind::Counter,
        unit: "{observation}",
        description: "Periodic storage and quota accounting drift verification observations.",
        labels: &[LabelDescriptor {
            name: "outcome",
            values: QuotaDriftOutcome::NAMES,
        }],
        buckets: None,
    },
    MetricDescriptor {
        name: "openmettle.backup.runs",
        prometheus_name: "openmettle_backup_runs_total",
        kind: InstrumentKind::Counter,
        unit: "{run}",
        description: "Coordinated maintenance-window backup capture outcomes and RPO overdue observations.",
        labels: &[LabelDescriptor {
            name: "outcome",
            values: BackupRunOutcome::NAMES,
        }],
        buckets: None,
    },
];

/// Sum of `max_series()` (OTLP data-point streams) across all v1 metrics.
pub const fn max_total_series() -> usize {
    let mut total = 0usize;
    let mut i = 0;
    while i < DESCRIPTORS.len() {
        total += DESCRIPTORS[i].max_series();
        i += 1;
    }
    total
}

/// Sum of `max_prometheus_series()` across all v1 metrics (per process, excluding `target_info`).
pub const fn max_total_prometheus_series() -> usize {
    let mut total = 0usize;
    let mut i = 0;
    while i < DESCRIPTORS.len() {
        total += DESCRIPTORS[i].max_prometheus_series();
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
const CAPACITY_GRANT_SLOTS: usize = CapacityOperation::NAMES.len() * CapacityOutcome::NAMES.len();
const CAPACITY_STALE_SLOTS: usize = CapacityStaleSurface::NAMES.len();
const CAPACITY_WAIT_SLOTS: usize = CapacityWaitOutcome::NAMES.len();
const QUOTA_DRIFT_SLOTS: usize = QuotaDriftOutcome::NAMES.len();
const BACKUP_RUN_SLOTS: usize = BackupRunOutcome::NAMES.len();

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
    gateway_failures: [[AtomicU64; 7]; 7],
    gateway_lag: [AtomicU64; 3],
    overdue_handoffs: AtomicU64,
    cancellations: [AtomicU64; CancelReason::NAMES.len()],
    telemetry_dropped: [AtomicU64; DROPPED_SLOTS],
    capacity_grants: [AtomicU64; CAPACITY_GRANT_SLOTS],
    capacity_stale_observations: [AtomicU64; CAPACITY_STALE_SLOTS],
    capacity_wait_duration: [HistogramSlot; CAPACITY_WAIT_SLOTS],
    quota_drift: [AtomicU64; QUOTA_DRIFT_SLOTS],
    backup_runs: [AtomicU64; BACKUP_RUN_SLOTS],
    backup_runs_seeded: AtomicBool,
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
            gateway_failures: Default::default(),
            gateway_lag: Default::default(),
            overdue_handoffs: AtomicU64::new(0),
            cancellations: std::array::from_fn(|_| AtomicU64::new(0)),
            telemetry_dropped: std::array::from_fn(|_| AtomicU64::new(0)),
            capacity_grants: std::array::from_fn(|_| AtomicU64::new(0)),
            capacity_stale_observations: std::array::from_fn(|_| AtomicU64::new(0)),
            capacity_wait_duration: std::array::from_fn(|_| HistogramSlot::new()),
            quota_drift: std::array::from_fn(|_| AtomicU64::new(0)),
            backup_runs: std::array::from_fn(|_| AtomicU64::new(0)),
            backup_runs_seeded: AtomicBool::new(false),
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

    pub fn record_gateway_failure(&self, step: GatewayStep, cause: GatewayCause) {
        self.gateway_failures[step as usize][cause as usize].fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_gateway_lag(&self, age_seconds: i64) {
        let bucket = match age_seconds {
            ..60 => 0,
            60..3600 => 1,
            _ => 2,
        };
        self.gateway_lag[bucket].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_overdue_handoffs(&self, count: u64) {
        self.overdue_handoffs.fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_cancellation(&self, reason: CancelReason) {
        self.cancellations[reason as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dropped(&self, signal: DroppedSignal, count: u64) {
        if count > 0 {
            self.telemetry_dropped[signal.index()].fetch_add(count, Ordering::Relaxed);
        }
    }

    pub fn dropped_count(&self, signal: DroppedSignal) -> u64 {
        self.telemetry_dropped[signal.index()].load(Ordering::Relaxed)
    }

    pub fn record_capacity_grant(&self, operation: CapacityOperation, outcome: CapacityOutcome) {
        let idx = operation.index() * CapacityOutcome::NAMES.len() + outcome.index();
        self.capacity_grants[idx].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_capacity_stale_observation(&self, surface: CapacityStaleSurface) {
        self.capacity_stale_observations[surface.index()].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_capacity_wait(&self, outcome: CapacityWaitOutcome, elapsed: Duration) {
        self.capacity_wait_duration[outcome.index()].observe(elapsed);
    }

    pub fn record_quota_drift(&self, outcome: QuotaDriftOutcome, count: u64) {
        if count > 0 {
            self.quota_drift[outcome.index()].fetch_add(count, Ordering::Relaxed);
        }
    }

    pub fn record_backup_run(&self, outcome: BackupRunOutcome, count: u64) {
        if count > 0 {
            self.backup_runs[outcome.index()].fetch_add(count, Ordering::Relaxed);
            self.backup_runs_seeded.store(true, Ordering::Release);
        }
    }

    /// Mark `openmettle.backup.runs` seeded so a worker with all-zero durable PostgreSQL totals
    /// starts emitting its 4-stream zero baseline in OTLP exports.
    pub fn mark_backup_runs_seeded(&self) {
        self.backup_runs_seeded.store(true, Ordering::Release);
    }

    /// Monotonically synchronize all four `openmettle.backup.runs` outcome slots with PostgreSQL's
    /// durable cumulative totals (`fetch_max`) and then publish the seeded flag with `Release`
    /// ordering so an OTLP export on a restarted worker never emits a premature `0` ahead of
    /// pre-existing historical failure, incomplete, or overdue counts.
    pub fn sync_backup_run_totals(
        &self,
        succeeded: u64,
        failed: u64,
        incomplete: u64,
        overdue: u64,
    ) {
        self.backup_runs[BackupRunOutcome::Succeeded.index()]
            .fetch_max(succeeded, Ordering::Relaxed);
        self.backup_runs[BackupRunOutcome::Failed.index()].fetch_max(failed, Ordering::Relaxed);
        self.backup_runs[BackupRunOutcome::Incomplete.index()]
            .fetch_max(incomplete, Ordering::Relaxed);
        self.backup_runs[BackupRunOutcome::Overdue.index()].fetch_max(overdue, Ordering::Relaxed);
        self.backup_runs_seeded.store(true, Ordering::Release);
    }

    /// Monotonically synchronize one `openmettle.backup.runs` outcome with PostgreSQL's durable
    /// cumulative total (`fetch_max`) and mark the metric seeded.
    pub fn observe_backup_run_total(&self, outcome: BackupRunOutcome, durable_total: u64) {
        self.backup_runs[outcome.index()].fetch_max(durable_total, Ordering::Relaxed);
        self.backup_runs_seeded.store(true, Ordering::Release);
    }

    pub fn backup_run_count(&self, outcome: BackupRunOutcome) -> u64 {
        self.backup_runs[outcome.index()].load(Ordering::Relaxed)
    }

    /// Encodes every non-zero cumulative metric series as an OTLP `ExportMetricsServiceRequest`.
    /// Returns `None` when nothing has been recorded yet so idle processes send no empty batch.
    pub fn encode_otlp(
        &self,
        role: Process,
        instance_id: Option<&str>,
    ) -> Option<ExportMetricsServiceRequest> {
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
                                ("openmettle.route_class", route.as_str()),
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
                            ("openmettle.route_class", route.as_str()),
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
        // Always emit all 3 closed drop-signal series (including 0) from process startup so
        // Prometheus records the zero baseline before any first outage; otherwise `increase()`
        // treats the first non-zero sample after a collector outage as a series appearance with
        // zero increase. These 3 streams are already counted in `max_series: 3`.
        let mut drop_points = Vec::with_capacity(DroppedSignal::ALL.len());
        for &signal in DroppedSignal::ALL {
            let value = self.telemetry_dropped[signal.index()].load(Ordering::Relaxed);
            drop_points.push(counter_point(
                start,
                now,
                value,
                &[("signal", signal.as_str())],
            ));
        }
        push_counter(&mut metrics, &DESCRIPTORS[7], drop_points);

        let mut points = Vec::new();
        for (slot, reason) in self.cancellations.iter().zip(CancelReason::NAMES) {
            let value = slot.load(Ordering::Relaxed);
            if value > 0 {
                points.push(counter_point(start, now, value, &[("reason", reason)]));
            }
        }
        push_counter(&mut metrics, &DESCRIPTORS[8], points);

        let overdue = self.overdue_handoffs.load(Ordering::Relaxed);
        if overdue > 0 || role == Process::Worker {
            push_counter(
                &mut metrics,
                &DESCRIPTORS[9],
                vec![counter_point(start, now, overdue, &[])],
            );
        }

        let mut failures = Vec::new();
        for step in GatewayStep::ALL {
            for cause in GatewayCause::ALL {
                let n =
                    self.gateway_failures[step as usize][cause as usize].load(Ordering::Relaxed);
                if n > 0 {
                    failures.push(counter_point(
                        start,
                        now,
                        n,
                        &[("step", step.as_str()), ("cause", cause.as_str())],
                    ));
                }
            }
        }
        push_counter(&mut metrics, &DESCRIPTORS[10], failures);
        let lag = self
            .gateway_lag
            .iter()
            .zip(LAG)
            .filter_map(|(count, lag)| {
                let n = count.load(Ordering::Relaxed);
                (n > 0).then(|| counter_point(start, now, n, &[("lag", lag)]))
            })
            .collect();
        push_counter(&mut metrics, &DESCRIPTORS[11], lag);

        // 12: openmettle.capacity.grants
        let mut cap_points = Vec::new();
        for &op in CapacityOperation::ALL {
            for &outcome in CapacityOutcome::ALL {
                let idx = op.index() * CapacityOutcome::NAMES.len() + outcome.index();
                let value = self.capacity_grants[idx].load(Ordering::Relaxed);
                if value > 0 {
                    cap_points.push(counter_point(
                        start,
                        now,
                        value,
                        &[("operation", op.as_str()), ("outcome", outcome.as_str())],
                    ));
                }
            }
        }
        push_counter(&mut metrics, &DESCRIPTORS[12], cap_points);

        // 13: openmettle.capacity.observations.stale
        let mut stale_points = Vec::new();
        for &surface in CapacityStaleSurface::ALL {
            let value = self.capacity_stale_observations[surface.index()].load(Ordering::Relaxed);
            if value > 0 {
                stale_points.push(counter_point(
                    start,
                    now,
                    value,
                    &[("surface", surface.as_str())],
                ));
            }
        }
        push_counter(&mut metrics, &DESCRIPTORS[13], stale_points);

        // 14: openmettle.capacity.wait.duration
        let mut wait_hpoints = Vec::new();
        for &outcome in CapacityWaitOutcome::ALL {
            let (count, sum, buckets) = self.capacity_wait_duration[outcome.index()].snapshot();
            if count > 0 {
                wait_hpoints.push(histogram_point(
                    start,
                    now,
                    count,
                    sum,
                    buckets,
                    &[("outcome", outcome.as_str())],
                ));
            }
        }
        push_histogram(&mut metrics, &DESCRIPTORS[14], wait_hpoints);

        // 15: openmettle.storage.quota.drift
        // Always emit all 8 closed outcome series (including 0) on `openmettle-worker` from startup
        // so Prometheus records a zero baseline before the first hourly drift, error or timeout
        // observation; otherwise `increase(...[3h])` treats a first mismatch as a series
        // appearance with zero increase. These 8 streams are already counted in `max_series: 8`.
        let mut drift_points = Vec::new();
        for &outcome in QuotaDriftOutcome::ALL {
            let value = self.quota_drift[outcome.index()].load(Ordering::Relaxed);
            if value > 0 || role == Process::Worker {
                drift_points.push(counter_point(
                    start,
                    now,
                    value,
                    &[("outcome", outcome.as_str())],
                ));
            }
        }
        push_counter(&mut metrics, &DESCRIPTORS[15], drift_points);

        // 16: openmettle.backup.runs
        // Gate ALL `openmettle.backup.runs` export strictly on `backup_runs_seeded` (`Acquire`),
        // paired with `sync_backup_run_totals`'s `Release` store after all 4 slots are updated.
        // This guarantees a concurrent export never emits a partial subset of slots mid-seed and
        // restarted workers never export a premature `0` ahead of pre-existing historical
        // `failed`/`incomplete`/`overdue` counts.
        let mut backup_points = Vec::new();
        if self.backup_runs_seeded.load(Ordering::Acquire) {
            for &outcome in BackupRunOutcome::ALL {
                let value = self.backup_runs[outcome.index()].load(Ordering::Relaxed);
                if value > 0 || role == Process::Worker {
                    backup_points.push(counter_point(
                        start,
                        now,
                        value,
                        &[("outcome", outcome.as_str())],
                    ));
                }
            }
        }
        push_counter(&mut metrics, &DESCRIPTORS[16], backup_points);

        if metrics.is_empty() {
            return None;
        }
        let mut resource_attributes =
            vec![kv("service.name", &format!("openmettle-{}", role.as_str()))];
        if let Some(id) = instance_id {
            resource_attributes.push(kv("service.instance.id", id));
        }
        Some(ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(Resource {
                    attributes: resource_attributes,
                    dropped_attributes_count: 0,
                    entity_refs: Vec::new(),
                }),
                scope_metrics: vec![ScopeMetrics {
                    scope: Some(InstrumentationScope {
                        name: TARGET.to_owned(),
                        version: CONTRACT_VERSION.to_owned(),
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

pub(crate) fn quota_sweep_failed() {
    tracing::warn!(target: super::TARGET, event="worker.sweep.failed", role="worker", "error.type"="reconcile_stale_quotas");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_runs_never_exports_any_slot_before_seeded_flag_is_published() {
        let store = Metrics::new();
        // Simulate mid-seed partial counter update before `backup_runs_seeded` becomes `true`.
        store.backup_runs[BackupRunOutcome::Failed.index()].store(3, Ordering::Relaxed);

        for role in [Process::Worker, Process::Api] {
            let encoded = store
                .encode_otlp(role, Some("44444444-5555-4666-8777-888888888888"))
                .expect("baseline dropped telemetry is always emitted");
            assert!(
                !encoded.resource_metrics[0].scope_metrics[0]
                    .metrics
                    .iter()
                    .any(|m| m.name == "openmettle.backup.runs"),
                "unseeded registry must never export openmettle.backup.runs for {role:?}"
            );
        }

        store.mark_backup_runs_seeded();
        let worker = store
            .encode_otlp(
                Process::Worker,
                Some("44444444-5555-4666-8777-888888888888"),
            )
            .unwrap();
        let metric = worker.resource_metrics[0].scope_metrics[0]
            .metrics
            .iter()
            .find(|m| m.name == "openmettle.backup.runs")
            .expect("seeded worker must emit openmettle.backup.runs");
        match metric.data.as_ref().unwrap() {
            metric::Data::Sum(sum) => {
                assert_eq!(sum.data_points.len(), BackupRunOutcome::ALL.len())
            }
            other => panic!("expected Sum, got {other:?}"),
        }
    }
}
