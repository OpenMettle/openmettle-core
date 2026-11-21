# 0028 — Telemetry contract v1 and bounded operational metrics

Status: proposed V1-29 increments 3–4 of 4, 20 November 2026. Agent-authored; implements the
V1-29 increment plan recorded on #26. Owner approval of this record, independent review and
CI acceptance are separate gates. Refs #26; Refs #34. #26 remains open until owner acceptance.

## Problem

[ADR 0024](0024-process-telemetry-and-redaction.md) delivered structured stderr logging behind
a default-deny callsite guard, and [ADR 0026](0026-otlp-trace-export.md) added opt-in
OTLP/HTTP protobuf trace export over the ADR 0010 transport core. Neither yet provides a
machine-checked versioned telemetry contract beside the API contract, bounded-cardinality
aggregate metrics independent of sampled traces, or deterministic Prometheus alert rules for
the base signals already present in `openmettle-core`.

## Decision

### Versioned telemetry contract

`contracts/telemetry/v1.json` is the canonical telemetry contract for `openmettle-core`,
versioned independently at `1.0.0` with pinned OpenTelemetry semantic conventions (`1.37.0`).
It records:

- Privacy and transport policy: inbound `traceparent` ignored, logs on stderr, HTTPS HTTP/1.1
  protobuf OTLP export, Prometheus translation mode `UnderscoreEscapingWithSuffixes`, resource
  attributes (`service.name` and per-process random UUIDv4 `service.instance.id`), retention
  ceiling defaults (traces 72 h, logs 7 d, metrics 14 d; operator-confirmed per jurisdiction),
  disallowed metric label substrings, and fields excluded from all telemetry.
- The exact stderr log field allowlist (`telemetry::FIELDS`) and event catalog.
- The exact trace span field allowlist (`telemetry::SPAN_FIELDS`) and span limits.
- Every v1 metric: OTel name, Prometheus normalized name, instrument kind (`counter` or
  `histogram`), unit, explicit histogram bucket bounds, closed label enum values (including
  `openmettle.route_class` so metric buckets never collide with SemConv `http.route` templates
  on trace spans), storage helper attempt semantics (counts helper executions including retries
  before transaction commit), and exact per-metric and total ceilings.
- ADR 0033 adds `openmettle.runs.cancellations`. It counts terminal cancellation events
  appended by store helpers before commit. Its reason is `requested` or `revoked`.
- Reserved future signal namespaces (`openmettle.runs.queue.age`,
  `openmettle.capacity.grants`,
  `openmettle.storage.quota.drift`, `openmettle.backup.runs`), owned by V1-10, V1-17,
  V1-18 and V1-30 respectively.

### Statically bounded metrics registry

`src/telemetry/metrics.rs` provides a fixed-size, wait-free `Metrics` registry backed solely
by pre-allocated `AtomicU64` counters and fixed-bucket histograms (`DURATION_BUCKETS`).

- Every metric label is a closed Rust enum (`Method`, `RouteClass`, `StatusClass`,
  `ReadinessOutcome`, `ProviderOperation`, `ProviderOutcome`, `StorageOperation`,
  `StorageOutcome`, `DroppedSignal`, `CancelReason`). No `String`, raw path, user ID, scope ID, run ID, or
  request ID can be supplied as a metric label.
- Total worst-case cardinality across all nine v1 metrics is **359**
  OTLP data-point streams per process, expanding to at most **1,022** Prometheus series per
  process (each 11-boundary histogram stream expands to 12 `_bucket` + `_sum` + `_count` = 14
  series, excluding `target_info`), multiplied by active replica count via `service.instance.id`.
- Histogram snapshots derive `count` from the sum of loaded bucket counts so the OTLP
  invariant `count == sum(bucket_counts)` holds even under concurrent writers.
- Log-line drops (`signal="log_lines"`) are counted once at the point a line is actually lost
  (full stderr queue or write failure in `sink.rs`), never when a failed `telemetry.dropped`
  stderr notice is retried.

### Opt-in OTLP/HTTP protobuf metrics export

`telemetry::otlp::Settings::parse` reads four keys in order under the process prefix:
`OTLP_TRACES_ENDPOINT`, `OTLP_METRICS_ENDPOINT`, `OTLP_CA_FILE`, `OTLP_PRIVATE_RANGES`.

- Both endpoints default to unset (export off). When neither endpoint is set, `OTLP_CA_FILE`
  and `OTLP_PRIVATE_RANGES` are refused just as in ADR 0026.
- Either or both endpoints may be configured independently. Both share the loaded CA trust
  bundle, private CIDR allowlist, the 2-slot exporter DNS semaphore, and one per-process
  random UUIDv4 `service.instance.id` generated at exporter startup so multi-replica API and
  worker processes produce disjoint Prometheus `instance` streams without exposing host, pod,
  or user identities.
- When `OTLP_METRICS_ENDPOINT` is set, one Tokio task periodically snapshots non-zero
  cumulative metrics plus all three zero-initialized `openmettle.telemetry.dropped`
  (`DroppedSignal::ALL`) series from process startup so Prometheus records a zero baseline
  before any first collector outage, encodes `ExportMetricsServiceRequest` via
  `opentelemetry-proto` (`metrics` feature enabled with zero new crates in `Cargo.lock`), and
  POSTs with `Content-Type: application/x-protobuf` over the ADR 0010 `Route`.
- Failures (non-2xx, timeout, DNS/TLS/transport error, or oversized body) drop the export
  cycle without retry, increment `openmettle.telemetry.dropped{signal="metric_exports"}`, and
  emit one `telemetry.dropped` event with `dropped_metric_exports` to stderr.
- On shutdown, trace and metrics export tasks drain concurrently within the existing half-slice
  of `shutdown_budget` and are aborted on deadline expiry.

### Deterministic alert rules

`contracts/telemetry/alerts-v1.yaml` defines Prometheus alert rules strictly over the v1
metrics emitted today: `OpenMettleApiHighServerErrorRatio` (scoped to `job="openmettle-api"`
and excluding `healthz`/`readyz` probes), `OpenMettleDatabaseReadinessFailing`,
`OpenMettleTelemetryDropsDetected` (`increase(openmettle_telemetry_dropped_total[15m]) > 0`
with `for: 5m` so a single collector outage transitions from zero baseline to `firing` and
resolves cleanly), and `OpenMettleProviderTransportFailures`.
`contracts/telemetry/alerts-v1-test.yaml` supplies deterministic positive and negative
`promtool test rules` cases for all four alerts, executed alongside `promtool check rules`
in CI via the pinned Prometheus image.

## Dependencies

Enabling `metrics` on `opentelemetry-proto = "=0.33.1"` activates only crates already locked
in `Cargo.lock` (`futures-channel`, `futures-executor`, `futures-util`, `thiserror`). No new
package enters `Cargo.lock`, and the ADR 0026 banned-crate guard in
`scripts/check_repository.py` remains unchanged.

## Verification

- `tests/telemetry_contract.rs` verifies 1:1 bijective equality between
  `contracts/telemetry/v1.json` and compiled Rust constants (`CONTRACT_VERSION`, `FIELDS`,
  `SPAN_FIELDS`, `metrics::DESCRIPTORS`, bucket bounds, closed label values, and both
  data-point stream and Prometheus series ceilings), verifies `service.name` and
  `service.instance.id` encoding, verifies zero disallowed/ID label names, and checks that
  every metric, grouping label, and selector label/value referenced in
  `contracts/telemetry/alerts-v1.yaml` `expr` blocks is declared in `contracts/telemetry/v1.json`.
- `src/telemetry/tests/otlp.rs` exercises `OTLP_METRICS_ENDPOINT` configuration parsing,
  end-to-end HTTPS OTLP/HTTP protobuf metrics export against an in-process synthetic-CA
  collector, concurrent trace + metrics export sharing one `service.instance.id` and clean
  `Exporter::stop`, collector 503 drop reporting, and stalled metrics collector shutdown within
  budget.
- `src/telemetry/tests.rs` verifies that `metric_exports_dropped` and `spans_dropped` pass
  the allowlist guard and that retried stderr drop-report writes never double-count
  `openmettle.telemetry.dropped{signal="log_lines"}`.
- `.github/workflows/telemetry-qualification.yml` and `tests/telemetry_kind/qualify.py`
  (V1-29 increment 4 of 4) run `tests/telemetry_kind/test_qualify.py`, execute `promtool check
  rules` and `promtool test rules` against `contracts/telemetry/alerts-v1-test.yaml`, and
  qualify live `openmettle-api` and `openmettle-worker` pods against pinned Grafana Alloy
  (`v1.10.0`) and Prometheus (`v3.5.0`) on an ephemeral `dev` `kind` cluster: HTTPS OTLP
  trace and metrics ingestion with synthetic CA, inbound `traceparent` / secret redaction,
  per-process UUIDv4 `instance` separation, closed-enum contract label verification on every
  live `openmettle_*` series, single-outage collector resilience (zero probe failures and zero
  restarts while `telemetry.dropped` is logged, `openmettle_telemetry_dropped_total` rises
  from its zero baseline, and `OpenMettleTelemetryDropsDetected` reaches `firing` in
  Prometheus), and clean SIGTERM shutdown.
