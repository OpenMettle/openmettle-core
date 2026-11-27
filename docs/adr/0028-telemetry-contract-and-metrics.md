# 0028 — Telemetry contract v1 and bounded operational metrics

Status: accepted with its implementation; V1-29 increments 3–4 of 4, 20 November 2026. Agent-authored; implements the
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

- Privacy, access control, and transport policy: inbound `traceparent` ignored, logs on
  stderr, HTTPS HTTP/1.1 protobuf OTLP export, Prometheus translation mode
  `UnderscoreEscapingWithSuffixes`, resource attributes (`service.name` and per-process
  random UUIDv4 `service.instance.id`), retention ceiling defaults (traces 72 h, logs 7 d,
  metrics 14 d; operator-confirmed per jurisdiction), `policy.access_control` enforcing an
  infrastructure-operator-only reader boundary independent from `/v1/*`, tenant/project
  roles, product memory, and `openmettle.authorization_audit` (see
  [`docs/operator/telemetry-access-and-retention.md`](../operator/telemetry-access-and-retention.md)),
  disallowed metric label substrings, and fields excluded from all telemetry.
- The exact stderr log field allowlist (`telemetry::FIELDS`, 26 fields) and event catalog
  (including bounded correlation of validated `request_id`, `run_id`, `operation_id`,
  non-reversible derived `rl-…` worker `lease_id`, and public `grant_id` UUID `lease_id` on
  `capacity.grant.completed`, with `401 Unauthorized` HTTP responses centrally suppressing
  resource correlation IDs).
- The exact trace span field allowlist (`telemetry::SPAN_FIELDS`, 11 fields) and span limits
  across `http.server.request`, `worker.run`, child `worker.operation`, and `capacity.grant`
  spans (`<= 8` exported attributes per span, `dropped_attributes_count == 0`).
- Every v1 metric: OTel name, Prometheus normalized name, instrument kind (`counter` or
  `histogram`), unit, explicit histogram bucket bounds (`DURATION_BUCKETS` for short-latency
  histograms; `QUEUE_AGE_BUCKETS` up to `300.0` s for `openmettle.runs.queue.age`), closed
  label enum values (including `openmettle.route_class` so metric buckets never collide with
  SemConv `http.route` templates on trace spans, and `ProviderOperation` covering
  `discovery`, `jwks`, `token`, `inference`, `mcp`, and `oauth_refresh`), storage helper
  attempt semantics (counts helper executions including retries before transaction commit),
  and exact per-metric and total ceilings.
- ADR 0033 adds `openmettle.runs.cancellations`. It counts terminal cancellation events
  appended by store helpers before commit. Its reason is `requested` or `revoked`.
- *Update, 27 November 2026:* `reserved_signals` is now empty (`[]`). V1-10 promoted
  `openmettle.runs.queue.age` (`openmettle_runs_queue_age_seconds`, `QUEUE_AGE_BUCKETS`,
  `outcome ∈ {claimed, resumed, cancelled, expired}`) into the implemented v1 catalog. It
  is recorded **strictly after transaction commit** (`claimed` from `runs.created_at`,
  `resumed` from `run_approval_decisions.decided_at`, `expired` from `runs.created_at` on
  `expire_queued` and from `run_approval_decisions.decided_at` on `expire_waits` for approved
  resumable waits, and `cancelled` only when a run leaves the queue while `queued` or while
  `waiting` with an eligible decided `'approve'` decision—never when cancelling an executing
  run or an undecided human-approval wait). Earlier reserved signals `openmettle.capacity.grants`
  (V1-18 PR3), `openmettle.storage.quota.drift` (V1-17), and `openmettle.backup.runs`
  (V1-30 / [ADR 0046](0046-maintenance-window-coordinated-backup-capture.md)) are likewise
  implemented.

### Statically bounded metrics registry

`src/telemetry/metrics.rs` provides a fixed-size, wait-free `Metrics` registry backed solely
by pre-allocated `AtomicU64` counters and fixed-bucket histograms (`DURATION_BUCKETS`).

- Every metric label is a closed Rust enum (`Method`, `RouteClass`, `StatusClass`,
  `ReadinessOutcome`, `ProviderOperation`, `ProviderOutcome`, `StorageOperation`,
  `StorageOutcome`, `DroppedSignal`, `CancelReason`, `GatewayStep`, `GatewayCause`,
  `CapacityOperation`, `CapacityOutcome`, `CapacityStaleSurface`, `CapacityWaitOutcome`,
  `QuotaDriftOutcome`, `BackupRunOutcome`, `RunQueueAgeOutcome`, plus the fixed 3-bucket
  `lag` label for gateway backfill age). No `String`, raw path, user ID, scope ID, run ID,
  operation ID, lease ID, or request ID can be supplied as a metric label.
- Total worst-case cardinality across all nine original v1 metrics was **359**
  OTLP data-point streams per process, expanding to at most **1,022** Prometheus series per
  process (each 11-boundary histogram stream expands to 12 `_bucket` + `_sum` + `_count` = 14
  series, excluding `target_info`), multiplied by active replica count via `service.instance.id`.
  *Update, 27 November 2026:* the contract now defines **18** metrics, **532** data-point
  streams and **1,624** Prometheus series per process (extending `ProviderOperation` to
  `inference`, `mcp`, and `oauth_refresh`, adding `ProviderOutcome::Cancelled` for
  caller-cancelled/dropped in-flight calls, and promoting V1-10 `openmettle.runs.queue.age`
  with `QUEUE_AGE_BUCKETS`, alongside V1-06 gateway failure/backfill signals, V1-17 overdue
  handoffs and `openmettle.storage.quota.drift`, V1-18 capacity grant, stale observation and
  wait duration signals, and V1-30 `openmettle.backup.runs`).
  `policy.max_data_point_streams` and `policy.max_prometheus_series_per_process` in
  `contracts/telemetry/v1.json` define the current ceilings; `tests/telemetry_contract.rs`
  checks them against `metrics::DESCRIPTORS`.
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
  (`DroppedSignal::ALL`) series from process startup, all 49 zero-initialized
  `openmettle.gateway.failures` (`GatewayStep::ALL × GatewayCause::ALL`) series on
  `openmettle-gateway` (omitted on `openmettle-api` and `openmettle-worker` when unrecorded),
  all four zero-initialized `openmettle.runs.queue.age` (`RunQueueAgeOutcome::ALL`)
  histogram points on `openmettle-api` and `openmettle-worker` (omitted on
  `openmettle-gateway` when unrecorded), and, on `openmettle-worker`, the zero-initialized
  `openmettle.quota.overdue.handoffs` series, all eight `openmettle.storage.quota.drift`
  `QuotaDriftOutcome::ALL` series, and all four `openmettle.backup.runs`
  `BackupRunOutcome::ALL` series, so Prometheus records a zero baseline before any first
  collector outage, gateway failure burst, slow queue exit, hourly drift, or backup
  failure/overdue event, encodes
  `ExportMetricsServiceRequest` via `opentelemetry-proto` (`metrics` feature enabled with zero
  new crates in `Cargo.lock`), and POSTs with `Content-Type: application/x-protobuf` over the
  ADR 0010 `Route`.
- Failures (non-2xx, timeout, DNS/TLS/transport error, or oversized body) drop the export
  cycle without retry, increment `openmettle.telemetry.dropped{signal="metric_exports"}`, and
  emit one `telemetry.dropped` event with `dropped_metric_exports` to stderr.
- On shutdown, trace and metrics export tasks drain concurrently within the existing half-slice
  of `shutdown_budget` and are aborted on deadline expiry.

### Deterministic alert rules

`contracts/telemetry/alerts-v1.yaml` defines eight Prometheus alert rules strictly over the
v1 metrics emitted today: `OpenMettleApiHighServerErrorRatio` (scoped to
`job="openmettle-api"` and excluding `healthz`/`readyz` probes),
`OpenMettleDatabaseReadinessFailing`, `OpenMettleTelemetryDropsDetected`
(`increase(openmettle_telemetry_dropped_total[15m]) > 0` with `for: 5m` so a single
collector outage transitions from zero baseline to `firing` and resolves cleanly),
`OpenMettleProviderTransportFailures` (covering all six outbound `operation` values
including `inference`, `mcp`, and `oauth_refresh` across API and worker),
`OpenMettleGatewayFailuresDetected`
(`sum by (step, cause) (increase(openmettle_gateway_failures_total[5m])) >= 3` with
`for: 2m`), `OpenMettleRunQueueHighAge` (detecting runs waiting over 60 seconds in
`openmettle_runs_queue_age_seconds_bucket` over a 10-minute window with `for: 5m`),
`OpenMettleStorageQuotaDriftDetected`
(`sum by (outcome) (increase(openmettle_storage_quota_drift_total{outcome!="healthy"}[3h])) > 0`
with `for: 5m` so any non-healthy ledger mismatch, filesystem drift, quarantined row,
verification error or timeout transitions from its worker zero baseline to `firing`, stays
continuously firing across jittered hourly maintenance sweeps, and resolves cleanly once
clear), and `OpenMettleBackupFailedOrOverdue`
(`sum by (outcome) (increase(openmettle_backup_runs_total{outcome=~"failed|incomplete|overdue"}[15m])) > 0`
with `for: 0m`, `severity: critical`, `component: backup` so any failed or incomplete backup run
or RPO overdue observation fires immediately from the worker's zero baseline).
`contracts/telemetry/alerts-v1-test.yaml` supplies deterministic positive and negative
`promtool test rules` cases for all eight alerts, executed alongside `promtool check rules`
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
