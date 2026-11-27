# Telemetry Access Control, Retention, and Sampling Policy

This runbook defines the operator boundary for OpenMettle operational telemetry
(structured stderr logs, OTLP traces, and OTLP/Prometheus metrics) governed by
[`contracts/telemetry/v1.json`](../../contracts/telemetry/v1.json) and
[ADR 0028](../adr/0028-telemetry-contract-and-metrics.md).

## 1. Infrastructure-operator-only reader boundary

Operational telemetry is strictly an **infrastructure-operator-only** surface
(`policy.access_control.audience = "infrastructure_operator_only"` in `contracts/telemetry/v1.json`):

- **Never exposed on `/v1/*`:** `openmettle-api` exposes no application endpoint for
  reading raw logs, trace spans, Prometheus metrics, or collector backends
  (`exposed_via_product_api = false`).
- **Never granted by tenant or project roles:** Neither `account_admin`, project
  `owner`/`editor`/`viewer` roles, nor resource shares grant read access to telemetry
  backends, Grafana/Prometheus dashboards, or Alloy/OTel collectors
  (`granted_by_tenant_or_project_roles = false`).
- **Separate credentials and network plane:** Telemetry backends and query interfaces must
  use separate infrastructure-operator authentication and network policies, completely
  isolated from OpenMettle browser cookies (`__Host-openmettle-session`) and native
  application sessions.
- **No collector-side content expansion:** Core processes enforce default-deny allowlists
  (`telemetry::FIELDS` and `telemetry::SPAN_FIELDS`) and never emit prompts, responses,
  documents, credentials, tool arguments, raw exception bodies, cookies, authorization
  headers, query strings, `user_id`, `scope_id`, raw `claim_token`, or raw `fence_token`.
  Deployments must also disable request-target/query/cookie/body capture on ingress and
  reverse proxies before exposing sign-in or `/v1` routes.

## 2. Independence from product memory and authorization audit

Telemetry retention and sampling are completely independent of product data and
compliance/audit stores:

- **Product memory (`independent_from_product_memory = true`):** Deleting, purging, or
  configuring retention windows for product conversations, artifacts, Graphiti memory, or
  Chroma vectors does not depend on telemetry stores, and telemetry backends must never
  serve as a shadow store for user content.
- **Authorization audit (`independent_from_authorization_audit = true`):**
  `openmettle.authorization_audit` in PostgreSQL is the authoritative, append-only
  security and administrative audit trail. Operational logs, traces, and metrics are
  best-effort diagnostic signals (bounded queues drop under backpressure) and never
  replace or share retention schedules with `openmettle.authorization_audit`.

## 3. Retention ceilings and sampling policy

### Retention ceilings

- **Contract v1 baseline defaults (`contracts/telemetry/v1.json`):**
  - **Traces:** `72 hours` (`traces_hours: 72`)
  - **Logs:** `7 days` (`logs_days: 7`)
  - **Metrics:** `14 days` (`metrics_days: 14`)
- **Operator-confirmed jurisdiction ceilings:** Deployments may configure shorter windows
  or explicitly approved longer operational windows (for example, up to `logs: 30d`,
  `traces: 14d`, `metrics: 90d` where locally justified and permitted), provided every
  signal's backend retention policy is explicitly approved for the deployment's legal
  jurisdiction and documented before enabling OTLP export
  (`requires_jurisdiction_retention_confirmation = true`). Never leave telemetry backends
  on unbounded ("infinite") retention.

### Sampling and export defaults

- **Off by default:** OTLP trace and metrics export stay completely disabled until
  `OTLP_TRACES_ENDPOINT` and/or `OTLP_METRICS_ENDPOINT` are explicitly set under the
  process prefix. Ambient `OTEL_*` environment variables have no effect.
- **Trace sampling when enabled:** Processes ignore inbound `traceparent`/`tracestate`
  headers and sample locally emitted root spans (`http.server.request` excluding
  `/healthz` and `/readyz`, `worker.run`, and `capacity.grant`) plus child `worker.operation`
  spans with parent-consistent always-on sampling (`Sampler::AlwaysOn` in `openmettle-core`;
  collectors may apply tail or head sampling downstream).
- **Aggregate metrics independent of trace sampling:** All 19 v1 counters and histograms
  in `contracts/telemetry/v1.json` (at most 536 data-point streams / 1,628 Prometheus
  series per process) are recorded directly in-process and exported independently of
  whether traces are enabled or downstream-sampled. Never reconstruct request, error, or
  queue counts by summing sampled traces.

## 4. Pre-enablement operator confirmation checklist

Before setting `OTLP_TRACES_ENDPOINT` or `OTLP_METRICS_ENDPOINT` in a staging or
production deployment, the infrastructure operator must confirm and record each item:

- [ ] **Jurisdiction retention confirmed:** Configured backend retention ceilings for
      logs, traces, and metrics match or sit below the approved ceiling for the
      deployment's jurisdiction, and automated expiry/compaction is enabled on every store.
- [ ] **Reader boundary enforced:** Prometheus, Alloy/OTel collectors, log aggregators,
      and trace stores are reachable only by infrastructure operators over authenticated,
      isolated paths—never through `/v1/*` and never delegated to `account_admin` or
      project roles.
- [ ] **TLS and private egress pinned:** `OTLP_CA_FILE` pins the collector CA bundle (or
      verified platform roots) and `OTLP_PRIVATE_RANGES` restricts private CIDRs strictly
      to the collector subnet.
- [ ] **Ingress/proxy redaction verified:** Edge proxies do not log query strings,
      `Cookie`, `Authorization`, callback codes, or request/response bodies.
- [ ] **Alert rules loaded:** All 8 rules in `contracts/telemetry/alerts-v1.yaml` are
      validated with `promtool check rules` and loaded into Prometheus/Alertmanager with
      operator routing configured.
- [ ] **Failure isolation verified:** Collector downtime produces bounded drops
      (`openmettle_telemetry_dropped_total` and `telemetry.dropped` stderr events)
      without blocking `/healthz`, `/readyz`, API traffic, or worker execution.
