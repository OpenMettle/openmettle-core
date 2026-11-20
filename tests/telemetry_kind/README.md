# Telemetry contract `kind` qualification (V1-29 Increment 4)

This directory qualifies the V1-29 telemetry contract ([`contracts/telemetry/v1.json`](../../contracts/telemetry/v1.json)) and deterministic Prometheus alert rules ([`contracts/telemetry/alerts-v1.yaml`](../../contracts/telemetry/alerts-v1.yaml)) on an ephemeral [kind](https://kind.sigs.k8s.io/) cluster (ADR 0028). The manifests are test fixtures only; they are not an installer, Helm chart, or production telemetry deployment.

## What the run proves

| Check | Observed through |
| --- | --- |
| Alert rule syntax and firing/non-firing thresholds | `promtool check rules` and `promtool test rules` against [`contracts/telemetry/alerts-v1-test.yaml`](../../contracts/telemetry/alerts-v1-test.yaml) in the pinned Prometheus v3.5.0 image |
| Live Prometheus loads all 4 v1 alerts cleanly | Prometheus `/api/v1/rules` (`health == "ok"`) |
| HTTPS OTLP/HTTP protobuf trace ingestion & redaction | Grafana Alloy `/metrics` (`otelcol_receiver_accepted_spans_total`) and `otelcol.exporter.debug` logs with synthetic canary `traceparent`, `Authorization`, and query secret verified absent |
| HTTPS OTLP/HTTP protobuf metrics ingestion & translation | Prometheus `/api/v1/query` (`openmettle_http_server_requests_total`, `openmettle_http_server_request_duration_seconds_count`, `openmettle_db_readiness_checks_total`) for both `openmettle-api` and `openmettle-worker` with distinct UUIDv4 `instance` (`service.instance.id`) |
| Closed-enum cardinality & zero disallowed labels | Every live `{__name__=~"openmettle_.*"}` series validated against `contracts/telemetry/v1.json` |
| Collector-outage resilience & drop alert firing | Single event-driven Alloy scale-to-0 outage from zero-initialized `openmettle_telemetry_dropped_total` baseline while probing `/healthz` and `/readyz` at 4 Hz (0 failures, 0 restarts), `telemetry.dropped` in `openmettle-api` stderr JSON logs, `openmettle_telemetry_dropped_total{signal="metric_exports"}` increasing from `0` to `>= 1` in Prometheus, and `OpenMettleTelemetryDropsDetected` reaching `firing` in Prometheus `/api/v1/rules` |
| Clean SIGTERM shutdown with OTLP exporters active | Exit code 0 for both `openmettle-worker` and `openmettle-api` containers |

## Safety guards

`qualify.py` reuses the safety guards from [`tests/kubernetes/qualify.py`](../kubernetes/qualify.py):

- Refuses to run (exit 3) unless `OPENMETTLE_K8S_QUALIFICATION=isolated-dev` and `OPENMETTLE_K8S_DOCKER_CONTEXT` points to a local `unix://` Docker context.
- Uses a uniquely named `dev` cluster (`openmettle-dev-telemetry-<8 hex>`), a temporary kubeconfig, and an ephemeral per-run RSA-2048 CA whose private key is deleted immediately after signing the collector certificate.
- Enforces the `restricted` Pod Security Standard on `openmettle-qualification`.
- Deletes only the cluster and local image tags it created; any cleanup failure fails the run and retains the temporary kubeconfig for recovery.

## Running it

CI runs [`.github/workflows/telemetry-qualification.yml`](../../.github/workflows/telemetry-qualification.yml) on GitHub-hosted `ubuntu-24.04`.

```sh
python3 -m unittest discover -s tests/telemetry_kind -v   # guards, TLS, fixtures and validators (no cluster)
```

For an isolated local run on a disposable Linux amd64 Docker daemon:

```sh
bash tests/kubernetes/install-tools.sh "$(mktemp -d)/tools"
OPENMETTLE_K8S_QUALIFICATION=isolated-dev OPENMETTLE_K8S_DOCKER_CONTEXT=default \
  python3 tests/telemetry_kind/qualify.py --tools-dir <that directory>/tools --report /tmp/telemetry-qualification.json
```

## Pinned test fixtures

| Fixture | Pin | Origin | Licence |
| --- | --- | --- | --- |
| Prometheus + `promtool` | `docker.io/prom/prometheus:v3.5.0@sha256:63805ebb8d2b3920190daf1cb14a60871b16fd38bed42b857a3182bc621f4996` | https://github.com/prometheus/prometheus | Apache-2.0 |
| Grafana Alloy | `docker.io/grafana/alloy:v1.10.0@sha256:1bc130e909116a4bf950eb5187a346007d3b796f96832b529acb14a64e41230f` | https://github.com/grafana/alloy | Apache-2.0 |
| `kind`, `kubectl`, node image, PostgreSQL | Reused directly from [`tests/kubernetes/qualify.py`](../kubernetes/qualify.py) | See [`tests/kubernetes/README.md`](../kubernetes/README.md) | Apache-2.0 / PostgreSQL |

Prometheus and Grafana Alloy multi-arch Docker Hub index digests were resolved on 20 November 2026. These images are test-only fixtures and are not distributed.
