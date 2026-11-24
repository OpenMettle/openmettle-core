# 0026 — OTLP/HTTP protobuf trace export, off by default

Status: accepted with its implementation; V1-29 increment 2 of 4, 19 November 2026. Agent-authored; implements the
owner decisions recorded on #26 the same day. Owner approval of this record, independent
review and CI acceptance are separate gates. Refs #26. #26 remains open.

## Problem

ARCHITECTURE-v1.md requires OpenTelemetry export through OTLP, bounded export, exclusion of
prompts, responses, credentials, tool arguments and raw exception bodies, and a core that
keeps working when telemetry is down. [ADR 0024](0024-process-telemetry-and-redaction.md)
delivered increment 1: structured stderr events behind a default-deny guard, with no
network export. This record is increment 2: trace export to a collector such as Grafana
Alloy on port 4318.

The usual Rust exporter, `opentelemetry-otlp`, brings an HTTP or gRPC client of its own
(`reqwest` or `tonic`/`h2`), an async-runtime integration and a batch processor configured by
`OTEL_*` variables. Each would bypass the ADR 0010 transport bounds: destination policy, address
checks over every DNS answer, explicit rustls, no proxy, redirect or retry, and response limits.

## Owner decisions (#26, 19 November 2026)

1. **HTTPS only.** No plain `http://` collector URL. An optional PEM CA bundle
   (`OTLP_CA_FILE`) covers a cluster-CA collector certificate, and optional explicit private
   ranges (`OTLP_PRIVATE_RANGES`) reuse the ADR 0010 range parser.
2. **Option A′.** Link only the OpenTelemetry API, SDK span model, generated protobuf messages
   and the `tracing` bridge, at exact versions; send over the ADR 0010 core. `opentelemetry-otlp`,
   `opentelemetry-http`, `h2`, `tonic`, `reqwest`, `async-trait`, compression, `internal-logs`,
   `rt-tokio` and `tracing-log` must not enter the dependency tree.
3. **No probe spans.** `/healthz` and `/readyz` produce no exported span.

## Decision

### Configuration

The API and the worker read three keys under their own prefix (`OPENMETTLE_API_` or
`OPENMETTLE_WORKER_`), after `LOG_FORMAT` and `LOG_LEVEL` and before the API's `AUTH_CONFIG`:

| Key | Default | Values |
| --- | --- | --- |
| `OTLP_TRACES_ENDPOINT` | unset: export off | Canonical HTTPS URL with a DNS host, validated by the ADR 0010 endpoint parser |
| `OTLP_CA_FILE` | platform roots | Absolute path; a regular file of at most 1 MiB holding 1–256 PEM certificates, which replace the platform roots |
| `OTLP_PRIVATE_RANGES` | none | Comma-separated canonical CIDRs, each inside one RFC 1918, CGNAT or ULA block, at most 32, no duplicates or empty items |

- **Unset is off.** Without an endpoint the process creates no tracer provider, export task,
  DNS semaphore or socket. The subscriber is exactly the increment 1 stack, so startup,
  stderr and shutdown are unchanged.
- **A set key is never ignored.** `OTLP_CA_FILE` or `OTLP_PRIVATE_RANGES` without an endpoint
  is refused.
- **Refusals.** Exit 78 with one fixed line: `configuration error: invalid OTLP_TRACES_ENDPOINT`,
  `invalid OTLP_CA_FILE` or `invalid OTLP_PRIVATE_RANGES`, or `OTLP trust roots unavailable`
  when no CA file is given and the platform roots cannot be loaded. No value, path, URL or
  file content is printed. The CA file is read through the auth-config loader's bounded
  reader before telemetry is installed and before the listener opens.
- **The migrator is stderr-only.** It never reads these keys. `telemetry::Settings::parse`
  is unchanged for that reason; OTLP settings have their own `telemetry::otlp::Settings::parse`,
  called only by the serving configuration.
- **Ambient variables are neutralised.** Sampling (`Sampler::AlwaysOn`), span limits and the
  resource (`Resource::builder_empty()` with only `service.name = openmettle-{role}`) are
  set explicitly, so `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_TRACES_SAMPLER*`
  and `OTEL_SPAN_*_LIMIT` have no effect. The SDK's batch processor, which reads `OTEL_BSP_*`,
  is not used, and no crate that reads `OTEL_EXPORTER_OTLP_*` is linked. The transport never
  reads proxy variables.

### What is exported

- **One span per request.** The request middleware creates `http.server.request`, a root
  span of kind server, for every route except `/healthz` and `/readyz` (matched route
  template). Its fields are `request_id` (the server-generated UUIDv4), `http.route`,
  `http.request.method` and `http.response.status_code` (recorded as an integer when the
  response head is ready). The span is never entered, so nothing nests under it.
- **No inbound context.** The span has `parent: None`. No `TextMapPropagator` is installed,
  no global tracer provider is set and no context is extracted, so `traceparent` and
  `tracestate` are ignored by construction and every request starts its own trace.
- **Two guards.** The stderr `Guard` now admits events only, so the request span never adds
  span context to text lines. A second callsite filter, `SpanGuard`, sits in front of the
  `tracing-opentelemetry` layer and admits spans only: target exactly
  `openmettle_core::telemetry`, level `info` or below (independent of `LOG_LEVEL`) and every
  field in `SPAN_FIELDS` (`otel.kind` plus the four above; the bridge consumes `otel.kind` as
  the span kind). Third-party spans (`axum`, `hyper`, `sqlx`, `rustls`, `tower`), our own
  spans with other fields or levels, and every event, including our admitted log events, are
  invisible to the exporter.
- **Bridge settings.** No source location, thread, target, level or busy/idle attributes; no
  error-field mapping; no OpenTelemetry context activation.
- **Span limits.** At most 8 attributes and no events or links per span.

### Delivery

- **Processor.** A custom `SpanProcessor` offers each ended span to a bounded Tokio `mpsc`
  channel of 2048 with `try_send` and never waits. A full queue drops the span and adds it
  to an `AtomicU64`.
- **Export task.** One Tokio task collects up to 512 spans or waits at most 5 s, encodes
  `ExportTraceServiceRequest` with `group_spans_by_resource_and_scope` and
  `prost::Message::encode_to_vec`, and sends one `POST` with
  `Content-Type: application/x-protobuf` through `provider_http::transport::Route`. One batch
  is in flight at a time.
- **Transport.** The ADR 0010 core unchanged: canonical HTTPS endpoint, address policy over
  every DNS answer (private only through `OTLP_PRIVATE_RANGES`, metadata addresses never),
  rustls with ring and ALPN `http/1.1`, one request per connection with `Connection: close`,
  no proxy, redirect, retry, compression, client certificate or early data. The exporter owns
  its own DNS semaphore of 2 slots, separate from the provider transports' 8.
- **Bounds.** Request body at most 1 MiB, refused before any DNS work; response body at most
  64 KiB and 32 headers in 8 KiB; one 3 s deadline for each export, with setup clamped to it.
  The response body is read only to complete the exchange; an OTLP partial-success body is
  not decoded.
- **Failures.** A non-2xx status (3xx and 429 included), timeout, DNS, address, TLS or
  protocol failure, or an oversized batch drops the whole batch and adds its span count to the
  counter. Nothing is retried.
- **Drop reports.** After each cycle the task swaps the counter and, if it is non-zero, emits
  one `telemetry.dropped` event with `dropped_spans` at `error`. `dropped_spans` joins the
  stderr allowlist. The event is not a span, so it is never exported.

### Shutdown

`shutdown_budget` is unchanged: draining gets `SHUTDOWN_TIMEOUT_MS` less a flush slice of a
tenth, at most 250 ms. The slice now covers both sinks, before one deadline:

1. The tracer provider is shut down, which stops new spans and signals the task.
2. The task drains the queue and sends what it can; the process waits for it until half
   the slice has passed, then aborts it. Aborting drops any connection in progress, which
   closes its socket.
3. The stderr queue is flushed with the remainder of the slice.

Spans not sent before the abort are lost uncounted. The serving binaries now build their
runtime explicitly and call `shutdown_background()` after `run` returns. Before, `#[tokio::main]`
dropped the runtime, which waits for every blocking task. An abandoned operating-system DNS
lookup, which cannot be cancelled, could then hold the exit after the deadline. This
applies to the provider transport as well.

## Dependencies

All four direct crates are exact pins with default features off. `prost` is direct only so
that `Message::encode_to_vec` is in scope; it was resolved through `opentelemetry-proto`.

| Crate | Version | Features | Origin | Licence | Checksum (sha256) |
| --- | --- | --- | --- | --- | --- |
| opentelemetry | =0.33.1 | `trace` | https://github.com/open-telemetry/opentelemetry-rust | Apache-2.0 | 8c1f1a6ac9c875a4941e4c7c085b61e8f4daa326de03b4701768c3491a6ad9ee |
| opentelemetry_sdk | =0.33.1 | `trace` | https://github.com/open-telemetry/opentelemetry-rust | Apache-2.0 | 372a912db2974d1990207006fd0e3aa0ef3fd4ad3be43c65cfaadf2206866061 |
| opentelemetry-proto | =0.33.1 | `gen-tonic-messages`, `trace` | https://github.com/open-telemetry/opentelemetry-rust | Apache-2.0 | d576f5dddc3299341bcd85a04be17b2564844c0c9563214f02d85f2524d1afae |
| tracing-opentelemetry | =0.34.0 | none (no `tracing-log`, `metrics`) | https://github.com/tokio-rs/tracing-opentelemetry | MIT | 0a904802a1b902f43638b677ff2a650847e3b4404101b6c586d648e8c1e3e8fe |
| prost | =0.14.6 | none of its own | https://github.com/tokio-rs/prost | Apache-2.0 | 3ef0b569d1d907ab3a28596aee62cf1f61dacb0529a4bedcd8e7460e2d5228b4 |

New transitive packages in `Cargo.lock`:

| Crate | Version | Through | Origin | Licence | Checksum (sha256) |
| --- | --- | --- | --- | --- | --- |
| prost-derive | 0.14.6 | prost (proc macro) | https://github.com/tokio-rs/prost | Apache-2.0 | 1ad9c5423459fa2f729b8d9235fab810aa29628b171467744fc86d21460ad70d |
| anyhow | 1.0.104 | prost-derive (build time) | https://github.com/dtolnay/anyhow | MIT OR Apache-2.0 | 330a5ed07fa54e4702c9d6c4174f74427fc0ef6e214bbd677ae50a5099946470 |
| futures-executor | 0.3.34 | opentelemetry_sdk | https://github.com/rust-lang/futures-rs | MIT OR Apache-2.0 | 031b47cf1a3c6cc8bc2fc76cd437f521619387907d469316e7c0bc278f1f5432 |
| futures-macro | 0.3.34 | futures-util, as enabled by opentelemetry_sdk's default-feature futures-executor (proc macro) | https://github.com/rust-lang/futures-rs | MIT OR Apache-2.0 | 9fb9654ba8355388abeb8dcb4fc62f511300867002afc858860463bdd9fe0c44 |
| rand | 0.9.5 | opentelemetry_sdk (span and trace IDs) | https://github.com/rust-random/rand | MIT OR Apache-2.0 | b9ef1d0d795eb7d84685bca4f72f3649f064e6641543d3a8c415898726a57b41 |
| rand_chacha | 0.9.0 | rand | https://github.com/rust-random/rand | MIT OR Apache-2.0 | d3022b5f1df60f26e1ffddd6c66e8aa15de382ae63b3a0c1bfc0e4d3e3f325cb |
| rand_core | 0.9.5 | rand | https://github.com/rust-random/rand | MIT OR Apache-2.0 | 76afc826de14238e6e8c374ddcc1fa19e374fd8dd986b0d2af0d02377261d83c |
| web-time | 1.1.0 | tracing-opentelemetry, wasm32 only; not compiled on supported targets | https://github.com/daxpedda/web-time | MIT OR Apache-2.0 | 5a6580f308b1fad9207618087a65c04e7a10bc77e02c8e84e9b00dd4b12fa0bb |

`futures-util` already in the lockfile gains its `futures-macro` dependency. Every new package
has a generated record in `provenance/cargo-reviews.json` with outcome `allowed` under the
owner-approved allow-list (`python3 scripts/provenance.py review-cargo`). Those records are
licence bookkeeping, not clearance.

`scripts/check_repository.py` now fails if `Cargo.lock` contains `h2`, `tonic`, `reqwest`,
`hyper-rustls`, `opentelemetry-otlp`, `opentelemetry-http`, `async-trait`, `tracing-log`,
`flate2`, `zstd` or `zstd-sys`. It checks the whole lockfile, so a dev dependency is refused
too. That is stricter than the owner's normal-dependency rule; relax it in a later record if
a test ever needs one of them. `cargo tree -e normal -i` reports each of them absent.

## Clarification to ADR 0024

ADR 0024's Delivery section says the stderr queue is a `std::sync::mpsc::sync_channel` used
with `try_send`. The implementation merged with it is a `Mutex<VecDeque>` with a capacity,
two condition variables and accepted and handled counters, so that the exit flush can wait for
exactly the lines accepted before it. The behaviour ADR 0024 describes (1024 lines, never
waiting, drop and count, one report after the next write) is unchanged.

## Limits

- **Values are not inspected.** As in ADR 0024, guards check targets, field names and levels.
  A future span on our target that passed request-derived text through an allowlisted field
  would be exported. Typed constructors and review are the control.
- **No collector authentication.** No header or client certificate is sent. The collector
  must be reachable only on a trusted network path, and its TLS identity comes from the CA
  bundle or the platform roots.
- **Partial success is not read.** A 2xx response with `rejected_spans` counts as delivered.
- **Loss on shutdown.** Spans queued at shutdown get at most half the flush slice (at most
  125 ms); what is not sent is lost without a count.
- **Interest sharing in tests.** In production one global dispatcher gives the request span's
  callsite `never` interest when export is off, so the span is disabled outright. Library
  tests install per-thread subscribers that share callsite interest, so they assert the
  observable result (no output, no span context) rather than `Span::is_disabled`.
- **No metrics or logs over OTLP.** Increment 3 adds `contracts/telemetry/v1.json` and typed
  metrics; logs stay on stderr for node collection.
- **No cluster qualification.** Export to a real Alloy collector over the cluster CA is
  increment 4 (kind qualification). Nothing here claims a deployed collector works.

## Evidence

Local, without PostgreSQL, a cluster or external network:

- `telemetry::tests::otlp` (library):
  - TLS HTTP/1.1 export to an in-process synthetic-CA collector through the production stack
    and the served routes. The collector sees `POST /v1/traces HTTP/1.1` with exactly `host`,
    `connection: close`, `content-type: application/x-protobuf` and `content-length`. The
    prost-decoded request holds one root server span for each of the two non-probe requests,
    with exactly the four allowlisted attributes, a fresh trace ID that is not the inbound
    `traceparent`, no events or links, scope `openmettle_core::telemetry` and the single
    resource attribute `service.name = openmettle-api`. `GET /healthz`, `GET /readyz` and
    `POST /healthz` produce no span. Third-party spans and events, our spans with unlisted
    fields or below `info`, and our admitted events produce nothing; no planted canary is
    exported or written to stderr.
  - A collector that accepts TCP and never reads: 10,000 spans emitted without blocking,
    health probes answering within a second, exactly 10,000 spans reported in exactly four
    `telemetry.dropped` events (one per cycle) after four connections with no retry, and a
    stop with a 100 ms deadline that returns in under 500 ms and closes the stalled socket.
  - Failure isolation: 307 redirect (no connection to its target), 500, 429, a 64 KiB + 1
    response, a certificate for another host and a private address without an allowlisted
    range each drop exactly the three-span batch, with at most one request and one
    connection, at most one report, and the served probe still answering. A 200 drops
    nothing.
  - An oversized batch is dropped with zero DNS lookups and zero connections.
  - DNS isolation: hung exporter lookups exhaust its two slots while a provider transport on
    the process-wide pool still resolves and completes a TLS request.
  - Settings: accepted and refused endpoints, CA paths and ranges; orphaned keys refused;
    unusable CA files refused at load; key order after `LOG_*` and before `AUTH_CONFIG`
    for the API, and the same keys for the worker.
  - Without export the request span produces no output and adds no span context.
- `provider_keys::tests::telemetry`: the auth-router canary test now also installs the span
  layer with a collector. The four sign-in routes and the fallback each produce one span, the
  probes none, and none of the planted canaries is exported.
- `tests/runtime.rs` (binaries):
  - API and worker with ambient `OTEL_EXPORTER_OTLP_*` variables pointing at a local listener,
    canary headers, service name and resource attributes, and proxy variables: zero
    connections to either listener, stderr exactly `process.started`, `process.stopping`,
    `process.stopped`, and no canary.
  - Invalid `OTLP_*` values for both binaries exit 78 with the exact fixed line and no canary.
  - The API with export configured to `collector.localhost` and every proxy variable set:
    zero proxy connections, requests served, SIGTERM exit 0 in under 2 s with
    `SHUTDOWN_TIMEOUT_MS=1000`, and only lifecycle or `telemetry.dropped` events.
- `scripts/tests/test_check_repository.py`: the lockfile ban reports each banned name exactly
  and the committed lockfile has none.
