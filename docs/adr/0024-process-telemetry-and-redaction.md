# 0024 — Process telemetry and default-deny redaction

Status: proposed V1-29 increment 1 of 4, 19 November 2026. Agent-authored; owner approval,
independent review and CI acceptance are separate gates. Refs #26; Refs #34. #26 remains
open. Number 0023 is reserved for native sign-in (V1-04 block C).

## Problem

ARCHITECTURE-v1.md (Telemetry and operational analysis) requires OpenTelemetry export
through OTLP, a versioned telemetry contract beside each service API, and the exclusion of
prompts, responses, credentials, tool arguments and raw exception bodies. IDs must never be
metric labels, export must be bounded, and the core must keep working when telemetry is down.

Before this change the processes wrote ad-hoc `eprintln!` lines and had no structured
output. ADRs 0017, 0019 and 0022 require telemetry redaction before the login routes are
mounted. Without it, an access log or trace could capture callback codes and states, login
and session cookies, or invitation codes from initiation bodies.

## Decision

### Contract direction

Telemetry is delivered in four increments:

1. This change: a tracing foundation with a default-deny redaction guard.
2. OTLP export, off by default.
3. `contracts/telemetry/v1.json` with typed metrics.
4. kind qualification.

Throughout, the following rules hold:

- Telemetry carries classifications, durations, counts and server-generated opaque IDs only.
- User and scope IDs are excluded.
- IDs are never metric labels.
- An inbound `traceparent` or request-ID header is ignored.
- Structured logs go to stderr for node collection and are not sent over OTLP.

### Increment 1 scope

- `tracing` and `tracing-subscriber` only. No OpenTelemetry crate is linked, so nothing is
  exported and no telemetry socket is opened.
- `src/telemetry.rs` is the only emitter, through typed constructors.
- A request-ID middleware covers the served `/healthz` and `/readyz` routes and their fallback.
- Lifecycle events for the API, worker and migrator.
- `LOG_FORMAT` and `LOG_LEVEL` settings.

### Redaction mechanism

1. **Typed source.** Each event comes from a function in `src/telemetry.rs`. Identifiers
   are server-generated UUIDv4 newtypes. Every other value is an enum, a duration or a
   count. No constructor accepts free text, a request target, a header, a body, a
   configuration value or an error's `Display` or `Debug` output.
2. **Callsite guard.** A per-layer `Filter` sits in front of the only sink. Its
   `callsite_enabled` returns `Interest::never()` when the callsite's target is not exactly
   `openmettle_core::telemetry`, a field name is outside the allowlist, or the level exceeds
   `LOG_LEVEL`. `enabled` repeats the same check, because a callsite shared with another
   dispatcher is re-evaluated per use.
   - **Allowlisted fields:** `event`, `role`, `signal`, `request_id`, `http.route`,
     `http.request.method`, `http.response.status_code`, `duration_us`, `error.type` and
     `schema_version`.
   - **`message` is not allowlisted,** so a formatted free-text event never reaches the sink.
   - **Third-party targets are refused,** including sqlx, hyper, rustls and openidconnect.
     This covers their spans too.
   - **No `log` bridge** (`tracing-log`) is installed, and no `log` logger is set, so crates
     that log through `log` are not collected.
3. **Requests.** The middleware records:
   - `http.route`: the matched route template from `axum::extract::MatchedPath`, or
     `unmatched`;
   - `http.request.method`: a closed method set, with `_OTHER`;
   - `http.response.status_code`;
   - `duration_us`;
   - `request_id`: a fresh UUIDv4, also placed in request extensions for handlers.

   It never records `url.full`, a path, a query, a header, a cookie or a body. The event is
   `debug` for a status below 500 and `warn` for a server error, so frequent health probes
   stay quiet at the default level.
4. **Database settings** never reach telemetry. `Config` and `PgConnectOptions` are not
   passed to any constructor. Failures are classified at our own call sites.

### Configuration

Each process reads two keys under its existing prefix (`OPENMETTLE_API_`,
`OPENMETTLE_WORKER_` or `OPENMETTLE_MIGRATE_`), after its existing keys:

| Key | Default | Values |
| --- | --- | --- |
| `LOG_FORMAT` | `json` | `json` or `text`, matched exactly |
| `LOG_LEVEL` | `info` | `error`, `warn`, `info` or `debug`, matched exactly. No `trace` and no filter directives |

An invalid value exits 78 with one fixed line, `configuration error: invalid LOG_FORMAT` or
`... LOG_LEVEL`, which never includes the value. This extends the settings in ADRs 0002 and
0003. The process contract is unchanged.

### Events

| Event | Level | Fields besides `event` |
| --- | --- | --- |
| `process.started` | info | `role` |
| `process.stopping` | info | `role`, `signal` |
| `process.stopped` | info | `role` |
| `process.failed` | error | `role`, `error.type` (`SignalRegistration`, `Bind`, `Server`, `Shutdown`, `ShutdownDeadline`) |
| `migration.started` | info | `role` |
| `migration.completed` | info | `role`, `schema_version` |
| `migration.failed` | error | `role`, `error.type` (a `migrate::Failure` class) |
| `migration.interrupted` | warn | `role`, `signal` |
| `http.request.completed` | debug or warn | `request_id`, `http.route`, `http.request.method`, `http.response.status_code`, `duration_us` |

Each JSON line is one object with `timestamp`, `level` and these fields at the top level.

### Output kept outside telemetry

The following lines are unchanged. Tests and operator documentation rely on them.

- **`configuration error: ...`** stays one fixed stderr line, written before telemetry is
  installed, because its own settings may be the invalid ones.
- **`--check-auth-config`** keeps all its output (ADRs 0015 and 0020). It never installs
  telemetry.
- **The migrator** keeps `schema is at migration N` on stdout and `migration error: ...` on
  stderr. The detail (category, version, SQLSTATE, and role and object names) follows
  ADR 0003. `migration.failed` adds only the class.

The serving processes' `runtime error: ...` lines and the migrator's
`migration interrupted` and signal-registration lines are replaced by events.

## Dependencies

| Crate | Version and features | Origin | Licence | Notes |
| --- | --- | --- | --- | --- |
| tracing | =0.1.44, defaults off, `std` | https://github.com/tokio-rs/tracing | MIT | Already locked through sqlx; now direct |
| tracing-subscriber | =0.3.23, defaults off, `std`, `registry`, `fmt`, `json` | https://github.com/tokio-rs/tracing | MIT | **New.** No `env-filter`, `ansi` or `tracing-log` |
| tracing-serde | 0.2.0 | https://github.com/tokio-rs/tracing | MIT | **New**, through `json` |
| sharded-slab | 0.1.7 | https://github.com/hawkw/sharded-slab | MIT | **New**, through `registry` |
| thread_local | 1.1.10 | https://github.com/Amanieu/thread_local-rs | MIT OR Apache-2.0 | **New**, through `registry` |
| valuable | 0.1.1 | https://github.com/tokio-rs/valuable | MIT | **New** in `Cargo.lock` only; gated on `cfg(tracing_unstable)` and not compiled |

axum's `matched-path` feature is enabled. It adds no crate. Every new package has a
generated record in `provenance/cargo-reviews.json` with outcome `allowed` under the
owner-approved allow-list. Those records are licence bookkeeping, not clearance.

## Limits

- **Process scope only.** Ingress, proxy and collector access logs are outside this code.
  Before the login routes are mounted, the deployment must also stop ingress and proxies
  recording request targets, cookies and bodies. Collector-side allowlists belong to
  packaging (V1-32) and the owner's stack repository.
- **Values are not inspected.** The guard checks targets, field names and levels, not
  values. A future constructor that passes request-derived text through an allowlisted
  field would not be caught by the guard. Typed constructors and review are the control.
  A repository hygiene check that refuses `tracing::` or `log::` macros outside
  `src/telemetry*` has not been added.
- **Panics.** The Rust runtime's default panic hook writes panic messages to stderr, outside
  telemetry. A panic payload could contain data.
- **Spans.** No spans are emitted yet. Correlation within a request uses `request_id` on the
  completion event. Spans arrive with OTLP export in increment 2.
- **Route templates are server-defined but operator-configurable.** The login paths come
  from the browser-routing profile (ADR 0020). They are bounded literals, not client input.
- **Missing request ID.** If the operating system's random source fails, the request is
  still served and its event carries no `request_id` rather than an invented one.

## Evidence

Local, without PostgreSQL:

- `cargo test --locked --offline --lib telemetry`:
  - settings defaults, accepted values and refusals;
  - settings ordering after the existing serving keys;
  - request IDs as fresh canonical v4 UUIDs;
  - the guard refusing unlisted fields, foreign and look-alike targets, the module's own
    default target, formatted messages and a foreign span, in both formats;
  - level bounds;
  - each constructor's exact fields;
  - the served health routes, through the production stack, recording only the template,
    method, status and a server-generated ID. The test plants canaries in the database
    password, query, cookie, headers, path and body, and supplies a client request ID.
- `provider_keys::tests::telemetry` (the canary test):
  - drives the unmounted login and session router, merged with the health routes and
    observed by the production middleware, under the production stack in both formats;
  - plants canaries in the database password, the login key, the login and session
    cookies, the callback code and state, an invitation code, a run payload body,
    `Authorization` and a client `X-Request-Id`;
  - asserts that none appears, and that exactly one event per request does (the positive
    control). With the guard opened, sqlx's `.pgpass` notice reaches the sink and the test
    fails.
- `tests/runtime.rs`:
  - exit 78 with the fixed line for invalid `LOG_*` values;
  - the real API binary in JSON at `debug` and the worker in text at `warn`, with canaries
    planted;
  - lifecycle order, stderr only, and the bind-failure event.
- `tests/schema.rs`: the migrator exits 78 for invalid `LOG_*` values.

PostgreSQL-backed migrator tests were not run locally. They check stderr substrings that
this change keeps.
