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
  It also covers the browser sign-in routes when
  [ADR 0025](0025-browser-auth-runtime-mounting.md) mounts them.
- Lifecycle events for the API, worker and migrator.
- `LOG_FORMAT` and `LOG_LEVEL` settings.
- Non-blocking delivery to stderr, and a panic hook that writes one fixed event.

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
     `http.request.method`, `http.response.status_code`, `duration_us`, `error.type`,
     `schema_version` and `dropped_lines`.
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
5. **Panics.** `telemetry::install` replaces the default panic hook, which writes the
   payload and location. The replacement writes one `process.panicked` event with only
   `role`, waits at most 250 ms for queued lines to be written (the panicking thread waits
   that long only if stderr is stalled), and returns. Unwinding or
   abort then proceeds as before: a panic on the main thread exits 101, and a panic in a
   request task ends that task. The default hook still applies before telemetry is
   installed and in `--check-auth-config`, neither of which formats request or secret data
   into a panic.

### Delivery

ARCHITECTURE-v1.md requires the core to keep operating when telemetry is unavailable. An
unread stderr pipe must not stop serving. The guard and formatter run on the emitting thread,
usually a Tokio worker, so a synchronous write to a full pipe would block request handling,
liveness and shutdown. Delivery is therefore decoupled, using only the standard library:

- **Queue.** The formatting layer's writer offers each finished line to a bounded
  `std::sync::mpsc::sync_channel` of 1024 lines with `try_send`, and never waits. The guard
  has already run, so refused events are neither queued nor counted.
- **Writer thread.** One dedicated thread (`telemetry-writer`) writes queued lines to stderr.
  It is the only code that can block on the stream.
- **Drop accounting.** A line is dropped and counted when the queue is full, the writer
  thread has stopped or the write fails. After its next successful write, the writer writes
  one `telemetry.dropped` event with `dropped_lines`, the count since the last report, and
  resets the count. The report goes through the same guard and formatter, on a private
  stack on the writer thread, so it is never queued behind the lines it reports. It is
  `error`, so it shows at every configured level.
- **Exit flush.** Before exiting, a process waits for the lines queued so far, with a bound.
  The serving processes split `SHUTDOWN_TIMEOUT_MS` so that the whole stop fits it: draining
  gets the deadline less a tenth of it, at most 250 ms, and the flush gets the remainder. The
  migrator has no shutdown setting and waits at most 250 ms. If the bound passes, the
  process exits and the unwritten lines are lost.
- **Plain lines stay synchronous.** `configuration error:` is written before telemetry is
  installed. The migrator's result lines are its operator output (ADR 0003). Both are
  single synchronous writes in a one-shot path, not in request handling.

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
| `process.panicked` | error | `role` |
| `migration.started` | info | `role` |
| `migration.completed` | info | `role`, `schema_version` |
| `migration.failed` | error | `role`, `error.type`: the `migrate::Failure` class (`Invalid`, `ConnectTimeout`, `Connect`, `Check`, `Refused`, `Violated` or `Migrate`), or `SignalRegistration` when signal handlers could not be installed before the run |
| `migration.interrupted` | error | `role`, `signal`. The run exits 1, so it is visible at every level |
| `http.request.completed` | debug or warn | `request_id`, `http.route`, `http.request.method`, `http.response.status_code`, `duration_us` |
| `telemetry.dropped` | error | `dropped_lines` (and `dropped_spans` / `dropped_metric_exports` when OTLP export is enabled; ADRs 0026 and 0028) |

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
`migration interrupted` and signal-registration lines are replaced by events. If telemetry
itself cannot be installed, the process exits 1 with one fixed line, `runtime error:
telemetry subscriber already installed` or `runtime error: telemetry writer could not
start`.

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
- **Panics before installation.** The default panic hook applies until telemetry is
  installed, and throughout `--check-auth-config`. Those paths parse configuration and do
  not format secret values into panics, but this is not enforced.
- **Lost lines.** Under a stalled or slow reader, lines are dropped rather than delayed. The
  `telemetry.dropped` count shows how many, not which. If stderr never recovers, neither the
  dropped lines nor the count are written. Up to 1024 queued lines (a few hundred kilobytes)
  are held in memory.
- **Shutdown deadline.** Draining now gets slightly less than `SHUTDOWN_TIMEOUT_MS`
  (4750 ms of the 5000 ms default), so the final flush fits inside it.
- **Spans.** No spans are emitted yet. Correlation within a request uses `request_id` on the
  completion event. Spans arrive with OTLP export in increment 2.
  [ADR 0026](0026-otlp-trace-export.md) adds them, off by default, restricts this guard to
  events, adds `dropped_spans` to the allowlist and clarifies the queue described under
  Delivery (a bounded `VecDeque`, not a `sync_channel`).
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
- `cargo test --locked --offline --lib telemetry` also covers delivery, with a stand-in
  stderr whose writes block until released, or forever:
  - ten thousand lines and ten thousand events are emitted promptly while the writer is
    blocked, and the flush gives up at its bound;
  - a full queue drops and counts lines, and one `telemetry.dropped` report with the exact
    count follows the next successful write, in both formats, with no second report;
  - refused events are neither queued nor counted;
  - the shutdown split keeps draining plus flush equal to the deadline.
- `migrate::tests::failures_map_to_their_own_telemetry_class` pins each `migrate::Failure`
  to its `error.type`.
- `tests/runtime.rs`:
  - exit 78 with the fixed line for invalid `LOG_*` values;
  - the real API binary in JSON at `debug` and the worker in text at `warn`, with canaries
    planted;
  - lifecycle order, stderr only, and the bind-failure event;
  - the worker at the defaults (JSON, `info`): exactly `process.started`,
    `process.stopping` (`SIGINT`) and `process.stopped`, with `role=worker`;
  - the API at `debug` with a stderr pipe that is never read: 3000 keep-alive health checks
    each answer within a second, failed readiness checks return within a second, and
    SIGTERM exits 0 within 2 s with `SHUTDOWN_TIMEOUT_MS=1000`. Before this change the
    pipe filled after a few hundred lines and the probes hung.
- `tests/panic_hook.rs`: the hook is process-wide, so the test re-executes its own binary,
  filtered to that one test, as a child that installs telemetry on its real stderr and panics
  with a canary in the message, on the test thread in JSON and text and on a spawned thread.
  Stderr holds exactly one `process.panicked` line, and neither stream holds the canary,
  `panicked at` or a source location. It is an ordinary test target, so the manifest declares
  no extra target and the image build, which copies no tests, is unaffected.
- `tests/schema.rs`, without PostgreSQL:
  - the migrator exits 78 for invalid `LOG_*` values with only the fixed line;
  - a connection deadline and a refused connection each report `migration.started` and
    `migration.failed` with `ConnectTimeout` or `Connect`, beside the unchanged
    `migration error:` line;
  - SIGTERM (JSON) and SIGINT (text) during the connection attempt, at `LOG_LEVEL=error`,
    exit 1 with exactly one `migration.interrupted` line.

PostgreSQL-backed migrator tests were not run locally. They check stderr substrings that
this change keeps.
