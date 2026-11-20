# 0025 — Browser sign-in runtime mounting, off by default

Status: proposed V1-04 implementation contract, 19 November 2026. Agent-authored; owner
approval, independent review and CI acceptance are separate gates. Refs #5; Refs #34.
#5 remains open.

## Problem

ADRs 0015–0020 built and qualified the browser sign-in stack: the settings loader, the
pooled service, the handoff and its bounded router. Each record ends with the same open
item, runtime enablement. No process loaded the settings, constructed the service or
mounted a route, so the stack could only be exercised by tests that assemble it themselves.
ADR 0024 supplied the redacting request telemetry that ADRs 0017, 0019 and 0022 required
before any route is served.

## Decision

`openmettle-api` gains one optional setting. When it is unset, nothing changes.

| Setting | Default | Meaning |
| --- | --- | --- |
| `OPENMETTLE_API_AUTH_CONFIG` | unset | Absolute path of a version-2 auth settings document (ADR 0020) |

- **Unset.** The API loads no auth file, constructs no service, serves `/healthz` and
  `/readyz` only and answers `404` on every sign-in path. This is the behaviour before this
  change, and it is the default of the image and of the Kubernetes qualification fixture.
- **Set.** At startup the API loads the document through `auth_config::load_browser`, which
  is the ADR 0015 loader plus a requirement that the browser profile is present. It builds
  `BrowserAuth` on the primary pool, `LoginHandoff` and `router_with_sessions` from the
  validated `BrowserProfile`, merges that router with the operational routes and wraps the
  result in `telemetry::observe`.
- **Worker and migrator.** The worker never reads `OPENMETTLE_WORKER_AUTH_CONFIG` or the
  API's key and never mounts a sign-in route. `Config::parse` asks for `AUTH_CONFIG` only
  for the API role. The migrator is unchanged.
- **Native sign-in is not mounted.** ADR 0023 leaves its settings-document form and runtime
  construction to a separate increment. Nothing in this change constructs `NativeAuth`.

> [ADR 0029](0029-native-sign-in-mounting-and-session-context.md) mounts native sign-in beside these routes when the same
> document has the optional `native` member, over the same service and pool.

There is no serve flag, live reload or second pool. Changed files take effect at the next
start. `--check-auth-config PATH` is unchanged for both versions (ADRs 0015 and 0020).

### Startup contract

The order is: serving configuration, auth settings, telemetry, signal handlers, listener.
A refusal in the first two steps is a configuration error: exit 78, one fixed stderr line,
no telemetry event and no listener.

| Cause | Exit | stderr |
| --- | --- | --- |
| Any existing serving key is invalid | 78 | `configuration error: ...`, as before. Reported first |
| `AUTH_CONFIG` is empty or not an absolute path | 78 | `configuration error: invalid AUTH_CONFIG` |
| The document or a file it names is refused | 78 | `auth configuration error: ` and the ADR 0015 or 0020 category |
| The document is version 1 | 78 | `auth configuration error: serving requires a version 2 browser profile` |
| Telemetry cannot be installed | 1 | `runtime error: ...` (ADR 0024) |
| The listener cannot bind, or a later runtime failure | 1 | `process.failed` event (ADR 0024) |

- An empty value is refused, never read as unset.
- `AUTH_CONFIG` is read after every existing key, so existing refusals keep their order.
- A version-1 document passes every version-1 check before it is refused. The offline check
  still accepts it, because that check validates a file and does not serve.
- The new category is `auth_config::Error::BrowserProfileRequired`. Only `load_browser`
  returns it.
- No line carries a path, JSON text, URL, provider identifier, key byte, parser message or
  operating-system error. Every line is a fixed string or a fixed enum's `Display`.
- Loading reads local files only. It makes no DNS, provider or database request, and the
  lazy pool stays unconnected. A started API therefore does not show that the provider is
  reachable or that the database authority agrees (ADRs 0012 and 0014).
- `LoginHandoff::new` and `router_with_sessions` repeat the loader's settings checks. A
  refusal there would be the same fixed category and exit 78, before telemetry. The loader
  already ran the same checks, so this is not expected to occur.

### Probe invariants

- **No shadowing.** The router's settings check (ADR 0018, run offline by ADR 0020) already
  refuses `/healthz` and `/readyz` as the initiation, session check or logout path and as
  the path of the provider's registered callback. It also refuses two equal paths and route
  syntax. The check runs in the loader and again in the constructor, before any route is
  added, so `Router::merge` cannot panic on a duplicate route. No new rule was needed.
- **Readiness stays database-only.** `/readyz` is the same `SELECT 1` within
  `DB_TIMEOUT_MS`. It reads no auth state and contacts no provider. A provider outage
  therefore does not remove a replica from service; sign-in requests fail on their own.
- **Liveness is unchanged.** `/healthz` does no work.
- **One pool.** The sign-in service uses a handle to the pool that readiness uses
  (ADR 0016). `DB_MAX_CONNECTIONS` bounds both together.

### Telemetry

No telemetry code, event or field changes. `process.started`, `process.stopping` and
`process.stopped` are exactly as in ADR 0024 and do not say whether sign-in is mounted.

`telemetry::observe` is applied after the merge, so the sign-in routes and the fallback emit
the same `http.request.completed` event as the probes: `request_id`, `http.route`,
`http.request.method`, `http.response.status_code` and `duration_us`. `http.route` is the
matched route's literal path from the document, or `unmatched`. The request ID is generated
by the server. A client `X-Request-Id` is ignored and no request-ID response header is sent.
The handoff and router log nothing themselves. A `5xx` from a sign-in route is `warn`; every
other status is `debug`.

### Shutdown

Unchanged. SIGTERM or SIGINT stops accepting, drains in-flight requests and closes the pool
within the drain share of `SHUTDOWN_TIMEOUT_MS`, then flushes telemetry (ADR 0024).

### Process contract

`runtime/process-contract.json` is unchanged. The new key falls under the API's existing
`configurationPrefix`, the default behaviour is the one the Kubernetes qualification
exercises, and no consumer of the fixture needs a new member.

## Limits

- **Setting the key exposes sign-in to whatever can reach the API port.** The exposure
  gates of ADRs 0017–0020 are not met by this change: TLS termination for the configured
  origin, ingress that routes only that origin, preserves paths and records no target,
  cookie or body, transport limits, operated cleanup and measured budgets. ADR 0024 covers
  this process's own output only.
- **Budgets are per process.** Replicas do not share rate budgets or the in-flight cap, and
  budgets restart full with the process (ADR 0018).
- **Slow sign-in work can use the whole drain.** A request waiting on a provider at SIGTERM
  is drained like any other. If it outlasts the drain share the process exits 1 with
  `ShutdownDeadline`, as any slow request would. Closing a connection that ADR 0016
  discarded as in doubt can also take part of that bound.
- **Startup reads files on the runtime thread**, before any request is served.
- **Panics while loading** use the default hook, because telemetry is not installed yet.
  The same holds for `--check-auth-config` (ADR 0024).
- **`http.route` carries operator-configured paths.** They are bounded literals from the
  document, not client input (ADR 0024).
- **No reload and no partial mount.** A refused document stops the process. It never
  starts with the probes alone.

## Compatibility

- **Behaviour change:** an API whose environment already contains
  `OPENMETTLE_API_AUTH_CONFIG` now reads it. It was ignored before.
- Otherwise the API, worker and migrator behave as before. `Config::parse` takes the role
  instead of a port, and `Role` is `Copy`.
- New public items: `auth_config::load_browser` and
  `auth_config::Error::BrowserProfileRequired`.
- No dependency, Cargo feature, lockfile, migration, provenance record, HTTP or OpenAPI
  contract, image, CI workflow or process-contract change.

## Evidence

Local, without PostgreSQL, a provider or network:

- `cargo test --locked --offline --lib` (`tests::` in `src/tests.rs`):
  - `AUTH_CONFIG` unset, absolute, empty and relative, and its position after the existing
    keys;
  - the worker asks for exactly the API's keys except `AUTH_CONFIG`;
  - unset serves the probes and `404`;
  - a missing file, a version-1 document and a profile naming `/healthz` or `/readyz` build
    no router and dial nothing;
  - a version-2 document mounts all four routes under the production telemetry stack, with
    the exact status and body of twelve requests, one event each with the route template,
    and no planted canary (database password, login key, session credential, callback code
    and state, invitation code, client request ID, issuer and file paths).
- `auth_config::tests::serving_load_requires_the_version_2_profile`: `load_browser` on
  versions 1 and 2, and loader refusals passed through unchanged.
- `cargo test --locked --offline --test runtime`, through the built binaries:
  - fourteen refused values of `OPENMETTLE_API_AUTH_CONFIG` (empty, relative, missing, a
    directory, invalid JSON, version 1, a short and a missing key file, each of the four
    paths colliding with a probe, and a foreign origin). Each exits 78 with exactly the
    fixed line while the bind address is occupied, with canaries in the path, JSON and key;
  - an invalid database URL is still reported before a valid auth file;
  - the worker with both prefixes' `AUTH_CONFIG` set to a valid file, an empty value, a
    relative path and a missing file: it starts, answers `404` on every sign-in path and
    writes only its usual events;
  - the API with a valid version-2 document, in JSON and text: 21 requests with exact
    status, body, `Allow`, `Cache-Control` and `Referrer-Policy`; no `Set-Cookie`,
    `Location` or request-ID header; the database is not dialled until a session request
    needs it; `process.started` has exactly the unmounted event's fields; each request event
    has only the allowlisted fields and a distinct server-generated ID; stderr holds no
    canary; SIGTERM exits 0 within two seconds at `SHUTDOWN_TIMEOUT_MS=1000`;
  - the existing default-path tests (probes, `404` for sign-in paths, lifecycle, unread
    stderr) pass unchanged.

Compiled locally, to be run by CI's existing `PostgreSQL process integration` step:

- `postgres_mounted_session_routes_use_the_primary_database`: the API binary as
  `openmettle_api` on a freshly migrated database with a version-2 document. `/readyz` is
  `200` although the configured provider is an unreachable reserved name, and the session
  check and logout answer `403` for an unknown credential three times over, with readiness
  between them. **Not run locally:** no PostgreSQL service was available.

Not claimed: no browser, real provider, ingress, image, cluster or rollout was exercised
with the binary. The full sign-in journey through a provider is covered for the same
router by the managed PostgreSQL tests (ADRs 0017–0019) and the Keycloak qualification,
both of which serve the router in-process rather than through `openmettle-api`.

## Remaining

> [ADR 0029](0029-native-sign-in-mounting-and-session-context.md) supplies the native settings-document form, runtime construction
> and mounting. The other items stand.

For V1-04: deployment and ingress qualification of the mounted routes (TLS for the origin,
path preservation, access-log redaction, transport limits); running the Keycloak browser
journey against the `openmettle-api` binary rather than an in-process router; operating
values from measurement; operated cleanup and retired-key reservation reclamation; the
native settings-document form, runtime construction and mounting (ADR 0023); the Flutter
invitation field and the corrective migration (ADR 0022); provisioning, reconciliation and
audited recovery. Resource authorization is V1-05. #5 stays open.
