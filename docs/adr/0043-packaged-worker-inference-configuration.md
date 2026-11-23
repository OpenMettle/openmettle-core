# 0043 — Packaged worker inference configuration

Accepted with its implementation, 23 November 2026 (V1-07 worker activation). Refs #8 and #11.
Builds on [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md) (leases and the run
loop), [ADR 0036](0036-conversation-branches-presets-and-effective-model-config.md) (catalog and
turn executor), [ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md) (reservations,
handoff and settlement) and [ADR 0038](0038-sglang-and-external-provider-conformance-adapter.md)
(route qualification). The dispatch credential source in this record is provisional; see
[Dispatch credential](#dispatch-credential-provisional).

## Problem

The library has a tested turn executor (`worker::turns::TurnExecutor`) that claims runs under
ADR 0033 leases, reserves each round, unseals the admitted user's gateway key inside the fenced
handoff and calls the gateway. The `openmettle-worker` binary never built it: ADR 0033 PR3 made
the binary refuse `OPENMETTLE_WORKER_RUN_SLOTS` until an executor existed. The executor's inputs
had no configuration surface for the worker. The gateway endpoint, trust anchors, private-range
opt-in, timeouts and qualification were only `Gateway::new` arguments. The model catalog and the
gateway key ring were parsed only from the API's `auth.json`. That document also names login
keys, cursor keys and identity-provider settings, which the worker must not hold.

## Decision

### Settings

The worker gains one key, `OPENMETTLE_WORKER_INFERENCE_CONFIG`: the absolute path of a
version-1 JSON document. It is required exactly when `RUN_SLOTS` is set. Each mismatch exits 78
with one fixed line before telemetry or the listener starts:

| Environment | Line after `configuration error:` |
| --- | --- |
| `RUN_SLOTS` without the document | `RUN_SLOTS requires INFERENCE_CONFIG` |
| The document without `RUN_SLOTS` | `INFERENCE_CONFIG requires RUN_SLOTS` |
| A relative or empty path | `invalid INFERENCE_CONFIG` |

There is no fallback to maintenance alone when slots were requested. The ADR 0033 lease and claim
settings are unchanged. The API refuses this key under either prefix, as it refuses the other
worker run settings.

### Document

| Member | Meaning |
| --- | --- |
| `version` | `1` |
| `catalog_file` | The catalog file the API mounts. Admission pins its revision and profiles. |
| `installation` | Canonical lowercase UUID of the gateway installation the worker dispatches under. Provisional. |
| `gateway_keys` | The API document's `gateway_keys` member, reused unchanged: `active` and `decrypt_only` key files of 32 raw bytes, at most four keys, distinct IDs and material. Provisional. |
| `routes` | One member per catalog model ID, and no others. |

Each route has these members:

| Member | Meaning |
| --- | --- |
| `endpoint` | Canonical `https://` URL with a DNS host. |
| `trust` | `{"roots": "native"}` or `{"roots": "bundle", "bundle_path": …}`. |
| `private_cidrs` | Opt-in ranges inside RFC 1918, CGNAT or ULA space. |
| `pin` | The profile tuple the route was qualified against. It must equal the catalog profile's `pin`. |
| `protocol` | `chat_completions` or `responses`. |
| `stream` | `true` requests SSE, `false` JSON. Only that mode is qualified. |
| `images`, `usage` | Inline PNG/JPEG inputs and gateway-reported usage counts are qualified. |
| `setup_timeout_milliseconds` | 100–30,000. Covers DNS, connect and TLS. |
| `idle_timeout_milliseconds` | 1,000–3,600,000. Bounds each body read. |
| `overall_timeout_milliseconds` | 1,000–86,400,000. Bounds the call and is at least the other two. |

The document and every file it names are read once at startup, before telemetry, the listener
or any database, DNS or network work. The loader reuses the ADR 0015 rules: absolute paths,
regular files within bounds, symbolic links followed for projected volumes, duplicate JSON keys
refused and strict members. The catalog loader shared with the API also refuses a repeated
member in any of its maps. Policy checks follow:

- The routes name exactly the catalog's models.
- Each route's `pin` equals its profile's `pin`.
- No profile sets `requires_device_slot`. Device slots need ADR 0042 capacity grants, which this
  worker does not hold.
- `Gateway::new` accepts each route under the unchanged ADR 0010 transport rules. Loopback and
  metadata addresses are never permitted.

A refusal exits 78 with `inference configuration error: ` followed by one fixed category. The
line never contains a value, path, URL, identifier or key byte.

### Execution

The binary builds `TurnExecutor` with `worker::config::GatewayRoutes`. Every round uses
`Route::metered`: the reservation, the fenced handoff, the `x-request-id` correlation committed
before the send and the settlement inputs are the library's, unchanged.

The worker offers no tools. Function, parallel-call and separator qualifications stay off until
V1-14 wires reviewed tool rounds, and a model tool call fails the turn. With
`OPENMETTLE_WORKER_ARTIFACTS_DIR`, the executor reads attachment revisions from that store, on
the connection prompt assembly already holds.

No turn-path task waits for a second pooled connection while holding one, so every accepted
`DB_MAX_CONNECTIONS` works, including 1, and no minimum is enforced. A claimed run uses at most
two connections at a time (its step and its renewal), and the sweeps use one. At
`2 × RUN_SLOTS + 1` connections nothing waits; below that, tasks queue for up to
`DB_TIMEOUT_MS`, which `LEASE_MS` already covers six times.

Shutdown follows ADR 0033. The run loop drains within half the drain budget while the HTTP
server keeps answering probes. HTTP shutdown and the pool close use the rest. A round in
flight at `SIGTERM` stops, and the lease is handed back for immediate re-claim. A run whose
handoff outlasts its drain window is dropped, and its lease lapses, so another worker claims it
after up to `LEASE_MS`. A round already handed to the gateway counts against the run's budget,
and its request keeps its hold for usage settlement.

### Dispatch credential (provisional)

On 23 November 2026 the owner decided that the inference gateway becomes a forwarding and
metering proxy, authorized per request by an OpenMettle-owned endpoint against OpenMettle's
database. The gateway will no longer hold per-user virtual keys. A later gateway-authorization
increment amends ADR 0037 and defines what the worker presents at dispatch. This record does not
amend ADR 0037.

Until then, the worker uses the library's current credential path unchanged: the fenced handoff
opens the admitted user's sealed gateway key with the configured ring and sends it as the
bearer. This increment does only what that path requires. It reuses the API document's
`gateway_keys` format, reads the ring in one statement of the loader and supplies it in one
place, `GatewayRoutes::route`. It defines no distribution, rotation or operator procedure for
the ring. The replacement changes `installation`, `gateway_keys` and that method, and nothing
else in the worker.

The worker's document is separate from the API's. The worker never reads the API's document,
login keys, cursor keys, issuance credential or provider settings. Today the worker's ring holds
the same key bytes as the sealing ring, because it opens the same envelopes. The ADR 0037
cross-ring separation check runs only in the API's offline check, when the API document names
the ring.

## Process contract

`runtime/process-contract.json` is unchanged. The key falls under the worker's existing
`configurationPrefix`, and the default without slots is the behaviour the kind qualification
exercises (as in ADRs 0025 and 0031). To enable turns, deploy must:

- set `RUN_SLOTS`, the ADR 0033 lease and claim settings and `INFERENCE_CONFIG`;
- mount the document, the API's catalog file, any trust bundles and, provisionally, the gateway
  ring read-only;
- limit the worker's inference egress to the gateway endpoints, keeping its PostgreSQL and
  cluster DNS rules;
- size `SHUTDOWN_TIMEOUT_MS` and the pod's termination grace period for the drain.

## Alternatives

- **Load the API's document.** Rejected: its loader reads login keys and provider settings.
- **Environment variables for routes.** Rejected: per-model qualification does not fit flat
  keys, and file references keep any credential material out of the environment.
- **Take the pin from the catalog.** Rejected: a catalog edit would re-qualify a route silently.
  ADR 0038 qualifies only the tested profile and route.
- **Allow models without a route.** Rejected: runs would fail at dispatch instead of startup.
- **A test resolver or loopback opt-in in the binary.** Rejected: process tests bind the gateway
  fixture to a private address that the system resolver names.

## Consequences

- The packaged worker executes metered turn rounds. Live gateway and model qualification
  (ADR 0038 PR3) remain separate.
- The dispatch credential source is provisional and will be replaced by the
  gateway-authorization increment.
- A catalog change needs the same file on the API and worker and matching route pins, then a
  restart of both.
- Profiles that require a device slot cannot be served by the packaged worker yet.
- No migration, dependency, HTTP or OpenAPI change. No new telemetry event or metric.

## Evidence

- `src/worker/config/tests.rs`: strict shape, repeated models and routes, coverage, pins,
  device slots, transport rules, timeout bounds, ring limits and value-free refusals.
- `tests/model_config.rs` and `src/auth_config/tests.rs`: repeated catalog members refused.
- `tests/runtime.rs`: setting pairing and API refusal, refusals through the binary before any
  database contact, and a valid document that starts and stops cleanly.
- `tests/schema/worker_leases.rs`, with PostgreSQL 18 and a synthetic TLS gateway on a private
  address: the API-admitted metered turn with quota holds, wire correlation, settlement ingest
  and zero drift; `SIGTERM` handoff and re-claim with a probe answered during the drain;
  `SIGKILL` lease exclusion without replay; and an image turn on a one-connection pool.
