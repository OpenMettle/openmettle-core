# 0043 — Packaged worker inference configuration

Accepted with its implementation, 23 November 2026 (V1-07 worker activation). Refs #8 and #11.
Builds on [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md) (leases and the run
loop), [ADR 0036](0036-conversation-branches-presets-and-effective-model-config.md) (catalog and
turn executor), [ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md) (per-user
gateway keys and reservations) and [ADR 0038](0038-sglang-and-external-provider-conformance-adapter.md)
(route qualification).

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
| `installation` | Canonical lowercase UUID of the gateway installation whose bindings the worker dispatches under. |
| `gateway_keys` | `active` and `decrypt_only` key files. They use the format and limits of the API document's member: 32 raw bytes each, one active key and up to three previous keys, distinct IDs and material. |
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
refused and strict members. Policy checks follow:

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
`Route::metered`: the reservation, the fenced handoff that unseals the admitted actor's own key,
the `x-request-id` correlation and settlement inputs are the library's, unchanged. The packaged
binary has no static or shared bearer route. `Route::bearer` remains a library path.

The worker offers no tools. Function, parallel-call and separator qualifications stay off until
V1-14 wires reviewed tool rounds, and a model tool call fails the turn. With
`OPENMETTLE_WORKER_ARTIFACTS_DIR`, the executor reads attachment revisions from that store.

Shutdown follows ADR 0033. The run loop drains within half the drain budget while the probes
keep serving. HTTP shutdown and the pool close use the rest. A round in flight at `SIGTERM`
stops, and the lease is handed back for immediate re-claim. A round already handed to the
gateway counts against the run's budget, and its request keeps its hold for usage settlement.

### Key material

The wrapping keys are shared. The worker must unseal the envelopes that the reconciliation
process seals, so its ring holds the same key bytes. The mounts are separate. The worker's
document names only the catalog, the gateway ring and route trust bundles. The worker never
reads the API's document, login keys, cursor keys, issuance credential or provider settings.
Project only the gateway ring into the worker's volume. The ADR 0037 cross-ring separation
check stays in the API's offline check, which compares the gateway ring with the login and
cursor rings when the API document names it. The worker sees no other ring, so it cannot repeat
that check.

## Process contract

`runtime/process-contract.json` is unchanged. The key falls under the worker's existing
`configurationPrefix`, and the default without slots is the behaviour the kind qualification
exercises (as in ADRs 0025 and 0031). To enable turns, deploy must:

- set `RUN_SLOTS`, the ADR 0033 lease and claim settings and `INFERENCE_CONFIG`;
- mount the document, the API's catalog file, the gateway ring and any trust bundles read-only;
- allow egress from the worker to the gateway endpoints only;
- size `SHUTDOWN_TIMEOUT_MS` and the pod's termination grace period for the drain.

## Alternatives

- **Load the API's document.** Rejected: its loader reads login keys and provider settings.
- **Environment variables for routes.** Rejected: ADR 0037 forbids key material in variables,
  and per-model qualification does not fit flat keys.
- **Take the pin from the catalog.** Rejected: a catalog edit would re-qualify a route silently.
  ADR 0038 qualifies only the tested profile and route.
- **Allow models without a route.** Rejected: runs would fail at dispatch instead of startup.
- **A test resolver or loopback opt-in in the binary.** Rejected: process tests bind the gateway
  fixture to a private address that the system resolver names.

## Consequences

- The packaged worker executes metered turn rounds. Live gateway and model qualification
  (ADR 0038 PR3) and gateway reconciliation (ADR 0037 PR3) remain separate.
- A catalog change needs the same file on the API and worker and matching route pins, then a
  restart of both.
- Profiles that require a device slot cannot be served by the packaged worker yet.
- No migration, dependency, HTTP or OpenAPI change. No new telemetry event or metric.

## Evidence

- `src/worker/config/tests.rs`: strict shape, coverage, pins, device slots, transport rules,
  timeout bounds, ring limits and value-free refusals.
- `tests/runtime.rs`: setting pairing and API refusal, refusals through the binary before any
  database contact, and a valid document that starts and stops cleanly.
- `tests/schema/worker_leases.rs`, with PostgreSQL 18 and a synthetic TLS gateway on a private
  address: the API-admitted metered turn with quota holds, wire correlation, settlement ingest
  and zero drift; `SIGTERM` handoff and re-claim; and `SIGKILL` lease exclusion without replay.
