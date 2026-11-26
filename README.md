# OpenMettle core

Rust API, worker, gateway and migration processes for OpenMettle. By default, `openmettle-api` and `openmettle-worker` serve CPU-only `/healthz` and PostgreSQL `/readyz` probes and answer `404` on sign-in and `/v1/*` paths.

- **`openmettle-api`**: When `OPENMETTLE_API_AUTH_CONFIG` (a version-2 settings document) and `OPENMETTLE_API_ISSUANCE_DATABASE_URL` are set, mounts same-origin browser sign-in/session/logout routes ([ADR 0025](docs/adr/0025-browser-auth-runtime-mounting.md), [ADR 0030](docs/adr/0030-session-issuance-database-boundary.md)), optional native sign-in routes (`native` profile, [ADR 0029](docs/adr/0029-native-sign-in-mounting-and-session-context.md)), and the authenticated `/v1/*` routes marked `"x-openmettle-implementation": "implemented"` in [`contracts/openapi/openmettle-v1.json`](contracts/openapi/openmettle-v1.json) (enforcing per-request authorization under [ADR 0027](docs/adr/0027-authorization-and-private-projects.md); ordinary conversation creation/reads on `POST`/`GET /v1/conversations` and `GET /v1/conversations/{conversation_id}` and branch creation/reads on `POST`/`GET /v1/conversations/{conversation_id}/branches…` require neither `catalog_file` nor `admission_limits`). Optional version-2 settings supply the model/preset catalog and enable `effective-configuration` previews (`catalog_file` only, [ADR 0036](docs/adr/0036-conversation-branches-presets-and-effective-model-config.md)), enable fresh `POST /v1/runs` admission (`catalog_file`, `admission_limits`, and `cursor_keys`, [ADR 0032](docs/adr/0032-durable-run-admission-and-fair-work-queue.md)), and enable cursor signing for fresh/replayed `POST /v1/runs`, `POST /v1/runs/{run_id}/cancel`, run snapshots, and SSE event streams (`cursor_keys`, [ADR 0034](docs/adr/0034-ordered-events-and-replayable-sse.md)); `OPENMETTLE_API_ARTIFACTS_DIR` enables streaming artifact uploads and byte-range downloads ([ADR 0031](docs/adr/0031-filesystem-artifact-storage-and-streaming-multipart.md)).
- **`openmettle-worker`**: Runs scheduled maintenance sweeps for expired queued runs, expired approval waits (`authz::approvals::expire_waits`, [ADR 0035](docs/adr/0035-approvals-permitted-yolo-and-effect-ledger.md)), expired executing runs ([ADR 0033](docs/adr/0033-worker-leases-deadlines-and-restart-recovery.md)), and undispatched or stale unreported gateway requests ([ADR 0044](docs/adr/0044-own-inference-proxy-and-binding-free-dispatch.md)), plus abandoned-upload reconciliation and retained-revision purges when `OPENMETTLE_WORKER_ARTIFACTS_DIR` is set. With `OPENMETTLE_WORKER_RUN_SLOTS` and an `OPENMETTLE_WORKER_INFERENCE_CONFIG` document, it also claims queued runs and executes metered model turn rounds through the configured gateway ([ADR 0043](docs/adr/0043-packaged-worker-inference-configuration.md), [worker turn execution](#worker-turn-execution-off-by-default)). Tool rounds (V1-14) and live gateway qualification (V1-08) remain separate.
- **`openmettle-gateway`**: OpenMettle's own inference proxy (V1-06, [ADR 0044](docs/adr/0044-own-inference-proxy-and-binding-free-dispatch.md)). It authenticates each caller by the round bearer of the handed-off gateway request named in `x-request-id`, allows that request one dispatch, checks the model, refuses caller-supplied SGLang cache/routing fields (`cache_salt`, `extra_key`, `session_id`, `rid`, `lora_path`), injects a proxy-derived `cache_salt` (`OPENMETTLE_GATEWAY_CACHE_MODE`, migration 36) while preserving caller JSON bytes verbatim, forwards `POST /v1/chat/completions` to one plain-HTTP SGLang upstream, relays the response as it arrives and records the usage the upstream reports, connected as `openmettle_gateway` (narrowed in migration 37 to a function-only boundary with zero table/column privileges: `gateway_dispatch`, `gateway_dispatch_scoped` and `gateway_settle_report`). It listens on plain HTTP, which the worker may use inside the cluster, with TLS terminated in front of it as the stricter option. Both `usage_tokens` and `usage_cost_micros` holds settle from the upstream's reported token counts (deriving cost in PostgreSQL from the profile pricing recorded at handoff; migration 34). Family policy schedules, per-user overrides and model switches (migration 35, `openmettle-admin family`) are enforced at admission/preview, worker recheck, round handoff and proxy dispatch. A dispatched request that ends without usage is closed by a final report that names the reason, with nothing charged; requests that were never dispatched or never reported by the proxy are closed by the worker's maintenance sweep at revision 0. Increment 7a delivers its `Dockerfile` `gateway` target, `runtime/process-contract.json` entry and CI/kind qualification; Helm chart packaging and `NetworkPolicy` templates live in `openmettle-deploy` (Increment 7b). See [the gateway proxy page](docs/operator/gateway-proxy.md).
- **`openmettle-migrate`**: One-shot PostgreSQL 18 schema migrator owning identities, scopes, projects, conversations, managed branches, immutable message turns, runs/events/operations, scoped approvals and receipts (Migration 22, [ADR 0035](docs/adr/0035-approvals-permitted-yolo-and-effect-ledger.md)), artifact revisions and storage accounting, and typed grants ([ADR 0003](docs/adr/0003-schema-migrations.md)–[ADR 0006](docs/adr/0006-grant-persistence.md)).

Runtime qualification and deployment acceptance remain separate gates.

## Start here

- [Accepted architecture v1](ARCHITECTURE-v1.md), including service diagrams and all 43 delivery tickets.
- [Repository boundaries](REPOSITORIES.md), [decisions index (ADRs 0001–0044)](DECISIONS.md) and [provenance](UPSTREAM.md).
- [Live delivery tracker](https://github.com/orgs/OpenMettle/projects/1/views/1?filterQuery=%5BV1-00%5D&pane=issue&itemId=307308630).

## Development

Install Rust through the [official rustup installer](https://rustup.rs/). The repository pins Rust 1.100.0 with rustfmt and Clippy; Cargo installs the selected components through rustup when required. Python 3.10+ runs the repository check.

```sh
python3 scripts/check_repository.py
python3 scripts/contract_fixtures.py --check
python3 -m unittest discover -s scripts/tests
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
```

API, worker and gateway share operational code and build independently with `cargo build --locked --bin openmettle-api`, `cargo build --locked --bin openmettle-worker` and `cargo build --locked --bin openmettle-gateway`. After `cargo fetch --locked`, add `--offline` to build, Clippy and test commands. Locked resolution and digest-pinned images constrain inputs; they do not prove bit-for-bit reproducibility.

### CI caching

The Rust runtime job restores Cargo downloads and `target/` build outputs before
running the normal checks. Every format, lint, build, unit test and PostgreSQL
integration command still runs; a cache hit never substitutes for a test result.
Keys separate operating systems and architectures and include the toolchain,
Cargo manifests/lockfiles, Cargo configuration and workflow. Each commit can save
an updated build cache while restoring a compatible earlier entry. Cargo decides
which outputs need rebuilding. Incremental compiler state is excluded.

Only successful pushes to `main` save caches. Pull requests restore them without
writing. A miss rebuilds normally with `cargo fetch --locked`; subsequent checks
remain locked and offline. Do not add credentials, database data, kubeconfigs or
qualification reports to the cached paths. The pinned GitHub `actions/cache` v5
restore/save actions are MIT-licensed CI tooling (see `provenance/register.json`).

For a cold verification run, dispatch **CI** with **use_cache** disabled. To
invalidate the shared cache namespace, increment `cargo-v1` in both key prefixes.
Compare the Rust job's restore, compile/test and save durations on cold and warm
runs before claiming a speed improvement. Cache storage and transfer overhead
must remain worthwhile as the workspace grows. This cache does not accelerate
the separate Docker image or kind build jobs; those need BuildKit layer caching.

## Runtime

Read [runtime ADR 0002](docs/adr/0002-cpu-runtime.md) for dependency origins, licences, configuration bounds and shutdown behavior. Supply each process's database URI through deployment-managed environment configuration. Do not commit credentials. For an isolated local test database only:

```sh
export OPENMETTLE_API_DATABASE_URL='postgres://fixture:fixture@127.0.0.1:5432/fixture?sslmode=disable'
cargo run --locked --bin openmettle-api
```

In another terminal, `curl --fail http://127.0.0.1:8080/healthz` returns `ok`. `/readyz` returns `ready` after a successful database query, or HTTP 503 if PostgreSQL is unavailable. Restoring PostgreSQL allows a later probe to succeed without restarting the process. The API and worker never create or migrate tables, and readiness does not check the schema version. These endpoints are operational and must not be exposed as a public product API.

The worker uses `OPENMETTLE_WORKER_DATABASE_URL` and port 8081, and the gateway `OPENMETTLE_GATEWAY_DATABASE_URL` and port 8082 ([gateway proxy](docs/operator/gateway-proxy.md)). Every setting is independent: `BIND`, `DATABASE_URL`, `DB_MAX_CONNECTIONS`, `DB_TIMEOUT_MS` and `SHUTDOWN_TIMEOUT_MS` use the corresponding `OPENMETTLE_API_`, `OPENMETTLE_WORKER_` or `OPENMETTLE_GATEWAY_` prefix. Defaults bind loopback; containers bind all interfaces unless overridden. Send SIGTERM or SIGINT to drain and stop. Invalid configuration exits 78; runtime failures or shutdown deadline expiry exit 1. Correct configuration and restart after these errors. Database failures affect readiness, not liveness.

The worker sweeps expired queued runs, expired approval waits (`authz::approvals::expire_waits`, [ADR 0035](docs/adr/0035-approvals-permitted-yolo-and-effect-ledger.md)), and expired executing runs in batches of 100. With `OPENMETTLE_WORKER_ARTIFACTS_DIR` set to the same payload directory used by the API, it also schedules `artifact_fs::reconcile_expired` (releasing abandoned uploads older than 900 seconds) and `artifact_fs::purge_due` (purging due retained revisions). Artifact sweeps skip locked reservations and continue through the batch after an item fails. Each scheduled sweep has a 15-second budget. A failure or timeout emits `worker.sweep.failed` with the sweep category (both queue and approval-wait expiry report under `expire_queued`), and the worker moves on to the next sweep. On shutdown, the worker reserves half the process drain budget for run handover and the rest for HTTP and database shutdown.

| Worker setting (`OPENMETTLE_WORKER_` prefix) | Range | Default |
| --- | --- | --- |
| `SWEEP_MS` | 1,000–3,600,000 ms | 60,000 |
| `POLL_MS` | 100–60,000 ms | 1,000 |
| `RUN_SLOTS` | 1–256 | Unset |
| `LEASE_MS` | 30,000–600,000 ms and at least six times `DB_TIMEOUT_MS` | Required with slots |
| `EXECUTION_TIMEOUT_MS` | 60,000–86,400,000 ms and at least twice `LEASE_MS` | Required with slots |
| `EXECUTING_PER_ACTOR`, `EXECUTING_PER_SCOPE` | 1–1,024 each | Required with slots |
| `INFERENCE_CONFIG` | Absolute path to the worker inference document | Required with slots and refused without them |

Sweep and idle poll intervals add up to 20% jitter. Without slots the worker runs maintenance only. With slots it also runs the turn executor described under [Worker turn execution](#worker-turn-execution-off-by-default). The API refuses every worker setting in this table.

The API, worker, gateway and migrator write structured events to stderr ([ADR 0024](docs/adr/0024-process-telemetry-and-redaction.md)). The API, worker and gateway write nothing to stdout. The `configuration error:` line, the `--check-auth-config` output and the migrator's result lines keep their existing plain form. Two settings use the process's own prefix (`OPENMETTLE_API_`, `OPENMETTLE_WORKER_`, `OPENMETTLE_GATEWAY_` or `OPENMETTLE_MIGRATE_`):

| Setting | Default | Values |
| --- | --- | --- |
| `LOG_FORMAT` | `json` | `json` (one object per line) or `text` |
| `LOG_LEVEL` | `info` | `error`, `warn`, `info` or `debug`. `trace` and filter directives are refused |

Values must match exactly; anything else exits 78 with `configuration error: invalid LOG_FORMAT` or `invalid LOG_LEVEL`.

- **Default level.** `info` shows start, stop and failure events.
- **Request events.** Each request gets a server-generated `request_id`, which is never taken from a client header. A request completion is logged at `debug`, or at `warn` for a 5xx response such as a failed readiness check.
- **What is recorded.** Events carry fixed event names, the matched route template, the method, the status, durations, counts and failure classes. They never carry URLs, queries, headers, cookies, bodies, database settings or third-party library logs.
- **Slow or unread stderr.** Events are queued (up to 1024 lines) for one writer thread, so a stalled log reader never blocks requests, readiness or shutdown. Lines that do not fit are dropped and counted, and a `telemetry.dropped` event with the count follows the next successful write. The stop, including the final flush, fits `SHUTDOWN_TIMEOUT_MS`: draining gets the deadline less a tenth (at most 250 ms), which is kept for the flush.
- **Panics.** After telemetry starts, a panic writes one `process.panicked` event and never the panic message or location.
- **Not covered.** Ingress and proxy access logs are outside these processes. Configure them separately before exposing login routes.
- **No export by default.** Nothing is sent over the network unless an OTLP endpoint setting below is given.

### OTLP trace and metrics export (off by default)

[ADR 0026](docs/adr/0026-otlp-trace-export.md) and [ADR 0028](docs/adr/0028-telemetry-contract-and-metrics.md) add four settings for the API, worker and gateway, under their own prefix. The migrator never reads them. Ambient `OTEL_*` variables (`OTEL_EXPORTER_OTLP_*`, `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`, `OTEL_TRACES_SAMPLER*`, `OTEL_SPAN_*_LIMIT`, `OTEL_METRICS_*`) and proxy variables have no effect. The versioned telemetry contract and baseline Prometheus alert rules live in [`contracts/telemetry/v1.json`](contracts/telemetry/v1.json) and [`contracts/telemetry/alerts-v1.yaml`](contracts/telemetry/alerts-v1.yaml).

| Setting | Default | Values |
| --- | --- | --- |
| `OTLP_TRACES_ENDPOINT` | unset (export off) | A canonical `https://` URL with a DNS host, for example `https://alloy.monitoring.svc.cluster.local:4318/v1/traces`. No `http://`, IP literal, user information, query, fragment or percent-encoding |
| `OTLP_METRICS_ENDPOINT` | unset (export off) | A canonical `https://` URL with a DNS host, for example `https://alloy.monitoring.svc.cluster.local:4318/v1/metrics`. Same URL rules as `OTLP_TRACES_ENDPOINT` |
| `OTLP_CA_FILE` | platform roots | Absolute path to a PEM CA bundle (1 to 256 certificates, at most 1 MiB) that replaces the platform roots, for example the cluster CA |
| `OTLP_PRIVATE_RANGES` | none | Comma-separated canonical CIDRs inside 10/8, 172.16/12, 192.168/16, 100.64/10 or fc00::/7 (at most 32). A collector address in a private range is refused unless a listed range contains it |

Unset, no exporter, task, DNS slot or socket exists and the process behaves exactly as before. Either endpoint may be configured alone or together; `OTLP_CA_FILE` or `OTLP_PRIVATE_RANGES` without at least one endpoint is refused rather than ignored. An invalid value exits 78 with one fixed line, `configuration error: invalid OTLP_TRACES_ENDPOINT`, `invalid OTLP_METRICS_ENDPOINT`, `invalid OTLP_CA_FILE` or `invalid OTLP_PRIVATE_RANGES`, which never includes the value, path or file contents; `configuration error: OTLP trust roots unavailable` means no CA file was given and the platform roots could not be loaded.

- **What is exported (traces).** One root server span, `http.server.request`, per request other than `/healthz` and `/readyz`, with only `request_id`, `http.route`, `http.request.method` and `http.response.status_code`, and the resource attributes `service.name` (`openmettle-api`, `openmettle-worker` or `openmettle-gateway`) and a per-process random UUIDv4 `service.instance.id`. No third-party span, log event, URL, header, cookie, body or source location is exported. An inbound `traceparent` or `tracestate` is ignored, so each request starts its own trace.
- **What is exported (metrics).** Nine statically bounded cumulative counters and histograms covering HTTP requests/duration, database readiness checks/duration, provider HTTP requests/duration, storage helper attempts, terminal cancellation event appends by reason, and internal telemetry drops (`openmettle.*`, at most 359 data-point streams / 1,022 Prometheus series per process excluding `target_info`, zero dynamic labels or identity/path values), encoded directly as `ExportMetricsServiceRequest` protobuf with `service.name` and a per-process random UUIDv4 `service.instance.id`.
- **Transport.** OTLP/HTTP protobuf (`POST`, `Content-Type: application/x-protobuf`) over the same bounded HTTP/1.1 TLS core as the provider transport ([ADR 0010](docs/adr/0010-provider-http-transport.md)): one request per connection, no compression, retry, redirect, proxy or authentication header, and its own two DNS lookup slots shared across trace and metrics exports.
- **Bounds.** Up to 2048 ended spans are queued; trace batches of up to 512 and cumulative metric snapshots are sent at least every 5 s; each export has 3 s, a 1 MiB request and a 64 KiB response. A full queue, a non-2xx response (including 3xx and 429), a timeout or any DNS, address or TLS failure drops the batch/cycle, and a `telemetry.dropped` event with `dropped_spans` or `dropped_metric_exports` goes to stderr at most once per export cycle.
- **Shutdown.** The exporter gets at most half of the final flush slice (at most 125 ms) to send queued spans and a final metrics snapshot and is then cancelled, closing its connection; the stderr flush gets the rest. A stalled collector cannot extend the stop beyond `SHUTDOWN_TIMEOUT_MS`, and the runtime does not wait for an abandoned DNS lookup at exit.

### Artifact storage directory (off by default)

[ADR 0031](docs/adr/0031-filesystem-artifact-storage-and-streaming-multipart.md) adds one setting for the API and the worker, under their own prefix. The migrator never reads it. The API's [artifact upload and download routes](#authenticated-application-routes) use it; unset, they answer `503 provisioning` and the other routes are unaffected. When `OPENMETTLE_WORKER_ARTIFACTS_DIR` is set, `openmettle-worker` schedules `artifact_fs::reconcile_expired` and `artifact_fs::purge_due` on its maintenance loop.

| Setting | Default | Values |
| --- | --- | --- |
| `ARTIFACTS_DIR` | unset (artifact file I/O disabled) | Absolute path to an existing directory whose leaf is not a symbolic link, typically the mount point of a persistent volume |

Unset, the process opens no directory and starts exactly as before. Set, it creates `staging/` and `revisions/` (mode 0700) inside the directory if they are absent, before telemetry or the listener starts. Any refusal (empty, relative, missing, a file, a symbolic-link leaf, or a subdirectory that cannot be created or is not a real directory) exits 78 with exactly `configuration error: invalid ARTIFACTS_DIR`, never the path.

- **Layout.** `staging/<reservation_id>` holds an upload in progress (mode 0600, created exclusively); `revisions/<reservation_id>` holds a published payload. The name is always the server-generated reservation UUID, never a client file name, which is kept only as the revision's display name.
- **Durability.** A payload is `fsync`ed, renamed into `revisions/` and the directory `fsync`ed before the database records the revision. Refused, truncated or cancelled uploads leave no staging file, and their reservation is released, or released later by `artifact_fs::reconcile_expired`. A crashed process before the rename leaves its orphaned staging file and reservation until that reconciler runs, and a retry with the same key returns `409 conflict` while that staging file exists; a crash after the rename into `revisions/` but before database settlement can replace the unsettled file and settle on retry. `artifact_fs::purge_due` deletes expired retained payloads before confirming the purge. When `OPENMETTLE_WORKER_ARTIFACTS_DIR` is set, `openmettle-worker` schedules both helpers in batches of 100 with a 15-second budget: `artifact_fs::reconcile_expired` releases uploads older than 900 seconds (300 s beyond the 600 s upload limit), and `artifact_fs::purge_due` removes due retained revisions.
- **Topology.** Every API and worker replica that writes or purges payloads must see the same directory. Use a `ReadWriteOnce` volume with all those pods on one node, or a `ReadWriteMany` storage class qualified for POSIX `rename`, exclusive creation and `fsync`. Back up PostgreSQL and the volume together.

### Worker turn execution (off by default)

[ADR 0043](docs/adr/0043-packaged-worker-inference-configuration.md) lets `openmettle-worker` claim queued runs and execute their model rounds. Set `OPENMETTLE_WORKER_RUN_SLOTS` with the ADR 0033 lease and claim settings above, and `OPENMETTLE_WORKER_INFERENCE_CONFIG` to the absolute path of this document:

```json
{
  "version": 1,
  "catalog_file": "/etc/openmettle/catalog/catalog.json",
  "installation": "00000000-0000-4000-8000-000000000001",
  "routes": {
    "example-model": {
      "endpoint": "https://gateway.example.test/v1/chat/completions",
      "trust": {"roots": "bundle", "bundle_path": "/etc/openmettle/gateway-ca/ca.pem"},
      "private_cidrs": ["10.0.0.0/8"],
      "pin": {"provider": "…", "revision": "…", "checkpoint": "…", "template": "…",
              "parser": "…", "runtime": "…", "gateway": "…"},
      "protocol": "chat_completions",
      "stream": false,
      "images": false,
      "usage": true,
      "setup_timeout_milliseconds": 5000,
      "idle_timeout_milliseconds": 120000,
      "overall_timeout_milliseconds": 600000
    }
  }
}
```

- **Catalog.** Mount the same catalog file as the API's `catalog_file`. `routes` must name exactly its model IDs, and each route's `pin` must equal that model's catalog `pin`. A changed profile therefore needs a re-qualified route before the worker starts. The packaged worker cannot serve a profile with `requires_device_slot`.
- **Dispatch credential.** Every round reserves its budget, commits its `x-request-id` and is handed off for usage settlement ([ADR 0037](docs/adr/0037-gateway-provisioning-and-usage-reconciliation.md)). Since [ADR 0044](docs/adr/0044-own-inference-proxy-and-binding-free-dispatch.md) the round is authorized without a gateway binding, and the bearer the worker sends `openmettle-gateway` is a random value made for that round, of which the database stores only a hash. `installation` is also the usage report source. The document holds no credential: a document that still has the former `gateway_keys` member is refused as an unknown field. The worker never reads the API's document, login keys or cursor keys.
- **Routes.** Each endpoint is a canonical `https://` URL with a DNS name, or, for `openmettle-gateway` inside the cluster, a canonical `http://` one. Every other provider transport rule applies to both: no loopback or metadata address, and private addresses only inside `private_cidrs`. An `https://` route needs `trust`, the native roots or exactly one PEM bundle; an `http://` route has no `trust` member, and its `private_cidrs` must hold every address its name resolves to, so it never reaches a public address. Over `http://` the round's bearer and the prompt and response bodies cross the cluster network unencrypted; see [plain HTTP](docs/operator/worker-turn-execution.md#plain-http-inside-the-cluster). `stream` selects SSE or JSON, the only mode qualified for the route. Timeouts: setup 100–30,000 ms, idle 1,000–3,600,000 ms, overall 1,000–86,400,000 ms and at least the other two.
- **Tools.** The worker offers no tools until V1-14. A model tool call fails the turn.
- **Refusals.** The document and every file it names are read once before telemetry, the listener or any database or network work. A refusal exits 78 with `inference configuration error: ` and one fixed category, never a value or path.
- **Shutdown.** `SIGTERM` stops claiming and stops in-flight rounds. Probes keep answering while, within half the drain budget, each run waits at most `LEASE_MS / 6` for its step to stop and hands its lease back for immediate re-claim. A run whose handoff does not finish in time is dropped, and another worker claims it after up to `LEASE_MS` ([ADR 0033](docs/adr/0033-worker-leases-deadlines-and-restart-recovery.md)). A round already handed to the gateway still counts against the run's round budget; a reserved round that was never sent is reused. Size `SHUTDOWN_TIMEOUT_MS` and the pod's termination grace period accordingly. After `SIGKILL`, runs wait up to `LEASE_MS` before another worker can claim them.
- **Pool.** Any accepted `DB_MAX_CONNECTIONS` works: no task waits for a second connection while holding one. Each claimed run uses at most two connections and the sweeps one, so run and maintenance work needs at most `2 × RUN_SLOTS + 1`. Each `/readyz` probe in flight needs one more, so `2 × RUN_SLOTS + 2` avoids queueing with one probe at a time. On a full pool `/readyz` waits up to `DB_TIMEOUT_MS` and answers 503 while work continues.

The process contract is unchanged; deploy must set these keys, mount the files read-only and allow the worker's inference egress to the gateway endpoints, beside its existing PostgreSQL and DNS access. [Enabling worker turn execution](docs/operator/worker-turn-execution.md) is the operator checklist.

### Browser sign-in routes (off by default)

[ADR 0025](docs/adr/0025-browser-auth-runtime-mounting.md) adds one API-only setting, and [ADR 0030](docs/adr/0030-session-issuance-database-boundary.md) the session issuance pool that sign-in requires. The worker and migrator never read them.

| Setting | Default | Effect |
| --- | --- | --- |
| `OPENMETTLE_API_AUTH_CONFIG` | unset | Unset: the API loads no auth file, serves `/healthz` and `/readyz` only and answers `404` on every sign-in and `/v1` path, as before. Set: the absolute path of a [version-2 auth settings document](#browser-routing-profile-version-2), loaded once at startup; the [`/v1` routes](#authenticated-application-routes) are mounted with it |
| `OPENMETTLE_API_ISSUANCE_DATABASE_URL` | unset | Required with `AUTH_CONFIG` and refused without it. The URL of a login role of `openmettle_issuance` (see [Schema migrations](#schema-migrations)) on the same primary, with the same scheme, TLS and redaction rules as `DATABASE_URL`. Its resolved user, including one filled from `PGUSER` or the operating-system user, must differ from the `DATABASE_URL` user. Never logged |
| `OPENMETTLE_API_ISSUANCE_DB_MAX_CONNECTIONS` | `2` | Size of the issuance pool, 1–64. Refused when the issuance URL is unset |

When set, the API validates the document and the files it names with the same loader as `--check-auth-config`, before it installs telemetry or opens its listener. It then mounts the document's four routes beside the probes: the initiation `POST`, the provider's registered callback `GET`, the session check `GET` and the logout `POST`. They use the API's existing database pool, except that session issuance runs on a separate lazy issuance pool whose connections wait at most `DB_TIMEOUT_MS`. `/readyz` is still one query on the primary pool and contacts no provider; an unusable issuance pool refuses sign-in completion only. If the document also has the optional [native profile](#native-sign-in-profile-version-2), the API mounts the five native sign-in routes beside them over the same service and pool ([ADR 0029](docs/adr/0029-native-sign-in-mounting-and-session-context.md)); otherwise every `/auth/native/` path is `404`.

A refusal exits 78 with one fixed stderr line and no listener:

| Cause | Line |
| --- | --- |
| The value is empty or not an absolute path | `configuration error: invalid AUTH_CONFIG` |
| `AUTH_CONFIG` without an issuance URL, or the reverse | `configuration error: ISSUANCE_DATABASE_URL is required with AUTH_CONFIG`, or `… requires AUTH_CONFIG` |
| The issuance URL has another scheme, does not parse or is not UTF-8 | `configuration error: invalid ISSUANCE_DATABASE_URL scheme`, `… invalid ISSUANCE_DATABASE_URL` or `… configuration must be UTF-8` |
| The issuance URL resolves to the `DATABASE_URL` user | `configuration error: ISSUANCE_DATABASE_URL must use a different user` |
| `ISSUANCE_DB_MAX_CONNECTIONS` without the URL, or outside 1–64 | `configuration error: ISSUANCE_DB_MAX_CONNECTIONS requires ISSUANCE_DATABASE_URL`, or the numeric categories |
| `OPENMETTLE_API_ISSUANCE_DATABASE_URL` is present, with any value, in the worker's or migrator's environment | `configuration error: OPENMETTLE_API_ISSUANCE_DATABASE_URL is refused outside the API` |
| The document or a file it names is refused | `auth configuration error: ` and the category `--check-auth-config` prints |
| The document is version 1 | `auth configuration error: serving requires a version 2 browser profile` |
| The native profile is refused | `auth configuration error: native profile refused: ` and a fixed category |

No line carries a path, value, URL, identifier or parser message. Run `--check-auth-config` in the same image and mounts first: it accepts version 1, which serving refuses. There is no live reload; restart the API to apply changed files. Request events for these routes carry the route's configured literal path, the method, the status and a server-generated request ID, and nothing from the request.

**Setting this exposes sign-in to whatever can reach the API port.** The exposure gates of ADRs 0017–0020 are deployment work that this setting does not perform: TLS termination for the configured origin, ingress that preserves paths and does not log targets, cookies or bodies, the database authority and login limit (ADRs 0012 and 0014), operated cleanup, and measured budgets. Each replica keeps its own rate budgets.

### Authenticated application routes

With `OPENMETTLE_API_AUTH_CONFIG` set, the API serves the operations of the [application API contract](#application-api-contract) marked `"x-openmettle-implementation": "implemented"` in `contracts/openapi/openmettle-v1.json`: `GET /v1/capabilities` (an empty, core-only list), projects, membership, conversation and artifact access and sharing ([ADR 0027](docs/adr/0027-authorization-and-private-projects.md)), managed conversations, branches, models, presets, effective-configuration previews and run admission/cancellation ([ADR 0032](docs/adr/0032-durable-run-admission-and-fair-work-queue.md), [ADR 0036](docs/adr/0036-conversation-branches-presets-and-effective-model-config.md)), run snapshots and replayable SSE event streams when `cursor_keys` are configured ([ADR 0034](docs/adr/0034-ordered-events-and-replayable-sse.md)), artifact and revision metadata routes (which read from PostgreSQL even when `OPENMETTLE_API_ARTIFACTS_DIR` is unset), and artifact payload uploads and downloads when `OPENMETTLE_API_ARTIFACTS_DIR` is set (`503 provisioning` when unset, [ADR 0031](docs/adr/0031-filesystem-artifact-storage-and-streaming-multipart.md)).

- **Sessions.** Each request presents exactly one OpenMettle session: the browser cookie `__Host-openmettle-session`, or `Authorization: Bearer` with a native credential when the document has a native profile. A browser write needs exactly one `Origin` equal to the configured `browser.origin`; a browser read may omit `Origin`. Both channels at once, a repeated field or a refused `Origin` is `401`, decided before any database work.
- **Authorization.** The session, the caller's principal and every project, conversation and artifact are read from the primary for each request, so disablement, logout, group, membership and share changes apply on the next request. Items are private to their creator until shared. A target the caller may not know about is `404`; an account administrator gains no access.
- **Writes** need an `Idempotency-Key` (1–128 visible ASCII characters). Repeating it with the same request on the same operation and target replays the result; another request with it is `409 idempotency_conflict`. Authorization, project, membership, share, conversation and branch creation writes are recorded in the append-only `openmettle.authorization_audit` table, while run admission and cancellation append durable `openmettle.run_events` rows.
- **Lifecycle.** An archived project stays readable, and member and share revocations, restore and delete remain available; settings, new roles and new shares are `409`. A deleted project is `404`, except that repeating the delete with its key returns `204` again.
- **Bounds.** At most 256 unary or artifact requests and 128 event streams in flight per process (`503` beyond), the sign-in routes' header ceilings, JSON bodies read within 2 s of at most 128 KiB for `POST /v1/runs` and `POST …/effective-configuration` preview or 64 KiB for other JSON writes, and a 10 s database phase (`504`). Every response carries `OpenMettle-API-Version: 1.0` and `Cache-Control: no-store`; every error is an `application/problem+json` problem with a fixed message and the logged request ID.
- **Conversations, branches, catalog and run admission.** `/v1/conversations`, `/v1/conversations/{conversation_id}/branches` (plus `messages` and `effective-configuration`), `/v1/models`, `/v1/presets`, `POST /v1/runs` and `POST /v1/runs/{run_id}/cancel` enforce per-user authorization on every request. Migration 21 adds managed conversation branches while keeping legacy branch IDs and run inputs valid (history stays unavailable for legacy branch IDs; an authorized writer can create an empty managed root). Without `catalog_file`, authorized first-page `GET /v1/models` and `GET /v1/presets` return `200` with empty `items: []`, and `GET /v1/presets/{preset_id}` returns `404 not_found`. `POST …/effective-configuration` preview requires `catalog_file` (`503 provisioning` when omitted; it does not require `admission_limits`). Fresh `POST /v1/runs` admission requires `catalog_file`, `admission_limits` and `cursor_keys` (`503 provisioning` when missing; an exact idempotent replay still requires `admission_limits` and `cursor_keys` and returns the current run projection—re-read from PostgreSQL and re-signed with a fresh cursor, reflecting current state such as `cancelled` and the latest sequence—without `catalog_file`), and `POST /v1/runs/{run_id}/cancel` requires `cursor_keys`.
- **Run replay.** Read `GET /v1/runs/{run_id}` for the state, last sequence, resume cursor and terminal event. Connect to `GET /v1/runs/{run_id}/events?after=<resume_cursor>` for later events, or omit the cursor to replay from creation. On reconnect, `Last-Event-ID` takes precedence. Apply each sequence once. Events remain available for the life of the run. After `400 invalid_cursor`, discard local run state and fetch a fresh snapshot. A terminal snapshot needs no stream. A reconnect at the final sequence returns `204`. The stream checks conversation access before each delivery and periodically while idle.
- **Artifact uploads.** `POST /v1/artifacts` (into the caller's personal scope, or `?scope_id=` a project where the caller is an editor) and `POST /v1/artifacts/{artifact_id}/revisions` (needs write access) take `multipart/form-data` with one `file` part, whose `Content-Type` becomes the revision's media type and whose optional file name becomes its display name, and one `metadata` part holding `{}`, in either order. The target is authorized before anything is reserved or written. The file is streamed to the artifacts directory with bounded memory and must not exceed `?max_bytes=` (default and maximum 64 MiB), which is charged against storage quotas until the upload settles. An upload must finish within 600 s and holds one in-flight slot meanwhile. Retrying with the same key and file, even with another boundary or part order, returns the same revision and charges once. Quota exhaustion is `429 quota`; unconfigured storage limits, or no `ARTIFACTS_DIR`, is `503 provisioning`.
- **Artifact downloads.** `GET /v1/artifacts/{artifact_id}/revisions/{revision_id}` returns a revision's metadata; `GET …/content` streams an active revision's bytes in 64 KiB reads, with its media type, `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` and `Accept-Ranges: bytes`. One `Range` is served as `206`; a range outside the content is `416` with `Content-Range: bytes */<size>`; a list of ranges is `400`. `HEAD` returns the same headers without a body. Access is checked on the primary for every request, so a revoked share or membership stops the next download.

Request events record the route template, such as `/v1/projects/{project_id}`, never an identifier. No sign-in path may be `/v1` or lie under it; the offline check refuses one as a collision.

Run the real PostgreSQL subprocess test against an isolated test database:

```sh
export TEST_DATABASE_URL='postgres://fixture:fixture@127.0.0.1:5432/fixture?sslmode=disable'
cargo test --locked --test runtime -- --ignored
```

The normal test suite covers configuration rejection, bind failure, database timeout, liveness and shutdown without PostgreSQL. CI separately requires the PostgreSQL tests, builds the API, worker, gateway and migrate Docker targets and exercises binary isolation, fail-closed gateway configuration, database loss/recovery and API/gateway survival after stopping the worker. Test credentials above are synthetic and must never be used for a deployment.

Build separate images with `docker build --target api -t openmettle-api:test .`, `docker build --target worker -t openmettle-worker:test .` and `docker build --target gateway -t openmettle-gateway:test .`. No images are published by CI. The [process contract fixture](runtime/process-contract.json) supplies separate service-account names, resource request examples and probes for deploy. The [Kubernetes qualification](tests/kubernetes/README.md) workflow runs that contract on an ephemeral kind cluster classified dev. It observes separate ServiceAccounts with token automount disabled, the requested resources, independent process settings, readiness, API and gateway survival with the worker scaled to zero, independent scaling and clean shutdown. Its manifests are test fixtures. Resource sizing is unqualified, and generic Helm packaging and RBAC belong to deploy (V1-32).

## Application API contract

[ADR 0007](docs/adr/0007-application-api-contract.md) defines the v1 HTTP/JSON contract in [contracts/](contracts/README.md): one canonical OpenAPI 3.2.1 document, fixtures generated from its examples and offline compatibility checks that need no Flutter client. It specifies errors, pagination, idempotency, run-event SSE items and capabilities with independent installed, authorization and readiness dimensions. Operations marked `x-openmettle-implementation: implemented` are served when `OPENMETTLE_API_AUTH_CONFIG` is configured; an API started without `OPENMETTLE_API_AUTH_CONFIG` returns 404 for every `/v1/*` path. The `browserSession` and `nativeSession` schemes describe the settled V1-04 transports. After editing the document, run `python3 scripts/contract_fixtures.py` and commit the regenerated fixtures. `cargo test --test contract` validates the document against the vendored official OpenAPI 3.2 schema, checks every fixture with a JSON Schema 2020-12 validator (a development-only dependency), decodes fixtures with an independent typed consumer and validates the problems a mounted API returns without a database.

The internal evaluator in `src/capabilities.rs` keeps installation, supplied caller decisions and observed readiness separate. Hidden entries are omitted; absent, disabled and non-authorized entries never call the observer. Failures map to a bounded unavailable reason; timeouts remain unknown. No authorization policy or HTTP serialization is implemented. Isolation currently holds because no runtime path calls the evaluator. The ignored runtime suite guards the real PostgreSQL `/readyz` against regression while optional evaluation runs separately in the test harness. CI uses isolated PostgreSQL; the test does not inject providers into the API. The first V1-04/05 handler that hosts an observer must qualify isolation within that process. See ADR 0007 for the acceptance evidence and limits.

## OIDC ID-token verification

[ADR 0008](docs/adr/0008-oidc-id-token-verification.md) adds `src/auth.rs`, an offline verifier for the first V1-04 increment. It uses `openidconnect` to check untrusted ID-token bytes against an explicitly trusted provider (exact HTTPS issuer, client ID and JWKS), an expected nonce and an injected clock. Only RS256 tokens with a single audience pass. A valid token yields only the provider UUID, issuer and subject; failures are fixed categories that never echo token or claim values. The verifier itself has no route, discovery, network access, state/PKCE handling, session, admission or account creation, so it does not authenticate requests. `cargo test --test auth` runs the negative tests offline with in-memory keys.

## Internal browser login transactions

[ADR 0009](docs/adr/0009-protected-login-transactions.md) adds protected PKCE storage,
separately committed AEAD nonce reservations and single-use callback consumption.
An exchange permit owns the callback code and trusted configuration and reaches the
library exchange only after commit acknowledgement. An injected fake transport exercises
code/challenge/client/callback binding. The production transport is described below; the
browser and native login routes are off by default until `OPENMETTLE_API_AUTH_CONFIG` is set.
The nonce verifier accepts stored digests without weakening the existing token checks.
From migration 13 the sealed value also carries an optional home invitation code, at one
fixed length (ADR 0022). Logins sealed before that migration still complete.

The browser cookie handoff below is mounted only when `OPENMETTLE_API_AUTH_CONFIG` is set
(ADR 0025), and the native handoff only when that document also has a native profile
(ADR 0029). Key files are read only by the offline check below and by `openmettle-api` at startup when `OPENMETTLE_API_AUTH_CONFIG` is set. Internal local approval and sessions are described below. The outstanding-login
cap below is not a rate limit. The login router below adds per-process request,
rate and concurrency bounds; public exposure remains blocked on ingress
transport limits, operated cleanup and retired-key reservation reclamation. After database restore,
follow the [Database backup restore](#database-backup-restore-pre-worker-checklist) checklist:
invalidate pending login transactions and rotate the active login encryption key before any
encryption, and never resume restored logins.
These are deployment requirements, not provided recovery commands. Lost/ambiguous logins
restart rather than retrying single-use authorization codes.

## Provider token transport

[ADR 0010](docs/adr/0010-provider-http-transport.md) adds `src/provider_http.rs`, the HTTPS
transport for that exchange. It sends one token `POST` per TLS connection (hyper HTTP/1.1 and
rustls with ring) to an exact configured `https` endpoint. That endpoint must use a DNS host
name. Every DNS answer must pass an address policy before any connection: loopback,
link-local, metadata, IPv6 transition forms and unallocated space are refused. Private
addresses need an explicit per-provider CIDR allowlist. A configured CA bundle replaces the
native roots.

Responses are capped at 32 headers, 8 KiB of header bytes and 64 KiB of body. Ambiguous
framing, compression and trailers are refused. The transport never follows redirects,
retries, pools connections or reads proxy environment variables. Abandoned OS DNS lookups are
the only work that can outlive a dropped request, limited to 8 process-wide slots.

Deployments behind an egress proxy are unsupported. Network policy remains a deployment
control. Managed discovery/JWKS support is described below; runtime configuration loading
and sign-in routes are enabled via `OPENMETTLE_API_AUTH_CONFIG` ([ADR 0025](docs/adr/0025-browser-auth-runtime-mounting.md)).
Stock Keycloak 26.8.2 is qualified in CI ([Hosted Keycloak 26.8.2 CI qualification](#hosted-keycloak-2682-ci-qualification));
owner provider registrations and other OIDC providers remain unqualified.

### Gateway inference conformance adapter

[ADR 0038](docs/adr/0038-sglang-and-external-provider-conformance-adapter.md) adds
`src/provider_http/inference/` (`provider_http::inference`, V1-08 PR2), a bounded gateway
inference conformance adapter built over the same HTTP/1.1 TLS transport core
(`src/provider_http/transport.rs`). It validates explicit requests against pinned model
capability profiles, streams visible text deltas while buffering and validating complete
tool calls, and includes wire conformance fixtures. Live deployed profile qualification
belongs to V1-08 PR3.

## Managed discovery and signing keys

[ADR 0011](docs/adr/0011-managed-provider-keys.md) adds an internal managed login path.
Deployment supplies a keyless identity, exact discovery/JWKS and login endpoints, TLS/egress
configuration, and explicit freshness/cooldown/deadline/capacity policy. A process-owned
`ProviderManager` registers generation-bound handles for preflight, begin, consume,
`ExchangePermit::exchange_with_keys` and `ManagedProvider::release`. Discovery confirms configured destinations; it never
selects URLs. The existing offline APIs and POST-only transport remain available.

Managed exchange sends the authorization code once, then verifies the original ID token with
fresh current keys. A bounded unknown-key refresh can reverify that token once. Valid
replacements retire removed keys, and expired keys never receive outage grace. Both metadata
and keys must remain fresh. The profile requires S256 and RFC 9207 support. It does not
require advertised token-endpoint authentication methods; the client stays public and sends
no secret. Responses with explicit max-age and Date are reused until they expire. Responses
with `no-store` or `no-cache` are reused for an operator-set window, 60 seconds by default and
at most 300, then fetched again
([ADR 0011 amendment](docs/adr/0011-managed-provider-keys.md#amendment-19-nov-2026)). A key
the provider removes can therefore stay trusted until the window ends.
These are compatibility limits, not real-provider qualification. The maintained verifier supports RSA
through 4096 bits; the online document parser's 8192-bit ceiling does not expand that support.

Keep the manager alive across requests. Registering identical configuration is a no-op;
a changed configuration or a retire/restore retains cooldown and invalidates keys. A document
expiring before cooldown ends blocks login until another refresh is allowed. For a provider
that refuses caching, set `provider_refresh.uncacheable_reuse_seconds` explicitly: the
offline check then requires it to be at least the cooldown, so the documents do not expire
while a refresh is still blocked unless the response carries `Age`. Provider Age,
short cache lifetimes and clock skew can reduce availability; qualify policy values against
actual provider behavior. The offline check below validates configuration files;
`openmettle-api` loads a version-2 document at startup only when `OPENMETTLE_API_AUTH_CONFIG`
is set.
The managed provider returns a sealed proof to the internal session consumer described below. `cargo test --lib provider_keys --locked --offline` exercises isolated TLS,
rotation, cancellation, capacity and freshness behavior without PostgreSQL.

## Login provider authority

[ADR 0012](docs/adr/0012-login-provider-authority.md) makes managed login depend on a durable,
operator-owned authority in migration 7. `openmettle.login_providers` fixes each provider
UUID to its issuer and client; `openmettle.login_provider_revisions` is an append-only log
whose latest epoch per provider is current, with a `NULL` revision meaning retired. Only
`openmettle_owner` writes these tables, using the locked protocol transaction in ADR 0012;
the API can only read them. Stored logins bind the full configuration and that epoch, never a
process counter.

Begin and consume read authority inside their transactions. A managed exchange returns a sealed
result; `ManagedProvider::release` rechecks authority in a fresh read-only transaction before
returning an identity. Retiring or changing a revision therefore refuses pending logins and
in-flight exchanges on every replica at their next authority read. Release linearizes at its
read snapshot; a change committed after that snapshot is ordered after the release. After an
upgrade the tables are empty and managed login fails closed until providers are recorded.

After restoring the database, follow the [Database backup restore](#database-backup-restore-pre-worker-checklist)
checklist before reopening. Authority reads must use the primary, and acknowledged
commits must survive failover; lagging standbys and asynchronous failover are unsupported.
The database stores revisions, not full configuration: keep configuration identical across
replicas for the same revision. `cargo test --locked --offline --lib provider_keys::tests::postgres -- --ignored --skip provider_keys::tests::postgres::browser::`
runs the managed PostgreSQL tests against an isolated test database only. The first-approval
and approval-change session tests also need `POSTGRES_CONTAINER`, the isolated CI service
container whose `psql` runs the operator scripts.

## Local identity approval and sessions

[ADR 0013](docs/adr/0013-local-identity-sessions.md) adds internal sessions for already-existing
exact issuer/subject identities with a personal scope and owner-recorded local approval.
For a new home user, an operator can authorize first-account creation with a single-use
[invitation bound to the exact provider, issuer and subject](docs/operator/home-invitations.md).
From schema 13, redeeming it also requires the one-time code that the create command prints.
The person enters it in the browser sign-in form, and the login seals it until redemption
([ADR 0022](docs/adr/0022-home-invitation-codes.md)). `ManagedProvider::issue_session` consumes
only its sealed online proof; an offline `VerifiedIdentity` cannot mint a session. From schema
18 only the `openmettle_issuance` role can insert a session, mark a login issued, record
membership evidence, create a native handoff or redeem an invitation
([ADR 0030](docs/adr/0030-session-issuance-database-boundary.md)), so SQL limited to
`openmettle_api` can no longer forge a session. Issuance commits on an issuance connection, and
the credential is released only after a fresh validation on a primary `openmettle_api`
connection.

Routine configuration/approval revisions preserve sessions. Explicit revoke, provider retirement,
approval withdrawal and user disablement advance access generations; restoration never revives
old sessions. Follow ADR 0013's updated owner write protocol, including the provider lock before
epoch allocation. Owners create an approval with the
[first local identity approval procedure](docs/operator/first-identity-approval.md) and change
it with the [approval change procedure](docs/operator/identity-approval-change.md).
On schema version 10 or later, owners can perform an [audited restoration of a retired provider](docs/operator/restore-login-provider.md) during an OIDC outage. Fresh login still requires a successful provider exchange and current local approval.
Validation and logout use the primary database without provider network access.
Session context alone grants no resource access: schema 15 stores V1-05 authorization state
(project settings, local groups, account administrators, capability denies and an append-only
audit), enforced per request on every authenticated `/v1` route when `OPENMETTLE_API_AUTH_CONFIG`
is configured ([ADR 0027](docs/adr/0027-authorization-and-private-projects.md)).
Owners designate the first or a break-glass `account_admin` with the
[account administrator procedure](docs/operator/account-admin-recovery.md).

Credentials are random opaque values; only domain-separated digests are stored. Lifetime,
retained-row allowance and operation deadline are explicit bounded inputs with no deployment
defaults. Issuance must finish before the originating login's existing expiry. A delayed commit
can leave an undisclosed row but never returns a credential after failed final checks.
Operators can free retained-session capacity by deleting revoked or expired sessions, then
remove expired login gates that no session references. Each step skips locked rows and commits a separate batch.
The operator sets a limit of 1–1000 rows per batch. Session deletion
preserves issuance markers and nonce reservations. See the
[session and login-gate cleanup procedure](docs/operator/session-cleanup.md).

For enrolled approvals, session issuance reconciles mapped project group memberships (`membership::reconcile`, [ADR 0021](docs/adr/0021-project-membership.md)); broader tenant/group qualification remains outside this core increment. The cookie handoff below is mounted only on request (ADR 0025) and the native handoff only with a native profile (ADR 0029).
Run the managed PostgreSQL tests only in isolated CI with the explicit module filter above;
normal workspace tests leave them ignored. Migration 8 and authentic v7 compatibility are CI gates.

## Outstanding login admission

[ADR 0014](docs/adr/0014-login-admission.md) adds migration 9: one owner-configured limit on
outstanding login rows (unexpired, no issued session, consumed or not). It is an
outstanding-work cap, not a rate limiter, request/concurrency control or storage bound. The
limit installs as NULL, so **every login initiation is refused until the owner sets it**; 65 536
is an implementation ceiling, not a deployment default. The API can read and lock the row
but not change it.

Initiation first runs an advisory read-only precheck, so unconfigured, full or
stale-authority attempts spend no nonce reservation. It then reserves a nonce as before and
rechecks under an exclusive lock with the primary clock sampled after the wait. Concurrent,
cancelled or refused-after-precheck attempts still spend one permanent reservation each;
reservations keep growing by design. Begin and consume now await rollback on every returned
error so idle connections never keep row or admission locks.

Change the limit only with
[`docs/operator/login-admission-limit.psql`](docs/operator/login-admission-limit.psql)
(compare-and-set; lowering preserves existing rows). Remove expired, unreferenced login gates
with [`docs/operator/login-gate-cleanup.psql`](docs/operator/login-gate-cleanup.psql)
(batch 1–1000, `SKIP LOCKED`; never deletes nonce reservations), as the second step of the
cleanup procedure above. CI runs these scripts unchanged with the pinned PostgreSQL 18
`psql`. No limit, schedule or retention value is selected. Old version-8 replicas do not
enforce the cap during a rolling upgrade.

## Offline browser-auth configuration check

[ADR 0015](docs/adr/0015-offline-auth-config-check.md) adds `src/auth_config.rs`, a typed
loader for mounted browser-auth settings, and one API argument form that runs it and exits:

```sh
openmettle-api --check-auth-config /etc/openmettle/auth/auth.json
```

Use the exit status to check the result. Exit 0 indicates success and writes
`auth configuration valid (local files only)` to stdout. A write error returns 1.
Invalid configuration returns 78 with `auth configuration error:` and one fixed category.
Invalid arguments also return 78. The check needs no `DATABASE_URL`, opens no listener and
makes no DNS, provider or database request. Run it in the API image with the mounts and
environment the API will use before installing changed settings.

Starting the API without arguments is unchanged and loads none of these files. The worker and
migrator never read them. The API serves from a version-2 document only when
`OPENMETTLE_API_AUTH_CONFIG` names it ([ADR 0025](docs/adr/0025-browser-auth-runtime-mounting.md)).
There is no live reload.

The check reads one JSON document, version 1 or 2, and the files it names. Native trust also
loads platform roots and honors `SSL_CERT_FILE` and `SSL_CERT_DIR` under ADR 0010. ADR 0015
gives the version-1 shape with synthetic values. Version 2 adds one required browser-routing
profile, described below.

- In the base profile, every setting is required, with its unit in the field name, except
  `provider_refresh.uncacheable_reuse_seconds`. That one is optional: the reuse window for
  provider documents that refuse caching, 60 seconds when absent. An explicit value must be
  1–300 seconds, at least `cooldown_seconds` and at most `freshness_seconds`. No other
  default or operational value is selected. Unknown, repeated, missing or mistyped fields are
  refused in every object.
- At least one provider, each with a unique canonical UUID, exact issuer and client, revision,
  HTTPS endpoints, callback, destination tag, private CIDRs and either native roots or one PEM
  bundle. The existing constructors (ADRs 0008–0013) judge every value.
- Every path is absolute. Symbolic links are followed, so Kubernetes projected volumes work,
  but each must resolve to a regular file. Directories, FIFOs, sockets and devices are
  refused without being opened.
- Login keys are files of exactly 32 raw bytes: the active key first, then up to three
  decrypt-only keys. Secrets cannot be inlined or supplied through the environment. The check
  never creates a file, changes a permission or generates a key.

File ownership and mode are not inspected. Mount the document, keys and bundles read-only
from directories that only the deployment authority can write. The check does not defend
against a hostile local writer.

A successful check covers local files only. It does not show that a provider is reachable or
that the database agrees: each `revision` must equal the current revision recorded under
ADR 0012, and the ADR 0014 limit must be set. Keep the document, keys and bundles identical
on every replica for a revision. Follow ADR 0015 for login-key rotation, provider revision
changes and the unchanged restore requirements. `cargo test --locked --offline --lib auth_config`
runs the loader tests without PostgreSQL or network access.

### Run cursor keys (version 2)

Add the optional top-level `cursor_keys` object to enable run reads (`GET /v1/runs/{run_id}`,
`GET /v1/runs/{run_id}/events`), run admission/cancellation (`POST /v1/runs`,
`POST /v1/runs/{run_id}/cancel`), and paginated list cursors. If omitted, the API starts and
requests that require cursor keys receive `503 provisioning`. Generate 32 fresh random bytes
for each key in a private deployment directory. For example, for a new file:

```sh
(umask 077; set -C; openssl rand 32 > cursor-b)
```

Mount the raw file read-only on every API replica and reference its absolute path:

```json
"cursor_keys": {
  "active": {"id": "cursor-b", "path": "/etc/openmettle/auth-keys/cursor-b"},
  "verify_only": []
}
```

Use distinct identifiers of 1–64 ASCII letters, digits, hyphens or underscores. Use separate
material for every cursor and login key. For rotation, first distribute the new key in
`verify_only` on every replica. Then activate it and move the old key to `verify_only`
(up to three keys). Remove the old key when clients may resynchronize from a snapshot.
At each step, run `openmettle-api --check-auth-config /etc/openmettle/auth/auth.json`
against the mounted files before restarting the replicas. After a database restore, replace
all pre-restore cursor keys before reopening the API (see [Database backup restore](#database-backup-restore-pre-worker-checklist)).

### Model catalog and run admission limits (version 2)

Version 2 adds two optional top-level fields used by the catalog, branch preview and run
admission routes ([ADR 0032](docs/adr/0032-durable-run-admission-and-fair-work-queue.md),
[ADR 0036](docs/adr/0036-conversation-branches-presets-and-effective-model-config.md)).
Version 1 must not contain either field.

- `catalog_file`: optional absolute path to a regular JSON catalog file validated by
  `--check-auth-config` and loaded once at startup. A relative path exits 78 with
  `auth configuration error: a path is not absolute`, while an unreadable or invalid catalog
  file exits 78 with `auth configuration error: model catalog is unreadable or invalid`.
  When omitted, authorized first-page `GET /v1/models` and `GET /v1/presets` return `200`
  with empty `items: []`, `GET /v1/presets/{preset_id}` returns `404 not_found`, and
  `POST …/effective-configuration` and fresh `POST /v1/runs` admissions answer
  `503 provisioning` (an exact idempotent `POST /v1/runs` replay still returns the current
  run projection—re-read from PostgreSQL and re-signed with a fresh cursor, reflecting current
  state such as `cancelled` and the latest sequence—without `catalog_file`, provided
  `admission_limits` and `cursor_keys` are configured; `POST …/effective-configuration` does
  not require `admission_limits`).
- `admission_limits`: optional object setting the admission bounds for `POST /v1/runs`:
  `live_per_actor` (1–1,000), `live_per_scope` (1–10,000), `queued_in_instance` (1–10,000),
  `queue_timeout_seconds` (1–86,400) and `round_cap` (1–1,000). Missing or unknown fields
  exit 78 with `auth configuration error: configuration lacks a required field` or
  `auth configuration error: configuration has an unknown field`. Non-object values (including
  `null`) and member values that are not plain non-negative JSON integers—such as negative
  integers like `-1`, fractions, exponents, strings or `null`—fail unsigned integer parsing
  and exit 78 with
  `auth configuration error: a configuration field has the wrong type or keyword`. Parsed
  unsigned integers that violate those per-field semantic bounds (for example `0`, `1001` for
  `live_per_actor` or `round_cap`, `10001` for `live_per_scope` or `queued_in_instance`, or
  `86401` for `queue_timeout_seconds`) exit 78 with
  `auth configuration error: run admission limits are invalid`. When omitted, `POST /v1/runs`
  answers `503 provisioning` (fresh `POST /v1/runs` also requires `catalog_file` and
  `cursor_keys`, exact replays also require `cursor_keys`, and `POST /v1/runs/{run_id}/cancel`
  requires `cursor_keys`).

### Browser-routing profile (version 2)

[ADR 0020](docs/adr/0020-browser-routing-profile.md) defines version 2: every version-1
member plus one required `browser` object. It selects one configured provider UUID and
sets the canonical HTTPS application origin, the landing path, three literal paths
(initiation, session check and logout), four rate budgets (initiation, callback, session
check and logout, each a burst and `interval_milliseconds`) and one shared `max_in_flight`
cap. The callback path comes from the selected provider's registered callback. Nothing has
a default.

The same checks as the handoff and router (ADRs 0017–0019) judge these values,
without a database, async runtime, listener or provider request. A refusal is
`auth configuration error: browser profile refused: ` followed by one fixed category. A
version-1 document still passes unchanged and must not contain `browser`. The API mounts
the profile's routes only when `OPENMETTLE_API_AUTH_CONFIG` names the document
([ADR 0025](docs/adr/0025-browser-auth-runtime-mounting.md)); by default it serves
`/healthz` and `/readyz` only. The check cannot show that ingress, browsers or the provider registration agree with it.

### Native sign-in profile (version 2)

[ADR 0029](docs/adr/0029-native-sign-in-mounting-and-session-context.md) adds one optional
`native` object to version 2. When present it needs all of `provider_id`, `issuer` (the
canonical HTTPS origin that serves the native routes), `callback` (the exact upstream
callback on that origin), `client_id` (1–128 ASCII letters, digits, `-`, `.` or `_`),
`redirect_uri` (the exact HTTPS app link), `rate` (`burst` 1–65 536 and
`interval_milliseconds` 1–3 600 000, applied to each native route and method) and
`max_in_flight` (1–1024). Absent means no native routes; `null` is refused. Version 1 must
not contain it.

`--check-auth-config` and API startup judge it with the native service's own settings
check, after the browser profile. The native paths and the app link must not collide with
`/healthz`, `/readyz`, the browser routes or a provider's registered callback. A refusal is
`auth configuration error: native profile refused: ` followed by one fixed category.

## Pooled browser-auth service

[ADR 0016](docs/adr/0016-pooled-browser-auth-service.md) adds `src/browser_auth.rs`, one
internal service built from the validated settings above, a handle to the API's existing
primary pool and, from [ADR 0030](docs/adr/0030-session-issuance-database-boundary.md), one to
its issuance pool. It starts a login for an exactly configured provider UUID, completes a
callback (committed consumption, one token request, session issuance from the sealed proof)
and validates or logs out local sessions. **No process constructs it by default**; the API
does so only under ADR 0025. `/readyz` checks the database only. The service handles no
request or cookie itself and has no rate policy; the adapter and router below do.

The service holds a pooled connection only while database work runs, never during a
provider document fetch or the token request, and never one from each pool at once: a
callback consumes on the primary, exchanges with neither, issues on the issuance pool and
returns that connection before the final validation asks the primary for one. Waiting for a connection counts against the
existing deadlines and never extends the login's expiry or the proof's original deadline.
Validation and logout contact no provider.

A connection returns to the pool only after success or an ordinary denial whose COMMIT or
ROLLBACK was acknowledged. After cancellation, a deadline, a panic or a `Database` or
`Timeout` error it is closed and the pool opens a replacement. Nothing is retried; restart
the login after any failure. Limits to plan for before exposure:

- SQLx closes the connection on its own task (at most 5 seconds) and keeps the pool slot
  counted until then.
- Closing the socket does not interrupt PostgreSQL. A cancelled backend can keep row locks
  until its statement ends, normally within the 2-second lock and 3-second statement
  timeouts these transactions set.
- A replacement can briefly coexist with the old backend, so server connections can exceed
  `DB_MAX_CONNECTIONS` for that process. The connection budget below does not include this.

ADR 0016 lists the reuse rules per error category and the evidence. Its PostgreSQL tests run
only in isolated CI, under the existing `provider_keys::tests::postgres` filter. Locally,
`cargo test --locked --offline --lib browser_auth` and
`cargo test --locked --offline --lib provider_keys::tests::service` run the tests that need
no database. Connection churn and capacity under load are unmeasured.

## Browser login handoff

[ADR 0017](docs/adr/0017-browser-login-handoff.md) adds `src/browser_auth/handoff.rs`, an
adapter that turns one browser request into one response over the service above. **It is
not mounted by default**: unless ADR 0025's setting is given, no process constructs it and
the API serves `/healthz` and `/readyz` only and answers `404` for a callback path. The isolated CI browser fixture is described below.

It takes three explicit settings with no defaults: the canonical HTTPS application origin,
a landing path on that origin and one configured provider UUID. Auth settings version 2
carries them and the offline check applies the adapter's own checks (ADR 0020). The issuer and the exact registered callback
come from that provider. `Host`, forwarded headers, callback fields and return URLs never
select an origin, provider, callback or destination.

- **Initiation** accepts a form `POST` with exactly one `Origin` equal to the application
  origin. It answers `303` to the provider's authorization URL and sets
  `__Host-openmettle-login` (`Secure`, `HttpOnly`, `Path=/`, `SameSite=Lax`, `Max-Age` equal
  to the login lifetime). The page with the form must not use `Referrer-Policy: no-referrer`,
  which makes browsers send `Origin: null`. The form may carry one optional field,
  `invitation_code`, for a first sign-in (ADR 0022). Any other field or a malformed code is
  `400` before any provider or database work. The response is the same with or without a
  code.
- **Callback** accepts a `GET` on the exact registered callback path. It refuses malformed
  escapes, repeated parameters, provider errors, an incomplete response, a missing or
  different `iss` and a missing, repeated or mismatched caller cookie before calling the
  service. Success answers `303` to the landing and sets `__Host-openmettle-session` with
  the same attributes and no `Max-Age`; expiry in the database stays authoritative.
- **Every response** has `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
  Refusals are fixed lines that set and delete no cookie. The landing URL and response
  bodies carry no credential, code, state or caller secret.

A browser holds one caller cookie for the application hostname. If a callback carries
another login's cookie, the transaction named by the callback stays unconsumed and holds its
admission slot until expiry. A callback already sent with its matching cookie can still
finish. A new login replaces the browser's session cookie. The earlier session stays valid
until expiry or revocation.

Before exposure, remaining work includes broader browser qualification, trusted ingress
routing for the application origin and redaction of request targets and cookies in
ingress/proxy telemetry, ingress transport limits, and operated cleanup and retired-key
reservation reclamation. The router below supplies per-process request, rate and
concurrency bounds, plus the optional off-by-default session check and logout routes
(mounted only when `OPENMETTLE_API_AUTH_CONFIG` is configured). `cargo test --locked --offline --lib handoff` runs the tests that need no database;
the end-to-end test runs only in isolated CI under the existing
`provider_keys::tests::postgres` filter.

## Bounded browser login router

[ADR 0018](docs/adr/0018-bounded-login-router.md) adds `src/browser_auth/router.rs`, which
builds an Axum router over the handoff above. **It is not mounted by default**: the API
mounts `router_with_sessions` only under ADR 0025, and otherwise the API and worker serve
`/healthz` and `/readyz` only.

It routes two exact literal paths: an explicit initiation path for the form `POST`, and the
provider's registered callback path for `GET`. Both are validated before any route is
built. Route syntax, escapes, dot or empty segments, a shared path and `/healthz` or
`/readyz` are refused with fixed categories, never a panic. Any other method, including
`HEAD`, is `405` and reaches no login work.

Every other setting is explicit, with no defaults: a rate budget for initiations, a separate
one for callbacks (burst and refill interval each) and one in-flight cap shared by both
routes. The ranges in ADR 0018 are implementation ceilings, not operating values. Auth
settings version 2 carries these settings, and the offline check runs the router's own
validation (ADR 0020). Requests
are decided in this order, and the first four steps do no provider, pool or database work:

1. Method (`405`).
2. Request bounds measured after HTTP parsing: a target of at most 33 792 bytes (`414`), at
   most 64 header fields and 24 576 header bytes (`431`), and an empty body (`413`). The body
   is judged from its metadata and never read, so a nonzero declared length or chunked body
   is refused without waiting for it. The handoff's query and cookie ceilings still fit and still apply.
   The initiation route alone also admits one declared `application/x-www-form-urlencoded`
   body of at most 256 bytes, for the invitation code field (ADR 0022).
3. An in-flight permit, without waiting (`503`, `login busy; try again later`).
4. One unit of the route's rate budget (`429`). A unit is spent here, before the handoff
   decides, and is never refunded. Earlier refusals spend nothing.
5. The handoff, with the original request head. A dropped request releases its permit. A
   declared initiation form is read first, under the permit: at most 256 bytes within 2
   seconds, or `408`.

These refusals are fixed lines with `no-store`, `no-referrer`, no cookie and no `Location`.
Mount the router with `Router::merge`, never `Router::nest`, and keep ingress from
rewriting the path.

The bounds hold per router value and its clones in one process. They are not cluster-wide,
fair between clients, durable across restarts or a limit on what the HTTP server reads
while parsing a request head. Deployments still need ingress and server transport limits
before exposure. `cargo test --locked --offline --lib browser_auth::router` and
`cargo test --locked --offline --lib provider_keys::tests::router` run the local tests,
which serve the router on loopback. The PostgreSQL handoff case also completes a login
through the router, in isolated CI only.

## Session check and logout routes

[ADR 0019](docs/adr/0019-session-check-and-logout-routes.md) adds `router_with_sessions`,
which builds the router above plus two explicit literal routes. **They are not mounted by
default**: the API mounts this router only under ADR 0025, and otherwise the API and worker
answer `404` for every login and session path. `router` itself is unchanged and still builds only the login routes.

The session and logout paths obey the same shape and collision rules as the login paths.
All four must differ. Each route has its own rate budget (burst and refill interval,
explicit, no defaults), so session polling cannot spend logout or login rate. The in-flight
cap is shared by all four. Requests pass the same method, bound, permit and rate steps
before any service call.

- **Session check** accepts a `GET` with exactly one `Sec-Fetch-Site: same-origin` field.
  The browser must supply this field before the check reads cookies. The check requires
  exactly one `__Host-openmettle-session` cookie. A valid session gets an empty `204` with
  no identity, cookie or redirect. An invalid credential gets `403 session not valid`.
  Operational failures get `503`.
- **Logout** accepts a form `POST` with an empty body and exactly one `Origin` equal to the
  application origin, by the same rule as initiation. Any other `Origin` is `403` before
  the cookie is read. `BrowserAuth::logout` then revokes by possession, with no eligibility
  check, so an issued session can be ended after expiry, disablement or lost approval.
  Only after the commit is acknowledged does the response become `204` with one deletion:
  `__Host-openmettle-session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`.
  Refusals and failures delete nothing. The caller cookie is left alone. Other sessions of
  the same user are not revoked.

Every response has `no-store` and `no-referrer`. Fixed lines carry no request, cookie or
credential value. Repeated logout with the same credential is acknowledged again while the
revoked row is retained. After cleanup removes the row, logout returns `403 session not
valid`. A browser applies `Set-Cookie` in response processing order. A logout deletion can
remove a new cookie set in another tab while that new session stays valid in the database.
ADR 0019 describes these orderings and the per-process budget limits.

Cross-browser qualification, ingress limits and ingress/proxy telemetry redaction remain
outstanding. `cargo test --locked --offline --lib provider_keys::tests::session_routes`
runs the loopback tests. The PostgreSQL case
`provider_keys::tests::postgres::handoff::issued_cookies_validate_and_logout_revokes_without_current_eligibility`
runs only in isolated CI under the existing filter.

### Single-browser CI qualification

The Rust runtime job selects `provider_keys::tests::postgres::browser::cross_site_session_lifecycle`
once against its isolated PostgreSQL 18 service. The ignored test requires runner-provided
Google Chrome and NSS `certutil`. It prints the version reported by the running browser.
Normal offline workspace tests leave this case ignored.

The fixture serves the application at `app.relying.test` and the synthetic provider's
authorization page at `issuer.example.test`, on ephemeral loopback ports with HTTPS.
Chrome trusts the temporary CA in a private NSS database. A form on the issuer site
first attempts a login that the router refuses. An application form then starts a login.
Chrome commits the issuer document, follows its link back to the callback, and reaches
the configured landing URL with no query or fragment. The fixture checks the browser's
cross-site document GET, one PKCE-bound
token POST, a successful same-origin session check, an acknowledged logout POST, and
a refused check after Chrome removes the session cookie. PostgreSQL must contain one
consumed login and its revoked session for the approved synthetic user.

A passing run supplies evidence for the Chrome version in that run.

### Hosted Keycloak 26.8.2 CI qualification

The dedicated workflow `.github/workflows/keycloak-qualification.yml` exercises the
browser auth stack, served in-process by the test, against a pinned stock Keycloak 26.8.2 container
(`quay.io/keycloak/keycloak@sha256:c68e286cacd87b942ac1939a0a1481461109d6acd3a57dc496969a319a76bbf0`)
on an isolated `--internal` Docker bridge network (no container egress) alongside PostgreSQL 18
and headless Chrome.

`tests/keycloak/fixture.py` creates a per-run test CA and provider certificate for
`keycloak.provider.test`, imports a synthetic realm with one public PKCE `S256` client, exact
redirect URI, RFC 9207 `iss` enabled and two synthetic users with generated passwords written
only to files, and writes a version-2 auth settings document with explicit
`provider_refresh.uncacheable_reuse_seconds` (300 s, at least the 60 s cooldown) and
`trust.roots = "bundle"` pointing solely at the per-run CA. After
`openmettle-api --check-auth-config` validates the file offline and HTTPS discovery passes
strictly against the test CA, the ignored test
`provider_keys::tests::postgres::browser::keycloak_browser_sign_in_qualification` loads the
settings via `auth_config::load`, serves `BrowserAuth` / `LoginHandoff` / `router_with_sessions`
on loopback HTTPS, and drives two full Chrome journeys:

1. An existing synthetic identity approved with `docs/operator/first-identity-approval.psql`
   (ADR 0013).
2. A first-account redemption using a single-use code created with
   `docs/operator/home-invitation-create.psql` (ADR 0022).

Both journeys assert PKCE `S256`, exact redirect URI, RFC 9207 `iss` on the cross-site callback,
ID-token verification, session issuance, same-origin session check (`204`), logout (`204`),
post-logout refusal (`403 session not valid`), PostgreSQL state, and that discovery and JWKS
were fetched once over HTTPS and reused across begin, callback and the second sign-in inside the
configured `uncacheable_reuse_seconds` window.

This is CI qualification of pinned stock Keycloak 26.8.2 against the router served in-process, not the
`openmettle-api` binary, owner deployment or production enablement. Other browser engines, mobile and native handoff, other OIDC providers, owner provider
registrations, and deployed ingress remain qualification gaps for V1-04.

## Native sign-in

[ADR 0023](docs/adr/0023-native-sign-in.md) adds `src/browser_auth/native.rs`, a router
that brokers sign-in for a native app through the same provider registration, with its own
upstream callback. **It is off by default.** The API mounts it only from a
[native profile](#native-sign-in-profile-version-2) (ADR 0029). The app opens the system browser
at the deployment, where the person confirms the sign-in and, for a first sign-in, enters
their [invitation code](docs/operator/home-invitations.md). The app never handles that
code. After the provider sign-in the API redirects to the app's registered HTTPS link with
a one-use code. The app exchanges that code and its own PKCE verifier over a back channel
for an opaque bearer. A browser-cookie session and a native bearer have separate digest
domains, so neither validates as the other. Each bearer validates and signs out only
through the native registration that delivered it.

Migration 14 adds the delivery table and lets a login that a native sign-in started redeem
a home invitation under the same rules as a browser login, including the code. The ADR
gives the protocol, limits, evidence and the gates that remain before exposure, including
device link ownership and the companion app's simulator qualification.

## Schema migrations

Read [ADR 0003](docs/adr/0003-schema-migrations.md) for the migration, role and ownership contract and [ADR 0004](docs/adr/0004-run-persistence.md) for run/event/operation persistence, limits and replay semantics, [ADR 0005](docs/adr/0005-artifact-storage-accounting.md) for artifact revisions, storage reservations and byte accounting, and [ADR 0006](docs/adr/0006-grant-persistence.md) for grant provenance, replay and revocation persistence. PostgreSQL 18 is the only qualified major version. Migrations in `migrations/` are embedded in the `openmettle-migrate` binary, forward-only and transactional; released migrations are never edited. Run the migrate image once per release, before rolling out new API and worker versions. Each release's migrations must remain compatible with the previous API and worker, with one deliberate exception: on schema 18 the previous API's sign-in completion and first-account redemption fail closed, because it issues as `openmettle_api` ([ADR 0030](docs/adr/0030-session-issuance-database-boundary.md#upgrade)).

Provision the roles and one dedicated database before the first migration, using deployment-managed secrets for passwords. Before creating anything, and on every later run, the migrator checks the provisioning and exits 1 with nothing changed if it is unsafe. Log in as `openmettle_owner`, which must own the database. Do not make any of these roles superuser or give them CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS. Keep `openmettle_owner`, `openmettle_api`, `openmettle_issuance`, `openmettle_worker` and `openmettle_gateway` out of every other role, including predefined roles such as `pg_read_all_data` and `pg_write_all_data`; this applies to `SET ROLE`-only memberships too. Separate login roles may be members of exactly one of `openmettle_api`, `openmettle_issuance`, `openmettle_worker` or `openmettle_gateway` and of nothing else. Do not grant those roles, their logins or `PUBLIC` any database, schema or table privilege yourself, and do not set default privileges for `openmettle_owner`; the migrations grant exactly what [ADR 0003](docs/adr/0003-schema-migrations.md) and the subsequent schema ADRs list. The error names each violation to fix. Role names are cluster-global: installations sharing a PostgreSQL cluster would share these roles and so each other's database access, which this increment does not isolate. A superuser runs, for example (psql variables):

```sql
CREATE ROLE openmettle_owner LOGIN PASSWORD :'owner_password';
CREATE ROLE openmettle_api LOGIN PASSWORD :'api_password' CONNECTION LIMIT 8;
CREATE ROLE openmettle_issuance LOGIN PASSWORD :'issuance_password' CONNECTION LIMIT 4;
CREATE ROLE openmettle_worker LOGIN PASSWORD :'worker_password' CONNECTION LIMIT 8;
CREATE ROLE openmettle_gateway LOGIN PASSWORD :'gateway_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 8;
CREATE DATABASE openmettle OWNER openmettle_owner;
```

`openmettle_issuance` is required from migration 18 ([ADR 0030](docs/adr/0030-session-issuance-database-boundary.md)), and `openmettle_gateway` is required from migration 23 ([ADR 0037](docs/adr/0037-gateway-provisioning-and-usage-reconciliation.md), [ADR 0044](docs/adr/0044-own-inference-proxy-and-binding-free-dispatch.md)). On an existing installation, create each required role before migrating; while a required role is missing, the migration refuses, rolls back and leaves the previous schema. Migration 18 keeps every session, and existing sessions stay valid. Where `openmettle_api` SQL may have been exposed, revoke every pre-upgrade session after migration 18 commits and before the new release serves sign-ins, with the statement in [ADR 0030](docs/adr/0030-session-issuance-database-boundary.md#upgrade) run as `openmettle_owner` on the primary. Each person then signs in again.

Then run the migrator with the owner's URL. It reads `OPENMETTLE_MIGRATE_DATABASE_URL` and optional `OPENMETTLE_MIGRATE_CONNECT_TIMEOUT_MS` (default 5000), `OPENMETTLE_MIGRATE_LOCK_TIMEOUT_MS` (default 15000) and `OPENMETTLE_MIGRATE_STATEMENT_TIMEOUT_MS` (default 300000), plus `OPENMETTLE_MIGRATE_LOG_FORMAT` and `OPENMETTLE_MIGRATE_LOG_LEVEL` as described under Runtime. On success it prints `schema is at migration N` to stdout; a failure prints `migration error:` and a fixed description to stderr, beside a `migration.failed` event. It exits 0 on success, 78 on invalid configuration and 1 on any other failure, including a lock wait past its deadline. Concurrent runs are serialized. A failed or interrupted run leaves no partial migration and can be retried immediately. A checksum mismatch or a database newer than the binary is refused. Do not delete history rows or rerun edited files; ship a corrective migration or restore a backup instead.

```sh
export OPENMETTLE_MIGRATE_DATABASE_URL='postgres://openmettle_owner:<password>@127.0.0.1:5432/openmettle?sslmode=disable'
cargo run --locked --bin openmettle-migrate
```

Give the API `openmettle_api` credentials and, when sign-in is mounted, `openmettle_issuance` credentials as its issuance URL; give the worker `openmettle_worker` credentials; give each `openmettle-gateway` replica `openmettle_gateway` credentials. Never give a process the owner's, and never mount the issuance credential into the worker, gateway or migrator. These roles bound each process, not each user: per-user authorization (V1-05, [ADR 0027](docs/adr/0027-authorization-and-private-projects.md)) is enforced on every authenticated `/v1` route. Migration 22 ([ADR 0035](docs/adr/0035-approvals-permitted-yolo-and-effect-ledger.md)) adds scoped approval requests (`openmettle.run_approvals`), human decision receipts (`openmettle.run_approval_decisions`), admission/YOLO evidence columns on `openmettle.runs`, and a 13-column non-secret `SELECT` grant on `openmettle.local_sessions` for `openmettle_worker` so workers verify session authority without access to credential digests.

Storage limits are durable deployment inputs that only `openmettle_owner` sets, in the single `openmettle.storage_instance` row: `instance_budget_bytes` (the logical ceiling left after operational headroom, not measured disk capacity), `personal_limit_bytes` and `project_limit_bytes`. Migrations install them as NULL, which refuses every new storage reservation until the deployment configures them; see [ADR 0005](docs/adr/0005-artifact-storage-accounting.md#limits). Lowering a limit preserves existing data and reservations and refuses only new reservations.

Migration 27 ([ADR 0042](docs/adr/0042-shared-capacity-api-and-resource-grants.md)) adds the fenced GPU capacity store. `openmettle_owner` configures each managed group in `openmettle.capacity_groups` (`id`, `observation_ttl_ms` from 1,000 to 600,000) and its devices in `openmettle.capacity_devices` (`id`, `group_id`, and `chat_floor_bytes`, the minimum active-chat floor the current sample must cover). A device belongs to one group and cannot move to another in this release; moving one, even with only released grant history, needs a later migration. Raising a floor closes the group to new grants until a sample covers the new floor. A device configuration write locks its own group, so it waits for that group's in-progress decisions; add devices once their group is committed, or in the transaction that creates it. A configuration transaction can still deadlock with another that changes devices in several groups, or (a device `DELETE`, say) with a concurrent grant or publication that references the device; PostgreSQL aborts one (SQLSTATE `40P01`), and it can be retried. Controller epochs come from one database sequence, so a recreated group never reuses an epoch. `openmettle_worker` reads the store and changes it only through fenced functions that require `READ COMMITTED` and the controller secret returned once on acquisition; no process runs the controller yet, and no route exposes capacity. A run's committed `device_reservations` slot is credited only when a released capacity grant bound to it exists, so a slot bound before migration 27 stays charged.

Migration 28 ([ADR 0041](docs/adr/0041-retention-purge-and-deletion-journal.md), V1-16 PR2a) makes artifact retention policy-driven. `openmettle_owner` sets the deployment bounds in the single `openmettle.retention_policy` row (`min_grace_seconds`, `max_grace_seconds`); the migration installs `[2592000, 2592000]`, so only the 30-day default grace applies until the operator widens them, and `0` (purge eligibility as soon as a revision is removed) needs `min_grace_seconds = 0`. Within the bounds an active `account_admin` changes `grace_seconds` through `openmettle.retention_set_grace(actor, approval, grace_seconds, reason, request_key)` (replaced with the approval-bound 5-argument form in migration 38 so changes serialize with demotion, user disablement, approval withdrawal, provider retirement and post-lock approval expiry), called in a `READ COMMITTED` transaction, which writes an `authorization_audit` row; no route calls it yet. Every change increments `revision`, and a change affects later removals only. The database sets each removal's deadline from the current policy and its wall clock, whatever the caller supplies. The operator places a hold that keeps a revision from purge by inserting it into `openmettle.artifact_retention_holds`, and releases it by deleting the row. A revision is never claimed for purge while it is attached to any message (conversations cannot be deleted yet, so attached revisions are never purged), held, or written by a run that has not finished or has an operation without a known outcome. As break-glass erasure, `openmettle_owner` may still move such a revision to `purging` itself; the worker then deletes its payload, and the purge is journaled like any other. Each confirmed purge appends one hash-chained record to `openmettle.deletion_journal` in the same transaction. No application role can read or change the journal or its head (`deletion_journal_head`), and its export and restore replay are not implemented yet (PR2b). For the upgrade from 27, including purge claims committed before it, see [the operator note](docs/operator/storage-adoption-and-quota-upgrade.md#upgrade-from-0027-to-0028-retention).

Migration 39 ([ADR 0039](docs/adr/0039-scoped-mcp-adapter-and-bounded-tool-results.md), V1-14 PR3) adds `openmettle.runtime_feature_gates` (`two_phase_effect_intents_enabled`, `SELECT` only for `openmettle_api` and `openmettle_worker`) and the `SECURITY DEFINER` terminal write-intent trigger `openmettle.resolve_terminal_write_intents()`. Fresh installations from version `0` start with `two_phase_effect_intents_enabled = true`; populated upgrades from schema `0038` or earlier start with `false` until all previous-release worker replicas exit and the owner runs `openmettle-admin runtime activate-two-phase-intents` ([operator rollout checklist](docs/operator/storage-adoption-and-quota-upgrade.md#upgrade-from-0038-to-0039-mcp-runtime-feature-gate-and-terminal-write-intent-resolution)).

Connection budget: `api_replicas × (API DB_MAX_CONNECTIONS + ISSUANCE_DB_MAX_CONNECTIONS) + worker_replicas × worker DB_MAX_CONNECTIONS + gateway_replicas × gateway DB_MAX_CONNECTIONS + 1 migrator + admin/backup headroom` must not exceed `max_connections − superuser_reserved_connections − reserved_connections` (`gateway_replicas` is `0` when no gateway replica is deployed, or the sum across all per-model gateway Deployments when enabled). Count surge replicas during a rolling update. For example, 2 × (4 + 2) + 2 × 4 + 0 × 4 + 1 + 3 = 24 with no gateway deployed, or 2 × (4 + 2) + 2 × 4 + 1 × 4 + 1 + 3 = 28 with one model gateway replica. Enforce each process's share with its login role's `CONNECTION LIMIT`. These figures are illustrative, not qualified sizing.

### Database backup restore (pre-worker checklist)

After restoring PostgreSQL from a backup, complete all steps below while authentication remains closed and before reopening authentication or starting `openmettle-worker` (this is separate from [retired login-provider recovery](docs/operator/restore-login-provider.md)):

1. **Invalidate all restored sessions and pending logins:** Enumerate **every login provider present in the restored PostgreSQL database** (`openmettle.login_providers`), not only providers listed in the current auth configuration file. Browser session validation reads database provider state, so an unexpired session for a provider omitted from the current config file could still pass if that provider remained active in the backup. Preserve existing provider retirements and reapply any post-backup retirements using [ADR 0013](docs/adr/0013-local-identity-sessions.md)'s owner `retire` protocol (which advances `access_generation` and appends a `NULL`-revision tombstone epoch in one transaction). For every remaining active restored provider, run [ADR 0013](docs/adr/0013-local-identity-sessions.md)'s owner `revoke` protocol with [ADR 0012](docs/adr/0012-login-provider-authority.md)'s epoch allocator rules to advance `access_generation` and append a fresh non-retirement epoch in the same transaction. Appending a non-retirement revision alone fences pending logins without invalidating ordinary sessions, and advancing `access_generation` alone does not fence already-exchanged login proofs. Rotate the active login encryption key ([ADR 0009](docs/adr/0009-protected-login-transactions.md)), replace all pre-restore cursor keys ([ADR 0034](docs/adr/0034-ordered-events-and-replayable-sse.md)), and never resume restored logins.
2. **Reconcile identity approvals, account disablement, authorization revocations, home invitations and login admission limits:** Reconcile restored local identity approvals (`openmettle.local_identity_approvals` withdrawals and revocations), user account disablements (`openmettle.users.disabled_at`, `session_generation`), and administrator demotions (`openmettle.account_admins.active`) against post-backup records. Reconcile local group disablements and membership removals (`openmettle.local_groups.disabled_at`, `openmettle.local_group_memberships.active`), project archives and deletions (`openmettle.project_settings.archived_at`, `deleted_at`), and capability grant revocations or denies (`openmettle.user_capability_grants.granted`, `openmettle.user_capability_denies.denied`, `openmettle.platform_capability_denies.denied`). Also reconcile project membership removals or role reductions and resource-share revocations in `openmettle.grant_assignments` and `openmettle.grant_changes` (`openmettle.project-role`, `openmettle.project-member`, and `openmettle.resource-grant` head rows at `last_revision`, plus ADR 0021 evidence for `source_kind = 'mapped'`). Use post-backup `openmettle.authorization_audit` exports or external deployment change records; if post-backup authorization or revocation evidence is unavailable, keep authentication closed ([ADR 0013](docs/adr/0013-local-identity-sessions.md), [ADR 0027](docs/adr/0027-authorization-and-private-projects.md)) so an enabled user cannot sign in afresh and regain revoked access. Reconcile restored pending home invitations against current operator records and withdraw stale decisions ([home invitations](docs/operator/home-invitations.md)). Review the restored login-admission ceiling before reopening; restored unexpired login rows continue counting toward it until they expire or are cleaned up ([ADR 0014](docs/adr/0014-login-admission.md)).
3. **Align `ARTIFACTS_DIR` payload volume before starting the worker:** When artifact storage is enabled, restore PostgreSQL and its matching `ARTIFACTS_DIR` filesystem payload volume to the same recovery point before starting `openmettle-worker` maintenance. Otherwise, mismatched database reservation or revision state allows `reconcile_expired` or `purge_due` to unlink staging or published payload files ([ADR 0031](docs/adr/0031-filesystem-artifact-storage-and-streaming-multipart.md)). If the volume was restored by file copy (`cp -a`, `tar`, restic or similar), every payload is a new file that the ledger's inode numbers no longer identify: run `openmettle-admin storage rebind` and then the filesystem drift check `openmettle-admin quota verify ROOT` before starting any API or worker process, following [Restore the artifact volume](docs/operator/restore-artifact-volume.md). If a service ran on the restored volume before rebind succeeded, stop every service, restore the matched database and volume again, and restart this checklist at step 1; restoring only one of the two, or continuing from this step, would undo or skip the steps above.
4. **Cancel parked `waiting` runs and reconcile effect intents before enabling workers:** Cancel parked `waiting` runs on `openmettle.runs`. That transition marks each run `cancelled` and appends its cancellation event while preserving immutable `openmettle.run_approvals` and `openmettle.run_approval_decisions` history. Inspect committed effect-ledger intents (`openmettle.operations`) through read-only reconciliation while worker dispatch remains disabled, then start `openmettle-worker` ([ADR 0035](docs/adr/0035-approvals-permitted-yolo-and-effect-ledger.md)).

### Schema compatibility tests

The schema tests require authentic historical release binaries via `OLD_BINARY_DIR` (schema 2, `18f52463c9d6bc12dda4bd1558e4597e067018f8`), `V3_BINARY_DIR` (`2f1be947aa933177c2e407cd7290bf9909bd08ca`), `V4_BINARY_DIR` (`d80e37819f847072dfa272bdddcc1fbee6d622ef`), `V5_BINARY_DIR` (`4a51242839e16e1d7b8ad3538887bf8e41081e6e`), `V6_BINARY_DIR` (`3978dff2864488bbdd9e748afd7116f39683f129`), `V7_BINARY_DIR` (`5ff1d2a8ed5e7424be006e78c16f0c30e784336d`), `V8_BINARY_DIR` (`e55aff07527ad6452f8a0d49953b3fc2ffc51352`), `V9_BINARY_DIR` (`940b8c2032d863e29fd04ad7c6357ad8cacc42fc`), `V10_BINARY_DIR` (`05dd18489242e545e3529b4e3750c74837b05638`), `V11_BINARY_DIR` (`0ab3401714762f28a730eae4cd7c91052648dabd`), `V12_BINARY_DIR` (`4441b4236ad0dd1ea868d507bb10b50d9b0ddb6f`), and `V13_BINARY_DIR` (`615dcffc93af18ab0db40a7a2fafc3c0752d4c77`). See [`.github/workflows/checks.yml`](.github/workflows/checks.yml) and [`tests/schema/grants.rs`](tests/schema/grants.rs) for the canonical release pins and upgrade checks. The ADR 0014 operator-script tests also need `POSTGRES_CONTAINER`, the isolated CI PostgreSQL service container whose `psql` runs them. Do not substitute the current binary with a truncated migration list.

The schema tests need a superuser on an isolated, disposable PostgreSQL 18 service. They create synthetic `openmettle_*` cluster roles with a test-only password and one database per test. Never point them at a shared server.

```sh
export TEST_DATABASE_URL='postgres://fixture:fixture@127.0.0.1:5432/fixture?sslmode=disable'
cargo test --locked --test schema -- --ignored
```

Build the migrate image with `docker build --target migrate -t openmettle-migrate:test .`; it runs as the same non-root user as the other images. Deploy (V1-32) owns the Kubernetes Job or hook, production role provisioning and secrets.

## Ownership

V1-02 owns schema/migrations (run/event/operation, artifact/reservation/accounting and grant persistence are implemented; final acceptance and independent review remain open), V1-03 owns application/event/capacity contracts (the first contract increment is published; internal evaluation is implemented; final qualification and coordinator acceptance remain open), and V1-42 owns transitive provenance and distribution clearance. Supported runtime targets for this increment are Linux containers and Unix development hosts; Windows signal behavior is not implemented.

The app repository consumes core APIs. The deploy repository owns generic Helm packages. Private site values and curated fork implementations stay outside this tree.

## Baseline maintenance

The baseline is the complete accepted document exported from the [planning Page](https://chatgpt.com/space/page_fef707d85d8c8191a14f162d6281307d). SOURCE-REFERENCES.md retains neutral aliases, source pins and paths for personal repository citations; the Page retains original URLs. The native workbook reference points back to that archive. These portability/privacy changes do not amend the accepted architecture. Record subsequent decisions in DECISIONS.md and link implementation tickets.

## Login-time project membership

After all participating login replicas, grant writers and membership readers are upgraded,
an owner can enroll one rule revision and one project per exact identity approval in schema 11.
Managed session issuance then reconciles the signed group or app-role observation with
that rule's project assignment. The internal membership reader expires a confirmation at
the configured age or token expiry, whichever comes first. A complete removal revokes the
mapped assignment. Missing or partial evidence withholds a positive membership decision
and preserves the grant history. See [ADR 0021](docs/adr/0021-project-membership.md) for
the configuration, evidence profile and recovery boundaries.

## Authorization policy

[ADR 0027](docs/adr/0027-authorization-and-private-projects.md) adds `src/authz.rs`, a pure
policy evaluator for V1-05: strict grant vocabulary, `Owner`/`Editor`/`Viewer` project roles,
private-by-default conversations, artifacts and memory, sharing that requires active project
membership, platform and user capability denies, last-owner and last-admin refusals and an
execution-time run recheck. `account_admin` never grants content access.

A validated browser or native session reports the approval it was issued under and the
primary database's millisecond clock at which it was checked
(`sessions::Context::{approval_id, observed_ms}`, [ADR 0029](docs/adr/0029-native-sign-in-mounting-and-session-context.md)).
When `OPENMETTLE_API_AUTH_CONFIG` is configured, every authenticated `/v1` route hydrates
the caller's principal from the primary via `authz::store::hydrate_api_principal` and
enforces these rules per request. The `openmettle-worker` binary runs periodic
maintenance sweeps and, with run slots and its inference document, the turn executor
([ADR 0043](docs/adr/0043-packaged-worker-inference-configuration.md)). When
`worker::run` or `worker::run_with_approvals` runs an `Executor`, the runner claims a run
first (`claim_next` / `reclaim_next`) and then rechecks current execution authority on the
primary (`recheck_claim`) before each step and before dispatching fenced effects
([ADR 0027](docs/adr/0027-authorization-and-private-projects.md),
[ADR 0035](docs/adr/0035-approvals-permitted-yolo-and-effect-ledger.md)).
