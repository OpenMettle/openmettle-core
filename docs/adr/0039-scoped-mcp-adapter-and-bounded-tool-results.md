# 0039 — Scoped MCP adapter, reviewed tool contracts and bounded spill artifacts

Status: proposed V1-14 design (PR1), 21 November 2026. Refs #14. The base is `main` at
`45df33c60e7a84fe8a2db0a8e2d9b93a8d29e5a5` (schema 22). PR2 and PR3 own implementation and
qualification. Dependencies: [V1-03](https://github.com/OpenMettle/openmettle-core/issues/4),
[V1-05](https://github.com/OpenMettle/openmettle-core/issues/6),
[V1-13](https://github.com/OpenMettle/openmettle-core/issues/13) and
[V1-28](https://github.com/OpenMettle/openmettle-core/issues/25).

## Decision

`openmettle-worker` executes server-owned tools through one owned Model Context Protocol (MCP)
and internal-tool adapter. Every tool call binds to a reviewed `(tool_id, tool_version)`
contract, passes closed-schema validation and primary PostgreSQL authorization, records a
fenced ADR 0035 effect intent before dispatch, classifies failures into a closed fault
taxonomy and returns a bounded inline or spilled result.

| Existing boundary | V1-14 addition |
| --- | --- |
| [ADR 0010](0010-provider-http-transport.md) and [ADR 0038](0038-sglang-and-external-provider-conformance-adapter.md), `src/provider_http/transport.rs` | Add a Streamable HTTP JSON-RPC 2.0 MCP client over `provider_http::transport` with a dedicated DNS slot semaphore, strict header allowlist and 4 MiB streaming response ceiling. |
| [ADR 0027](0027-authorization-and-private-projects.md) and [ADR 0035](0035-approvals-permitted-yolo-and-effect-ledger.md), `src/authz/approvals.rs` | Implement `EffectPolicy` in the reviewed tool registry and bind every invocation to `Proposal`, `Destination`, `EffectClass`, `EndpointKey` and `record_fenced_intent`. |
| [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md), `src/worker.rs` | Implement `ApprovedAdapter` for resumed writes, reuse the same committed-envelope dispatch for immediate reads and permitted YOLO writes, and implement read-only `Executor::reconcile`. |
| [ADR 0005](0005-artifact-storage-accounting.md) and [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md), `src/storage.rs` and `src/artifact_fs.rs` | Add direct byte publication (`artifact_fs::publish_bytes`) and run-linked spill cleanup for outputs exceeding the inline threshold, paired with a read-only `artifact.read_range` tool. |

**Zero new Cargo crates.** V1-14 reuses the locked `hyper`, `hyper-util`, `http-body-util`,
`rustls`, `tokio-rustls`, `serde`, `serde_json`, `sha2`, `bytes`, `httpdate` and `ring` stack
rather than adding `rmcp` or another unreviewed MCP SDK crate. Adopting an external MCP SDK
later requires a separate dependency and V1-42 distribution gate.

## Tool registry, ownership and first read-only tool

The reviewed tool registry separates two tool classes behind one dispatch contract.

| Tool class | Execution boundary | Authority and credential source |
| --- | --- | --- |
| Reviewed internal tools | Compiled Rust handlers inside `openmettle-core` | Primary PostgreSQL authority (`src/authz/`, `src/storage.rs`, `src/artifact_fs.rs`); never consults Open WebUI APIs or forwarded user headers |
| Scoped configured external MCP connections | Outbound HTTPS Streamable HTTP JSON-RPC 2.0 endpoints pinned to a scope and reviewed manifest | Server-side `McpCredentialProvider` seam resolved at dispatch for `(connection_id, account_id, scope_id, actor_user_id)`; production vault storage and rotation stay gated on V1-28 (#25) |

### First working read-only tool (`artifact.read_range` v1)

The first working tool is the reviewed internal tool `artifact.read_range` (`tool_version = "1"`).
It accepts `artifact_id` (canonical UUID string), `revision_id` (canonical UUID string),
`offset` (`0..=i64::MAX`, default `0`) and `max_bytes` (`1..=16384`, default `8192`).

Before reading any byte, the handler verifies the run's live step fence and continuation
authority on the primary (`recheck_leased` with the `tools.artifact.read` capability), hydrates
the worker principal via `authz::store::hydrate_worker_principal`, loads the revision via
`storage::read_revision`, confirms `revision.scope_id == run.scope_id`, checks
`authorize_resource(principal, resource, Action::Read)` on the artifact and requires
`revision.state == "active"`. Leaving `Review.artifact` as `None` for reads avoids requiring
write (`RunExecute`) access through `RunRecheckRequest::extra_target`, which stays reserved for
artifact-writing tools. The handler accepts only UTF-8 text or JSON media types, requires
`offset` to start on a UTF-8 character boundary (returning a semantic tool fault on binary
content or misaligned offsets), reads `[offset, offset + len)` via `artifact_fs::Store::read`,
trims any trailing split UTF-8 code point within `max_bytes` and returns the UTF-8 slice with
`next_offset`, `size_bytes`, `media_type`, `content_digest` and `eof`. This single read-only
tool also lets a model inspect sections of any spilled tool output on demand.

### Ownership and hard prohibitions

- **Tool ownership ([ADR 0038](0038-sglang-and-external-provider-conformance-adapter.md)).**
  Caller-supplied `tools` on caller-owned completions remain caller-executed; `tools: []` opts
  out and omitted `tools` offers none. Only explicit server-owned runs invoke this adapter in
  `openmettle-worker`. Model output, presets and remote server metadata cannot switch ownership
  or register tools.
- **No arbitrary code or subprocess execution.** `openmettle-api` and `openmettle-worker`
  forbid in-process plugin execution, dynamic library loading and `stdio` child-process
  spawning. Any local tool service runs as a separate deployment behind an authenticated HTTPS
  boundary.
- **No unreviewed `tools/list` auto-exposure.** Remote MCP `tools/list` may run only as a
  read-only verification check against a server-pinned `(connection_id, tool_id, tool_version,
  input_schema_digest)` manifest. Undeclared remote tools are ignored; missing tools or schema
  digest drift fail closed before dispatch.
- **Scope exclusions and deferrals (#14).** Selective tool discovery and deferred MCP tool
  definitions (`PLAN-21`) are explicitly deferred out of V1-14 scope; every offered tool for a
  run is pinned at admission. Bounded independent tool fan-out research (`PLAN-19`) remains
  conditional research outside V1-14 implementation; V1-14 executes validated calls within the
  run's existing round budget without adding a fan-out scheduler.

## Reviewed tool contracts and ADR 0035 integration

### Schema validation and argument bounds

Every tool contract in the registry declares an immutable closed JSON input schema and default
values. Before calling `Proposal::new`, the adapter validates raw model arguments in this
order:

1. **Duplicate-key and byte check.** Decode raw UTF-8 bytes (`<= 65536` bytes) with
   `provider_keys::documents::unique` so repeated object keys fail before conversion.
2. **Structural bounds.** Require a JSON object root. Enforce maximum nesting depth `16`, at
   most `64` properties per object, at most `256` elements per array and at most `16384` UTF-8
   bytes per string scalar. Reject control characters in identifier fields.
3. **Closed schema and integer-only scalars.** Require `additionalProperties: false` on every
   object schema. Reject unknown fields, missing required fields and floating-point or
   out-of-range numbers outside signed 64-bit integers (`i64`), matching
   `approvals::canonical_arguments`. Tools that need decimal quantities declare bounded string
   formats in their schemas.
4. **Default expansion and canonicalization.** Materialize reviewed defaults before canonical
   serialization so `Proposal::arguments()` and human approval prompts (`listRunApprovals`)
   display the exact arguments that will be dispatched.
5. **Destination pinning.** Resolve `Destination { connection, account, action, resource }`
   with bounded, non-wildcard identifiers (`<= 512` bytes serialized as
   `["v1", connection, account, action, resource]`). Internal tools pin
   `connection = "internal"`, `account = <scope_id>`, `action = <tool_id>` and
   `resource = <target UUID>`. External MCP tools pin the configured `connection_id`,
   authorized `account_id`, pinned `tool_id` and explicit target resource identifier. Refuse
   any call whose destination cannot be pinned through send.

### Policy review and effect-ledger lifecycle

The reviewed tool registry implements `approvals::EffectPolicy::review(scope, run, proposal)`.
Unknown tools, schema violations, unpinned destinations, unavailable V1-28 credentials or
missing required storage reservations return `Ok(None)` or `Err`, failing closed before
parking or intent insertion.

| Reviewed `EffectClass` | `EndpointKey` and lookup support | Stored `operations.capability` | Approval and replay rule |
| --- | --- | --- | --- |
| `EffectClass::Read` | Any | `repeatable_read` | No human decision required; records `basis = "read"` intent after per-call authority check. |
| `EligibleWrite`, `HumanRequired`, `Sharing` | `EndpointKey::Supported` (active, unexpired window) | `idempotent` | Human approval (or permitted YOLO for `EligibleWrite`); persists outbound key before send; never silently resent on replay. |
| `EligibleWrite`, `HumanRequired`, `Sharing` | `Unsupported` or `Unknown`, `authoritative_lookup = true` | `lookup` | Human approval (or permitted YOLO for `EligibleWrite`); reconciler queries `downstream_handle` or authoritative read. |
| `EligibleWrite`, `HumanRequired`, `Sharing` | `Unsupported` or `Unknown`, `authoritative_lookup = false` | `non_repeatable` | Human approval (or permitted YOLO for `EligibleWrite`); ambiguous send settles as `outcome_unknown` and interrupts. |
| `EffectClass::Prohibited` | Any | Refused before insert | Rejected unconditionally in `Review::validate`; human approval cannot override. |

Per-call execution uses one fenced sequence in `openmettle-worker`:

1. Call `authz::runs::recheck_leased` with the step's tool capability (which evaluates
   `authorize_run_continuation` on the primary) and call `approvals::record_fenced_intent`.
2. On `IntentResult::ApprovalRequired`, drain `StepContext::tasks`, call `approvals::park` and
   stop the step so the API can collect the human decision.
3. On `IntentResult::Replayed(op_id)`, do **not** resend a write. Inspect the existing
   `operations` row: reuse recorded terminal evidence if `succeeded` or `failed`, or defer to
   ADR 0033 and ADR 0035 reconciliation if `intent` or `outcome_unknown`.
4. On `IntentResult::Invalidated(_)`, stop immediately; the fenced check already settled the
   run.
5. On `IntentResult::Applied(committed)`, release the PostgreSQL connection before any I/O and
   call `committed.start(&step)`. If `start` returns `None`, issue no outbound call and leave
   the `intent` for settlement or reconciliation.
6. Dispatch the committed `openmettle.effect` v1 envelope through the adapter's
   `ApprovedAdapter::send` path (the same path `worker::execute` uses after `pending_effect`
   for resumed human approvals).
7. When `EndpointKey::Supported { field, key, .. }` is recorded in the committed envelope, emit
   `key` unchanged in the contract-pinned HTTP header or JSON-RPC `_meta` field. Never
   allocate a fresh key for the same `logical_key`.
8. After dispatch, borrow a connection and record the outcome under
   `leases::with_lease(..., Fence::Hold, ...)` via `runs::record_observation` with the expected
   revision, stable append key, `downstream_handle` when returned and bounded redacted
   evidence.

`Executor::reconcile(&UnresolvedOperation, StepContext)` runs only when the reviewed contract
declares a read-only reconciliation call and the operation is `lookup` or `idempotent` with a
persisted `downstream_handle` or active `EndpointKey::Supported`. If the contract lacks a
reconciler or the remote endpoint cannot prove an outcome, return `None` so ADR 0033 preserves
uncertainty and settles the run as `interrupted`.

## Transport, typed faults and bounded retries

### Streamable HTTP MCP transport over `provider_http::transport`

External MCP calls reuse `provider_http::transport`'s canonical `https://` endpoint validator,
IANA Server-Side Request Forgery (SSRF) address policy over all DNS answers, `rustls` (ring)
TLS 1.2/1.3 ALPN `http/1.1` handshake, `Connection: close`, no-proxy, no-redirect and
caller-driven hyper connection rules ([ADR 0010](0010-provider-http-transport.md)).

- **Isolated DNS slots.** MCP owns a dedicated process-wide 8-slot `MCP_DNS_SLOTS` semaphore,
  separate from OIDC `DNS_SLOTS` and gateway inference `DNS_SLOTS`.
- **Header admission.** Mirroring [ADR 0038](0038-sglang-and-external-provider-conformance-adapter.md),
  add a narrow MCP request builder in `src/provider_http/` without widening `Route::send`.
  Allow only `POST` with `Content-Type: application/json`,
  `Accept: application/json, text/event-stream`, a pinned `MCP-Protocol-Version` header, an
  optional server-supplied `Authorization` marked `HeaderValue::set_sensitive(true)` and an
  optional contract-pinned `Idempotency-Key` header. Reject header blocks exceeding `2 KiB`
  outbound or `8 KiB` / `32` headers inbound, and outbound bodies exceeding `128 KiB`.
- **Stateless single-call framing.** Each `tools/call` uses one request/response exchange.
  Accept `application/json` (one JSON-RPC 2.0 response matching the request `id`) or
  `text/event-stream` (Server-Sent Events delivering one matching JSON-RPC 2.0 response event).
  Match media types and `charset=utf-8` case-insensitively; refuse non-UTF-8 charsets,
  non-`identity` `Content-Encoding`, chunked trailers, unsolicited server requests, duplicate
  responses and premature EOF. Do not run background SSE notification loops.
- **Hard inbound wire ceiling.** Enforce `MAX_TOOL_WIRE_BYTES = 4 MiB` (`4_194_304` bytes).
  Reject declared `Content-Length > 4 MiB` before reading any body bytes and abort chunked or
  SSE reads through `http_body_util::Limited` as soon as observed bytes exceed `4 MiB`.
- **Clocks and cancellation.** Apply `setup_timeout` (default `5 s`), `idle_read_timeout`
  (default `15 s`) and a per-tool reviewed `call_timeout` (default `30 s`, maximum `300 s`).
  Before starting any attempt, check `CommittedIntent::start(&step)` (enforcing
  `step.stop.is_none()`, the pre-renewal `StepContext::deadline` snapshot and the intent's
  authority expiry). While I/O is in flight, follow ADR 0038: race `step.stop`,
  `ActiveRun::execution_deadline`, the intent's authority expiry and the adapter timeouts. On
  any stop signal, drop the HTTP future immediately so the socket closes.

### Typed fault taxonomy and retry rules (`PLAN-10`)

Every tool failure maps to one of three disjoint fault classes.

| Fault class | Qualifying evidence | Retries | Ledger outcome | Model / worker action |
| --- | --- | --- | --- | --- |
| **Transient transport** (`ToolFault::Transient`) | Pre-send DNS/TCP connect failure; HTTP `408`, `429`, `502`, `503`, `504`; mid-stream disconnect or idle/call timeout | Up to `3` total attempts (`1` initial + `2` retries) for `repeatable_read` and active unexpired `idempotent` writes with the identical persisted key. For `lookup`/`non_repeatable` writes: retry **only** proven pre-send failures; **never** retry after request bytes are sent. | `failed` for exhausted `repeatable_read` or proven pre-send failure; `outcome_unknown` for any sent `idempotent`, `lookup` or `non_repeatable` write that times out or disconnects without endpoint proof. | Sleep with `ring::rand::SystemRandom` full jitter (`250 ms`, `500 ms`). For a single valid integer `Retry-After` (seconds): sleep at least that delay when `<= 60 s` and within remaining call, authority and run execution deadlines; fail without retrying if `Retry-After` exceeds `60 s` or the remaining budget; ignore malformed or duplicate headers. Abort sleep immediately on `step.stop`. |
| **Semantic tool fault** (`ToolFault::Semantic`) | MCP JSON-RPC `result` with `isError: true`, JSON-RPC `-32602`, or internal tool domain refusal (for example offset past EOF or non-`active` revision) | `0` transport retries | `failed` for reads and for writes whose reviewed contract guarantees `isError: true` caused no side effect; otherwise `outcome_unknown`. | Return a bounded structured error envelope (`status: "tool_error"`, closed `fault_code`, `<= 2 KiB` UTF-8 summary, `retryable_by_model`) so the model can recover within `round_limit`. |
| **Policy, auth or contract failure** (`ToolFault::TerminalRefusal`) | Revoked session/grant/capability, schema/bounds violation, unpinned destination, missing V1-28 credential or V1-17 quota; SSRF `Address`, TLS cert/host failure, `3xx` redirect, `401`/`403`, unexpected `4xx`, `tools/list` drift, malformed JSON-RPC/framing or `> 4 MiB` response | `0` retries | `failed` when refused pre-send or on definitive `401`/`403`; `outcome_unknown` if malformed framing or `TooLarge` arrives after a write was already sent. | Fail closed immediately. Authority revocation settles the run under ADR 0033/0035; contract or auth refusals return fixed redacted diagnostics without fallback or upstream body echoing. |

### Redaction and telemetry

Errors use fixed text and closed enum variants ([ADR 0024](0024-process-telemetry-and-redaction.md)).
Never place credentials, `Authorization` values, endpoint URLs, hosts, IP addresses, tool
arguments, raw tool bodies, `downstream_handle` tokens or echoed upstream errors in `Display`,
`Debug`, stderr logs, OTLP traces or run-event projections. If PR3 instruments MCP counters or
histograms, update `contracts/telemetry/v1.json`, `src/telemetry/metrics.rs` and Prometheus
rule checks together under [ADR 0028](0028-telemetry-contract-and-metrics.md) using only
closed low-cardinality outcome and fault-class labels (never `tool_id`, `endpoint_id`, `run_id`
or `user_id`).

## Bounded inline tool results and scoped artifact spill

Normalized UTF-8 tool output obeys three size bands:

| Band | Condition | Handling |
| --- | --- | --- |
| **Inline** | `<= 16 KiB` (`16_384` bytes) **and** `<= 200` lines | Returned directly in the tool-result envelope (`storage: "inline"`, `truncated: false`, `size_bytes`, `line_count`, `content_sha256`). |
| **Spill** | Exceeds `16 KiB` or `200` lines, up to `4 MiB` (`4_194_304` bytes) | Published as an immutable scoped artifact in the run's `scope_id`; model receives a compact `<= 16 KiB` head/tail preview envelope with provenance and artifact coordinates. |
| **Refused** | Exceeds `4 MiB` wire or payload ceiling | Aborted during streaming before memory or disk exhaustion (`ToolFault::TerminalRefusal` / `TooLarge`). |

### Scoped artifact publication and cleanup

`openmettle_worker` already holds PostgreSQL column grants on `storage_instance`,
`storage_accounts`, `artifacts`, `storage_reservations` and `artifact_revisions` (including
`display_name`, verified in `src/boundaries.sql`). PR2 adds a non-multipart helper
`artifact_fs::publish_bytes` using the exact [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md)
durability order:

1. Derive a deterministic idempotency key from `(run_id, operation_id, "tool-spill")` and
   resolve the artifact UUID via `storage::upload_artifact` so retries target one artifact.
2. Call `storage::reserve` with `scope = run.scope_id`, `actor = run.actor_user_id`,
   `max_bytes = payload.len() as i64`, `run = Some(run_id)` and `operation = Some(operation_id)`.
3. Create `<ARTIFACTS_DIR>/staging/<reservation_id>` exclusively (mode `0600`), write the
   normalized UTF-8 bytes, compute SHA-256 and `fsync`.
4. In one short transaction, lock the reservation row `FOR UPDATE`, `rename` to
   `revisions/<reservation_id>`, `fsync` `revisions/` and call `storage::settle` with
   `media_type` (`text/plain; charset=utf-8` or `application/json; charset=utf-8`) and a
   bounded display name passing `storage::valid_display_name`.

Because `artifact_fs::reconcile_expired` currently scans only upload reservations
(`run_id IS NULL`), PR2 adds `artifact_fs::reconcile_run_spills` to the worker maintenance
sweep. It releases abandoned run-linked spill reservations (`state = 'reserved'`,
`run_id IS NOT NULL`) only after unlinking their staging/revision files and only once the
linked operation has a terminal outcome (`succeeded` or `failed`) or the run is terminal,
preserving `storage::release`'s invariant that unresolved `intent`/`outcome_unknown`
operations block release.

### Head/tail preview envelope and unavailable-spill policy

A spilled result returns a closed JSON envelope capped at `16 KiB`:

- `status`: `"ok"`
- `storage`: `"spilled"`
- `truncated`: `true`
- `head`: prefix of at most `4 KiB` (`4_096` bytes) or `60` lines (whichever is smaller), cut
  strictly on a valid UTF-8 character boundary.
- `tail`: suffix of at most `4 KiB` or `60` lines (whichever is smaller), cut strictly on a
  valid UTF-8 character boundary and guaranteed non-overlapping with `head`.
- `provenance`: `source = "tool_spill"`, `tool_id`, `tool_version`, `operation_id`,
  `artifact_id`, `revision_id`, `content_sha256` (64 lowercase hex), `size_bytes`,
  `line_count`, `inline_head_bytes`, `inline_tail_bytes` and `omitted_bytes`.

The model inspects omitted middle ranges by calling `artifact.read_range` with the returned
`artifact_id` and `revision_id`, subject to live scope and `Action::Read` rechecks.

**When spill storage is unavailable.** If `OPENMETTLE_WORKER_ARTIFACTS_DIR` is unset, storage
limits are unconfigured, owner/instance storage quota is exhausted or filesystem publication
fails:

- **Default tools (`spill_required = false`).** Record the proven tool outcome in `operations`
  first (so a completed write is never hidden or falsely marked failed), include the redacted
  `spill_error` (`store_unconfigured`, `quota_exceeded` or `storage_io`) in observation
  evidence and return a bounded fallback envelope with `storage: "truncated_no_spill"`,
  `truncated: true`, `artifact_id: null`, `revision_id: null`, the same UTF-8-safe `head`/`tail`
  preview, `omitted_bytes` and `content_sha256`. Truncation is always explicit; partial output
  is never labeled complete.
- **Strict-spill tools (`spill_required = true`).** Reviewed tools whose contract requires
  durable artifact output pre-reserve a `StorageReservation` in `Review.reservation` (already
  enforced by `src/authz/approvals.rs`) so unconfigured storage or exhausted quota fails closed
  before dispatch.

## Delivery and verification

| Slice | Deliverable | Acceptance evidence |
| --- | --- | --- |
| PR1 | This ADR (`0039`). | Review against #14, #25, ADRs 0010, 0031, 0033, 0035 and 0038; `ai-guardrails docs audit` reports zero findings. |
| PR2 | Reviewed tool registry (`EffectPolicy`), strict schema/argument validator and default expander, internal `artifact.read_range` v1 tool, `artifact_fs::publish_bytes`, `reconcile_run_spills` and head/tail preview builder. | PostgreSQL 18 tests: cross-user, cross-scope, archived/deleted project and non-`active` revision refusals; duplicate-key, float, depth, bound and wildcard rejections; inline vs spill thresholds (`16 KiB`, `200` lines, multi-byte UTF-8 cuts); unconfigured-store, quota-refused and I/O fallback envelopes; crash/retry spill reservation reconciliation. |
| PR3 | Streamable HTTP MCP adapter over `provider_http::transport`, `MCP_DNS_SLOTS`, `McpCredentialProvider` seam, `ApprovedAdapter` implementation, read-only `Executor::reconcile`, and `PLAN-10` / `PLAN-22` conformance harness on synthetic `rcgen` TLS + PostgreSQL 18. | Synthetic TLS + PostgreSQL 18 tests: bounded retries with identical persisted `Idempotency-Key` on `repeatable_read`/`idempotent` (`408`/`429` with `Retry-After`/`502`/`503`/`504`, pre-send TCP reset) obeying `step.stop` and deadlines; zero post-send retries on `lookup`/`non_repeatable` writes (exact server write count `1`, `outcome_unknown` in ledger); semantic `isError: true` / `-32602` with zero transport retries; SSRF/TLS/redirect/`401`/`403`/`tools/list`-drift/`> 4 MiB` refusals; canary redaction checks across errors, stderr, traces and metrics; end-to-end `park` -> `decide` -> resume -> `ApprovedAdapter::send` -> spill -> `artifact.read_range` round trip. |

### External boundaries

- **V1-28 (#25).** Owns encrypted personal/project connection secrets, key rotation, OAuth
  refresh and revocation. Production external MCP credentials stay gated on V1-28; PR2 and PR3
  qualify external MCP only against pinned synthetic TLS fixtures.
- **V1-17 (#17).** Owns non-storage quota units (provider request and token budgets). V1-14
  enforces storage byte reservations through ADR 0005 and ADR 0035 and leaves non-storage
  quotas gated on V1-17.
- **V1-07 (#8).** Owns the live worker turn executor connecting ADR 0038 model rounds to this
  tool adapter.
- **Issue #14** remains open through PR1, PR2 and PR3 until all acceptance criteria are
  implemented and verified.
