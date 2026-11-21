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
| [ADR 0010](0010-provider-http-transport.md) and [ADR 0038](0038-sglang-and-external-provider-conformance-adapter.md), `src/provider_http/transport.rs` | Add a Streamable HTTP JSON-RPC 2.0 MCP (`2026-07-28`) client over `provider_http::transport` with a dedicated DNS slot semaphore, strict header allowlist and 4 MiB streaming response ceiling. |
| [ADR 0027](0027-authorization-and-private-projects.md) and [ADR 0035](0035-approvals-permitted-yolo-and-effect-ledger.md), `src/authz/approvals.rs` | Implement `EffectPolicy` in the reviewed tool registry and bind every invocation to `Proposal`, `Destination`, `EffectClass`, `EndpointKey` and `record_fenced_intent`. |
| [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md), `src/worker.rs` | Implement `ApprovedAdapter` for resumed writes, reuse the same committed-envelope dispatch for immediate reads and permitted YOLO writes, and implement read-only `Executor::reconcile`. |
| [ADR 0005](0005-artifact-storage-accounting.md) and [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md), `src/storage.rs` and `src/artifact_fs.rs` | Add lease-fenced direct byte publication (`artifact_fs::publish_bytes`) and spill-scoped cleanup (`artifact_fs::reconcile_run_spills`) for outputs exceeding the inline ceiling, paired with a strictly inline read-only `artifact.read_range` tool. |

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
`offset` (`0..=i64::MAX`, default `0`) and `max_bytes` (`4..=16384`, default `8192`). Requiring
`max_bytes >= 4` (one maximum-width UTF-8 code point) ensures every valid UTF-8 read before EOF
makes forward progress; values below `4` or above `16384` fail closed with a schema validation
refusal (`ToolFault::TerminalRefusal`).

Before reading or replaying any byte, the handler verifies the run's live step fence, bound
effect authority and continuation authority on the primary (`tools.artifact.read` capability),
hydrates the worker principal via `authz::store::hydrate_worker_principal`, loads the revision
via `storage::read_revision`, confirms `revision.scope_id == run.scope_id`, checks
`authorize_resource(principal, resource, Action::Read)` on the artifact and requires
`revision.state == "active"`. Leaving `Review.artifact` as `None` for reads avoids requiring
write (`RunExecute`) access through `RunRecheckRequest::extra_target`, which stays reserved for
artifact-writing tools. The handler accepts only UTF-8 text or JSON media types, requires
`offset` to start on a UTF-8 character boundary and returns `ToolFault::Semantic` on binary
media types, invalid UTF-8 bytes or misaligned offsets. It reads `[offset, offset + len)` via
`artifact_fs::Store::read`, trims any trailing split UTF-8 code point within `max_bytes`, caps
each returned page at `<= 200` lines (advancing `next_offset` cleanly to the first byte after
line 200 when more lines remain so the caller paginates without exceeding the inline line
ceiling) and trims trailing code points further if needed so the **final UTF-8 serialized JSON
tool-result string** fits `<= 16_384` bytes (accounting for JSON string escaping and envelope
metadata). `artifact.read_range` is explicitly exempt from spill publication: its pages stay
strictly inline and never spill into derived artifacts. The response returns the UTF-8 slice
with `next_offset`, `size_bytes`, `media_type`, `content_digest` and `eof`. This single
read-only tool also lets a model inspect sections of any spilled tool output on demand, subject
to live `Action::Read` and `active` revision checks.

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
Unknown tools, schema violations, unpinned destinations or unavailable V1-28 credentials return
`Ok(None)` or `Err`, failing closed before parking or intent insertion. V1-14 spills are
post-response opportunistic artifacts and do not require `Review.reservation` before dispatch.

| Reviewed `EffectClass` | `EndpointKey` and lookup support | Stored `operations.capability` | Approval and replay rule |
| --- | --- | --- | --- |
| `EffectClass::Read` | Any | `repeatable_read` | No human decision required; records `basis = "read"` intent after per-call authority check; excluded from `leases::unresolved_operations` and never blocks park or settlement. |
| `EligibleWrite`, `HumanRequired`, `Sharing` | `EndpointKey::Supported` (active, unexpired window) | `idempotent` | Human approval (or permitted YOLO for `EligibleWrite`); persists outbound key before send; never silently resent on replay. |
| `EligibleWrite`, `HumanRequired`, `Sharing` | `Unsupported` or `Unknown`, `authoritative_lookup = true` | `lookup` | Human approval (or permitted YOLO for `EligibleWrite`); reconciler queries `downstream_handle` or deterministic authoritative lookup. |
| `EligibleWrite`, `HumanRequired`, `Sharing` | `Unsupported` or `Unknown`, `authoritative_lookup = false` | `non_repeatable` | Human approval (or permitted YOLO for `EligibleWrite`); ambiguous send settles as `outcome_unknown` and interrupts. |
| `EffectClass::Prohibited` | Any | Refused before insert | Rejected unconditionally in `Review::validate`; human approval cannot override. |

Per-call execution uses one fenced sequence in `openmettle-worker`:

1. Call `authz::runs::recheck_leased` with the step's tool capability (which evaluates
   `authorize_run_continuation` on the primary) and call `approvals::record_fenced_intent`
   (which additionally enforces ADR 0035 effect-level and bound-session authority under
   `Fence::Step`).
2. On `IntentResult::ApprovalRequired`, drain `StepContext::tasks`, call `approvals::park` and
   stop the step so the API can collect the human decision.
3. On `IntentResult::Replayed(op_id)`, do **not** resend a write (`IntentResult::Replayed`
   returns only `operation_id`, never a one-use `CommittedIntent` write permit). Inspect the
   existing `operations` row:
   - If `succeeded` or `failed`, never blindly replay cached bytes or previews after source
     access is lost: before replaying any result backed by a source or spilled artifact,
     reauthorize live `Action::Read` on `(artifact_id, revision_id)` and confirm
     `revision.state == "active"`.
   - If `intent` or `outcome_unknown`, unresolved writes (`idempotent`, `lookup`,
     `non_repeatable`) defer to ADR 0033 and ADR 0035 reconciliation. Unfinished
     `repeatable_read` operations (`outcome = 'intent'`, where an earlier attempt recorded an
     intent and crashed before recording a terminal observation) are excluded from
     `leases::unresolved_operations` and never enter `Executor::reconcile`. Instead, PR2 adds a
     dedicated fenced read-revalidation helper (`approvals::start_replayed_read` under
     `Fence::Step`) that rechecks live ADR 0035 effect and bound-session authority on the
     primary, verifies the operation is `capability = 'repeatable_read'` with no terminal
     observation and matches the requested canonical `Proposal`, and returns
     `(operation_id, committed_request_bytes, bounded_deadline)` **without** issuing a
     `CommittedIntent` write permit so the adapter can dispatch the committed read bounded by
     `step.deadline.min(bounded_deadline)`.
4. On `IntentResult::Invalidated(_)`, stop immediately; the fenced check already settled the
   run.
5. On `IntentResult::Applied(committed)`, release the PostgreSQL connection before any I/O and
   consume the one-use send permit `committed.start(&step)` once before attempt 1, applying the
   returned shortened `deadline` to `step.deadline`. If `start` returns `None`, issue no
   outbound call and leave the `intent` for settlement or reconciliation. On resumed human
   approvals, `worker::execute` (`src/worker.rs`) has already consumed `intent.start(&step)`
   and passes `ApprovedAdapter::send` the committed request bytes and shortened `step.deadline`.
6. Dispatch the committed `openmettle.effect` v1 envelope through `ApprovedAdapter::send` (the
   same committed-envelope path for immediate reads, permitted YOLO writes and resumed human
   approvals; unfinished `repeatable_read` replays reuse the same committed-envelope dispatch
   with the bytes and deadline returned by `approvals::start_replayed_read`).
7. When `EndpointKey::Supported { field, key, .. }` is recorded in the committed envelope, emit
   `key` unchanged in the contract-pinned HTTP header or JSON-RPC `_meta` field. Never
   allocate a fresh key for the same `logical_key`.
8. After dispatch, borrow a connection and record the outcome under
   `leases::with_lease(..., Fence::Hold, ...)` via `runs::record_observation` with the expected
   revision, stable append key, `downstream_handle` when returned and bounded redacted
   evidence.

`Executor::reconcile` aligns strictly with `leases::unresolved_operations` (`src/authz/leases.rs`)
and ADR 0035: `repeatable_read` operations are excluded and never enter `Executor::reconcile`.
Reconciliation runs only for unresolved writes (`idempotent`, `lookup`, `non_repeatable`) when
the reviewed contract declares a read-only reconciliation query:

- For `lookup` writes, the reconciler queries **either** the persisted `downstream_handle`
  **or** a deterministic, contract-defined authoritative lookup derived from the committed
  canonical arguments and logical key (handling responses lost before a remote handle arrived).
- For `idempotent` writes, the reconciler queries a read-only status endpoint keyed by the
  persisted `EndpointKey::Supported` without resending the write.
- In `src/worker.rs`, `worker::execute` enters `Executor::reconcile` when
  `run.state == ExecState::Reconciling`, where `Fence::Step` — and therefore `recheck_leased` —
  explicitly rejects with `LeaseError::Stopping` (`src/authz/leases.rs`). Furthermore,
  `Executor::reconcile` currently receives `(&UnresolvedOperation, StepContext)` without the
  worker's `ActiveRun` / `ClaimedRun`, and `leases::UnresolvedOperation` carries only
  `(id, logical_key, target, capability, outcome, revision, downstream_handle)`. PR3 therefore
  passes `&ActiveRun` (or `&Lease<'_>`) into `Executor::reconcile` (or an extended
  reconciliation hook), loads the operation's committed `openmettle.effect` v1 payload and run
  metadata on a worker DB connection, and performs a **read-only authority and claim check
  under `Fence::Hold`** (`leases::with_lease(..., Fence::Hold, ...)` validating the active
  lease token, `ExecState::Reconciling`, and current principal, scope, target and tool
  read-reconciliation authority via `recheck_decision` without requiring `Fence::Step` or live
  originating-session dispatch rights, matching ADR 0035's read-only reconciliation contract)
  before resolving credentials from `McpCredentialProvider`.
- If the contract lacks a reconciler, authority fails or the remote endpoint cannot prove an
  outcome, return `None` so ADR 0033 preserves uncertainty and settles the run as `interrupted`.

## Transport, typed faults and bounded retries

### Streamable HTTP MCP transport over `provider_http::transport`

External MCP calls pin MCP revision **`2026-07-28`** ([ARCHITECTURE-v1.md](../../ARCHITECTURE-v1.md))
and reuse `provider_http::transport`'s canonical `https://` endpoint validator, IANA
Server-Side Request Forgery (SSRF) address policy over all DNS answers, `rustls` (ring) TLS
1.2/1.3 ALPN `http/1.1` handshake, `Connection: close`, no-proxy, no-redirect and
caller-driven hyper connection rules ([ADR 0010](0010-provider-http-transport.md)).

- **Isolated DNS slots.** MCP owns a dedicated process-wide 8-slot `MCP_DNS_SLOTS` semaphore,
  separate from OIDC `DNS_SLOTS` and gateway inference `DNS_SLOTS`.
- **Header admission and `params._meta` (`2026-07-28`).** Mirroring
  [ADR 0038](0038-sglang-and-external-provider-conformance-adapter.md), add a narrow MCP
  request builder in `src/provider_http/` without widening `Route::send`. Allow only `POST`
  with `Content-Type: application/json`, `Accept: application/json, text/event-stream`,
  `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method` (`tools/call` or `tools/list`), `Mcp-Name`
  (the reviewed tool name on `tools/call`), an optional server-supplied `Authorization` marked
  `HeaderValue::set_sensitive(true)` and an optional contract-pinned `Idempotency-Key` header.
  Every outbound `tools/list` and `tools/call` JSON-RPC request body MUST populate
  `params._meta["io.modelcontextprotocol/protocolVersion"] = "2026-07-28"` (agreeing with
  `MCP-Protocol-Version`) and `params._meta["io.modelcontextprotocol/clientCapabilities"] = {}`
  per the MCP `2026-07-28` specification, alongside any contract-pinned `_meta` idempotency
  field derived strictly from the reviewed call. Keep stateful `Mcp-Session-Id` out of this
  stateless v1 profile (never send or adopt server session IDs). Reject header blocks exceeding
  `2 KiB` outbound or `8 KiB` / `32` headers inbound, and outbound bodies exceeding `128 KiB`.
- **Stateless single-call framing (`2026-07-28`).** Each `tools/call` uses one request/response
  exchange. Accept `application/json` (one JSON-RPC 2.0 response matching the request `id`) or
  `text/event-stream` (Server-Sent Events delivering optional SSE comments and progress
  notifications before one final matching JSON-RPC 2.0 response event). A matching JSON-RPC
  `id` alone does not prove completion: under MCP `2026-07-28`, server-initiated JSON-RPC
  requests are not permitted on a response stream when client capabilities declare none (`{}`)
  — interactive prompts (such as elicitation or sampling) instead return an `input_required`
  result. Any unexpected server-to-client JSON-RPC request frame on SSE or any `input_required`
  result violates this stateless non-interactive profile and is rejected closed as
  `ToolFault::TerminalRefusal` (unsupported protocol/contract fault) without issuing follow-up
  calls and without recording tool success. Match media types and `charset=utf-8`
  case-insensitively; refuse non-UTF-8 charsets, non-`identity` `Content-Encoding`, chunked
  trailers, mismatched JSON-RPC IDs, duplicate final responses and premature EOF. Do not run
  background SSE notification loops.
- **Hard inbound wire ceiling.** Enforce `MAX_TOOL_WIRE_BYTES = 4 MiB` (`4_194_304` bytes).
  Reject declared `Content-Length > 4 MiB` before reading any body bytes and abort chunked or
  SSE reads through `http_body_util::Limited` as soon as aggregate wire bytes across the stream
  (including SSE comments and progress notifications) exceed `4 MiB`, before buffering.
- **Clocks, retry rechecks and cancellation.** Apply `setup_timeout` (default `5 s`),
  `idle_read_timeout` (default `15 s`) and a per-tool reviewed `call_timeout` (default `30 s`,
  maximum `300 s`). `CommittedIntent::start(self, &step)` is consumed once before attempt 1
  (and is already consumed by `worker::execute` on resumed human approvals, leaving the
  shortened `step.deadline` that incorporates `EndpointKey::Supported.expires_us` and intent
  authority expiry). Before **every** permitted retry across **all** effect classes
  (`read_only` / `repeatable_read`, active unexpired `idempotent` writes, **and**
  proven-pre-send connection-refused/DNS retries of `lookup` and `non_repeatable` writes),
  enforce the attempt cap (`<= 3` total attempts), `step.stop`, `step.deadline` (including
  `EndpointKey::Supported.expires_us`) **and** a fenced **effect-level authority recheck** on
  the primary under `Fence::Step` — verifying current principal, scope, target, capability and
  destination policy **plus** the live bound originating/deciding session and approval, user
  and provider generations per ADR 0035 (never relying on `recheck_leased` alone, which
  intentionally ignores `originating_session_active` for background run continuation). While
  I/O is in flight, follow ADR 0038: race `step.stop`, `step.deadline`,
  `ActiveRun::execution_deadline` and the adapter timeouts. On any stop signal, drop the HTTP
  future immediately so the socket closes.

### Typed fault taxonomy and retry rules (`PLAN-10`)

Every tool failure maps to one of three disjoint fault classes. The adapter tracks transport
send uncertainty as a **sticky flag across the whole logical operation**: once attempt 1 may
have left the process (timeout, socket reset or mid-stream disconnect after request write), any
subsequent retry that fails pre-send, hits a deadline or stop signal, or returns `401`/`403` or
malformed framing MUST keep the ledger outcome `outcome_unknown` (never downgrading to
proven-unsent `failed` or `aborted`). Enforce `retryable_by_model: false` for **every**
uncertain write (`outcome_unknown`) — **including** an `idempotent` write whose retries or
`EndpointKey::Supported` window expired after a possible send, as well as any ambiguous
`lookup` or `non_repeatable` write (which also allow zero post-send retries) — so the model
can never re-issue an uncertain write under a fresh logical call.

| Fault class | Qualifying evidence | Retries | Ledger outcome | Model / worker action |
| --- | --- | --- | --- | --- |
| **Transient transport** (`ToolFault::Transient`) | Pre-send DNS/TCP connect failure; HTTP `408`, `429`, `502`, `503`, `504`; mid-stream disconnect or idle/call timeout | Up to `3` total attempts (`1` initial + `2` retries) for `read_only` / `repeatable_read` and active unexpired `idempotent` writes with the identical persisted key; for `lookup` and `non_repeatable` writes, retry **only** proven pre-send DNS/connection-refused failures and **never** retry after request bytes are sent. Before **every** permitted retry across all classes, enforce the attempt cap, `step.stop`, `step.deadline` (including `EndpointKey::Supported.expires_us`) and a fenced ADR 0035 effect-level authority recheck (principal, scope, target, capability, destination policy plus live bound session and approval/user/provider generations). | `failed` for exhausted `repeatable_read` or proven pre-send failure when no prior attempt left the process; `outcome_unknown` for any `idempotent`, `lookup` or `non_repeatable` write once any attempt may have left the process without endpoint proof. | Sleep with `ring::rand::SystemRandom` full jitter (`250 ms`, `500 ms`). For a single valid integer `Retry-After` (seconds): sleep at least that delay when `<= 60 s` and within remaining call, authority and run execution deadlines; fail without retrying if `Retry-After` exceeds `60 s` or the remaining budget; ignore malformed or duplicate headers. Abort sleep immediately on `step.stop`. Force `retryable_by_model: false` for every write ending in `outcome_unknown` (including an `idempotent` write whose retries or `EndpointKey::Supported` window expired after a possible send). |
| **Semantic tool fault** (`ToolFault::Semantic`) | MCP JSON-RPC `result` with `isError: true`, JSON-RPC `-32602`, or internal tool domain refusal (for example invalid UTF-8 binary content, offset past EOF or non-`active` revision) | `0` transport retries | `failed` for reads and for writes whose reviewed contract guarantees `isError: true` caused no side effect (and no prior attempt was ambiguous); otherwise `outcome_unknown`. | Return a bounded structured error envelope (`status: "tool_error"`, closed `fault_code`, `<= 2 KiB` UTF-8 summary, `retryable_by_model` forced `false` after any ambiguous write) so the model can recover within `round_limit`. |
| **Policy, auth or contract failure** (`ToolFault::TerminalRefusal`) | Revoked session/grant/capability, schema/bounds violation (`max_bytes < 4`), unpinned destination, missing V1-28 credential or V1-17 quota; SSRF `Address`, TLS cert/host failure, `3xx` redirect, `401`/`403`, unexpected `4xx`, `tools/list` drift, `input_required` or server-initiated JSON-RPC request, malformed JSON-RPC/framing or `> 4 MiB` response | `0` retries | `failed` when refused pre-send or on definitive `401`/`403` with no prior ambiguous attempt; `outcome_unknown` if any prior write attempt may have left the process or if `input_required`, malformed framing or `TooLarge` arrives after a write was sent. | Fail closed immediately without follow-up calls. Authority revocation settles the run under ADR 0033/0035; contract or auth refusals return fixed redacted diagnostics with `retryable_by_model: false` and no upstream body echoing. |

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

Normalized UTF-8 tool output obeys three size bands (with `artifact.read_range` explicitly
exempt from spill publication because each `artifact.read_range` page is capped at `<= 200`
lines and `<= 16_384` serialized JSON bytes and paginates via `next_offset`). The `16 KiB`
(`16_384` bytes) ceiling applies to the **final UTF-8 serialized JSON tool-result string**
(after JSON escaping — such as `\u001b` 6x expansion — and all envelope and provenance
metadata), never just raw unescaped output bytes:

| Band | Condition | Handling |
| --- | --- | --- |
| **Inline** | `<= 200` lines **and** final UTF-8 serialized JSON inline envelope `<= 16_384` bytes | Returned directly in the tool-result envelope (`storage: "inline"`, `truncated: false`, `size_bytes`, `line_count`, `content_sha256`). |
| **Spill** | Exceeds `200` lines or `16_384` serialized JSON bytes (excluding `artifact.read_range`), up to `4 MiB` (`4_194_304` bytes) raw payload | Published as an immutable scoped artifact in the run's `scope_id`; model receives a compact head/tail preview envelope whose final UTF-8 serialized JSON is `<= 16_384` bytes. |
| **Refused** | Exceeds `4 MiB` wire or payload ceiling | Aborted during streaming before memory or disk exhaustion (`ToolFault::TerminalRefusal` / `TooLarge`). |

### Scoped artifact ownership, publication and cleanup

**Private ownership, scope quota and retention.** Per `migrations/0004_artifacts_storage_accounting.sql`
and [ADR 0027](0027-authorization-and-private-projects.md), a spilled tool artifact created
inside a `project` scope still has `owner_user_id = run.actor_user_id` and is **private to that
creator by default** until explicitly shared (a project scope never auto-publishes artifacts to
other members), while the project scope's `storage_accounts` row owns the storage quota charge.
Spilled tool artifacts follow the [ARCHITECTURE-v1.md](../../ARCHITECTURE-v1.md) retention
lifecycle: they remain `active` while referenced by retained conversation turns (inheriting the
scope/project retention policy on disassociation or deletion), immediately fail `Action::Read`
once transitioned to `retained`, and are physically deleted only by `artifact_fs::purge_due`
after their grace deadline expires.

**Lease-fenced lock-first publication (`artifact_fs::publish_bytes`).** `openmettle_worker`
already holds PostgreSQL column grants on `storage_instance`, `storage_accounts`, `artifacts`,
`storage_reservations` and `artifact_revisions` (including `display_name`, verified in
`src/boundaries.sql`). PR2 adds `artifact_fs::publish_bytes`, reusing `artifact_fs::ingest`'s
exact lock-first discipline (`src/artifact_fs.rs` and `src/storage.rs`) under the worker's live
lease fence so a replay or deposed stale worker can never overwrite an immutable revision:

1. Derive a deterministic adapter-owned idempotency key with a distinct spill domain prefix
   (`tool-spill:<operation_id>`, `<= 128` bytes) and resolve the artifact UUID via
   `storage::upload_artifact` so retries target one artifact.
2. Under `leases::with_lease` (`Fence::Step`, or `Fence::Hold` when publishing alongside
   `runs::record_observation`), call `storage::reserve` with `scope = run.scope_id`,
   `actor = run.actor_user_id`, `max_bytes = payload.len() as i64`, `run = Some(run_id)` and
   `operation = Some(operation_id)`.
   - If `reserve` returns `ReservationState::Released`, refuse closed (`Conflict`) without
     staging or touching filesystem paths.
   - If `reserve` returns `ReservationState::Settled`, skip staging and rename completely;
     verify exact `(artifact_id, size_bytes, content_digest, media_type, display_name,
     created_by_user_id)` replay through `storage::settle` (refusing closed on digest or
     metadata mismatch) and confirm the published regular file in `revisions/<reservation_id>`
     has exact `size_bytes`.
3. Only when `reserve` returns `ReservationState::Reserved` (and after releasing the DB
   connection), create `<ARTIFACTS_DIR>/staging/<reservation_id>` exclusively (`create_new`,
   mode `0600`), write the normalized UTF-8 bytes, compute SHA-256 and `fsync`.
4. In one short fenced transaction (`leases::with_lease` with `Fence::Step` or `Fence::Hold`,
   preserving the `runs` -> `storage_reservations` lock order so a deposed stale worker cannot
   publish after takeover), lock the `storage_reservations` row `FOR UPDATE` first and inspect
   its `state`:
   - **If `state == 'reserved'`:** rename `staging/<reservation_id>` to
     `revisions/<reservation_id>`, `fsync` `revisions/` and call `storage::settle` with
     `media_type` (`text/plain; charset=utf-8` or `application/json; charset=utf-8`) and a
     bounded display name passing `storage::valid_display_name`.
   - **If `state == 'settled'`:** drop/unlink only the local staging file without touching
     `revisions/<reservation_id>`, verify exact `(size_bytes, content_digest, media_type,
     display_name, created_by_user_id)` replay via `storage::settle` (refusing closed on digest
     or length mismatch) and confirm the published regular file matches `size_bytes`.
   - **If `state == 'released'`:** drop/unlink only the local staging file and refuse closed
     (`Conflict`).
5. **Cancellation-safe `spawn_blocking` publication fence.** Because `tokio::task::spawn_blocking`
   cannot be aborted once started (`src/artifact_fs.rs`, `src/worker.rs`), dropping an async
   publication future during worker cancellation or drain would otherwise let an unguarded
   blocking rename or error-cleanup continue after the fenced DB transaction rolls back and a
   new worker reclaims the run. `artifact_fs::publish_bytes` MUST hold an async/sync
   publication guard across all `spawn_blocking` filesystem work and **await completion** of
   any started `spawn_blocking` stage, rename, `fsync` or error-cleanup step inside the
   worker's drain budget before releasing or closing the fenced DB transaction — never
   detaching filesystem mutations past lease release or transaction drop.

**Ledger-safe spill cleanup (`artifact_fs::reconcile_run_spills`).** Because
`artifact_fs::reconcile_expired` scans only upload reservations (`run_id IS NULL`) and
`run_id IS NOT NULL` matches all run-linked reservations (not only spills), PR2 adds
`artifact_fs::reconcile_run_spills` to the worker maintenance sweep with strict ledger safety
across both [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md) crash
windows:

- Scan adapter-owned spill reservations matching the deterministic `tool-spill:`
  `idempotency_key` prefix with `operation_id IS NOT NULL` across both `state = 'reserved'`
  and `state = 'released'` (for retryable cleanup of orphaned files left if a process crashed
  after `storage::release` committed and before filesystem unlink finished). Never touch
  `state = 'settled'` rows during spill reconciliation; settled revisions are deleted only by
  `artifact_fs::purge_due` after retention expiry.
- For each `state = 'reserved'` candidate, open a transaction respecting the existing lock
  order (`openmettle.runs` first via `FOR NO KEY UPDATE`, then `openmettle.storage_reservations`
  via `FOR UPDATE SKIP LOCKED`) and prove **both**:
  1. the publisher lease is inactive (the run is terminal or has no live lease claim), **and**
  2. the linked operation is resolved (terminal `succeeded` or `failed`, never `intent` or
     `outcome_unknown`). A terminal run alone is **not** sufficient because an `interrupted`
     run can still own an `outcome_unknown` operation (`src/authz/leases.rs`), for which
     `storage::release` rightly refuses with `Error::Unresolved` (`src/storage.rs`).
- Once proven under lock, call `storage::release` and commit the DB release, then unlink
  **both** `<ARTIFACTS_DIR>/staging/<reservation_id>` and any unsettled
  `<ARTIFACTS_DIR>/revisions/<reservation_id>` file for that released `reservation_id`
  (matching `artifact_fs::reconcile_expired` in `src/artifact_fs.rs` for the
  post-rename/pre-settlement crash window, because a `released` reservation has no
  `artifact_revisions` row and will never be visited by `purge_due`).
- For any `state = 'released'` spill candidate (handling crashes after `storage::release`
  committed and before unlink completed), retryably unlink any remaining orphaned
  `<ARTIFACTS_DIR>/staging/<reservation_id>` and unsettled
  `<ARTIFACTS_DIR>/revisions/<reservation_id>` files.

### Head/tail preview envelope and unavailable-spill policy

A spilled result returns a closed JSON envelope whose **final UTF-8 serialized JSON string** is
capped at `16 KiB` (`16_384` bytes):

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

If JSON string escaping (such as `\u001b` control characters) and envelope metadata push the
serialized JSON above `16_384` bytes, trim `head` and `tail` preview code points symmetrically
(preserving valid UTF-8 boundaries, non-overlap and accurate byte counts) until the final
serialized JSON fits `<= 16_384` bytes. The model inspects omitted middle ranges by calling
`artifact.read_range` with the returned `artifact_id` and `revision_id`, subject to live scope,
`Action::Read` and `active` revision rechecks.

**Startup check, opportunistic spill fallback and deferral of `spill_required`.** Matching
`src/lib.rs`, worker startup validates `OPENMETTLE_WORKER_ARTIFACTS_DIR` via
`artifact_fs::Store::open` **whenever configured** so an invalid, relative or unwritable
directory fails fast at boot, while leaving `OPENMETTLE_WORKER_ARTIFACTS_DIR` unset (`None`)
still allows the worker to boot in non-spill mode. All V1-14 spills are **post-response
opportunistic spills**; strict `spill_required` pre-reserved write tools are explicitly
deferred out of V1-14 because `Review::validate` (`src/authz/approvals.rs`) requires an
existing authorized `Review.artifact` whenever `Review.reservation` is set, whereas a newly
spilled tool output has neither an `operation_id` nor a known byte length before intent commit
and dispatch.

If `OPENMETTLE_WORKER_ARTIFACTS_DIR` is unset (`None`), storage limits are unconfigured,
owner/instance storage quota is exhausted or runtime filesystem publication fails, the worker
**always** records the tool's true observation in `operations` first (so a committed external
write is never hidden, falsely marked failed or re-dispatched), includes the redacted
`spill_error` (`store_unconfigured`, `quota_exceeded` or `storage_io`) in observation evidence
and returns a bounded fallback envelope (`<= 16_384` serialized JSON bytes) with
`storage: "truncated_no_spill"`, `truncated: true`, `artifact_id: null`, `revision_id: null`,
the same UTF-8-safe `head`/`tail` preview, `omitted_bytes` and `content_sha256`. Truncation is
always explicit; partial output is never labeled complete.

## Delivery and verification

| Slice | Deliverable | Acceptance evidence |
| --- | --- | --- |
| PR1 | This ADR (`0039`). | Review against #14, #25, ADRs 0010, 0031, 0033, 0035 and 0038; `ai-guardrails docs audit` reports zero findings. |
| PR2 | Reviewed tool registry (`EffectPolicy`), strict schema/argument validator and default expander, `approvals::start_replayed_read` for unfinished `repeatable_read` replays, internal `artifact.read_range` v1 tool, lease-fenced cancellation-safe `artifact_fs::publish_bytes`, `reconcile_run_spills` and serialized-budget head/tail preview builder. | PostgreSQL 18 tests: cross-user, cross-scope, archived/deleted project, private project-scope spill ownership (other members denied until shared), share revocation and `active` -> `retained` transition between original read and replay, and non-`active` revision refusals; `max_bytes < 4` validation refusal, invalid UTF-8 binary semantic fault and strictly inline `artifact.read_range` under both 6x JSON escaping and `<= 200`-line `next_offset` pagination; unfinished `repeatable_read` replay through `approvals::start_replayed_read` (rechecking bound session and canonical proposal without issuing a write permit); duplicate-key, float, depth, bound and wildcard rejections; serialized-JSON `16 KiB` inline/spill thresholds (`\u001b` expansion, `200` lines, multi-byte UTF-8 cuts); unset-`ARTIFACTS_DIR`, unconfigured-store, quota-refused and I/O fallback envelopes; `publish_bytes` settled-replay match/mismatch, `released` refusal, stale-lease rejection and takeover-during-publication (`spawn_blocking` cancellation/drain fence); `reconcile_run_spills` coverage of `interrupted` runs with `outcome_unknown`, concurrent publisher races, post-release/pre-unlink retryable cleanup of `released` rows, post-rename/pre-settlement cleanup of unsettled `revisions/<id>` and untouched `settled` rows. |
| PR3 | Streamable HTTP MCP (`2026-07-28`) adapter over `provider_http::transport`, `MCP_DNS_SLOTS`, `McpCredentialProvider` seam, `ApprovedAdapter` implementation, read-only `Executor::reconcile` under `Fence::Hold`, and `PLAN-10` / `PLAN-22` conformance harness on synthetic `rcgen` TLS + PostgreSQL 18. | Synthetic TLS + PostgreSQL 18 tests: MCP `2026-07-28` request headers (`MCP-Protocol-Version: 2026-07-28`, `Mcp-Method`, `Mcp-Name`, no `Mcp-Session-Id`) **and** body `params._meta` (`io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities = {}`) over `application/json` and `text/event-stream` (SSE comments and progress notifications before final response, mismatched JSON-RPC IDs, duplicate final responses, `input_required` and unexpected server-initiated request rejection, `4 MiB` aggregate stream ceiling before buffering); bounded retries with identical persisted `Idempotency-Key` on `repeatable_read`/`idempotent` plus proven-pre-send retries on `lookup`/`non_repeatable`, enforcing attempt cap, `step.stop`, `step.deadline` (including `EndpointKey::Supported.expires_us`) and full ADR 0035 effect-level + bound-session/generation revocation checks before every retry across all classes; sticky whole-operation send uncertainty (`outcome_unknown` preserved when a retry fails pre-send or receives `401`/`403`/deadline after ambiguous attempt 1) and `retryable_by_model: false` on every uncertain write including exhausted or window-expired `idempotent` writes and ambiguous `lookup`/`non_repeatable` writes (with zero post-send retries for `lookup`/`non_repeatable`); `lookup` reconciliation with and without `downstream_handle` passing `&ActiveRun`/`&Lease<'_>` into `Executor::reconcile`, enforcing the read-only `Fence::Hold` authority and claim check in `ExecState::Reconciling` before `McpCredentialProvider` lookup, and verifying `repeatable_read` exclusion from `Executor::reconcile`; semantic `isError: true` / `-32602` plus `PLAN-10` valid-schema wrong/stale-fact semantic recovery; internal-MCP identity-boundary check authenticating caller/scope via primary PostgreSQL authority rather than compiled bypass; `PLAN-22` fixed native vs internal-MCP vs remote-MCP route measurement harness hook; SSRF/TLS/redirect/`401`/`403`/`tools/list`-drift/`> 4 MiB` refusals; canary redaction checks across errors, stderr, traces and metrics; end-to-end `park` -> `decide` -> resume -> `ApprovedAdapter::send` -> spill -> `artifact.read_range` round trip including share-revocation and retention replay refusals. |

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
