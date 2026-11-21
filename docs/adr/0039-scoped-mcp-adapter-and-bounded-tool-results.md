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
| [ADR 0010](0010-provider-http-transport.md) and [ADR 0038](0038-sglang-and-external-provider-conformance-adapter.md), `src/provider_http/transport.rs` | Add a Streamable HTTP JSON-RPC 2.0 MCP (`2026-07-28`) client over `provider_http::transport` with a dedicated DNS slot semaphore, strict header allowlist (rejecting `x-mcp-header` schemas) and 4 MiB streaming response ceiling. |
| [ADR 0027](0027-authorization-and-private-projects.md) and [ADR 0035](0035-approvals-permitted-yolo-and-effect-ledger.md), `src/authz/approvals.rs` | Implement `EffectPolicy` in the reviewed tool registry, bind every invocation to `Proposal`, `Destination`, `EffectClass`, `EndpointKey` and `record_fenced_intent`, and add PR2's next sequential schema migration (e.g., `0024`) for durable pre-dispatch attempt accounting (`openmettle.operations.dispatched_attempts`), upgrade repair of pre-existing `queued`/`waiting` revision-zero `repeatable_read` intents and an `AFTER UPDATE OF state ON openmettle.runs` `SECURITY DEFINER` trigger (`openmettle.resolve_abandoned_repeatable_reads()`) enforcing mixed-version pre-`waiting`/pre-terminal resolution at the database layer. |
| [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md), `src/worker.rs` | Implement `ApprovedAdapter` for resumed writes, reuse the same committed-envelope dispatch for immediate reads and permitted YOLO writes, stop `outcome_unknown` writes into `ExecState::Reconciling` (adding `StepResult::Invalidated` -> `WorkEnd::Stop(Stop::LeaseLost)` in PR2 to halt deposed workers on lease loss), rely on PR2's database trigger to resolve abandoned `repeatable_read` intents before `run-waiting` / `run-terminal` across mixed-version `N-1`/`N` workers and API processes, and implement destination-authorized read-only `Executor::reconcile`. |
| [ADR 0005](0005-artifact-storage-accounting.md) and [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md), `src/storage.rs` and `src/artifact_fs.rs` | Add three-phase lease-fenced direct byte publication (`artifact_fs::publish_bytes`, never holding a DB transaction across disk I/O, racing Phase 2's `spawn_blocking` disk join against `step.deadline` and `step.stop.changed()` with detached late-completion cleanup, executing Phase 3 `storage::settle` and `runs::record_observation` atomically in one `Fence::Step` transaction with local `step.deadline`/`step.stop` rechecks before settling and immediately before commit, and rechecking `step.stop` under the `runs` lock and immediately before commit in inline `truncated_no_spill` fallbacks), startup writability probing (`Store::probe_writable`) and spill-scoped cleanup (`artifact_fs::reconcile_run_spills`), paired with a strictly inline read-only `artifact.read_range` tool. |

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
  input_schema_digest)` manifest. Undeclared remote tools are ignored; missing tools, schema
  digest drift or any schema containing MCP `2026-07-28` `x-mcp-header` parameter annotations
  fail closed before the tool is offered to the model or any call is admitted.
- **Scope exclusions and deferrals (#14).** Selective tool discovery and deferred MCP tool
  definitions (`PLAN-21`) are explicitly deferred out of V1-14 scope; every offered tool for a
  run is pinned at admission. Bounded independent tool fan-out research (`PLAN-19`) remains
  conditional research outside V1-14 implementation; V1-14 executes validated calls within the
  run's existing round budget without adding a fan-out scheduler.

## Reviewed tool contracts and ADR 0035 integration

### Schema validation and argument bounds

Every tool contract in the registry declares an immutable closed JSON input schema and default
values. V1 rejects any reviewed tool registration or upstream `tools/list` schema containing
MCP `2026-07-28` `x-mcp-header` parameter annotations (which require mirroring supplied
parameter values into outbound `Mcp-Param-*` HTTP headers) during both catalog validation and
runtime `tools/list` schema verification, before offering the tool to the model or admitting
calls. Before calling `Proposal::new`, the adapter validates raw model arguments in this
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

**Durable pre-dispatch attempt accounting (PR2 sequential schema migration).**
`openmettle.operations` (`migrations/0003_runs_events_operations.sql`) currently has no attempt
counter column, so in-memory attempt tracking would let a worker crash after attempt 3 before
`record_observation` and allow a reclaiming worker to dispatch three more attempts on a
`repeatable_read` replay. PR2 therefore adds its next sequential schema migration (e.g., `0024`,
avoiding collision with sibling migrations landing on `main` first) introducing
`dispatched_attempts integer NOT NULL DEFAULT 0 CHECK (dispatched_attempts >= 0)` on
`openmettle.operations`, grants `UPDATE (dispatched_attempts)` to `openmettle_worker` and adds
the matching `$1 >= <v1_14_schema_version>` column entry to `src/boundaries.sql`. Before
**every** outbound HTTP send — attempt 1, every in-process retry and every crash-reclaim replay
— a `Fence::Step` transaction atomically locks the run and operation row (`FOR UPDATE`),
verifies `dispatched_attempts < 3` and increments `dispatched_attempts = dispatched_attempts + 1`
before releasing the PostgreSQL connection.

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
     primary, verifies the operation is `capability = 'repeatable_read'` with
     `outcome = 'intent'` and matches the requested canonical `Proposal`, checks
     `dispatched_attempts < 3` and atomically increments `dispatched_attempts` by `1`, and
     returns `(operation_id, committed_request_bytes, bounded_deadline)` **without** issuing a
     `CommittedIntent` write permit so the adapter can dispatch the committed read bounded by
     `step.deadline.min(bounded_deadline)`. When `dispatched_attempts == 3`,
     `approvals::start_replayed_read` refuses dispatch without incrementing, records a terminal
     `failed` observation (`outcome = 'failed'` with non-empty redacted evidence) under
     `Fence::Step` and performs **zero** outbound HTTP sends.
4. On `IntentResult::Invalidated(_)`, stop immediately; the fenced check already settled the
   run.
5. On `IntentResult::Applied(committed)`, release the PostgreSQL connection before any I/O and
   consume the one-use send permit `committed.start(&step)` once before attempt 1, applying the
   returned shortened `deadline` to `step.deadline`. If `start` returns `None`, issue no
   outbound call and leave the `intent` for settlement or reconciliation. On resumed human
   approvals, `worker::execute` (`src/worker.rs`) has already consumed `intent.start(&step)`
   and passes `ApprovedAdapter::send` the committed request bytes and shortened `step.deadline`.
   Before issuing attempt 1 (and before every permitted retry), a short `Fence::Step`
   transaction verifies `dispatched_attempts < 3` and increments `dispatched_attempts` by `1`
   before releasing the connection.
6. Dispatch the committed `openmettle.effect` v1 envelope through `ApprovedAdapter::send` (the
   same committed-envelope path for immediate reads, permitted YOLO writes and resumed human
   approvals; unfinished `repeatable_read` replays reuse the same committed-envelope dispatch
   with the bytes and deadline returned by `approvals::start_replayed_read`).
7. When `EndpointKey::Supported { field, key, .. }` is recorded in the committed envelope, emit
   `key` unchanged in the contract-pinned HTTP header or JSON-RPC `_meta` field. Never
   allocate a fresh key for the same `logical_key`.
8. After dispatch, record the outcome in PostgreSQL with the expected revision, stable append
   key, `downstream_handle` when returned and bounded redacted evidence:
   - For **inline** results, errors or `truncated_no_spill` fallbacks, borrow a connection and
     commit `runs::record_observation` under `leases::with_lease(..., Fence::Hold, ...)` (or
     under `Fence::Step` returning `StepResult::Continue` when a completed known-outcome call
     aborts spill publication solely because its shortened local `step.deadline` elapsed while
     `step.stop` remains `None` through commit; see the spill-abort disposition rules below,
     including the mandatory `*step.stop.borrow()` rechecks under the `runs` lock and
     immediately before commit). If the fence rejects with `LeaseError::StaleClaim`,
     `LeaseError::Expired` or `LeaseError::Terminal` — or `*step.stop.borrow()` signals
     `Some(Stop::LeaseLost)` before commit — roll back and stop immediately with
     `StepResult::Invalidated` without further PostgreSQL writes.
   - For **spilled** results, `storage::settle` and `runs::record_observation` commit
     **atomically together in Phase 3's single `Fence::Step` transaction** (never across two
     separate transactions; see the three-phase publication rules below).
9. **Uncertain writes halt model continuation immediately (including on deposed-worker lease
   loss).** Whenever any external write (`lookup`, `non_repeatable`, or an `idempotent` write
   whose retries or `EndpointKey::Supported` window expired after a possible send) ends with an
   uncertain remote outcome, the adapter MUST attempt to commit `runs::record_observation` with
   `outcome = "outcome_unknown"` under `leases::with_lease(..., Fence::Hold, ...)`:
   - If `Fence::Hold` succeeds, immediately return **`StepResult::Stopped`** — **never**
     `StepResult::Continue`. In `src/worker.rs`, returning `StepResult::Stopped` exits
     `worker::execute` with `WorkEnd::Complete(Settle::Stopped)`, so `run_one` calls
     `leases::settle(..., Settle::Stopped)` and transitions the run to `ExecState::Reconciling`
     (when execution budget remains) or terminal `interrupted` (`src/authz/leases.rs`).
   - If `Fence::Hold` rejects with **`LeaseError::StaleClaim`**, **`LeaseError::Expired`** or
     **`LeaseError::Terminal`** (because the worker's claim already expired, was replaced or
     the run became terminal between the possible write send and `record_observation`), the
     deposed worker MUST stop immediately with **`StepResult::Invalidated`** (added to
     `StepResult` in **PR2** — since PR2's `publish_bytes` and `start_replayed_read` already
     return `StepResult::Invalidated` — and mapped in `worker::execute` (`src/worker.rs`) to
     `WorkEnd::Stop(Stop::LeaseLost)` so `run_one` exits immediately without touching
     PostgreSQL). On an expired or replaced non-terminal lease (`Expired` or `StaleClaim`),
     this leaves the already-committed durable `outcome = 'intent'` write row intact so the
     replacement worker's recovery path (`leases::reclaim_next` -> `src/worker.rs`, `execute`
     checking `recovered && !leases::unresolved_operations(...).is_empty()` and returning
     `WorkEnd::Complete(Settle::Stopped)`) routes the unresolved write directly into
     `ExecState::Reconciling` or terminal settlement before any model step; on an
     already-terminal run (`Terminal`), no replacement worker claims the run and zero further
     DB writes or outbound sends occur.

   Because `worker::execute` never runs another model step once a run is in
   `ExecState::Reconciling` (or on crash recovery while `leases::unresolved_operations` is
   non-empty) and `Fence::Step` rejects new intents with `LeaseError::Stopping` or
   `LeaseError::Terminal`, no subsequent model round can propose the same mutation under a
   fresh `tool_call_id` or fresh `logical_key` (which `approvals::record_fenced_intent` would
   otherwise admit as a new operation).

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
  worker's `ActiveRun` / `ClaimedRun`, `leases::UnresolvedOperation` carries only
  `(id, logical_key, target, capability, outcome, revision, downstream_handle)`, and
  `recheck_decision` (`src/authz/runs.rs`) verifies only principal, platform capabilities, run
  scope, conversation, optional local resource and run capabilities — **not** access to the
  specific MCP server, connection or account. PR3 therefore passes `&ActiveRun` (or
  `&Lease<'_>`) into `Executor::reconcile` (or an extended reconciliation hook), loads the
  operation's committed `openmettle.effect` v1 payload and run metadata on a worker DB
  connection, and under **`leases::with_lease(..., Fence::Hold, ...)`** performs **both**:
  1. a read-only authority and claim check validating the active lease token,
     `ExecState::Reconciling`, and current principal, scope, target and tool
     read-reconciliation authority via `recheck_decision` (without requiring `Fence::Step` or
     live originating-session dispatch rights, matching ADR 0035's read-only reconciliation
     contract); **and**
  2. a **live destination-specific read/reconcile authorization check** against the committed
     MCP server, `connection_id`, `account_id`, `tool_id` and `resource` binding recorded in
     the operation's `openmettle.effect` v1 intent (confirming that the destination connection
     and account remain enabled, bound to `run.scope_id` and authorized for `run.actor_user_id`
     for read-only reconciliation).

  Both checks run **before** any `McpCredentialProvider` lookup. If the actor's or scope's
  access to that MCP server, connection or account was revoked or disabled, `Executor::reconcile`
  refuses immediately (returning `None`) with **zero** `McpCredentialProvider` lookups and
  **zero** outbound HTTP calls, letting ADR 0033 settle the run as `interrupted`.
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
  Exclude `Mcp-Param-*` headers from this allowlist; because MCP `2026-07-28` requires
  mirroring `x-mcp-header`-annotated parameters into `Mcp-Param-*` headers, v1 rejects any
  reviewed registration or upstream `tools/list` schema containing `x-mcp-header` fail-closed
  before offering the tool or admitting calls, keeping the fixed allowlist airtight and
  protocol-compliant. Every outbound `tools/list` and `tools/call` JSON-RPC request body MUST
  populate `params._meta["io.modelcontextprotocol/protocolVersion"] = "2026-07-28"` (agreeing
  with `MCP-Protocol-Version`) and
  `params._meta["io.modelcontextprotocol/clientCapabilities"] = {}` per the MCP `2026-07-28`
  specification, alongside any contract-pinned `_meta` idempotency field derived strictly from
  the reviewed call. Keep stateful `Mcp-Session-Id` out of this stateless v1 profile (never
  send or adopt server session IDs). Reject header blocks exceeding `2 KiB` outbound or
  `8 KiB` / `32` headers inbound, and outbound bodies exceeding `128 KiB`.
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
  authority expiry). Before **every** outbound dispatch attempt across **all** effect classes
  (initial attempt 1, every permitted in-process retry of `repeatable_read`, active unexpired
  `idempotent` writes, or proven-pre-send connection-refused/DNS retries of `lookup` and
  `non_repeatable` writes, and every `start_replayed_read` crash-reclaim replay), enforce
  `step.stop`, `step.deadline` (including `EndpointKey::Supported.expires_us`) **and** a short
  `Fence::Step` transaction on the primary that atomically checks `dispatched_attempts < 3`,
  increments `openmettle.operations.dispatched_attempts` by `1` and performs an **effect-level
  authority recheck** — verifying current principal, scope, target, capability and destination
  policy **plus** the live bound originating/deciding session and approval, user and provider
  generations per ADR 0035 (never relying on `recheck_leased` alone, which intentionally
  ignores `originating_session_active` for background run continuation). While I/O is in
  flight, follow ADR 0038: race `step.stop`, `step.deadline`, `ActiveRun::execution_deadline`
  and the adapter timeouts. On any stop signal, drop the HTTP future immediately so the socket
  closes.

### Typed fault taxonomy and retry rules (`PLAN-10`)

Every tool failure maps to one of three disjoint fault classes. The adapter tracks transport
send uncertainty as a **sticky flag across the whole logical operation**: once attempt 1 may
have left the process (timeout, socket reset or mid-stream disconnect after request write), any
subsequent retry that fails pre-send, hits a deadline or stop signal, or returns `401`/`403` or
malformed framing MUST keep the ledger outcome `outcome_unknown` (never downgrading to
proven-unsent `failed` or `aborted`). Whenever **any** external write (`lookup`,
`non_repeatable`, or an `idempotent` write whose retries or `EndpointKey::Supported` window
expired after a possible send) ends with `outcome_unknown`, the adapter attempts to commit
`outcome = "outcome_unknown"` via `runs::record_observation` under `Fence::Hold`: on commit, it
returns **`StepResult::Stopped`** immediately — **never** `StepResult::Continue` and never a
model-visible error envelope — so `leases::settle(..., Settle::Stopped)` moves the run into
`ExecState::Reconciling` (or terminal `interrupted`) with zero further model rounds; if
`Fence::Hold` rejects with `LeaseError::StaleClaim`, `LeaseError::Expired` or
`LeaseError::Terminal`, the deposed worker stops immediately with **`StepResult::Invalidated`**
without touching PostgreSQL so the intact durable `outcome = 'intent'` write row routes the
replacement worker (`src/worker.rs`) straight into `ExecState::Reconciling` / settlement before
any model step. By contrast, `retryable_by_model: false` in model-visible tool error envelopes
applies to **known-outcome** non-retryable failures (such as pre-send validation/policy
refusals, proven pre-send transport failures or confirmed downstream
`401`/`403`/contract-guaranteed side-effect-free `isError` responses where the remote write
outcome is authoritatively `failed` and the run may continue within its round budget).

| Fault class | Qualifying evidence | Retries | Ledger outcome | Model / worker action |
| --- | --- | --- | --- | --- |
| **Transient transport** (`ToolFault::Transient`) | Pre-send DNS/TCP connect failure; HTTP `408`, `429`, `502`, `503`, `504`; mid-stream disconnect or idle/call timeout | Up to `3` durable total attempts (`openmettle.operations.dispatched_attempts < 3`, atomically incremented under `Fence::Step` before each send) for `repeatable_read` and active unexpired `idempotent` writes with the identical persisted key; for `lookup` and `non_repeatable` writes, retry **only** proven pre-send DNS/connection-refused failures and **never** retry after request bytes are sent. Before **every** permitted retry across all classes, enforce `dispatched_attempts < 3`, `step.stop`, `step.deadline` (including `EndpointKey::Supported.expires_us`) and a fenced ADR 0035 effect-level authority recheck (principal, scope, target, capability, destination policy plus live bound session and approval/user/provider generations). | `failed` for exhausted `repeatable_read` or proven pre-send failure when no prior attempt left the process; `outcome_unknown` for any `idempotent`, `lookup` or `non_repeatable` write once any attempt may have left the process without endpoint proof. | Sleep with `ring::rand::SystemRandom` full jitter (`250 ms`, `500 ms`). For a single valid integer `Retry-After` (seconds): sleep at least that delay when `<= 60 s` and within remaining call, authority and run execution deadlines; fail without retrying if `Retry-After` exceeds `60 s` or the remaining budget; ignore malformed or duplicate headers. Abort sleep immediately on `step.stop`. For known-outcome `failed` reads or proven-unsent writes, return a bounded error envelope (`retryable_by_model: false` for non-retryable failures). For **every** write ending in `outcome_unknown` (including an `idempotent` write whose retries or `EndpointKey::Supported` window expired after a possible send), attempt `outcome = "outcome_unknown"` under `Fence::Hold` and return `StepResult::Stopped` into `ExecState::Reconciling` / `interrupted`, or `StepResult::Invalidated` immediately without touching PostgreSQL if `Fence::Hold` rejects with `StaleClaim`, `Expired` or `Terminal` (zero further model rounds). |
| **Semantic tool fault** (`ToolFault::Semantic`) | MCP JSON-RPC `result` with `isError: true`, JSON-RPC `-32602`, or internal tool domain refusal (for example invalid UTF-8 binary content, offset past EOF or non-`active` revision) | `0` transport retries | `failed` for reads and for writes whose reviewed contract guarantees `isError: true` caused no side effect (and no prior attempt was ambiguous); otherwise `outcome_unknown`. | For known-outcome `failed` results, return a bounded structured error envelope (`status: "tool_error"`, closed `fault_code`, `<= 2 KiB` UTF-8 summary, `retryable_by_model`) so the model can recover within `round_limit`. If an uncertain write ends in `outcome_unknown`, attempt `outcome = "outcome_unknown"` under `Fence::Hold` and return `StepResult::Stopped` into reconciliation/settlement (or `StepResult::Invalidated` on `StaleClaim | Expired | Terminal`, never `StepResult::Continue`). |
| **Policy, auth or contract failure** (`ToolFault::TerminalRefusal`) | Revoked session/grant/capability, schema/bounds violation (`max_bytes < 4`), `x-mcp-header`-annotated tool schema, unpinned destination, missing V1-28 credential or V1-17 quota; SSRF `Address`, TLS cert/host failure, `3xx` redirect, `401`/`403`, unexpected `4xx`, `tools/list` drift, `input_required` or server-initiated JSON-RPC request, malformed JSON-RPC/framing or `> 4 MiB` response | `0` retries | `failed` when refused pre-send or on definitive `401`/`403` with no prior ambiguous attempt; `outcome_unknown` if any prior write attempt may have left the process or if `input_required`, malformed framing or `TooLarge` arrives after a write was sent. | Fail closed immediately without follow-up calls. Authority revocation settles the run under ADR 0033/0035. Known-outcome contract or auth refusals (`failed`) return fixed redacted diagnostics with `retryable_by_model: false` and no upstream body echoing. Any write ending in `outcome_unknown` attempts `outcome = "outcome_unknown"` under `Fence::Hold` and returns `StepResult::Stopped` into `ExecState::Reconciling` / `interrupted` (or `StepResult::Invalidated` on `StaleClaim | Expired | Terminal`, never `StepResult::Continue`). |

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

**Three-phase lease-fenced publication (`artifact_fs::publish_bytes`).** `openmettle_worker`
already holds PostgreSQL column grants on `storage_instance`, `storage_accounts`, `artifacts`,
`storage_reservations` and `artifact_revisions` (including `display_name`, verified in
`src/boundaries.sql`). Because `leases::fenced` (`src/authz/leases.rs`) sets
`SET LOCAL idle_in_transaction_session_timeout = '5s'`, `run_one` (`src/worker.rs`) drops a
step once its drain deadline (`until = (Instant::now() + settings.lease / 6).min(shutdown_limit)`)
elapses and `Staged::publish` (`src/artifact_fs.rs`) unlinks `revisions/<id>` on post-rename
`sync_dir` failure, `artifact_fs::publish_bytes` MUST **never** hold a `leases::fenced` DB
transaction open across `spawn_blocking` filesystem I/O. Instead, PR2 mirrors
`artifact_fs::ingest`'s three-phase separation with **both** short DB phases fenced under
`Fence::Step`, a **disjoint per-attempt `reservation_id`**, racing Phase 2's `spawn_blocking`
disk join against `step.deadline` and `step.stop.changed()`, local `step.deadline`/`step.stop`
enforcement after Phase 2, before Phase 3 settlement and immediately before Phase 3 commits,
lock-acquired and pre-commit `step.stop` enforcement inside the inline `truncated_no_spill`
fallback, and **single-transaction atomicity** between `storage::settle` and
`runs::record_observation`:

1. **Phase 1 — Short `Fence::Step` reservation (no filesystem I/O).** Mint a fresh per-attempt
   random 128-bit UUID/nonce `<attempt_id>` (`ring::rand::SystemRandom`), giving an
   adapter-owned idempotency key `tool-spill:<operation_id>:<attempt_id>` (`84` bytes,
   `<= 128` bytes) and a fresh `artifact_id`. Under `leases::with_lease(..., Fence::Step, ...)`,
   call `storage::reserve` with `scope = run.scope_id`, `actor = run.actor_user_id`,
   `max_bytes = payload.len() as i64`, `run = Some(run_id)` and
   `operation = Some(operation_id)`. Commit and release the PostgreSQL connection before any
   disk I/O. Every worker spill attempt therefore owns a **disjoint `reservation_id`,
   `staging/<reservation_id>` and `revisions/<reservation_id>`**: a replacement worker never
   reuses or settles an earlier worker's `reservation_id`. If `Fence::Step` rejects with
   `StaleClaim`, `Expired`, `Terminal` or `Stopping`, abort spill publication and apply the
   spill-abort disposition rule below.
2. **Phase 2 — Unfenced `spawn_blocking` disk I/O raced against local cutoffs (strictly
   outside any DB transaction).** With no PostgreSQL connection borrowed and no DB transaction
   open (so slow disk I/O `> 5 s` can never trip `idle_in_transaction_session_timeout`), check
   `Instant::now() < step.deadline && step.stop.borrow().is_none()` before spawning; if
   already false, skip disk I/O (leaving `<reservation_id>` in `state = 'reserved'` for
   `reconcile_run_spills`) and immediately apply the spill-abort disposition rule below.
   Otherwise, allocate a shared `Arc<AtomicBool>` (`cancelled = false`) and run the blocking
   disk pipeline on `spawn_blocking`: create `<ARTIFACTS_DIR>/staging/<reservation_id>`
   exclusively (`create_new`, mode `0600`), write the normalized UTF-8 bytes, compute SHA-256,
   `fsync` the file, check `cancelled.load(Ordering::Acquire)` before renaming, rename
   `staging/<reservation_id>` to `revisions/<reservation_id>` and `fsync` `revisions/`.
   Because `run_one` (`src/worker.rs`) waits only up to the drain deadline
   `until = (Instant::now() + settings.lease / 6).min(shutdown_limit)` before dropping `work`,
   the async adapter MUST race the `spawn_blocking` `JoinHandle` in a `tokio::select!` against
   **both** `tokio::time::sleep_until(step.deadline)` and `step.stop.changed()`:
   - **Cutoff fires before `spawn_blocking` completes (raced detach):** Set
     `cancelled.store(true, Ordering::Release)`, detach the `JoinHandle` (an in-flight OS
     blocking syscall cannot be preempted), leave the Phase-1 `<reservation_id>` in
     `state = 'reserved'` while late disk I/O may still be active (so
     `storage_accounts.reserved_bytes` continues to cover any in-flight bytes on disk without
     premature quota release) and **immediately** run the inline
     `storage: "truncated_no_spill"` fallback (under the spill-abort disposition rule below)
     during the drain window so the known call outcome (`Ok` or terminal `Err`) and required
     `StepResult` complete before `run_one` drops `work`. When the detached late
     `spawn_blocking` closure eventually unblocks, it inspects
     `cancelled.load(Ordering::Acquire)`: if `cancelled` is `true` before `rename`, it skips
     `rename` and immediately unlinks `staging/<reservation_id>` (`fsync`ing `staging/`); if
     `cancelled` became `true` during or after `rename` (when Phase 2 has already exited into
     the inline fallback, so Phase 3 will never run and no `artifact_revisions` row can ever
     reference this disjoint per-attempt `<reservation_id>`), it unlinks both
     `staging/<reservation_id>` (if present) and the unsettled `revisions/<reservation_id>`
     (`fsync`ing parent directories). `reconcile_run_spills` remains the crash-safe backstop
     that releases `<reservation_id>` via `storage::release` (returning `reserved_bytes` to
     `0`, since `operations.outcome` is already `'succeeded'` or `'failed'`) and retryably
     unlinks any remaining `staging/<reservation_id>` or unsettled `revisions/<reservation_id>`
     after `spill_reservation_ttl`.
   - **Normal uncancelled `spawn_blocking` completion (`cancelled == false`):** Unlike
     `Staged::publish` (`src/artifact_fs.rs`), an uncancelled Phase-2 spill helper never
     unlinks `revisions/<reservation_id>` on a post-rename `sync_dir` failure, nor if
     `step.deadline` or `step.stop` trips after the `JoinHandle` returns normally (leaving
     `<reservation_id>` in `state = 'reserved'` for `reconcile_run_spills`). Immediately after
     `spawn_blocking` returns normally, re-check
     `Instant::now() < step.deadline && step.stop.borrow().is_none()`; if false, do not enter
     Phase 3 (leaving `<reservation_id>` in `state = 'reserved'` for `reconcile_run_spills`)
     and apply the spill-abort disposition rule below. Because each attempt owns a disjoint
     `reservation_id`, a stalled or detached `spawn_blocking` thread on a deposed worker can
     never overwrite, clobber or unlink a replacement worker's revision even if `fsync` stalls
     past both the `5 s` DB timeout and the worker drain deadline.
3. **Phase 3 — Single atomic `Fence::Step` settlement and observation (no filesystem I/O).**
   Borrow a connection and open **one** short `leases::with_lease(..., Fence::Step, ...)`
   transaction (`leases::fenced` in `src/authz/leases.rs`, zero disk I/O inside the
   transaction). `Fence::Step` locks `openmettle.runs` (`FOR NO KEY UPDATE`) and verifies DB
   lease/execution timestamps, `state = 'running'` and `cancel_reason IS NULL`, failing closed
   with `StaleClaim`, `Expired`, `Terminal` or `Stopping` if the DB lease lapsed, was replaced
   or was cancelled while Phase 2 ran (leaving `<reservation_id>` in `state = 'reserved'` with
   zero settled revision and zero leaked quota; apply the spill-abort disposition rule below).
   Because `Fence::Step` checks only DB timestamps, `state` and `cancel_reason` — **not** the
   shortened local `step.deadline` (`src/authz/approvals.rs`, `CommittedIntent::start`) or
   local `step.stop` — Phase 3 MUST re-check
   `Instant::now() < step.deadline && step.stop.borrow().is_none()` **after** acquiring the
   `Fence::Step` DB lock and **before** executing `storage::settle` or
   `runs::record_observation`. Inside that **exact same `Fence::Step` PostgreSQL transaction**
   — following the canonical lock order
   `runs -> storage_reservations -> artifacts -> storage_accounts -> storage_instance`
   (`src/storage.rs`) — execute **both** `storage::settle` **and** `runs::record_observation`
   atomically: lock `storage_reservations` (`FOR UPDATE`), verify `state == 'reserved'`
   (refusing closed with `Conflict` if already `released`), call `storage::settle` with
   `media_type` (`text/plain; charset=utf-8` or `application/json; charset=utf-8`) and a
   bounded display name passing `storage::valid_display_name` to create the immutable
   `artifact_revisions` row and charge active quota, construct the bounded preview envelope
   carrying the settled `(artifact_id, revision_id)`, and call `runs::record_observation`
   (`openmettle.runs` already locked -> `openmettle.operations` `FOR UPDATE` ->
   `openmettle.run_events` append). Because `storage::settle` (`src/storage.rs`) can still
   block waiting for shared `storage_accounts` and `storage_instance` row locks *after* the
   initial lock check, the Phase-3 `leases::fenced` closure MUST perform a **final**
   `Instant::now() < step.deadline && step.stop.borrow().is_none()` check **after**
   `storage::settle` and `runs::record_observation` complete their SQL statements and
   **immediately before** returning `Ok(...)` to commit. If `step.deadline` expired or
   `step.stop` fired either before settlement or during that SQL row-lock wait, the closure
   returns `Err(...)`, causing `leases::fenced` to roll back **both** the `artifact_revisions`
   row / `storage_accounts` and `storage_instance` quota charge and the observation (leaving
   `storage_reservations` in `state = 'reserved'` for `reconcile_run_spills`), and then applies
   the spill-abort disposition rule below. Otherwise, the transaction commits once: either
   **both** the settled revision charge and the terminal operation observation commit together,
   or neither commits (guaranteeing at most one active revision and one storage charge ever
   commit per operation — never allowing a crash between `storage::settle` and
   `runs::record_observation` to strand an active charged spill revision alongside an
   `outcome = 'intent'` `repeatable_read` that a replacement worker would replay and charge a
   second time). On replay of an already-`succeeded` operation, the adapter reads
   `(artifact_id, revision_id)` from the committed observation evidence (after live
   `Action::Read` and `active` rechecks) rather than re-running `publish_bytes`.

**Spill-abort disposition for completed known-outcome calls.** In `src/worker.rs` (`run_one`)
and `src/authz/leases.rs` (`leases::decide`), when **only** the shortened per-tool
`step.deadline` elapsed on a completed, known-outcome write (while `step.stop` is `None`, zero
unresolved writes remain, `cancel_reason IS NULL` and remaining execution budget exceeds one
lease interval), returning `StepResult::Stopped` causes `run_one` to call
`leases::settle(..., Settle::Stopped)`, which `leases::decide` rejects with
`StoreError::InvalidInput("settle")` and leaves the lease held until expiry. Meanwhile, in
`src/worker.rs` (`stop_point`), `worker::monitor` signals `Stop::LeaseLost` locally `margin`
before PostgreSQL `lease_expires_at <= clock_timestamp()`. Consequently, a completed call
entering the inline `truncated_no_spill` fallback (`Fence::Step` with initial `step.stop ==
None`, or `Fence::Hold` with `Stop::Shutdown | Stop::Cancel | Stop::Deadline`) can receive
`Stop::LeaseLost` while waiting on `SELECT ... FROM openmettle.runs ... FOR NO KEY UPDATE`
(`src/authz/leases.rs`, `leases::lock`) while PostgreSQL still considers the lease unexpired —
and a `Fence::Step` tool-deadline fallback can receive `Stop::Shutdown | Stop::Cancel |
Stop::Deadline` while waiting on the lock and must not return `StepResult::Continue`. Whenever
Phase 1, Phase 2 or Phase 3 aborts spill publication on a completed known-outcome write (or
completed read), the adapter MUST distinguish the abort cause and enforce lock/pre-commit
`step.stop` checks inside the fallback transaction:

- **Shortened local tool `step.deadline` only (`step.stop.borrow().is_none()` and DB
  `Fence::Step` lease still active):** attempt to commit the inline
  `storage: "truncated_no_spill"` observation under **`Fence::Step`**. If `*step.stop.borrow()`
  remains `None` through commit, return **`StepResult::Continue`** (never
  `StepResult::Stopped`) so the run continues cleanly with the known write result without
  losing its lease or failing `leases::decide`. If `*step.stop.borrow()` transitioned to
  `Some(Stop::Shutdown | Stop::Cancel | Stop::Deadline)` before commit (without `LeaseLost`),
  commit the known observation under the held run lock (or retry under `Fence::Hold` with the
  same lock/pre-commit `*step.stop.borrow()` checks if `Fence::Step` rejected with
  `LeaseError::Stopping(_)`) and return **`StepResult::Stopped`** rather than
  `StepResult::Continue`. If `*step.stop.borrow()` transitioned to `Some(Stop::LeaseLost)` or
  the fence rejected with `StaleClaim | Expired | Terminal`, roll back and return
  `StepResult::Invalidated`.
- **Run stopping (`step.stop.borrow()` is `Some(Stop::Shutdown | Stop::Cancel | Stop::Deadline)`
  or `Fence::Step` rejected with `LeaseError::Stopping(_)`):** commit the inline
  `storage: "truncated_no_spill"` observation under **`Fence::Hold`** if the lease is still
  held (rolling back and returning `StepResult::Invalidated` immediately without further DB
  writes if `*step.stop.borrow()` becomes `Some(Stop::LeaseLost)` before commit or `Fence::Hold`
  rejects with `StaleClaim | Expired | Terminal`) and return **`StepResult::Stopped`**, so
  `run_one` cleanly hands off on `Stop::Shutdown`, settles cancellation on `Stop::Cancel` /
  `cancel_reason IS NOT NULL`, or settles `DeadlineExceeded` on `Stop::Deadline`.
- **DB or local lease lost (`step.stop.borrow()` is `Some(Stop::LeaseLost)` or
  `LeaseError::StaleClaim`, `LeaseError::Expired` or `LeaseError::Terminal`):** return
  **`StepResult::Invalidated`** immediately without further PostgreSQL writes (mapped in PR2
  in `worker::execute` to `WorkEnd::Stop(Stop::LeaseLost)` so `run_one` exits without touching
  PostgreSQL).
- **Mandatory in-closure `*step.stop.borrow()` rechecks for inline `truncated_no_spill`
  fallbacks (`Fence::Step` and `Fence::Hold`).** Inside the inline `truncated_no_spill`
  fallback's `leases::fenced` closure (`src/authz/leases.rs`), the adapter MUST re-inspect
  `*step.stop.borrow()` **both immediately after `leases::lock` acquires the `openmettle.runs`
  row lock AND immediately after `runs::record_observation` completes right before returning
  `Ok(...)` to commit**:
  1. If `*step.stop.borrow() == Some(Stop::LeaseLost)` at either check, return `Err(...)` to
     **roll back** the transaction (leaving `openmettle.operations`, `openmettle.run_events`
     and `openmettle.runs.last_event_sequence` completely untouched) and return
     **`StepResult::Invalidated`**.
  2. If the fallback entered under `Fence::Step` (`step.stop` initially `None`) and
     `*step.stop.borrow()` transitioned to `Some(Stop::Shutdown | Stop::Cancel |
     Stop::Deadline)` before commit (without `Stop::LeaseLost`), commit the known observation
     under the held run lock (or retry under `Fence::Hold` with the same two checks if
     `Fence::Step` returned `LeaseError::Stopping(_)`) and return **`StepResult::Stopped`**
     rather than `StepResult::Continue`.

**Pre-terminal resolution of abandoned `repeatable_read` intents (preserving SSE `204`
cursors across mixed-version rolling upgrades).** `runs::record_observation` (`src/runs.rs`)
appends an event to `openmettle.run_events` and increments `runs.last_event_sequence`, while
`GET`/`HEAD /v1/runs/{run_id}/events` (`src/v1/runs.rs`) returns `204 No Content` only when
`first.terminal && position == first.last` (`tests/schema/run_events_http.rs`). Calling
`runs::record_observation` *after* a run is already terminal (for instance inside
`reconcile_run_spills`) would advance `runs.last_event_sequence` past the terminal `run-*`
event's sequence and break reconnecting SSE clients (`200` instead of `204 No Content`).
Meanwhile, `storage::release` (`src/storage.rs`) rightly refuses with `Error::Unresolved`
whenever the linked operation has `outcome IN ('intent', 'outcome_unknown')`, so an abandoned
`repeatable_read` that crashed at `outcome = 'intent'` (`revision = 0`) after reserving a spill
would strand reserved quota forever if left unresolved at termination.

Under [ADR 0003](0003-schema-migrations.md), old (`N-1`) and new (`N`) API and worker
processes coexist during a rolling upgrade after PR2's migration applies. Relying on PR2 Rust
hooks alone would leave two rolling-upgrade holes: an `N-1` worker running `approvals::park`
(`tests/schema/approvals.rs`) could still transition a `running` run carrying a revision-zero
`capability = 'repeatable_read'` `outcome = 'intent'` operation into `state = 'waiting'` after
the one-time migration repair completes, and an `N-1` maintenance worker running
`leases::settle_expired` (`src/authz/leases.rs`) could terminalize an expired PR2 (`N`) run
holding a `'reserved'` `tool-spill:*` `storage_reservations` row and an abandoned revision-zero
`repeatable_read` `intent` without resolving that `intent` — after which `storage::release`
(`src/storage.rs`) would return `Error::Unresolved` forever and strand the reserved spill quota.
Across all `UPDATE openmettle.runs` callers in `src/authz/approvals.rs`, `src/authz/leases.rs`
and `src/authz/runs.rs`, every single transition into `'waiting'` or terminal (`'succeeded'`,
`'failed'`, `'cancelled'`, `'interrupted'`) executes `UPDATE openmettle.runs SET state = ...`
in one SQL statement (never `RETURNING last_event_sequence`) and appends
`run-approval-requested`/`run-waiting` or `run-terminal` in a *subsequent* SQL statement.

PR2's next sequential SQL migration (with zero edits to frozen migrations) therefore enforces
abandoned-`repeatable_read` resolution **at the PostgreSQL database layer** via two
complementary mechanisms:

- **Mixed-version `AFTER UPDATE OF state ON openmettle.runs` `SECURITY DEFINER` trigger
  (`openmettle.resolve_abandoned_repeatable_reads()`).** Owned by `openmettle_owner`, defined
  with `SECURITY DEFINER` and `SET search_path = pg_catalog`, locked down with `REVOKE ALL FROM
  PUBLIC`, and audited in `src/boundaries.sql` (preserving `openmettle_api`'s zero `UPDATE`
  grant on `openmettle.operations`):
  - Trigger declaration: `AFTER UPDATE OF state ON openmettle.runs FOR EACH ROW WHEN (OLD.state
    IS DISTINCT FROM NEW.state AND OLD.state NOT IN ('succeeded', 'failed', 'cancelled',
    'interrupted') AND NEW.state IN ('waiting', 'succeeded', 'failed', 'cancelled',
    'interrupted'))`.
  - Firing order: fires at the end of `UPDATE openmettle.runs SET state = ...` (after the outer
    `openmettle.runs` tuple update completes and PostgreSQL increments the command counter —
    avoiding any SQLSTATE `27000` self-update conflict — and **strictly before** the caller's
    next SQL statement appends `run-approval-requested`/`run-waiting` or `run-terminal`).
  - Body: for each `openmettle.operations` row on `(NEW.scope_id, NEW.id)` with
    `capability = 'repeatable_read' AND outcome = 'intent' AND revision = 0 ORDER BY id`,
    transitions the row to `outcome = 'failed'`, `revision = 1` with non-empty redacted
    observation payload, increments `openmettle.runs.last_event_sequence` via
    `UPDATE openmettle.runs SET last_event_sequence = last_event_sequence + 1 WHERE scope_id =
    NEW.scope_id AND id = NEW.id` (which does not update `state` and never recurses), and
    inserts the idempotent `abandoned-read:<operation_id>` `openmettle.run_events` row with
    exact [ADR 0004](0004-run-persistence.md) `openmettle/observation/1\0` length-prefixed
    `identity` and SHA-256 `digest`.
  - Because the PostgreSQL trigger handles every `'waiting'` and terminal transition uniformly
    across both `N-1` and `N` worker and API binaries (`leases::settle`, `leases::handoff`,
    `leases::settle_expired`, `approvals::park`, `approvals::fail`, `approvals::decide`,
    `cancel_run`, `cancel_scope_runs`, `cancel_user_runs`, `recheck_run` and `expire_queued`),
    PR2 Rust callers need no duplicate ad-hoc SQL updates before
    `UPDATE openmettle.runs SET state = ...`.
- **One-time migration repair for pre-existing `queued`/`waiting` runs.** In the same PR2
  sequential SQL migration (running as `openmettle_owner`), repair any runs *already* in
  `state IN ('queued', 'waiting')` at migration time that have revision-zero (`revision = 0`)
  `capability = 'repeatable_read'` operations in `outcome = 'intent'` by transitioning those
  operations to `outcome = 'failed'` (`revision = 1`, with non-empty redacted observation
  evidence) and appending their `abandoned-read:<operation_id>` `run_events` rows — updating
  `runs.last_event_sequence` with exact [ADR 0004](0004-run-persistence.md)
  `openmettle/observation/1\0` length-prefixed `identity` and SHA-256 `digest` — **while the
  run is still `queued`/`waiting`**, strictly before any `run-terminal` event exists (pre-PR2
  terminal runs never created `tool-spill:*` reservations and are left untouched). Together,
  the one-time repair and the `AFTER UPDATE OF state` trigger guarantee that both pre-existing
  rows and all subsequent mixed-version (`N-1` and `N` worker + API) transitions uphold the
  exact same invariant: every `'waiting'` or terminal transition resolves abandoned
  revision-zero `repeatable_read` intents strictly before `run-waiting` / `run-terminal`,
  keeping `runs.last_event_sequence == terminal_sequence` (`204 No Content` on terminal SSE
  cursor reconnect) while preserving `openmettle_api`'s zero `UPDATE` grant on
  `openmettle.operations` in `src/boundaries.sql`.

Write operations (`idempotent`, `lookup` and `non_repeatable`) are **never** modified by the
trigger or the upgrade repair, so `storage::release` continues to protect every unresolved
write (including `outcome_unknown` writes on `interrupted` runs) with `Error::Unresolved`.

**Ledger-safe spill cleanup (`artifact_fs::reconcile_run_spills`).** Because
`artifact_fs::reconcile_expired` scans only upload reservations (`run_id IS NULL`) and
`run_id IS NOT NULL` matches all run-linked reservations (not only spills), PR2 adds
`artifact_fs::reconcile_run_spills` to the worker maintenance sweep with strict ledger safety
across both [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md) crash
windows, zero post-terminal `run_events` appends and zero DB transactions held across disk
unlinks:

- Scan adapter-owned spill reservations matching the `tool-spill:` `idempotency_key` prefix
  with `operation_id IS NOT NULL` across `state = 'reserved'` and `state = 'released'`. Never
  touch `state = 'settled'` rows during spill reconciliation; settled revisions are deleted
  only by `artifact_fs::purge_due` after retention expiry.
- **Spill reservation TTL/age guard against in-flight races.** `openmettle.storage_reservations`
  records `created_at` (`migrations/0004_artifacts_storage_accounting.sql`, with no
  `expires_at` column). Mirroring `artifact_fs::reconcile_expired`'s `older_than` threshold
  (`src/artifact_fs.rs`), `reconcile_run_spills` only sweeps a `state = 'reserved'`
  `tool-spill:*` row once `created_at + spill_reservation_ttl <= clock_timestamp()`, where
  `spill_reservation_ttl` strictly exceeds the maximum single-attempt spill I/O plus worker
  drain window. Combined with disjoint per-attempt `reservation_id`s, active Phase 2
  stage/rename work stays inside the TTL window and never races `reconcile_run_spills`; even
  if an extreme post-TTL stall finishes `rename` after `storage::release`, it cannot touch a
  replacement worker's distinct `reservation_id`, cannot settle a `released` row or pass
  `Fence::Step`, and its orphaned file is cleaned up on the next `state = 'released'` sweep.
- For each aged `state = 'reserved'` candidate, open a short lock-ordered DB transaction
  (`openmettle.runs` first via `FOR NO KEY UPDATE`, then `openmettle.storage_reservations` via
  `FOR UPDATE SKIP LOCKED`, with zero filesystem I/O inside the transaction), verify
  `created_at + spill_reservation_ttl <= clock_timestamp()` **and** that the publisher lease is
  inactive or superseded (the run is terminal, its lease has lapsed with
  `lease_expires_at IS NULL OR lease_expires_at <= clock_timestamp()`, or the linked operation
  is already resolved with `outcome IN ('succeeded', 'failed')`), and call `storage::release`
  without calling `runs::record_observation` or appending any `run_events`. Because every
  abandoned `repeatable_read` was already transitioned to `outcome = 'failed'` strictly before
  `run-terminal`, `storage::release` succeeds cleanly after TTL on terminal runs while
  preserving `runs.last_event_sequence == terminal_sequence` (`204 No Content` on terminal SSE
  cursor reconnect) and continuing to fail closed with `Error::Unresolved` on any unresolved
  `idempotent`, `lookup` or `non_repeatable` write.
- Commit the short DB transaction; then, outside the DB transaction, unlink **both**
  `<ARTIFACTS_DIR>/staging/<reservation_id>` and any unsettled
  `<ARTIFACTS_DIR>/revisions/<reservation_id>` file for that released `reservation_id` (a
  `released` reservation has no `artifact_revisions` row and is never visited by `purge_due`).
- For any `state = 'released'` spill candidate (covering crashes after `storage::release`
  committed and before unlink completed, as well as any late post-TTL rename from a stalled
  worker), retryably unlink any remaining orphaned `<ARTIFACTS_DIR>/staging/<reservation_id>`
  and unsettled `<ARTIFACTS_DIR>/revisions/<reservation_id>` files.

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

**Startup writability probe, opportunistic spill fallback and deferral of `spill_required`.**
Today, `artifact_fs::Store::open` (`src/artifact_fs.rs`, called via `src/lib.rs`) validates
only that `root` is an absolute, non-symlink, readable directory, creates `staging/` and
`revisions/` (mode `0700`) if absent, confirms both are real readable directories and `fsync`s
`root`; it does **not** test file creation or rename inside pre-existing `staging/` and
`revisions/` directories, so a read-only mount can pass `Store::open` and fail on the first
spill. PR2 therefore adds an explicit startup writability probe
(`artifact_fs::Store::probe_writable`), run during worker initialization whenever
`OPENMETTLE_WORKER_ARTIFACTS_DIR` is configured: exclusively create a uniquely named non-UUID
probe file (mode `0600`) in `staging/`, `fsync` it, rename it into `revisions/`, `fsync`
`revisions/`, unlink the probe file and `fsync` `revisions/` (cleaning up on error), failing
closed at boot if the mount or either directory is unwritable. Leaving
`OPENMETTLE_WORKER_ARTIFACTS_DIR` unset (`None`) still boots the worker in non-spill mode. All
V1-14 spills are **post-response opportunistic spills**; strict `spill_required` pre-reserved
write tools are explicitly deferred out of V1-14 because `Review::validate`
(`src/authz/approvals.rs`) requires an existing authorized `Review.artifact` whenever
`Review.reservation` is set, whereas a newly spilled tool output has neither an `operation_id`
nor a known byte length before intent commit and dispatch.

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
| PR2 | PR2's next sequential schema migration (e.g., `0024`) adding `openmettle.operations.dispatched_attempts`, its matching `src/boundaries.sql` grant (`$1 >= <v1_14_schema_version>`), the `AFTER UPDATE OF state ON openmettle.runs FOR EACH ROW` `SECURITY DEFINER` trigger `openmettle.resolve_abandoned_repeatable_reads()` (owned by `openmettle_owner`, `SET search_path = pg_catalog`, `REVOKE ALL FROM PUBLIC`, audited in `src/boundaries.sql`, preserving `openmettle_api`'s zero `UPDATE` grant on `openmettle.operations`, resolving abandoned revision-zero `capability = 'repeatable_read'` `outcome = 'intent'` rows to `outcome = 'failed'`, `revision = 1` with idempotent `abandoned-read:<operation_id>` ADR 0004 `identity`/`digest` observation `run_events` strictly before `run-waiting` / `run-terminal` uniformly across mixed-version `N-1` and `N` worker/API binaries without duplicate Rust-caller SQL updates) and one-time upgrade repair (as `openmettle_owner`) of pre-existing `state IN ('queued', 'waiting')` runs, `StepResult::Invalidated` and its `worker::execute` (`src/worker.rs`) mapping to `WorkEnd::Stop(Stop::LeaseLost)`, reviewed tool registry (`EffectPolicy`) rejecting `x-mcp-header` schemas, strict schema/argument validator and default expander, `approvals::start_replayed_read` with durable 3-attempt cap, internal `artifact.read_range` v1 tool, `artifact_fs::Store::probe_writable`, three-phase `artifact_fs::publish_bytes` (no DB txn across disk I/O; per-attempt unique `reservation_id`; racing Phase 2's `spawn_blocking` `JoinHandle` in `tokio::select!` against `tokio::time::sleep_until(step.deadline)` and `step.stop.changed()` via shared `Arc<AtomicBool>` (`cancelled`), detaching on cutoff while keeping `<reservation_id>` in `state = 'reserved'` and immediately running the inline `truncated_no_spill` fallback during the drain window, with detached late-completion unlinking of `staging/<reservation_id>` and unsettled `revisions/<reservation_id>` when `cancelled == true`; local `step.deadline`/`step.stop` rechecks after normal Phase 2 completion, under the Phase 3 `Fence::Step` lock before settling and again inside the Phase 3 closure after `storage::settle` + `runs::record_observation` complete their SQL statements immediately before commit, rolling back on cutoff; single atomic `Fence::Step` commit of `storage::settle` + `runs::record_observation`; spill-abort disposition committing inline `truncated_no_spill` under `Fence::Step` + `StepResult::Continue` when only shortened `step.deadline` elapsed and `step.stop` remains `None`, under `Fence::Hold` + `StepResult::Stopped` when `step.stop` is `Some(Stop::Shutdown | Stop::Cancel | Stop::Deadline)` or `LeaseError::Stopping(_)`, and returning `StepResult::Invalidated` on `Stop::LeaseLost` / `StaleClaim | Expired | Terminal`, with mandatory `*step.stop.borrow()` rechecks inside the fallback's `leases::fenced` closure both immediately after `leases::lock` acquires the `runs` row lock and immediately after `runs::record_observation` completes right before commit), `reconcile_run_spills` (zero post-terminal `run_events`) and serialized-budget head/tail preview builder. | PostgreSQL 18 tests: cross-user, cross-scope, archived/deleted project, private project-scope spill ownership (other members denied until shared), share revocation and `active` -> `retained` transition between original read and replay, and non-`active` revision refusals; `max_bytes < 4` validation refusal, invalid UTF-8 binary semantic fault and strictly inline `artifact.read_range` under both 6x JSON escaping and `<= 200`-line `next_offset` pagination; unfinished `repeatable_read` replay through `approvals::start_replayed_read` (rechecking bound session and canonical proposal without issuing a write permit) plus crash-reclaim test at `dispatched_attempts == 3` proving dispatch refusal, terminal `failed` observation under `Fence::Step` and zero outbound sends; catalog registration rejection of `x-mcp-header` schemas plus duplicate-key, float, depth, bound and wildcard rejections; serialized-JSON `16 KiB` inline/spill thresholds (`\u001b` expansion, `200` lines, multi-byte UTF-8 cuts); startup `Store::probe_writable` fail-closed test on pre-existing read-only `staging/` and `revisions/`; unset-`ARTIFACTS_DIR`, unconfigured-store, quota-refused and I/O fallback envelopes; Phase 3 rollback/crash simulation verifying `storage::settle` and `runs::record_observation` commit atomically inside one `Fence::Step` transaction so at most one active revision and one storage quota charge ever commit per operation (zero double-charged spill revisions on replacement-worker replay); `publish_bytes` Phase 2/3 stall, lock-wait, barrier-race and takeover tests covering (a) delaying Phase 2 `spawn_blocking` disk I/O past **both** the `5 s` PostgreSQL `idle_in_transaction_session_timeout` and the worker drain deadline during lease takeover (proving replacement worker settlement succeeds intact with its own disjoint `reservation_id` and the stalled old worker returns `StepResult::Invalidated` with zero corrupted/unlinked revisions and zero leaked settled quota), (b) **stalling Phase 2's `fsync` on a barrier and triggering `Stop::Shutdown` (and shortened `step.deadline`)** (proving the adapter races out of `tokio::select!` within the drain window to commit inline `truncated_no_spill` and return the expected `StepResult`, then unblocking the barrier so late disk completion finishes, running `reconcile_run_spills`, and verifying both filesystem cleanliness — `staging/` and `revisions/` empty for `<reservation_id>` — and exact zero `storage_accounts` / `storage_reservations` quota drift), (c) local `step.deadline` expiry and `step.stop` firing while the DB lease is still live — including both pre-settlement cutoff and **holding the `storage_accounts` row lock across the local cutoff while the DB lease stays live** (proving Phase 3's final pre-commit check returns `Err` and rolls back both the `artifact_revisions` row and the `storage_accounts`/`storage_instance` quota charge, leaving `storage_reservations` in `state = 'reserved'`) — and asserting the exact resulting run and lease state alongside quota assertions: when only shortened `step.deadline` elapsed (`step.stop` stays `None`) on a completed known-outcome write with active `Fence::Step` lease, inline `truncated_no_spill` commits under `Fence::Step`, returns `StepResult::Continue` and leaves the run `running` with its active lease intact (zero `StoreError::InvalidInput("settle")` from `leases::decide`); when `step.stop` is `Some(Stop::Shutdown | Stop::Cancel | Stop::Deadline)` or `LeaseError::Stopping(_)`, inline `truncated_no_spill` commits under `Fence::Hold`, returns `StepResult::Stopped` and `run_one` hands off or settles cleanly; when the DB lease is lost (`StaleClaim | Expired | Terminal` or `Stop::LeaseLost`), `StepResult::Invalidated` -> `WorkEnd::Stop(Stop::LeaseLost)` exits with zero further PostgreSQL writes, and (d) **blocking the inline `truncated_no_spill` fallback on a competing `FOR NO KEY UPDATE` lock on `openmettle.runs` while signaling `Stop::LeaseLost` locally with PostgreSQL `lease_expires_at` still in the future (inside `worker::monitor`'s safety margin)**, then releasing the competing lock and verifying the fallback rolls back with `StepResult::Invalidated` leaving `operations`, `run_events` and `runs.last_event_sequence` completely untouched (plus verifying a `Fence::Step` tool-deadline fallback that receives `Stop::Shutdown | Stop::Cancel | Stop::Deadline` while waiting on the lock commits under the held run lock and returns `StepResult::Stopped` rather than `StepResult::Continue`); crashed `repeatable_read` (`outcome = 'intent'`) + terminal settlement (`leases::settle`, `leases::settle_expired` and `approvals::park` -> immediate terminal `cancel_run`) + `reconcile_run_spills` freeing spill quota with zero stranded bytes and zero post-terminal `run_events`, plus a **populated-upgrade PostgreSQL 18 test** creating a pre-upgrade `waiting` run with a revision-zero `repeatable_read` `intent` and linked `tool-spill:*` reservation, running PR2's migration, immediately cancelling the run via `openmettle_api` (`cancel_run`), running `reconcile_run_spills`, and verifying zero stranded quota AND `204 No Content` on `GET`/`HEAD /v1/runs/{run_id}/events?after=<terminal_cursor>`, AND **mixed-version rolling-upgrade PostgreSQL 18 tests** verifying **(i)** after PR2's migration applies, executing pre-PR2 (`N-1`) `approvals::park` on a `running` run carrying a revision-zero `repeatable_read` `intent`, followed by API cancel/deny, resolves the intent before `run-waiting` and returns `204 No Content` on `GET`/`HEAD /v1/runs/{run_id}/events?after=<terminal_cursor>` and **(ii)** executing pre-PR2 (`N-1`) `leases::settle_expired` on an expired PR2 (`N`) run holding a `'reserved'` `tool-spill:*` `storage_reservations` row and an abandoned `repeatable_read` `intent`, then running `reconcile_run_spills`, succeeds in `storage::release` with zero stranded quota and returns `204 No Content` on the terminal SSE cursor, while preserving `storage::release` `Error::Unresolved` protection for `interrupted` runs with `outcome_unknown` writes, spill TTL/age guard against active publishers, post-release/pre-unlink and post-TTL late-rename retryable cleanup of `released` rows, post-rename/pre-settlement cleanup of unsettled `revisions/<id>` and untouched `settled` rows. |
| PR3 | Streamable HTTP MCP (`2026-07-28`) adapter over `provider_http::transport` (rejecting `x-mcp-header` schemas on `tools/list`), `MCP_DNS_SLOTS`, `McpCredentialProvider` seam, `ApprovedAdapter` implementation stopping `outcome_unknown` writes via `StepResult::Stopped` and reusing PR2's `StepResult::Invalidated` -> `WorkEnd::Stop(Stop::LeaseLost)` mapping for deposed workers, destination-authorized read-only `Executor::reconcile` under `Fence::Hold`, and `PLAN-10` / `PLAN-22` conformance harness on synthetic `rcgen` TLS + PostgreSQL 18. | Synthetic TLS + PostgreSQL 18 tests: MCP `2026-07-28` request headers (`MCP-Protocol-Version: 2026-07-28`, `Mcp-Method`, `Mcp-Name`, no `Mcp-Session-Id`, no `Mcp-Param-*`) **and** body `params._meta` (`io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities = {}`) over `application/json` and `text/event-stream` (SSE comments and progress notifications before final response, mismatched JSON-RPC IDs, duplicate final responses, `input_required` and unexpected server-initiated request rejection, upstream `tools/list` `x-mcp-header` schema rejection before tool offer or call admission, `4 MiB` aggregate stream ceiling before buffering); bounded retries with durable `dispatched_attempts < 3` increments under `Fence::Step` and identical persisted `Idempotency-Key` on `repeatable_read`/`idempotent` plus proven-pre-send retries on `lookup`/`non_repeatable`, enforcing `step.stop`, `step.deadline` (including `EndpointKey::Supported.expires_us`), crash-reclaim at `dispatched_attempts == 3` with zero outbound HTTP sends, and full ADR 0035 effect-level + bound-session/generation revocation checks before every retry across all classes; sticky whole-operation send uncertainty (`outcome_unknown` preserved when a retry fails pre-send or receives `401`/`403`/deadline after ambiguous attempt 1) and immediate halt via `StepResult::Stopped` into `ExecState::Reconciling` / `interrupted` on every uncertain write (`lookup`, `non_repeatable`, or exhausted/window-expired `idempotent`), proving no further model round runs and a fresh-`logical_key` proposal cannot be admitted and produces **zero** additional outbound sends (while known-outcome non-retryable failures return `retryable_by_model: false`); deposed-worker lease takeover matrix between a possible write send and `runs::record_observation` explicitly covering both **(a)** an expired or replaced lease on a non-terminal run (`Fence::Hold` rejecting with `LeaseError::Expired` or `LeaseError::StaleClaim`, verifying the deposed worker returns `StepResult::Invalidated` immediately without touching PostgreSQL, leaves the durable `outcome = 'intent'` write row intact, and the replacement worker reclaims the run via `leases::reclaim_next` and routes the durable `intent` write straight into `ExecState::Reconciling` or terminal settlement with **zero** model steps and **zero** duplicate outbound sends) and **(b)** an already-terminal run (`Fence::Hold` rejecting with `LeaseError::Terminal`, verifying the deposed worker returns `StepResult::Invalidated` immediately without touching PostgreSQL, no replacement worker claims the run, and **zero** further DB writes or outbound sends occur); `lookup` reconciliation with and without `downstream_handle` passing `&ActiveRun`/`&Lease<'_>` into `Executor::reconcile`, enforcing both `recheck_decision` and the live destination-specific MCP server/connection/account authorization check under `Fence::Hold` in `ExecState::Reconciling` before `McpCredentialProvider` lookup (asserting **zero** `McpCredentialProvider` lookups and terminal `interrupted` settlement when destination/account access is revoked or disabled), and verifying `repeatable_read` exclusion from `Executor::reconcile`; semantic `isError: true` / `-32602` plus `PLAN-10` valid-schema wrong/stale-fact semantic recovery; internal-MCP identity-boundary check authenticating caller/scope via primary PostgreSQL authority rather than compiled bypass; `PLAN-22` fixed native vs internal-MCP vs remote-MCP route measurement harness hook; SSRF/TLS/redirect/`401`/`403`/`tools/list`-drift/`> 4 MiB` refusals; canary redaction checks across errors, stderr, traces and metrics; end-to-end `park` -> `decide` -> resume -> `ApprovedAdapter::send` -> spill -> `artifact.read_range` round trip including share-revocation and retention replay refusals. |

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
