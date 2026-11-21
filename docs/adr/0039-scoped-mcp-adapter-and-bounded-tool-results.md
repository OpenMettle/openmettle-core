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
| [ADR 0010](0010-provider-http-transport.md) and [ADR 0038](0038-sglang-and-external-provider-conformance-adapter.md), `src/provider_http/transport.rs` | Add a Streamable HTTP JSON-RPC 2.0 MCP (`2026-07-28`) client over `provider_http::transport` with a dedicated DNS slot semaphore, strict header allowlist (restricted stateless interoperability profile omitting `Mcp-Param-*` and failing closed on `x-mcp-header` schemas) and `MAX_TOOL_RESPONSE_BODY_BYTES = 4 MiB` (`4_194_304` decoded HTTP body bytes via `http_body_util::Limited` alongside fixed `8 KiB` / `32` header bounds and chunked-trailer rejection). |
| [ADR 0027](0027-authorization-and-private-projects.md) and [ADR 0035](0035-approvals-permitted-yolo-and-effect-ledger.md), `src/authz/approvals.rs` | Implement `EffectPolicy` in the reviewed tool registry, bind every invocation to `Proposal`, `Destination`, `EffectClass`, `EndpointKey` and `record_fenced_intent`, add `approvals::recheck_replay_effect_authority` (executing `authorized(c, &proof, &review)` under `Fence::Step` against bound `originating_session_id`/`deciding_session_id` and provider/approval/user generations in addition to `Action::Read` and `revision.state == "active"` before replaying any `succeeded`/`failed` artifact-backed result or `artifact.read_range` bytes, including during committed-observation recovery), add PR2's next sequential schema migration (e.g., `0024`) for nullable durable pre-dispatch attempt accounting (`openmettle.operations.dispatched_attempts integer DEFAULT NULL CHECK (dispatched_attempts BETWEEN 0 AND 3)` with a monotonicity trigger forbidding `non-null -> NULL` or decrements, executed across **two separate `Fence::Step` PostgreSQL transactions**: Transaction 1 in Step 1 `record_fenced_intent` committing `outcome = 'intent'` with `dispatched_attempts = 0` for `repeatable_read` in PR2 and for write classes `idempotent`/`lookup`/`non_repeatable` in PR3 (`N`) so pre-upgrade and `N-1` rows remain `NULL` and are treated conservatively like `>= 1`, and Transaction 2 in Step 5 separately locking `runs`/`operations` (`FOR UPDATE`) and committing `0 -> 1 -> 2 -> 3` before every outbound HTTP send), upgrade repair of pre-existing `queued`/`waiting` revision-zero `repeatable_read` intents and an `AFTER UPDATE OF state ON openmettle.runs` `SECURITY DEFINER` trigger (`openmettle.resolve_abandoned_repeatable_reads()`), and add PR3's sequential SQL migration installing/extending an `AFTER UPDATE OF state ON openmettle.runs` `SECURITY DEFINER` trigger (`openmettle.resolve_interrupted_write_intents()`, `NEW.state = 'interrupted'`) unconditionally transitioning all remaining revision-zero write intents to `outcome = 'outcome_unknown'`, `revision = 1` strictly before `run-terminal` to preserve exact `{"unresolved": n}` event/ledger parity across mixed-version `N-1`/`N` workers. |
| [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md), `src/worker.rs` | Implement `ApprovedAdapter` for resumed writes, reuse the same committed-envelope dispatch for immediate reads and permitted YOLO writes, stop `outcome_unknown` writes into `ExecState::Reconciling` (adding `StepResult::Invalidated` -> `WorkEnd::Stop(Stop::LeaseLost)` in PR2 to halt deposed workers on lease loss), rely on PR2's and PR3's database triggers to resolve abandoned `repeatable_read` intents (pre-`waiting`/pre-terminal) and remaining revision-zero write intents (unconditionally to `outcome_unknown` pre-`interrupted` `run-terminal`, preserving `{"unresolved": n}` parity across mixed-version `N-1`/`N` workers), evaluate `Settle::Succeeded` unconditionally against `n_raw` in PR3 `leases::settle_locked` (preserving `Err(StoreError::Conflict("unresolved operation"))` -> `Settle::Stopped` fallback when `state == ExecState::Running` and `n_raw >= 1`, whereas `ExecState::Reconciling` returns `Err(StoreError::InvalidInput("settle"))` regardless of `n_raw`) while for `input != Settle::Succeeded` pre-resolving proven-unsent non-null `dispatched_attempts = 0` write intents (`n_zero`) to `outcome = 'failed'` (`revision = 1`) and passing `n_after = n_raw - n_zero` to `decide` **iff** `state == ExecState::Reconciling \|\| !time \|\| (n_after == 0 && (cancel.is_some() \|\| matches!(input, Settle::Failed(_))))` (so both uncancelled `Running && cancel.is_none() && Settle::Stopped && time` and mixed-write `n_zero >= 1 && n_after >= 1 && time` enter `ExecState::Reconciling(n_raw)` without pre-resolution) and pre-resolving `dispatched_attempts = 0` write intents in PR3 `leases::settle_expired` before the `unresolved` CTE counts `u.n`, define deterministic recovery across `run_one` drain-window expiry (`WorkEnd::Incomplete`) for both unacknowledged commits (keyed committed-observation reuse gated by `approvals::recheck_replay_effect_authority`, `Action::Read`, and `revision.state == "active"` whenever backed by an artifact) and uncommitted `'intent'` observations (including `outcome_unknown` -> `interrupted` for dispatched or legacy `dispatched_attempts IS NULL` writes without a downstream read-only lookup, even when direct terminal settlement bypasses `Executor::reconcile`), and implement destination-authorized read-only `Executor::reconcile` reading `dispatched_attempts: Option<i32>` on `UnresolvedOperation`. |
| [ADR 0005](0005-artifact-storage-accounting.md) and [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md), `src/storage.rs` and `src/artifact_fs.rs` | Add PR2's `openmettle.storage_reservations.spill_reclaiming boolean NOT NULL DEFAULT false` cleanup-claim column (`CHECK (NOT spill_reclaiming OR state IN ('reserved', 'released'))`), update `Store::stage` (`src/artifact_fs.rs`) so HTTP uploads also open `staging/<id>` read-write with `create_new(true).mode(0o600)` and hold `File::try_lock_shared()` while streaming, add three-phase lease-fenced direct byte publication (`artifact_fs::publish_bytes`, gated by a process-wide `Arc<tokio::sync::Semaphore>` `spill_permits` bounded to `max_concurrent_runs`, pre-creating the single 0-byte payload file `staging/<reservation_id>` with a `ring::rand::SystemRandom`-backed RFC 9562 UUIDv4 via safe Rust 1.100 `fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600)` + `File::try_lock_shared()` + `sync_dir(&store.staging)` before Phase 1 `storage::reserve` with primary-DB `runs ... FOR NO KEY UPDATE` serialization on ambiguous Phase-1 commit ack, moving that single `LOCK_SH`-held `payload_file` and `OwnedSemaphorePermit` directly into Phase 2 `spawn_blocking` with chunked `<= 64 KiB` cancellation checks and holding `LOCK_SH` across `fs::rename` + `sync_dir` without any `.lock` sidecar — where cutoff before the final pre-rename check skips `fs::rename` while cutoff racing during `fs::rename` or post-rename `sync_dir` leaves the `LOCK_SH`-held inode at `revisions/<reservation_id>` with zero `fs::remove_file` and Phase 3 unconditionally disabled — never holding a DB transaction across disk I/O, racing Phase 2's `spawn_blocking` disk join against `step.deadline` and `step.stop.changed()`, local `step.deadline`/`step.stop` rechecks before Phase 3 settlement and immediately before commit, Phase 3 preserving `storage::settle`'s existing `ReservationState::Settled` idempotent metadata-matching replay branch (`src/storage.rs:362-379`) while enforcing `AND NOT spill_reclaiming` strictly on its `ReservationState::Reserved` settlement branch inside a single atomic `Fence::Step` `storage::settle` + `runs::record_observation` transaction, and rechecking `step.stop` under the `runs` lock and immediately before commit in inline `truncated_no_spill` fallbacks), startup writability probing (`Store::probe_writable`) and 3-step DB-claimed single-inode spill cleanup (`artifact_fs::reconcile_run_spills`, claiming `spill_reclaiming = true` before any unlink, requiring **each** of `staging/<id>` and `revisions/<id>` to finish Step 2 in a confirmed-clean outcome — either confirmed `ErrorKind::NotFound` on `symlink_metadata`/`open` OR confirmed `LOCK_EX` post-lock `(dev, ino)` match + `probe_file.set_len(0)` `Ok(())` + `fs::remove_file` `Ok(())` — and aborting without `sync_dir` or Step 3 `storage::release` on any `WouldBlock`, I/O error, non-regular file or inconclusive/mismatched post-lock `(dev, ino)` check before unconditionally `sync_dir`ing both `staging/` and `revisions/` and committing `storage::release`, plus an aged `> 900 s` orphan `staging/` sweep that acquires `File::try_lock()` *before* primary PostgreSQL recheck, serializes any zero-row observation against committing Phase 1 via `SELECT 1 FROM openmettle.storage_instance WHERE id FOR UPDATE` before re-querying `storage_reservations`, always skips `state = 'reserved'`, and on `state = 'settled'` reclaims only a proven-distinct stranded HTTP-upload retry inode still at `staging/<id>` whose `(dev, ino)` differs from `revisions/<id>` while leaving published `revisions/<id>` untouched), paired with a strictly inline read-only `artifact.read_range` tool and shared-volume read-write advisory `flock` qualification alongside ADR 0031. |

**Zero new Cargo crates.** V1-14 reuses the locked `hyper`, `hyper-util`, `http-body-util`,
`rustls`, `tokio-rustls`, `serde`, `serde_json`, `sha2`, `bytes`, `httpdate` and `ring` stack
rather than adding `rmcp` or another unreviewed MCP SDK crate. All filesystem locking,
metadata/inode verification, truncation, rename, removal and directory sync use stable safe
Rust 1.100 `std::fs` and `std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, MetadataExt}`
under `Cargo.toml`'s `unsafe_code = "forbid"` (matching `src/artifact_fs.rs`, with no
`rustix`/`nix` crate and no unstable `std::fs::Dir`). Adopting an external MCP SDK later
requires a separate dependency and V1-42 distribution gate.

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

Before reading or replaying any byte (on initial execution, `IntentResult::Replayed(op_id)`,
or committed-observation / unacknowledged-commit recovery), the handler executes a fenced
primary authority check (`approvals::recheck_replay_effect_authority` invoking
`authorized(c, &proof, &review)` under `Fence::Step` against the run's bound
`originating_session_id` / recorded `deciding_session_id` and provider/approval/user
generations, rather than relying on `authz::runs::recheck_leased` or `record_fenced_intent`'s
existing-intent replay branch alone) in addition to continuation authority
(`tools.artifact.read` capability), hydrates the worker principal via
`authz::store::hydrate_worker_principal`, loads the revision via `storage::read_revision`,
confirms `revision.scope_id == run.scope_id`, checks
`authorize_resource(principal, resource, Action::Read)` on the artifact and requires
`revision.state == "active"` — refusing replay and returning **zero** cached bytes
(`IntentResult::Invalidated` / `ToolFault::TerminalRefusal`) if the bound session logged out or
effect authority was revoked even while `Action::Read` access and `revision.state == "active"`
remain valid. Leaving `Review.artifact` as `None` for reads avoids requiring
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
to live ADR 0035 bound-session and effect authority (`approvals::recheck_replay_effect_authority`),
`Action::Read` and `active` revision checks.

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
  fail closed under OpenMettle v1's restricted stateless interoperability profile (omitting
  `Mcp-Param-*` rather than invoking an `x-mcp-header` tool with missing headers) before the
  tool is offered to the model or any call is admitted.
- **Scope exclusions and deferrals (#14).** Selective tool discovery and deferred MCP tool
  definitions (`PLAN-21`) are explicitly deferred out of V1-14 scope; every offered tool for a
  run is pinned at admission. Bounded independent tool fan-out research (`PLAN-19`) remains
  conditional research outside V1-14 implementation; V1-14 executes validated calls within the
  run's existing round budget without adding a fan-out scheduler.

## Reviewed tool contracts and ADR 0035 integration

### Schema validation and argument bounds

Every tool contract in the registry declares an immutable closed JSON input schema and default
values. While full MCP `2026-07-28` Streamable HTTP requires general-purpose clients to mirror
`x-mcp-header`-annotated parameters into outbound `Mcp-Param-*` HTTP headers, OpenMettle v1
intentionally defines a **restricted stateless interoperability profile** that omits
`Mcp-Param-*` from its fixed outbound header allowlist and fails closed on any reviewed tool
registration or upstream `tools/list` schema containing `x-mcp-header` during both catalog
validation and runtime `tools/list` schema verification before offering the tool to the model
or admitting calls (never invoking an `x-mcp-header` tool with missing headers, at the explicit
trade-off of rejecting `x-mcp-header`-dependent MCP tools). Before calling `Proposal::new`, the
adapter validates raw model arguments in this order:

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

**Durable pre-dispatch attempt accounting (nullable `DEFAULT NULL`, monotonic `0..=3`).**
`openmettle.operations` (`migrations/0003_runs_events_operations.sql`) currently has no attempt
counter column, so in-memory attempt tracking would let a worker crash after attempt 3 before
`record_observation` and allow a reclaiming worker to dispatch three more attempts on a
`repeatable_read` replay. Crucially, on `main` (`src/worker.rs:533-546`), the base (`N-1`)
worker can already invoke `ApprovedAdapter::send` without maintaining `dispatched_attempts`;
declaring the column `NOT NULL DEFAULT 0` would stamp existing pre-upgrade rows and `N-1`
rolling-upgrade rows with `0`, causing an `N` reconciler or settlement path to falsely record
`outcome = 'failed'` (proven unsent) on a write that was actually sent. PR2's next sequential
schema migration (e.g., `0024`, avoiding collision with sibling migrations landing on `main`
first) therefore introduces **`dispatched_attempts integer DEFAULT NULL CHECK
(dispatched_attempts BETWEEN 0 AND 3)`** on `openmettle.operations`, installs a
`BEFORE UPDATE ON openmettle.operations` monotonicity trigger forbidding `non-null -> NULL`
transitions or decrements (`OLD.dispatched_attempts IS NOT NULL AND (NEW.dispatched_attempts IS
NULL OR NEW.dispatched_attempts < OLD.dispatched_attempts)`), grants `INSERT
(dispatched_attempts)` and `UPDATE (dispatched_attempts)` to `openmettle_worker` and adds the
matching `$1 >= <v1_14_schema_version>` column entries to `src/boundaries.sql`. Pre-upgrade
rows and rows inserted by `N-1` workers during rolling upgrade have **`dispatched_attempts IS
NULL`** (legacy writer without enforced attempt accounting -> send status unknown, treated
conservatively like `>= 1`). Attempt accounting executes across **two separate `Fence::Step`
PostgreSQL transactions**:

- **Transaction 1 (Step 1 — `approvals::record_fenced_intent`):** commits the durable
  `outcome = 'intent'` row with **`dispatched_attempts = 0`** (for `repeatable_read` in PR2 —
  leaving write intents at `DEFAULT NULL` until PR3 — and for write capabilities `idempotent`,
  `lookup` and `non_repeatable` in PR3 (`N`)) before returning
  `IntentResult::Applied(committed)` (or parking for human approval), so a worker crash before
  Step 5 leaves a durably committed `dispatched_attempts = 0` row proving zero outbound sends
  occurred.
- **Transaction 2 (Step 5 — separate pre-send `Fence::Step` transaction before attempt 1, and
  before each permitted retry `1 -> 2 -> 3`):** locks `openmettle.runs` (`FOR NO KEY UPDATE`)
  and `openmettle.operations` (`FOR UPDATE`), verifies `coalesce(dispatched_attempts, 1) < 3`
  (counting any legacy `NULL` row conservatively as `1`), enforces live ADR 0035 effect-level
  and bound-session authority, and commits the monotonic increment (`0 -> 1`, `1 -> 2`,
  `2 -> 3`) under the monotonicity trigger **before** releasing the PostgreSQL connection and
  issuing the outbound HTTP request.

Per-call execution uses one fenced sequence in `openmettle-worker`:

1. Call `authz::runs::recheck_leased` with the step's tool capability (which evaluates
   `authorize_run_continuation` on the primary) and execute **Transaction 1**
   (`approvals::record_fenced_intent`, which enforces ADR 0035 effect-level and bound-session
   authority under `Fence::Step` on new intents and commits the durable `outcome = 'intent'`
   row with `dispatched_attempts = 0` — for `repeatable_read` in PR2 and for write classes
   `idempotent`, `lookup` and `non_repeatable` in PR3 — before returning
   `IntentResult::Applied(committed)` or parking).
2. On `IntentResult::ApprovalRequired`, drain `StepContext::tasks`, call `approvals::park` and
   stop the step so the API can collect the human decision.
3. On `IntentResult::Replayed(op_id)`, do **not** resend a write (`IntentResult::Replayed`
   returns only `operation_id`, never a one-use `CommittedIntent` write permit). Inspect the
   existing `operations` row:
   - If `succeeded` or `failed`, never blindly replay cached bytes or previews after source
     access or bound-session authority is lost. Because `authz::runs::recheck_leased`
     (`src/authz/runs.rs:402-431`) intentionally ignores `originating_session_id` and
     `approvals::record_fenced_intent`'s existing-intent branch
     (`src/authz/approvals.rs:1291-1337`) reconstructs the stored binding and returns
     `IntentResult::Replayed(op)` without re-running `authorized(c, &proof, &review)`,
     checking only artifact `Action::Read` and `revision.state == "active"` would allow cached
     `artifact.read_range` or spilled-artifact bytes to be replayed after the bound session
     logged out. Therefore, before returning or replaying any cached bytes or artifact-backed
     result (`artifact.read_range` or any `succeeded`/`failed` observation backed by a source
     or spilled artifact — both here on `IntentResult::Replayed(op_id)` and during
     committed-observation / unacknowledged-commit recovery), the worker MUST execute a fenced
     primary authority check (**`approvals::recheck_replay_effect_authority`** invoking
     `authorized(c, &proof, &review)` under `Fence::Step` against the run's bound
     `originating_session_id` / recorded `deciding_session_id` and provider/approval/user
     generations) **in addition to** `hydrate_worker_principal`, `revision.scope_id ==
     run.scope_id`, `authorize_resource(..., Action::Read)`, and `revision.state == "active"`
     — refusing replay and returning **zero** cached bytes (`IntentResult::Invalidated` /
     `ToolFault::TerminalRefusal`) if the bound session logged out or effect authority was
     revoked even while artifact `Action::Read` access and `revision.state == "active"` remain
     valid.
   - If `intent` or `outcome_unknown`, unresolved writes (`idempotent`, `lookup`,
     `non_repeatable`) defer to ADR 0033 and ADR 0035 reconciliation. Unfinished
     `repeatable_read` operations (`outcome = 'intent'`, where an earlier attempt recorded an
     intent and crashed before recording a terminal observation) are excluded from
     `leases::unresolved_operations` and never enter `Executor::reconcile`. Instead, PR2 adds a
     dedicated fenced read-revalidation helper (`approvals::start_replayed_read` under
     `Fence::Step`) that rechecks live ADR 0035 effect and bound-session authority on the
     primary, verifies the operation is `capability = 'repeatable_read'` with
     `outcome = 'intent'` and matches the requested canonical `Proposal`, checks
     `coalesce(dispatched_attempts, 1) < 3` and atomically sets
     `dispatched_attempts = coalesce(dispatched_attempts, 1) + 1` (conservatively counting any
     legacy `NULL` row as already having `1` unknown attempt), and returns
     `(operation_id, committed_request_bytes, bounded_deadline)` **without** issuing a
     `CommittedIntent` write permit so the adapter can dispatch the committed read bounded by
     `step.deadline.min(bounded_deadline)`. When `dispatched_attempts == 3`,
     `approvals::start_replayed_read` refuses dispatch without incrementing, records a terminal
     `failed` observation (`outcome = 'failed'` with non-empty redacted evidence) under
     `Fence::Step` and performs **zero** outbound HTTP sends.
4. On `IntentResult::Invalidated(_)`, stop immediately; the fenced check already settled the
   run.
5. On `IntentResult::Applied(committed)`, release the PostgreSQL connection from Transaction 1
   before any I/O and consume the one-use send permit `committed.start(&step)` once before
   attempt 1, applying the returned shortened `deadline` to `step.deadline`. If `start` returns
   `None`, issue no outbound call and leave the `intent` for settlement or reconciliation. On
   resumed human approvals, `worker::execute` (`src/worker.rs`) has already consumed
   `intent.start(&step)` and passes `ApprovedAdapter::send` the committed request bytes and
   shortened `step.deadline`. Before issuing attempt 1 — and in a fresh **Transaction 2**
   before each permitted retry (`1 -> 2 -> 3`) — execute a **separate** short `Fence::Step`
   PostgreSQL transaction that locks `openmettle.runs` (`FOR NO KEY UPDATE`) and
   `openmettle.operations` (`FOR UPDATE`), verifies `coalesce(dispatched_attempts, 1) < 3`
   (counting any legacy `NULL` row conservatively as `1`), enforces live ADR 0035 effect-level
   and bound-session authority, and commits the monotonic increment (`0 -> 1`, `1 -> 2`,
   `2 -> 3`) under the monotonicity trigger **before** releasing the PostgreSQL connection and
   issuing the outbound HTTP request.
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
Reconciliation runs only for unresolved writes (`idempotent`, `lookup`, `non_repeatable`) and
**never** re-sends a write:

- **Proven-unsent write (`outcome = 'intent'` and strictly non-null `dispatched_attempts = 0`).**
  Reserve the proven-unsent (`outcome = "failed"`) rule **strictly** for non-null
  `dispatched_attempts = 0` (never for `dispatched_attempts IS NULL`). When the operation row
  proves Step 5 never committed attempt 1, `Executor::reconcile` returns an observation for
  `runs::record_observation` with `outcome = "failed"` (`revision = 1`, non-empty redacted
  evidence) under `Fence::Hold` with **zero** credential lookups and **zero** outbound HTTP
  calls.
- **Dispatched or legacy write with an authorized read-only lookup (`dispatched_attempts IS
  NULL OR dispatched_attempts >= 1`):**
  - For `lookup` writes, the reconciler queries **either** the persisted `downstream_handle`
    **or** a deterministic, contract-defined authoritative lookup derived from the committed
    canonical arguments and logical key (handling responses lost before a remote handle arrived).
  - For `idempotent` writes, the reconciler queries a read-only status endpoint keyed by the
    persisted `EndpointKey::Supported` without resending the write.
- **Dispatched or legacy write with no downstream read-only lookup (`outcome = 'intent'` and
  `dispatched_attempts IS NULL OR dispatched_attempts >= 1`).** For every `non_repeatable`
  write, every legacy/`N-1` `dispatched_attempts IS NULL` write without an authorized read-only
  lookup, and any `lookup` write with `downstream_handle IS NULL` and no contract-defined
  deterministic query, `Executor::reconcile` **never** re-sends and performs **zero** credential
  lookups or outbound HTTP calls: it returns an observation so `worker::reconcile` commits
  `runs::record_observation` with **`outcome = "outcome_unknown"`** (`revision = 1`, fixed
  redacted post-send observation-lost diagnostic) under `Fence::Hold`. Because
  `leases::unresolved!()` (`src/authz/leases.rs`) still counts `'outcome_unknown'` (`n = 1`),
  `worker::reconcile` finishes `Settle::Stopped` and `leases::decide(ExecState::Reconciling, ...)`
  settles the run to terminal **`interrupted`** (`{"unresolved": 1}`) with
  `operations.outcome = 'outcome_unknown'` durably distinguishing a dispatched or legacy write
  from a proven-unsent `'intent'`.
- In `src/worker.rs`, `worker::execute` enters `Executor::reconcile` when
  `run.state == ExecState::Reconciling`, where `Fence::Step` — and therefore `recheck_leased` —
  explicitly rejects with `LeaseError::Stopping` (`src/authz/leases.rs`). Furthermore,
  `Executor::reconcile` currently receives `(&UnresolvedOperation, StepContext)` without the
  worker's `ActiveRun` / `ClaimedRun`, `leases::UnresolvedOperation` carries only
  `(id, logical_key, target, capability, outcome, revision, downstream_handle)`, and
  `recheck_decision` (`src/authz/runs.rs`) verifies only principal, platform capabilities, run
  scope, conversation, optional local resource and run capabilities — **not** access to the
  specific MCP server, connection or account. PR3 therefore adds
  `dispatched_attempts: Option<i32>` to `leases::UnresolvedOperation` (populated by
  `leases::unresolved_after`), passes `&ActiveRun` (or `&Lease<'_>`) into `Executor::reconcile`
  (or an extended reconciliation hook), loads the committed `openmettle.effect` v1 payload and
  run metadata on a worker DB connection, and before any remote lookup performs **both** under
  **`leases::with_lease(..., Fence::Hold, ...)`**:
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
- If an already-`'outcome_unknown'` operation lacks a reconciler, authority fails or the remote
  endpoint cannot prove an outcome, return `None` so ADR 0033 preserves uncertainty and settles
  the run as `interrupted`.

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
  While full MCP `2026-07-28` Streamable HTTP requires general-purpose clients to mirror
  `x-mcp-header`-annotated parameters into `Mcp-Param-*` headers, OpenMettle v1 intentionally
  defines a **restricted stateless interoperability profile** that omits `Mcp-Param-*` from
  this fixed outbound header allowlist and fails closed at registration and `tools/list`
  discovery on any schema containing `x-mcp-header` (never invoking an `x-mcp-header` tool with
  missing headers, at the explicit trade-off of rejecting `x-mcp-header`-dependent MCP tools).
  Every outbound `tools/list` and `tools/call` JSON-RPC request body MUST
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
- **Hard inbound response body ceiling.** Enforce `MAX_TOOL_RESPONSE_BODY_BYTES = 4 MiB`
  (`4_194_304` decoded HTTP body bytes). Reject declared `Content-Length > 4 MiB` before
  reading any body bytes, bound HTTP/1.1 response header and chunk-framing reads via the
  transport's fixed header/buffer limits (`8 KiB` / `32` headers, chunked trailers rejected),
  and enforce `http_body_util::Limited::new(body, 4_194_304)` across chunked and
  `text/event-stream` bodies so aggregate **decoded HTTP body bytes** (after HTTP/1.1 chunk
  framing is stripped, explicitly including raw SSE comment lines, event framing and progress
  notifications) abort immediately upon exceeding `4 MiB` before buffering.
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
  `Fence::Step` transaction on the primary that atomically checks
  `coalesce(dispatched_attempts, 1) < 3`, sets `openmettle.operations.dispatched_attempts =
  coalesce(dispatched_attempts, 1) + 1` and performs an **effect-level
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
| **Transient transport** (`ToolFault::Transient`) | Pre-send DNS/TCP connect failure; HTTP `408`, `429`, `502`, `503`, `504`; mid-stream disconnect or idle/call timeout | Up to `3` durable total attempts (`coalesce(openmettle.operations.dispatched_attempts, 1) < 3`, atomically incremented under `Fence::Step` before each send) for `repeatable_read` and active unexpired `idempotent` writes with the identical persisted key; for `lookup` and `non_repeatable` writes, retry **only** proven pre-send DNS/connection-refused failures and **never** retry after request bytes are sent. Before **every** permitted retry across all classes, enforce `coalesce(dispatched_attempts, 1) < 3`, `step.stop`, `step.deadline` (including `EndpointKey::Supported.expires_us`) and a fenced ADR 0035 effect-level authority recheck (principal, scope, target, capability, destination policy plus live bound session and approval/user/provider generations). | `failed` for exhausted `repeatable_read` or proven pre-send failure when no prior attempt left the process; `outcome_unknown` for any `idempotent`, `lookup` or `non_repeatable` write once any attempt may have left the process without endpoint proof. | Sleep with `ring::rand::SystemRandom` full jitter (`250 ms`, `500 ms`). For a single valid integer `Retry-After` (seconds): sleep at least that delay when `<= 60 s` and within remaining call, authority and run execution deadlines; fail without retrying if `Retry-After` exceeds `60 s` or the remaining budget; ignore malformed or duplicate headers. Abort sleep immediately on `step.stop`. For known-outcome `failed` reads or proven-unsent writes, return a bounded error envelope (`retryable_by_model: false` for non-retryable failures). For **every** write ending in `outcome_unknown` (including an `idempotent` write whose retries or `EndpointKey::Supported` window expired after a possible send), attempt `outcome = "outcome_unknown"` under `Fence::Hold` and return `StepResult::Stopped` into `ExecState::Reconciling` / `interrupted`, or `StepResult::Invalidated` immediately without touching PostgreSQL if `Fence::Hold` rejects with `StaleClaim`, `Expired` or `Terminal` (zero further model rounds). |
| **Semantic tool fault** (`ToolFault::Semantic`) | MCP JSON-RPC `result` with `isError: true`, JSON-RPC `-32602`, or internal tool domain refusal (for example invalid UTF-8 binary content, offset past EOF or non-`active` revision) | `0` transport retries | `failed` for reads and for writes whose reviewed contract guarantees `isError: true` caused no side effect (and no prior attempt was ambiguous); otherwise `outcome_unknown`. | For known-outcome `failed` results, return a bounded structured error envelope (`status: "tool_error"`, closed `fault_code`, `<= 2 KiB` UTF-8 summary, `retryable_by_model`) so the model can recover within `round_limit`. If an uncertain write ends in `outcome_unknown`, attempt `outcome = "outcome_unknown"` under `Fence::Hold` and return `StepResult::Stopped` into reconciliation/settlement (or `StepResult::Invalidated` on `StaleClaim`, `Expired` or `Terminal`, never `StepResult::Continue`). |
| **Policy, auth or contract failure** (`ToolFault::TerminalRefusal`) | Revoked session/grant/capability, schema/bounds violation (`max_bytes < 4`), `x-mcp-header`-annotated tool schema, unpinned destination, missing V1-28 credential or V1-17 quota; SSRF `Address`, TLS cert/host failure, `3xx` redirect, `401`/`403`, unexpected `4xx`, `tools/list` drift, `input_required` or server-initiated JSON-RPC request, malformed JSON-RPC/framing or `> 4 MiB` response | `0` retries | `failed` when refused pre-send or on definitive `401`/`403` with no prior ambiguous attempt; `outcome_unknown` if any prior write attempt may have left the process or if `input_required`, malformed framing or `TooLarge` arrives after a write was sent. | Fail closed immediately without follow-up calls. Authority revocation settles the run under ADR 0033/0035. Known-outcome contract or auth refusals (`failed`) return fixed redacted diagnostics with `retryable_by_model: false` and no upstream body echoing. Any write ending in `outcome_unknown` attempts `outcome = "outcome_unknown"` under `Fence::Hold` and returns `StepResult::Stopped` into `ExecState::Reconciling` / `interrupted` (or `StepResult::Invalidated` on `StaleClaim`, `Expired` or `Terminal`, never `StepResult::Continue`). |

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
| **Refused** | Exceeds `4 MiB` (`4_194_304` bytes) decoded HTTP response body or payload ceiling (`MAX_TOOL_RESPONSE_BODY_BYTES`) | Aborted during streaming before memory or disk exhaustion (`ToolFault::TerminalRefusal` / `TooLarge`). |

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
`storage_reservations` (including `INSERT (id)`) and `artifact_revisions` (including
`display_name`, verified in `src/boundaries.sql`); PR2's sequential SQL migration additionally
adds `spill_reclaiming boolean NOT NULL DEFAULT false` on `openmettle.storage_reservations`
with `CHECK (NOT spill_reclaiming OR state IN ('reserved', 'released'))` and grants
`UPDATE (spill_reclaiming)` to `openmettle_worker` (audited in `src/boundaries.sql`). Because
`leases::fenced` (`src/authz/leases.rs`) sets
`SET LOCAL idle_in_transaction_session_timeout = '5s'`, `run_one` (`src/worker.rs`) drops a
step once its drain deadline (`until = (Instant::now() + settings.lease / 6).min(shutdown_limit)`)
elapses and `Staged::publish` (`src/artifact_fs.rs`) unlinks `revisions/<id>` on post-rename
`sync_dir` failure, `artifact_fs::publish_bytes` MUST **never** hold a `leases::fenced` DB
transaction open across `spawn_blocking` filesystem I/O. Moreover, when a shortened tool
`step.deadline` expires while Phase 2's `spawn_blocking` task is stalled in `fsync`, returning
`StepResult::Continue` lets the run (and sibling runs) issue further tool calls while the
detached blocking task still holds a Tokio blocking thread and up to `4 MiB` of buffered
payload bytes; repeated spills on a wedged filesystem would otherwise accumulate unbounded
detached tasks beyond the worker's run-slot limit. PR2 therefore gates spill publication with
a **process-wide bounded `Arc<tokio::sync::Semaphore>` (`spill_permits`, bounded to the
worker's configured run-slot concurrency `max_concurrent_runs`, i.e.,
`OPENMETTLE_WORKER_RUN_SLOTS` / `RunPolicy::slots`)** and mirrors `artifact_fs::ingest`'s
three-phase separation with **both** short DB phases fenced under `Fence::Step`, a **disjoint
per-attempt `reservation_id`**, a **single pre-created, pre-synced 0-byte payload file
`<ARTIFACTS_DIR>/staging/<reservation_id>` (mode `0o600`, matching `src/artifact_fs.rs:151`)
opened read-write via `fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600)`
with `File::try_lock_shared()` + `sync_dir(&store.staging)` before Phase 1 and moved directly
into Phase 2 without any separate `.lock` sidecar or second `open()` call** (all using stable
safe Rust 1.100 `std::fs` + `std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, MetadataExt}`
under `unsafe_code = "forbid"`, eliminating pre-Phase-1 directory-loss, multi-FD `SIGKILL`
`close_files()` ordering, pre-`open` thread-pause and Linux NFS read-only `LOCK_EX` gaps),
racing Phase 2's `spawn_blocking` disk join against `step.deadline` and `step.stop.changed()`,
local `step.deadline`/`step.stop` enforcement after Phase 2, before Phase 3 settlement and
immediately before Phase 3 commits, Phase 3 enforcing `AND NOT spill_reclaiming` strictly on
`storage::settle`'s `ReservationState::Reserved` branch while preserving
`ReservationState::Settled` idempotent replay, lock-acquired and pre-commit `step.stop`
enforcement inside the inline `truncated_no_spill` fallback, and **single-transaction
atomicity** between `storage::settle` and `runs::record_observation`:

1. **Bounded spill permit acquisition, pre-Phase-1 durable 0-byte `staging/<reservation_id>`
   (read-write + `LOCK_SH` + `sync_dir(&store.staging)`) and Phase 1 — Short `Fence::Step`
   reservation (no filesystem I/O inside DB tx).** Before creating any file, entering Phase 1
   (`storage::reserve`) or spawning `spawn_blocking`, attempt to acquire an
   `OwnedSemaphorePermit` non-blockingly via `spill_permits.clone().try_acquire_owned()`. If no
   permit is available (`Err(TryAcquireError::NoPermits)`), skip staging creation and Phases
   1–3 completely — creating **zero** files, allocating **zero** `storage_reservations` rows
   and queuing **zero** `spawn_blocking` tasks or extra payload buffers — and **immediately**
   take the inline `storage: "truncated_no_spill"` disposition (recording redacted
   `spill_error: "spill_saturated"`). When a permit is acquired, mint a fresh random 128-bit
   `reservation_id` via `ring::rand::SystemRandom`-backed RFC 9562 UUIDv4 generation (reusing
   the existing 16-byte version-4 / RFC 9562 variant helper pattern in `src/telemetry.rs:328-350`,
   preserving zero new Cargo crates since `uuid` is not in `Cargo.lock`, and passed explicitly
   to `storage::reserve` using `openmettle_worker`'s existing `INSERT (id)` grant on
   `storage_reservations`), a fresh per-attempt random 128-bit UUID/nonce `<attempt_id>`
   (`ring::rand::SystemRandom`, giving an adapter-owned idempotency key
   `tool-spill:<operation_id>:<attempt_id>`, `84` bytes `<= 128` bytes) and a fresh
   `artifact_id`. **Before Phase 1 inserts `storage_reservations`** (outside
   any DB transaction), run pre-Phase-1 on `spawn_blocking`, raced in `tokio::select!` against
   `tokio::time::sleep_until(step.deadline)` and `step.stop.changed()` via a shared
   `Arc<AtomicBool>` (`cancelled = false`):
   - Validate via `fs::symlink_metadata(&store.staging)` (`file_type().is_dir()` and expected
     `(dir_meta.dev(), dir_meta.ino())` via `MetadataExt`, matching `src/artifact_fs.rs:108-130`)
     that `staging/` is not a symlink, then create the **0-byte payload file
     `<ARTIFACTS_DIR>/staging/<reservation_id>` itself** via
     `fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&staging_path)`
     -> `payload_file` (`create_new(true)` maps to POSIX `O_CREAT | O_EXCL`, refusing any
     existing file or live/dangling symlink with `ErrorKind::AlreadyExists`; mode `0o600`
     `rw-------` owned by the runtime user, matching `src/artifact_fs.rs:151`, and consuming
     zero logical bytes before quota reservation), immediately acquire
     **`payload_file.try_lock_shared()`** (stable safe Rust 1.100 `LOCK_SH | LOCK_NB`, zero
     `unsafe`), and **execute `sync_dir(&store.staging)` (`fs::File::open(&store.staging)?.sync_all()`,
     matching `src/artifact_fs.rs:223-225`) BEFORE Phase 1 (`storage::reserve`) runs**. Because
     `staging/` is `fsync`ed before Phase 1 commits `storage_reservations`, a storage-host crash
     can never leave a committed worker-spill `storage_reservations` row without its durable
     `staging/<reservation_id>` entry.
   - If cutoff fires before pre-Phase-1 completes (before Phase 1 starts), set
     `cancelled.store(true, Ordering::Release)` so the blocking helper calls
     `fs::remove_file(&staging_path)` while holding `LOCK_SH`, drops `payload_file`, runs
     `sync_dir(&store.staging)` and drops `OwnedSemaphorePermit`; skip Phase 1 with **zero**
     `storage_reservations` row created and apply the spill-abort disposition rule below.
   - Once `payload_file` is open, holds `LOCK_SH` and `staging/` has been `fsync`ed, run
     Phase 1 under `leases::with_lease(..., Fence::Step, ...)`, calling `storage::reserve` with
     the pre-minted `<reservation_id>`, `scope = run.scope_id`, `actor = run.actor_user_id`,
     `max_bytes = payload.len() as i64`, `run = Some(run_id)` and `operation =
     Some(operation_id)` (`spill_reclaiming` defaults to `false`). Commit and release the
     PostgreSQL connection before any payload disk I/O. Every worker spill attempt therefore
     owns a **disjoint `reservation_id`, `staging/<reservation_id>` and
     `revisions/<reservation_id>`** — and from the exact instant `storage_reservations` commits
     in Phase 1, the durable `staging/<reservation_id>` file **already exists on disk with
     `LOCK_SH` held**!
   - **Phase 1 failure / lost-commit-ack handling:**
     - If Phase 1 fails with a **deterministic pre-commit PostgreSQL error or confirmed
       rollback** (for example `Fence::Step` rejecting with `StaleClaim`, `Expired`, `Terminal`
       or `Stopping`, or `OMQ01` quota exceeded), call `fs::remove_file(&staging_path)` while
       holding `LOCK_SH`, drop `payload_file`, run `sync_dir(&store.staging)`, drop
       `OwnedSemaphorePermit` and apply the spill-abort disposition rule below.
     - If Phase 1 fails with an **ambiguous / lost commit acknowledgement** (connection drop or
       cutoff during `COMMIT`), **do NOT unlink `staging/<reservation_id>` blindly** and **do
       NOT rely on an unlocked `READ COMMITTED` `SELECT`** (which can take its statement
       snapshot before the in-flight Phase-1 backend finishes committing and falsely observe
       zero rows). While still holding `LOCK_SH` on `payload_file`, open a new `READ COMMITTED`
       transaction on the primary, **first acquire `SELECT 1 FROM openmettle.runs WHERE
       scope_id = $1 AND id = $2 FOR NO KEY UPDATE`** (matching the exact run-row lock held by
       Phase 1's `leases::with_lease`, blocking until the in-flight Phase-1 backend finishes
       committing or aborting and releases its row lock), and **in a separate subsequent SQL
       statement** inside that same `READ COMMITTED` transaction (so PostgreSQL takes a fresh
       statement snapshot *after* `FOR NO KEY UPDATE` is acquired), execute `SELECT state FROM
       openmettle.storage_reservations WHERE id = $1`. Call `fs::remove_file(&staging_path)`
       while holding `LOCK_SH` + `drop(payload_file)` + `sync_dir(&store.staging)` **only**
       when that post-lock query succeeds and confirms **zero rows** (`None`). If a row exists
       (`state = 'reserved'`), **or if the recovery transaction itself fails or times out and
       cannot establish the outcome**, **keep `staging/<reservation_id>` intact on disk** and
       simply drop `payload_file` and `OwnedSemaphorePermit` so `reconcile_run_spills` (or the
       aged `> 900 s` orphan sweep, which serializes any zero-row observation against any
       in-flight committing Phase 1 via `SELECT 1 FROM openmettle.storage_instance WHERE id
       FOR UPDATE` before re-querying `storage_reservations`) cleans it up safely, then apply
       the spill-abort disposition rule below.
2. **Phase 2 — Unfenced `spawn_blocking` disk I/O using the already-open, `LOCK_SH`-locked
   `payload_file` (strictly outside any DB transaction, zero sidecar `.lock` file).** With no
   PostgreSQL connection borrowed and no DB transaction open (so slow disk I/O `> 5 s` can
   never trip `idle_in_transaction_session_timeout`), check
   `Instant::now() < step.deadline && step.stop.borrow().is_none()` before spawning; if
   already false, `drop(payload_file)` (closing the single descriptor and releasing `LOCK_SH`
   while leaving `staging/<reservation_id>` intact on disk and `<reservation_id>` in
   `state = 'reserved'` for `reconcile_run_spills`), drop `OwnedSemaphorePermit` immediately,
   skip disk I/O and immediately apply the spill-abort disposition rule below. Otherwise,
   allocate a fresh shared `Arc<AtomicBool>` (`cancelled = false`), **move the already-open
   read-write, `LOCK_SH`-locked `payload_file` and the `OwnedSemaphorePermit` directly into
   Phase 2's `spawn_blocking` closure** — **zero second `open()` call and zero sidecar `.lock`
   file** (strictly bounding total concurrent in-flight plus detached spill jobs and buffered
   payload memory across the entire worker process) — and run the blocking disk pipeline on
   `spawn_blocking`:
   - Check `cancelled.load(Ordering::Acquire)` **before writing** and **before each `<= 64 KiB`
     chunk**, write payload bytes into `payload_file` while computing SHA-256, call
     `payload_file.sync_all()`, and perform a final pre-rename `cancelled.load(Ordering::Acquire)`
     check.
   - **If `cancelled` is `true` at or before that final pre-rename check (or any write /
     `sync_all` error occurs):** skip `fs::rename`, perform **no** `fs::remove_file` on
     `staging/<reservation_id>`, and simply **`drop(payload_file)`** (closing the single
     descriptor and releasing `LOCK_SH`) and **`drop(permit)`**! Because
     `staging/<reservation_id>` stays intact on disk with `<reservation_id>` in
     `state = 'reserved'`, `reconcile_run_spills` will acquire `LOCK_EX` directly on that
     single inode, reduce its logical byte length (`st_size`) to `0` via
     `probe_file.set_len(0)?`, remove it with `fs::remove_file`, `sync_dir` both `staging/`
     and `revisions/`, and release quota.
   - **If the final pre-rename check observes `cancelled == false`:** **keep `LOCK_SH` on
     `payload_file` continuously across `fs::rename(&staging_path, &revision_path)` +
     `sync_dir(&store.revisions)` + `sync_dir(&store.staging)`** (performing **no**
     `fs::remove_file` even if `cancelled` turns `true` or `sync_dir` fails), then
     **`drop(payload_file)`** and **`drop(permit)`**!
   Because `run_one` (`src/worker.rs`) waits only up to the drain deadline
   `until = (Instant::now() + settings.lease / 6).min(shutdown_limit)` before dropping `work`,
   the async adapter MUST race the `spawn_blocking` `JoinHandle` in a `tokio::select!` against
   **both** `tokio::time::sleep_until(step.deadline)` and `step.stop.changed()`:
   - **Cutoff fires before `spawn_blocking` completes (raced detach):** Set
     `cancelled.store(true, Ordering::Release)`, detach the `JoinHandle` (an in-flight OS
     blocking syscall cannot be preempted; the detached closure retains its single `LOCK_SH`
     `payload_file` and `OwnedSemaphorePermit` until it exits), unconditionally disable Phase 3
     (`storage::settle` + `runs::record_observation`), leave the Phase-1 `<reservation_id>` in
     `state = 'reserved'` while late disk I/O may still be active (so
     `storage_accounts.reserved_bytes` continues to cover any in-flight bytes on disk without
     premature quota release) and **immediately** run the inline
     `storage: "truncated_no_spill"` fallback (under the spill-abort disposition rule below)
     during the drain window so the known call outcome (`Ok` or terminal `Err`) and required
     `StepResult` complete before `run_one` drops `work`. When cutoff fires **before** the
     detached closure's final pre-rename `cancelled.load(Ordering::Acquire)` check, the closure
     skips `fs::rename` and leaves the `LOCK_SH`-held inode at `staging/<reservation_id>`; if
     cutoff races **after** that check (just before or during `fs::rename(&staging_path,
     &revision_path)`, or during post-rename `sync_dir(&store.revisions)` /
     `sync_dir(&store.staging)`), the reserved inode may already have been renamed to
     `revisions/<reservation_id>` while the detached closure continues holding `LOCK_SH` on
     `payload_file` until `sync_dir` finishes and `drop(payload_file)` + `drop(permit)`
     execute. In **both** cases, the detached closure performs **no `fs::remove_file`**,
     **Phase 3 remains unconditionally disabled**, `<reservation_id>` stays in
     `state = 'reserved'` (`max_bytes` remains charged), and because there is only **one**
     payload handle (`payload_file`) holding `LOCK_SH` continuously from pre-Phase-1 creation
     through exit (or `SIGKILL`), `reconcile_run_spills` cannot acquire `File::try_lock()`
     (`LOCK_EX | LOCK_NB`) or release quota while any writer holds the file; once `payload_file`
     closes (or the worker crashes), `reconcile_run_spills` — which probes **both**
     `staging/<reservation_id>` and `revisions/<reservation_id>` under `LOCK_EX` — claims
     `spill_reclaiming = true`, acquires read-write `File::try_lock()` directly on whichever
     path holds the unsettled inode, reduces its logical byte length (`st_size = 0`) with
     `probe_file.set_len(0)?` before `fs::remove_file`, durably `sync_dir`s both `staging/` and
     `revisions/`, and commits `storage::release`.
   - **Normal uncancelled `spawn_blocking` completion (`cancelled == false`):** Unlike
     `Staged::publish` (`src/artifact_fs.rs`), an uncancelled Phase-2 spill helper never
     unlinks `revisions/<reservation_id>` on a post-rename `sync_dir` failure, nor if
     `step.deadline` or `step.stop` trips after the `JoinHandle` returns normally (leaving
     `<reservation_id>` in `state = 'reserved'` for `reconcile_run_spills`). On normal closure
     exit, `payload_file` is dropped (after `fs::rename` + `sync_dir(&store.revisions)` +
     `sync_dir(&store.staging)`) and `OwnedSemaphorePermit` is dropped (Phase 3 is DB-serialized
     against `reconcile_run_spills` via `spill_reclaiming`). Immediately after `spawn_blocking`
     returns normally, re-check
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
   atomically. `storage::settle` (`src/storage.rs:362-379`, tested by
   `tests/schema/artifact_fs.rs:434`) **preserves its existing `ReservationState::Settled`
   idempotent metadata-matching replay branch intact**, and applies **`AND NOT
   spill_reclaiming` strictly to its `ReservationState::Reserved` settlement branch** (backed
   by PR2's table `CHECK (NOT spill_reclaiming OR state IN ('reserved', 'released'))`
   constraint, which guarantees `'settled'` rows never have `spill_reclaiming = true` and
   rejects any `state = 'settled'` update while `spill_reclaiming = true`). Thus, once Step 1
   of `reconcile_run_spills` commits `spill_reclaiming = true` on a `'reserved'` row, a stalled
   Phase 3 observes `ReservationState::Reserved` with `spill_reclaiming = true` under `FOR
   UPDATE`, fails closed with `Error::Conflict`, rolls back **both** `storage::settle` and
   `runs::record_observation` (leaving `storage_reservations` in `state = 'reserved',
   spill_reclaiming = true` for `reconcile_run_spills`), and applies the spill-abort
   disposition rule below; conversely, if Phase 3 commits `state = 'settled'` first, Step 1 of
   `reconcile_run_spills` sees `state = 'settled'` under the row lock and skips the row without
   touching any file. When `ReservationState::Reserved` has `NOT spill_reclaiming`,
   `storage::settle` proceeds with `media_type` (`text/plain; charset=utf-8` or
   `application/json; charset=utf-8`) and a bounded display name passing
   `storage::valid_display_name` to create the immutable `artifact_revisions` row and charge
   active quota, constructs the bounded preview envelope carrying the settled `(artifact_id,
   revision_id)`, and calls `runs::record_observation` (`openmettle.runs` already locked ->
   `openmettle.operations` `FOR UPDATE` -> `openmettle.run_events` append). Because
   `storage::settle` (`src/storage.rs`) can still block waiting for shared `storage_accounts`
   and `storage_instance` row locks *after* the initial lock check, the Phase-3
   `leases::fenced` closure MUST perform a **final**
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
   second time), with zero sidecar file left behind on disk. On replay of an already-`succeeded`
   operation, the adapter reads `(artifact_id, revision_id)` from the committed observation
   evidence (after fenced primary `approvals::recheck_replay_effect_authority` bound-session and
   effect-authority checks plus `hydrate_worker_principal`, `revision.scope_id == run.scope_id`,
   live `Action::Read`, and `revision.state == "active"` rechecks) rather than re-running
   `publish_bytes`.

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

**Recovery across `run_one` drain-window expiry (`WorkEnd::Incomplete`).** Even when Phase 2
races out immediately on cutoff — or while inline Step 8, Phase 3 or the Phase-2 cutoff
fallback is attempting to commit — if another transaction holds
`openmettle.runs FOR NO KEY UPDATE` (or DB I/O stalls) through `run_one`'s drain deadline
(`until = (Instant::now() + settings.lease / 6).min(shutdown_limit)`, `src/worker.rs`),
`run_one` drops `work` as **`WorkEnd::Incomplete`**. That leaves the known in-memory result in
one of two durable PostgreSQL states, with deterministic recovery across PR2
(`repeatable_read`) and PR3 (`idempotent`, `lookup`, `non_repeatable`):

- **Unacknowledged commit (`operations.outcome` already committed as `'succeeded'` or
  `'failed'`, `revision >= 1` right before the future or socket was dropped):**
  `leases::unresolved_operations` (`src/authz/leases.rs`) excludes the operation (`n = 0`). If
  the run remains non-terminal (`running`), a reclaiming worker (`leases::reclaim_next`) checks
  `openmettle.operations` by `(scope_id, run_id, logical_key)` before dispatch and **reuses the
  committed observation in history with zero additional outbound sends** — except that before
  returning or replaying any cached bytes or artifact-backed result (`artifact.read_range` or
  any `'succeeded'`/`'failed'` observation backed by a source or spilled artifact), the worker
  MUST execute a fenced primary authority check (`approvals::recheck_replay_effect_authority`,
  invoking `authorized(c, &proof, &review)` under `Fence::Step` against the run's bound
  `originating_session_id` / recorded `deciding_session_id` and provider/approval/user
  generations) **in addition to** `hydrate_worker_principal`, `revision.scope_id ==
  run.scope_id`, `authorize_resource(..., Action::Read)`, and `revision.state == "active"`,
  refusing replay and returning **zero** cached bytes (`IntentResult::Invalidated` /
  `ToolFault::TerminalRefusal`) if the bound session logged out or effect authority was revoked
  even while artifact `Action::Read` access and `revision.state == "active"` remain valid. If
  `run_one`'s post-drain `leases::handoff` or `leases::settle` ran after the commit, it
  releases or settles cleanly with `n = 0`.
- **Uncommitted observation (`operations.outcome` remained `'intent'`):**
  - **`repeatable_read` (side-effect-free, PR2):** A reclaiming worker on a `running` run
    safely replays the read under `Fence::Step` (via `approvals::start_replayed_read`,
    enforcing `coalesce(dispatched_attempts, 1) < 3` and minting a fresh `<reservation_id>` if
    spilled), whereas any transition to `'waiting'` or terminal resolves the revision-zero
    `'intent'` to `outcome = 'failed'` via PR2's `AFTER UPDATE OF state` trigger strictly
    before `run-waiting` / `run-terminal`.
  - **External writes (`idempotent`, `lookup`, `non_repeatable`, PR3):**
    `leases::unresolved!()` (`src/authz/leases.rs`) counts `outcome = 'intent'` as unresolved
    (`n >= 1`). Whether `run_one`'s post-drain `leases::handoff` /
    `leases::settle(..., Settle::Stopped)` succeeds or the lease lapses to
    `leases::reclaim_next` (`recovered = true`, where `worker::execute` returns
    `WorkEnd::Complete(Settle::Stopped)` before any model or tool step, `src/worker.rs`), the
    run transitions into **`ExecState::Reconciling`** (when remaining execution budget exceeds
    one lease interval) or directly into terminal **`interrupted`** (when `!time_to_reconcile`
    in `leases::decide`, `src/authz/leases.rs:408-415`, or via `leases::settle_expired`,
    `src/authz/leases.rs:649-664`), with **zero additional outbound write sends**:
    1. When entering **`ExecState::Reconciling`**, `Executor::reconcile` handles each
       unresolved write deterministically:
       - If strictly **non-null `dispatched_attempts = 0`** (proven unsent before Step 5
         committed attempt 1), `Executor::reconcile` records `runs::record_observation` with
         `outcome = "failed"` (`revision = 1`, non-empty redacted evidence, zero external send)
         under `Fence::Hold`.
       - If **`dispatched_attempts IS NULL OR dispatched_attempts >= 1`** and the reviewed
         contract declares an authorized read-only status/lookup query (`idempotent` or
         `lookup`), `Executor::reconcile` recovers the authoritative outcome (`"succeeded"` or
         `"failed"`, inline/bounded) via read-only query with **zero** write re-sends.
       - If **`dispatched_attempts IS NULL OR dispatched_attempts >= 1`** and no downstream
         read-only lookup is available (every **`non_repeatable` write**, every legacy/`N-1`
         `dispatched_attempts IS NULL` write without lookup, plus any `lookup` write with
         `downstream_handle IS NULL` and no contract-defined deterministic query),
         `Executor::reconcile` **never re-sends** — it commits `runs::record_observation` with
         **`outcome = "outcome_unknown"`** (`revision = 1`, fixed redacted post-send
         observation-lost diagnostic) under `Fence::Hold`. Because `leases::unresolved!()`
         still counts `'outcome_unknown'` (`n = 1`), `worker::reconcile` finishes
         `Settle::Stopped` and `leases::decide(ExecState::Reconciling, ...)` settles the run to
         terminal **`interrupted`** (`{"unresolved": 1}`) with
         `operations.outcome = 'outcome_unknown'` durably distinguishing a dispatched or legacy
         write from a proven-unsent `'intent'`.
    2. **Direct terminal settlement bypassing `Executor::reconcile` (`!time_to_reconcile` on
       `leases::settle(..., Settle::Stopped)` when remaining execution budget is `<= 1` lease
       interval, `src/authz/leases.rs:408-415`, or `leases::settle_expired`,
       `src/authz/leases.rs:649-694`) vs. non-terminal handoff/reclaim into `Reconciling`:**
       Because direct terminal settlement transitions to terminal `'interrupted'` without ever
       entering `ExecState::Reconciling` or invoking `Executor::reconcile`, PR3 enforces
       pre-terminal write resolution at **both** the worker pre-settlement layer and the
       PostgreSQL trigger layer — while carefully distinguishing non-terminal handoff/reclaim
       entry into `ExecState::Reconciling` from direct terminal settlement:
       - In PR3 (`N`), inside **`leases::settle_locked`** (`src/authz/leases.rs:547-570`),
         first query `(n_raw, n_zero, time)` on the locked run without mutating
         `openmettle.operations`, where `n_raw` is total rows matching `leases::unresolved!()`,
         `n_zero` is rows matching `unresolved!() AND outcome = 'intent' AND revision = 0 AND
         dispatched_attempts = 0`, `n_after = n_raw - n_zero`, and `time` is
         `execution_expires_at > clock_timestamp() + $3 * interval '1 millisecond'`.
         - **Preserve `Settle::Succeeded` conflict semantics unconditionally:** When
           `input == Settle::Succeeded`, `leases::settle_locked` **MUST NEVER** pre-resolve
           `n_zero`; evaluate `decide(state, cancel, Settle::Succeeded, n_raw, time)` directly
           against `n_raw` (`src/authz/leases.rs:393-417`), so when `state == ExecState::Running`
           (running or cancelling) and `n_raw >= 1` (including a lone `dispatched_attempts = 0`
           write even when `!time` or `cancel.is_some()`), `decide` returns
           `Err(StoreError::Conflict("unresolved operation"))` (rolling back with zero
           mutations) and triggers `src/worker.rs:676-681`'s `Settle::Stopped` fallback
           (extending `tests/schema/worker_runtime.rs:208-225`, so a run with an unexecuted
           write intent never falsely settles to `Resolution::Succeeded`), whereas
           `Settle::Succeeded` from `ExecState::Reconciling` returns
           `Err(StoreError::InvalidInput("settle"))` regardless of `n_raw`.
         - **Terminal-only pre-resolution predicate for `input != Settle::Succeeded`:**
           Pre-resolve the `n_zero` (`dispatched_attempts = 0`) write rows (`capability IN
           ('idempotent', 'lookup', 'non_repeatable') AND outcome = 'intent' AND revision = 0
           AND dispatched_attempts = 0`) on the locked run to `outcome = 'failed'`
           (`revision = 1`, with bounded redacted observation evidence and its ADR 0004
           `openmettle/observation/1\0` `run_events` row) and pass `n = n_after` to
           `decide(state, cancel, input, n_after, time)` **iff**:
           `input != Settle::Succeeded && (state == ExecState::Reconciling || !time || (n_after == 0 && (cancel.is_some() || matches!(input, Settle::Failed(_)))))`.
           In every valid branch of that predicate (`src/authz/leases.rs:401-417`),
           `decide(..., n_after, time)` resolves directly to a valid terminal
           `Ok(Resolution::...)` (`Interrupted(n_after)` or `Cancelled(r)` in `Reconciling`;
           `Interrupted(n_after)` when `!time && n_after >= 1`; `DeadlineExceeded`,
           `Cancelled(r)` or `Failed(f)` when `n_after == 0`), **never**
           `Err(StoreError::InvalidInput("settle"))` on a valid transition and **never**
           mutating rows before a non-terminal transition (and any invalid
           `(ExecState::Reconciling, Settle::Failed(_))` call returns
           `Err(StoreError::InvalidInput("settle"))`, rolling back the fenced transaction).
         - **Non-terminal `Reconciling(n_raw)` paths (zero pre-resolution):** Whenever the
           predicate is false (specifically **(i)** uncancelled `state == ExecState::Running &&
           cancel.is_none() && input == Settle::Stopped && time` during reclaim at
           `src/worker.rs:499-505` or graceful shutdown `leases::handoff` at
           `src/authz/leases.rs:519-537` with `> 1` lease interval remaining, where
           pre-resolving `n_zero` would drop `n` to `0` and trigger
           `Err(StoreError::InvalidInput("settle"))` at `src/authz/leases.rs:416, 796-799`,
           AND **(ii)** the **mixed-write** case `n_zero >= 1 && n_after >= 1 && time` — e.g.
           one `dispatched_attempts = 0` write intent plus one `dispatched_attempts >= 1` or
           `NULL` write intent — under `cancel.is_some()` or `Settle::Failed(_)` when `> 1`
           lease interval remains), `leases::settle_locked` leaves all `n_zero` rows untouched
           and passes `n = n_raw` to `decide`, transitioning cleanly into non-terminal
           `Resolution::Reconciling(n_raw)` (`Settled::Reconciling { unresolved: n_raw }`,
           followed by `release_lease` / `release_locked`). Then `worker::reconcile`
           (`src/worker.rs:424-478`, reading `dispatched_attempts: Option<i32>` on
           `UnresolvedOperation`) deterministically resolves both
           `dispatched_attempts == Some(0)` (`outcome = 'failed'`, `revision = 1`, zero network
           call) and `dispatched_attempts >= 1` / `NULL` (`succeeded`/`failed`/`outcome_unknown`)
           during reconciliation (settling `ExecState::Reconciling` to `Interrupted(n_rem)` or
           `Cancelled(r)`). By contrast, in the same mixed-write case when `time == false`
           (`<= 1` lease interval remaining), `!time` satisfies the predicate: `settle_locked`
           pre-resolves `n_zero -> 'failed'`, passes `n = n_after` to `decide` -> direct
           terminal `Interrupted(n_after)`, and PR3's `AFTER UPDATE` trigger transitions the
           remaining `n_after` intents to `'outcome_unknown'`.
       - Likewise, in PR3 (`N`)'s **`leases::settle_expired`** (`src/authz/leases.rs:649-694`),
         pre-resolve any `outcome = 'intent' AND revision = 0 AND dispatched_attempts = 0`
         write rows (`capability IN ('idempotent', 'lookup', 'non_repeatable')`) on the
         `FOR NO KEY UPDATE SKIP LOCKED` `due` runs to `outcome = 'failed'` (`revision = 1`,
         with bounded redacted observation evidence and its ADR 0004
         `openmettle/observation/1\0` `run_events` row) **before** the `SETTLE_EXPIRED`
         `unresolved` CTE counts `u.n`, so proven-unsent writes do not force `'interrupted'`.
       - In PR3's sequential SQL migration (see below), an **`AFTER UPDATE OF state ON
         openmettle.runs FOR EACH ROW`** `SECURITY DEFINER` trigger (`NEW.state =
         'interrupted'`) fires across **both `N-1` and `N` workers strictly before
         `run-terminal` is appended**, transitioning **every remaining** revision-zero write
         `intent` **unconditionally to `outcome = 'outcome_unknown'`, `revision = 1`** (never
         to `'failed'` inside the trigger) with bounded redacted observation evidence and its
         ADR 0004 `openmettle/observation/1\0` `run_events` row (incrementing
         `runs.last_event_sequence`) strictly before `run-terminal` — preserving exact
         `{"unresolved": n}` event/ledger parity across both `N-1` and `N` workers (`204 No
         Content` on terminal SSE cursor reconnect, with zero additional outbound sends).

**Pre-terminal resolution of abandoned intents (preserving SSE `204` cursors across
mixed-version rolling upgrades).** `runs::record_observation` (`src/runs.rs`) appends an event
to `openmettle.run_events` and increments `runs.last_event_sequence`, while `GET`/`HEAD
/v1/runs/{run_id}/events` (`src/v1/runs.rs`) returns `204 No Content` only when
`first.terminal && position == first.last` (`tests/schema/run_events_http.rs`). Calling
`runs::record_observation` *after* a run is already terminal (for instance inside
`reconcile_run_spills`) would advance `runs.last_event_sequence` past the terminal `run-*`
event's sequence and break reconnecting SSE clients (`200` instead of `204 No Content`).
Meanwhile, `storage::release` (`src/storage.rs`) rightly refuses with `Error::Unresolved`
whenever the linked operation has `outcome IN ('intent', 'outcome_unknown')`, so an abandoned
`repeatable_read` that crashed at `outcome = 'intent'` (`revision = 0`) after reserving a spill
would strand reserved quota forever if left unresolved at termination, while an unsettled
direct-terminal `'interrupted'` transition would otherwise leave dispatched writes stranded at
`outcome = 'intent', revision = 0`.

Under [ADR 0003](0003-schema-migrations.md), old (`N-1`) and new (`N`) API and worker
processes coexist during a rolling upgrade after PR2's and PR3's migrations apply. Relying on
Rust hooks alone would leave rolling-upgrade holes: an `N-1` worker running `approvals::park`
(`tests/schema/approvals.rs`) could still transition a `running` run carrying a revision-zero
`capability = 'repeatable_read'` `outcome = 'intent'` operation into `state = 'waiting'` after
the one-time migration repair completes; an `N-1` maintenance worker running
`leases::settle_expired` (`src/authz/leases.rs`) could terminalize an expired PR2 (`N`) run
holding a `'reserved'` `tool-spill:*` `storage_reservations` row and an abandoned revision-zero
`repeatable_read` `intent` without resolving that `intent` — after which `storage::release`
(`src/storage.rs`) would return `Error::Unresolved` forever and strand the reserved spill
quota; and either an `N-1` or `N` worker performing direct terminal `'interrupted'` settlement
(`!time_to_reconcile` or `leases::settle_expired`) would bypass `Executor::reconcile` and leave
dispatched writes at `outcome = 'intent', revision = 0`. Across all `UPDATE openmettle.runs`
callers in `src/authz/approvals.rs`, `src/authz/leases.rs` and `src/authz/runs.rs`, every
single transition into `'waiting'` or terminal (`'succeeded'`, `'failed'`, `'cancelled'`,
`'interrupted'`) executes `UPDATE openmettle.runs SET state = ...` in one SQL statement (never
`RETURNING last_event_sequence`) and appends `run-approval-requested`/`run-waiting` or
`run-terminal` in a *subsequent* SQL statement.

PR2's and PR3's sequential SQL migrations (with zero edits to frozen migrations) therefore
enforce pre-terminal resolution **at the PostgreSQL database layer**:

- **PR2 mixed-version `AFTER UPDATE OF state ON openmettle.runs` `SECURITY DEFINER` trigger
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
- **PR2 one-time migration repair for pre-existing `queued`/`waiting` runs.** In the same PR2
  sequential SQL migration (running as `openmettle_owner`), repair any runs *already* in
  `state IN ('queued', 'waiting')` at migration time that have revision-zero (`revision = 0`)
  `capability = 'repeatable_read'` operations in `outcome = 'intent'` by transitioning those
  operations to `outcome = 'failed'` (`revision = 1`, with non-empty redacted observation
  evidence) and appending their `abandoned-read:<operation_id>` `run_events` rows — updating
  `runs.last_event_sequence` with exact [ADR 0004](0004-run-persistence.md)
  `openmettle/observation/1\0` length-prefixed `identity` and SHA-256 `digest` — **while the
  run is still `queued`/`waiting`**, strictly before any `run-terminal` event exists (pre-PR2
  terminal runs never created `tool-spill:*` reservations and are left untouched).
- **PR3 mixed-version `AFTER UPDATE OF state ON openmettle.runs` `SECURITY DEFINER` trigger
  for direct terminal `'interrupted'` write resolution (preserving exact `{"unresolved": n}`
  parity across `N-1` and `N`).** PR3's sequential SQL migration installs/extends an **`AFTER
  UPDATE OF state ON openmettle.runs FOR EACH ROW`** `SECURITY DEFINER` trigger
  (`openmettle.resolve_interrupted_write_intents()`, `WHEN (OLD.state IS DISTINCT FROM
  'interrupted' AND OLD.state NOT IN ('succeeded', 'failed', 'cancelled') AND NEW.state =
  'interrupted')`, owned by `openmettle_owner`, `SET search_path = pg_catalog`, `REVOKE ALL
  FROM PUBLIC`, audited in `src/boundaries.sql`) that fires across **both `N-1` and `N`
  workers strictly before `run-terminal` is appended**: for **every remaining**
  `openmettle.operations` row on `(NEW.scope_id, NEW.id)` with
  `capability IN ('idempotent', 'lookup', 'non_repeatable') AND outcome = 'intent' AND
  revision = 0 ORDER BY id`, it transitions the row **unconditionally to
  `outcome = 'outcome_unknown'`, `revision = 1`** — **NEVER to `'failed'` inside the
  trigger** — with bounded redacted observation evidence, increments
  `openmettle.runs.last_event_sequence` and inserts its idempotent
  `interrupted-write:<operation_id>` [ADR 0004](0004-run-persistence.md)
  `openmettle/observation/1\0` `run_events` row strictly before `run-terminal`. This
  unconditional `'intent' -> 'outcome_unknown'` rule preserves exact `{"unresolved": n}`
  event/ledger parity across **both** worker versions:
  - On **`N` workers**, `leases::settle_locked` (on direct-terminal settlement) and
    `leases::settle_expired` already transitioned any non-null `dispatched_attempts = 0` write
    rows to `outcome = 'failed'` (`revision = 1`) *before* computing `u.n` and updating
    `runs.state`, so only `dispatched_attempts IS NULL OR dispatched_attempts >= 1` rows remain
    in `'intent'` when the trigger fires, and `'intent' -> 'outcome_unknown'` preserves `u.n`
    (`Δn = 0`).
  - On **`N-1` workers** during PR3's mixed-version rollout, frozen `N-1` `settle_expired` and
    `settle_locked` (`src/authz/leases.rs:649-694`,
    [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md)) compute `u.n` from
    `unresolved!()` (`outcome IN ('intent', 'outcome_unknown')`) *before*
    `UPDATE openmettle.runs SET state = 'interrupted'` fires the `AFTER UPDATE` trigger without
    inspecting `dispatched_attempts`, and then emit `openmettle.run-interrupted` with
    `{"unresolved": u.n}` from that saved count. Rewriting a `dispatched_attempts = 0` row to
    `'failed'` inside the trigger would drop the DB's unresolved count below `u.n` and emit a
    false `{"unresolved": 1}` when zero unresolved rows remained; instead, transitioning every
    remaining `'intent'` write row unconditionally to `'outcome_unknown'` (`revision = 1`)
    conservatively records unknown provenance strictly before `run-terminal` **and** keeps the
    post-settlement `outcome IN ('intent', 'outcome_unknown')` count strictly equal to
    `N-1`'s emitted `{"unresolved": u.n}` payload (`Δn = 0`).

Together, these triggers and PR2's one-time repair guarantee across pre-existing rows and
mixed-version `N-1`/`N` worker and API binaries that `runs.last_event_sequence ==
terminal_sequence` (`204 No Content` on terminal SSE cursor reconnect), `openmettle_api`
retains zero `UPDATE` grant on `openmettle.operations` in `src/boundaries.sql`, write
operations are never modified on `'waiting'`, `'succeeded'`, `'failed'` or `'cancelled'`
transitions, `openmettle.run-interrupted`'s `{"unresolved": n}` payload matches the
post-settlement `unresolved!()` count in `openmettle.operations` across both `N-1` and `N`
workers, and `storage::release` continues to protect every unresolved write (including every
`outcome_unknown` write transitioned on an `'interrupted'` run) with `Error::Unresolved`.

**Ledger-safe spill cleanup (`artifact_fs::reconcile_run_spills`).** Because
`artifact_fs::reconcile_expired` scans only upload reservations (`run_id IS NULL`) and
`run_id IS NOT NULL` matches all run-linked reservations (not only spills), PR2 adds
`artifact_fs::reconcile_run_spills` to the worker maintenance sweep with strict ledger safety
across both [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md) crash
windows, DB-serialized exclusion against stalled Phase-3 commits (`spill_reclaiming = true`
claimed before any filesystem removal), crash-safe single-inode read-write `File::try_lock()`
exclusion plus `probe_file.set_len(0)?` logical-length truncation (`st_size = 0`, matching
[ADR 0005](0005-artifact-storage-accounting.md)'s logical-byte accounting model) under
`LOCK_EX` before `fs::remove_file`, unconditional durable `sync_dir` of both `staging/` and
`revisions/` before quota decrement (all implemented with stable safe Rust 1.100 `std::fs` +
`std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, MetadataExt}` under `unsafe_code = "forbid"`,
eliminating multi-FD `SIGKILL` `close_files()` ordering, unsynced-unlink resurrection,
pre-`open` thread-pause and Linux NFS read-only `LOCK_EX` gaps), zero post-terminal `run_events`
appends and zero DB transactions held across disk I/O:

- Scan adapter-owned spill reservations matching the `tool-spill:` `idempotency_key` prefix
  with `operation_id IS NOT NULL` across `state = 'reserved'` and `state = 'released'`. Never
  touch `state = 'settled'` rows during spill reconciliation; settled revisions are deleted
  only by `artifact_fs::purge_due` after retention expiry.
- **Spill reservation TTL/age guard.** `openmettle.storage_reservations` records `created_at`
  (`migrations/0004_artifacts_storage_accounting.sql`, with no `expires_at` column). Mirroring
  `artifact_fs::reconcile_expired`'s `older_than` threshold (`src/artifact_fs.rs`),
  `reconcile_run_spills` only sweeps a `state = 'reserved'` `tool-spill:*` row once
  `created_at + spill_reservation_ttl <= clock_timestamp()`, where `spill_reservation_ttl`
  strictly exceeds the maximum single-attempt spill setup/I/O plus worker drain window.
  Because `staging/<reservation_id>` itself is created, locked with `File::try_lock_shared()`
  (`LOCK_SH`) and `sync_dir(&store.staging)`ed **before** Phase 1 commits
  `storage_reservations`, and that single `payload_file` handle retains `LOCK_SH` continuously
  across Phase 2 (including across `fs::rename(&staging_path, &revision_path)` + `sync_dir` on
  uncancelled paths, and never unlinking on cancelled paths), every live or paused Phase-2
  writer continuously blocks sweeper `File::try_lock()` (`LOCK_EX | LOCK_NB`) on the single
  payload inode.
- **3-step DB-claimed single-inode read-write `LOCK_EX` + `set_len(0)` cleanup protocol.** For
  each aged `state = 'reserved'` `tool-spill:*` candidate (either `spill_reclaiming = false` on
  first claim or `spill_reclaiming = true` on retry of an interrupted sweep):
  1. **Step 1 — Claim cleanup in PostgreSQL (`spill_reclaiming = true`) BEFORE any filesystem
     removal:** Open a short lock-ordered DB transaction (`openmettle.runs` first via `FOR NO
     KEY UPDATE`, then `openmettle.storage_reservations` via `FOR UPDATE SKIP LOCKED`, zero
     disk I/O inside the transaction), re-verify `state = 'reserved'`,
     `created_at + spill_reservation_ttl <= clock_timestamp()`, zero `artifact_revisions` row,
     and that the publisher lease is inactive/superseded (run is terminal or
     `lease_expires_at IS NULL OR lease_expires_at <= clock_timestamp()`) or the linked
     operation is resolved (`outcome IN ('succeeded', 'failed')`), and commit
     **`spill_reclaiming = true`** while keeping **`state = 'reserved'` and `max_bytes` fully
     charged** in `storage_accounts.reserved_bytes`! Because Phase 3 (`storage::settle`) locks
     `storage_reservations FOR UPDATE` and enforces `AND NOT spill_reclaiming` strictly on its
     `ReservationState::Reserved` settlement branch (backed by `CHECK (NOT spill_reclaiming OR
     state IN ('reserved', 'released'))`, while preserving `ReservationState::Settled`
     idempotent metadata-matching replay intact), a Phase-3 commit that stalled past TTL after
     its final pre-commit deadline check can **never** commit `state = 'settled'` once Step 1
     commits `spill_reclaiming = true` — and conversely, if Phase 3 already committed
     `state = 'settled'` before Step 1 acquired the lock, Step 1 observes `state = 'settled'`
     and skips the row without touching any file.
  2. **Step 2 — Open non-symlink regular file read-write, acquire `File::try_lock()` (`LOCK_EX`)
     directly on `staging/<id>` and `revisions/<id>`, truncate via `set_len(0)` under `LOCK_EX`,
     remove with `fs::remove_file`, and durably `sync_dir` BOTH `staging/` and `revisions/`
     (outside any DB transaction):** For each `spill_reclaiming = true` `<id>`, inspect
     `<ARTIFACTS_DIR>/staging/<id>` and `<ARTIFACTS_DIR>/revisions/<id>` using safe Rust 1.100
     `std::fs` + `std::os::unix::fs::MetadataExt` (matching `src/artifact_fs.rs:184-191`, zero
     `unsafe`): first validate `fs::symlink_metadata(dir)` on `staging/` and `revisions/`
     (`file_type().is_dir()` and matching `(dev(), ino())`; if either directory check fails,
     abort cleanup for `<id>` on this pass without proceeding to Step 3), then evaluate each
     candidate `path` (`staging/<id>` and `revisions/<id>`):
     - Query `sym_meta = fs::symlink_metadata(&path)` (which does not follow symlinks). If
       `ErrorKind::NotFound`, record **confirmed absent** for `path` (not renamed yet, already
       renamed to the other directory, or already removed by an earlier sweeper pass after
       `spill_reclaiming = true` that may have crashed *before* `sync_dir`). On any other
       metadata I/O error or `!sym_meta.file_type().is_file()`, **abort cleanup for `<id>` on
       this pass** without calling `sync_dir` or Step 3 `storage::release`.
     - Open read-write via `fs::OpenOptions::new().read(true).write(true).open(&path)` (a
       writable handle satisfies both local Linux `File::try_lock()` exclusive locking and
       Linux NFS `F_WRLCK` byte-range translation, which rejects exclusive locks on read-only
       descriptors). If `open(&path)` returns `ErrorKind::NotFound`, record **confirmed absent**
       for `path`; on any other I/O error, abort cleanup for `<id>` on this pass. Otherwise
       verify `fd_meta = probe_file.metadata()?` satisfies `fd_meta.file_type().is_file() &&
       (fd_meta.dev(), fd_meta.ino()) == (sym_meta.dev(), sym_meta.ino())` (if `path` was
       swapped with a symlink between `symlink_metadata` and `open`, `symlink_metadata`
       returned the symlink's own inode whereas `probe_file.metadata()` returns the target's
       inode, rejecting any symlink race without `unsafe`); on any metadata I/O error,
       non-regular file or `(dev(), ino())` mismatch, drop `probe_file` and abort cleanup for
       `<id>` on this pass.
     - Call **`probe_file.try_lock()`** (stable safe Rust 1.100 `LOCK_EX | LOCK_NB`, zero
       `unsafe`). If `try_lock()` returns **`TryLockError::WouldBlock`** (a live or paused
       Phase-2 writer still holds `LOCK_SH` on `payload_file` — including across `fs::rename` +
       `sync_dir` — OR a concurrent sweeper holds `LOCK_EX`) or any other lock error, drop
       `probe_file` and **abort cleanup for `<id>` on this pass**, keeping `state = 'reserved'`
       (`spill_reclaiming = true`) and `max_bytes` **fully charged** in
       `storage_accounts.reserved_bytes`!
     - Once **`LOCK_EX` succeeds on `probe_file`**:
       1. Re-verify `fs::symlink_metadata(&path)` still succeeds with `file_type().is_file()`
          and exact `(dev(), ino()) == (fd_meta.dev(), fd_meta.ino())` under `LOCK_EX`. If this
          post-lock recheck returns **any error** (including `ErrorKind::NotFound` or an I/O
          error), a non-regular file, or a **different `(dev(), ino())`** before `set_len(0)`,
          treat the path as **inconclusive on this pass**: drop `probe_file` without truncating
          or removing and **abort cleanup for `<id>` on this pass** without calling `sync_dir`
          or Step 3 `storage::release` (keeping `state = 'reserved'`, `spill_reclaiming = true`
          and `max_bytes` **fully charged** so the next retry pass cleanly re-probes the
          directory entry and confirms `NotFound` or locks the current inode).
       2. Call **`probe_file.set_len(0)?`** while holding `LOCK_EX` **before
          `fs::remove_file(&path)`** (requiring `Ok(())`). Unlike removal alone (which leaves an
          open inode's size unchanged until final close), `probe_file.set_len(0)?` reduces the
          open inode's **logical byte length (`st_size` / `Metadata::len()`) to `0` bytes**
          under `LOCK_EX` (matching [ADR 0005](0005-artifact-storage-accounting.md)'s
          logical-byte accounting model; physical block reuse remains filesystem- and
          journal-dependent), while `fs::remove_file` + `sync_dir` on both `staging/` and
          `revisions/` make directory removal durable before `storage::release` commits.
          Moreover, because the writer holds only **one** file handle (`payload_file`) with no
          separate sidecar `.lock` handle, `SIGKILL` `close_files()`
          (`linux/fs/file.c#L440-L466`) has zero multi-FD teardown ordering gap
          (`locks_remove_file` runs when `payload_file` itself closes, and `set_len(0)` zeroes
          the open inode's logical byte length before `fs::remove_file` removes the directory
          entry, so even a sweeper crash between `fs::remove_file` and Step 3 leaves a `0`-byte
          inode).
       3. Call **`fs::remove_file(&path)`** (requiring `Ok(())`) and **`drop(probe_file)`**,
          recording **confirmed truncated and unlinked** for `path`.
     - **Confirmed-clean gate and unconditional durable directory sync before Step 3:** For
       `<id>` to advance to `sync_dir` and Step 3 `storage::release`, **each** of the two
       candidate paths (`staging/<id>` and `revisions/<id>`) MUST finish Step 2 in one of two
       **confirmed-clean** outcomes:
       1. **Confirmed absent (`ErrorKind::NotFound`)** on `fs::symlink_metadata(&path)` or
          `OpenOptions::open(&path)` (and not concurrently replaced), **OR**
       2. **Confirmed truncated and unlinked under `LOCK_EX`**: post-lock
          `fs::symlink_metadata(&path)` under `LOCK_EX` succeeded with `file_type().is_file()`
          and exact `(dev(), ino()) == (fd_meta.dev(), fd_meta.ino())`,
          `probe_file.set_len(0)` returned `Ok(())`, and `fs::remove_file(&path)` returned
          `Ok(())`.
       If **either** candidate path hits `TryLockError::WouldBlock`, **any I/O error** (on
       `symlink_metadata`, `open`, `metadata`, `try_lock`, `set_len(0)`, or `remove_file`), a
       non-regular file, or an **inconclusive/mismatched post-lock `(dev(), ino())` check**
       (including `NotFound` or a different inode on the post-lock recheck before `set_len(0)`),
       Step 2 **MUST abort cleanup for `<id>` on this pass** without calling `sync_dir` or
       Step 3 `storage::release`, keeping `state = 'reserved'`, `spill_reclaiming = true` and
       `max_bytes` **fully charged** in `storage_accounts.reserved_bytes` for retry. Once
       **both** candidate paths reach a confirmed-clean outcome, **ALWAYS execute and require
       successful `sync_dir(&store.staging)` AND `sync_dir(&store.revisions)` before proceeding
       to Step 3 `storage::release` — including on retry passes where one or both candidate
       paths finished in confirmed `ErrorKind::NotFound`**. If an earlier sweeper removed
       `staging/<id>` or `revisions/<id>` and crashed before `sync_dir`, skipping `sync_dir` on
       `NotFound` would allow Step 3 to release quota while a subsequent storage-host crash
       could still resurrect the unsynced directory entry. If either `sync_dir` fails, abort
       cleanup for `<id>` on this pass with `state = 'reserved'`, `spill_reclaiming = true` and
       `max_bytes` still fully charged.
  3. **Step 3 — Commit `storage::release` in a short lock-ordered DB transaction:** Open a
     short lock-ordered DB transaction (`openmettle.runs` `FOR NO KEY UPDATE` ->
     `openmettle.storage_reservations` `FOR UPDATE SKIP LOCKED`, zero disk I/O inside the DB
     transaction), re-verify `state = 'reserved' AND spill_reclaiming` and commit
     `storage::release` (`state = 'released'`, subtracting `max_bytes` from `reserved_bytes`
     now that the open inode's logical byte length has been reduced to `0` via `set_len(0)`,
     the directory entry has been removed with `fs::remove_file`, and both `staging/` and
     `revisions/` have been durably `sync_dir`ed, without calling `runs::record_observation` or
     appending any `run_events`). Because every abandoned `repeatable_read` was transitioned to
     `outcome = 'failed'` strictly before `run-terminal`, `storage::release` succeeds cleanly
     after TTL on terminal runs while preserving `runs.last_event_sequence == terminal_sequence`
     (`204 No Content` on terminal SSE cursor reconnect) and continuing to fail closed with
     `Error::Unresolved` on any unresolved `idempotent`, `lookup` or `non_repeatable` write
     (including `outcome_unknown` writes).
- **HTTP upload `Store::stage` shared-lock alignment, defense-in-depth `state = 'released'`
  pass, and aged `> 900 s` orphan `staging/` sweep (`LOCK_EX` before primary PostgreSQL
  recheck, `storage_instance FOR UPDATE` zero-row serialization, and distinct settled retry
  inode reclamation).**
  - **PR2 `Store::stage` shared-lock update (`src/artifact_fs.rs:144-158`):** Update
    `Store::stage` so HTTP uploads also open `staging/<id>` with
    `fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600)` and
    immediately acquire `file.try_lock_shared()` (`LOCK_SH | LOCK_NB`, returning
    `Error::InProgress` if locked), holding `LOCK_SH` while streaming so any live HTTP upload
    blocks sweeper `File::try_lock()`.
  - **Defense-in-depth `state = 'released'` pass:** Retain the `state = 'released'` retry pass
    to verify non-symlink regular-file `(dev, ino)` identity, acquire read-write
    `probe_file.try_lock()`, re-verify `(dev, ino)`, call `probe_file.set_len(0)?` ->
    `fs::remove_file(&path)` -> `drop(probe_file)` -> `sync_dir(&store.staging)` +
    `sync_dir(&store.revisions)` (outside any DB transaction) on any remaining `staging/<id>`
    or unsettled `revisions/<id>` files.
  - **Aged `> 900 s` orphan `staging/` sweep:** Sweep any aged `> 900 s` orphan `staging/<id>`
    directory entries older than the `900 s` staging grace window using a strict
    **lock-before-DB-recheck**, **`storage_instance FOR UPDATE` zero-row serialization**, and
    **inode-identity-before-truncate** order:
    1. Validate `staging/` via `fs::symlink_metadata(&store.staging)` (`file_type().is_dir()`
       and expected `(dev(), ino())`), check `sym_meta = fs::symlink_metadata(&staging_path)?`
       has `sym_meta.file_type().is_file()`, open read-write via
       `fs::OpenOptions::new().read(true).write(true).open(&staging_path)?` -> `probe_file`,
       verify `probe_meta = probe_file.metadata()?` satisfies
       `probe_meta.file_type().is_file() && (probe_meta.dev(), probe_meta.ino()) ==
       (sym_meta.dev(), sym_meta.ino())` (capturing `(probe_dev, probe_ino)`), and attempt
       **`probe_file.try_lock()`** (`LOCK_EX | LOCK_NB`); on `TryLockError::WouldBlock`, drop
       `probe_file` and skip immediately (a live pre-Phase-1, Phase 1, Phase 2, or HTTP upload
       writer still holds `LOCK_SH`).
    2. **While continuing to hold `LOCK_EX` on `probe_file`, query primary PostgreSQL**
       (`SELECT state FROM openmettle.storage_reservations WHERE id = $1`). On any DB query
       error, drop `probe_file` and skip conservatively without touching disk.
    3. **Serialize zero-row (`None`) observations against committing Phase 1 via
       `storage_instance FOR UPDATE`:** If Phase 1 lost its commit ack while its PostgreSQL
       backend stalled mid-commit and the publisher's lost-ack recovery timed out and dropped
       `LOCK_SH` (leaving `staging/<id>` on disk), an unlocked `READ COMMITTED` `SELECT` could
       observe zero rows right before Phase 1's `COMMIT` becomes visible. However, PostgreSQL
       never commits an uncommitted session if `tx.commit()` was never sent
       (`SET LOCAL idle_in_transaction_session_timeout = '5s'`, `src/authz/leases.rs:201-215`),
       and **every** `storage::reserve` call that reaches `tx.commit()` already holds `FOR
       UPDATE` on the singleton `openmettle.storage_instance` row (`WHERE id`,
       `src/storage.rs:150`, the terminal leaf lock of `storage::reserve`) until its `COMMIT`
       finishes (`openmettle_worker` already holds `SELECT` + `UPDATE` on
       `openmettle.storage_instance` in `src/boundaries.sql`). Therefore, whenever the initial
       query returns **zero rows (`None`)**, the sweeper **MUST serialize against any
       in-flight committing Phase 1 backend** before treating `staging/<id>` as an uncommitted
       orphan: open a short primary `READ COMMITTED` transaction, **first execute
       `SELECT 1 FROM openmettle.storage_instance WHERE id FOR UPDATE`** (blocking until any
       in-flight `storage::reserve` `COMMIT` completes, with zero lock cycle because
       `storage_instance` is a leaf lock and the sweeper holds no prior DB locks; on lock
       timeout or any DB error, drop `probe_file` and skip `<id>` conservatively without
       unlinking), and **in a separate subsequent SQL statement** inside that transaction
       re-execute `SELECT state FROM openmettle.storage_reservations WHERE id = $1`. Use that
       post-`storage_instance`-lock result for the disposition below.
    4. **Disposition by primary PostgreSQL state under `LOCK_EX`:**
       - **`state = 'reserved'`:** **Always skip** — drop `probe_file` immediately with
         **zero** `set_len(0)` and **zero** `fs::remove_file` (`reconcile_run_spills` /
         `reconcile_expired` owns cleanup).
       - **`state = 'settled'`:** Distinguish **published Inode A** (where `probe_file` was
         opened before `fs::rename` moved Inode A out of `staging/` into `revisions/<id>` and
         Phase 3 committed `storage::settle`) from a **separate stranded HTTP-upload retry
         Inode B** still sitting at `staging/<id>` (which can arise if a concurrent HTTP upload
         retry observed `ReservationState::Reserved` at `src/artifact_fs.rs:468`, paused before
         `store.stage(&id)`, created a distinct Inode B in `staging/<id>` after Upload 1
         already renamed Inode A to `revisions/<id>` and committed `storage::settle`, and then
         crashed via `SIGKILL` while streaming). Check **both**:
         - **(a)** `fs::symlink_metadata(&staging_path)` succeeds with `file_type().is_file()`
           and **`(staging_meta.dev(), staging_meta.ino()) == (probe_dev, probe_ino)`**
           (proving `probe_file` was **not** renamed out of `staging/`), **AND**
         - **(b)** `fs::symlink_metadata(&revision_path)` either returns `ErrorKind::NotFound`
           (already retention-purged) **or** returns metadata with
           **`(rev_meta.dev(), rev_meta.ino()) != (probe_dev, probe_ino)`** (proving
           `probe_file` is a **different inode** from the published `revisions/<id>` payload).
         If **either** (a) or (b) fails (for example, `probe_file` was renamed to
         `revisions/<id>`, so `staging/<id>` is `NotFound` and
         `(rev_meta.dev(), rev_meta.ino()) == (probe_dev, probe_ino)`), drop `probe_file`
         immediately with **zero `set_len(0)` and zero `fs::remove_file`**, keeping the
         published `revisions/<id>` payload 100% intact. If **both** (a) and (b) hold under
         `LOCK_EX`, `probe_file` is a proven-distinct dead retry inode stranded at
         `staging/<id>` for an already-settled reservation — execute
         **`probe_file.set_len(0)?`** -> **`fs::remove_file(&staging_path)`** ->
         **`drop(probe_file)`** -> **`sync_dir(&store.staging)`**, leaving `revisions/<id>`
         (Inode A) completely untouched.
       - **Zero rows (`None`, confirmed after `storage_instance FOR UPDATE`) OR
         `state = 'released'`:** Verify `fs::symlink_metadata(&staging_path)` still succeeds
         with `file_type().is_file()` and
         **`(staging_meta.dev(), staging_meta.ino()) == (probe_dev, probe_ino)`**. If
         `NotFound`, non-file, or a different `(dev, ino)`, drop `probe_file` immediately with
         **zero** `set_len(0)` and **zero** `fs::remove_file`. Only when `(dev, ino)` matches
         does the orphan sweep execute **`probe_file.set_len(0)?`** ->
         **`fs::remove_file(&staging_path)`** -> **`drop(probe_file)`** ->
         **`sync_dir(&store.staging)`** (never touching settled `revisions/<id>`).
- **Shared-volume read-write advisory `flock` qualification (`ReadWriteMany`).** Alongside
  [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md)'s existing
  multi-node `ReadWriteMany` qualification of POSIX `rename`, `create_new` (`O_EXCL`) creation
  and `fsync`, deployments running multiple worker pods over a shared network volume MUST
  additionally qualify cross-node/cross-mount read-write advisory locking
  (`File::try_lock_shared()` vs `File::try_lock()`) exclusion semantics before relying on
  shared spill storage.

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
`artifact.read_range` with the returned `artifact_id` and `revision_id`, subject to live
ADR 0035 bound-session and effect authority (`approvals::recheck_replay_effect_authority`),
scope, `Action::Read` and `active` revision rechecks.

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
owner/instance storage quota is exhausted, the process-wide `spill_permits` semaphore is
saturated (`TryAcquireError::NoPermits`) or runtime filesystem publication fails, the worker
**always** records the tool's true observation in `operations` first (so a committed external
write is never hidden, falsely marked failed or re-dispatched), includes the redacted
`spill_error` (`store_unconfigured`, `quota_exceeded`, `spill_saturated` or `storage_io`) in
observation evidence and returns a bounded fallback envelope (`<= 16_384` serialized JSON
bytes) with `storage: "truncated_no_spill"`, `truncated: true`, `artifact_id: null`,
`revision_id: null`, the same UTF-8-safe `head`/`tail` preview, `omitted_bytes` and
`content_sha256`. Truncation is always explicit; partial output is never labeled complete.

## Delivery and verification

| Slice | Deliverable | Acceptance evidence |
| --- | --- | --- |
| PR1 | This ADR (`0039`). | Review against #14, #25, ADRs 0010, 0031, 0033, 0035 and 0038; `ai-guardrails docs audit` reports zero findings. |
| PR2 | PR2's next sequential schema migration (e.g., `0024`) adding nullable `openmettle.operations.dispatched_attempts integer DEFAULT NULL CHECK (dispatched_attempts BETWEEN 0 AND 3)` with a `BEFORE UPDATE` monotonicity trigger forbidding `non-null -> NULL` or decrements (Transaction 1 in PR2 `approvals::record_fenced_intent` commits `outcome = 'intent'` with `dispatched_attempts = 0` only for `repeatable_read`, leaving writes `DEFAULT NULL` until PR3, distinct from Step 5 Transaction 2's pre-send increment), `openmettle.storage_reservations.spill_reclaiming boolean NOT NULL DEFAULT false` with `CHECK (NOT spill_reclaiming OR state IN ('reserved', 'released'))`, their matching `src/boundaries.sql` grants (`INSERT`/`UPDATE (dispatched_attempts)` and `UPDATE (spill_reclaiming)` for `openmettle_worker`, `$1 >= <v1_14_schema_version>`), the `AFTER UPDATE OF state ON openmettle.runs FOR EACH ROW` `SECURITY DEFINER` trigger `openmettle.resolve_abandoned_repeatable_reads()` (owned by `openmettle_owner`, `SET search_path = pg_catalog`, `REVOKE ALL FROM PUBLIC`, audited in `src/boundaries.sql`, preserving `openmettle_api`'s zero `UPDATE` grant on `openmettle.operations`, resolving abandoned revision-zero `capability = 'repeatable_read'` `outcome = 'intent'` rows to `outcome = 'failed'`, `revision = 1` with idempotent `abandoned-read:<operation_id>` ADR 0004 `identity`/`digest` observation `run_events` strictly before `run-waiting` / `run-terminal` uniformly across mixed-version `N-1` and `N` worker/API binaries without duplicate Rust-caller SQL updates) and one-time upgrade repair (as `openmettle_owner`) of pre-existing `state IN ('queued', 'waiting')` runs, `StepResult::Invalidated` and its `worker::execute` (`src/worker.rs`) mapping to `WorkEnd::Stop(Stop::LeaseLost)`, reviewed tool registry (`EffectPolicy`) enforcing OpenMettle's restricted stateless MCP `2026-07-28` interoperability profile (omitting `Mcp-Param-*` and failing closed on `x-mcp-header` schemas), strict schema/argument validator and default expander, `approvals::recheck_replay_effect_authority` (executing `authorized(c, &proof, &review)` under `Fence::Step` against the run's bound `originating_session_id`/`deciding_session_id` and provider/approval/user generations before replaying any `succeeded`/`failed` artifact-backed result or `artifact.read_range` bytes, both on `IntentResult::Replayed(op_id)` and during committed-observation / unacknowledged-commit recovery, alongside `hydrate_worker_principal`, `revision.scope_id == run.scope_id`, `Action::Read` and `revision.state == "active"`), `approvals::start_replayed_read` with durable 3-attempt cap (`coalesce(dispatched_attempts, 1) < 3`), internal `artifact.read_range` v1 tool, `artifact_fs::Store::probe_writable`, updating `Store::stage` (`src/artifact_fs.rs:144-158`) so HTTP uploads also open `staging/<id>` via `fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600)` and hold `File::try_lock_shared()` (`LOCK_SH \| LOCK_NB`, returning `Error::InProgress` if locked) while streaming, three-phase `artifact_fs::publish_bytes` (implemented strictly with safe Rust 1.100 `std::fs` + `std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, MetadataExt}` under `unsafe_code = "forbid"` and zero new crates; gated by a process-wide bounded `Arc<tokio::sync::Semaphore>` `spill_permits` bounded to `max_concurrent_runs` / `OPENMETTLE_WORKER_RUN_SLOTS` via non-blocking `try_acquire_owned()` before pre-Phase-1 and Phase 1 — skipping staging creation and Phases 1–3 with zero files, zero `storage_reservations` rows and zero `spawn_blocking` tasks on `NoPermits` into inline `truncated_no_spill`; pre-minting `reservation_id` via `ring::rand::SystemRandom`-backed RFC 9562 UUIDv4 matching `src/telemetry.rs:328-350` and validating `staging/` via `fs::symlink_metadata` + `MetadataExt`, then pre-creating the single 0-byte payload file `staging/<reservation_id>` via `fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&staging_path)` + `payload_file.try_lock_shared()` (`LOCK_SH \| LOCK_NB`) + `sync_dir(&store.staging)` BEFORE Phase 1 inserts `storage_reservations`, raced against `step.deadline` and `step.stop.changed()`, removing `staging/<reservation_id>` with `fs::remove_file` while holding `LOCK_SH` + `drop(payload_file)` + `sync_dir(&store.staging)` on pre-Phase-1 cutoff or deterministic Phase-1 pre-commit error/rollback, while on ambiguous/lost Phase-1 commit ack opening a new primary `READ COMMITTED` transaction that first acquires `SELECT 1 FROM openmettle.runs WHERE scope_id = $1 AND id = $2 FOR NO KEY UPDATE` and then in a separate subsequent SQL statement queries `SELECT state FROM openmettle.storage_reservations WHERE id = $1`, removing `staging/<reservation_id>` under `LOCK_SH` only when that post-lock query succeeds with zero rows (`None`) and keeping `staging/<reservation_id>` intact on disk when committed or when the recovery transaction fails/times out; moving the already-open read-write, `LOCK_SH`-locked `payload_file` and `OwnedSemaphorePermit` directly into Phase 2's `spawn_blocking` closure with zero second `open()` call and zero `.lock` sidecar; no DB txn across disk I/O; per-attempt disjoint `reservation_id`; Phase 2 checking `cancelled.load(Ordering::Acquire)` before writing, before each `<= 64 KiB` chunk and after `payload_file.sync_all()`, skipping `fs::rename` if cutoff fires before the final pre-rename check while if cutoff races after that check — during `fs::rename(&staging_path, &revision_path)` or post-rename `sync_dir(&store.revisions)` / `sync_dir(&store.staging)` — continuing to hold `LOCK_SH` on `payload_file` until `sync_dir` finishes and dropping `payload_file` + `OwnedSemaphorePermit` (in both cases performing zero `fs::remove_file` and unconditionally disabling Phase 3); racing Phase 2's `spawn_blocking` `JoinHandle` in `tokio::select!` against `tokio::time::sleep_until(step.deadline)` and `step.stop.changed()` via shared `Arc<AtomicBool>` (`cancelled`), detaching on cutoff while keeping `<reservation_id>` in `state = 'reserved'` and immediately running the inline `truncated_no_spill` fallback during the drain window; Phase 3 locking `storage_reservations FOR UPDATE` where `storage::settle` preserves its existing `ReservationState::Settled` idempotent metadata-matching replay branch (`src/storage.rs:362-379`, `tests/schema/artifact_fs.rs:434`) and enforces `AND NOT spill_reclaiming` strictly on its `ReservationState::Reserved` settlement branch, rolling back both `storage::settle` and `runs::record_observation` if `spill_reclaiming = true`, plus local `step.deadline`/`step.stop` rechecks after normal Phase 2 completion, under the Phase 3 `Fence::Step` lock before settling and again inside the Phase 3 closure after `storage::settle` + `runs::record_observation` complete their SQL statements immediately before commit, rolling back on cutoff; single atomic `Fence::Step` commit of `storage::settle` + `runs::record_observation`; spill-abort disposition committing inline `truncated_no_spill` under `Fence::Step` + `StepResult::Continue` when only shortened `step.deadline` elapsed and `step.stop` remains `None`, under `Fence::Hold` + `StepResult::Stopped` when `step.stop` is `Some(Stop::Shutdown)`, `Some(Stop::Cancel)` or `Some(Stop::Deadline)` or `LeaseError::Stopping(_)`, and returning `StepResult::Invalidated` on `Stop::LeaseLost`, `StaleClaim`, `Expired` or `Terminal`, with mandatory `*step.stop.borrow()` rechecks inside the fallback's `leases::fenced` closure both immediately after `leases::lock` acquires the `runs` row lock and immediately after `runs::record_observation` completes right before commit; deterministic `WorkEnd::Incomplete` drain-window expiry recovery for `repeatable_read`), 3-step DB-claimed single-inode read-write `LOCK_EX` + `set_len(0)` `reconcile_run_spills` (Step 1: lock-ordered DB tx `runs` -> `storage_reservations` claiming `spill_reclaiming = true` while keeping `state = 'reserved'` and `max_bytes` charged BEFORE any filesystem removal; Step 2: outside DB tx, validating non-symlink regular-file `(dev(), ino())` via `fs::symlink_metadata` + `fs::OpenOptions::new().read(true).write(true).open(&path)` + `probe_file.metadata()` on `staging/<id>` and `revisions/<id>` + `probe_file.try_lock()` (`LOCK_EX \| LOCK_NB`), requiring **each** of the two candidate paths to finish Step 2 in a confirmed-clean outcome — either confirmed absent (`ErrorKind::NotFound` on `symlink_metadata`/`open`) OR confirmed truncated and unlinked under `LOCK_EX` (post-lock `fs::symlink_metadata(&path)` succeeds with `file_type().is_file()` and exact `(dev(), ino()) == (fd_meta.dev(), fd_meta.ino())`, `probe_file.set_len(0)` returns `Ok(())` to zero `st_size` matching ADR 0005, and `fs::remove_file(&path)` returns `Ok(())`) — and aborting cleanup for `<id>` without `sync_dir` or Step 3 `storage::release` (keeping `state = 'reserved'`, `spill_reclaiming = true` and `max_bytes` fully charged) if **either** path hits `TryLockError::WouldBlock`, any I/O error, a non-regular file, or an inconclusive/mismatched post-lock `(dev(), ino())` recheck (including `NotFound` or different inode before `set_len(0)`), and once both paths reach a confirmed-clean outcome unconditionally requiring successful `sync_dir(&store.staging)` AND `sync_dir(&store.revisions)` before Step 3 — including on retry passes where one or both paths returned `ErrorKind::NotFound`, aborting cleanup with `max_bytes` still charged if either `sync_dir` fails; Step 3: short lock-ordered DB tx committing `storage::release` with zero post-terminal `run_events`; plus defense-in-depth `state = 'released'` pass and aged `> 900 s` orphan `staging/` sweep that verifies non-symlink regular-file `(probe_dev, probe_ino)` and acquires `probe_file.try_lock()` *before* querying primary PostgreSQL `SELECT state FROM openmettle.storage_reservations WHERE id = $1`, serializes any zero-row (`None`) observation via a short primary `READ COMMITTED` transaction executing `SELECT 1 FROM openmettle.storage_instance WHERE id FOR UPDATE` followed by a separate subsequent `SELECT state FROM openmettle.storage_reservations WHERE id = $1` (skipping conservatively on lock timeout/error), always skips `state = 'reserved'`, on `state = 'settled'` checks **both** (a) `fs::symlink_metadata(&staging_path)` succeeds with `file_type().is_file()` and `(dev(), ino()) == (probe_dev, probe_ino)` AND (b) `fs::symlink_metadata(&revision_path)` returns `NotFound` or `(dev(), ino()) != (probe_dev, probe_ino)` (skipping with zero `set_len(0)` / zero `fs::remove_file` if either fails, and reclaiming only a proven-distinct dead retry inode while leaving published `revisions/<id>` untouched), and on confirmed zero rows (`None`) or `state = 'released'` verifies `(staging_meta.dev(), staging_meta.ino()) == (probe_dev, probe_ino)` before `probe_file.set_len(0)?` -> `fs::remove_file(&staging_path)` -> `drop(probe_file)` -> `sync_dir(&store.staging)`), shared-volume read-write advisory `flock` qualification requirement alongside ADR 0031, and serialized-budget head/tail preview builder. | PostgreSQL 18 tests: cross-user, cross-scope, archived/deleted project, private project-scope spill ownership (other members denied until shared), share revocation and `active` -> `retained` transition between original read and replay, **bound/originating session logout after `artifact.read_range` (or spilled tool output) commits its observation while artifact `Action::Read` access and `revision.state == "active"` remain valid** (proving `approvals::recheck_replay_effect_authority` causes both `IntentResult::Replayed` and committed-observation / unacknowledged-commit recovery to refuse replay with zero cached bytes returned), and non-`active` revision refusals; `max_bytes < 4` validation refusal, invalid UTF-8 binary semantic fault and strictly inline `artifact.read_range` under both 6x JSON escaping and `<= 200`-line `next_offset` pagination; unfinished `repeatable_read` replay through `approvals::start_replayed_read` (rechecking bound session and canonical proposal without issuing a write permit) plus crash-reclaim test at `dispatched_attempts == 3` proving dispatch refusal, terminal `failed` observation under `Fence::Step` and zero outbound sends; catalog registration rejection of `x-mcp-header` schemas under the restricted stateless profile plus duplicate-key, float, depth, bound and wildcard rejections; serialized-JSON `16 KiB` inline/spill thresholds (`\u001b` expansion, `200` lines, multi-byte UTF-8 cuts); startup `Store::probe_writable` fail-closed test on pre-existing read-only `staging/` and `revisions/`; unset-`ARTIFACTS_DIR`, unconfigured-store, quota-refused, `spill_saturated` and I/O fallback envelopes; existing `storage::settle` `ReservationState::Settled` idempotent HTTP upload replay (`tests/schema/artifact_fs.rs:434`) preserved alongside `AND NOT spill_reclaiming` on `ReservationState::Reserved`; Phase 3 rollback/crash simulation verifying `storage::settle` and `runs::record_observation` commit atomically inside one `Fence::Step` transaction so at most one active revision and one storage quota charge ever commit per operation (zero double-charged spill revisions on replacement-worker replay); `publish_bytes` and `reconcile_run_spills` Phase 1/2/3 stall, single-inode locking, cleanup-claim, orphan-sweep, saturation, `SIGKILL` and takeover tests covering (a) delaying Phase 2 `spawn_blocking` disk I/O past **both** the `5 s` PostgreSQL `idle_in_transaction_session_timeout` and the worker drain deadline during lease takeover (proving replacement worker settlement succeeds intact with its own disjoint `reservation_id` and the stalled old worker returns `StepResult::Invalidated` with zero corrupted/unlinked revisions and zero leaked settled quota), (b) **both race orders between a stalled Phase-3 commit and Step-1 `spill_reclaiming` claim** (when Step 1 commits `spill_reclaiming = true` first, stalled Phase 3 fails closed on `ReservationState::Reserved` + `AND NOT spill_reclaiming` / table `CHECK` constraint and rolls back both `storage::settle` and `runs::record_observation` before applying the spill-abort disposition while `reconcile_run_spills` cleans up and releases; when Phase 3 commits `state = 'settled'` first, Step 1 sees `state = 'settled'` and skips without removing `revisions/<id>`), (c) **pre-Phase-1 `sync_dir(&store.staging)` before `storage::reserve` and serialized lost Phase-1 commit-ack primary recheck**: verifying `staging/<id>` is created `0600` via `create_new(true)`, `LOCK_SH`-locked and `sync_dir`ed before Phase 1, that deterministic pre-commit failure (`OMQ01` / `Fence::Step` rejection) removes `staging/<id>` under `LOCK_SH`, and — delaying Phase 1's commit across the start of the lost-ack recovery transaction — proving the `SELECT 1 FROM openmettle.runs ... FOR NO KEY UPDATE` wait followed by the subsequent `SELECT state FROM openmettle.storage_reservations` statement prevents premature `0`-row observation and preserves `staging/<id>` intact on disk when Phase 1 commits (and also preserves `staging/<id>` when the recovery transaction fails/times out, removing only when the post-lock query succeeds with zero rows), (d) **single-handle `LOCK_SH` / `LOCK_EX` + `set_len(0)` before `fs::remove_file` + confirmed-clean Step 2 gate + unconditional `NotFound` retry `sync_dir` across cutoff (including cutoff during post-rename `sync_dir`), paused `fsync`, `<= 64 KiB` chunk-boundary cancellation, and subprocess `SIGKILL` crash qualification**: stalling a cancelled Phase-2 writer mid-chunk, during `payload_file.sync_all()`, **and during post-rename `sync_dir(&store.revisions)` / `sync_dir(&store.staging)`** past `spill_reservation_ttl`, racing out of `tokio::select!` within the drain window to commit inline `truncated_no_spill` (proving Phase 3 never runs even when cutoff arrives during post-rename `sync_dir`), running `reconcile_run_spills` while `payload_file` still holds `LOCK_SH` and asserting `spill_reclaiming = true`, `state = 'reserved'` and `max_bytes` remain fully charged (`TryLockError::WouldBlock` on sweeper read-write `File::try_lock()`), then verifying that once the writer finishes/exits and drops `payload_file` (or a child worker subprocess is terminated with `SIGKILL`) `reconcile_run_spills` acquires `LOCK_EX` on `staging/<id>` or unsettled `revisions/<id>`, zeroes logical byte length (`st_size = 0`) via `set_len(0)` before `fs::remove_file`, `sync_dir`s both `staging/` and `revisions/`, and drops quota charge to zero; PLUS **Step 2 post-lock `symlink_metadata` failure / inode-mismatch guard test** injecting a post-lock `symlink_metadata` I/O error or mismatched `(dev(), ino())` while both `sync_dir`s would succeed, asserting `storage::release` is **NOT** called and `reserved_bytes` remains unchanged until a subsequent clean pass confirms removal/absence; PLUS a retry test simulating an unsynced prior removal (confirmed `ErrorKind::NotFound` on both `staging/<id>` and `revisions/<id>`) verifying both `staging/` and `revisions/` are `sync_dir`ed before Step 3 `storage::release` commits (and that a `sync_dir` failure on either directory aborts cleanup before `storage::release` with `max_bytes` still charged), (e) **aged `> 900 s` orphan `staging/` sweep `LOCK_EX`-before-DB-recheck, `storage_instance FOR UPDATE` zero-row serialization, published-vs-retry `'settled'` inode-identity tests**: racing (i) an aged `staging/<id>` whose Phase 1 `storage::reserve` commits while holding `LOCK_SH` right before writer cutoff (proving the orphan sweep acquires `LOCK_EX` *before* querying primary PostgreSQL, observes `state = 'reserved'` and skips removing), (ii) **Phase 1 commit-stall / lost-ack recovery timeout interleaving**: stalling Phase 1 mid-commit while publisher lost-ack recovery times out and drops `LOCK_SH` (leaving `staging/<id>` on disk), running the aged orphan sweeper so it acquires `LOCK_EX`, observes initial zero rows, serializes on `SELECT 1 FROM openmettle.storage_instance WHERE id FOR UPDATE`, observes `state = 'reserved'` after Phase 1 commits, and preserves `staging/<id>` intact, (iii) **pausing the orphan sweeper between opening `staging/<id>` and `try_lock()`, letting the live publisher finish `fs::rename(&staging_path, &revision_path)` and Phase 3 `storage::settle` (`state = 'settled'`), resuming the orphan sweeper, and verifying the published `revisions/<id>` payload's exact bytes and SHA-256 digest remain intact** (zero `set_len(0)`, zero `fs::remove_file`), PLUS a **crashed concurrent HTTP-upload retry test** where Retry 2 staged a distinct `staging/<id>` inode (Inode B) after Upload 1 settled Inode A (`state = 'settled'`), proving the aged sweep reclaims `staging/<id>` (Inode B) while preserving `revisions/<id>` (Inode A) bytes and SHA-256 intact (and confirming a live streaming HTTP upload holds `LOCK_SH` via `Store::stage` and blocks `LOCK_EX`), and (iv) verifying the `fs::symlink_metadata(&staging_path)` `(dev(), ino())` guard skips `set_len(0)` when `staging/<id>` is `NotFound`, a symlink, or replaced by a different inode, while an unreferenced pre-Phase-1 crash file with confirmed post-`storage_instance`-lock zero primary DB rows (or `state = 'released'`) and matching `(dev(), ino())` is truncated (`st_size = 0`) and removed under `LOCK_EX`, (f) local `step.deadline` expiry and `step.stop` firing while the DB lease is still live — including both pre-settlement cutoff and **holding the `storage_accounts` row lock across the local cutoff while the DB lease stays live** (proving Phase 3's final pre-commit check returns `Err` and rolls back both the `artifact_revisions` row and the `storage_accounts`/`storage_instance` quota charge, leaving `storage_reservations` in `state = 'reserved'`) — and asserting the exact resulting run and lease state alongside quota assertions: when only shortened `step.deadline` elapsed (`step.stop` stays `None`) on a completed known-outcome write with active `Fence::Step` lease, inline `truncated_no_spill` commits under `Fence::Step`, returns `StepResult::Continue` and leaves the run `running` with its active lease intact (zero `StoreError::InvalidInput("settle")` from `leases::decide`); when `step.stop` is `Some(Stop::Shutdown)`, `Some(Stop::Cancel)` or `Some(Stop::Deadline)` or `LeaseError::Stopping(_)`, inline `truncated_no_spill` commits under `Fence::Hold`, returns `StepResult::Stopped` and `run_one` hands off or settles cleanly; when the DB lease is lost (`StaleClaim`, `Expired`, `Terminal` or `Stop::LeaseLost`), `StepResult::Invalidated` -> `WorkEnd::Stop(Stop::LeaseLost)` exits with zero further PostgreSQL writes, (g) **blocking the inline `truncated_no_spill` fallback on a competing `FOR NO KEY UPDATE` lock on `openmettle.runs` while signaling `Stop::LeaseLost` locally with PostgreSQL `lease_expires_at` still in the future (inside `worker::monitor`'s safety margin)**, then releasing the competing lock and verifying the fallback rolls back with `StepResult::Invalidated` leaving `operations`, `run_events` and `runs.last_event_sequence` completely untouched (plus verifying a `Fence::Step` tool-deadline fallback that receives `Stop::Shutdown`, `Stop::Cancel` or `Stop::Deadline` while waiting on the lock commits under the held run lock and returns `StepResult::Stopped` rather than `StepResult::Continue`), (h) **`WorkEnd::Incomplete` drain-expiry contention tests for `repeatable_read`** holding a competing `FOR NO KEY UPDATE` lock on `openmettle.runs` across `run_one`'s full drain window, verifying `WorkEnd::Incomplete` drop, releasing the lock, driving recovery and asserting exact durable `operations.outcome` (safe replay under `Fence::Step` on a `running` run or trigger-resolved `failed` on `'waiting'`/terminal transition when uncommitted `'intent'`; reused committed `succeeded` observation with zero additional outbound sends on unacknowledged commit after fenced `approvals::recheck_replay_effect_authority`, `Action::Read`, and `active` checks), and (i) **spill-semaphore (`spill_permits`) saturation test** (e.g., `1` spill permit) holding the first call's `spawn_blocking` job at `fsync`, triggering shortened `step.deadline` so the run continues (`StepResult::Continue`), executing subsequent large-output calls while the first task stays wedged, and verifying subsequent calls immediately fall back inline (`storage: "truncated_no_spill"`, `spill_error: "spill_saturated"`) with **zero** new staging files, **zero** new `storage_reservations` rows and **zero** queued `spawn_blocking` disk tasks until the first blocking closure drops `payload_file` and exits; crashed `repeatable_read` (`outcome = 'intent'`) + terminal settlement (`leases::settle`, `leases::settle_expired` and `approvals::park` -> immediate terminal `cancel_run`) + `reconcile_run_spills` freeing spill quota with zero stranded bytes and zero post-terminal `run_events`, plus a **populated-upgrade PostgreSQL 18 test** creating a pre-upgrade `waiting` run with a revision-zero `repeatable_read` `intent` and linked `tool-spill:*` reservation, running PR2's migration, immediately cancelling the run via `openmettle_api` (`cancel_run`), running `reconcile_run_spills`, and verifying zero stranded quota AND `204 No Content` on `GET`/`HEAD /v1/runs/{run_id}/events?after=<terminal_cursor>`, AND **mixed-version rolling-upgrade PostgreSQL 18 tests** verifying **(i)** after PR2's migration applies, executing pre-PR2 (`N-1`) `approvals::park` on a `running` run carrying a revision-zero `repeatable_read` `intent`, followed by API cancel/deny, resolves the intent before `run-waiting` and returns `204 No Content` on `GET`/`HEAD /v1/runs/{run_id}/events?after=<terminal_cursor>` and **(ii)** executing pre-PR2 (`N-1`) `leases::settle_expired` on an expired PR2 (`N`) run holding a `'reserved'` `tool-spill:*` `storage_reservations` row and an abandoned `repeatable_read` `intent`, then running `reconcile_run_spills`, succeeds in `storage::release` with zero stranded quota and returns `204 No Content` on the terminal SSE cursor, while preserving `storage::release` `Error::Unresolved` protection for `interrupted` runs with `outcome_unknown` writes, spill TTL/age guard against active publishers, defense-in-depth `state = 'released'` retryable cleanup, post-rename/pre-settlement cleanup of unsettled `revisions/<id>` and untouched `settled` rows; multi-node/shared-volume deployment qualification explicitly requiring cross-node/cross-mount read-write advisory locking (`File::try_lock_shared()` vs `File::try_lock()`) + `set_len(0)` before `fs::remove_file` exclusion alongside [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md)'s `rename`, `create_new` (`O_EXCL`) and `fsync` checks. |
| PR3 | PR3's sequential SQL migration installing/extending the `AFTER UPDATE OF state ON openmettle.runs FOR EACH ROW` `SECURITY DEFINER` trigger (`openmettle.resolve_interrupted_write_intents()`, `WHEN (OLD.state IS DISTINCT FROM 'interrupted' AND OLD.state NOT IN ('succeeded', 'failed', 'cancelled') AND NEW.state = 'interrupted')`, owned by `openmettle_owner`, `SET search_path = pg_catalog`, `REVOKE ALL FROM PUBLIC`, audited in `src/boundaries.sql`) unconditionally transitioning **all remaining** revision-zero write intents (`capability IN ('idempotent', 'lookup', 'non_repeatable') AND outcome = 'intent' AND revision = 0`) to `outcome = 'outcome_unknown'`, `revision = 1` (never `'failed'` inside the trigger) with bounded redacted observation evidence and ADR 0004 `openmettle/observation/1\0` `run_events` strictly before `run-terminal` so `openmettle.run-interrupted`'s `{"unresolved": n}` payload stays strictly equal to the post-settlement `unresolved!()` count across both `N-1` and `N` workers (`Δn = 0`); PR3 (`N`) two-transaction durable attempt accounting where **Transaction 1 (Step 1 `approvals::record_fenced_intent`)** commits the durable `outcome = 'intent'` row with `dispatched_attempts = 0` for write capabilities (`idempotent`, `lookup`, `non_repeatable`) before returning `Applied` or parking (leaving pre-upgrade and `N-1` write rows at `dispatched_attempts IS NULL`) and **Transaction 2 (Step 5, separate `Fence::Step` transaction before attempt 1 and before each permitted retry)** locks `runs` and `operations` (`FOR UPDATE`), verifies `coalesce(dispatched_attempts, 1) < 3` and commits the monotonic `0 -> 1 -> 2 -> 3` increment under the monotonicity trigger before releasing the PostgreSQL connection and issuing the outbound HTTP send; PR3 (`N`) `leases::settle_locked` first querying `(n_raw, n_zero, time)` without mutating `openmettle.operations` (`n_after = n_raw - n_zero`), unconditionally evaluating `Settle::Succeeded` against `n_raw` without pre-resolution (preserving `Err(StoreError::Conflict("unresolved operation"))` -> `src/worker.rs:676-681`'s `Settle::Stopped` fallback when `state == ExecState::Running` and `n_raw >= 1`, while `Settle::Succeeded` from `ExecState::Reconciling` returns `Err(StoreError::InvalidInput("settle"))` regardless of `n_raw`), and pre-resolving non-null `dispatched_attempts = 0` write intents to `outcome = 'failed'` (`revision = 1` + `openmettle/observation/1\0` `run_events`) passing `n = n_after` to `decide` **iff** `input != Settle::Succeeded && (state == ExecState::Reconciling \|\| !time \|\| (n_after == 0 && (cancel.is_some() \|\| matches!(input, Settle::Failed(_)))))`, otherwise passing `n = n_raw` untouched so `leases::decide` transitions cleanly to non-terminal `Resolution::Reconciling(n_raw)` without mutating intents (covering both uncancelled `Running && Settle::Stopped && time` and mixed-write `n_zero >= 1 && n_after >= 1 && time` under cancellation or `Settle::Failed(_)`), and PR3 (`N`) `leases::settle_expired` pre-resolving non-null `dispatched_attempts = 0` write intents on locked `due` runs to `outcome = 'failed'` (`revision = 1`) before the `SETTLE_EXPIRED` `unresolved` CTE counts `u.n`; Streamable HTTP MCP (`2026-07-28`) adapter over `provider_http::transport` (restricted stateless interoperability profile omitting `Mcp-Param-*` and failing closed on `x-mcp-header` schemas on `tools/list`, enforcing `MAX_TOOL_RESPONSE_BODY_BYTES = 4 MiB` (`4_194_304` decoded HTTP body bytes via `http_body_util::Limited`) alongside fixed `8 KiB` / `32` header bounds and chunked-trailer rejection), `MCP_DNS_SLOTS`, `McpCredentialProvider` seam, `ApprovedAdapter` implementation stopping `outcome_unknown` writes via `StepResult::Stopped` and reusing PR2's `StepResult::Invalidated` -> `WorkEnd::Stop(Stop::LeaseLost)` mapping for deposed workers, destination-authorized read-only `Executor::reconcile` under `Fence::Hold` (adding `dispatched_attempts: Option<i32>` to `leases::UnresolvedOperation` and implementing deterministic `WorkEnd::Incomplete` recovery: strictly non-null `dispatched_attempts == Some(0)` -> `failed` with zero network calls -> `Interrupted(0)` or `Cancelled(r)`; `dispatched_attempts IS NULL OR dispatched_attempts >= 1` with authorized read-only lookup -> `succeeded`/`failed`; `dispatched_attempts IS NULL OR dispatched_attempts >= 1` with no downstream read-only lookup -> `outcome = "outcome_unknown"`, `revision = 1` -> terminal `interrupted` `{"unresolved": 1}` with zero write re-sends), and `PLAN-10` / `PLAN-22` conformance harness on synthetic `rcgen` TLS + PostgreSQL 18. | Synthetic TLS + PostgreSQL 18 tests: MCP `2026-07-28` request headers (`MCP-Protocol-Version: 2026-07-28`, `Mcp-Method`, `Mcp-Name`, no `Mcp-Session-Id`, no `Mcp-Param-*`) **and** body `params._meta` (`io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities = {}`) over `application/json` and `text/event-stream` (SSE comments and progress notifications before final response, mismatched JSON-RPC IDs, duplicate final responses, `input_required` and unexpected server-initiated request rejection, restricted-profile upstream `tools/list` `x-mcp-header` schema rejection before tool offer or call admission, `MAX_TOOL_RESPONSE_BODY_BYTES = 4 MiB` decoded HTTP response body ceiling via `http_body_util::Limited` before buffering alongside fixed `8 KiB` / `32` header bounds and chunked-trailer rejection); two-transaction durable `dispatched_attempts` accounting (Transaction 1 in Step 1 committing `dispatched_attempts = 0` before Step 5; Transaction 2 in Step 5 committing `0 -> 1 -> 2 -> 3` under `Fence::Step` before each outbound send and enforcing the monotonicity trigger forbidding `non-null -> NULL` or decrements) and identical persisted `Idempotency-Key` on `repeatable_read`/`idempotent` plus proven-pre-send retries on `lookup`/`non_repeatable`, enforcing `step.stop`, `step.deadline` (including `EndpointKey::Supported.expires_us`), crash-reclaim at `dispatched_attempts == 3` with zero outbound HTTP sends, and full ADR 0035 effect-level + bound-session/generation revocation checks before every retry across all classes; **PR3 mixed-version rolling-upgrade tests** covering both (i) a legacy/`N-1` `dispatched_attempts IS NULL` write `intent` verifying `Executor::reconcile` and direct terminal settlement resolve it to `outcome = 'outcome_unknown'` (`revision = 1`, terminal `interrupted`), never `failed`, and (ii) an **`N-1` worker settling a run containing a PR3-created `dispatched_attempts = 0` write `intent`** directly to `'interrupted'`, explicitly asserting PR3's trigger fires strictly before `run-terminal`, transitions the write to `outcome = 'outcome_unknown'`, `revision = 1`, and preserves **exact equality** between the committed `openmettle.run-interrupted` payload's `{"unresolved": n}` value (`1`) and the post-settlement `unresolved!()` row count (`1`) in `openmettle.operations`; **reclaimed uncancelled `Running` run, graceful shutdown `leases::handoff`, `Settle::Succeeded` (`!time`) and mixed-write settlement regression tests**: covering **(a)** `reclaim_next -> execute -> Reconciling(1) -> reconcile -> Interrupted(0)` (zero network calls, `outcome = 'failed'`, `revision = 1`, `{"unresolved": 0}`) and `leases::handoff` on graceful worker shutdown (`Settled::Reconciling { unresolved: 1 }` followed by `release_locked`, then `reconcile -> Interrupted(0)`) with one `dispatched_attempts = 0` write intent (`> 1` lease interval remaining), proving zero `StoreError::InvalidInput("settle")` errors, **(b)** `Settle::Succeeded` (`StepResult::Finished`) with one `dispatched_attempts = 0` write intent and `<= 1` lease interval remaining (`!time`), verifying `Err(StoreError::Conflict("unresolved operation"))` -> `Settle::Stopped` fallback -> `failed` (`DeadlineExceeded`, never `Succeeded`, extending `tests/schema/worker_runtime.rs:208-225`), and **(c)** **mixed writes** (`1` `dispatched_attempts = 0` + `1` `dispatched_attempts = 1`) under cancellation and `Settle::Failed` for both `time == true` (`Reconciling(2)` with zero pre-resolution) and `time == false` (`n_zero -> 'failed'`, `n_after -> 'outcome_unknown'`, terminal `Interrupted(1)`); sticky whole-operation send uncertainty (`outcome_unknown` preserved when a retry fails pre-send or receives `401`/`403`/deadline after ambiguous attempt 1) and immediate halt via `StepResult::Stopped` into `ExecState::Reconciling` / `interrupted` on every uncertain write (`lookup`, `non_repeatable`, or exhausted/window-expired `idempotent`), proving no further model round runs and a fresh-`logical_key` proposal cannot be admitted and produces **zero** additional outbound sends (while known-outcome non-retryable failures return `retryable_by_model: false`); deposed-worker lease takeover matrix between a possible write send and `runs::record_observation` explicitly covering both **(a)** an expired or replaced lease on a non-terminal run (`Fence::Hold` rejecting with `LeaseError::Expired` or `LeaseError::StaleClaim`, verifying the deposed worker returns `StepResult::Invalidated` immediately without touching PostgreSQL, leaves the durable `outcome = 'intent'` write row intact, and the replacement worker reclaims the run via `leases::reclaim_next` and routes the durable `intent` write straight into `ExecState::Reconciling` or terminal settlement with **zero** model steps and **zero** duplicate outbound sends) and **(b)** an already-terminal run (`Fence::Hold` rejecting with `LeaseError::Terminal`, verifying the deposed worker returns `StepResult::Invalidated` immediately without touching PostgreSQL, no replacement worker claims the run, and **zero** further DB writes or outbound sends occur); **`WorkEnd::Incomplete` drain-expiry contention matrix** holding a competing `FOR NO KEY UPDATE` lock on `openmettle.runs` across `run_one`'s full drain window, verifying `WorkEnd::Incomplete` drop, releasing the lock, driving recovery (`handoff`/`settle` or `reclaim_next` -> `ExecState::Reconciling` -> `Executor::reconcile`), and asserting exact durable `operations.outcome` and **zero additional outbound write sends** across (i) an externally successful **`non_repeatable` write** (`dispatched_attempts >= 1`, no downstream lookup -> `Executor::reconcile` commits `outcome = 'outcome_unknown'`, `revision = 1` under `Fence::Hold` -> terminal `interrupted` `{"unresolved": 1}`), (ii) `idempotent` and `lookup` writes (`dispatched_attempts IS NULL OR dispatched_attempts >= 1` -> read-only reconciled `succeeded`; strictly non-null `dispatched_attempts = 0` -> `failed` with zero sends; `lookup` with `downstream_handle IS NULL` and no deterministic query -> `outcome_unknown` -> `interrupted`), (iii) the **unacknowledged-commit** subcase (`operations.outcome` already committed `'succeeded'` right before `WorkEnd::Incomplete` drop -> reclaiming worker reuses the committed observation by `(scope_id, run_id, logical_key)` with zero additional outbound sends, subject to fenced `approvals::recheck_replay_effect_authority`, `Action::Read`, and `revision.state == "active"` rechecks whenever backed by an artifact), and (iv) **direct terminal settlement drain-expiry tests with insufficient reconciliation time (`<= 1` lease interval remaining)** on **both** `leases::settle(..., Settle::Stopped)` and `leases::settle_expired` after a dispatched `non_repeatable` write, verifying `operations.outcome = 'outcome_unknown'`, `revision = 1`, `runs.state = 'interrupted'`, exact `{"unresolved": 1}` matching `unresolved!()`, `run-terminal` as the final event (`204 No Content` on `GET`/`HEAD /v1/runs/{run_id}/events?after=<terminal_cursor>`), and zero additional outbound sends (plus verifying non-null `dispatched_attempts = 0` direct-terminal pre-settlement in `leases::settle_locked` iff `input != Settle::Succeeded && (state == ExecState::Reconciling \|\| !time \|\| (n_after == 0 && (cancel.is_some() \|\| matches!(input, Settle::Failed(_)))))` and in `leases::settle_expired` resolves to `outcome = 'failed'`, `revision = 1` before counting `u.n` without forcing `'interrupted'`); `lookup` reconciliation with and without `downstream_handle` passing `&ActiveRun`/`&Lease<'_>` into `Executor::reconcile`, enforcing both `recheck_decision` and the live destination-specific MCP server/connection/account authorization check under `Fence::Hold` in `ExecState::Reconciling` before `McpCredentialProvider` lookup (asserting **zero** `McpCredentialProvider` lookups and terminal `interrupted` settlement when destination/account access is revoked or disabled), and verifying `repeatable_read` exclusion from `Executor::reconcile`; semantic `isError: true` / `-32602` plus `PLAN-10` valid-schema wrong/stale-fact semantic recovery; internal-MCP identity-boundary check authenticating caller/scope via primary PostgreSQL authority rather than compiled bypass; `PLAN-22` fixed native vs internal-MCP vs remote-MCP route measurement harness hook; SSRF/TLS/redirect/`401`/`403`/`tools/list`-drift/`> 4 MiB` decoded-body refusals; canary redaction checks across errors, stderr, traces and metrics; end-to-end `park` -> `decide` -> resume -> `ApprovedAdapter::send` -> spill -> `artifact.read_range` round trip including bound-session logout, share-revocation and retention replay refusals. |

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
