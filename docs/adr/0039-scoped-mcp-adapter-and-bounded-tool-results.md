# 0039 — Scoped MCP adapter, reviewed tool contracts and bounded spill artifacts

Status: proposed V1-14 design (PR1), 21 November 2026. Refs #14. The base is `main` at
`45df33c60e7a84fe8a2db0a8e2d9b93a8d29e5a5` (schema 22). PR2 and PR3 own implementation and
qualification. Dependencies: [V1-03](https://github.com/OpenMettle/openmettle-core/issues/4),
[V1-05](https://github.com/OpenMettle/openmettle-core/issues/6),
[V1-13](https://github.com/OpenMettle/openmettle-core/issues/13),
[V1-17](https://github.com/OpenMettle/openmettle-core/issues/17) (PR2) and
[V1-28](https://github.com/OpenMettle/openmettle-core/issues/25).

## Decision

`openmettle-worker` executes server-owned tools through one owned Model Context Protocol (MCP)
and internal-tool adapter. Every tool call binds to a reviewed `(tool_id, tool_version)`
contract, passes closed-schema validation and primary PostgreSQL authorization, records a
fenced ADR 0035 effect intent before dispatch, classifies failures into a closed fault
taxonomy and returns a bounded inline or spilled result.

| Existing boundary | V1-14 addition |
| --- | --- |
| [ADR 0010](0010-provider-http-transport.md) and [ADR 0038](0038-sglang-and-external-provider-conformance-adapter.md), `src/provider_http/transport.rs` | Add a Streamable HTTP JSON-RPC 2.0 MCP (`2026-07-28`) client over `provider_http::transport` with a dedicated DNS slot semaphore, strict header allowlist (restricted stateless interoperability profile omitting `Mcp-Param-*` and failing closed on `x-mcp-header` schemas, and applying MCP `2026-07-28` `#value-encoding` Base64 sentinel wire encoding to `Mcp-Name` using already-locked `base64 = "=0.22.1"` `STANDARD` whenever `params.name` is empty, contains any byte outside `0x20..=0x7E` — explicitly Base64-encoding every control byte `0x00..=0x1F` including `0x09` HTAB, `0x7F`, and non-ASCII `>= 0x80` — has leading or trailing `0x20` space, or simultaneously starts with `"=?base64?"` and ends with `"?="`), RFC 9110 §15.2 HTTP/1.1 interim `1xx` handling (consuming non-`101` informational `1xx` responses such as `103 Early Hints` within `call_timeout`, per-block `8 KiB` / `32` header bounds, and `<= 4` interim responses while awaiting the final non-`1xx` HTTP status, while immediately rejecting unrequested `101 Switching Protocols` as `ToolFault::TerminalRefusal`), and `MAX_TOOL_RESPONSE_BODY_BYTES = 4 MiB` (`4_194_304` decoded HTTP body bytes via `http_body_util::Limited` alongside fixed `8 KiB` / `32` header bounds and chunked-trailer rejection). |
| [ADR 0027](0027-authorization-and-private-projects.md) and [ADR 0035](0035-approvals-permitted-yolo-and-effect-ledger.md), `src/authz/approvals.rs` | Implement `EffectPolicy` in the reviewed tool registry (with `artifact.read_range` setting `Review.artifact = Some(artifact_id)`, `Review.class = EffectClass::Read` and `Review.reservation = None` to bind `$7::uuid` in `AUTH`, capturing the source artifact's grant cycle/revision, local groups and OIDC-mapped evidence in `authority_evidence` and `binding_digest`), update `approvals::authorized(c, p, review)` (`src/authz/approvals.rs:597-627`) in PR2 so `EffectClass::Read` passes `RunRecheckRequest.extra_target = None` and enforces in-scope read-only `Action::Read` visibility on `p.artifact == Some(artifact_id)` without requiring `Action::Write`, bind every invocation to `Proposal`, `Destination`, `EffectClass`, `EndpointKey` and `record_fenced_intent`, store separate `effect_deadline: Instant` (`sent + Duration::from_micros((effective_until - snap.now).max(0) as u64)`) and `lease_margin_deadline: Instant` (`sent + held.lease_remaining.min(held.execution_remaining).saturating_sub(margin)`) on `CommittedIntent` replacing `CommittedIntent::start(&step)`'s `Option<(Vec<u8>, Instant)>` with explicit enum **`StartPermit`** (`Stopped(Stop)`, `AuthorityExpired { operation_id, request }`, `LeaseMarginExhausted`, `Ready { request, deadline }`) plus `approvals::expire_unstarted_intent` (rechecking primary PostgreSQL `db_time(c) >= effective_expires_bound_us` under `Fence::Step` before routing to `approvals::invalidate_post_intent`, or recomputing remaining duration and proceeding on monotonic clock skew), explicitly amend ADR 0035 (`docs/adr/0035-approvals-permitted-yolo-and-effect-ledger.md:260-268`) strictly for proven-unsent **`o.outcome = 'intent' AND o.dispatched_attempts = 0` (`IS NOT NULL AND = 0`)** write rows: update `PENDING_EFFECT` (`src/authz/approvals.rs:1241`, `src/worker.rs:519`) in PR3 to the NULL-safe predicate `AND NOT EXISTS (SELECT FROM openmettle.operations o WHERE o.run_id = a.run_id AND o.logical_key = a.logical_key AND (o.outcome = 'intent' AND o.dispatched_attempts = 0) IS NOT TRUE)` (never `NOT (...)`, so legacy `o.outcome = 'intent' AND o.dispatched_attempts IS NULL` evaluates `UNKNOWN IS NOT TRUE` = `TRUE` and stays excluded alongside `dispatched_attempts >= 1` and non-`'intent'` rows, while keeping `REQUEST.consumed` unchanged as `EXISTS (SELECT FROM openmettle.operations ...)` so HTTP `decide` still treats the approval as consumed while `worker::execute`'s `approvals::pending_effect` discovers `(approval_id, proposal)` strictly for a consumed human approval whose operation is still `outcome = 'intent' AND dispatched_attempts = 0`, and PR4's `Executor::step` discovers automatic writes `o.approval_id IS NULL AND o.outcome = 'intent' AND o.dispatched_attempts = 0`), update `record_fenced_intent`'s existing-operation branch (`src/authz/approvals.rs:1291-1337`, under `Fence::Step`) in PR3 to lock `SELECT id::text, request, capability, outcome, dispatched_attempts, effective_expires_us, approval_id::text FROM openmettle.operations WHERE run_id = $1::uuid AND logical_key = $2 FOR UPDATE` (returning `Err(CONFLICT)` if caller supplied `approval = Some(caller_id)` disagreeing with `stored_approval_id`, otherwise resolving `effective_approval = stored_approval_id.as_deref()`, verifying committed `authorization.basis` (`"human"` iff `effective_approval.is_some()`) and `authorization.approval_id == effective_approval`, and verifying `durable::existing_intent`): when **`old.outcome == "intent" && old.dispatched_attempts == Some(0)` AND `capability != "repeatable_read"`**, re-verify live `EffectPolicy` (`reviewed(policy, &s, &p)?` with `live_review == committed_review`) + `{AUTH}` (`authorized(c, &proof, &live_review)` — loading `run_approvals` + `run_approval_decisions.deciding_session_id` by `old.approval_id` even though `REQUEST.consumed` is `true` when `old.approval_id IS NOT NULL`, or verifying automatic `eligible && yolo` + `hydrate_worker_principal` + `authorize_capability(YOLO)` when `old.approval_id IS NULL`, plus exact `live_evidence == committed_evidence && live_hash == committed_binding_digest`) + `snap.now < effective_expires_bound_us` (routing expiry/revocation immediately through `approvals::invalidate_post_intent` -> `IntentResult::Invalidated(settled)` with zero sends), and when valid return **`IntentResult::Applied(CommittedIntent { operation_id: op, request: old_bytes, effect_deadline, lease_margin_deadline })`** (while all other existing-row cases — `repeatable_read`, `dispatched_attempts IS NULL`, `dispatched_attempts >= 1`, or `outcome <> 'intent'` — still **never** receive a write send permit and return `Ok(IntentResult::Replayed(op))`), add `approvals::recheck_replay_effect_authority(..., policy: &impl EffectPolicy)` (under `Fence::Step` on primary: parsing the committed `openmettle.effect` v1 envelope from `operations.request` — reconstructing committed `Proposal` `p` and requiring exact match with the requested `Proposal` and stored `operations` columns, extracting `authorization.basis`, `authorization.approval_id`, `authorization.expires_us`, `committed_evidence = STANDARD.decode(authorization.authority)`, `committed_binding_digest`, and `endpoint` (`committed_review`) — resolving the current live `Review` via `live_review = reviewed(policy, &s, &p)?` and requiring exact equality `live_review == committed_review` (`serde_json::to_vec(&live_review) == serde_json::to_vec(&committed_review)`; failing closed on `committed_review.reservation.is_some()` unless explicitly matched), joining `openmettle.run_approvals a JOIN openmettle.run_approval_decisions d ON d.approval_id = a.id` (`WHERE a.scope_id = $scope AND a.run_id = $run AND a.id = $approval_id AND a.logical_key = $logical_key`, requiring `d.decision == "approve"` and `d.binding_digest == a.binding_digest == committed_binding_digest`, passing `Some(d.deciding_session_id)` as `Proof.decider`) when `basis == "human"`, executing `snap = authorized(c, &proof, &live_review)`, checking `snap.now < expires_us.min(validity(&snap, &live_review))` plus `automatic(&r, &snap)` and `YOLO` capability when `basis == "yolo"`, rebuilding `live_evidence = snap.evidence(&live_review, auto)` and `live_hash = p.binding(&s, expires_us, &live_evidence)` (`Binding::new`), and requiring exact byte equality `live_evidence == committed_evidence && live_hash == committed_binding_digest` in addition to `hydrate_worker_principal`, `revision.scope_id == run.scope_id`, `Action::Read` and `revision.state == "active"` before replaying any `succeeded` source/spilled artifact-backed result or `artifact.read_range` bytes, including during committed-observation recovery, and requiring the same live `EffectPolicy` resolution and committed-evidence equality before replaying `failed` inline `status: "tool_error"` envelopes or resuming unfinished `repeatable_read` via `approvals::start_replayed_read(..., policy: &impl EffectPolicy)`), add ledger-aware **`approvals::invalidate_post_intent`** (extending `leases::FailReason` with `FailReason::ApprovalExpired` -> `openmettle.run-approval-expired`, keeping `invalidate_running`'s raw `fail(c, ..., EXPIRED)` strictly for pre-intent expiry where zero `operations` row exists; computing `effective_expires_bound_us` as `min` over durable `o.effective_expires_us` (when `NOT NULL`), `envelope["authorization"]["expires_us"]`, `live_review.endpoint_key` `expires_us` (when `EndpointKey::Supported`), and a direct un-filtered expiry query of bound non-revoked `local_sessions` / `local_identity_approvals` and unrevoked bound `membership_observations` so natural shorter-lived `deciding_session_id` / `originating_session_id` / OIDC observation expiry classifies accurately as expiry rather than `revoked`; partitioning strictly by `(capability, outcome, dispatched_attempts)` **regardless of caller** (`start_replayed_read`, `recheck_replay_effect_authority`, `record_fenced_intent` zero-attempt re-authorization, `CommittedIntent::start`, or Step 5 Transaction 2): **Branch 1** covers **`capability == 'repeatable_read'` for ALL `dispatched_attempts` (`NULL`, `0`, `1`, `2`, `3`) regardless of caller** (including in-process read retries), plus write `'intent'` rows with `dispatched_attempts == Some(0)`, and already-completed `outcome IN ('succeeded', 'failed')` rows — recording `outcome = 'failed'` if still `'intent'`, then calling `leases::settle_locked(c, lease, ExecState::Running, reason, settings, settle_input)` using `Settle::Failed(FailReason::ApprovalExpired)` when `db_time(c) >= effective_expires_bound_us` or `Settle::Stopped` with `Some(CancelReason::Revoked)` when `db_time(c) < effective_expires_bound_us`; **Branch 2** covers `capability IN ('idempotent', 'lookup', 'non_repeatable')` with `(outcome == 'intent' AND (dispatched_attempts IS NULL OR dispatched_attempts >= 1)) OR outcome == 'outcome_unknown'` — **never** calling `fail(...)` or `Settle::Failed`, performing zero additional outbound sends, transitioning non-reconcilable writes to `outcome = 'outcome_unknown'` or leaving reconcilable writes unresolved so `unresolved >= 1`, and settling via `leases::settle_locked(c, lease, ExecState::Running, reason, settings, Settle::Stopped)` into `Settled::Reconciling` or `Settled::Terminal { state: "interrupted" }`, returning `leases::Settled` inside `StepResult::Invalidated(leases::Settled)`), add PR2's next sequential schema migration (e.g., `0024`) for nullable durable pre-dispatch attempt accounting (`openmettle.operations.dispatched_attempts integer DEFAULT NULL CHECK (dispatched_attempts BETWEEN 0 AND 3)` with a monotonicity trigger forbidding `non-null -> NULL` or decrements) and nullable immutable **`openmettle.operations.effective_expires_us bigint`** (`GRANT INSERT (effective_expires_us) ON openmettle.operations TO openmettle_worker` — immutable after insert with zero `UPDATE` grant and trigger guard, preserving `openmettle_api`'s zero `INSERT`/`UPDATE` grant on `openmettle.operations`, with zero change to `Binding` or `request_identity` canonical bytes, populated by `INSERT_INTENT` at `src/authz/approvals.rs:1262, 1422` from `$20 = effective_until`), executed across **two separate `Fence::Step` PostgreSQL transactions** (`approvals::record_fenced_intent` writes **zero** `openmettle.operations` rows when returning `IntentResult::ApprovalRequired` so `approvals::park` inserts only `openmettle.run_approvals`, Transaction 1 commits `outcome = 'intent'` with `dispatched_attempts = 0` and `effective_expires_us = effective_until` strictly when returning `IntentResult::Applied(committed)` — immediate `repeatable_read` in PR2, and permitted automatic `yolo` writes or human-approved resume via `record_fenced_intent(..., Some(approval_id))` in PR3 once PR3's database-backed worker rollout gate **`openmettle.runtime_feature_gates.two_phase_effect_intents_enabled = true`** confirms all `N-1` workers and expiry sweepers are drained, while keeping pre-existing ADR 0035 external approval writes at `dispatched_attempts = NULL` and scoped MCP execution disabled while `two_phase_effect_intents_enabled = false` — so pre-upgrade and `N-1` rows remain `NULL` and are treated conservatively as exhausted `coalesce(dispatched_attempts, 3) >= 3` for dispatch and unknown `>= 1` for write reconciliation, and **both** Step 5 Transaction 2 and `approvals::start_replayed_read` lock `runs`/`operations` (`FOR UPDATE`), **evaluate live `EffectPolicy` + `{AUTH}` / `effective_expires_us` authority validity FIRST before checking `coalesce(dispatched_attempts, 3) >= 3`** (routing expired or revoked authority — including when `dispatched_attempts IS NULL` or `dispatched_attempts == 3` — immediately through `approvals::invalidate_post_intent` Branch 1 to `openmettle.run-approval-expired` or `openmettle.run-revoked`, skipping ordinary failed observation and model continuation), **only when live authority is still valid** require `dispatched_attempts IS NOT NULL AND dispatched_attempts < 3` (recording an ordinary exhausted `outcome = 'failed'` observation with zero sends and continuing the turn on `repeatable_read` when `NULL` or `>= 3`), and guard the `UPDATE openmettle.operations` statement **itself** — `SET dispatched_attempts = 1 ... AND outcome = 'intent' AND dispatched_attempts = 0` strictly before attempt 1, and `SET dispatched_attempts = o.dispatched_attempts + 1 ... AND o.dispatched_attempts < 3` on permitted retries — with the live `{AUTH}` CTE (`FROM snap, t, openmettle.runs r` matching `INSERT_INTENT` at `src/authz/approvals.rs:1262-1267`, verifying `$expected_base`, `$expected_tool`, `(NOT $auto OR (snap.eligible AND snap.yolo = $expected_yolo))`, `snap.now_us < $effective_expires_bound_us`, and active claim/lease/execution timestamps — settling via ledger-aware `approvals::invalidate_post_intent` -> `StepResult::Invalidated(settled)` with zero increment and zero sends if `0` rows are updated) before releasing the connection and issuing every outbound HTTP send), upgrade repair of pre-existing `queued`/`waiting` revision-zero `repeatable_read` intents and an `AFTER UPDATE OF state ON openmettle.runs` `SECURITY DEFINER` trigger (`openmettle.resolve_abandoned_repeatable_reads()`), and add PR3's sequential SQL migration creating **`openmettle.runtime_feature_gates (id boolean PRIMARY KEY DEFAULT true CHECK (id), two_phase_effect_intents_enabled boolean NOT NULL DEFAULT false)`** (`GRANT SELECT` to `openmettle_api, openmettle_worker`; enabled by `openmettle-admin` / rollout once all `N-1` workers and `settle_expired` sweepers are drained, and enabled by `bootstrap` on fresh databases) plus installing/extending an `AFTER UPDATE OF state ON openmettle.runs` `SECURITY DEFINER` defense-in-depth trigger (`openmettle.resolve_terminal_write_intents()`, across all terminal states `NEW.state IN ('succeeded', 'failed', 'cancelled', 'interrupted')`: raising an invariant exception if `NEW.state = 'succeeded'` with any unresolved write, and on `'failed'`, `'cancelled'`, or `'interrupted'` unconditionally transitioning any remaining revision-zero write intents to `outcome = 'outcome_unknown'`, `revision = 1` strictly before `run-terminal`). |
| [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md), `src/worker.rs` | Implement `ApprovedAdapter` for resumed writes, reuse the same committed-envelope dispatch for immediate reads and permitted YOLO writes, gate two-phase `dispatched_attempts = 0` writes and PR4 scoped MCP tool execution behind **`openmettle.runtime_feature_gates.two_phase_effect_intents_enabled`** so no `N-1` worker or `N-1` `settle_expired` sweeper ever sees a `dispatched_attempts = 0` row, update **`leases::unresolved!()`** (`src/authz/leases.rs:310-314`) in PR3 from `outcome IN ('intent', 'outcome_unknown') AND capability IN (...)` to **`(outcome = 'outcome_unknown' OR (outcome = 'intent' AND coalesce(dispatched_attempts, 1) > 0)) AND capability IN ('idempotent', 'lookup', 'non_repeatable')`** (so legacy `dispatched_attempts IS NULL` and dispatched `>= 1` rows remain unresolved while proven-unsent `dispatched_attempts = 0` rows are excluded), add **`StepResult::Handoff`** to `pub enum StepResult` (`src/worker.rs`) and explicit **`WorkEnd::Handoff`** to `WorkEnd` (`src/worker.rs`), updating `worker::execute` (`src/worker.rs:554-559`) to map **`StepResult::Handoff => return Ok(WorkEnd::Handoff)`** (leaving `StepResult::Stopped => return Ok(WorkEnd::Complete(Settle::Stopped))` strictly for graceful `shutdown`, explicit stop, or `outcome_unknown`!) and routing `WorkEnd::Handoff` in `run_one` (`src/worker.rs:661-675`) to **`leases::handoff(&mut c, &lease, &settings).await`** whenever `cause != Some(Stop::LeaseLost)`, update **`leases::handoff`** (`src/authz/leases.rs:503-535`, under `Fence::Hold`) to check **`time_to_reclaim = execution_expires_at > clock_timestamp() + $3::bigint * interval '1 millisecond'`** (`settings.lease` — matching `reclaim_next` and `SETTLEMENT_INPUTS` `time_to_reconcile` verbatim: calling `release_locked` keeping `state = 'running'` when `held.cancel.is_none() && !pending && time_to_reclaim`, and calling `settle_locked(..., Settle::Stopped)` inside the same `Fence::Hold` transaction when `held.cancel.is_some() \|\| pending \|\| !time_to_reclaim` so `<= settings.lease` remaining immediately selects `Resolution::DeadlineExceeded` (`state = 'failed'`, `{"reason":"deadline_exceeded"}`) and atomically closes `outcome = 'intent' AND dispatched_attempts = 0` to `outcome = 'failed', revision = revision + 1` with zero stranded unreclaimable runs and zero `Reconciling`/`Interrupted`), update both `worker::execute` (`src/worker.rs:536-548` on resumed human approvals) and `Executor::step` / `ApprovedAdapter::send` (`src/worker.rs:138-156`) to match `CommittedIntent::start(&step)`'s explicit **`StartPermit`** enum (`StartPermit::Stopped(Stop)` returning `WorkEnd::Stop(why)` — `Stop::Shutdown` routing to `leases::handoff`, terminal `Stop::Cancel` / `Stop::Deadline` settling directly to `Resolution::Cancelled` / `Resolution::DeadlineExceeded` with `n = 0`; `StartPermit::LeaseMarginExhausted` — or pre-dispatch remaining-lease margin cutoff `execution_remaining <= settings.lease` while `shutdown` has NOT fired — returning **`Ok(WorkEnd::Handoff)`** in `worker::execute`'s reviewed-approval branch and **`StepResult::Handoff`** in `Executor::step` / `ApprovedAdapter::send`, mapped by `worker::execute` at `src/worker.rs:554-559` to `Ok(WorkEnd::Handoff)`, so `leases::handoff` either calls `release_locked` when `> settings.lease` remains — keeping `runs.state = 'running'` and `operations.outcome = 'intent', dispatched_attempts = 0` so a successor worker reclaims (`recovered == true`) with empty `leases::unresolved_operations(..., 1)` (`src/worker.rs:500`), stays in `Running`, discovers the consumed human approval via NULL-safe `PENDING_EFFECT` (`src/authz/approvals.rs:1241`, `(o.outcome = 'intent' AND o.dispatched_attempts = 0) IS NOT TRUE`) or the automatic write via `Executor::step`, re-authorizes via `record_fenced_intent` returning **`IntentResult::Applied(CommittedIntent)`** under live `EffectPolicy` + `{AUTH}`, passes `StartPermit::Ready`, commits `dispatched_attempts: 0 -> 1` in Transaction 2, dispatches the write once, and finishes **`succeeded`** — or immediately settles `Resolution::DeadlineExceeded` + `outcome = 'failed'` when `<= settings.lease` remains; `StartPermit::AuthorityExpired { operation_id, request }` invoking `approvals::expire_unstarted_intent` / `approvals::invalidate_post_intent` under `Fence::Step` to mark the `dispatched_attempts = 0` intent `'failed'` and settle via `FailReason::ApprovalExpired` -> `openmettle.run-approval-expired` (`state = "failed"`) when `db_time(c) >= effective_expires_bound_us` or recomputing remaining budget on monotonic clock skew; and `StartPermit::Ready { request, deadline }` proceeding to dispatch), stop every `outcome_unknown` write (including **every** post-send write refusal — explicitly including first-attempt HTTP `401` and `403`, since post-intent `failed` on writes applies strictly when zero request bytes ever left the process across all attempts) under `Fence::Hold` + `StepResult::Stopped` into `ExecState::Reconciling` / `interrupted`, add **`StepResult::Invalidated(leases::Settled)`** -> **`WorkEnd::Invalidated(settled)`** in PR2 (so `Settled::Reconciling { .. }` immediately executes `leases::release_lease(&mut c, &lease)` at `src/worker.rs:660-663` without stranding the live lease across `leases::reclaim_next`'s `> 1` lease interval requirement, while `Settled::Terminal { .. }` exits at `src/worker.rs:652`) alongside distinct **`StepResult::LeaseLost`** -> **`WorkEnd::Stop(Stop::LeaseLost)`** strictly for deposed-worker own lease loss (`Stop::LeaseLost`, `LeaseError::StaleClaim \| Expired \| Terminal`), rely on PR2's and PR3's database triggers to resolve abandoned `repeatable_read` intents (pre-`waiting`/pre-terminal) and remaining revision-zero write intents (`openmettle.resolve_terminal_write_intents()`, raising on `'succeeded'` with any unresolved or open write intent and coercing any remaining `'intent'` writes to `outcome_unknown` pre-`run-terminal` on `'failed'`/`'cancelled'`/`'interrupted'`), in PR3 `leases::settle_locked` preserve `Err(StoreError::Conflict("unresolved operation"))` -> `Settle::Stopped` fallback on `Settle::Succeeded` whenever any unresolved OR open `outcome = 'intent' AND dispatched_attempts = 0` write exists (whereas `ExecState::Reconciling` returns `Err(StoreError::InvalidInput("settle"))`), AND inside that exact same `settle_locked` transaction whenever settling to any terminal state (`Cancelled`, `DeadlineExceeded`, `Failed`, or `Interrupted` — and likewise in PR3 `leases::settle_expired` strictly before `run-terminal`), **atomically transition any remaining `outcome = 'intent' AND (capability = 'repeatable_read' OR dispatched_attempts = 0)` rows on the run to `outcome = 'failed', revision = revision + 1`** (so no terminal run ever retains an open `'intent'` row and run-linked storage cleanup predicates fire cleanly), define deterministic recovery across `run_one` drain-window expiry (`WorkEnd::Incomplete`) for both unacknowledged commits (keyed committed-observation reuse gated by `approvals::recheck_replay_effect_authority(..., policy)` with live `EffectPolicy` resolution `live_review == committed_review`, `run_approvals JOIN run_approval_decisions` for `basis == "human"`, and exact committed `authority_evidence` + `binding_digest` equality, plus `Action::Read` and `revision.state == "active"` for `succeeded` source/spilled artifacts, while `failed` observations always replay their bounded inline `status: "tool_error"` envelope) and uncommitted `'intent'` observations (including `outcome_unknown` -> `interrupted` for dispatched or legacy `dispatched_attempts IS NULL` writes without a downstream read-only lookup, even when direct terminal settlement bypasses `Executor::reconcile`), and implement destination-authorized read-only `Executor::reconcile` reading `dispatched_attempts: Option<i32>` on `UnresolvedOperation`. |
| [ADR 0005](0005-artifact-storage-accounting.md), [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md) and [ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md), `src/storage.rs` and `src/artifact_fs.rs` | Sequence `V1-14` PR2 after `V1-17` PR2 (`ADR 0040` PR2) for the dedicated 1-row read-mostly control table **`openmettle.storage_volume_control (id boolean PRIMARY KEY DEFAULT true CHECK (id), volume_id uuid, bootstrap_auto_pin_allowed boolean NOT NULL DEFAULT false, adoption_run_id uuid, CONSTRAINT storage_volume_control_auto_pin_check CHECK (volume_id IS NULL OR NOT bootstrap_auto_pin_allowed))`** with **ONLY `GRANT SELECT ON openmettle.storage_volume_control TO openmettle_api, openmettle_worker;`** (zero `INSERT`/`UPDATE`/`DELETE`/`TRUNCATE` for runtime roles, eliminating PostgreSQL 18 `FOR SHARE` `42501` privilege errors and direct pin rewrites), exposing two `openmettle_owner`-owned `SECURITY DEFINER` (`SET search_path = pg_catalog`) functions: **`openmettle.storage_lock_pinned_volume() RETURNS uuid`** (`REVOKE ALL FROM PUBLIC; GRANT EXECUTE TO openmettle_api, openmettle_worker;`, executing `SELECT volume_id, adoption_run_id INTO v_vol, v_adopt FROM openmettle.storage_volume_control WHERE id FOR SHARE`, raising `OMQ03` on `NOT FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL`, and returning `v_vol` — called by ALL runtime paths and by `enforce_runtime_storage_volume_pinned()`, NEVER raw invoker `FOR SHARE`!) and strictly **API-only** **`openmettle.storage_pin_volume_id(p_volume_id uuid) RETURNS uuid`** (`GRANT EXECUTE ON FUNCTION openmettle.storage_pin_volume_id(uuid) TO openmettle_api;`: only `openmettle_api` initializes fresh `.openmettle-volume-id` sentinels and calls `storage_pin_volume_id(uuid)` on empty fresh bootstrap without raw invoker `FOR UPDATE`/`UPDATE`; `openmettle_worker` never initializes sentinels and never calls `storage_pin_volume_id(uuid)`, cleanly observing `OMQ03` via `storage_lock_pinned_volume()` without `42501` until pinned) under canonical lock order **`runs -> storage_reservations -> artifacts -> artifact_revisions -> storage_volume_control -> storage_accounts -> storage_instance`**, `openmettle.storage_reservations.adoption_unverified` with tightened **`storage_reservations_adoption_unverified_check`** **`CHECK (NOT adoption_unverified OR state = 'reserved')`**, **`stage_claimed boolean NOT NULL DEFAULT false`** (`CHECK (payload_ino IS NULL OR stage_claimed)`), **`payload_ino numeric(20, 0)`** ONLY (`CHECK (payload_ino IS NULL OR payload_ino >= 0)`, zero `payload_dev`), **`publish_pending boolean NOT NULL DEFAULT false`** (`CHECK (NOT publish_pending OR (state = 'reserved' AND payload_ino IS NOT NULL))`), the unified **4-state** cleaner lease shared by all 4 cleaners (`artifact_fs::abort`, `reconcile_expired`, generic run-linked cleaner, and `reconcile_run_spills`) — **`reclaim_state text NOT NULL DEFAULT 'none' CHECK (reclaim_state IN ('none', 'claiming', 'truncated', 'anchor_pending_unlink'))`**, **`reclaim_claim_token uuid`**, **`reclaim_lease_until timestamptz`**, and partial index **`storage_reservations_reclaim_anchor_idx`** (`ON openmettle.storage_reservations (closed_at, id) WHERE state = 'released' AND reclaim_state = 'anchor_pending_unlink'`), **`openmettle.artifact_revisions.purge_stage text NOT NULL DEFAULT 'none'`** with **`artifact_revisions_purge_stage_check`** (`CHECK (purge_stage IN ('none', 'anchor_pending_unlink') AND (purge_stage = 'none' OR state = 'purged'))`), partial index **`artifact_revisions_purge_anchor_idx`** (`ON openmettle.artifact_revisions (purged_at, id) WHERE state = 'purged' AND purge_stage = 'anchor_pending_unlink'`), and worker-only **`GRANT UPDATE (purge_stage) ON openmettle.artifact_revisions TO openmettle_worker;`**, runtime grants on `storage_reservations` (`src/boundaries.sql`), PostgreSQL `SECURITY INVOKER` (`SET search_path = pg_catalog`) triggers **`openmettle.enforce_runtime_storage_volume_pinned()`** (`IF NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE') THEN PERFORM openmettle.storage_lock_pinned_volume(); END IF; RETURN NEW;`) and **`openmettle.enforce_storage_reservation_monotonic_guards()`** (`payload_ino` write-once, never cleared to `NULL`), `storage_reservations_tool_spill_binding_guard` (`23514`), `rustix`-backed (`default-features = false, features = ["fs", "std"]`, 100% safe Rust under `unsafe_code = "forbid"`) verified directory descriptors (`root_fd`, `staging_dir_fd`, `revisions_dir_fd`), and `V1-17` PR2's shared zero-truncation `StagingSweepState` + 3-stage `artifact_fs::purge_due` in `worker::maintenance`; align HTTP **`Store::stage` / `Store::publish` / `Store::read`** (`src/artifact_fs.rs:144-158, 190-208, 300-355`) with `V1-17` PR2 (plain `SELECT` without `FOR SHARE` during mixed-version unpinned window `volume_id IS NULL AND adoption_run_id IS NULL`, `SELECT openmettle.storage_lock_pinned_volume()` once pinned, non-destructive `StagedFile::drop`, `publish_pending = true` committed after `sync_all()` and before `linkat` + `fsync(&revisions_dir_fd)`, `storage::settle` retaining `payload_ino`, post-commit `LOCK_SH` detach of `staging/<id>` without `set_len(0)`; **`Store::read`** opening `revisions/<reservation>` with `OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK`, immediately checking `file.metadata()?.file_type().is_file()` (failing closed with `Err(Error::Missing)` without blocking on writerless FIFOs/sockets/devices/directories), acquiring non-blocking `file.try_lock_shared()` (`LOCK_SH \| LOCK_NB`; `WouldBlock` -> `Err(Error::Missing)` before response headers), strictly AFTER `LOCK_SH` re-verifying `file.metadata()` (`is_file()`, `st_dev == store.root_dev`, `st_ino == sr.payload_ino` when non-null, `len() == size`) and `statat(&revisions_dir_fd, reservation, AtFlags::SYMLINK_NOFOLLOW)` matching `(fd_dev, fd_ino)` before seeking and **retaining that locked `fs::File` inside `Content` for the entire response stream lifetime** so concurrent `purge_due` Stage A `LOCK_EX` defers cleanly); add lease-fenced direct byte publication (`artifact_fs::publish_bytes`, restricted exclusively to `succeeded` tool outputs; gated by `spill_permits` bounded to `max_concurrent_runs`, with **zero `set_len(0)` anywhere in writers** and `unlinkat` strictly limited to post-`commit` best-effort `LOCK_SH` detach of `staging/<id>`): **Phase 1a** acquires `OwnedSemaphorePermit` and calls `SELECT openmettle.storage_lock_pinned_volume()` + `storage::reserve` (`stage_claimed = true, payload_ino = NULL, publish_pending = false, reclaim_state = 'none'`) BEFORE touching disk; **Step 1 (Phase 1b)** creates `0`-byte `staging/<id>` under continuous **`LOCK_EX`** (held continuously across Steps 1–5 with zero lock-mode conversion!) + `fsync(&staging_dir_fd)` and commits write-once `payload_ino` via `storage_lock_pinned_volume()` + `UPDATE` keeping **`publish_pending = false`** while `0` bytes; **Step 2 (Phase 2a)** writes payload + `sync_all()` (`actual_size == reserved_bytes`) under continuous `LOCK_EX`; **Step 3 (Phase 2b)** executes the pre-`linkat` SQL fence under continuous `LOCK_EX` (`SELECT openmettle.storage_lock_pinned_volume(); UPDATE openmettle.storage_reservations SET publish_pending = true WHERE ... AND payload_ino = $3 RETURNING id;`, aborting cleanly before `linkat` on `OMQ03` if adoption started or `0` rows if a cleaner claimed `reclaim_state <> 'none'`); **Step 4 (Phase 2c)** executes `rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id, AtFlags::empty())` + `fsync(&revisions_dir_fd)` + post-`linkat` verify keeping `staging/<id>` linked until settlement (`N-1` retry protection) while **holding `LOCK_EX` continuously with zero lock-mode conversion (never downgrading to `try_lock_shared()` pre-commit!)**; **Step 5 (Phase 3)** executes atomic `Fence::Step` `storage::settle` (calling `storage_lock_pinned_volume()`, retaining `payload_ino`) + `runs::record_observation` with permit-bounded `<= 2 s` pre-commit verification while still holding `LOCK_EX`, drops `payload_file` (`LOCK_EX`) **only AFTER** confirmed `COMMIT`, and only then opens `staging/<id>` post-commit with `OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + immediate `is_file()` + `try_lock_shared()` for best-effort `unlinkat(&staging_dir_fd, id)` (never `set_len(0)`) + `fsync(&staging_dir_fd)`; startup `Store::probe_writable`; **exclusive single-owner** unified **4-step crash-safe & replacement-safe** spill cleanup (`artifact_fs::reconcile_run_spills`, exact complement of `V1-17` generic run-linked cleaner) preserving `payload_ino` via **`staging/.reclaim.<id>`** and opening **EVERY `LOCK_EX` target with `OFlags::RDWR \| OFlags::NOFOLLOW` (explicitly WITHOUT `OFlags::TRUNC`, preserving zero `set_len(0)` on non-truncating paths)** because Linux NFS emulates `flock(LOCK_EX)` via `fcntl(F_SETLK, F_WRLCK)` (`EBADF` on `O_RDONLY`, whereas `OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + immediate `is_file()` remains valid for shared `LOCK_SH` / `F_RDLCK`): **Step 1** serialized DB claim via `storage_lock_pinned_volume()`; **Step 2** probes `staging/.reclaim.<id>` first in `'claiming'` (covering predecessor crash after `linkat`+`unlinkat` before `'truncated'` commit) and **ONLY `staging/.reclaim.<id>`** (`OFlags::RDWR \| OFlags::NOFOLLOW`, no `OFlags::TRUNC`, zero `set_len(0)`) in `'truncated'` — **executing guarded `300 s` lease renewal (`SELECT openmettle.storage_lock_pinned_volume(); UPDATE ... SET reclaim_lease_until = clock_timestamp() + interval '300 seconds' WHERE ... AND payload_ino = $3 AND reclaim_state = 'truncated' AND reclaim_claim_token = $4::uuid RETURNING id;`) under `LOCK_EX` strictly BEFORE the two directory `fsync`s in Subcase A2 (`'truncated'`)**, with **mandatory Step 2a fenced SQL lease renewal UNDER `LOCK_EX` strictly BEFORE `set_len(0)` / `linkat` / `unlinkat` — in Subcase A1 (`payload_ino IS NOT NULL`) AND in Subcase B / Step 2 Case 2 (`payload_ino IS NULL` `0`-byte regular `staging/<id>` with `revisions/<id>` and `staging/.reclaim.<id>` `ENOENT`, opened `OFlags::RDWR \| OFlags::NOFOLLOW`, no `OFlags::TRUNC`, zero `set_len(0)`, re-verifying `fstat` (`S_ISREG`, `st_dev == store.root_dev`, `st_size == 0`), `statat(&staging_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` `(fd_dev, fd_ino)` match, and `revisions/<id>` + `staging/.reclaim.<id>` `ENOENT` under continuous `LOCK_EX` and executing **`rustix::fs::fsync(&staging_dir_fd)?` strictly BEFORE Step 2a's SQL `UPDATE`** so a crash right after Step 2a commits can never leave a bound reservation with all three names absent, where Step 2a atomically binds `stage_claimed = true, payload_ino = fd_ino` under `LOCK_EX` and promotes directly into the `.reclaim.<id>` anchor sequence `linkat` -> unconditional `fsync(&staging_dir_fd)?` -> `unlinkat(id)` -> dual `fsync` -> `'truncated'` -> Step 3 -> Step 4, so `payload_ino` stays `NULL` through Step 3 ONLY when all three are `ENOENT` with zero `unlinkat` calls!)** (aborting with zero FS mutation on `0` rows / `OMQ03`), `set_len(0)?` + `sync_all()?`, creating/verifying `staging/.reclaim.<id>` + **unconditional `fsync(&staging_dir_fd)?` strictly BEFORE unlinking `<id>` whether `.reclaim.<id>` was newly created or pre-existing**, then unlinking `revisions/<id>` & `staging/<id>` + dual `fsync` -> committing `'truncated'`; **Step 3** `storage::release` -> `'anchor_pending_unlink'` (firing `enforce_runtime_storage_volume_pinned()` -> `storage_lock_pinned_volume()`); **Step 4** `LOCK_EX` **`OFlags::RDWR \| OFlags::NOFOLLOW`** (without `OFlags::TRUNC`, never `set_len(0)`) detach of `staging/.reclaim.<id>` + `fsync(&staging_dir_fd)` + `reclaim_state = 'none'`, backed by a **general bounded ledger-driven Step 4 sweep across ALL reservations** (both uploads and spills via `storage_reservations_reclaim_anchor_idx`) with per-worker wrapping keyset cursor **`reclaim_anchor_cursor: Option<(DateTime<Utc>, Uuid)>`** paired with pass-start fixed upper watermark **`reclaim_anchor_pass_upper: Option<(DateTime<Utc>, Uuid)>`** (`ORDER BY closed_at DESC, id DESC LIMIT 1`, constraining pages with `AND (closed_at, id) <= ($3::timestamptz, $4::uuid)`, advancing past every inspected row including anomalous/WouldBlock rows, and resetting BOTH cursor and upper watermark to `None` when `< LIMIT` rows return OR `(upper_ts, upper_id)` is reached); **zero-truncation `StagingSweepState` (`OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC` on every `LOCK_EX` open, ZERO `set_len(0)` calls in ANY branch — including `0`-row aged orphans and `.reclaim.<id>`!)** with explicit 3-way `ReadDir` classification (`.openmettle-volume-id`, `.reclaim.<id>`, regular UUID `<id>` + aged non-UUID/malformed `.reclaim.*`), detaching `'settled'` `staging/<id>` **STRICTLY ONLY when `artifact_revisions.state IN ('active', 'retained')` AND `revisions/<id>` matches `payload_ino`** (removing the `'purged'` `ENOENT` exception completely); **3-stage inode-preserving `artifact_fs::purge_due`** (`begin_purge` -> **Stage A** `revisions/.purge.<id>` anchor + `LOCK_EX` + DB revalidation via `storage_lock_pinned_volume()` + `set_len(0)?` + `sync_all()?` + **unconditional `fsync(&revisions_dir_fd)?` before unlinking `revisions/<id>`** + `staging/<id>` matching-`payload_ino` detach + dual `fsync` while `.purge.<id>` pins `payload_ino` at `nlink >= 1` -> **Stage B** `confirm_purge` setting `state = 'purged', purge_stage = 'anchor_pending_unlink'` -> **Stage C** post-commit + bounded DB sweep via `artifact_revisions_purge_anchor_idx` with per-worker wrapping keyset cursor **`purge_anchor_cursor: Option<(DateTime<Utc>, Uuid)>`** paired with pass-start fixed upper watermark **`purge_anchor_pass_upper: Option<(DateTime<Utc>, Uuid)>`** (both watermark and page queries joining `openmettle.storage_reservations sr ON sr.scope_id = r.scope_id AND sr.id = r.reservation_id` with `AND NOT sr.adoption_unverified AND sr.payload_ino IS NOT NULL`, `ORDER BY r.purged_at DESC, r.id DESC LIMIT 1`, constraining pages with `AND (r.purged_at, r.id) <= ($3::timestamptz, $4::uuid)`, resetting BOTH to `None` when `< LIMIT` rows return OR `(upper_ts, upper_id)` is reached) detaching `revisions/.purge.<id>` under `LOCK_EX` (`OFlags::RDWR \| OFlags::NOFOLLOW`, without `OFlags::TRUNC`, zero `set_len(0)`) -> `purge_stage = 'none'`); and aligned **`openmettle storage adopt`** enforcing Phase 3A cross-reservation inode uniqueness (`R1 <> R2 => ino(R1) <> ino(R2)`) across **ONLY live payloads, surviving on-disk anchors, and all candidates for `payload_ino` backfill or `adoption_unverified = false` clearance** — `artifact_revisions` with `state IN ('active', 'retained')`, surviving `'purging'`, or `(state = 'purged' AND purge_stage = 'anchor_pending_unlink')` **STRICTLY ONLY when `revisions/.purge.<id>` is verified still present on disk**, AND `storage_reservations` with `(state = 'reserved' AND (payload_ino IS NOT NULL OR candidate_for_backfill_or_unquarantine))` or `(state = 'released' AND reclaim_state = 'anchor_pending_unlink')` **STRICTLY ONLY when `staging/.reclaim.<id>` is verified still present on disk** (**explicitly EXCLUDING retired historical rows AND already-detached `ENOENT` pending anchors** — `(state = 'released' AND reclaim_state = 'none')`, `'settled'` rows whose revision is `(artifact_revisions.state = 'purged' AND purge_stage = 'none')`, `(state = 'released' AND reclaim_state = 'anchor_pending_unlink')` with `staging/.reclaim.<id>` `ENOENT`, and `(artifact_revisions.state = 'purged' AND purge_stage = 'anchor_pending_unlink')` with `revisions/.purge.<id>` `ENOENT`, while Phase 3C clears those `ENOENT` pending anchors to `'none'`), maintaining **`held_candidate_locks: HashMap<(u64, u64), Uuid>`** (`(st_dev, st_ino) -> reservation_id`) across Step 2's scan and acquiring non-blocking `OFlags::RDWR \| OFlags::NOFOLLOW` (no `OFlags::TRUNC`) `LOCK_EX` across **ALL `'reserved'` rows' matching regular files on disk** — covering BOTH `payload_ino IS NULL` backfill candidates AND already-bound `payload_ino IS NOT NULL` `'reserved'` rows including `reclaim_state IN ('none', 'claiming', 'truncated')` and previously quarantined `adoption_unverified = true` clearance candidates whenever `sr.payload_ino IS NULL \|\| fd_ino == sr.payload_ino` (classifying foreign `sr.payload_ino IS NOT NULL && fd_ino != sr.payload_ino` directly as mismatch/quarantine without calling `try_lock()`), inspecting `held_candidate_locks.get(&(fd_dev, fd_ino))` **strictly BEFORE calling `try_lock()`** (recording deterministic hard failure **`cross_reservation_inode_alias`** -> Phase 3B with zero backfills when owned by `other_res_id != reservation_id`, never self-locking into `WouldBlock`, and verifying `statat` + reusing held `LOCK_EX` when owned by `same_res_id`), calling `try_lock()` only when absent (`WouldBlock` from an active cleaner/writer — BOTH before and after Step 2a commit — clearing `adoption_run_id = NULL` in Step 3 with zero quarantines/backfills and returning retryable `OMQ03` busy), re-probing `staging/.reclaim.<id>` (and `revisions/<id>`) once more before classifying a `'reserved'` row as missing whenever all three initially return `ENOENT` or post-`LOCK_EX` `statat` on `staging/<id>`/`revisions/<id>` returns `ENOENT`, and retaining all acquired `LOCK_EX` descriptors continuously through Phase 3C commit, performing **zero `payload_ino` backfills and zero Case 6b purge completions in Phase 3B** (verification-failure branch), and in **Phase 3C** (success-only commit branch) never writing `payload_ino` onto rows that remain quarantined, keeping `reclaim_state = 'claiming'` as `'claiming'` (never promoting `'claiming'` to `'truncated'`) with `reclaim_lease_until = clock_timestamp()`, requiring `staging/.reclaim.<id>` (`st_size == 0`) AND `staging/<id>`/`revisions/<id>` `ENOENT` on already-`'truncated'` rows, requiring **exact `st_size == size_bytes` AND `sha256 == content_digest`** on surviving legacy `'purging'` rows (`sr.payload_ino IS NULL`; reserving the `st_size == 0` Stage A crash exception strictly for `sr.payload_ino IS NOT NULL AND st_ino == sr.payload_ino`), and atomically completing verified-absent legacy `'purging'` rows in **Phase 3C** as `openmettle_owner` (absent rows never counting as positive on-disk file evidence); paired with strictly inline read-only `artifact.read_range` and two-client Linux NFS `ReadWriteMany` qualification. |

**Zero new Cargo crates beyond `V1-17` PR2's `rustix` foundation.** V1-14 adds zero new Cargo
dependencies of its own, reusing the locked `hyper`, `hyper-util`, `http-body-util`, `rustls`,
`tokio-rustls`, `serde`, `serde_json`, `sha2`, `bytes`, `base64` (`=0.22.1`), `httpdate` and
`ring` stack (rather than adding `rmcp` or another unreviewed MCP SDK crate) together with
`V1-17` PR2's `rustix` (`default-features = false, features = ["fs", "std"]`, 100% safe Rust
under `Cargo.toml`'s `unsafe_code = "forbid"`). All filesystem locking, metadata/inode
verification, truncation, verified-directory `openat`/`statat`/`linkat`/`unlinkat` and `fsync`
use stable safe Rust 1.100 `std::fs`,
`std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, MetadataExt}` and `V1-17` PR2's
`rustix::fs` helpers (with no `nix` crate and no unstable `std::fs::Dir`). Adopting an external
MCP SDK later requires a separate dependency and V1-42 distribution gate.

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
makes forward progress; values below `4` or above `16384` fail closed pre-intent with a schema
validation refusal (`ToolFault::TerminalRefusal`, writing zero `openmettle.operations` rows and
returning a bounded inline `status: "tool_error"` envelope).

**Source-artifact grant-cycle binding without requiring write access (`Review.artifact =
Some(artifact_id)`).** `artifact.read_range`'s `EffectPolicy` sets
**`Review.artifact = Some(artifact_id)`** (with `Review.class = EffectClass::Read` and
`Review.reservation = None`, which satisfies `Review::validate()` in
`src/authz/approvals.rs:235`). Binding `Review.artifact = Some(artifact_id)` populates
`$7::uuid` (`Proof.artifact`) in `AUTH` (`src/authz/approvals.rs:319-324, 349-355`), capturing
the source artifact's exact `grant_assignments` / `grant_changes` (`[id, cycle_id,
last_revision]`), local `groups`, and OIDC `mapped` evidence inside `snap.tool` (and
`Review.artifact` inside serialized `Review`) in `authority_evidence` and `binding_digest` at
initial authorization. To preserve read-only (`Action::Read`) access without demanding write
(`RunExecute`) privileges through `RunRecheckRequest::extra_target`, PR2 updates
`approvals::authorized(c, p, review)` (`src/authz/approvals.rs:597-627`) so that when
`review.class == EffectClass::Read`:
1. `RunRecheckRequest.extra_target` is passed as `None` (keeping `extra_target`
   write/`RunExecute` enforcement strictly for non-`Read` effects), **and**
2. whenever `p.artifact == Some(artifact_id)` on `EffectClass::Read`, `authorized` hydrates the
   worker principal, run scope, and artifact resource (`projects::hydrate_resource(c,
   ResourceKind::Artifact, artifact_id, snap.now / 1000)`) and requires in-scope read-only
   visibility (`same_scope(&artifact_resource.scope, &run_scope)` and
   `authorize_resource(&principal, &artifact_resource, Action::Read).is_allowed()`), returning
   `DENIED` / `HIDDEN` on failure without requiring `Action::Write`.

Before reading or replaying any byte (on initial execution, `IntentResult::Replayed(op_id)`,
or committed-observation / unacknowledged-commit recovery), the handler executes a fenced
primary authority check (`approvals::recheck_replay_effect_authority(..., policy)` under
`Fence::Step` on the primary, rather than relying on `authz::runs::recheck_leased` or
`record_fenced_intent`'s existing-intent replay branch alone). On replay or
committed-observation recovery, `approvals::recheck_replay_effect_authority(..., policy)`
parses the committed `openmettle.effect` v1 envelope from `operations.request` — reconstructing
committed `Proposal` `p` (`logical_key`, `tool`, `tool_version`, `arguments`, `destination`)
and requiring exact match with the caller's requested `Proposal` and stored `operations`
columns, extracting `authorization.basis` (`"read"`, `"yolo"`, or `"human"`, with
`auto = (basis == "yolo")`), `authorization.approval_id`, `authorization.expires_us`,
`committed_evidence = STANDARD.decode(authorization.authority)`, `committed_binding_digest`,
and `endpoint` (`committed_review`) — **resolves the current live `Review` via
`live_review = reviewed(policy, &s, &p)?` (`policy.review(s.scope, run, &p)?.ok_or(DENIED)?` +
`live_review.validate()?`) and requires exact equality `live_review == committed_review`**
(`serde_json::to_vec(&live_review) == serde_json::to_vec(&committed_review)`; failing closed if
`committed_review.reservation.is_some()` unless explicitly matched), joins
`openmettle.run_approvals a JOIN openmettle.run_approval_decisions d ON d.approval_id = a.id`
(`WHERE a.scope_id = $scope AND a.run_id = $run AND a.id = $approval_id AND a.logical_key =
$logical_key`, requiring `d.decision == "approve"` and `d.binding_digest == a.binding_digest ==
committed_binding_digest`, passing `Some(d.deciding_session_id)` as `Proof.decider`) when
`basis == "human"`, executes `snap = authorized(c, &proof, &live_review)` (verifying live
originating/deciding session, provider/approval/user generations, run continuation, and
in-scope read-only `Action::Read` visibility on `artifact_id`), checks
`snap.now < expires_us.min(validity(&snap, &live_review))` (plus `automatic(&r, &snap)` and
`YOLO` capability when `basis == "yolo"`), **rebuilds
`live_evidence = snap.evidence(&live_review, auto)` and
`live_hash = p.binding(&s, expires_us, &live_evidence)` (`Binding::new`), and requires exact
byte equality `live_evidence == committed_evidence && live_hash == committed_binding_digest`**
(enforcing ADR 0035's exact same-evidence-at-use invariant so disabling/changing `EffectPolicy`,
revoking and re-granting the tool capability, or revoking and re-granting the direct
source-artifact share — changing `[id, cycle_id, last_revision]` in `authority_evidence` — all
fail closed). In addition, the handler verifies continuation authority (`tools.artifact.read`
capability), hydrates the worker principal via `authz::store::hydrate_worker_principal`, loads
the revision via `storage::read_revision`, confirms `revision.scope_id == run.scope_id`, checks
`authorize_resource(&principal, &resource, Action::Read)` on the artifact and requires
`revision.state == "active"` — refusing replay via `approvals::invalidate_post_intent` and
returning **zero** cached bytes (`IntentResult::Invalidated(settled)` /
`StepResult::Invalidated(settled)` -> `WorkEnd::Invalidated(settled)`) if the bound or deciding
session logged out, effect authority was revoked, live `EffectPolicy` disabled or changed the
policy, or either the tool capability or direct source-artifact share was revoked and
re-granted (changing `authority_evidence`) even while `Action::Read` access and
`revision.state == "active"` remain valid. The handler accepts only UTF-8 text or JSON media
types, requires `offset` to start on a UTF-8 character boundary and returns
`ToolFault::Semantic` on binary media types, invalid UTF-8 bytes or misaligned offsets. It
reads `[offset, offset + len)` via `artifact_fs::Store::read` (which opens
`revisions/<reservation>` with `OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK`,
immediately checks `file.metadata()?.file_type().is_file()` failing closed with
`Err(Error::Missing)` without blocking on writerless FIFOs/sockets/devices/directories,
acquires non-blocking `file.try_lock_shared()` (`LOCK_SH | LOCK_NB`; `WouldBlock` ->
`Err(Error::Missing)` before response headers), strictly AFTER `LOCK_SH` re-verifies
`sr.adoption_unverified = false`, `is_file()`, local same-mount `file_meta.dev() ==
revisions_dir_fd_meta.dev() == root_fd_meta.dev()`, `file_meta.ino() == sr.payload_ino`
whenever `sr.payload_ino IS NOT NULL` — allowing `sr.payload_ino IS NULL` **only** while
`storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL` — `len() == size`, and
`statat(&revisions_dir_fd, reservation, AtFlags::SYMLINK_NOFOLLOW)` matching `(fd_dev, fd_ino)`
before seeking and retaining the locked `fs::File` inside `Content` for the full read/stream
lifetime so concurrent `purge_due` Stage A `LOCK_EX` defers cleanly), trims any trailing split UTF-8
code point within `max_bytes`, caps each returned page at `<= 200` lines (advancing
`next_offset` cleanly to the first byte after line 200 when more lines remain so the caller
paginates without exceeding the inline line ceiling) and trims trailing code points further if
needed so the **final UTF-8 serialized JSON tool-result string** fits `<= 16_384` bytes
(accounting for JSON string escaping and envelope metadata). `artifact.read_range` is explicitly
exempt from spill publication: its pages stay strictly inline and never spill into derived
artifacts. The response returns the UTF-8 slice with `next_offset`, `size_bytes`, `media_type`,
`content_digest` and `eof`. This single read-only tool also lets a model inspect sections of
any spilled tool output on demand, subject to live `EffectPolicy` resolution, ADR 0035
bound/deciding-session and exact committed-evidence equality
(`approvals::recheck_replay_effect_authority(..., policy)`), `Action::Read` and `active`
revision checks.

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
**Pre-intent refusals write zero `openmettle.operations` rows:** unknown tools, prohibited
effects, schema/bounds validation failures (such as `max_bytes < 4`), `x-mcp-header`-annotated
tool rejections, unpinned destinations, unavailable V1-28 credentials or V1-17 quota refusals
occurring before `approvals::record_fenced_intent` commits return `Ok(None)` or `Err` without
inserting any `openmettle.operations` row and without calling `runs::record_observation` (which
requires an existing `operation_id`). When run authority remains valid, pre-intent refusals
return a bounded redacted inline `ToolFault::TerminalRefusal` error envelope
(`status: "tool_error"`, `retryable_by_model: false`, never spilled); if authority was
invalidated, the run settles under ADR 0033/0035. `runs::record_observation`
(`outcome = 'failed'` or `'outcome_unknown'`) applies strictly **after** an
`openmettle.operations` row has been committed. V1-14 spills are post-response opportunistic
artifacts restricted exclusively to `succeeded` outputs and do not require `Review.reservation`
before dispatch.

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
`outcome = 'failed'` (proven unsent) on a write that was actually sent. Furthermore, in
`src/authz/approvals.rs:1382-1390`, `Binding::new` stores `expires` (`a.approval_expires_at`)
in `envelope["authorization"]["expires_us"]`, while `effective_until = expires.min(validity(&snap,
&review))` can be earlier because `deciding_session_id` (or `originating_session_id`,
`local_identity_approvals.expires_ms`, or `membership_observations.until_ms`) expires before
`a.approval_expires_at`; once that deciding session expires, `authorized()` returns no `snap`,
so comparing `db_time(c)` only against `envelope["authorization"]["expires_us"]` would
misclassify natural deciding-session expiry as `CancelReason::Revoked`. PR2's next sequential
schema migration (e.g., `0024`, avoiding collision with sibling migrations landing on `main`
first) therefore introduces both **`dispatched_attempts integer DEFAULT NULL CHECK
(dispatched_attempts BETWEEN 0 AND 3)`** and nullable immutable **`effective_expires_us
bigint`** on `openmettle.operations`, installs a `BEFORE UPDATE ON openmettle.operations`
trigger forbidding `dispatched_attempts` `non-null -> NULL` transitions or decrements
(`OLD.dispatched_attempts IS NOT NULL AND (NEW.dispatched_attempts IS NULL OR
NEW.dispatched_attempts < OLD.dispatched_attempts)`) as well as any post-insert mutation of
`effective_expires_us` (`NEW.effective_expires_us IS DISTINCT FROM OLD.effective_expires_us`),
grants `INSERT (dispatched_attempts, effective_expires_us)` and `UPDATE (dispatched_attempts)`
to `openmettle_worker` (keeping `effective_expires_us` immutable with zero `UPDATE` grant to
any runtime role and preserving `openmettle_api`'s zero `INSERT` and zero `UPDATE` grant on
`openmettle.operations`), and adds the matching `$1 >= <v1_14_schema_version>` column entries to
`src/boundaries.sql`. Storing `effective_expires_us` on `openmettle.operations` makes **zero
change** to `Binding` or `request_identity` canonical bytes, and `INSERT_INTENT`
(`src/authz/approvals.rs:1262, 1422`) populates `effective_expires_us` directly from the exact
`$20 = effective_until` value already bound to `INSERT_INTENT`! Pre-upgrade rows and rows
inserted by `N-1` workers during rolling upgrade have **`dispatched_attempts IS NULL`** (legacy
writer without enforced attempt accounting -> treated conservatively as **exhausted
(`coalesce(dispatched_attempts, 3) >= 3`) for dispatch**, since an `N-1` worker without attempt
tracking may already have dispatched up to 3 attempts, and as **unknown (`>= 1` send possible)
for write reconciliation**) and `effective_expires_us IS NULL` (covered by
`invalidate_post_intent`'s independent live unrevoked-credential SQL expiry query below).
- **PR3 database-backed worker rollout gate (`openmettle.runtime_feature_gates` — never exposing `dispatched_attempts = 0` rows to `N-1` workers or `N-1` expiry sweepers):**
  PR3's sequential SQL migration creates a dedicated 1-row feature-gate table:
  ```sql
  CREATE TABLE openmettle.runtime_feature_gates (
      id boolean PRIMARY KEY DEFAULT true CHECK (id),
      two_phase_effect_intents_enabled boolean NOT NULL DEFAULT false
  );
  INSERT INTO openmettle.runtime_feature_gates (id) VALUES (true);
  GRANT SELECT ON openmettle.runtime_feature_gates TO openmettle_api, openmettle_worker;
  ```
  - While `two_phase_effect_intents_enabled = false` (during rolling upgrade while any `N-1`
    `openmettle-worker` claimer or `settle_expired` sweeper is still running):
    1. Scoped MCP tool execution in PR4 fails closed / stays disabled until
       `two_phase_effect_intents_enabled = true`, **and**
    2. Pre-existing ADR 0035 external approval writes (`record_fenced_intent` on non-`repeatable_read`
       capabilities) keep **`dispatched_attempts = NULL`** (`N-1`-compatible single-phase
       behavior) until all `N-1` `openmettle-worker` replicas are drained.
  - Once all `N-1` `openmettle-worker` processes are drained and only `N` workers (carrying the
    updated `unresolved!()`, `leases::handoff`, `settle_locked`, and `settle_expired`
    predicates) are active, `openmettle-admin` / migration rollout flips
    `two_phase_effect_intents_enabled = true` (and `bootstrap` on a fresh database sets
    `two_phase_effect_intents_enabled = true` once migrated to `N`), guaranteeing that **no
    `N-1` worker or `N-1` `settle_expired` sweeper can EVER claim or sweep a
    `dispatched_attempts = 0` row**!

Attempt accounting executes across **two separate `Fence::Step` PostgreSQL transactions**
(while `IntentResult::ApprovalRequired` inserts **zero** `openmettle.operations` rows):

- **Human approval required (`IntentResult::ApprovalRequired`) — zero `openmettle.operations`
  rows:** When `approvals::record_fenced_intent` returns `IntentResult::ApprovalRequired`, it
  writes **zero** `openmettle.operations` rows (`approvals::park`'s `BLOCKS_PARK` check at
  `src/authz/approvals.rs:749-754` rejects parking with `Conflict("unresolved operation")` if
  any `openmettle.operations` row already exists for `logical_key` or any unresolved
  operation). Step 2 drains `StepContext::tasks` and calls `approvals::park`, inserting into
  `openmettle.run_approvals` only.
- **Transaction 1 (Step 1 — `approvals::record_fenced_intent` returning
  `IntentResult::Applied(committed)`):** commits the durable `openmettle.operations`
  `outcome = 'intent'` row with **`dispatched_attempts = 0`** and
  **`effective_expires_us = effective_until`** strictly when `record_fenced_intent` returns
  **`IntentResult::Applied(committed)`** — i.e., on immediate `repeatable_read` calls (PR2,
  leaving write intents at `dispatched_attempts DEFAULT NULL` until PR3 while persisting
  `effective_expires_us = effective_until` on all PR2/PR3 `INSERT_INTENT` rows), and in PR3
  once `openmettle.runtime_feature_gates.two_phase_effect_intents_enabled = true`, on permitted
  automatic (`yolo`) writes and **approved human resume** when `worker::execute` calls
  `record_fenced_intent(..., Some(approval_id))` after human approval — so a worker crash
  before Step 5 leaves a durably committed `dispatched_attempts = 0` row proving zero outbound
  sends occurred and durably recording the exact initial `effective_until` expiry bound.
- **Transaction 2 (Step 5 — separate pre-send `Fence::Step` transaction before attempt 1, and
  before each permitted retry `1 -> 2 -> 3`):** locks `openmettle.runs` (`FOR NO KEY UPDATE`)
  and `openmettle.operations` (`FOR UPDATE`), evaluates live ADR 0035 `EffectPolicy`,
  bound/deciding-session, `effective_expires_us`, and exact committed
  `authority_evidence`/`binding_digest` equality via `authorized(c, &proof, &live_review)`
  **FIRST** (routing expiry/revocation immediately through `approvals::invalidate_post_intent`),
  then requires **`dispatched_attempts IS NOT NULL AND dispatched_attempts < 3`** (treating any
  legacy `NULL` row conservatively as exhausted `coalesce(dispatched_attempts, 3) >= 3` with
  zero outbound sends — recording terminal `outcome = 'failed'` for `repeatable_read` and
  `outcome = 'outcome_unknown'` + `StepResult::Stopped` for writes), and **guards the `UPDATE
  openmettle.operations` statement itself** — `SET dispatched_attempts = 1 ... WHERE ... AND
  o.outcome = 'intent' AND o.dispatched_attempts = 0` strictly before attempt 1 (both in
  `worker::execute`'s approved-adapter path and in the MCP adapter, requiring
  `rows_affected() == 1` strictly before the first outbound byte leaves the process), and `SET
  dispatched_attempts = o.dispatched_attempts + 1 ... AND o.dispatched_attempts < 3` on
  permitted retries — **with the live `{AUTH}` CTE** (`FROM snap, t, openmettle.runs r`,
  mirroring `INSERT_INTENT` in `src/authz/approvals.rs:1262-1267`) so a concurrent session
  logout, grant or capability revocation, or expiry (`db_time(c) >= effective_expires_bound_us`)
  between `authorized()` and `UPDATE` updates `0` rows and settles via ledger-aware
  **`approvals::invalidate_post_intent`** (never calling `invalidate_running`'s raw
  `fail(c, ..., EXPIRED)` post-intent) returning `StepResult::Invalidated(settled)`
  (`WorkEnd::Invalidated(settled)`) with zero `dispatched_attempts` increment and zero sends;
  otherwise commits the monotonic increment (`0 -> 1`, `1 -> 2`, `2 -> 3`) under the
  monotonicity trigger **before** releasing the PostgreSQL connection and issuing the outbound
  HTTP request.

**Explicit narrow amendment to ADR 0035 (`docs/adr/0035-approvals-permitted-yolo-and-effect-ledger.md:260-268`) — discovery and send-permit authorization for proven-unsent (`dispatched_attempts = 0`) writes.**
ADR 0035 forbade issuing a send permit on an existing `openmettle.operations` row because
migration-`0020` `openmettle.operations` lacked `dispatched_attempts` (so `outcome = 'intent'`
could represent an already-dispatched write). ADR 0039 refines ADR 0035 **strictly for
`o.outcome = 'intent' AND o.dispatched_attempts = 0` (`IS NOT NULL AND = 0`)**: because
Transaction 1 commits `dispatched_attempts = 0` and Transaction 2 commits
`dispatched_attempts = 1` strictly before the first outbound byte leaves the process,
`dispatched_attempts = 0` is durable PostgreSQL proof that zero sends ever started. Every row
with `dispatched_attempts IS NULL`, `dispatched_attempts >= 1`, or `outcome <> 'intent'` still
**never** receives a write send permit.

- **How a reclaiming successor discovers BOTH consumed human-approved AND automatic unsent
  writes:**
  1. **Consumed human approval (`src/authz/approvals.rs:1241` `PENDING_EFFECT` /
     `src/worker.rs:519`):** `openmettle.runs.approval_wait_id` remains set after Transaction 1
     inserts `openmettle.operations`, while `PENDING_EFFECT` previously filtered
     `AND NOT EXISTS (SELECT FROM openmettle.operations o WHERE o.run_id = a.run_id AND
     o.logical_key = a.logical_key)`. PR3 updates `PENDING_EFFECT` to the NULL-safe predicate:
     `AND NOT EXISTS (SELECT FROM openmettle.operations o WHERE o.run_id = a.run_id AND o.logical_key = a.logical_key AND (o.outcome = 'intent' AND o.dispatched_attempts = 0) IS NOT TRUE)`
     (never `AND NOT (...)`, because legacy pre-upgrade rows with `o.outcome = 'intent' AND
     o.dispatched_attempts IS NULL` evaluate `NOT UNKNOWN = UNKNOWN`, which drops the row from
     the `NOT EXISTS` subquery and would falsely rediscover consumed legacy approvals!). Under
     SQL 3-valued logic, `(o.outcome = 'intent' AND o.dispatched_attempts = 0) IS NOT TRUE`
     evaluates cleanly across all 4 cases:
     - `outcome = 'intent', dispatched_attempts = 0` -> inner `TRUE` -> `IS NOT TRUE` is `FALSE` -> excluded from blocking subquery -> **discovered** by `PENDING_EFFECT`;
     - `outcome = 'intent', dispatched_attempts = 1` (or `>= 1`) -> inner `FALSE` -> `IS NOT TRUE` is `TRUE` -> matches blocking subquery -> **excluded**;
     - `outcome = 'intent', dispatched_attempts IS NULL` (legacy pre-upgrade row) -> inner `UNKNOWN` -> `IS NOT TRUE` is `TRUE` -> matches blocking subquery -> **excluded**;
     - any non-`'intent'` outcome (`'succeeded'`, `'failed'`, `'outcome_unknown'`) -> inner `FALSE` -> `IS NOT TRUE` is `TRUE` -> matches blocking subquery -> **excluded**;
     (while keeping `REQUEST.consumed` unchanged as `EXISTS (SELECT FROM openmettle.operations
     ...)` so HTTP `decide` still treats the approval as consumed!). Thus `worker::execute`'s
     `approvals::pending_effect` (`src/worker.rs:519`) immediately discovers `(approval_id,
     proposal)` strictly for a consumed human approval whose operation is still `outcome =
     'intent' AND dispatched_attempts = 0`!
  2. **Automatic write (`approval_id IS NULL`):** In `Executor::step` (PR4 worker turn loop),
     deterministic replay of the active turn round re-proposes the tool call to
     `approvals::record_fenced_intent(..., approval = None, ...)` (and before starting any new
     model round, checks for any open `o.approval_id IS NULL AND o.outcome = 'intent' AND
     o.dispatched_attempts = 0` row on `(scope_id, run_id)`).
- **Authorizing `CommittedIntent` in `approvals::record_fenced_intent` (`src/authz/approvals.rs:1291-1337`, PR3):**
  Inside `approvals::record_fenced_intent` (under `leases::fenced(..., Fence::Step, ...)`),
  lock the existing operation row with
  `SELECT id::text, request, capability, outcome, dispatched_attempts, effective_expires_us, approval_id::text FROM openmettle.operations WHERE run_id = $1::uuid AND logical_key = $2 FOR UPDATE`:
  1. If caller supplied `approval = Some(caller_id)` disagreeing with `stored_approval_id`
     (`stored_approval_id.as_deref() != Some(caller_id)`), return `Err(CONFLICT)`.
  2. Otherwise (`approval == None` on an ordinary/reclaimed same-key call, or `approval ==
     stored_approval_id.as_deref()`), resolve `effective_approval =
     stored_approval_id.as_deref()`, verify committed `authorization.basis` (`"human"` iff
     `effective_approval.is_some()`, `"read"` when `effective_approval.is_none() &&
     review.class == EffectClass::Read`, `"yolo"` when `effective_approval.is_none() &&
     review.class != EffectClass::Read`) and `authorization.approval_id == effective_approval`,
     rebuild `binding.envelope(p, &s, &review, effective_approval)?`, and verify
     `durable::existing_intent(c, &intent, effective_approval, &id)` (`request_identity`,
     `request_digest`, and `approval_id` match).
  3. **Zero-attempt write send-permit authorization (`old.outcome == "intent" &&
     old.dispatched_attempts == Some(0) && capability != "repeatable_read"`):**
     - Re-verify live `EffectPolicy` (`live_review = reviewed(policy, &s, &p)?` with exact
       `live_review == committed_review`) + `{AUTH}` (`snap = authorized(c, &proof,
       &live_review)` — loading `openmettle.run_approvals a JOIN
       openmettle.run_approval_decisions d ON d.approval_id = a.id` by `old.approval_id` and
       passing `Some(d.deciding_session_id)` as `Proof.decider` even though `REQUEST.consumed`
       is `true` when `old.approval_id IS NOT NULL`, and verifying automatic `eligible && yolo`
       + `hydrate_worker_principal` + `authorize_capability(YOLO)` when `old.approval_id IS
       NULL`, plus exact byte equality `live_evidence == committed_evidence && live_hash ==
       committed_binding_digest`) + `snap.now < effective_expires_bound_us` (bounded by
       `old.effective_expires_us` and `expires_us.min(validity(&snap, &live_review))`).
     - If live authority, live `EffectPolicy`, or `effective_expires_bound_us` has expired or
       been revoked: route immediately through **`approvals::invalidate_post_intent`** Branch 1
       (`IntentResult::Invalidated(settled)` -> `outcome = 'failed'`, run settles
       `ApprovalExpired` or `Revoked`, zero sends!).
     - If valid: return **`IntentResult::Applied(CommittedIntent { operation_id: op, request:
       old_bytes, effect_deadline, lease_margin_deadline })`**! `CommittedIntent::start(&step)`
       then yields `StartPermit::Ready { request, deadline }`, and **Step 5 Transaction 2**
       (both in `worker::execute`'s approved-adapter path and in the MCP adapter) commits
       `UPDATE openmettle.operations SET dispatched_attempts = 1 WHERE scope_id = $1::uuid AND
       run_id = $2::uuid AND id = $3::uuid AND outcome = 'intent' AND dispatched_attempts = 0`
       (guarded by the live `{AUTH}` CTE under `Fence::Step`, `rows_affected() == 1` required
       strictly before the first outbound byte leaves the process!).
  4. **All other existing-row cases** (`repeatable_read`, `dispatched_attempts IS NULL`,
     `dispatched_attempts >= 1`, or `outcome <> 'intent'`) return `Ok(IntentResult::Replayed(op))`
     cleanly to Step 3 (never issuing a `CommittedIntent` write permit).

Per-call execution uses one fenced sequence in `openmettle-worker`:

1. Call `authz::runs::recheck_leased` with the step's tool capability (which evaluates
   `authorize_run_continuation` on the primary) and execute `approvals::record_fenced_intent`
   under `Fence::Step`. When human approval is required, `record_fenced_intent` returns
   `IntentResult::ApprovalRequired` and writes **zero** `openmettle.operations` rows.
   Otherwise, **Transaction 1** commits the durable `openmettle.operations` `outcome = 'intent'`
   row with **`dispatched_attempts = 0`** and **`effective_expires_us = effective_until`**
   strictly when returning `IntentResult::Applied(committed)` — i.e., on immediate
   `repeatable_read` calls (PR2), and in PR3 once `runtime_feature_gates.two_phase_effect_intents_enabled = true`,
   on permitted automatic (`yolo`) writes and approved human resume when `worker::execute`
   calls `record_fenced_intent(..., Some(approval_id))` after human approval — or re-authorizes
   an existing `outcome = 'intent' AND dispatched_attempts = 0` write row into
   `IntentResult::Applied(CommittedIntent)` under the narrow ADR 0035 amendment above.
2. On `IntentResult::ApprovalRequired` (zero `openmettle.operations` rows written), drain
   `StepContext::tasks`, call `approvals::park` (inserting into `openmettle.run_approvals`
   only) and stop the step so the API can collect the human decision.
3. On `IntentResult::Replayed(op_id)`, do **not** resend a write (`IntentResult::Replayed`
   returns only `operation_id`, never a one-use `CommittedIntent` write permit, and is returned
   for every completed observation, unfinished `repeatable_read`, legacy `dispatched_attempts IS
   NULL` row, or already-dispatched `dispatched_attempts >= 1` write; proven-unsent
   `dispatched_attempts = 0` writes already returned `IntentResult::Applied(CommittedIntent)`
   or `IntentResult::Invalidated(settled)` in Step 1).
   Inspect the existing `operations` row:
   - If `succeeded` or `failed`, never blindly replay cached bytes, previews or errors after
     source access, live `EffectPolicy`, bound/deciding-session authority or exact grant
     evidence is lost. Because `authz::runs::recheck_leased` (`src/authz/runs.rs:402-431`)
     intentionally ignores `originating_session_id`, `approvals::record_fenced_intent`'s
     existing-intent branch (`src/authz/approvals.rs:1291-1337`) returns
     `IntentResult::Replayed(op)` without re-running `reviewed(policy, &s, &p)` or
     `authorized(c, &proof, &live_review)`, and `snap.evidence(&review, auto)`
     (`src/authz/approvals.rs:453-463`) serializes the caller-supplied `Review`, passing a
     deserialized committed `Review` back into `snap.evidence` would allow a disabled or
     changed destination/tool `EffectPolicy` (`tool_policy`, `destination_policy`,
     `endpoint_id`, `endpoint_version`, `endpoint_key`, `class`, `capability`, `gate`, or
     `policy.review(...)` returning `Ok(None)` / `Err(DENIED)`) to match the committed
     evidence; similarly, `authorized(...)` alone (`src/authz/approvals.rs:597-627`) returns a
     live `Snapshot` without comparing `snap.evidence(&live_review, auto)` against the
     committed `authorization.authority` stored in `operations.request`
     (`src/authz/approvals.rs:649-718`, ADR 0035 lines 113–121), so revoking and re-granting a
     tool capability or direct source-artifact share (changing the grant revision/`cycle_id` in
     `authority_evidence`) would otherwise pass `authorized(...)` and return stale cached
     bytes. Therefore, before replaying any completed observation (both here on
     `IntentResult::Replayed(op_id)` and during committed-observation / unacknowledged-commit
     recovery), the worker MUST execute
     **`approvals::recheck_replay_effect_authority(..., policy: &impl EffectPolicy)`** under
     `Fence::Step` on the primary, which:
     1. parses the committed `openmettle.effect` v1 envelope from `operations.request`,
        reconstructing the committed `Proposal` `p` (`logical_key`, `tool`, `tool_version`,
        `arguments`, `destination`) and requiring exact match with the caller's requested
        `Proposal` and stored `operations` columns, and extracting `authorization.basis`
        (`"read"`, `"yolo"`, or `"human"`, with `auto = (basis == "yolo")`),
        `authorization.approval_id`, `authorization.expires_us`,
        `committed_evidence = STANDARD.decode(authorization.authority)`,
        `committed_binding_digest`, and `endpoint` (`committed_review`);
     2. resolves the **current live `Review`** from the supplied `policy` via
        `live_review = reviewed(policy, &s, &p)?` (`policy.review(s.scope, run, &p)?.ok_or(DENIED)?`
        + `live_review.validate()?`), and requires that `live_review` authorizes the call and
        matches the committed `endpoint` with exact `Review` equality
        (`serde_json::to_vec(&live_review) == serde_json::to_vec(&committed_review)` / derived
        `PartialEq, Eq`; note all V1-14 tools have `Review.reservation = None`, and any
        `committed_review.reservation.is_some()` fails closed unless explicitly matched);
     3. when `basis == "human"`, reuses the `openmettle.run_approvals a JOIN
        openmettle.run_approval_decisions d ON d.approval_id = a.id` join
        (`migrations/0022_approvals_and_effect_ledger.sql:38-51`, `src/authz/approvals.rs:541-546`)
        filtered by `WHERE a.scope_id = $scope AND a.run_id = $run AND a.id = $approval_id AND
        a.logical_key = $logical_key`, requires `d.decision == "approve"` and
        `d.binding_digest == a.binding_digest == committed_binding_digest`, and sets
        `decider = Some(d.deciding_session_id)` (otherwise `None`); and
     4. builds `proof = proof(&s, &live_review, decider)`, executes
        `snap = authorized(c, &proof, &live_review)` (verifying live originating/deciding
        session, provider/approval/user generations, run continuation, and — for
        `artifact.read_range` with `live_review.class == EffectClass::Read` and
        `live_review.artifact == Some(artifact_id)` — in-scope read-only `Action::Read`
        visibility without requiring `Action::Write` while binding `$7::uuid` in `AUTH`),
        checks `snap.now < expires_us.min(validity(&snap, &live_review))` (plus
        `automatic(&r, &snap)` and `YOLO` capability when `basis == "yolo"`), **rebuilds
        `live_evidence = snap.evidence(&live_review, auto)` and
        `live_hash = p.binding(&s, expires_us, &live_evidence)` (`Binding::new`), and requires
        exact byte equality `live_evidence == committed_evidence && live_hash ==
        committed_binding_digest`** (enforcing ADR 0035's exact same-evidence-at-use
        invariant across tool capability, direct source-artifact grant cycle, and live
        `EffectPolicy`).
     If `approvals::recheck_replay_effect_authority(..., policy)` fails on live policy,
     session, grant, evidence equality, or expiry (`db_time(c) >= effective_expires_bound_us`),
     route settlement through the dedicated ledger-aware post-intent helper
     **`approvals::invalidate_post_intent`** (defined below — never calling
     `invalidate_running`'s raw `fail(c, ..., EXPIRED)` directly when an `operations` row
     exists), returning `IntentResult::Invalidated(settled)` ->
     `StepResult::Invalidated(settled)` (`WorkEnd::Invalidated(settled)`). Then apply the
     outcome-specific replay rule:
     - For a **`succeeded`** observation backed by a source (`artifact.read_range`) or spilled
       (`storage: "spilled"`, `status: "ok"`) artifact, **in addition to**
       `approvals::recheck_replay_effect_authority(..., policy)`, verify
       `hydrate_worker_principal`, `revision.scope_id == run.scope_id`,
       `authorize_resource(..., Action::Read)`, and `revision.state == "active"` — refusing
       replay and returning **zero** cached bytes (`IntentResult::Invalidated(settled)` ->
       `StepResult::Invalidated(settled)` / `ToolFault::TerminalRefusal`) if the bound or
       deciding session logged out, effect authority was revoked, the live `EffectPolicy`
       disabled or changed the tool/destination policy, or the tool capability or direct
       source-artifact share was revoked and re-granted (changing `authority_evidence`) even
       while artifact `Action::Read` access and `revision.state == "active"` remain valid.
     - For a **`failed`** observation, enforce
       `approvals::recheck_replay_effect_authority(..., policy)` and return its bounded inline
       `status: "tool_error"` envelope (all `failed` tool results use the bounded inline
       `status: "tool_error"` envelope, are never spilled to an artifact, and never carry
       `status: "ok"`).
   - If `intent` or `outcome_unknown`, writes matched by PR3's updated `leases::unresolved!()`
     (`(outcome = 'outcome_unknown' OR (outcome = 'intent' AND coalesce(dispatched_attempts, 1) > 0))
     AND capability IN ('idempotent', 'lookup', 'non_repeatable')`) are **never** resent and defer
     to ADR 0033 and ADR 0035 reconciliation. (A proven-unsent write `outcome = 'intent'` with
     strictly non-null `dispatched_attempts = 0` — yielded cleanly via `WorkEnd::Handoff` /
     `leases::handoff` when `execution_expires_at > clock_timestamp() + settings.lease` — is
     excluded from `leases::unresolved!()`, discovered on successor reclaim via updated
     `PENDING_EFFECT` for consumed human approvals or `Executor::step` for automatic writes,
     and re-authorized directly in Step 1 `approvals::record_fenced_intent` into
     **`IntentResult::Applied(CommittedIntent)`** -> `StartPermit::Ready` -> Step 5 Transaction
     2 `dispatched_attempts: 0 -> 1` rather than entering Step 3 `IntentResult::Replayed`.) Unfinished
     `repeatable_read` operations (`outcome = 'intent'`, where an earlier attempt recorded an
     intent and crashed before recording a terminal observation) are excluded from
     `leases::unresolved_operations` and never enter `Executor::reconcile`. Instead, PR2 adds a
     dedicated fenced read-revalidation helper
     (`approvals::start_replayed_read(..., policy: &impl EffectPolicy)` under `Fence::Step` on
     the primary) that locks `openmettle.runs` (`FOR NO KEY UPDATE`) and
     `openmettle.operations` (`FOR UPDATE`), verifies the operation is
     `capability = 'repeatable_read'` with `outcome = 'intent'`, and **evaluates live
     `EffectPolicy` + `{AUTH}` / `effective_expires_us` authority validity FIRST — BEFORE
     checking `coalesce(dispatched_attempts, 3) >= 3`**:
     1. **Live authority check first (including when `dispatched_attempts IS NULL` or
        `dispatched_attempts == 3`):** Parse the committed `openmettle.effect` v1 envelope from
        `operations.request` (reconstructing committed `Proposal` `p` and requiring exact match
        with the caller's requested `Proposal` and stored `operations` columns, verifying
        `authorization.basis == "read"`, `authorization.expires_us`,
        `committed_evidence = STANDARD.decode(authorization.authority)`,
        `committed_binding_digest`, and `endpoint` (`committed_review`)), **resolve the current
        live `Review` via `live_review = reviewed(policy, &s, &p)?` and require exact equality
        `live_review == committed_review`** (`serde_json::to_vec(&live_review) ==
        serde_json::to_vec(&committed_review)`; failing closed if `committed_review.reservation.is_some()`
        unless explicitly matched), build `proof = proof(&s, &live_review, None)`, execute
        `snap = authorized(c, &proof, &live_review)`, compute
        `effective_expires_bound_us = expires_us.min(validity(&snap, &live_review))` (further
        bounded by `o.effective_expires_us` when `NOT NULL`), check
        `snap.now < effective_expires_bound_us`, **rebuild
        `live_evidence = snap.evidence(&live_review, false)` and
        `live_hash = p.binding(&s, expires_us, &live_evidence)` (`Binding::new`), and require
        exact byte equality `live_evidence == committed_evidence && live_hash ==
        committed_binding_digest`** (so a disabled/changed `EffectPolicy`, expired approval/session,
        a revoked and re-granted read capability, or a revoked and re-granted direct
        source-artifact share fails closed immediately). If the approval, session, user,
        provider, grant, live `EffectPolicy`, or `effective_expires_us` /
        `effective_expires_bound_us` is expired or revoked — **including when
        `dispatched_attempts IS NULL` or `dispatched_attempts == 3`** — route **immediately**
        through **`approvals::invalidate_post_intent` Branch 1** (`outcome = 'failed'` +
        immediate terminal run settlement `openmettle.run-approval-expired` or
        `openmettle.run-revoked`, returning `IntentResult::Invalidated(settled)` ->
        `StepResult::Invalidated(settled)` -> `WorkEnd::Invalidated(settled)` with zero outbound
        sends, skipping any ordinary failed observation and model continuation!).
     2. **Exhaustion check strictly after live authority succeeds:** **Only when live authority
        is still valid**, treat legacy `dispatched_attempts IS NULL` as **conservatively
        exhausted (`coalesce(dispatched_attempts, 3) >= 3`, i.e., dispatch requires
        `dispatched_attempts IS NOT NULL AND dispatched_attempts < 3`)**: if
        `dispatched_attempts IS NULL` or `dispatched_attempts >= 3`, refuse dispatch without
        incrementing, record an ordinary exhausted `outcome = 'failed'` observation (`revision =
        1`, with non-empty redacted evidence) under `Fence::Step` with **zero** outbound HTTP
        sends, and continue the turn.
     3. **Guarded attempt increment (`{AUTH}` CTE):** Under PostgreSQL `READ COMMITTED`, locking
        `runs` and `operations` does not serialize concurrent session logout, grant changes, or
        capability denials between `authorized()` and `UPDATE`; mirroring `INSERT_INTENT`
        (`src/authz/approvals.rs:1262-1267`), `approvals::start_replayed_read` MUST therefore
        **guard the `UPDATE openmettle.operations` statement itself with the live `{AUTH}` CTE**:
        `{AUTH} UPDATE openmettle.operations o SET dispatched_attempts = o.dispatched_attempts + 1 FROM snap, t, openmettle.runs r WHERE o.id = $op_id::uuid AND o.run_id = $11::uuid AND o.scope_id = $5::uuid AND o.capability = 'repeatable_read' AND o.outcome = 'intent' AND o.dispatched_attempts IS NOT NULL AND o.dispatched_attempts < 3 AND r.id = $11::uuid AND r.scope_id = $5::uuid AND r.state = 'running' AND r.cancel_reason IS NULL AND r.claim_token = $claim_token::uuid AND r.lease_expires_at > t.at AND r.execution_expires_at > t.at AND snap.now_us < $effective_expires_bound_us AND snap.base = $expected_base AND snap.tool = $expected_tool RETURNING o.id::text, o.dispatched_attempts`
        (with `$expected_base = snap.base`, `$expected_tool = snap.tool`, and
        `$effective_expires_bound_us` verified against `committed_evidence` and
        `committed_binding_digest`). If that guarded `UPDATE` affects **`0` rows** (because the
        bound session logged out, a grant or capability changed, or lease/execution/effect expiry
        elapsed between `authorized()` and `UPDATE`), settle the running step via **ledger-aware
        `approvals::invalidate_post_intent`** (`IntentResult::Invalidated(settled)` ->
        `StepResult::Invalidated(settled)` -> `WorkEnd::Invalidated(settled)`) with **zero
        `dispatched_attempts` increment and zero outbound sends** (never calling
        `invalidate_running`'s raw `fail(...)`); otherwise return
        `(operation_id, committed_request_bytes, bounded_deadline)` **without** issuing a
        `CommittedIntent` write permit so the adapter can dispatch the committed read bounded by
        `step.deadline.min(bounded_deadline)`.
4. On `IntentResult::Invalidated(settled)`, return **`StepResult::Invalidated(settled)`**
   immediately (mapped in `worker::execute` (`src/worker.rs`) to
   **`WorkEnd::Invalidated(settled)`** so `run_one` exits at `src/worker.rs:652` on
   `Settled::Terminal { .. }` and **immediately calls `leases::release_lease(&mut c, &lease)`
   at `src/worker.rs:660-663` on `Settled::Reconciling { .. }`** without stranding the live
   lease until natural lease expiry).
   - **Dedicated ledger-aware post-intent invalidation/expiry settlement helper
     (`approvals::invalidate_post_intent`, PR2/PR3):** Keep `invalidate_running`'s raw
     `fail(c, lease.scope_id, lease.run_id, EXPIRED)` (`src/authz/approvals.rs:915-924,
     1207-1238`) strictly for **pre-intent** approval expiry where zero `openmettle.operations`
     row exists for the proposed call (and zero other unresolved writes exist). Whenever
     **Step 5 `CommittedIntent::start` (`approvals::expire_unstarted_intent`)**, **Step 5
     Transaction 2**, **Step 3 `approvals::recheck_replay_effect_authority`**, or **Step 3/4
     `approvals::start_replayed_read`** fails `{AUTH}` / live `EffectPolicy` / session / grant /
     `db_time(c) >= effective_expires_bound_us` **after** an `operations` row already exists,
     invoke **`approvals::invalidate_post_intent`** inside the held run lock (first re-verifying
     `state = 'running' AND claim_token = $2::uuid AND cancel_reason IS NULL AND
     least(lease_expires_at, execution_expires_at) > clock_timestamp()`, returning
     `Err(CONFLICT)` / `StepResult::LeaseLost` if the lease lapsed).
     - **Dual durable + independent live unrevoked-credential SQL recovery of
       `effective_expires_bound_us` (never misclassifying shorter-lived deciding-session or
       OIDC-observation expiry as `revoked`):** Inside `approvals::invalidate_post_intent`
       (covering both `o.effective_expires_us IS NOT NULL` and upgraded legacy
       `o.effective_expires_us IS NULL` rows, plus any live credential or endpoint-key expiry),
       compute **`effective_expires_bound_us`** as the `min` over:
       1. durable `o.effective_expires_us` on `openmettle.operations` (when `NOT NULL`,
          persisted from `$20 = effective_until` by `INSERT_INTENT`),
       2. `envelope["authorization"]["expires_us"]` (`a.approval_expires_at` / run execution
          ceiling),
       3. `live_review.endpoint_key` `expires_us` (when `EndpointKey::Supported { expires_us,
          .. }`), and
       4. **direct un-filtered expiry query of bound non-revoked credentials:**
          `SELECT min(least(s.expires_ms, ia.expires_ms) * 1000) FROM openmettle.local_sessions s JOIN openmettle.login_providers p ON p.id = s.provider_id JOIN openmettle.local_identity_approvals ia ON ia.id = s.approval_id AND ia.provider_id = p.id JOIN openmettle.users u ON u.id = s.user_id WHERE s.id IN ($originating_session_id, $deciding_session_id) AND NOT s.revoked AND u.disabled_at IS NULL AND ia.active AND s.provider_generation = p.access_generation AND s.approval_generation = ia.access_generation AND s.user_generation = u.session_generation`,
          plus unrevoked bound `openmettle.membership_observations`
          `least(m.expires_ms, m.issued_ms + 1000::bigint * m.max_age_seconds) * 1000` when
          grants depend on mapped OIDC observations.
       Thus, if `deciding_session_id` (or `originating_session_id`,
       `local_identity_approvals.expires_ms`, or a mapped `membership_observations` window)
       naturally expired (`least(s.expires_ms, ia.expires_ms) * 1000 <= db_time(c)` while
       `NOT s.revoked` and generations still match), **both** `o.effective_expires_us` **and**
       the direct credential query yield `effective_expires_bound_us <= db_time(c)` ->
       classified accurately as **EXPIRY** (`FailReason::ApprovalExpired` / `reason = None`,
       never `cancel_reason = "revoked"`); conversely, if `deciding_session_id` was explicitly
       revoked (`s.revoked = true`) *before* `o.effective_expires_us`, `db_time(c) <
       effective_expires_bound_us` -> classified accurately as **REVOCATION**
       (`CancelReason::Revoked`).
     Extend `leases::FailReason` (`src/authz/leases.rs:304-307`) with
     **`FailReason::ApprovalExpired`** (emitting
     `("openmettle.run-approval-expired", br#"{"reason":"approval_expired"}"#)` in
     `Resolution::event`, matching `approvals::EXPIRED`) so `leases::settle_locked`
     (`src/authz/leases.rs:542-565`) evaluates `SETTLEMENT_INPUTS` (`leases::unresolved!()` on
     the already-locked transaction without nested transactions) uniformly, partitioning
     strictly by **`(capability, outcome, dispatched_attempts)` regardless of caller**
     (`start_replayed_read`, `recheck_replay_effect_authority`, `CommittedIntent::start`, or
     Step 5 Transaction 2):
     1. **Branch 1 — All `repeatable_read` operations at ANY `dispatched_attempts`, zero-attempt
        writes (`dispatched_attempts == Some(0)`), and already-completed `outcome IN
        ('succeeded', 'failed')` rows:** Covers **`capability == 'repeatable_read'` for ALL
        `dispatched_attempts` (`NULL`, `0`, `1`, `2`, `3`) regardless of caller** (explicitly
        including in-process read retries in Step 5 Transaction 2 after transient attempt 1
        failure at `dispatched_attempts == 1` or `2`), plus write `'intent'` rows with
        `dispatched_attempts == Some(0)` and already-completed `outcome IN ('succeeded',
        'failed')` rows. If the target operation is still `outcome = 'intent'`, first record
        `operations.outcome = 'failed'` (`revision = 1`, bounded redacted expiry/revocation
        evidence + ADR 0004 `openmettle/observation/1\0` `run_events` row) so it is no longer
        `'intent'`. Then:
        - if `db_time(c) >= effective_expires_bound_us` (expiry), settle via **ledger-aware**
          `leases::settle_locked(c, lease, ExecState::Running, None, settings,
          Settle::Failed(FailReason::ApprovalExpired))` — producing
          `Settled::Terminal { state: "failed" }` with `openmettle.run-approval-expired` when
          zero unresolved writes remain (`n == 0`), or `Settled::Reconciling` /
          `Settled::Terminal { state: "interrupted" }` if any *other* unresolved write exists
          on the run (`n >= 1`), with **zero** additional outbound sends;
        - if `db_time(c) < effective_expires_bound_us` (authority revocation), execute
          `UPDATE openmettle.runs SET cancel_reason = 'revoked' WHERE id = $1::uuid` and settle
          via `leases::settle_locked(c, lease, ExecState::Running, Some(CancelReason::Revoked),
          settings, Settle::Stopped)` — producing `Settled::Terminal { state: "cancelled" }`
          when `n == 0`, or `Settled::Reconciling` / `Settled::Terminal { state: "interrupted" }`
          when `n >= 1`.
     2. **Branch 2 — Post-dispatch writes (`capability IN ('idempotent', 'lookup',
        'non_repeatable')` with `(outcome == 'intent' AND (dispatched_attempts IS NULL OR
        dispatched_attempts >= 1)) OR outcome == 'outcome_unknown'`):** **NEVER** call
        `fail(...)` or `Settle::Failed(...)`! Perform **zero additional outbound sends**.
        Transition a non-`lookup` write (or any write that cannot be reconciled read-only —
        including `non_repeatable`, an `idempotent` write whose `EndpointKey::Supported` window
        expired so read-only reconciliation cannot resolve it, or a `lookup` write with no
        downstream read-only lookup) from `'intent'` to `outcome = 'outcome_unknown'`
        (`revision = 1`, bounded redacted evidence + `run_events` row), or for a reconcilable
        `authoritative_lookup` / read-only-reconcilable `idempotent` write leave
        `'intent'`/`'outcome_unknown'` unresolved per ADR 0035's `Executor::reconcile` contract
        (either way `leases::unresolved!()` guarantees `n >= 1`). Then settle via **ledger-aware
        `leases::settle_locked(c, lease, ExecState::Running, reason, settings,
        Settle::Stopped)`** — with `reason = Some(CancelReason::Revoked)` (after setting
        `cancel_reason = 'revoked'`) when `db_time(c) < effective_expires_bound_us` (authority
        revocation), and `reason = None` when `db_time(c) >= effective_expires_bound_us`
        (effect/key/session expiry)! Because `n >= 1`, `leases::settle_locked` transitions the
        run into **`Settled::Reconciling { unresolved }`** (when `time_to_reconcile` permits
        `Executor::reconcile`, whereupon returning `StepResult::Invalidated(settled)` ->
        `WorkEnd::Invalidated(settled)` immediately triggers `leases::release_lease(&mut c,
        &lease)` at `src/worker.rs:660-663` so a reclaiming worker immediately runs
        `Executor::reconcile` without waiting for natural lease expiry!) or
        **`Settled::Terminal { state: "interrupted" }`** (appending the `'interrupted'`
        `run-terminal` event and firing PR3's terminal-run trigger to coerce any remaining
        `'intent'` write to `'outcome_unknown'`).
5. On `IntentResult::Applied(committed)`, release the PostgreSQL connection from Transaction 1
   before any I/O and consume the one-use send permit `committed.start(&step)` once before
   attempt 1.
   - **Explicit `StartPermit` on `CommittedIntent::start(&step)` (distinguishing effect/authority
     expiry from shutdown and lease-margin exhaustion in both `worker::execute` at
     `src/worker.rs:533` and Step 5):** Effect, endpoint-key, session, or approval authority can
     expire *after* `record_fenced_intent` Transaction 1 commits (`outcome = 'intent',
     dispatched_attempts = 0`) and *before* `CommittedIntent::start(&step)` runs; returning
     `None` -> `WorkEnd::Complete(Settle::Stopped)` at `src/worker.rs:533-535` (or leaving the
     `dispatched_attempts = 0` write `'intent'` for `Settle::Stopped` in Step 5) would send an
     unsent zero-attempt write into `Reconciling` / `interrupted` instead of marking the
     zero-attempt operation `'failed'` and emitting `openmettle.run-approval-expired` (`state =
     "failed"`). PR2 therefore stores separate **`effect_deadline: Instant`** (`sent +
     Duration::from_micros((effective_until - snap.now).max(0) as u64)`) and
     **`lease_margin_deadline: Instant`** (`sent +
     held.lease_remaining.min(held.execution_remaining).saturating_sub(margin)`) on
     `CommittedIntent` (`src/authz/approvals.rs:1195-1205, 1426-1436`) and replaces
     `Option<(Vec<u8>, Instant)>` on `CommittedIntent::start(self, step: &StepContext)` with
     explicit enum **`StartPermit`** handled uniformly across **both** `worker::execute`
     (`src/worker.rs:533` on resumed human approvals) **and** Step 5's direct adapter path:
     1. **`StartPermit::Stopped(Stop)`** when `let Some(why) = step.stop.borrow().clone()` ->
        caller (`worker::execute` at `src/worker.rs:533` and Step 5) returns `WorkEnd::Stop(why)`
        (with `StepResult::LeaseLost` on `Stop::LeaseLost`, exiting `run_one` without touching
        PostgreSQL): on `Stop::Shutdown`, `run_one` invokes **`leases::handoff`**
        (`src/worker.rs:671`), which under `Fence::Hold` checks `held.cancel.is_none()`,
        `NOT EXISTS (... unresolved!())` (excluding proven-unsent `dispatched_attempts = 0`
        writes), and **`time_to_reclaim = execution_expires_at > clock_timestamp() + $3::bigint *
        interval '1 millisecond'`** (`settings.lease` — the exact `reclaim_next` and
        `SETTLEMENT_INPUTS` `time_to_reconcile` predicate): calling `release_locked` keeping
        `runs.state = 'running'` and `operations.outcome = 'intent', dispatched_attempts = 0`
        when `time_to_reclaim` is `true`, or calling `settle_locked(..., Settle::Stopped)` inside
        the same `Fence::Hold` transaction when `NOT time_to_reclaim` (`<= settings.lease`
        remaining, settling directly to `Resolution::DeadlineExceeded` and closing
        `dispatched_attempts = 0` to `outcome = 'failed', revision = revision + 1`); on terminal
        `Stop::Cancel` or `Stop::Deadline`, `leases::settle_locked` sees `n = 0` from updated
        `leases::unresolved!()`, atomically transitions any remaining `outcome = 'intent' AND
        (capability = 'repeatable_read' OR dispatched_attempts = 0)` rows to `outcome = 'failed',
        revision = revision + 1`, and settles directly to `Resolution::Cancelled` (`cancelled`)
        or `Resolution::DeadlineExceeded` (`failed`, `{"reason":"deadline_exceeded"}`) with zero
        `Reconciling` and zero `Interrupted`.
     2. **`StartPermit::AuthorityExpired { operation_id, request }`** when
        `step.stop.borrow().is_none()` and `Instant::now() >= effect_deadline` (checked
        **before** `lease_margin_deadline` whenever `effect_deadline <= lease_margin_deadline`,
        or whenever `Instant::now() >= effect_deadline && Instant::now() <
        step.deadline.min(lease_margin_deadline)`) -> **both `worker::execute`
        (`src/worker.rs:533` on resumed human approvals) AND Step 5** invoke
        **`approvals::expire_unstarted_intent`** (delegating to
        `approvals::invalidate_post_intent`) on a fresh primary connection under `Fence::Step`:
        - If PostgreSQL confirms `db_time(c) >= effective_expires_bound_us`,
          `invalidate_post_intent` (Branch 1) records `operations.outcome = 'failed'` (`revision
          = 1`, zero outbound sends) on the `dispatched_attempts = 0` `'intent'` row and settles
          via `leases::settle_locked(..., Settle::Failed(FailReason::ApprovalExpired))` ->
          `Settled::Terminal { state: "failed" }` with `openmettle.run-approval-expired` +
          `run-terminal` (returning `WorkEnd::Invalidated(settled)` /
          `StepResult::Invalidated(settled)`).
        - If monotonic clock skew meant `db_time(c) < effective_expires_bound_us`, recompute the
          remaining `Duration::from_micros((effective_expires_bound_us - db_now_us) as u64)`
          (capped by `step.deadline.min(lease_margin_deadline)`), set `step.deadline` to the
          recomputed bound, and proceed into `ApprovedAdapter::send` / Step 5 Transaction 2 with
          the carried `request` bytes!
     3. **`StartPermit::LeaseMarginExhausted`** when `step.stop.borrow().is_none()` and
        `Instant::now() >= step.deadline.min(lease_margin_deadline)` (remaining-lease margin
        cutoff, e.g., `execution_remaining <= settings.lease`, while `shutdown` has NOT fired
        and `Instant::now() < effect_deadline`) -> **never** call `Settle::Stopped` directly
        with a live `dispatched_attempts = 0` write `'intent'`! Add **`StepResult::Handoff`**
        to `pub enum StepResult` and explicit **`WorkEnd::Handoff`** to `WorkEnd` in
        `src/worker.rs`, and update `worker::execute` (`src/worker.rs:554-559`) to map
        **`StepResult::Handoff => return Ok(WorkEnd::Handoff)`** (leaving `StepResult::Stopped
        => return Ok(WorkEnd::Complete(Settle::Stopped))` strictly for graceful worker
        `shutdown`, explicit stop, or `outcome_unknown`!). In `worker::execute`'s
        reviewed-approval branch (`src/worker.rs:536-548`), `StartPermit::LeaseMarginExhausted`
        or pre-dispatch `execution_remaining <= settings.lease` (while `shutdown` has NOT fired)
        returns `Ok(WorkEnd::Handoff)`; in `Executor::step` and `ApprovedAdapter::send`
        (`src/worker.rs:138-156`), hitting `StartPermit::LeaseMarginExhausted` or the
        pre-dispatch remaining-lease margin cutoff returns **`StepResult::Handoff`** (which
        `worker::execute` maps at `src/worker.rs:554-559` to `Ok(WorkEnd::Handoff)`), and
        `run_one` (`src/worker.rs:661-675`) routes `WorkEnd::Handoff` to
        **`leases::handoff(&mut c, &lease, &settings).await`** whenever `cause !=
        Some(Stop::LeaseLost)`, and update **`leases::handoff`** (`src/authz/leases.rs:503-535`,
        under `Fence::Hold`) to check **`time_to_reclaim = execution_expires_at >
        clock_timestamp() + $3::bigint * interval '1 millisecond'`** (`settings.lease` — the
        **exact** `reclaim_next` (`src/authz/leases.rs:595`) and `SETTLEMENT_INPUTS`
        `time_to_reconcile` (`src/authz/leases.rs:497`) predicate!):
        - When `held.cancel.is_none()` AND `NOT EXISTS (... unresolved!())` (excluding
          `dispatched_attempts = 0`) AND **`time_to_reclaim` is `true` (`> settings.lease`
          remaining)**: `leases::handoff` calls `release_locked`, keeping `runs.state =
          'running'` and `operations.outcome = 'intent', dispatched_attempts = 0` so a successor
          worker reclaims (`reclaim_next` -> `recovered == true`) with empty
          `leases::unresolved_operations(..., 1)`, stays in `Running`, discovers the consumed
          human approval via updated `PENDING_EFFECT` (`src/authz/approvals.rs:1241`) or the
          automatic write via `Executor::step`, re-authorizes via `record_fenced_intent`
          returning **`IntentResult::Applied(CommittedIntent)`** under live `EffectPolicy` +
          `{AUTH}`, passes `StartPermit::Ready`, commits `dispatched_attempts: 0 -> 1` in
          Transaction 2, executes the write once, and finishes **`succeeded`**! (If wall time
          passes after `release_locked` so `<= settings.lease` remains before any worker calls
          `reclaim_next`, `leases::settle_expired` settles the lapsed run at
          `execution_expires_at` with `n = 0` from `unresolved!()`, closing
          `dispatched_attempts = 0` to `'failed'` and settling `DeadlineExceeded` with zero
          `Reconciling`/`Interrupted`.)
        - When `held.cancel.is_some()` OR `EXISTS (... unresolved!())` OR **`NOT time_to_reclaim`
          (`<= settings.lease` remaining, e.g., `10 s` left on a `30 s` lease!)**:
          `leases::handoff` calls `settle_locked(..., Settle::Stopped)` right inside the same
          `Fence::Hold` transaction! When `n = 0` (`dispatched_attempts = 0` excluded by
          `unresolved!()`), `cancel = None`, and `!time_to_reclaim`, `leases::decide()`
          (`src/authz/leases.rs:412`) immediately selects **`Resolution::DeadlineExceeded`**
          (`state = 'failed'`, `openmettle.run-failed` `{"reason":"deadline_exceeded"}`) and
          `settle_locked` atomically closes `outcome = 'intent' AND (capability =
          'repeatable_read' OR dispatched_attempts = 0)` to `outcome = 'failed', revision =
          revision + 1` — zero stranded unreclaimable run, zero `Reconciling`, zero `Interrupted`!
     4. **`StartPermit::Ready { request, deadline }`** when all deadlines remain live -> apply
        `step.deadline = deadline` and proceed to `ApprovedAdapter::send` / Step 5 Transaction 2.
   On resumed human approvals, `worker::execute` (`src/worker.rs:533`) has already called
   `record_fenced_intent(..., Some(approval_id))` (committing Transaction 1's
   `dispatched_attempts = 0` and `effective_expires_us = effective_until` row on
   `IntentResult::Applied`, or re-authorizing an existing `outcome = 'intent' AND
   dispatched_attempts = 0` row into `IntentResult::Applied`), matched `intent.start(&step)`
   across all four `StartPermit` variants (handling `AuthorityExpired` / `Stopped` /
   `LeaseMarginExhausted` cleanly before dispatch), and on `StartPermit::Ready { request,
   deadline }` passes `ApprovedAdapter::send` the committed request bytes and shortened
   `step.deadline`.
   Before issuing attempt 1 — and in a fresh **Transaction 2** before each permitted retry
   (`1 -> 2 -> 3`) — execute a **separate** short `Fence::Step` PostgreSQL transaction that
   locks `openmettle.runs` (`FOR NO KEY UPDATE`) and `openmettle.operations` (`FOR UPDATE`),
   verifies `outcome = 'intent'`, **evaluates live `EffectPolicy` + `{AUTH}` /
   `effective_expires_us` authority validity FIRST before checking `dispatched_attempts`
   exhaustion** — resolving the current live `Review` via `live_review = reviewed(policy, &s,
   &p)?` requiring exact `live_review == committed_review`, loading `d.deciding_session_id` and
   `d.decision == "approve"` with `d.binding_digest == a.binding_digest ==
   committed_binding_digest` via `openmettle.run_approvals a JOIN
   openmettle.run_approval_decisions d ON d.approval_id = a.id` when `basis == "human"`,
   executing `snap = authorized(c, &proof, &live_review)` verifying
   `effective_expires_bound_us = expires_us.min(validity(&snap, &live_review))` (further bounded
   by `o.effective_expires_us` when `NOT NULL`),
   `snap.now < effective_expires_bound_us`, `automatic(&r, &snap)` + `YOLO` capability when `auto =
   (basis == "yolo")`, and exact committed `snap.evidence(&live_review, auto) ==
   committed_evidence && live_hash == committed_binding_digest` (routing any expired or revoked
   authority immediately through `approvals::invalidate_post_intent` even if
   `dispatched_attempts IS NULL` or `>= 3`!) — **and only when live authority is valid** checks
   `dispatched_attempts IS NOT NULL AND dispatched_attempts < 3` (treating legacy `NULL` as
   conservatively exhausted `coalesce(dispatched_attempts, 3) >= 3`), and **guards the `UPDATE
   openmettle.operations` statement itself with the live `{AUTH}` CTE** (mirroring
   `INSERT_INTENT` in `src/authz/approvals.rs:1262-1267`):
   - **Attempt 1 (both in `worker::execute`'s approved-adapter path and in the MCP adapter):**
     `{AUTH} UPDATE openmettle.operations o SET dispatched_attempts = 1 FROM snap, t, openmettle.runs r WHERE o.id = $op_id::uuid AND o.run_id = $11::uuid AND o.scope_id = $5::uuid AND o.outcome = 'intent' AND o.dispatched_attempts = 0 AND r.id = $11::uuid AND r.scope_id = $5::uuid AND r.state = 'running' AND r.cancel_reason IS NULL AND r.claim_token = $claim_token::uuid AND r.lease_expires_at > t.at AND r.execution_expires_at > t.at AND snap.now_us < $effective_expires_bound_us AND snap.base = $expected_base AND snap.tool = $expected_tool AND (NOT $auto OR (snap.eligible AND snap.yolo = $expected_yolo)) RETURNING o.id::text, o.dispatched_attempts`
     (`rows_affected() == 1` strictly required before the first outbound byte leaves the process!).
   - **Permitted retries (`1 -> 2 -> 3`):**
     `{AUTH} UPDATE openmettle.operations o SET dispatched_attempts = o.dispatched_attempts + 1 FROM snap, t, openmettle.runs r WHERE o.id = $op_id::uuid AND o.run_id = $11::uuid AND o.scope_id = $5::uuid AND o.outcome = 'intent' AND o.dispatched_attempts IS NOT NULL AND o.dispatched_attempts < 3 AND r.id = $11::uuid AND r.scope_id = $5::uuid AND r.state = 'running' AND r.cancel_reason IS NULL AND r.claim_token = $claim_token::uuid AND r.lease_expires_at > t.at AND r.execution_expires_at > t.at AND snap.now_us < $effective_expires_bound_us AND snap.base = $expected_base AND snap.tool = $expected_tool AND (NOT $auto OR (snap.eligible AND snap.yolo = $expected_yolo)) RETURNING o.id::text, o.dispatched_attempts`
   (under the monotonicity trigger, with `$expected_base = snap.base`, `$expected_tool =
   snap.tool`, `$expected_yolo = snap.yolo`, and `$effective_expires_bound_us`). If pre-`UPDATE`
   policy/authority/expiry checks fail or that guarded `UPDATE` affects **`0` rows** (because a
   deciding or originating session logged out, a grant or capability changed, or
   lease/execution/effect/key expiry elapsed between `authorized()` and `UPDATE`), settle the
   running step via **ledger-aware `approvals::invalidate_post_intent`**
   (`IntentResult::Invalidated(settled)` -> `StepResult::Invalidated(settled)` ->
   `WorkEnd::Invalidated(settled)`) with **zero `dispatched_attempts` increment and zero
   outbound sends** (never calling `invalidate_running`'s raw `fail(...)`); otherwise commit
   the monotonic increment (`0 -> 1`, `1 -> 2`, `2 -> 3`) **before** releasing the PostgreSQL
   connection and issuing the outbound HTTP request.
6. Dispatch the committed `openmettle.effect` v1 envelope through `ApprovedAdapter::send` (the
   same committed-envelope path for immediate reads, permitted YOLO writes and resumed human
   approvals; unfinished `repeatable_read` replays reuse the same committed-envelope dispatch
   with the bytes and deadline returned by `approvals::start_replayed_read`).
7. When `EndpointKey::Supported { field, key, .. }` is recorded in the committed envelope, emit
   `key` unchanged in the contract-pinned HTTP header or JSON-RPC `_meta` field. Never
   allocate a fresh key for the same `logical_key`.
8. After dispatch, record the outcome in PostgreSQL with the expected revision, stable append
   key, `downstream_handle` when returned and bounded redacted evidence:
   - For **inline** `succeeded` results, **all `failed` tool results** (which always use the
     bounded inline `status: "tool_error"` envelope and are never spilled) or
     `truncated_no_spill` fallbacks, borrow a connection and commit `runs::record_observation`
     under `leases::with_lease(..., Fence::Hold, ...)` (or under `Fence::Step` returning
     `StepResult::Continue` when a completed known-outcome call aborts spill publication solely
     because its shortened local `step.deadline` elapsed while `step.stop` remains `None`
     through commit; see the spill-abort disposition rules below, including the mandatory
     `*step.stop.borrow()` rechecks under the `runs` lock and immediately before commit). If
     the fence rejects with `LeaseError::StaleClaim`, `LeaseError::Expired` or
     `LeaseError::Terminal` — or `*step.stop.borrow()` signals `Some(Stop::LeaseLost)` before
     commit — roll back and stop immediately with **`StepResult::LeaseLost`** without further
     PostgreSQL writes.
   - For **spilled `succeeded`** results (`storage: "spilled"`, `status: "ok"`), `storage::settle`
     and `runs::record_observation` commit **atomically together in Phase 3's single
     `Fence::Step` transaction** (never across two separate transactions; see the three-phase
     publication rules below).
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
     deposed worker MUST stop immediately with **`StepResult::LeaseLost`** (added to
     `pub enum StepResult` in **PR2** alongside **`StepResult::Invalidated(leases::Settled)`**
     and **`StepResult::Handoff`** — mapping `StepResult::LeaseLost` in `worker::execute`
     (`src/worker.rs:554-559`) to `WorkEnd::Stop(Stop::LeaseLost)` so `run_one` exits at
     `src/worker.rs:652` without touching PostgreSQL, mapping `StepResult::Invalidated(settled)`
     directly to `WorkEnd::Invalidated(settled)` so `Settled::Reconciling { .. }` immediately
     executes `leases::release_lease(&mut c, &lease)` at `src/worker.rs:660-663`, and mapping
     `StepResult::Handoff` to `return Ok(WorkEnd::Handoff)` so `run_one` calls `leases::handoff`
     while leaving `StepResult::Stopped => return Ok(WorkEnd::Complete(Settle::Stopped))`
     strictly for graceful `shutdown`, explicit stop, or `outcome_unknown`!). On an expired or
     replaced non-terminal lease (`Expired` or `StaleClaim`), returning `StepResult::LeaseLost`
     leaves the already-committed durable `outcome = 'intent'` write row intact so the
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
- **Header admission, `Mcp-Name` `#value-encoding` and `params._meta` (`2026-07-28`).**
  Mirroring [ADR 0038](0038-sglang-and-external-provider-conformance-adapter.md), add a narrow
  MCP request builder in `src/provider_http/` without widening `Route::send`. Allow only `POST`
  with `Content-Type: application/json`, `Accept: application/json, text/event-stream`,
  `MCP-Protocol-Version: 2026-07-28`, `Mcp-Method` (`tools/call` or `tools/list`), `Mcp-Name`
  (the reviewed tool name on `tools/call`), an optional server-supplied `Authorization` marked
  `HeaderValue::set_sensitive(true)` and an optional contract-pinned `Idempotency-Key` header.
  Because `Proposal::new` admits bounded UTF-8 tool names (`1..=128` bytes), constructing the
  `Mcp-Name` HTTP header from the reviewed `params.name` MUST enforce MCP `2026-07-28`
  Streamable HTTP `#value-encoding` (reusing already-locked `base64 = "=0.22.1"`):
  - Emit `Mcp-Name` verbatim (`params.name` as-is) **if and only if** `params.name` is
    non-empty, every byte is in `0x20..=0x7E` (printable ASCII `0x21..=0x7E` or interior ASCII
    space `0x20` — **zero control bytes `0x00..=0x1F` (explicitly encoding `0x09` HTAB)**, zero
    `0x7F`, and zero non-ASCII bytes `>= 0x80`), has **no leading or trailing `0x20` space**
    (that RFC 9110 OWS stripping would alter), **AND does NOT simultaneously start with
    `"=?base64?"` and end with `"?="`** (for example, `"left\tright"` encodes to
    `=?base64?bGVmdAlyaWdodA==?=`).
  - Otherwise (any non-ASCII byte `>= 0x80`, any control byte `0x00..=0x1F` including `0x09`
    HTAB, `0x7F`, leading/trailing `0x20` space, or literal `"=?base64?...?="` sentinel
    collision), encode `Mcp-Name` on the wire as
    **`format!("=?base64?{}?=", base64::engine::general_purpose::STANDARD.encode(name.as_bytes()))`**
    while keeping `params.name` in the JSON-RPC request body as the exact raw UTF-8 string.
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
- **Stateless single-call framing (`2026-07-28`) and HTTP/1.1 interim `1xx` handling.** Each
  `tools/call` uses one request/response exchange over `hyper::client::conn::http1`. Under RFC
  9110 §15.2, non-`101` informational `1xx` interim responses (`100`, `102`–`199`, e.g., `103
  Early Hints`) are consumed by HTTP/1.1 framing within the overall `call_timeout`, the
  per-header-block `<= 32` headers / `<= 8 KiB` ceiling, and a bounded maximum of **`<= 4`
  interim `1xx` responses** per exchange (preventing infinite `1xx` drip attacks) while
  awaiting the **final** non-`1xx` HTTP response; exceeding `4` interim `1xx` responses fails
  closed as `ToolFault::TerminalRefusal`. Unrequested **`101 Switching Protocols`** (protocol
  upgrade when no `Upgrade` header was sent) is rejected immediately as
  `ToolFault::TerminalRefusal` (`0` retries; `outcome = "outcome_unknown"` +
  `StepResult::Stopped` on post-send writes). The HTTP status taxonomy (`200` success vs
  `{408, 429, 502, 503, 504}` -> `ToolFault::Transient` vs every other **final** non-`200`
  status `201`, `202`, `204`, `3xx`, `401`, `403`, other `4xx`, `500`, `501`, `505+` ->
  `ToolFault::TerminalRefusal`) applies strictly to the **final** non-`1xx` HTTP response
  status. On final `200 OK`, accept `application/json` (one JSON-RPC 2.0 response matching the
  request `id`) or `text/event-stream` (Server-Sent Events delivering optional SSE comments and
  progress notifications before one final matching JSON-RPC 2.0 response event). A matching
  JSON-RPC `id` alone does not prove completion: under MCP `2026-07-28`, server-initiated
  JSON-RPC requests are not permitted on a response stream when client capabilities declare
  none (`{}`) — interactive prompts (such as elicitation or sampling) instead return an
  `input_required` result. Any unexpected server-to-client JSON-RPC request frame on SSE or any
  `input_required` result violates this stateless non-interactive profile and is rejected
  closed as `ToolFault::TerminalRefusal` (unsupported protocol/contract fault) without issuing
  follow-up calls and without recording tool success. Match media types and `charset=utf-8`
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
  maximum `300 s`). `CommittedIntent::start(self, &step)` returns the explicit `StartPermit`
  enum (`StartPermit::Stopped(Stop)`, `StartPermit::AuthorityExpired { operation_id, request }`,
  `StartPermit::LeaseMarginExhausted`, `StartPermit::Ready { request, deadline }`) and is
  consumed once before attempt 1 (including in `worker::execute` at `src/worker.rs:533` on
  resumed human approvals, where `StartPermit::AuthorityExpired` invokes
  `approvals::expire_unstarted_intent` / `approvals::invalidate_post_intent` under `Fence::Step`
  instead of routing an unsent `dispatched_attempts = 0` write into `Settle::Stopped` /
  `Reconciling`; `StartPermit::Stopped(Stop::Shutdown)` returns `WorkEnd::Stop(Stop::Shutdown)`
  and `StartPermit::LeaseMarginExhausted` returns explicit **`WorkEnd::Handoff`** in
  `worker::execute`'s reviewed-approval branch (`src/worker.rs:536-548`) and
  **`StepResult::Handoff`** in `Executor::step` / `ApprovedAdapter::send`
  (`src/worker.rs:138-156`, mapped by `worker::execute` at `src/worker.rs:554-559` to
  `Ok(WorkEnd::Handoff)`, leaving `StepResult::Stopped => Ok(WorkEnd::Complete(Settle::Stopped))`
  strictly for graceful `shutdown` / explicit stop / `outcome_unknown`), both routed in
  `run_one` (`src/worker.rs:661-675`) to **`leases::handoff(&mut c, &lease, &settings)`**
  whenever `cause != Some(Stop::LeaseLost)`, where `leases::handoff` checks **`time_to_reclaim =
  execution_expires_at > clock_timestamp() + $3::bigint * interval '1 millisecond'`**
  (`settings.lease` — matching `reclaim_next` at `src/authz/leases.rs:595` and
  `SETTLEMENT_INPUTS` `time_to_reconcile` at `src/authz/leases.rs:497`): when `held.cancel.is_none()`,
  `NOT EXISTS (... unresolved!())` (updated `leases::unresolved!()` excludes
  `dispatched_attempts = 0`), and `time_to_reclaim` is `true` (`> settings.lease` remaining),
  `leases::handoff` calls `release_locked` keeping `runs.state = 'running'` and
  `dispatched_attempts = 0` for clean successor reclaim in `Running` (where the successor
  discovers the row via updated `PENDING_EFFECT` or `Executor::step`, obtains
  `IntentResult::Applied(CommittedIntent)` from `approvals::record_fenced_intent` after live
  authority re-verification, and commits `dispatched_attempts: 0 -> 1` in Transaction 2),
  whereas when `NOT time_to_reclaim` (`<= settings.lease` remaining) or `held.cancel.is_some()`,
  `leases::handoff` calls `settle_locked(..., Settle::Stopped)` inside that same `Fence::Hold`
  transaction so `decide()` (`src/authz/leases.rs:412`) immediately settles
  `Resolution::DeadlineExceeded` (`state = 'failed'`, `{"reason":"deadline_exceeded"}`) or
  `Resolution::Cancelled` while atomically transitioning remaining `outcome = 'intent' AND
  (capability = 'repeatable_read' OR dispatched_attempts = 0)` rows to `outcome = 'failed',
  revision = revision + 1` with zero `Reconciling` / `Interrupted` and zero stranded
  unreclaimable runs; terminal `Stop::Cancel` / `Stop::Deadline` settle directly the same way;
  and `StartPermit::Ready` leaves the shortened `step.deadline` incorporating
  `EndpointKey::Supported.expires_us` and intent authority expiry). Before **every** outbound
  dispatch attempt across **all** effect classes (initial attempt 1, every permitted in-process
  retry of `repeatable_read`, active unexpired `idempotent` writes, or proven-pre-send
  connection-refused/DNS retries of `lookup` and `non_repeatable` writes, and every
  `start_replayed_read` crash-reclaim replay), enforce `step.stop`, `step.deadline` (including
  `EndpointKey::Supported.expires_us`) **and** a short `Fence::Step` transaction on the primary
  that **evaluates live `EffectPolicy` + `{AUTH}` / `effective_expires_us` authority validity
  FIRST before checking `dispatched_attempts` exhaustion** — resolving the current live `Review`
  via `live_review = reviewed(policy, &s, &p)?` and requiring exact equality `live_review ==
  committed_review`, loading `d.deciding_session_id` and `d.decision == "approve"` with
  `d.binding_digest == a.binding_digest == committed_binding_digest` from
  `openmettle.run_approvals a JOIN openmettle.run_approval_decisions d ON d.approval_id = a.id`
  when `basis == "human"`, verifying current principal, scope, target, capability and
  destination policy **plus** the live bound originating/deciding session,
  approval/user/provider generations, and exact committed `authority_evidence` +
  `binding_digest` equality per ADR 0035 (never relying on `recheck_leased` alone, which
  intentionally ignores `originating_session_active` for background run continuation; routing
  expired or revoked authority immediately through `approvals::invalidate_post_intent` even if
  `dispatched_attempts IS NULL` or `>= 3`!) — **and only when live authority is valid** enforces
  `dispatched_attempts IS NOT NULL AND dispatched_attempts < 3` (treating legacy `NULL` as
  conservatively exhausted `coalesce(dispatched_attempts, 3) >= 3`) **and guards the `UPDATE
  openmettle.operations SET dispatched_attempts = o.dispatched_attempts + 1` statement itself
  with the live `{AUTH}` CTE** (`FROM snap, t, openmettle.runs r`, verifying
  `o.dispatched_attempts IS NOT NULL AND o.dispatched_attempts < 3`, `$expected_base`,
  `$expected_tool`, `(NOT $auto OR (snap.eligible AND snap.yolo = $expected_yolo))`,
  `snap.now_us < $effective_expires_bound_us` bounded by `o.effective_expires_us`,
  `envelope["authorization"]["expires_us"]`, `EndpointKey::Supported.expires_us`, and bound
  unrevoked session/OIDC expiry, and active claim/lease/execution timestamps, mirroring
  `INSERT_INTENT` at `src/authz/approvals.rs:1262-1267`; settling via caller-independent
  ledger-aware `approvals::invalidate_post_intent` -> `StepResult::Invalidated(settled)` with
  zero increment and zero sends if `0` rows are updated, never calling `invalidate_running`'s
  raw `fail(...)`). While I/O is in flight, follow ADR 0038: race `step.stop`, `step.deadline`,
  `ActiveRun::execution_deadline` and the adapter timeouts. On any stop signal, drop the HTTP
  future immediately so the socket closes.

### Typed fault taxonomy and retry rules (`PLAN-10`)

Every tool failure maps to one of three disjoint fault classes. **Pre-intent refusals** (schema
or bounds validation failures such as `max_bytes < 4`, `x-mcp-header`-annotated tool schemas,
unpinned destinations, unknown tools, prohibited effects, missing V1-28 credentials or V1-17
quota refusals occurring before `approvals::record_fenced_intent` commits) **write zero
`openmettle.operations` rows** and never call `runs::record_observation` (returning a bounded
redacted inline `ToolFault::TerminalRefusal` envelope when run authority remains valid, or
settling the run if authority was invalidated); `runs::record_observation` (`outcome = 'failed'`
or `'outcome_unknown'`) applies strictly **after** an `openmettle.operations` row has been
committed. **Every `failed` tool result** (`ToolFault::Semantic`, known-outcome
`ToolFault::Transient`, or pre-/post-intent `ToolFault::TerminalRefusal`) MUST return the
**bounded inline error envelope (`status: "tool_error"`, closed `fault_code`, `<= 2 KiB` UTF-8
summary, `retryable_by_model`, never spilled to an artifact and never carrying `status: "ok"`)**.

The adapter tracks transport send uncertainty as a **sticky flag across the whole logical
operation**: once attempt 1 may have left the process (timeout, socket reset, mid-stream
disconnect, or any HTTP response after request bytes were written to the socket), any
subsequent retry that fails pre-send, hits a deadline or stop signal, or returns `401`/`403`,
HTTP `500` or malformed framing MUST keep the ledger outcome `outcome_unknown` (never
downgrading to proven-unsent `failed` or `aborted`). Whenever **any** external write (`lookup`,
`non_repeatable`, or an `idempotent` write whose retries or `EndpointKey::Supported` window
expired after a possible send, or **any** write that received a post-send HTTP refusal —
**explicitly including first-attempt HTTP `401` and `403`** — because an HTTP status code alone
cannot prove an upstream server or proxy did not mutate state before or while returning
`401`/`403`) ends with `outcome_unknown`, the adapter attempts to commit
`outcome = "outcome_unknown"` via `runs::record_observation` under `Fence::Hold`: on commit, it
returns **`StepResult::Stopped`** immediately — **never** `StepResult::Continue` and never a
model-visible error envelope — so `leases::settle(..., Settle::Stopped)` moves the run into
`ExecState::Reconciling` (or terminal `interrupted`) with zero further model rounds; if
`Fence::Hold` rejects with `LeaseError::StaleClaim`, `LeaseError::Expired` or
`LeaseError::Terminal`, the deposed worker stops immediately with **`StepResult::LeaseLost`**
without touching PostgreSQL so the intact durable `outcome = 'intent'` write row routes the
replacement worker (`src/worker.rs`) straight into `ExecState::Reconciling` / settlement before
any model step. By contrast, `retryable_by_model: false` in model-visible
`status: "tool_error"` envelopes applies to **known-outcome** non-retryable failures (such as
pre-intent validation/policy refusals, proven pre-send transport failures where zero request
bytes ever left the process across all attempts, downstream `401`/`403` on **`repeatable_read`**
only, or contract-guaranteed side-effect-free `isError` responses where no uncertain write
occurred and the run may continue within its round budget).

| Fault class | Qualifying evidence | Retries | Ledger outcome | Model / worker action |
| --- | --- | --- | --- | --- |
| **Transient transport** (`ToolFault::Transient`) | Pre-send DNS/TCP connect failure; final HTTP `408`, `429`, `502`, `503`, `504` (exhaustive transient final HTTP status set); mid-stream disconnect or idle/call timeout | Up to `3` durable total attempts (`openmettle.operations.dispatched_attempts IS NOT NULL AND dispatched_attempts < 3`, treating legacy `NULL` as conservatively exhausted `coalesce(dispatched_attempts, 3) >= 3`, atomically incremented via an `{AUTH}`-guarded `UPDATE openmettle.operations SET dispatched_attempts = o.dispatched_attempts + 1 ... FROM snap, t, openmettle.runs r` under `Fence::Step` before each send, settling via ledger-aware `approvals::invalidate_post_intent` -> `StepResult::Invalidated(settled)` on `0` rows updated) for `repeatable_read` and active unexpired `idempotent` writes with the identical persisted key; for `lookup` and `non_repeatable` writes, retry **only** proven pre-send DNS/connection-refused failures and **never** retry after request bytes are sent. Before **every** permitted retry across all classes, enforce `dispatched_attempts IS NOT NULL AND dispatched_attempts < 3`, `step.stop`, `step.deadline` (including `EndpointKey::Supported.expires_us`) and a fenced ADR 0035 effect-level authority recheck (live `EffectPolicy` resolution `live_review = reviewed(policy, &s, &p)?` with exact `live_review == committed_review`, `run_approvals JOIN run_approval_decisions` for `basis == "human"`, principal, scope, target, capability, destination policy plus live bound originating/deciding session, approval/user/provider generations, and exact committed `authority_evidence` + `binding_digest` equality, re-verified atomically inside the `{AUTH}`-guarded `UPDATE`). | Post-intent (`runs::record_observation`): `failed` for exhausted `repeatable_read` or proven pre-send failure when no prior attempt left the process; `outcome_unknown` for any `idempotent`, `lookup` or `non_repeatable` write once any attempt may have left the process without endpoint proof. | Sleep with `ring::rand::SystemRandom` full jitter (`250 ms`, `500 ms`). For a single valid integer `Retry-After` (seconds): sleep at least that delay when `<= 60 s` and within remaining call, authority and run execution deadlines; fail without retrying if `Retry-After` exceeds `60 s` or the remaining budget; ignore malformed or duplicate headers. Abort sleep immediately on `step.stop`. For known-outcome `failed` reads or proven-unsent writes, return the bounded inline error envelope (`status: "tool_error"`, closed `fault_code`, `<= 2 KiB` UTF-8 summary, `retryable_by_model`, never spilled). For **every** write ending in `outcome_unknown` (including an `idempotent` write whose retries or `EndpointKey::Supported` window expired after a possible send), attempt `outcome = "outcome_unknown"` under `Fence::Hold` and return `StepResult::Stopped` into `ExecState::Reconciling` / `interrupted`, or `StepResult::LeaseLost` immediately without touching PostgreSQL if `Fence::Hold` rejects with `StaleClaim`, `Expired` or `Terminal` (zero further model rounds). |
| **Semantic tool fault** (`ToolFault::Semantic`) | MCP JSON-RPC `result` with `isError: true`, JSON-RPC `-32602`, or internal tool domain refusal (for example invalid UTF-8 binary content, offset past EOF or non-`active` revision) | `0` transport retries | Post-intent (`runs::record_observation`): `failed` for reads and for writes whose reviewed contract guarantees `isError: true` caused no side effect (and no prior attempt was ambiguous); otherwise `outcome_unknown`. | For known-outcome `failed` results, return the bounded inline structured error envelope (`status: "tool_error"`, closed `fault_code`, `<= 2 KiB` UTF-8 summary, `retryable_by_model`, never spilled to an artifact and never `status: "ok"`) so the model can recover within `round_limit`. If an uncertain write ends in `outcome_unknown`, attempt `outcome = "outcome_unknown"` under `Fence::Hold` and return `StepResult::Stopped` into reconciliation/settlement (or `StepResult::LeaseLost` on `StaleClaim`, `Expired` or `Terminal`, never `StepResult::Continue`). |
| **Policy, auth or contract failure** (`ToolFault::TerminalRefusal`) | Pre-intent admission refusals: revoked session/grant/capability, schema/bounds violation (`max_bytes < 4`), `x-mcp-header`-annotated tool schema, unpinned destination, unknown tool, prohibited effect, missing V1-28 credential or V1-17 quota. Post-intent transport/protocol refusals: SSRF `Address`, TLS cert/host failure, unrequested **`101 Switching Protocols`** (or `> 4` interim `1xx` responses; non-`101` informational `1xx` such as `103 Early Hints` are consumed within `call_timeout` and `8 KiB` / `32` header bounds while awaiting the final HTTP response), **every final non-`200` HTTP status code outside `{408, 429, 502, 503, 504}` — explicitly including HTTP `500`, other unlisted `5xx` (`501`, `505+`), non-`200` `2xx` (`201`, `202`, `204`), `3xx` redirects, `401`/`403`, and other `4xx`**, `tools/list` drift, `input_required` or server-initiated JSON-RPC request, malformed JSON-RPC/framing, or `> 4 MiB` response | `0` retries | **Pre-intent refusals write zero `openmettle.operations` rows** (never calling `runs::record_observation`). **Post-intent (`runs::record_observation`):** `failed` strictly for `repeatable_read` or, for writes (`idempotent`, `lookup`, `non_repeatable`), **strictly when zero request bytes ever left the process across all attempts** (proven pre-send local failure on attempt 1 prior to writing any request bytes to the socket, e.g., pre-connect DNS/SSRF `Address` refusal, TCP connect failure, or TLS handshake failure before HTTP write); **`outcome_unknown`** for **every** post-send write refusal — **explicitly including first-attempt HTTP `401` and `403`, HTTP `500`, other unlisted `5xx` (`501`, `505+`), unrequested `101 Switching Protocols` (or `> 4` interim `1xx` frames), final non-`200` `2xx` (`201`, `202`, `204`), `3xx` redirects, and other `4xx`**, as well as `input_required`, malformed framing, `TooLarge`, or any fault after a prior ambiguous attempt. | Fail closed immediately without follow-up calls. Authority revocation settles the run under ADR 0033/0035. Pre-intent refusals (when run authority remains valid) and post-intent known-outcome `failed` refusals (`repeatable_read` or proven pre-send write failures with zero bytes written across all attempts) return the bounded inline error envelope (`status: "tool_error"`, closed `fault_code`, `<= 2 KiB` UTF-8 summary, `retryable_by_model: false`, never spilled, no upstream body echoing). **Every** post-send write refusal (explicitly including first-attempt HTTP `401`/`403` and unrequested `101 Switching Protocols`) records `outcome = "outcome_unknown"` under `Fence::Hold` and returns **`StepResult::Stopped`** into `ExecState::Reconciling` / `interrupted` (or `StepResult::LeaseLost` on `StaleClaim`, `Expired` or `Terminal`, never `StepResult::Continue`). |

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

Normalized UTF-8 **`succeeded`** tool outputs obey three size bands (with `artifact.read_range`
explicitly exempt from spill publication because each `artifact.read_range` page is capped at
`<= 200` lines and `<= 16_384` serialized JSON bytes and paginates via `next_offset`). Spill
publication (`storage: "spilled"`, `status: "ok"`) is restricted **exclusively to `succeeded`
tool outputs**; every `failed` tool result uses the bounded inline `status: "tool_error"`
envelope (`<= 2 KiB` UTF-8 summary, never spilled to an artifact). The `16 KiB` (`16_384`
bytes) ceiling applies to the **final UTF-8 serialized JSON tool-result string** (after JSON
escaping — such as `\u001b` 6x expansion — and all envelope and provenance metadata), never
just raw unescaped output bytes:

| Band | Condition | Handling |
| --- | --- | --- |
| **Inline** | `succeeded` output with `<= 200` lines **and** final UTF-8 serialized JSON inline envelope `<= 16_384` bytes | Returned directly in the tool-result envelope (`status: "ok"`, `storage: "inline"`, `truncated: false`, `size_bytes`, `line_count`, `content_sha256`). |
| **Spill** | `succeeded` output exceeding `200` lines or `16_384` serialized JSON bytes (excluding `artifact.read_range`), up to `4 MiB` (`4_194_304` bytes) raw payload | Published as an immutable scoped artifact in the run's `scope_id`; model receives a compact head/tail preview envelope (`status: "ok"`, `storage: "spilled"`) whose final UTF-8 serialized JSON is `<= 16_384` bytes. |
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

**Three-phase lease-fenced publication (`artifact_fs::publish_bytes`, Phase 1a -> 1b -> 2 -> 3 +
post-commit detach).** `openmettle_worker` already holds PostgreSQL column grants on
`storage_instance`, `storage_accounts`, `artifacts`, `storage_reservations` (including `INSERT
(id)`) and `artifact_revisions` (including `display_name`, verified in `src/boundaries.sql`);
`V1-17` PR2 ([ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md) PR2) adds
the unified shared storage contract used verbatim by both ADR 0040 and ADR 0039:

- **Dedicated read-mostly singleton `openmettle.storage_volume_control` + narrow `SECURITY
  DEFINER` lock/pin functions (eliminating PostgreSQL 18 `FOR SHARE` `42501` errors and
  `FOR SHARE -> FOR NO KEY UPDATE` self-upgrade deadlocks on `storage_instance`).**
  `storage::adjust` (`src/storage.rs:289-310`) updates `storage_accounts -> storage_instance`
  (`FOR NO KEY UPDATE`) on every `reserve`, `settle`, `release`, and `confirm_purge`. Taking
  `FOR SHARE` on `storage_instance` earlier in `reserve` or inside
  `enforce_runtime_storage_volume_pinned()` would cause two concurrent reserves or releases to
  hold `FOR SHARE` and deadlock trying to upgrade `storage_instance` to `FOR NO KEY UPDATE`.
  Furthermore, **PostgreSQL 18 requires `UPDATE` privilege on at least one column of a table to
  execute `SELECT ... FOR SHARE`**, so granting `openmettle_worker` only `SELECT` causes
  `42501` (`permission denied`) even on a healthy pinned volume and before the trigger can
  raise `OMQ03`, while granting `UPDATE (volume_id, bootstrap_auto_pin_allowed)` to
  `openmettle_api` would allow direct pin rewrites outside the guarded bootstrap path. `V1-17`
  PR2 therefore keeps only `warn_pct_1`, `warn_pct_2`, and `config_revision` added to
  `openmettle.storage_instance`'s byte counters, moves `(volume_id, bootstrap_auto_pin_allowed,
  adoption_run_id)` onto a dedicated 1-row read-mostly control table
  **`openmettle.storage_volume_control`** with **ONLY `SELECT` granted to runtime roles** (zero
  `INSERT`, `UPDATE`, `DELETE`, or `TRUNCATE` on `openmettle.storage_volume_control` for either
  `openmettle_api` or `openmettle_worker`), and exposes two narrow `openmettle_owner`-owned
  `SECURITY DEFINER` functions (`SET search_path = pg_catalog`):
  **`openmettle.storage_lock_pinned_volume() RETURNS uuid`** (executable by `openmettle_api`
  and `openmettle_worker`) and **`openmettle.storage_pin_volume_id(p_volume_id uuid) RETURNS
  uuid`** (executable by `openmettle_api` for guarded fresh empty-ledger `Store::open`
  bootstrap):

  ```sql
  CREATE TABLE openmettle.storage_volume_control (
      id boolean PRIMARY KEY DEFAULT true CHECK (id),
      volume_id uuid,
      bootstrap_auto_pin_allowed boolean NOT NULL DEFAULT false,
      adoption_run_id uuid,
      CONSTRAINT storage_volume_control_auto_pin_check
          CHECK (volume_id IS NULL OR NOT bootstrap_auto_pin_allowed)
  );
  INSERT INTO openmettle.storage_volume_control (id) VALUES (true);
  GRANT SELECT ON openmettle.storage_volume_control TO openmettle_api, openmettle_worker;

  CREATE FUNCTION openmettle.storage_lock_pinned_volume()
  RETURNS uuid
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path = pg_catalog
  AS $$
  DECLARE
      v_vol uuid;
      v_adopt uuid;
  BEGIN
      SELECT volume_id, adoption_run_id
        INTO v_vol, v_adopt
        FROM openmettle.storage_volume_control
       WHERE id
         FOR SHARE;
      IF NOT FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL THEN
          RAISE EXCEPTION 'runtime storage operations require pinned, non-adopting storage_volume_control.volume_id'
              USING ERRCODE = 'OMQ03';
      END IF;
      RETURN v_vol;
  END;
  $$;
  REVOKE ALL ON FUNCTION openmettle.storage_lock_pinned_volume() FROM PUBLIC;
  GRANT EXECUTE ON FUNCTION openmettle.storage_lock_pinned_volume() TO openmettle_api, openmettle_worker;
  ```

  Fresh empty-ledger bootstrap is strictly **API-only**: only `openmettle_api` (`Store::open`
  in API) initializes fresh `.openmettle-volume-id` sentinels and invokes
  **`SELECT openmettle.storage_pin_volume_id($1)`** (`openmettle_owner`-owned `SECURITY
  DEFINER`, `SET search_path = pg_catalog`, `REVOKE ALL FROM PUBLIC; GRANT EXECUTE ON FUNCTION
  openmettle.storage_pin_volume_id(uuid) TO openmettle_api;` — **API-only** grant, matching ADR
  0040), which internally acquires `SELECT volume_id, bootstrap_auto_pin_allowed,
  adoption_run_id FROM openmettle.storage_volume_control WHERE id FOR UPDATE`, raises `OMQ03`
  when `NOT FOUND OR adoption_run_id IS NOT NULL`, returns the existing `volume_id` when
  `volume_id = p_volume_id` or raises `OMQ03` when `volume_id IS DISTINCT FROM p_volume_id`,
  requires `bootstrap_auto_pin_allowed = true` and empty `openmettle.storage_reservations` +
  `openmettle.artifact_revisions` when `volume_id IS NULL`, sets `volume_id = p_volume_id,
  bootstrap_auto_pin_allowed = false`, and returns `p_volume_id` — eliminating all raw invoker
  `FOR UPDATE` and `UPDATE` privileges on `openmettle.storage_volume_control`.
  **`openmettle_worker` NEVER initializes sentinels and NEVER calls
  `storage_pin_volume_id(uuid)`** — if a worker starts before API pins a fresh volume (or
  before `openmettle storage adopt` pins an upgraded volume), worker storage sweeps and
  `publish_bytes` observe `OMQ03` / unpinned state cleanly via `storage_lock_pinned_volume()`
  (with zero `42501` privilege errors!) and skip/fail closed cleanly until `volume_id` is
  pinned. All runtime paths (`Store::open` pinned check, `publish_bytes`, Step 2a reclamation
  revalidation, Step 3 `storage::release`, `StagingSweepState` orphan recheck, `purge_due`, and
  `enforce_runtime_storage_volume_pinned()`) invoke
  **`SELECT openmettle.storage_lock_pinned_volume()`** (comparing the returned `uuid` against
  `store.volume_id`), **NEVER** raw invoker `SELECT ... FOR SHARE`. Because `FOR SHARE` inside
  `storage_lock_pinned_volume()` is 100% compatible with `FOR SHARE`, concurrent reserves,
  settles, releases, and purges have zero `42501` privilege errors and zero `FOR SHARE -> FOR
  NO KEY UPDATE` lock-upgrade deadlocks!
- **Canonical storage lock order:** **`runs -> storage_reservations -> artifacts ->
  artifact_revisions -> storage_volume_control -> storage_accounts -> storage_instance`** (with
  `storage_volume_control (FOR SHARE)` acquired strictly via
  `openmettle.storage_lock_pinned_volume()`).
  - In `publish_bytes` Phase 1a (`storage::reserve`): lock `runs (FOR NO KEY UPDATE) ->
    storage_lock_pinned_volume() [storage_volume_control FOR SHARE] -> storage_accounts (FOR
    UPDATE) -> storage_instance (FOR UPDATE) -> INSERT storage_reservations`.
  - In Cleaner Step 3 (`storage::release`): lock `(runs FOR NO KEY UPDATE ->)
    storage_reservations (FOR UPDATE)` -> `UPDATE storage_reservations` fires
    `enforce_runtime_storage_volume_pinned()` calling **`openmettle.storage_lock_pinned_volume()`**
    (`storage_volume_control FOR SHARE`) -> `storage::adjust()` updates
    **`storage_accounts (FOR UPDATE) -> storage_instance (FOR UPDATE)`**.
- On `openmettle.storage_reservations`:
  - `adoption_unverified boolean NOT NULL DEFAULT false` with tightened constraint
    **`storage_reservations_adoption_unverified_check`: `CHECK (NOT adoption_unverified OR state
    = 'reserved')`** (so a quarantined row can NEVER transition to `'released'` or `'settled'`
    while `adoption_unverified = true`, and `enforce_storage_reservation_monotonic_guards()`
    rejects non-owner `OLD.adoption_unverified AND NOT NEW.adoption_unverified` (`OMQ03`),
    making non-owner release of a quarantined reservation impossible at the PostgreSQL boundary;
    `openmettle_owner` releases by updating `state = 'released', adoption_unverified = false`
    together, and `storage::settle`'s `Reserved` branch requires `NOT adoption_unverified`).
  - **Only `payload_ino numeric(20, 0)`** (`CHECK (payload_ino IS NULL OR payload_ino >= 0)`),
    storing exact unsigned 64-bit `u64` `MetadataExt::ino()` with zero signed-cast ambiguity
    (**never** persisting `st_dev`, because Linux NFS assigns client-local anonymous `st_dev`
    via `get_anon_bdev`, which would falsely quarantine valid shared-volume payloads across
    nodes; on each host, verify local same-mount equality `file_meta.dev() == dir_fd_meta.dev()
    == root_fd_meta.dev()` using only that host's open FDs, verify role-tagged
    `.openmettle-volume-id` sentinels `:root`, `:staging`, `:revisions` when `volume_id IS NOT
    NULL`, and compare `file_meta.ino() == payload_ino`).
  - **`stage_claimed boolean NOT NULL DEFAULT false`** (`CHECK (payload_ino IS NULL OR
    stage_claimed)`).
  - **`publish_pending boolean NOT NULL DEFAULT false`** (`CHECK (NOT publish_pending OR
    (state = 'reserved' AND payload_ino IS NOT NULL))`).
  - Unified **4-state** cleaner lease shared by all 4 cleaners (`artifact_fs::abort`,
    `reconcile_expired`, generic run-linked cleaner, and `reconcile_run_spills`) preserving
    `payload_ino` allocation via the `staging/.reclaim.<id>` anchor until Step 3 commits:
    - **`reclaim_state text NOT NULL DEFAULT 'none' CHECK (reclaim_state IN ('none', 'claiming',
      'truncated', 'anchor_pending_unlink'))`**, **`reclaim_claim_token uuid`**, and
      **`reclaim_lease_until timestamptz`**;
    - `CHECK ((state = 'reserved' AND reclaim_state IN ('none', 'claiming', 'truncated')) OR
      (state = 'released' AND reclaim_state IN ('none', 'anchor_pending_unlink')) OR (state =
      'settled' AND reclaim_state = 'none'))`;
    - `CHECK ((reclaim_state IN ('claiming', 'truncated') AND reclaim_claim_token IS NOT NULL AND
      reclaim_lease_until IS NOT NULL) OR (reclaim_state IN ('none', 'anchor_pending_unlink')
      AND reclaim_claim_token IS NULL AND reclaim_lease_until IS NULL))`;
    - `CHECK (reclaim_state NOT IN ('truncated', 'anchor_pending_unlink') OR NOT
      publish_pending)`;
    - Partial index for bounded Step 4 anchor sweeps across **all** reservations (ordinary
      uploads and MCP spills alike):
      `CREATE INDEX storage_reservations_reclaim_anchor_idx ON openmettle.storage_reservations (closed_at, id) WHERE state = 'released' AND reclaim_state = 'anchor_pending_unlink';`.
  - Runtime grants on `openmettle.storage_reservations` (`src/boundaries.sql`):
    `GRANT INSERT (lease_expires_at, stage_claimed) ON openmettle.storage_reservations TO
    openmettle_api, openmettle_worker;` and `GRANT UPDATE (lease_expires_at,
    adoption_unverified, stage_claimed, payload_ino, publish_pending, reclaim_state,
    reclaim_claim_token, reclaim_lease_until) ON openmettle.storage_reservations TO
    openmettle_api, openmettle_worker;`.
- On `openmettle.artifact_revisions` (durable purge anchor `revisions/.purge.<reservation_id>`
  preserving `payload_ino` allocation at `nlink >= 1` until `storage::confirm_purge` commits
  `state = 'purged'`):
  - **`purge_stage text NOT NULL DEFAULT 'none'`** with
    **`CONSTRAINT artifact_revisions_purge_stage_check CHECK (purge_stage IN ('none',
    'anchor_pending_unlink') AND (purge_stage = 'none' OR state = 'purged'))`**;
  - Partial index for bounded Stage C purge-anchor cleanup:
    `CREATE INDEX artifact_revisions_purge_anchor_idx ON openmettle.artifact_revisions (purged_at, id) WHERE state = 'purged' AND purge_stage = 'anchor_pending_unlink';`;
  - Worker-only column grant (preserving ADR 0005's worker-only purge split):
    `GRANT UPDATE (purge_stage) ON openmettle.artifact_revisions TO openmettle_worker;`.
- PostgreSQL **`SECURITY INVOKER`** triggers (`SET search_path = pg_catalog`) in `V1-17` PR2:
  - **`openmettle.enforce_runtime_storage_volume_pinned()`** (`BEFORE UPDATE` on
    `storage_reservations` `WHEN (OLD.state = 'reserved' AND NEW.state = 'released')` and
    `artifact_revisions` `WHEN (NEW.state IN ('purging', 'purged'))`): evaluates
    `NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')` as `SECURITY
    INVOKER` across both `INHERIT` and `NOINHERIT`/`SET ROLE` logins, then delegates to
    `openmettle.storage_lock_pinned_volume()` (`SECURITY DEFINER`), executing `SELECT ... FOR
    SHARE` as `openmettle_owner` without PostgreSQL 18 `42501` privilege errors and raising
    `OMQ03` when the singleton row is missing, unpinned (`volume_id IS NULL`), or under
    adoption (`adoption_run_id IS NOT NULL`):

    ```sql
    CREATE FUNCTION openmettle.enforce_runtime_storage_volume_pinned()
    RETURNS trigger
    LANGUAGE plpgsql
    SECURITY INVOKER
    SET search_path = pg_catalog
    AS $$
    BEGIN
        IF NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE') THEN
            PERFORM openmettle.storage_lock_pinned_volume();
        END IF;
        RETURN NEW;
    END;
    $$;
    ```

  - **`openmettle.enforce_storage_reservation_monotonic_guards()`** (`BEFORE UPDATE ON
    openmettle.storage_reservations FOR EACH ROW`): when `NOT
    pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')`, raises `OMQ03` if: (1)
    `OLD.adoption_unverified AND NOT NEW.adoption_unverified` (enforcing owner-only quarantine
    clearance at the DB boundary — combined with `storage_reservations_adoption_unverified_check`
    making non-owner release of a quarantined reservation impossible), (2) `OLD.payload_ino IS NOT
    NULL AND NEW.payload_ino IS DISTINCT FROM OLD.payload_ino` (**`payload_ino` is write-once
    and NEVER cleared to `NULL`**, even during/after cleanup, settlement, or release), or (3)
    `OLD.stage_claimed AND NOT NEW.stage_claimed` (at most one writer can ever claim staging per
    `reservation_id`).

Because `leases::fenced` (`src/authz/leases.rs`) sets `SET LOCAL
idle_in_transaction_session_timeout = '5s'` and `run_one` (`src/worker.rs`) drops a step once
its drain deadline (`until = (Instant::now() + settings.lease / 6).min(shutdown_limit)`)
elapses, `artifact_fs::publish_bytes` MUST **never** hold a `leases::fenced` DB transaction open
across `spawn_blocking` bulk payload write / `fsync` I/O. Moreover, when a shortened tool
`step.deadline` expires while Phase 1b's or Phase 2's `spawn_blocking` task is stalled in
`openat` or `fsync`, returning `StepResult::Continue` lets the run (and sibling runs) issue
further tool calls while the detached blocking task still holds a Tokio blocking thread and up
to `4 MiB` of buffered payload bytes; repeated spills on a wedged filesystem would otherwise
accumulate unbounded detached tasks beyond the worker's run-slot limit. PR2 therefore gates
spill publication with a **process-wide bounded `Arc<tokio::sync::Semaphore>` (`spill_permits`,
bounded to the worker's configured run-slot concurrency `max_concurrent_runs`, i.e.,
`OPENMETTLE_WORKER_RUN_SLOTS` / `RunPolicy::slots`)**, moving the `OwnedSemaphorePermit` into
**every** `spawn_blocking` closure (Phase 1b, Phase 2a write, Phase 2c `linkat`, and Phase 3's
pre-commit check), binds **all** spill creation, publication, stat and directory sync
operations strictly to `artifact_fs::Store`'s `V1-17` PR2
([ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md)) `Arc`-shared verified
directory descriptors (**`root_fd`**, **`staging_dir_fd`**, **`revisions_dir_fd`**: `OwnedFd`
opened via `rustix::fs::openat` with `OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW` and
verified host-local same-mount `st_dev` + `st_ino`), enforces **non-destructive pre-settlement
writers throughout (`publish_bytes` and `Store::stage` NEVER call `set_len(0)` anywhere and
NEVER call `unlinkat` on any error, cancellation, `StagedFile::drop`, or lost commit ack; the
only writer `unlinkat` is the post-`commit` best-effort detach of the `staging/<id>` hard-link
alias strictly AFTER `storage::settle` commits `state = 'settled'` while still holding
`LOCK_SH`; all pre-settlement disk cleanup is delegated exclusively to the 4-step `LOCK_EX`
cleaners!)**, publishes via mandatory POSIX/NFS **`rustix::fs::linkat(&staging_dir_fd, id,
&revisions_dir_fd, id, AtFlags::empty())`** (which atomically fails with `Errno::EXIST` without
overwriting any pre-existing `revisions/<id>` **and keeps `staging/<id>` linked on disk
throughout the entire pre-settlement `state = 'reserved'` window** so any mixed-version `N-1`
API replica receiving a same-key retry hits `OpenOptions::create_new(true)` ->
`ErrorKind::AlreadyExists` -> `Err(Error::InProgress)` at `src/artifact_fs.rs:474-475` without
calling `abort()` or replacing `fs::rename`!), and executes the exact **Phase 1a -> Step 1
(Phase 1b `LOCK_EX` + `payload_ino` bind keeping `publish_pending = false`) -> Step 2 (Phase 2a
write + `sync_all()` under continuous `LOCK_EX`) -> Step 3 (Phase 2b pre-`linkat` SQL fence
committing `publish_pending = true` under continuous `LOCK_EX`) -> Step 4 (Phase 2c `linkat` +
`fsync`) -> Step 5 (Phase 3 `storage::settle` + `runs::record_observation` + post-commit
`LOCK_SH` detach)** lifecycle aligned verbatim with
[ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md) (100% safe Rust 1.100
`std::fs` + `std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, MetadataExt}` + `V1-17` PR2's
`rustix::fs` under `unsafe_code = "forbid"`):

1. **Phase 1a — Bounded spill permit acquisition and DB `storage::reserve` BEFORE touching
   disk (`stage_claimed = true, payload_ino = NULL, publish_pending = false, reclaim_state =
   'none'`).** Before creating any file or spawning `spawn_blocking`, attempt to acquire an
   `OwnedSemaphorePermit` non-blockingly via `spill_permits.clone().try_acquire_owned()`. If no
   permit is available (`Err(TryAcquireError::NoPermits)`), skip Phases 1a–3 completely —
   creating **zero** files, allocating **zero** `storage_reservations` rows and queuing **zero**
   `spawn_blocking` tasks or extra payload buffers — and **immediately** take the inline
   `storage: "truncated_no_spill"` disposition (recording redacted `spill_error:
   "spill_saturated"`). Otherwise mint a fresh random 128-bit `reservation_id` via
   `ring::rand::SystemRandom`-backed RFC 9562 UUIDv4 generation (reusing the existing 16-byte
   version-4 / RFC 9562 variant helper pattern in `src/telemetry.rs:328-350`, adding zero new
   Cargo crates beyond `V1-17` PR2's `rustix` (`fs`, `std`) foundation since `uuid` is not in
   `Cargo.lock`, and passed explicitly to `storage::reserve` using `openmettle_worker`'s
   existing `INSERT (id)` grant on `storage_reservations`), a fresh per-attempt random 128-bit
   UUID/nonce `<attempt_id>` (`ring::rand::SystemRandom`, giving an adapter-owned idempotency
   key `tool-spill:<operation_id>:<attempt_id>`, `84` bytes `<= 128` bytes) and a fresh
   `artifact_id`. Run **Phase 1a** under `leases::with_lease(..., Fence::Step, ...)` following
   the canonical lock order **`runs (FOR NO KEY UPDATE) -> storage_lock_pinned_volume()
   [storage_volume_control FOR SHARE] -> storage_accounts (FOR UPDATE) -> storage_instance (FOR
   UPDATE) -> INSERT storage_reservations`**: execute
   **`SELECT openmettle.storage_lock_pinned_volume()`** and verify the returned `uuid ==
   store.volume_id` (on `OMQ03` — missing row, `volume_id IS NULL`, or `adoption_run_id IS NOT
   NULL` — or UUID mismatch, abort Phase 1a cleanly, drop `OwnedSemaphorePermit`, and fall back
   immediately to inline `storage: "truncated_no_spill"` with `spill_error: "storage_io"`),
   then call `storage::reserve` with the pre-minted `<reservation_id>`, `scope = run.scope_id`,
   `actor = run.actor_user_id`, `max_bytes = payload.len() as i64`, `run = Some(run_id)`,
   `operation = Some(operation_id)`, inserting the new `storage_reservations` row with
   **`stage_claimed = true, payload_ino = NULL, publish_pending = false, reclaim_state =
   'none'`**. Commit and release the PostgreSQL connection before touching disk. Because Phase
   1a executes strictly **before** any `openat`, pre-Phase-1a cutoff, Phase-1a deterministic DB
   rollback (`OMQ01` quota exceeded or `Fence::Step` rejection), and Phase-1a lost commit ack
   create **ZERO files on disk** and execute **ZERO `unlinkat`**! On Phase-1a lost commit ack or
   post-Phase-1a pre-Phase-1b abort, simply drop `OwnedSemaphorePermit` and apply the
   spill-abort disposition rule below; if Phase 1a did commit, `reconcile_run_spills` cleanly
   releases the `payload_ino IS NULL` row under the 4-step protocol (Subcase B) once the run is
   terminal/eligible.
2. **Step 1 (Phase 1b) — Permit-owning `spawn_blocking` creation & durable sync of 0-byte
   `staging/<reservation_id>` under continuous `LOCK_EX`, then bind write-once `payload_ino`
   keeping `publish_pending = false`.** Check `Instant::now() < step.deadline &&
   step.stop.borrow().is_none()`; if already false, drop `OwnedSemaphorePermit` (leaving zero
   files on disk and the Phase-1a `payload_ino IS NULL` row for `reconcile_run_spills` Subcase
   B) and apply the spill-abort disposition rule below. Otherwise **move `spill_permit:
   OwnedSemaphorePermit` directly INTO Phase 1b's `spawn_blocking` closure** (strictly outside
   any DB transaction, returning `(payload_file, staged_ino, spill_permit)` on uncancelled
   completion — so if cutoff or timeout fires while Phase 1b is stalled in `openat` or
   `fsync(&staging_dir_fd)`, `spill_permit` stays held inside that detached blocking task until
   `spawn_blocking` exits and drops `(payload_file, spill_permit)`, strictly bounding
   concurrent blocking tasks to `max_concurrent_runs`), raced in `tokio::select!` against
   `tokio::time::sleep_until(step.deadline)` and `step.stop.changed()` via a shared
   `Arc<AtomicBool>` (`cancelled = false`):
   - **Pre-`openat` directory-descriptor + role-tagged sentinel re-verification, `openat`,
     `LOCK_EX`, local `st_dev` + `staged_ino` verification, and `fsync(&staging_dir_fd)`:**
     Re-open `<root>` by path and `"staging"` / `"revisions"` relative to that fresh root FD
     (`rustix::fs::openat(..., OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
     Mode::empty())`), verify host-local same-mount equality (`root_meta.dev() ==
     staging_meta.dev() == revisions_meta.dev()`) and exact `(st_dev, st_ino)` match against
     `Store`'s pinned `(root_fd, staging_dir_fd, revisions_dir_fd)`, and verify their
     role-tagged regular-file `.openmettle-volume-id` sentinels (`:root`, `:staging`,
     `:revisions` matching the non-null pinned `volume_id` via `openat(..., OFlags::RDONLY |
     OFlags::NOFOLLOW | OFlags::NONBLOCK)` + `fstat` `S_ISREG`, failing closed before creating
     any file if replaced or mismatched). Open the **0-byte payload file `<reservation_id>`
     strictly relative to `staging_dir_fd`** via `rustix::fs::openat(&staging_dir_fd, id,
     OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW, Mode::RUSR | Mode::WUSR)`
     -> safe `let payload_file = std::fs::File::from(owned_fd)` (mode `0o600`), immediately
     acquire **`payload_file.try_lock()` (`LOCK_EX | LOCK_NB`, held continuously across Steps
     1–5 through Step 5's commit with zero lock-mode conversion!)**, verify `file_meta = payload_file.metadata()?` vs
     `rustix::fs::statat(&staging_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` (`S_ISREG`,
     host-local same-mount `file_meta.dev() == staging_dir_meta.dev() == root_fd_meta.dev()`,
     `staged_ino = file_meta.ino()`, `stat.st_ino as u64 == staged_ino`), **execute
     `rustix::fs::fsync(&staging_dir_fd)`** (making the `staging/<reservation_id>` directory
     entry crash-durable **BEFORE** binding `payload_ino` in PostgreSQL!), and return
     `(payload_file, staged_ino, spill_permit)` on uncancelled completion (dropping
     `(payload_file, spill_permit)` inside the closure on cancellation or error with zero
     `set_len(0)` and zero `unlinkat`).
   - **Short `Fence::Step` DB bind of write-once `payload_ino` keeping `publish_pending =
     false`:** After `spawn_blocking` returns `(payload_file, staged_ino, spill_permit)` (and
     re-checking `Instant::now() < step.deadline && step.stop.borrow().is_none()`), run a short
     `leases::with_lease(..., Fence::Step, ...)` transaction (zero disk I/O inside the DB
     transaction) that locks `runs (FOR NO KEY UPDATE) -> storage_reservations (FOR UPDATE)` ->
     executes **`SELECT openmettle.storage_lock_pinned_volume()`** (verifying returned `uuid ==
     store.volume_id`) and commits **write-once `payload_ino` WITHOUT setting `publish_pending
     = true` while the staged file is still `0` bytes**:
     ```sql
     SELECT openmettle.storage_lock_pinned_volume();
     UPDATE openmettle.storage_reservations
        SET stage_claimed = true,
            payload_ino = COALESCE(payload_ino, $3::text::numeric(20, 0))
      WHERE scope_id = $1::uuid
        AND id = $2::uuid
        AND state = 'reserved'
        AND NOT adoption_unverified
        AND reclaim_state = 'none'
        AND (payload_ino IS NULL OR payload_ino = $3::text::numeric(20, 0))
     RETURNING id;
     ```
     (`enforce_storage_reservation_monotonic_guards()` guarantees `payload_ino` is write-once
     and never modified or cleared thereafter.)
   - **Zero `set_len(0)` and zero `unlinkat` on ANY Step 1 error, cancellation, or lost commit
     ack:** If cutoff fires during Step 1 `spawn_blocking` (detaching the blocking handle while
     it retains `spill_permit` until exit), if `storage_lock_pinned_volume()` raises `OMQ03`,
     if `UPDATE` returns `0` rows or fails deterministically, or if the DB commit experiences a
     lost commit acknowledgement, **do NOT call `set_len(0)` and do NOT call `unlinkat`** —
     simply **`drop(payload_file)`** (pure `close()`, releasing `LOCK_EX`) and
     **`drop(spill_permit)`**, deferring all disk cleanup exclusively to `reconcile_run_spills`
     (which handles both committed `payload_ino = staged_ino` via Subcase A1 and uncommitted
     `payload_ino IS NULL` 0-byte `staging/<id>` via Subcase B safely under `LOCK_EX`!), and
     apply the spill-abort disposition rule below.
3. **Steps 2–4 (Phase 2) — Write & `sync_all()` under continuous `LOCK_EX` -> Pre-`linkat` SQL
   fence committing `publish_pending = true` -> `linkat` no-replace publish keeping
   `staging/<id>` linked until Phase 3 commits (aligned verbatim with
   [ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md); strictly zero DB tx
   across disk I/O, zero sidecar `.lock` file, zero `unlinkat` / `set_len(0)`).** Check
   `Instant::now() < step.deadline && step.stop.borrow().is_none()` before Step 2; if already
   false, `drop(payload_file)` (releasing `LOCK_EX`) and `drop(spill_permit)` with zero
   `set_len(0)` and zero `unlinkat` (leaving `staging/<id>` for `reconcile_run_spills` Subcase
   A1) and apply the spill-abort disposition rule below.
   - **Step 2 (Write & `sync_all()` under continuous `LOCK_EX`):** Allocate a fresh shared
     `Arc<AtomicBool>` (`cancelled = false`), move `payload_file` (still holding `LOCK_EX`),
     `staged_ino`, `Arc`-cloned `(root_fd, staging_dir_fd, revisions_dir_fd)`, and
     `spill_permit: OwnedSemaphorePermit` into Step 2's `spawn_blocking` closure, raced in
     `tokio::select!` against `tokio::time::sleep_until(step.deadline)` and
     `step.stop.changed()`. Check `cancelled.load(Ordering::Acquire)` before writing and before
     each `<= 64 KiB` chunk, write `payload` into `payload_file` while computing SHA-256 and
     verifying `actual_size == reserved_bytes`, call **`payload_file.sync_all()?`**, re-stat
     `payload_file` (`S_ISREG`, local `st_dev`, `st_ino == staged_ino`, `st_size ==
     reserved_bytes`) and `rustix::fs::statat(&staging_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)`
     (`S_ISREG`, local `st_dev`, `st_ino == staged_ino`, `st_size == reserved_bytes`), and
     return `(payload_file, spill_permit)` on uncancelled completion (dropping `(payload_file,
     spill_permit)` inside the closure on cancellation/error with zero `set_len(0)` and zero
     `unlinkat`).
   - **Step 3 (Pre-`linkat` SQL fence committing `publish_pending = true` under continuous
     `LOCK_EX`):** Re-check `Instant::now() < step.deadline && step.stop.borrow().is_none()`.
     While **continuing to hold `LOCK_EX` on `payload_file`**, run a short `leases::with_lease(...,
     Fence::Step, ...)` transaction (zero disk I/O inside the DB transaction) locking `runs (FOR
     NO KEY UPDATE) -> storage_reservations (FOR UPDATE)` -> executing:
     ```sql
     SELECT openmettle.storage_lock_pinned_volume();
     UPDATE openmettle.storage_reservations
        SET publish_pending = true
      WHERE scope_id = $1::uuid
        AND id = $2::uuid
        AND state = 'reserved'
        AND NOT adoption_unverified
        AND reclaim_state = 'none'
        AND payload_ino = $3::text::numeric(20, 0)
     RETURNING id;
     ```
     (confirming returned `volume_id == store.volume_id`). **Deterministic interleaving
     outcome:** if `openmettle storage adopt` started during Step 2's write (`adoption_run_id
     IS NOT NULL` -> `storage_lock_pinned_volume()` raises `OMQ03`) OR a cleaner claimed
     `reclaim_state <> 'none'` during Step 2's write (`0` rows returned), Step 3 fails
     **strictly BEFORE `linkat`**, so `publish_bytes` aborts cleanly (`drop(payload_file)`,
     `drop(spill_permit)`, zero `set_len(0)`, zero `unlinkat`) without creating
     `revisions/<id>` and applies the spill-abort disposition rule below! Conversely, once Step
     3 commits `publish_pending = true`, cleaners' Step 1 (`AND NOT publish_pending` while
     run/lease is active, plus `LOCK_EX` serialization on `payload_file`) is fenced off while
     Step 4 executes `linkat`!
   - **Step 4 (Atomic non-overwriting `linkat` + `fsync(&revisions_dir_fd)` + post-`linkat`
     re-verify under continuous `LOCK_EX`):** Move `(payload_file, spill_permit)` into Step 4's
     `spawn_blocking` closure (raced in `tokio::select!` against `step.deadline` and
     `step.stop.changed()`). Re-open `<root>` by path and `"staging"` / `"revisions"` relative
     to that fresh root FD (`OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW`), verify
     host-local same-mount `st_dev` equality, pinned `(st_dev, st_ino)` match against
     `(root_fd, staging_dir_fd, revisions_dir_fd)`, role-tagged `.openmettle-volume-id`
     sentinels (`:root`, `:staging`, `:revisions`), and
     `rustix::fs::statat(&staging_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` (`S_ISREG`, local
     `st_dev` match, `st_ino as u64 == staged_ino`, `st_size == reserved_bytes`). If `cancelled
     == false` and re-verification succeeds, keep `LOCK_EX` continuously across
     **`rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id, AtFlags::empty())`**
     (mandatory POSIX/NFS `LINK`, which **atomically fails with `Errno::EXIST` (`EEXIST`)
     without overwriting any pre-existing `revisions/<id>`** AND **keeps `staging/<id>` linked
     on disk throughout the entire pre-settlement `state = 'reserved'` window**!). Because
     **`staging/<id>` stays present on disk** until `storage::settle` commits `state =
     'settled'` (including if the `N` writer crashes after `linkat` and before
     `storage::settle`), any same-key retry routed to an **`N-1` API replica** hits
     `store.stage(&id)` -> `OpenOptions::create_new(true)` (`src/artifact_fs.rs:474`) ->
     `ErrorKind::AlreadyExists` -> **`Err(Error::InProgress)` (`src/artifact_fs.rs:475`)** and
     returns immediately **without** calling `abort()`, **without** creating a new staging
     file, and **without** calling replacing `fs::rename`! On `Errno::EXIST` or any
     directory/sentinel/leaf-inode mismatch: **ZERO `set_len(0)` and ZERO `unlinkat`**; drop
     `payload_file` and `spill_permit`, disable Step 5 (Phase 3), commit quarantine `UPDATE
     openmettle.storage_reservations SET adoption_unverified = true, publish_pending = false
     WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved' AND NOT
     adoption_unverified AND reclaim_state = 'none'` (retaining write-once `payload_ino`), and
     take the inline `storage: "truncated_no_spill"` fallback. After `linkat` returns `Ok(())`,
     execute **`rustix::fs::fsync(&revisions_dir_fd)`** (never calling `unlinkat` or
     `set_len(0)` if `cancelled` turns `true` or `fsync` fails!), then re-verify `<root>`,
     `"staging"`, `"revisions"` (local `st_dev`, pinned `(st_dev, st_ino)`, and role-tagged
     sentinels) + `rustix::fs::statat(&revisions_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)`
     (`S_ISREG`, local `st_dev` match, `st_ino as u64 == staged_ino`, `st_size ==
     reserved_bytes`), and on uncancelled success **hold `LOCK_EX` continuously with zero
     lock-mode conversion (NEVER downgrading `payload_file` to `try_lock_shared()` pre-commit,
     because Linux `flock(2)` lock conversion is not atomic and can momentarily drop
     exclusivity!) and return `(payload_file, spill_permit)` into Step 5 (Phase 3)** (dropping
     `(payload_file, spill_permit)` inside Step 4 only on cancellation or error).
   - **Cutoff fires before Step 2 or Step 4 `spawn_blocking` completes (raced detach):** Set
     `cancelled.store(true, Ordering::Release)`, detach the `JoinHandle` (the detached closure
     keeps holding `LOCK_EX` on `payload_file` and `spill_permit` until it exits, performing
     **zero `set_len(0)` and zero `unlinkat`**!), unconditionally disable Step 5 (Phase 3),
     leave `<reservation_id>` in `state = 'reserved'` (`payload_ino = staged_ino`,
     `max_bytes` charged), and immediately run the inline `storage: "truncated_no_spill"`
     fallback. Once `payload_file` closes (or the worker crashes), `reconcile_run_spills`
     reclaims the verified `payload_ino` file from `staging/<id>` and (if Step 4 linked it)
     `revisions/<id>` using the 4-step `LOCK_EX` `staging/.reclaim.<id>` protocol below.
     Immediately after normal uncancelled Step 4 completion, re-check `Instant::now() <
     step.deadline && step.stop.borrow().is_none()`; if false, drop `(payload_file,
     spill_permit)` (pure `close()`, zero `set_len(0)`, zero `unlinkat`), skip Step 5 (leaving
     `<reservation_id>` in `state = 'reserved'` for `reconcile_run_spills`), and apply the
     spill-abort disposition rule below.
4. **Step 5 (Phase 3) — Single atomic `Fence::Step` settlement (`storage::settle` +
   `runs::record_observation`) with permit-bounded, time-bounded pre-`commit` verification,
   followed by post-`commit` best-effort `LOCK_SH` detach of `staging/<id>`.** Borrow a
   connection and open **one** short `leases::with_lease(..., Fence::Step, ...)` transaction
   (`SET LOCAL idle_in_transaction_session_timeout = '5s'`, zero bulk disk I/O inside the
   transaction). Re-check `Instant::now() < step.deadline && step.stop.borrow().is_none()`
   **after** acquiring the `Fence::Step` DB lock and **before** executing `storage::settle` or
   `runs::record_observation`. Inside that **exact same `Fence::Step` PostgreSQL transaction**
   — following the canonical lock order **`runs -> storage_reservations -> artifacts ->
   artifact_revisions -> storage_lock_pinned_volume() [storage_volume_control FOR SHARE] ->
   storage_accounts -> storage_instance`** — execute **both** `storage::settle` **and**
   `runs::record_observation` atomically. `storage::settle` (`src/storage.rs:362-379`, tested
   by `tests/schema/artifact_fs.rs:434`) preserves its existing `ReservationState::Settled`
   idempotent metadata-matching replay branch intact, and on its `ReservationState::Reserved`
   settlement branch strictly requires **`state = 'reserved' AND NOT adoption_unverified AND
   payload_ino = $staged_ino AND reclaim_state = 'none'`** (along with
   **`SELECT openmettle.storage_lock_pinned_volume()`** verifying returned `uuid ==
   store.volume_id`, NEVER raw invoker `FOR SHARE`!), inserts the immutable
   `artifact_revisions` row, charges active quota (`storage_accounts -> storage_instance`), and
   commits **`state = 'settled', publish_pending = false`** (**retaining write-once
   `payload_ino`**, never clearing it — enforced by
   `enforce_storage_reservation_monotonic_guards()`!). Once Step 1 of `reconcile_run_spills`
   commits `reclaim_state != 'none'` (or if `adoption_unverified = true`), a stalled Phase 3
   observes `reclaim_state != 'none'` or `adoption_unverified = true` under `FOR UPDATE`, fails
   closed with `Error::Conflict`, rolls back **both** `storage::settle` and
   `runs::record_observation`, drops `(payload_file, spill_permit)` via pure `close()` (zero
   `set_len(0)`, zero `unlinkat`), and applies the spill-abort disposition rule below;
   conversely, if Phase 3 commits `state = 'settled'` first, Step 1 of `reconcile_run_spills`
   sees `state = 'settled'` under `FOR UPDATE` and skips the row without touching any file.
   **Permit-bounded, time-bounded `spawn_blocking` pre-`commit` recheck (matching
   [ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md) PR2):** After
   `storage::settle` and `runs::record_observation` complete their SQL statements and
   **strictly before** returning `Ok(...)` to commit:
   1. **Move `spill_permit: OwnedSemaphorePermit` into Phase 3's `spawn_blocking` pre-commit
      verification closure**, re-opening `<root>`, `"staging"`, `"revisions"` (`OFlags::RDONLY |
      OFlags::DIRECTORY | OFlags::NOFOLLOW`), verifying host-local same-mount `st_dev` equality,
      pinned `(st_dev, st_ino)` match against `(root_fd, staging_dir_fd, revisions_dir_fd)`,
      role-tagged `.openmettle-volume-id` sentinels (`:root`, `:staging`, `:revisions`), and
      `rustix::fs::statat(&revisions_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` is `S_ISREG` with
      local `st_dev` match, **`st_ino as u64 == staged_ino`**, and **`st_size == size_bytes`**.
      Bound awaiting that `spawn_blocking` `JoinHandle` with
      **`tokio::time::timeout(remaining_step_budget.min(Duration::from_secs(2)), ...)`** (raced
      against `step.stop.changed()`, strictly below `5 s` `idle_in_transaction_session_timeout`).
      On timeout (`Elapsed`), `step.stop`, `JoinError`, or verification mismatch: return
      `Err(...)` so `leases::fenced` **rolls back Phase 3** (detaching a timed-out handle while
      it retains `spill_permit` until exit, dropping `payload_file` via pure `close()` with
      **zero `set_len(0)` and zero `unlinkat`**, leaving `state = 'reserved'` for guarded
      reconciliation on timeout, and committing quarantine `SET adoption_unverified = true,
      publish_pending = false WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved'
      AND NOT adoption_unverified AND reclaim_state = 'none'` on directory displacement or
      leaf-inode mismatch) and apply the inline `storage: "truncated_no_spill"` fallback; **and**
   2. On `Ok((Ok(()), spill_permit))`, perform the final `Instant::now() < step.deadline &&
      step.stop.borrow().is_none()` check; if false, roll back **both** settlement and
      observation, drop `(payload_file, spill_permit)` (pure `close()`), and apply the
      spill-abort disposition rule below.
   3. **Post-`commit` best-effort `LOCK_SH` detach of `staging/<id>` alias (strictly AFTER
      Phase 3's `COMMIT` succeeds):** Once Phase 3 returns confirmed `Ok(...)`, **drop
      `payload_file` (`LOCK_EX`) strictly AFTER Step 5 commits** (zero pre-commit lock-mode
      conversion, because Linux `flock(2)` lock conversion is not atomic and can momentarily
      drop exclusivity!), and **only then** run a bounded best-effort `spawn_blocking` detach
      holding `spill_permit`: open `staging/<id>` post-commit via `openat(&staging_dir_fd, id,
      OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK, Mode::empty())`, immediately check
      `file.metadata()?.file_type().is_file()`, acquire non-blocking `file.try_lock_shared()`
      (`LOCK_SH | LOCK_NB`, fencing `StagingSweepState` and `artifact_fs::purge_due`, which
      require `LOCK_EX`, while `state = 'settled'` and `stage_claimed = true` prevent any
      `N-1` or `N` writer from creating `staging/<id>`), verify `fstat(fd)` +
      `statat(&staging_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` match `S_ISREG`, local `st_dev`,
      and **`st_ino as u64 == staged_ino`** AND `statat(&revisions_dir_fd, id,
      AtFlags::SYMLINK_NOFOLLOW)` has `S_ISREG`, local `st_dev`, and **`st_ino as u64 ==
      staged_ino`**; call **`rustix::fs::unlinkat(&staging_dir_fd, id, AtFlags::empty())`**
      (**NEVER `set_len(0)`!**) -> `drop(file)` ->
      **`rustix::fs::fsync(&staging_dir_fd)`** -> `drop(spill_permit)`. (If the process crashes
      or times out before this post-commit detach completes, `StagingSweepState` `'settled'` and
      `artifact_fs::purge_due` Stage A detach `staging/<id>` safely.)
   **Phase 3 lost commit acknowledgement / cancellation safety:** If Phase 3's `COMMIT`
   experiences a lost commit acknowledgement, error, or cancellation, `publish_bytes` MUST NOT
   enter post-commit detach — it executes **pure `drop(payload_file)` (`close()` only — ZERO
   `set_len(0)` and ZERO `unlinkat`!)** and `drop(spill_permit)`, so a lost commit
   acknowledgement can **never** zero or unlink a settled artifact! Any recovery checks
   `storage_reservations` under `runs FOR NO KEY UPDATE -> storage_reservations FOR UPDATE`
   (`state == 'settled'` -> already published, `StagingSweepState`/`purge_due` Stage A safely
   detach any remaining `staging/<id>` hard-link alias; `state == 'reserved'` ->
   `reconcile_run_spills` reclaims safely under the 4-step `staging/.reclaim.<id>` protocol).
   On replay of an already-`succeeded` operation, the adapter reads `(artifact_id, revision_id)`
   from the committed observation evidence (after fenced primary
   `approvals::recheck_replay_effect_authority(..., policy)` verifying live `EffectPolicy`
   resolution `live_review == committed_review`, live bound/deciding-session/effect authority
   and exact committed `authority_evidence` + `binding_digest` equality, plus
   `hydrate_worker_principal`, `revision.scope_id == run.scope_id`, live `Action::Read`, and
   `revision.state == "active"` rechecks) rather than re-running `publish_bytes`.

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
  `StepResult::LeaseLost`.
- **Run stopping (`step.stop.borrow()` is `Some(Stop::Shutdown | Stop::Cancel | Stop::Deadline)`
  or `Fence::Step` rejected with `LeaseError::Stopping(_)`):** commit the inline
  `storage: "truncated_no_spill"` observation under **`Fence::Hold`** if the lease is still
  held (rolling back and returning `StepResult::LeaseLost` immediately without further DB
  writes if `*step.stop.borrow()` becomes `Some(Stop::LeaseLost)` before commit or `Fence::Hold`
  rejects with `StaleClaim | Expired | Terminal`) and return **`StepResult::Stopped`**, so
  `run_one` cleanly hands off on `Stop::Shutdown`, settles cancellation on `Stop::Cancel` /
  `cancel_reason IS NOT NULL`, or settles `DeadlineExceeded` on `Stop::Deadline`.
- **DB or local lease lost (`step.stop.borrow()` is `Some(Stop::LeaseLost)` or
  `LeaseError::StaleClaim`, `LeaseError::Expired` or `LeaseError::Terminal`):** return
  **`StepResult::LeaseLost`** immediately without further PostgreSQL writes (mapped in PR2 in
  `worker::execute` (`src/worker.rs`) to `WorkEnd::Stop(Stop::LeaseLost)` so `run_one` exits
  immediately without touching PostgreSQL, distinct from `StepResult::Invalidated(settled)` ->
  `WorkEnd::Invalidated(settled)` for in-lease authority invalidations/expiries).
- **Mandatory in-closure `*step.stop.borrow()` rechecks for inline `truncated_no_spill`
  fallbacks (`Fence::Step` and `Fence::Hold`).** Inside the inline `truncated_no_spill`
  fallback's `leases::fenced` closure (`src/authz/leases.rs`), the adapter MUST re-inspect
  `*step.stop.borrow()` **both immediately after `leases::lock` acquires the `openmettle.runs`
  row lock AND immediately after `runs::record_observation` completes right before returning
  `Ok(...)` to commit**:
  1. If `*step.stop.borrow() == Some(Stop::LeaseLost)` at either check, return `Err(...)` to
     **roll back** the transaction (leaving `openmettle.operations`, `openmettle.run_events`
     and `openmettle.runs.last_event_sequence` completely untouched) and return
     **`StepResult::LeaseLost`**.
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
  `openmettle.operations` by `(scope_id, run_id, logical_key)` before dispatch — using PR3's
  `record_fenced_intent` existing-operation branch (`src/authz/approvals.rs:1291-1337`,
  `SELECT request, capability, approval_id::text`, resolving `effective_approval =
  stored_approval_id.as_deref()` when the caller passes `approval = None` after
  `approvals::pending_effect` omits the already-consumed approval, rejecting mismatched
  `Some(caller_id)` with `Err(CONFLICT)`, verifying the committed envelope's
  `authorization.basis` (`"human"` iff `effective_approval.is_some()`) and
  `authorization.approval_id == effective_approval`, rebuilding
  `binding.envelope(p, &s, &review, effective_approval)?`, and calling
  `durable::existing_intent(c, &intent, effective_approval, &id)`) so ordinary and
  crash-recovery same-key replays return `Ok(IntentResult::Replayed(op))` cleanly instead of
  `Err(CONFLICT)` — and **reuses the committed observation in history with zero additional
  outbound sends** — strictly gated by
  **`approvals::recheck_replay_effect_authority(..., policy)`** under `Fence::Step` on the
  primary (parsing the committed `openmettle.effect` v1 envelope from `operations.request`,
  reconstructing committed `Proposal` `p` and requiring exact match with the caller's requested
  `Proposal` and stored `operations` columns, resolving the current live `Review` via
  `live_review = reviewed(policy, &s, &p)?` and requiring exact equality
  `live_review == committed_review` (`serde_json::to_vec(&live_review) ==
  serde_json::to_vec(&committed_review)`; failing closed if `committed_review.reservation.is_some()`
  unless explicitly matched), joining `openmettle.run_approvals a JOIN
  openmettle.run_approval_decisions d ON d.approval_id = a.id` (`WHERE a.scope_id = $scope AND
  a.run_id = $run AND a.id = $approval_id AND a.logical_key = $logical_key`, requiring
  `d.decision == "approve"` and `d.binding_digest == a.binding_digest == committed_binding_digest`
  and passing `Some(d.deciding_session_id)` as `Proof.decider`) when `basis == "human"`,
  executing `snap = authorized(c, &proof, &live_review)`, checking
  `snap.now < expires_us.min(validity(&snap, &live_review))` plus `automatic(&r, &snap)` and
  `YOLO` capability when `basis == "yolo"`, rebuilding
  `live_evidence = snap.evidence(&live_review, auto)` and
  `live_hash = p.binding(&s, expires_us, &live_evidence)` (`Binding::new`), and requiring exact
  byte equality `live_evidence == committed_evidence && live_hash ==
  committed_binding_digest`). For any `'succeeded'` observation backed by a source
  (`artifact.read_range`) or spilled (`storage: "spilled"`, `status: "ok"`) artifact, the
  worker additionally checks `hydrate_worker_principal`, `revision.scope_id == run.scope_id`,
  `authorize_resource(..., Action::Read)`, and `revision.state == "active"`, refusing replay
  via `approvals::invalidate_post_intent` and returning **zero** cached bytes
  (`IntentResult::Invalidated(settled)` / `StepResult::Invalidated(settled)` ->
  `WorkEnd::Invalidated(settled)`) if the bound or deciding session logged out, effect authority
  was revoked, the live `EffectPolicy` disabled or changed the tool/destination policy
  (`policy.review(...)` returning `Ok(None)` / `Err(DENIED)` or a changed `Review`), or the
  tool capability or direct source-artifact share was revoked and re-granted (changing
  `authority_evidence`) even while artifact `Action::Read` access and
  `revision.state == "active"` remain valid; for any `'failed'` observation, after
  `approvals::recheck_replay_effect_authority(..., policy)` succeeds, it returns the bounded
  inline `status: "tool_error"` envelope (never spilled and never `status: "ok"`). If
  `run_one`'s post-drain `leases::handoff` or `leases::settle` ran after the commit, it
  releases or settles cleanly with `n = 0`.
- **Uncommitted observation (`operations.outcome` remained `'intent'`):**
  - **`repeatable_read` (side-effect-free, PR2):** A reclaiming worker on a `running` run
    safely replays the read under `Fence::Step` via
    `approvals::start_replayed_read(..., policy)`. **`approvals::start_replayed_read` evaluates
    live `EffectPolicy` + `{AUTH}` / `effective_expires_us` authority validity FIRST before
    checking `coalesce(dispatched_attempts, 3) >= 3`** — verifying `live_review =
    reviewed(policy, &s, &p)?` + `live_review == committed_review`, live
    `authorized(c, &proof, &live_review)`, `effective_expires_us`, and exact committed
    `authority_evidence` + `binding_digest` equality (including the source artifact's grant
    cycle for `artifact.read_range`). If the approval, session, user, provider, grant, or
    `effective_expires_us` is expired or revoked — **including when `dispatched_attempts IS
    NULL` or `dispatched_attempts == 3`** — `start_replayed_read` routes immediately through
    `approvals::invalidate_post_intent` Branch 1 (`outcome = 'failed'` + immediate terminal run
    settlement `openmettle.run-approval-expired` or `openmettle.run-revoked`, skipping any
    ordinary failed observation and model continuation!). **Only when live authority is still
    valid** does `coalesce(dispatched_attempts, 3) >= 3` record an ordinary exhausted `outcome
    = 'failed'` observation and continue the turn; when live authority is valid and
    `dispatched_attempts < 3`, it guards the `UPDATE openmettle.operations SET
    dispatched_attempts = o.dispatched_attempts + 1` statement **itself** with the live
    `{AUTH}` CTE `FROM snap, t, openmettle.runs r` so concurrent session logout, grant
    revocation, or lease/execution/effect expiry between `authorized()` and `UPDATE` affects
    `0` rows and settles via ledger-aware `approvals::invalidate_post_intent`
    (`IntentResult::Invalidated(settled)` / `StepResult::Invalidated(settled)`) with zero
    increment and zero sends, minting a fresh `<reservation_id>` if spilled. Any transition to
    `'waiting'` or terminal resolves remaining revision-zero `'intent'` reads to `outcome =
    'failed'` via PR2's `AFTER UPDATE OF state` trigger strictly before `run-waiting` /
    `run-terminal`.
  - **External writes (`idempotent`, `lookup`, `non_repeatable`, PR3) — unified durable
    zero-attempt disposition across `leases::unresolved!()`, shutdown/margin handoff, reclaim
    and terminal settlement:**
    1. **Update `leases::unresolved!()` (`src/authz/leases.rs:310-314`):** Update the unresolved
       write predicate from `outcome IN ('intent', 'outcome_unknown') AND capability IN (...)`
       to:
       **`(outcome = 'outcome_unknown' OR (outcome = 'intent' AND coalesce(dispatched_attempts,
       1) > 0)) AND capability IN ('idempotent', 'lookup', 'non_repeatable')`**.
       Legacy pre-upgrade rows (`dispatched_attempts IS NULL`) and post-Transaction-2 rows
       (`dispatched_attempts >= 1`) evaluate `coalesce(dispatched_attempts, 1) > 0` to `true`
       and still enter `Reconciling` / `Interrupted`; proven-unsent `dispatched_attempts = 0`
       rows evaluate to `false` because PostgreSQL holds durable proof that zero outbound
       attempts were ever dispatched!
    2. **Graceful shutdown and explicit `StepResult::Handoff` / `WorkEnd::Handoff` lease-margin
       handoff aligned with `reclaim_next` -> clean successor reclaim in `Running`
       (`src/worker.rs:138-156, 498-505, 536-559, 661-675`, `src/authz/leases.rs:412, 497,
       503-535, 595`):**
       - Add **`StepResult::Handoff`** to `pub enum StepResult` (`src/worker.rs`) and
         **`WorkEnd::Handoff`** to `WorkEnd` (`src/worker.rs`). Update `worker::execute`
         (`src/worker.rs:554-559`) to map **`StepResult::Handoff => return Ok(WorkEnd::Handoff)`**
         (leaving `StepResult::Stopped => return Ok(WorkEnd::Complete(Settle::Stopped))` strictly
         for graceful worker `shutdown`, explicit stop, or `outcome_unknown`!). When
         `StartPermit::LeaseMarginExhausted` triggers (remaining-lease margin cutoff, e.g.,
         `execution_remaining <= settings.lease`, while `shutdown` has NOT fired),
         `worker::execute`'s reviewed-approval branch (`src/worker.rs:536-548`) returns
         `Ok(WorkEnd::Handoff)` directly and `Executor::step` / `ApprovedAdapter::send`
         (`src/worker.rs:138-156`) return `StepResult::Handoff` (mapped by `worker::execute` at
         `src/worker.rs:554-559` to `Ok(WorkEnd::Handoff)`), and `run_one` (`src/worker.rs:661-675`)
         routes `WorkEnd::Handoff` alongside `WorkEnd::Stop(Stop::Shutdown)` to
         **`leases::handoff(&mut c, &lease, &settings)`** whenever `cause` is not
         `Some(Stop::LeaseLost)`.
       - Update **`leases::handoff`** (`src/authz/leases.rs:503-535`, under `Fence::Hold`) to
         check **`time_to_reclaim = execution_expires_at > clock_timestamp() + $3::bigint *
         interval '1 millisecond'`** (`settings.lease` — the **exact** `reclaim_next` at
         `src/authz/leases.rs:595` and `SETTLEMENT_INPUTS` `time_to_reconcile` at
         `src/authz/leases.rs:497` predicate!):
         - When `held.cancel.is_none()` AND `NOT EXISTS (... unresolved!())` (updated
           `leases::unresolved!()` excludes `dispatched_attempts = 0`) AND **`time_to_reclaim`
           is `true` (`> settings.lease` remaining)**: `leases::handoff` calls
           `release_locked`, keeping the run in **`state = 'running'`** and the operation in
           **`outcome = 'intent', dispatched_attempts = 0`** so `reclaim_next` can reclaim the
           run cleanly. (If time passes after `release_locked` so `<= settings.lease` remains
           before any worker calls `reclaim_next`, `leases::settle_expired` settles the lapsed
           run at `execution_expires_at` with `n = 0` from `unresolved!()`, closing
           `dispatched_attempts = 0` to `outcome = 'failed', revision = revision + 1` and
           settling `DeadlineExceeded` with zero `Reconciling`/`Interrupted`.)
         - When `held.cancel.is_some()` OR `EXISTS (... unresolved!())` OR **`NOT
           time_to_reclaim` (`<= settings.lease` remaining, e.g., `10 s` left on a `30 s`
           lease)**: `leases::handoff` calls `settle_locked(..., Settle::Stopped)` right inside
           that same `Fence::Hold` transaction! When `n = 0` (`dispatched_attempts = 0`
           excluded by `unresolved!()`), `cancel = None`, and `!time_to_reclaim`, `decide()`
           (`src/authz/leases.rs:412`) immediately selects **`Resolution::DeadlineExceeded`**
           (`state = 'failed'`, `openmettle.run-failed` `{"reason":"deadline_exceeded"}`) and
           `settle_locked` atomically closes `outcome = 'intent' AND dispatched_attempts = 0`
           to `outcome = 'failed', revision = revision + 1` — zero stranded unreclaimable run
           and zero `Reconciling`/`Interrupted`!
       - **Clean successor discovery and send-permit issuance on reclaim (`recovered == true`):**
         When a successor worker reclaims the `running` run via `reclaim_next`,
         `leases::unresolved_operations(..., 1)` is empty (`src/worker.rs:500`), so the
         successor stays in `Running`:
         - **Consumed human approval (`approval_id IS NOT NULL`):** `worker::execute` calls
           `approvals::pending_effect` (`src/worker.rs:519`), whose updated NULL-safe
           `PENDING_EFFECT` SQL (`src/authz/approvals.rs:1241`, `AND NOT EXISTS (... AND
           (o.outcome = 'intent' AND o.dispatched_attempts = 0) IS NOT TRUE)` — never `NOT (...)`
           because legacy `o.outcome = 'intent' AND o.dispatched_attempts IS NULL` evaluates
           `NOT UNKNOWN = UNKNOWN` and would falsely rediscover consumed legacy approvals! —
           while keeping `REQUEST.consumed` unchanged so HTTP `decide` still treats the approval
           as consumed) immediately discovers `(approval_id, proposal)` and calls
           `approvals::record_fenced_intent(..., Some(approval_id), ...)`.
         - **Automatic write (`approval_id IS NULL`):** `Executor::step` (PR4) deterministically
           replays the active turn round (checking for any open `o.approval_id IS NULL AND
           o.outcome = 'intent' AND o.dispatched_attempts = 0` row on `(scope_id, run_id)`
           before starting a new model round) and calls `approvals::record_fenced_intent(...,
           None, ...)`.
         - Under this ADR's explicit narrow amendment to
           [ADR 0035](0035-approvals-permitted-yolo-and-effect-ledger.md) (`lines 260-268`),
           `approvals::record_fenced_intent` locks the existing operation row (`FOR UPDATE`),
           verifies `durable::existing_intent`, and strictly when **`old.outcome == "intent" &&
           old.dispatched_attempts == Some(0) && capability != "repeatable_read"`** re-verifies
           live `EffectPolicy` + `{AUTH}` (loading `run_approvals JOIN run_approval_decisions`
           even though `REQUEST.consumed` is `true` when `old.approval_id IS NOT NULL`, or
           automatic `eligible && yolo` + `hydrate_worker_principal` + `YOLO` when
           `old.approval_id IS NULL`) + `snap.now < old.effective_expires_us` (routing expired
           or revoked authority immediately through `approvals::invalidate_post_intent` ->
           `IntentResult::Invalidated(settled)` with zero sends), returning
           **`IntentResult::Applied(CommittedIntent)`** when valid. `CommittedIntent::start(&step)`
           yields `StartPermit::Ready`, Step 5 Transaction 2 commits **`UPDATE
           openmettle.operations SET dispatched_attempts = 1 WHERE scope_id = $1::uuid AND
           run_id = $2::uuid AND id = $3::uuid AND outcome = 'intent' AND dispatched_attempts =
           0`** under `Fence::Step` (`rows_affected() == 1` strictly required before sending),
           executes the write once, and finishes **`succeeded`**!
    3. **Terminal run settlement (`leases::settle_locked` & `leases::settle_expired`) with zero
       false `Reconciling`/`Interrupted` and atomic cleanup of remaining `'intent'` rows:**
       - **Preserve `Settle::Succeeded` guard unconditionally:** Even though
         `leases::unresolved!()` excludes `dispatched_attempts = 0`, when `input ==
         Settle::Succeeded` `leases::settle_locked` still checks whether ANY write row has
         `outcome IN ('intent', 'outcome_unknown') AND capability IN ('idempotent', 'lookup',
         'non_repeatable')` (including `dispatched_attempts = 0`) and returns
         `Err(StoreError::Conflict("unresolved operation"))` so a run with an unexecuted write
         intent never falsely settles `Resolution::Succeeded` (rolling back with zero
         mutations, matched at the DB boundary by `resolve_terminal_write_intents()` on
         `NEW.state = 'succeeded'`).
       - **On terminal run stop (`Stop::Cancel` / `ExecState::Cancelling`, `Stop::Deadline`,
         `WorkEnd::Handoff` / `leases::handoff` when `NOT time_to_reclaim` (`<= settings.lease`
         remaining), or `Settle::Failed(_)`):** `leases::settle_locked` queries `n` using
         updated `leases::unresolved!()`. When no genuinely dispatched/legacy unresolved writes
         remain (`n = 0`), `leases::settle_locked` settles directly to
         **`Resolution::Cancelled` (`cancelled`)**, **`Resolution::DeadlineExceeded` (`failed`,
         `{"reason":"deadline_exceeded"}`)**, or **`Resolution::Failed(...)`** with **zero
         `Reconciling` and zero `Interrupted`**! **Inside that exact same `settle_locked`
         transaction (whenever settling to any terminal state `Cancelled`, `DeadlineExceeded`,
         `Failed`, or `Interrupted`) — and likewise inside `leases::settle_expired`
         (`src/authz/leases.rs:649-694`) — atomically transition any remaining `outcome =
         'intent' AND (capability = 'repeatable_read' OR dispatched_attempts = 0)` rows on the
         run to `outcome = 'failed', revision = revision + 1`** (with bounded redacted
         observation evidence and its ADR 0004 `openmettle/observation/1\0` `run_events` row
         strictly before `run-terminal`), so no terminal run ever retains an open `'intent'`
         operation row and run-linked storage cleanup predicates fire cleanly!
    4. **Genuinely dispatched or legacy unresolved writes (`outcome = 'outcome_unknown'`, or
       `outcome = 'intent' AND coalesce(dispatched_attempts, 1) > 0`, `n >= 1`):** Whether
       `run_one`'s post-drain `leases::handoff` / `leases::settle(..., Settle::Stopped)`
       succeeds or the lease lapses to `leases::reclaim_next` (`recovered == true`, where
       `leases::unresolved_operations(..., 1)` is non-empty and `worker::execute` returns
       `WorkEnd::Complete(Settle::Stopped)` before any model or tool step, `src/worker.rs:500`),
       the run transitions into **`ExecState::Reconciling`** (when remaining execution budget
       exceeds one lease interval) or directly into terminal **`interrupted`** (when
       `!time_to_reconcile` in `leases::decide`, `src/authz/leases.rs:408-415`, or via
       `leases::settle_expired`), with **zero additional outbound write sends**:
       - Inside **`ExecState::Reconciling`**, `Executor::reconcile` handles each unresolved
         write deterministically:
         - If strictly non-null `dispatched_attempts = 0` (defensive fallback if entered on a
           mixed-write run): records `runs::record_observation` with `outcome = "failed"`
           (`revision = 1`, non-empty redacted evidence, zero external send) under
           `Fence::Hold`.
         - If `dispatched_attempts IS NULL OR dispatched_attempts >= 1` and the reviewed
           contract declares an authorized read-only status/lookup query (`idempotent` or
           `lookup`): recovers the authoritative outcome (`"succeeded"` or `"failed"`,
           inline/bounded) via read-only query with **zero** write re-sends.
         - If `dispatched_attempts IS NULL OR dispatched_attempts >= 1` and no downstream
           read-only lookup is available (every `non_repeatable` write, every legacy/`N-1`
           `dispatched_attempts IS NULL` write without lookup, plus any `lookup` write with
           `downstream_handle IS NULL` and no contract-defined deterministic query): **never
           re-sends** — commits `runs::record_observation` with **`outcome =
           "outcome_unknown"`** (`revision = 1`, fixed redacted post-send observation-lost
           diagnostic) under `Fence::Hold`, settling `ExecState::Reconciling` to terminal
           **`interrupted`** (`{"unresolved": n}`).
       - **Worker rollout gate (`openmettle.runtime_feature_gates.two_phase_effect_intents_enabled`)
         + defense-in-depth trigger:** PR3 gates two-phase zero-attempt writes behind
         `openmettle.runtime_feature_gates.two_phase_effect_intents_enabled` (default `false`
         on upgrade) until all `N-1` `openmettle-worker` claimers and `settle_expired` sweepers
         are drained, ensuring **no `N-1` worker can EVER claim or sweep a `dispatched_attempts
         = 0` write row**; in addition, PR3's `AFTER UPDATE OF state ON openmettle.runs FOR
         EACH ROW` `SECURITY DEFINER` trigger (`openmettle.resolve_terminal_write_intents()`,
         see below) enforces the `NEW.state = 'succeeded'` invariant guard and transitions any
         remaining dispatched/legacy revision-zero write `intent` (`dispatched_attempts IS NULL
         OR dispatched_attempts >= 1`) to `outcome = 'outcome_unknown', revision = 1` strictly
         before `run-terminal`.

**Pre-terminal resolution of abandoned intents & PR3 worker rollout gate (preserving SSE `204`
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
quota; and a direct terminal `'interrupted'` settlement (`!time_to_reconcile` or
`leases::settle_expired`) would bypass `Executor::reconcile` and leave dispatched writes at
`outcome = 'intent', revision = 0`. Across all `UPDATE openmettle.runs` callers in
`src/authz/approvals.rs`, `src/authz/leases.rs` and `src/authz/runs.rs`, every single
transition into `'waiting'` or terminal (`'succeeded'`, `'failed'`, `'cancelled'`,
`'interrupted'`) executes `UPDATE openmettle.runs SET state = ...` in one SQL statement (never
`RETURNING last_event_sequence`) and appends `run-approval-requested`/`run-waiting` or
`run-terminal` in a *subsequent* SQL statement.

PR2's and PR3's sequential SQL migrations (with zero edits to frozen migrations) therefore
enforce pre-terminal resolution and worker rollout gating **at the PostgreSQL database layer**:

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
- **PR3 database-backed worker rollout gate (`openmettle.runtime_feature_gates`) forbidding
  `N-1` workers from ever seeing a `dispatched_attempts = 0` write row.** An `N-1`
  `openmettle-worker` claimer or `leases::settle_expired` sweeper uses the frozen pre-PR3
  `unresolved!()` SQL predicate (`outcome IN ('intent', 'outcome_unknown')`) without inspecting
  `dispatched_attempts`, so emitting `dispatched_attempts = 0` write rows while any `N-1`
  worker is still active would allow an `N-1` worker to falsely turn an unsent write into
  `Reconciling` / `Interrupted` / `outcome_unknown`. PR3's sequential SQL migration therefore
  adds a dedicated 1-row feature-gate table **`openmettle.runtime_feature_gates`**:

  ```sql
  CREATE TABLE openmettle.runtime_feature_gates (
      id boolean PRIMARY KEY DEFAULT true CHECK (id),
      two_phase_effect_intents_enabled boolean NOT NULL DEFAULT false
  );
  INSERT INTO openmettle.runtime_feature_gates (id) VALUES (true);
  GRANT SELECT ON openmettle.runtime_feature_gates TO openmettle_api, openmettle_worker;
  ```

  - **While `two_phase_effect_intents_enabled = false`** (during rolling upgrade while any
    `N-1` `openmettle-worker` claimer or `settle_expired` sweeper is still running):
    1. Scoped MCP tool execution in PR4 fails closed / stays disabled until
       `two_phase_effect_intents_enabled = true`; **and**
    2. Pre-existing ADR 0035 external approval writes in `approvals::record_fenced_intent` keep
       `dispatched_attempts = NULL` (`N-1`-compatible single-phase behavior) so **zero**
       `dispatched_attempts = 0` write rows are emitted while any `N-1` worker exists!
  - **Once all `N-1` `openmettle-worker` processes are drained** and only `N` workers (with the
    updated `unresolved!()`, `leases::handoff`, `settle_locked`, and `settle_expired`
    predicates) are active, `openmettle-admin` / rollout sets
    `two_phase_effect_intents_enabled = true` (and fresh database `bootstrap` sets
    `two_phase_effect_intents_enabled = true` once migrated to `N`), guaranteeing **no `N-1`
    worker can EVER claim or sweep a `dispatched_attempts = 0` write row**!
- **PR3 `AFTER UPDATE OF state ON openmettle.runs` `SECURITY DEFINER` trigger for terminal
  write resolution (`openmettle.resolve_terminal_write_intents()`, defense-in-depth across all
  terminal states).** PR3's sequential SQL migration installs/extends an **`AFTER UPDATE OF
  state ON openmettle.runs FOR EACH ROW`** `SECURITY DEFINER` trigger
  (`openmettle.resolve_terminal_write_intents()`, `WHEN (OLD.state IS DISTINCT FROM NEW.state
  AND OLD.state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted') AND NEW.state IN
  ('succeeded', 'failed', 'cancelled', 'interrupted'))`, owned by `openmettle_owner`, `SET
  search_path = pg_catalog`, `REVOKE ALL FROM PUBLIC`, audited in `src/boundaries.sql`) that
  fires strictly before `run-terminal` is appended:
  - **Invariant guard on `NEW.state = 'succeeded'`:** If any `openmettle.operations` row on
    `(NEW.scope_id, NEW.id)` has `capability IN ('idempotent', 'lookup', 'non_repeatable') AND
    outcome IN ('intent', 'outcome_unknown')`, **`RAISE EXCEPTION`** (invariant violation — a
    run with an unresolved write — including `dispatched_attempts = 0` — can never commit
    `state = 'succeeded'`).
  - **Defense-in-depth coercion on `NEW.state IN ('failed', 'cancelled', 'interrupted')`:** For
    **every remaining** `openmettle.operations` row on `(NEW.scope_id, NEW.id)` with
    `capability IN ('idempotent', 'lookup', 'non_repeatable') AND outcome = 'intent' AND
    revision = 0 ORDER BY id`, transition the row **unconditionally to
    `outcome = 'outcome_unknown'`, `revision = 1`** — **NEVER to `'failed'` inside the
    trigger** — with bounded redacted observation evidence, increment
    `openmettle.runs.last_event_sequence`, and insert its idempotent
    `terminal-write:<operation_id>` [ADR 0004](0004-run-persistence.md)
    `openmettle/observation/1\0` `run_events` row strictly before `run-terminal`. Because
    `openmettle.runtime_feature_gates.two_phase_effect_intents_enabled` prevents any `N-1`
    worker from ever seeing a `dispatched_attempts = 0` write row, and because `N` workers'
    `leases::settle_locked` (on every terminal settlement `Cancelled`, `DeadlineExceeded`,
    `Failed`, `Interrupted`) and `leases::settle_expired` atomically transition any remaining
    `outcome = 'intent' AND (capability = 'repeatable_read' OR dispatched_attempts = 0)` rows
    to `outcome = 'failed', revision = revision + 1` *before* committing the terminal state,
    only genuinely dispatched or legacy (`dispatched_attempts IS NULL OR dispatched_attempts >=
    1`) write rows remain in `'intent'` when the trigger fires, so `'intent' ->
    'outcome_unknown'` preserves exact `{"unresolved": n}` event/ledger parity (`Δn = 0`) while
    ensuring zero dangling revision-zero write `'intent'` rows on any terminal state.

Together, the `two_phase_effect_intents_enabled` rollout gate, these triggers, and PR2's
one-time repair guarantee across pre-existing rows and mixed-version `N-1`/`N` deployments that
no `N-1` worker ever claims or sweeps a `dispatched_attempts = 0` write row,
`runs.last_event_sequence == terminal_sequence` (`204 No Content` on terminal SSE cursor
reconnect), `openmettle_api` retains zero `UPDATE` grant on `openmettle.operations` in
`src/boundaries.sql`, write operations are never modified on `'waiting'` transitions,
`'succeeded'` fails closed if any unresolved write exists, no terminal run (`'failed'`,
`'cancelled'`, `'interrupted'`) ever retains a dangling revision-zero write `'intent'`,
`openmettle.run-interrupted`'s `{"unresolved": n}` payload matches the post-settlement
`unresolved!()` count in `openmettle.operations`, and `storage::release` continues to protect
every unresolved write (including every `outcome_unknown` write transitioned on a terminal run)
with `Error::Unresolved`.

**Ledger-safe spill cleanup (`artifact_fs::reconcile_run_spills`) and single cleanup owner.**
`V1-14` PR2 sequences after `V1-17` PR2 ([ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md)
PR2) to reuse the exact shared storage contract verbatim: the dedicated read-mostly singleton
**`openmettle.storage_volume_control (id, volume_id, bootstrap_auto_pin_allowed,
adoption_run_id)`** (`GRANT SELECT` ONLY to `openmettle_api, openmettle_worker` — zero
`INSERT`/`UPDATE`/`DELETE`/`TRUNCATE` grants — paired with `openmettle_owner`-owned `SECURITY
DEFINER` functions **`openmettle.storage_lock_pinned_volume() RETURNS uuid`** and
**`openmettle.storage_pin_volume_id(p_volume_id uuid) RETURNS uuid`**, keeping only
`warn_pct_1`, `warn_pct_2`, `config_revision` added to `storage_instance`, enforcing the
canonical storage lock order **`runs -> storage_reservations -> artifacts -> artifact_revisions
-> storage_volume_control -> storage_accounts -> storage_instance`** so runtime `SELECT
openmettle.storage_lock_pinned_volume()` never hits PostgreSQL 18 `42501` `FOR SHARE` errors
and never deadlocks against `storage::adjust`'s `FOR NO KEY UPDATE` on `storage_instance`),
`openmettle.storage_reservations.adoption_unverified` with tightened
**`storage_reservations_adoption_unverified_check`** (`CHECK (NOT adoption_unverified OR state
= 'reserved')`), **`stage_claimed boolean NOT NULL DEFAULT false`**, write-once **`payload_ino
numeric(20, 0)`** (`CHECK (payload_ino IS NULL OR payload_ino >= 0)`, `CHECK (payload_ino IS
NULL OR stage_claimed)` — **no `payload_dev` column**), `publish_pending boolean NOT NULL
DEFAULT false` (`CHECK (NOT publish_pending OR (state = 'reserved' AND payload_ino IS NOT
NULL))`), the unified **4-state** cleaner lease shared by all 4 cleaners (`artifact_fs::abort`,
`reconcile_expired`, generic run-linked cleaner, and `reconcile_run_spills`: **`reclaim_state
text NOT NULL DEFAULT 'none' CHECK (reclaim_state IN ('none', 'claiming', 'truncated',
'anchor_pending_unlink'))`**, **`reclaim_claim_token uuid`**, **`reclaim_lease_until
timestamptz`** with their 4 `CHECK` constraints and partial index
`storage_reservations_reclaim_anchor_idx`), durable purge-anchor tracking on
`openmettle.artifact_revisions` (`purge_stage`, `artifact_revisions_purge_stage_check`,
`artifact_revisions_purge_anchor_idx`, and worker-only `GRANT UPDATE (purge_stage) ON
openmettle.artifact_revisions TO openmettle_worker;`), `V1-17` PR2's `SECURITY INVOKER`
triggers **`openmettle.enforce_runtime_storage_volume_pinned()`** (delegating to `PERFORM
openmettle.storage_lock_pinned_volume()` for non-`openmettle_owner` roles) and
**`openmettle.enforce_storage_reservation_monotonic_guards()`** (`OMQ03` forbidding
non-`openmettle_owner` clearing of `adoption_unverified`, modifying/clearing non-null
`payload_ino`, or clearing `stage_claimed`), `V1-17` PR2's
`storage_reservations_tool_spill_binding_guard` trigger (`23514`), and `artifact_fs`'s
`rustix`-backed (`default-features = false, features = ["fs", "std"]`, 100% safe Rust under
`unsafe_code = "forbid"`, adding zero new Cargo crates beyond `V1-17` PR2) verified
directory-descriptor infrastructure (`root_fd`, `staging_dir_fd`, `revisions_dir_fd`). Because
`artifact_fs::reconcile_expired` scans only upload reservations (`run_id IS NULL`) and `run_id
IS NOT NULL` matches all run-linked reservations (not only spills), **exact-complement
cross-ADR partition invariant (`state = 'reserved'`)**: **`V1-14`
(`artifact_fs::reconcile_run_spills`) is the sole automatic cleanup owner of `state =
'reserved'` `operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%'` rows**, and
**`V1-17` ([ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md))'s generic
run-linked `storage_reservations` cleaner uses the exact logical complement `run_id IS NOT NULL
AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')`** (owning any legacy
pre-upgrade malformed `tool-spill:%` row with `operation_id IS NULL` so there is zero unowned
gap, while never releasing quota while ADR 0039's detached streaming writer still holds
`LOCK_EX` on `staging/<id>` and never preserving an unsettled `revisions/<id>` instead of
reclaiming it), while Step 4 anchor sweeps (`state = 'released' AND reclaim_state =
'anchor_pending_unlink'`) run boundedly across ALL reservation kinds, and `V1-17` PR2's
`storage_reservations_tool_spill_binding_guard` trigger (`23514`) forbids inserting or updating
`idempotency_key LIKE 'tool-spill:%'` with `run_id IS NULL OR operation_id IS NULL`.
`artifact_fs::reconcile_run_spills` runs in the worker maintenance sweep using the exact
**unified 4-step crash-safe & replacement-safe reclamation protocol** (preserving `payload_ino`
allocation via `staging/.reclaim.<id>` across cleanup AND fencing Step 2a under `LOCK_EX` so
there is **zero inode-reuse window** before Step 3 commits!) shared by all 4 cleaners
(`artifact_fs::abort`, `reconcile_expired`, generic run-linked cleaner, and
`reconcile_run_spills`), with zero post-terminal `run_events` appends and **zero filesystem I/O
inside any DB transaction**:

- Scan exclusively adapter-owned spill reservations matching `state = 'reserved' AND
  operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%' AND NOT adoption_unverified`
  (strictly requiring `SELECT openmettle.storage_lock_pinned_volume()` matching
  `store.volume_id`). Never touch `state = 'settled'` rows during spill reconciliation; settled
  revisions are deleted only by `artifact_fs::purge_due` after retention expiry.
- **Spill reservation TTL/age guard.** `openmettle.storage_reservations` records `created_at`
  (`migrations/0004_artifacts_storage_accounting.sql`, with no `expires_at` column). Mirroring
  `artifact_fs::reconcile_expired`'s `older_than` threshold (`src/artifact_fs.rs`),
  `reconcile_run_spills` only sweeps a `state = 'reserved'` `tool-spill:*` row once
  `created_at + spill_reservation_ttl <= clock_timestamp()`. `spill_reservation_ttl` is defined
  strictly against the **bounded foreground tool call deadline (`call_timeout` /
  `step.deadline`) plus `run_one`'s bounded worker drain window (`settings.lease / 6`) plus a
  fixed safety margin (default `900 s`)**, ensuring `reconcile_run_spills` never claims an
  active foreground spill early. Payload safety past `spill_reservation_ttl` relies strictly on
  `payload_file`'s continuous `LOCK_EX` (or `Store::stage`'s `LOCK_SH`) blocking sweeper
  `File::try_lock()` (`LOCK_EX | LOCK_NB`) until the writer exits or crashes.
- **Unified 4-step crash-safe & replacement-safe reclamation protocol (`reconcile_run_spills`
  and all ADR 0040 cleaners — zero inode-reuse window via fenced Step 2a under `LOCK_EX` +
  `staging/.reclaim.<id>` + `anchor_pending_unlink`):** Unlinking the last link of
  `payload_ino` and closing the FD before Step 3 commits would allow the filesystem to reassign
  `payload_ino` to a newly created foreign file at `<id>` if the cleaner crashed before Step 3;
  likewise, an expired cleaner could otherwise call `set_len(0)` after a successor cleaner
  completed Steps 2–4 and freed `payload_ino`. All 4 cleaners therefore preserve `payload_ino`
  allocation via hard-link anchor **`staging/.reclaim.<id>`** (`reclaim_name =
  format!(".reclaim.{id}")`) AND revalidate their claim token under `LOCK_EX` strictly before
  any truncation or unlink:
  1. **Step 1 — Serialized DB Claim BEFORE any truncation/unlink (zero FS I/O inside DB tx):**
     Open a short lock-ordered DB transaction (`openmettle.runs FOR NO KEY UPDATE SKIP LOCKED`
     -> `openmettle.storage_reservations FOR UPDATE SKIP LOCKED` -> **`SELECT
     openmettle.storage_lock_pinned_volume()`** comparing the returned `uuid` against
     `store.volume_id`; abort immediately with zero claims, zero unlinks, and zero releases on
     `OMQ03` or mismatch). Require **`state = 'reserved' AND NOT adoption_unverified AND
     (reclaim_state = 'none' OR reclaim_lease_until <= clock_timestamp())`** plus
     `reconcile_run_spills`'s path preconditions (`operation_id IS NOT NULL AND idempotency_key
     LIKE 'tool-spill:%'`, `created_at + spill_reservation_ttl <= clock_timestamp()`, zero
     `artifact_revisions` row, and terminal-run/inactive-lease or resolved `outcome IN
     ('succeeded', 'failed')` non-ambiguous operation). Mint a fresh UUID `$my_token` and
     commit: **`reclaim_state = CASE WHEN reclaim_state = 'truncated' THEN 'truncated' ELSE
     'claiming' END, reclaim_claim_token = $my_token, reclaim_lease_until = clock_timestamp() +
     interval '60 seconds'`** (keeping `state = 'reserved'` and `max_bytes` fully charged, and
     returning `(id, payload_ino, observed_state)`). Because Step 1 acquires `FOR UPDATE` on
     `storage_reservations` first and sets `reclaim_state != 'none'`, any in-flight
     `storage::settle` or Phase 2b `publish_pending = true` fence resolves before Step 2 can
     ever truncate, and no concurrent writer or second healthy cleaner can enter Step 2!
  2. **Step 2 — Target Selection, Fenced Step 2a Lease Revalidation UNDER `LOCK_EX`, Durable
     `0`-Byte Truncation & Unconditionally `fsync`ed `staging/.reclaim.<id>` Anchor (outside DB
     tx, `payload_ino` NEVER drops to `nlink = 0` before Step 3 commits, NEVER clearing
     write-once `payload_ino`!):**
     - **Mandatory pinned-volume & `adoption_run_id IS NULL` verification:** Before treating
       `ENOENT` as absence or touching any file, verify `Store`'s three directories (`root_fd`,
       `staging_dir_fd`, `revisions_dir_fd`) using `rustix::fs::openat` (`OFlags::RDONLY |
       OFlags::DIRECTORY | OFlags::NOFOLLOW`), verifying host-local same-mount `st_dev`
       equality (`staging_meta.dev() == revisions_meta.dev() == root_meta.dev() ==
       store.root_dev`) and regular-file `.openmettle-volume-id` sentinels (`:root`,
       `:staging`, `:revisions` matching `store.volume_id` via `OFlags::RDONLY | OFlags::NOFOLLOW
       | OFlags::NONBLOCK` + `fstat` `S_ISREG`). Fail closed immediately with zero unlinks and
       zero releases on any mismatch or absence.
     - **Subcase A1 (`payload_ino IS NOT NULL` and `reclaim_state = 'claiming'`):**
       **Target selection & `'claiming'` crash recovery:** Probe **`staging/.reclaim.<id>`
       first** if present (covering a predecessor cleaner crash after `linkat(".reclaim.<id>")`
       + `unlinkat("<id>")` before SQL committed `'truncated'`), else probe `staging/<id>` (and
       also check `revisions/<id>` from an aborted pre-settle `linkat`), using
       `rustix::fs::statat(dir_fd, name, AtFlags::SYMLINK_NOFOLLOW)`:
       1. If **any** existing entry is non-regular, wrong local `st_dev` (`stat.st_dev !=
          store.root_dev`), or **`stat.st_ino as u64 != payload_ino`** -> **ZERO `set_len(0)`
          and ZERO `unlinkat`**! Commit quarantine (`SET adoption_unverified = true,
          publish_pending = false, reclaim_state = 'none', reclaim_claim_token = NULL,
          reclaim_lease_until = NULL`) in a short lock-ordered `FOR UPDATE` tx invoking
          `SELECT openmettle.storage_lock_pinned_volume()` (verifying `== store.volume_id`) and
          re-verifying **`state = 'reserved' AND NOT adoption_unverified AND
          reclaim_claim_token = $my_token AND reclaim_state = 'claiming' AND payload_ino =
          $expected_ino`** (leaving the foreign/replacement file untouched, `max_bytes` 100%
          charged, and write-once `payload_ino` intact!).
       2. **Only if ALL THREE (`staging/.reclaim.<id>`, `staging/<id>`, and `revisions/<id>`)
          return confirmed `ENOENT`** does `'claiming'` promote to `adoption_unverified = true`
          under the exact same `FOR UPDATE` guard **`state = 'reserved' AND NOT
          adoption_unverified AND reclaim_claim_token = $my_token AND reclaim_state =
          'claiming' AND payload_ino = $expected_ino`** (ensuring a stale cleaner whose lease
          expired can NEVER quarantine a reservation already truncated or released by another
          cleaner!).
       3. **Step 2a — Mandatory SQL Claim Revalidation & Lease Renewal UNDER `LOCK_EX` Strictly
          BEFORE `set_len(0)` / `linkat` / `unlinkat`:** Open the matched target regular file
          (`staging/.reclaim.<id>` if present, else `staging/<id>` or `revisions/<id>`) with
          `OFlags::RDWR | OFlags::NOFOLLOW`, acquire **`probe_file.try_lock()`** (`LOCK_EX |
          LOCK_NB`; abort on `TryLockError::WouldBlock` with zero truncation/unlink, keeping
          `max_bytes` charged), and verify open-FD `S_ISREG`, `st_dev == store.root_dev`,
          `st_ino as u64 == payload_ino`, and `statat` namespace identity (quarantining
          untouched under the `$my_token` guard on any post-lock foreign mismatch). **While
          CONTINUING to hold `LOCK_EX` on that open FD — and STRICTLY BEFORE calling
          `set_len(0)`, `linkat`, or `unlinkat` — execute a fenced PostgreSQL revalidation &
          lease-renewal transaction:**

          ```sql
          SELECT openmettle.storage_lock_pinned_volume();
          UPDATE openmettle.storage_reservations
             SET reclaim_lease_until = clock_timestamp() + interval '300 seconds'
           WHERE scope_id = $1::uuid
             AND id = $2::uuid
             AND state = 'reserved'
             AND NOT adoption_unverified
             AND payload_ino = $3
             AND reclaim_state = 'claiming'
             AND reclaim_claim_token = $4::uuid
          RETURNING id;
          ```

          (confirming returned `volume_id == store.volume_id`). If `0` rows are returned
          (because an expired cleaner's token `$4` was superseded by a successor that already
          completed Steps 2–4 and freed `payload_ino`, or `state` is no longer `'reserved'`),
          **abort immediately and drop `probe_file` with ZERO `set_len(0)`, ZERO `linkat`, and
          ZERO `unlinkat`!** Because `1` returned row while holding `LOCK_EX` proves `state` is
          still `'reserved'` (`payload_ino` has never reached `nlink = 0`), and while this
          cleaner holds `LOCK_EX` on `probe_file`, no successor cleaner can acquire `LOCK_EX`
          in Step 2a or Step 4 to detach `.reclaim.<id>`, this fence closes the stale-cleaner
          inode-reuse window completely.
       4. Still holding `LOCK_EX` after Step 2a returns `1` row:
          - **(i)** Call **`probe_file.set_len(0)?`** + **`probe_file.sync_all()?`** (`0` bytes
            crash-durable on disk!).
          - **(ii)** Ensure hard-link anchor **`staging/.reclaim.<id>`** (`reclaim_name =
            format!(".reclaim.{id}")`) exists: if not yet present, call
            **`rustix::fs::linkat(&src_dir_fd, src_name, &staging_dir_fd, &reclaim_name,
            AtFlags::empty())`** (if `Errno::EXIST`, verify `statat(&staging_dir_fd,
            &reclaim_name, AtFlags::SYMLINK_NOFOLLOW)` is `S_ISREG` on `store.root_dev` with
            `st_ino as u64 == payload_ino`, aborting untouched otherwise), and
            **UNCONDITIONALLY call and require `Ok(())` from
            `rustix::fs::fsync(&staging_dir_fd)` whether `staging/.reclaim.<id>` was newly
            created in this call OR already existed from a crashed predecessor**, strictly
            BEFORE calling `unlinkat(&staging_dir_fd, id)` or `unlinkat(&revisions_dir_fd,
            id)`! (`nlink` stays `>= 1` durably on disk, so `payload_ino` NEVER hits `nlink =
            0` and CANNOT be reused!)
          - **(iii)** While `staging/.reclaim.<id>` holds `nlink >= 1` and `probe_file` holds
            `LOCK_EX`: unlink any existing `<id>` entry in `revisions/<id>` and `staging/<id>`
            (re-verifying `statat(&dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` is `S_ISREG` on
            `store.root_dev` with `st_ino as u64 == payload_ino` immediately before each
            `unlinkat`) + `rustix::fs::fsync(&revisions_dir_fd)` +
            `rustix::fs::fsync(&staging_dir_fd)`.
          - **(iv)** Still holding `LOCK_EX` on `probe_file` (anchored at
            `staging/.reclaim.<id>`!), commit a short lock-ordered `FOR UPDATE` tx invoking
            `SELECT openmettle.storage_lock_pinned_volume()` (zero disk I/O inside DB tx)
            setting **`reclaim_state = 'truncated', publish_pending = false`** (`WHERE id =
            $1::uuid AND state = 'reserved' AND NOT adoption_unverified AND reclaim_claim_token =
            $my_token AND reclaim_state = 'claiming' AND payload_ino = $expected_ino` —
            **`payload_ino` remains non-null!**). If that short DB commit fails or affects `0`
            rows, drop `probe_file` and abort Step 2!
     - **Subcase A2 (`payload_ino IS NOT NULL` and `reclaim_state = 'truncated'` — crash
       recovery before Step 3):**
       - **NEVER truncate or unlink `staging/<id>` or `revisions/<id>` in `'truncated'`!** Any
         entry appearing at `staging/<id>` or `revisions/<id>` after `'truncated'` is preserved
         100% untouched!
       - Probe **`staging/.reclaim.<id>`** ONLY via `rustix::fs::statat(&staging_dir_fd,
         &reclaim_name, AtFlags::SYMLINK_NOFOLLOW)`: it MUST exist, be `S_ISREG`, same local
         `st_dev == store.root_dev`, **`st_ino as u64 == payload_ino`**, AND **`st_size ==
         0`**. If `ENOENT`, non-regular, wrong local `st_dev`, `st_ino as u64 != payload_ino`,
         or `st_size != 0` -> **quarantine** under `FOR UPDATE` (`SELECT
         openmettle.storage_lock_pinned_volume()`) verifying `state = 'reserved' AND NOT
         adoption_unverified AND reclaim_claim_token = $my_token AND reclaim_state =
         'truncated' AND payload_ino = $expected_ino` (zero `set_len(0)`, zero `unlinkat`).
       - Open `staging/.reclaim.<id>` (**`OFlags::RDWR | OFlags::NOFOLLOW`**, explicitly
         **WITHOUT `OFlags::TRUNC`** and with **zero `set_len(0)`** when already `'truncated'`
         and `st_size == 0` — required on Linux NFS because `flock(LOCK_EX)` maps to
         `fcntl(F_SETLK, F_WRLCK)` which fails with `EBADF` on `O_RDONLY`) -> `LOCK_EX |
         LOCK_NB` -> re-verify `fstat` + `statat` (`S_ISREG`, `st_dev == store.root_dev`,
         `st_ino as u64 == payload_ino`, `st_size == 0`) -> **while holding `LOCK_EX` and
         strictly BEFORE the two directory `fsync`s, execute guarded `300 s` lease renewal**
         (so a slow `fsync` cannot outlast the `60 s` Step 1 claim):

         ```sql
         SELECT openmettle.storage_lock_pinned_volume();
         UPDATE openmettle.storage_reservations
            SET reclaim_lease_until = clock_timestamp() + interval '300 seconds'
          WHERE scope_id = $1::uuid
            AND id = $2::uuid
            AND state = 'reserved'
            AND NOT adoption_unverified
            AND payload_ino = $3
            AND reclaim_state = 'truncated'
            AND reclaim_claim_token = $4::uuid
         RETURNING id;
         ```

         (Confirming returned `volume_id == store.volume_id` and aborting on `0` rows /
         `OMQ03`!) -> only after `1` row returns, execute unconditional
         `rustix::fs::fsync(&staging_dir_fd)?` + `rustix::fs::fsync(&revisions_dir_fd)?` ->
         proceed to Step 3 (**keeping `probe_file` open with `LOCK_EX`**)!
     - **Subcase B (Step 2 Case 2 — `payload_ino IS NULL`, reservation never bound a writer
       inode, e.g., crashed after Phase 1a or `Store::stage` Step 1a/1b):**
       - If `revisions/<id>` exists (any type), OR `staging/.reclaim.<id>` exists (any type),
         OR `staging/<id>` exists and is non-regular, different local `st_dev`, or **`st_size >
         0`**: **ZERO `set_len(0)` and ZERO `unlinkat`**! Commit quarantine (`SET
         adoption_unverified = true, publish_pending = false, reclaim_state = 'none',
         reclaim_claim_token = NULL, reclaim_lease_until = NULL`) under `FOR UPDATE` verifying
         `state = 'reserved' AND NOT adoption_unverified AND reclaim_claim_token = $my_token
         AND payload_ino IS NULL` (`SELECT openmettle.storage_lock_pinned_volume()` active
         check).
       - If `staging/<id>` is a `0`-byte regular file (`st_size == 0`, `st_dev ==
         store.root_dev`) with `revisions/<id>` and `staging/.reclaim.<id>` `ENOENT`: open
         `staging/<id>` (**`OFlags::RDWR | OFlags::NOFOLLOW`**, explicitly **WITHOUT
         `OFlags::TRUNC`**, zero `set_len(0)`, required for Linux NFS `LOCK_EX` / `F_WRLCK`) ->
         acquire `LOCK_EX` (`probe_file.try_lock()`) -> re-verify `fstat` (`S_ISREG`, `st_dev
         == store.root_dev`, `st_size == 0`), `statat(&staging_dir_fd, id,
         AtFlags::SYMLINK_NOFOLLOW)` `(fd_dev, fd_ino)` match, and BOTH `revisions/<id>` and
         `staging/.reclaim.<id>` `ENOENT` -> **while still holding continuous `LOCK_EX`,
         execute `rustix::fs::fsync(&staging_dir_fd)?` strictly BEFORE executing Step 2a's SQL
         `UPDATE`** (matching the writer path's directory-sync-before-inode-commit barrier so a
         storage/power crash immediately after Step 2a commits can never leave a bound
         reservation with all three names absent!). Then **while still holding `LOCK_EX`**,
         execute Step 2a SQL **atomically binding `stage_claimed = true, payload_ino = fd_ino`**
         in that same atomic `UPDATE`:

         ```sql
         SELECT openmettle.storage_lock_pinned_volume();
         UPDATE openmettle.storage_reservations
            SET stage_claimed = true,
                payload_ino = $3,
                reclaim_lease_until = clock_timestamp() + interval '300 seconds'
          WHERE scope_id = $1::uuid
            AND id = $2::uuid
            AND state = 'reserved'
            AND NOT adoption_unverified
            AND payload_ino IS NULL
            AND reclaim_state = 'claiming'
            AND reclaim_claim_token = $4::uuid
         RETURNING id;
         ```

         (Confirming returned `volume_id == store.volume_id` and aborting with zero filesystem
         mutations on `0` rows / `OMQ03`.) On `1` returned row (still holding `LOCK_EX`),
         promote directly into the standard `.reclaim.<id>` anchor sequence:
         `rustix::fs::linkat(&staging_dir_fd, id, &staging_dir_fd, &reclaim_name,
         AtFlags::empty())` -> unconditional `rustix::fs::fsync(&staging_dir_fd)?` ->
         `rustix::fs::unlinkat(&staging_dir_fd, id, AtFlags::empty())` (never `set_len(0)`) ->
         unconditional `rustix::fs::fsync(&staging_dir_fd)?` +
         `rustix::fs::fsync(&revisions_dir_fd)?` -> commit `reclaim_state = 'truncated',
         publish_pending = false` (`WHERE scope_id = $1::uuid AND id = $2::uuid AND state =
         'reserved' AND NOT adoption_unverified AND payload_ino = $3 AND reclaim_state =
         'claiming' AND reclaim_claim_token = $4::uuid`) -> proceed to Step 3
         (`storage::release` setting `reclaim_state = 'anchor_pending_unlink'`) -> Step 4!
       - **All-three-`ENOENT` case:** Thus `payload_ino` stays `NULL` through Step 3 **ONLY**
         when `staging/<id>`, `staging/.reclaim.<id>`, and `revisions/<id>` are ALL already
         `ENOENT`, where the cleaner executes unconditional
         `rustix::fs::fsync(&staging_dir_fd)?` + `rustix::fs::fsync(&revisions_dir_fd)?` and
         performs **ZERO `unlinkat` calls** before Step 3!
  3. **Step 3 — Final `storage::release` (ZERO filesystem I/O inside DB tx in BOTH ADR 0039 and
     ADR 0040!):** Open a short lock-ordered DB transaction (`(runs FOR NO KEY UPDATE SKIP
     LOCKED ->) storage_reservations FOR UPDATE SKIP LOCKED`), strictly requiring **`state =
     'reserved' AND NOT adoption_unverified AND NOT publish_pending AND reclaim_claim_token =
     $my_token AND (payload_ino IS NULL OR reclaim_state = 'truncated')`** (plus path
     preconditions), setting **`reclaim_state = CASE WHEN payload_ino IS NOT NULL THEN
     'anchor_pending_unlink' ELSE 'none' END, reclaim_claim_token = NULL, reclaim_lease_until =
     NULL`**, and committing `storage::release` (**retaining write-once `payload_ino` on the
     `'released'` row**; `UPDATE storage_reservations` fires `V1-17` PR2's `SECURITY INVOKER`
     `enforce_runtime_storage_volume_pinned()` trigger invoking **`PERFORM
     openmettle.storage_lock_pinned_volume()`** — taking `storage_volume_control FOR SHARE` as
     `openmettle_owner` without PostgreSQL 18 `42501` errors and raising `OMQ03` if
     missing/unpinned/adopting — and `storage::adjust()` updates **`storage_accounts (FOR
     UPDATE) -> storage_instance (FOR UPDATE)`** with zero `FOR SHARE -> FOR NO KEY UPDATE`
     deadlock across concurrent releases and reserves, and zero post-terminal `run_events`).
     Because every abandoned `repeatable_read` (and every terminal `dispatched_attempts = 0`
     write) was transitioned to `outcome = 'failed'` strictly before `run-terminal`,
     `storage::release` succeeds cleanly after TTL on terminal runs while preserving
     `runs.last_event_sequence == terminal_sequence` (`204 No Content` on terminal SSE cursor
     reconnect) and continuing to fail closed with `Error::Unresolved` on any unresolved
     dispatched/legacy write (`outcome = 'outcome_unknown'` or `outcome = 'intent'`).
  4. **Step 4 — Post-release `LOCK_EX` detach of `staging/.reclaim.<id>` + Bounded Ledger-Driven
     Step 4 Sweep Across ALL Reservation Kinds (strictly AFTER Step 3 commits `'released'`):**
     - Immediately after Step 3 commits when `payload_ino IS NOT NULL` (either reusing
       `probe_file` still holding `LOCK_EX`, or opening `staging/.reclaim.<id>` with
       **`OFlags::RDWR | OFlags::NOFOLLOW`** — explicitly **WITHOUT `OFlags::TRUNC`**, required
       for Linux NFS `LOCK_EX` / `F_WRLCK` -> `try_lock()` `LOCK_EX`): re-verify `fstat(fd)` +
       `statat(&staging_dir_fd, &reclaim_name, AtFlags::SYMLINK_NOFOLLOW)` match `S_ISREG`,
       `st_dev == store.root_dev`, `st_ino as u64 == payload_ino`, and `st_size == 0`; call
       **`rustix::fs::unlinkat(&staging_dir_fd, &reclaim_name, AtFlags::empty())`** (**NEVER
       `set_len(0)`**) -> `drop(probe_file)` -> **`rustix::fs::fsync(&staging_dir_fd)`** ->
       commit `UPDATE openmettle.storage_reservations SET reclaim_state = 'none' WHERE id =
       $1::uuid AND state = 'released' AND reclaim_state = 'anchor_pending_unlink'`.
     - **Bounded ledger-driven Step 4 sweep across ALL reservation kinds with wrapping keyset
       cursor + pass-start fixed upper watermark (replacing any `tool-spill:%`-only
       released-anchor pass):** In `StagingSweepState` / `artifact_fs::reconcile_expired`
       (backed by partial index `CREATE INDEX storage_reservations_reclaim_anchor_idx ON
       openmettle.storage_reservations (closed_at, id) WHERE state = 'released' AND
       reclaim_state = 'anchor_pending_unlink';`), maintain a per-worker wrapping keyset cursor
       **`reclaim_anchor_cursor: Option<(DateTime<Utc>, Uuid)>`** paired with a pass-start
       fixed upper watermark **`reclaim_anchor_pass_upper: Option<(DateTime<Utc>, Uuid)>`**
       covering **both ordinary uploads and MCP spills** (after verifying `SELECT
       openmettle.storage_lock_pinned_volume()` matches `store.volume_id` and all three
       sentinels). At the start of each sweep pass (whenever `reclaim_anchor_pass_upper` is
       `None`), capture `(upper_ts, upper_id)` via:

       ```sql
       SELECT closed_at, id
         FROM openmettle.storage_reservations
        WHERE state = 'released'
          AND reclaim_state = 'anchor_pending_unlink'
          AND NOT adoption_unverified
          AND payload_ino IS NOT NULL
        ORDER BY closed_at DESC, id DESC
        LIMIT 1;
       ```

       (Returning immediately if `None`.) Constrain every page in that pass to `(upper_ts,
       upper_id)`:

       ```sql
       SELECT scope_id::text, id::text, payload_ino, closed_at
         FROM openmettle.storage_reservations
        WHERE state = 'released'
          AND reclaim_state = 'anchor_pending_unlink'
          AND NOT adoption_unverified
          AND payload_ino IS NOT NULL
          AND ($1::timestamptz IS NULL OR (closed_at, id) > ($1::timestamptz, $2::uuid))
          AND (closed_at, id) <= ($3::timestamptz, $4::uuid)
        ORDER BY closed_at ASC, id ASC
        LIMIT $5;
       ```

       Advance `reclaim_anchor_cursor = Some((row.closed_at, row.id))` past **every** inspected
       row (including anomalous foreign-inode / non-zero-size rows left pending for operator
       inspection and `WouldBlock` rows!) so `LIMIT` anomalous anchors cannot starve later rows
       whose anchor was already unlinked before a crash (`ENOENT`, invisible to `ReadDir`), and
       reset **BOTH `reclaim_anchor_cursor = None` AND `reclaim_anchor_pass_upper = None`** as
       soon as a page returns `< LIMIT` rows **OR** reaches `(upper_ts, upper_id)` —
       guaranteeing bounded wrap back to earlier `WouldBlock` rows even under sustained
       arrivals of `>= LIMIT` newly released rows per tick! For each row: if
       `staging/.reclaim.<id>` exists as `S_ISREG` on `store.root_dev` with `st_ino as u64 ==
       payload_ino` and `st_size == 0`, detach under `LOCK_EX` (**`OFlags::RDWR |
       OFlags::NOFOLLOW`**, explicitly without `OFlags::TRUNC`, NEVER `set_len(0)`) -> `drop`
       -> `fsync(&staging_dir_fd)` -> `UPDATE ... SET reclaim_state = 'none' WHERE id =
       $1::uuid AND state = 'released' AND reclaim_state = 'anchor_pending_unlink'`; if
       `Errno::NOENT` (crashed after `unlinkat` + `fsync` before SQL update), call
       `fsync(&staging_dir_fd)` and set `reclaim_state = 'none'`; if foreign inode or non-zero
       size, leave untouched and log an operator anomaly warning.
- **`openmettle storage adopt` alignment (verbatim with ADR 0040):**
  - **Phase 3A (read-only verification, cross-reservation inode uniqueness excluding retired
    historical inodes and already-detached `ENOENT` pending anchors, `LOCK_EX` serialization
    across ALL `'reserved'` rows' matching regular files with `held_candidate_locks` self-lock
    tracking and stable `.reclaim.<id>` re-probe, and intermediate crash-state recognition):**
    - **Cross-reservation inode uniqueness (`R1 <> R2 => ino(R1) <> ino(R2)`):** Because
      retaining `payload_ino` on released/purged rows after Step 4 / Stage C detaches the last
      anchor is intentional, Phase 3A compares **ONLY live payloads, surviving on-disk anchors,
      and all candidates for `payload_ino` backfill or `adoption_unverified = false`
      clearance** — namely:
      - `artifact_revisions` with `state IN ('active', 'retained')`, surviving `state =
        'purging'`, OR `(state = 'purged' AND purge_stage = 'anchor_pending_unlink')`
        **STRICTLY ONLY when `revisions/.purge.<id>` is verified still present on disk**; AND
      - `storage_reservations` with `(state = 'reserved' AND (payload_ino IS NOT NULL OR
        candidate_for_backfill_or_unquarantine))` OR `(state = 'released' AND reclaim_state =
        'anchor_pending_unlink')` **STRICTLY ONLY when `staging/.reclaim.<id>` is verified
        still present on disk**!
      - **Explicitly EXCLUDE retired historical rows AND already-detached (`ENOENT`) pending
        anchors whose files and anchors are no longer on disk:** `(state = 'released' AND
        reclaim_state = 'none')`, `state = 'settled'` rows whose revision is
        `(artifact_revisions.state = 'purged' AND purge_stage = 'none')`, `(state = 'released'
        AND reclaim_state = 'anchor_pending_unlink')` when `staging/.reclaim.<id>` is already
        `ENOENT` on disk (crash after Step 4 `unlinkat` + `fsync` before SQL cleared
        `'anchor_pending_unlink'`), AND `(artifact_revisions.state = 'purged' AND purge_stage =
        'anchor_pending_unlink')` when `revisions/.purge.<id>` is already `ENOENT` on disk
        (crash after Stage C `unlinkat` + `fsync` before SQL cleared `'anchor_pending_unlink'`)
        — because their inodes are already freed to the filesystem so legitimate OS inode reuse
        on later uploads never falsely rejects re-adoption (while Phase 3C clears those
        `ENOENT` `'anchor_pending_unlink'` rows to `'none'`)! Phase 3A rejects adoption with
        `cross_reservation_inode_alias` if two distinct in-scope reservation IDs share an inode
        (hard-link alias across distinct reservation IDs) while allowing intra-reservation
        `<id>` / `.reclaim.<id>` / `.purge.<id>` aliases.
    - **Adoption `LOCK_EX` serialization across ALL `'reserved'` rows' matching regular files,
      adopter self-lock tracking (`held_candidate_locks`), and stable `.reclaim.<id>`
      re-probe:** Across adoption's Step 2 scan, maintain
      **`held_candidate_locks: HashMap<(u64, u64), Uuid>`** (`(st_dev, st_ino) ->
      reservation_id`) and acquire non-blocking **`OFlags::RDWR | OFlags::NOFOLLOW`** (without
      `OFlags::TRUNC`, zero `set_len(0)`) **`LOCK_EX`** on **ALL `'reserved'` rows' matching
      regular files on disk** — covering **BOTH `payload_ino IS NULL` backfill candidates AND
      already-bound `payload_ino IS NOT NULL` `'reserved'` rows** (explicitly including
      `reclaim_state IN ('none', 'claiming', 'truncated')` and previously quarantined
      `adoption_unverified = true` clearance candidates whenever `sr.payload_ino IS NULL ||
      fd_ino == sr.payload_ino`; foreign `sr.payload_ino IS NOT NULL && fd_ino !=
      sr.payload_ino` is classified directly as mismatch/quarantine without calling
      `try_lock()`):
      - **Self-lock tracking BEFORE `try_lock()`:** After opening a `'reserved'` candidate file
        (`OFlags::RDWR | OFlags::NOFOLLOW`, no `OFlags::TRUNC`) and checking `fstat(fd)`
        (`S_ISREG`, `st_dev == store.root_dev`), inspect
        **`held_candidate_locks.get(&(fd_dev, fd_ino))` strictly BEFORE calling `try_lock()`**:
        - If owned by `other_res_id != reservation_id`: immediately record deterministic hard
          failure **`cross_reservation_inode_alias`** (entering Phase 3B with zero backfills —
          **NEVER calling a second `try_lock()` that would self-contend with `WouldBlock` on
          Linux `flock(2)`!**).
        - If owned by `same_res_id == reservation_id` (intra-reservation hard link across
          `<id>` / `.reclaim.<id>` / `revisions/<id>`): verify `statat` matches `(fd_dev,
          fd_ino)` and reuse the already-held `LOCK_EX` without calling `try_lock()` again.
        - Only when `(fd_dev, fd_ino)` is absent from `held_candidate_locks`: call
          `try_lock()` (`LOCK_EX | LOCK_NB`; if `WouldBlock` because an active cleaner or
          writer holds `LOCK_EX`/`LOCK_SH` — **BOTH before Step 2a commit (`payload_ino IS
          NULL`) AND after Step 2a commit (`payload_ino IS NOT NULL`, e.g., `reclaim_state =
          'claiming'` or `'truncated'`)** — adoption clears `adoption_run_id = NULL` in Step 3
          with zero quarantines and zero backfills and returns retryable `OMQ03` busy!),
          re-verify `fstat(fd)` + `statat` namespace identity, insert `((fd_dev, fd_ino),
          reservation_id)` into `held_candidate_locks`, and **retain the locked descriptor
          continuously through Phase 3C commit**!
      - **Stable observation rule before classifying a `'reserved'` row (including bound
        `reclaim_state = 'claiming'`) as missing:** Probe `staging/.reclaim.<id>`,
        `staging/<id>`, and `revisions/<id>`. If all three initially return `ENOENT` — OR if
        post-`LOCK_EX` `statat` on `staging/<id>`/`revisions/<id>` returns `ENOENT` because an
        active cleaner unlinked `<id>` just before releasing `LOCK_EX` — **re-probe
        `staging/.reclaim.<id>` (and `revisions/<id>`) once more** before classifying the row
        as absent (guaranteed race-free because cleaners link `.reclaim.<id>` strictly before
        unlinking `<id>` and Step 3/Step 4 cannot run while `adoption_run_id IS NOT NULL`, and
        publishers link `revisions/<id>` strictly before unlinking `staging/<id>`).
    - **Intermediate crash-state verification in Phase 3A:**
      - **`reclaim_state = 'truncated'`:** For rows ALREADY in `reclaim_state = 'truncated'`,
        Phase 3A positively requires `staging/.reclaim.<id>` (`S_ISREG`, `st_dev ==
        store.root_dev`, `st_ino == payload_ino`, `st_size == 0`) **AND requires both
        `staging/<id>` and `revisions/<id>` to be `ENOENT`** (rejecting adoption if visible
        names still share that inode on an already-`'truncated'` row!).
      - **`artifact_revisions.state = 'purging'`:** The `st_size == 0` Stage A intermediate
        crash exception on `revisions/<id>` or `revisions/.purge.<id>` is reserved **strictly
        for already-bound revisions (`sr.payload_ino IS NOT NULL AND st_ino ==
        sr.payload_ino`)**! Because pinned `main`'s `purge_due` (`src/artifact_fs.rs:227-232,
        694-707`) calls `fs::remove_file` + `sync_dir` and never truncates, surviving legacy
        `'purging'` rows (`sr.payload_ino IS NULL` with `revisions/<id>` present on disk) MUST
        match **exact recorded `st_size == size_bytes` AND `sha256 == content_digest`**
        (identical to `'active'` and `'retained'` revisions; **rejecting `st_size == 0` when
        `size_bytes > 0`**).
  - **Phase 3B (verification-failure branch ONLY — zero backfills, zero Case 6b purge
    completions):** When Phase 3A verification fails (including `cross_reservation_inode_alias`),
    **Phase 3B** performs **ZERO `payload_ino` backfills and ZERO Case 6b purge completions**
    (clearing `adoption_run_id = NULL` without writing `payload_ino` or completing `'purging'`
    rows, and returning failure!).
  - **Phase 3C (success-only commit branch ONLY):** Strictly when Phase 3A succeeds, **Phase
    3C** commits atomically as `openmettle_owner`: (a) **never writes `payload_ino` onto rows
    that remain quarantined**, backfilling `payload_ino` on verified candidates while
    continuously holding all acquired `LOCK_EX` descriptors across matching `'reserved'` rows
    through Phase 3C commit; (b) **keeps `reclaim_state = 'claiming'` as `'claiming'` (NEVER
    promoting `'claiming'` to `'truncated'`)** and expires **`reclaim_lease_until =
    clock_timestamp()`** (backfilling `payload_ino` if `NULL`) so the resumed cleaner runs full
    Step 2 (`.reclaim.<id>`-first probe -> `LOCK_EX` -> Step 2a SQL revalidation ->
    `fsync(&staging_dir_fd)` -> unlink any surviving `staging/<id>` and `revisions/<id>` ->
    dual `fsync` -> `'truncated'`), keeps already-`'truncated'` rows as `'truncated'` with
    `reclaim_lease_until = clock_timestamp()` so the next cleaner tick finishes Step 3 -> Step
    4 without stranding quota, and clears already-detached (`ENOENT`) `'anchor_pending_unlink'`
    rows (`reclaim_state = 'none'` / `purge_stage = 'none'`); (c) atomically completes
    verified-absent legacy `'purging'` rows (**Case 6b**: `sr.payload_ino IS NULL` with
    `ENOENT` across `revisions/<id>`, `revisions/.purge.<id>`, and `staging/<id>`) as
    `openmettle_owner` inside **Phase 3C** (`SET state = 'purged', purged_at =
    clock_timestamp(), purge_stage = 'none'` + `retained_bytes` decrement on `storage_accounts`
    and `storage_instance`), noting explicitly that **absent rows never count as positive
    on-disk file evidence for volume identity**; and (d) links the role-tagged sentinels, pins
    `volume_id`, and clears `adoption_run_id = NULL`.

- **Unified HTTP `Store::stage` / `Store::publish` / `Store::read` companion rules, shared
  zero-truncation `StagingSweepState`, and 3-stage inode-preserving `artifact_fs::purge_due`:**
  - **Mixed-version rollout availability & API-only bootstrap contract (aligned verbatim with
    ADR 0040):** HTTP `Store::stage` and `Store::publish` (`openmettle_api`) **succeed during
    mixed-version rolling upgrade while `storage_volume_control.volume_id IS NULL AND
    adoption_run_id IS NULL`** (reading `SELECT volume_id, adoption_run_id FROM
    openmettle.storage_volume_control WHERE id` without `FOR SHARE` and skipping role-tagged
    sentinel reads while `volume_id IS NULL`, and invoking `SELECT
    openmettle.storage_lock_pinned_volume()` + verifying role-tagged sentinels `:root`,
    `:staging`, `:revisions` once `volume_id IS NOT NULL`), whereas worker `publish_bytes` and
    all 4 cleaners (`artifact_fs::abort`, `reconcile_expired`, generic run-linked cleaner, and
    `reconcile_run_spills`) strictly require **`SELECT openmettle.storage_lock_pinned_volume()`
    matching `store.volume_id`** (`volume_id IS NOT NULL AND adoption_run_id IS NULL`)!
    **API-only fresh bootstrap:** `GRANT EXECUTE ON FUNCTION
    openmettle.storage_pin_volume_id(uuid) TO openmettle_api;` is strictly **API-only** — only
    `openmettle_api` (`Store::open` in API) initializes fresh `.openmettle-volume-id` sentinels
    and invokes `SELECT openmettle.storage_pin_volume_id($1)` (`SECURITY DEFINER`) on an empty
    fresh bootstrap (`bootstrap_auto_pin_allowed = true`) without raw invoker `FOR UPDATE` or
    `UPDATE`. **`openmettle_worker` NEVER initializes sentinels and NEVER calls
    `storage_pin_volume_id(uuid)`**: if a worker starts before API pins a fresh volume (or
    before `openmettle storage adopt` pins an upgraded volume), worker storage sweeps and
    `publish_bytes` observe `OMQ03` / unpinned state cleanly via
    `storage_lock_pinned_volume()` (with zero `42501` privilege errors!) and skip/fail closed
    cleanly until `volume_id` is pinned.
  - **PR2 HTTP `Store::stage` / `Store::publish` (`src/artifact_fs.rs:144-158`) non-destructive
    staged-claim & `linkat` lifecycle:**
    - **Step 1a:** Under `FOR UPDATE` (checking `SELECT openmettle.storage_lock_pinned_volume()`
      when pinned, or plain `SELECT` `adoption_run_id IS NULL` while unpinned during rollout),
      commit **`stage_claimed = true`** requiring `state = 'reserved' AND NOT
      adoption_unverified AND NOT stage_claimed AND payload_ino IS NULL AND reclaim_state =
      'none'` BEFORE `openat`.
    - **Step 1b:** Re-verify `(root_fd, staging_dir_fd, revisions_dir_fd)` host-local
      same-mount `st_dev` (plus role-tagged sentinels when `volume_id IS NOT NULL`), open
      `staging/<id>` (`OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW`, `0`
      bytes, mode `0o600`) -> `file.try_lock_shared()` (`LOCK_SH | LOCK_NB`) -> capture
      `staged_ino` -> **`rustix::fs::fsync(&staging_dir_fd)`**.
    - **Step 1c:** Under `FOR UPDATE`, commit write-once **`payload_ino = staged_ino`**
      (`reclaim_state = 'none'`, keeping `publish_pending = false` while `0` bytes).
    - **`StagedFile::drop` is 100% non-destructive (`close` only — NEVER calls `set_len(0)`
      and NEVER calls `unlinkat`)!** After payload bytes are written and `sync_all()`ed,
      pre-publish commits `publish_pending = true` under `FOR UPDATE` (`state = 'reserved' AND
      NOT adoption_unverified AND payload_ino = $staged_ino AND reclaim_state = 'none'`),
      publishes via **`rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id,
      AtFlags::empty())`** (failing atomically with `Errno::EXIST` without overwriting any
      pre-existing `revisions/<id>` AND **keeping `staging/<id>` linked on disk throughout the
      entire pre-settlement `state = 'reserved'` window** so any `N-1` API retry hits
      `OpenOptions::create_new(true)` -> `Err(Error::InProgress)` at `src/artifact_fs.rs:474-475`
      without calling `abort()` or replacing `fs::rename`!) + `fsync(&revisions_dir_fd)` +
      post-`linkat` re-verification (`<root>`, `"staging"`, `"revisions"` + sentinels when
      pinned + `statat(&revisions_dir_fd, id)` `S_ISREG`, local `st_dev`, `st_ino as u64 ==
      staged_ino`, `st_size == size_bytes`), settles `storage::settle` (`state = 'settled',
      publish_pending = false`, **retaining write-once `payload_ino`**!), and **strictly AFTER
      `storage::settle` commits** performs post-`commit` best-effort detach of `staging/<id>`
      while holding `LOCK_SH` (verifying `statat(&staging_dir_fd, id).st_ino == staged_ino` AND
      `statat(&revisions_dir_fd, id).st_ino == staged_ino` -> `unlinkat(&staging_dir_fd, id,
      AtFlags::empty())` with **NEVER `set_len(0)`** -> `drop(file)` ->
      `fsync(&staging_dir_fd)`). Ambiguous `storage::settle` commit NEVER calls `abort` and
      NEVER detaches; `abort` runs only on confirmed pre-settlement failure and uses the exact
      4-step `LOCK_EX` `staging/.reclaim.<id>` protocol above!
  - **`Store::read` (`src/artifact_fs.rs:190-208, 300-355`) `LOCK_SH` acquisition,
    payload-inode verification, and `Content` stream retention (aligned verbatim with ADR
    0040):** Without `LOCK_SH` held across the open descriptor, a slow streaming download
    (`Content`) spanning retention + grace deadline would allow `purge_due` Stage A to acquire
    `LOCK_EX` and `set_len(0)` mid-stream, failing `file.read_exact` (`src/artifact_fs.rs:334`)
    after advertising full `Content-Length`. `Store::read` therefore requires
    `sr.adoption_unverified = false` and executes the exact 4-step locked read sequence:
    1. Open `revisions/<reservation>` via **`openat(&revisions_dir_fd, reservation,
       OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK, Mode::empty())`** (`O_RDONLY` is
       valid for shared `LOCK_SH` / `F_RDLCK` on both local POSIX and Linux NFS, and
       `O_NONBLOCK` guarantees `openat` never blocks indefinitely in the kernel if
       `revisions/<reservation>` is a writerless FIFO), and immediately check
       **`file.metadata()?.file_type().is_file()`** (failing closed with `Err(Error::Missing)`
       on FIFOs, sockets, devices, or directories without blocking!).
    2. Acquire non-blocking **`file.try_lock_shared()`** (`LOCK_SH | LOCK_NB`; if `WouldBlock`
       because `purge_due` Stage A holds `LOCK_EX`, return `Err(Error::Missing)` strictly
       before response headers are sent!).
    3. **Strictly AFTER acquiring `LOCK_SH`**, re-verify `file.metadata()?` (`is_file()`, local
       same-mount `st_dev == store.root_dev` / `revisions_dir_meta.dev() ==
       root_fd_meta.dev()`, `st_ino == sr.payload_ino` whenever `sr.payload_ino IS NOT NULL`,
       and `len() == size`) AND verify `statat(&revisions_dir_fd, reservation,
       AtFlags::SYMLINK_NOFOLLOW)` matches `(fd_dev, fd_ino)` (so an already-unlinked file
       returns `Err(Error::Missing)`), allowing `sr.payload_ino IS NULL` **only** while
       `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL` (pre-adoption
       legacy rows, since `openmettle storage adopt` Step 3 backfills `payload_ino` on all
       verified `'active'`/`'retained'`/`'purging'` revisions before pinning `volume_id`), then
       `seek(SeekFrom::Start(start))?`.
    4. **Retain that locked `fs::File` inside `Content` (`src/artifact_fs.rs:300-355`) for the
       entire response body stream lifetime** until `Content` completes or drops — causing any
       concurrent `purge_due` Stage A `try_lock()` (`LOCK_EX | LOCK_NB`) to observe
       `WouldBlock` and defer truncation/purge to a subsequent tick after the download
       completes!
  - **Shared zero-truncation `StagingSweepState` in `worker::maintenance` (ZERO `set_len(0)`
    calls in ANY branch — including `0`-row orphans and `.reclaim.<id>`!):** `V1-14` PR2 shares
    `V1-17` PR2's single unified **`StagingSweepState`** in `worker::maintenance`, strictly
    requiring **`SELECT openmettle.storage_lock_pinned_volume()` matching `store.volume_id`**
    and exact three-directory pinned volume identity (`root_fd`, `staging_dir_fd`,
    `revisions_dir_fd`, local same-mount `st_dev == store.root_dev`, role-tagged sentinels
    `:root`, `:staging`, `:revisions`). **`StagingSweepState` NEVER calls `set_len(0)` in ANY
    branch** and opens every `LOCK_EX` target with **`OFlags::RDWR | OFlags::NOFOLLOW`**
    (explicitly **WITHOUT `OFlags::TRUNC`** — required on Linux NFS because `flock(LOCK_EX)` is
    emulated via `fcntl(F_SETLK, F_WRLCK)`, which fails with `EBADF` on `O_RDONLY` descriptors,
    while `OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK` + immediate `is_file()`
    remains valid for shared `LOCK_SH` / `F_RDLCK` in `Store::read` and post-`settle`
    publisher detach): unlinking (`unlinkat`) detaches only the
    `staging/` directory entry (`nlink -= 1`), so if `nlink == 1` the filesystem frees 100% of
    blocks when the FD closes, whereas if `nlink > 1` (e.g., an aged `staging/A` or unowned
    `staging/.reclaim.<id>` hard-linked to active `revisions/B`), `revisions/B` retains 100% of
    its committed bytes! `StagingSweepState` explicitly partitions `ReadDir` entries strictly
    relative to `staging_dir_fd` into three classes:
    1. **`.openmettle-volume-id`:** always skip.
    2. **Entries named `.reclaim.<id>` (where `<id>` is a valid lowercase canonical UUID):**
       Query `SELECT state, adoption_unverified, payload_ino, reclaim_state FROM
       openmettle.storage_reservations WHERE id = $1::uuid`:
       - **`state = 'reserved'` (any `reclaim_state`, e.g., `'claiming'` or `'truncated'`) or
         `adoption_unverified = true`:** skip 100% untouched (active/recovering reclaim anchor
         or quarantined row).
       - **`state = 'released' AND reclaim_state = 'anchor_pending_unlink' AND NOT
         adoption_unverified AND payload_ino IS NOT NULL`:** execute Step 4 anchor detach —
         verify `S_ISREG`, `st_dev == store.root_dev`, `st_ino as u64 == payload_ino`, and
         `st_size == 0`, open **`OFlags::RDWR | OFlags::NOFOLLOW`** (explicitly without
         `OFlags::TRUNC`) -> `LOCK_EX` (`try_lock()`) -> re-verify `fstat(fd)` + `statat` match
         `(store.root_dev, payload_ino)` and `st_size == 0` ->
         `rustix::fs::unlinkat(&staging_dir_fd, ".reclaim.<id>", AtFlags::empty())` (**NEVER
         `set_len(0)`**) -> `drop` -> `rustix::fs::fsync(&staging_dir_fd)` -> `UPDATE
         openmettle.storage_reservations SET reclaim_state = 'none' WHERE id = $1::uuid AND
         state = 'released' AND reclaim_state = 'anchor_pending_unlink'` (if `st_ino !=
         payload_ino` or `st_size != 0`, leave untouched and log an anomaly warning).
       - **`0` rows in `storage_reservations` (aged `st_mtime > 900 s`), OR `(state =
         'released' AND reclaim_state = 'none' AND st_mtime > 900 s)`, OR `(state = 'settled'
         AND st_mtime > 900 s)`:** open **`OFlags::RDWR | OFlags::NOFOLLOW`** (explicitly
         without `OFlags::TRUNC`) -> `LOCK_EX` (`try_lock()`) -> re-verify `fstat` (`S_ISREG`,
         `st_dev == store.root_dev`) and `statat` match same inode -> serialize in PostgreSQL
         (`SELECT openmettle.storage_lock_pinned_volume()` verifying `== store.volume_id` +
         `SELECT 1 FROM openmettle.storage_instance WHERE id FOR NO KEY UPDATE` + re-check
         `storage_reservations WHERE id = <id>` still matches `0` rows / `released+none` /
         `settled`) -> **`rustix::fs::unlinkat(&staging_dir_fd, ".reclaim.<id>",
         AtFlags::empty())` STRICTLY WITHOUT `set_len(0)`** -> `drop` ->
         `rustix::fs::fsync(&staging_dir_fd)`.
    3. **Regular UUID entries `<id>` (not starting with `.reclaim.`):**
       - **`state = 'reserved'` or `adoption_unverified = true`:** skip 100% untouched (owned
         by dedicated cleaners or quarantined).
       - **`state = 'released'`:** if `payload_ino IS NOT NULL` OR `adoption_unverified = true`
         OR `st_size > 0`, **preserve untouched and log an anomaly warning**; ONLY when
         `payload_ino IS NULL AND NOT adoption_unverified AND st_size == 0` (legacy pre-upgrade
         released row), open **`OFlags::RDWR | OFlags::NOFOLLOW`** (explicitly without
         `OFlags::TRUNC`) -> `LOCK_EX` (`try_lock()`) -> re-verify `statat` + `st_size == 0` ->
         `rustix::fs::unlinkat(&staging_dir_fd, id, AtFlags::empty())` (**NEVER `set_len(0)`**)
         -> `drop` -> `rustix::fs::fsync(&staging_dir_fd)`.
       - **`state = 'settled'`:** skip untouched if `adoption_unverified = true` or
         `payload_ino IS NULL` or `staging_ino != payload_ino` (protecting cross-reservation
         hard links such as `staging/A` -> `revisions/B`). When **`staging_ino == payload_ino`**,
         detach `staging/<id>` (**`OFlags::RDWR | OFlags::NOFOLLOW`** explicitly without
         `OFlags::TRUNC` -> `LOCK_EX` (`try_lock()`) -> re-verify `statat(&staging_dir_fd, id)`
         has `st_ino as u64 == payload_ino` -> `rustix::fs::unlinkat(&staging_dir_fd, id,
         AtFlags::empty())` **WITHOUT `set_len(0)`** -> `drop` ->
         `rustix::fs::fsync(&staging_dir_fd)`) **STRICTLY ONLY when
         `artifact_revisions.state IN ('active', 'retained')` AND `revisions/<id>` currently
         exists on disk as `S_ISREG` on `store.root_dev` with `rev_stat.st_ino as u64 ==
         payload_ino`**! **There is NO `artifact_revisions.state = 'purged'` `ENOENT`
         exception**: `purge_due` Stage A already detaches any matching `staging/<id>` alias
         while `revisions/.purge.<id>` pins `payload_ino` alive before `confirm_purge`; once
         `artifact_revisions.state IN ('purging', 'purged')`, `StagingSweepState` never trusts
         historical `payload_ino` to unlink `staging/<id>`, preserving any surviving
         `staging/<id>` untouched!
       - **`0` rows in `storage_reservations` (aged `st_mtime > 900 s`), plus any non-UUID /
         malformed `.reclaim.*` regular file aged `st_mtime > 900 s`:** open **`OFlags::RDWR |
         OFlags::NOFOLLOW`** (explicitly without `OFlags::TRUNC`) -> `LOCK_EX` (`try_lock()`,
         skipping active pre-commit writers holding `LOCK_EX`/`LOCK_SH`) -> re-verify `fstat`
         (`S_ISREG`, `st_dev == store.root_dev`, `st_mtime > 900 s`) and
         `statat(&staging_dir_fd, entry_name)` matches `(fd_dev, fd_ino)` -> serialize in
         PostgreSQL (`SELECT openmettle.storage_lock_pinned_volume()` verifying `==
         store.volume_id` -> `SELECT 1 FROM openmettle.storage_instance WHERE id FOR NO KEY
         UPDATE` -> if UUID, confirm `0` rows in `storage_reservations WHERE id = <id>`) ->
         **`rustix::fs::unlinkat(&staging_dir_fd, entry_name, AtFlags::empty())` STRICTLY
         WITHOUT `set_len(0)`** -> `drop` -> `rustix::fs::fsync(&staging_dir_fd)`.
    In addition, `StagingSweepState` runs the bounded ledger-driven Step 4 sweep across ALL
    reservation kinds using its per-worker wrapping keyset cursor **`reclaim_anchor_cursor:
    Option<(DateTime<Utc>, Uuid)>`** paired with pass-start fixed upper watermark
    **`reclaim_anchor_pass_upper: Option<(DateTime<Utc>, Uuid)>`** (`ORDER BY closed_at DESC,
    id DESC LIMIT 1` captured when `None`, constraining every page with `AND ($1::timestamptz
    IS NULL OR (closed_at, id) > ($1::timestamptz, $2::uuid)) AND (closed_at, id) <=
    ($3::timestamptz, $4::uuid) ORDER BY closed_at ASC, id ASC LIMIT $5` via
    `storage_reservations_reclaim_anchor_idx`, advancing past every inspected row including
    anomalous/foreign-inode and `WouldBlock` rows, and resetting BOTH `reclaim_anchor_cursor =
    None` and `reclaim_anchor_pass_upper = None` when `< LIMIT` rows return OR `(upper_ts,
    upper_id)` is reached) described above.
  - **3-stage inode-preserving `artifact_fs::purge_due` (`revisions/.purge.<reservation_id>` +
    `artifact_revisions.purge_stage`, aligned verbatim with ADR 0040):**
    Unlinking `revisions/<id>` before `storage::confirm_purge` without a purge anchor would
    drop `nlink` to `0` while `state = 'purging'`, opening an inode-reuse window on crash.
    `V1-17` PR2 therefore adds **`purge_stage text NOT NULL DEFAULT 'none'`** on
    `openmettle.artifact_revisions` with `CONSTRAINT artifact_revisions_purge_stage_check CHECK
    (purge_stage IN ('none', 'anchor_pending_unlink') AND (purge_stage = 'none' OR state =
    'purged'))`, partial index `CREATE INDEX artifact_revisions_purge_anchor_idx ON
    openmettle.artifact_revisions (purged_at, id) WHERE state = 'purged' AND purge_stage =
    'anchor_pending_unlink';`, and worker-only grant `GRANT UPDATE (purge_stage) ON
    openmettle.artifact_revisions TO openmettle_worker;` (preserving ADR 0005's worker-only
    purge grant split). `payload_ino` **NEVER hits `nlink = 0` before `storage::confirm_purge`
    commits `state = 'purged'`**:
    1. **`storage::begin_purge`:** Joins `openmettle.storage_reservations sr ON sr.scope_id =
       r.scope_id AND sr.id = r.reservation_id`, requiring **`NOT sr.adoption_unverified AND
       sr.payload_ino IS NOT NULL`** (failing closed without FS I/O otherwise), firing
       `enforce_runtime_storage_volume_pinned()` -> `storage_lock_pinned_volume()`, and
       transitioning `'retained'` (`purge_after <= now()`) -> `'purging'` (`purge_stage =
       'none'`).
    2. **Stage A (Anchor + Truncate + Visible-Name Detach BEFORE `confirm_purge`, keeping
       `revisions/.purge.<id>` linked with `nlink >= 1`):**
       - Verify `SELECT openmettle.storage_lock_pinned_volume()` matches `store.volume_id` and
         all three `:root`, `:revisions`, `:staging` sentinels.
       - Probe `revisions/.purge.<id>` (`SYMLINK_NOFOLLOW`, where `<id>` is `reservation_id`):
         - **If `revisions/.purge.<id>` exists:** require `S_ISREG`, `st_dev ==
           store.root_dev`, and `st_ino as u64 == payload_ino` (otherwise STOP immediately with
           zero `set_len(0)`, zero `unlinkat`, and DO NOT call `confirm_purge`). Open
           `revisions/.purge.<id>` (`OFlags::RDWR | OFlags::NOFOLLOW`) -> `LOCK_EX`
           (`try_lock()`) -> re-verify `fstat` + `statat` -> revalidate in PostgreSQL (`SELECT
           openmettle.storage_lock_pinned_volume(); SELECT 1 FROM openmettle.artifact_revisions
           WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'purging'`) ->
           `set_len(0)?` + `sync_all()?` -> **unconditional `rustix::fs::fsync(&revisions_dir_fd)?`**.
           Keep `LOCK_EX` held through Stage A.
         - **If `revisions/.purge.<id>` is `Errno::NOENT`:** probe `revisions/<id>`
           (`SYMLINK_NOFOLLOW`). If `revisions/<id>` is `Errno::NOENT` (impossible
           post-adoption unless tampered, since `revisions/<id>` is never unlinked before
           `.purge.<id>` is durably `fsync`ed, and legacy absent `'purging'` rows are completed
           at adoption time!), non-regular, wrong `st_dev`, or `st_ino as u64 != payload_ino`:
           **STOP IMMEDIATELY with zero `set_len(0)`, zero `unlinkat` (do NOT touch
           `staging/<id>`!), and DO NOT call `confirm_purge`!** Otherwise open `revisions/<id>`
           (`OFlags::RDWR | OFlags::NOFOLLOW`) -> `LOCK_EX` (`try_lock()`) -> re-verify `fstat`
           + `statat` -> revalidate in PostgreSQL (`storage_lock_pinned_volume()` + `state =
           'purging'`) -> `set_len(0)?` + `sync_all()?` ->
           `rustix::fs::linkat(&revisions_dir_fd, id, &revisions_dir_fd, ".purge.<id>",
           AtFlags::empty())` (if `Errno::EXIST`, verify `.purge.<id>` is `S_ISREG` on
           `store.root_dev` with `st_ino as u64 == payload_ino`) -> **unconditional
           `rustix::fs::fsync(&revisions_dir_fd)?` strictly BEFORE unlinking `revisions/<id>`**!
           Keep `LOCK_EX` held through Stage A.
       - Still holding `LOCK_EX` on `payload_ino` while `revisions/.purge.<id>` holds `nlink >=
         1`:
         - If `revisions/<id>` exists with `S_ISREG`, `st_dev == store.root_dev`, and `st_ino
           as u64 == payload_ino`, call `rustix::fs::unlinkat(&revisions_dir_fd, id,
           AtFlags::empty())?` (if foreign `st_ino != payload_ino`, leave untouched and log
           anomaly).
         - If `staging/<id>` exists with `S_ISREG`, `st_dev == store.root_dev`, and `st_ino as
           u64 == payload_ino` (immune to inode reuse because `.purge.<id>` holds `payload_ino`
           alive!), call `rustix::fs::unlinkat(&staging_dir_fd, id, AtFlags::empty())?` (never
           `set_len(0)` on foreign inodes; if `st_ino != payload_ino`, leave foreign
           `staging/<id>` untouched!).
         - Unconditionally require `Ok(())` from **BOTH `rustix::fs::fsync(&revisions_dir_fd)`
           AND `rustix::fs::fsync(&staging_dir_fd)`**, then drop the `LOCK_EX` FD
           (`revisions/.purge.<id>` stays linked!).
    3. **Stage B (`storage::confirm_purge` while `revisions/.purge.<id>` still pins
       `payload_ino`):** Sets `state = 'purged', purged_at = now(), purge_stage =
       'anchor_pending_unlink'` and decrements `retained_bytes` via `storage::adjust()`.
    4. **Stage C (Post-`confirm_purge` detach of `revisions/.purge.<id>` + bounded wrapping
       keyset-cursor DB pass with pass-start fixed upper watermark):** Immediately after
       `confirm_purge` commits AND in a bounded DB pass in `purge_due` using per-worker
       wrapping keyset cursor **`purge_anchor_cursor: Option<(DateTime<Utc>, Uuid)>`** paired
       with pass-start fixed upper watermark **`purge_anchor_pass_upper:
       Option<(DateTime<Utc>, Uuid)>`** over `artifact_revisions_purge_anchor_idx`. At the
       start of each sweep pass (whenever `purge_anchor_pass_upper` is `None`), capture the
       pass's fixed upper watermark `(upper_ts, upper_id)` via:

       ```sql
       SELECT r.purged_at, r.id
         FROM openmettle.artifact_revisions r
         JOIN openmettle.storage_reservations sr
           ON sr.scope_id = r.scope_id AND sr.id = r.reservation_id
        WHERE r.state = 'purged'
          AND r.purge_stage = 'anchor_pending_unlink'
          AND NOT sr.adoption_unverified
          AND sr.payload_ino IS NOT NULL
        ORDER BY r.purged_at DESC, r.id DESC
        LIMIT 1;
       ```

       (Returning immediately if `None`.) Constrain every page in that pass to `(upper_ts,
       upper_id)`:

       ```sql
       SELECT r.scope_id::text, r.id::text, r.reservation_id::text, sr.payload_ino, r.purged_at
         FROM openmettle.artifact_revisions r
         JOIN openmettle.storage_reservations sr
           ON sr.scope_id = r.scope_id AND sr.id = r.reservation_id
        WHERE r.state = 'purged'
          AND r.purge_stage = 'anchor_pending_unlink'
          AND NOT sr.adoption_unverified
          AND sr.payload_ino IS NOT NULL
          AND ($1::timestamptz IS NULL OR (r.purged_at, r.id) > ($1::timestamptz, $2::uuid))
          AND (r.purged_at, r.id) <= ($3::timestamptz, $4::uuid)
        ORDER BY r.purged_at ASC, r.id ASC
        LIMIT $5;
       ```

       Advance `purge_anchor_cursor = Some((row.purged_at, row.id))` past **every** inspected
       row (including anomalous foreign-inode rows left in `'anchor_pending_unlink'` for
       operator inspection and `WouldBlock` rows, preventing `LIMIT` anomalous anchors from
       starving later already-unlinked `ENOENT` rows!), and reset **BOTH
       `purge_anchor_cursor = None` AND `purge_anchor_pass_upper = None`** as soon as a page
       returns `< LIMIT` rows **OR** reaches `(upper_ts, upper_id)` — guaranteeing bounded wrap
       back to earlier `WouldBlock` rows even under sustained arrivals of `>= LIMIT` newly
       purged rows per tick! For each row, detach `revisions/.purge.<id>` opening
       **`OFlags::RDWR | OFlags::NOFOLLOW` (explicitly WITHOUT `OFlags::TRUNC` and NEVER
       calling `set_len(0)` — required on Linux NFS because `flock(LOCK_EX)` maps to
       `fcntl(F_SETLK, F_WRLCK)` which fails with `EBADF` on `O_RDONLY`)** -> `LOCK_EX`
       (`try_lock()`) -> verifying `st_ino as u64 == payload_ino` and `st_size == 0` ->
       `rustix::fs::unlinkat(&revisions_dir_fd, &purge_name, AtFlags::empty())` -> `drop` ->
       `rustix::fs::fsync(&revisions_dir_fd)` -> `UPDATE openmettle.artifact_revisions SET
       purge_stage = 'none' WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'purged'
       AND purge_stage = 'anchor_pending_unlink'` (or `fsync(&revisions_dir_fd)` + `SET
       purge_stage = 'none'` on `Errno::NOENT`).

- **Filesystem & `ReadWriteMany` shared-volume qualification (`linkat`, `flock(2)`, and
  cross-client stable 64-bit `st_ino`).** Startup, adoption, and shared-volume qualification
  require `O_CREAT | O_EXCL | O_NOFOLLOW`, mandatory POSIX/NFS **`rustix::fs::linkat`**
  (rejecting `ENOSYS`/`EOPNOTSUPP`/`EINVAL`/`EXDEV`/`EMLINK` fail-closed and proving a second
  `linkat` onto an existing destination returns `Errno::EXIST` without overwrite), and file +
  directory `fsync` (`sync_all`). For `ReadWriteMany` shared volumes across multiple
  pods/nodes, deployments MUST additionally qualify **both** two-client / separate-mount Linux
  NFS `flock(2)` (`LOCK_SH` vs `LOCK_EX | LOCK_NB` `WouldBlock`) exclusion — explicitly
  exercising `OFlags::RDWR | OFlags::NOFOLLOW` (without `OFlags::TRUNC`, zero `set_len(0)`)
  across two Linux NFS clients for `'truncated'` reopen-and-`LOCK_EX`, Step 4 `.reclaim.<id>`,
  `purge_due` Stage C `.purge.<id>`, and `StagingSweepState` alongside `OFlags::RDONLY |
  OFlags::NOFOLLOW | OFlags::NONBLOCK` `LOCK_SH` in `Store::read` (proving zero `EBADF` under
  Linux NFS `F_WRLCK`/`F_RDLCK` emulation) — **and** stable 64-bit `st_ino` coherence +
  second-client recovery verification across clients and remounts before enabling shared
  artifact/spill storage.

### Head/tail preview envelope and unavailable-spill policy

Spill publication (`publish_bytes`, `storage: "spilled"`, `status: "ok"`) is restricted
**exclusively to `succeeded` tool outputs**. **Every `failed` tool result**
(`ToolFault::Semantic`, known-outcome `ToolFault::Transient`, or pre-/post-intent
`ToolFault::TerminalRefusal`) MUST use the **bounded inline error envelope
(`status: "tool_error"`, closed `fault_code`, `<= 2 KiB` UTF-8 summary, `retryable_by_model`,
never spilled to an artifact and never carrying `status: "ok"`)**.

A spilled `succeeded` result returns a closed JSON envelope whose **final UTF-8 serialized JSON
string** is capped at `16 KiB` (`16_384` bytes):

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
`EffectPolicy` resolution, ADR 0035 bound/deciding-session and exact committed-evidence
equality (`approvals::recheck_replay_effect_authority(..., policy)`), scope, `Action::Read`
and `active` revision rechecks.

**Startup writability & `linkat` qualification probe, opportunistic spill fallback and deferral
of `spill_required`.** Today, `artifact_fs::Store::open` (`src/artifact_fs.rs`, called via
`src/lib.rs`) validates only that `root` is an absolute, non-symlink, readable directory,
creates `staging/` and `revisions/` (mode `0700`) if absent, confirms both are real readable
directories and `fsync`s `root`; it does **not** test file creation or non-replacing hard-link
publication inside pre-existing `staging/` and `revisions/` directories, so a read-only mount
or a filesystem lacking POSIX/NFS `linkat` (`LINK`) can pass `Store::open` and fail on the
first spill. PR2 therefore adds an explicit startup qualification probe
(`artifact_fs::Store::probe_writable`), run during worker initialization whenever
`OPENMETTLE_WORKER_ARTIFACTS_DIR` is configured: strictly relative to `Store`'s verified
`staging_dir_fd` and `revisions_dir_fd`, exclusively create uniquely named non-UUID probe files
(`rustix::fs::openat(&staging_dir_fd, probe_name, OFlags::RDWR | OFlags::CREATE | OFlags::EXCL
| OFlags::NOFOLLOW, Mode::RUSR | Mode::WUSR)`), `sync_all()` them, publish via
**`rustix::fs::linkat(&staging_dir_fd, probe_name, &revisions_dir_fd, probe_name,
AtFlags::empty())`** (rejecting `ENOSYS`/`EOPNOTSUPP`/`EINVAL`/`EXDEV`/`EMLINK` fail-closed
**and** explicitly verifying that a second `linkat` onto the existing destination returns
`Errno::EXIST` without overwriting it!), `fsync(&revisions_dir_fd)`, unlink the probe files via
`rustix::fs::unlinkat(..., AtFlags::empty())`, and `fsync(&revisions_dir_fd)` +
`fsync(&staging_dir_fd)` (cleaning up on error), failing closed at boot if the mount or either
directory is unwritable or lacks atomic `linkat`. Leaving `OPENMETTLE_WORKER_ARTIFACTS_DIR`
unset (`None`) still boots the worker in non-spill mode. All V1-14 spills are **post-response
opportunistic spills**; strict `spill_required` pre-reserved write tools are explicitly
deferred out of V1-14 because `Review::validate` (`src/authz/approvals.rs`) requires an
existing authorized `Review.artifact` whenever `Review.reservation` is set, whereas a newly
spilled tool output has neither an `operation_id` nor a known byte length before intent commit
and dispatch.

If `OPENMETTLE_WORKER_ARTIFACTS_DIR` is unset (`None`), storage limits are unconfigured,
owner/instance storage quota is exhausted, the process-wide `spill_permits` semaphore is
saturated (`TryAcquireError::NoPermits`) or runtime filesystem publication fails on a
`succeeded` result, the worker **always** records the tool's true observation in `operations`
first (so a committed external write is never hidden, falsely marked failed or re-dispatched),
includes the redacted `spill_error` (`store_unconfigured`, `quota_exceeded`, `spill_saturated`
or `storage_io`) in observation evidence and returns a bounded fallback envelope (`<= 16_384`
serialized JSON bytes) with `status: "ok"`, `storage: "truncated_no_spill"`, `truncated: true`,
`artifact_id: null`, `revision_id: null`, the same UTF-8-safe `head`/`tail` preview,
`omitted_bytes` and `content_sha256`. Truncation is always explicit; partial output is never
labeled complete.

## Delivery and verification

| Slice | Deliverable | Acceptance evidence |
| --- | --- | --- |
| PR1 | This ADR (`0039`). | Review against #14, #25, ADRs 0010, 0031, 0033, 0035 and 0038; `ai-guardrails docs audit` reports zero findings. |
| PR2 | PR2's next sequential schema migration (e.g., `0024`) adding nullable `openmettle.operations.dispatched_attempts integer DEFAULT NULL CHECK (dispatched_attempts BETWEEN 0 AND 3)` and nullable immutable `openmettle.operations.effective_expires_us bigint DEFAULT NULL` (zero change to `Binding` or `request_identity` canonical bytes; populated by `INSERT_INTENT` from `$20 = effective_until`) with a `BEFORE UPDATE` monotonicity/immutability trigger forbidding `dispatched_attempts` `non-null -> NULL` or decrements and forbidding any post-insert mutation of `effective_expires_us` (Transaction 1 in PR2 `approvals::record_fenced_intent` commits `outcome = 'intent'` with `dispatched_attempts = 0` and `effective_expires_us = effective_until` strictly on `IntentResult::Applied(committed)` for `repeatable_read`, leaving writes `dispatched_attempts DEFAULT NULL` until PR3's `runtime_feature_gates.two_phase_effect_intents_enabled = true` and writing zero `operations` rows on `IntentResult::ApprovalRequired`, distinct from Step 5 Transaction 2's pre-send increment), their matching `src/boundaries.sql` grants (`INSERT`/`UPDATE (dispatched_attempts)`, `INSERT (effective_expires_us)` with zero `UPDATE` grant and zero `openmettle_api` `INSERT`/`UPDATE` grant on `openmettle.operations`, `$1 >= <v1_14_schema_version>`), sequencing after `V1-17` PR2 / ADR 0040 PR2 for the unified shared storage schema (dedicated 1-row read-mostly singleton **`openmettle.storage_volume_control (id boolean PRIMARY KEY DEFAULT true CHECK (id), volume_id uuid, bootstrap_auto_pin_allowed boolean NOT NULL DEFAULT false, adoption_run_id uuid, CONSTRAINT storage_volume_control_auto_pin_check CHECK (volume_id IS NULL OR NOT bootstrap_auto_pin_allowed))`** with **`GRANT SELECT ON openmettle.storage_volume_control TO openmettle_api, openmettle_worker;` ONLY** — zero `INSERT`/`UPDATE`/`DELETE`/`TRUNCATE` grants to `openmettle_api` or `openmettle_worker` — paired with two narrow `openmettle_owner`-owned `SECURITY DEFINER` (`SET search_path = pg_catalog`, `REVOKE ALL ... FROM PUBLIC`) functions: **`openmettle.storage_lock_pinned_volume() RETURNS uuid`** (`GRANT EXECUTE ... TO openmettle_api, openmettle_worker`, executing `SELECT volume_id, adoption_run_id INTO v_vol, v_adopt FROM openmettle.storage_volume_control WHERE id FOR SHARE` without requiring PostgreSQL 18 invoker `UPDATE` privilege and raising `OMQ03` if `NOT FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL`, returning `v_vol`) and **`openmettle.storage_pin_volume_id(p_volume_id uuid) RETURNS uuid`** (`GRANT EXECUTE ... TO openmettle_api` strictly API-only — only `openmettle_api` (`Store::open` in API) initializes fresh `.openmettle-volume-id` sentinels and calls `storage_pin_volume_id(uuid)` on empty fresh bootstrap without raw invoker `FOR UPDATE`/`UPDATE`, whereas `openmettle_worker` never initializes sentinels and never calls `storage_pin_volume_id(uuid)`, cleanly observing `OMQ03`/unpinned state via `storage_lock_pinned_volume()` without `42501` and skipping/failing closed until `volume_id` is pinned), keeping only `warn_pct_1`, `warn_pct_2`, `config_revision` alongside `storage_instance`'s byte counters so runtime `reserve`/`settle`/`release`/`purge` ONLY ever invoke `SELECT openmettle.storage_lock_pinned_volume()` under canonical lock order **`runs -> storage_reservations -> artifacts -> artifact_revisions -> storage_volume_control -> storage_accounts -> storage_instance`**, eliminating both `FOR SHARE -> FOR NO KEY UPDATE` self-upgrade deadlocks on `storage_instance` and PostgreSQL 18 `42501` `FOR SHARE` permission errors; tightened `storage_reservations_adoption_unverified_check` **`CHECK (NOT adoption_unverified OR state = 'reserved')`** so non-owner release of a quarantined reservation is impossible in PostgreSQL; `openmettle.storage_reservations` columns `stage_claimed boolean NOT NULL DEFAULT false`, write-once `payload_ino numeric(20, 0)` with **no `payload_dev`**, `publish_pending boolean NOT NULL DEFAULT false`, unified **4-state** cleaner lease `reclaim_state text NOT NULL DEFAULT 'none' CHECK (reclaim_state IN ('none', 'claiming', 'truncated', 'anchor_pending_unlink'))` / `reclaim_claim_token uuid` / `reclaim_lease_until timestamptz` with their `CHECK` constraints (`(state = 'reserved' AND reclaim_state IN ('none', 'claiming', 'truncated')) OR (state = 'released' AND reclaim_state IN ('none', 'anchor_pending_unlink')) OR (state = 'settled' AND reclaim_state = 'none')`, lease token/timestamp `CHECK`, `reclaim_state NOT IN ('truncated', 'anchor_pending_unlink') OR NOT publish_pending`), partial index `storage_reservations_reclaim_anchor_idx ON openmettle.storage_reservations (closed_at, id) WHERE state = 'released' AND reclaim_state = 'anchor_pending_unlink'`, `openmettle.artifact_revisions.purge_stage text NOT NULL DEFAULT 'none'` with `CONSTRAINT artifact_revisions_purge_stage_check CHECK (purge_stage IN ('none', 'anchor_pending_unlink') AND (purge_stage = 'none' OR state = 'purged'))`, partial index `artifact_revisions_purge_anchor_idx ON openmettle.artifact_revisions (purged_at, id) WHERE state = 'purged' AND purge_stage = 'anchor_pending_unlink'`, and worker-only grant `GRANT UPDATE (purge_stage) ON openmettle.artifact_revisions TO openmettle_worker;`, runtime grants `INSERT (lease_expires_at, stage_claimed)` & `UPDATE (lease_expires_at, adoption_unverified, stage_claimed, payload_ino, publish_pending, reclaim_state, reclaim_claim_token, reclaim_lease_until)` to `openmettle_api, openmettle_worker`, and `SECURITY INVOKER` `SET search_path = pg_catalog` triggers **`openmettle.enforce_runtime_storage_volume_pinned()`** (`IF NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE') THEN PERFORM openmettle.storage_lock_pinned_volume(); END IF;`) and `openmettle.enforce_storage_reservation_monotonic_guards()` raising `OMQ03`), the `AFTER UPDATE OF state ON openmettle.runs FOR EACH ROW` `SECURITY DEFINER` trigger `openmettle.resolve_abandoned_repeatable_reads()` (owned by `openmettle_owner`, `SET search_path = pg_catalog`, `REVOKE ALL FROM PUBLIC`, audited in `src/boundaries.sql`, preserving `openmettle_api`'s zero `UPDATE` grant on `openmettle.operations`, resolving abandoned revision-zero `capability = 'repeatable_read'` `outcome = 'intent'` rows to `outcome = 'failed'`, `revision = 1` with idempotent `abandoned-read:<operation_id>` ADR 0004 `identity`/`digest` observation `run_events` strictly before `run-waiting` / `run-terminal` uniformly across mixed-version `N-1` and `N` worker/API binaries without duplicate Rust-caller SQL updates) and one-time upgrade repair (as `openmettle_owner`) of pre-existing `state IN ('queued', 'waiting')` runs, `leases::FailReason::ApprovalExpired` (`openmettle.run-approval-expired`), `CommittedIntent` storing separate `effect_deadline: Instant` and `lease_margin_deadline: Instant` with `CommittedIntent::start(self, &step)` returning explicit `StartPermit::{Stopped(Stop), AuthorityExpired { operation_id, request }, LeaseMarginExhausted, Ready { request, deadline }}` (so `worker::execute` at `src/worker.rs:533-548` and Step 5 handle `StartPermit::AuthorityExpired` via `approvals::expire_unstarted_intent` / `approvals::invalidate_post_intent` under `Fence::Step` with clock-skew recomputation when `db_time(c) < effective_expires_bound_us`, and `StartPermit::LeaseMarginExhausted` yields `StepResult::Handoff` -> `WorkEnd::Handoff` so `leases::handoff` hands off while `> settings.lease` execution budget remains or settles `DeadlineExceeded` immediately when `<= settings.lease` remains without ever forcing false `Reconciling`/`Interrupted` on a `dispatched_attempts = 0` write), caller-independent ledger-aware `approvals::invalidate_post_intent` (partitioned strictly by `(capability, outcome, dispatched_attempts)` regardless of caller so Branch 1 covers `capability == 'repeatable_read'` at ALL `dispatched_attempts` `NULL`/`0`/`1`/`2`/`3` including in-process read retries plus zero-attempt writes `dispatched_attempts == Some(0)` and already-completed rows while Branch 2 covers post-dispatch writes, computing `effective_expires_bound_us` as `min` over `o.effective_expires_us`, `envelope["authorization"]["expires_us"]`, `EndpointKey::Supported.expires_us`, and a direct un-filtered SQL expiry query of bound non-revoked `local_sessions`/`local_identity_approvals`/`login_providers`/`users` and unrevoked bound `membership_observations` so natural shorter-lived deciding-session/originating-session/OIDC expiry never misclassifies as `CancelReason::Revoked`, keeping `invalidate_running`'s raw `fail(c, ..., EXPIRED)` strictly pre-intent), **`StepResult::Handoff`** mapped in `worker::execute` (`src/worker.rs:554-559`) to `Ok(WorkEnd::Handoff)` (leaving `StepResult::Stopped => return Ok(WorkEnd::Complete(Settle::Stopped))` strictly for graceful worker `shutdown` / explicit stop / `outcome_unknown`), `StepResult::Invalidated(leases::Settled)` mapped in `worker::execute` (`src/worker.rs`) directly to `WorkEnd::Invalidated(settled)` (so `Settled::Reconciling { .. }` immediately runs `leases::release_lease(&mut c, &lease)` at `src/worker.rs:660-663` while `Settled::Terminal { .. }` exits at `src/worker.rs:652`), and distinct `StepResult::LeaseLost` mapped to `WorkEnd::Stop(Stop::LeaseLost)` strictly for deposed-worker own lease loss (`Stop::LeaseLost`, `LeaseError::StaleClaim \| Expired \| Terminal`), reviewed tool registry (`EffectPolicy`) enforcing OpenMettle's restricted stateless MCP `2026-07-28` interoperability profile (omitting `Mcp-Param-*` and failing closed on `x-mcp-header` schemas, with all pre-intent refusals writing zero `openmettle.operations` rows and returning bounded inline `status: "tool_error"`), strict schema/argument validator and default expander, `approvals::recheck_replay_effect_authority(..., policy: &impl EffectPolicy)` (under `Fence::Step` on primary: parsing the committed `openmettle.effect` v1 envelope from `operations.request` — reconstructing committed `Proposal` `p` and requiring exact match with the caller's requested `Proposal` and stored `operations` columns, verifying `openmettle.run_approvals JOIN openmettle.run_approval_decisions` with `Some(d.deciding_session_id)` when `basis == "human"`, resolving `live_review = reviewed(policy, &s, &p)?` with exact `live_review == committed_review`, executing `snap = authorized(c, &proof, &live_review)`, checking `snap.now < expires_us.min(validity(&snap, &live_review))` plus `automatic(&r, &snap)` and `YOLO` when `basis == "yolo"`, rebuilding `live_evidence == committed_evidence && live_hash == committed_binding_digest` before replaying any `succeeded` source/spilled artifact-backed result or `artifact.read_range` bytes — alongside `hydrate_worker_principal`, `revision.scope_id == run.scope_id`, `Action::Read` and `revision.state == "active"` — or replaying any `failed` bounded inline `status: "tool_error"` result, both on `IntentResult::Replayed(op_id)` and during committed-observation / unacknowledged-commit recovery), `approvals::start_replayed_read(..., policy: &impl EffectPolicy)` **evaluating live `EffectPolicy` (`live_review = reviewed(policy, &s, &p)?` + `live_review == committed_review`) + `authorized(c, &proof, &live_review)` / `effective_expires_us` + exact `live_evidence == committed_evidence && live_hash == committed_binding_digest` authority validity FIRST before checking `coalesce(dispatched_attempts, 3) >= 3`** (so expired or revoked authority — including when `dispatched_attempts IS NULL` or `dispatched_attempts == 3` — routes immediately through `approvals::invalidate_post_intent` Branch 1 (`outcome = 'failed'` + immediate terminal run settlement `openmettle.run-approval-expired` or `openmettle.run-revoked`, skipping any ordinary failed observation and model continuation), and **only when live authority is still valid** does `coalesce(dispatched_attempts, 3) >= 3` record an ordinary exhausted `outcome = 'failed'` observation under `Fence::Step` and continue the turn) AND guarding the `UPDATE openmettle.operations SET dispatched_attempts = o.dispatched_attempts + 1` statement **itself** with the live `{AUTH}` CTE (`WHERE ... AND o.dispatched_attempts IS NOT NULL AND o.dispatched_attempts < 3 AND snap.now_us < $effective_expires_bound_us AND snap.base = $expected_base AND snap.tool = $expected_tool AND (NOT $auto OR (snap.eligible AND snap.yolo = $expected_yolo))`, settling via ledger-aware `approvals::invalidate_post_intent` — never `invalidate_running` — on `0` rows updated with zero increment and zero sends), updating `approvals::authorized(c, p, review)` (`src/authz/approvals.rs:597-627`) so `EffectClass::Read` sets `RunRecheckRequest.extra_target = None` and `p.artifact == Some(artifact_id)` enforces in-scope `Action::Read`, internal `artifact.read_range` v1 tool (`Review.artifact = Some(artifact_id)`, `EffectClass::Read`, `Review.reservation = None`), `artifact_fs::Store::probe_writable` (operating strictly relative to `Store`'s verified `staging_dir_fd` and `revisions_dir_fd` via `rustix::fs::openat` / **`rustix::fs::linkat(&staging_dir_fd, src, &revisions_dir_fd, dst, AtFlags::empty())`** — rejecting `ENOSYS`/`EOPNOTSUPP`/`EINVAL` fail-closed and proving an existing destination returns `Errno::EXIST` without overwrite — / `unlinkat` / `fsync`), unified HTTP `Store::stage` / `Store::publish` / `Store::read` companion rules (HTTP `Store::stage` and `Store::publish` (`openmettle_api`) succeeding during mixed-version rolling upgrade while `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL` via plain `SELECT` without `FOR SHARE` and skipping sentinel reads while `volume_id IS NULL`, calling `SELECT openmettle.storage_lock_pinned_volume()` and verifying role-tagged sentinels once `volume_id IS NOT NULL`, whereas worker `publish_bytes` and all 4 cleaners strictly require `SELECT openmettle.storage_lock_pinned_volume()` matching `store.volume_id`, and fresh empty-ledger `Store::open` invokes `SELECT openmettle.storage_pin_volume_id($1)`; `Store::stage` Step 1a committing `stage_claimed = true` under `FOR UPDATE` (`state = 'reserved' AND NOT adoption_unverified AND NOT stage_claimed AND payload_ino IS NULL AND reclaim_state = 'none'`) BEFORE `openat`, Step 1b opening `staging/<id>` (`OFlags::CREATE \| OFlags::EXCL \| OFlags::RDWR \| OFlags::NOFOLLOW`, `0` bytes) + `LOCK_SH` + local same-mount `st_dev` check + `fsync(&staging_dir_fd)`, Step 1c committing write-once `payload_ino = staged_ino` under `FOR UPDATE` (`reclaim_state = 'none'`), **`StagedFile::drop` 100% non-destructive (`close` only — NEVER `set_len(0)` and NEVER `unlinkat`)**, `Store::publish` setting `publish_pending = true` under `FOR UPDATE` after payload write + `sync_all()` (`state = 'reserved' AND NOT adoption_unverified AND payload_ino = $staged_ino AND reclaim_state = 'none'`), publishing via **`rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id, AtFlags::empty())`** — keeping `staging/<id>` linked throughout the entire pre-settlement `state = 'reserved'` window so same-key `N-1` API retries hit `OpenOptions::create_new(true)` -> `Err(Error::InProgress)` (`src/artifact_fs.rs:474-475`) without calling `abort()` or replacing `fs::rename` — + `fsync(&revisions_dir_fd)` + post-`linkat` re-verification, committing `storage::settle` (`state = 'settled', publish_pending = false`, retaining `payload_ino`), then running post-commit best-effort detach of `staging/<id>` under `LOCK_SH` (`unlinkat` ONLY, NEVER `set_len(0)`, after verifying both `staging/<id>` and `revisions/<id>` match `staged_ino`), ambiguous `storage::settle` commit NEVER calling `abort`, `abort` running only on confirmed pre-settlement failure via the unified 4-step `LOCK_EX` protocol, and `Store::read` (`src/artifact_fs.rs:190-208, 300-355`) opening `revisions/<reservation>` via `openat(&revisions_dir_fd, reservation, OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK, Mode::empty())` (`O_RDONLY` is valid for `LOCK_SH`/`F_RDLCK` on both local POSIX and Linux NFS, and `O_NONBLOCK` prevents indefinite blocking in `openat` on a writerless FIFO), immediately checking `file.metadata()?.file_type().is_file()` (returning `Err(Error::Missing)` without blocking on FIFOs/sockets/devices/directories), acquiring non-blocking `file.try_lock_shared()` (`LOCK_SH \| LOCK_NB`; `WouldBlock` -> `Err(Error::Missing)` before response headers), strictly AFTER `LOCK_SH` re-verifying `sr.adoption_unverified = false`, `file.metadata()?` (`is_file()`, `st_dev == store.root_dev`, `file_meta.ino() == sr.payload_ino` whenever `sr.payload_ino IS NOT NULL` while allowing `sr.payload_ino IS NULL` only while `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL`, and `len() == size`), and `statat(&revisions_dir_fd, reservation, AtFlags::SYMLINK_NOFOLLOW)` matching `(fd_dev, fd_ino)`, seeking to `start`, and retaining that locked `fs::File` inside `Content` for the entire response body stream lifetime so concurrent `purge_due` Stage A `try_lock()` sees `WouldBlock` and defers truncation/purge), `artifact_fs::publish_bytes` (restricted exclusively to `succeeded` tool outputs while every `failed` tool result uses bounded inline `status: "tool_error"`, never spilled; implemented strictly with safe Rust + `V1-17` PR2's `rustix` verified directory-descriptor foundation under `unsafe_code = "forbid"`, gated by `spill_permits` `Arc<tokio::sync::Semaphore>`, **writers NEVER calling `unlinkat` (except post-commit detach of `staging/<id>` after `storage::settle` commits `state = 'settled'`) and NEVER calling `set_len(0)` anywhere including on error/cancellation/lost-commit-ack or `Drop`**, aligned verbatim with ADR 0040's pre-publication `publish_pending` fence: **Phase 1a** acquires `OwnedSemaphorePermit`, locks `runs (FOR NO KEY UPDATE) -> SELECT openmettle.storage_lock_pinned_volume()` (verifying returned `volume_id == store.volume_id`, else clean inline `truncated_no_spill`) `-> storage_accounts (FOR UPDATE) -> storage_instance (FOR UPDATE)` inside `storage::reserve` under `Fence::Step` inserting `stage_claimed = true, payload_ino = NULL, publish_pending = false, reclaim_state = 'none'` BEFORE touching disk; **Phase 1b (Step 1 — bind write-once `payload_ino` under `LOCK_EX`, keeping `publish_pending = false`)** moves `OwnedSemaphorePermit` directly into Phase 1b's `spawn_blocking` closure returning `(payload_file, staged_ino, spill_permit)`, re-verifies `<root>`, `"staging"`, `"revisions"` + role-tagged sentinels, opens `staging/<reservation_id>` (`OFlags::CREATE \| OFlags::EXCL \| OFlags::RDWR \| OFlags::NOFOLLOW`, `0` bytes) + acquires **`LOCK_EX`** (`try_lock()`, held continuously with zero lock-mode conversion across Steps 1–5 through Step 5's commit!) + verifies `S_ISREG`, local same-mount `st_dev == store.root_dev`, `staged_ino = file_meta.ino()` + **`fsync(&staging_dir_fd)`**, then under `Fence::Step` executes `SELECT openmettle.storage_lock_pinned_volume(); UPDATE openmettle.storage_reservations SET stage_claimed = true, payload_ino = COALESCE(payload_ino, $3) WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved' AND NOT adoption_unverified AND reclaim_state = 'none' AND (payload_ino IS NULL OR payload_ino = $3) RETURNING id;` (**keeping `publish_pending = false` while `0` bytes!**); **Phase 2a (Step 2 — write & `sync_all()` under continuous `LOCK_EX`)** (`spawn_blocking` moving `spill_permit`, raced against `step.deadline`/`step.stop.changed()`) writes chunks, verifies `actual_size == reserved_bytes` & SHA-256, calls `payload_file.sync_all()?`, re-stats `fd` and `statat(&staging_dir_fd, id)` (`st_size == reserved_bytes`, `st_ino == staged_ino`); **Phase 2b (Step 3 — pre-`linkat` SQL fence committing `publish_pending = true` under continuous `LOCK_EX`)** runs short `Fence::Step` tx executing `SELECT openmettle.storage_lock_pinned_volume(); UPDATE openmettle.storage_reservations SET publish_pending = true WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved' AND NOT adoption_unverified AND reclaim_state = 'none' AND payload_ino = $3 RETURNING id;` (if `openmettle storage adopt` started (`OMQ03`) or a cleaner claimed `reclaim_state <> 'none'` (`0` rows), aborts cleanly BEFORE `linkat` without creating `revisions/<id>`!); **Phase 2c (Step 4 — `linkat` publish under continuous `LOCK_EX`)** re-verifies dirs/sentinels/`statat`, runs **`rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id, AtFlags::empty())`** (on `Errno::EXIST` or mismatch committing quarantine `adoption_unverified = true, publish_pending = false` with zero `set_len(0)` / `unlinkat`) + `fsync(&revisions_dir_fd)` + post-`linkat` re-verify — **holding `LOCK_EX` continuously with zero lock-mode conversion (never downgrading to `try_lock_shared()` pre-commit!)**; **Phase 3 (Step 5 — atomic `storage::settle` + `runs::record_observation` + post-commit detach)** still holding `LOCK_EX` runs bounded `<= 2 s` pre-commit `spawn_blocking` verification holding `spill_permit`, commits `storage::settle` (`state = 'settled', publish_pending = false`, retaining write-once `payload_ino`, calling `storage_lock_pinned_volume()`) + `runs::record_observation`, drops `payload_file` (`LOCK_EX`) **only AFTER** Step 5 commits, and only then opens `staging/<id>` post-commit with `OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + immediate `is_file()` + `try_lock_shared()` for best-effort `unlinkat` (`unlinkat` ONLY, NEVER `set_len(0)` -> `drop` -> `fsync(&staging_dir_fd)`), with pure `close()` on lost commit ack/cancellation and deterministic spill-abort disposition), unified **4-step** `reconcile_run_spills` using **`staging/.reclaim.<id>`** so `payload_ino` NEVER drops to `nlink = 0` before Step 3 commits (sole automatic cleanup owner of `state = 'reserved'` `operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%'`, complementing `V1-17`'s `run_id IS NOT NULL AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')` + `storage_reservations_tool_spill_binding_guard` (`23514`); **Step 1** serialized lock-ordered DB claim invoking `SELECT openmettle.storage_lock_pinned_volume()` setting `reclaim_state = CASE WHEN reclaim_state = 'truncated' THEN 'truncated' ELSE 'claiming' END, reclaim_claim_token = $my_token, reclaim_lease_until = clock_timestamp() + interval '60 seconds'` with zero FS I/O inside DB tx; **Step 2** outside DB tx after verifying pinned FDs + sentinels, NEVER clearing `payload_ino`: **Subcase A1 (`payload_ino IS NOT NULL` & `'claiming'`)** probes `staging/.reclaim.<id>` first if present (recovering a predecessor crash after `linkat(".reclaim.<id>")` + `unlinkat("<id>")`), else `staging/<id>` + `revisions/<id>` — quarantining foreign mismatch or all-three-`ENOENT` strictly under `$my_token` guard — and on matching regular file acquires **`LOCK_EX`**, verifies `fstat` + `statat`, executes **mandatory Step 2a fenced SQL claim revalidation & `300 s` lease renewal UNDER continuous `LOCK_EX` strictly BEFORE `set_len(0)` / `linkat` / `unlinkat`** (`SELECT openmettle.storage_lock_pinned_volume(); UPDATE openmettle.storage_reservations SET reclaim_lease_until = clock_timestamp() + interval '300 seconds' WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved' AND NOT adoption_unverified AND payload_ino = $3 AND reclaim_state = 'claiming' AND reclaim_claim_token = $4::uuid RETURNING id;` — aborting with zero FS mutations on `0` rows!), then runs `probe_file.set_len(0)?` + `probe_file.sync_all()?` -> creates/verifies hard-link anchor **`staging/.reclaim.<id>`** + **unconditional `fsync(&staging_dir_fd)` strictly BEFORE unlinking `<id>`** (whether newly created OR pre-existing!) -> unlinks `revisions/<id>` & `staging/<id>` + dual `fsync` -> commits `reclaim_state = 'truncated', publish_pending = false`; **Subcase A2 (`payload_ino IS NOT NULL` & `'truncated'`)** probes ONLY `staging/.reclaim.<id>` opening **`OFlags::RDWR \| OFlags::NOFOLLOW` (explicitly without `OFlags::TRUNC` and zero `set_len(0)` when already `'truncated'` and `st_size == 0` — required on Linux NFS because `flock(LOCK_EX)` maps to `F_WRLCK` which fails `EBADF` on `O_RDONLY`, whereas `OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + immediate `is_file()` remains valid for shared `LOCK_SH` / `F_RDLCK`)** -> `LOCK_EX` -> re-verifies `st_ino == payload_ino` & `st_size == 0` -> **executes guarded `300 s` lease renewal under `LOCK_EX` strictly BEFORE the two directory `fsync`s (`SELECT openmettle.storage_lock_pinned_volume(); UPDATE openmettle.storage_reservations SET reclaim_lease_until = clock_timestamp() + interval '300 seconds' WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved' AND NOT adoption_unverified AND payload_ino = $3 AND reclaim_state = 'truncated' AND reclaim_claim_token = $4::uuid RETURNING id;`, confirming returned `volume_id == store.volume_id` and aborting on `0` rows)** -> unconditional dual `fsync` -> Step 3 (keeping `LOCK_EX` held); **Subcase B (Step 2 Case 2, `payload_ino IS NULL`)** quarantines any `revisions/<id>`, `staging/.reclaim.<id>`, or non-zero/non-regular/foreign-`st_dev` `staging/<id>`, and on `0`-byte regular `staging/<id>` on `store.root_dev` with `revisions/<id>` and `staging/.reclaim.<id>` `ENOENT` opens `OFlags::RDWR \| OFlags::NOFOLLOW` (no `OFlags::TRUNC`, zero `set_len(0)`) -> acquires `LOCK_EX` -> re-verifies `fstat` (`S_ISREG`, `st_dev == store.root_dev`, `st_size == 0`), `statat(&staging_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` `(fd_dev, fd_ino)` match, and BOTH `revisions/<id>` and `staging/.reclaim.<id>` `ENOENT` -> **while holding continuous `LOCK_EX`, executes `rustix::fs::fsync(&staging_dir_fd)?` strictly BEFORE Step 2a's SQL `UPDATE`** (matching the writer path's directory-sync-before-inode-commit barrier so a storage/power crash right after Step 2a commits can never leave a bound reservation with all three names absent) -> **while still holding `LOCK_EX`, executes Step 2a SQL atomically binding `stage_claimed = true, payload_ino = fd_ino` (`SELECT openmettle.storage_lock_pinned_volume(); UPDATE openmettle.storage_reservations SET stage_claimed = true, payload_ino = $3, reclaim_lease_until = clock_timestamp() + interval '300 seconds' WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved' AND NOT adoption_unverified AND payload_ino IS NULL AND reclaim_state = 'claiming' AND reclaim_claim_token = $4::uuid RETURNING id;`, aborting with zero FS mutations on `0` rows / `OMQ03`)** -> on `1` returned row (still holding `LOCK_EX`) promotes directly into the standard `.reclaim.<id>` anchor sequence: `linkat(&staging_dir_fd, id, &staging_dir_fd, ".reclaim.<id>", AtFlags::empty())` -> unconditional `fsync(&staging_dir_fd)?` -> `unlinkat(&staging_dir_fd, id, AtFlags::empty())` -> unconditional `fsync(&staging_dir_fd)?` + `fsync(&revisions_dir_fd)?` -> commits `reclaim_state = 'truncated', publish_pending = false` (`WHERE ... AND payload_ino = $3 AND reclaim_claim_token = $4::uuid`) -> Step 3 (`reclaim_state = 'anchor_pending_unlink'`) -> Step 4 (so `payload_ino` stays `NULL` through Step 3 **ONLY** when `staging/<id>`, `staging/.reclaim.<id>`, and `revisions/<id>` are ALL already `ENOENT`, performing **ZERO `unlinkat` calls**!); **Step 3** final `storage::release` with **ZERO filesystem I/O inside DB tx** setting `reclaim_state = CASE WHEN payload_ino IS NOT NULL THEN 'anchor_pending_unlink' ELSE 'none' END, reclaim_claim_token = NULL, reclaim_lease_until = NULL` (firing `enforce_runtime_storage_volume_pinned()` -> `storage_lock_pinned_volume()`); **Step 4** post-release detach of `staging/.reclaim.<id>` under `LOCK_EX` (`OFlags::RDWR \| OFlags::NOFOLLOW`, explicitly without `OFlags::TRUNC`, `unlinkat` NEVER `set_len(0)` -> `drop` -> `fsync(&staging_dir_fd)` -> `SET reclaim_state = 'none'`) plus a **general bounded ledger-driven Step 4 sweep across ALL reservation kinds** using per-worker wrapping keyset cursor `reclaim_anchor_cursor: Option<(DateTime<Utc>, Uuid)>` paired with pass-start fixed upper watermark `reclaim_anchor_pass_upper: Option<(DateTime<Utc>, Uuid)>` (`ORDER BY closed_at DESC, id DESC LIMIT 1` captured when `None`, constraining every page with `AND ($1::timestamptz IS NULL OR (closed_at, id) > ($1::timestamptz, $2::uuid)) AND (closed_at, id) <= ($3::timestamptz, $4::uuid) ORDER BY closed_at ASC, id ASC LIMIT $5` via `storage_reservations_reclaim_anchor_idx`, advancing past every inspected row including anomalous foreign-inode and `WouldBlock` rows, and resetting BOTH `reclaim_anchor_cursor = None` and `reclaim_anchor_pass_upper = None` when `< LIMIT` rows return OR `(upper_ts, upper_id)` is reached so sustained `>= LIMIT` arrivals per tick cannot starve earlier rows)), shared zero-truncation **`StagingSweepState`** (**ZERO `set_len(0)` calls in ANY branch**, using **`OFlags::RDWR \| OFlags::NOFOLLOW` explicitly without `OFlags::TRUNC`** for every `LOCK_EX` open for Linux NFS compatibility, explicit 3-way `ReadDir` classification: `.openmettle-volume-id` skip; `.reclaim.<id>` skipping `'reserved'`/`adoption_unverified`, Step 4 `LOCK_EX` detach for `'released' + 'anchor_pending_unlink'`, and aged `> 900 s` `LOCK_EX` unlink without `set_len(0)` after `storage_lock_pinned_volume()` + `storage_instance FOR NO KEY UPDATE` re-check for `0`-row/`'released'+'none'`/`'settled'`; regular UUID `<id>` skipping `'reserved'`/`adoption_unverified`, `'released'` preserving `payload_ino IS NOT NULL OR st_size > 0` and unlinking only legacy `payload_ino IS NULL AND st_size == 0`, `'settled'` detaching `staging_ino == payload_ino` without `set_len(0)` **STRICTLY ONLY when `artifact_revisions.state IN ('active', 'retained')` AND `revisions/<id>` exists on disk matching `payload_ino`** — completely removing the `artifact_revisions.state = 'purged'` `ENOENT` exception! — and aged `> 900 s` `0`-row UUIDs / non-UUID / malformed `.reclaim.*` unlinking under `LOCK_EX` without `set_len(0)` after `storage_lock_pinned_volume()` + `storage_instance FOR NO KEY UPDATE` re-check), 3-stage inode-preserving **`artifact_fs::purge_due`** (`revisions/.purge.<reservation_id>` + `artifact_revisions.purge_stage`: `begin_purge` requiring `NOT sr.adoption_unverified AND sr.payload_ino IS NOT NULL`; **Stage A** anchoring `payload_ino` at `revisions/.purge.<id>` with `LOCK_EX` + `set_len(0)` + `sync_all()` + unconditional `fsync(&revisions_dir_fd)` strictly BEFORE unlinking `revisions/<id>` and matching `staging/<id>` alias while `.purge.<id>` holds `nlink >= 1` + dual `fsync`; **Stage B** `confirm_purge` setting `state = 'purged', purge_stage = 'anchor_pending_unlink'`; **Stage C** post-commit + bounded DB pass using per-worker wrapping keyset cursor `purge_anchor_cursor: Option<(DateTime<Utc>, Uuid)>` paired with pass-start fixed upper watermark `purge_anchor_pass_upper: Option<(DateTime<Utc>, Uuid)>` (both watermark and page queries joining `openmettle.storage_reservations sr ON sr.scope_id = r.scope_id AND sr.id = r.reservation_id` with `AND NOT sr.adoption_unverified AND sr.payload_ino IS NOT NULL`, `ORDER BY r.purged_at DESC, r.id DESC LIMIT 1` captured when `None`, constraining every page with `AND ($1::timestamptz IS NULL OR (r.purged_at, r.id) > ($1::timestamptz, $2::uuid)) AND (r.purged_at, r.id) <= ($3::timestamptz, $4::uuid) ORDER BY r.purged_at ASC, r.id ASC LIMIT $5` via `artifact_revisions_purge_anchor_idx`, advancing past every inspected row and resetting BOTH `purge_anchor_cursor = None` and `purge_anchor_pass_upper = None` when `< LIMIT` rows return OR `(upper_ts, upper_id)` is reached so sustained `>= LIMIT` arrivals per tick cannot starve earlier rows) detaching `.purge.<id>` under `LOCK_EX` (`OFlags::RDWR \| OFlags::NOFOLLOW`, explicitly without `OFlags::TRUNC`, NEVER `set_len(0)`) + `fsync(&revisions_dir_fd)` + `SET purge_stage = 'none'`), `openmettle storage adopt` alignment (Phase 3A cross-reservation inode uniqueness `R1 <> R2 => ino(R1) <> ino(R2)` comparing **ONLY live payloads, surviving on-disk anchors, and all candidates for `payload_ino` backfill or `adoption_unverified = false` clearance** — `artifact_revisions` with `state IN ('active', 'retained')`, surviving `state = 'purging'`, or `(state = 'purged' AND purge_stage = 'anchor_pending_unlink')` **STRICTLY ONLY when `revisions/.purge.<id>` is verified still present on disk**, AND `storage_reservations` with `(state = 'reserved' AND (payload_ino IS NOT NULL OR candidate_for_backfill_or_unquarantine))` or `(state = 'released' AND reclaim_state = 'anchor_pending_unlink')` **STRICTLY ONLY when `staging/.reclaim.<id>` is verified still present on disk**, **explicitly EXCLUDING retired historical rows AND already-detached (`ENOENT`) pending anchors** — `(state = 'released' AND reclaim_state = 'none')`, `'settled'` rows whose revision is `(artifact_revisions.state = 'purged' AND purge_stage = 'none')`, `(state = 'released' AND reclaim_state = 'anchor_pending_unlink')` with `staging/.reclaim.<id>` `ENOENT`, and `(artifact_revisions.state = 'purged' AND purge_stage = 'anchor_pending_unlink')` with `revisions/.purge.<id>` `ENOENT`, while Phase 3C clears those `ENOENT` pending anchors to `'none'`; maintaining **`held_candidate_locks: HashMap<(u64, u64), Uuid>`** (`(st_dev, st_ino) -> reservation_id`) across Step 2's scan and acquiring non-blocking `OFlags::RDWR \| OFlags::NOFOLLOW` (no `OFlags::TRUNC`) `LOCK_EX` across **ALL `'reserved'` rows' matching regular files on disk** — covering BOTH `payload_ino IS NULL` backfill candidates AND already-bound `payload_ino IS NOT NULL` `'reserved'` rows including `reclaim_state IN ('none', 'claiming', 'truncated')` and previously quarantined `adoption_unverified = true` clearance candidates whenever `sr.payload_ino IS NULL \|\| fd_ino == sr.payload_ino` (classifying foreign `sr.payload_ino IS NOT NULL && fd_ino != sr.payload_ino` directly as mismatch/quarantine without calling `try_lock()`), inspecting `held_candidate_locks.get(&(fd_dev, fd_ino))` **strictly BEFORE calling `try_lock()`** (recording deterministic hard failure **`cross_reservation_inode_alias`** -> Phase 3B with zero backfills when owned by `other_res_id != reservation_id`, never self-locking into `WouldBlock`, and verifying `statat` + reusing held `LOCK_EX` when owned by `same_res_id`), calling `try_lock()` only when absent (`WouldBlock` from an active cleaner/writer — BOTH before and after Step 2a commit — clearing `adoption_run_id = NULL` in Step 3 without quarantining or backfilling and returning retryable `OMQ03` busy), re-probing `staging/.reclaim.<id>` (and `revisions/<id>`) once more before classifying a `'reserved'` row as missing whenever all three initially return `ENOENT` or post-`LOCK_EX` `statat` on `staging/<id>`/`revisions/<id>` returns `ENOENT`, and retaining all acquired `LOCK_EX` descriptors continuously through Phase 3C commit; **Phase 3B** verification-failure branch performing **zero `payload_ino` backfills and zero Case 6b purge completions**; **Phase 3C** success-only commit branch never writing `payload_ino` onto rows that remain quarantined, **keeping `reclaim_state = 'claiming'` as `'claiming'` — never promoting `'claiming'` to `'truncated'` —** with `reclaim_lease_until = clock_timestamp()` and backfilling `payload_ino` if `NULL` so the resumed cleaner runs full Step 2 including visible-name unlinks, clearing already-detached (`ENOENT`) `'anchor_pending_unlink'` rows to `'none'`, while for rows already in `reclaim_state = 'truncated'` Phase 3A requires `staging/.reclaim.<id>` (`st_size == 0`) AND requires `staging/<id>` and `revisions/<id>` to be `ENOENT` and Phase 3C keeps `'truncated'` with `reclaim_lease_until = clock_timestamp()`; requiring surviving legacy `'purging'` rows (`sr.payload_ino IS NULL` with `revisions/<id>` present on disk) to match **exact recorded `st_size == size_bytes` AND `sha256 == content_digest`** — rejecting `st_size == 0` when `size_bytes > 0` and reserving the `st_size == 0` Stage A crash exception strictly for already-bound revisions `sr.payload_ino IS NOT NULL AND st_ino == sr.payload_ino` — while atomically completing verified-absent legacy `'purging'` rows as `openmettle_owner` in **Phase 3C** without counting absent rows as positive on-disk file evidence for volume identity), `ReadWriteMany` qualification (`O_CREAT \| O_EXCL \| O_NOFOLLOW`, `linkat` (`Errno::EXIST`), file + directory `fsync`, two-client/separate-mount Linux NFS `flock(2)` exclusion exercising `OFlags::RDWR \| OFlags::NOFOLLOW` `LOCK_EX` across `'truncated'` reopen-and-`LOCK_EX`, Step 4 `.reclaim.<id>`, `purge_due` Stage C `.purge.<id>`, and `StagingSweepState` alongside `OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` `LOCK_SH` in `Store::read`, AND stable 64-bit `st_ino` coherence + second-client recovery across clients and remounts), and serialized-budget head/tail preview builder. | PostgreSQL 18 tests: cross-user, cross-scope, archived/deleted project, private project-scope spill ownership (other members denied until shared), share revocation and `active` -> `retained` transition between original read and replay, bound/originating session logout after `artifact.read_range` (or spilled tool output) commits its observation while artifact `Action::Read` access and `revision.state == "active"` remain valid, capability revoke + re-grant (changing grant revision/`cycle_id` in `authority_evidence`), live `EffectPolicy` withdrawal/change ONLY (`Ok(None)` / `Err(DENIED)` or changed `destination_policy` / `tool_policy` / `endpoint_version`), AND direct source-artifact share revoke + re-grant (`Review.artifact = Some(artifact_id)` while read-only `Action::Read` share holder without `Action::Write` succeeds on initial read and valid replay), failing closed via `approvals::invalidate_post_intent` (`IntentResult::Invalidated(settled)` / `StepResult::Invalidated(settled)` -> `WorkEnd::Invalidated(settled)`) with zero cached bytes and zero sends; pre-intent `max_bytes < 4`, `x-mcp-header`, duplicate-key, float, depth, bound and wildcard rejections verifying zero `openmettle.operations` rows written and bounded inline `status: "tool_error"`; invalid UTF-8 binary semantic fault and strictly inline `artifact.read_range` under 6x JSON escaping and `<= 200`-line `next_offset` pagination; verifying `failed` tool results never spill and always replay bounded inline `status: "tool_error"`; **`PENDING_EFFECT` three-valued logic & `StepResult::Handoff` unit/schema tests**: exercising `PENDING_EFFECT`'s `(o.outcome = 'intent' AND o.dispatched_attempts = 0) IS NOT TRUE` across `dispatched_attempts = NULL`, `0`, and `1` (proving `0` is discovered while `NULL` and `1` are excluded), and verifying `StepResult::Handoff` -> `worker::execute` -> `WorkEnd::Handoff` -> `leases::handoff`; **`approvals::start_replayed_read` live-authority-before-exhaustion & `{AUTH}`-guarded `UPDATE` tests**: (1) evaluating live `EffectPolicy` + `{AUTH}` / `effective_expires_us` authority FIRST before `coalesce(dispatched_attempts, 3) >= 3` across **both `dispatched_attempts = NULL` (legacy `N-1` upgrade fixture) AND `dispatched_attempts = 3`** under **both expired authority AND revoked authority** — asserting immediate `approvals::invalidate_post_intent` Branch 1 (`outcome = 'failed'` + immediate terminal run settlement `openmettle.run-approval-expired` or `openmettle.run-revoked`, zero ordinary failed observation and zero model continuation, zero outbound sends), (2) confirming that **only when live authority is still valid** do `dispatched_attempts == 3` and legacy `dispatched_attempts IS NULL` record an ordinary exhausted `outcome = 'failed'` observation under `Fence::Step` and continue the turn with zero sends, and (3) interleaving concurrent session logout or grant/capability revocation *between* `authorized()` snapshot acquisition and the `{AUTH}`-guarded `UPDATE`, verifying `0` rows updated, zero increment, `approvals::invalidate_post_intent` -> `IntentResult::Invalidated(settled)` / `StepResult::Invalidated(settled)` -> `WorkEnd::Invalidated(settled)`, and zero sends; serialized-JSON `16 KiB` inline/spill thresholds; startup `Store::probe_writable` fail-closed test on pre-existing read-only `staging/` and `revisions/` AND proving `rustix::fs::linkat` returns `Errno::EXIST` without overwriting an existing destination (rejecting `ENOSYS`/`EOPNOTSUPP`/`EINVAL` fail-closed); unset-`ARTIFACTS_DIR`, unconfigured-store, quota-refused, `spill_saturated` and I/O fallback envelopes; **`V1-17` PR2 `storage_volume_control` PostgreSQL 18 role-privilege, deadlock-freedom, `OMQ03`, monotonic & quarantined-release tests**: (1) **explicit role-scoped tests executed under BOTH `SET ROLE openmettle_worker` AND `SET ROLE openmettle_api`** covering: (a) healthy pinned volume (`SELECT openmettle.storage_lock_pinned_volume()` + `storage::release` / `begin_purge` trigger execution succeed with ZERO `42501` errors!), (b) missing-singleton-row (`OMQ03`), (c) unpinned `volume_id IS NULL` (`OMQ03`), (d) active-adoption `adoption_run_id IS NOT NULL` (`OMQ03`), (e) direct `UPDATE openmettle.storage_volume_control` denial (`42501` for BOTH `openmettle_worker` AND `openmettle_api`!), and (f) empty-ledger `SELECT openmettle.storage_pin_volume_id($1)` bootstrap tested under BOTH `SET ROLE openmettle_api` (succeeds, initializing sentinels and pinning `volume_id`) AND `SET ROLE openmettle_worker` (direct `storage_pin_volume_id` invocation fails with `42501`, while worker runtime never initializes sentinels or invokes `storage_pin_volume_id` and cleanly awaits pin via `storage_lock_pinned_volume()` observing `OMQ03` without `42501`), (2) **concurrent two-release + two-spill-reserve deadlock-freedom test** executing two concurrent `storage::release` calls alongside two concurrent `publish_bytes` Phase 1a `storage::reserve` calls asserting zero PostgreSQL `40P01` deadlocks and exact counter conservation, and (3) verifying `enforce_storage_reservation_monotonic_guards()` raises `OMQ03` for runtime roles attempting to clear `adoption_unverified` (`true -> false`), mutate/clear `payload_ino`, or clear `stage_claimed` (`true -> false`), AND verifying tightened `storage_reservations_adoption_unverified_check` (`CHECK (NOT adoption_unverified OR state = 'reserved')`) makes non-owner release of a quarantined reservation impossible in PostgreSQL (`23514` if `adoption_unverified = true` is kept, `OMQ03` if cleared, while `openmettle_owner` succeeds updating `state = 'released', adoption_unverified = false` together); **mixed-version rolling-upgrade HTTP vs worker rollout & `N` post-`linkat` crash + `N-1` HTTP retry interleaving tests**: verifying HTTP `Store::stage`, `Store::publish`, and `Store::read` (including legacy `payload_ino IS NULL` rows) succeed while `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL` (skipping sentinel reads while `volume_id IS NULL` and enforcing `storage_lock_pinned_volume()` + role-tagged sentinels + `file_meta.ino() == sr.payload_ino` once `volume_id IS NOT NULL`), while worker `publish_bytes` and all 4 cleaners fail closed whenever `volume_id IS NULL OR adoption_run_id IS NOT NULL`; AND **`N` post-`linkat` crash + `N-1` same-key HTTP retry interleaving test** simulating an `N` writer crashing after `rustix::fs::linkat` creates `revisions/<id>` while `staging/<id>` stays linked and `state = 'reserved'`, then routing a same-key retry to an `N-1` API replica (`src/artifact_fs.rs:474-475` `OpenOptions::create_new(true)`), proving the `N-1` replica returns `Err(Error::InProgress)` immediately without calling `abort()`, without creating a new staging file, and without overwriting `revisions/<id>` via replacing `fs::rename`; existing `storage::settle` `ReservationState::Settled` idempotent HTTP upload replay (`tests/schema/artifact_fs.rs:434`) preserved alongside `AND NOT adoption_unverified AND payload_ino = $staged_ino AND reclaim_state = 'none'` on `ReservationState::Reserved` (atomically clearing `publish_pending = false` while retaining write-once `payload_ino` on `state = 'settled'`); Phase 3 rollback/crash simulation verifying atomic `storage::settle` + `runs::record_observation` inside one `Fence::Step` transaction while holding `LOCK_EX` continuously with zero lock-mode conversion, dropping `payload_file` (`LOCK_EX`) only AFTER Step 5 commits and reopening `staging/<id>` post-commit with `OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + immediate `is_file()` + `try_lock_shared()` for best-effort detach without `set_len(0)`, and lost Phase-3 commit ack dropping `payload_file` via pure `close()` (zero `set_len(0)` / zero `unlinkat`, preserving the settled artifact); `publish_bytes`, `Store::stage`/`Store::publish`, `reconcile_run_spills`, `StagingSweepState`, and `artifact_fs::purge_due` concurrency, `linkat`, 4-step reclamation, Step 2a fenced revalidation, 3-stage `purge_due`, stale-cleaner, stalled-Phase-1b permit-saturation, `SIGKILL`, and takeover tests covering (a) delaying Phase 2 `spawn_blocking` disk I/O past both `5 s` `idle_in_transaction_session_timeout` and drain deadline during lease takeover (replacement worker settles intact with disjoint `reservation_id`, stalled worker exits `StepResult::LeaseLost` with zero corrupted/unlinked revisions), (b) **both race orders between stalled Phase-3 commit and Step-1 `reclaim_state = 'claiming'` claim**, AND **Phase 2b pre-`linkat` `publish_pending = true` fence interleaving** (starting `openmettle storage adopt` (`OMQ03`) or claiming `reclaim_state <> 'none'` (`0` rows) during Phase 2a's write aborts strictly BEFORE `linkat` with zero `revisions/<id>` created!), (c) **Phase 1a DB reserve BEFORE disk (`stage_claimed = true, payload_ino = NULL`) -> Phase 1b `OwnedSemaphorePermit`-bound `spawn_blocking` (`openat` + `LOCK_EX` + `fsync(&staging_dir_fd)`) + bind write-once `payload_ino` keeping `publish_pending = false` -> Phase 2a write + `sync_all()` -> Phase 2b `publish_pending = true` fence -> Phase 2c `linkat` with 100% non-destructive writers & `StagedFile::drop` AND stalled-Phase-1b permit-saturation test**: proving pre-Phase-1a cutoff, deterministic Phase-1a rollback (`OMQ01` / `Fence::Step`), and Phase-1a lost commit ack create zero files on disk and execute zero `unlinkat`; proving stalling Phase 1b inside `openat`/`fsync(&staging_dir_fd)` past cutoff/timeout keeps `OwnedSemaphorePermit` held until the blocking task finishes so concurrent blocking tasks never exceed `max_concurrent_runs` (`spill_saturated` fallback); proving Phase-1b error/lost-commit-ack and `StagedFile::drop` execute pure `close()` (zero `set_len(0)` and zero `unlinkat`, even if `staging/<id>` was replaced by another file), deferring all cleanup exclusively to the unified 4-step cleaner (`Subcase B` for `payload_ino IS NULL`, `Subcase A1` for `payload_ino IS NOT NULL`), (d) **`linkat` pre-existing `revisions/<id>` `Errno::EXIST` non-overwrite quarantine test** for both `publish_bytes` and `Store::publish` (placing a pre-existing file at `revisions/<id>`, verifying `rustix::fs::linkat` fails with `Errno::EXIST` without overwriting `revisions/<id>`, commits `adoption_unverified = true, publish_pending = false`, and performs zero `set_len(0)` / zero `unlinkat`), (e) **unified 4-step reclamation protocol (`reconcile_run_spills` Subcases A1, A2, B + Step 2a `LOCK_EX` revalidation + unconditional pre-unlink anchor `fsync` + Step 4 `LOCK_EX` + bounded DB-driven Step 4 sweep across ALL reservations), `staging/.reclaim.<id>` inode-reuse prevention, adoption preservation of `'truncated'`/`'claiming'`/`'purging'` states + cross-reservation uniqueness, stale-cleaner `$my_token` race, cutoff during post-`linkat` `fsync`, and subprocess `SIGKILL` tests**: stalling cancelled Phase-2 writer mid-chunk, during `sync_all()`, and during post-`linkat` `fsync` past `spill_reservation_ttl` (`LOCK_EX` returns `WouldBlock` keeping `max_bytes` charged until writer exits / `SIGKILL`), verifying Subcase A1 probes `.reclaim.<id>` first if present (covering crash after `linkat(".reclaim.<id>")` + `unlinkat("<id>")` before `'truncated'` commit), acquires `LOCK_EX`, runs **Step 2a fenced SQL claim revalidation & `300 s` lease renewal UNDER `LOCK_EX` strictly BEFORE `set_len(0)`** (proving an expired Cleaner 1 whose token was superseded by Cleaner 2 sees `0` rows and aborts with zero `set_len(0)`/`linkat`/`unlinkat` even if `payload_ino` was reused!), runs `set_len(0)` + `sync_all()`, ensures hard-link anchor **`staging/.reclaim.<id>`** + **unconditional `fsync(&staging_dir_fd)` BEFORE unlinking `<id>`** (whether newly created OR pre-existing!), unlinks `revisions/<id>` & `staging/<id>` + dual `fsync`, commits `reclaim_state = 'truncated', publish_pending = false`, runs Step 3 `storage::release` with ZERO FS I/O inside DB tx setting `reclaim_state = 'anchor_pending_unlink'`, and runs Step 4 `LOCK_EX` (`OFlags::RDWR \| OFlags::NOFOLLOW`, no `OFlags::TRUNC`, zero `set_len(0)`) detach + bounded ledger-driven Step 4 sweep (`storage_reservations_reclaim_anchor_idx`, including a **wrapping keyset cursor starvation-prevention & sustained-arrival wrap test placing `LIMIT` anomalous foreign-inode anchors ahead of an already-unlinked (`ENOENT`) pending row AND sustaining `>= LIMIT` newly arriving pending rows per tick while an earlier `WouldBlock` row becomes unlocked, proving `reclaim_anchor_cursor` + pass-start fixed upper watermark `reclaim_anchor_pass_upper` advance past anomalous rows and wrap boundedly to clear both the later `ENOENT` row and the earlier unlocked `WouldBlock` row!**) across both ordinary uploads and MCP spills; **Subcase A2 crash-recovery (verifying guarded `300 s` lease renewal under `LOCK_EX` strictly before dual `fsync`) & foreign `<id>` preservation test**; **adoption tests** verifying (i) Phase 3A cross-reservation inode uniqueness (`R1 <> R2 => ino(R1) <> ino(R2)`) comparing **ONLY live payloads, surviving on-disk anchors, and all candidates for `payload_ino` backfill or `adoption_unverified = false` clearance** — `artifact_revisions` with `state IN ('active', 'retained')`, surviving `'purging'`, or `(state = 'purged' AND purge_stage = 'anchor_pending_unlink')` **STRICTLY ONLY when `revisions/.purge.<id>` is verified still present on disk**, AND `storage_reservations` with `(state = 'reserved' AND (payload_ino IS NOT NULL OR candidate_for_backfill_or_unquarantine))` or `(state = 'released' AND reclaim_state = 'anchor_pending_unlink')` **STRICTLY ONLY when `staging/.reclaim.<id>` is verified still present on disk**, **explicitly EXCLUDING retired historical rows AND already-detached (`ENOENT`) pending anchors** — `(state = 'released' AND reclaim_state = 'none')`, `'settled'` rows whose revision is `(artifact_revisions.state = 'purged' AND purge_stage = 'none')`, `(state = 'released' AND reclaim_state = 'anchor_pending_unlink')` with `staging/.reclaim.<id>` `ENOENT`, and `(artifact_revisions.state = 'purged' AND purge_stage = 'anchor_pending_unlink')` with `revisions/.purge.<id>` `ENOENT` — including a **retired-inode reuse re-adoption test proving re-adoption succeeds when a new active revision reuses the retired `payload_ino` of an already-released (`reclaim_state = 'none'`), already-purged (`purge_stage = 'none'`), OR post-unlink `ENOENT` crash-window pending anchor (`reclaim_state = 'anchor_pending_unlink'` with `staging/.reclaim.<id>` `ENOENT`, AND `purge_stage = 'anchor_pending_unlink'` with `revisions/.purge.<id>` `ENOENT`, with Phase 3C clearing `'anchor_pending_unlink'` -> `'none'`)**, while **Phase 3B** (verification-failure branch) performs zero `payload_ino` backfills and zero Case 6b purge completions and **Phase 3C** (success-only commit branch) never writes `payload_ino` onto rows that remain quarantined, (ii) **Phase 3C keeping `reclaim_state = 'claiming'` as `'claiming'` (never promoting `'claiming'` to `'truncated'`)** with `reclaim_lease_until = clock_timestamp()` so a resumed cleaner runs full Step 2 unlinking surviving `staging/<id>` / `revisions/<id>`, while rows already in `reclaim_state = 'truncated'` require `staging/.reclaim.<id>` (`st_size == 0`) AND `staging/<id>`/`revisions/<id>` `ENOENT` (rejecting adoption if visible names still share that inode), (iii) surviving legacy `'purging'` rows (`sr.payload_ino IS NULL` with `revisions/<id>` present) requiring **exact recorded `st_size == size_bytes` AND `sha256 == content_digest`** (rejecting `st_size == 0` when `size_bytes > 0`, reserving the `st_size == 0` Stage A crash exception strictly for already-bound `sr.payload_ino IS NOT NULL AND st_ino == sr.payload_ino`) plus atomic completion of verified-absent legacy `'purging'` rows as `openmettle_owner` in **Phase 3C** (never counting absent rows as positive on-disk file evidence for volume identity), (iv) **adoption `LOCK_EX` serialization across ALL `'reserved'` rows' matching regular files & stable `.reclaim.<id>` re-probe tests** (`OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC` -> `try_lock()` on BOTH `payload_ino IS NULL` backfill candidates AND already-bound `payload_ino IS NOT NULL` `'reserved'` rows including `reclaim_state IN ('none', 'claiming', 'truncated')` and `adoption_unverified = true` clearance candidates whenever `sr.payload_ino IS NULL \|\| fd_ino == sr.payload_ino`, held through Phase 3C commit): (a) pausing an in-flight cleaner holding `LOCK_EX` **BOTH before Step 2a (`payload_ino IS NULL`) AND immediately after Step 2a commit (`payload_ino IS NOT NULL, reclaim_state = 'claiming'`)**, asserting `WouldBlock` clears `adoption_run_id = NULL` in Step 3 with zero quarantines and zero backfills and returns retryable `OMQ03` busy; AND (b) **interleaving `linkat(.reclaim.<id>) -> unlinkat(staging/<id>)` after adoption's initial `.reclaim.<id>` `ENOENT` probe** (with the cleaner dropping `LOCK_EX` on Step 3 `OMQ03`), proving adoption's re-probe stably observes and locks `.reclaim.<id>` and preserves `'claiming'` without false quarantine, and (v) **adopter self-lock tracking (`held_candidate_locks: HashMap<(u64, u64), Uuid>`) hard-link alias test**: two `payload_ino IS NULL` `'reserved'` candidates hard-linked to the same on-disk inode deterministically fail adoption with **`cross_reservation_inode_alias`** (entering Phase 3B with zero backfills) rather than retryable `OMQ03` `WouldBlock`; **stale-cleaner all-three-`ENOENT` race test**; **Subcase B (Step 2 Case 2, `payload_ino IS NULL`) pause-across-adopt & `.reclaim.<id>` anchor-promotion tests**: verifying `rustix::fs::fsync(&staging_dir_fd)?` executes under continuous `LOCK_EX` strictly **BEFORE** Step 2a's SQL `UPDATE` (after re-verifying `fstat`, `statat`, and `revisions/<id>` + `staging/.reclaim.<id>` `ENOENT`) and covering pausing the cleaner **BOTH before Step 2a AND immediately AFTER the Step 2a commit** (`stage_claimed = true, payload_ino = fd_ino, reclaim_lease_until = clock_timestamp() + interval '300 seconds'` under `LOCK_EX` -> direct promotion into `.reclaim.<id>` `linkat` -> unconditional `fsync(&staging_dir_fd)` -> `unlinkat` -> dual `fsync` -> `'truncated'` -> Step 3 -> Step 4; `payload_ino` staying `NULL` through Step 3 ONLY when `staging/<id>`, `staging/.reclaim.<id>`, and `revisions/<id>` are ALL `ENOENT` with zero `unlinkat` calls), proving zero orphaned/lost inodes, zero refused releases, and zero false quarantines across concurrent `openmettle storage adopt`, plus replacement-leaf quarantine & Step 2 failure-guard tests, (f) **shared zero-truncation `StagingSweepState` (`> 900 s` orphan check, extended two-reservation hard-link fixtures, `'settled'`, `'released'`, and `.reclaim.<id>`)**: verifying (i) **ZERO `set_len(0)` calls in ANY branch of `StagingSweepState`**, (ii) **extended two-reservation hard-link fixtures**: (A) settled `staging/A` hard-linked to active `revisions/B` (`staging_ino != A.payload_ino`) preserved 100% untouched, **(B) missing reservation row `A` (`0` rows in `storage_reservations`, aged `> 900 s`) with `staging/A` hard-linked to active `revisions/B`**, AND **(C) unowned anchor `staging/.reclaim.<untracked_uuid>` (`0` rows, aged `> 900 s`) hard-linked to active `revisions/B`** — proving `StagingSweepState` unlinks the aged `staging/` alias strictly WITHOUT `set_len(0)` and `revisions/B` retains 100% of its committed bytes and SHA-256, (iii) **`'settled'` (`staging_ino == payload_ino`)**: unlinks `staging/<id>` ONLY (no `set_len(0)`) under `LOCK_EX` when `artifact_revisions.state IN ('active', 'retained')` AND `revisions/<id>` exists on disk matching `payload_ino`, and preserves `staging/<id>` untouched whenever `artifact_revisions.state IN ('purging', 'purged')` or `revisions/<id>` is `ENOENT` or mismatched, (iv) **`'released'`**: NEVER touches `staging/<id>` when `payload_ino IS NOT NULL` or `st_size > 0`, unlinking only legacy `payload_ino IS NULL AND st_size == 0` under `LOCK_EX`, (v) **`.reclaim.<id>`**: skipping `'reserved'`, detaching `'released' + 'anchor_pending_unlink'` matching `(root_dev, payload_ino, st_size == 0)` under `LOCK_EX`, and unlinking aged `> 900 s` `0`-row/`'released'+'none'`/`'settled'` anchors under `LOCK_EX` without `set_len(0)` after `storage_lock_pinned_volume()` + `storage_instance FOR NO KEY UPDATE` re-check, (g) **3-stage inode-preserving `artifact_fs::purge_due` (`revisions/.purge.<id>` + `purge_stage`) tests**: (i) settled reservation `A` with both `staging/A` and `revisions/A` sharing `A.payload_ino` running `purge_due` BEFORE `StagingSweepState`, proving Stage A anchors `revisions/.purge.A` (`nlink >= 1`) + `fsync(&revisions_dir_fd)` BEFORE unlinking `revisions/A` and `staging/A` + dual `fsync`, Stage B `confirm_purge` sets `state = 'purged', purge_stage = 'anchor_pending_unlink'`, and Stage C (and its bounded DB pass via `artifact_revisions_purge_anchor_idx` — both watermark and page queries joining `openmettle.storage_reservations sr ON sr.scope_id = r.scope_id AND sr.id = r.reservation_id` with `AND NOT sr.adoption_unverified AND sr.payload_ino IS NOT NULL`, including a **wrapping keyset cursor starvation-prevention & sustained-arrival wrap test placing `LIMIT` anomalous `.purge.<id>` anchors ahead of an already-unlinked (`ENOENT`) pending row AND sustaining `>= LIMIT` newly arriving pending rows per tick while an earlier `WouldBlock` row becomes unlocked, proving `purge_anchor_cursor` + pass-start fixed upper watermark `purge_anchor_pass_upper` advance past anomalous rows and wrap boundedly to clear both the later `ENOENT` row and the earlier unlocked `WouldBlock` row!**) detaches `revisions/.purge.A` under `LOCK_EX` (`OFlags::RDWR \| OFlags::NOFOLLOW`, no `OFlags::TRUNC`, zero `set_len(0)`) + `SET purge_stage = 'none'`, (ii) crash after Stage A before Stage B proving retry resumes via `revisions/.purge.A` with zero inode-reuse window and preserves any foreign file at `revisions/A` or `staging/A` untouched, (iii) missing both `.purge.A` and `revisions/A` stopping immediately without touching `staging/A` or calling `confirm_purge`, (iv) foreign `revisions/A` (`st_ino != payload_ino`) stopping with zero `set_len(0)`, zero `unlinkat`, and zero `confirm_purge`, and (v) **`Store::read` mid-stream `purge_due` contention & writerless FIFO non-blocking rejection tests**: holding `Content` (`src/artifact_fs.rs:300-355`, retaining the `OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` `LOCK_SH` `fs::File`) open across retention + grace expiry, proving concurrent `purge_due` Stage A `try_lock()` (`LOCK_EX \| LOCK_NB`) observes `WouldBlock` and defers truncation/purge until `Content` completes/drops (zero mid-stream `read_exact` failure after advertising `Content-Length`), proving `Store::read` returns `Err(Error::Missing)` before response headers when `purge_due` Stage A already holds `LOCK_EX`, AND proving `Store::read` rejects a writerless FIFO at `revisions/<reservation>` immediately with `Err(Error::Missing)` without blocking in `openat` (`OFlags::NONBLOCK` + immediate `is_file()` before `try_lock_shared()`, plus post-`LOCK_SH` `fstat` + `statat` re-verification), (h) local `step.deadline`/`step.stop` cutoff + `storage_accounts` lock-stall + competing `runs` lock `Stop::LeaseLost` fallback tests + Phase 3 `2 s` sentinel-read stall + `spill_permits` saturation tests, (i) exact complement cleaner partition (`operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%'` vs `run_id IS NOT NULL AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')` + `storage_reservations_tool_spill_binding_guard` `23514`), `adoption_run_id IS NOT NULL` / `volume_id IS NULL` / sentinel / local `st_dev` mismatch fail-closed tests, populated-upgrade and mixed-version `N-1`/`N` `resolve_abandoned_repeatable_reads()` SSE `204 No Content` tests, and (j) **`ReadWriteMany` cross-client Linux NFS qualification tests** proving `O_CREAT \| O_EXCL \| O_NOFOLLOW`, `rustix::fs::linkat` (`Errno::EXIST`), file+dir `fsync`, two-client/separate-mount Linux NFS `flock(2)` (`LOCK_SH`/`LOCK_EX` vs `LOCK_EX \| LOCK_NB` `WouldBlock`) exclusion — **explicitly exercising `OFlags::RDWR \| OFlags::NOFOLLOW` (without `OFlags::TRUNC`, zero `set_len(0)`) across two Linux NFS clients for `'truncated'` reopen-and-`LOCK_EX`, Step 4 `.reclaim.<id>`, `purge_due` Stage C `.purge.<id>`, and `StagingSweepState` alongside `OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` `LOCK_SH` in `Store::read` with zero `EBADF`** — AND **stable 64-bit `st_ino` coherence + second-client recovery across clients/remounts where two clients observe different local anonymous NFS `st_dev` values** (confirming zero false quarantine from cross-node `st_dev` differences!). |
| PR3 | PR3's sequential SQL migration creating the dedicated 1-row worker rollout gate **`openmettle.runtime_feature_gates (id boolean PRIMARY KEY DEFAULT true CHECK (id), two_phase_effect_intents_enabled boolean NOT NULL DEFAULT false)`** (`GRANT SELECT ON openmettle.runtime_feature_gates TO openmettle_api, openmettle_worker`; default `false` on upgrade while any `N-1` `openmettle-worker` claimer or `settle_expired` sweeper is active so PR4 scoped MCP tool execution stays disabled / fails closed and pre-existing ADR 0035 external approval writes keep `dispatched_attempts = NULL`, enabled to `true` by `openmettle-admin` / rollout once all `N-1` workers are drained or by `bootstrap` on a fresh `N` database, guaranteeing **no `N-1` worker can EVER claim or sweep a `dispatched_attempts = 0` row**) and installing/extending the `AFTER UPDATE OF state ON openmettle.runs FOR EACH ROW` `SECURITY DEFINER` trigger `openmettle.resolve_terminal_write_intents()` (owned by `openmettle_owner`, `SET search_path = pg_catalog`, `REVOKE ALL FROM PUBLIC`, audited in `src/boundaries.sql`, preserving `openmettle_api`'s zero `UPDATE` grant on `openmettle.operations`): on `NEW.state = 'succeeded'` raising an invariant error if any write row (`capability IN ('idempotent', 'lookup', 'non_repeatable')`) still has `outcome IN ('intent', 'outcome_unknown')` (including `dispatched_attempts = 0`), and on `NEW.state IN ('failed', 'cancelled', 'interrupted')` transitioning every remaining revision-zero write `intent` unconditionally to `outcome = 'outcome_unknown'`, `revision = 1` with bounded redacted observation evidence and its ADR 0004 `openmettle/observation/1\0` `run_events` row strictly before `run-terminal`; PR3 update to **`leases::unresolved!()` (`src/authz/leases.rs:310-314`)** changing the unresolved write predicate to **`(outcome = 'outcome_unknown' OR (outcome = 'intent' AND coalesce(dispatched_attempts, 1) > 0)) AND capability IN ('idempotent', 'lookup', 'non_repeatable')`** (excluding proven-unsent `dispatched_attempts = 0` write intents while keeping legacy `dispatched_attempts IS NULL` and post-Transaction-2 `dispatched_attempts >= 1` rows in `Reconciling`/`Interrupted`); **explicit narrow amendment to ADR 0035 (`docs/adr/0035-approvals-permitted-yolo-and-effect-ledger.md:260-268`)** permitting a write send permit on an existing `operations` row strictly when **`o.outcome = 'intent' AND o.dispatched_attempts = 0` (`IS NOT NULL AND = 0`)** (while rows with `dispatched_attempts IS NULL`, `dispatched_attempts >= 1`, or `outcome <> 'intent'` still NEVER receive a write send permit); **complete successor discovery & zero-attempt write send-permit authorization**: **(a) consumed human approvals (`src/authz/approvals.rs:1241` `PENDING_EFFECT` / `src/worker.rs:519`)** updating `PENDING_EFFECT` with NULL-safe three-valued logic to `AND NOT EXISTS (SELECT FROM openmettle.operations o WHERE o.run_id = a.run_id AND o.logical_key = a.logical_key AND (o.outcome = 'intent' AND o.dispatched_attempts = 0) IS NOT TRUE)` (so legacy `o.outcome = 'intent' AND o.dispatched_attempts IS NULL` evaluates `UNKNOWN IS NOT TRUE` = `TRUE` and stays excluded, never rediscovering consumed legacy approvals, while keeping `REQUEST.consumed` unchanged so HTTP `decide` still treats the approval as consumed), **(b) automatic writes (`approval_id IS NULL`)** via deterministic turn-round replay in `Executor::step` plus a pre-round check for any open `o.approval_id IS NULL AND o.outcome = 'intent' AND o.dispatched_attempts = 0` row on `(scope_id, run_id)`, and **(c) `approvals::record_fenced_intent` (`src/authz/approvals.rs:1293-1337`)** locking the existing row `FOR UPDATE`, verifying `durable::existing_intent`, and when `old.outcome == "intent" && old.dispatched_attempts == Some(0) && capability != "repeatable_read"`, re-verifying live `EffectPolicy` (`reviewed`) + `{AUTH}` (`authorized` — loading `run_approvals` + `deciding_session_id` by `old.approval_id` even when `REQUEST.consumed == true` for human approvals, or `eligible && yolo` + `hydrate_worker_principal` + `authorize_capability(YOLO)` for automatic writes) + `snap.now < old.effective_expires_us`, routing expired/revoked authority through `approvals::invalidate_post_intent` (`IntentResult::Invalidated(settled)`), and returning **`IntentResult::Applied(CommittedIntent { operation_id: op, request: old_bytes, effect_deadline, lease_margin_deadline })`** when valid so `CommittedIntent::start(&step)` yields `StartPermit::Ready` and Step 5 Transaction 2 commits **`UPDATE openmettle.operations SET dispatched_attempts = 1 WHERE scope_id = $1::uuid AND run_id = $2::uuid AND id = $3::uuid AND outcome = 'intent' AND dispatched_attempts = 0`** (`rows_affected() == 1` required strictly before sending, in both `worker::execute`'s approved-adapter path and the MCP adapter), while all other existing-row cases (`repeatable_read`, `dispatched_attempts IS NULL`, `dispatched_attempts >= 1`, `outcome <> 'intent'`) return `IntentResult::Replayed(op)` (resolving `effective_approval = stored_approval_id.as_deref()`, returning `Err(CONFLICT)` only on conflicting `Some(other_id)`); **unified `StepResult::Handoff` -> `WorkEnd::Handoff` & `leases::handoff` alignment with `reclaim_next`** across `src/authz/leases.rs` and `src/worker.rs`: **(1)** adding **`StepResult::Handoff`** to `pub enum StepResult` and **`WorkEnd::Handoff`** to `WorkEnd` in `src/worker.rs`, updating `worker::execute` (`src/worker.rs:554-559`) to map `StepResult::Handoff => return Ok(WorkEnd::Handoff)` (leaving `StepResult::Stopped => return Ok(WorkEnd::Complete(Settle::Stopped))` strictly for graceful worker `shutdown` / explicit stop / `outcome_unknown`), returning `Ok(WorkEnd::Handoff)` directly in `worker::execute`'s reviewed-approval branch (`src/worker.rs:536-548`) when `intent.start(&step)` returns `StartPermit::LeaseMarginExhausted` or the pre-dispatch remaining-lease margin check (`execution_remaining <= settings.lease` while `shutdown` has NOT fired) triggers, returning `StepResult::Handoff` from `Executor::step` (`src/worker.rs:138-147`) and `ApprovedAdapter::send` (`src/worker.rs:149-156`) when an automatic or reviewed two-phase write hits `StartPermit::LeaseMarginExhausted` / remaining-lease margin cutoff (`execution_remaining <= settings.lease` while `shutdown` has NOT fired), routing `WorkEnd::Handoff` in `run_one` (`src/worker.rs:661-675`) to `leases::handoff(&mut c, &lease, &settings).await` whenever `cause != Some(Stop::LeaseLost)`, and updating **`leases::handoff`** (`src/authz/leases.rs:503-535`, under `Fence::Hold`) to evaluate **`time_to_reclaim = execution_expires_at > clock_timestamp() + $3::bigint * interval '1 millisecond'`** (`settings.lease`, matching `reclaim_next` and `SETTLEMENT_INPUTS`): calling `release_locked` iff `held.cancel.is_none() && !unresolved && time_to_reclaim` (keeping `state = 'running'` and `outcome = 'intent', dispatched_attempts = 0` so a reclaiming successor discovers the unsent write via `PENDING_EFFECT` or `Executor::step`, obtains `IntentResult::Applied(CommittedIntent)`, increments `dispatched_attempts` `0 -> 1` in Transaction 2, executes once, and finishes `succeeded`; if time later elapses to `<= settings.lease` before reclaim, `settle_expired` settles `DeadlineExceeded` with `n = 0` at `execution_expires_at` closing `dispatched_attempts = 0` to `'failed'`), and calling **`settle_locked(..., Settle::Stopped)` right inside the same `Fence::Hold` transaction** whenever `held.cancel.is_some() \|\| unresolved \|\| !time_to_reclaim` (so `<= settings.lease` remaining — e.g., `10 s` left on a `30 s` lease — immediately selects `Resolution::DeadlineExceeded` (`state = 'failed'`, `{"reason":"deadline_exceeded"}`) and atomically closes `outcome = 'intent' AND dispatched_attempts = 0` to `outcome = 'failed', revision = revision + 1`, with zero stranded unreclaimable run and zero `Reconciling`/`Interrupted`), **(2)** preserving `Settle::Succeeded`'s unconditional guard in `leases::settle_locked` against ANY write row with `outcome IN ('intent', 'outcome_unknown')` (including `dispatched_attempts = 0`, returning `Err(StoreError::Conflict("unresolved operation"))`), and **(3)** inside `settle_locked` / `settle_expired` on every terminal settlement (`Cancelled`, `DeadlineExceeded`, `Failed`, `Interrupted`), atomically transitioning any remaining `outcome = 'intent' AND (capability = 'repeatable_read' OR dispatched_attempts = 0)` rows on the run to `outcome = 'failed', revision = revision + 1` with bounded redacted evidence and ADR 0004 `openmettle/observation/1\0` `run_events` strictly before `run-terminal`; PR3 write-class two-transaction durable `dispatched_attempts` split (enabled when `runtime_feature_gates.two_phase_effect_intents_enabled = true`) where `approvals::record_fenced_intent` writes zero `operations` rows on `IntentResult::ApprovalRequired`, **Transaction 1** commits `outcome = 'intent'` with `dispatched_attempts = 0` and immutable `effective_expires_us = effective_until` (`$20`) for write capabilities strictly on `IntentResult::Applied(committed)`, followed by explicit 4-variant `StartPermit` handling on `CommittedIntent::start(&step)` in both `worker::execute` (`src/worker.rs:533-548`) and Step 5, and **Transaction 2** (separate `Fence::Step` transaction before attempt 1 and before each permitted retry) evaluates **live `EffectPolicy` + `{AUTH}` / `effective_expires_us` authority validity FIRST before checking `coalesce(dispatched_attempts, 3) >= 3`** (routing expired/revoked authority — including `dispatched_attempts IS NULL` or `dispatched_attempts == 3` — immediately through ledger-aware `approvals::invalidate_post_intent`) and guards `UPDATE openmettle.operations SET dispatched_attempts = o.dispatched_attempts + 1` with the live `{AUTH}` CTE (`AND o.outcome = 'intent' AND o.dispatched_attempts = 0` on attempt 1) before releasing the DB connection and issuing the outbound HTTP send; Streamable HTTP MCP (`2026-07-28`) adapter over `provider_http::transport` (restricted stateless interoperability profile omitting `Mcp-Param-*`, failing closed on `x-mcp-header` schemas on `tools/list`, encoding `Mcp-Name` per MCP `2026-07-28` `#value-encoding` using locked `base64 = "=0.22.1"`, consuming RFC 9110 §15.2 non-`101` HTTP/1.1 `1xx` interim responses `<= 4` frames while rejecting unrequested `101 Switching Protocols` as `ToolFault::TerminalRefusal`, exhaustive final non-`200` HTTP status mapping with `{408, 429, 502, 503, 504}` -> `ToolFault::Transient` and all other final non-`200` statuses including `500`/`401`/`403`/`201`/`202`/`204`/`3xx` -> `ToolFault::TerminalRefusal` with `0` retries and `outcome_unknown` + `StepResult::Stopped` on every post-send write refusal, `MAX_TOOL_RESPONSE_BODY_BYTES = 4 MiB` via `http_body_util::Limited`, fixed `8 KiB`/`32` header bounds, chunked-trailer rejection), `MCP_DNS_SLOTS`, `McpCredentialProvider` seam, `ApprovedAdapter` stopping `outcome_unknown` writes via `StepResult::Stopped` and reusing PR2's `StepResult::Handoff` / `StepResult::Invalidated(leases::Settled)` / `StepResult::LeaseLost` mappings, destination-authorized read-only `Executor::reconcile` under `Fence::Hold` (`dispatched_attempts: Option<i32>` on `leases::UnresolvedOperation`), and `PLAN-10` / `PLAN-22` conformance harness on synthetic `rcgen` TLS + PostgreSQL 18. | Synthetic TLS + PostgreSQL 18 tests: MCP `2026-07-28` request headers (`MCP-Protocol-Version: 2026-07-28`, `Mcp-Method`, `Mcp-Name` with `#value-encoding` fixtures for plain ASCII `execute_sql`, interior HTAB `"left\tright"` -> `=?base64?bGVmdAlyaWdodA==?=`, non-ASCII UTF-8, leading/trailing `0x20`, and literal `"=?base64?literal?="`, no `Mcp-Session-Id`, no `Mcp-Param-*`) and body `params._meta` over `application/json` and `text/event-stream` (SSE comments/progress notifications, mismatched IDs, duplicate final responses, `input_required`/server-initiated request rejection, `x-mcp-header` schema rejection, `MAX_TOOL_RESPONSE_BODY_BYTES = 4 MiB` limit, `8 KiB`/`32` header bounds, chunked-trailer rejection); **`openmettle.runtime_feature_gates.two_phase_effect_intents_enabled` worker rollout gate tests**: verifying (1) when `two_phase_effect_intents_enabled = false`, scoped MCP tool execution fails closed / stays disabled AND pre-existing ADR 0035 external approval writes keep `dispatched_attempts = NULL` (`N-1`-compatible single-phase behavior, never exposing a `dispatched_attempts = 0` write row to `N-1` workers or `N-1` expiry sweepers), and (2) once enabled to `true` (and on fresh `bootstrap`), two-phase zero-attempt writes are active; two-transaction durable `dispatched_attempts` accounting verifying `IntentResult::ApprovalRequired` writes zero `operations` rows before `approvals::park`, Transaction 1 commits `dispatched_attempts = 0` strictly on `IntentResult::Applied(committed)`, Transaction 2 commits `0 -> 1 -> 2 -> 3` via the `{AUTH}`-guarded `UPDATE` (`AND o.outcome = 'intent' AND o.dispatched_attempts = 0` on attempt 1) under the monotonicity trigger, and concurrent logout/revocation interleaving between `authorized()` and `{AUTH}`-guarded `UPDATE` produces `0` rows updated, zero increment, `StepResult::Invalidated(settled)` -> `WorkEnd::Invalidated(settled)`, and zero sends; **live-authority-before-exhaustion tests for `approvals::start_replayed_read` AND Step 5 Transaction 2** covering **both `dispatched_attempts = NULL` and `dispatched_attempts = 3`** under **both expired and revoked** authority (verifying immediate `approvals::invalidate_post_intent` settlement — `openmettle.run-approval-expired` / `openmettle.run-revoked` for reads, `Reconciling`/`interrupted` for post-dispatch writes — skipping ordinary failed observation and model continuation, with zero sends); **end-to-end durable zero-attempt write discovery, send-permit, `StepResult::Handoff` -> `WorkEnd::Handoff`, `leases::handoff` `time_to_reclaim`, reclaim & terminal settlement tests**: **(a0) `PENDING_EFFECT` three-valued logic unit/schema test (`src/authz/approvals.rs:1241`)** exercising `o.outcome = 'intent'` with **`dispatched_attempts = NULL`, `0`, and `1`** (plus non-`'intent'` outcomes), proving `dispatched_attempts = 0` IS discovered, while `dispatched_attempts = 1`, `dispatched_attempts IS NULL` (legacy pre-upgrade consumed approval), and non-`'intent'` outcomes are ALL excluded (`IS NOT TRUE`); **(a) consumed human approval (`approval_id IS NOT NULL`) zero-attempt successor send & post-Transaction-1 expiry/revocation tests**: Worker 1 commits Transaction 1 (`dispatched_attempts = 0`, `approval_id IS NOT NULL`) and yields on `Stop::Shutdown` AND in a second fixture on `StartPermit::LeaseMarginExhausted` (`worker::execute` `src/worker.rs:536-548` / `ApprovedAdapter::send` -> `StepResult::Handoff` -> `WorkEnd::Handoff` with `> settings.lease` remaining), proving HTTP `decide` still sees `REQUEST.consumed = true` while Worker 2's `approvals::pending_effect` (`PENDING_EFFECT`) discovers `(approval_id, proposal)`, `record_fenced_intent` re-verifies live `EffectPolicy` + `{AUTH}` (`run_approvals` + `deciding_session_id`) + `effective_expires_us` and returns `IntentResult::Applied(CommittedIntent)`, Transaction 2 commits `dispatched_attempts: 0 -> 1`, the write executes once, and the run settles `succeeded`; AND in paired negative fixtures where `deciding_session_id` is revoked or `effective_expires_us` lapses after Transaction 1, Worker 2's `record_fenced_intent` routes immediately through `approvals::invalidate_post_intent` (`IntentResult::Invalidated(settled)` -> `outcome = 'failed'`, `openmettle.run-revoked` / `openmettle.run-approval-expired`, zero sends); **(b) automatic write (`approval_id IS NULL`) end-to-end remaining-lease margin cutoff (`Executor::step -> StepResult::Handoff -> worker::execute -> WorkEnd::Handoff -> leases::handoff`), zero-attempt successor send & post-Transaction-1 expiry/revocation tests**: Worker 1 commits Transaction 1 (`dispatched_attempts = 0`, `approval_id IS NULL`) and hits the remaining-lease margin cutoff while `shutdown` has NOT fired, proving **`Executor::step` returns `StepResult::Handoff` -> `worker::execute` (`src/worker.rs:554-559`) maps to `Ok(WorkEnd::Handoff)` -> `run_one` calls `leases::handoff`** (never settling terminal `'stopped'` via `StepResult::Stopped`!), with `> settings.lease` remaining releasing the lease in `state = 'running'` so Worker 2 discovers the open unsent write via `Executor::step` replay/pre-round check, `record_fenced_intent` re-verifies `eligible && yolo` + `hydrate_worker_principal` + `authorize_capability(YOLO)` + `effective_expires_us` and returns `IntentResult::Applied(CommittedIntent)` (or `IntentResult::Invalidated(settled)` with zero sends if revoked/expired), Transaction 2 commits `0 -> 1`, the write executes once, and the run settles `succeeded` (while proving rows with `dispatched_attempts IS NULL`, `dispatched_attempts >= 1`, or `outcome <> 'intent'` NEVER receive a write send permit and return `IntentResult::Replayed(op)`); **(c) `StepResult::Handoff` -> `WorkEnd::Handoff` + `leases::handoff` `time_to_reclaim` boundary tests (`> settings.lease` vs `<= settings.lease`)**: (i) with `> settings.lease` remaining, `WorkEnd::Handoff` calls `leases::handoff` -> `release_locked` -> `reclaim_next` -> `succeeded` (and if time subsequently elapses to `<= settings.lease` before reclaim, `settle_expired` settles `DeadlineExceeded` at `execution_expires_at` with `n = 0`, closing `dispatched_attempts = 0` to `outcome = 'failed'` with zero `Reconciling`/`Interrupted`), and (ii) with **`<= settings.lease` remaining (e.g., `10 s` left on a `30 s` lease)**, `Executor::step` / `worker::execute` returns `StepResult::Handoff` / `WorkEnd::Handoff` -> `leases::handoff` sees `NOT time_to_reclaim` and calls `settle_locked(..., Settle::Stopped)` right inside the same `Fence::Hold` transaction, immediately settling **`Resolution::DeadlineExceeded`** (`state = 'failed'`, `{"reason":"deadline_exceeded"}`) and atomically closing `dispatched_attempts = 0` to **`outcome = 'failed', revision = revision + 1`** strictly before `run-terminal` (`204 No Content` on terminal SSE cursor, zero stranded unreclaimable run, zero `Reconciling`/`Interrupted`); **(d) `Stop::Cancel` / `ExecState::Cancelling` direct terminal settlement, `Settle::Succeeded` guard & mixed-write regression tests**: proving `Stop::Cancel` on a `dispatched_attempts = 0` write settles directly to `cancelled` + `outcome = 'failed', revision = revision + 1` with zero `Reconciling`/`Interrupted`, `Settle::Succeeded` (`StepResult::Finished`) with one `dispatched_attempts = 0` write in both `ExecState::Running` (`!time`) and `ExecState::Cancelling` returns `Err(StoreError::Conflict("unresolved operation"))` (never settling `Succeeded`), and mixed writes (`1` `dispatched_attempts = 0` + `1` `dispatched_attempts = 1`) yield `n = 1` from `leases::unresolved!()` (`Reconciling(1)` when `time == true`; when `time == false` or `Interrupted`, `dispatched_attempts = 0` -> `outcome = 'failed', revision = revision + 1` and `dispatched_attempts = 1` -> `outcome = 'outcome_unknown', revision = 1` with terminal `Interrupted(1)`); **post-intent effect/endpoint-key/session expiry & revocation settlement tests**: (a) pre-attempt-1 expiry (`StartPermit::AuthorityExpired` -> `approvals::expire_unstarted_intent` / `approvals::invalidate_post_intent` -> `openmettle.run-approval-expired`, zero `reconciling`, zero sends, plus clock-skew recomputation), (b) post-ambiguous-attempt-1 expiry (`dispatched_attempts == 1` -> `Reconciling` / `interrupted`, `outcome_unknown`, zero retry sends), (b2) caller-independent in-process `repeatable_read` retry invalidation (`dispatched_attempts = 1` + transient `503` -> expiry/revocation -> `outcome = 'failed'` + `openmettle.run-approval-expired`/`revoked`, `1` total send), (b3) shorter-lived `deciding_session_id` expiry vs revocation (`effective_expires_us` + live unrevoked-credential SQL recovery classifying natural expiry as expiry, never `cancel_reason = "revoked"`), (c) immediate `Settled::Reconciling` lease-release via `leases::release_lease` at `src/worker.rs:660-663`, and (d) defense-in-depth `openmettle.resolve_terminal_write_intents()` trigger tests (verifying `NEW.state = 'succeeded'` invariant guard and `NEW.state IN ('failed', 'cancelled', 'interrupted')` fallback transitioning any remaining revision-zero write `intent` to `outcome_unknown` strictly before `run-terminal` with `204 No Content`); `WorkEnd::Incomplete` drain-expiry contention matrix across `non_repeatable`, `idempotent`, `lookup`, unacknowledged-commit recovery (with live `EffectPolicy` withdrawal/change, capability revoke+re-grant, and `deciding_session_id` logout), and direct terminal settlement with `<= 1` lease interval remaining; `StepResult::LeaseLost` deposed-worker tests on both reclaimed non-terminal and already-terminal runs; `lookup` reconciliation with/without `downstream_handle` enforcing live destination authorization under `Fence::Hold` before `McpCredentialProvider` lookup (zero credential lookups when revoked) and excluding `repeatable_read`; semantic `isError: true` / `-32602` plus `PLAN-10` recovery and `PLAN-22` measurement harness; HTTP/1.1 `103 Early Hints` + `200 OK`, `> 4` interim overflow, unrequested `101 Switching Protocols`, and exhaustive final non-`200` status refusals (explicitly including first-attempt HTTP `401`/`403`/`500` writes -> `outcome_unknown` + `StepResult::Stopped`, zero retries); SSRF/TLS/`tools/list`-drift/`> 4 MiB` refusals; canary redaction checks; end-to-end `park` -> `decide` -> resume -> `ApprovedAdapter::send` -> spill -> `artifact.read_range` round trip including positive same-key replay (`approval = None` resolving `effective_approval = stored_approval_id.as_deref()`, `Err(CONFLICT)` on mismatched `Some(other_id)`), originating/deciding session logout, `EffectPolicy` withdrawal/change, capability revoke+re-grant, and share-revocation/retention replay refusals. |

### External boundaries

- **V1-28 (#25).** Owns encrypted personal/project connection secrets, key rotation, OAuth
  refresh and revocation. Production external MCP credentials stay gated on V1-28; PR2 and PR3
  qualify external MCP only against pinned synthetic TLS fixtures.
- **V1-17 (#17).** Owns non-storage quota units (provider request and token budgets) and
  [ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md) PR2's unified shared
  storage contract: dedicated 1-row read-mostly control singleton
  **`openmettle.storage_volume_control (id boolean PRIMARY KEY DEFAULT true CHECK (id),
  volume_id uuid, bootstrap_auto_pin_allowed boolean NOT NULL DEFAULT false, adoption_run_id
  uuid, CONSTRAINT storage_volume_control_auto_pin_check CHECK (volume_id IS NULL OR NOT
  bootstrap_auto_pin_allowed))`** (`GRANT SELECT ON openmettle.storage_volume_control TO
  openmettle_api, openmettle_worker;` ONLY — neither `openmettle_api` nor `openmettle_worker`
  holds `INSERT`, `UPDATE`, `DELETE`, or `TRUNCATE` on `openmettle.storage_volume_control`),
  paired with two narrow `openmettle_owner`-owned `SECURITY DEFINER` (`SET search_path =
  pg_catalog`, `REVOKE ALL ... FROM PUBLIC`) functions:
  **`openmettle.storage_lock_pinned_volume() RETURNS uuid`** (`GRANT EXECUTE` to
  `openmettle_api, openmettle_worker`, acquiring `SELECT volume_id, adoption_run_id INTO v_vol,
  v_adopt FROM openmettle.storage_volume_control WHERE id FOR SHARE` without requiring
  PostgreSQL 18 invoker `UPDATE` privilege and raising `OMQ03` if `NOT FOUND OR v_vol IS NULL
  OR v_adopt IS NOT NULL`, returning `v_vol`) and
  **`openmettle.storage_pin_volume_id(p_volume_id uuid) RETURNS uuid`** (`GRANT EXECUTE` strictly
  to `openmettle_api` ONLY — only `openmettle_api` (`Store::open` in API) initializes fresh
  `.openmettle-volume-id` sentinels and calls `storage_pin_volume_id(uuid)` for one-time fresh
  empty-ledger bootstrap internally locking `storage_volume_control WHERE id FOR UPDATE`, raising
  `OMQ03` on missing row / `adoption_run_id IS NOT NULL` / mismatched existing `volume_id`,
  requiring `bootstrap_auto_pin_allowed = true` and empty `storage_reservations` +
  `artifact_revisions`, and setting `volume_id = p_volume_id, bootstrap_auto_pin_allowed = false`,
  while `openmettle_worker` never initializes sentinels and never calls `storage_pin_volume_id(uuid)`
  — observing `OMQ03` / unpinned state cleanly via `storage_lock_pinned_volume()` without `42501`
  and skipping/failing closed until `volume_id` is pinned), moving
  `(volume_id, bootstrap_auto_pin_allowed, adoption_run_id)` off the counter table
  `storage_instance` (which keeps only `warn_pct_1`, `warn_pct_2`, `config_revision` alongside
  its byte counters) so runtime `reserve`/`settle`/`release`/`purge` ONLY ever invoke
  `SELECT openmettle.storage_lock_pinned_volume()` (taking `FOR SHARE` on
  `storage_volume_control` as `openmettle_owner`) under canonical lock order **`runs ->
  storage_reservations -> artifacts -> artifact_revisions -> storage_volume_control ->
  storage_accounts -> storage_instance`** (eliminating `FOR SHARE -> FOR NO KEY UPDATE`
  self-upgrade deadlocks on `storage_instance` and preventing PostgreSQL 18 `42501` errors on
  `FOR SHARE`), pinned volume identity (`openmettle.storage_volume_control.volume_id` +
  three-directory role-tagged `.openmettle-volume-id` sentinels `:root`, `:staging`,
  `:revisions`), nullable `openmettle.storage_volume_control.adoption_run_id uuid DEFAULT NULL`
  adoption barrier (non-null iff an active `openmettle-admin` adoption session owns Steps 1b–3),
  tightened `openmettle.storage_reservations.adoption_unverified` protection
  (`storage_reservations_adoption_unverified_check`: **`CHECK (NOT adoption_unverified OR state
  = 'reserved')`**, making non-owner release of a quarantined reservation impossible in
  PostgreSQL while `openmettle_owner` releases by updating `state = 'released',
  adoption_unverified = false` together), `stage_claimed boolean NOT NULL DEFAULT false`
  (`CHECK (payload_ino IS NULL OR stage_claimed)`), write-once `payload_ino numeric(20, 0)`
  (`CHECK (payload_ino IS NULL OR payload_ino >= 0)`, storing exact unsigned 64-bit `u64`
  `MetadataExt::ino()`, with **no `payload_dev`** so cross-node NFS anonymous `st_dev`
  differences never falsely quarantine valid shared-volume payloads; each host verifies local
  same-mount `file_meta.dev() == dir_fd_meta.dev() == root_fd_meta.dev()` using only its own
  open FDs), `publish_pending boolean NOT NULL DEFAULT false` (`CHECK (NOT publish_pending OR
  (state = 'reserved' AND payload_ino IS NOT NULL))`, committed right BEFORE `linkat` after
  payload bytes are written and `sync_all()`ed, never while `0` bytes), the unified **4-state**
  cleaner lease + **`staging/.reclaim.<id>`** hard-link anchor protocol shared by all 4 cleaners
  (`artifact_fs::abort`, `reconcile_expired`, generic run-linked cleaner, and
  `reconcile_run_spills`) — `reclaim_state text NOT NULL DEFAULT 'none' CHECK (reclaim_state IN
  ('none', 'claiming', 'truncated', 'anchor_pending_unlink'))`, `reclaim_claim_token uuid`, and
  `reclaim_lease_until timestamptz` (`CHECK ((state = 'reserved' AND reclaim_state IN ('none',
  'claiming', 'truncated')) OR (state = 'released' AND reclaim_state IN ('none',
  'anchor_pending_unlink')) OR (state = 'settled' AND reclaim_state = 'none'))`, `CHECK
  ((reclaim_state IN ('claiming', 'truncated') AND reclaim_claim_token IS NOT NULL AND
  reclaim_lease_until IS NOT NULL) OR (reclaim_state IN ('none', 'anchor_pending_unlink') AND
  reclaim_claim_token IS NULL AND reclaim_lease_until IS NULL))`, `CHECK (reclaim_state NOT IN
  ('truncated', 'anchor_pending_unlink') OR NOT publish_pending)`), where **every** `LOCK_EX`
  open (including `'truncated'` crash recovery — which also executes guarded `300 s` lease
  renewal under `LOCK_EX` strictly before its two directory `fsync`s — Step 2 Case 2
  `payload_ino IS NULL` `0`-byte `staging/<id>` — which under continuous `LOCK_EX` re-verifies
  `fstat`, `statat`, and `revisions/<id>` + `staging/.reclaim.<id>` `ENOENT`, executes
  **`rustix::fs::fsync(&staging_dir_fd)?` strictly BEFORE Step 2a's SQL `UPDATE`** atomically
  binding `stage_claimed = true, payload_ino = fd_ino`, and promotes directly into the
  `.reclaim.<id>` anchor sequence so `payload_ino` stays `NULL` through Step 3 ONLY when
  `staging/<id>`, `staging/.reclaim.<id>`, and `revisions/<id>` are ALL `ENOENT` with zero
  `unlinkat` calls — Step 4 `.reclaim.<id>`, Stage C `.purge.<id>`, `StagingSweepState`, and
  `openmettle storage adopt` `LOCK_EX` serialization across ALL `'reserved'` rows' matching
  regular files on disk) uses **`OFlags::RDWR | OFlags::NOFOLLOW` explicitly WITHOUT
  `OFlags::TRUNC` and preserving ZERO `set_len(0)` calls on non-truncating paths** (because
  Linux NFS emulates `flock(LOCK_EX)` via `fcntl(F_SETLK, F_WRLCK)`, which fails with `EBADF`
  on `O_RDONLY`, whereas `OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK` + immediate
  `is_file()` remains valid for shared `LOCK_SH` / `F_RDLCK` in `Store::read` and post-`settle`
  publisher `LOCK_SH` detach), partial index `storage_reservations_reclaim_anchor_idx ON
  openmettle.storage_reservations (closed_at, id) WHERE state = 'released' AND reclaim_state =
  'anchor_pending_unlink'` driving a bounded ledger-driven Step 4 anchor sweep with per-worker
  wrapping keyset cursor `reclaim_anchor_cursor: Option<(DateTime<Utc>, Uuid)>` and pass-start
  fixed upper watermark `reclaim_anchor_pass_upper: Option<(DateTime<Utc>, Uuid)>` across ALL
  reservation kinds, and durable purge-anchor tracking on `openmettle.artifact_revisions`:
  **`purge_stage text NOT NULL DEFAULT 'none'`** with `CONSTRAINT
  artifact_revisions_purge_stage_check CHECK (purge_stage IN ('none', 'anchor_pending_unlink')
  AND (purge_stage = 'none' OR state = 'purged'))`, partial index
  `artifact_revisions_purge_anchor_idx ON openmettle.artifact_revisions (purged_at, id) WHERE
  state = 'purged' AND purge_stage = 'anchor_pending_unlink'` driving Stage C's bounded sweep
  with per-worker wrapping keyset cursor `purge_anchor_cursor: Option<(DateTime<Utc>, Uuid)>`
  and pass-start fixed upper watermark `purge_anchor_pass_upper: Option<(DateTime<Utc>, Uuid)>`,
  and worker-only grant `GRANT UPDATE (purge_stage) ON openmettle.artifact_revisions TO
  openmettle_worker;`, with runtime grants `GRANT INSERT (lease_expires_at, stage_claimed)` and
  `GRANT UPDATE (lease_expires_at,
  adoption_unverified, stage_claimed, payload_ino, publish_pending, reclaim_state,
  reclaim_claim_token, reclaim_lease_until)` to `openmettle_api, openmettle_worker`, backed by
  `V1-17` PR2's two `SECURITY INVOKER` (`SET search_path = pg_catalog`) PostgreSQL triggers:
  `openmettle.enforce_runtime_storage_volume_pinned()` (`BEFORE UPDATE` on
  `storage_reservations` `WHEN (OLD.state = 'reserved' AND NEW.state = 'released')` and
  `artifact_revisions` `WHEN (NEW.state IN ('purging', 'purged'))`, checking `IF NOT
  pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE') THEN PERFORM
  openmettle.storage_lock_pinned_volume(); END IF;`) and
  `openmettle.enforce_storage_reservation_monotonic_guards()` (`BEFORE UPDATE ON
  openmettle.storage_reservations FOR EACH ROW`, raising `OMQ03` for non-`openmettle_owner`
  roles if `OLD.adoption_unverified AND NOT NEW.adoption_unverified`, `OLD.payload_ino IS NOT
  NULL AND NEW.payload_ino IS DISTINCT FROM OLD.payload_ino`, or `OLD.stage_claimed AND NOT
  NEW.stage_claimed`), shared zero-truncation `StagingSweepState` in `worker::maintenance`,
  3-stage inode-preserving `artifact_fs::purge_due` (`revisions/.purge.<reservation_id>` +
  `purge_stage`), `openmettle storage adopt` (Phase 3A cross-reservation inode uniqueness `R1 <>
  R2 => ino(R1) <> ino(R2)` comparing **ONLY live payloads, surviving on-disk anchors, and all
  candidates for `payload_ino` backfill or `adoption_unverified = false` clearance** —
  `artifact_revisions` with `state IN ('active', 'retained')`, surviving `state = 'purging'`,
  or `(state = 'purged' AND purge_stage = 'anchor_pending_unlink')` **STRICTLY ONLY when
  `revisions/.purge.<id>` is verified still present on disk**, AND `storage_reservations` with
  `(state = 'reserved' AND (payload_ino IS NOT NULL OR candidate_for_backfill_or_unquarantine))`
  or `(state = 'released' AND reclaim_state = 'anchor_pending_unlink')` **STRICTLY ONLY when
  `staging/.reclaim.<id>` is verified still present on disk**, **explicitly EXCLUDING retired
  historical rows AND already-detached (`ENOENT`) pending anchors** — `(state = 'released' AND
  reclaim_state = 'none')`, `'settled'` rows whose revision is `(artifact_revisions.state =
  'purged' AND purge_stage = 'none')`, `(state = 'released' AND reclaim_state =
  'anchor_pending_unlink')` with `staging/.reclaim.<id>` `ENOENT`, and `(artifact_revisions.state
  = 'purged' AND purge_stage = 'anchor_pending_unlink')` with `revisions/.purge.<id>` `ENOENT`,
  while Phase 3C clears those `ENOENT` pending anchors to `'none'` and permitting
  intra-reservation `<id>`/`.reclaim.<id>`/`.purge.<id>` aliases; maintaining
  `held_candidate_locks: HashMap<(u64, u64), Uuid>` (`(st_dev, st_ino) -> reservation_id`) across
  Step 2's scan and acquiring non-blocking `OFlags::RDWR | OFlags::NOFOLLOW` (no `OFlags::TRUNC`)
  `LOCK_EX` across **ALL `'reserved'` rows' matching regular files on disk** — covering BOTH
  `payload_ino IS NULL` backfill candidates AND already-bound `payload_ino IS NOT NULL`
  `'reserved'` rows including `reclaim_state IN ('none', 'claiming', 'truncated')` and
  previously quarantined `adoption_unverified = true` clearance candidates whenever
  `sr.payload_ino IS NULL || fd_ino == sr.payload_ino` (classifying foreign `sr.payload_ino IS
  NOT NULL && fd_ino != sr.payload_ino` directly as mismatch/quarantine without calling
  `try_lock()`) — checking `held_candidate_locks.get(&(fd_dev, fd_ino))` **strictly BEFORE
  calling `try_lock()`** (recording deterministic hard failure `cross_reservation_inode_alias` ->
  Phase 3B with zero backfills when owned by `other_res_id != reservation_id`, never self-locking
  into `WouldBlock`, and verifying `statat` + reusing held `LOCK_EX` when owned by `same_res_id`),
  calling `try_lock()` only when absent (`WouldBlock` from an active cleaner/writer — BOTH before
  and after Step 2a commit — clearing `adoption_run_id = NULL` with zero quarantines/backfills
  and returning retryable `OMQ03` busy), re-probing `staging/.reclaim.<id>` (and `revisions/<id>`)
  once more before classifying a `'reserved'` row as missing whenever all three initially return
  `ENOENT` or post-`LOCK_EX` `statat` on `staging/<id>`/`revisions/<id>` returns `ENOENT`, and
  retaining all acquired `LOCK_EX` descriptors continuously through Phase 3C commit; **Phase 3B**
  verification-failure branch performing **zero `payload_ino` backfills and zero Case 6b purge
  completions**; **Phase 3C** success-only commit branch never writing `payload_ino` onto rows
  that remain quarantined, keeping `reclaim_state = 'claiming'` as `'claiming'` — **never
  promoting `'claiming'` to `'truncated'`** — with `reclaim_lease_until = clock_timestamp()` and
  backfilling `payload_ino` if `NULL` so the resumed cleaner runs full Step 2 including
  visible-name unlinks, clearing already-detached (`ENOENT`) `'anchor_pending_unlink'` rows to
  `'none'`, while for rows already in `reclaim_state = 'truncated'` Phase 3A requires
  `staging/.reclaim.<id>` (`st_size == 0`) AND requires `staging/<id>` and `revisions/<id>` to be
  `ENOENT` and Phase 3C keeps `'truncated'` with `reclaim_lease_until = clock_timestamp()`;
  requiring surviving legacy `'purging'` rows (`sr.payload_ino IS NULL` with `revisions/<id>`
  present on disk) to match **exact recorded `st_size == size_bytes` AND `sha256 ==
  content_digest`** — rejecting `st_size == 0` when `size_bytes > 0` and reserving the `st_size
  == 0` Stage A intermediate crash exception strictly for already-bound revisions `sr.payload_ino
  IS NOT NULL AND st_ino == sr.payload_ino` — while atomically completing verified-absent legacy
  `'purging'` rows as `openmettle_owner` in **Phase 3C** without counting absent rows as positive
  on-disk file evidence for volume identity), and `artifact_fs`'s `rustix`-backed (`default-features = false, features = ["fs",
  "std"]`, 100% safe Rust under `unsafe_code = "forbid"`) verified directory-descriptor
  infrastructure (`root_fd`, `staging_dir_fd`, `revisions_dir_fd`) using
  **`rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id, AtFlags::empty())`**
  (keeping `staging/<id>` linked until `storage::settle` commits so `N-1` API retries hit
  `Err(Error::InProgress)` without overwriting `revisions/<id>`) and requiring `ReadWriteMany`
  shared-volume qualification of `O_CREAT | O_EXCL | O_NOFOLLOW`, `linkat` (`Errno::EXIST`), file
  + directory `fsync`, two-client / separate-mount Linux NFS `flock(2)` exclusion (explicitly
  exercising `OFlags::RDWR | OFlags::NOFOLLOW` `LOCK_EX` across `'truncated'` reopen-and-`LOCK_EX`,
  Step 4 `.reclaim.<id>`, `purge_due` Stage C `.purge.<id>`, and `StagingSweepState` alongside
  `OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK` `LOCK_SH` in `Store::read`), and stable
  64-bit `st_ino` coherence + second-client recovery across clients and remounts. **V1-14 PR2
  sequences after V1-17 PR2** to reuse that foundation with zero additional Cargo crates. Under
  that shared contract:
  - **Mixed-version rollout & `Store::read` (`src/artifact_fs.rs:190-208, 300-355`):** HTTP
    `Store::stage` and `Store::publish` (`openmettle_api`) succeed during mixed-version rolling
    upgrade while `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL` (plain
    `SELECT` without `FOR SHARE` and skipping sentinel reads while `volume_id IS NULL`, calling
    `SELECT openmettle.storage_lock_pinned_volume()` and verifying role-tagged sentinels once
    `volume_id IS NOT NULL`; only `openmettle_api` initializes fresh `.openmettle-volume-id`
    sentinels and calls `storage_pin_volume_id(uuid)` on fresh empty bootstrap), whereas
    `openmettle_worker` never initializes sentinels and never calls `storage_pin_volume_id(uuid)`
    — worker `publish_bytes` and all 4 cleaners strictly require `SELECT
    openmettle.storage_lock_pinned_volume()` matching `store.volume_id` (`volume_id IS NOT NULL
    AND adoption_run_id IS NULL`), observing `OMQ03` / unpinned state cleanly without `42501`
    until pinned. `StagedFile::drop` and writers (`publish_bytes` and `Store::stage`) are 100%
    non-destructive (never calling `set_len(0)` and never calling `unlinkat` prior to committed
    `state = 'settled'`, committing `publish_pending = true` strictly after payload bytes are
    written and `sync_all()`ed right before `linkat` with **zero lock-mode conversion** —
    `publish_bytes` holding `LOCK_EX` continuously from Step 1 through Step 4 and Step 5's
    `Fence::Step` `WriteTransaction`, dropping `LOCK_EX` only AFTER Step 5 commits, and only then
    opening `staging/<id>` post-commit with `OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK`
    + `is_file()` + `try_lock_shared()` for best-effort `unlinkat`). `Store::read` opens
    `revisions/<reservation>` via `openat(&revisions_dir_fd, reservation, OFlags::RDONLY |
    OFlags::NOFOLLOW | OFlags::NONBLOCK, Mode::empty())` (`O_RDONLY` is valid for `LOCK_SH` /
    `F_RDLCK` on both local POSIX and Linux NFS, and `OFlags::NONBLOCK` prevents blocking on a
    writerless FIFO), immediately checks `file.metadata()?.file_type().is_file()` (failing closed
    with `Err(Error::Missing)` without blocking on FIFOs/sockets/devices/directories), acquires
    non-blocking `file.try_lock_shared()` (`LOCK_SH | LOCK_NB`; returning `Err(Error::Missing)`
    before response headers on `WouldBlock`), strictly AFTER `LOCK_SH` re-verifies
    `sr.adoption_unverified = false`, `file.metadata()?` (`is_file()`, `st_dev == store.root_dev`,
    `st_ino == sr.payload_ino` when non-null — allowing `sr.payload_ino IS NULL` only while
    `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL` — and `len() == size`),
    and `statat(&revisions_dir_fd, reservation, AtFlags::SYMLINK_NOFOLLOW)` matching `(fd_dev,
    fd_ino)`, seeks to `start`, and retains that locked `fs::File` inside `Content`
    (`src/artifact_fs.rs:300-355`) for the entire response body stream lifetime so concurrent
    `purge_due` Stage A `try_lock()` (`LOCK_EX | LOCK_NB`) sees `WouldBlock` and defers
    truncation/purge until the download completes.
  - **Shared zero-truncation `StagingSweepState` (ZERO `set_len(0)` calls in ANY branch —
    including `0`-row orphans and `.reclaim.<id>`!):** Requires
    `SELECT openmettle.storage_lock_pinned_volume()` matching `store.volume_id` and explicitly
    partitions `ReadDir` entries into: (1) `.openmettle-volume-id` (always skip); (2)
    `.reclaim.<id>` (valid lowercase canonical UUID) — skipping `state = 'reserved'` and
    `adoption_unverified = true`, executing Step 4 `LOCK_EX` detach (`OFlags::RDWR |
    OFlags::NOFOLLOW`, explicitly without `OFlags::TRUNC`, zero `set_len(0)`) when `state =
    'released' AND reclaim_state = 'anchor_pending_unlink' AND NOT adoption_unverified AND
    payload_ino IS NOT NULL` matching `(store.root_dev, payload_ino, st_size == 0)`, and
    unlinking aged `> 900 s` `0`-row / `(released AND reclaim_state = 'none')` / `settled`
    anchors under `LOCK_EX` (`OFlags::RDWR | OFlags::NOFOLLOW`, explicitly without
    `OFlags::TRUNC`) after PostgreSQL serialization (`SELECT
    openmettle.storage_lock_pinned_volume()` + `SELECT 1 FROM openmettle.storage_instance WHERE
    id FOR NO KEY UPDATE` + re-check) strictly WITHOUT `set_len(0)`; and (3) regular UUID `<id>`
    (plus aged `> 900 s` non-UUID / malformed `.reclaim.*`) — skipping `state = 'reserved'` and
    `adoption_unverified = true`; on `'released'` preserving `payload_ino IS NOT NULL OR
    adoption_unverified OR st_size > 0` untouched and unlinking only legacy `payload_ino IS NULL
    AND NOT adoption_unverified AND st_size == 0` under `LOCK_EX` (`OFlags::RDWR |
    OFlags::NOFOLLOW`, no `OFlags::TRUNC`) without `set_len(0)`; on `'settled'` preserving
    `adoption_unverified OR payload_ino IS NULL OR staging_ino != payload_ino` untouched and
    detaching `staging_ino == payload_ino` under `LOCK_EX` (`OFlags::RDWR | OFlags::NOFOLLOW`, no
    `OFlags::TRUNC`) without `set_len(0)` **STRICTLY ONLY when `artifact_revisions.state IN
    ('active', 'retained')` AND `revisions/<id>` currently exists on disk as `S_ISREG` on
    `store.root_dev` with `rev_stat.st_ino as u64 == payload_ino`** (never unlinking
    `staging/<id>` when `artifact_revisions.state IN ('purging', 'purged')`); and on aged `> 900
    s` `0`-row UUIDs / non-UUID / malformed `.reclaim.*` regular files unlinking under `LOCK_EX`
    (`OFlags::RDWR | OFlags::NOFOLLOW`, explicitly without `OFlags::TRUNC`) after
    `storage_lock_pinned_volume()` + `storage_instance FOR NO KEY UPDATE` re-check strictly
    WITHOUT `set_len(0)` (so hard links to active `revisions/B` retain 100% of their bytes!).
    Also runs the bounded ledger-driven Step 4 sweep across ALL reservation kinds using
    per-worker wrapping keyset cursor `reclaim_anchor_cursor: Option<(DateTime<Utc>, Uuid)>`
    paired with pass-start fixed upper watermark `reclaim_anchor_pass_upper: Option<(DateTime<Utc>,
    Uuid)>` (`ORDER BY closed_at DESC, id DESC LIMIT 1` captured when `None`, constraining every
    page with `AND ($1::timestamptz IS NULL OR (closed_at, id) > ($1::timestamptz, $2::uuid))
    AND (closed_at, id) <= ($3::timestamptz, $4::uuid) ORDER BY closed_at ASC, id ASC LIMIT $5`
    via `storage_reservations_reclaim_anchor_idx`, advancing past every inspected row including
    anomalous foreign-inode and `WouldBlock` rows, and resetting BOTH `reclaim_anchor_cursor =
    None` and `reclaim_anchor_pass_upper = None` when `< LIMIT` rows return OR `(upper_ts,
    upper_id)` is reached so sustained `>= LIMIT` arrivals per tick cannot starve earlier rows).
  - **3-stage inode-preserving `artifact_fs::purge_due` (`revisions/.purge.<reservation_id>` +
    `artifact_revisions.purge_stage`):** `storage::begin_purge` joins `storage_reservations`
    requiring `NOT sr.adoption_unverified AND sr.payload_ino IS NOT NULL` (firing
    `enforce_runtime_storage_volume_pinned()` -> `storage_lock_pinned_volume()`). **Stage A**
    verifies `storage_lock_pinned_volume()` + all three sentinels, anchors `payload_ino` at
    `revisions/.purge.<id>` (`nlink >= 1`, `LOCK_EX`, `set_len(0)` + `sync_all()` +
    unconditional `fsync(&revisions_dir_fd)` strictly BEFORE unlinking `revisions/<id>` —
    stopping with zero mutations if neither `.purge.<id>` nor `revisions/<id>` matches
    `payload_ino`), detaches matching `revisions/<id>` and `staging/<id>` aliases (`st_ino ==
    payload_ino`, leaving foreign inodes untouched) while `.purge.<id>` holds `nlink >= 1`, and
    requires BOTH `fsync(&revisions_dir_fd)` AND `fsync(&staging_dir_fd)`. **Stage B**
    (`storage::confirm_purge` while `.purge.<id>` still pins `payload_ino`) commits `state =
    'purged', purged_at = now(), purge_stage = 'anchor_pending_unlink'` and decrements
    `retained_bytes`. **Stage C** (immediately post-commit and via bounded DB pass using
    per-worker wrapping keyset cursor `purge_anchor_cursor: Option<(DateTime<Utc>, Uuid)>` paired
    with pass-start fixed upper watermark `purge_anchor_pass_upper: Option<(DateTime<Utc>, Uuid)>`
    — both watermark and page queries joining `openmettle.storage_reservations sr ON sr.scope_id =
    r.scope_id AND sr.id = r.reservation_id` with `AND NOT sr.adoption_unverified AND
    sr.payload_ino IS NOT NULL`, `ORDER BY r.purged_at DESC, r.id DESC LIMIT 1` captured when
    `None`, constraining every page with `AND ($1::timestamptz IS NULL OR (r.purged_at, r.id) >
    ($1::timestamptz, $2::uuid)) AND (r.purged_at, r.id) <= ($3::timestamptz, $4::uuid) ORDER BY
    r.purged_at ASC, r.id ASC LIMIT $5` over `artifact_revisions_purge_anchor_idx`, advancing past
    every inspected row and resetting BOTH `purge_anchor_cursor = None` and
    `purge_anchor_pass_upper = None` when `< LIMIT` rows return OR `(upper_ts, upper_id)` is
    reached so sustained `>= LIMIT` arrivals per tick cannot starve earlier rows) detaches `revisions/.purge.<id>` under `LOCK_EX`
    (`OFlags::RDWR | OFlags::NOFOLLOW`, explicitly without `OFlags::TRUNC`, never `set_len(0)`) +
    `fsync(&revisions_dir_fd)` + `SET purge_stage = 'none'`.
  - **Exact complement cleaner partition (`state = 'reserved'`):** **V1-14
    (`artifact_fs::reconcile_run_spills`) is the sole automatic cleanup owner of `state =
    'reserved'` `operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%'` rows**, and
    **V1-17 ([ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md))'s generic
    run-linked `storage_reservations` cleaner uses the exact logical complement `run_id IS NOT
    NULL AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')`** (owning any
    legacy pre-upgrade malformed `tool-spill:%` row with `operation_id IS NULL`), while `V1-17`
    PR2's `storage_reservations_tool_spill_binding_guard` trigger (`23514`) forbids inserting or
    updating `idempotency_key LIKE 'tool-spill:%'` with `run_id IS NULL OR operation_id IS NULL`
    and Step 4 anchor sweeps (`state = 'released' AND reclaim_state = 'anchor_pending_unlink'`)
    run boundedly across ALL reservation kinds. V1-14 enforces storage byte reservations
    through ADR 0005, ADR 0035 and ADR 0040 PR2 and leaves non-storage quotas gated on V1-17.
- **V1-07 (#8).** Owns the live worker turn executor connecting ADR 0038 model rounds to this
  tool adapter.
- **Issue #14** remains open through PR1, PR2 and PR3 until all acceptance criteria are
  implemented and verified.
