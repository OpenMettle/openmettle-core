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
| [ADR 0027](0027-authorization-and-private-projects.md) and [ADR 0035](0035-approvals-permitted-yolo-and-effect-ledger.md), `src/authz/approvals.rs` | Implement `EffectPolicy` in the reviewed tool registry (with `artifact.read_range` setting `Review.artifact = Some(artifact_id)`, `Review.class = EffectClass::Read` and `Review.reservation = None` to bind `$7::uuid` in `AUTH`, capturing the source artifact's grant cycle/revision, local groups and OIDC-mapped evidence in `authority_evidence` and `binding_digest`), update `approvals::authorized(c, p, review)` (`src/authz/approvals.rs:597-627`) in PR2 so `EffectClass::Read` passes `RunRecheckRequest.extra_target = None` and enforces in-scope read-only `Action::Read` visibility on `p.artifact == Some(artifact_id)` without requiring `Action::Write`, bind every invocation to `Proposal`, `Destination`, `EffectClass`, `EndpointKey` and `record_fenced_intent`, store separate `effect_deadline: Instant` (`sent + Duration::from_micros((effective_until - snap.now).max(0) as u64)`) and `lease_margin_deadline: Instant` (`sent + held.lease_remaining.min(held.execution_remaining).saturating_sub(margin)`) on `CommittedIntent` replacing `CommittedIntent::start(&step)`'s `Option<(Vec<u8>, Instant)>` with explicit enum **`StartPermit`** (`Stopped(Stop)`, `AuthorityExpired { operation_id, request }`, `LeaseMarginExhausted`, `Ready { request, deadline }`) plus `approvals::expire_unstarted_intent` (rechecking primary PostgreSQL `db_time(c) >= effective_expires_bound_us` under `Fence::Step` before routing to `approvals::invalidate_post_intent`, or recomputing remaining duration and proceeding on monotonic clock skew), explicitly amend ADR 0035 (`docs/adr/0035-approvals-permitted-yolo-and-effect-ledger.md:260-268`) strictly for proven-unsent **`o.outcome = 'intent' AND o.dispatched_attempts = 0` (`IS NOT NULL AND = 0`)** write rows: update `PENDING_EFFECT` (`src/authz/approvals.rs:1241`, `src/worker.rs:519`) in PR3 to `AND NOT EXISTS (SELECT FROM openmettle.operations o WHERE o.run_id = a.run_id AND o.logical_key = a.logical_key AND NOT (o.outcome = 'intent' AND o.dispatched_attempts = 0))` (keeping `REQUEST.consumed` unchanged as `EXISTS (SELECT FROM openmettle.operations ...)` so HTTP `decide` still treats the approval as consumed while `worker::execute`'s `approvals::pending_effect` discovers `(approval_id, proposal)` for a consumed human approval whose operation is still `outcome = 'intent' AND dispatched_attempts = 0`, and PR4's `Executor::step` discovers automatic writes `o.approval_id IS NULL AND o.outcome = 'intent' AND o.dispatched_attempts = 0`), update `record_fenced_intent`'s existing-operation branch (`src/authz/approvals.rs:1291-1337`, under `Fence::Step`) in PR3 to lock `SELECT id::text, request, capability, outcome, dispatched_attempts, effective_expires_us, approval_id::text FROM openmettle.operations WHERE run_id = $1::uuid AND logical_key = $2 FOR UPDATE` (returning `Err(CONFLICT)` if caller supplied `approval = Some(caller_id)` disagreeing with `stored_approval_id`, otherwise resolving `effective_approval = stored_approval_id.as_deref()`, verifying committed `authorization.basis` (`"human"` iff `effective_approval.is_some()`) and `authorization.approval_id == effective_approval`, and verifying `durable::existing_intent`): when **`old.outcome == "intent" && old.dispatched_attempts == Some(0)` AND `capability != "repeatable_read"`**, re-verify live `EffectPolicy` (`reviewed(policy, &s, &p)?` with `live_review == committed_review`) + `{AUTH}` (`authorized(c, &proof, &live_review)` — loading `run_approvals` + `run_approval_decisions.deciding_session_id` by `old.approval_id` even though `REQUEST.consumed` is `true` when `old.approval_id IS NOT NULL`, or verifying automatic `eligible && yolo` + `hydrate_worker_principal` + `authorize_capability(YOLO)` when `old.approval_id IS NULL`, plus exact `live_evidence == committed_evidence && live_hash == committed_binding_digest`) + `snap.now < effective_expires_bound_us` (routing expiry/revocation immediately through `approvals::invalidate_post_intent` -> `IntentResult::Invalidated(settled)` with zero sends), and when valid return **`IntentResult::Applied(CommittedIntent { operation_id: op, request: old_bytes, effect_deadline, lease_margin_deadline })`** (while all other existing-row cases — `repeatable_read`, `dispatched_attempts IS NULL`, `dispatched_attempts >= 1`, or `outcome <> 'intent'` — still **never** receive a write send permit and return `Ok(IntentResult::Replayed(op))`), add `approvals::recheck_replay_effect_authority(..., policy: &impl EffectPolicy)` (under `Fence::Step` on primary: parsing the committed `openmettle.effect` v1 envelope from `operations.request` — reconstructing committed `Proposal` `p` and requiring exact match with the requested `Proposal` and stored `operations` columns, extracting `authorization.basis`, `authorization.approval_id`, `authorization.expires_us`, `committed_evidence = STANDARD.decode(authorization.authority)`, `committed_binding_digest`, and `endpoint` (`committed_review`) — resolving the current live `Review` via `live_review = reviewed(policy, &s, &p)?` and requiring exact equality `live_review == committed_review` (`serde_json::to_vec(&live_review) == serde_json::to_vec(&committed_review)`; failing closed on `committed_review.reservation.is_some()` unless explicitly matched), joining `openmettle.run_approvals a JOIN openmettle.run_approval_decisions d ON d.approval_id = a.id` (`WHERE a.scope_id = $scope AND a.run_id = $run AND a.id = $approval_id AND a.logical_key = $logical_key`, requiring `d.decision == "approve"` and `d.binding_digest == a.binding_digest == committed_binding_digest`, passing `Some(d.deciding_session_id)` as `Proof.decider`) when `basis == "human"`, executing `snap = authorized(c, &proof, &live_review)`, checking `snap.now < expires_us.min(validity(&snap, &live_review))` plus `automatic(&r, &snap)` and `YOLO` capability when `basis == "yolo"`, rebuilding `live_evidence = snap.evidence(&live_review, auto)` and `live_hash = p.binding(&s, expires_us, &live_evidence)` (`Binding::new`), and requiring exact byte equality `live_evidence == committed_evidence && live_hash == committed_binding_digest` in addition to `hydrate_worker_principal`, `revision.scope_id == run.scope_id`, `Action::Read` and `revision.state == "active"` before replaying any `succeeded` source/spilled artifact-backed result or `artifact.read_range` bytes, including during committed-observation recovery, and requiring the same live `EffectPolicy` resolution and committed-evidence equality before replaying `failed` inline `status: "tool_error"` envelopes or resuming unfinished `repeatable_read` via `approvals::start_replayed_read(..., policy: &impl EffectPolicy)`), add ledger-aware **`approvals::invalidate_post_intent`** (extending `leases::FailReason` with `FailReason::ApprovalExpired` -> `openmettle.run-approval-expired`, keeping `invalidate_running`'s raw `fail(c, ..., EXPIRED)` strictly for pre-intent expiry where zero `operations` row exists; computing `effective_expires_bound_us` as `min` over durable `o.effective_expires_us` (when `NOT NULL`), `envelope["authorization"]["expires_us"]`, `live_review.endpoint_key` `expires_us` (when `EndpointKey::Supported`), and a direct un-filtered expiry query of bound non-revoked `local_sessions` / `local_identity_approvals` and unrevoked bound `membership_observations` so natural shorter-lived `deciding_session_id` / `originating_session_id` / OIDC observation expiry classifies accurately as expiry rather than `revoked`; partitioning strictly by `(capability, outcome, dispatched_attempts)` **regardless of caller** (`start_replayed_read`, `recheck_replay_effect_authority`, `record_fenced_intent` zero-attempt re-authorization, `CommittedIntent::start`, or Step 5 Transaction 2): **Branch 1** covers **`capability == 'repeatable_read'` for ALL `dispatched_attempts` (`NULL`, `0`, `1`, `2`, `3`) regardless of caller** (including in-process read retries), plus write `'intent'` rows with `dispatched_attempts == Some(0)`, and already-completed `outcome IN ('succeeded', 'failed')` rows — recording `outcome = 'failed'` if still `'intent'`, then calling `leases::settle_locked(c, lease, ExecState::Running, reason, settings, settle_input)` using `Settle::Failed(FailReason::ApprovalExpired)` when `db_time(c) >= effective_expires_bound_us` or `Settle::Stopped` with `Some(CancelReason::Revoked)` when `db_time(c) < effective_expires_bound_us`; **Branch 2** covers `capability IN ('idempotent', 'lookup', 'non_repeatable')` with `(outcome == 'intent' AND (dispatched_attempts IS NULL OR dispatched_attempts >= 1)) OR outcome == 'outcome_unknown'` — **never** calling `fail(...)` or `Settle::Failed`, performing zero additional outbound sends, transitioning non-reconcilable writes to `outcome = 'outcome_unknown'` or leaving reconcilable writes unresolved so `unresolved >= 1`, and settling via `leases::settle_locked(c, lease, ExecState::Running, reason, settings, Settle::Stopped)` into `Settled::Reconciling` or `Settled::Terminal { state: "interrupted" }`, returning `leases::Settled` inside `StepResult::Invalidated(leases::Settled)`), add PR2's next sequential schema migration (e.g., `0024`) for nullable durable pre-dispatch attempt accounting (`openmettle.operations.dispatched_attempts integer DEFAULT NULL CHECK (dispatched_attempts BETWEEN 0 AND 3)` with a monotonicity trigger forbidding `non-null -> NULL` or decrements) and nullable immutable **`openmettle.operations.effective_expires_us bigint`** (`GRANT INSERT (effective_expires_us) ON openmettle.operations TO openmettle_worker` — immutable after insert with zero `UPDATE` grant and trigger guard, preserving `openmettle_api`'s zero `INSERT`/`UPDATE` grant on `openmettle.operations`, with zero change to `Binding` or `request_identity` canonical bytes, populated by `INSERT_INTENT` at `src/authz/approvals.rs:1262, 1422` from `$20 = effective_until`), executed across **two separate `Fence::Step` PostgreSQL transactions** (`approvals::record_fenced_intent` writes **zero** `openmettle.operations` rows when returning `IntentResult::ApprovalRequired` so `approvals::park` inserts only `openmettle.run_approvals`, Transaction 1 commits `outcome = 'intent'` with `dispatched_attempts = 0` and `effective_expires_us = effective_until` strictly when returning `IntentResult::Applied(committed)` — immediate `repeatable_read` in PR2, and permitted automatic `yolo` writes or human-approved resume via `record_fenced_intent(..., Some(approval_id))` in PR3 once PR3's database-backed worker rollout gate **`openmettle.runtime_feature_gates.two_phase_effect_intents_enabled = true`** confirms all `N-1` workers and expiry sweepers are drained, while keeping pre-existing ADR 0035 external approval writes at `dispatched_attempts = NULL` and scoped MCP execution disabled while `two_phase_effect_intents_enabled = false` — so pre-upgrade and `N-1` rows remain `NULL` and are treated conservatively as exhausted `coalesce(dispatched_attempts, 3) >= 3` for dispatch and unknown `>= 1` for write reconciliation, and **both** Step 5 Transaction 2 and `approvals::start_replayed_read` lock `runs`/`operations` (`FOR UPDATE`), **evaluate live `EffectPolicy` + `{AUTH}` / `effective_expires_us` authority validity FIRST before checking `coalesce(dispatched_attempts, 3) >= 3`** (routing expired or revoked authority — including when `dispatched_attempts IS NULL` or `dispatched_attempts == 3` — immediately through `approvals::invalidate_post_intent` Branch 1 to `openmettle.run-approval-expired` or `openmettle.run-revoked`, skipping ordinary failed observation and model continuation), **only when live authority is still valid** require `dispatched_attempts IS NOT NULL AND dispatched_attempts < 3` (recording an ordinary exhausted `outcome = 'failed'` observation with zero sends and continuing the turn on `repeatable_read` when `NULL` or `>= 3`), and guard the `UPDATE openmettle.operations` statement **itself** — `SET dispatched_attempts = 1 ... AND outcome = 'intent' AND dispatched_attempts = 0` strictly before attempt 1, and `SET dispatched_attempts = o.dispatched_attempts + 1 ... AND o.dispatched_attempts < 3` on permitted retries — with the live `{AUTH}` CTE (`FROM snap, t, openmettle.runs r` matching `INSERT_INTENT` at `src/authz/approvals.rs:1262-1267`, verifying `$expected_base`, `$expected_tool`, `(NOT $auto OR (snap.eligible AND snap.yolo = $expected_yolo))`, `snap.now_us < $effective_expires_bound_us`, and active claim/lease/execution timestamps — settling via ledger-aware `approvals::invalidate_post_intent` -> `StepResult::Invalidated(settled)` with zero increment and zero sends if `0` rows are updated) before releasing the connection and issuing every outbound HTTP send), upgrade repair of pre-existing `queued`/`waiting` revision-zero `repeatable_read` intents and an `AFTER UPDATE OF state ON openmettle.runs` `SECURITY DEFINER` trigger (`openmettle.resolve_abandoned_repeatable_reads()`), and add PR3's sequential SQL migration creating **`openmettle.runtime_feature_gates (id boolean PRIMARY KEY DEFAULT true CHECK (id), two_phase_effect_intents_enabled boolean NOT NULL DEFAULT false)`** (`GRANT SELECT` to `openmettle_api, openmettle_worker`; enabled by `openmettle-admin` / rollout once all `N-1` workers and `settle_expired` sweepers are drained, and enabled by `bootstrap` on fresh databases) plus installing/extending an `AFTER UPDATE OF state ON openmettle.runs` `SECURITY DEFINER` defense-in-depth trigger (`openmettle.resolve_terminal_write_intents()`, across all terminal states `NEW.state IN ('succeeded', 'failed', 'cancelled', 'interrupted')`: raising an invariant exception if `NEW.state = 'succeeded'` with any unresolved write, and on `'failed'`, `'cancelled'`, or `'interrupted'` unconditionally transitioning any remaining revision-zero write intents to `outcome = 'outcome_unknown'`, `revision = 1` strictly before `run-terminal`). |
| [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md), `src/worker.rs` | Implement `ApprovedAdapter` for resumed writes, reuse the same committed-envelope dispatch for immediate reads and permitted YOLO writes, gate two-phase `dispatched_attempts = 0` writes and PR4 scoped MCP tool execution behind **`openmettle.runtime_feature_gates.two_phase_effect_intents_enabled`** so no `N-1` worker or `N-1` `settle_expired` sweeper ever sees a `dispatched_attempts = 0` row, update **`leases::unresolved!()`** (`src/authz/leases.rs:310-314`) in PR3 from `outcome IN ('intent', 'outcome_unknown') AND capability IN (...)` to **`(outcome = 'outcome_unknown' OR (outcome = 'intent' AND coalesce(dispatched_attempts, 1) > 0)) AND capability IN ('idempotent', 'lookup', 'non_repeatable')`** (so legacy `dispatched_attempts IS NULL` and dispatched `>= 1` rows remain unresolved while proven-unsent `dispatched_attempts = 0` rows are excluded), add explicit **`WorkEnd::Handoff`** in `src/worker.rs` routed in `run_one` (`src/worker.rs:661-675`) to **`leases::handoff(&mut c, &lease, &settings).await`** whenever `cause != Some(Stop::LeaseLost)`, update **`leases::handoff`** (`src/authz/leases.rs:503-535`, under `Fence::Hold`) to check **`time_to_reclaim = execution_expires_at > clock_timestamp() + $3::bigint * interval '1 millisecond'`** (`settings.lease` — matching `reclaim_next` and `SETTLEMENT_INPUTS` `time_to_reconcile` verbatim: calling `release_locked` keeping `state = 'running'` when `held.cancel.is_none() && !pending && time_to_reclaim`, and calling `settle_locked(..., Settle::Stopped)` inside the same `Fence::Hold` transaction when `held.cancel.is_some() \|\| pending \|\| !time_to_reclaim` so `<= settings.lease` remaining immediately selects `Resolution::DeadlineExceeded` (`state = 'failed'`, `{"reason":"deadline_exceeded"}`) and atomically closes `outcome = 'intent' AND dispatched_attempts = 0` to `outcome = 'failed', revision = revision + 1` with zero stranded unreclaimable runs and zero `Reconciling`/`Interrupted`), update both `worker::execute` (`src/worker.rs:533` on resumed human approvals) and Step 5 to match `CommittedIntent::start(&step)`'s explicit **`StartPermit`** enum (`StartPermit::Stopped(Stop)` returning `WorkEnd::Stop(why)` — `Stop::Shutdown` routing to `leases::handoff`, terminal `Stop::Cancel` / `Stop::Deadline` settling directly to `Resolution::Cancelled` / `Resolution::DeadlineExceeded` with `n = 0`; `StartPermit::LeaseMarginExhausted` returning **`WorkEnd::Handoff`** so `leases::handoff` either calls `release_locked` when `> settings.lease` remains — keeping `runs.state = 'running'` and `operations.outcome = 'intent', dispatched_attempts = 0` so a successor worker reclaims (`recovered == true`) with empty `leases::unresolved_operations(..., 1)` (`src/worker.rs:500`), stays in `Running`, discovers the consumed human approval via updated `PENDING_EFFECT` (`src/authz/approvals.rs:1241`) or the automatic write via `Executor::step`, re-authorizes via `record_fenced_intent` returning **`IntentResult::Applied(CommittedIntent)`** under live `EffectPolicy` + `{AUTH}`, passes `StartPermit::Ready`, commits `dispatched_attempts: 0 -> 1` in Transaction 2, dispatches the write once, and finishes **`succeeded`** — or immediately settles `Resolution::DeadlineExceeded` + `outcome = 'failed'` when `<= settings.lease` remains; `StartPermit::AuthorityExpired { operation_id, request }` invoking `approvals::expire_unstarted_intent` / `approvals::invalidate_post_intent` under `Fence::Step` to mark the `dispatched_attempts = 0` intent `'failed'` and settle via `FailReason::ApprovalExpired` -> `openmettle.run-approval-expired` (`state = "failed"`) when `db_time(c) >= effective_expires_bound_us` or recomputing remaining budget on monotonic clock skew; and `StartPermit::Ready { request, deadline }` proceeding to dispatch), stop every `outcome_unknown` write (including **every** post-send write refusal — explicitly including first-attempt HTTP `401` and `403`, since post-intent `failed` on writes applies strictly when zero request bytes ever left the process across all attempts) under `Fence::Hold` + `StepResult::Stopped` into `ExecState::Reconciling` / `interrupted`, add **`StepResult::Invalidated(leases::Settled)`** -> **`WorkEnd::Invalidated(settled)`** in PR2 (so `Settled::Reconciling { .. }` immediately executes `leases::release_lease(&mut c, &lease)` at `src/worker.rs:660-663` without stranding the live lease across `leases::reclaim_next`'s `> 1` lease interval requirement, while `Settled::Terminal { .. }` exits at `src/worker.rs:652`) alongside distinct **`StepResult::LeaseLost`** -> **`WorkEnd::Stop(Stop::LeaseLost)`** strictly for deposed-worker own lease loss (`Stop::LeaseLost`, `LeaseError::StaleClaim \| Expired \| Terminal`), rely on PR2's and PR3's database triggers to resolve abandoned `repeatable_read` intents (pre-`waiting`/pre-terminal) and remaining revision-zero write intents (`openmettle.resolve_terminal_write_intents()`, raising on `'succeeded'` with any unresolved or open write intent and coercing any remaining `'intent'` writes to `outcome_unknown` pre-`run-terminal` on `'failed'`/`'cancelled'`/`'interrupted'`), in PR3 `leases::settle_locked` preserve `Err(StoreError::Conflict("unresolved operation"))` -> `Settle::Stopped` fallback on `Settle::Succeeded` whenever any unresolved OR open `outcome = 'intent' AND dispatched_attempts = 0` write exists (whereas `ExecState::Reconciling` returns `Err(StoreError::InvalidInput("settle"))`), AND inside that exact same `settle_locked` transaction whenever settling to any terminal state (`Cancelled`, `DeadlineExceeded`, `Failed`, or `Interrupted` — and likewise in PR3 `leases::settle_expired` strictly before `run-terminal`), **atomically transition any remaining `outcome = 'intent' AND (capability = 'repeatable_read' OR dispatched_attempts = 0)` rows on the run to `outcome = 'failed', revision = revision + 1`** (so no terminal run ever retains an open `'intent'` row and run-linked storage cleanup predicates fire cleanly), define deterministic recovery across `run_one` drain-window expiry (`WorkEnd::Incomplete`) for both unacknowledged commits (keyed committed-observation reuse gated by `approvals::recheck_replay_effect_authority(..., policy)` with live `EffectPolicy` resolution `live_review == committed_review`, `run_approvals JOIN run_approval_decisions` for `basis == "human"`, and exact committed `authority_evidence` + `binding_digest` equality, plus `Action::Read` and `revision.state == "active"` for `succeeded` source/spilled artifacts, while `failed` observations always replay their bounded inline `status: "tool_error"` envelope) and uncommitted `'intent'` observations (including `outcome_unknown` -> `interrupted` for dispatched or legacy `dispatched_attempts IS NULL` writes without a downstream read-only lookup, even when direct terminal settlement bypasses `Executor::reconcile`), and implement destination-authorized read-only `Executor::reconcile` reading `dispatched_attempts: Option<i32>` on `UnresolvedOperation`. |
| [ADR 0005](0005-artifact-storage-accounting.md), [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md) and [ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md), `src/storage.rs` and `src/artifact_fs.rs` | Sequence `V1-14` PR2 after `V1-17` PR2 (`ADR 0040` PR2) for the dedicated 1-row read-mostly control table **`openmettle.storage_volume_control (id boolean PRIMARY KEY DEFAULT true CHECK (id), volume_id uuid, bootstrap_auto_pin_allowed boolean NOT NULL DEFAULT false, adoption_run_id uuid, CONSTRAINT storage_volume_control_auto_pin_check CHECK (volume_id IS NULL OR NOT bootstrap_auto_pin_allowed))`** (`GRANT SELECT` to `openmettle_api, openmettle_worker`, `GRANT UPDATE (volume_id, bootstrap_auto_pin_allowed)` to `openmettle_api`; runtime `reserve`/`settle`/`release`/`purge` **only ever take `FOR SHARE` on `storage_volume_control` and never `UPDATE` it**, eliminating `FOR SHARE -> FOR NO KEY UPDATE` self-upgrade deadlocks on counter table `storage_instance` under canonical lock order **`runs -> storage_reservations -> artifacts -> artifact_revisions -> storage_volume_control -> storage_accounts -> storage_instance`**), `openmettle.storage_reservations.adoption_unverified` with tightened **`storage_reservations_adoption_unverified_check`** **`CHECK (NOT adoption_unverified OR state = 'reserved')`** (making non-owner release/settlement of quarantined rows impossible in PostgreSQL), **`stage_claimed boolean NOT NULL DEFAULT false`** (`CHECK (payload_ino IS NULL OR stage_claimed)`), **`payload_ino numeric(20, 0)`** ONLY (`CHECK (payload_ino IS NULL OR payload_ino >= 0)`, storing exact unsigned 64-bit `u64` `MetadataExt::ino()`, with **zero `payload_dev` column** because Linux NFS assigns client-local anonymous `st_dev` via `get_anon_bdev`; each host verifies local same-mount equality `file_meta.dev() == dir_fd_meta.dev() == root_fd_meta.dev()` using only its own open FDs, role-tagged `.openmettle-volume-id` sentinels `:root`/`:staging`/`:revisions` when `volume_id IS NOT NULL`, and `file_meta.ino() == payload_ino`), **`publish_pending boolean NOT NULL DEFAULT false`** (`CHECK (NOT publish_pending OR (state = 'reserved' AND payload_ino IS NOT NULL))`), and the unified **4-state** cleaner lease shared by all 4 cleaners (`artifact_fs::abort`, `reconcile_expired`, generic run-linked cleaner, and `reconcile_run_spills`) — **`reclaim_state text NOT NULL DEFAULT 'none' CHECK (reclaim_state IN ('none', 'claiming', 'truncated', 'anchor_pending_unlink'))`**, **`reclaim_claim_token uuid`**, and **`reclaim_lease_until timestamptz`** (`CHECK ((state = 'reserved' AND reclaim_state IN ('none', 'claiming', 'truncated')) OR (state = 'released' AND reclaim_state IN ('none', 'anchor_pending_unlink')) OR (state = 'settled' AND reclaim_state = 'none'))`, `CHECK ((reclaim_state IN ('claiming', 'truncated') AND reclaim_claim_token IS NOT NULL AND reclaim_lease_until IS NOT NULL) OR (reclaim_state IN ('none', 'anchor_pending_unlink') AND reclaim_claim_token IS NULL AND reclaim_lease_until IS NULL))`, `CHECK (reclaim_state NOT IN ('truncated', 'anchor_pending_unlink') OR NOT publish_pending)`), runtime grants (`GRANT INSERT (lease_expires_at, stage_claimed)` and `GRANT UPDATE (lease_expires_at, adoption_unverified, stage_claimed, payload_ino, publish_pending, reclaim_state, reclaim_claim_token, reclaim_lease_until)` to `openmettle_api, openmettle_worker` in `src/boundaries.sql`), PostgreSQL `SECURITY INVOKER` (`SET search_path = pg_catalog`) triggers **`openmettle.enforce_runtime_storage_volume_pinned()`** (`BEFORE UPDATE` on `storage_reservations` `WHEN (OLD.state = 'reserved' AND NEW.state = 'released')` and `artifact_revisions` `WHEN (NEW.state IN ('purging', 'purged'))`: executing `SELECT volume_id, adoption_run_id INTO v_vol, v_adopt FROM openmettle.storage_volume_control WHERE id FOR SHARE` and raising `OMQ03` when `NOT FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL`, failing closed even if the singleton row is missing!) and **`openmettle.enforce_storage_reservation_monotonic_guards()`** (`BEFORE UPDATE ON openmettle.storage_reservations FOR EACH ROW`: raising `OMQ03` for non-`openmettle_owner` roles on (1) `OLD.adoption_unverified AND NOT NEW.adoption_unverified`, (2) `OLD.payload_ino IS NOT NULL AND NEW.payload_ino IS DISTINCT FROM OLD.payload_ino` — making **`payload_ino` write-once and NEVER cleared to `NULL`** even during/after cleanup, settlement, or release — or (3) `OLD.stage_claimed AND NOT NEW.stage_claimed`), `storage_reservations_tool_spill_binding_guard` (`23514`), `rustix`-backed (`default-features = false, features = ["fs", "std"]`, 100% safe Rust under `unsafe_code = "forbid"`) verified directory descriptors (`root_fd`, `staging_dir_fd`, `revisions_dir_fd`: `OwnedFd` via `rustix::fs::openat` with `OFlags::RDONLY \| OFlags::DIRECTORY \| OFlags::NOFOLLOW`), and `V1-17` PR2's shared unified `StagingSweepState` + `artifact_fs::purge_due` in `worker::maintenance`; align HTTP **`Store::stage` / `Store::publish` / `Store::read`** (`src/artifact_fs.rs`) with `V1-17` PR2 so HTTP `Store::stage` and `Store::publish` (`openmettle_api`) succeed during mixed-version rolling upgrade while `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL` (skipping sentinel reads while `volume_id IS NULL` and verifying role-tagged sentinels once `volume_id IS NOT NULL`, whereas worker `publish_bytes` and all 4 cleaners strictly require `volume_id IS NOT NULL AND adoption_run_id IS NULL`), `Store::stage` commits `stage_claimed = true` under `FOR UPDATE` (`state = 'reserved' AND NOT adoption_unverified AND NOT stage_claimed AND payload_ino IS NULL AND reclaim_state = 'none'` + `storage_volume_control FOR SHARE` `adoption_run_id IS NULL`) BEFORE `openat` (Step 1a), opens `staging/<id>` (`OFlags::CREATE \| OFlags::EXCL \| OFlags::RDWR \| OFlags::NOFOLLOW`, `0` bytes) + `LOCK_SH` + local same-mount `st_dev` check + `fsync(&staging_dir_fd)` (Step 1b), commits write-once `payload_ino = staged_ino` under `FOR UPDATE` (`reclaim_state = 'none'`, Step 1c), keeps **`StagedFile::drop` 100% non-destructive (`close` only — writers NEVER call `set_len(0)` and NEVER call `unlinkat` on error, cutoff, drop, or lost commit ack)**, sets `publish_pending = true` under `FOR UPDATE` (`state = 'reserved' AND NOT adoption_unverified AND payload_ino = $staged_ino AND reclaim_state = 'none'`) before **`rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id, AtFlags::empty())`** + `fsync(&revisions_dir_fd)` (mandatory POSIX/NFS `LINK` failing atomically with `Errno::EXIST` without overwriting `revisions/<id>` AND keeping `staging/<id>` linked on disk until `storage::settle` commits so any `N-1` API same-key retry hits `OpenOptions::create_new(true)` -> `Err(Error::InProgress)` at `src/artifact_fs.rs:475` without calling `abort` or replacing `fs::rename`!), commits `storage::settle` (`state = 'settled', publish_pending = false`, retaining `payload_ino`), then performs post-`commit` best-effort detach of the `staging/<id>` alias while holding `LOCK_SH` (verifying `statat(&staging_dir_fd, id).st_ino == staged_ino` AND `statat(&revisions_dir_fd, id).st_ino == staged_ino` -> `unlinkat(&staging_dir_fd, id, AtFlags::empty())` with **NEVER `set_len(0)`** -> `drop(file)` -> `fsync(&staging_dir_fd)`), never calls `abort` on ambiguous `storage::settle` commit (running `abort` only on confirmed pre-settlement failure via the unified 4-step `LOCK_EX` protocol), and **`Store::read`** verifies `sr.adoption_unverified = false`, local same-mount `st_dev`, and `file_meta.ino() == sr.payload_ino` whenever `sr.payload_ino IS NOT NULL` (allowing `sr.payload_ino IS NULL` only while `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL`); add lease-fenced direct byte publication (`artifact_fs::publish_bytes`, restricted exclusively to `succeeded` tool outputs while every `failed` tool result uses bounded inline `status: "tool_error"`; gated by process-wide `Arc<tokio::sync::Semaphore>` `spill_permits` bounded to `max_concurrent_runs`, with **zero `cleanup_own_staged_leaf`, zero `set_len(0)` anywhere in writers, and `unlinkat` strictly limited to post-`commit` best-effort `staging/<id>` alias detach after `storage::settle` commits `state = 'settled'`**): **Phase 1a** acquires `OwnedSemaphorePermit`, locks `runs (FOR NO KEY UPDATE) -> storage_volume_control (FOR SHARE)` (`volume_id = $expected_volume_id AND adoption_run_id IS NULL`, else clean inline `truncated_no_spill`) `-> storage_accounts (FOR UPDATE) -> storage_instance (FOR UPDATE) -> INSERT storage_reservations` inserting `stage_claimed = true, payload_ino = NULL, publish_pending = false, reclaim_state = 'none'` BEFORE touching disk; **Phase 1b** **moves `OwnedSemaphorePermit` directly into Phase 1b's `spawn_blocking` closure** and returns `(payload_file, staged_ino, spill_permit)` on completion (strictly bounding concurrent blocking tasks to `max_concurrent_runs` even when cutoff fires during `openat`/`fsync(&staging_dir_fd)`), re-verifies `<root>`, `"staging"`, `"revisions"` directory FDs + role-tagged sentinels, opens `staging/<reservation_id>` (`OFlags::CREATE \| OFlags::EXCL \| OFlags::RDWR \| OFlags::NOFOLLOW`, `0` bytes) + `LOCK_SH` + verifies `S_ISREG`, local same-mount `file_meta.dev() == staging_dir_fd_meta.dev() == root_fd_meta.dev()`, and `staged_ino = file_meta.ino()` + **`fsync(&staging_dir_fd)`**, then commits `UPDATE openmettle.storage_reservations SET payload_ino = $3::text::numeric(20, 0), publish_pending = true WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved' AND NOT adoption_unverified AND stage_claimed AND payload_ino IS NULL AND reclaim_state = 'none'` under `Fence::Step` + `storage_volume_control FOR SHARE` (on any error/cutoff/lost ack, purely dropping `payload_file` + `OwnedSemaphorePermit` with zero `set_len(0)` and zero `unlinkat`); **Phase 2** (`spawn_blocking`, chunked `<= 64 KiB` cancellation checks, zero DB tx across disk I/O) writes `payload` + `payload_file.sync_all()?`, re-verifies `<root>`, `"staging"`, `"revisions"` + sentinels + `statat(&staging_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` (`S_ISREG`, local `st_dev` match, `st_ino == staged_ino`, `st_size == size_bytes`), publishes via **`rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id, AtFlags::empty())`** (failing atomically with `Errno::EXIST` without overwriting and keeping `staging/<id>` linked on disk until `storage::settle` commits; on `Errno::EXIST` or mismatch committing quarantine `adoption_unverified = true, publish_pending = false` with zero `set_len(0)` / zero `unlinkat`) + `fsync(&revisions_dir_fd)` + post-`linkat` verification of `revisions/<id>` (`S_ISREG`, local `st_dev`, `st_ino == staged_ino`, `st_size == size_bytes`) while returning **`(payload_file, spill_permit)`** (keeping `LOCK_SH` held!) into Phase 3; **Phase 3** executes a single atomic `Fence::Step` `storage::settle` (preserving `ReservationState::Settled` idempotent replay while enforcing `state = 'reserved' AND NOT adoption_unverified AND payload_ino = $staged_ino AND reclaim_state = 'none'` + `storage_volume_control FOR SHARE` on `ReservationState::Reserved`, committing `state = 'settled', publish_pending = false` while **retaining `payload_ino`**) + `runs::record_observation` transaction with permit-bounded, `<= 2 s` time-bounded `spawn_blocking` pre-commit directory/sentinel/`revisions/<id>` verification (rolling back + quarantining on displacement/mismatch, and on lost Phase-3 commit ack purely closing `payload_file` with zero `set_len(0)` / zero `unlinkat`), then on confirmed `COMMIT` performs post-`commit` best-effort detach of the `staging/<id>` alias while still holding `LOCK_SH` on `payload_file` (verifying `statat(&staging_dir_fd, id).st_ino == staged_ino` AND `statat(&revisions_dir_fd, id).st_ino == staged_ino` -> `unlinkat(&staging_dir_fd, id, AtFlags::empty())` with **NEVER `set_len(0)`** -> `drop(payload_file)` -> `fsync(&staging_dir_fd)`), plus lock/pre-commit `step.stop` rechecks in inline `truncated_no_spill` fallbacks; startup writability and `linkat` qualification (`Store::probe_writable`, verifying `O_CREAT \| O_EXCL \| O_NOFOLLOW`, `rustix::fs::linkat` returning `Errno::EXIST` without overwrite and rejecting `ENOSYS`/`EOPNOTSUPP`/`EINVAL`/`EXDEV`/`EMLINK` fail-closed, and file + directory `fsync`); **exclusive single-owner** unified **4-step crash-safe & replacement-safe** spill cleanup preserving `payload_ino` allocation via **`staging/.reclaim.<id>`** (`artifact_fs::reconcile_run_spills`, sole automatic cleanup owner of `operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%'` rows while `V1-17` (`ADR 0040`)'s generic run-linked cleaner uses the exact logical complement `run_id IS NOT NULL AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')`): **Step 1** (serialized DB claim BEFORE any truncation/unlink, zero FS I/O inside DB tx) locks `runs FOR NO KEY UPDATE SKIP LOCKED -> storage_reservations FOR UPDATE SKIP LOCKED -> storage_volume_control FOR SHARE` (`NOT FOUND OR v_vol IS DISTINCT FROM $expected_volume_id OR v_adopt IS NOT NULL` -> abort), requires `state = 'reserved' AND NOT adoption_unverified AND (reclaim_state = 'none' OR reclaim_lease_until <= clock_timestamp())` (+ spill/terminal preconditions), and commits `reclaim_state = CASE WHEN reclaim_state = 'truncated' THEN 'truncated' ELSE 'claiming' END, reclaim_claim_token = $my_token, reclaim_lease_until = clock_timestamp() + interval '60 seconds'`; **Step 2** (outside DB tx, keeping `payload_ino` allocated at `nlink >= 1` until Step 3 commits!): verifies pinned three-directory volume identity + `adoption_run_id IS NULL`, then in **Subcase A1 (`payload_ino IS NOT NULL` and `'claiming'`)** probes `staging/<id>`, `revisions/<id>`, and `staging/.reclaim.<id>`: any foreign/non-regular/wrong-`st_dev`/`st_ino != payload_ino` entry or triple `ENOENT` -> zero `set_len(0)` / zero `unlinkat`, quarantine under `FOR UPDATE` verifying `reclaim_claim_token = $my_token AND reclaim_state = 'claiming' AND payload_ino = $expected_ino`; when matching, opens `OFlags::RDWR \| OFlags::NOFOLLOW` -> `LOCK_EX` -> re-verifies `payload_ino` -> (1) **`probe_file.set_len(0)?` + `probe_file.sync_all()?`**, (2) creates/verifies hard-link anchor **`staging/.reclaim.<id>`** via `linkat` + `fsync(&staging_dir_fd)` (`nlink` `1 -> 2` BEFORE unlinking `<id>` so `payload_ino` NEVER hits `nlink = 0` and cannot be reused!), (3) unlinks `revisions/<id>` and `staging/<id>` + dual `fsync`, (4) still holding `LOCK_EX`, commits **`reclaim_state = 'truncated', publish_pending = false`** (retaining `payload_ino`!); in **Subcase A2 (`payload_ino IS NOT NULL` and `'truncated'` — crash recovery before Step 3)**, **NEVER truncates or unlinks `staging/<id>` or `revisions/<id>`**, probing **`staging/.reclaim.<id>` ONLY** (`S_ISREG`, local `st_dev`, `st_ino == payload_ino`, `st_size == 0`, else quarantine under `$my_token` guard) -> `LOCK_EX` -> dual `fsync` -> Step 3; in **Subcase B (`payload_ino IS NULL`)**, quarantines any `revisions/<id>` or non-`0`-byte `staging/<id>`, unlinks `0`-byte `staging/<id>` under `LOCK_EX` (never `set_len(0)`), dual `fsync` -> Step 3; **Step 3** (final `storage::release` with **zero FS I/O inside DB tx**) locks `(runs ->) storage_reservations FOR UPDATE`, requires `state = 'reserved' AND NOT adoption_unverified AND NOT publish_pending AND reclaim_claim_token = $my_token AND (payload_ino IS NULL OR reclaim_state = 'truncated')`, sets **`reclaim_state = CASE WHEN payload_ino IS NOT NULL THEN 'anchor_pending_unlink' ELSE 'none' END, reclaim_claim_token = NULL, reclaim_lease_until = NULL`**, and commits `storage::release` (firing `enforce_runtime_storage_volume_pinned()` taking `storage_volume_control FOR SHARE` -> `storage_accounts` -> `storage_instance`, retaining `payload_ino`); **Step 4** (post-release detach of `staging/.reclaim.<id>`) verifies `st_ino == payload_ino` and `st_size == 0` under `LOCK_EX`, calls `unlinkat(&staging_dir_fd, &reclaim_name, AtFlags::empty())` (never `set_len(0)`) -> `drop(probe_file)` -> `fsync(&staging_dir_fd)` -> sets `reclaim_state = 'none'` (and `openmettle-admin` adoption positively verifies and **preserves `'truncated'` holds** with `reclaim_lease_until = clock_timestamp()` when `staging/.reclaim.<id>` matches `payload_ino` and `st_size == 0`); plus `state = 'released'` retry pass, `V1-17` PR2's shared `StagingSweepState` (**NEVER calling `set_len(0)` on `'settled'`, `'released'`, or `.reclaim.<id>`**: on `'settled'` preserving `adoption_unverified = true`, `payload_ino IS NULL`, or `staging_ino != payload_ino` 100% untouched — protecting cross-reservation hard links such as `staging/A` -> `revisions/B` — and unlinking `staging_ino == payload_ino` without `set_len(0)` iff `revisions/<id>` matches `payload_ino` OR `revisions/<id>` is `ENOENT` and `artifact_revisions.state = 'purged'`; on `'released'` never touching `staging/<id>` when `payload_ino IS NOT NULL` and unlinking `0`-byte `staging/<id>` without `set_len(0)` when `payload_ino IS NULL`; on `.reclaim.<id>` detaching without `set_len(0)` when `state = 'released' AND reclaim_state = 'anchor_pending_unlink'`; serializing zero-row orphans via `storage_volume_control FOR SHARE -> storage_instance FOR UPDATE`), and **`artifact_fs::purge_due`** (`begin_purge` joining `storage_reservations` requiring `NOT sr.adoption_unverified AND sr.payload_ino IS NOT NULL`, verifying `revisions/<id>` `st_ino == payload_ino` before `set_len(0)` + `sync_all()` + `unlinkat`, also checking `staging/<id>` and detaching any hard-link alias with `st_ino == payload_ino` via `LOCK_EX` `set_len(0)` + `sync_all()` + `unlinkat` while leaving foreign `staging/<id>` untouched, and unconditionally executing **BOTH `fsync(&revisions_dir_fd)` AND `fsync(&staging_dir_fd)`** strictly before `storage::confirm_purge`), paired with a strictly inline read-only `artifact.read_range` tool and `ReadWriteMany` qualification requiring `O_CREAT \| O_EXCL \| O_NOFOLLOW`, `rustix::fs::linkat` (`Errno::EXIST`), `fsync`, two-client `flock(2)` exclusion, and stable 64-bit `st_ino` coherence + second-client recovery across clients and remounts. |

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
reads `[offset, offset + len)` via `artifact_fs::Store::read` (which verifies
`sr.adoption_unverified = false`, local same-mount `file_meta.dev() == revisions_dir_fd_meta.dev() ==
root_fd_meta.dev()`, and `file_meta.ino() == sr.payload_ino` whenever `sr.payload_ino IS NOT NULL`,
allowing `sr.payload_ino IS NULL` **only** while `storage_volume_control.volume_id IS NULL AND
adoption_run_id IS NULL`), trims any trailing split UTF-8
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
     o.logical_key = a.logical_key)`. PR3 updates `PENDING_EFFECT` to:
     `AND NOT EXISTS (SELECT FROM openmettle.operations o WHERE o.run_id = a.run_id AND o.logical_key = a.logical_key AND NOT (o.outcome = 'intent' AND o.dispatched_attempts = 0))`
     (while keeping `REQUEST.consumed` unchanged as `EXISTS (SELECT FROM openmettle.operations
     ...)` so HTTP `decide` still treats the approval as consumed!). Thus `worker::execute`'s
     `approvals::pending_effect` (`src/worker.rs:519`) immediately discovers `(approval_id,
     proposal)` for a consumed human approval whose operation is still `outcome = 'intent' AND
     dispatched_attempts = 0`!
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
        `Instant::now() >= step.deadline.min(lease_margin_deadline)` (while `Instant::now() <
        effect_deadline`) -> **never** call `Settle::Stopped` directly with a live
        `dispatched_attempts = 0` write `'intent'`! Add explicit **`WorkEnd::Handoff`** to
        `WorkEnd` in `src/worker.rs` (returned on `StartPermit::LeaseMarginExhausted` in both
        `worker::execute`'s `pending_effect` path and `Executor::step`, and routed in `run_one`
        at `src/worker.rs:661-675` to **`leases::handoff(&mut c, &lease, &settings).await`**
        whenever `cause != Some(Stop::LeaseLost)`), and update **`leases::handoff`**
        (`src/authz/leases.rs:503-535`, under `Fence::Hold`) to check
        **`time_to_reclaim = execution_expires_at > clock_timestamp() + $3::bigint * interval '1
        millisecond'`** (`settings.lease` — the **exact** `reclaim_next` (`src/authz/leases.rs:595`)
        and `SETTLEMENT_INPUTS` `time_to_reconcile` (`src/authz/leases.rs:497`) predicate!):
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
     `StepResult` in **PR2** alongside **`StepResult::Invalidated(leases::Settled)`** —
     mapping `StepResult::LeaseLost` in `worker::execute` (`src/worker.rs`) to
     `WorkEnd::Stop(Stop::LeaseLost)` so `run_one` exits at `src/worker.rs:652` without
     touching PostgreSQL, while mapping `StepResult::Invalidated(settled)` directly to
     `WorkEnd::Invalidated(settled)` so `Settled::Reconciling { .. }` immediately executes
     `leases::release_lease(&mut c, &lease)` at `src/worker.rs:660-663`!). On an expired or
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
  and `StartPermit::LeaseMarginExhausted` returns explicit **`WorkEnd::Handoff`**, both routed
  in `run_one` (`src/worker.rs:661-675`) to **`leases::handoff(&mut c, &lease, &settings)`**
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

- **Dedicated read-mostly singleton `openmettle.storage_volume_control` (eliminating `FOR SHARE
  -> FOR NO KEY UPDATE` self-upgrade deadlocks on `storage_instance`).** `storage::adjust`
  (`src/storage.rs:289-310`) updates `storage_accounts -> storage_instance` (`FOR NO KEY
  UPDATE`) on every `reserve`, `settle`, `release`, and `confirm_purge`. Taking `FOR SHARE` on
  `storage_instance` earlier in `reserve` or inside `enforce_runtime_storage_volume_pinned()`
  would cause two concurrent reserves or releases to hold `FOR SHARE` and deadlock trying to
  upgrade `storage_instance` to `FOR NO KEY UPDATE`. `V1-17` PR2 therefore keeps only
  `warn_pct_1`, `warn_pct_2`, and `config_revision` added to `openmettle.storage_instance`'s
  byte counters, and moves `(volume_id, bootstrap_auto_pin_allowed, adoption_run_id)` onto a
  dedicated 1-row read-mostly control table **`openmettle.storage_volume_control`**:

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
  GRANT UPDATE (volume_id, bootstrap_auto_pin_allowed) ON openmettle.storage_volume_control TO openmettle_api;
  ```

  Runtime `reserve`, `settle`, `release`, and `purge` **ONLY ever take `FOR SHARE` on
  `openmettle.storage_volume_control`** and **NEVER `UPDATE` `storage_volume_control`** — only
  `openmettle-admin` adoption and one-time empty-ledger `Store::open` bootstrap acquire `FOR
  UPDATE` on `storage_volume_control`. Because `FOR SHARE` is 100% compatible with `FOR SHARE`,
  concurrent reserves, settles, releases, and purges have zero `FOR SHARE -> FOR NO KEY UPDATE`
  lock-upgrade deadlocks!
- **Canonical storage lock order:** **`runs -> storage_reservations -> artifacts ->
  artifact_revisions -> storage_volume_control -> storage_accounts -> storage_instance`**.
  - In `publish_bytes` Phase 1a (`storage::reserve`): lock `runs (FOR NO KEY UPDATE) ->
    storage_volume_control (FOR SHARE) -> storage_accounts (FOR UPDATE) -> storage_instance
    (FOR UPDATE) -> INSERT storage_reservations`.
  - In Cleaner Step 3 (`storage::release`): lock `(runs FOR NO KEY UPDATE ->)
    storage_reservations (FOR UPDATE)` -> `UPDATE storage_reservations` fires
    `enforce_runtime_storage_volume_pinned()` taking **`storage_volume_control (FOR SHARE)`** ->
    `storage::adjust()` updates **`storage_accounts (FOR UPDATE) -> storage_instance (FOR
    UPDATE)`**.
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
      publish_pending)`.
  - Runtime grants on `openmettle.storage_reservations` (`src/boundaries.sql`):
    `GRANT INSERT (lease_expires_at, stage_claimed) ON openmettle.storage_reservations TO
    openmettle_api, openmettle_worker;` and `GRANT UPDATE (lease_expires_at,
    adoption_unverified, stage_claimed, payload_ino, publish_pending, reclaim_state,
    reclaim_claim_token, reclaim_lease_until) ON openmettle.storage_reservations TO
    openmettle_api, openmettle_worker;`.
- PostgreSQL **`SECURITY INVOKER`** triggers (`SET search_path = pg_catalog`) in `V1-17` PR2:
  - **`openmettle.enforce_runtime_storage_volume_pinned()`** (`BEFORE UPDATE` on
    `storage_reservations` `WHEN (OLD.state = 'reserved' AND NEW.state = 'released')` and
    `artifact_revisions` `WHEN (NEW.state IN ('purging', 'purged'))`), failing closed with
    `OMQ03` if the `storage_volume_control` singleton row is missing (`IF NOT FOUND`), unpinned
    (`v_vol IS NULL`), or under adoption (`v_adopt IS NOT NULL`):

    ```sql
    CREATE FUNCTION openmettle.enforce_runtime_storage_volume_pinned()
    RETURNS trigger
    LANGUAGE plpgsql
    SECURITY INVOKER
    SET search_path = pg_catalog
    AS $$
    DECLARE
        v_vol uuid;
        v_adopt uuid;
    BEGIN
        IF NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE') THEN
            SELECT volume_id, adoption_run_id
              INTO v_vol, v_adopt
              FROM openmettle.storage_volume_control
             WHERE id
               FOR SHARE;
            IF NOT FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL THEN
                RAISE EXCEPTION 'runtime storage release and purge require pinned, non-adopting storage_volume_control.volume_id'
                    USING ERRCODE = 'OMQ03';
            END IF;
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
**every** `spawn_blocking` closure (Phase 1b, Phase 2, and Phase 3's pre-commit check), binds
**all** spill creation, publication, stat and directory sync operations strictly to
`artifact_fs::Store`'s `V1-17` PR2
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
calling `abort()` or replacing `fs::rename`!), and executes the exact **Phase 1a -> 1b -> 2 -> 3
+ post-commit detach** lifecycle (100% safe Rust 1.100 `std::fs` +
`std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, MetadataExt}` + `V1-17` PR2's `rustix::fs`
under `unsafe_code = "forbid"`):

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
   the canonical lock order **`runs (FOR NO KEY UPDATE) -> storage_volume_control (FOR SHARE) ->
   storage_accounts (FOR UPDATE) -> storage_instance (FOR UPDATE) -> INSERT
   storage_reservations`**: execute `SELECT volume_id, adoption_run_id FROM
   openmettle.storage_volume_control WHERE id FOR SHARE` and verify `FOUND AND volume_id =
   $expected_volume_id AND adoption_run_id IS NULL` (if missing, `volume_id IS NULL`, or
   `adoption_run_id IS NOT NULL`, abort Phase 1a cleanly, drop `OwnedSemaphorePermit`, and fall
   back immediately to inline `storage: "truncated_no_spill"` with `spill_error: "storage_io"`),
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
2. **Phase 1b — Permit-owning `spawn_blocking` creation & durable sync of 0-byte
   `staging/<reservation_id>` outside DB tx, then commit write-once `payload_ino` +
   `publish_pending = true`.** Check `Instant::now() < step.deadline &&
   step.stop.borrow().is_none()`; if already false, drop `OwnedSemaphorePermit` (leaving zero
   files on disk and the Phase-1a `payload_ino IS NULL` row for `reconcile_run_spills` Subcase
   B) and apply the spill-abort disposition rule below. Otherwise **move `spill_permit:
   OwnedSemaphorePermit` directly INTO Phase 1b's `spawn_blocking` closure** (strictly outside
   any DB transaction, matching Phase 2 and returning `(payload_file, staged_ino, spill_permit)`
   on uncancelled completion — so if cutoff or timeout fires while Phase 1b is stalled in
   `openat` or `fsync(&staging_dir_fd)`, `spill_permit` stays held inside that detached blocking
   task until `spawn_blocking` exits and drops `(payload_file, spill_permit)`, strictly bounding
   concurrent blocking tasks across Phases 1b/2/3 to `max_concurrent_runs`), raced in
   `tokio::select!` against `tokio::time::sleep_until(step.deadline)` and `step.stop.changed()`
   via a shared `Arc<AtomicBool>` (`cancelled = false`):
   - **Pre-`openat` directory-descriptor + role-tagged sentinel re-verification, `openat`,
     `LOCK_SH`, local `st_dev` + `staged_ino` verification, and `fsync(&staging_dir_fd)`:**
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
     acquire **`payload_file.try_lock_shared()`** (`LOCK_SH | LOCK_NB`), verify
     `file_meta = payload_file.metadata()?` vs `rustix::fs::statat(&staging_dir_fd, id,
     AtFlags::SYMLINK_NOFOLLOW)` (`S_ISREG`, host-local same-mount `file_meta.dev() ==
     staging_dir_meta.dev() == root_fd_meta.dev()`, `staged_ino = file_meta.ino()`,
     `stat.st_ino as u64 == staged_ino`), **execute `rustix::fs::fsync(&staging_dir_fd)`**
     (making the `staging/<reservation_id>` directory entry crash-durable **BEFORE** binding
     `payload_ino` in PostgreSQL!), and return `(payload_file, staged_ino, spill_permit)` on
     uncancelled completion (dropping `(payload_file, spill_permit)` inside the closure on
     cancellation or error with zero `set_len(0)` and zero `unlinkat`).
   - **Short `Fence::Step` DB bind of write-once `payload_ino` + `publish_pending = true`:**
     After `spawn_blocking` returns `(payload_file, staged_ino, spill_permit)` (and re-checking
     `Instant::now() < step.deadline && step.stop.borrow().is_none()`), run a short
     `leases::with_lease(..., Fence::Step, ...)` transaction locking `storage_reservations FOR
     UPDATE` -> `SELECT volume_id, adoption_run_id FROM openmettle.storage_volume_control WHERE
     id FOR SHARE` (`FOUND AND volume_id = $expected_volume_id AND adoption_run_id IS NULL`),
     and commit **`UPDATE openmettle.storage_reservations SET payload_ino =
     $3::text::numeric(20, 0), publish_pending = true WHERE scope_id = $1::uuid AND id =
     $2::uuid AND state = 'reserved' AND NOT adoption_unverified AND stage_claimed AND
     payload_ino IS NULL AND reclaim_state = 'none'`** (zero disk I/O inside the DB transaction;
     `enforce_storage_reservation_monotonic_guards()` guarantees `payload_ino` is write-once and
     never modified or cleared thereafter).
   - **Zero `set_len(0)` and zero `unlinkat` on ANY Phase 1b error, cancellation, or lost commit
     ack:** If cutoff fires during Phase 1b `spawn_blocking` (detaching the blocking handle
     while it retains `spill_permit` until exit), if `UPDATE` affects `0` rows or fails
     deterministically, or if the DB commit experiences a lost commit acknowledgement, **do NOT
     call `set_len(0)` and do NOT call `unlinkat`** — simply **`drop(payload_file)`** (pure
     `close()`, releasing `LOCK_SH`) and **`drop(spill_permit)`**, deferring all disk cleanup
     exclusively to `reconcile_run_spills` (which handles both committed `payload_ino =
     staged_ino` via Subcase A1 and uncommitted `payload_ino IS NULL` 0-byte `staging/<id>` via
     Subcase B safely under `LOCK_EX`!), and apply the spill-abort disposition rule below.
3. **Phase 2 — Unfenced `spawn_blocking` payload write + `linkat` no-replace publish keeping
   `staging/<id>` linked until Phase 3 commits (strictly outside any DB transaction, zero
   sidecar `.lock` file, zero `unlinkat` / `set_len(0)`).** Check `Instant::now() <
   step.deadline && step.stop.borrow().is_none()` before spawning; if already false,
   `drop(payload_file)` (closing `LOCK_SH`) and `drop(spill_permit)` with zero `set_len(0)` and
   zero `unlinkat` (leaving `staging/<id>` for `reconcile_run_spills` Subcase A1) and apply the
   spill-abort disposition rule below. Otherwise allocate a fresh shared `Arc<AtomicBool>`
   (`cancelled = false`), move `payload_file`, `staged_ino`, `Arc`-cloned `(root_fd,
   staging_dir_fd, revisions_dir_fd)`, and `spill_permit: OwnedSemaphorePermit` into Phase 2's
   `spawn_blocking` closure, raced in `tokio::select!` against
   `tokio::time::sleep_until(step.deadline)` and `step.stop.changed()`:
   - Check `cancelled.load(Ordering::Acquire)` before writing and before each `<= 64 KiB` chunk,
     write `payload` into `payload_file` while computing SHA-256, call
     **`payload_file.sync_all()?`**, and perform a final pre-`linkat`
     `cancelled.load(Ordering::Acquire)` check.
   - **Pre-`linkat` three-directory identity, sentinel, and leaf `staged_ino` re-verification:**
     Strictly before publishing (while holding `LOCK_SH`), re-open `<root>` by path and
     `"staging"` / `"revisions"` relative to that fresh root FD (`OFlags::RDONLY |
     OFlags::DIRECTORY | OFlags::NOFOLLOW`), verify host-local same-mount `st_dev` equality and
     pinned `(st_dev, st_ino)` match against `(root_fd, staging_dir_fd, revisions_dir_fd)`,
     verify role-tagged `.openmettle-volume-id` sentinels (`:root`, `:staging`, `:revisions`),
     and verify `rustix::fs::statat(&staging_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` is
     `S_ISREG` with local `st_dev` match, `st_ino as u64 == staged_ino`, and `st_size ==
     size_bytes` (`payload.len() as i64`).
   - **Atomic non-overwriting publish via `rustix::fs::linkat` (mixed-version `N-1` retry
     protection!):** If `cancelled == false` and re-verification succeeds, keep `LOCK_SH`
     continuously across **`rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id,
     AtFlags::empty())`** (mandatory POSIX/NFS `LINK`, which **atomically fails with
     `Errno::EXIST` (`EEXIST`) without overwriting any pre-existing `revisions/<id>`** AND
     **keeps `staging/<id>` linked on disk throughout the entire pre-settlement `state =
     'reserved'` window**!). Because **`staging/<id>` stays present on disk** until
     `storage::settle` commits `state = 'settled'` (including if the `N` writer crashes after
     `linkat` and before `storage::settle`), any same-key retry routed to an **`N-1` API
     replica** hits `store.stage(&id)` -> `OpenOptions::create_new(true)` (`src/artifact_fs.rs:474`)
     -> `ErrorKind::AlreadyExists` -> **`Err(Error::InProgress)` (`src/artifact_fs.rs:475`)**
     and returns immediately **without** calling `abort()`, **without** creating a new staging
     file, and **without** calling replacing `fs::rename`! On `Errno::EXIST` or any
     directory/sentinel/leaf-inode mismatch: **ZERO `set_len(0)` and ZERO `unlinkat`**; drop
     `payload_file` and `spill_permit`, disable Phase 3, commit quarantine `UPDATE
     openmettle.storage_reservations SET adoption_unverified = true, publish_pending = false
     WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved' AND NOT
     adoption_unverified AND reclaim_state = 'none'` (retaining write-once `payload_ino`), and
     take the inline `storage: "truncated_no_spill"` fallback.
   - **Post-`linkat` durable directory `fsync` + post-`linkat` verification (retaining
     `payload_file` with `LOCK_SH` into Phase 3):** After `linkat` returns `Ok(())`, execute
     **`rustix::fs::fsync(&revisions_dir_fd)`** (never calling `unlinkat` or `set_len(0)` if
     `cancelled` turns `true` or `fsync` fails!), then re-verify `<root>`, `"staging"`,
     `"revisions"` (local `st_dev`, pinned `(st_dev, st_ino)`, and role-tagged sentinels) +
     `rustix::fs::statat(&revisions_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` (`S_ISREG`, local
     `st_dev` match, `st_ino as u64 == staged_ino`, `st_size == size_bytes`), and — on
     uncancelled success — **return `(payload_file, spill_permit)` out of Phase 2 into Phase 3**
     while still holding `LOCK_SH` on `payload_file` (dropping `(payload_file, spill_permit)`
     inside Phase 2 only on cancellation or error).
   - **Cutoff fires before `spawn_blocking` completes (raced detach):** Set
     `cancelled.store(true, Ordering::Release)`, detach the `JoinHandle` (the detached closure
     keeps holding `LOCK_SH` on `payload_file` and `spill_permit` until it exits, performing
     **zero `set_len(0)` and zero `unlinkat`**!), unconditionally disable Phase 3, leave
     `<reservation_id>` in `state = 'reserved'` (`payload_ino = staged_ino, publish_pending =
     true`, `max_bytes` charged), and immediately run the inline `storage:
     "truncated_no_spill"` fallback. Once `payload_file` closes (or the worker crashes),
     `reconcile_run_spills` reclaims the verified `payload_ino` file from `staging/<id>` and
     `revisions/<id>` using the 4-step `LOCK_EX` `staging/.reclaim.<id>` protocol below.
     Immediately after normal uncancelled `spawn_blocking` completion, re-check
     `Instant::now() < step.deadline && step.stop.borrow().is_none()`; if false, drop
     `(payload_file, spill_permit)` (pure `close()`, zero `set_len(0)`, zero `unlinkat`), skip
     Phase 3 (leaving `<reservation_id>` in `state = 'reserved'` for `reconcile_run_spills`),
     and apply the spill-abort disposition rule below.
4. **Phase 3 — Single atomic `Fence::Step` settlement (`storage::settle` +
   `runs::record_observation`) with permit-bounded, time-bounded pre-`commit` verification,
   followed by post-`commit` best-effort detach of `staging/<id>`.** Borrow a connection and
   open **one** short `leases::with_lease(..., Fence::Step, ...)` transaction (`SET LOCAL
   idle_in_transaction_session_timeout = '5s'`, zero bulk disk I/O inside the transaction).
   Re-check `Instant::now() < step.deadline && step.stop.borrow().is_none()` **after** acquiring
   the `Fence::Step` DB lock and **before** executing `storage::settle` or
   `runs::record_observation`. Inside that **exact same `Fence::Step` PostgreSQL transaction** —
   following the canonical lock order **`runs -> storage_reservations -> artifacts ->
   artifact_revisions -> storage_volume_control -> storage_accounts -> storage_instance`** —
   execute **both** `storage::settle` **and** `runs::record_observation` atomically.
   `storage::settle` (`src/storage.rs:362-379`, tested by `tests/schema/artifact_fs.rs:434`)
   preserves its existing `ReservationState::Settled` idempotent metadata-matching replay branch
   intact, and on its `ReservationState::Reserved` settlement branch strictly requires
   **`state = 'reserved' AND NOT adoption_unverified AND payload_ino = $staged_ino AND
   reclaim_state = 'none'`** (along with `SELECT volume_id, adoption_run_id FROM
   openmettle.storage_volume_control WHERE id FOR SHARE` verifying `FOUND AND volume_id =
   $expected_volume_id AND adoption_run_id IS NULL`), inserts the immutable `artifact_revisions`
   row, charges active quota (`storage_accounts -> storage_instance`), and commits **`state =
   'settled', publish_pending = false`** (**retaining write-once `payload_ino`**, never clearing
   it — enforced by `enforce_storage_reservation_monotonic_guards()`!). Once Step 1 of
   `reconcile_run_spills` commits `reclaim_state != 'none'` (or if `adoption_unverified =
   true`), a stalled Phase 3 observes `reclaim_state != 'none'` or `adoption_unverified = true`
   under `FOR UPDATE`, fails closed with `Error::Conflict`, rolls back **both** `storage::settle`
   and `runs::record_observation`, drops `(payload_file, spill_permit)` via pure `close()` (zero
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
   3. **Post-`commit` best-effort detach of `staging/<id>` alias (strictly AFTER Phase 3's
      `COMMIT` succeeds):** Once Phase 3 returns confirmed `Ok(...)`, while still holding
      `LOCK_SH` on `payload_file` (fencing `StagingSweepState` and `artifact_fs::purge_due`,
      which require `LOCK_EX`, while `state = 'settled'` and `stage_claimed = true` prevent any
      `N-1` or `N` writer from creating `staging/<id>`), run a bounded best-effort
      `spawn_blocking` detach holding `(payload_file, spill_permit)`: verify
      `statat(&staging_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` has `S_ISREG`, local `st_dev`,
      and **`st_ino as u64 == staged_ino`** AND `statat(&revisions_dir_fd, id,
      AtFlags::SYMLINK_NOFOLLOW)` has `S_ISREG`, local `st_dev`, and **`st_ino as u64 ==
      staged_ino`**; call **`rustix::fs::unlinkat(&staging_dir_fd, id, AtFlags::empty())`**
      (**NEVER `set_len(0)`!**) -> `drop(payload_file)` ->
      **`rustix::fs::fsync(&staging_dir_fd)`** -> `drop(spill_permit)`. (If the process crashes
      or times out before this post-commit detach completes, `StagingSweepState` `'settled'` and
      `artifact_fs::purge_due` detach `staging/<id>` safely.)
   **Phase 3 lost commit acknowledgement / cancellation safety:** If Phase 3's `COMMIT`
   experiences a lost commit acknowledgement, error, or cancellation, `publish_bytes` MUST NOT
   enter post-commit detach — it executes **pure `drop(payload_file)` (`close()` only — ZERO
   `set_len(0)` and ZERO `unlinkat`!)** and `drop(spill_permit)`, so a lost commit
   acknowledgement can **never** zero or unlink a settled artifact! Any recovery checks
   `storage_reservations` under `runs FOR NO KEY UPDATE -> storage_reservations FOR UPDATE`
   (`state == 'settled'` -> already published, `StagingSweepState`/`purge_due` safely detach any
   remaining `staging/<id>` hard-link alias; `state == 'reserved'` -> `reconcile_run_spills`
   reclaims safely under the 4-step `staging/.reclaim.<id>` protocol). On replay of an
   already-`succeeded` operation, the adapter reads `(artifact_id, revision_id)` from the
   committed observation evidence (after fenced primary
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
    2. **Graceful shutdown and explicit `WorkEnd::Handoff` lease-margin handoff aligned with
       `reclaim_next` -> clean successor reclaim in `Running` (`src/worker.rs:498-505,
       661-675`, `src/authz/leases.rs:412, 497, 503-535, 595`):**
       - Add **`WorkEnd::Handoff`** to `WorkEnd` in `src/worker.rs`, returned on
         `StartPermit::LeaseMarginExhausted` (in both `worker::execute`'s `pending_effect` path
         and `Executor::step`) and routed in `run_one` (`src/worker.rs:661-675`) alongside
         `WorkEnd::Stop(Stop::Shutdown)` to **`leases::handoff(&mut c, &lease, &settings)`**
         whenever `cause` is not `Some(Stop::LeaseLost)`.
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
           `approvals::pending_effect` (`src/worker.rs:519`), whose updated `PENDING_EFFECT`
           SQL (`src/authz/approvals.rs:1241`, `AND NOT EXISTS (... AND NOT (o.outcome =
           'intent' AND o.dispatched_attempts = 0))` while keeping `REQUEST.consumed` unchanged
           so HTTP `decide` still treats the approval as consumed) immediately discovers
           `(approval_id, proposal)` and calls `approvals::record_fenced_intent(...,
           Some(approval_id), ...)`.
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
adoption_run_id)`** (keeping only `warn_pct_1`, `warn_pct_2`, `config_revision` added to
`storage_instance`, enforcing the canonical storage lock order **`runs -> storage_reservations
-> artifacts -> artifact_revisions -> storage_volume_control -> storage_accounts ->
storage_instance`** so runtime `FOR SHARE` on `storage_volume_control` never deadlocks against
`storage::adjust`'s `FOR NO KEY UPDATE` on `storage_instance`),
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
timestamptz`** with their 4 `CHECK` constraints), `V1-17` PR2's `SECURITY INVOKER` triggers
**`openmettle.enforce_runtime_storage_volume_pinned()`** (`OMQ03`, failing closed on `IF NOT
FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL` from `openmettle.storage_volume_control WHERE id
FOR SHARE`) and **`openmettle.enforce_storage_reservation_monotonic_guards()`** (`OMQ03`
forbidding non-`openmettle_owner` clearing of `adoption_unverified`, modifying/clearing non-null
`payload_ino`, or clearing `stage_claimed`), `V1-17` PR2's
`storage_reservations_tool_spill_binding_guard` trigger (`23514`), and `artifact_fs`'s
`rustix`-backed (`default-features = false, features = ["fs", "std"]`, 100% safe Rust under
`unsafe_code = "forbid"`, adding zero new Cargo crates beyond `V1-17` PR2) verified
directory-descriptor infrastructure (`root_fd`, `staging_dir_fd`, `revisions_dir_fd`). Because
`artifact_fs::reconcile_expired` scans only upload reservations (`run_id IS NULL`) and `run_id
IS NOT NULL` matches all run-linked reservations (not only spills), **exact-complement
cross-ADR partition invariant**: **`V1-14` (`artifact_fs::reconcile_run_spills`, including its
`state = 'released'` anchor-detach/retry pass) is the sole automatic cleanup owner of
`operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%'` rows**, and **`V1-17`
([ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md))'s generic
run-linked `storage_reservations` cleaner uses the exact logical complement `run_id IS NOT
NULL AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')`** (owning any
legacy pre-upgrade malformed `tool-spill:%` row with `operation_id IS NULL` so there is zero
unowned gap, while never releasing quota while ADR 0039's detached streaming writer still
holds `LOCK_SH` on `staging/<id>` and never preserving an unsettled `revisions/<id>` instead
of reclaiming it), and `V1-17` PR2's `storage_reservations_tool_spill_binding_guard` trigger
(`23514`) forbids inserting or updating `idempotency_key LIKE 'tool-spill:%'` with `run_id IS
NULL OR operation_id IS NULL`. `artifact_fs::reconcile_run_spills` runs in the worker
maintenance sweep using the exact **unified 4-step crash-safe & replacement-safe reclamation
protocol** (preserving `payload_ino` allocation via `staging/.reclaim.<id>` across cleanup so
there is **zero inode-reuse window** before Step 3 commits!) shared by all 4 cleaners
(`artifact_fs::abort`, `reconcile_expired`, generic run-linked cleaner, and
`reconcile_run_spills`), with zero post-terminal `run_events` appends and **zero filesystem I/O
inside any DB transaction**:

- Scan exclusively adapter-owned spill reservations matching `operation_id IS NOT NULL AND
  idempotency_key LIKE 'tool-spill:%'` across `state = 'reserved'` and `state = 'released'`
  (**excluding `adoption_unverified = true` in both states**, i.e., `AND NOT
  adoption_unverified`, and strictly requiring `storage_volume_control.volume_id IS NOT NULL AND
  adoption_run_id IS NULL`). Never touch `state = 'settled'` rows during spill reconciliation;
  settled revisions are deleted only by `artifact_fs::purge_due` after retention expiry.
- **Spill reservation TTL/age guard.** `openmettle.storage_reservations` records `created_at`
  (`migrations/0004_artifacts_storage_accounting.sql`, with no `expires_at` column). Mirroring
  `artifact_fs::reconcile_expired`'s `older_than` threshold (`src/artifact_fs.rs`),
  `reconcile_run_spills` only sweeps a `state = 'reserved'` `tool-spill:*` row once
  `created_at + spill_reservation_ttl <= clock_timestamp()`. `spill_reservation_ttl` is defined
  strictly against the **bounded foreground tool call deadline (`call_timeout` /
  `step.deadline`) plus `run_one`'s bounded worker drain window (`settings.lease / 6`) plus a
  fixed safety margin (default `900 s`)**, ensuring `reconcile_run_spills` never claims an
  active foreground spill early. Payload safety past `spill_reservation_ttl` relies strictly on
  `payload_file`'s continuous `LOCK_SH` blocking sweeper `File::try_lock()` (`LOCK_EX |
  LOCK_NB`) until the writer exits or crashes.
- **Unified 4-step crash-safe & replacement-safe reclamation protocol (`reconcile_run_spills`
  and all ADR 0040 cleaners — zero inode-reuse window via `staging/.reclaim.<id>` +
  `anchor_pending_unlink`):** Unlinking the last link of `payload_ino` and closing the FD
  before Step 3 commits would allow the filesystem to reassign `payload_ino` to a newly created
  foreign file at `<id>` if the cleaner crashed before Step 3. All 4 cleaners therefore preserve
  `payload_ino` allocation via a dedicated hard-link anchor **`staging/.reclaim.<id>`**
  (`reclaim_name = format!(".reclaim.{id}")`) until AFTER Step 3 commits `'released'`:
  1. **Step 1 — Serialized DB Claim BEFORE any truncation/unlink (zero FS I/O inside DB tx):**
     Open a short lock-ordered DB transaction (`openmettle.runs FOR NO KEY UPDATE SKIP LOCKED`
     -> `openmettle.storage_reservations FOR UPDATE SKIP LOCKED` -> **`SELECT volume_id,
     adoption_run_id FROM openmettle.storage_volume_control WHERE id FOR SHARE`**), strictly
     requiring `FOUND AND v_vol = $expected_volume_id AND v_adopt IS NULL` (aborting
     immediately with zero claims, zero unlinks, and zero releases if missing, `v_vol IS
     DISTINCT FROM $expected_volume_id`, or `v_adopt IS NOT NULL`). Require **`state =
     'reserved' AND NOT adoption_unverified AND (reclaim_state = 'none' OR reclaim_lease_until
     <= clock_timestamp())`** plus `reconcile_run_spills`'s path preconditions (`operation_id IS
     NOT NULL AND idempotency_key LIKE 'tool-spill:%'`, `created_at + spill_reservation_ttl <=
     clock_timestamp()`, zero `artifact_revisions` row, and terminal-run/inactive-lease or
     resolved `outcome IN ('succeeded', 'failed')` non-ambiguous operation). Mint a fresh UUID
     `$my_token` and commit: **`reclaim_state = CASE WHEN reclaim_state = 'truncated' THEN
     'truncated' ELSE 'claiming' END, reclaim_claim_token = $my_token, reclaim_lease_until =
     clock_timestamp() + interval '60 seconds'`** (keeping `state = 'reserved'` and `max_bytes`
     fully charged, and returning `(id, payload_ino, observed_state)`). Because Step 1 acquires
     `FOR UPDATE` on `storage_reservations` first and sets `reclaim_state != 'none'`, any
     in-flight `storage::settle` resolves before Step 2 can ever truncate, and no concurrent
     writer or second healthy cleaner can enter Step 2!
  2. **Step 2 — Durable `0`-Byte Truncation & `staging/.reclaim.<id>` Link Anchor (outside DB
     tx, `payload_ino` NEVER drops to `nlink = 0` before Step 3 commits, NEVER clearing
     write-once `payload_ino`!):**
     - **Mandatory pinned-volume & `adoption_run_id IS NULL` verification:** Before treating
       `ENOENT` as absence or touching any file, verify `Store`'s three directories (`root_fd`,
       `staging_dir_fd`, `revisions_dir_fd`) using `rustix::fs::openat` (`OFlags::RDONLY |
       OFlags::DIRECTORY | OFlags::NOFOLLOW`), verifying host-local same-mount `st_dev`
       equality (`staging_meta.dev() == revisions_meta.dev() == root_meta.dev()`) and
       regular-file `.openmettle-volume-id` sentinels (`:root`, `:staging`, `:revisions`
       matching `<expected_volume_id>` via `OFlags::RDONLY | OFlags::NOFOLLOW |
       OFlags::NONBLOCK` + `fstat` `S_ISREG`). Fail closed immediately with zero unlinks and
       zero releases on any mismatch or absence.
     - **Subcase A1 (`payload_ino IS NOT NULL` and `reclaim_state = 'claiming'`):**
       Probe `staging/<id>`, `revisions/<id>`, and `staging/.reclaim.<id>` via
       `rustix::fs::statat(dir_fd, name, AtFlags::SYMLINK_NOFOLLOW)`:
       1. If **any** existing entry is non-regular, wrong local `st_dev` (`stat.st_dev !=
          dir_fd_meta.dev()`), or **`stat.st_ino as u64 != payload_ino`** -> **ZERO
          `set_len(0)` and ZERO `unlinkat`**! Commit quarantine (`SET adoption_unverified =
          true, publish_pending = false, reclaim_state = 'none', reclaim_claim_token = NULL,
          reclaim_lease_until = NULL`) in a short lock-ordered `FOR UPDATE` tx
          (`storage_volume_control FOR SHARE` verifying `FOUND AND v_vol = $expected_volume_id
          AND v_adopt IS NULL`) re-verifying **`state = 'reserved' AND NOT adoption_unverified
          AND reclaim_claim_token = $my_token AND reclaim_state = 'claiming' AND payload_ino =
          $expected_ino`** (leaving the foreign/replacement file untouched, `max_bytes` 100%
          charged, and write-once `payload_ino` intact!).
       2. If **all three** (`staging/<id>`, `revisions/<id>`, and `staging/.reclaim.<id>`)
          return confirmed `ENOENT` -> **quarantine** under the exact same `FOR UPDATE` guard
          **`state = 'reserved' AND NOT adoption_unverified AND reclaim_claim_token = $my_token
          AND reclaim_state = 'claiming' AND payload_ino = $expected_ino`** (ensuring a stale
          cleaner whose lease expired can NEVER quarantine a reservation already truncated or
          released by another cleaner!).
       3. When all existing entries match `S_ISREG`, same local `st_dev`, and `st_ino as u64 ==
          payload_ino`: open an existing matching candidate (`src_dir_fd`, `src_name`) with
          `OFlags::RDWR | OFlags::NOFOLLOW` -> `probe_file.try_lock()` (`LOCK_EX | LOCK_NB`;
          abort on `TryLockError::WouldBlock` with zero truncation/unlink, keeping `max_bytes`
          charged) -> re-verify under `LOCK_EX` that `probe_file.metadata().ino() ==
          payload_ino` and `statat` matches `S_ISREG`, local `st_dev == dir_fd_meta.dev() ==
          root_fd_meta.dev()`, and `st_ino as u64 == payload_ino` (quarantining untouched under
          the `$my_token` guard on any post-lock foreign mismatch):
          - **(i)** Call **`probe_file.set_len(0)?`** + **`probe_file.sync_all()?`** (`0` bytes
            crash-durable on disk!).
          - **(ii)** Create/verify hard-link anchor **`staging/.reclaim.<id>`**
            (`reclaim_name = format!(".reclaim.{id}")`): if `staging/.reclaim.<id>` is
            `ENOENT`, call **`rustix::fs::linkat(&src_dir_fd, src_name, &staging_dir_fd,
            &reclaim_name, AtFlags::empty())`** + **`rustix::fs::fsync(&staging_dir_fd)`**
            (`nlink` goes `1 -> 2` BEFORE unlinking `<id>`, so **`payload_ino` NEVER hits
            `nlink = 0` and CANNOT be reused by the filesystem!**).
          - **(iii)** While `staging/.reclaim.<id>` holds `nlink >= 1` and `probe_file` holds
            `LOCK_EX`: unlink any existing `<id>` entry in `revisions/<id>` and `staging/<id>`
            (re-verifying `statat(&dir_fd, id, AtFlags::SYMLINK_NOFOLLOW).st_ino as u64 ==
            payload_ino` immediately before each `unlinkat`) +
            `rustix::fs::fsync(&revisions_dir_fd)` + `rustix::fs::fsync(&staging_dir_fd)`.
          - **(iv)** Still holding `LOCK_EX` on `probe_file` (anchored at
            `staging/.reclaim.<id>`!), commit a short lock-ordered `FOR UPDATE` tx
            (`storage_volume_control FOR SHARE` active check, zero disk I/O inside DB tx)
            setting **`reclaim_state = 'truncated', publish_pending = false`** (`WHERE id =
            $1::uuid AND state = 'reserved' AND NOT adoption_unverified AND reclaim_claim_token
            = $my_token AND reclaim_state = 'claiming' AND payload_ino = $expected_ino` —
            **`payload_ino` remains non-null!**). If that short DB commit fails or affects `0`
            rows, drop `probe_file` and abort Step 2!
     - **Subcase A2 (`payload_ino IS NOT NULL` and `reclaim_state = 'truncated'` — crash
       recovery before Step 3):**
       - **NEVER truncate or unlink `staging/<id>` or `revisions/<id>` in `'truncated'`!** Any
         entry appearing at `staging/<id>` or `revisions/<id>` after `'truncated'` is preserved
         100% untouched!
       - Probe **`staging/.reclaim.<id>`** ONLY via `rustix::fs::statat(&staging_dir_fd,
         &reclaim_name, AtFlags::SYMLINK_NOFOLLOW)`: it MUST exist, be `S_ISREG`, same local
         `st_dev`, **`st_ino as u64 == payload_ino`**, AND **`st_size == 0`**. If `ENOENT`,
         non-regular, wrong local `st_dev`, `st_ino as u64 != payload_ino`, or `st_size != 0`
         -> **quarantine** under `FOR UPDATE` (`storage_volume_control FOR SHARE`) verifying
         `state = 'reserved' AND NOT adoption_unverified AND reclaim_claim_token = $my_token
         AND reclaim_state = 'truncated' AND payload_ino = $expected_ino` (zero `set_len(0)`,
         zero `unlinkat`).
       - Open `staging/.reclaim.<id>` (`OFlags::RDWR | OFlags::NOFOLLOW`) -> `LOCK_EX |
         LOCK_NB` -> re-verify `S_ISREG`, local `st_dev`, `st_ino as u64 == payload_ino`, and
         `st_size == 0` -> execute `rustix::fs::fsync(&staging_dir_fd)` +
         `rustix::fs::fsync(&revisions_dir_fd)` -> proceed to Step 3 (**keeping `probe_file`
         open with `LOCK_EX`**)!
     - **Subcase B (`payload_ino IS NULL` — reservation never bound a writer inode, e.g.,
       crashed after Phase 1a or `Store::stage` Step 1a/1b):**
       - If `revisions/<id>` exists (any type) OR `staging/<id>` exists and is non-regular,
         different local `st_dev`, or **`st_size > 0`**: **ZERO `set_len(0)` and ZERO
         `unlinkat`**! Commit quarantine (`SET adoption_unverified = true, publish_pending =
         false, reclaim_state = 'none', reclaim_claim_token = NULL, reclaim_lease_until =
         NULL`) under `FOR UPDATE` verifying `state = 'reserved' AND NOT adoption_unverified
         AND reclaim_claim_token = $my_token AND payload_ino IS NULL` (`storage_volume_control
         FOR SHARE` active check).
       - If `staging/<id>` is a `0`-byte regular file (`st_size == 0`, same local `st_dev`):
         open `OFlags::RDWR | OFlags::NOFOLLOW` -> `probe_file.try_lock()` (`LOCK_EX |
         LOCK_NB`) -> re-verify `S_ISREG`, same local `st_dev`, `st_size == 0`, and `statat ==
         probe_file` -> `rustix::fs::unlinkat(&staging_dir_fd, id, AtFlags::empty())` ->
         `drop(probe_file)`.
       - Execute unconditional `rustix::fs::fsync(&staging_dir_fd)` +
         `rustix::fs::fsync(&revisions_dir_fd)` -> proceed to Step 3!
  3. **Step 3 — Final `storage::release` (ZERO filesystem I/O inside DB tx in BOTH ADR 0039 and
     ADR 0040!):** Open a short lock-ordered DB transaction (`(runs FOR NO KEY UPDATE SKIP
     LOCKED ->) storage_reservations FOR UPDATE SKIP LOCKED`), strictly requiring **`state =
     'reserved' AND NOT adoption_unverified AND NOT publish_pending AND reclaim_claim_token =
     $my_token AND (payload_ino IS NULL OR reclaim_state = 'truncated')`** (plus path
     preconditions), setting **`reclaim_state = CASE WHEN payload_ino IS NOT NULL THEN
     'anchor_pending_unlink' ELSE 'none' END, reclaim_claim_token = NULL, reclaim_lease_until =
     NULL`**, and committing `storage::release` (**retaining write-once `payload_ino` on the
     `'released'` row**; `UPDATE storage_reservations` fires `V1-17` PR2's `SECURITY INVOKER`
     `enforce_runtime_storage_volume_pinned()` trigger taking **`storage_volume_control FOR
     SHARE`** and raising `OMQ03` if missing/unpinned/adopting, and `storage::adjust()` updates
     **`storage_accounts (FOR UPDATE) -> storage_instance (FOR UPDATE)`** with zero
     `FOR SHARE -> FOR NO KEY UPDATE` deadlock across concurrent releases and reserves, and
     zero post-terminal `run_events`). Because every abandoned `repeatable_read` (and every
     terminal `dispatched_attempts = 0` write) was transitioned to `outcome = 'failed'`
     strictly before `run-terminal`, `storage::release` succeeds cleanly after TTL on terminal
     runs while preserving `runs.last_event_sequence == terminal_sequence` (`204 No Content` on
     terminal SSE cursor reconnect) and continuing to fail closed with `Error::Unresolved` on
     any unresolved dispatched/legacy write (`outcome = 'outcome_unknown'` or `outcome =
     'intent'`).
  4. **Step 4 — Post-release detach of `staging/.reclaim.<id>` (strictly AFTER Step 3 commits
     `'released'`):** When `payload_ino IS NOT NULL` (still holding `probe_file` with
     `LOCK_EX`): verify `statat(&staging_dir_fd, &reclaim_name, AtFlags::SYMLINK_NOFOLLOW)` is
     `S_ISREG`, same local `st_dev`, `st_ino as u64 == payload_ino`, and `st_size == 0`; call
     **`rustix::fs::unlinkat(&staging_dir_fd, &reclaim_name, AtFlags::empty())`** (**NEVER
     `set_len(0)`**) -> `drop(probe_file)` -> **`rustix::fs::fsync(&staging_dir_fd)`** ->
     commit best-effort `UPDATE openmettle.storage_reservations SET reclaim_state = 'none' WHERE
     id = $1::uuid AND state = 'released' AND reclaim_state = 'anchor_pending_unlink'`. (If the
     cleaner crashes after Step 3 and before Step 4 completes, the `state = 'released'` retry
     pass and `StagingSweepState` safely finish detaching `staging/.reclaim.<id>` and clearing
     `reclaim_state = 'none'`.)
- **Adoption preservation of `'truncated'` holds (aligned verbatim with ADR 0040):** When
  `openmettle-admin` adoption scans `<root>/staging` and encounters a `'reserved'` row in
  `reclaim_state = 'truncated'`, if **`staging/.reclaim.<id>` exists as `S_ISREG` with
  `st_ino == payload_ino` and `st_size == 0`**, adoption **positively verifies and PRESERVES
  `reclaim_state = 'truncated'`** (setting `reclaim_lease_until = clock_timestamp()` so the
  next cleaner tick immediately completes Step 3 -> Step 4 without stranding quota in
  `adoption_unverified`; only if `staging/.reclaim.<id>` is missing or mismatched does adoption
  quarantine the row!).

- **Unified HTTP `Store::stage` / `Store::publish` / `Store::read` companion rules,
  defense-in-depth `state = 'released'` pass, shared `StagingSweepState`, and
  `artifact_fs::purge_due` hard-link alias detach:**
  - **Mixed-version rollout availability (aligned verbatim with ADR 0040):** HTTP
    `Store::stage` and `Store::publish` (`openmettle_api`) **succeed during mixed-version
    rolling upgrade while `storage_volume_control.volume_id IS NULL AND adoption_run_id IS
    NULL`** (skipping role-tagged sentinel reads while `volume_id IS NULL`, and verifying
    role-tagged sentinels `:root`, `:staging`, `:revisions` once `volume_id IS NOT NULL`),
    whereas worker `publish_bytes` and all 4 cleaners (`artifact_fs::abort`,
    `reconcile_expired`, generic run-linked cleaner, and `reconcile_run_spills`) strictly
    require **`volume_id IS NOT NULL AND adoption_run_id IS NULL`**!
  - **PR2 HTTP `Store::stage` / `Store::publish` (`src/artifact_fs.rs:144-158`) non-destructive
    staged-claim & `linkat` lifecycle:**
    - **Step 1a:** Under `FOR UPDATE` (`storage_volume_control FOR SHARE` verifying `FOUND AND
      adoption_run_id IS NULL`), commit **`stage_claimed = true`** requiring `state =
      'reserved' AND NOT adoption_unverified AND NOT stage_claimed AND payload_ino IS NULL AND
      reclaim_state = 'none'` BEFORE `openat`.
    - **Step 1b:** Re-verify `(root_fd, staging_dir_fd, revisions_dir_fd)` host-local
      same-mount `st_dev` (plus role-tagged sentinels when `volume_id IS NOT NULL`), open
      `staging/<id>` (`OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW`, `0`
      bytes, mode `0o600`) -> `file.try_lock_shared()` (`LOCK_SH | LOCK_NB`) -> capture
      `staged_ino` -> **`rustix::fs::fsync(&staging_dir_fd)`**.
    - **Step 1c:** Under `FOR UPDATE`, commit write-once **`payload_ino = staged_ino`**
      (`reclaim_state = 'none'`).
    - **`StagedFile::drop` is 100% non-destructive (`close` only — NEVER calls `set_len(0)`
      and NEVER calls `unlinkat`)!** Pre-publish commits `publish_pending = true` under `FOR
      UPDATE` (`state = 'reserved' AND NOT adoption_unverified AND payload_ino = $staged_ino
      AND reclaim_state = 'none'`), publishes via **`rustix::fs::linkat(&staging_dir_fd, id,
      &revisions_dir_fd, id, AtFlags::empty())`** (failing atomically with `Errno::EXIST`
      without overwriting any pre-existing `revisions/<id>` AND **keeping `staging/<id>` linked
      on disk throughout the entire pre-settlement `state = 'reserved'` window** so any `N-1`
      API retry hits `OpenOptions::create_new(true)` -> `Err(Error::InProgress)` at
      `src/artifact_fs.rs:474-475` without calling `abort()` or replacing `fs::rename`!) +
      `fsync(&revisions_dir_fd)` + post-`linkat` re-verification (`<root>`, `"staging"`,
      `"revisions"` + sentinels when pinned + `statat(&revisions_dir_fd, id)` `S_ISREG`, local
      `st_dev`, `st_ino as u64 == staged_ino`, `st_size == size_bytes`), settles `storage::settle`
      (`state = 'settled', publish_pending = false`, **retaining write-once `payload_ino`**!),
      and **strictly AFTER `storage::settle` commits** performs post-`commit` best-effort
      detach of `staging/<id>` while holding `LOCK_SH` (verifying `statat(&staging_dir_fd,
      id).st_ino == staged_ino` AND `statat(&revisions_dir_fd, id).st_ino == staged_ino` ->
      `unlinkat(&staging_dir_fd, id, AtFlags::empty())` with **NEVER `set_len(0)`** ->
      `drop(file)` -> `fsync(&staging_dir_fd)`). Ambiguous `storage::settle` commit NEVER calls
      `abort` and NEVER detaches; `abort` runs only on confirmed pre-settlement failure and
      uses the exact 4-step `LOCK_EX` `staging/.reclaim.<id>` protocol above!
  - **`Store::read` payload-inode verification:** `Store::read` verifies `sr.adoption_unverified
    = false`, local same-mount `st_dev` equality (`file_meta.dev() == revisions_dir_meta.dev()
    == root_fd_meta.dev()`), and **`file_meta.ino() == sr.payload_ino`** whenever
    `sr.payload_ino IS NOT NULL`; it allows `sr.payload_ino IS NULL` **only** while
    `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL` (pre-adoption legacy
    rows, since `openmettle-admin` adoption Step 3 backfills `payload_ino` on all verified
    `'active'`/`'retained'` revisions before pinning `volume_id`!).
  - **Defense-in-depth `state = 'released'` pass (exclusive to `operation_id IS NOT NULL AND
    idempotency_key LIKE 'tool-spill:%' AND NOT adoption_unverified`):** Select **`(id,
    payload_ino, reclaim_state)`** with `WHERE state = 'released' AND operation_id IS NOT NULL
    AND idempotency_key LIKE 'tool-spill:%' AND NOT adoption_unverified`, requiring
    `storage_volume_control.volume_id IS NOT NULL AND adoption_run_id IS NULL` +
    three-directory pinned volume verification. **NEVER call `set_len(0)` in this pass!**
    - When `payload_ino IS NOT NULL AND reclaim_state = 'anchor_pending_unlink'`: probe
      `staging/.reclaim.<id>` ONLY (**NEVER touch `staging/<id>` or `revisions/<id>`!**); if
      `staging/.reclaim.<id>` is `ENOENT`, clear `reclaim_state = 'none'`; if `S_ISREG` on same
      local `st_dev` with `st_ino as u64 == payload_ino` and `st_size == 0`, under `LOCK_EX`
      re-verify and call `unlinkat(&staging_dir_fd, &reclaim_name, AtFlags::empty())` ->
      `drop(probe_file)` -> `fsync(&staging_dir_fd)` -> `SET reclaim_state = 'none'`. Once
      `reclaim_state = 'none'`, skip untouched!
    - When `payload_ino IS NULL`: if `staging/<id>` is a `0`-byte regular file (`st_size == 0`,
      same local `st_dev`), under `LOCK_EX` re-verify `statat == probe_file` and `st_size == 0`
      and call `unlinkat(&staging_dir_fd, id, AtFlags::empty())` -> `drop(probe_file)` ->
      `fsync(&staging_dir_fd)`. Skip untouched if `st_size > 0`!
  - **Aged `> 900 s` orphan `staging/` sweep (shared with `V1-17` PR2's unified
    `StagingSweepState` in `worker::maintenance` — NEVER calls `set_len(0)` on `'settled'`,
    `'released'`, or `.reclaim.<id>`!):** `V1-14` PR2 shares `V1-17` PR2's single unified
    **`StagingSweepState`** in `worker::maintenance`, strictly requiring
    **`storage_volume_control.volume_id IS NOT NULL AND adoption_run_id IS NULL`** and exact
    three-directory pinned volume identity (`root_fd`, `staging_dir_fd`, `revisions_dir_fd`,
    local same-mount `st_dev`, role-tagged sentinels `:root`, `:staging`, `:revisions`).
    1. Strictly relative to `staging_dir_fd`, inspect UUID entries (`<id>`) and anchor entries
       (`.reclaim.<id>`): check `statat(&staging_dir_fd, entry_name, AtFlags::SYMLINK_NOFOLLOW)`
       is `S_ISREG` on the same local `st_dev`, open `OFlags::RDWR | OFlags::NOFOLLOW` ->
       `probe_file`, verify `probe_file.metadata()` matches `statat` (`staging_ino =
       probe_meta.ino()`, `staging_size = probe_meta.len()`), and acquire
       **`probe_file.try_lock()`** (`LOCK_EX | LOCK_NB`; skip immediately on `WouldBlock`).
    2. While holding `LOCK_EX`, query primary PostgreSQL **`SELECT state, adoption_unverified,
       payload_ino, reclaim_state FROM openmettle.storage_reservations WHERE id = $1::uuid`**.
       On zero rows (`None`), serialize against any in-flight `storage::reserve` `COMMIT` in
       canonical lock order via a short primary `READ COMMITTED` transaction executing
       **`SELECT volume_id, adoption_run_id FROM openmettle.storage_volume_control WHERE id FOR
       SHARE`** (asserting `FOUND && volume_id == Some(expected_volume_id) &&
       adoption_run_id.is_none()`) -> **`SELECT 1 FROM openmettle.storage_instance WHERE id FOR
       UPDATE`** followed by a separate subsequent `SELECT state, adoption_unverified,
       payload_ino, reclaim_state FROM openmettle.storage_reservations WHERE id = $1::uuid`.
    3. Disposition under `LOCK_EX` (after confirming `statat(&staging_dir_fd, entry_name,
       AtFlags::SYMLINK_NOFOLLOW)` is still `S_ISREG`, same local `st_dev`, and `st_ino as u64
       == staging_ino`):
       - **Any row with `adoption_unverified = true`** or **`state = 'reserved'`**: skip
         untouched (zero `set_len(0)`, zero `unlinkat`).
       - **On `staging/<id>` with `state = 'settled'` (`adoption_unverified = false`) — NEVER
         calls `set_len(0)`!:**
         - If `payload_ino IS NULL` OR **`staging_ino != payload_ino`**: **PRESERVE
           `staging/<id>` 100% UNTOUCHED (ZERO `set_len(0)`, ZERO `unlinkat`!)**! For example,
           in a two-reservation hard-link fixture where `staging/A` is hard-linked to active
           `revisions/B` while `revisions/A` matches `A.payload_ino`, `staging/A` has
           `staging_ino == B.payload_ino != A.payload_ino`, so `StagingSweepState` **preserves
           `staging/A` and `revisions/B` 100% untouched** (`B`'s bytes remain completely intact,
           and `verify_accounting_drift` flags the unexpected `staging/A` entry)!
         - When **`staging_ino == payload_ino`** (hard-link alias to `<id>`'s own settled
           payload): probe `statat(&revisions_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` and call
           **`rustix::fs::unlinkat(&staging_dir_fd, id, AtFlags::empty())`** (**NEVER
           `set_len(0)`!**) -> `drop(probe_file)` -> `rustix::fs::fsync(&staging_dir_fd)`
           **ONLY** when **EITHER** (i) `revisions/<id>` is `S_ISREG` on same local `st_dev`
           with **`rev_stat.st_ino as u64 == payload_ino`**, **OR** (ii) `revisions/<id>`
           returns `Errno::NOENT` AND a fresh `READ COMMITTED` `SELECT state FROM
           openmettle.artifact_revisions WHERE reservation_id = $1::uuid` returns
           **`Some('purged')`**. If `revisions/<id>` is `ENOENT` while `'active'`/`'retained'`/
           `'purging'`, or has `rev_stat.st_ino as u64 != payload_ino`, **preserve BOTH
           `staging/<id>` and `revisions/<id>` 100% untouched**!
       - **On `staging/<id>` with `state = 'released'` (`adoption_unverified = false`) — NEVER
         calls `set_len(0)`!:**
         - **If `payload_ino IS NOT NULL`: NEVER truncate or unlink `staging/<id>`!** (Every
           `payload_ino IS NOT NULL` reservation moved `<id>` to `staging/.reclaim.<id>` before
           `'released'` committed, so any file at `staging/<id>` — even if it reused a freed
           inode number — is foreign and preserved 100% untouched!)
         - If `payload_ino IS NULL` and **`staging_size == 0`**: call
           `rustix::fs::unlinkat(&staging_dir_fd, id, AtFlags::empty())` (**NEVER `set_len(0)`**)
           -> `drop(probe_file)` -> `rustix::fs::fsync(&staging_dir_fd)`. (Skip untouched if
           `staging_size > 0`!)
       - **On `staging/.reclaim.<id>` (`reclaim_name`) — NEVER calls `set_len(0)`!:**
         - When `state = 'released' AND reclaim_state = 'anchor_pending_unlink' AND NOT
           adoption_unverified AND payload_ino IS NOT NULL`: if `.reclaim.<id>` is `S_ISREG` on
           same local `st_dev` with **`staging_ino == payload_ino`** and **`staging_size ==
           0`**, call `rustix::fs::unlinkat(&staging_dir_fd, &reclaim_name, AtFlags::empty())`
           (**NEVER `set_len(0)`**) -> `drop(probe_file)` ->
           `rustix::fs::fsync(&staging_dir_fd)` -> commit `UPDATE openmettle.storage_reservations
           SET reclaim_state = 'none' WHERE id = $1::uuid AND state = 'released' AND
           reclaim_state = 'anchor_pending_unlink'` (and if `.reclaim.<id>` is already
           `ENOENT`, clear `reclaim_state = 'none'`). Once `reclaim_state = 'none'`, skip
           untouched!
       - **Confirmed zero rows (`None` after `storage_volume_control FOR SHARE ->
         storage_instance FOR UPDATE` with `volume_id == Some(expected_volume_id) &&
         adoption_run_id.is_none()`):** Execute `probe_file.set_len(0)?` ->
         `probe_file.sync_all()?` -> `unlinkat(&staging_dir_fd, entry_name, AtFlags::empty())`
         -> `drop(probe_file)` -> `fsync(&staging_dir_fd)`.
  - **`artifact_fs::purge_due` leaf `payload_ino` verification AND `staging/<id>` hard-link
    alias detach BEFORE `confirm_purge` (aligned verbatim with ADR 0040):**
    `storage::begin_purge` joins `openmettle.storage_reservations sr` to load
    `(reservation_id, size_bytes, sr.payload_ino, sr.adoption_unverified)`, requiring **`NOT
    sr.adoption_unverified AND sr.payload_ino IS NOT NULL`** (and firing
    `enforce_runtime_storage_volume_pinned()` taking `storage_volume_control FOR SHARE`).
    Strictly BEFORE `storage::confirm_purge`, `purge_due` checks **BOTH** `revisions/<id>` AND
    `staging/<id>` (after verifying `(root_fd, staging_dir_fd, revisions_dir_fd)` host-local
    same-mount `st_dev` and role-tagged sentinels):
    1. **On `revisions/<id>`:** Probe `statat(&revisions_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)`.
       If `revisions/<id>` exists and is non-regular, wrong local `st_dev`, or
       **`rev_stat.st_ino as u64 != payload_ino`** -> **STOP immediately with ZERO `set_len(0)`,
       ZERO `unlinkat`, and DO NOT call `confirm_purge`** (keeping `retained_bytes` charged!).
       If `rev_stat.st_ino as u64 == payload_ino`, open `OFlags::RDWR | OFlags::NOFOLLOW` ->
       `LOCK_EX` -> re-verify `st_ino as u64 == payload_ino` -> `set_len(0)?` + `sync_all()?`
       -> `unlinkat(&revisions_dir_fd, id, AtFlags::empty())` -> `drop`. (`ENOENT` is valid
       resumable mid-purge.)
    2. **On `staging/<id>`:** Probe `statat(&staging_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)`. If
       `staging/<id>` exists as `S_ISREG` on same local `st_dev` with **`staging_stat.st_ino as
       u64 == payload_ino`** (hard-link alias to the revision being purged, e.g., when
       `purge_due` runs *before* `StagingSweepState` after a post-commit crash!), open
       `OFlags::RDWR | OFlags::NOFOLLOW` -> `LOCK_EX` -> re-verify `st_ino as u64 ==
       payload_ino` -> `set_len(0)?` + `sync_all()?` -> **`unlinkat(&staging_dir_fd, id,
       AtFlags::empty())`** -> `drop`! (If `staging/<id>` has `staging_stat.st_ino as u64 !=
       payload_ino`, leave foreign `staging/<id>` 100% untouched!)
    3. Unconditionally execute **BOTH `rustix::fs::fsync(&revisions_dir_fd)` AND
       `rustix::fs::fsync(&staging_dir_fd)`** strictly BEFORE calling `storage::confirm_purge`!

- **Filesystem & `ReadWriteMany` shared-volume qualification (`linkat`, `flock(2)`, and
  cross-client stable 64-bit `st_ino`).** Startup, adoption, and shared-volume qualification
  require `O_CREAT | O_EXCL | O_NOFOLLOW`, mandatory POSIX/NFS **`rustix::fs::linkat`**
  (rejecting `ENOSYS`/`EOPNOTSUPP`/`EINVAL`/`EXDEV`/`EMLINK` fail-closed and proving a second
  `linkat` onto an existing destination returns `Errno::EXIST` without overwrite), and file +
  directory `fsync` (`sync_all`). For `ReadWriteMany` shared volumes across multiple
  pods/nodes, deployments MUST additionally qualify **both** two-client / separate-mount
  `flock(2)` (`LOCK_SH` vs `LOCK_EX | LOCK_NB` `WouldBlock`) exclusion **and** stable 64-bit
  `st_ino` coherence + second-client recovery verification across clients and remounts before
  enabling shared artifact/spill storage.

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
| PR2 | PR2's next sequential schema migration (e.g., `0024`) adding nullable `openmettle.operations.dispatched_attempts integer DEFAULT NULL CHECK (dispatched_attempts BETWEEN 0 AND 3)` and nullable immutable `openmettle.operations.effective_expires_us bigint DEFAULT NULL` (zero change to `Binding` or `request_identity` canonical bytes; populated by `INSERT_INTENT` from `$20 = effective_until`) with a `BEFORE UPDATE` monotonicity/immutability trigger forbidding `dispatched_attempts` `non-null -> NULL` or decrements and forbidding any post-insert mutation of `effective_expires_us` (Transaction 1 in PR2 `approvals::record_fenced_intent` commits `outcome = 'intent'` with `dispatched_attempts = 0` and `effective_expires_us = effective_until` strictly on `IntentResult::Applied(committed)` for `repeatable_read`, leaving writes `dispatched_attempts DEFAULT NULL` until PR3's `runtime_feature_gates.two_phase_effect_intents_enabled = true` and writing zero `operations` rows on `IntentResult::ApprovalRequired`, distinct from Step 5 Transaction 2's pre-send increment), their matching `src/boundaries.sql` grants (`INSERT`/`UPDATE (dispatched_attempts)`, `INSERT (effective_expires_us)` with zero `UPDATE` grant and zero `openmettle_api` `INSERT`/`UPDATE` grant on `openmettle.operations`, `$1 >= <v1_14_schema_version>`), sequencing after `V1-17` PR2 / ADR 0040 PR2 for the unified shared storage schema (dedicated 1-row read-mostly singleton **`openmettle.storage_volume_control (id boolean PRIMARY KEY DEFAULT true CHECK (id), volume_id uuid, bootstrap_auto_pin_allowed boolean NOT NULL DEFAULT false, adoption_run_id uuid, CONSTRAINT storage_volume_control_auto_pin_check CHECK (volume_id IS NULL OR NOT bootstrap_auto_pin_allowed))`** with `GRANT SELECT ... TO openmettle_api, openmettle_worker` and `GRANT UPDATE (volume_id, bootstrap_auto_pin_allowed) ... TO openmettle_api`, keeping only `warn_pct_1`, `warn_pct_2`, `config_revision` alongside `storage_instance`'s byte counters so runtime `reserve`/`settle`/`release`/`purge` ONLY ever take `FOR SHARE` on `storage_volume_control` under canonical lock order **`runs -> storage_reservations -> artifacts -> artifact_revisions -> storage_volume_control -> storage_accounts -> storage_instance`**, eliminating `FOR SHARE -> FOR NO KEY UPDATE` self-upgrade deadlocks on `storage_instance`; tightened `storage_reservations_adoption_unverified_check` **`CHECK (NOT adoption_unverified OR state = 'reserved')`** so non-owner release of a quarantined reservation is impossible in PostgreSQL; `openmettle.storage_reservations` columns `stage_claimed boolean NOT NULL DEFAULT false`, write-once `payload_ino numeric(20, 0)` with **no `payload_dev`**, `publish_pending boolean NOT NULL DEFAULT false`, and unified **4-state** cleaner lease `reclaim_state text NOT NULL DEFAULT 'none' CHECK (reclaim_state IN ('none', 'claiming', 'truncated', 'anchor_pending_unlink'))` / `reclaim_claim_token uuid` / `reclaim_lease_until timestamptz` with their `CHECK` constraints (`(state = 'reserved' AND reclaim_state IN ('none', 'claiming', 'truncated')) OR (state = 'released' AND reclaim_state IN ('none', 'anchor_pending_unlink')) OR (state = 'settled' AND reclaim_state = 'none')`, lease token/timestamp `CHECK`, `reclaim_state NOT IN ('truncated', 'anchor_pending_unlink') OR NOT publish_pending`), `INSERT (lease_expires_at, stage_claimed)` & `UPDATE (lease_expires_at, adoption_unverified, stage_claimed, payload_ino, publish_pending, reclaim_state, reclaim_claim_token, reclaim_lease_until)` grants to `openmettle_api, openmettle_worker`, and `SECURITY INVOKER` `SET search_path = pg_catalog` triggers **`openmettle.enforce_runtime_storage_volume_pinned()`** (querying `openmettle.storage_volume_control WHERE id FOR SHARE` and failing closed with `OMQ03` on **`IF NOT FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL`**) and `openmettle.enforce_storage_reservation_monotonic_guards()` raising `OMQ03`), the `AFTER UPDATE OF state ON openmettle.runs FOR EACH ROW` `SECURITY DEFINER` trigger `openmettle.resolve_abandoned_repeatable_reads()` (owned by `openmettle_owner`, `SET search_path = pg_catalog`, `REVOKE ALL FROM PUBLIC`, audited in `src/boundaries.sql`, preserving `openmettle_api`'s zero `UPDATE` grant on `openmettle.operations`, resolving abandoned revision-zero `capability = 'repeatable_read'` `outcome = 'intent'` rows to `outcome = 'failed'`, `revision = 1` with idempotent `abandoned-read:<operation_id>` ADR 0004 `identity`/`digest` observation `run_events` strictly before `run-waiting` / `run-terminal` uniformly across mixed-version `N-1` and `N` worker/API binaries without duplicate Rust-caller SQL updates) and one-time upgrade repair (as `openmettle_owner`) of pre-existing `state IN ('queued', 'waiting')` runs, `leases::FailReason::ApprovalExpired` (`openmettle.run-approval-expired`), `CommittedIntent` storing separate `effect_deadline: Instant` and `lease_margin_deadline: Instant` with `CommittedIntent::start(self, &step)` returning explicit `StartPermit::{Stopped(Stop), AuthorityExpired { operation_id, request }, LeaseMarginExhausted, Ready { request, deadline }}` (so `worker::execute` at `src/worker.rs:533` and Step 5 handle `StartPermit::AuthorityExpired` via `approvals::expire_unstarted_intent` / `approvals::invalidate_post_intent` under `Fence::Step` with clock-skew recomputation when `db_time(c) < effective_expires_bound_us`, and `StartPermit::LeaseMarginExhausted` yields `WorkEnd::Handoff` so `leases::handoff` hands off while `> settings.lease` execution budget remains or settles `DeadlineExceeded` immediately when `<= settings.lease` remains without ever forcing false `Reconciling`/`Interrupted` on a `dispatched_attempts = 0` write), caller-independent ledger-aware `approvals::invalidate_post_intent` (partitioned strictly by `(capability, outcome, dispatched_attempts)` regardless of caller so Branch 1 covers `capability == 'repeatable_read'` at ALL `dispatched_attempts` `NULL`/`0`/`1`/`2`/`3` including in-process read retries plus zero-attempt writes `dispatched_attempts == Some(0)` and already-completed rows while Branch 2 covers post-dispatch writes, computing `effective_expires_bound_us` as `min` over `o.effective_expires_us`, `envelope["authorization"]["expires_us"]`, `EndpointKey::Supported.expires_us`, and a direct un-filtered SQL expiry query of bound non-revoked `local_sessions`/`local_identity_approvals`/`login_providers`/`users` and unrevoked bound `membership_observations` so natural shorter-lived deciding-session/originating-session/OIDC expiry never misclassifies as `CancelReason::Revoked`, keeping `invalidate_running`'s raw `fail(c, ..., EXPIRED)` strictly pre-intent), `StepResult::Invalidated(leases::Settled)` mapped in `worker::execute` (`src/worker.rs`) directly to `WorkEnd::Invalidated(settled)` (so `Settled::Reconciling { .. }` immediately runs `leases::release_lease(&mut c, &lease)` at `src/worker.rs:660-663` while `Settled::Terminal { .. }` exits at `src/worker.rs:652`), and distinct `StepResult::LeaseLost` mapped to `WorkEnd::Stop(Stop::LeaseLost)` strictly for deposed-worker own lease loss (`Stop::LeaseLost`, `LeaseError::StaleClaim \| Expired \| Terminal`), reviewed tool registry (`EffectPolicy`) enforcing OpenMettle's restricted stateless MCP `2026-07-28` interoperability profile (omitting `Mcp-Param-*` and failing closed on `x-mcp-header` schemas, with all pre-intent refusals writing zero `openmettle.operations` rows and returning bounded inline `status: "tool_error"`), strict schema/argument validator and default expander, `approvals::recheck_replay_effect_authority(..., policy: &impl EffectPolicy)` (under `Fence::Step` on primary: parsing the committed `openmettle.effect` v1 envelope from `operations.request` — reconstructing committed `Proposal` `p` and requiring exact match with the caller's requested `Proposal` and stored `operations` columns, verifying `openmettle.run_approvals JOIN openmettle.run_approval_decisions` with `Some(d.deciding_session_id)` when `basis == "human"`, resolving `live_review = reviewed(policy, &s, &p)?` with exact `live_review == committed_review`, executing `snap = authorized(c, &proof, &live_review)`, checking `snap.now < expires_us.min(validity(&snap, &live_review))` plus `automatic(&r, &snap)` and `YOLO` when `basis == "yolo"`, rebuilding `live_evidence == committed_evidence && live_hash == committed_binding_digest` before replaying any `succeeded` source/spilled artifact-backed result or `artifact.read_range` bytes — alongside `hydrate_worker_principal`, `revision.scope_id == run.scope_id`, `Action::Read` and `revision.state == "active"` — or replaying any `failed` bounded inline `status: "tool_error"` result, both on `IntentResult::Replayed(op_id)` and during committed-observation / unacknowledged-commit recovery), `approvals::start_replayed_read(..., policy: &impl EffectPolicy)` **evaluating live `EffectPolicy` (`live_review = reviewed(policy, &s, &p)?` + `live_review == committed_review`) + `authorized(c, &proof, &live_review)` / `effective_expires_us` + exact `live_evidence == committed_evidence && live_hash == committed_binding_digest` authority validity FIRST before checking `coalesce(dispatched_attempts, 3) >= 3`** (so expired or revoked authority — including when `dispatched_attempts IS NULL` or `dispatched_attempts == 3` — routes immediately through `approvals::invalidate_post_intent` Branch 1 (`outcome = 'failed'` + immediate terminal run settlement `openmettle.run-approval-expired` or `openmettle.run-revoked`, skipping any ordinary failed observation and model continuation), and **only when live authority is still valid** does `coalesce(dispatched_attempts, 3) >= 3` record an ordinary exhausted `outcome = 'failed'` observation under `Fence::Step` and continue the turn) AND guarding the `UPDATE openmettle.operations SET dispatched_attempts = o.dispatched_attempts + 1` statement **itself** with the live `{AUTH}` CTE (`WHERE ... AND o.dispatched_attempts IS NOT NULL AND o.dispatched_attempts < 3 AND snap.now_us < $effective_expires_bound_us AND snap.base = $expected_base AND snap.tool = $expected_tool AND (NOT $auto OR (snap.eligible AND snap.yolo = $expected_yolo))`, settling via ledger-aware `approvals::invalidate_post_intent` — never `invalidate_running` — on `0` rows updated with zero increment and zero sends), updating `approvals::authorized(c, p, review)` (`src/authz/approvals.rs:597-627`) so `EffectClass::Read` sets `RunRecheckRequest.extra_target = None` and `p.artifact == Some(artifact_id)` enforces in-scope `Action::Read`, internal `artifact.read_range` v1 tool (`Review.artifact = Some(artifact_id)`, `EffectClass::Read`, `Review.reservation = None`), `artifact_fs::Store::probe_writable` (operating strictly relative to `Store`'s verified `staging_dir_fd` and `revisions_dir_fd` via `rustix::fs::openat` / **`rustix::fs::linkat(&staging_dir_fd, src, &revisions_dir_fd, dst, AtFlags::empty())`** — rejecting `ENOSYS`/`EOPNOTSUPP`/`EINVAL` fail-closed and proving an existing destination returns `Errno::EXIST` without overwrite — / `unlinkat` / `fsync`), unified HTTP `Store::stage` / `Store::publish` / `Store::read` companion rules (HTTP `Store::stage` and `Store::publish` (`openmettle_api`) succeeding during mixed-version rolling upgrade while `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL` — skipping sentinel reads while `volume_id IS NULL` and verifying role-tagged sentinels once `volume_id IS NOT NULL` — whereas worker `publish_bytes` and all 4 cleaners strictly require `volume_id IS NOT NULL AND adoption_run_id IS NULL`; `Store::stage` Step 1a committing `stage_claimed = true` under `FOR UPDATE` (`state = 'reserved' AND NOT adoption_unverified AND NOT stage_claimed AND payload_ino IS NULL AND reclaim_state = 'none'`) + `storage_volume_control FOR SHARE` (`adoption_run_id IS NULL`) BEFORE `openat`, Step 1b opening `staging/<id>` (`OFlags::CREATE \| OFlags::EXCL \| OFlags::RDWR \| OFlags::NOFOLLOW`, `0` bytes) + `LOCK_SH` + local same-mount `st_dev` check + `fsync(&staging_dir_fd)`, Step 1c committing write-once `payload_ino = staged_ino` under `FOR UPDATE` (`reclaim_state = 'none'`), **`StagedFile::drop` 100% non-destructive (`close` only — NEVER `set_len(0)` and NEVER `unlinkat`)**, `Store::publish` setting `publish_pending = true` under `FOR UPDATE` (`state = 'reserved' AND NOT adoption_unverified AND payload_ino = $staged_ino AND reclaim_state = 'none'`), publishing via **`rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id, AtFlags::empty())`** — keeping `staging/<id>` linked throughout the entire pre-settlement `state = 'reserved'` window so same-key `N-1` API retries hit `OpenOptions::create_new(true)` -> `Err(Error::InProgress)` (`src/artifact_fs.rs:474-475`) without calling `abort()` or replacing `fs::rename` — + `fsync(&revisions_dir_fd)` + post-`linkat` re-verification, committing `storage::settle` (`state = 'settled', publish_pending = false`, retaining `payload_ino`), then running post-commit best-effort detach of `staging/<id>` under `LOCK_SH` (`unlinkat` ONLY, NEVER `set_len(0)`, after verifying both `staging/<id>` and `revisions/<id>` match `staged_ino`), ambiguous `storage::settle` commit NEVER calling `abort`, `abort` running only on confirmed pre-settlement failure via the unified 4-step `LOCK_EX` protocol, and `Store::read` verifying `sr.adoption_unverified = false` and `file_meta.ino() == sr.payload_ino` whenever `sr.payload_ino IS NOT NULL` while allowing `sr.payload_ino IS NULL` only while `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL`), `artifact_fs::publish_bytes` (restricted exclusively to `succeeded` tool outputs while every `failed` tool result uses bounded inline `status: "tool_error"`, never spilled; implemented strictly with safe Rust + `V1-17` PR2's `rustix` verified directory-descriptor foundation under `unsafe_code = "forbid"`, gated by `spill_permits` `Arc<tokio::sync::Semaphore>`, **writers NEVER calling `unlinkat` (except post-commit detach of `staging/<id>` after `storage::settle` commits `state = 'settled'`) and NEVER calling `set_len(0)` anywhere including on error/cancellation/lost-commit-ack or `Drop`**, following the exact **Phase 1a -> 1b -> 2 -> 3 -> post-commit detach** lifecycle: **Phase 1a** acquires `OwnedSemaphorePermit`, locks `runs (FOR NO KEY UPDATE) -> storage_volume_control (FOR SHARE)` (`volume_id = $expected_volume_id AND adoption_run_id IS NULL`, else clean inline `truncated_no_spill`) `-> storage_accounts (FOR UPDATE) -> storage_instance (FOR UPDATE)` inside `storage::reserve` under `Fence::Step` inserting `stage_claimed = true, payload_ino = NULL, publish_pending = false, reclaim_state = 'none'` BEFORE touching disk; **Phase 1b** **moves `OwnedSemaphorePermit` directly into Phase 1b's `spawn_blocking` closure** returning `(payload_file, staged_ino, spill_permit)` (so cutoff/timeout while stalled in `openat` or `fsync(&staging_dir_fd)` keeps the permit held until the blocking task finishes, strictly bounding concurrent blocking tasks to `max_concurrent_runs`), re-verifies `<root>`, `"staging"`, `"revisions"` + role-tagged sentinels, opens `staging/<reservation_id>` (`OFlags::CREATE \| OFlags::EXCL \| OFlags::RDWR \| OFlags::NOFOLLOW`, `0` bytes) + `LOCK_SH` + verifies `S_ISREG`, local same-mount `st_dev` equality (`file_meta.dev() == dir_fd_meta.dev() == root_fd_meta.dev()`), `staged_ino = file_meta.ino()` + **`fsync(&staging_dir_fd)`**, then under `Fence::Step` locks `storage_reservations FOR UPDATE` + `storage_volume_control FOR SHARE` (`volume_id = $expected_volume_id AND adoption_run_id IS NULL`) and commits `SET payload_ino = $3::text::numeric(20, 0), publish_pending = true WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved' AND NOT adoption_unverified AND stage_claimed AND payload_ino IS NULL AND reclaim_state = 'none'` — on any error/lost-ack simply dropping `payload_file` and `spill_permit` with zero `set_len(0)` / `unlinkat`; **Phase 2** (`spawn_blocking` moving `spill_permit` and raced against `step.deadline`/`step.stop.changed()`) writes chunks + `payload_file.sync_all()`, re-verifies dirs/sentinels/`statat` (`S_ISREG`, local `st_dev`, `st_ino == staged_ino`, `st_size == size_bytes`), publishes via **`rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id, AtFlags::empty())`** (keeping `staging/<id>` linked until `storage::settle` commits!) — on `Errno::EXIST` or mismatch committing quarantine `adoption_unverified = true, publish_pending = false` with zero `set_len(0)` / `unlinkat` — + `fsync(&revisions_dir_fd)` + post-`linkat` re-verify; **Phase 3** under `Fence::Step` runs bounded `<= 2 s` pre-commit `spawn_blocking` verification holding `spill_permit` checking dirs/sentinels/`statat(&revisions_dir_fd, id)` (`st_ino == staged_ino`, `st_size == size_bytes`), requires `state = 'reserved' AND NOT adoption_unverified AND payload_ino = $staged_ino AND reclaim_state = 'none'` on `storage::settle`'s `Reserved` branch while preserving `ReservationState::Settled` idempotent replay, atomically commits `storage::settle` (`state = 'settled', publish_pending = false`, retaining write-once `payload_ino`) + `runs::record_observation`, then performs **post-commit best-effort detach of `staging/<id>`** while still holding `LOCK_SH` on `payload_file` (verifying `statat(&staging_dir_fd, id).st_ino == staged_ino` AND `statat(&revisions_dir_fd, id).st_ino == staged_ino` -> `unlinkat(&staging_dir_fd, id, AtFlags::empty())` (**NEVER `set_len(0)`**) -> `drop(payload_file)` -> `fsync(&staging_dir_fd)`), with pure `close()` on lost commit ack/cancellation and deterministic spill-abort disposition into `Fence::Step`/`StepResult::Continue`, `Fence::Hold`/`StepResult::Stopped`, or `StepResult::LeaseLost`), unified **4-step** `reconcile_run_spills` using **`staging/.reclaim.<id>`** so `payload_ino` NEVER drops to `nlink = 0` before Step 3 commits (sole automatic cleanup owner of `operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%'`, complementing `V1-17`'s `run_id IS NOT NULL AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')` + `storage_reservations_tool_spill_binding_guard` (`23514`); **Step 1** serialized lock-ordered DB claim (`runs FOR NO KEY UPDATE SKIP LOCKED -> storage_reservations FOR UPDATE SKIP LOCKED -> storage_volume_control FOR SHARE` verifying `volume_id = $expected_volume_id AND adoption_run_id IS NULL`) setting `reclaim_state = CASE WHEN reclaim_state = 'truncated' THEN 'truncated' ELSE 'claiming' END, reclaim_claim_token = $my_token, reclaim_lease_until = clock_timestamp() + interval '60 seconds'` with zero FS I/O inside DB tx; **Step 2** outside DB tx after verifying local same-mount `<root>`/`staging`/`revisions` FDs + role-tagged sentinels, NEVER clearing `payload_ino`: **Subcase A1 (`payload_ino IS NOT NULL` & `'claiming'`)** probes `staging/<id>`, `revisions/<id>`, and `staging/.reclaim.<id>` — quarantining non-regular / local `st_dev` / `st_ino != payload_ino` or all-three-`ENOENT` strictly under `FOR UPDATE` verifying `reclaim_claim_token = $my_token AND reclaim_state = 'claiming' AND payload_ino = $expected_ino` (zero `set_len(0)` / `unlinkat`), and on matching `S_ISREG` acquiring `LOCK_EX` -> `probe_file.set_len(0)?` + `probe_file.sync_all()?` -> `linkat` hard-link anchor **`staging/.reclaim.<id>`** + `fsync(&staging_dir_fd)` -> unlinking `revisions/<id>` & `staging/<id>` + dual `fsync` -> committing `reclaim_state = 'truncated', publish_pending = false` while holding `LOCK_EX` on `probe_file`; **Subcase A2 (`payload_ino IS NOT NULL` & `'truncated'`)** NEVER truncates or unlinks `staging/<id>` or `revisions/<id>`, probes ONLY `staging/.reclaim.<id>` (quarantining `ENOENT`, non-regular, `st_ino != payload_ino`, or `st_size != 0` under `reclaim_claim_token = $my_token AND reclaim_state = 'truncated' AND payload_ino = $expected_ino`), acquires `LOCK_EX` + re-verifies `st_ino == payload_ino && st_size == 0` + dual `fsync` -> proceeds to Step 3 holding `LOCK_EX`; **Subcase B (`payload_ino IS NULL`)** quarantines any `revisions/<id>` or non-regular / different local `st_dev` / `st_size > 0` `staging/<id>` under `reclaim_claim_token = $my_token AND payload_ino IS NULL`, unlinks `0`-byte `staging/<id>` under `LOCK_EX`, and `fsync`s both dirs; **Step 3** final `storage::release` with **ZERO filesystem I/O inside DB tx** (lock order `runs -> storage_reservations -> storage_volume_control (FOR SHARE via trigger) -> storage_accounts (FOR UPDATE) -> storage_instance (FOR UPDATE)`), requiring `state = 'reserved' AND NOT adoption_unverified AND NOT publish_pending AND reclaim_claim_token = $my_token AND (payload_ino IS NULL OR reclaim_state = 'truncated')`, setting **`reclaim_state = CASE WHEN payload_ino IS NOT NULL THEN 'anchor_pending_unlink' ELSE 'none' END, reclaim_claim_token = NULL, reclaim_lease_until = NULL`** and retaining write-once `payload_ino` on `'released'`, backed by `enforce_runtime_storage_volume_pinned()` & `enforce_storage_reservation_monotonic_guards()` (`OMQ03`); **Step 4** post-release detach of `staging/.reclaim.<id>` while holding `LOCK_EX` (`statat` verify `st_ino == payload_ino && st_size == 0` -> `unlinkat` -> `drop` -> `fsync(&staging_dir_fd)` -> best-effort `SET reclaim_state = 'none' WHERE state = 'released' AND reclaim_state = 'anchor_pending_unlink'`), with `openmettle-admin` adoption positively verifying and preserving `'truncated'` holds when `staging/.reclaim.<id>` matches `st_ino == payload_ino && st_size == 0`), defense-in-depth `state = 'released'` pass (detaching only `reclaim_state = 'anchor_pending_unlink'` `.reclaim.<id>` and `payload_ino IS NULL` `0`-byte `staging/<id>`, NEVER touching `staging/<id>` for `payload_ino IS NOT NULL`), shared `StagingSweepState` (**NEVER calling `set_len(0)` on `'settled'`, `'released'`, or `.reclaim.<id>`**: `> 900 s` zero-row orphan check locking `storage_volume_control FOR SHARE -> storage_instance FOR UPDATE`; `'settled'` preserving `staging/<id>` untouched whenever `adoption_unverified \|\| payload_ino IS NULL \|\| staging_ino != payload_ino`, and when `staging_ino == payload_ino` unlinking `staging/<id>` ONLY under `LOCK_EX` iff `revisions/<id>` has `rev_stat.st_ino as u64 == payload_ino` OR `revisions/<id>` is `ENOENT` and fresh `SELECT state FROM artifact_revisions` returns `Some('purged')`; `'released'` NEVER touching `staging/<id>` when `payload_ino IS NOT NULL`, unlinking only `0`-byte `staging/<id>` when `payload_ino IS NULL`; `.reclaim.<id>` unlinking only `state = 'released' AND reclaim_state = 'anchor_pending_unlink' AND NOT adoption_unverified AND payload_ino IS NOT NULL` matching `st_ino == payload_ino && st_size == 0` then clearing `reclaim_state = 'none'`), `artifact_fs::purge_due` leaf `payload_ino` verification AND `staging/<id>` hard-link alias detach (`storage::begin_purge` joining `storage_reservations` requiring `NOT sr.adoption_unverified AND sr.payload_ino IS NOT NULL`; refusing foreign `revisions/<id>` `st_ino != payload_ino` without `set_len(0)`/`unlinkat`/`confirm_purge`; probing `staging/<id>` and detaching matching `staging_ino == payload_ino` alias under `LOCK_EX` with `set_len(0)` + `sync_all()` + `unlinkat` while leaving foreign `staging_ino != payload_ino` untouched; running unconditional dual `fsync(&revisions_dir_fd)` + `fsync(&staging_dir_fd)` strictly BEFORE `storage::confirm_purge`), `ReadWriteMany` qualification (`O_CREAT \| O_EXCL \| O_NOFOLLOW`, `linkat` (`Errno::EXIST`), file + directory `fsync`, two-client/separate-mount `flock(2)` exclusion, AND stable 64-bit `st_ino` coherence + second-client recovery across clients and remounts), and serialized-budget head/tail preview builder. | PostgreSQL 18 tests: cross-user, cross-scope, archived/deleted project, private project-scope spill ownership (other members denied until shared), share revocation and `active` -> `retained` transition between original read and replay, bound/originating session logout after `artifact.read_range` (or spilled tool output) commits its observation while artifact `Action::Read` access and `revision.state == "active"` remain valid, capability revoke + re-grant (changing grant revision/`cycle_id` in `authority_evidence`), live `EffectPolicy` withdrawal/change ONLY (`Ok(None)` / `Err(DENIED)` or changed `destination_policy` / `tool_policy` / `endpoint_version`), AND direct source-artifact share revoke + re-grant (`Review.artifact = Some(artifact_id)` while read-only `Action::Read` share holder without `Action::Write` succeeds on initial read and valid replay), failing closed via `approvals::invalidate_post_intent` (`IntentResult::Invalidated(settled)` / `StepResult::Invalidated(settled)` -> `WorkEnd::Invalidated(settled)`) with zero cached bytes and zero sends; pre-intent `max_bytes < 4`, `x-mcp-header`, duplicate-key, float, depth, bound and wildcard rejections verifying zero `openmettle.operations` rows written and bounded inline `status: "tool_error"`; invalid UTF-8 binary semantic fault and strictly inline `artifact.read_range` under 6x JSON escaping and `<= 200`-line `next_offset` pagination; verifying `failed` tool results never spill and always replay bounded inline `status: "tool_error"`; **`approvals::start_replayed_read` live-authority-before-exhaustion & `{AUTH}`-guarded `UPDATE` tests**: (1) evaluating live `EffectPolicy` + `{AUTH}` / `effective_expires_us` authority FIRST before `coalesce(dispatched_attempts, 3) >= 3` across **both `dispatched_attempts = NULL` (legacy `N-1` upgrade fixture) AND `dispatched_attempts = 3`** under **both expired authority AND revoked authority** — asserting immediate `approvals::invalidate_post_intent` Branch 1 (`outcome = 'failed'` + immediate terminal run settlement `openmettle.run-approval-expired` or `openmettle.run-revoked`, zero ordinary failed observation and zero model continuation, zero outbound sends), (2) confirming that **only when live authority is still valid** do `dispatched_attempts == 3` and legacy `dispatched_attempts IS NULL` record an ordinary exhausted `outcome = 'failed'` observation under `Fence::Step` and continue the turn with zero sends, and (3) interleaving concurrent session logout or grant/capability revocation *between* `authorized()` snapshot acquisition and the `{AUTH}`-guarded `UPDATE`, verifying `0` rows updated, zero increment, `approvals::invalidate_post_intent` -> `IntentResult::Invalidated(settled)` / `StepResult::Invalidated(settled)` -> `WorkEnd::Invalidated(settled)`, and zero sends; serialized-JSON `16 KiB` inline/spill thresholds; startup `Store::probe_writable` fail-closed test on pre-existing read-only `staging/` and `revisions/` AND proving `rustix::fs::linkat` returns `Errno::EXIST` without overwriting an existing destination (rejecting `ENOSYS`/`EOPNOTSUPP`/`EINVAL` fail-closed); unset-`ARTIFACTS_DIR`, unconfigured-store, quota-refused, `spill_saturated` and I/O fallback envelopes; **`V1-17` PR2 `storage_volume_control` deadlock-freedom, missing-row `OMQ03`, monotonic & quarantined-release tests**: (1) **concurrent two-release + two-spill-reserve deadlock-freedom test** executing two concurrent `storage::release` calls alongside two concurrent `publish_bytes` Phase 1a `storage::reserve` calls (`storage_volume_control FOR SHARE -> storage_accounts FOR UPDATE -> storage_instance FOR UPDATE`) asserting zero PostgreSQL `40P01` deadlocks and exact counter conservation, (2) **missing-row `storage_volume_control` `OMQ03` trigger test** deleting the `storage_volume_control` singleton row as `openmettle_owner` and proving `enforce_runtime_storage_volume_pinned()` fails closed with `OMQ03` (`IF NOT FOUND`) alongside `volume_id IS NULL` and `adoption_run_id IS NOT NULL`, and (3) verifying `enforce_storage_reservation_monotonic_guards()` raises `OMQ03` for runtime roles attempting to clear `adoption_unverified` (`true -> false`), mutate/clear `payload_ino`, or clear `stage_claimed` (`true -> false`), AND verifying tightened `storage_reservations_adoption_unverified_check` (`CHECK (NOT adoption_unverified OR state = 'reserved')`) makes non-owner release of a quarantined reservation impossible in PostgreSQL (`23514` if `adoption_unverified = true` is kept, `OMQ03` if cleared, while `openmettle_owner` succeeds updating `state = 'released', adoption_unverified = false` together); **mixed-version rolling-upgrade HTTP vs worker rollout & `N` post-`linkat` crash + `N-1` HTTP retry interleaving tests**: verifying HTTP `Store::stage`, `Store::publish`, and `Store::read` (including legacy `payload_ino IS NULL` rows) succeed while `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL` (skipping sentinel reads while `volume_id IS NULL` and enforcing role-tagged sentinels + `file_meta.ino() == sr.payload_ino` once `volume_id IS NOT NULL`), while worker `publish_bytes` and all 4 cleaners fail closed whenever `volume_id IS NULL OR adoption_run_id IS NOT NULL`; AND **`N` post-`linkat` crash + `N-1` same-key HTTP retry interleaving test** simulating an `N` writer crashing after `rustix::fs::linkat` creates `revisions/<id>` while `staging/<id>` stays linked and `state = 'reserved'`, then routing a same-key retry to an `N-1` API replica (`src/artifact_fs.rs:474-475` `OpenOptions::create_new(true)`), proving the `N-1` replica returns `Err(Error::InProgress)` immediately without calling `abort()`, without creating a new staging file, and without overwriting `revisions/<id>` via replacing `fs::rename`; existing `storage::settle` `ReservationState::Settled` idempotent HTTP upload replay (`tests/schema/artifact_fs.rs:434`) preserved alongside `AND NOT adoption_unverified AND payload_ino = $staged_ino AND reclaim_state = 'none'` on `ReservationState::Reserved` (atomically clearing `publish_pending = false` while retaining write-once `payload_ino` on `state = 'settled'`); Phase 3 rollback/crash simulation verifying atomic `storage::settle` + `runs::record_observation` inside one `Fence::Step` transaction, post-commit best-effort detach of `staging/<id>` under `LOCK_SH` without `set_len(0)`, and lost Phase-3 commit ack dropping `payload_file` via pure `close()` (zero `set_len(0)` / zero `unlinkat`, preserving the settled artifact); `publish_bytes`, `Store::stage`/`Store::publish`, `reconcile_run_spills`, `StagingSweepState`, and `artifact_fs::purge_due` concurrency, `linkat`, 4-step reclamation, stale-cleaner, stalled-Phase-1b permit-saturation, `SIGKILL`, and takeover tests covering (a) delaying Phase 2 `spawn_blocking` disk I/O past both `5 s` `idle_in_transaction_session_timeout` and drain deadline during lease takeover (replacement worker settles intact with disjoint `reservation_id`, stalled worker exits `StepResult::LeaseLost` with zero corrupted/unlinked revisions), (b) **both race orders between stalled Phase-3 commit and Step-1 `reclaim_state = 'claiming'` claim** (Step 1 claiming first causes Phase 3 to fail closed on `reclaim_state = 'none'` and roll back both `storage::settle` and `runs::record_observation`; Phase 3 committing `'settled'` first causes Step 1 to skip untouched), (c) **Phase 1a DB reserve BEFORE disk (`stage_claimed = true, payload_ino = NULL`) -> Phase 1b `OwnedSemaphorePermit`-bound `spawn_blocking` (`openat` + `LOCK_SH` + `fsync(&staging_dir_fd)`) + bind write-once `payload_ino` + `publish_pending = true` with 100% non-destructive writers & `StagedFile::drop` AND stalled-Phase-1b permit-saturation test**: proving pre-Phase-1a cutoff, deterministic Phase-1a rollback (`OMQ01` / `Fence::Step`), and Phase-1a lost commit ack create zero files on disk and execute zero `unlinkat`; proving stalling Phase 1b inside `openat`/`fsync(&staging_dir_fd)` past cutoff/timeout keeps `OwnedSemaphorePermit` held until the blocking task finishes so concurrent blocking tasks never exceed `max_concurrent_runs` (`spill_saturated` fallback); proving Phase-1b error/lost-commit-ack and `StagedFile::drop` execute pure `close()` (zero `set_len(0)` and zero `unlinkat`, even if `staging/<id>` was replaced by another file), deferring all cleanup exclusively to the unified 4-step cleaner (`Subcase B` for `payload_ino IS NULL`, `Subcase A1` for `payload_ino IS NOT NULL`), (d) **`linkat` pre-existing `revisions/<id>` `Errno::EXIST` non-overwrite quarantine test** for both `publish_bytes` and `Store::publish` (placing a pre-existing file at `revisions/<id>`, verifying `rustix::fs::linkat` fails with `Errno::EXIST` without overwriting `revisions/<id>`, commits `adoption_unverified = true, publish_pending = false`, and performs zero `set_len(0)` / zero `unlinkat`), (e) **unified 4-step reclamation protocol (`reconcile_run_spills` Subcases A1, A2, B + Step 4 `anchor_pending_unlink`), `staging/.reclaim.<id>` inode-reuse prevention, adoption preservation of `'truncated'` holds, stale-cleaner `$my_token` race, cutoff during post-`linkat` `fsync`, and subprocess `SIGKILL` tests**: stalling cancelled Phase-2 writer mid-chunk, during `sync_all()`, and during post-`linkat` `fsync` past `spill_reservation_ttl` (`LOCK_EX` returns `WouldBlock` keeping `max_bytes` charged until writer exits / `SIGKILL`), verifying Subcase A1 executes `set_len(0)` + `sync_all()` FIRST -> creates hard-link anchor **`staging/.reclaim.<id>`** + `fsync(&staging_dir_fd)` SECOND -> unlinks `revisions/<id>` & `staging/<id>` + dual `fsync` THIRD -> commits `reclaim_state = 'truncated', publish_pending = false` (retaining `payload_ino`) FOURTH -> Step 3 `storage::release` with ZERO FS I/O inside DB tx setting `reclaim_state = 'anchor_pending_unlink'` FIFTH -> Step 4 detaches `staging/.reclaim.<id>` under `LOCK_EX` + `fsync(&staging_dir_fd)` + best-effort `SET reclaim_state = 'none'` SIXTH; **Subcase A2 crash-recovery & foreign `<id>` preservation test**: crashing after `'truncated'` commits and placing a new foreign file at `staging/<id>` or `revisions/<id>` while `staging/.reclaim.<id>` remains anchored (`st_ino == payload_ino && st_size == 0`), proving Subcase A2 verifies ONLY `staging/.reclaim.<id>`, completes Step 3 -> Step 4 cleanly, and leaves the foreign `<id>` file 100% untouched (and quarantines if `staging/.reclaim.<id>` is missing, wrong inode, or non-zero); **adoption `'truncated'` preservation test**: running `openmettle-admin` adoption against a `'reserved'` row in `reclaim_state = 'truncated'` with valid `0`-byte `staging/.reclaim.<id>` (`st_ino == payload_ino`), proving adoption positively verifies and preserves `reclaim_state = 'truncated'` (resetting `reclaim_lease_until = clock_timestamp()`) so the next cleaner tick completes Step 3 -> Step 4 cleanly without stranding quota in `adoption_unverified`; **stale-cleaner all-three-`ENOENT` race test**: Cleaner 1 holds expired `'claiming'` lease and observes all-three-`ENOENT` after Cleaner 2 takes over (`$token_2`), truncates, releases, and detaches `.reclaim.<id>` — proving Cleaner 1's quarantine `UPDATE ... WHERE reclaim_claim_token = $token_1 AND reclaim_state = 'claiming'` matches `0` rows and never quarantines Cleaner 2's row; **Subcase B (`payload_ino IS NULL`) & replacement-leaf quarantine & Step 2 failure-guard tests** verifying zero `set_len(0)` / `unlinkat` on mismatches and `max_bytes` kept charged on any Step 2 error, (f) **shared `StagingSweepState` (`> 900 s` orphan check, two-reservation hard-link fixture `staging/A` -> `revisions/B`, `'settled'`, `'released'`, and `.reclaim.<id>`)**: verifying (i) `adoption_unverified = true` skipped across all states and **ZERO `set_len(0)` anywhere in `StagingSweepState`**, (ii) **two-reservation hard-link fixture (`staging/A` hard-linked to active `revisions/B`, while `revisions/A` matches `A.payload_ino`)**: proving `staging/A` has `staging_ino == B.payload_ino != A.payload_ino`, so `StagingSweepState` preserves `staging/A` and `revisions/B` 100% untouched (zero `set_len(0)`, zero `unlinkat`, `B`'s bytes intact) and `verify_accounting_drift` flags the unexpected `staging/A` entry, (iii) **`'settled'` (`staging_ino == payload_ino`)**: unlinks `staging/<id>` ONLY (no `set_len(0)`) under `LOCK_EX` when `revisions/<id>` matches `payload_ino` OR `revisions/<id>` is `ENOENT` and fresh `SELECT state FROM artifact_revisions` returns `Some('purged')`, and preserves `staging/<id>` untouched when `revisions/<id>` is `ENOENT` while `'active'`/`'retained'` or has `rev_ino != payload_ino`, (iv) **`'released'`**: NEVER touches `staging/<id>` when `payload_ino IS NOT NULL` (even if an inode number was later reused at `staging/<id>`!), and for `payload_ino IS NULL` unlinks only `0`-byte `staging/<id>` under `LOCK_EX`, (v) **`.reclaim.<id>`**: unlinks only `state = 'released' AND reclaim_state = 'anchor_pending_unlink' AND NOT adoption_unverified AND payload_ino IS NOT NULL` matching `st_ino == payload_ino && st_size == 0` then sets `reclaim_state = 'none'` (skipping once `reclaim_state = 'none'`), and (vi) zero-row (`None`) serialization via `storage_volume_control FOR SHARE -> storage_instance FOR UPDATE`, (g) **`artifact_fs::purge_due` hard-link alias & leaf `payload_ino` tests**: (i) creating settled reservation `A` where both `staging/A` and `revisions/A` share `A.payload_ino` and running **`purge_due` BEFORE `StagingSweepState`**, proving `purge_due` truncates and unlinks **BOTH** `revisions/A` and the `staging/A` alias and runs dual `fsync(&revisions_dir_fd)` + `fsync(&staging_dir_fd)` strictly before `storage::confirm_purge` so disk blocks are freed before `retained_bytes` drops, (ii) placing a foreign file (`st_ino != payload_ino`) at `revisions/A` proving `purge_due` stops with zero `set_len(0)`, zero `unlinkat`, and zero `confirm_purge` (keeping `retained_bytes` charged), and (iii) placing a foreign file (`st_ino != payload_ino`) at `staging/A` proving `purge_due` purges `revisions/A` while preserving foreign `staging/A` untouched, (h) local `step.deadline`/`step.stop` cutoff + `storage_accounts` lock-stall + competing `runs` lock `Stop::LeaseLost` fallback tests + Phase 3 `2 s` sentinel-read stall + `spill_permits` saturation tests, (i) exact complement cleaner partition (`operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%'` vs `run_id IS NOT NULL AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')` + `storage_reservations_tool_spill_binding_guard` `23514`), `adoption_run_id IS NOT NULL` / `volume_id IS NULL` / sentinel / local `st_dev` mismatch fail-closed tests, populated-upgrade and mixed-version `N-1`/`N` `resolve_abandoned_repeatable_reads()` SSE `204 No Content` tests, and (j) **`ReadWriteMany` cross-client qualification tests** proving `O_CREAT \| O_EXCL \| O_NOFOLLOW`, `rustix::fs::linkat` (`Errno::EXIST`), file+dir `fsync`, two-client/separate-mount `flock(2)` (`LOCK_SH` vs `LOCK_EX \| LOCK_NB` `WouldBlock`) exclusion, AND **stable 64-bit `st_ino` coherence + second-client recovery across clients/remounts where two clients observe different local anonymous NFS `st_dev` values** (confirming zero false quarantine from cross-node `st_dev` differences!). |
| PR3 | PR3's sequential SQL migration creating the dedicated 1-row worker rollout gate **`openmettle.runtime_feature_gates (id boolean PRIMARY KEY DEFAULT true CHECK (id), two_phase_effect_intents_enabled boolean NOT NULL DEFAULT false)`** (`GRANT SELECT ON openmettle.runtime_feature_gates TO openmettle_api, openmettle_worker`; default `false` on upgrade while any `N-1` `openmettle-worker` claimer or `settle_expired` sweeper is active so PR4 scoped MCP tool execution stays disabled / fails closed and pre-existing ADR 0035 external approval writes keep `dispatched_attempts = NULL`, enabled to `true` by `openmettle-admin` / rollout once all `N-1` workers are drained or by `bootstrap` on a fresh `N` database, guaranteeing **no `N-1` worker can EVER claim or sweep a `dispatched_attempts = 0` row**) and installing/extending the `AFTER UPDATE OF state ON openmettle.runs FOR EACH ROW` `SECURITY DEFINER` trigger `openmettle.resolve_terminal_write_intents()` (owned by `openmettle_owner`, `SET search_path = pg_catalog`, `REVOKE ALL FROM PUBLIC`, audited in `src/boundaries.sql`, preserving `openmettle_api`'s zero `UPDATE` grant on `openmettle.operations`): on `NEW.state = 'succeeded'` raising an invariant error if any write row (`capability IN ('idempotent', 'lookup', 'non_repeatable')`) still has `outcome IN ('intent', 'outcome_unknown')` (including `dispatched_attempts = 0`), and on `NEW.state IN ('failed', 'cancelled', 'interrupted')` transitioning every remaining revision-zero write `intent` unconditionally to `outcome = 'outcome_unknown'`, `revision = 1` with bounded redacted observation evidence and its ADR 0004 `openmettle/observation/1\0` `run_events` row strictly before `run-terminal`; PR3 update to **`leases::unresolved!()` (`src/authz/leases.rs:310-314`)** changing the unresolved write predicate to **`(outcome = 'outcome_unknown' OR (outcome = 'intent' AND coalesce(dispatched_attempts, 1) > 0)) AND capability IN ('idempotent', 'lookup', 'non_repeatable')`** (excluding proven-unsent `dispatched_attempts = 0` write intents while keeping legacy `dispatched_attempts IS NULL` and post-Transaction-2 `dispatched_attempts >= 1` rows in `Reconciling`/`Interrupted`); **explicit narrow amendment to ADR 0035 (`docs/adr/0035-approvals-permitted-yolo-and-effect-ledger.md:260-268`)** permitting a write send permit on an existing `operations` row strictly when **`o.outcome = 'intent' AND o.dispatched_attempts = 0` (`IS NOT NULL AND = 0`)** (while rows with `dispatched_attempts IS NULL`, `dispatched_attempts >= 1`, or `outcome <> 'intent'` still NEVER receive a write send permit); **complete successor discovery & zero-attempt write send-permit authorization**: **(a) consumed human approvals (`src/authz/approvals.rs:1241` `PENDING_EFFECT` / `src/worker.rs:519`)** updating `PENDING_EFFECT` to `AND NOT EXISTS (SELECT FROM openmettle.operations o WHERE o.run_id = a.run_id AND o.logical_key = a.logical_key AND NOT (o.outcome = 'intent' AND o.dispatched_attempts = 0))` (keeping `REQUEST.consumed` unchanged so HTTP `decide` still treats the approval as consumed), **(b) automatic writes (`approval_id IS NULL`)** via deterministic turn-round replay in `Executor::step` plus a pre-round check for any open `o.approval_id IS NULL AND o.outcome = 'intent' AND o.dispatched_attempts = 0` row on `(scope_id, run_id)`, and **(c) `approvals::record_fenced_intent` (`src/authz/approvals.rs:1293-1337`)** locking the existing row `FOR UPDATE`, verifying `durable::existing_intent`, and when `old.outcome == "intent" && old.dispatched_attempts == Some(0) && capability != "repeatable_read"`, re-verifying live `EffectPolicy` (`reviewed`) + `{AUTH}` (`authorized` — loading `run_approvals` + `deciding_session_id` by `old.approval_id` even when `REQUEST.consumed == true` for human approvals, or `eligible && yolo` + `hydrate_worker_principal` + `authorize_capability(YOLO)` for automatic writes) + `snap.now < old.effective_expires_us`, routing expired/revoked authority through `approvals::invalidate_post_intent` (`IntentResult::Invalidated(settled)`), and returning **`IntentResult::Applied(CommittedIntent { operation_id: op, request: old_bytes, effect_deadline, lease_margin_deadline })`** when valid so `CommittedIntent::start(&step)` yields `StartPermit::Ready` and Step 5 Transaction 2 commits **`UPDATE openmettle.operations SET dispatched_attempts = 1 WHERE scope_id = $1::uuid AND run_id = $2::uuid AND id = $3::uuid AND outcome = 'intent' AND dispatched_attempts = 0`** (`rows_affected() == 1` required strictly before sending, in both `worker::execute`'s approved-adapter path and the MCP adapter), while all other existing-row cases (`repeatable_read`, `dispatched_attempts IS NULL`, `dispatched_attempts >= 1`, `outcome <> 'intent'`) return `IntentResult::Replayed(op)` (resolving `effective_approval = stored_approval_id.as_deref()`, returning `Err(CONFLICT)` only on conflicting `Some(other_id)`); **unified `WorkEnd::Handoff` & `leases::handoff` alignment with `reclaim_next`** across `src/authz/leases.rs` and `src/worker.rs`: **(1)** adding **`WorkEnd::Handoff`** to `WorkEnd` in `src/worker.rs` (returned on `StartPermit::LeaseMarginExhausted` in both `worker::execute`'s `pending_effect` path and `Executor::step` and routed in `run_one` (`src/worker.rs:661-675`) to `leases::handoff(&mut c, &lease, &settings).await` whenever `cause != Some(Stop::LeaseLost)`) and updating **`leases::handoff`** (`src/authz/leases.rs:503-535`, under `Fence::Hold`) to evaluate **`time_to_reclaim = execution_expires_at > clock_timestamp() + $3::bigint * interval '1 millisecond'`** (`settings.lease`, matching `reclaim_next` and `SETTLEMENT_INPUTS`): calling `release_locked` iff `held.cancel.is_none() && !unresolved && time_to_reclaim` (keeping `state = 'running'` and `outcome = 'intent', dispatched_attempts = 0` so a reclaiming successor discovers the unsent write via `PENDING_EFFECT` or `Executor::step`, obtains `IntentResult::Applied(CommittedIntent)`, increments `dispatched_attempts` `0 -> 1` in Transaction 2, executes once, and finishes `succeeded`; if time later elapses to `<= settings.lease` before reclaim, `settle_expired` settles `DeadlineExceeded` with `n = 0` at `execution_expires_at` closing `dispatched_attempts = 0` to `'failed'`), and calling **`settle_locked(..., Settle::Stopped)` right inside the same `Fence::Hold` transaction** whenever `held.cancel.is_some() \|\| unresolved \|\| !time_to_reclaim` (so `<= settings.lease` remaining — e.g., `10 s` left on a `30 s` lease — immediately selects `Resolution::DeadlineExceeded` (`state = 'failed'`, `{"reason":"deadline_exceeded"}`) and atomically closes `outcome = 'intent' AND dispatched_attempts = 0` to `outcome = 'failed', revision = revision + 1`, with zero stranded unreclaimable run and zero `Reconciling`/`Interrupted`), **(2)** preserving `Settle::Succeeded`'s unconditional guard in `leases::settle_locked` against ANY write row with `outcome IN ('intent', 'outcome_unknown')` (including `dispatched_attempts = 0`, returning `Err(StoreError::Conflict("unresolved operation"))`), and **(3)** inside `settle_locked` / `settle_expired` on every terminal settlement (`Cancelled`, `DeadlineExceeded`, `Failed`, `Interrupted`), atomically transitioning any remaining `outcome = 'intent' AND (capability = 'repeatable_read' OR dispatched_attempts = 0)` rows on the run to `outcome = 'failed', revision = revision + 1` with bounded redacted evidence and ADR 0004 `openmettle/observation/1\0` `run_events` strictly before `run-terminal`; PR3 write-class two-transaction durable `dispatched_attempts` split (enabled when `runtime_feature_gates.two_phase_effect_intents_enabled = true`) where `approvals::record_fenced_intent` writes zero `operations` rows on `IntentResult::ApprovalRequired`, **Transaction 1** commits `outcome = 'intent'` with `dispatched_attempts = 0` and immutable `effective_expires_us = effective_until` (`$20`) for write capabilities strictly on `IntentResult::Applied(committed)`, followed by explicit 4-variant `StartPermit` handling on `CommittedIntent::start(&step)` in both `worker::execute` (`src/worker.rs:533`) and Step 5, and **Transaction 2** (separate `Fence::Step` transaction before attempt 1 and before each permitted retry) evaluates **live `EffectPolicy` + `{AUTH}` / `effective_expires_us` authority validity FIRST before checking `coalesce(dispatched_attempts, 3) >= 3`** (routing expired/revoked authority — including `dispatched_attempts IS NULL` or `dispatched_attempts == 3` — immediately through ledger-aware `approvals::invalidate_post_intent`) and guards `UPDATE openmettle.operations SET dispatched_attempts = o.dispatched_attempts + 1` with the live `{AUTH}` CTE (`AND o.outcome = 'intent' AND o.dispatched_attempts = 0` on attempt 1) before releasing the DB connection and issuing the outbound HTTP send; Streamable HTTP MCP (`2026-07-28`) adapter over `provider_http::transport` (restricted stateless interoperability profile omitting `Mcp-Param-*`, failing closed on `x-mcp-header` schemas on `tools/list`, encoding `Mcp-Name` per MCP `2026-07-28` `#value-encoding` using locked `base64 = "=0.22.1"`, consuming RFC 9110 §15.2 non-`101` HTTP/1.1 `1xx` interim responses `<= 4` frames while rejecting unrequested `101 Switching Protocols` as `ToolFault::TerminalRefusal`, exhaustive final non-`200` HTTP status mapping with `{408, 429, 502, 503, 504}` -> `ToolFault::Transient` and all other final non-`200` statuses including `500`/`401`/`403`/`201`/`202`/`204`/`3xx` -> `ToolFault::TerminalRefusal` with `0` retries and `outcome_unknown` + `StepResult::Stopped` on every post-send write refusal, `MAX_TOOL_RESPONSE_BODY_BYTES = 4 MiB` via `http_body_util::Limited`, fixed `8 KiB`/`32` header bounds, chunked-trailer rejection), `MCP_DNS_SLOTS`, `McpCredentialProvider` seam, `ApprovedAdapter` stopping `outcome_unknown` writes via `StepResult::Stopped` and reusing PR2's `StepResult::Invalidated(leases::Settled)` / `StepResult::LeaseLost` mappings, destination-authorized read-only `Executor::reconcile` under `Fence::Hold` (`dispatched_attempts: Option<i32>` on `leases::UnresolvedOperation`), and `PLAN-10` / `PLAN-22` conformance harness on synthetic `rcgen` TLS + PostgreSQL 18. | Synthetic TLS + PostgreSQL 18 tests: MCP `2026-07-28` request headers (`MCP-Protocol-Version: 2026-07-28`, `Mcp-Method`, `Mcp-Name` with `#value-encoding` fixtures for plain ASCII `execute_sql`, interior HTAB `"left\tright"` -> `=?base64?bGVmdAlyaWdodA==?=`, non-ASCII UTF-8, leading/trailing `0x20`, and literal `"=?base64?literal?="`, no `Mcp-Session-Id`, no `Mcp-Param-*`) and body `params._meta` over `application/json` and `text/event-stream` (SSE comments/progress notifications, mismatched IDs, duplicate final responses, `input_required`/server-initiated request rejection, `x-mcp-header` schema rejection, `MAX_TOOL_RESPONSE_BODY_BYTES = 4 MiB` limit, `8 KiB`/`32` header bounds, chunked-trailer rejection); **`openmettle.runtime_feature_gates.two_phase_effect_intents_enabled` worker rollout gate tests**: verifying (1) when `two_phase_effect_intents_enabled = false`, scoped MCP tool execution fails closed / stays disabled AND pre-existing ADR 0035 external approval writes keep `dispatched_attempts = NULL` (`N-1`-compatible single-phase behavior, never exposing a `dispatched_attempts = 0` write row to `N-1` workers or `N-1` expiry sweepers), and (2) once enabled to `true` (and on fresh `bootstrap`), two-phase zero-attempt writes are active; two-transaction durable `dispatched_attempts` accounting verifying `IntentResult::ApprovalRequired` writes zero `operations` rows before `approvals::park`, Transaction 1 commits `dispatched_attempts = 0` strictly on `IntentResult::Applied(committed)`, Transaction 2 commits `0 -> 1 -> 2 -> 3` via the `{AUTH}`-guarded `UPDATE` (`AND o.outcome = 'intent' AND o.dispatched_attempts = 0` on attempt 1) under the monotonicity trigger, and concurrent logout/revocation interleaving between `authorized()` and `{AUTH}`-guarded `UPDATE` produces `0` rows updated, zero increment, `StepResult::Invalidated(settled)` -> `WorkEnd::Invalidated(settled)`, and zero sends; **live-authority-before-exhaustion tests for `approvals::start_replayed_read` AND Step 5 Transaction 2** covering **both `dispatched_attempts = NULL` and `dispatched_attempts = 3`** under **both expired and revoked** authority (verifying immediate `approvals::invalidate_post_intent` settlement — `openmettle.run-approval-expired` / `openmettle.run-revoked` for reads, `Reconciling`/`interrupted` for post-dispatch writes — skipping ordinary failed observation and model continuation, with zero sends); **end-to-end durable zero-attempt write discovery, send-permit, `WorkEnd::Handoff`, `leases::handoff` `time_to_reclaim`, reclaim & terminal settlement tests**: **(a) consumed human approval (`approval_id IS NOT NULL`) zero-attempt successor send & post-Transaction-1 expiry/revocation tests**: Worker 1 commits Transaction 1 (`dispatched_attempts = 0`, `approval_id IS NOT NULL`) and yields on `Stop::Shutdown` AND in a second fixture on `StartPermit::LeaseMarginExhausted` (`WorkEnd::Handoff` with `> settings.lease` remaining), proving HTTP `decide` still sees `REQUEST.consumed = true` while Worker 2's `approvals::pending_effect` (`PENDING_EFFECT`) discovers `(approval_id, proposal)`, `record_fenced_intent` re-verifies live `EffectPolicy` + `{AUTH}` (`run_approvals` + `deciding_session_id`) + `effective_expires_us` and returns `IntentResult::Applied(CommittedIntent)`, Transaction 2 commits `dispatched_attempts: 0 -> 1`, the write executes once, and the run settles `succeeded`; AND in paired negative fixtures where `deciding_session_id` is revoked or `effective_expires_us` lapses after Transaction 1, Worker 2's `record_fenced_intent` routes immediately through `approvals::invalidate_post_intent` (`IntentResult::Invalidated(settled)` -> `outcome = 'failed'`, `openmettle.run-revoked` / `openmettle.run-approval-expired`, zero sends); **(b) automatic write (`approval_id IS NULL`) zero-attempt successor send & post-Transaction-1 expiry/revocation tests**: Worker 1 commits Transaction 1 (`dispatched_attempts = 0`, `approval_id IS NULL`) and hands off (`WorkEnd::Handoff` with `> settings.lease` remaining), proving Worker 2 discovers the open unsent write via `Executor::step` replay/pre-round check, `record_fenced_intent` re-verifies `eligible && yolo` + `hydrate_worker_principal` + `authorize_capability(YOLO)` + `effective_expires_us` and returns `IntentResult::Applied(CommittedIntent)` (or `IntentResult::Invalidated(settled)` with zero sends if revoked/expired), Transaction 2 commits `0 -> 1`, the write executes once, and the run settles `succeeded` (while proving rows with `dispatched_attempts IS NULL`, `dispatched_attempts >= 1`, or `outcome <> 'intent'` NEVER receive a write send permit and return `IntentResult::Replayed(op)`); **(c) `WorkEnd::Handoff` + `leases::handoff` `time_to_reclaim` boundary tests (`> settings.lease` vs `<= settings.lease`)**: (i) with `> settings.lease` remaining, `WorkEnd::Handoff` calls `leases::handoff` -> `release_locked` -> `reclaim_next` -> `succeeded` (and if time subsequently elapses to `<= settings.lease` before reclaim, `settle_expired` settles `DeadlineExceeded` at `execution_expires_at` with `n = 0`, closing `dispatched_attempts = 0` to `outcome = 'failed'` with zero `Reconciling`/`Interrupted`), and (ii) with **`<= settings.lease` remaining (e.g., `10 s` left on a `30 s` lease)**, `WorkEnd::Handoff` calls `leases::handoff` which sees `NOT time_to_reclaim` and calls `settle_locked(..., Settle::Stopped)` right inside the same `Fence::Hold` transaction, immediately settling **`Resolution::DeadlineExceeded`** (`state = 'failed'`, `{"reason":"deadline_exceeded"}`) and atomically closing `dispatched_attempts = 0` to **`outcome = 'failed', revision = revision + 1`** strictly before `run-terminal` (`204 No Content` on terminal SSE cursor, zero stranded unreclaimable run, zero `Reconciling`/`Interrupted`); **(d) `Stop::Cancel` / `ExecState::Cancelling` direct terminal settlement, `Settle::Succeeded` guard & mixed-write regression tests**: proving `Stop::Cancel` on a `dispatched_attempts = 0` write settles directly to `cancelled` + `outcome = 'failed', revision = revision + 1` with zero `Reconciling`/`Interrupted`, `Settle::Succeeded` (`StepResult::Finished`) with one `dispatched_attempts = 0` write in both `ExecState::Running` (`!time`) and `ExecState::Cancelling` returns `Err(StoreError::Conflict("unresolved operation"))` (never settling `Succeeded`), and mixed writes (`1` `dispatched_attempts = 0` + `1` `dispatched_attempts = 1`) yield `n = 1` from `leases::unresolved!()` (`Reconciling(1)` when `time == true`; when `time == false` or `Interrupted`, `dispatched_attempts = 0` -> `outcome = 'failed', revision = revision + 1` and `dispatched_attempts = 1` -> `outcome = 'outcome_unknown', revision = 1` with terminal `Interrupted(1)`); **post-intent effect/endpoint-key/session expiry & revocation settlement tests**: (a) pre-attempt-1 expiry (`StartPermit::AuthorityExpired` -> `approvals::expire_unstarted_intent` / `approvals::invalidate_post_intent` -> `openmettle.run-approval-expired`, zero `reconciling`, zero sends, plus clock-skew recomputation), (b) post-ambiguous-attempt-1 expiry (`dispatched_attempts == 1` -> `Reconciling` / `interrupted`, `outcome_unknown`, zero retry sends), (b2) caller-independent in-process `repeatable_read` retry invalidation (`dispatched_attempts = 1` + transient `503` -> expiry/revocation -> `outcome = 'failed'` + `openmettle.run-approval-expired`/`revoked`, `1` total send), (b3) shorter-lived `deciding_session_id` expiry vs revocation (`effective_expires_us` + live unrevoked-credential SQL recovery classifying natural expiry as expiry, never `cancel_reason = "revoked"`), (c) immediate `Settled::Reconciling` lease-release via `leases::release_lease` at `src/worker.rs:660-663`, and (d) defense-in-depth `openmettle.resolve_terminal_write_intents()` trigger tests (verifying `NEW.state = 'succeeded'` invariant guard and `NEW.state IN ('failed', 'cancelled', 'interrupted')` fallback transitioning any remaining revision-zero write `intent` to `outcome_unknown` strictly before `run-terminal` with `204 No Content`); `WorkEnd::Incomplete` drain-expiry contention matrix across `non_repeatable`, `idempotent`, `lookup`, unacknowledged-commit recovery (with live `EffectPolicy` withdrawal/change, capability revoke+re-grant, and `deciding_session_id` logout), and direct terminal settlement with `<= 1` lease interval remaining; `StepResult::LeaseLost` deposed-worker tests on both reclaimed non-terminal and already-terminal runs; `lookup` reconciliation with/without `downstream_handle` enforcing live destination authorization under `Fence::Hold` before `McpCredentialProvider` lookup (zero credential lookups when revoked) and excluding `repeatable_read`; semantic `isError: true` / `-32602` plus `PLAN-10` recovery and `PLAN-22` measurement harness; HTTP/1.1 `103 Early Hints` + `200 OK`, `> 4` interim overflow, unrequested `101 Switching Protocols`, and exhaustive final non-`200` status refusals (explicitly including first-attempt HTTP `401`/`403`/`500` writes -> `outcome_unknown` + `StepResult::Stopped`, zero retries); SSRF/TLS/`tools/list`-drift/`> 4 MiB` refusals; canary redaction checks; end-to-end `park` -> `decide` -> resume -> `ApprovedAdapter::send` -> spill -> `artifact.read_range` round trip including positive same-key replay (`approval = None` resolving `effective_approval = stored_approval_id.as_deref()`, `Err(CONFLICT)` on mismatched `Some(other_id)`), originating/deciding session logout, `EffectPolicy` withdrawal/change, capability revoke+re-grant, and share-revocation/retention replay refusals. |

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
  bootstrap_auto_pin_allowed))`** (`GRANT SELECT ... TO openmettle_api, openmettle_worker` and
  `GRANT UPDATE (volume_id, bootstrap_auto_pin_allowed) ... TO openmettle_api`), moving
  `(volume_id, bootstrap_auto_pin_allowed, adoption_run_id)` off the counter table
  `storage_instance` (which keeps only `warn_pct_1`, `warn_pct_2`, `config_revision` alongside
  its byte counters) so runtime `reserve`/`settle`/`release`/`purge` ONLY ever take `FOR SHARE`
  on `storage_volume_control` under canonical lock order **`runs -> storage_reservations ->
  artifacts -> artifact_revisions -> storage_volume_control -> storage_accounts ->
  storage_instance`** (eliminating `FOR SHARE -> FOR NO KEY UPDATE` self-upgrade deadlocks on
  `storage_instance`), pinned volume identity (`openmettle.storage_volume_control.volume_id` +
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
  (state = 'reserved' AND payload_ino IS NOT NULL))`), and the unified **4-state** cleaner
  lease + **`staging/.reclaim.<id>`** hard-link anchor protocol shared by all 4 cleaners
  (`artifact_fs::abort`, `reconcile_expired`, generic run-linked cleaner, and
  `reconcile_run_spills`) — `reclaim_state text NOT NULL DEFAULT 'none' CHECK (reclaim_state IN
  ('none', 'claiming', 'truncated', 'anchor_pending_unlink'))`, `reclaim_claim_token uuid`, and
  `reclaim_lease_until timestamptz` (`CHECK ((state = 'reserved' AND reclaim_state IN ('none',
  'claiming', 'truncated')) OR (state = 'released' AND reclaim_state IN ('none',
  'anchor_pending_unlink')) OR (state = 'settled' AND reclaim_state = 'none'))`, `CHECK
  ((reclaim_state IN ('claiming', 'truncated') AND reclaim_claim_token IS NOT NULL AND
  reclaim_lease_until IS NOT NULL) OR (reclaim_state IN ('none', 'anchor_pending_unlink') AND
  reclaim_claim_token IS NULL AND reclaim_lease_until IS NULL))`, `CHECK (reclaim_state NOT IN
  ('truncated', 'anchor_pending_unlink') OR NOT publish_pending)`), with runtime grants `GRANT
  INSERT (lease_expires_at, stage_claimed)` and `GRANT UPDATE (lease_expires_at,
  adoption_unverified, stage_claimed, payload_ino, publish_pending, reclaim_state,
  reclaim_claim_token, reclaim_lease_until)` to `openmettle_api, openmettle_worker`, backed by
  `V1-17` PR2's two `SECURITY INVOKER` (`SET search_path = pg_catalog`) PostgreSQL triggers:
  `openmettle.enforce_runtime_storage_volume_pinned()` (`BEFORE UPDATE` on
  `storage_reservations` `WHEN (OLD.state = 'reserved' AND NEW.state = 'released')` and
  `artifact_revisions` `WHEN (NEW.state IN ('purging', 'purged'))`, locking
  `openmettle.storage_volume_control WHERE id FOR SHARE` and failing closed with `OMQ03` if
  **`NOT FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL`**) and
  `openmettle.enforce_storage_reservation_monotonic_guards()` (`BEFORE UPDATE ON
  openmettle.storage_reservations FOR EACH ROW`, raising `OMQ03` for non-`openmettle_owner`
  roles if `OLD.adoption_unverified AND NOT NEW.adoption_unverified`, `OLD.payload_ino IS NOT
  NULL AND NEW.payload_ino IS DISTINCT FROM OLD.payload_ino`, or `OLD.stage_claimed AND NOT
  NEW.stage_claimed`), shared `StagingSweepState` in `worker::maintenance`, `artifact_fs::purge_due`
  leaf `payload_ino` verification + `staging/<id>` hard-link alias detach, `openmettle-admin`
  adoption preservation of valid `'truncated'` holds (`staging/.reclaim.<id>` matching
  `st_ino == payload_ino && st_size == 0`), and `artifact_fs`'s `rustix`-backed
  (`default-features = false, features = ["fs", "std"]`, 100% safe Rust under `unsafe_code =
  "forbid"`) verified directory-descriptor infrastructure (`root_fd`, `staging_dir_fd`,
  `revisions_dir_fd`) using **`rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id,
  AtFlags::empty())`** (keeping `staging/<id>` linked until `storage::settle` commits so `N-1`
  API retries hit `Err(Error::InProgress)` without overwriting `revisions/<id>`) and requiring
  `ReadWriteMany` shared-volume qualification of `O_CREAT | O_EXCL | O_NOFOLLOW`, `linkat`
  (`Errno::EXIST`), file + directory `fsync`, two-client / separate-mount `flock(2)` exclusion,
  and stable 64-bit `st_ino` coherence + second-client recovery across clients and remounts.
  **V1-14 PR2 sequences after V1-17 PR2** to reuse that foundation with zero additional Cargo
  crates. Under that shared contract:
  - **Mixed-version rollout & `Store::read`:** HTTP `Store::stage` and `Store::publish`
    (`openmettle_api`) succeed during mixed-version rolling upgrade while
    `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL` (skipping sentinel
    reads while `volume_id IS NULL`, verifying role-tagged sentinels once `volume_id IS NOT
    NULL`), whereas worker `publish_bytes` and all 4 cleaners strictly require `volume_id IS
    NOT NULL AND adoption_run_id IS NULL`. `StagedFile::drop` and writers (`publish_bytes` and
    `Store::stage`) are 100% non-destructive (never calling `set_len(0)` and never calling
    `unlinkat` prior to committed `state = 'settled'`, with only post-commit best-effort detach
    of `staging/<id>` under `LOCK_SH` after `storage::settle` commits), and `Store::read`
    verifies `sr.adoption_unverified = false` and `file_meta.ino() == sr.payload_ino` whenever
    `sr.payload_ino IS NOT NULL` (allowing `sr.payload_ino IS NULL` only while
    `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL`).
  - **Shared `StagingSweepState` (NEVER calling `set_len(0)` on `'settled'`, `'released'`, or
    `.reclaim.<id>`):** Requires `storage_volume_control.volume_id IS NOT NULL AND
    adoption_run_id IS NULL` (serializing its `> 900 s` zero-row orphan check with
    `storage_volume_control FOR SHARE -> storage_instance FOR UPDATE`), queries `SELECT state,
    adoption_unverified, payload_ino, reclaim_state FROM openmettle.storage_reservations WHERE
    id = $1::uuid`, skips `adoption_unverified = true` across all states: on `staging/<id>`
    with `state = 'settled'`, preserves `staging/<id>` 100% untouched (zero `set_len(0)`, zero
    `unlinkat`) whenever `adoption_unverified = true OR payload_ino IS NULL OR staging_ino !=
    payload_ino`, and when `staging_ino == payload_ino` unlinks `staging/<id>` ONLY (NEVER
    `set_len(0)`) under `LOCK_EX` -> `drop` -> `fsync(&staging_dir_fd)` iff `revisions/<id>` is
    `S_ISREG` same local `st_dev` with `rev_stat.st_ino as u64 == payload_ino` OR
    `revisions/<id>` is `ENOENT` and a fresh `READ COMMITTED` `SELECT state FROM
    openmettle.artifact_revisions WHERE reservation_id = $1::uuid` returns `Some('purged')`
    (preserving `staging/<id>` untouched otherwise); on `staging/<id>` with `state =
    'released'`, NEVER touches `staging/<id>` when `payload_ino IS NOT NULL`, and when
    `payload_ino IS NULL` unlinks only `st_size == 0` under `LOCK_EX` (never `set_len(0)`); on
    `staging/.reclaim.<id>`, unlinks ONLY when `state = 'released' AND reclaim_state =
    'anchor_pending_unlink' AND NOT adoption_unverified AND payload_ino IS NOT NULL` and
    `.reclaim.<id>` matches `S_ISREG`, same local `st_dev`, `st_ino == payload_ino`, and
    `st_size == 0` under `LOCK_EX` -> `drop` -> `fsync(&staging_dir_fd)` -> `SET reclaim_state
    = 'none'` (skipping once `reclaim_state = 'none'`).
  - **`artifact_fs::purge_due` hard-link alias detach & `payload_ino` verification:**
    `storage::begin_purge` joins `storage_reservations` requiring `NOT sr.adoption_unverified
    AND sr.payload_ino IS NOT NULL`; before `storage::confirm_purge`, `purge_due` verifies
    `revisions/<id>` (refusing non-regular, wrong local `st_dev`, or `st_ino != payload_ino`
    with zero `set_len(0)`, zero `unlinkat`, and zero `confirm_purge`), probes `staging/<id>`
    and detaches any matching `staging_ino == payload_ino` hard-link alias under `LOCK_EX`
    (`set_len(0)` + `sync_all()` + `unlinkat`, leaving foreign `staging_ino != payload_ino`
    untouched), and unconditionally executes BOTH `fsync(&revisions_dir_fd)` AND
    `fsync(&staging_dir_fd)` strictly before `storage::confirm_purge`.
  - **Exact complement cleaner partition:** **V1-14 (`artifact_fs::reconcile_run_spills`,
    including its `state = 'released'` retry pass) is the sole automatic cleanup owner of
    `operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%'` rows**, and **V1-17
    ([ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md))'s generic
    run-linked `storage_reservations` cleaner uses the exact logical complement `run_id IS NOT
    NULL AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')`** (owning any
    legacy pre-upgrade malformed `tool-spill:%` row with `operation_id IS NULL`), while `V1-17`
    PR2's `storage_reservations_tool_spill_binding_guard` trigger (`23514`) forbids inserting or
    updating `idempotency_key LIKE 'tool-spill:%'` with `run_id IS NULL OR operation_id IS NULL`.
    V1-14 enforces storage byte reservations through ADR 0005, ADR 0035 and ADR 0040 PR2 and
    leaves non-storage quotas gated on V1-17.
- **V1-07 (#8).** Owns the live worker turn executor connecting ADR 0038 model rounds to this
  tool adapter.
- **Issue #14** remains open through PR1, PR2 and PR3 until all acceptance criteria are
  implemented and verified.
