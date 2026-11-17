# 0004 — Run, event and operation persistence

Status: implementation of the coordinator-agreed V1-02 persistence increment, 17 November
2026; independent review and qualification remain required. Related: core #3 and sprint #34.
This does not complete #3 or enable product APIs. Follow ADR 0003 for migration and role
provisioning. Migrations 1 and 2 are unchanged.

## Scope and identities

Migration 3 adds `conversation_branches`, `runs`, `run_events` and `operations`. A branch is
an immutable identity with an optional fork message, constrained to its conversation and
scope. It has no mutable head or admission guard. A run references that branch and an input
message in the same conversation. The actor is separate from the conversation's private
owner. Neither a project scope nor a valid foreign key grants access to another user's rows.
V1-05 authorization is required before exposing this data. RLS remains a future decision.

Runs store immutable input/configuration bytes, format/version, identity and digest. Callers
must include all effective execution choices and pinned profile/policy revisions in those
bytes. Credentials must not be included. Snapshot interpretation is not implemented. Tenant
indexes support scope/conversation runs, scope/run events and operations; actor lookup has a
separate index. Foreign keys use NO ACTION. There is no retention or deletion job.

The nine run state names are `queued`, `running`, `waiting`, `cancelling`, `reconciling`,
`succeeded`, `failed`, `cancelled` and `interrupted`. Wait reason is separate. This is storage
vocabulary only. Application roles can insert only the default queued state and cannot update
state or wait reason. There are no transitions, leases, attempts, deadlines or cancellation
handlers. The linked [lifecycle Page](https://chatgpt.com/space/page_b77d424331e88191bac6eacd40ee70b7)
(sequence 5 inspected) describes proposed policies, not approved execution defaults.

## Exact identity encoding and limits

`src/runs.rs` computes SHA-256 itself; no helper accepts a caller-supplied digest. Each
identity starts with its fixed ASCII domain below, including a trailing zero byte. Every
subsequent field is its unsigned 64-bit big-endian byte length followed by exactly those
bytes. Strings are UTF-8 without normalization. UUID inputs must use lowercase canonical
36-character spelling. Integers inside fields use signed big-endian i32/i64 encoding.
There is no generic canonical JSON layer.

| Domain | Fields in order |
| --- | --- |
| `openmettle/run/1` | scope, actor, conversation, branch, input message, idempotency key, snapshot format, snapshot version (i32), input bytes, configuration bytes |
| `openmettle/event/1` | scope, run, append key, format, version (i32), payload |
| `openmettle/intent/1` | scope, run, logical key, target, capability, request format, version (i32), request bytes |
| `openmettle/intent-event/1` | operation ID, complete intent identity bytes |
| `openmettle/observation/1` | scope, run, operation, append key, expected revision (i64), outcome, handle-presence byte (0 or 1), handle UTF-8 (empty if absent), evidence format, version (i32), evidence bytes |

All domains have the trailing zero byte even though it is not displayed in the table.
Replays compare complete stored identity bytes and digest, and also compare the actual stored
immutable data fields. Equal supplied hashes cannot disguise a different stored request.
Replay excludes mutable operation observations and run progress.

Initial persistence limits, not measured capacity or a final wire schema:

- Combined run input/configuration: 256 KiB.
- Event, operation request and observation evidence: 64 KiB each.
- Idempotency, logical and append keys and format identifiers: 1–128 UTF-8 bytes; no NUL.
- Target: 1–512 bytes. Optional downstream handle: 1–2048 bytes.
- Format versions are positive i32. Sequence and revision counters are nonnegative i64,
  with positive event sequences. Overflow fails atomically.

Identity columns allow envelope overhead: 264 KiB for run identity and 72 KiB for event and
operation identity. Large files belong in future immutable artifact storage, not these fields.

## Transactions and recovery

Public helpers accept a caller-owned SQLx PostgreSQL transaction. Use READ COMMITTED and
bounded caller connection/statement/lock deadlines. They create nested savepoints, release
on success and roll back on any returned error. SQLx queues rollback when a cancelled helper
drops its savepoint. If rollback fails or the connection is lost, abandon the transaction;
never acknowledge a successful commit. Helpers never commit the outer transaction. They do
not undo writes made by the caller before the helper: the caller must roll back the outer
transaction when rejecting a composed admission.

`create_run` inserts a run and its deterministic empty `openmettle.run-created` version-1
event under append key `run-created`. Unique `(scope_id, actor_user_id, idempotency_key)`
serializes duplicates. On conflict a separate statement reads the committed winner. Same
identity returns its run ID; changed identity conflicts. This is persistence, not admission:
current authorization, branch guards, budgets and request validation are absent. V1-10 must
look up authorized replays before making new-message/branch decisions and compose accepted
messages, reservations and the run in the same outer transaction.

`append_event` locks the run with FOR NO KEY UPDATE, checks `(run_id, append_key)`, increments
its counter, then inserts the event. Counter and event commit together. The lock is held until
the outer transaction ends. Thus later committed sequences for the same run cannot overtake
an earlier uncommitted append. Other runs remain independent. Rollback returns the counter
to its committed value. Exact replay returns the original sequence; changed identity conflicts.
This ordering is a helper protocol; raw INSERT privileges do not force every writer to follow
it. Unique keys/FKs enforce only their stated relational constraints. There is no global order.

`record_intent` locks the run and deduplicates `(run_id, logical_key)` by exact identity. It
inserts the operation and an event keyed `intent:<operation UUID>` atomically. Capability
values are `repeatable_read`, `idempotent`, `lookup`, `non_repeatable`; these record an adapter
classification, not permission or proof that a backend supports safe replay. The event payload
contains only the operation ID; its identity also binds the request.

Operation outcomes are `intent`, `outcome_unknown`, `succeeded`, `failed`. An observation
requires an expected revision and a run-wide append key. It updates the operation and appends
its evidence event atomically. Exact retries return their original revision even after later
observations. New stale revisions are rejected. Known outcomes require nonempty evidence;
the caller remains responsible for its authoritative meaning. Known outcomes cannot be
rewritten by the helper. Once recorded, a handle must be repeated unchanged. Unknown outcomes
can acquire a handle and later settle. A timeout does not automatically mean failure.

A committed intent is not dispatch authorization. No helper sends requests, retries effects,
reconciles a backend or claims exactly-once execution. After an uncertain commit, recover by
the same key and bytes. Do not invent a new key or silently dispatch again. There is no public
retry-window promise. Keys, events and evidence are retained until a later retention contract.
Event keys reserved above share the run namespace; collision with a different identity fails.
No database connection may be retained across external execution or approval waits.

## Privileges and upgrade compatibility

`src/boundaries.sql` remains the authoritative explicit grant allowlist. New grants are allowed
only when successful migration 3 exists in history; v2 preflight retains the old contract.
Migrations never edit history or relax PUBLIC/default/member-role restrictions.

| Object | API | Worker |
| --- | --- | --- |
| Branches | SELECT, INSERT | SELECT |
| Runs | SELECT, INSERT only immutable identity/snapshot columns | SELECT |
| Run counter | UPDATE last_event_sequence | UPDATE last_event_sequence |
| Events | SELECT, INSERT | SELECT, INSERT |
| Operations | SELECT | SELECT, INSERT only immutable intent columns |
| Operation observation | None | UPDATE outcome, revision, handle, evidence format/version/bytes |

Neither application role receives state/ownership/snapshot mutation, event mutation, DELETE,
DDL, history access, grant options or function execution. Column INSERT grants exclude initial
run state/counter and operation outcome/revision. Database owner privileges remain operational
rather than application authorization.

New migrators accept populated v2, apply v3 and rerun. The prior API/worker still serve their
operational endpoints and use existing grants. The old migrator refuses v3 at its strict
preflight, possibly before SQLx can report an unknown version. Refusal is correct; do not weaken
it to enable downgrade. Deploy uses the release's new migrator before rolling out processes.
Postflight refusal still occurs after migration commit, as documented in ADR 0003.

There is no new pool or listener. Preserve ADR 0003's aggregate connection budget, including
surge replicas, one migrator, admin/backup headroom and future separate LISTEN sessions.

## Dependencies and verification

Add direct exact-pinned `sha2 = 0.10.9`, default features disabled. Origin:
https://github.com/RustCrypto/hashes, licence MIT OR Apache-2.0. This version was already locked
and compiled through SQLx; Cargo.lock adds one root dependency edge and no packages or source
changes. The direct dependency makes the request digest implementation explicit. There is no
new runtime, database extension, serialization framework or canonical-JSON dependency.

`tests/schema/durable.rs` reuses the existing disposable PostgreSQL fixture and calls the real
helpers. It covers duplicate identities, caller rollback, helper savepoint failures, append
ordering/replay/connection loss, operation observations, ownership and role denials, and v3
migration failure/timeout/termination/retry. Released migration byte hashes are pinned in a
non-database test. CI builds the authentic 18f52463c9d6bc12dda4bd1558e4597e067018f8 release
from `git archive` and sets OLD_BINARY_DIR for populated upgrade and prior-binary checks.
These are required tests; their presence is not a claim that a particular run passed.

V1-02 still owes grants, artifacts/revisions and reservations/accounting constraints. V1-03
owns wire mapping; V1-05 authorization; V1-07 branch editing; V1-10 admission and queue policy;
V1-11 claims/fencing/recovery; V1-12 authorized SSE and replay retention; V1-13 approval bindings;
V1-15 storage publication; V1-17 quota composition/reconciliation. Schema contracts precede
those behaviors without requiring their completed services. Inference budgets remain owned
by the gateway and device-capacity authority remains separate. No dependent API is unblocked.
