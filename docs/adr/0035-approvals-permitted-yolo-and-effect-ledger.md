# 0035 — Approvals, permitted YOLO and the effect ledger

Status: proposed V1-13 design (PR1), 21 November 2026. Refs #13. The base is schema 20
at `5cae93b1265183f58aed30858f738922a2661915`. PR2 and PR3 own implementation and
qualification. The [v1 architecture](../../ARCHITECTURE-v1.md#tool-permissions-and-yolo-mode)
defines the run mode and its limits.

## Decision

Authorize one logical operation against an exact request. An approval request may exist
before an operation has an intent. An affirmative decision makes a parked run eligible for a
worker. Only a freshly authorized lease holder may commit the intent and send the request.
PostgreSQL records what the application authorized and what the endpoint subsequently proved.

| Existing boundary | V1-13 addition |
| --- | --- |
| [ADR 0004](0004-run-persistence.md), `src/runs.rs` | Bind the approval to the future `(run_id, logical_key)`. Use the existing operation UUID, intent identity and revisioned observations at dispatch. |
| [ADR 0006](0006-grant-persistence.md) and [ADR 0027](0027-authorization-and-private-projects.md), `src/authz.rs` | Hydrate the actor on the primary. Bind the effect to the grant cycles and policy revisions that authorized it. |
| [ADR 0032](0032-durable-run-admission-and-fair-work-queue.md) and [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md), `authz::runs` and `authz::leases` | Resume an approved wait through the fair claim with its original execution deadline. ADR 0035 amends ADR 0033 to count `idempotent` writes with outcome `intent` or `outcome_unknown` as unresolved for park, settlement, `settle_expired` and reconciliation. |
| [ADR 0007](0007-application-api-contract.md) and [ADR 0034](0034-ordered-events-and-replayable-sse.md) | Give the actor a private decision endpoint. Project lifecycle events for authorized conversation readers. |

## Request identity and decision

The reviewed tool adapter resolves a pinned tool ID and version, validates the arguments
against that version's schema and expands defaults before the worker asks for approval.
It resolves the exact destination, including the connection/account, action and recipient or
resource addressed. Use a bounded, versioned target identifier that distinguishes those
fields. A display name, host alone, wildcard or mutable alias cannot identify a destination.
If the adapter cannot pin the destination through send (including redirects), refuse the call.
Credentials stay in the adapter. A credential reference must identify its authorized account.

The v1 arguments format is a JSON object. Reject duplicate or unknown fields, ambiguous
numbers and input outside the tool's bounds before converting to a value. Encode compact
UTF-8 JSON with object names sorted recursively by UTF-8 bytes, array order preserved,
strings escaped by the pinned `serde_json` compact writer and no Unicode normalization.
Accept null, booleans, strings and signed 64-bit integers as scalars. A tool requiring
decimals must define their exact string representation in its schema. Compute
`canonical_arguments_digest = SHA-256(canonical_argument_bytes)` in the store.

Use ADR 0004's `identity` and `digest` functions. The domain is
`openmettle/effect-approval/1` with a trailing NUL. In order, its length-prefixed fields
are `scope_id`, `run_id`, `logical_key`, `actor_user_id`, `tool_id`, `tool_version`,
`canonical_arguments_digest`, `destination`, `approval_expires_at`, and the digest of the
authority evidence below. UUIDs are canonical lowercase text, digests are 32 raw bytes,
and the deadline is signed big-endian i64 UTC microseconds since the Unix epoch. Bound tool
ID and version to 128 UTF-8 bytes each and destination to the 512-byte `operations.target`
limit. Bound the **whole** versioned operation request (including arguments and evidence)
to ADR 0004's 64 KiB before parking. Keep the exact canonical bytes and immutable fields.
When replaying a proposal or using it for dispatch, reconstruct the binding and compare
fields, bytes and digest. The digest on the wire lets a client name what it saw.
Possession of it confers no authority.

PR2 adds these records to `openmettle` in one additive migration. Names below are proposed.

| Record | Identity and writes |
| --- | --- |
| `runs` admission evidence | API inserts the authorized `execution_mode`, `originating_session_id` (nullable `text`, no FK to `local_sessions`) and `admission_evidence` (bounded, versioned authorizing grant and policy revisions). All three columns are nullable for pre-migration rows. The migration grants `openmettle_api` column `INSERT` only and `src/boundaries.sql` verifies that it has no `UPDATE` on them. |
| `run_approvals` | Worker inserts an immutable UUID `id`, scoped run FK `(scope_id, run_id)`, logical key, tool, version, canonical arguments, destination, authority evidence, binding digest and two database timestamps, `approval_expires_at` and `resume_execution_expires_at`. Derive the actor from the locked run and bind its immutable ID. Keep `UNIQUE (run_id, logical_key)`, `UNIQUE (scope_id, run_id, id)` for the wait pointer and `UNIQUE (scope_id, run_id, id, logical_key)` for the operation. |
| `run_approval_decisions` | API inserts an immutable receipt with `approval_id` as primary key and a scoped FK to the request. Record the actor from the authenticated session, that session's internal locator, request binding digest, decision (`approve` or `deny`), scoped idempotency key and DB decision time. Add `UNIQUE (approval_id, decision)` for the operation's decision FK. Exact replay reads this row. |
| `runs.approval_wait_id` | Nullable UUID. Composite FK `(scope_id, id, approval_wait_id)` to `run_approvals(scope_id, run_id, id)`. The worker sets it on park. It names the latest request through resume and terminal history. Only a run in `waiting` for `approval` with this pointer can be claimed by the approval path. |
| `operations.approval_id` | Nullable UUID, unique when present. Two composite FKs bind a human-approved operation to its exact request and positive decision (below). For YOLO the worker records policy evidence in the immutable request envelope. |

Of the approval fields, only the client-requested mode (`ordinary` or `yolo`) belongs in
`RunInput.config`. Its bytes in `config_snapshot` contribute to `request_identity` and
`request_digest`. Changing the requested mode under the same `Idempotency-Key` returns
`409 idempotency_conflict`. After `admit_run` takes the project then actor locks (the
owner's user lock for a personal scope), it checks current authority. For a new admission
it captures the three server fields under those locks and passes them to `insert_run` in
`AdmissionColumns` (`src/runs.rs`). They are outside the request identity and digest.
An authorized exact replay reads the original run, even from another active session or
after a grant revision advances. It preserves the original snapshot bytes, identity,
digest and all three server columns, including NULLs on pre-migration rows.

`runs.actor_approval_id` references the local **identity** approval. Each tool approval
has its own UUID. PR2 extends the validated `sessions::Context` with the non-secret
`local_sessions.id`. Session cleanup can delete expired or revoked sessions while the
locator remains on the run or receipt. A missing bound session fails the effect check.
Never store a cookie, bearer secret or secret hash in an approval.

On `operations`, use `(scope_id, run_id, approval_id, logical_key)` as a foreign key to
`run_approvals(scope_id, run_id, id, logical_key)`. Following migration 5's `cycle_kind`
pattern, generate the stored column `approval_decision` as
`CASE WHEN approval_id IS NOT NULL THEN 'approve' END`. Use `(approval_id, approval_decision)`
as a foreign key to `run_approval_decisions(approval_id, decision)`. With `MATCH SIMPLE`
on both FKs, a NULL approval ID needs no receipt. A non-NULL ID requires a matching
request and an `approve` receipt, even for a direct SQL insert.

The following `runs` constraint enforces the wait pointer and reason even when the reason is NULL.

```sql
CHECK (
    (wait_reason IS NOT DISTINCT FROM 'approval') =
        (state = 'waiting' AND approval_wait_id IS NOT NULL)
    AND (wait_reason IS DISTINCT FROM 'approval' OR claim_token IS NULL)
)
```

An approval wait therefore has a request and no claim. With a NULL token,
`runs_claim_check` forces `claimed_at` to NULL and `runs_lease_check` forces both
deadlines to NULL. After resume or settlement the run can retain its request pointer.
A bare wait with a NULL pointer and a NULL or other reason remains valid until the sweep.

Before creating a request, recording a new decision or dispatching the effect, rehydrate
the run actor with its admitted identity approval. Check `RunExecute` on the scope,
conversation and affected resources, the tool capability, destination policy and any
required live reservation.
Check the originating session's validity for this effect and, once approved, the deciding
session's validity too. Both must belong to this actor and identity approval. Check revocation,
expiry and issued provider, approval and user generations against current authority on
the primary. ADR 0027's general run continuation still permits background work after logout.
Withdrawing a session used to authorize an effect invalidates that effect.

The versioned, bounded authority evidence includes the applicable ADR 0006 assignment IDs
and active change cycles, local group membership and group revisions,
mapped observation identity and validity deadline when used, identity generations, applicable
capability grant/deny revisions (including absence), tool, endpoint and destination policy revisions and
required reservation identity and validity. Include the admission session locator. Order
entries by kind and stable key and length-prefix their fields as in ADR 0004. Require both
current authorization and the same evidence at use. Regrant, re-enable or restoration of
membership cannot make an old decision current. Unknown vocabulary, an unavailable authority,
or a missing proof prevents dispatch.

## Permitted YOLO

Admission defaults to ordinary approval. An authenticated actor must select YOLO explicitly
for this run. Under the locks for a new YOLO admission and at each automatic dispatch, evaluate
`authorize_capability(principal, platform, "runs.use_yolo", CapabilityGate::OptIn)` with
freshly loaded `PlatformPolicy`. Capture the active assignment and grant/policy revisions
in `runs.admission_evidence` at opt-in. Dispatch requires the same evidence and the stored
`execution_mode = 'yolo'`. A platform or user deny wins even for an account administrator. The same
actor must independently hold the effective project/resource grants and tool capability.

| Per-call policy result | Worker action |
| --- | --- |
| Prohibited, outside scope, destination denied or required quota/reservation unavailable | Refuse dispatch in either mode. A human approval cannot override the refusal. |
| Human confirmation mandatory under immutable platform policy | Park for a human decision even in a YOLO run. The server's reviewed policy fixes this class. A preference, administrator toggle or adapter declaration cannot remove it. |
| Ordinary confirmation required, eligible for YOLO | Park in ordinary mode. With explicit selection, current eligibility, valid quota and an allowed destination, record `yolo` and the exact per-call binding and policy evidence with the intent. |
| Policy allows a read without confirmation | Record its read classification and policy basis. It needs no human decision. |

The server never permits a tool call to grant itself authority, change account or platform
controls, export credentials or escape server isolation. An otherwise permitted change
to a resource's sharing audience always requires human confirmation.
Only reviewed, explicitly eligible classes can skip an ordinary prompt. Model output, tool
results, retrieved documents and memory are data. They cannot select the mode, attest to
a grant, change the destination allowlist or satisfy a prompt. Loss of YOLO eligibility
before intent requires a fresh ordinary approval if the action is still permitted, otherwise
stop. An existing intent goes to observation or reconciliation. Server mode grants no
local ACP permissions.

## Park, decision and fair resume

Use bounded READ COMMITTED transactions and `clock_timestamp()` on the primary. For each
mutation, test the deadline **after** acquiring the run lock. Equality means expired.

1. **Park.** Stop and join all work owned by the step. Under `leases::fenced` with
   `Fence::Step`, require the current token, live lease, `state = 'running'`,
   `cancel_reason IS NULL` and a future execution deadline. Under the same run lock require
   zero operations on this run with `outcome IN ('intent','outcome_unknown')` and
   `capability IN ('idempotent','lookup','non_repeatable')`. The proposed effect's
   `(run_id, logical_key)` must also have no `operations` row, whatever its outcome or
   capability. An existing row goes through ledger recovery. If work has not drained or
   a write is unresolved, follow ADR 0033 settlement and reconciliation. Park before
   calling `record_intent` for a new effect.
2. Copy the exact `execution_expires_at` to the request's `resume_execution_expires_at`.
   Set `approval_expires_at` to the earliest of that timestamp, the DB time plus the bounded
   server approval TTL (positive and at most the configured execution timeout) and the
   expiry of the authority evidence. An already due request cannot park. Insert the
   request, recheck the live step fence at the update, and set
   `state = 'waiting'`, `wait_reason = 'approval'`, `approval_wait_id = request.id`,
   `claim_token = NULL`, `claimed_at = NULL`, `lease_expires_at = NULL` and
   `execution_expires_at = NULL` together. Append the request and waiting events in that
   order and commit. An uncertain commit is read back by the same logical key and bytes.
   Never extend either deadline on a retry. Release the worker slot and database connection.
3. **Decide.** The API locks the run `FOR NO KEY UPDATE`, then looks up the scoped request.
   First handle an existing receipt under the replay rules below. For a new decision
   require this exact current wait, no cancel reason, valid authority, time before
   approval expiry and a matching client `binding_digest`. Insert the receipt and append the
   decision event in the same transaction. Approval makes the wait eligible for claim.
   It remains `waiting` without a lease. Denial immediately sets `cancelled`, clears
   `wait_reason`, sets `cancel_reason = 'requested'` and appends the existing terminal
   event under `run-terminal`.
4. **Resume.** Extend `authz::runs::claim_next`'s candidate set with approved current waits.
   Acquire `run_dispatch_lock` first, then select one run `FOR NO KEY UPDATE OF r SKIP LOCKED`.
   Apply the same actor/scope executing counts and least-loaded-actor, then `created_at, id`
   order across both sources. A waiting run counts as live and occupies zero executing slots.
   As in `src/authz/leases.rs`, materialize the locked run row before reading the clock.
   Sample the primary's `clock_timestamp()` once as `t`. Recheck the wait pointer,
   positive decision, state and cancel reason. Require both `t < approval_expires_at` and
   `t < resume_execution_expires_at`. For a resumed run set `running`, clear `wait_reason`, generate
   a fresh `claim_token`, set `claimed_at = t`, restore `execution_expires_at` from the
   request and set `lease_expires_at = least(t + lease, execution_expires_at)` using the
   restored value. Append the resume event and commit. First claims keep their existing
   queue deadline and start event. `queue_expires_at` governs the initial queue only.
5. **Use.** After claim, require a new `Step` fence and execution-time recheck for the exact
   approved effect before any new step. Use the decision logic behind `recheck_leased`
   inside the intent transaction. Read authority without taking project or user locks
   under the run lock. Revalidate the live step fence, evidence revisions and deadlines
   in the final guarded intent write against one primary snapshot. Give the adapter the
   exact committed request and a stop deadline capped by the lease stop point, execution
   deadline and approval validity for starting the call. Check that stop point again
   after commit, immediately before send.
   If any check fails, issue no call. Changed arguments, tool ID/version, destination or
   authority evidence invalidate the approval and settle the run. A replacement proposal
   for that invalidated operation requires a new admission. A replacement holder finding
   an approved wait pointer with no intent must repeat this entire check. Once an intent
   exists for the key, the ledger governs recovery. A later approval expiry cannot erase
   an observed result or authorize another send.

Human wait consumes wall-clock execution time. Copying the cap preserves migration 20's
`runs_lease_check` and migration 19's `runs_claim_check` without granting more time on
resume. A long wait can exhaust the run. There is no fresh execution allowance after a
second park, worker restart or lease renewal.

The API and the worker serialize denial, cancellation, expiry and resume on the run row.
The API never takes the dispatch lock. Archive/delete/disable retain their existing
ordered bulk cancellations. For a bound pending or approved wait, only server-observed
expiry (`approval_expires_at <= t`) fails the run with `approval_expired`. If the server
observes revoked or superseded authority on a still-live wait, it sets `cancelled` with
`cancel_reason = 'revoked'`. Both transitions clear `wait_reason` and append one
`run-terminal` event atomically. Decision submission commits any such transition before
returning a conflict. A wrong or stale digest from the client on a current, authorized,
unexpired wait returns `409 conflict` without changing the run, request, receipt or events.

The worker wait-expiry sweep selects from `runs` in ascending `id` order with
`FOR NO KEY UPDATE SKIP LOCKED` and a batch limit of 1–1000. Recheck under lock that
the state is `waiting` and either the current request is due (pending or approved), or
`approval_wait_id IS NULL OR wait_reason IS DISTINCT FROM 'approval'`. Each matching run
becomes `failed` with `wait_reason = NULL` and one `run-terminal` event in the same
transaction. Use `approval_expired` for a bound, due request and `invalid_wait` for a bare
or legacy wait. The latter needs no matching request row. Failing it frees the live actor
and scope slots, as `expire_queued` and `settle_expired` do for missing queue and
execution deadlines.

After resume, expiry before intent fails the run with `approval_expired` under the live
fence. If an intent exists, the holder settles using the ledger. A terminal run makes
all its approvals unusable. Keep the request and original receipt as history. During backup
restore, revoke the restored bound sessions and cancel parked approvals before enabling workers. Inspect
committed intents through read-only reconciliation while dispatch remains disabled.

## Effect ledger and recovery (PLAN-09)

Keep one `operations` row per `(run_id, logical_key)`. Extend the versioned `Intent.request`
envelope with tool/version, canonical arguments, destination, authorization basis and
endpoint contract. Human evidence names the approval and its binding. YOLO evidence records
the selected mode, authorizing grant and policy revisions, applicable quota/reservation,
actor, exact arguments digest and destination. The adapter supplies the reviewed endpoint
identity/version, idempotency support (`supported`, `unsupported` or `unknown`) and, when
supported, the endpoint's key namespace, validity window and actual outbound idempotency
key. Leave the key absent when support is unknown or unavailable. Allocate one key per
supported logical effect, persist it before send, and use it unchanged in
the endpoint's specified field. A caller's HTTP decision key has a different purpose.

| Stored `operations.capability` | Recovery with `intent` or `outcome_unknown` |
| --- | --- |
| `repeatable_read` | A reviewed side-effect-free read may run again within current authority and deadlines. |
| `lookup` | Query the existing `downstream_handle` or an independent authoritative read. Record only a proven outcome. |
| `idempotent` | Requires evidence that this exact endpoint deduplicates the same request in the recorded namespace and window. Consult the endpoint for the prior result when possible. Recovery never silently resends a write. |
| `non_repeatable` | Use an independent observation if available. Otherwise preserve uncertainty and interrupt. |

Unsupported or unknown idempotency on a write selects `lookup` when there is an authoritative
lookup, otherwise `non_repeatable`. An operation UUID alone cannot establish endpoint
support. Today's `record_intent` returns the same UUID for an insert and a replay.
Have the fenced store return which occurred under the run lock. Only the process that
observes a successful commit of a new intent may initiate that write. A lost commit reply,
crash before send, lost response or stale claim goes to ledger inspection. Neither an
identical approval receipt nor finding the same UUID is a send instruction. Release the DB
connection before adapter I/O.

Record observations under `Fence::Hold` with `record_observation`, the expected revision,
a stable append key and the original handle once known. A proven success or failure gives
`succeeded` or `failed` with evidence. Timeout, disconnect or ambiguous cancellation gives
`outcome_unknown`. A crash may leave `intent`. Either can settle later with proof. Preserve
terminal observations on replay. ADR 0035 amends ADR 0033's unresolved-operation rule
for park, settlement, `settle_expired` and reconciliation. For all four paths, count an
`idempotent` write with `outcome IN ('intent','outcome_unknown')` alongside `lookup` and
`non_repeatable` operations with those outcomes. Only `repeatable_read` is exempt.
Deduplication proves nothing about a write's result. A new holder may observe it, never
manufacture a new key or claim a clean cancellation while the result is unknown. A
revocation committed before the final authority observation prevents dispatch. A concurrent
revocation after that observation stops subsequent work and cannot recall the call. The database
transaction and the endpoint have independent commit points. External exactly-once
execution is not a guarantee.

## Roles and upgrade

Version-gate the additive migration and its `src/boundaries.sql` entries together as in
[ADR 0003](0003-schema-migrations.md). Both application roles read the request and decision
records. Restrict writes to the following columns or existing column grants.

| Role | Writes and additional reads |
| --- | --- |
| `openmettle_worker` | INSERT request fields, UPDATE `runs.approval_wait_id`, INSERT `operations.approval_id`. The existing worker grants cover claims, leases, `run_dispatch_lock`, observations and events. For effect-only session checks grant column SELECT on `local_sessions` for `id, user_id, approval_id, provider_id, identity_id, issued_client, issued_epoch, provider_generation, approval_generation, user_generation, created_ms, expires_ms, revoked`. Use existing authority-table reads. |
| `openmettle_api` | Grant column `INSERT (execution_mode, originating_session_id, admission_evidence)` on `openmettle.runs` and verify those grants in `src/boundaries.sql`. Never grant `UPDATE` on those columns. INSERT decision fields except DB-generated time. Existing run state, wait/cancel reason, event counter and event grants suffice for denial or expiry. Workers alone write requests, operation intent and lease fields. |
| `openmettle_issuance` | No approval, operation or dispatch privileges. Session issuance keeps its migration 18 boundary. |

Request/decision identity has no application UPDATE or DELETE grant. The worker cannot
insert a human decision or read session secret hashes. Existing raw SQL grants do not
enforce Rust fence or authorization protocols. Enable approval waits only after all active
claim, cancellation and recovery writers and event readers understand them. Existing rows
have NULL new references and admission evidence. Before adding the wait check, clear any
pre-migration `wait_reason = 'approval'` label with no request pointer. Preserve the run
state and event history. The worker sweep fails bare and legacy waits, including rows
with a NULL reason, and frees their live admission slots. They cannot resume.
Legacy intents remain observable history and never acquire inferred human authority, YOLO
eligibility or endpoint support.

## HTTP and visible events

Use ADR 0007 OpenAPI 3.2.1 operations, browser session with the configured Origin on writes
or native bearer, canonical path UUIDs, version header, `Cache-Control: no-store` and RFC
9457 problems. Authenticate and authorize each request on the primary before returning a
request or receipt. Require the run's actor and current `RunRead` visibility on the
scope and conversation (ADR 0034). A different actor (including a project owner,
account administrator or conversation reader), revoked access, deleted scope or mismatched
run/request returns `404 not_found`. An invalid session returns `401 unauthenticated`.
Listing a pending request or making a new decision also requires the admitted identity
approval, current execution and target authority, an unarchived project when applicable,
and the live originating session.

| Operation | Success |
| --- | --- |
| `listRunApprovals` · `GET /v1/runs/{run_id}/approvals` | `200` with an `items` array of at most one current, unexpired, authorized, undecided request. Return `approval_id`, `tool_id`, `tool_version`, `arguments_json` (the exact canonical UTF-8 text), `destination`, `binding_digest` (64 lowercase hex) and `approval_expires_at` (ADR 0007 Timestamp). Refuse tools whose effects cannot be shown without disclosing credentials. |
| `decideRunApproval` · `POST /v1/runs/{run_id}/approvals/{approval_id}/decision` | Require `Idempotency-Key` and a closed JSON body with `decision` (`approve` or `deny`) and `binding_digest`. Return `200` with the immutable approval ID, decision, digest and decision time. |

Derive the request key with ADR 0007's domain, operation and path, scoped to the actor
and the run's scope. The key stays stable across sessions. Serialize submissions on the run.
For an existing receipt, the same authenticated actor with current `RunRead` on the scope
and conversation can replay the identical key and input. Return the original receipt without a state change, even
after project archive, run cancellation or settlement, or logout of the originating
session. Receipt replay requires neither `RunExecute` nor a live originating session.
Changed input under the same key returns `409 idempotency_conflict`. A different key
after decision returns `409 conflict`. For a new decision, a client digest mismatch on
an otherwise valid wait returns `409 conflict` without mutation. An expired, cancelled
or invalidated wait also returns `409 conflict` under the transition rules above.
Reject malformed inputs with `400 validation`. An authority lookup failure returns the
existing availability/timeout problem and grants no approval.

Extend ADR 0034's `(format, format_version)` allowlist with the rows below. All formats
and wire types are version 1. Append in the state transaction with the existing per-run
sequence. `A` stands for the request UUID in a private append key. Use the displayed JSON
as the internal payload too. Each projection validates its closed shape and has a matching
OpenAPI `if`/`then` data schema and fixture.

| Internal format | Append key | Wire type | Closed wire data |
| --- | --- | --- | --- |
| `openmettle.run-approval-requested` | `approval-request:A` | `run.approval_requested` | `{}` |
| `openmettle.run-waiting` | `waiting:A` | `run.waiting` | `{"reason":"approval"}` |
| `openmettle.run-approval-decided` | `approval-decision:A` | `run.approval_decided` | `{}` |
| `openmettle.run-resumed` | `claim:<fresh token>` | `run.resumed` | `{}` |
| `openmettle.run-approval-expired` | `run-terminal` | `run.failed` | `{"reason":"approval_expired"}` |
| `openmettle.run-failed` (bare or legacy wait) | `run-terminal` | `run.failed` | `{"reason":"invalid_wait"}` |

The shared stream can prompt the actor to refresh the private endpoint. The decision,
request UUID, arguments, digest, destination, session locator, token, operation evidence
and handle stay out of frames and logs. Keep cursor binding, authorization on replay,
hidden-event sequence advancement and malformed-known-payload failure as in ADR 0034.

## Delivery and verification

| Slice | Deliverable and acceptance evidence |
| --- | --- |
| PR1 | This decision and the ADR 0004 pointer. Review against #13, migrations 3/19/20 and the live role and store boundaries. |
| PR2 | Deliver the migration, versioned privileges, admission evidence, binding and decision store, fenced park/consume, fair resume and bounded worker sweeps. Implement the ADR 0033 amendment for unresolved `idempotent` writes across park, settlement, `settle_expired` and reconciliation. Update `unresolved!()` in `src/authz/leases.rs`, the existing `idempotent` replay case in `tests/schema/worker_leases.rs` and the forward pointer in [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md). Exercise the real store as API and worker on PostgreSQL 18. |
| PR3 | Serve the two approval operations, extend the OpenAPI 3.2.1 document and SSE projection, generate fixtures and exercise both session channels, replay and refusals through HTTP on PostgreSQL 18. |

| Gate | Required cases |
| --- | --- |
| PR2 · binding and policy | Known-answer digest, reordered object keys, duplicate fields, changed array order, tool/version/recipient substitution. Test explicit opt-in, absent or denied grant, scope, exhausted reservation, immutable prohibition, prompt injection and stale mapped membership. Revoke then regrant between checks. |
| PR2 · admission and integrity | Replay after a grant revision advances and from a new active session. Compare the original identity, digest and all three server columns. Changing the requested mode under the same key must conflict. Verify API INSERT and denied UPDATE on each evidence column. As worker, attempt operation inserts for a wrong key, foreign run/scope, pending request and denial. Require FK rejection in each case and acceptance for the exact approved key and for an operation with NULL approval ID. |
| PR2 · wait races | Refuse park with owned work, an unresolved write, any existing operation for the proposed key, a stale token or a lapsed lease. Verify all four NULL fields on park. Race approve/deny, cancel, expiry and two claimers at slot limits. Assert one decision, at most one new token, no early dispatch and one terminal event. Test equality at each resume deadline using the post-lock observation, repeated parks and a saturated queue that outlasts approval. |
| PR2 · wait integrity and expiry | Reject an approval reason without a pointer, an approval reason outside `waiting`, and a pointed wait with a NULL or other reason or a live claim. Preserve the pointer after resume. Upgrade populated bare waits with NULL, `approval` and other reasons. With a small batch and a locked row, verify ordered, bounded sweeps, one failure event per run across retries, and recovered `live_per_actor` and `live_per_scope` capacity. |
| PR2 · ADR 0033 amendment | For each of `intent` and `outcome_unknown`, verify an `idempotent` write blocks park and successful settlement, appears in reconciliation, and counts toward interruption in `settle_expired`. A `repeatable_read` on another key stays non-blocking. |
| PR2 · recovery and roles | Lose the intent commit reply, crash either side of send, lose the outcome, expire the endpoint key, reconcile with/without a handle, and retry an observation. Count outbound writes with a synthetic adapter. Logout, identity withdrawal, restart and restore must never revive an approval. Exercise populated upgrade, legacy unknown intents, role denials including issuance, and session cleanup with retained receipts. |
| PR3 · HTTP and SSE | Exercise browser Origin and native bearer, malformed input, competing decisions and conflicting key reuse. A stale client digest leaves a valid wait untouched. Server-observed revocation cancels and expiry fails it. Replay the original receipt after archive, cancellation, settlement and originating-session logout. Verify 404 for a foreign actor/run, revoked read access and deleted scope. Replay park/decision/resume and terminal events after reconnect. Verify private fields are absent for a shared reader and snapshots agree with the terminal event. |

V1-07 (#8) owns run creation, the effective configuration and the executor that calls this
boundary. V1-14 (#14) owns actual MCP transport, reviewed tool schemas, endpoint guarantees
and result handling. V1-17 (#17) owns quota units, reservations and reconciliation. An
effect that requires an undelivered adapter or quota check stays unavailable. These slices
add no dependency, client UI or live endpoint qualification.
