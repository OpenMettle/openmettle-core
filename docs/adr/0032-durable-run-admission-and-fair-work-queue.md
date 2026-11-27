# 0032 — Durable run admission and fair PostgreSQL work queue

Status: accepted with its implementation; V1-10 design (PR1) with its PR2 implementation and PR3 measurement harness,
20 November 2026. Agent-authored; owner approval, independent review and CI acceptance are
separate gates. Refs #10. PR2 adds migration 19, the store functions and their PostgreSQL 18
schema tests (see [Implementation](#implementation-pr2)); PR3 adds the
[measurement harness](#measurement-harness-pr3). No workstation measurement has been run; #10
remains open for it.

## Problem

ADR 0004 stores runs and events but admits nothing: `create_run` inserts a `queued` row and
its `run-created` event with no authorization, limit or deadline. ADR 0027 PR5 rechecks
authority before each step but explicitly left admission open: it "must refuse new runs in an
archived or deleted project and serialize with archive on the project row". V1-10 must admit
work durably, bound it per user and project, and hand it to workers fairly without a broker.

### What schema 17 already provides

| Need | Present on `main` (`94d21f8`) | Gap |
| --- | --- | --- |
| Run identity and idempotent replay | `create_run`: unique `(scope_id, actor_user_id, idempotency_key)`, `request_identity` and `request_digest` compared on replay, `run-created` at sequence 1 in the same savepoint | None; reused unchanged |
| Ordered events | `append_event`: run row lock, `last_event_sequence` counter, unique `(run_id, append_key)` | None; reused |
| Authorization | `authorize_create_in_scope` (personal owner or project editor, lifecycle); `authorize_run_continuation` (`RunExecute` on scope and conversation, capabilities); `recheck_run` | Nothing composes `RunExecute` with project lifecycle under the project lock |
| Approval for the recheck | `RunRecheckRequest::actor_approval_id` is required | Not stored on `runs`; a worker cannot know it |
| Revocation | `recheck_run`, `cancel_scope_runs` (archive, delete) and `cancel_user_runs` (disable) set `cancelled` | None of them appends an event, so a cancelled run has no terminal event |
| Limits, round cap, queue deadline, claim | Worker `SELECT` and `UPDATE (state, wait_reason)` on `runs` | No columns, no claim protocol, no caller cancellation |
| Indexes | `runs_actor_idx (actor_user_id, created_at, id)`, `runs_scope_conversation_idx` | No index on `state`: counting live runs would scan an actor's whole history |

## Decision

PostgreSQL is the queue. The API admits a run in one transaction that locks the scope and the
actor, authorizes, checks limits and calls `create_run`. Workers claim one run per free slot
with a fair `FOR NO KEY UPDATE SKIP LOCKED` query serialized by one dispatch lock row. No
broker, no `LISTEN`/`NOTIFY`, no new dependency and no in-process state: every decision is
read from committed rows, so queued work survives any API or worker restart.

### Migration 19

Migration 18 belongs to AUTHSEC-01 (ADR 0030). V1-10 is migration 19 and is rebased behind
it if that lands first. It is additive; no existing row changes.

```sql
ALTER TABLE openmettle.runs
    ADD COLUMN actor_approval_id uuid REFERENCES openmettle.local_identity_approvals (id),
    ADD COLUMN round_limit integer CHECK (round_limit BETWEEN 1 AND 1000),
    ADD COLUMN queue_expires_at timestamptz,
    ADD COLUMN claim_token uuid,
    ADD COLUMN claimed_at timestamptz,
    ADD CONSTRAINT runs_admission_check CHECK (
        (actor_approval_id IS NULL) = (round_limit IS NULL)
        AND (round_limit IS NULL) = (queue_expires_at IS NULL)
        AND (queue_expires_at IS NULL OR queue_expires_at > created_at)),
    ADD CONSTRAINT runs_claim_check CHECK (
        (claim_token IS NULL) = (claimed_at IS NULL)
        AND (claim_token IS NULL OR queue_expires_at IS NOT NULL));
-- Each query below repeats its index predicate verbatim so the planner can prove it.
CREATE INDEX runs_live_actor_idx ON openmettle.runs (actor_user_id)
    WHERE state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted');
CREATE INDEX runs_live_scope_idx ON openmettle.runs (scope_id)
    WHERE state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted');
CREATE INDEX runs_dispatch_idx ON openmettle.runs (state, created_at, id)
    WHERE state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted');
CREATE TABLE openmettle.run_dispatch_lock (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    lock_guard boolean NOT NULL DEFAULT false CHECK (lock_guard = false)
);
INSERT INTO openmettle.run_dispatch_lock (id) VALUES (true);
```

The three admission columns are server decisions, not request data. They are outside
`request_identity`, so a retry after a policy change replays the original admission instead of
conflicting. They are written by the same `INSERT` in `create_run` (one writer, no second
statement) and never updated. Rows written by bare `create_run` or before version 19 have all
three `NULL`: they are never claimed and the first expiry sweep fails them (below).

`round_limit` and the `1..=1000` range are a storage bound, not a recommended value. The
`claim_*` columns record which claim moved the run to `running`; V1-11 fences on
`claim_token` and adds lease expiry and renewal.

### Limits

Limits are parameters of the store calls, validated before any query. Their values are
deployment inputs wired by the first consumer of each call (the run route for admission, the
V1-11 worker loop for dispatch). This ADR sets no default: an unconfigured route is not
mounted.

| Limit | Range | Enforced by | Exact? |
| --- | --- | --- | --- |
| Live (non-terminal) runs per actor | 1–1000 | admission | Yes: serialized on the actor's user row |
| Live runs per scope | 1–10 000 | admission | Yes: serialized on the scope row |
| Queued runs in the instance | 1–10 000 | admission | No: may overshoot by the number of concurrent admission transactions |
| Queue timeout | 1 s – 24 h | admission sets `queue_expires_at`; claim and sweep honour it | Yes: database clock only |
| Per-turn round cap | 1–1000 | admission persists the effective value | Yes |
| Executing runs per actor | 1–1024 | claim | Yes: claims serialize on `run_dispatch_lock` |
| Executing runs per scope | 1–1024 | claim | Yes |

Executing means `running`, `cancelling` or `reconciling`: the states that hold a worker.
`waiting` (an approval wait, V1-13) holds no worker and counts only as live.

**Per-turn round cap.** This is the retained "allow administrators to cap the per-turn round
limit" item. The caller passes the round count it validated from its request (or none). The
effective value is `min(requested, cap)`, or `cap` when none was requested; a requested value
below 1 is `InvalidInput`. The effective value is stored in `round_limit` and returned. The
executor (V1-11) may lower it further to the current cap and never raises it. In V1-10 the cap
is an operator setting; a runtime administrator override per user or project belongs with the
V1-17 limit store and its `ManageQuotas` action, and is not claimed here.

### Admission (`openmettle_api`)

`admit_run(tx, request, limits)` borrows the caller's `WriteTransaction` (ADR 0004), so V1-07
can compose the input message, and V1-17 its budget reservations, in the same transaction.
The request carries the ADR 0004 `RunInput`, the session's approval ID, the capabilities the
run needs and the requested round count. The steps, after `SET LOCAL lock_timeout = '2s'` and
`statement_timeout = '3s'` as in `provider_keys`:

1. **Lock the scope.** A project scope locks the project row through `lock_project`
   (`FOR NO KEY UPDATE` on `lock_guard`), which archive, delete, membership and share changes
   already take. A personal scope locks its owner's user row `FOR NO KEY UPDATE`, as a
   personal share does.
2. **Lock the actor.** In a project scope, lock the actor's user row `FOR NO KEY UPDATE`. In a
   personal scope the owner is the only actor `RunExecute` admits, so step 1 holds it.
3. **Authorize after the locks.** Hydrate the principal with the session's approval and the
   scope, conversation and capabilities, then decide with `authorize_run_continuation` (the
   recheck's decision, now at admission). A missing scope, a deleted or invisible project or
   conversation is concealed (`NotFound`); an inactive principal or insufficient role is
   `Denied`.
4. **Replay.** Read the run with `(scope_id, actor_user_id, idempotency_key)`. If one exists,
   compare it as `create_run` does: identical returns `Replayed` with its current state, any
   difference returns `Conflict(KEY_REUSED)`. A replay never checks limits or appends an
   event, and it is returned even if the project has since been archived.
5. **Lifecycle.** An archived project refuses a new run with `ARCHIVED`.
6. **Limits.** Count live runs of the actor and of the scope, and queued runs in the
   instance, each bounded by its limit through the new partial indexes:
   `SELECT count(*) FROM (SELECT 1 FROM openmettle.runs WHERE actor_user_id = $1 AND <live>
   LIMIT $limit) q`. A full count refuses.
7. **Insert.** `create_run` with the approval ID, the effective round limit and
   `queue_expires_at = clock_timestamp() + queue_timeout`. This writes the run as `queued` and
   `run-created` at sequence 1 atomically. The new row is the reservation of the run slot; there
   is no separate counter to reconcile.

The caller commits. Because archive and disable lock the same rows before their bulk
cancellation, an admission either commits first and is cancelled by them, or runs after them
and is refused. A run never survives an archive, delete or disable it raced.

V1-07 must also call the read-only replay lookup of step 4 before inserting a new input
message, as ADR 0004 requires; `admit_run` repeats it under the locks.

| Outcome | Store result | HTTP (ADR 0007) |
| --- | --- | --- |
| Admitted | `Admitted { run, round_limit }` | 201 (route ticket) |
| Exact replay | `Replayed { run, state, round_limit }` | 200 with the original run |
| Key reused with another request | `Conflict(KEY_REUSED)` | 409 `idempotency_conflict` |
| Archived project | `Conflict(ARCHIVED)` | 409 `conflict` |
| Missing or concealed scope, project or conversation | `NotFound` | 404 `not_found` |
| Inactive actor, missing role or capability | `Denied` | 403 `policy` or 404, per ADR 0027 |
| Invalid input or round request | `InvalidInput` | 400 `validation` |
| Actor or scope live limit | `Refused(ActorLimit \| ScopeLimit)` | 429 `rate_limited` |
| Instance queue full | `Refused(QueueFull)` | 503 `unavailable` with `Retry-After` |
| Lock or statement timeout, pool or primary failure | `Database` | 503 `unavailable` |

Live limits clear when the caller's own runs finish, and nothing is consumed, so they are
`rate_limited`; `quota` stays for V1-17 budgets. A full queue is system saturation, not the
caller's fault, so it is `503`.

### Fair claim (`openmettle_worker`)

A worker with a free slot calls `claim_next(c, limits)`. One short transaction, with the same
local timeouts:

```sql
SELECT FROM openmettle.run_dispatch_lock FOR NO KEY UPDATE;

WITH executing AS (
    SELECT actor_user_id, scope_id FROM openmettle.runs
     WHERE state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')
       AND state IN ('running', 'cancelling', 'reconciling')
), actor_load AS (
    SELECT actor_user_id, count(*) AS n FROM executing GROUP BY actor_user_id
), scope_load AS (
    SELECT scope_id, count(*) AS n FROM executing GROUP BY scope_id
), next AS (
    SELECT r.id FROM openmettle.runs r
      LEFT JOIN actor_load a ON a.actor_user_id = r.actor_user_id
      LEFT JOIN scope_load s ON s.scope_id = r.scope_id
     WHERE r.state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')
       AND r.state = 'queued'
       AND r.queue_expires_at > clock_timestamp()
       AND coalesce(a.n, 0) < $1          -- executing runs per actor
       AND coalesce(s.n, 0) < $2          -- executing runs per scope
     ORDER BY coalesce(a.n, 0), r.created_at, r.id
     LIMIT 1
     FOR NO KEY UPDATE OF r SKIP LOCKED
)
UPDATE openmettle.runs r
   SET state = 'running', claim_token = gen_random_uuid(), claimed_at = clock_timestamp()
  FROM next WHERE r.id = next.id
RETURNING r.scope_id::text, r.id::text, r.claim_token::text,
          r.actor_approval_id::text, r.round_limit;
```

The same transaction appends `openmettle.run-claimed` (version 1, payload `{}`) under append
key `claim:<claim_token>`, then commits. If no row qualifies, `claim_next` returns `None`.

- **Ordering rule.** Least-loaded actor first, then FIFO by admission time and ID. An actor with
  no executing run is served before any actor that has one, and among idle actors the oldest
  run wins. A newly submitted run from an idle user therefore waits only for older runs of
  other idle users, never behind another user's backlog. An actor that already holds `k`
  workers yields to every actor holding fewer.
- **No monopoly.** No actor ever executes more than its limit and no scope more than its limit,
  so with more worker slots than the per-actor limit one user cannot occupy every worker. A run
  skipped at its limit is not starved: it becomes eligible when one of its own runs finishes,
  or it expires.
- **Exactness.** The second statement runs after the lock is granted, so its READ COMMITTED
  snapshot includes every earlier claim. Without the lock, concurrent claimers each see the
  same counts and can exceed a limit by the number of claimers. Runs that finish only lower
  the counts, so they need no lock.
- **`SKIP LOCKED`.** A run row held by the API (cancel, recheck, append) is skipped, so a claim
  never waits on a run lock while holding the dispatch lock, and never returns nothing because
  a re-checked `LIMIT 1` row changed under `FOR UPDATE`.
- **Bounded work.** The claim reads live rows through `runs_dispatch_idx` and sorts at most the
  configured number of queued runs plus the executing ones. The cost is linear in that bound,
  not in run history. PR3 measures it at the configured limit.
- **Priority.** V1 has one run kind, the interactive turn, so there is one class. A priority
  column, its weights and aging wait for the first background run kind (V1-25 or scheduled
  work), which must amend this ADR.

**Recheck before dispatch.** A claimed run executes nothing until `recheck_run` with its
`actor_approval_id` returns `Continue` (ADR 0027 PR5). The recheck runs in its own
transaction after the claim commits, to keep the dispatch lock short. A revoked run is then
cancelled with its terminal event; it held a slot only between the two transactions.

**Waking.** Workers poll. While a worker has a free slot it claims again at once after a
successful claim or a finished run; after an empty claim it sleeps a bounded, jittered
interval. Idle load is
one indexed query per worker per interval; admission-to-claim latency is at most one interval
plus the claim. A `LISTEN`/`NOTIFY` hint may be added only if PR3 shows the interval matters,
on a dedicated session counted in the ADR 0003 connection budget.

### Before execution: cancellation, deadline and revocation

Every terminal transition owned here appends exactly one terminal event under the append key
`run-terminal`, in the transaction that sets the state. The unique `(run_id, append_key)`
makes a second, different terminal event a conflict, so a run has at most one. V1-11 uses the
same key for `succeeded`, `failed` and `interrupted`.

| Trigger | Who | Transition | Terminal event |
| --- | --- | --- | --- |
| Caller cancels | API `cancel_run` | `queued` → `cancelled` | `openmettle.run-cancelled` v1, payload `{"reason":"requested"}` |
| Queue deadline passes | worker `expire_queued` (either role may run it) | `queued` → `failed` | `openmettle.run-expired` v1, payload `{}` |
| Archive, delete, disable | API bulk cancellation (ADR 0027) | non-terminal → `cancelled` | `openmettle.run-cancelled` v1, payload `{"reason":"revoked"}` |
| Membership, share, capability, approval or provider revocation | worker `recheck_run` after claim | non-terminal → `cancelled` | `openmettle.run-cancelled` v1, payload `{"reason":"revoked"}` |

- **`cancel_run(c, principal, scope_id, run_id)`.** The principal is hydrated by the route for
  the request. Lock the run row; a run of another actor is concealed (`NotFound`). `queued`
  becomes `cancelled`; a terminal run returns `Terminal { state }` unchanged, so repeating a
  cancel is idempotent without a key. An executing or waiting run returns `Executing { state }`
  unchanged: cooperative cancellation of started work is V1-11.
- **`expire_queued(c, limit)`.** One statement locks up to `limit` (1–1000) due queued rows
  `FOR NO KEY UPDATE SKIP LOCKED` in ascending `id` order, sets them `failed` and returns
  them; the same transaction appends each terminal event. Due means `queue_expires_at <= clock_timestamp()` or `queue_expires_at IS
  NULL` (pre-19 and bare `create_run` rows, which fail closed). The worker loop calls it before
  each claim. Safety does not depend on the sweep: the claim predicate already refuses an
  expired run.
- **Revocation.** PR2 changes `recheck_run`, `cancel_scope_runs` and `cancel_user_runs` to append
  the terminal event for each row they cancel, in the same transaction and after the locks they
  already hold. The bulk statements return the cancelled `(scope_id, id)` pairs; the event loop
  is bounded by the live limits. A revocation the API cannot see (membership, share,
  capability, approval, provider) leaves the run queued and counted until it is claimed and
  rechecked, or expires.

### Lock order

| Path | Order |
| --- | --- |
| Admission | project row (or personal owner) → actor user row → new run row |
| Archive, delete | project row → live run rows by ascending `id` (unchanged) |
| Disable | `account_admin_lock` → user row → live run rows by ascending `id` (unchanged) |
| Project share | project row → recipient user row `FOR SHARE` (unchanged) |
| Claim | `run_dispatch_lock` → one run row, `SKIP LOCKED` |
| Cancel, recheck | one run row, then reads only |
| Expiry | run rows, `SKIP LOCKED`, ascending `id` |

Admission takes project before user, as project share does; disable never takes a project
lock. Admission's new run row is invisible to concurrent bulk cancellations until it commits.
Nothing that holds a run lock waits on a project, user or dispatch lock. V1-11 and V1-13 must
take `run_dispatch_lock` before locking any run they move into an executing state (requeue,
resume after approval) so the executing limits stay exact.

### Privileges (`boundaries.sql`, version 19)

| Object | API | Worker |
| --- | --- | --- |
| `runs` admission columns `actor_approval_id`, `round_limit`, `queue_expires_at` | `INSERT` | None |
| `runs` claim columns `claim_token`, `claimed_at` | None | `UPDATE` |
| `runs.state`, `wait_reason`, `last_event_sequence`; `run_events` | Unchanged (migrations 3 and 15) | Unchanged |
| `run_dispatch_lock` | None | `SELECT`, `UPDATE (lock_guard)` |

No role gains `DELETE`, an `UPDATE` of an admission or identity column, or a grant option. The
existing `UPDATE (state)` grants still let arbitrary role SQL bypass these protocols, as
ADR 0004 records; V1-11 fencing is the enforcement step.

### Rejected alternatives

- **Redis, NATS or another broker.** A second durable store with dual writes and its own
  recovery, contrary to #10 and the agreed database decision.
- **`LISTEN`/`NOTIFY` as the wake path.** Needs a connection per worker outside the pool, loses
  notifications while disconnected (so polling is still required), and adds work to every
  notifying commit. Possible later as a hint.
- **Deficit round robin or virtual finish times.** Needs a persisted per-actor state row updated
  on every claim and a quantum to tune. Least-loaded-then-FIFO gives the required guarantees
  with no state.
- **Counter tables for live and executing runs.** A second source of truth to reconcile; bounded
  counts over partial indexes are exact.
- **Advisory locks.** A hash namespace outside the row lock order ADR 0027 analyses.
- **`SKIP LOCKED` without the dispatch lock.** Limits overshoot under concurrent claims.
- **Recheck inside the claim transaction.** Holds the global lock across several hydration reads.

## Implementation (PR2)

The store functions live in `authz::runs` (`src/authz/runs.rs`) beside the recheck they share
their decision and transaction with; `src/runs.rs` gains only the admission columns of the
run `INSERT` and an append for a run row the caller already holds.

- `admit_run(tx, &RunAdmission, &AdmissionLimits)` returns `Admission::Admitted { run_id,
  round_limit }`, `Admission::Replayed { run_id, state, round_limit }` or
  `Admission::Refused(RunLimit)`; the caller commits only after `Admitted`. Errors are the
  ADR 0027 `StoreError`: concealment is `Denied(DenialReason::NotFound)`, an inactive actor
  `Denied(InactivePrincipal)`, a missing role or capability `Denied(Policy(_))`, and the two
  conflicts are `Conflict(KEY_REUSED)` and `Conflict(ARCHIVED)`. A replay of a run written by
  bare `create_run` or before version 19 reports `round_limit: None`.
- Because exactness depends on each statement after a lock seeing earlier commits,
  `admit_run` refuses a caller transaction that is not READ COMMITTED (`InvalidInput`).
- `find_run(c, scope_id, actor_user_id, idempotency_key)` is the read-only replay lookup. It
  returns the stored conversation, branch and input message IDs so a retry reuses the original
  input identity, and `RunReplay::matches` compares a request with the stored identity.
- `cancel_run` returns `CancelOutcome::{Cancelled, Terminal { state }, Executing { state }}`;
  `expire_queued` returns the failed run IDs in ascending order; `claim_next` returns
  `Option<ClaimedRun { scope_id, run_id, claim_token, actor_approval_id, round_limit }>`.
- Bare `create_run` still names only the pre-19 columns, so its rows keep `NULL` admission
  columns and it also works against an older schema.
- *Update, 27 November 2026 (`openmettle.runs.queue.age`):* `claim_next`, `expire_queued`,
  `approvals::expire_waits`, `cancel_run`, `recheck_run`, `cancel_scope_runs`
  (`archive_project`/`delete_project`), `cancel_user_runs` (`disable_user`), and approval
  wait invalidation project PostgreSQL clock queue wait durations in SQL and record
  `openmettle.runs.queue.age` (`openmettle_runs_queue_age_seconds`, `QUEUE_AGE_BUCKETS` up to
  `300.0` s) strictly **after transaction commit** (`claimed` from `runs.created_at`,
  `resumed` from `run_approval_decisions.decided_at`, `expired` from `runs.created_at` on
  `expire_queued` and from `run_approval_decisions.decided_at` on `expire_waits` for approved
  resumable waits, and `cancelled` only for runs cancelled while `queued` or while `waiting`
  with an eligible decided `'approve'` approval—never when cancelling an executing run or an
  undecided human-approval wait, and never on a rolled-back transaction). Bulk revocation
  (`cancel_scope_runs`/`cancel_user_runs`) locks candidate runs in ascending `id` order before
  evaluating approval decisions in a fresh `READ COMMITTED` statement snapshot so concurrent
  `approvals::decide` commits are never missed.

## Delivery and evidence

| PR | Content | Evidence for #10 |
| --- | --- | --- |
| PR1 | ADR 0032 and a pointer from ADR 0004 | Review |
| PR2 | Migration 19, `boundaries.sql` version 19, `admit_run`, replay lookup, `cancel_run`, `expire_queued`, `claim_next`, terminal events in the three revocation paths, schema tests on CI PostgreSQL 18 (`tests/schema/run_admission.rs`, terminal-event assertions in `tests/schema/authz_runs.rs`) | Tests below pass in CI |
| PR3 | An ignored test harness that drives many actors and claimers against a disposable database and records latency, lock waits and `EXPLAIN (ANALYZE, BUFFERS)` of the admission counts and the claim (`tests/schema/run_admission_measurement.rs`); CI runs its bounded profile | CI: the bounded profile passes. Capacity: owner-run on the workstation profile in the agreed 20:00–07:00 window; results recorded on #10 (open) |

PR2 tests use the existing disposable PostgreSQL fixture:

- Concurrent identical admissions produce one run and one `run-created`; a changed request
  under the same key conflicts; a replay after archive returns the original run.
- With N concurrent admissions released together, exactly the actor limit and the scope limit
  are admitted; the rest are refused.
- Admission racing archive, delete or disable never leaves a live run in that project or for
  that user, and every cancelled run has one terminal event.
- `cancel_run`: queued becomes cancelled once; repeat returns `Terminal`; another actor gets
  `NotFound`; an executing run is unchanged.
- An expired run is never claimed; the sweep fails it with one event; sweep and claim racing on
  the same row produce exactly one outcome. A pre-19 row is never claimed and is failed.
- Concurrent claimers never claim one run twice and never exceed either executing limit.
- Fairness: while actor A executes at least one run and has 50 queued, actor B queues one;
  the next free claim takes B's. Ties between idle actors are FIFO.
- Claim skips a run row locked by the API instead of waiting.
- Privileges: each role is refused the columns and table it is not granted; populated upgrade
  from version 18 to 19.

### Measurement harness (PR3)

One routine, `measure_queue_contention_and_plans`, drives a migrated disposable database and
returns a JSON report. It measures:

- **Admission contention.** Half the actors admit into one shared ("hot") project, so they
  serialize on its row; the others admit into their personal scopes. Each actor admits its runs
  sequentially on its own `openmettle_api` connection through `admit_run`, and cancels every
  fourth one with `cancel_run`. The report gives p50, p95, p99, maximum and mean latency per
  group, plus throughput.
- **Claim serialization.** Concurrent `openmettle_worker` claimers call `claim_next` with
  bounded executing limits until the queue drains. Each holds its claimed run briefly, then
  marks it `succeeded` directly as a stand-in for the V1-11 executor. The report gives claim
  latency, throughput and empty polls.
- **Lock waits.** A superuser connection samples `pg_stat_activity` rows with
  `wait_event_type = 'Lock'` and classifies each waiter by the statement it is blocked in:
  project row, user row, `run_dispatch_lock` or other. Before the load, a calibration step
  holds each of the three locks and blocks one admission or claim on each. It then requires
  exactly one sample in each class, which proves the classification against the shipped
  statements. The same sampler records the peak executing runs per actor and per scope.
- **Invariants.** The report records executing limits exceeded in any sample, duplicate claims,
  lost completions, admissions that are neither claimed nor cancelled, and live runs left after
  the drain. Every count must be zero.
- **Plans over history.** Before the load, terminal runs with 512-byte snapshots are seeded so
  that history spans many heap pages. After the drain, the harness leaves a bounded live set
  (queued, plus some running) and runs `ANALYZE`. It then records `EXPLAIN (ANALYZE, BUFFERS,
  FORMAT JSON)` of the admission `LIVE_COUNTS` statement as `openmettle_api`. It also records
  the `CLAIM` statement as `openmettle_worker`, in a rolled-back transaction after taking the
  dispatch lock. The SQL is rebuilt from `src/authz/runs.rs`, embedded at compile time, so the
  harness explains the shipped text rather than a copy. Each plan summary has execution and
  planning time, shared hit and read buffers, the indexes used and any sequential scans.
  `seq_scan` is not disabled.

The verification requires a complete report, all invariants at zero, `LIVE_COUNTS` using
`runs_live_actor_idx` and `runs_live_scope_idx`, `CLAIM` using `runs_dispatch_idx`, and
no sequential scan or history index on `runs` in either plan. Only the partial live indexes and
`runs_pkey` (the claim's `UPDATE` join) are allowed.

| Profile | Test | When it runs | Default size |
| --- | --- | --- | --- |
| Bounded CI | `bounded_queue_measurement_reports_contention_invariants_and_index_plans` | Every hosted CI run, in the existing `--test schema -- --ignored` step on PostgreSQL 18 | 6 actors (3 in the hot project) × 12 runs, 4 claimers, 900 history rows, executing limits 1 per actor and 2 per scope |
| Workstation | `workstation_queue_contention_profile` | Only with `OPENMETTLE_QUEUE_BENCH=1`; otherwise it returns at once, because CI runs every ignored schema test | 48 actors × 40 runs, 16 claimers, 200 000 history rows, executing limits 2 per actor and 8 per scope |

The workstation sizes are starting points, not recommended limits. Override them with
`OPENMETTLE_QUEUE_BENCH_ACTORS`, `OPENMETTLE_QUEUE_BENCH_RUNS_PER_ACTOR`,
`OPENMETTLE_QUEUE_BENCH_CLAIMERS` and `OPENMETTLE_QUEUE_BENCH_HISTORY`. The run opens about
one connection per actor and per claimer, plus a few more, so the server's `max_connections`
must exceed `actors + claimers + 10`. The report is always printed to standard error;
`OPENMETTLE_QUEUE_BENCH_REPORT` also writes it to a file.

The owner runs the workstation profile in the agreed 20:00–07:00 window against a disposable
PostgreSQL 18 service with a superuser fixture account (the same `TEST_DATABASE_URL` contract as
the other schema tests). The command creates its own database:

```sh
OPENMETTLE_QUEUE_BENCH=1 \
OPENMETTLE_QUEUE_BENCH_REPORT="$PWD/target/queue-bench-report.json" \
TEST_DATABASE_URL='postgres://<fixture>@<host>:5432/<db>?sslmode=disable' \
cargo test --locked --release --test schema \
  run_admission::run_admission_measurement::workstation_queue_contention_profile \
  -- --ignored --exact --nocapture
```

Attach the JSON report, the PostgreSQL configuration and the workstation profile to #10.
The CI profile shows that the harness, its SQL and its invariants work on hosted PostgreSQL 18,
and that the planner uses the partial indexes over a history-dominated table. Its latencies come
from a shared CI runner and are not capacity evidence. No capacity number for the workstation
profile, and no decision on `LISTEN`/`NOTIFY` or admission serialization, is claimed until the
owner's run is recorded on #10.

## Boundaries

- **V1-07 (#8):** the HTTP run routes, input message and branch composition, the OpenAPI
  entries and the API settings that supply admission limits.
- **V1-11 (#11):** the worker loop and slots, lease expiry and renewal fenced on
  `claim_token`, execution deadlines, cancellation of started work and restart recovery. Until
  then a worker that dies after a claim leaves its run `running`.
- **V1-12 (#12):** event wire types for `run-created`, `run-claimed` and the terminal events,
  SSE replay and retention.
- **V1-13 (#13):** approvals and the `waiting` state.
- **V1-17 (#17):** token and storage budgets reserved in the admission transaction, and any
  administrator override of run limits.

## Consequences

- No new crate, process, connection pool or broker.
- Admissions in one project serialize on its row, as membership and share changes already do.
  PR3 measures whether that is a bottleneck.
- Claims serialize instance-wide on one row for the length of one indexed statement.
- A queued run whose actor lost access through a revocation the API cannot see keeps its slot
  until it is claimed and rechecked, or expires.
- Not implemented here: routes, settings, the worker loop, leases, priority classes, runtime
  administrator limits, queue-depth metrics and any measured capacity.

## Amendment by ADR 0033

`claim_next` now takes lease settings and returns the time remaining on the lease and the
execution deadline. Caller cancellation returns `Requested { state }` for executing runs.
The first request records its reason and the lease holder settles the run. Queued and
waiting runs cancel immediately.
See [Worker leases, deadlines, fencing and restart recovery](0033-worker-leases-deadlines-and-restart-recovery.md).
