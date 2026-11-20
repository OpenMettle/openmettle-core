# 0033 — Worker leases, deadlines, fencing and restart recovery

Status: proposed V1-11 design (PR1), 20 November 2026. Agent-authored; owner approval,
independent review and CI acceptance are separate gates. Refs #11; Refs #15. PR1 is this
document and a pointer from ADR 0004. Nothing here is implemented yet: PR2 adds the schema and
store functions, PR3 the worker loop and sweeps ([Delivery](#delivery-and-evidence)). #11 and
#15 remain open.

## Problem

ADR 0032 moves a run from `queued` to `running` and records the `claim_token` of that claim,
but nothing stops two processes from writing progress for the same run, nothing bounds how
long a run executes, and a worker that dies after a claim leaves its run `running` forever.
ADR 0004 left fencing to V1-11: its helpers lock the run row but do not check who owns it.
V1-11 must let only the current holder commit progress, bound execution end to end, stop work
honestly on cancellation and recover after a crash without replaying uncertain effects.

### What schema 19 already provides

| Need | Present on `main` (`3613a51`) | Gap |
| --- | --- | --- |
| Claim identity | `claim_next` sets `state = 'running'`, a fresh `claim_token` and `claimed_at`; event `claim:<token>` | No expiry, renewal or check on later writes |
| Execution states | `running`, `cancelling`, `reconciling` count as executing in `claim_next` | Nothing writes `cancelling` or `reconciling` |
| Effect ledger | `operations`: `intent` before dispatch, then `outcome_unknown`, `succeeded` or `failed`, with capability `repeatable_read`, `idempotent`, `lookup` or `non_repeatable` | Nothing reads it to decide recovery |
| Terminal events | One event under `run-terminal`: `run-cancelled` (`requested`, `revoked`) and `run-expired` | No succeeded, failed or interrupted event |
| Cancellation | `cancel_run` cancels a queued run; returns `Executing` for started runs | Started runs cannot be cancelled |
| Revocation | Bulk cancellation and `recheck_run` set any non-terminal run `cancelled` | A run with an effect in flight is reported cleanly cancelled |
| Worker process | Health and readiness only; `ARTIFACTS_DIR` validated but unused | No loop, no sweeps; ADR 0031 and 0032 sweeps are never scheduled |

## Decision

The run row is the lease. A claim installs a fresh `claim_token` and a lease deadline measured
on the database clock; only that token, while its lease is live, may write progress, and every
such write locks the run row and checks both first. A run also gets an execution deadline at
its first claim that no renewal or re-claim extends. Cancellation of started work is a request
the holder settles. Settlement inspects the operations ledger: a run with an effect of unknown
outcome is reconciled or reported `interrupted`, never replayed and never reported clean.
Recovery is two bounded queries run by any worker. No broker, no `LISTEN`, no advisory lock and
no new crate.

### Migration 20

Additive. Rows written before version 20 keep `NULL` in the new columns and are treated as
expired (below), as ADR 0032 treats a `NULL` queue deadline.

```sql
ALTER TABLE openmettle.runs
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN execution_expires_at timestamptz,
    ADD COLUMN cancel_reason text CHECK (cancel_reason IN ('requested', 'revoked')),
    ADD CONSTRAINT runs_lease_check CHECK (
        (execution_expires_at IS NULL OR claim_token IS NOT NULL)
        AND (lease_expires_at IS NULL
             OR (execution_expires_at IS NOT NULL AND lease_expires_at <= execution_expires_at))),
    ADD CONSTRAINT runs_cancelling_check CHECK (state <> 'cancelling' OR cancel_reason IS NOT NULL);
```

- `lease_expires_at`: written only by the worker (claim, renewal, release). It is never cleared:
  every fenced predicate also requires an executing state, so a terminal row's last lease is
  inert history.
- `execution_expires_at`: the execution deadline, set once by the first claim and never moved.
  The check keeps every lease inside it, so no renewal outlives the run's deadline.
- `cancel_reason`: set once, first reason wins. It survives `reconciling`, so a cancellation
  requested while uncertain effects are reconciled is still honoured. The request time is the
  `created_at` of its event; no timestamp column is needed.
- No helper before version 20 writes `cancelling`. A row put there by raw SQL fails
  `runs_cancelling_check` and the migration rolls back; the operator corrects it.
- No new index. Recovery reads executing rows through `runs_dispatch_idx`, as the claim's load
  count already does, and the number of executing rows is bounded by the executing limits.

### Timing

`LeaseSettings`, validated before any query:

```rust
pub struct LeaseSettings {
    /// Lease length `L`: 30 s to 10 min.
    pub lease: Duration,
    /// Execution allowance from the first claim: 1 min to 24 h, and at least `2 * lease`.
    pub execution_timeout: Duration,
}
```

All deadlines are database timestamps compared with `clock_timestamp()`. The database returns
remaining time as milliseconds (`(extract(epoch FROM t - clock_timestamp()) * 1000)::bigint`),
and the worker anchors it at the local `Instant` the request was *sent*, so a slow round trip or
a skewed worker clock only shortens the local view. The worker:

- renews every `L/3` while its step loop is healthy;
- stops owned work at its *stop point*, `min(lease deadline, execution deadline) − L/3`;
- gives stopped work a drain window of `L/6`, leaving at least `L/6` to settle while the lease
  is still live;
- passes adapters one deadline, `min(stop point, the step's own timeout)`, and a stop signal.

`L ≥ 6 × DB_TIMEOUT_MS` is required at worker start (exit 78 otherwise), so one renewal that
waits the full pool acquisition timeout still leaves time for another before the stop point.

### The fence

Every worker write runs in one transaction that starts with the fence. `with_lease` opens it
with `authz::store::begin` (READ COMMITTED, `lock_timeout` 2 s, `statement_timeout` 3 s) plus
`SET LOCAL idle_in_transaction_session_timeout = '5s'`, so a worker that stalls inside a fenced
transaction is disconnected and rolled back instead of holding the run row indefinitely.

```sql
SELECT claim_token = $3::uuid, lease_expires_at > clock_timestamp(), state, cancel_reason,
       (extract(epoch FROM lease_expires_at - clock_timestamp()) * 1000)::bigint,
       (extract(epoch FROM execution_expires_at - clock_timestamp()) * 1000)::bigint
  FROM openmettle.runs
 WHERE scope_id = $1::uuid AND id = $2::uuid
   FOR NO KEY UPDATE
```

A write proceeds only if, on the locked row,
`claim_token = $3 AND lease_expires_at > clock_timestamp() AND state IN ('running',
'cancelling', 'reconciling')`. The worker learns why it may not:

```rust
pub struct Lease<'a> { pub scope_id: &'a str, pub run_id: &'a str, pub claim_token: &'a str }

pub enum Fence {
    /// Settle, observe and renew: any executing state.
    Hold,
    /// Start new work: also `state = 'running' AND cancel_reason IS NULL`.
    Step,
}

pub struct Held {
    pub state: ExecState,              // Running | Cancelling | Reconciling
    pub cancel: Option<CancelReason>,  // Requested | Revoked
    pub lease_remaining: Duration,
    pub execution_remaining: Duration,
}

pub enum LeaseError {
    /// The run is terminal. Stop; write nothing.
    Terminal { state: String },
    /// Another claim holds the run. Stop; write nothing.
    StaleClaim,
    /// This claim's lease has lapsed. Stop; write nothing; recovery owns the run now.
    Expired,
    /// `Fence::Step` only: the lease is live but no new work may start. Settle instead.
    Stopping(Held),
    /// `NotFound` for a run that does not exist in this scope; otherwise discard the connection.
    Store(StoreError),
}

pub async fn with_lease<T>(
    c: &mut PgConnection,
    lease: &Lease<'_>,
    fence: Fence,
    body: impl AsyncFnOnce(&mut WriteTransaction<'_>, &Held) -> Result<T, crate::runs::Error>,
) -> Result<T, LeaseError>;
```

The checks are made in this order: terminal, token, lease, then the step condition. `body`
composes the unchanged ADR 0004 helpers on the same transaction; they re-lock the row the
fence already holds. `with_lease` commits on success and rolls back otherwise. A commit whose
response is lost is retried with the same append and logical keys after a new fence, which
either replays the committed write or reports why the run moved on.

| Worker write | Fence | Notes |
| --- | --- | --- |
| `record_intent`, step events | `Step` | No new effect after a cancellation, revocation or lapse |
| `record_observation` | `Hold` | An in-flight effect's outcome stays recordable while cancelling or reconciling |
| `recheck_leased` | `Step` | Below |
| `renew_lease`, `release_lease` | `Hold` | Below |
| `settle` | `Hold` | [Settlement](#settlement) |
| `unresolved_operations(c, &Lease, limit)` | `Hold` | Read under the lock; at most `limit` (1–1000) rows by `id` |

ADR 0004's helpers remain public and unfenced for the API's own writes. The worker calls them
only inside `with_lease`; PR3 keeps every worker call site in `with_lease` bodies.

### Claim, renewal and release

`claim_next(c, &ClaimLimits, &LeaseSettings)` (amends ADR 0032) keeps its fair selection, the
dispatch lock and the `claim:<token>` event, and writes the deadlines from one timestamp:

```sql
     ), next AS (
       SELECT r.id, clock_timestamp() AS t FROM openmettle.runs r ... -- joins, predicate, order
        LIMIT 1 FOR NO KEY UPDATE OF r SKIP LOCKED
     )
     UPDATE openmettle.runs r
        SET state = 'running', claim_token = gen_random_uuid(), claimed_at = next.t,
            execution_expires_at = next.t + $4 * interval '1 millisecond',
            lease_expires_at = next.t + $3 * interval '1 millisecond'
       FROM next WHERE r.id = next.id
     RETURNING r.scope_id::text, r.id::text, r.claim_token::text,
               r.actor_approval_id::text, r.round_limit, <lease ms>, <execution ms>
```

`$3` is `L` and `$4` the execution timeout, in milliseconds. `ClaimedRun` gains
`lease_remaining` and `execution_remaining`. A claim and its lease are one statement, so no
claimed row is ever without a lease.

`renew_lease(c, &Lease, &LeaseSettings) -> Result<Held, LeaseError>`, after a `Hold` fence:

```sql
UPDATE openmettle.runs
   SET lease_expires_at = least(clock_timestamp() + $3 * interval '1 millisecond',
                                execution_expires_at)
 WHERE scope_id = $1::uuid AND id = $2::uuid
RETURNING state, cancel_reason, <lease ms>, <execution ms>
```

Renewal never extends past `execution_expires_at`, never shortens a lease, and never revives a
lapsed one: after `Expired`, only recovery takes the run, under a new token. Renewal is also how
a holder learns of a cancellation, within `L/3`.

`release_lease(c, &Lease)` sets `lease_expires_at = clock_timestamp()` after a `Hold` fence. A
draining worker uses it so another worker can re-claim at once instead of after `L`.

**Only the worker renews.** The API has no `UPDATE` on `lease_expires_at` or
`execution_expires_at`. No client request, SSE heartbeat, reconnect or event append extends a
lease or depends on one; client presence is not execution health, and a client disconnect never
cancels a run. The API keeps the table-level `SELECT` on `runs` it has held since migration 3:
narrowing it would rewrite that grant for timestamps that are not confidential.

### Cancellation and revocation

One statement serves the caller's cancellation (`$3 = 'requested'`) and every revocation
(`'revoked'`), replacing `CANCEL_ONE` and the bodies of `CANCEL_SCOPE` and `CANCEL_USER`:

```sql
UPDATE openmettle.runs
   SET state = CASE WHEN state IN ('queued', 'waiting') THEN 'cancelled'
                    WHEN state = 'running' THEN 'cancelling'
                    ELSE state END,
       wait_reason = NULL,
       cancel_reason = coalesce(cancel_reason, $3)
 WHERE scope_id = $1::uuid AND id = $2::uuid
   AND state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')
RETURNING new.state, old.cancel_reason IS NULL
```

`RETURNING old.…` is PostgreSQL 18, the only qualified major version (ADR 0003). The bulk forms
keep their ordered `MATERIALIZED` lock and return `(scope_id, id, new.state, old.cancel_reason
IS NULL)`.

- `queued` or `waiting` becomes `cancelled` with its terminal event, as before. A waiting run
  holds no worker and no unresolved operation (a precondition V1-13 must keep), so nothing can be
  in flight.
- `running` becomes `cancelling`; `reconciling` stays `reconciling`. If this statement set the
  reason, it appends `openmettle.run-cancel-requested` v1 `{"reason":"<reason>"}` under the
  append key `cancel-requested`. The holder settles the run.
- `cancel_run` returns `CancelOutcome::{Cancelled, Requested { state }, Terminal { state }}`;
  `Requested` replaces `Executing` and is idempotent: a repeat writes nothing and appends nothing.
  V1-07 maps `Requested` to `202`.
- `recheck_run` keeps its outcomes; `Invalidated` now means the run was cancelled *or* moved to
  `cancelling` for its holder to settle.

The API therefore never makes an executing run terminal. Moving `running` to `cancelling`
changes no executing count, so it needs no dispatch lock (ADR 0032).

`recheck_leased(c, &Lease, &RunRecheckRequest) -> Result<RunRecheckOutcome, LeaseError>` is the
worker's recheck before dispatch and before every model or tool step. It runs the ADR 0027
decision after a `Step` fence, in the same transaction. On `Invalidate` it sets
`cancel_reason = coalesce(cancel_reason, 'revoked')` and applies `settle(Stopped)` (below)
before returning `Invalidated`. Rechecks happen between steps, when the holder has no owned work,
so this normally ends `cancelled` with `{"reason":"revoked"}`. A lapsed or stale holder gets
`LeaseError` and changes nothing; it does not reach the decision.

### Settlement

`settle(c, &Lease, &LeaseSettings, Settle) -> Result<Settled, LeaseError>`, after a `Hold` fence:

```rust
pub enum Settle { Succeeded, Failed(FailReason), Stopped }
pub enum FailReason { StepFailed, RoundLimit }
pub enum Settled { Terminal { state: &'static str }, Reconciling { unresolved: u32 } }
```

`Stopped` means the holder stopped without finishing: cancellation, deadline, revocation, or a
re-claimed run with nothing to resume. Under the lock it counts unresolved operations, those
whose outcome cannot be proven by replay:

```sql
SELECT count(*) FROM openmettle.operations
 WHERE scope_id = $1::uuid AND run_id = $2::uuid
   AND outcome IN ('intent', 'outcome_unknown') AND capability IN ('lookup', 'non_repeatable')
```

`repeatable_read` and `idempotent` operations are replay-safe by their recorded classification
(ADR 0004) and never block. An intent can only be inserted under the run lock, so the count is
exact for the transaction. With `n` unresolved, `r` the stored cancel reason and `E` the
execution time remaining, the first matching rule decides:

| # | State and input | Result | Terminal event under `run-terminal` |
| --- | --- | --- | --- |
| 1 | `Succeeded` from `running` or `cancelling`, `n = 0` | `succeeded` | `openmettle.run-succeeded` v1 `{}` |
| 2 | `Succeeded`, `n > 0`; or `Succeeded`/`Failed` from `reconciling` | Refused: `Conflict("unresolved operation")`, `InvalidInput("settle")` | None |
| 3 | `reconciling`, `Stopped`, `n > 0` | `interrupted` | `openmettle.run-interrupted` v1 `{"unresolved":n}` |
| 4 | `reconciling`, `Stopped`, `n = 0`, `r` set | `cancelled` | `openmettle.run-cancelled` v1 `{"reason":"<r>"}` |
| 5 | `reconciling`, `Stopped`, `n = 0` | `interrupted` | `openmettle.run-interrupted` v1 `{"unresolved":0}` |
| 6 | `n > 0`, `E > L` | `reconciling` (not terminal) | None |
| 7 | `n > 0`, `E ≤ L` | `interrupted` | `openmettle.run-interrupted` v1 `{"unresolved":n}` |
| 8 | `n = 0`, `r` set | `cancelled` | `openmettle.run-cancelled` v1 `{"reason":"<r>"}` |
| 9 | `Failed(reason)`, `n = 0` | `failed` | `openmettle.run-failed` v1 `{"reason":"step_failed"}` or `{"reason":"round_limit"}` |
| 10 | `Stopped`, `n = 0`, `E ≤ L` | `failed` | `openmettle.run-failed` v1 `{"reason":"deadline_exceeded"}` |
| 11 | `Stopped`, `n = 0`, `E > L`, no `r` | Refused: `InvalidInput`; use `release_lease` | None |

Payloads are exact bytes with no white space; `n` is a decimal integer. Every terminal result
sets `wait_reason = NULL` and appends its event in the same transaction. The unique
`(run_id, append_key)` keeps one terminal event per run whichever path writes it.

- **Succeeded wins over a late cancellation.** If all work finished, reporting `cancelled` would
  be false; cancellation is not rollback.
- **Uncertainty is never reported clean.** With an unresolved operation, `Failed` and `Stopped`
  reconcile or interrupt, and `Succeeded` is refused: an executor that claims success with an
  unresolved effect is a bug, not a result.
- **Reconciliation ends the run.** A reconciled run is not resumed in V1: after its pass it is
  `cancelled` if cancellation was requested and every outcome is now known, otherwise
  `interrupted`. The payload count says whether outcomes remain unknown; the operations carry
  the evidence. Resumption after reconciliation waits for PLAN-11's evidence.

### Reconciliation

A holder in `reconciling` lists `unresolved_operations` and, for each, asks the executor's
reconciler for an observation within the step deadline. A proven outcome is recorded with
`record_observation` (a `Hold` fence), using the operation's `downstream_handle` or an
independent read, never by dispatching the request again. A reconciler that cannot prove an
outcome, including one whose downstream is unavailable, returns none; the operation keeps its
`intent` or `outcome_unknown` row. A `non_repeatable` operation without a lookup has no
reconciler. One pass per claim, then `settle(Stopped)` applies rules 3 to 5. Bounded: one pass,
inside the execution deadline, and rule 7 skips reconciliation when no lease-length of time is
left.

### Recovery

Two worker queries take over runs whose lease has lapsed or that never had one. Both lock with
`SKIP LOCKED` and re-check their predicate on the locked row, so they never wait on a holder or
on each other and never take a live lease.

`settle_expired(c, limit)` (1–1000) settles in place, without a claim, every executing run whose
execution deadline has passed:

```sql
WITH due AS MATERIALIZED (
       SELECT id FROM openmettle.runs
        WHERE state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')
          AND state IN ('running', 'cancelling', 'reconciling')
          AND (lease_expires_at IS NULL OR lease_expires_at <= clock_timestamp())
          AND (execution_expires_at IS NULL OR execution_expires_at <= clock_timestamp())
        ORDER BY id LIMIT $1 FOR NO KEY UPDATE SKIP LOCKED
     ), unresolved AS (
       SELECT o.run_id, count(*) AS n FROM openmettle.operations o JOIN due ON o.run_id = due.id
        WHERE o.outcome IN ('intent', 'outcome_unknown')
          AND o.capability IN ('lookup', 'non_repeatable')
        GROUP BY o.run_id
     )
UPDATE openmettle.runs r
   SET state = CASE WHEN coalesce(u.n, 0) > 0 THEN 'interrupted'
                    WHEN r.cancel_reason IS NOT NULL THEN 'cancelled'
                    WHEN r.state = 'reconciling' THEN 'interrupted'
                    ELSE 'failed' END,
       wait_reason = NULL
  FROM due LEFT JOIN unresolved u ON u.run_id = due.id
 WHERE r.id = due.id
RETURNING r.scope_id::text, r.id::text, new.state, r.cancel_reason, coalesce(u.n, 0)
```

The `CASE` is the settlement table with `Stopped` and no time left (rules 3, 4, 5, 7, 8, 10).
The same transaction appends each terminal event in ascending run ID order. No model or tool
work runs. A version-19 claim (no deadlines) and a raw-SQL executing row are settled here.

`reclaim_next(c, &LeaseSettings) -> Result<Option<Reclaimed>, StoreError>` takes one run whose
lease lapsed but whose execution deadline is more than one lease away:

```sql
WITH next AS (
       SELECT id, clock_timestamp() AS t FROM openmettle.runs
        WHERE state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')
          AND state IN ('running', 'cancelling', 'reconciling')
          AND (lease_expires_at IS NULL OR lease_expires_at <= clock_timestamp())
          AND execution_expires_at > clock_timestamp() + $1 * interval '1 millisecond'
        ORDER BY lease_expires_at NULLS FIRST, id
        LIMIT 1 FOR NO KEY UPDATE SKIP LOCKED
     )
UPDATE openmettle.runs r
   SET claim_token = gen_random_uuid(), claimed_at = next.t,
       lease_expires_at = least(next.t + $1 * interval '1 millisecond', r.execution_expires_at)
  FROM next WHERE r.id = next.id
RETURNING <ClaimedRun columns>, r.state, r.cancel_reason
```

It appends `openmettle.run-claimed` under `claim:<new token>` and returns
`Reclaimed { run: ClaimedRun, state: ExecState, cancel: Option<CancelReason> }`. The state and
`execution_expires_at` are unchanged, so the run keeps its executing slot and its deadline; no
executing count changes and no dispatch lock is taken. A run with a lapsed lease and at most one
lease of execution left is not re-claimed; `settle_expired` takes it once the deadline passes.

The re-claimer then decides from durable state only:

| Re-claimed state | Unresolved | Next |
| --- | --- | --- |
| `running` | 0 | `recheck_leased`, then resume. Replay-safe operations may be dispatched again under their recorded logical keys; settled operations are read, not redone |
| `running` or `cancelling` | > 0 | `settle(Stopped)`: `reconciling` (rule 6) |
| `cancelling` | 0 | `settle(Stopped)`: `cancelled` (rule 8) |
| `reconciling` | any | One reconciliation pass, then `settle(Stopped)` |

### Single holder

- **Ownership changes and fenced writes serialize on the run row.** `claim_next`,
  `reclaim_next`, the fence and `settle_expired` all lock it `FOR NO KEY UPDATE`. A fenced
  transaction checks token and lease after the lock is granted and keeps the lock until it ends,
  so no other token can be installed between its check and its commit.
- **A stale holder cannot match again.** Each claim draws a new `gen_random_uuid()`. After a
  re-claim, the old token fails the fence (`StaleClaim`) for every later write, including its
  settlement, so a worker that returns from a pause, a partition or a slow commit commits nothing.
- **A lapsed holder cannot extend.** Lease validity is compared with the database clock only.
  Once lapsed, renewal and every write fail (`Expired`) even if nobody re-claimed yet.
- **Duplicate claims.** Both claim queries lock with `SKIP LOCKED` and READ COMMITTED re-checks
  the predicate on the locked row, so two claimers never both take a run; the loser takes the
  next row or nothing.
- **Terminal races.** An executing run becomes terminal only through its live holder's `settle`
  or, after its deadline, `settle_expired`, and both lock the row. Cancellation and revocation
  only move it to `cancelling`. The unique `run-terminal` key is a second barrier.
- **Bounded lock holding.** Fenced transactions have the 2 s lock, 3 s statement and 5 s idle
  timeouts, so a stalled holder delays recovery by seconds, not indefinitely.

The threat model is stale, paused or duplicate processes using these helpers. It is not
arbitrary SQL under the worker's credentials: that role holds `UPDATE` on `state` and
`claim_token` and could forge any transition. ADR 0003 grants no function execution, and a
trigger cannot know which token its caller legitimately holds, so database-enforced fencing is
not possible within the role contract. This completes the helper enforcement ADR 0004 required
before execution is enabled; it does not change that limit.

### Worker runtime (PR3)

The loop is library code in `src/worker.rs`; `openmettle-worker` keeps serving `/healthz` and
`/readyz` beside it.

```rust
pub enum Stop { Cancel, Deadline, LeaseLost, Shutdown }

pub struct StepContext {
    /// `min(stop point, the step's own timeout)`; adapters must apply it to every call.
    pub deadline: tokio::time::Instant,
    /// `Some` once the runner stops this run; adapters stop at their next safe point.
    pub stop: tokio::sync::watch::Receiver<Option<Stop>>,
    /// Spawns into the run's `JoinSet`; the only way an executor may start concurrent work.
    pub tasks: TaskHandle,
}

pub enum StepResult { Continue, Finished, Failed(FailReason), Stopped }

pub trait Executor: Send + Sync + 'static {
    fn step(&self, run: &ActiveRun, cx: StepContext) -> impl Future<Output = StepResult> + Send;
    fn reconcile(&self, operation: &UnresolvedOperation, cx: StepContext)
        -> impl Future<Output = Option<OwnedObservation>> + Send;
}
```

**Per run.** One task per run holds the claim. A renewal timer on that task calls
`renew_lease` every `L/3`; an `Expired`, `StaleClaim` or `Terminal` result, or reaching the
local stop point while the lease deadline sets it, sends `Stop::LeaseLost`. Reaching it while the
execution deadline sets it sends `Stop::Deadline`. A `Cancelling` state from renewal sends
`Stop::Cancel`. Before each step the runner calls `recheck_leased`; `Stopping` ends the loop.

**Drain.** On any stop the runner waits up to `L/6` for the step to return, then drops it, calls
`JoinSet::abort_all` and awaits `join_next` for the rest of the window. Then:

- `LeaseLost`: write nothing more. Recovery owns the run.
- Otherwise `settle(Stopped)`, or `settle(Succeeded)` if the step returned `Finished`.

Adapters must not swallow cancellation or timeouts (PLAN-08): a stopped call returns `Stopped`,
never `Continue`, `Finished` or a generic failure, and a timeout after dispatch records
`outcome_unknown`, not failure. A step that returns `Continue` after a stop is treated as
`Stopped`, and no further step starts. A task that outlives the drain (blocking work cannot be
aborted) cannot commit: its intent needs a `Step` fence, which `cancelling`, terminal and lapsed
runs refuse, and an intent it committed earlier is counted unresolved by `settle`, so the run
reconciles or is interrupted rather than being reported clean. Executors must record an intent
before dispatching an effect (ADR 0004), must not use `tokio::spawn` or detached
`spawn_blocking` for effects, and need no new crate: `watch`, `JoinSet` and `time` are in the
locked Tokio features.

**Claiming.** While a slot is free: `reclaim_next`, else `claim_next`. After an empty result the
loop sleeps `POLL_MS` with up to 20 % jitter; after a claim or a finished run it tries again at
once. A claimed run executes nothing before `recheck_leased` returns `Continue`.

**Maintenance.** One task, every `SWEEP_MS` with up to 20 % jitter, runs each call once with a
batch of 100, logs a failure as a fixed category and continues next tick:

| Sweep | Call | Notes |
| --- | --- | --- |
| Queue deadline | `authz::runs::expire_queued(c, 100)` | ADR 0032 |
| Execution deadline | `settle_expired(c, 100)` | Above |
| Abandoned uploads | `artifact_fs::reconcile_expired(pool, store, UPLOAD_TIMEOUT + 300 s, 100)` | Only with `OPENMETTLE_WORKER_ARTIFACTS_DIR`; 900 s exceeds the 600 s upload deadline plus settlement (ADR 0031) |
| Retained revisions | `artifact_fs::purge_due(pool, store, 100)` | Only with `ARTIFACTS_DIR` |

Every sweep locks rows and re-checks, so concurrent replicas are safe and at worst repeat a
lookup. `begin_purge` and `confirm_purge` are idempotent for a revision already `purging` or
`purged`.

**Shutdown.** `SIGTERM` or `SIGINT` stops claiming and sweeping, then sends `Stop::Shutdown` to
every run while renewal continues. A drained `running` or `cancelling` run with a cancellation or
an unresolved operation is settled with `settle(Stopped)` (rule 6 leaves an uncertain run
`reconciling` for another worker). A `reconciling` run whose pass did not finish, and any other
run, calls `release_lease` so another worker re-claims it at once. Runs get half of the ADR 0002
drain budget, and their drain window is the smaller of `L/6` and that share; HTTP drain and
`PgPool::close` get the rest. A run still draining at its deadline is dropped and its lease
lapses: recovery handles it as after a crash. With the 5 s default `SHUTDOWN_TIMEOUT_MS` most
runs are recovered that way; immediate hand-over needs a larger value and a pod grace period
above it. Exit codes are unchanged.

**Connections.** One pool of `DB_MAX_CONNECTIONS` (ADR 0002), no `LISTEN` session, so the
ADR 0003 budget is unchanged. Every call borrows a connection for one short transaction; none is
held across a step, a reconciliation call, a sleep or a drain (ADR 0004). Per run the steady load
is one renewal per `L/3`. The number of slots a pool sustains is not measured here.

**Settings** (`OPENMETTLE_WORKER_` prefix, invalid values exit 78 as in ADR 0002):

| Setting | Range | Default |
| --- | --- | --- |
| `SWEEP_MS` | 1 000–3 600 000 | 60 000 |
| `RUN_SLOTS` | 1–256 | Unset: no run loop |
| `LEASE_MS` | 30 000–600 000, at least `6 × DB_TIMEOUT_MS` | Required with `RUN_SLOTS` |
| `EXECUTION_TIMEOUT_MS` | 60 000–86 400 000, at least `2 × LEASE_MS` | Required with `RUN_SLOTS` |
| `EXECUTING_PER_ACTOR`, `EXECUTING_PER_SCOPE` | 1–1024 (ADR 0032) | Required with `RUN_SLOTS` |
| `POLL_MS` | 100–60 000 | 1 000 |

Policy values have no default, as in ADR 0032. The binary has no executor until V1-07 provides
the model and tool loop, so PR3 refuses `RUN_SLOTS` until then (exit 78) and the maintenance
sweeps are the worker's only work.

### Lock order

| Path | Order |
| --- | --- |
| Fenced write, renewal, release, settle, leased recheck | one run row, then the operation row it observes; reads only otherwise |
| `claim_next` | `run_dispatch_lock` → one run row, `SKIP LOCKED` (unchanged) |
| `reclaim_next` | one run row, `SKIP LOCKED` |
| `settle_expired` | run rows, `SKIP LOCKED`, ascending `id`; then reads operations |
| `cancel_run`, `recheck_run` | one run row (unchanged) |
| Archive, delete, disable | unchanged; their run rows by ascending `id` |

No path holding a run lock waits on a project, user, dispatch or other run row. The operation
row is always taken after its run row, as ADR 0004's `record_observation` does. No V1-11 path
moves a run into an executing state from outside it, so none needs `run_dispatch_lock`.

### Privileges (`boundaries.sql`, version 20)

| Object | API | Worker | Issuance |
| --- | --- | --- | --- |
| `runs.lease_expires_at`, `runs.execution_expires_at` | None | `UPDATE` | None |
| `runs.cancel_reason` | `UPDATE` | `UPDATE` | None |
| `runs.state`, `wait_reason`, `claim_token`, `claimed_at`; `run_events`; `operations` | Unchanged | Unchanged | None |

The worker's `UPDATE` on `cancel_reason` is for `recheck_leased`. No role gains `DELETE`,
`INSERT` of the new columns, function execution or a grant option. The issuance role
(ADR 0030) gains nothing.

### Rolling upgrade

Version 19 API replicas still running during the upgrade cancel started runs directly to
`cancelled`. A version 20 holder sees `Terminal` and stops, but an effect in flight then stays
`intent` under a `cancelled` run. The window closes when every API replica runs version 20;
the run loop is not enabled before V1-07 in any case. Version 19 binaries never write the new
columns, and the checks accept their `NULL`s.

### Rejected alternatives

- **Advisory locks.** Session-scoped, lost with a pooled connection, outside the row lock order.
- **A separate lease or attempt table.** A second source of truth beside the row that already
  serializes every transition.
- **Renewal by the API or SSE.** Client presence is not worker health; a dead worker would keep
  its lease while a client watched.
- **Unbounded renewal.** A looping run would hold a slot forever; the execution deadline caps it.
- **Worker clocks for expiry.** Skew would let two holders believe they own the run.
- **Replay after a crash or timeout.** Duplicates effects (#11 acceptance, ADR 0004).
- **Resuming after reconciliation.** Needs checkpoint semantics PLAN-11 has not established.
- **`cancel_requested_at`.** The reason is needed after `reconciling`; the time is on its event.
- **Triggers or `SECURITY DEFINER` functions for fencing.** See [Single holder](#single-holder).

## Delivery and evidence

| PR | Content | Evidence |
| --- | --- | --- |
| PR1 | This ADR and a pointer from ADR 0004 | Review |
| PR2 | Migration 20, `boundaries.sql` version 20, `src/authz/leases.rs` (`with_lease`, `renew_lease`, `release_lease`, `settle`, `unresolved_operations`, `reclaim_next`, `settle_expired`), and in `src/authz/runs.rs` the `claim_next` deadlines, the cancellation statement, `cancel_run`'s `Requested` and `recheck_leased`; ADR 0027 and 0032 amendment notes | PostgreSQL 18 tests below pass in CI |
| PR3 | `src/worker.rs` loop, `Executor` trait, renewal, drain, shutdown, maintenance sweeps and their settings; README and process contract updates | Subprocess tests below; the existing `kind` job extended to sweeps and graceful and forced worker termination |

PR2 tests use the disposable PostgreSQL fixture and backdate lease and deadline columns as the
owner rather than waiting:

- **Duplicate claims.** Concurrent `claim_next` and `reclaim_next` callers never hold one run
  twice; each claim has a distinct token and exactly one `claim:<token>` event.
- **Stale worker.** A claims; its lease lapses; B re-claims and settles `succeeded`. A's later
  intent, observation, renewal and `settle` each return `StaleClaim` and change nothing; the run
  has one terminal event. Without B, A gets `Expired` and cannot renew.
- **Renewal.** Capped at `execution_expires_at`; never shortens; refused once lapsed.
- **Stalled transaction.** A fenced transaction left idle is terminated after 5 s, its writes
  roll back and `reclaim_next` then proceeds.
- **Cancellation.** `running` → `cancelling` with one `cancel-requested` event; a repeat is
  `Requested` with no write; renewal reports it; `settle(Stopped)` gives `cancelled`
  `{"reason":"requested"}`. `waiting` and `queued` → `cancelled`. Cancel racing
  `settle(Succeeded)` produces exactly one terminal state. Archive and disable move `running` to
  `cancelling` with `{"reason":"revoked"}`.
- **Swallowed cancellation and orphan work.** After a cancellation, a `Step` write is
  `Stopping`; after settlement or lapse, every write is refused; an observation for an in-flight
  effect is still accepted while `cancelling`.
- **No blind replay.** A `non_repeatable` or `lookup` operation in `intent` or `outcome_unknown`
  makes `Succeeded` fail, `Stopped` give `reconciling`, and `settle_expired` give
  `{"unresolved":1}`; the operation row is unchanged and no intent is added. Replay-safe
  operations alone let a re-claimed `running` run resume, and `record_intent` with the same key
  returns the same operation.
- **Deadlines.** `settle_expired` fails a lapsed run with no operations as `deadline_exceeded`
  and settles a populated version 19 claim. API reads, cancellation and event appends never move
  `lease_expires_at`; API `UPDATE` of either lease column is refused (42501).
- **Sweeps racing.** `settle_expired`, `reclaim_next` and a late holder on one row give exactly
  one outcome.
- **Privileges and upgrade.** The version 20 grant matrix, issuance has nothing, and a populated
  upgrade from version 19 keeps every row.

PR3 in-process tests drive `src/worker.rs` against the fixture with a fault-injecting executor
and a shutdown future in place of the signal: a step that ignores `stop`, a child task that
outlives the drain, a reconciler whose downstream is unavailable (the run ends `interrupted`), a
lost renewal, shutdown with release and immediate re-claim by a second loop, and an aborted loop
recovered after its lease lapses. Subprocess tests run the real binary for each sweep with and
without `ARTIFACTS_DIR`, `SIGTERM` and `SIGKILL` during a sweep, and the new configuration
refusals. Live run recovery in `kind` needs an executor in the image and stays
open on #11 until V1-07 provides one.

## Boundaries

- **V1-07 (#8):** the executor (model and tool loop), the cancel route and its `202` mapping.
- **V1-12 (#12):** wire types and SSE replay of the new events; SSE never touches leases.
- **V1-13 (#13):** `waiting`. A worker may park a run there only with no unresolved operation
  and no owned work, sets `lease_expires_at` to `NULL`, and resumes it through
  `run_dispatch_lock` with a new claim. Whether waiting pauses the execution allowance is
  decided there.
- **V1-15 (#15):** this ADR schedules ADR 0031's sweeps. An orphan-file sweep, a per-chunk idle
  deadline and storage-class qualification remain open on #15.
- **V1-29 (#26):** PR3 adds the reserved `openmettle.runs.cancellations` counter (ADR 0028) with
  closed labels in `contracts/telemetry/v1.json`; nothing else is claimed here.

## Consequences

- No new crate, process, pool, listener or index; three nullable columns and two checks.
- Every worker write takes the run row lock it already took under ADR 0004, plus one fence read.
- Cancellation of a running run is visible at once as `cancelling` and settled by the holder
  within `L/3` plus the drain.
- An effect of unknown outcome ends the run `interrupted` unless a reconciler proves it; users
  re-submit. Nothing is replayed.
- A crashed worker's runs wait up to `L` before re-claim; graceful shutdown releases them at
  once.
- Not implemented here: everything in PR2 and PR3, the executor, priority classes, resumption
  after reconciliation, an absolute run expiry across waits, and any measured slot or lease
  sizing.
