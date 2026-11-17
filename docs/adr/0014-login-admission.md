# 0014 — Outstanding login admission

Status: coordinator-agreed V1-04 implementation contract, 17 November 2026.
Refs #5; Refs #34. Independent review and CI acceptance are separate gates. #5 remains open.

## Problem

Every browser login initiation commits a permanent AES-GCM nonce reservation and inserts a
login row (ADR 0009). Before this increment nothing bounded how many login rows could be
outstanding, and owner cleanup (ADR 0013) removed only consumed gates. Consumption needs only
the initiator's own state and caller binding plus the configured issuer, so a caller can
consume its own row with an invented code. That marks the row consumed and spends one token
POST. A cap counting only unconsumed rows would therefore not hold work outstanding.

## Decision

Migration 9 adds an operator-owned **outstanding-work cap**. It is not a rate limiter, a
request or concurrency control, or a bound on total storage:

- Varied caller lifetimes (1–600 s), successful session issuance, advisory-precheck races,
  cancellations and retries all change how quickly slots turn over. No initiation rate or
  outbound request rate follows from the limit.
- Nonce reservations are retained by design and keep growing monotonically. Expired login rows
  remain until owner cleanup runs.
- It does not make public routes ready. Request/rate/concurrency controls, scheduled cleanup
  operation and safe reclamation of retired-key reservations remain exposure gates, alongside
  the other gates recorded in ADRs 0009–0013.

### Schema and privileges

`openmettle.login_admission` is a singleton (`id boolean PRIMARY KEY CHECK (id)`) with
`outstanding_limit integer NULL CHECK (BETWEEN 1 AND 65536)`, a constrained `lock_guard`
column (`CHECK (lock_guard = false)`, as in migration 8) and explicit `changed_at`,
`changed_by` and `change_reason` provenance without defaults. Migration 9 inserts the row with
a NULL limit and `migration-9` provenance. **NULL refuses every login initiation** until the
owner configures a value. 65 536 is an implementation ceiling, not a deployment default; no
deployment value is selected.

The API receives `SELECT` and `UPDATE (lock_guard)` only, which permits `FOR UPDATE` without
granting authority over the limit. Worker and PUBLIC receive nothing. No DELETE, sequence,
function or DDL grant is added. The boundary check admits these grants only once version 9 is
recorded. A partial index `login_transactions (expires_ms) WHERE NOT session_issued` supports
the bounded count. Migrations 1–8 are unchanged.

### What counts

A row is outstanding while `expires_ms` is after the primary clock and `session_issued` is
false, **whether or not it is consumed**. A consumed row whose exchange failed keeps its slot
until its original expiry. Issuing a session or expiry frees the slot. The count stops at the
configured limit.

### Initiation protocol

`login::begin` (and therefore `ManagedProvider::begin`) runs, in order:

1. Existing lifetime/enabled validation and secret generation (no database work).
2. **Advisory precheck** in its own bounded READ COMMITTED, READ ONLY root transaction: read
   the limit, read managed provider authority (ADR 0012), sample the primary clock and count.
   It always ends with ROLLBACK. Unconfigured, full or stale-authority attempts are refused
   here **without spending a nonce reservation**.
3. The unchanged, separately committed nonce reservation (ADR 0009). Encryption still follows
   only an acknowledged reservation commit.
4. **Authoritative transaction:** lock the singleton `FOR UPDATE`, then sample
   `clock_timestamp()` in a separate statement **after any lock wait**, read the limit from the
   locked row, count, read managed authority after the clock statement (ADR 0012), encrypt
   and insert. Expiry is computed from that post-wait clock sample.

The precheck is advisory only. Concurrent attempts can all pass it and then lose the locked
recheck; cancelled, timed-out or later-refused attempts also keep their committed
reservation. **Each such attempt permanently spends one reservation.** No finite bound on that
per-attempt leak follows from the limit; request controls are still required before exposure.

New lock order: admission singleton → (plain authority reads) → new login row. Only begin and
the owner limit procedure lock the singleton. Consume (login row), issuance (login → provider
→ approval → user → session), validation, logout and cleanup never take it, so no cycle is
introduced. No provider HTTP runs under the singleton lock: managed preflight happens before
`login::begin`, and token exchange happens after consumption commits.

### Failures

| Condition | Result |
| --- | --- |
| Limit NULL, missing or out of range | `login::Error::Unconfigured`; precheck spends no reservation |
| Outstanding rows ≥ limit | `login::Error::Capacity`; precheck spends no reservation |
| Authority missing, retired or changed | `login::Error::Rejected` (existing ADR 0012 behaviour) |
| Lock wait beyond 2 s, statement beyond 3 s, other SQL error | `login::Error::Database` |
| Cancellation, timeout or ambiguous commit | Uncertain: discard the connection and start a new login |

A commit whose acknowledgement is lost can leave a committed row holding a slot until its
original expiry while the caller receives nothing.

Every ordinary returned error in begin, the precheck and consume (including transaction
setup failures) now **awaits ROLLBACK** before returning, so an idle caller connection never
keeps the singleton or a login row lock. Dropping a SQLx transaction only queues its rollback.
The original error is preserved when cleanup succeeds; a failed cleanup returns `Database`
and the connection must be discarded. Root transaction ownership, single-use consumption,
commit-before-permit, original expiry and the separation of network work from database locks
are unchanged.

Before exposing login routes, the route/pool integration must prove that cancellation,
timeout and `Database` errors discard the connection, including cleanup failure. A dropped
future can otherwise leave the singleton locked on an idle connection and block every
replica's login starts until that connection is closed or its queued rollback is flushed.
Returned ordinary errors with successful rollback do not retain that lock. This connection
lifecycle qualification is an exposure gate; it is not supplied by the outstanding-work cap.
[ADR 0016](0016-pooled-browser-auth-service.md) adds the pool integration and its evidence.

## Operator procedures

Run these exact scripts with `psql` against the primary as `openmettle_owner` under deployment
change controls. Each sets `ON_ERROR_STOP`; a refusal or error rolls back and exits non-zero.
CI executes both files unchanged with the pinned PostgreSQL 18 `psql` in the isolated service
container.

### Limit changes

[`docs/operator/login-admission-limit.psql`](../operator/login-admission-limit.psql) is a
compare-and-set on the current value. Lowering below the current outstanding count preserves
every existing row and refuses only new initiation until rows are issued or expire. An empty
`limit` restores NULL, refusing all new initiation. A malformed value fails its cast or check
and also exits non-zero with nothing committed.

```sql
-- ADR 0014: set, raise, lower or clear the outstanding-login limit (schema version 9+).
-- Run against the primary as openmettle_owner under deployment change control. Supply every
-- variable: expected_limit (current value, empty when unset), limit (1-65536, or empty to
-- refuse all new initiation), actor and reason (synthetic operator identifiers only).
-- A stale expectation or invalid value rolls back and exits non-zero; existing rows remain.
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
SET LOCAL synchronous_commit = on;
SELECT outstanding_limit IS NOT DISTINCT FROM NULLIF(:'expected_limit', '')::integer
   AND (NULLIF(:'limit', '') IS NULL
        OR (:'limit' ~ '^[0-9]{1,5}$' AND NULLIF(:'limit', '')::integer BETWEEN 1 AND 65536)) AS expected
  FROM openmettle.login_admission WHERE id FOR UPDATE \gset
\if :expected
  UPDATE openmettle.login_admission
     SET outstanding_limit = NULLIF(:'limit', '')::integer,
         changed_by = :'actor', change_reason = :'reason', changed_at = clock_timestamp()
   WHERE id;
  COMMIT;
\else
  ROLLBACK;
  DO $refused$ BEGIN RAISE EXCEPTION 'operator change refused; no changes committed'; END; $refused$;
\endif
```

Example: `psql -v expected_limit= -v limit=<value> -v actor=<id> -v reason=<text> -f
docs/operator/login-admission-limit.psql`.

### Expired gate cleanup

[`docs/operator/login-gate-cleanup.psql`](../operator/login-gate-cleanup.psql) replaces
ADR 0013's consumed-only gate cleanup for schema version 9 onward and also removes expired
**unconsumed** rows. It deletes only gates whose **original** expiry has passed and that no
session references; the `local_sessions.login_id` foreign key remains NO ACTION, so a
referenced gate cannot be deleted. Selection is bounded (`batch` 1–1000; anything else exits
non-zero with nothing deleted) and uses `FOR UPDATE SKIP LOCKED`, so rows held by a concurrent
consume or issuance are left for a later batch. Expiry is re-evaluated in the DELETE.

```sql
-- ADR 0014: delete one bounded batch of expired login gates that no session references
-- (schema version 9+). Covers unconsumed, consumed and issued-but-session-deleted gates.
-- Run against the primary as openmettle_owner. Supply batch (1-1000). Run ADR 0013 session
-- cleanup first if session-referenced gates should become eligible. Never deletes nonce
-- reservations or unexpired gates; locked rows are skipped for a later batch.
\set ON_ERROR_STOP on
SELECT :'batch' ~ '^[0-9]{1,4}$' AND :'batch'::integer BETWEEN 1 AND 1000 AS valid \gset
\if :valid
  BEGIN;
  SET LOCAL lock_timeout = '2s';
  SET LOCAL statement_timeout = '5s';
  SET LOCAL synchronous_commit = on;
  WITH candidates AS (
    SELECT l.id FROM openmettle.login_transactions AS l
     WHERE l.expires_ms <= floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
       AND NOT EXISTS (SELECT FROM openmettle.local_sessions AS s WHERE s.login_id = l.id)
     ORDER BY l.id
     LIMIT :batch
     FOR UPDATE OF l SKIP LOCKED
  )
  DELETE FROM openmettle.login_transactions AS l USING candidates AS c
   WHERE l.id = c.id
     AND l.expires_ms <= floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint;
  COMMIT;
\else
  DO $refused$ BEGIN RAISE EXCEPTION 'cleanup refused: batch must be 1-1000; nothing deleted'; END; $refused$;
\endif
```

Run ADR 0013's session cleanup first when session-referenced gates should become eligible.
Deleting a gate makes every retained proof for it ineligible: consume and session issuance
both require the original row, and issuance additionally requires a time before its original
expiry. Cleanup never recreates gates, resets markers or deletes nonce reservations.
**Never delete active-key nonce reservations.** Safe reclamation of retired-key reservations
needs its own contract (key IDs are never rebound, per ADR 0009) and remains deferred. No
schedule, retention period or batch value is selected.

## Restore and compatibility

Restore requirements are unchanged: before reopening, append fresh provider epochs and
advance access generations (ADR 0013), rotate the active PKCE key (ADR 0009) and never resume
restored logins. A restored limit row is whatever the backup held; review it before reopening.
Restored unexpired rows count toward the limit until they expire or are cleaned up.

Migration 9 is additive. Authentic version-8 binaries
(`e55aff07527ad6452f8a0d49953b3fc2ffc51352`) keep API/worker readiness on a populated
migrated database and do not enforce the cap; the version-8 migrator refuses the newer schema
without changes. During a rolling upgrade old replicas therefore initiate without the cap; it
holds only when every replica runs this version. There are no routes, so no deployed
behaviour changes. After upgrade every begin fails closed with `Unconfigured` until the owner
sets a limit; existing login, approval and session rows are untouched. Creating the index
briefly blocks login-row writes during migration.

No dependency, Cargo feature, lockfile, contract or provenance-register change.
`login::Error` gains `Capacity` and `Unconfigured` (internal API; no route maps them yet).

## Evidence

Managed PostgreSQL tests (`provider_keys::tests::postgres::admission`) cover: unconfigured,
full, consumed-after-failed-exchange and retired prechecks spending no reservation; issued
and expired rows freeing capacity; two waiters for the last slot with exactly one winner, no
oversubscription and the loser's spent reservation; limit and primary clock read after a real
lock wait (a lowered limit refuses; expiry during the wait admits); begin and consume
returned errors releasing locks while the connection stays idle; cancellation while waiting;
and cancellation at the login INSERT versus COMMIT response. Schema tests cover exact
privileges, the NULL default and fresh-migration refusal, boundary refusals, constraints,
atomic failure and version gating, frozen hashes for migrations 1–8, a populated version-8
upgrade with authentic binaries, and both operator scripts (compare-and-set, range and
missing-variable refusals, lowering with existing rows, NULL restoration, bounded batches,
SKIP LOCKED, session references, nonce preservation and replay refusal after cleanup).

Throughput of the serialized singleton and the bounded count is unmeasured. No local
PostgreSQL, real provider, route, cluster or rollout evidence is claimed.
