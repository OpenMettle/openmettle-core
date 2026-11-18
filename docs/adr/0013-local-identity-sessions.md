# 0013 — Local identity approval and opaque sessions

Status: owner choices and coordinator implementation contract accepted, 17 November 2026.
Refs #5; Refs #34. Implementation and independent review/CI acceptance are separate.

## Boundary

The owner selected exact existing OIDC identity approval first. This is **local identity
approval**, not invitation delivery or redemption. The managed login consumer requires an
existing exact issuer/subject identity, its personal scope, a current provider-specific
approval and an enabled user. Unknown identities, missing scopes and missing approvals are
denied. It creates no users, identities, scopes or resource grants.

Routine provider configuration revisions and approval edits preserve existing sessions.
Explicit provider revocation, provider retirement (`NULL` revision), approval withdrawal and
user disablement are revocation actions. They advance the relevant access generation in the
same transaction. Restoration and re-enable never reset generations. Provider UUID fixes
issuer/client as in ADR 0012: changing either requires a new UUID.

There are no routes, cookies, native handoff, invitation delivery, account provisioning,
tenant/group claims, directory reconciliation, configuration loader or B+ configuration pin.
The offline verifier and existing `release` remain available, but neither can mint a session.
Only `ManagedProvider::issue_session` consumes a sealed online `ExchangedIdentity`.
The API process still serves only health/readiness. Session context is not V1-05 resource
permission; protected writes must recheck in their own transaction before product exposure.

## Schema and privileges

Migration 8 adds:

- Provider `access_generation`, an inert `lock_guard`, and latest-change actor, reason and time.
- User `session_generation` and login-row `session_issued`.
- `local_identity_approvals`: exact provider/identity references, current revision, generation,
  active flag, explicit expiry, latest-change actor/reason/time and inert lock guard.
- `local_sessions`: random lookup ID, secret digest, originating login, identity/user/approval,
  issued provider client/epoch and approval revision, all three access generations, absolute
  creation/expiry times and revocation flag. References and bounds are enforced by SQL.

API receives SELECT on approvals/sessions, INSERT only on session inputs, UPDATE only on
session revocation, user generation, login issuance marker and the two lock guards. It cannot
change provider generations, approval eligibility or session identity/expiry/digest fields.
Worker and PUBLIC receive no access to approval/session tables. Existing worker SELECT on
users includes the added generation column. No sequence, DELETE, function EXECUTE or DDL
grant is added.

Each guard is `boolean NOT NULL DEFAULT false CHECK (lock_guard = false)`. PostgreSQL requires
UPDATE privilege on at least one column to use row-locking SELECT. The constrained column
permits SHARE locks without granting authority-data changes
([PostgreSQL SELECT](https://www.postgresql.org/docs/18/sql-select.html)). The normal protocol
never updates guards. Redundant false updates are possible and can cause contention; bounded
operation/lock deadlines limit normal callers, not a malicious database role.

The existing table-wide users INSERT grant is retained for compatibility. It includes the
new generation column. Generation initialization, monotonic updates, one-way session revoke
and single-use login markers are trusted API protocols, not protection from arbitrary API SQL.
Absent column grants do not override table grants
([PostgreSQL GRANT](https://www.postgresql.org/docs/18/sql-grant.html)). The owner can override
all protocols, constraints and grants. Latest-change provenance is not an immutable audit log
or the deferred audited recovery implementation. Do not put credentials or personal details in
actor/reason fields; use deployment-controlled synthetic/operator identifiers.

## Issuance and clocks

The permit and sealed result privately carry the consumed login ID and its authenticated
original expiry. No caller can supply a replacement user, identity, admission boolean or proof.
The result is non-cloneable; there is no credential replay/retrieval API.

The operation rejects a connection already in a SQLx-managed transaction and owns one tracked
root `WriteTransaction`. Raw BEGIN/COMMIT/savepoints are unsupported. READ COMMITTED,
synchronous commit, 2-second lock timeout and 3-second statement timeout are explicit. The
whole operation is bounded by the lesser of the original exchange deadline and the explicit
session policy deadline. No HTTP or key refresh runs under database locks.

Lock order is login → provider → approval → user → session. Validation uses the suffix from
provider; logout uses only session; disable uses only user. No suffix operation later acquires
an earlier lock. Multi-row owner operations must use stable ascending IDs.

1. Lock the login row FOR UPDATE. Reject missing, unconsumed, issued, changed binding or
   changed original expiry.
2. Lock provider FOR SHARE, then read current authority in a **separate statement**. Require
   the exact proof epoch, configured revision, issuer and client. The owner takes FOR UPDATE
   before allocating epochs, so allocation order remains commit order among protocol writers.
3. Resolve the existing exact identity. Lock its provider-specific approval FOR SHARE, then
   read current eligibility and revision in a new statement.
4. Lock user FOR UPDATE. Read disablement and generation after waiting; require personal scope.
   Count all retained session rows under this lock, including expired/revoked/undisclosed rows.
5. Insert a new session and mark the originating login issued in the same transaction.
6. Recheck primary database time after blocking writes and managed proof freshness before commit.
   Return nothing until commit acknowledgement, a fresh primary-database session validation,
   and another managed freshness/deadline check all succeed.

Use `clock_timestamp()` from the primary after locks/waits for login, approval and local-session
expiry. `now()` is transaction-start time and cannot establish post-wait freshness
([PostgreSQL time functions](https://www.postgresql.org/docs/18/functions-datetime.html)).
Issuance additionally requires database time strictly before the **original login expiry**.
This is an intended tighter cutoff for this new consumer; the older exchange API did not
bound how long a consumed permit could be held before starting exchange. No new deployment
login lifetime is selected: ADR 0009's explicit 1–600-second input still applies.

The managed application wall clock checks signed-token expiry/issue age and rollback. The
monotonic clock bounds the original exchange operation and key/metadata freshness. Do not
compare these clocks as interchangeable values. Local session lifetime uses checked arithmetic
from a primary DB observation and cannot exceed approval expiry at issuance; final checks reject time moving backward within issuance.
Database clock discipline remains a deployment prerequisite; this is not cross-failover clock
rollback detection.

A provider writer that commits before issuance's lock/read is observed and can deny it. A
writer arriving after the shared lock waits until issuance ends. Approval withdrawal and user
disablement follow the same ordering. A plain SELECT alone would not establish this guarantee
([PostgreSQL locking](https://www.postgresql.org/docs/18/explicit-locking.html)).

Commit acknowledgement can arrive after token expiry, authority revocation or deadline expiry.
Then a bounded committed session and issuance marker can remain, but no credential is returned.
Cancellation or ambiguous commit also returns no credential. Discard uncertain connections and
start a new managed login; do not retry the authorization code or clear an issuance marker.
For ordinary returned errors before commit, the helper awaits rollback before returning, so
an idle caller connection does not retain row locks. A rollback failure returns a database
error and requires discarding the connection. Cancellation during cleanup remains uncertain.
Memory generation checks and PostgreSQL commit are separate observation points, not one atomic
operation. Revocation after final validation is ordered after that check. No validity-through-
network-delivery or retraction of already-issued external effects is promised.

## Credentials, policy and local operations

`Policy::new` requires all values; there is no Default. Implementation ceilings are 1 second–
24 hours absolute session lifetime, 1–1024 retained rows per user, and 10 ms–60 seconds whole
operation deadline. These are resource/representation limits, not deployment recommendations.
There is no sliding renewal or refresh-token consumer. Cleanup has separate explicit batch
bounds below. A full retained-row allowance refuses issuance until owner cleanup frees space.

Generate independent 32-byte lookup and secret values using existing ring SystemRandom.
Credential encoding is exactly two canonical 43-character base64url values separated by a dot
(87 bytes). Store only SHA-256 over a domain-separated, length-prefixed session ID and secret.
Compare fixed 32-byte digests with subtle, including a dummy comparison for a lookup miss.
Malformed/oversized input is refused before database work. Debug and errors are redacted;
callers must never log `Credential::expose()`. No memory-zeroization/core-dump protection is
claimed. API-process or owner compromise remains outside database-only credential protection.

Validation takes shared locks on provider, approval, user and session, then reads current
active authority, exact identity/client compatibility, all generations, user disablement,
revocation and expiry from the primary. Issued epoch/revision are provenance only: they are
not compared for equality with routine changes. No provider network or manager is needed.

Logout verifies possession of the digest and updates the session under its row lock. It does
not require current provider, approval or user eligibility, and works during provider outage,
retirement and disablement. It is idempotent for a retained already-revoked session.

`disable_user` is an internal administrative persistence operation, not a product-authorized
route. It requires an expected user generation, locks the user, advances generation with checked
overflow and sets disabled_at atomically. No session fan-out is needed. An old expected value
refuses. Owner re-enable clears only disabled_at, preserving generation. The API's existing
UPDATE privilege does not prevent raw SQL from violating this protocol.

All waits consume the existing API connection budget, with no new pool or background task.
Keep the ADR 0003 budget including rollout surge, workers, migrator and administrative headroom.
Validation takes SHARE locks, including on the common provider row. These locks permit
concurrent validators but add transaction and WAL overhead and can form multixacts. Their
throughput and latency are unmeasured; qualify them before exposing per-request validation.
Logout takes no provider lock, so an owner provider lock cannot prevent logout. Long streams,
queued work and external dispatch need V1-05 checks at their own defined boundaries.

## Operator protocol

Run these blocks as psql scripts with `ON_ERROR_STOP` against the primary as
`openmettle_owner`, under deployment change controls. Supply every named variable explicitly.
Do not continue after an error. A failed expectation rolls back and raises an explicit SQL
exception; [psql `ON_ERROR_STOP`](https://www.postgresql.org/docs/18/app-psql.html#APP-PSQL-EXIT-STATUS)
makes the script exit non-zero. Read current state and review it
before retrying the complete transaction. Operator changes use bounded transactions and
synchronous commit. Multi-row operations lock stable IDs in ascending order.

### Provider revision, revocation, retirement and restoration

Supply `provider`, `expected_generation`, `expected_epoch`, `actor`, `reason`, `action` and
`revision`. Use action `routine` to change an active configuration without signing users out;
`revoke` to invalidate sessions and pending logins while keeping the provider active;
`retire` to disable it; or `restore` to reactivate a retired provider. For `revoke`, `revision`
may be the current string, but **a fresh epoch is mandatory**. For `retire`, supply an empty
revision variable: the CASE expression writes literal SQL NULL, not its text value.

```sql
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
SET LOCAL synchronous_commit = on;
SELECT access_generation AS observed_generation FROM openmettle.login_providers
 WHERE id=:'provider'::uuid FOR UPDATE \gset
SELECT epoch AS observed_epoch, revision IS NULL AS retired
 FROM openmettle.login_provider_revisions
 WHERE provider_id=:'provider'::uuid ORDER BY epoch DESC LIMIT 1 \gset
SELECT :observed_generation = :expected_generation
 AND :observed_epoch = :expected_epoch
 AND ((:'action' IN ('routine','revoke','retire') AND NOT :'retired'::boolean)
      OR (:'action' = 'restore' AND :'retired'::boolean)) AS expected \gset
\if :expected
  UPDATE openmettle.login_providers
   SET access_generation=access_generation +
         CASE WHEN :'action' IN ('revoke','retire') THEN 1 ELSE 0 END,
       changed_by=:'actor', change_reason=:'reason', changed_at=clock_timestamp()
   WHERE id=:'provider'::uuid;
  INSERT INTO openmettle.login_provider_revisions(provider_id,revision)
   VALUES (:'provider'::uuid, CASE WHEN :'action'='retire' THEN NULL ELSE :'revision' END)
   RETURNING epoch AS new_epoch \gset
  SELECT NOT EXISTS (SELECT FROM openmettle.login_provider_revisions
    WHERE provider_id=:'provider'::uuid AND epoch > :new_epoch) AS current \gset
  \if :current
    COMMIT;
  \else
    ROLLBACK;
    DO $refused$ BEGIN RAISE EXCEPTION 'operator change refused; no changes committed'; END; $refused$;
  \endif
\else
  ROLLBACK;
  DO $refused$ BEGIN RAISE EXCEPTION 'operator change refused; no changes committed'; END; $refused$;
\endif
```

Locking precedes epoch allocation. Revocation and retirement increment the access generation
and append the epoch **in the same transaction**. A generation-only update invalidates existing
sessions but does not fence an already-exchanged login proof; it is not this revocation protocol.
Overflow aborts the transaction. Restoration preserves the advanced generation and allocates a
new epoch. Validation also refuses sessions issued before any later retirement tombstone, so
using the older migration-7 retirement recipe cannot revive sessions on restoration. Routine
non-NULL revisions remain compatible with existing sessions.

This supersedes ADR 0012's write examples for schema version 8 onward. Its allocator repair
requirements still apply. A new provider and its first revision must be inserted in one owner
transaction with explicit actor/reason; defaults backfill existing rows during migration only.
Owner writes that bypass the protocol remain outside its concurrency guarantee.

### Approval edits, revocation, withdrawal and reapproval

Use the exact script in the
[local identity approval change procedure](../operator/identity-approval-change.md). It
locks one existing approval by UUID, rechecks its expected revision and generation and the
primary clock after the wait, and updates only that row with operator provenance. Find the
UUID and counters with the first approval procedure's read-only inspection by exact
provider, issuer and subject. Use `routine` only for an active, unexpired approval; `revoke`
to invalidate its sessions while retaining eligibility; `withdraw` to remove eligibility; or
`restore` to reapprove an inactive or expired identity. Every action advances the revision;
all but `routine` advance the generation. `expires_ms` is required for every action but
written only by `routine` and `restore`; the others retain the stored expiry. Malformed,
stale, overflowing or inapplicable requests are refused with fixed text and commit nothing.
This replaces the earlier inline block, which interpolated counters as SQL text.

Restoration advances the generation again, including when the previous approval merely expired.
It cannot revive sessions bound to that earlier approval. Never change provider/identity on an
existing approval. Create a distinct approval only for an existing exact identity and compatible
provider issuer, with explicit expiry and operator provenance, using the exact script in the
[first local identity approval procedure](../operator/first-identity-approval.md). It inserts
only that row and refuses when any approval already exists for the pair. No API admission-write
or user-provisioning helper is provided.

### User disablement and re-enable

Supply `user`, `expected_generation` and boolean psql variable `disable`. Disabling advances
the generation atomically; re-enable clears disablement without resetting it. Both require the
expected generation. An old script that only sets `disabled_at` does not implement this protocol.
The internal disable helper provides the same generation fence for a separately authorized caller.

```sql
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
SET LOCAL synchronous_commit = on;
SELECT session_generation AS observed_generation FROM openmettle.users
 WHERE id=:'user'::uuid FOR UPDATE \gset
SELECT :observed_generation = :expected_generation AS expected \gset
\if :expected
  UPDATE openmettle.users
   SET session_generation=session_generation + CASE WHEN :'disable'::boolean THEN 1 ELSE 0 END,
       disabled_at=CASE WHEN :'disable'::boolean THEN GREATEST(created_at,clock_timestamp()) ELSE NULL END
   WHERE id=:'user'::uuid;
  COMMIT;
\else
  ROLLBACK;
  DO $refused$ BEGIN RAISE EXCEPTION 'operator change refused; no changes committed'; END; $refused$;
\endif
```

## Bounded owner cleanup and restore

The API has no DELETE privilege. Operators delete revoked sessions and sessions whose absolute
expiry has passed on the primary clock with the exact script in the
[session and login-gate cleanup procedure](../operator/session-cleanup.md). Each run is one
short transaction of 1–1000 rows (`batch` is required and refused before use if invalid),
with lock_timeout 2s, statement_timeout 5s, synchronous_commit on and `FOR UPDATE SKIP LOCKED`
in ascending ID order. It deletes session rows only and prints only a row count. No schedule,
default batch or retention duration is selected.

Commit the session batch before selecting login rows. Then a separate bounded transaction can
remove expired, consumed gates that no session references. For schema version 9 onward, run
[ADR 0014's gate cleanup script](0014-login-admission.md#expired-gate-cleanup) as the
procedure's second step; it also removes expired unconsumed gates and refuses invalid
batches. The procedure describes failure between the two steps and idle batches. The
version-8 gate statement:

```sql
WITH candidates AS (
 SELECT l.id FROM openmettle.login_transactions l
 WHERE l.consumed AND l.expires_ms <= floor(extract(epoch FROM clock_timestamp())*1000)::bigint
   AND NOT EXISTS (SELECT FROM openmettle.local_sessions s WHERE s.login_id=l.id)
 ORDER BY l.id LIMIT LEAST(GREATEST(:batch,0),1000) FOR UPDATE SKIP LOCKED
)
DELETE FROM openmettle.login_transactions l USING candidates c WHERE l.id=c.id;
```

Session deletion never clears session_issued. Gate deletion makes every old proof ineligible
because issuance requires the original row. The FK prevents gate deletion with retained sessions;
concurrent issuance serializes on the gate. No cleanup path recreates gates or resets markers.
Do not delete login_nonce_reservations with this procedure. Active-key nonce uniqueness and key
rotation/restore requirements from ADR 0009 still apply. These commands are cleanup mechanics,
not retention of security audit history. Login initiation limits, pending-login pruning and
rate limits remain blockers to public routes; a per-user session cap does not bound global
login reservations. Cleanup not run means retained rows and eventual capacity refusal.

After restore, invalidate all restored local sessions before reopening: advance every provider
access generation using the owner revocation protocol, append fresh epochs, and rotate the
active PKCE key per ADRs 0009/0012. Revalidate current local approvals and disablement against
known newer revocation records. Missing reconciliation evidence is not permission to reopen.
Primary reads and acknowledged-commit durability remain prerequisites. No restore/failover
qualification or audited recovery implementation is claimed.

## Compatibility and verification

Migrations 1–7 are unchanged. Migration 8 is additive and preserves table-wide users INSERT.
New approval/session tables start empty: no old identity is automatically approved. Authentic
v7 binaries are pinned to 5ff1d2a8ed5e7424be006e78c16f0c30e784336d. Old API/worker readiness must
survive upgrade; the old migrator must refuse without changes. Previous compatibility gates
remain. Snapshot checks compare every prior column, with explicit checks of new-column defaults.

No new dependency, Cargo feature, lockfile or service is introduced. Existing distribution
blockers remain. Tests include bounded credential parsing/RNG failure/redaction, real managed TLS
login with isolated PostgreSQL, routine edits versus revocation/restoration, actual lock waits,
post-wait expiry, caller transaction preservation, retained-row cap races, marker replay after
session deletion and absent gates, precommit cancellation, ambiguous commit and postcommit
expiry/revocation. Role and upgrade tests execute in CI only; compilation is not PG acceptance.

Required CI: normal Rust/fixtures/Python checks, explicit managed PostgreSQL filter, schema and
process PostgreSQL tests, authentic v2–v7 compatibility, CPU images and ephemeral kind. Independent
Claude review is a separate coordinator gate. #5 remains open; this does not complete browser/
native login, invitation delivery, provisioning, reconciliation, recovery or #6 authorization.

Observed local implementation checks: formatting, all-target Clippy with warnings denied,
locked offline workspace build and 119 non-PostgreSQL Rust tests passed after review corrections.
The 96 ignored entries are 27 managed PostgreSQL tests, 66 schema tests, 2 process tests and the proxy child invoked
by its parent. None of the PostgreSQL tests ran locally. All 52 Python tests and 180-fixture
freshness passed. Two inventories were identical: 333 packages, 433 existing distribution
blockers. Cargo manifests/lockfile are unchanged. An initial cache-miss compilation was
interrupted; subsequent checks used a copied PR52 target cache, preserving the other worktree.
Final-head CI, images/kind and independent review remain required; no rollout is claimed.
