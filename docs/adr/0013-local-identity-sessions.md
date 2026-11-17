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
Logout takes no provider lock, so an owner provider lock cannot prevent logout. Long streams,
queued work and external dispatch need V1-05 checks at their own defined boundaries.

## Operator protocol

Run only as openmettle_owner against the primary under deployment change controls. Use bounded
transactions, synchronous commit and explicit expected epoch/revision/generation. Obtain the
stable row lock before checking expectations and before allocating an epoch. Zero-row CAS,
overflow, an unexpected latest epoch or any SQL error requires ROLLBACK. Examples use psql
variables and `ON_ERROR_STOP`; they are not automatic deployment commands.

For a routine provider revision change:

```sql
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
SET LOCAL synchronous_commit = on;
SELECT access_generation FROM openmettle.login_providers
 WHERE id = :'provider'::uuid AND access_generation = :expected_generation FOR UPDATE \gset
SELECT epoch AS observed_epoch FROM openmettle.login_provider_revisions
 WHERE provider_id = :'provider'::uuid ORDER BY epoch DESC LIMIT 1 \gset
SELECT :observed_epoch = :expected_epoch AS expected \gset
\if :expected
  UPDATE openmettle.login_providers SET changed_by=:'actor', change_reason=:'reason',
    changed_at=clock_timestamp() WHERE id=:'provider'::uuid;
  INSERT INTO openmettle.login_provider_revisions(provider_id,revision)
    VALUES (:'provider'::uuid, :'revision') RETURNING epoch AS new_epoch \gset
  SELECT NOT EXISTS (SELECT FROM openmettle.login_provider_revisions
    WHERE provider_id=:'provider'::uuid AND epoch > :new_epoch) AS current \gset
  \if :current
    COMMIT;
  \else
    ROLLBACK;
  \endif
\else
  ROLLBACK;
\endif
```

Explicit provider revocation uses the same locked transaction and expected checks, but advances
`access_generation=access_generation+1` in the UPDATE. It may append the same revision string;
this also fences pending logins. Retirement advances the generation and uses this INSERT:

```sql
INSERT INTO openmettle.login_provider_revisions(provider_id,revision)
 VALUES (:'provider'::uuid, NULL) RETURNING epoch AS new_epoch \gset
```

Use literal NULL, not quoted `'NULL'`. Restore appends an active revision using the routine
protocol and preserves the already-advanced generation. Never reuse an old epoch or lower a
generation. The current-row check and allocator repair requirements in ADR 0012 remain.
An initial provider plus first revision is created in one owner transaction as before; record
its actor/reason/time. Existing providers receive migration provenance, not invented authors.

For approval changes, take `FOR UPDATE` on the exact approval ID, require the expected revision
and generation, then UPDATE in that transaction with `RETURNING revision` (exactly one row):

```sql
UPDATE openmettle.local_identity_approvals SET revision=revision+1,
  expires_ms=:expires_ms, changed_by=:'actor', change_reason=:'reason',
  changed_at=clock_timestamp()
 WHERE id=:'approval'::uuid AND revision=:expected_revision
   AND access_generation=:expected_generation AND active
   AND expires_ms > floor(extract(epoch FROM clock_timestamp())*1000)::bigint
   AND :expires_ms > floor(extract(epoch FROM clock_timestamp())*1000)::bigint
 RETURNING revision;
```

This is a routine edit of a still-active, unexpired approval, preserving generation and active
state. An edit that removes eligibility or restores an expired approval must advance generation;
it is not a routine extension. Explicit revoke adds
`access_generation=access_generation+1`; withdrawal also sets `active=false`. Restoration sets
`active=true` and advances revision, preserving generation. Never change provider_id/identity_id
on an existing approval: use a distinct approval. Create an approval only for an existing exact
identity and compatible provider issuer, with explicit positive expires_ms and actor/reason.
No API admission-write or user-provisioning helper is provided. A zero-row result is not success.

For owner user re-enable, lock the user FOR UPDATE, compare the expected generation, then clear
only disabled_at and commit. Disable must advance generation in the same transaction; prefer
the internal helper once a separately authorized administrative caller exists. Do not apply a
routine UPDATE(disabled_at) from an old script. Old API/worker binaries have no such handlers.

## Bounded owner cleanup and restore

The API has no DELETE privilege. Operators may execute one short cleanup transaction per batch,
with lock_timeout 2s, statement_timeout 5s and synchronous_commit on. Supply `batch` explicitly;
use 1–1000 rows. SQL clamps the supplied limit to 0–1000 as a safety bound (0 does no work).
No schedule or retention duration is selected.

```sql
WITH candidates AS (
 SELECT id FROM openmettle.local_sessions
 WHERE revoked OR expires_ms <= floor(extract(epoch FROM clock_timestamp())*1000)::bigint
 ORDER BY id LIMIT LEAST(GREATEST(:batch,0),1000) FOR UPDATE SKIP LOCKED
)
DELETE FROM openmettle.local_sessions s USING candidates c WHERE s.id=c.id;
```

Commit this batch before selecting login rows. Then a separate bounded transaction can remove
expired, consumed gates that no session references:

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
locked offline workspace build and 118 non-PostgreSQL Rust tests passed. The 90 ignored entries
are 22 managed PostgreSQL tests, 65 schema tests, 2 process tests and the proxy child invoked
by its parent. None of the PostgreSQL tests ran locally. All 52 Python tests and 180-fixture
freshness passed. Two inventories were identical: 333 packages, 433 existing distribution
blockers. Cargo manifests/lockfile are unchanged. An initial cache-miss compilation was
interrupted; subsequent checks used a copied PR52 target cache, preserving the other worktree.
Final-head CI, images/kind and independent review remain required; no rollout is claimed.
