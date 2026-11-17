# 0012 — Durable login provider authority

Status: coordinator-approved V1-04 implementation contract, 17 November 2026.
Refs #5; Refs #34. Independent review remains required. #5 remains open.
Supersedes only ADR 0011's process-local registration-serial binding and its
"identical re-registration clears keys" behaviour. Every other ADR 0011 rule stands.

Migration 8 / [ADR 0013](0013-local-identity-sessions.md) adds constrained lock permission and
separate session access generations. Use its owner revocation/retirement protocol once sessions
are installed; the epoch allocation order and current-row checks below still apply.

## Problem

ADR 0011 persisted a managed login binding that included a process-local registration
counter. Each process started at generation 1, so:

- a login begun before a provider was retired could be completed by a restarted process
  that registered the same configuration again;
- replicas with different reload histories disagreed on what a generation meant;
- re-registering identical configuration cleared keys and invalidated pending logins;
- `retire` affected one process only; other replicas kept releasing identities.

## Decision

Migration 7 adds an operator-owned, per-provider authority in PostgreSQL. The persisted
managed binding is the canonical configuration binding plus the authority **epoch**. The
process registration generation stays in memory only, to invalidate handles and key
snapshots. Configuration identity (deployment-owned bytes) and process generations are
separate concepts.

### Schema

- `openmettle.login_providers(id uuid PK, issuer, client_id, created_at)`: the stable
  provider identity. A different issuer or client needs a new UUID.
- `openmettle.login_provider_revisions(epoch bigint GENERATED ALWAYS AS IDENTITY PK,
  provider_id FK, revision text NULL, created_at)`: append-only by protocol. The highest
  committed epoch per provider is current; a `NULL` revision means retired.
- The API receives `SELECT` on both tables only. It has no sequence privilege and cannot
  insert, update, delete or lock rows `FOR UPDATE`. The worker and `PUBLIC` have no access.
  The boundary check refuses any other grant. Migrations 1–6 are unchanged.

The database records the active revision string per provider, not the full configuration.
The full canonical configuration binding (endpoints, callback, destination, trust-root and
CIDR fingerprint) remains deployment-authoritative. If two replicas run different
configuration under the same UUID and revision, logins begun on one fail binding comparison
on the other. The database does not detect that drift.

### Operator write protocol

The examples and lifecycle table below describe schema version 7. For version 8 onward,
use [ADR 0013’s complete operator procedures](0013-local-identity-sessions.md#operator-protocol):
revocation and retirement must atomically advance the session access generation and append
a fresh epoch. The older retirement INSERT alone does not implement session revocation.

Identity values are allocated when `nextval` runs, not at commit, and aborted allocations
leave gaps ([PostgreSQL 18, sequence functions](https://www.postgresql.org/docs/18/functions-sequence.html)).
Allocation order is therefore not commit order. Every change uses one bounded owner
transaction that serializes writers on the stable provider row before allocating:

```sql
-- psql variables for activation: :'provider' (uuid), :'revision' (revision text)
BEGIN;
SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
SET LOCAL synchronous_commit = on;
SELECT id FROM openmettle.login_providers WHERE id = :'provider' FOR UPDATE; -- exactly 1 row
INSERT INTO openmettle.login_provider_revisions (provider_id, revision)
    VALUES (:'provider', :'revision') RETURNING epoch AS new_epoch \gset
SELECT NOT EXISTS (SELECT FROM openmettle.login_provider_revisions
    WHERE provider_id = :'provider' AND epoch > :new_epoch) AS current; -- must be true
COMMIT; -- or ROLLBACK if no provider row, current is false, or anything failed
```

To retire a provider, use the same transaction, lock and checks, but replace only
the `INSERT` above with this statement:

```sql
INSERT INTO openmettle.login_provider_revisions (provider_id, revision)
    VALUES (:'provider', NULL) RETURNING epoch AS new_epoch \gset
```

Use literal SQL `NULL` for retirement. Setting the psql `revision` variable to
`NULL` does not work: `:'revision'` quotes it as the text `'NULL'`, which is an
active revision string, not a retirement tombstone
([psql variable interpolation](https://www.postgresql.org/docs/18/app-psql.html#APP-PSQL-INTERPOLATION)).

A second writer's `FOR UPDATE` waits for the first to commit or roll back
([PostgreSQL 18, Read Committed](https://www.postgresql.org/docs/18/transaction-iso.html#XACT-READ-COMMITTED)),
so among protocol writers allocation happens in commit order. The `current` check refuses to
commit an append that would not be the latest row, for example after an owner override or
restored rows ahead of the allocator. Repair that by advancing the sequence past every row
(`setval`, which is not undone by rollback) and appending again. A new provider inserts its
`login_providers` row and first revision in one such transaction.

The identity is `GENERATED ALWAYS`, so explicit epochs are refused unless the owner writes
`OVERRIDING SYSTEM VALUE`. These are protections against mistakes, not a security boundary:
`openmettle_owner` can bypass the protocol, overrides, constraints and grants. As in
ADR 0009, a malicious deployment authority is out of scope. There are no triggers.

| Change | Statement | Effect |
| --- | --- | --- |
| Add provider | Insert identity, then revision `r1` | Managed login allowed for config revision `r1` |
| Change or revert configuration | Append the new revision | New epoch; pending logins from older epochs fail |
| Retire | Append `NULL` | Begin, consume and release refuse on every replica at their next authority read |
| Restore a retired provider | Append a revision (same string allowed) | New epoch; logins from before the retirement stay dead |
| Identical reload | None | No-op in process and database |
| Signing-key (JWKS) rotation | None | In-memory cache only, per ADR 0011 |

During a rolling revision change, replicas whose configured revision differs from the
current row refuse logins. That window fails closed.

### Where authority is read

All reads compare the latest row's epoch, non-NULL revision, issuer and client with the
process configuration.

- **Begin** reads authority inside the existing login transaction, after the clock statement,
  and stores `persisted(config_binding, epoch)`.
- **Consume** reads authority after the login row lock, so a consumer that waited observes
  revisions committed meanwhile. A mismatch rejects without consuming. The permit records
  the epoch. Old offline `begin`/`consume`/`exchange` behaviour is unchanged.
- **Exchange** checks only in-memory state before its single code POST. It holds no database
  connection during the POST and returns a sealed `ExchangedIdentity`: not cloneable, Debug
  redacted, no identity accessor or conversion. It carries the exchange's original deadline.
- **Release** (`ManagedProvider::release`) is the only conversion to `VerifiedIdentity`, on
  the handle that exchanged. It refuses a connection already in a SQLx-managed transaction,
  using the driver's transaction-depth guard. Manual transaction-control SQL is unsupported,
  as in ADR 0004. It then opens a
  fresh root `READ COMMITTED, READ ONLY` transaction with 2-second lock and 3-second
  statement timeouts, all inside the original deadline. It reads authority once and
  requires the permit's epoch. It then repeats ADR 0011's in-memory check (registration
  generation, key generation and freshness, wall-clock rollback, deadline). Last, it
  rechecks token expiry and issue age at the current time, after every await.

### Linearization and its limits

A plain `SELECT` under Read Committed sees a snapshot taken when the statement begins
([PostgreSQL 18, Read Committed](https://www.postgresql.org/docs/18/transaction-iso.html#XACT-READ-COMMITTED)).
Release therefore linearizes at that snapshot, not at function return:

- a retirement or revision committed **before** the snapshot always refuses release,
  including for a code POST that was already in flight;
- a retirement that commits **after** the snapshot, even before release returns, is ordered
  after this release, which succeeds;
- an uncommitted writer neither blocks nor affects the read, and a rolled-back writer never
  becomes current.

Future application-session creation must re-read **and serialize** authority inside the
session-insert transaction. A plain read before that transaction does not close the race.
Row locks such as `FOR KEY SHARE` need an `UPDATE` privilege the API does not hold, so that
increment must choose and review its serialization mechanism and any grant. Sessions are
not implemented here.

## Restore and durability prerequisites

Before reopening after a database restore, the operator appends the current revision for
**every** provider using the protocol above, and performs ADR 0009's active PKCE key
rotation. Restored pending logins then fail on epoch even if an old decryption key remains.
The current-row check guards against a restored allocator that is behind restored rows.

Authority reads assume the API connects to the primary and that acknowledged commits
survive failover. Reading from a lagging standby, or an asynchronous failover that loses an
acknowledged authority row, can revive old authority. This increment provides no guarantee
against those deployments. Only a simulated restore (epoch bump with old pending rows) is
tested; no backup or failover qualification is claimed.

## Configuration lifecycle in process

`ProviderManager::register` compares the canonical full binding without generation or epoch.
For an active entry with identical bytes it is a no-op: keys, cooldown, any in-flight
refresh and existing handles survive. A changed binding, or registration after `retire`,
increments the generation, invalidates handles and keys, and keeps the cooldown budget.
The configuration file/environment loader remains deferred.

## Compatibility

- Migration 7 is additive. Authentic version-6 binaries from
  `3978dff2864488bbdd9e748afd7116f39683f129` keep readiness against a migrated database; the
  version-6 migrator refuses it without changes. Populated version-6 login rows are preserved.
- After upgrade the authority tables are empty, so managed login fails closed until the
  operator records providers. Pending managed rows using ADR 0011's binding domain fail closed.
- The managed `exchange_with_keys` result type changed and identical registration is now a
  no-op. These internal APIs were never exposed by a route.
- No dependency, lockfile, API contract or provenance-register change.

## Evidence

Offline library tests cover identical registration, every binding input change, retire and
restore generations, sealed-result redaction and in-memory release. Ignored PostgreSQL
library tests (`provider_keys::tests::postgres`) drive real managed begin → consume →
in-memory TLS POST → release against isolated CI PostgreSQL 18. They cover restart and
identical reload portability, authority refusals, epoch change and retire/restore denial,
simulated restore with key rotation, snapshot-ordering barriers in both orders, an in-flight
POST after retirement, nested-transaction refusal, original deadline and token-time checks,
writer blocking, lock timeout, rollback, explicit-epoch refusal and the current-row check.
Schema tests cover migration 7 grants, sequence privileges, boundary refusal, atomic failure,
history gating, frozen hashes for migrations 6 and 7, and the populated v6 upgrade. No local
database, real provider, session, admission or rollout evidence is claimed.
