# 0005 — Artifact revisions, storage reservations and byte accounting

Status: implementation of the coordinator-agreed V1-02 storage increment, 17 November 2026;
independent review and qualification remain required. Related: core #3 and sprint #34. This
does not complete #3: grants remain outstanding. It enables no product API, upload service,
quota policy, retention job or filesystem work. Follow ADR 0003 for migration and role
provisioning and ADR 0004 for transaction composition. Migrations 1–3 are unchanged.

## Scope

Migration 4 adds five tables:

- `storage_instance`: one row (`id = true`) holding the owner-configured limits and the
  installation's active, retained and reserved byte counters.
- `storage_accounts`: one counter row per owner scope, created lazily by the reservation helper.
  Scopes created before the upgrade, or by the previous API during a rolling update, work
  without a backfill.
- `artifacts`: logical file identity. The scope is the single accounting owner.
  `owner_user_id` is the private creator, using the same composite keys as conversations. A
  project scope does not publish an artifact to members.
- `storage_reservations`: a bounded allowance for writing one revision of one artifact. It may
  link a run, or a run and one of its operations, through composite scope keys. An operation
  link without a run is rejected.
- `artifact_revisions`: immutable payload metadata (number, size, SHA-256 content digest, media
  type, creator, reservation) plus lifecycle columns. No filesystem path is stored; V1-15
  derives storage locations from the immutable identifiers.

Tenant-leading indexes cover artifacts by scope and owner, revisions by scope and artifact or
state, and reservations by scope, state and age, or by scope and run. A partial index on
`purge_after` serves the future instance-wide purge scan. Foreign keys use NO ACTION.

## Accounting

A scope's charged bytes are `active + retained + reserved`. Retained and purging revisions stay
charged until purge is confirmed. Only revisions carry bytes, and each revision is charged once,
from the reservation it settles. A unique key allows one revision per reservation. Additional
references or future grants never add a charge. A copy needs a new reservation and revision in
the target scope. There is no ownership transfer or copy service.

`src/storage.rs` provides:

| Helper | Effect |
| --- | --- |
| `reserve` | Checks the owner and instance limits under row locks and adds `max_bytes` to reserved |
| `settle` | Creates the artifact on first use and the next revision; moves the actual size to active and releases the remainder |
| `release` | Releases the whole allowance of an unsettled reservation |
| `retain_revision` | active → retained; sets `purge_after = now() + grace`; bytes stay charged |
| `restore_revision` | retained → active, only before `purge_after` |
| `begin_purge` | retained → purging, only at or after `purge_after`; bytes stay charged |
| `confirm_purge` | purging → purged; removes the bytes from the counters |

Reservation identity uses the ADR 0004 framing with domain `openmettle/reservation/1`. Its
fields, in order: scope, actor, key, artifact, max bytes (i64), run-presence byte, run,
operation-presence byte, operation. Absent links are encoded as an empty field. The namespace
is `(scope, actor, key)`, as for runs. An exact replay returns the original reservation and its
current state (reserved, settled or released) without rechecking limits, so replay after an
uncertain commit or a later limit reduction never charges again. Changed input conflicts.

`settle` replay compares the full stored revision metadata (artifact, size, digest, media type
and creator) with the request and returns the same revision. Any difference, or settling a
released reservation, conflicts. A size above `max_bytes` is invalid. `release` and repeated
`confirm_purge` are no-ops after they have taken effect, so counters move exactly once.

## Limits

`storage_instance` holds `instance_budget_bytes`, `personal_limit_bytes` and
`project_limit_bytes`. They are durable deployment inputs that only `openmettle_owner` can set.
Application roles cannot insert, delete or update those columns or the singleton. Migration 4
installs the row with all three NULL. NULL means unconfigured, and new reservations are refused
(`LimitUnconfigured`). No production values are invented. Configure them with the owner login
during deployment, for example:

```sql
UPDATE openmettle.storage_instance
SET instance_budget_bytes = :instance_budget,
    personal_limit_bytes = :personal_limit,
    project_limit_bytes = :project_limit;
```

The instance budget is the logical byte ceiling available after the operator has subtracted
operational headroom. It is not a measurement of physical disk capacity. Filesystem allocation,
database growth, indexes and backup staging must be tracked separately. The scope's kind selects
the owner limit. Every reservation must fit both the owner limit and the instance budget.

`reserve` reads the limits while holding the instance row lock, and a limit update locks the
same row, so a reduction serializes with in-flight reservations. A replica with stale
configuration cannot ignore it. Lowering a limit below current usage preserves all data and
existing reservations: they can still settle, release, retain and purge. Only new reservations
are refused until usage falls or the limit rises. Limit changes never shorten a grace period or
trigger purge. Per-owner overrides, expiry, audit records and warning thresholds belong to V1-17
and are not implemented.

## Release and external outcomes

`release` refuses (`Unresolved`) while the linked operation is `intent` or `outcome_unknown`.
For a run-only link, any operation of that run in those states blocks release. The check runs
under the run lock that `record_intent` and `record_observation` also take. A timeout never
authorizes release, and nothing releases reservations automatically or on expiry. A known
outcome is necessary but not sufficient: the caller is the reconciliation authority and must
first establish that none of the reservation's bytes still need settlement, for example that a
succeeded write has been settled or its staging data removed. Stale-reservation discovery uses
the `(scope_id, state, created_at)` index; recovery policy and renewal belong to V1-15/V1-17.

## Retention

`retain_revision` takes the deployment's configured grace in whole seconds. It must be positive;
the agreed initial default is 30 days (2,592,000 seconds), configured by the deployment rather
than embedded here. The deadline uses database time (`now()`, the transaction timestamp) and is
stored once. A retry, or a call in any later state, returns the stored deadline unchanged; a
different grace on retry is ignored. A restored and later re-retained revision is a new removal
and receives a new deadline. Timestamp overflow fails the statement. `restore_revision` is
refused at or after the deadline; `begin_purge` before it. Expiry does not by itself purge.

`confirm_purge` requires `purging` state from a claim committed by an earlier transaction
(`purging_at < now()`), so payload deletion can occur between the two. A claim and confirmation
in one transaction are refused. Repeated confirmation never decrements twice. Physical deletion,
reference checks, read leases and the deletion journal belong to V1-15/V1-16.

## Locking and transactions

Helpers follow ADR 0004: each takes the outer transaction from `WriteTransaction`, works in a
savepoint, restores it without an await point, and never commits. Cancellation consumes the
owner; a cleanup failure leaves it unavailable. The lock order inside helpers is: run,
reservation, artifact, revision, owner account, then the instance row last. Every storage
helper locks the instance row, so storage writes across the installation serialize until each
transaction commits. Keep transactions that reserve short, do no external I/O while holding them
and reserve late in admission. This is a documented throughput limit, not a measured one.

Composing helpers for several owners, or composing them in a different order inside one caller
transaction, can deadlock. PostgreSQL then aborts one statement with SQLSTATE 40P01. The helper
returns that error after rolling back its savepoint, but the transaction still holds its earlier
locks. Roll back the whole transaction and retry it with the same idempotency keys; do not
continue it. A failed or interrupted commit is not a success. Recover by replaying the same keys
and bytes, never by generating a new key.

Admission composes `runs::create_run` and `storage::reserve` in one transaction. Both commit or
both roll back, and a replay returns the same run and reservation.

## Enforcement boundary

Counters and transitions are maintained by the helper protocol, as in ADR 0004. The database
enforces only the stated relational keys, CHECK constraints and column privileges. These cover
nonnegative counters, one revision per reservation, settled bytes within `max_bytes`, lifecycle
timestamp consistency, `purging_at >= purge_after`, scoped references and immutable metadata.
Arbitrary direct SQL by an application role that holds the counter and state UPDATE privileges
can still bypass helper accounting. This increment does not claim database-enforced accounting.
Tests compare counters with totals recomputed from rows; periodic reconciliation belongs to V1-17.

## Privileges and upgrade compatibility

| Object | API | Worker |
| --- | --- | --- |
| All five tables | SELECT | SELECT |
| Instance and account counters | UPDATE active/retained/reserved bytes | UPDATE active/retained/reserved bytes |
| Accounts | INSERT `scope_id` | INSERT `scope_id` |
| Artifacts | INSERT id/scope/kind/owner; UPDATE `last_revision` | Same |
| Reservations | INSERT immutable columns; UPDATE state/settled bytes/closed time | Same |
| Revisions | INSERT immutable metadata; UPDATE state, `retained_at`, `purge_after` | INSERT immutable metadata; UPDATE state, `purging_at`, `purged_at` |

Neither role receives limit columns, DELETE, TRUNCATE, DDL, grant options or function
execution. CHECK constraints tie each lifecycle state to its timestamps, so the column split
means the API cannot enter or leave `purging`/`purged` and the worker cannot retain or restore.

`src/boundaries.sql` now takes one parameter: the highest successfully applied migration version.
Migration 1's PUBLIC tolerance, migration 3's grants and migration 4's grants are each allowed
only once their version is recorded. This replaces the earlier per-version booleans without
changing the version-1 or version-3 contracts. The migrator still holds its advisory lock across
both boundary checks and all versions.

New migrators accept a populated version-3 database, apply version 4 and rerun idempotently.
Previous API and worker binaries (`2f1be947aa933177c2e407cd7290bf9909bd08ca`) remain ready. The
previous migrator refuses a version-4 database at its strict preflight, before changing anything;
that is intended. Deploy runs the new migrator before rolling out new processes. There is no new
pool or listener. ADR 0003's connection budget still applies; storage row-lock waits occupy pool
connections, so bound lock and statement timeouts per role.

## Verification

No new dependency. `tests/schema/storage.rs` runs against the isolated PostgreSQL 18 fixture.
It covers:

- Limits and replay: unconfigured refusal; owner, project and instance limits; reservation and
  settlement replay and conflicts; one charge per revision; release-once.
- Admission: `create_run` + `reserve` atomicity and replay.
- Unknown outcomes: release refused for intent and `outcome_unknown` operations.
- Concurrency: a 13-transaction race for one instance budget across owners; a limit reduction
  waiting on an in-flight reservation, followed by usage preservation, exact replay and refusal
  of new work; a cross-owner deadlock retried as a whole transaction.
- Retention: deadline preservation, role split, expiry boundaries and exactly-once purge.
- Denials: direct SQL privileges and scoped-key violations; v4 grants refused at v3.
- Cancellation and commits: cancellation at savepoint open, release and rollback round trips;
  a lost COMMIT acknowledgement recovered by replay.
- Migration 4: failure, statement timeout, SIGTERM/SIGKILL and four concurrent migrators.
- Upgrade: a populated v3 database upgraded to v4 with authentic `2f1be94` binaries.

CI builds those binaries from `git archive`, alongside the existing `18f5246` build, and sets
`V3_BINARY_DIR`. Released migration hashes, now including 3 and 4, are pinned in a non-database
test. These tests are required checks; their presence is not a claim that a particular run
passed. Throughput, hot-row contention and sizing are not measured.

## Remaining

ADR 0006 adds project/resource grant persistence with direct and mapped provenance and
revocation history. V1-04 mapping behavior and V1-05 permission meanings are consumer contracts,
not prerequisites to this storage vocabulary. V1-02 final acceptance remains open. Other areas
stay with their own tickets:

- V1-15: uploads, staging, paths and downloads.
- V1-16: references, purge execution and the deletion journal.
- V1-17: overrides, warnings, renewal, reconciliation and refusal presentation.
- V1-05: authorization.
- V1-30/31: backup and restore.
