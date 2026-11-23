# 0041 — Retention, purge and deletion journal

Status: proposed for Wave 21c, V1-16 PR1, 22 November 2026. Refs #16. Base `main` is
`e152f8f8d4a382c688ee8e41d197e790ce22b1ee` (schema 23). Dependencies:
[V1-15](https://github.com/OpenMettle/openmettle-core/issues/15)
([ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md)) and
[V1-17](https://github.com/OpenMettle/openmettle-core/issues/17)
([ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md)); coordinates restore
barriers with [V1-30](https://github.com/OpenMettle/openmettle-core/issues/27). PR1 records this
decision; PR2 and PR3 own schema, store, worker, HTTP routes and verification. Issue #16 remains
open. No new Cargo crate is introduced beyond ADR 0040's `rustix` foundation.

## Triggering problem

[ADR 0005](0005-artifact-storage-accounting.md) defines `active -> retained -> purging -> purged`
accounting (`active_bytes + retained_bytes + reserved_bytes`) and low-level helpers in
[`src/storage.rs`](../../src/storage.rs). [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md)
adds PVC payloads and an unscheduled `purge_due`, and
[ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md) hardens physical deletion
into the 3-stage `.purge.<reservation_id>` inode-preserving protocol pinned via
`storage_volume_control` (`OMQ03`). Three gaps remain for V1-16 (`#16`):

1. **Configurable retention and disassociation.** There is no audited administrator-configurable
   grace policy (30-day default, bounded range including `0` for immediate purge eligibility when
   policy permits), nor authorized disassociation and pre-expiry restore workflows that keep
   retained bytes charged to the owning scope and instance quota until purge succeeds.
2. **Safe purge recheck.** `storage::begin_purge` currently checks only `state = 'retained'` and
   `purge_after <= now()`. It does not guard against live `message_parts` attachments, active
   runs or tool spills, knowledge/derived-source links, retention holds or concurrent
   reattachment.
3. **Deletion/revocation journal and restore barrier.** Live deletion grace (30 days) is shorter
   than backup retention (7 daily, 4 weekly, 3 monthly in
   [ARCHITECTURE-v1.md](../../ARCHITECTURE-v1.md)). Without an authoritative deletion and
   revocation journal replayed before reopening a restored database and PVC, V1-30 (`#27`)
   recovery could resurrect purged payloads, revive revoked grants/shares or restart expired
   grace windows.

## Decision

Keep retention state, reference rechecks, the append-only deletion/revocation journal and the
restore reconciliation gate in PostgreSQL alongside the existing storage ledger, and reuse
ADR 0040's volume-pinned 3-stage physical purge on the durable worker path.

### Retention policy and disassociation lifecycle

- **Audited grace configuration.** Store an installation-wide `retention_grace_seconds` setting
  (default `2_592_000` s = 30 days) within operator-configured deployment bounds
  `[min_grace_seconds, max_grace_seconds]` (permitting `0` for immediate purge eligibility only
  when deployment policy sets `min_grace_seconds = 0`). Only `account_admin` (or
  `openmettle_owner` bootstrap/break-glass) may mutate the policy, and every change increments a
  monotonic `policy_revision` (a trigger enforces this for every writer). An `account_admin`
  change, through `openmettle.retention_set_grace`, also writes an `authorization_audit` record
  with actor, old/new values, reason and request key; `openmettle_owner` sets the deployment
  bounds as configuration, outside the application audit trail.
- **Forward-only policy edits.** Changing `retention_grace_seconds` governs subsequent
  disassociations. Adjusting existing `purge_after` deadlines is a separate explicit, previewable
  and audited `account_admin` action. Quota reductions, expired overrides or hard-limit pressure
  never shorten grace periods or trigger early purge (ADR 0005, ADR 0040).
- **Disassociation (`active -> retained`).** An authorized `Delete` on an artifact, revision,
  conversation or project transitions affected `active` revisions to `retained`, stamping
  `retained_at = now()`, `purge_after = now() + grace` and the applied `policy_revision` once on
  the database clock. Supporting `grace = 0` requires PR2's additive migration to relax Migration
  0004's `artifact_revisions_lifecycle_check` from `purge_after > retained_at` to
  `purge_after >= retained_at` and update `storage::retain_revision` to accept `0` only when the
  configured policy permits it. Bytes shift from `active_bytes` to `retained_bytes`, leaving total
  charged exposure unchanged for both the owning scope and `storage_instance`.
- **Immediate invisibility.** Once `retained`, a revision is immediately excluded from default
  listings, content downloads (`409 conflict`, ADR 0031), new message attachments, model context
  and retrieval/recall ([ADR 0036](0036-conversation-branches-presets-and-effective-model-config.md)).
  Shared payloads only enter `retained` once their final live association is removed; expiring
  revisions remain inaccessible even if physical purge lags.
- **Pre-expiry restore (`retained -> active`).** Strictly before `purge_after` and before
  `begin_purge` claims `'purging'`, an authorized caller may restore a disassociated revision to
  `active`. Restore rechecks current primary authorization, project lifecycle (refusing deleted or
  archived projects as appropriate per ADR 0027) and active holds, restores explicit target
  associations without reinstating revoked shares or stale grants, and shifts `retained_bytes`
  back to `active_bytes` (zero net quota increase) while re-validating scope and instance ledger
  invariants under the canonical lock order. A restored revision that is later deleted again
  starts a fresh retention window from the then-current policy.
- **Canonical lock order.** All retention, restore, hold, purge and journal transactions follow
  the global lock order established across ADR 0005 and ADR 0040:
  `runs -> storage_reservations -> artifacts -> artifact_revisions -> storage_volume_control -> storage_accounts -> storage_instance`
  (followed by append-only journal/audit inserts).

### Safe purge recheck and cross-reference to ADR 0040

| Phase | Owner | Required transactional and filesystem invariants |
| --- | --- | --- |
| Claim (`retained -> purging`) | `openmettle_worker` (`storage::begin_purge`) | Lock in canonical order; verify `openmettle.storage_lock_pinned_volume()` (`OMQ03`), `NOT adoption_unverified`, non-null `payload_ino`, `state = 'retained'` and `purge_after <= now()`. Recheck zero live references (`message_parts` in non-deleted conversations, non-terminal runs or unresolved operations/tool spills per [ADR 0004](0004-run-persistence.md), [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md) and [ADR 0039](0039-scoped-mcp-adapter-and-bounded-tool-results.md), active knowledge/derived-source links, and active retention holds). Commit `'purging'` before any disk mutation. |
| Physical delete & anchor | `openmettle_worker` (`artifact_fs::purge_due`) | Delegate verbatim to [ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md)'s 3-stage protocol: Stage A creates/validates `revisions/.purge.<reservation_id>` under non-blocking `LOCK_EX` (deferring cleanly on `WouldBlock` while `Store::read` holds `LOCK_SH`), truncates and unlinks `revisions/<id>` and matching `staging/<id>` while `.purge.<id>` keeps `payload_ino` pinned; Stage B commits `storage::confirm_purge` (`purging -> purged`, `purge_stage = 'anchor_pending_unlink'`) and releases `retained_bytes` exactly once; Stage C detaches `.purge.<id>` via bounded cursor sweep. |
| Derived & provenance cleanup | Durable worker sweeps | Removal immediately excludes source-dependent indexes, previews and memory facts from recall. Terminal purge enqueues idempotent cleanup of derived copies using recorded source provenance; independently supported shared facts require provenance-aware checks, and deletion cannot retract data already sent to an external model or provider. |

- **Concurrent reattachment and race safety.** Any operation that attaches a revision to a
  message, run, knowledge collection or hold, or invokes `restore_revision`, locks the
  `artifact_revisions` row in canonical order and requires `state = 'active'` (or `state =
  'retained' AND now() < purge_after` for restore). Because `begin_purge` locks the same row
  before rechecking references and setting `state = 'purging'`, either the reattachment commits
  first (causing `begin_purge` to defer without purging) or `begin_purge` commits `'purging'`
  first (causing the concurrent attach/restore to fail with `NotEligible` / `409 conflict`).
- **Role separation and crash idempotency.** Preserve ADR 0005's column-privilege split:
  `openmettle_api` updates retention columns (`retained_at`, `purge_after`) only;
  `openmettle_worker` updates purge columns (`purging_at`, `purged_at`, `purge_stage`) only. A
  worker crash after `begin_purge` or during Stage A/C resumes cleanly on the next sweep without
  double-decrementing `retained_bytes` or re-releasing capacity.

### Durable deletion and revocation journal and restore barrier

- **Authoritative append-only journal (`deletion_journal`).** Record an immutable, monotonically
  sequenced (`journal_seq`) entry in PostgreSQL for every irreversible state transition that must
  never be undone by restoring an older backup:
  1. Terminal artifact revision purges (appended atomically in the same transaction as
     `storage::confirm_purge`).
  2. Hard scope, project, conversation and artifact deletion tombstones and authoritative
     `purge_after` deadline commitments/adjustments.
  3. Security revocations: project membership and resource share revocations, local group
     removals/disablement, user account disablement, identity approval withdrawal, provider
     authority retirement and capability denies.
- **Minimal metadata, zero private content.** Each journal record stores only `journal_seq`,
  `recorded_at`, `event_kind`, `entity_kind`, `entity_id`, `scope_id` (nullable for instance/user
  events), `cause_kind` (`user`, `admin`, `operator`, `worker_purge`), actor/operator UUID,
  `original_purge_after`, `purged_at`, `content_digest` (SHA-256 bytes for purged revisions only),
  `policy_revision` and `request_key`, plus a running hash-chain digest linking `journal_seq` to
  `journal_seq - 1`. It never stores `display_name`, filenames, prompts, message text, secrets,
  credentials, emails or payload bytes. Application roles never receive `UPDATE`, `DELETE` or
  `TRUNCATE`. Purge records are appended by a `SECURITY DEFINER` trigger on the confirmation, so
  application roles need no journal privilege for them.
- **Backup-survivable watermark contract (coordinated with V1-30 `#27`).** Because restoring an
  older PostgreSQL dump rolls back in-database rows, V1-30's backup/export pipeline continuously
  or per-capture exports append-only, integrity-checked journal segments and a signed/checksummed
  watermark `(journal_seq, chain_digest, exported_at)` outside the primary storage failure domain
  across the full backup retention horizon (7 daily, 4 weekly, 3 monthly). Live purges do not
  rewrite historical encrypted backups; instead, the surviving journal overrides resurrected state
  on restore.
- **Fail-closed restore reconciliation barrier (`restore_reconciliation_gate`).** Every V1-30
  restore boots with the singleton `restore_reconciliation_gate` locked (`open = false`, storing
  the restored snapshot's `snapshot_journal_seq` and target `required_journal_seq`). While closed,
  `openmettle-api` refuses mutating and content-serving `/v1` routes (`503 unavailable`) and
  `openmettle-worker` refuses run claims and purge sweeps. Before opening the gate,
  `openmettle-admin` must verify and replay every surviving journal record with
  `journal_seq > snapshot_journal_seq` in order:
  - Re-apply tombstones and purges (removing resurrected payloads via the volume-pinned purge path
    and stripping resurrected references).
  - Re-apply all recorded security revocations and invalidate restored browser/native sessions.
  - Preserve original `purge_after` deadlines from the restored database and journal; never
    restart the 30-day grace window on restore.
  - **Fail closed on any journal fault.** If the external journal is absent, unreadable,
    truncated, fails hash-chain/checksum verification, lags the restored snapshot, or leaves an
    unresolved deletion/revocation gap or volume/ledger conflict, replay aborts with a hard
    restore-validation failure. Audited operator break-glass permits offline repair/reconciliation
    tooling only; live API/worker access and `restore_reconciliation_gate` stay locked until replay succeeds.

### API, authorization and telemetry invariants

- **Authorization and concealment ([ADR 0007](0007-application-api-contract.md),
  [ADR 0027](0027-authorization-and-private-projects.md)).** Artifact/revision disassociation and
  restore evaluate primary PostgreSQL authorization and conceal unknown, cross-scope or unshared
  private targets with `404 not_found` (`401 unauthenticated` for missing/inactive principals;
  `403 policy` only on visible targets or denied admin actions). `account_admin` may configure
  retention policy, preview/apply deadline adjustments and read restore-gate/journal watermark
  health (with `authorization_audit` entries) without gaining read or download visibility into
  private artifacts, filenames, conversations or memory.
- **Wire contract.** Mutating endpoints require `Idempotency-Key`, closed request schemas
  (`additionalProperties: false`), `NonNegativeDecimal` strings for byte counts and journal
  sequences, and RFC 9457 `Problem` responses (`409 conflict` for expired, purging, held or
  live-referenced transitions; `409 idempotency_conflict`; `503 unavailable` while the restore
  gate is closed).
- **Redaction and bounded telemetry ([ADR 0024](0024-process-telemetry-and-redaction.md),
  [ADR 0028](0028-telemetry-contract-and-metrics.md)).** Instrument only closed-enum counters and
  fixed-bucket histograms (purge outcomes, deferred-reference causes, purge lag past
  `purge_after`, journal append/replay outcomes and restore-gate state). Never emit user IDs,
  scope IDs, artifact IDs, filenames, digests or prompts in metric labels, logs, traces or error
  responses. Any new metric updates [`contracts/telemetry/v1.json`](../../contracts/telemetry/v1.json),
  `src/telemetry/metrics.rs` and Prometheus alert fixtures together.

## Alternatives considered

| Alternative | Decision and rationale |
| --- | --- |
| Immediate synchronous `unlink` on delete | Rejected: breaks the agreed 30-day recovery grace, collides with concurrent readers/runs and prevents transactional reference/hold checks. |
| Store the deletion journal only inside primary PostgreSQL | Rejected: restoring an older PostgreSQL backup rolls back the journal itself, allowing purged payloads and revoked grants to reappear silently. |
| Rewrite historical encrypted backups on every live purge | Rejected: breaks immutable backup verification, requires live access to offline backup credentials and conflicts with `ARCHITECTURE-v1.md`. |
| Restart the 30-day grace window after restore | Rejected: violates V1-16 acceptance and delays erasure of already-expired items indefinitely across repeated restores. |

## Consequences and affected contracts

- **Positive.** Eliminates live-revision deletion races, guarantees retained-byte quota integrity
  without double release across crashes, and gives V1-30 a verifiable, fail-closed anti-resurrection
  contract without introducing a broker or scrubbing offline backups.
- **Costs and limits.** `begin_purge` performs indexed reference/hold lookups under the canonical
  lock order, and V1-30 backup/restore operators must maintain the independent journal export
  alongside encrypted backups; records never exported before catastrophic primary loss cannot be
  reconstructed and deliberately trigger a fail-closed restore validation failure.
- **Affected contracts and boundaries.** Additive forward migration after ADR 0040 PR2;
  [`src/storage.rs`](../../src/storage.rs), [`src/artifact_fs.rs`](../../src/artifact_fs.rs),
  `src/authz/`, `src/worker.rs`, `src/boundaries.sql`,
  [`contracts/openapi/openmettle-v1.json`](../../contracts/openapi/openmettle-v1.json),
  `contracts/fixtures/` and [`contracts/telemetry/v1.json`](../../contracts/telemetry/v1.json).
  Cross-references ADR 0005, ADR 0007, ADR 0024, ADR 0027, ADR 0028, ADR 0031, ADR 0033, ADR 0036,
  ADR 0039 and ADR 0040; establishes the journal/gate boundary consumed by V1-30 (`#27`).

## Delivery split

| Increment | Scope and mandatory verification |
| --- | --- |
| **PR1 (this record)** | Concise ADR 0041 and [`DECISIONS.md`](../../DECISIONS.md) index update (`0039`–`0041`). No schema, code or fixture changes; `#16` remains open. |
| **PR2 (Schema, store, journal and restore barrier)** | Additive migration (policy table/revision, `purge_after >= retained_at`, hold/reference indexes, append-only `deletion_journal`, `restore_reconciliation_gate`, role grants and `src/boundaries.sql`), `storage::begin_purge` reference/hold recheck, atomic `confirm_purge` journal append, scheduled worker `purge_due` integration and `openmettle-admin` journal export/replay gate. Isolated PostgreSQL 18 suite covering expiry boundaries (`grace = 0`, `now() == purge_after`), live-reference and concurrent-reattachment races, duplicate purge/retries, worker death across all stages without double release, storage/`OMQ03` failures and fail-closed journal lag/tamper replay gates. |
| **PR3 (`/v1` API, admin routes and OpenAPI fixtures)** | Authenticated `/v1` artifact/revision disassociation and pre-expiry restore routes, audited `account_admin` retention-policy and deadline-preview/apply routes, restore-gate health/status surfacing, OpenAPI contract updates plus regenerated `contracts/fixtures/`, telemetry contract/alert updates if metrics are added, and authorization/concealment/redaction canary tests. |

PR2 is delivered in two increments (23 November 2026). **PR2a** (migration 28) adds the
retention policy and `retention_set_grace`, `purge_after >= retained_at`, operator-only holds,
the reference predicate (`artifact_revision_pinned`) used by `begin_purge` and by a claim guard
for every writer, the attach/hold row lock, and the hash-chained `deletion_journal` holding purge
records only (journal fields for revocations and tombstones arrive with those events). Every
attachment counts as live because no conversation or project tombstone exists yet; no knowledge
links exist yet. Its suite covers expiry boundaries, races, retries, duplicates, interrupted
stages and `OMQ03`. **PR2b** adds `restore_reconciliation_gate`, the `openmettle-admin` journal
export/replay gate with lag and tamper checks, and worker `purge_due` scheduling.
