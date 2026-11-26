# ADR 0046: Maintenance-window coordinated backup capture

- **Status:** Accepted
- **Date:** 26 November 2026
- **Ticket:** V1-30 ([openmettle-core#27](https://github.com/OpenMettle/openmettle-core/issues/27), [openmettle-core#26](https://github.com/OpenMettle/openmettle-core/issues/26))
- **Related ADRs:** [ADR 0028](0028-telemetry-contract-and-metrics.md), [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md), [ADR 0040](0040-transactional-quotas-and-reservation-reconciliation.md), [ADR 0041](0041-retention-purge-and-deletion-journal.md), [ADR 0044](0044-own-inference-proxy-and-binding-free-dispatch.md), [ADR 0045](0045-credential-vault-and-external-connection-lifecycle.md)

## Triggering problem

`ARCHITECTURE-v1.md` requires a nightly (`24h` RPO) coordinated, encrypted backup of every authoritative OpenMettle store to an off-workstation failure domain, paired with Grandfather-Father-Son (GFS) retention (`7 daily, 4 weekly, 3 monthly`) and immediate alerting on backup failures or overdue schedules (`openmettle.backup.runs`).

Taking uncoordinated copies of PostgreSQL, the POSIX artifact volume, and optional Graphiti/Neo4j state risks:

- skewed artifact ledger rows versus on-disk payloads, causing post-restore `storage rebind` / `quota verify` drift or accidental worker unlinks;
- unsettled quota holds, in-flight worker turns, active external-connection credential refreshes, or unreported gateway dispatches;
- missing deletion-journal watermarks required by [ADR 0041](0041-retention-purge-and-deletion-journal.md) to stop purged artifact revisions and revoked external connections from resurrecting after a restore;
- coupling v1 backup consistency to storage-specific CSI, LVM, or ZFS snapshot drivers rather than generic POSIX PVCs.

V1 therefore adopts a short, explicitly coordinated maintenance window that pauses new write admission, drains in-flight work, captures a single verified encrypted recovery set across all authoritative stores, and reports run outcomes and RPO compliance through OTLP/Prometheus telemetry.

## Decision

Implement PostgreSQL-coordinated maintenance-window backup capture in `openmettle-core` (`migration 0045`, `src/backup`, `openmettle-admin backup`), promote the reserved telemetry signal `openmettle.backup.runs`, and codify explicit consistency, custody, encryption, retention, and recovery invariants.

### 1. Coordinated maintenance gate and durable run ledger (Migration 45)

Migration `0045_maintenance_backup_coordination.sql` (pure 7-bit ASCII, `SQL_ASCII` and `WIN1252` safe, acquiring `ACCESS EXCLUSIVE` on `openmettle.authorization_audit` via a bounded `NOWAIT` retry loop) adds two `openmettle_owner`-owned tables with zero direct table or column privileges for runtime roles (`openmettle_api`, `openmettle_worker`, `openmettle_issuance`, `openmettle_gateway`, or `PUBLIC`):

- **`openmettle.backup_maintenance_gate`** (singleton `id boolean PRIMARY KEY DEFAULT true CHECK (id)`):
  - Tracks `maintenance_active`, `backup_run_id`, `entered_at`, `entered_by_operator_id`, `reason`, `quiesced_at`, `rpo_target_seconds` (default `86400`, bounded `[3600, 604800]`), `rpo_tracking_armed_at`, `last_overdue_observed_at`, and `updated_at`.
  - `backup_maintenance_gate_state_check` enforces that `backup_run_id`, `entered_at`, `entered_by_operator_id`, `reason`, and `quiesced_at` are all `NULL` when `NOT maintenance_active`, and that `entered_at`, `entered_by_operator_id`, and validated `reason` (`capacity_valid_name(reason, 512)`) are populated whenever `maintenance_active = true`.
- **`openmettle.backup_runs`**:
  - Durable append-only lifecycle ledger (`draining -> capturing -> succeeded | failed | incomplete`) with unique `request_key`, `operator_id`, `started_at`, `lease_until`, `quiesced_at`, `completed_at`, `destination_domain`, `encryption_key_id`, `bundle_digest`, `manifest_digest`, deletion-journal watermarks (`journal_origin_us`, `journal_seq`, `journal_chain_digest`, optional `lifecycle_origin_us`, `lifecycle_baseline_digest`, `connection_origin_us`), redacted ASCII `failure_code`, `telemetry_observed`, and `manifest_summary`.
  - A `BEFORE UPDATE OR DELETE` trigger (`enforce_backup_runs_transitions`) forbids row deletion and rejects any update to a terminal row except `telemetry_observed: false -> true`.
- **Audit trail:** `openmettle.authorization_audit` widens its action and target-kind constraints to record `backup.maintenance_entered`, `backup.capture_succeeded`, `backup.capture_failed`, `backup.maintenance_released`, and `backup.rpo_armed` (`actor_kind = 'operator'`, target kinds `backup_maintenance` and `backup_run`).

### 2. Deadlock-free admission closing, SQLSTATE contracts, and in-flight drain

- **Canonical lock order:** Runtime write transactions acquire a lightweight `FOR SHARE` lock on `backup_maintenance_gate` via `SECURITY DEFINER` function `openmettle.backup_maintenance_lock_open()` (granted to `openmettle_api`, `openmettle_worker`, and `openmettle_issuance`), which raises `SQLSTATE OMM01` while `maintenance_active = true`. Owner maintenance/capture functions and `openmettle.backup_observe_telemetry()` lock strictly `backup_maintenance_gate -> backup_runs -> authorization_audit` (insert-only) and never lock runtime data tables, making `backup_maintenance_gate` a pure lock sink that cannot deadlock with runtime writers.
- **Read-only status check:** `openmettle.backup_maintenance_is_active()` (`SECURITY DEFINER`) is granted to `openmettle_api`, `openmettle_worker`, `openmettle_issuance`, and `openmettle_gateway`.
- **Runtime behavior while `maintenance_active = true`:**
  - **`openmettle-api`:** refuses mutating `/v1` operations (projects, conversations, branches, run admission/cancellation, approval decisions, artifact uploads and revision retain/restore transitions, retention policy writes, quota mutations, external connection mutations, and session issuance) with HTTP `503 unavailable`.
  - **Open during drain:** `/healthz`, `/readyz`, `/v1` `GET` reads (including `GET /v1/admin/retention/status` and `POST .../effective-configuration` preview), settlement of already-reserved artifact uploads, already-claimed worker run settlement (including spill reservations where `run.is_some()`), and gateway usage settlement remain open so acknowledged in-flight work finishes cleanly.
  - **`openmettle-worker`:** `claim_next` and `reclaim_next` return `Ok(None)`, `purge_due` is skipped while maintenance is active, already-claimed turns finish and settle, and the maintenance loop continues sweeping `backup_observe_telemetry()`.
- **Bounded drain & fail-closed recovery:**
  - `openmettle-admin backup capture` polls six in-flight drain counters (`runs`, `storage_reservations`, `artifact_revisions` purges, unsettled `gateway_requests`, active `external_connections` refreshes, and unconfirmed `capacity_grants`) while renewing its capture lease (`lease_until`).
  - Once all six counts reach zero, capture checks `restore_reconciliation_gate.open = true`, zero active `storage_volume_control.adoption_run_id`, and healthy `verify_accounting_drift()`, then marks the run `capturing` and stamps `quiesced_at`.
  - Any drain timeout (`failure_code = 'drain_timeout'`), drift error, or dump/I/O failure removes `.staging.<run_id>`, marks `backup_runs.state = 'failed'`, and keeps `maintenance_active = true` for explicit operator recovery.
  - Releasing maintenance while an unexpired capture lease is held fails with `SQLSTATE OMB02` unless the operator explicitly passes `--abort-active-run` after confirming the capture process has exited (transitioning the active run to `incomplete`).

### 3. Per-component consistency and custody boundaries

| Component | Bundle entry | Consistency & custody rule |
| --- | --- | --- |
| PostgreSQL 18 | `pg.dump.enc` | `pg_dump --format=custom --schema=openmettle --no-owner` captured after quiesce; preserves schema objects and bounded role ACLs without touching `public`. Credentials pass solely through an ephemeral `0600` `PGPASSFILE` unlinked on drop (never argv or `PGPASSWORD`). |
| `openmettle-gateway` | `gateway-entitlements.json.enc` | Stateless under [ADR 0044](0044-own-inference-proxy-and-binding-free-dispatch.md); PostgreSQL is authoritative (`gateway_consistency_mode = "postgresql_authoritative_adr_0044"`). Captures a `REPEATABLE READ, READ ONLY` snapshot of quota defaults, overrides, budgets, family policies, and usage summaries. |
| POSIX artifact PVC | `artifacts.bin.enc` | Deterministic `OMART01` stream over generic POSIX files (no CSI/LVM/ZFS dependency). Verifies `.openmettle-volume-id`, `O_NOFOLLOW`, `nlink == 1`, `payload_ino`, empty `staging/`, exact `size_bytes`, and live SHA-256 against `artifact_revisions`. |
| Deletion journal | `deletion-journal.bin.enc` | Exported via `restore::export()` and watermark-pinned in both `manifest.json.enc` and `backup_runs` so post-restore `restore lock` + `restore replay` runs directly from the unpacked set. |
| Graphiti / Neo4j | `neo4j.dump.enc` (optional) | Explicitly declared via `--graphiti-mode not-provisioned` (default) or `--graphiti-mode offline-dump --neo4j-dump <PATH>`. Never silently omitted or inferred. |
| Non-secret config | `config.json.enc` | Explicitly declared `--config-file NAME=PATH` files plus non-secret `vault_required_key_ids` inventory. Refuses keyring/vault paths/inodes, PEM private keys, and JSON secret fields. |
| External vault keys | Excluded (off-host) | External-connection vault master keys ([ADR 0045](0045-credential-vault-and-external-connection-lifecycle.md)) and backup encryption keys stay in separate off-host custody outside every backup. |
| Rebuildable indexes | Excluded (declared) | Manifest explicitly records `["postgresql_secondary_indexes", "chroma_vector_embeddings", "derived_search_and_fulltext_indexes"]` as rebuildable post-restore. |

### 4. Streaming AEAD encryption, destination isolation, CLI, and GFS retention

- **Dedicated backup keyring (`BACKUP_KEYS_CONFIG`):** Version-1 JSON manifest (`0400`/`0600`, owner-only) referencing 32-byte key files (`0400`/`0600`). Loader validates non-zero keys, rejects duplicate keys (`subtle::ConstantTimeEq`), wraps material in zeroizing `SharedSecret`, and refuses any path, `(dev, ino)`, or key-byte overlap with `OPENMETTLE_*_VAULT_KEYS_CONFIG`.
- **Chunked AEAD wire format (`OMBKUP01`):** 64 KiB chunks encrypted via HKDF-SHA256 per-file keys and AES-256-GCM (`ring`, zero new Cargo dependencies, `unsafe_code = "forbid"`), binding canonical AAD `(backup_run_id, artifact_role, key_id, chunk_seq, is_final)` with strict EOF and trailing-byte rejection.
- **Atomic publishing & destination guard:** Stages inside `.staging.<backup_run_id>` (`0700` dir, `0600` files), writes `manifest.json.enc` and non-secret routing header `backup-meta.json`, `fsync`s staging, atomically renames to `backup-<YYYYMMDDTHHMMSSZ>-<backup_run_id>`, and `fsync`s the destination root before committing `backup_runs.state = 'succeeded'`. `openmettle-admin` permanently enforces `allow_local_test_paths = false`, refusing `/tmp`, `/var/tmp`, `$TMPDIR`, git workspaces, artifact-root overlaps, and keyring overlaps, and supports `--require-separate-device`.
- **Owner CLI (`openmettle-admin backup`):**
  - `status`: reports gate state, RPO target/armed timestamp, last succeeded run, and latest run status.
  - `enter-maintenance` / `release-maintenance [--abort-active-run]` / `arm-rpo [--rpo-seconds N]`: idempotent, operator-audited maintenance and RPO controls.
  - `capture`: runs the full coordinated workflow (optional `--release-on-success`, default GFS pruning unless `--no-prune`).
  - `verify` / `unpack` / `prune [--dry-run]`: offline AEAD + SHA-256 + `bundle_digest` verification, `0700` unpack ready for `pg_restore` -> `restore lock` -> `storage rebind` -> `restore replay`, and `7 daily, 4 weekly, 3 monthly` GFS retention (keeping the newest completed backup unconditionally and ignoring incomplete or foreign directories).

### 5. Telemetry promotion (`openmettle.backup.runs`) and RPO monitoring

- Promotes `openmettle.backup.runs` (`openmettle_backup_runs_total`, `outcome ∈ {succeeded, failed, incomplete, overdue}`) from `reserved_signals` into active `metrics` in `contracts/telemetry/v1.json` (`17` metrics, `480` data-point streams, `1,208` Prometheus series per process; [ADR 0028](0028-telemetry-contract-and-metrics.md)).
- `openmettle-worker` calls `SECURITY DEFINER` `openmettle.backup_observe_telemetry()` (`FOR UPDATE SKIP LOCKED`) every maintenance tick to:
  1. expire abandoned active backup leases to `incomplete` while keeping `maintenance_active = true`;
  2. claim each unobserved terminal `backup_runs` row exactly once (`telemetry_observed = true`);
  3. emit `overdue` (throttled to at most once per hour via `last_overdue_observed_at`) whenever `rpo_tracking_armed_at IS NOT NULL` and `now() - coalesce(last_succeeded_at, rpo_tracking_armed_at) > rpo_target_seconds`.
- Fresh dev/test databases start unarmed (`rpo_tracking_armed_at IS NULL`) and arm automatically on the first capture or via `openmettle-admin backup arm-rpo`, avoiding spurious `overdue` alerts before scheduling is enabled.
- `contracts/telemetry/alerts-v1.yaml` adds `OpenMettleBackupFailedOrOverdue` (`for: 0m`, `severity: critical`, `component: backup`, `service: openmettle-worker`), verified by `contracts/telemetry/alerts-v1-test.yaml` under `promtool test rules`.

## Alternatives considered

- **Online PITR + CSI volume snapshots:** Deferred to post-v1 uninterrupted backups (`itemId=307064202`) because it requires storage-class-specific snapshot controllers and continuous WAL archive orchestration.
- **Adding external encryption/archive crates (`age`, `tar`, `flate2`):** Rejected to keep zero new Cargo dependencies and keep the streaming AEAD and archive formats minimal, auditable, and `unsafe_code = "forbid"`.
- **Auto-releasing maintenance on capture failure:** Rejected because drain timeouts, accounting drift, or destination I/O failures require explicit operator inspection before reopening mutation admission.

## Consequences

- Nightly coordinated backups incur a brief mutation-admission pause while reads, health probes, and in-flight run/upload/gateway settlements stay open.
- Because `pg.dump.enc` is captured inside maintenance, restoring `pg.dump` boots with `maintenance_active = true` as extra defense-in-depth until the operator completes `openmettle-migrate`, `restore lock`, `storage rebind`, `restore replay`, pre-worker checks, and `backup release-maintenance --abort-active-run`.
- Uninterrupted zero-maintenance backups (continuous WAL/PITR and online snapshot coordination) remain explicitly deferred (`itemId=307064202`).

## Affected contracts, evidence, and delivery split

- **Database & boundaries:** `migrations/0045_maintenance_backup_coordination.sql`, `src/migrate.rs`, `src/boundaries.sql`, `tests/schema.rs`, `tests/schema/authorization.rs`.
- **Core engine & CLI:** `src/backup.rs`, `src/backup/{crypto,archive}.rs`, `src/bin/admin.rs`, runtime admission gates (`src/authz/`, `src/v1/`, `src/storage.rs`, `src/quotas.rs`, `src/vault.rs`, `src/sessions.rs`, `src/worker.rs`).
- **Telemetry & alerts:** `contracts/telemetry/v1.json`, `contracts/telemetry/alerts-v1.yaml`, `contracts/telemetry/alerts-v1-test.yaml`, `src/telemetry/metrics.rs`, [ADR 0028](0028-telemetry-contract-and-metrics.md), `tests/telemetry_contract.rs`.
- **Operator runbook & deploy boundary:** [`docs/operator/maintenance-backup-and-recovery.md`](../operator/maintenance-backup-and-recovery.md); Kubernetes `CronJob`, PVC mounts, and off-host secret distribution belong to `openmettle-deploy` (V1-32).
- **Evidence:** Unit tests in `src/backup/{crypto,archive}.rs`, `src/backup.rs`, and `src/bin/admin.rs`; `promtool check rules` / `promtool test rules`; PostgreSQL 18.1 integration tests in `tests/schema/backup.rs` exercising real `pg_dump`, `pg_restore`, `openmettle-migrate`, `restore lock`, `storage rebind`, `restore replay`, and `quota verify`. Live workstation/cluster qualification and scheduled rollout remain separate owner gates.
