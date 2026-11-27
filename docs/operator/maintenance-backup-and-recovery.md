# Maintenance-window coordinated backup and recovery

Use this runbook to operate nightly coordinated backups (`V1-30`, [ADR 0046](../adr/0046-maintenance-window-coordinated-backup-capture.md)), monitor backup telemetry (`openmettle.backup.runs`), recover from failed or interrupted maintenance windows, and hand an unpacked recovery set into the PostgreSQL + artifact volume restore checklist.

## Preconditions

1. **Owner login and tooling:** Run `openmettle-admin` with `OPENMETTLE_ADMIN_DATABASE_URL` set to the `openmettle_owner` database login and `pg_dump` (PostgreSQL 18 client) on `PATH` (or override the executable path via `--pg-dump-bin PATH` / `OPENMETTLE_PG_DUMP_BIN` when multiple PostgreSQL client versions are installed). Never grant `openmettle_owner` credentials to API, worker, issuance, or gateway workloads.
2. **Off-workstation destination mount:** Mount a destination directory in a failure domain separate from the primary workstation/cluster storage (for example, an NFS/SMB/object-mounted NAS backup directory). `openmettle-admin backup capture` refuses temporary directories (`/tmp`, `/var/tmp`, `$TMPDIR`), git workspaces, and any path overlapping `ARTIFACTS_DIR` or keyring directories. Pass `--require-separate-device` in production to enforce that the backup destination resides on a distinct filesystem device from the artifact volume.
3. **Separate backup encryption keyring (`BACKUP_KEYS_CONFIG`):** Provision a dedicated version-1 backup keyring manifest (`0400` or `0600`, owner-only) referencing 32-byte key files (`0400` or `0600`):

   ```json
   {
     "version": 1,
     "active_key_id": "backup-2026-11",
     "keys": [
       {
         "id": "backup-2026-11",
         "file": "/etc/openmettle/backup-keys/backup-2026-11.key"
       }
     ]
   }
   ```

   - **Strict separation from vault keys:** Never point `OPENMETTLE_ADMIN_BACKUP_KEYS_CONFIG` (or `--backup-keys-config`) at `OPENMETTLE_*_VAULT_KEYS_CONFIG` or reuse credential-vault key material ([ADR 0045](../adr/0045-credential-vault-and-external-connection-lifecycle.md)). Keep backup keys and vault master keys in separate off-host custody outside the backup destination.
   - Generate a 32-byte key with `head -c 32 /dev/urandom > backup-2026-11.key && chmod 0400 backup-2026-11.key`.

4. **Arm nightly 24h RPO tracking:** Fresh databases start with RPO tracking unarmed so local development and test instances do not emit spurious `overdue` alerts. Either arm explicitly before the first scheduled job or let the first `backup capture` arm it automatically:

   ```sh
   openmettle-admin backup arm-rpo \
     --operator-id "$OPERATOR_ID" \
     --request-key "arm-rpo-2026-11-26" \
     --reason "Enable nightly 24h RPO alerting" \
     --rpo-seconds 86400
   ```

## Nightly coordinated backup capture

Run `openmettle-admin backup capture` during the scheduled maintenance window:

```sh
openmettle-admin backup capture \
  --destination-root /mnt/offhost-backups/openmettle \
  --destination-domain offhost-nas-primary \
  --backup-keys-config /etc/openmettle/backup-keys/keyring.json \
  --artifact-root /var/lib/openmettle/artifacts \
  --operator-id "$OPERATOR_ID" \
  --request-key "nightly-$(date -u +%Y%m%dT%H%M%SZ)" \
  --reason "Scheduled nightly coordinated backup" \
  --drain-timeout-secs 300 \
  --require-separate-device \
  --graphiti-mode not-provisioned \
  --chroma-mode not-provisioned \
  --config-file catalog.json=/etc/openmettle/catalog/catalog.json \
  --config-file inference.json=/etc/openmettle/worker/inference.json \
  --keep-daily 7 \
  --keep-weekly 4 \
  --keep-monthly 3 \
  --release-on-success
```

What happens during capture:

1. **Pre-flight validation:** Validates database URI allow-list + strict `sslrootcert`-only TLS preflight (for `verify-ca` / `verify-full`, isolating `pg_dump` from ambient `$HOME/.postgresql/*` defaults), destination isolation, non-secret config files (refusing PEM private keys, secret JSON keys, or keyring/vault paths), optional `--neo4j-dump`, and Chroma disposition (`--chroma-mode`) before closing admission.
2. **Admission closes (`maintenance_active = true`):** `openmettle-api` answers `503 unavailable` on mutating `/v1` routes and session issuance while keeping `/healthz`, `/readyz`, `/v1` reads, and settlement of already-started uploads/runs/gateway reports open. `openmettle-worker` stops claiming runs and skips `purge_due`.
3. **Drain & drift verification:** Polls until active runs, open reservations, active purges, unsettled gateway requests, active external-connection refreshes, and unconfirmed capacity grants all hit `0`, opens a single exported `REPEATABLE READ` snapshot (recording its `transaction_timestamp()` as `quiesced_at`), confirms `restore_reconciliation_gate.open = true` and zero adoption/rebind barrier, and runs `verify_accounting_drift()`.
4. **Encrypted capture, staged publication & atomic publish:** Streams `pg.dump.enc`, `gateway-entitlements.json.enc`, `deletion-journal.bin.enc`, `artifacts.bin.enc` (POSIX `OMART01` archive verified live by SHA-256), optional `neo4j.dump.enc`, optional `chroma.archive.enc`, `config.json.enc`, and `manifest.json.enc` (AEAD `OMBKUP01`) into `.staging.<run_id>`, `fsync`s both `.staging.<run_id>` and the destination root, stages publication in PostgreSQL (`backup_runs.state = 'publishing'`), atomically publishes non-secret `backup-meta.json` (via a CSPRNG-unique exclusive `0600` temp file in the destination root + `sync_all()` + rename into `.staging.<run_id>/backup-meta.json`), renames `.staging.<run_id>` to `backup-<YYYYMMDDTHHMMSSZ>-<run_id>`, verifies and `fsync`s `backup-meta.json`, the published directory, and the destination root, and confirms `backup_runs.state = 'succeeded'`. Only `succeeded` runs increment the `succeeded` metric and reset the 24h RPO clock (anchored to `quiesced_at`).
5. **GFS pruning & release:** Applies `7 daily, 4 weekly, 3 monthly` pruning (always keeping the newest completed set and ignoring foreign/incomplete directories), then releases `maintenance_active` when `--release-on-success` is set.

### Optional Graphiti / Neo4j and Chroma dispositions

When Graphiti/Neo4j is provisioned, stop Neo4j during the maintenance window, produce a consistent offline dump (`neo4j-admin database dump`), and pass:

```sh
--graphiti-mode offline-dump --neo4j-dump /var/backups/neo4j/graphiti.dump
```

When Graphiti/Neo4j is not provisioned, keep `--graphiti-mode not-provisioned` (the default).

Chroma vector embeddings are **never** assumed rebuildable without explicit qualification. Choose one of three explicit modes:

- **Not provisioned (default):** `--chroma-mode not-provisioned` (records `chroma.mode = "not_provisioned"` and excludes `chroma_vector_embeddings` from `rebuildable_indexes`).
- **Offline archive included in backup:** Stop Chroma during the maintenance window, archive its persistent directory into a regular file, and pass:

  ```sh
  --chroma-mode archive --chroma-archive /var/backups/chroma/chroma.tar
  ```

  This encrypts the archive as `chroma.archive.enc` and unpacks it to `chroma.archive`.
- **Qualified post-restore rebuild:** Only after qualifying a complete, deterministic re-embedding/rebuild procedure against PostgreSQL + artifact storage, pass:

  ```sh
  --chroma-mode qualified-rebuild --chroma-qualification-ref "<QUALIFICATION_TICKET_OR_REPORT_ID>"
  ```

  This records the qualification reference in `manifest.json` and adds `chroma_vector_embeddings` to `rebuildable_indexes`.

### Verifying and pruning backups offline

Verify AEAD integrity, per-component plaintext/ciphertext SHA-256 digests, and the aggregate bundle digest without a database connection:

```sh
openmettle-admin backup verify \
  --backup-dir /mnt/offhost-backups/openmettle/backup-20261126T020000Z-<RUN_ID> \
  --backup-keys-config /etc/openmettle/backup-keys/keyring.json
```

Preview or run standalone GFS pruning (requires `--backup-keys-config` or `OPENMETTLE_ADMIN_BACKUP_KEYS_CONFIG` so every candidate's `manifest.json.enc` and component `.enc` digests are cryptographically verified before older sets can be pruned; sets are scoped per `(installation_id, destination_domain)` and unverified directories are never deleted):

```sh
openmettle-admin backup prune \
  --destination-root /mnt/offhost-backups/openmettle \
  --backup-keys-config /etc/openmettle/backup-keys/keyring.json \
  --keep-daily 7 --keep-weekly 4 --keep-monthly 3 --dry-run
```

## Telemetry and alerting (`openmettle.backup.runs`)

- `openmettle-worker` calls `openmettle.backup_observe_telemetry()` on each maintenance sweep and emits cumulative counter `openmettle.backup.runs` (`openmettle_backup_runs_total`, `outcome ∈ {succeeded, failed, incomplete, overdue}`).
- Alert rule `OpenMettleBackupFailedOrOverdue` in [`contracts/telemetry/alerts-v1.yaml`](../../contracts/telemetry/alerts-v1.yaml) fires immediately (`for: 0m`, `severity: critical`) on any `failed`, `incomplete`, or `overdue` increase.
- Inspect current gate and latest run status at any time:

  ```sh
  openmettle-admin backup status
  ```

## Failure and explicit maintenance recovery

A capture failure before staging publication (for example `drain_timeout`, `drift_detected`, or destination I/O error) cleans up `.staging.<run_id>`, marks `backup_runs.state = 'failed'`, and **intentionally leaves `maintenance_active = true`** so admission does not reopen blindly after an abnormal condition. Likewise, if a backup host crashes mid-capture, the worker expires its lease to `incomplete` while keeping `maintenance_active = true`.

If a failure or process crash happens *after* PostgreSQL stages publication (`backup_runs.state = 'publishing'`, visible in `openmettle-admin backup status`), the encrypted set stays preserved in `.staging.<run_id>`, `succeeded` is **not** incremented, and the 24h RPO clock is **not** reset. To finish publishing without re-dumping PostgreSQL or artifacts (and without needing `--neo4j-dump` or `--config-file` on disk again), re-run `openmettle-admin backup capture` with the **exact same `--request-key`, `--operator-id`, `--destination-domain`, and `--reason`**. If the destination cannot be recovered and you want to abandon the unpublished run instead, release maintenance with `--abort-active-run` (transitioning the `publishing` run to `incomplete` with `failure_code = 'publication_aborted'`).

1. Inspect the gate and latest run:

   ```sh
   openmettle-admin backup status
   ```

2. Resolve the underlying issue (stuck run, drift, or destination mount failure), or retry a `publishing` run with the exact same `--request-key`.
3. Release maintenance explicitly once safe:

   ```sh
   # Normal release when no active leased or publishing capture run exists:
   openmettle-admin backup release-maintenance \
     --operator-id "$OPERATOR_ID" \
     --request-key "release-2026-11-26-1" \
     --reason "Verified system healthy after backup drain timeout"

   # If a crashed capture process still holds an unexpired lease or stopped in `publishing`
   # (confirm the process exited first):
   openmettle-admin backup release-maintenance \
     --operator-id "$OPERATOR_ID" \
     --request-key "release-abort-2026-11-26-1" \
     --reason "Confirmed crashed backup CLI exited; aborting active run and reopening admission" \
     --abort-active-run
   ```

## Restore handoff (unpacked recovery set to running cluster)

Keep `openmettle-api`, `openmettle-worker`, and `openmettle-gateway` stopped until every step completes.

1. **Unpack and verify the encrypted backup into a fresh `0700` staging directory:**

   ```sh
   openmettle-admin backup unpack \
     --backup-dir /mnt/offhost-backups/openmettle/backup-20261126T020000Z-<RUN_ID> \
     --output-dir /var/restore/openmettle-recovery \
     --backup-keys-config /etc/openmettle/backup-keys/keyring.json
   ```

   This verifies every AEAD tag and digest and writes `pg.dump`, `gateway-entitlements.json`, `deletion-journal.bin`, `artifacts/` (with `revisions/`, `staging/`, and `.openmettle-volume-id` sentinels), `config/` (including `vault-key-inventory.json`), optional `neo4j.dump`, optional `chroma.archive`, and plaintext `manifest.json`.

2. **Restore PostgreSQL 18 into a freshly provisioned `openmettle_owner` database** (with `REVOKE ALL ON SCHEMA public FROM PUBLIC`, `REVOKE ALL ON DATABASE <db> FROM PUBLIC`, and `GRANT CONNECT` to the bounded runtime roles matching [Schema migrations](../../README.md#schema-migrations)). Never pass a password-bearing database URL on the `pg_restore` command line (process arguments are visible via `ps` / `/proc/<pid>/cmdline`); supply credentials through an owner-only `0600` `PGPASSFILE` and explicit password-free connection flags:

   ```sh
   PGPASSFILE=/run/secrets/openmettle-owner.pgpass \
   PGSSLMODE=verify-full \
   PGSSLROOTCERT=/etc/openmettle/pg-ca.pem \
   pg_restore --no-owner --exit-on-error \
     --host="$PGHOST" \
     --port="${PGPORT:-5432}" \
     --username=openmettle_owner \
     --dbname="$PGDATABASE" \
     /var/restore/openmettle-recovery/pg.dump
   openmettle-migrate
   ```

   Running `openmettle-migrate` immediately after `pg_restore` reapplies `openmettle_owner`'s global and `openmettle`-schema `ALTER DEFAULT PRIVILEGES ... REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC` (which `pg_dump --schema=openmettle` omits) and verifies every schema ownership and bounded-role boundary (`src/boundaries.sql`) without modifying data. Because `pg.dump` was captured inside the maintenance window, the restored database boots with `backup_maintenance_gate.maintenance_active = true` (extra defense-in-depth keeping admission closed until step 7).

3. **Select ONE authoritative deletion journal export (`SELECTED_JOURNAL`) and close `restore_reconciliation_gate`:**

   Choose a single verified journal export file (either a newer post-backup `openmettle-admin journal export` file if available, or `/var/restore/openmettle-recovery/deletion-journal.bin` from the unpacked backup) and carry that exact `"$SELECTED_JOURNAL"` through both `restore lock` (this step) and `restore replay` (step 5):

   - **When to pass `--export-complete`:** Pass `--export-complete` on `restore lock` **only** when `"$SELECTED_JOURNAL"`'s `(seq, digest)` matches an independently recorded watermark captured *after* all primary writes, purges, and connection revocations stopped (for example, a clean coordinated maintenance backup with zero post-backup primary writes before loss, or a fresh `openmettle-admin journal export` taken from an intact stopped primary). Do **not** pass `--export-complete` merely because an external export is newer than the backup.
   - **When post-export primary activity may have occurred:** Whenever writes, purges, or external-connection revocations could have happened on the primary *after* `"$SELECTED_JOURNAL"` was exported and *before* primary loss, **omit `--export-complete`** on `restore lock` and run audited `openmettle-admin restore accept-coverage-gap` before `restore replay` (see [Restore the deletion journal](storage-adoption-and-quota-upgrade.md#restore-the-deletion-journal-after-a-database-restore)).

   Extract the watermark headers (`origin`, `lifecycle_origin`, `lifecycle_baseline`, `connection_origin`, and `watermark <origin> <seq> <digest> <ts>`) directly from `"$SELECTED_JOURNAL"` and run `openmettle-admin restore lock` with those exact values.

4. **Copy/mount the restored artifact tree and run `storage rebind`:**

   Copy `/var/restore/openmettle-recovery/artifacts/` into the target `ARTIFACTS_DIR` PVC (preserving permissions) and follow [Restore the artifact volume](restore-artifact-volume.md):

   ```sh
   openmettle-admin storage rebind "$ARTIFACT_ROOT"
   ```

   If a payload is unrecoverable across all backup copies, follow [Declaring an unrecoverable payload lost](restore-artifact-volume.md#declaring-an-unrecoverable-payload-lost).

5. **Replay the same `"$SELECTED_JOURNAL"` and verify zero drift:**

   ```sh
   openmettle-admin restore replay "$SELECTED_JOURNAL" "$ARTIFACT_ROOT"
   openmettle-admin quota verify "$ARTIFACT_ROOT"
   ```

6. **Complete pre-worker security and external-store checks:**
   - Complete the [Database backup restore checklist](../../README.md#database-backup-restore-pre-worker-checklist) (session/provider invalidation, login/cursor key rotation, identity/grant reconciliation, parked `waiting` runs).
   - Verify external-connection vault key coverage against `config/vault-key-inventory.json` using `openmettle-admin vault status` ([Credential vault and key recovery](credential-vault-and-key-recovery.md)).
   - If `neo4j.dump` is present in the unpacked directory, restore Graphiti/Neo4j offline (`neo4j-admin database load`) before starting dependent services.
   - If `chroma.archive` is present in the unpacked directory, restore the Chroma persistent directory from `chroma.archive` before starting dependent services.
   - Rebuild declared rebuildable indexes listed in `manifest.json` (`postgresql_secondary_indexes` via `REINDEX` if needed, `derived_search_and_fulltext_indexes`, and `chroma_vector_embeddings` only when `manifest.json` records `chroma.mode = "qualified_rebuild"`).

7. **Release the restored maintenance gate and start services:**

   ```sh
   openmettle-admin backup release-maintenance \
     --operator-id "$OPERATOR_ID" \
     --request-key "post-restore-release-$(date -u +%Y%m%dT%H%M%SZ)" \
     --reason "Completed restore verification and pre-worker checklist" \
     --abort-active-run
   ```

   Delete `/var/restore/openmettle-recovery` after verification, confirm `openmettle-admin backup status` reports `maintenance_active: false`, and start `openmettle-gateway`, `openmettle-api`, and `openmettle-worker`.
