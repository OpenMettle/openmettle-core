# Upgrade storage and activate metering

Sections 1 through 4 cover upgrading an existing database from migration 0023 or earlier to the current quota schema (0026). Deployments already on migration 0024 or 0025 should follow [Upgrade from 0024 or 0025 to 0026](#upgrade-from-0024-or-0025-to-0026) instead. This procedure applies even if the deployment has never accepted an upload or gateway request. Schedule a maintenance window and retain a matched database backup and artifact volume snapshot. Record the filesystem UUID and the device and inode of the original revisions directory independently of the tree you intend to adopt.

## 1. Stop all legacy artifact cleaners

Before running the migration, scale the old worker deployment to zero, or restart every old worker with artifact storage disabled. Check both the worker-specific environment and any inherited artifact directory setting. Confirm that every previous worker process and its in-flight maintenance sweep have exited. A legacy cleaner can unlink a file before its database transaction encounters a guard.

## 2. Apply the migration

Run the new `openmettle-migrate` job with its existing owner connection. In the migrated database, inspect the singleton markers.

```sql
SELECT volume_id, adoption_run_id, bootstrap_auto_pin_allowed,
       metering_enforced, metering_enforced_at,
       overrides_enforced, overrides_enforced_at
FROM openmettle.storage_volume_control CROSS JOIN openmettle.quota_enforcement;
```

Both IDs and both enforcement timestamps must be null and all three flags false on an upgrade from 0023 or earlier. A new installation starts with metering and overrides enabled and permits the API to pin an empty store. Configure operator-approved limits before serving metered requests. The actor's personal token ceiling applies to project requests too. Set the deployment cost denomination by updating the existing instance cost default. The denomination becomes permanent.

## 3. Replace every API and worker

Roll the API and worker processes to the new binaries. Confirm the deployed image digests and completion of previous jobs and terminating replicas. Keep the volume unpinned throughout replacement. Drain any gateway settlement writer that does not lock the request before writing its settlement. After pinning, exclude legacy worker binaries from restart and rollback.

## 4. Adopt the volume, sweep orphans and activate

Run the admin image with the original artifact tree mounted, readable and writable using the service filesystem identity. Supply `OPENMETTLE_ADMIN_DATABASE_URL` through the deployment secret mechanism, using the `openmettle_owner` database login. The command uses the absolute artifact root containing both `staging` and `revisions`.

```sh
openmettle-admin storage adopt "$ARTIFACT_ROOT"
```

For a nonempty ledger with no digest-verifiable payload, supply independent device evidence from the original volume. On Linux the filesystem UUID must identify the mounted block device through `/dev/disk/by-uuid`. The expected revisions directory identity uses decimal device and inode numbers. If the tree contains no payloads, also confirm that absence explicitly after checking the backup.

```sh
openmettle-admin storage adopt "$ARTIFACT_ROOT" \
  --expected-fs-uuid "$EXPECTED_FS_UUID" \
  --expected-revisions-inode "$EXPECTED_DEVICE:$EXPECTED_INODE" \
  --confirm-no-on-disk-payloads
```

For a storage-disabled deployment, skip adoption only when all API and worker artifact settings are unset and both tables below are empty. If storage is provisioned later, adopt its volume before enabling workers.

```sql
SELECT (SELECT count(*) FROM openmettle.storage_reservations) AS reservations,
       (SELECT count(*) FROM openmettle.artifact_revisions) AS revisions;
```

After adoption, check that `volume_id` is set and `adoption_run_id` is null. Review every quarantined reservation. Each stays charged until verified on the restored tree. Preserve surviving files and anchors when investigating a mismatch. If an adopter crashed, read the recorded adoption UUID, establish that its process exited, and retry with `--replace-adoption-run` and that UUID. Use the same volume and evidence options as the first attempt.

Drain legacy request producers and allow 15 minutes for recent reserved requests to age. Run the orphan sweep. It processes one fixed upper bound in bounded transactions. Repeat after outstanding leases or locked rows clear. Activate metering in a separate invocation.

```sh
openmettle-admin quota drain-orphans
openmettle-admin quota activate
```

Verify `metering_enforced` and `overrides_enforced` are both true and both `metering_enforced_at` and `overrides_enforced_at` are set. Activation is irreversible. A committed gateway handoff retains its hold until accepted gateway usage settles it. A committed device slot stays charged until V1-18 provides durable evidence of release or non-allocation.

## Upgrade from 0024 or 0025 to 0026

Existing `0024` or `0025` deployments, including installations that already have `metering_enforced = true`, enter schema `0026` with `overrides_enforced = false` and `overrides_enforced_at = NULL`. Until activation completes, `ManageQuotas` scope override writes fail closed with `503 provisioning` while older replicas drain.

1. Apply migration `0026` with `openmettle-migrate` using its existing owner connection.
2. Roll all API and worker deployments to the `0026` binaries and confirm that every `0024`/`0025` API and worker replica and job has exited.
3. Inspect the current adoption and enforcement markers:

```sql
SELECT volume_id, adoption_run_id,
       metering_enforced, metering_enforced_at,
       overrides_enforced, overrides_enforced_at
FROM openmettle.storage_volume_control CROSS JOIN openmettle.quota_enforcement;
```

4. Activate according to the observed `metering_enforced` state:
   - **If `metering_enforced = true`:** rerun `openmettle-admin quota activate`. The command is idempotent, preserves the original `metering_enforced_at` timestamp, and sets `overrides_enforced = true` and `overrides_enforced_at`.
   - **If `metering_enforced = false`:** do **not** run `openmettle-admin quota activate` yet. First configure operator-approved quota limits and the permanent instance `cost_denomination` (Section 2), then complete volume adoption (if storage is enabled or nonempty) and `openmettle-admin quota drain-orphans` (Section 4), and finally run `openmettle-admin quota activate` to enable both `metering_enforced` and `overrides_enforced`.
5. Verify in SQL that all four enforcement columns are active and non-null:

```sql
SELECT metering_enforced, metering_enforced_at, overrides_enforced, overrides_enforced_at
FROM openmettle.quota_enforcement;
```

## Monitor overdue handoffs

The worker records up to 100 overdue committed handoffs per maintenance sweep in `openmettle_quota_overdue_handoffs_total`. The counter measures observations across sweeps. An outstanding handoff can contribute more than once. Use the database ledger to identify the holds. The observation leaves quota charges intact.

## Verify accounting

Run `openmettle-admin quota verify "$ARTIFACT_ROOT"` after restore to check the pinned volume and ledgers. Omit the root on a storage-disabled deployment. A failed verification exits with a nonzero status. For a database-only investigation, run this read as the owner or worker. The storage, budget and settlement mismatch counts must be zero. Pending gateway reconciliations and their oldest age identify accepted evidence awaiting application. Investigate mismatches against the same backup and volume before resuming writers.

```sql
SELECT * FROM openmettle.quota_verify_accounting_drift();
SELECT count(*) AS quarantined
FROM openmettle.storage_reservations WHERE adoption_unverified;
```

The local adoption probe exercises hard links, file locking and directory syncs on its own mount. Qualify lock exclusion and file visibility between every API and worker host on shared storage. A successful probe on a single host establishes only that host's behavior.
