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

Both IDs and both enforcement timestamps must be null and all three flags false on an upgrade from 0023 or earlier. A new installation starts with metering and overrides enabled and permits the API to pin an empty store. Configure operator-approved limits before serving metered requests. The actor's personal token ceiling applies to project requests too. Set the deployment cost denomination by updating the existing instance cost default. The denomination becomes permanent. Before setting any non-null `usage_cost_micros` default (`quota_defaults`) or scope override (`quota_overrides`), configure and deployment-qualify `cost_bound` (`fixed_micros` and `micros_per_token`, expressed in the permanent `cost_denomination` micro-units) on every catalog model profile that will serve cost-metered runs and roll API and worker processes onto that catalog revision; profiles without `cost_bound` fail closed with `503 provisioning` (`quota.resource_kind = "usage_cost_micros"`) once cost limits are active.

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
   - **If `metering_enforced = true`:** if any `usage_cost_micros` default or override is active (or before adding one), confirm that every catalog model profile serving cost-metered runs carries a deployment-qualified `cost_bound` (`fixed_micros` and `micros_per_token` in the permanent `cost_denomination` micro-units) and that all API and worker processes are rolled onto that catalog revision; profiles without `cost_bound` fail closed with `503 provisioning` (`quota.resource_kind = "usage_cost_micros"`). Then rerun `openmettle-admin quota activate`. The command is idempotent, preserves the original `metering_enforced_at` timestamp, and sets `overrides_enforced = true` and `overrides_enforced_at`.
   - **If `metering_enforced = false`:** do **not** run `openmettle-admin quota activate` yet. First configure operator-approved quota limits and the permanent instance `cost_denomination` (Section 2), configure and deployment-qualify `cost_bound` (`fixed_micros` and `micros_per_token`) on every catalog model profile serving cost-metered runs and roll API and worker processes onto that catalog revision before setting any non-null `usage_cost_micros` default or override (profiles without `cost_bound` fail closed with `503 provisioning` and `quota.resource_kind = "usage_cost_micros"`), complete volume adoption (if storage is enabled or nonempty) and `openmettle-admin quota drain-orphans` (Section 4), and finally run `openmettle-admin quota activate` to enable both `metering_enforced` and `overrides_enforced`.
5. Verify in SQL that all four enforcement columns are active and non-null:

```sql
SELECT metering_enforced, metering_enforced_at, overrides_enforced, overrides_enforced_at
FROM openmettle.quota_enforcement;
```

## Upgrade from 0027 to 0028 (retention)

Migration `0028` ([ADR 0041](../adr/0041-retention-purge-and-deletion-journal.md)) needs no activation step. Apply it with `openmettle-migrate` and roll the API and worker deployments. Purges are deferred while a revision is still referenced (an attachment, an operator hold, or a run that wrote it and has not finished). Each confirmed purge is recorded in `openmettle.deletion_journal`.

- The database sets every removal's deadline from `openmettle.retention_policy`. That includes removals by a `0027` API during the rollout, whose own grace is ignored.
- A `0027` worker's purge claim on a referenced revision fails with SQLSTATE `OMR01`. Expect `worker.sweep.failed` for `purge_due` until the old workers exit.
- A claim the old worker already committed (the revision is `purging`) is completed even if the revision is attached. Schema `0027` checked no references, the claim was valid when it was made, and its payload may already be truncated, so returning it to `retained` would offer damaged bytes for restore. Schema `0028` lets no `purging` revision gain an attachment or hold, so only these older claims (and owner break-glass claims) complete while referenced. Before upgrading, list the affected claims with:

```sql
SELECT r.id FROM openmettle.artifact_revisions r
 WHERE r.state = 'purging'
   AND EXISTS (SELECT FROM openmettle.message_parts p
                WHERE p.scope_id = r.scope_id AND p.artifact_revision_id = r.id);
```

At any time afterwards, this lists every journaled purge whose revision is still attached. Each one is either a claim made before the upgrade completed or an operator-forced (break-glass) purge. Schema `0028` never claims an attached revision otherwise.

```sql
SELECT j.journal_seq, j.entity_id
  FROM openmettle.deletion_journal j
 WHERE EXISTS (SELECT FROM openmettle.message_parts p
                WHERE p.scope_id = j.scope_id AND p.artifact_revision_id = j.entity_id);
```

## Upgrade from 0028 to 0029 (restore gate)

Migration `0029` adds `openmettle.restore_reconciliation_gate` and needs no activation step. Apply it with `openmettle-migrate` and roll the API and worker deployments. The gate starts open, because a live database is not a restore, and the deletion journal is unchanged: purges after the upgrade continue the same hash chain.

- Previous-release workers purge as before while the gate is open. Once an operator closes it (only during a restore), their purge claims and confirmations fail with SQLSTATE `OMR02`, logged as `worker.sweep.failed` for `purge_due`, but they still claim runs. Never start a `0028` worker against a restored database.
- No previous-release API or admin binary reads or changes the gate.

## Restore the deletion journal after a database restore

A database cannot tell that it was restored, and a backup carries the gate as it was when the backup was taken, normally open. The restore procedure therefore closes it before any API or worker starts. While it is closed, no application role can move a revision into `purging` or `purged` (`OMR02`), so nothing appends to the restored journal, and `openmettle-worker` claims no run and runs no purge sweep. The API does not read the gate in this release (V1-16 PR3 adds `503 unavailable`), so keep it stopped until the gate opens.

**Export.** Run the export with every backup, as the owner, and keep the file outside the primary storage failure domain for the full backup retention. The command refuses to overwrite an existing file and prints the export's watermark, `watermark <journal_seq> <chain_digest> <exported_at Unix microseconds>`. Record that line separately from the export file, for example with the recovery set. The export carries a SHA-256 checksum that detects damage, not forgery: it is not signed.

```sh
openmettle-admin journal export "$EXPORT_FILE"
```

**Restore.** With the API and worker stopped and PostgreSQL and the artifact volume restored to the same recovery point:

1. Restore database-level privileges if the restore method does not: migration 1 revokes `PUBLIC` access to the database and grants `CONNECT` to the application roles, and the migrator refuses a database where `PUBLIC` keeps it. Run `openmettle-migrate` if the backup predates the release. A backup from before `0029` gets an open gate from the migration, like any other.
2. Close the gate, naming the newest watermark sequence recorded independently of the export you will replay. The gate records the restored journal head as its snapshot and requires the larger of the two. Closing a closed gate keeps its snapshot and only raises the requirement.

   ```sh
   openmettle-admin restore lock --required-seq "$WATERMARK_SEQ"
   ```

3. Replay the newest export. Pass the artifact root; it may be omitted only when no volume is pinned.

   ```sh
   openmettle-admin restore replay "$EXPORT_FILE" "$ARTIFACT_ROOT"
   ```

Replay first applies every record in one transaction, or none. A record already in the restored journal must match it exactly; each later record must extend its hash chain and is stored verbatim. A revision the restored database still holds unpurged moves to `purging` under the journal's original deadline, never a new grace window. Restored revisions that the journal does not name keep their stored deadlines. Replay then deletes the resurrected payloads through the volume-pinned purge, releasing each revision's bytes once, runs the accounting verification, and opens the gate only if the restored journal ends at the export's watermark, reaches the required sequence and names no unpurged revision. Any failure leaves the gate closed. Rerunning after a fix resumes where the previous attempt stopped.

| Failure | Meaning |
| --- | --- |
| `invalid export: …` | The file is damaged or truncated, or its records are out of order or have a gap. Use an intact copy. |
| `OMR02` | The gate is not closed. |
| `OMR03` | A record differs from the restored journal, does not extend its chain, or names a revision with other content: a wrong, altered or forged export, or a backup from another deployment. |
| `OMR04` | The export ends before the restored journal (it is older than the backup) or before the required sequence. Find a newer export; records never exported cannot be reconstructed. |
| `OMR05` | A replayed revision is still unpurged, for example because its payload binding is unverified or quarantined. Repair it and rerun. |
| `accounting drift detected` | Run `openmettle-admin quota verify "$ARTIFACT_ROOT"` and repair before rerunning. |

Then continue with the README's database restore checklist and start the worker. This release journals confirmed purges only. A removal made after the backup but not yet purged is not journaled, so its revision is active again after the restore; no route performs removals until V1-16 PR3, which must journal them. Revocations and tombstones are not journaled yet either.

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
