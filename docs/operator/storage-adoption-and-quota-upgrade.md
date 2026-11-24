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

After adoption, check that `volume_id` is set and `adoption_run_id` is null. Review every quarantined reservation. Each stays charged until verified on the restored tree. Preserve surviving files and anchors when investigating a mismatch. If an adopter crashed, read the recorded adoption UUID, establish that its process exited, and retry with `--replace-adoption-run` and that UUID. Use the same volume and evidence options as the first attempt. An adoption that is refused or fails verification hands the marker back as it found it: after a failed retry the recorded UUID is still set, and the next retry names it again.

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

## Upgrade from 0028 to 0029 (gateway dispatch)

Migration `0029` ([ADR 0044](../adr/0044-own-inference-proxy-and-binding-free-dispatch.md)) needs no activation step and no backfill. It adds the columns `dispatched_at`, `bearer_hash` and `claim_hash` to `gateway_requests`, replaces the unnamed handoff CHECK on that table with `gateway_requests_handoff_check` and adds four functions. Existing rows satisfy the new CHECK.

- Apply it with `openmettle-migrate` before rolling workers. A worker of this release on schema `0028` fails every metered round, because `openmettle.gateway_handoff_round` does not exist yet.
- A worker of the previous release keeps calling `openmettle.gateway_handoff`, which still needs a gateway binding that no deployment can create. Its metered rounds fail as they did before the upgrade.
- **Do not enable metered workers on schema `0029` against the increment 1 gateway proxy.** That proxy looks a request up through its gateway binding, so it cannot route a round handed off without one: it answers `404 not_found` after the handoff committed, and the round's hold then stays until increment 3 reconciles it. Wait for the proxy of increment 2b.
- The migration finds the old CHECK by the columns it constrains and stops if it finds none or several. `openmettle-migrate` then prints `migration 29 failed (SQLSTATE P0001)`. The PostgreSQL server log carries the exception text, `expected one gateway_requests handoff CHECK, found N`. That means the table was altered outside the migrations; inspect its constraints before retrying.

## Upgrade from 0029 to 0030 (quota override actor lock)

Migration `0030` replaces only `openmettle.quota_lock_override`. The signature, security and privileges stay the same. No table, column, grant or row changes, so the upgrade needs no action beyond running `openmettle-migrate`. Afterwards, a quota override and a disable of its acting administrator are ordered by the administrator's user row. The override locks that row after its scope locks, so the order in which the requests started does not decide the outcome:

- If the override locks the row first, the disable waits for the override to commit.
- If the disable locks it first and commits within the override's lock wait limit (2 seconds for the API), the override sees the disabled administrator and is refused with `42501`.
- If that limit expires first, the override fails with a lock timeout (`55P03`) and changes nothing.

## Upgrade from 0030 to 0031 (incomplete usage reports)

Migration `0031` ([ADR 0044](../adr/0044-own-inference-proxy-and-binding-free-dispatch.md), amendment of 24 November 2026) needs no activation step and no backfill. It adds the nullable column `gateway_usage_reports.incomplete` with a CHECK on its closed list of reasons, grants `openmettle_gateway` the insert on it, and replaces `openmettle.quota_gateway_fold` with the same signature, security and privileges. Stored reports keep their counts and get no reason; settled holds are unchanged.

- Apply it with `openmettle-migrate` before rolling the gateway proxy. A proxy of this release on schema `0030` cannot store any report, because its insert names the new column: each request then logs `gateway.usage.failed` and keeps its hold.
- A proxy of the previous release still works on schema `0031`. It writes its reports at revision 0 and writes none for a request without usage, as before.
- From this release the proxy closes a dispatched request that ended without usage: its token hold becomes `settled` with nothing charged, and the report names the reason. [Gateway proxy](gateway-proxy.md#when-there-is-no-usage) lists the reasons and the cases that still keep their hold.
- Adding the CHECK reads `gateway_usage_reports` once under an exclusive lock on that table.

## Upgrade from 0031 to 0032 (unreported request sweep)

Migration `0032` ([ADR 0044](../adr/0044-own-inference-proxy-and-binding-free-dispatch.md), increment 3b) needs no activation step and no backfill. Before installing its guard, it fails closed if any unsettled unbound request already has an accepted revision-0 report or settlement and removes any unaccepted dangling raw revision-0 report on an unbound unsettled request (historical schema 29–30 requests already settled at revision 0 stay intact). It extends `gateway_usage_reports_incomplete_check` with the two sweep-only revision-0 reasons (`not_dispatched` and `unreported`), adds a `BEFORE INSERT OR UPDATE` trigger restricting those two reasons and revision 0 on unbound requests to `openmettle_owner` (keeping revision 0 available on bound ADR 0037 rows), updates `openmettle.enforce_gateway_final_settlement_closes` with the same signature, security and privileges, adds a partial index on unbound outstanding `gateway_requests`, and grants `openmettle_worker` execution on `openmettle.gateway_unreported_candidates` and `openmettle.gateway_close_unreported`.

- Apply migration `0032` with `openmettle-migrate` before rolling workers of this release. A worker of this release running against schema `0031` logs `worker.sweep.failed` (`reconcile_stale_quotas`) on the sweep until `0032` applies, without interrupting run execution.
- Workers and proxies of the previous release (`0031`, writing reports at revision 1) continue working unchanged on schema `0032`.
- Once workers of this release run on schema `0032`, the maintenance loop closes undispatched unbound requests as `not_dispatched` as soon as their run can no longer dispatch them, and closes dispatched unbound requests with no settlement as `unreported` once 15 minutes have passed after their run's execution deadline (releasing token and cost holds at zero charged; a late proxy report at revision 1 supersedes `unreported`).
- Replacing `gateway_usage_reports_incomplete_check` validates against existing `gateway_usage_reports` rows under `ACCESS EXCLUSIVE`, and `CREATE INDEX gateway_requests_unbound_outstanding_idx` takes `SHARE` on `gateway_requests`, blocking writes to those tables until the migration transaction commits; lock duration scales with table size.

## Monitor overdue handoffs

The worker records up to 100 overdue committed handoffs per maintenance sweep in `openmettle_quota_overdue_handoffs_total`. The counter measures observations across sweeps. An outstanding handoff can contribute more than once. Use the database ledger to identify the holds. The observation leaves quota charges intact.

## Verify accounting

Run `openmettle-admin quota verify "$ARTIFACT_ROOT"` after restore to check the pinned volume and ledgers. This filesystem check is the required post-restore check. A volume restored by file copy must first be rebound, following [Restore the artifact volume](restore-artifact-volume.md); until then the check fails. Omit the root on a storage-disabled deployment. A failed verification exits with a nonzero status. For a database-only investigation, run the read below as the owner or worker. It compares no file, so it reports a copied volume as healthy and does not replace the filesystem check. The storage, budget and settlement mismatch counts must be zero. Pending gateway reconciliations and their oldest age identify accepted evidence awaiting application. Investigate mismatches against the same backup and volume before resuming writers.

```sql
SELECT * FROM openmettle.quota_verify_accounting_drift();
SELECT count(*) AS quarantined
FROM openmettle.storage_reservations WHERE adoption_unverified;
```

The local adoption probe exercises hard links, file locking and directory syncs on its own mount. Qualify lock exclusion and file visibility between every API and worker host on shared storage. A successful probe on a single host establishes only that host's behavior.
