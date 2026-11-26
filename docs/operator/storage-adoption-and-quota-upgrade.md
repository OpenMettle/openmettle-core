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
- Migration `0032` acquires `EXCLUSIVE` on `gateway_requests`, `ACCESS EXCLUSIVE` on `gateway_usage_reports` (validating `gateway_usage_reports_incomplete_check` against existing rows), and `SHARE` on `gateway_settlements` before its upgrade preflight and partial index build, blocking writes and row-locking reads on `gateway_requests` until the migration transaction commits; lock duration scales with table size.

## Upgrade from 0032 to 0033 (message turn stop reason)

Migration `0033` ([ADR 0036](../adr/0036-conversation-branches-presets-and-effective-model-config.md), [ADR 0038](../adr/0038-sglang-and-external-provider-conformance-adapter.md), [ADR 0044](../adr/0044-own-inference-proxy-and-binding-free-dispatch.md) increment 3c) needs no activation step and no backfill. It adds the nullable `stop_reason text` column to `openmettle.message_turns` with `message_turns_stop_reason_check` (`stop_reason IS NULL OR (author_user_id IS NULL AND stop_reason IN ('limit'))`), grants `SELECT (stop_reason)` to `openmettle_api`, and grants `INSERT (stop_reason)` to `openmettle_worker`.

- Apply migration `0033` with `openmettle-migrate` before rolling API and worker binaries of this release so token-limit stops can persist and expose `stop_reason = 'limit'`. On a pre-`0033` database, history reads return `stop_reason: null`, normal turns publish normally, and token-limit turns fail closed rather than silently dropping `stop_reason`.
- API and worker binaries of the previous release (`0032`) continue working unchanged on schema `0033`: pre-existing and older-writer rows leave `stop_reason` null.
- Adding the CHECK validates `openmettle.message_turns` once under `ACCESS EXCLUSIVE` without rewriting the table.

## Upgrade from 0033 to 0034 (gateway request cost settlement)

Migration `0034` ([ADR 0044](../adr/0044-own-inference-proxy-and-binding-free-dispatch.md), issue `#166`) needs no activation step and no backfill. Admission (`openmettle-api`) pins each profile's optional `cost_bound` (`fixed_micros`, `micros_per_token`) into `openmettle.runs.config_snapshot`, and `openmettle.gateway_handoff_round` validates both coefficients individually against that snapshot when recording them on `openmettle.gateway_requests`. PostgreSQL then derives `usage_cost_micros` settlement inside `openmettle.quota_gateway_fold` from reported token counts and those recorded prices, forbids caller-supplied `cost`/`unit` on unbound usage reports (`gateway_usage_reports_bound_cost_guard` and commit-time settlement enforcement), blocks direct measured settlement on undispatched unbound requests, and removes migration `0031`'s open-cost-hold carve-out from `openmettle.enforce_gateway_final_settlement_closes`.

- **Upgrade preflight and lock acquisition:** Inside an autocommit-safe `DO` block acquiring `ACCESS EXCLUSIVE` on `gateway_requests`, `gateway_usage_reports` and `gateway_settlements` and `SHARE` on `quota_reservations` via a bounded `NOWAIT` retry loop (respecting `lock_timeout` and avoiding lock-order deadlocks with concurrent schema-`0033` report writers), migration `0034` fails closed (`SQLSTATE 23514`) if any unbound request (`binding_id IS NULL`) still has an unsettled `usage_cost_micros` hold (`state IN ('held', 'handoff_committed')`), removes any unaccepted historical raw unbound usage reports carrying `cost`/`unit`, preserves already-settled and released historical rows intact, and leaves bound ADR 0037 rows unaffected.
- **Rollout order:** Apply migration `0034` with `openmettle-migrate` before rolling API and worker binaries of this release onto cost-metered deployments (roll `openmettle-api` before enabling new cost-metered runs so `runs.config_snapshot` pins `cost_bound`). A worker of this release on schema `0033` fails closed when handing off a round with a bound `usage_cost_micros` hold while continuing to serve token-only rounds; an older (`0033`) worker calling the 4-arg `gateway_handoff_round` on schema `0034` continues serving pre-`0034` token-only rounds and fails closed on cost-metered or snapshot-pinned rounds until rolled to `0034`.
- **Reconciling a late report after a schema-`0033` `unreported` sweep:** If a dispatched cost-held unbound request was swept as `unreported` at revision `0` on schema `0033` (so `cost_fixed_micros` is `NULL` and its cost hold settled at `0`), any count-bearing report already accepted on schema `0033` upgrades with zero drift, while any new count-bearing report arriving on schema `0034` fails closed (`Error::Refused`) rather than silently settling the cost hold at `0` micros. An administrator running as `openmettle_owner` can backfill the request's immutable profile pricing from the catalog revision that admitted the run (verified against the hold's exact `reserved_units`, and reconciling any already-accepted token-only usage immediately) before re-ingesting new corrections:

```sql
SELECT openmettle.gateway_backfill_legacy_request_cost_bound(
    '<request_id>'::uuid,
    <fixed_micros>,
    <micros_per_token>
);
```

- **Proxy configuration:** `openmettle-gateway` requires no catalog file or new environment variable; it continues reporting token counts with `cost = NULL, unit = NULL`, and PostgreSQL settles both `usage_tokens` and `usage_cost_micros` holds atomically.

## Upgrade from 0034 to 0035 (family policy tables and enforcement)

Migration `0035` ([ADR 0044](../adr/0044-own-inference-proxy-and-binding-free-dispatch.md), increment 4) needs no activation step and no backfill. It creates `openmettle.family_policies` and `openmettle.family_policy_models` (`openmettle_api` `SELECT` and column-scoped `INSERT`/`UPDATE` only; no `DELETE` for any runtime role; no table privileges for `openmettle_worker`, `openmettle_gateway` or `openmettle_issuance`), widens `openmettle.authorization_audit` CHECK constraints under a bounded `NOWAIT` lock retry loop, installs the authoritative SQL evaluators `openmettle.family_policy_filter_models` (`openmettle_api`) and `openmettle.family_policy_permits` (`openmettle_api` and `openmettle_worker`), and enforces them inside `openmettle.gateway_round_authority`, `openmettle.gateway_handoff_round` and `openmettle.gateway_dispatch`.

- **Rollout order:** Apply migration `0035` with `openmettle-migrate` before configuring family policies or rolling API and worker binaries of this release. While no active rows exist in `openmettle.family_policies`, `family_policy_permits` returns `true` for all requests so older and newer binaries operate identically. Once family policies are configured, all API and worker replicas should be on `0035` so admission/preview (`403 policy`, study-hours default fallback) and worker recheck (`cancel_reason = 'revoked'`) enforce the same schedule as PostgreSQL handoff and proxy dispatch.
- **Operator CLI (`openmettle-admin family`):** Operators manage household/group/user schedules and model rules using `OPENMETTLE_ADMIN_DATABASE_URL` (`openmettle_owner`), recording append-only `'operator'` rows in `openmettle.authorization_audit`:

```sh
openmettle-admin family set-policy --oidc-group Family --zone Europe/London \
  --quiet 22:00-07:00 --study 16:00-18:00 \
  --operator-id "$OPERATOR_UUID" --request-key "$KEY" --reason "household schedule"
openmettle-admin family set-model --oidc-group Family --kind study_allow --model fast --enable \
  --operator-id "$OPERATOR_UUID" --request-key "$KEY2" --reason "allow fast model during study hours"
openmettle-admin family clear-policy --oidc-group Family \
  --operator-id "$OPERATOR_UUID" --request-key "$KEY3" --reason "pause household schedule"
```

In `set-model`, `--enable` activates the specified rule (`active = true`: `family_policy.model_study_allow` for `--kind study_allow`, `family_policy.model_disable` for `--kind disabled`) and `--disable` deactivates it (`active = false`: `family_policy.model_study_revoke` or `family_policy.model_enable`).

## Upgrade from 0037 to 0038 (administrative write serialization)

Migration `0038` ([ADR 0027](../adr/0027-authorization-and-private-projects.md), issue `#160`) needs no activation step and no backfill:

- Replaces `openmettle.quota_lock_override(uuid, uuid, text)` with the same signature, invoker security, `search_path` and privileges, keeping a fast pre-target administrator check under `account_admin_lock` so non-admins never wait on contended scope locks, locking personal-scope owner and actor in ascending `users.id` order, re-checking administrator status under the actor's `users` lock, and placing `run_dispatch_lock` after the actor lock so SQL and Rust follow one canonical lock order (`account_admin_lock -> projects -> login_providers -> local_identity_approvals -> users (ascending id) -> storage_volume_control -> run_dispatch_lock -> storage_accounts | quota_budgets`). Previous-release API binaries calling `quota_upsert_scope_override` and `quota_revoke_scope_override` continue working unchanged.
- Replaces the unexposed 4-argument `openmettle.retention_set_grace(uuid, integer, text, text)` (no route or runtime caller existed in any prior release) with the 5-argument approval-bound `openmettle.retention_set_grace(p_actor uuid, p_approval uuid, p_grace_seconds integer, p_reason text, p_request_key text)` (`SECURITY DEFINER`, `openmettle_api` only), serializing under `account_admin_lock -> login_providers -> local_identity_approvals -> users -> retention_policy` and verifying full live authority at `clock_timestamp()` both before target locking and after the final `authorization_audit` insert.

## Upgrade from 0038 to 0039 (MCP runtime feature gate and terminal write-intent resolution)

Migration `0039` ([ADR 0039](../adr/0039-scoped-mcp-adapter-and-bounded-tool-results.md), V1-14 PR3) adds the 1-row rollout gate table `openmettle.runtime_feature_gates` (`two_phase_effect_intents_enabled`, `SELECT` only for `openmettle_api` and `openmettle_worker`) and the owner-owned `SECURITY DEFINER` trigger `openmettle.resolve_terminal_write_intents()` on `openmettle.runs`:

- **Populated upgrade default (`false`):** On an upgrade from schema `0038` or earlier, `two_phase_effect_intents_enabled` starts `false`. While `false`, pre-existing ADR 0035 external approval writes keep `dispatched_attempts = NULL` (`N-1`-compatible single-phase behavior) and scoped MCP tool execution stays fail-closed so no previous-release (`N-1`) worker or `settle_expired` sweeper ever observes a `dispatched_attempts = 0` write row. Fresh databases migrated from version `0` start with `two_phase_effect_intents_enabled = true`.
- **Rollout order:**
  1. Apply migration `0039` with `openmettle-migrate` using its existing owner connection.
  2. Roll every `openmettle-worker` (and `openmettle-api`) deployment to the `0039` release binaries and confirm that every previous-release (`0038` or earlier) worker replica and maintenance sweeper has exited.
  3. Enable two-phase write intents as `openmettle_owner` using the idempotent admin command:

```sh
openmettle-admin runtime activate-two-phase-intents
```

  4. Verify `two_phase_effect_intents_enabled = true`:

```sql
SELECT two_phase_effect_intents_enabled FROM openmettle.runtime_feature_gates WHERE id;
```

- **Terminal write-intent invariant:** `openmettle.resolve_terminal_write_intents()` rejects any transition to `runs.state = 'succeeded'` while any write operation (`idempotent`, `lookup`, `non_repeatable`) remains in `outcome IN ('intent', 'outcome_unknown')` (including `dispatched_attempts = 0`), and on `failed`, `cancelled`, or `interrupted` transitions any remaining revision-zero write `intent` to `outcome = 'outcome_unknown', revision = 1` with its ADR 0004 observation event strictly before `run-terminal`.

## Upgrade from 0040 to 0041 (restore reconciliation gate)

Migration `0041` ([ADR 0041](../adr/0041-retention-purge-and-deletion-journal.md), V1-16 PR2b) needs no activation step. Apply it with `openmettle-migrate` and roll the API, worker and admin deployments.

- `openmettle.deletion_journal_head.coverage_started_at` is backfilled from migration `28`'s `installed_on` timestamp in `openmettle._sqlx_migrations`, identifying when deletion-journal coverage started on this installation.
- `openmettle.restore_reconciliation_gate` starts open (`open = true`, `coverage_complete = true`), because a live database is not a restore, and the deletion journal continues the same hash chain unchanged.
- `openmettle.retention_policy_bump_revision()` is replaced so ordinary grace edits keep incrementing by 1 while restore replay can advance `revision` past any replayed `policy_revision`.
- `openmettle.authorization_audit` widens its `action` and `target_kind` CHECK constraints under a bounded `NOWAIT` lock retry loop to record `'restore.accept_coverage_gap'` against `'restore_gate'`.
- Previous-release (`0040`) workers purge as before while the gate is open. Once an operator closes the gate during a restore, their purge claims and confirmations fail with SQLSTATE `OMR02`, logged as `worker.sweep.failed` for `purge_due`, but they still claim runs. Never start a `0040` or earlier worker against a restored database.

## Restore the deletion journal after a database restore

A database cannot detect that it was restored, and a backup carries `openmettle.restore_reconciliation_gate` open. The restore procedure therefore closes the gate before any API or worker starts. While it is closed, no application role can move a revision into `purging` or `purged` (`OMR02`), so nothing appends to the restored journal, and `openmettle-worker` claims no run and runs no purge sweep. The API does not read the gate in this release (V1-16 PR3 adds `503 unavailable`), so keep the API stopped until the gate opens.

**Export.** Run the export continuously and after quiescing writes before planned restores, as `openmettle_owner`, keeping each export file outside the primary storage failure domain for the full backup retention horizon. The command creates the file exclusively with `0600` permissions (on Unix), refuses to overwrite an existing file, `fsync`s both the file and its parent directory, and only then prints the watermark line `watermark <origin_us> <journal_seq> <chain_digest> <exported_at_unix_us>`. Record `<origin_us>`, `<journal_seq>` and `<chain_digest>` independently of the export file (for example in the recovery set manifest). The export carries a SHA-256 checksum that detects damage, not forgery; signing belongs to V1-30.

```sh
openmettle-admin journal export "$EXPORT_FILE"
```

**Restore.** With the API and worker stopped and PostgreSQL and the artifact volume restored to the same recovery point:

1. Restore database-level privileges if the restore method does not (`REVOKE ALL ON DATABASE ... FROM PUBLIC` and `GRANT CONNECT` to the application roles). Run `openmettle-migrate` if the backup predates schema `0041`. A backup taken at schema `0028` through `0040` preserves migration `28`'s `installed_on` timestamp and migrates cleanly; a backup taken at schema `0027` or earlier predates the deletion journal and gets a newer `coverage_started_at`, failing closed with `OMR04` as soon as `restore lock` compares `--required-origin`.
2. Close the restore gate, naming the newest independently recorded installation origin (`<origin_us>`), watermark sequence and 64-character lowercase hex digest. Pass `--export-complete` **only** when the export was taken after primary writes were quiesced so no unexported purge window exists (passing `--export-complete` for a watermark sequence below the restored head or an already-higher locked `required_journal_seq` fails closed with `OMR04`). After catastrophic primary loss without a post-quiesce export, omit `--export-complete` (`coverage_complete = false`). The command prints the minted `restore_run` UUID.

   ```sh
   openmettle-admin restore lock \
     --required-origin "$WATERMARK_ORIGIN_US" \
     --required-seq "$WATERMARK_SEQ" \
     --required-digest "$WATERMARK_DIGEST" \
     --export-complete
   ```

   If the gate is already closed (either to update the same in-progress restore with a newer watermark, or because the backup itself was captured while an earlier restore gate was closed), read the current run ID with `SELECT restore_run_id FROM openmettle.restore_reconciliation_gate;` and pass `--replace-restore-run "$RESTORE_RUN_ID"`. To start a fresh restore over a backup captured with a closed gate (so it never inherits `coverage_complete = true` or stale checkpoints), pass **both** `--replace-restore-run "$RESTORE_RUN_ID"` and `--new-restore`. Updating the same restore without `--new-restore` preserves `snapshot_journal_seq`, never lowers `required_journal_seq`, and retains every previously pinned `(seq, digest)` checkpoint for verification on replay.
3. If the artifact volume was restored by file copy (`cp -a`, `tar`, `restic` or similar), run [`openmettle-admin storage rebind`](restore-artifact-volume.md) before `restore replay`:

   ```sh
   openmettle-admin storage rebind "$ARTIFACT_ROOT"
   ```

   Skipping `storage rebind` on a copied volume causes `restore replay` to fail closed with `run \`openmettle-admin storage rebind\` first`.
4. If the gate was locked without `--export-complete` (catastrophic primary loss leaving a possible unexported purge window after the last surviving export), inspect the gap against operator records. Only after explicit operator sign-off, record the audited break-glass acceptance bound to the active `--restore-run` UUID:

   ```sh
   openmettle-admin restore accept-coverage-gap \
     --restore-run "$RESTORE_RUN_ID" \
     --operator-id "$OPERATOR_UUID" \
     --request-key "$REQUEST_KEY" \
     --reason "$REASON"
   ```

   This writes an `'operator'` row (`action = 'restore.accept_coverage_gap'`, `target_kind = 'restore_gate'`) to `openmettle.authorization_audit` and sets `coverage_complete = true`. Replaying the exact same arguments with the same `--request-key` is idempotent (`replayed restore.accept_coverage_gap`); changing parameters on a reused `--request-key` fails with SQLSTATE `23505`.
5. Replay the matching export. Pass the artifact root; omit it only on a storage-disabled deployment where no volume is pinned.

   ```sh
   openmettle-admin restore replay "$EXPORT_FILE" "$ARTIFACT_ROOT"
   ```

   Replay first verifies the export's installation `origin`, `required_journal_seq` and `required_chain_digest`, replays every record, and verifies all pinned checkpoints in one `READ COMMITTED` transaction, rolling everything back on any mismatch. Records at or below the restored head must match verbatim; later records must extend the hash chain, strip resurrected mutable rows in `openmettle.artifact_retention_holds`, advance `openmettle.retention_policy.revision` strictly past each replayed `policy_revision`, and move still-unpurged revisions to `purging` under their original `purge_after` deadline (never a new grace window). Replay then claims the exclusive restore volume-phase lease, deletes resurrected payloads on the volume-pinned path (refusing foreign hard links before truncation), scrubs every `state = 'reserved'` unsettled upload (`reclaim_state IN ('none', 'claiming', 'truncated')`, syncing every file and both artifact directories while holding `storage_volume_control FOR SHARE` and refusing foreign hard links and any remaining unsettled bytes on quarantined or unbound rows), runs `verify_accounting_drift` requiring zero mismatches and zero unsettled payloads, and opens the gate only when `coverage_complete = true` and every journaled revision is `purged`. Rerunning after a fix resumes safely.
6. Run `openmettle-admin quota verify "$ARTIFACT_ROOT"` and complete the remaining steps of the [database backup restore checklist](../../README.md#database-backup-restore-pre-worker-checklist) before starting `openmettle-api` and `openmettle-worker`.

| Failure | Meaning |
| --- | --- |
| `invalid export: ...` | The file is damaged, truncated, missing `origin`/`watermark`, carries mismatched origin or malformed hex/UUIDs, or has out-of-order/gapped records. Use an intact copy. |
| `OMR02` | The gate state or `restore_run_id` does not match (lock it first before replay/break-glass, pass `--replace-restore-run` to update/replace a closed gate, or wait for an active volume-phase lease to finish). |
| `OMR03` | The locked watermark digest, a pinned checkpoint, a record, the chain digest, or a revision's content digest disagrees with the restored database or export (wrong, altered, forked or cross-installation export). |
| `OMR04` | The installation `origin` disagrees (backup predates migration `28` or belongs to another installation), the export sequence does not match the locked `required_journal_seq` (raise the lock requirement first with `--replace-restore-run` if a newer valid export was found), or `coverage_complete` is `false` (investigate and run `restore accept-coverage-gap` if authorized). |
| `OMR05` | A journaled revision is still unpurged (for example quarantined or missing payload binding). Repair and rerun. |
| `OMQ03` | An adoption or rebind barrier (`adoption_run_id`) is still held on `storage_volume_control`. Complete `storage rebind` or `storage adopt` first. |
| `run \`openmettle-admin storage rebind\` first` | The artifact volume was restored by file copy and has not been rebound yet. |
| `accounting drift detected` | Unsettled payloads, quarantines or volume/ledger drift remain. Run `openmettle-admin quota verify "$ARTIFACT_ROOT"` and repair before rerunning. |

This release journals confirmed purges only. Removals not yet purged (PR3) and revocations/tombstones are not journaled yet and still follow the README's pre-worker restore checklist.

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
