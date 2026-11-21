# 0040 — Transactional quotas and reservation reconciliation

Proposed for V1-17 PR1, 21 November 2026. Refs #17. The base is schema 22 at
`45df33c60e7a84fe8a2db0a8e2d9b93a8d29e5a5`. This design depends on V1-02 (`#3`), V1-05 (`#6`),
V1-10 (`#10`), V1-15 (`#15`) and V1-06 (`#7`, [ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md)).
Migration `0023` (`V1-06` PR2 `openmettle_gateway` role provisioning and accepted usage report
schema) is a prerequisite before the V1-17 PR2 migration. PR1 records the architecture decision.
PR2 and PR3 own schema, store, worker sweeps, `/v1` routes and verification. This design adds
zero Cargo crates.

## Decision

PostgreSQL 18 enforces transactional user and project quotas across active usage, retained data
and outstanding reservations. One shared reservation protocol extends
[ADR 0005](0005-artifact-storage-accounting.md) and
[ADR 0032](0032-durable-run-admission-and-fair-work-queue.md) without adding a service or broker.
Storage bytes, token and provider usage budgets, and active execution or device capacity
reservations remain strictly separate resource classes. Concurrent admissions serialize in a
canonical global lock order so competing requests cannot oversubscribe a budget or deadlock.
Cancellations, aborts, failures, partial usage reports, corrections and purges reconcile each
reservation exactly once internally.

| Existing boundary | V1-17 addition |
| --- | --- |
| [ADR 0005](0005-artifact-storage-accounting.md), [`src/storage.rs`](../../src/storage.rs) | Keep `storage_instance`, `storage_accounts`, `storage_reservations` and `artifact_revisions` as the single storage ledger. Add `storage_instance.volume_id`, per-scope overrides, fail-closed rolling-upgrade backstop triggers on `storage_accounts` (`OMQ01`) and on `storage_reservations`/`artifact_revisions` for unpinned `openmettle_worker` releases/purges (`OMQ03`), warning thresholds, reservation `lease_expires_at` and DB-plus-filesystem drift verification. |
| [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md), [`src/artifact_fs.rs`](../../src/artifact_fs.rs) | Bind upload reservations (`run_id IS NULL`) to `lease_expires_at` within the 600 s upload timeout plus 300 s settlement margin. Pin durable artifact volume identity (`storage_instance.volume_id` <-> `<root>/.openmettle-volume-id` with matching `st_dev` across `revisions/` and `staging/`): restrict automatic bootstrap pinning strictly to an empty storage ledger (`OMQ03` otherwise), require verified volume adoption on populated upgrades (accepting missing `state = 'purging'` files after independent volume verification and supporting idempotent operator retry after sentinel `fsync`), and gate **all** worker cleaners — explicitly including `artifact_fs::purge_due` alongside `reconcile_expired`, run-linked `ENOENT` recovery and `staging/` cleanup — on verified non-null `volume_id` + sentinel/`st_dev` identity (backed in PostgreSQL by `enforce_worker_storage_volume_pinned()` so unquiesced `N-1` workers fail closed with `OMQ03` while `volume_id IS NULL`). Keep `reconcile_expired` and `purge_due` as the sole upload and purge cleaners. Preserve published revision payloads after post-rename/pre-settlement crashes and recognize missing `purging` payloads as a valid resumable mid-purge state during both adoption and restore verification. |
| [ADR 0032](0032-durable-run-admission-and-fair-work-queue.md) and [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md), [`src/authz/runs.rs`](../../src/authz/runs.rs) | Keep exact partial-index counts on `runs` for live and executing runs. Resolve per-scope overrides for live caps and `round_cap` (`1..=1000`) at admission, and serialize `executing_runs_*` cap changes with `claim_next` (including approval resume) via `run_dispatch_lock`. Compose usage and device holds inside admission and renew run-bound holds on the worker lease cadence. |
| [ADR 0035](0035-approvals-permitted-yolo-and-effect-ledger.md), [`src/authz/approvals.rs`](../../src/authz/approvals.rs) | Keep `StorageReservation` for run-bound artifact and tool-result spills (including V1-14 (`#14`) bounded outputs). Align parked reservation expiry with `resume_execution_expires_at`. Require configured `ARTIFACTS_DIR`, verified non-null pinned `storage_instance.volume_id` <-> `<root>/.openmettle-volume-id` (`O_NOFOLLOW`, matching `st_dev` with open `revisions/` and `staging/` FDs) and directory-relative `ENOENT` proof that `revisions/<id>` does not exist before committing `storage::release` and unlinking `staging/<id>`, plus retryable staging cleanup via persistent `StagingSweepState` (retaining at most one `InFlight` `spawn_blocking` `ReadDir` slice and `pending_names` queue outside `worker::sweep`'s 15 s `tokio::time::timeout`) for already-`released` rows; never release or unlink when `revisions/<id>` exists while `state = 'reserved'` or when `volume_id IS NULL` or volume identity/`revisions/` verification fails. |
| [ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md) | Reconcile local token and cost budget holds strictly from authoritative `openmettle_gateway` settlement reports (`openmettle.gateway_usage_reports` in Migration `0023`) via narrow `SECURITY DEFINER` transitions. Introduce in-transaction `authz::gateway` helpers (`reserve_in`, `handoff_in`, `release_in`) so inserting `'reserved'` `openmettle.gateway_requests` and creating all metered `openmettle.quota_reservations` holds execute atomically in one `WriteTransaction`, backed by a two-phase ADR 0003 rolling-upgrade activation gate (`openmettle.quota_enforcement.metering_enforced`, auto-`true` on fresh installs, `false` on populated upgrades until flipped irreversibly `false -> true` by `openmettle_owner`) plus a `DEFERRABLE INITIALLY DEFERRED` commit-time `CONSTRAINT TRIGGER quota_enforce_gateway_handoff_holds` (`openmettle.enforce_gateway_handoff_holds()`, `OMQ04`, zero edits to frozen `0023`), fenced successor-worker unwind `openmettle.quota_unwind_superseded_round(...)` for crashed post-commit `'reserved'` rounds, and bounded raw index-key paging in `quota_release_orphan_gateway_requests` for pre-V1-17 orphan `'reserved'` rows. Enforce scope-pinned composite FK `(scope_id, gateway_request_id) REFERENCES openmettle.gateway_requests (scope_id, id)`, unique `(gateway_request_id, resource_kind)`, a `SECURITY DEFINER` `BEFORE INSERT OR UPDATE` gateway-binding guard trigger, 32-byte `p_dispatch` secret verification (`dispatch_hash = sha256(p_dispatch)`), ownership recheck under sweep locks, composite FKs to `gateway_usage_reports`, nullable `accepted_source_revision` supporting `revision >= 0` (including `revision = 0`), run-to-round `held` allocation coupled atomically with `openmettle.gateway_handoff` / `openmettle.gateway_release`, caller-scoped `SECURITY DEFINER` `openmettle.quota_recover_lost_handoff` for lost commit-ack recovery (without granting `SELECT` on `gateway_requests`, distinguishing `'handoff_committed'` vs `'unmetered_legacy_handoff'` across activation), atomic stale-sweep closure of `'reserved'` `gateway_requests` (`'reserved' -> 'released'` + `gateway_reservations` restoration), signed partial corrections and SQL-enforced `BEFORE INSERT OR UPDATE OR DELETE` deployment denomination immutability (`OMQ02`) with the seeded `('instance', 'usage_cost_micros')` row strictly `UPDATE`-only after migration (serialized via `quota_cost_unit_lock` with zero lock cycle alongside a `BEFORE INSERT` guard trigger on `gateway_usage_reports` (`cost IS NOT NULL`, zero edits to frozen `0023`)). |
| [ADR 0007](0007-application-api-contract.md) and [ADR 0027](0027-authorization-and-private-projects.md) | Expose authenticated `/v1` effective-quota projections (including active threshold warnings), audited `ManageQuotas` override routes backed by `SECURITY DEFINER` functions and privacy-safe `429 quota` / `429 rate_limited` / `503 provisioning` RFC 9457 problems. |
| V1-18 (`#18`) shared capacity controller | Separate user and project concurrent device-slot quotas (`window_kind = 'concurrent'`) from GPU VRAM allocation. Gate admission in PostgreSQL, reject run-linked `device_reservations` holds in generic `quota_commit_handoff`, require lease-fenced `openmettle_worker` handoff of run device holds exclusively via `quota_commit_device_handoff`, and release device quota holds only after durable V1-18 confirmation of backend release or non-allocation. |

## Resource classes, ownership and precedence

OpenMettle separates three resource classes so bytes, provider tokens, cost micro-units, run
concurrency and device slots never share a counter or unit. Every quota value is a signed 64-bit
nonnegative integer in PostgreSQL and a `NonNegativeDecimal` on `/v1`. Floating-point arithmetic
is forbidden for balances and threshold comparisons.

| Resource class | Kinds and units | Authoritative store | Charged exposure | Reconciliation owner |
| --- | --- | --- | --- | --- |
| Storage bytes | `storage_bytes` (logical bytes) | `storage_instance`, `storage_accounts`, `storage_reservations`, `artifact_revisions` | `active_bytes + retained_bytes + reserved_bytes` | `openmettle_api` and `openmettle_worker` (`settle`, `release`, `confirm_purge`) |
| Token and provider usage budgets | `usage_tokens` (tokens), `usage_cost_micros` (integer micro-units in one immutable deployment denomination) | Consolidated `quota_budgets` (`window_kind IN ('windowed', 'static')`), `quota_reservations`, `quota_reservation_charges`, `quota_reconciliations` | `active_used + reserved_held` per budget row | `openmettle_gateway` settles provider usage via `quota_settle_gateway_usage`; API and worker release only pre-handoff `held` holds via `quota_release_unsent` |
| Active execution and device capacity | `live_runs_per_actor`, `live_runs_per_scope`, `executing_runs_per_actor`, `executing_runs_per_scope`, `round_cap` (counts); `device_reservations` (concurrent active device slots) | Live/executing counts on `runs` (ADR 0032); non-windowed `quota_budgets` (`window_kind = 'concurrent'`, `window_start = EPOCH`) and `quota_reservations` for `device_reservations` | Current non-terminal/executing counts on `runs`; `reserved_held` for `device_reservations` | Run transitions settle `runs` counts automatically; `openmettle_worker` commits run-linked device handoffs under an active lease via `quota_commit_device_handoff` and settles them on durable V1-18 (`#18`) confirmation via `quota_release_device_slot` |

- **Storage bytes.** Retained and purging revisions (`state IN ('retained', 'purging')`) remain
  charged until `confirm_purge` succeeds (ADR 0005, V1-15 `#15`, V1-16 `#16`). In-flight
  multipart uploads (`run_id IS NULL`) and run-linked `StorageReservation` writes (`run_id IS NOT
  NULL`) charge `max_bytes` to `reserved_bytes` until settled or released. Physical disk
  allocation, database indexes, backup staging and sandbox home filesystems are monitored
  separately. `storage_instance.instance_budget_bytes` is the logical byte ceiling left after
  operator headroom.
- **Token and provider usage budgets.** The selected gateway remains authoritative for provider
  billing, rates and family schedules (ADR 0037). Local `quota_budgets` rows prevent concurrent
  server runs and caller-owned completions from oversubscribing user or project budgets before
  dispatch. Token accounting follows each profile's declaration of whether `reasoning_tokens` are
  included in `completion_tokens` so reasoning tokens are never counted twice. `usage_cost_micros`
  enforces **one immutable deployment-wide denomination** (`cost_denomination` configured once via
  direct `UPDATE` on the migration-seeded, undeletable `('instance', 'usage_cost_micros')` row in
  `quota_defaults`, such as `USD_MICROS` or `CREDITS_MICROS`). PostgreSQL enforces write-once
  immutability and concurrent `READ COMMITTED` serialization via `BEFORE INSERT OR UPDATE OR
  DELETE` trigger `quota_defaults_cost_denomination_immutable` on `quota_defaults` (attached after
  seeding the singleton row) and `SECURITY DEFINER` `BEFORE INSERT` trigger
  `gateway_usage_reports_cost_unit_guard` on Migration `0023`'s `openmettle.gateway_usage_reports`
  (`WHEN (NEW.cost IS NOT NULL)`, added in PR2's migration with zero edits to frozen `0023`), both
  coordinated through a dedicated 1-row `openmettle.quota_cost_unit_lock` (SQLSTATE `OMQ02`):
  inserting `('instance', 'usage_cost_micros')` (including via `INSERT ... ON CONFLICT DO UPDATE`),
  deleting it, or renaming any row into or out of `('instance', 'usage_cost_micros')` is forbidden
  unconditionally **without acquiring `quota_cost_unit_lock`**, making that row strictly
  `UPDATE`-only after migration; first-time `NULL -> non-NULL` configuration via direct `UPDATE`
  acquires `quota_cost_unit_lock FOR UPDATE` exclusively under `BEFORE UPDATE` (after PostgreSQL
  already holds the `quota_defaults` row lock) and verifies every committed `gateway_usage_reports`
  row with `cost IS NOT NULL` matches `NEW.cost_denomination` (and no local cost rows exist); once
  `OLD.cost_denomination IS NOT NULL`, any change or clearing is rejected with `OMQ02` so existing
  balances cannot be silently reinterpreted and in-flight reports cannot be orphaned. Conversely,
  concurrent `gateway_usage_reports` cost inserts while `cost_denomination IS NULL` acquire
  `quota_cost_unit_lock FOR UPDATE` (never locking `quota_defaults`) so neither commit order,
  concurrent cost reports, nor `quota_defaults` updates can introduce diverging units or an AB/BA
  lock cycle. Changing currency or credit unit
  in-place is permanently unsupported by operator contract and requires a separate deployment or an
  explicit offline `openmettle_owner` ledger migration after draining and archiving all prior cost
  balances and reports. `openmettle_gateway` refuses any provider report whose `unit` mismatches
  `cost_denomination` (or triggers `OMQ02`) and routes it to ADR 0037 quarantine without mutating
  balances.
- **Execution and device capacity.** ADR 0032 already enforces live and executing run counts and
  `round_limit` (`1..=1000`, [`migrations/0019_run_admission_and_queue.sql`](../../migrations/0019_run_admission_and_queue.sql))
  directly on `runs` without a duplicate counter table. V1-17 adds optional per-scope overrides
  for `live_runs_per_actor`, `live_runs_per_scope`, `executing_runs_per_actor`,
  `executing_runs_per_scope` and `round_cap` (`1..=1000`). Actor-wide kinds (`*_per_actor`) attach
  exclusively to a user's `personal` scope; scope kinds (`*_per_scope`, `round_cap`) attach to
  `personal` or `project` scopes. For GPUs, V1-18 (`#18`) owns the active controller, Dynamic
  Resource Allocation (DRA) claims, physical VRAM observation and elastic KV tail handoffs. V1-17
  `device_reservations` uses a **non-windowed concurrent balance** (`window_kind = 'concurrent'`,
  `window_start = '1970-01-01T00:00:00Z'`, `window_end IS NULL`) so active device slots never reset
  at UTC window rollover.

### Ownership, scope charging and limit precedence

Every billable resource has one primary accounting scope (`scope_id` in `openmettle.scopes`,
either `personal` or `project`). Sharing a conversation or artifact never changes its accounting
owner or duplicates a charge ([Architecture quota policy](../../ARCHITECTURE-v1.md#quota-policy)).

| Target scope | Storage bytes | Token and provider usage | Execution and device capacity |
| --- | --- | --- | --- |
| `personal` | Charges owner `storage_accounts` and `storage_instance`. | Charges owner `quota_budgets` (and `instance` budget when configured). | Enforces personal actor/scope ceilings and personal `device_reservations` (plus `instance` when configured). |
| `project` | Charges project `storage_accounts` and `storage_instance`. Does not double-charge the uploading actor's personal storage. | Charges project `quota_budgets` when configured **and** enforces the acting user's personal `quota_budgets` ceiling, because ADR 0037 binds each gateway virtual key and family budget to `(gateway_installation, actor_user_id)`. All charged `quota_budgets` rows reserve atomically in one transaction, each with its own configured window. | Enforces both project scope ceiling and actor ceiling (matching ADR 0032), and charges both project and actor `device_reservations` concurrent balances when configured. |

Effective limits resolve in a strict three-level hierarchy with no implicit OIDC group-to-quota
composition:

1. **Instance hard ceiling.** Operator-configured `storage_instance.instance_budget_bytes` or
   `quota_defaults` row with `scope_kind = 'instance'`. Every new reservation must fit both its
   owner limit and available instance capacity. No administrator override can bypass the instance
   ceiling or physical headroom.
2. **Explicit active administrator override.** One row in `quota_overrides` for `(scope_id,
   resource_kind)` where `revoked_at IS NULL` and `(expires_at IS NULL OR expires_at >
   clock_timestamp())`. Only `account_admin` (`Action::ManageQuotas`, ADR 0027) may set or revoke
   an override, exclusively through the `SECURITY DEFINER` functions
   `openmettle.quota_upsert_scope_override(...)` and `openmettle.quota_revoke_scope_override(...)`.
3. **Operator deployment default.** `storage_instance.personal_limit_bytes` or
   `project_limit_bytes` for storage, or `quota_defaults` for `(scope_kind, resource_kind)`.
   Only `openmettle_owner` writes defaults. If no active override exists and the default is
   `NULL` or absent (or `usage_cost_micros` lacks a configured `cost_denomination`), admission
   fails closed with `503 provisioning` (`LimitUnconfigured`, matching ADR 0005).

An administrator override can raise or lower a limit and optionally set an expiry. If a reduced
or expired limit falls below current usage, existing artifacts, settled usage and in-flight
reservations remain intact. New reservations fail with `429 quota` (or `429 rate_limited` for
run-concurrency caps) until usage falls or the limit rises. Lowering an executing-run cap leaves
queued and approval-waiting runs queued cleanly without terminating already-executing runs. Limit
changes never shorten the 30-day deletion grace period or trigger early purge.

### Threshold warnings and zero-limit semantics

Warning thresholds are operator-configurable in `storage_instance` and `quota_defaults`, with
initial defaults of `warn_pct_1 = 80` and `warn_pct_2 = 90` plus a hard-limit state at `100%`
([Architecture quota policy](../../ARCHITECTURE-v1.md#quota-policy)).

- **Integer evaluation and zero limits (`hard_limit = 0`).** Percentage math never uses division
  or floating-point numbers. When `hard_limit > 0`, threshold `P` (`warn_pct_1`, `warn_pct_2`, or
  `100`) is crossed when `charged * 100 >= hard_limit * P` using overflow-safe 128-bit integer
  arithmetic. When `hard_limit = 0`, percentage evaluation is skipped completely (zero divide-by-zero
  risk and zero spurious percentage warning events): `remaining` is `0`, `status` is `hard_limit`
  (blocked/exhausted), every new reservation requesting `> 0` units fails with `429 quota`, and
  reads, cancellations and deletions remain allowed.
- **Deduplication and re-arming.** Each crossing attempts an idempotent insert into
  `quota_warning_events` keyed by `(target_kind, scope_id, resource_kind, dedupe_bucket,
  threshold_pct, limit_revision, config_revision)`. `dedupe_bucket` is `window_start` for windowed
  usage budgets and the UTC day (`date_trunc('day', clock_timestamp() AT TIME ZONE 'UTC')`) for
  non-windowed `storage_bytes`, `device_reservations` and static envelopes. Under unchanged limits
  and thresholds, repeated flapping within the same bucket inserts nothing and emits no duplicate
  warning. Editing or revoking an administrator override via `quota_upsert_scope_override` /
  `quota_revoke_scope_override` increments `quota_overrides.revision` (`limit_revision`) while
  holding the matching balance lock, and editing operator defaults or warning percentages
  increments `config_revision`, cleanly re-arming threshold warnings within the active window.
- **Surfacing and emission.** Inserts into `quota_warning_events` (`ON CONFLICT DO NOTHING
  RETURNING`) execute strictly inside `SECURITY DEFINER` quota functions (`quota_reserve`,
  `quota_settle_gateway_usage` and `quota_record_storage_warning`) so no runtime role requires
  direct write privileges on `quota_warning_events`. Each newly inserted row emits one structured
  operational telemetry event redacted under [ADR 0024](0024-process-telemetry-and-redaction.md)
  and registered under [ADR 0028](0028-telemetry-contract-and-metrics.md) (carrying only
  `target_kind`, `scope_kind`, `resource_kind`, `threshold_pct` and `dedupe_bucket`; zero user IDs
  or counts in metric labels) for operator and admin notification pipelines. Authenticated `/v1`
  `QuotaSummary` responses also project active crossed thresholds directly in a `warnings` array
  alongside each resource's configured thresholds and status. Warning evaluation never blocks
  admission.

## Schema, lock order and exact-once reconciliation

PR2 adds the next available forward migration in schema `openmettle` after Migration `0023`
(`V1-06` `openmettle_gateway` provisioning) and any concurrently landed migrations. The migration
is additive and preserves all migration 4 storage rows.

```sql
ALTER TABLE openmettle.storage_instance
    ADD COLUMN volume_id uuid,
    ADD COLUMN warn_pct_1 smallint NOT NULL DEFAULT 80 CHECK (warn_pct_1 BETWEEN 1 AND 99),
    ADD COLUMN warn_pct_2 smallint NOT NULL DEFAULT 90
        CHECK (warn_pct_2 BETWEEN 1 AND 99 AND warn_pct_2 > warn_pct_1),
    ADD COLUMN config_revision bigint NOT NULL DEFAULT 1 CHECK (config_revision >= 1);

ALTER TABLE openmettle.storage_reservations
    ADD COLUMN lease_expires_at timestamptz,
    ADD CONSTRAINT storage_reservations_lease_check
        CHECK (lease_expires_at IS NULL OR lease_expires_at > created_at);

CREATE INDEX storage_reservations_run_expiry_idx
    ON openmettle.storage_reservations (lease_expires_at, id)
    WHERE state = 'reserved' AND run_id IS NOT NULL;

CREATE TABLE openmettle.quota_defaults (
    scope_kind text NOT NULL CHECK (scope_kind IN ('instance', 'personal', 'project')),
    resource_kind text NOT NULL CHECK (resource_kind IN (
        'usage_tokens', 'usage_cost_micros',
        'live_runs_per_actor', 'live_runs_per_scope',
        'executing_runs_per_actor', 'executing_runs_per_scope',
        'round_cap', 'device_reservations'
    )),
    hard_limit bigint CHECK (hard_limit >= 0),
    window_seconds integer CHECK (window_seconds IS NULL OR window_seconds BETWEEN 60 AND 2678400),
    cost_denomination text
        CHECK (cost_denomination IS NULL OR octet_length(cost_denomination) BETWEEN 1 AND 32),
    warn_pct_1 smallint NOT NULL DEFAULT 80 CHECK (warn_pct_1 BETWEEN 1 AND 99),
    warn_pct_2 smallint NOT NULL DEFAULT 90
        CHECK (warn_pct_2 BETWEEN 1 AND 99 AND warn_pct_2 > warn_pct_1),
    config_revision bigint NOT NULL DEFAULT 1 CHECK (config_revision >= 1),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_kind, resource_kind),
    CHECK (resource_kind <> 'round_cap' OR hard_limit IS NULL OR hard_limit BETWEEN 1 AND 1000),
    CHECK (resource_kind NOT IN ('live_runs_per_actor', 'executing_runs_per_actor')
        OR scope_kind = 'personal'),
    CHECK (resource_kind NOT IN ('live_runs_per_scope', 'executing_runs_per_scope', 'round_cap')
        OR scope_kind IN ('personal', 'project')),
    CHECK (resource_kind NOT IN (
            'live_runs_per_actor', 'live_runs_per_scope',
            'executing_runs_per_actor', 'executing_runs_per_scope',
            'round_cap', 'device_reservations'
        ) OR window_seconds IS NULL),
    CHECK ((resource_kind = 'usage_cost_micros' AND scope_kind = 'instance')
        OR cost_denomination IS NULL)
);
-- Seeded once in PR2's migration; DELETE/rename is forbidden unconditionally by OMQ02.
INSERT INTO openmettle.quota_defaults (scope_kind, resource_kind, cost_denomination)
VALUES ('instance', 'usage_cost_micros', NULL);

-- Dedicated 1-row lock serializing first cost_denomination configuration against
-- concurrent Migration 0023 gateway_usage_reports inserts carrying cost IS NOT NULL.
CREATE TABLE openmettle.quota_cost_unit_lock (
    id boolean PRIMARY KEY DEFAULT true CHECK (id)
);
INSERT INTO openmettle.quota_cost_unit_lock (id) VALUES (true);

-- Singleton rolling-upgrade activation gate for mandatory gateway metering.
-- Seeded true automatically on fresh installs (zero existing gateway state);
-- seeded false on populated upgrades until flipped write-once false -> true by
-- openmettle_owner once all N-1 API/worker replicas are replaced by N.
CREATE TABLE openmettle.quota_enforcement (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    metering_enforced boolean NOT NULL,
    metering_enforced_at timestamptz,
    CHECK (NOT metering_enforced OR metering_enforced_at IS NOT NULL)
);
INSERT INTO openmettle.quota_enforcement (id, metering_enforced, metering_enforced_at)
SELECT true, is_fresh, CASE WHEN is_fresh THEN clock_timestamp() END
  FROM (
      SELECT NOT EXISTS (SELECT 1 FROM openmettle.gateway_bindings)
             AND NOT EXISTS (SELECT 1 FROM openmettle.gateway_requests) AS is_fresh
  ) s;

CREATE TABLE openmettle.quota_overrides (
    scope_id uuid NOT NULL,
    scope_kind text NOT NULL CHECK (scope_kind IN ('personal', 'project')),
    resource_kind text NOT NULL CHECK (resource_kind IN (
        'storage_bytes', 'usage_tokens', 'usage_cost_micros',
        'live_runs_per_actor', 'live_runs_per_scope',
        'executing_runs_per_actor', 'executing_runs_per_scope',
        'round_cap', 'device_reservations'
    )),
    hard_limit bigint NOT NULL CHECK (hard_limit >= 0),
    expires_at timestamptz,
    revoked_at timestamptz,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    reason text NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 256),
    updated_by_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (scope_id, resource_kind),
    FOREIGN KEY (scope_id, scope_kind) REFERENCES openmettle.scopes (id, kind),
    CHECK (resource_kind <> 'round_cap' OR hard_limit BETWEEN 1 AND 1000),
    CHECK (resource_kind NOT IN ('live_runs_per_actor', 'executing_runs_per_actor')
        OR scope_kind = 'personal')
);

CREATE TABLE openmettle.quota_budgets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    target_kind text NOT NULL CHECK (target_kind IN ('scope', 'instance')),
    scope_id uuid REFERENCES openmettle.scopes (id),
    resource_kind text NOT NULL CHECK (resource_kind IN (
        'usage_tokens', 'usage_cost_micros', 'device_reservations'
    )),
    window_kind text NOT NULL CHECK (window_kind IN ('windowed', 'static', 'concurrent')),
    window_start timestamptz NOT NULL,
    window_end timestamptz,
    active_used bigint NOT NULL DEFAULT 0 CHECK (active_used >= 0),
    reserved_held bigint NOT NULL DEFAULT 0 CHECK (reserved_held >= 0),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE NULLS NOT DISTINCT (target_kind, scope_id, resource_kind, window_kind, window_start),
    CHECK ((target_kind = 'scope' AND scope_id IS NOT NULL)
        OR (target_kind = 'instance' AND scope_id IS NULL)),
    CHECK (
        (resource_kind = 'device_reservations' AND window_kind = 'concurrent'
            AND window_start = '1970-01-01T00:00:00Z'::timestamptz AND window_end IS NULL
            AND active_used = 0)
        OR (resource_kind IN ('usage_tokens', 'usage_cost_micros')
            AND window_kind = 'windowed' AND window_end IS NOT NULL AND window_end > window_start)
        OR (resource_kind IN ('usage_tokens', 'usage_cost_micros')
            AND window_kind = 'static'
            AND window_start = '1970-01-01T00:00:00Z'::timestamptz AND window_end IS NULL)
    )
);

CREATE TABLE openmettle.quota_reservations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL REFERENCES openmettle.scopes (id),
    actor_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    actor_scope_id uuid NOT NULL,
    origin_role text NOT NULL CHECK (origin_role IN ('api', 'worker')),
    resource_kind text NOT NULL CHECK (resource_kind IN (
        'usage_tokens', 'usage_cost_micros', 'device_reservations'
    )),
    idempotency_key text NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128),
    request_identity bytea NOT NULL CHECK (octet_length(request_identity) <= 1024),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    parent_reservation_id uuid REFERENCES openmettle.quota_reservations (id),
    run_id uuid,
    operation_id uuid,
    gateway_request_id uuid,
    device_grant_id uuid,
    reserved_units bigint NOT NULL CHECK (reserved_units > 0),
    allocated_units bigint NOT NULL DEFAULT 0
        CHECK (allocated_units >= 0 AND allocated_units <= reserved_units),
    held_units bigint NOT NULL
        CHECK (held_units >= 0 AND held_units <= reserved_units - allocated_units),
    settled_units bigint NOT NULL DEFAULT 0 CHECK (settled_units >= 0),
    accepted_source_revision bigint
        CHECK (accepted_source_revision IS NULL OR accepted_source_revision >= 0),
    state text NOT NULL DEFAULT 'held'
        CHECK (state IN ('held', 'handoff_committed', 'settled', 'released')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    lease_expires_at timestamptz NOT NULL,
    closed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (scope_id, actor_user_id, resource_kind, idempotency_key),
    UNIQUE (id, gateway_request_id),
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES openmettle.scopes (id, personal_user_id),
    FOREIGN KEY (scope_id, gateway_request_id)
        REFERENCES openmettle.gateway_requests (scope_id, id),
    FOREIGN KEY (scope_id, run_id) REFERENCES openmettle.runs (scope_id, id),
    FOREIGN KEY (scope_id, run_id, operation_id)
        REFERENCES openmettle.operations (scope_id, run_id, id),
    CHECK (operation_id IS NULL OR run_id IS NOT NULL),
    CHECK (parent_reservation_id IS NULL OR (run_id IS NOT NULL AND allocated_units = 0)),
    CHECK (allocated_units = 0
        OR (run_id IS NOT NULL AND gateway_request_id IS NULL AND settled_units = 0)),
    CHECK (gateway_request_id IS NULL OR resource_kind IN ('usage_tokens', 'usage_cost_micros')),
    CHECK (device_grant_id IS NULL OR resource_kind = 'device_reservations'),
    CHECK (
        (state IN ('held', 'handoff_committed') AND closed_at IS NULL)
        OR (state = 'settled' AND held_units = 0 AND allocated_units = 0
            AND closed_at IS NOT NULL AND closed_at >= created_at)
        OR (state = 'released' AND held_units = 0 AND settled_units = 0
            AND closed_at IS NOT NULL AND closed_at >= created_at)
    )
);
CREATE INDEX quota_reservations_stale_idx
    ON openmettle.quota_reservations (lease_expires_at, id) WHERE state = 'held';
CREATE INDEX quota_reservations_overdue_handoff_idx
    ON openmettle.quota_reservations (lease_expires_at, id) WHERE state = 'handoff_committed';
CREATE INDEX quota_reservations_run_idx
    ON openmettle.quota_reservations (scope_id, run_id) WHERE run_id IS NOT NULL;
CREATE INDEX quota_reservations_parent_idx
    ON openmettle.quota_reservations (parent_reservation_id)
    WHERE parent_reservation_id IS NOT NULL;
CREATE UNIQUE INDEX quota_reservations_gateway_request_kind_uidx
    ON openmettle.quota_reservations (gateway_request_id, resource_kind)
    WHERE gateway_request_id IS NOT NULL;
CREATE UNIQUE INDEX quota_reservations_device_grant_uidx
    ON openmettle.quota_reservations (device_grant_id)
    WHERE device_grant_id IS NOT NULL;

CREATE TABLE openmettle.quota_reservation_charges (
    reservation_id uuid NOT NULL REFERENCES openmettle.quota_reservations (id),
    budget_id uuid NOT NULL REFERENCES openmettle.quota_budgets (id),
    charge_role text NOT NULL CHECK (charge_role IN ('primary_scope', 'actor_scope', 'instance')),
    PRIMARY KEY (reservation_id, budget_id),
    UNIQUE (reservation_id, charge_role)
);
CREATE INDEX quota_reservation_charges_budget_idx
    ON openmettle.quota_reservation_charges (budget_id, reservation_id);

CREATE TABLE openmettle.quota_reconciliations (
    reservation_id uuid NOT NULL REFERENCES openmettle.quota_reservations (id),
    transition_revision bigint NOT NULL CHECK (transition_revision >= 1),
    source_key text NOT NULL CHECK (octet_length(source_key) BETWEEN 1 AND 128),
    gateway_request_id uuid,
    gateway_report_source uuid,
    gateway_report_id uuid,
    source_revision bigint CHECK (source_revision IS NULL OR source_revision >= 0),
    kind text NOT NULL CHECK (kind IN (
        'partial_settle', 'partial_correction', 'final_settle', 'final_correction', 'release'
    )),
    cumulative_units bigint NOT NULL CHECK (cumulative_units >= 0),
    delta_active bigint NOT NULL,
    delta_reserved bigint NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (reservation_id, transition_revision),
    UNIQUE (reservation_id, source_key),
    FOREIGN KEY (reservation_id, gateway_request_id)
        REFERENCES openmettle.quota_reservations (id, gateway_request_id),
    FOREIGN KEY (gateway_request_id, source_revision)
        REFERENCES openmettle.gateway_usage_reports (request_id, revision),
    FOREIGN KEY (gateway_report_source, gateway_report_id, source_revision)
        REFERENCES openmettle.gateway_usage_reports (source, report_id, revision),
    CHECK (
        (kind = 'release'
            AND gateway_request_id IS NULL
            AND gateway_report_source IS NULL
            AND gateway_report_id IS NULL
            AND source_revision IS NULL
            AND delta_active = 0 AND delta_reserved <= 0)
        OR (kind IN ('partial_settle', 'partial_correction', 'final_settle', 'final_correction')
            AND gateway_request_id IS NOT NULL
            AND gateway_report_source IS NOT NULL
            AND gateway_report_id IS NOT NULL
            AND source_revision IS NOT NULL)
    )
);

CREATE TABLE openmettle.quota_warning_events (
    target_kind text NOT NULL CHECK (target_kind IN ('scope', 'instance')),
    scope_id uuid REFERENCES openmettle.scopes (id),
    resource_kind text NOT NULL CHECK (resource_kind IN (
        'storage_bytes', 'usage_tokens', 'usage_cost_micros', 'device_reservations'
    )),
    dedupe_bucket timestamptz NOT NULL,
    threshold_pct smallint NOT NULL CHECK (threshold_pct BETWEEN 1 AND 100),
    limit_revision bigint NOT NULL CHECK (limit_revision >= 0),
    config_revision bigint NOT NULL CHECK (config_revision >= 1),
    triggered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE NULLS NOT DISTINCT (
        target_kind, scope_id, resource_kind, dedupe_bucket,
        threshold_pct, limit_revision, config_revision
    ),
    CHECK ((target_kind = 'scope' AND scope_id IS NOT NULL)
        OR (target_kind = 'instance' AND scope_id IS NULL))
);

-- Reinforces scope-pinned FK (scope_id, gateway_request_id) with actor, run and
-- initial 'reserved' state checks. quota_reserve and quota_allocate_round additionally
-- verify the caller's 32-byte p_dispatch secret (q.dispatch_hash = sha256(p_dispatch)).
CREATE FUNCTION openmettle.enforce_quota_reservation_gateway_binding()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    req openmettle.gateway_requests%ROWTYPE;
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.gateway_request_id IS DISTINCT FROM OLD.gateway_request_id THEN
        RAISE EXCEPTION 'quota_reservations.gateway_request_id is immutable'
            USING ERRCODE = '23514';
    END IF;
    IF NEW.gateway_request_id IS NOT NULL THEN
        SELECT * INTO req
          FROM openmettle.gateway_requests q
         WHERE q.scope_id = NEW.scope_id
           AND q.id = NEW.gateway_request_id;
        IF NOT FOUND
           OR req.actor_user_id <> NEW.actor_user_id
           OR req.run_id IS DISTINCT FROM NEW.run_id
           OR (TG_OP = 'INSERT' AND req.state <> 'reserved') THEN
            RAISE EXCEPTION 'quota reservation gateway_request binding violates ownership or state'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_quota_reservation_gateway_binding() FROM PUBLIC;
CREATE TRIGGER quota_reservations_gateway_binding_guard
    BEFORE INSERT OR UPDATE ON openmettle.quota_reservations
    FOR EACH ROW EXECUTE FUNCTION openmettle.enforce_quota_reservation_gateway_binding();

-- Attached strictly AFTER seeding ('instance', 'usage_cost_micros'). That singleton
-- row is UPDATE-only thereafter: INSERT (including INSERT ... ON CONFLICT), DELETE,
-- and rename into/out of ('instance', 'usage_cost_micros') fail immediately with
-- OMQ02 without touching quota_cost_unit_lock, ensuring quota_cost_unit_lock is
-- acquired solely under BEFORE UPDATE after the quota_defaults row lock is held.
CREATE FUNCTION openmettle.enforce_cost_denomination_immutability()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.scope_kind = 'instance' AND NEW.resource_kind = 'usage_cost_micros' THEN
            RAISE EXCEPTION 'instance usage_cost_micros default row is UPDATE-only after migration'
                USING ERRCODE = 'OMQ02';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.scope_kind = 'instance' AND OLD.resource_kind = 'usage_cost_micros' THEN
        IF TG_OP = 'DELETE'
           OR NEW.scope_kind <> OLD.scope_kind
           OR NEW.resource_kind <> OLD.resource_kind THEN
            RAISE EXCEPTION 'instance usage_cost_micros default row cannot be deleted or renamed'
                USING ERRCODE = 'OMQ02';
        ELSIF NEW.cost_denomination IS DISTINCT FROM OLD.cost_denomination THEN
            PERFORM FROM openmettle.quota_cost_unit_lock WHERE id FOR UPDATE;
            IF OLD.cost_denomination IS NOT NULL
               OR NEW.cost_denomination IS NULL
               OR EXISTS (SELECT 1 FROM openmettle.quota_overrides
                           WHERE resource_kind = 'usage_cost_micros')
               OR EXISTS (SELECT 1 FROM openmettle.quota_budgets
                           WHERE resource_kind = 'usage_cost_micros')
               OR EXISTS (SELECT 1 FROM openmettle.quota_reservations
                           WHERE resource_kind = 'usage_cost_micros')
               OR EXISTS (SELECT 1 FROM openmettle.gateway_usage_reports
                           WHERE cost IS NOT NULL AND unit <> NEW.cost_denomination) THEN
                RAISE EXCEPTION 'cost_denomination is immutable once configured or used'
                    USING ERRCODE = 'OMQ02';
            END IF;
        END IF;
    ELSIF TG_OP = 'UPDATE'
          AND NEW.scope_kind = 'instance' AND NEW.resource_kind = 'usage_cost_micros' THEN
        RAISE EXCEPTION 'cannot rename another quota_defaults row to instance usage_cost_micros'
            USING ERRCODE = 'OMQ02';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_cost_denomination_immutability() FROM PUBLIC;
CREATE TRIGGER quota_defaults_cost_denomination_immutable
    BEFORE INSERT OR UPDATE OR DELETE ON openmettle.quota_defaults
    FOR EACH ROW EXECUTE FUNCTION openmettle.enforce_cost_denomination_immutability();

-- Added in PR2's migration (zero edits to frozen Migration 0023). Serializes
-- gateway_usage_reports cost inserts with first-time cost_denomination configuration
-- via quota_cost_unit_lock without ever locking quota_defaults.
CREATE FUNCTION openmettle.enforce_gateway_report_cost_unit()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_denom text;
BEGIN
    SELECT cost_denomination INTO v_denom
      FROM openmettle.quota_defaults
     WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros';

    IF v_denom IS NOT NULL THEN
        IF NEW.unit <> v_denom THEN
            RAISE EXCEPTION 'gateway usage report unit mismatches cost_denomination'
                USING ERRCODE = 'OMQ02';
        END IF;
        RETURN NEW;
    END IF;

    PERFORM FROM openmettle.quota_cost_unit_lock WHERE id FOR UPDATE;

    SELECT cost_denomination INTO v_denom
      FROM openmettle.quota_defaults
     WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros';

    IF v_denom IS NOT NULL THEN
        IF NEW.unit <> v_denom THEN
            RAISE EXCEPTION 'gateway usage report unit mismatches cost_denomination'
                USING ERRCODE = 'OMQ02';
        END IF;
    ELSIF EXISTS (
        SELECT 1 FROM openmettle.gateway_usage_reports
         WHERE cost IS NOT NULL AND unit <> NEW.unit
    ) THEN
        RAISE EXCEPTION 'gateway usage report unit conflicts with existing cost reports'
            USING ERRCODE = 'OMQ02';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_gateway_report_cost_unit() FROM PUBLIC;
CREATE TRIGGER gateway_usage_reports_cost_unit_guard
    BEFORE INSERT ON openmettle.gateway_usage_reports
    FOR EACH ROW WHEN (NEW.cost IS NOT NULL)
    EXECUTE FUNCTION openmettle.enforce_gateway_report_cost_unit();

-- Enforces write-once false -> true activation on openmettle.quota_enforcement
-- (attached strictly AFTER seeding the singleton row in PR2's migration).
CREATE FUNCTION openmettle.enforce_quota_enforcement_write_once()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF TG_OP IN ('INSERT', 'DELETE')
       OR (OLD.metering_enforced AND (NOT NEW.metering_enforced
           OR NEW.metering_enforced_at IS DISTINCT FROM OLD.metering_enforced_at)) THEN
        RAISE EXCEPTION 'quota_enforcement.metering_enforced is write-once (false -> true)'
            USING ERRCODE = 'OMQ04';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_quota_enforcement_write_once() FROM PUBLIC;
CREATE TRIGGER quota_enforcement_write_once
    BEFORE INSERT OR UPDATE OR DELETE ON openmettle.quota_enforcement
    FOR EACH ROW EXECUTE FUNCTION openmettle.enforce_quota_enforcement_write_once();

-- Added in PR2's migration (zero edits to frozen Migration 0023). Fires at COMMIT
-- after both openmettle.gateway_handoff and openmettle.quota_commit_handoff run in
-- the same WriteTransaction, rejecting un-transitioned bound holds unconditionally
-- and rejecting missing required metered holds once metering_enforced = true.
CREATE FUNCTION openmettle.enforce_gateway_handoff_holds()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_enforced boolean;
    v_scope_kind text;
    v_actor_scope_id uuid;
    v_cost_denom text;
    v_cost_required boolean := false;
BEGIN
    IF EXISTS (
        SELECT 1
          FROM openmettle.quota_reservations qr
         WHERE qr.gateway_request_id = NEW.id
           AND qr.state <> 'handoff_committed'
    ) THEN
        RAISE EXCEPTION 'bound quota reservations must be handoff_committed on gateway handoff'
            USING ERRCODE = 'OMQ04';
    END IF;

    SELECT metering_enforced INTO v_enforced
      FROM openmettle.quota_enforcement
     WHERE id;

    IF NOT COALESCE(v_enforced, false) THEN
        RETURN NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM openmettle.quota_reservations qr
         WHERE qr.gateway_request_id = NEW.id
           AND qr.resource_kind = 'usage_tokens'
           AND qr.state = 'handoff_committed'
    ) THEN
        RAISE EXCEPTION 'missing handoff_committed usage_tokens reservation for gateway handoff'
            USING ERRCODE = 'OMQ04';
    END IF;

    SELECT cost_denomination INTO v_cost_denom
      FROM openmettle.quota_defaults
     WHERE scope_kind = 'instance' AND resource_kind = 'usage_cost_micros';

    IF v_cost_denom IS NOT NULL THEN
        SELECT kind INTO v_scope_kind
          FROM openmettle.scopes
         WHERE id = NEW.scope_id;
        SELECT id INTO v_actor_scope_id
          FROM openmettle.scopes
         WHERE personal_user_id = NEW.actor_user_id;

        v_cost_required := EXISTS (
            SELECT 1
              FROM openmettle.quota_defaults qd
             WHERE qd.resource_kind = 'usage_cost_micros'
               AND qd.hard_limit IS NOT NULL
               AND qd.scope_kind IN ('instance', 'personal', v_scope_kind)
        ) OR EXISTS (
            SELECT 1
              FROM openmettle.quota_overrides qo
             WHERE qo.resource_kind = 'usage_cost_micros'
               AND qo.scope_id IN (NEW.scope_id, v_actor_scope_id)
               AND qo.revoked_at IS NULL
               AND (qo.expires_at IS NULL OR qo.expires_at > clock_timestamp())
        );

        IF v_cost_required AND NOT EXISTS (
            SELECT 1
              FROM openmettle.quota_reservations qr
             WHERE qr.gateway_request_id = NEW.id
               AND qr.resource_kind = 'usage_cost_micros'
               AND qr.state = 'handoff_committed'
        ) THEN
            RAISE EXCEPTION 'missing handoff_committed usage_cost_micros reservation for gateway handoff'
                USING ERRCODE = 'OMQ04';
        END IF;
    END IF;

    RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_gateway_handoff_holds() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER quota_enforce_gateway_handoff_holds
    AFTER UPDATE OF state ON openmettle.gateway_requests
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    WHEN (OLD.state = 'reserved' AND NEW.state = 'handed_off')
    EXECUTE FUNCTION openmettle.enforce_gateway_handoff_holds();

-- Added in PR2's migration. Fails closed if an unquiesced N-1 openmettle_worker runs
-- reconcile_expired or purge_due while storage_instance.volume_id IS NULL.
-- openmettle_api (disjoint role per ADR 0003) keeps in-flight upload abort cleanup working.
CREATE FUNCTION openmettle.enforce_worker_storage_volume_pinned()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF pg_has_role(session_user, 'openmettle_worker', 'USAGE')
       AND (SELECT volume_id FROM openmettle.storage_instance WHERE id) IS NULL THEN
        RAISE EXCEPTION 'worker storage release and purge require pinned storage_instance.volume_id'
            USING ERRCODE = 'OMQ03';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_worker_storage_volume_pinned() FROM PUBLIC;
CREATE TRIGGER storage_reservations_worker_volume_pin_guard
    BEFORE UPDATE ON openmettle.storage_reservations
    FOR EACH ROW
    WHEN (OLD.state = 'reserved' AND NEW.state = 'released')
    EXECUTE FUNCTION openmettle.enforce_worker_storage_volume_pinned();
CREATE TRIGGER artifact_revisions_worker_volume_pin_guard
    BEFORE UPDATE ON openmettle.artifact_revisions
    FOR EACH ROW
    WHEN (NEW.state IN ('purging', 'purged'))
    EXECUTE FUNCTION openmettle.enforce_worker_storage_volume_pinned();
```

- **Exact multi-budget addressing.** Consolidating scope and instance balances into one
  `quota_budgets` table and recording immutable `quota_reservation_charges` child rows eliminates
  lossy single-window addressing. A daily project budget, a weekly actor ceiling and a monthly
  instance cap each receive their own `budget_id` row at reservation time. Settlement, correction,
  run-to-round child allocation and release join `quota_reservation_charges` directly without
  recomputing `window_start`, even if deployment window lengths or defaults change later.
- **Unique external-request, ownership/secret binding and device-grant binding.**
  `quota_reservations` binds `gateway_request_id` through the scope-pinned composite foreign key
  `FOREIGN KEY (scope_id, gateway_request_id) REFERENCES openmettle.gateway_requests (scope_id,
  id)` (supported by Migration `0023`'s `UNIQUE (scope_id, id)` on `openmettle.gateway_requests`).
  The `SECURITY DEFINER` `BEFORE INSERT OR UPDATE` trigger
  `quota_reservations_gateway_binding_guard` (`openmettle.enforce_quota_reservation_gateway_binding()`)
  enforces immutability of `gateway_request_id` and verifies against `openmettle.gateway_requests`
  that `q.scope_id = NEW.scope_id`, `q.actor_user_id = NEW.actor_user_id`, `q.run_id IS NOT
  DISTINCT FROM NEW.run_id`, and on `INSERT` that `q.state = 'reserved'`. In addition, both
  `openmettle.quota_reserve(...)` (standalone `run_id IS NULL`) and
  `openmettle.quota_allocate_round(...)` (`run_id IS NOT NULL`) require the caller to present the
  32-byte `p_dispatch` secret matching `octet_length(p_dispatch) = 32 AND q.dispatch_hash =
  sha256(p_dispatch)` so no caller can bind a hold to another request even within the same scope
  and actor. The partial unique index `quota_reservations_gateway_request_kind_uidx` (`UNIQUE
  (gateway_request_id, resource_kind) WHERE gateway_request_id IS NOT NULL`) guarantees at most
  one `usage_tokens` reservation and at most one `usage_cost_micros` reservation can bind to a
  given `gateway_request_id`, preventing two distinct `idempotency_key`s from attaching duplicate
  holds to the same gateway request. Likewise, `quota_reservations_device_grant_uidx` binds each
  durable `device_grant_id` to at most one `device_reservations` hold.
- **Commit-time mandatory gateway metering across rolling upgrades (`OMQ04`).** Because frozen
  Migration `0023` leaves `EXECUTE` on `openmettle.gateway_handoff` granted to `openmettle_api`
  and `openmettle_worker`, an `N-1` binary (`src/authz/gateway.rs`) can still commit
  `gateway_handoff` on its own with zero `quota_reservations` rows. PR2 closes this without
  editing frozen `0023` via two coordinated layers: (a) the singleton `openmettle.quota_enforcement`
  activation row (`metering_enforced boolean NOT NULL`, `SELECT`-granted to runtime roles,
  write-once `false -> true` by `openmettle_owner` enforced by `quota_enforcement_write_once`)
  is seeded `true` automatically on fresh installations (`NOT EXISTS` in `gateway_bindings` and
  `gateway_requests`) and `false` on populated upgrades so `N-1` replicas drain cleanly before
  `openmettle_owner` (`openmettle-admin`) flips it irreversibly `false -> true`; and (b)
  `DEFERRABLE INITIALLY DEFERRED` `CONSTRAINT TRIGGER quota_enforce_gateway_handoff_holds`
  (`openmettle.enforce_gateway_handoff_holds()`, `SECURITY DEFINER`, `SET search_path = pg_catalog`,
  audited in `src/boundaries.sql`) fires at `COMMIT` on `gateway_requests` `'reserved' ->
  'handed_off'`, unconditionally rejecting (`OMQ04`) any bound hold not in `'handoff_committed'`
  even while `metering_enforced = false`, and once `metering_enforced = true` requiring both a
  bound `'handoff_committed'` `usage_tokens` hold and — whenever `('instance',
  'usage_cost_micros').cost_denomination IS NOT NULL` and any effective `usage_cost_micros`
  default or active override applies to the request's scope, actor personal scope or instance — a
  bound `'handoff_committed'` `usage_cost_micros` hold, rolling back any `N-1` `0023`-only
  `gateway_handoff` at `COMMIT`.
- **Unpinned worker storage volume guard (`OMQ03`).** While `storage_instance.volume_id IS NULL`
  on a populated upgrade, `SECURITY DEFINER` `BEFORE UPDATE` trigger
  `openmettle.enforce_worker_storage_volume_pinned()` on both `openmettle.storage_reservations`
  (`OLD.state = 'reserved' AND NEW.state = 'released'`) and `openmettle.artifact_revisions`
  (`NEW.state IN ('purging', 'purged')`) rejects any `openmettle_worker` transition with `OMQ03`
  (leaving disjoint `openmettle_api` in-flight upload abort cleanup unaffected), ensuring even an
  unquiesced `N-1` worker running `reconcile_expired` or `purge_due` against an empty replacement
  mount fails closed in PostgreSQL with zero released holds or confirmed purges.
- **Immutable deployment cost denomination with concurrent `0023` serialization (zero lock cycle).**
  PR2 seeds the singleton `('instance', 'usage_cost_micros')` row in `quota_defaults`
  (`cost_denomination = NULL`) *before* attaching `quota_defaults_cost_denomination_immutable` and
  seeds the 1-row `openmettle.quota_cost_unit_lock` table. After migration, that singleton row is
  **strictly `UPDATE`-only**: `quota_defaults_cost_denomination_immutable` (`BEFORE INSERT OR
  UPDATE OR DELETE`, SQLSTATE `OMQ02`) unconditionally rejects `INSERT` (including `INSERT ... ON
  CONFLICT DO UPDATE`), `DELETE`, and any `UPDATE` renaming a row into or out of `('instance',
  'usage_cost_micros')` **without acquiring `quota_cost_unit_lock`**. `openmettle_owner` updates
  `quota_defaults` solely via direct `UPDATE` (never `INSERT ... ON CONFLICT`). Consequently,
  `quota_cost_unit_lock` on `quota_defaults` is acquired exclusively under `BEFORE UPDATE` *after*
  PostgreSQL already holds the `('instance', 'usage_cost_micros')` row lock (`quota_defaults` row
  -> `quota_cost_unit_lock`) before checking `openmettle.gateway_usage_reports` and local cost
  tables on first-time `NULL -> non-NULL` configuration, and any later change or clearing fails
  with `OMQ02`. Simultaneously, PR2 attaches `BEFORE INSERT` trigger
  `gateway_usage_reports_cost_unit_guard` (`SECURITY DEFINER`, `SET search_path = pg_catalog`,
  zero edits to frozen Migration `0023`) on `openmettle.gateway_usage_reports` (`WHEN (NEW.cost IS
  NOT NULL)`): once `cost_denomination` is configured, steady-state inserts validate `NEW.unit =
  cost_denomination` with a lock-free read (rejecting mismatches with `OMQ02` for ADR 0037
  quarantine); while `cost_denomination IS NULL`, the trigger acquires `quota_cost_unit_lock FOR
  UPDATE` (never locking `quota_defaults`) and re-checks both `quota_defaults` and
  `gateway_usage_reports` in a fresh `READ COMMITTED` snapshot, preventing commit-order races,
  diverging units across concurrent unconfigured inserts, and any AB/BA lock cycle.
- **Composite personal-scope binding.** `quota_reservations` binds `(actor_scope_id,
  actor_user_id)` through a composite foreign key to `openmettle.scopes (id, personal_user_id)`
  ([`migrations/0001_identity_and_scopes.sql`](../../migrations/0001_identity_and_scopes.sql)),
  proving at the schema layer that `actor_scope_id` is the actor's genuine personal scope.
- **Reusing Migration `0023` report identity and revision `0`.** In Migration `0023`,
  `openmettle.gateway_usage_reports` has `PRIMARY KEY (source, report_id, revision)`,
  `UNIQUE (request_id, revision)` and `revision >= 0` (`0` is a valid initial report revision).
  `quota_reservations.accepted_source_revision` is therefore nullable (`NULL` = no report accepted
  yet; `CHECK (accepted_source_revision IS NULL OR accepted_source_revision >= 0)`), and
  `quota_reconciliations` binds each gateway settlement via three composite foreign keys:
  `(reservation_id, gateway_request_id) REFERENCES openmettle.quota_reservations (id,
  gateway_request_id)`, `(gateway_request_id, source_revision) REFERENCES
  openmettle.gateway_usage_reports (request_id, revision)` and `(gateway_report_source,
  gateway_report_id, source_revision) REFERENCES openmettle.gateway_usage_reports (source,
  report_id, revision)` (with `source_revision >= 0`). Inside `quota_settle_gateway_usage`, a
  single lookup on `openmettle.gateway_usage_reports` matching `(request_id, source, report_id,
  revision)` proves both report foreign keys reference the exact same accepted report row, without
  duplicating raw provider token, cost or quarantine rows.
- **Audit extension.** PR2 extends `authorization_audit` constraints to accept actions
  `quota.override.set` and `quota.override.revoke` and target kind `quota_scope`. Audit `details`
  store only `{scope_id, resource_kind, old_limit, new_limit, expires_at, revision}`.

### Invariants and post-dispatch overage

- **Nonnegativity.** `CHECK` constraints enforce `active_used >= 0`, `reserved_held >= 0`,
  `0 <= allocated_units <= reserved_units`, `0 <= held_units <= reserved_units - allocated_units`
  and `settled_units >= 0` (alongside migration 4's nonnegative `storage_accounts` and
  `storage_instance` counters).
- **Non-oversubscription at reservation time.** Every reservation transaction runs at
  `READ COMMITTED` with `SET LOCAL lock_timeout = '2s'` and `statement_timeout = '3s'`. After
  acquiring `FOR NO KEY UPDATE` on each affected `quota_budgets` row in canonical order inside
  `openmettle.quota_reserve(...)` (or `storage_accounts` then `storage_instance` for storage), the
  function reads active `quota_overrides` and `quota_defaults` in a subsequent statement so any
  committed limit change is visible. It admits the hold only if `active_used + reserved_held +
  requested <= effective_limit` for every charged budget row.
- **Post-dispatch actual provider overage.** `quota_budgets` deliberately omits a table-level
  `CHECK (active_used <= hard_limit)`. Under ADR 0037, actual upstream provider usage may exceed
  the pre-dispatch estimate (`settled_units > reserved_units`). Settlement records the full
  measured overage in `active_used`, reduces `reserved_held` by the remaining `held_units`, and
  commits without failing. Subsequent new reservations then see
  `active_used + reserved_held + requested > effective_limit` and fail with `429 quota` until the
  next accounting window opens or an override raises the limit.

### Deterministic lock order

All quota operations extend the established global lock order from
[ADR 0005](0005-artifact-storage-accounting.md),
[ADR 0032](0032-durable-run-admission-and-fair-work-queue.md),
[ADR 0036](0036-conversation-branches-presets-and-effective-model-config.md) and
[ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md) (Migration `0023`):

```text
account_admin_lock -> run_dispatch_lock -> projects -> users -> runs -> branch_heads -> operations
  -> gateway_bindings -> gateway_intents -> gateway_reservations -> gateway_requests (Migration 0023)
  -> quota_defaults (openmettle_owner only) -> quota_cost_unit_lock (trigger serialization only)
  -> quota_reservations (parent before child) / storage_reservations
  -> artifacts (upload settlement only) / artifact_revisions (retention/purge only)
  -> quota_budgets (FOR NO KEY UPDATE: scope rows asc (scope_id, resource_kind, window_start, id),
                    then instance rows asc (resource_kind, window_start, id))
  -> storage_accounts (asc scope_id) -> storage_instance (singleton instance row last)
  -> quota_overrides (written only inside SECURITY DEFINER while holding matching dispatch/entity/budget lock)
```

| Path | Exact lock sequence |
| --- | --- |
| Run admission with usage/device hold (`openmettle_api`) | `projects` (if project, `FOR NO KEY UPDATE`) -> actor `users` (`FOR NO KEY UPDATE`) -> new `runs` row -> inside `quota_reserve(...)` (`SECURITY DEFINER`): upsert and `FOR NO KEY UPDATE` affected `quota_budgets` (scope rows asc, then instance row last) -> non-locking `SELECT` on `quota_overrides` and `quota_defaults` -> insert `quota_reservations` + `quota_reservation_charges` -> update `reserved_held` and evaluate `quota_warning_events`. |
| Standalone gateway request + metered quota hold (`openmettle_api`, atomic `authz::gateway::reserve_in` + `quota_reserve`) | In **one PostgreSQL `WriteTransaction`**: `authz::gateway::reserve_in(&mut tx, ...)` inserts the caller `gateway_reservations` row (`run_id IS NULL`) and `'reserved'` `gateway_requests` row (whose `gateway_allocate` trigger updates `gateway_reservations.allocated`); immediately in the **same transaction**, `openmettle.quota_reserve(...)` (`SECURITY DEFINER`) locks `gateway_requests` (`FOR SHARE`, verifying `scope_id`, `actor_user_id`, `run_id IS NULL`, `state = 'reserved'`, and 32-byte `p_dispatch` matching `dispatch_hash = sha256(p_dispatch)`) -> upserts and `FOR NO KEY UPDATE` affected `quota_budgets` (scope rows asc, then instance row last) -> non-locking `SELECT` on `quota_overrides` and `quota_defaults` -> inserts ALL metered `quota_reservations` holds (`usage_tokens`, `usage_cost_micros`, reinforced by `quota_reservations_gateway_binding_guard`) + `quota_reservation_charges` -> updates `reserved_held` and evaluates `quota_warning_events`. Any quota refusal or pre-commit crash rolls back both `gateway_requests`/`gateway_reservations` and all quota holds atomically. |
| Worker claim and approval resume (`openmettle_worker`, [`src/authz/runs.rs`](../../src/authz/runs.rs)) | `run_dispatch_lock` (`FOR NO KEY UPDATE`) -> one eligible `queued` or approved-`waiting` `runs` row (`FOR NO KEY UPDATE SKIP LOCKED`), evaluating effective `executing_runs_per_actor` and `executing_runs_per_scope` (active `quota_overrides` coalesced with `quota_defaults`) inside the claim query. Serializes directly on `run_dispatch_lock` with `executing_runs_*` override and default updates. `reclaim_next` ([`src/authz/leases.rs`](../../src/authz/leases.rs)) only re-leases already-executing runs (`running`, `cancelling`, `reconciling`) without increasing executing counts or taking `run_dispatch_lock`. |
| Run-to-round gateway request + hold allocation (`openmettle_worker`, atomic `authz::gateway::reserve_in` + `quota_allocate_round`) | In **one PostgreSQL `WriteTransaction`**: lock `runs` (`FOR NO KEY UPDATE`, verifying active `Step` lease `state = 'running'`, `cancel_reason IS NULL`, `claim_token`, `lease_expires_at > clock_timestamp()`) -> `authz::gateway::reserve_in(&mut tx, ...)` inserts the `'reserved'` `gateway_requests` row (`run_id IS NOT NULL`, whose `gateway_allocate` trigger locks and updates `gateway_reservations.allocated`) -> immediately in the **same transaction**, `openmettle.quota_allocate_round(...)` (`SECURITY DEFINER`) re-verifies `runs` (`FOR NO KEY UPDATE`) -> `gateway_reservations` (`FOR SHARE`) -> `gateway_requests` (`FOR SHARE`, verifying `state = 'reserved'`, matching `scope_id`, `actor_user_id`, `run_id`, and 32-byte `p_dispatch` matching `dispatch_hash = sha256(p_dispatch)`) -> parent `quota_reservations` (`FOR NO KEY UPDATE`) -> inserts ALL metered child `quota_reservations` (`usage_tokens`, `usage_cost_micros`) in **`state = 'held'`** bound to `gateway_request_id` (reinforced by `quota_reservations_gateway_binding_guard`) + copies `quota_reservation_charges` -> decrements parent `held_units`, increments `allocated_units` (`quota_budgets.reserved_held` delta = `0`). Any failure or pre-commit crash rolls back `gateway_requests`, `gateway_reservations.allocated` and all child holds together without stranding `gateway_requests_run_round_active_idx`. |
| Gateway handoff (`openmettle_api` standalone or `openmettle_worker` run round, atomic `authz::gateway::handoff_in` + `quota_commit_handoff`) | In **one PostgreSQL `WriteTransaction`**: `authz::gateway::handoff_in(&mut tx, ...)` invokes `openmettle.gateway_handoff(...)` (Migration `0023`), which locks `account_admin_lock -> projects -> login_providers / local_identity_approvals -> users -> runs` (`FOR SHARE`, verifying active `Step` lease for run rounds) -> `local_sessions` (`FOR SHARE`) -> `gateway_bindings` (`FOR SHARE`) -> `gateway_reservations` (`FOR SHARE`) -> `gateway_requests` (`FOR UPDATE`) and transitions `gateway_requests.state` `'reserved' -> 'handed_off'`; immediately in the **same transaction**, `openmettle.quota_commit_handoff(...)` locks `gateway_requests` (`FOR SHARE`, no lock upgrade; verifying `state = 'handed_off'`) -> `quota_reservations` (`FOR NO KEY UPDATE`, verifying `state = 'held'`, matching `gateway_request_id`, caller role/`origin_role`, and rejecting any run-linked `device_reservations` hold) and transitions `quota_reservations.state` `'held' -> 'handoff_committed'`. At `COMMIT`, deferred `CONSTRAINT TRIGGER quota_enforce_gateway_handoff_holds` (`openmettle.enforce_gateway_handoff_holds()`, `SECURITY DEFINER`, non-locking reads only) verifies zero bound holds remain outside `'handoff_committed'` and — whenever `quota_enforcement.metering_enforced = true` — verifies required `'handoff_committed'` holds (`usage_tokens` plus applicable `usage_cost_micros`) exist, rolling back `gateway_handoff` with `OMQ04` otherwise. Any pre-commit or commit-time failure rolls back both transitions before ciphertext leaves the process; on lost commit acknowledgement (`UnknownCommit`), the caller suppresses HTTP dispatch and invokes `openmettle.quota_recover_lost_handoff(...)`. |
| Lost commit-ack handoff recovery (`openmettle_api` / `openmettle_worker`, via `quota_recover_lost_handoff`) | Inside `SECURITY DEFINER`: verify `pg_has_role(session_user, CASE WHEN p_run_id IS NULL THEN 'openmettle_api' ELSE 'openmettle_worker' END, 'USAGE')`, `octet_length(p_dispatch) = 32`, and matching `gateway_requests` (`id`, `dispatch_hash = sha256(p_dispatch)`, `scope_id`, `actor_user_id`, `run_id`) -> lock `(runs ->) gateway_reservations -> gateway_requests -> (parent ->) quota_reservations` (all bound rows in deterministic order, `FOR NO KEY UPDATE`) -> re-verify `(q.scope_id, q.actor_user_id) = (qr.scope_id, qr.actor_user_id) AND q.run_id IS NOT DISTINCT FROM qr.run_id` -> if `gateway_requests.state = 'handed_off'`, assert zero bound holds remain outside `'handoff_committed'`, require the same bound `'handoff_committed'` hold presence (`usage_tokens` plus applicable `usage_cost_micros`) whenever `quota_enforcement.metering_enforced = true` (`OMQ04` if missing), and return `'handoff_committed'` (or `'unmetered_legacy_handoff'` if zero bound holds exist during a pre-activation rolling upgrade while `metering_enforced = false`, still keeping HTTP dispatch suppressed); otherwise lock charged `quota_budgets` (if not returning to an active `'held'` parent), atomically unwind `'reserved'`/`'released'` `gateway_requests` + `gateway_reservations.allocated` + bound `'held'` `quota_reservations`, and return `'unwound_unsent'`. |
| Fenced successor-worker unwind of superseded `'reserved'` round (`openmettle_worker`, via `quota_unwind_superseded_round`) | Inside `SECURITY DEFINER`: verify `pg_has_role(session_user, 'openmettle_worker', 'USAGE')` and `p_round BETWEEN 1 AND 1000` -> lock `runs` (`FOR NO KEY UPDATE`, verifying current live worker lease `r.scope_id = p_scope_id AND r.id = p_run_id AND r.claim_token = p_claim_token AND r.state IN ('running', 'cancelling', 'reconciling') AND r.lease_expires_at > clock_timestamp()`) -> `gateway_reservations` (`FOR NO KEY UPDATE`) -> active `gateway_requests` for `(run_id = p_run_id, round = p_round, state <> 'released')` (`FOR NO KEY UPDATE`) -> parent `quota_reservations` (`FOR NO KEY UPDATE`, asc `id`) -> bound child `quota_reservations` (`FOR NO KEY UPDATE`, asc `id`). If `gateway_requests.state = 'reserved'` (never `'handed_off'`), atomically transitions `gateway_requests.state := 'released'`, restores `gateway_reservations.allocated := allocated - q.units`, and transitions all bound `'held'` child holds to `'released'` (`held_units = 0`, `closed_at = clock_timestamp()`), returning capacity directly to their active `'held'` parent run holds (`allocated_units := allocated_units - child.reserved_units`, `held_units := held_units + child.held_units`, `quota_budgets` delta = `0`), returning `true`. Leaves `'handed_off'` untouched and returns `false`. |
| Run-linked device handoff (`openmettle_worker`, via `quota_commit_device_handoff`) | **Sole** transition path for run-linked `device_reservations` holds. Inside `SECURITY DEFINER`: `runs` (`FOR NO KEY UPDATE`, verifying active `Step` lease `state = 'running'`, `cancel_reason IS NULL`, matching `claim_token`, `lease_expires_at > clock_timestamp()`) -> `quota_reservations` (`FOR NO KEY UPDATE`, `resource_kind = 'device_reservations'`, `run_id IS NOT NULL`, `origin_role IN ('api', 'worker')`, matching `scope_id` and `run_id`) -> bind durable `device_grant_id` and transition `held -> handoff_committed`. |
| Gateway cost report insert & first `cost_denomination` configuration | `openmettle_owner` configures `('instance', 'usage_cost_micros')` in `quota_defaults` solely via direct `UPDATE` (never `INSERT ... ON CONFLICT`). `enforce_cost_denomination_immutability()` rejects `INSERT` (including `INSERT ... ON CONFLICT`), `DELETE`, and rename into/out of `('instance', 'usage_cost_micros')` with `OMQ02` **without acquiring `quota_cost_unit_lock`**, acquiring `quota_cost_unit_lock` (`FOR UPDATE`) exclusively under `BEFORE UPDATE` after PostgreSQL already holds the `quota_defaults` row lock (`quota_defaults` -> `quota_cost_unit_lock`). `openmettle_gateway` inserting `gateway_usage_reports` (`WHEN NEW.cost IS NOT NULL`) fires `BEFORE INSERT` trigger `enforce_gateway_report_cost_unit()` (`SECURITY DEFINER`), which performs a non-locking `SELECT` on `quota_defaults` (never locking `quota_defaults`) and, when `cost_denomination IS NULL`, locks `quota_cost_unit_lock` (`FOR UPDATE`) before re-checking `quota_defaults` and `gateway_usage_reports` — serializing both commit orders and concurrent unconfigured cost reports with zero lock cycle. |
| Gateway usage settlement or correction (`openmettle_gateway`, via `quota_settle_gateway_usage`) | Inside `SECURITY DEFINER`: `runs` (if run-linked, `FOR SHARE`) -> `gateway_bindings` (`FOR SHARE`) -> `gateway_reservations` (`FOR SHARE`) -> `gateway_requests` (`FOR SHARE`) -> `quota_reservations` (`FOR NO KEY UPDATE`) -> charged `quota_budgets` via `quota_reservation_charges` (scope rows asc, instance row last) -> insert `quota_reconciliations` (with composite FKs to `openmettle.gateway_usage_reports`) -> update reservation (`held_units`, `settled_units`, `accepted_source_revision`, `state`/`closed_at`), budget balances and `quota_warning_events`. |
| Pre-send abort, stale release, orphan `'reserved'` gateway sweep or V1-18 device release (via `quota_release_unsent` / `quota_release_orphan_gateway_requests` / `quota_release_device_slot`) | **One reservation/request per short transaction, locks acquired inside `SECURITY DEFINER`:** `runs` (if run-linked: `FOR NO KEY UPDATE SKIP LOCKED` in stale/orphan sweep, `FOR NO KEY UPDATE` on explicit abort/release) -> if bound to `gateway_request_id`, `gateway_reservations` -> `gateway_requests` (explicit pre-send unwind couples with `authz::gateway::release_in(&mut tx, ...)` / `openmettle.gateway_release(p_request, p_dispatch)` after locking `runs`, or verifies `gateway_requests.state = 'released'` from a prior `gateway_release` commit; sweep mode acquires `FOR NO KEY UPDATE SKIP LOCKED` on `gateway_reservations` then `gateway_requests`, proceeds if `gateway_requests.state = 'released'`, **atomically transitions stale `'reserved'` `gateway_requests` to `'released'` and restores `gateway_reservations.allocated`** when expiry/terminal preconditions hold, and leaves `'handed_off'` or locked rows untouched) -> parent `quota_reservations` (if child, `FOR NO KEY UPDATE SKIP LOCKED` in sweep / `FOR NO KEY UPDATE` on explicit release) -> target `quota_reservations` (`FOR NO KEY UPDATE SKIP LOCKED` in stale sweep, `FOR NO KEY UPDATE` on explicit abort/release). Whenever `gateway_request_id IS NOT NULL`, `quota_release_unsent` **explicitly re-verifies `(q.scope_id, q.actor_user_id) = (qr.scope_id, qr.actor_user_id) AND q.run_id IS NOT DISTINCT FROM qr.run_id` under lock before mutating either ledger** (raising an invariant error and mutating neither ledger on mismatch). If unwinding an unsent child hold back to an active `held` parent run hold, transfer `held_units` back to parent (`quota_budgets` delta = `0`); otherwise lock charged `quota_budgets` via `quota_reservation_charges` (scope rows asc, instance row last) -> insert `quota_reconciliations` -> update reservation (`closed_at = clock_timestamp()`) and budget balances. Separately, `openmettle.quota_release_orphan_gateway_requests(...)` materializes a bounded page of at most `p_page_size` raw `(created_at, id)` index keys from `gateway_requests_reserved_idx`, filters binding absence and run eligibility only on those keys, locks `(runs ->) gateway_reservations -> gateway_requests` (`FOR NO KEY UPDATE SKIP LOCKED`) for eligible orphans, and advances the persistent cursor across pages even when a page contains zero orphans. |
| Storage upload reservation (`openmettle_api` / `openmettle_worker`) | `runs` (if run-linked) -> `storage_accounts` (`FOR UPDATE`) -> non-locking `SELECT` on `storage_reservations`, `artifacts`, `quota_overrides` -> `storage_instance` (`FOR UPDATE`) -> insert `storage_reservations` -> update `storage_accounts` then `storage_instance` -> call `quota_record_storage_warning(...)`. |
| Storage upload settlement (`storage::settle`) | `projects` (if authorized in tx) -> `storage_reservations` (`FOR UPDATE`) -> `artifacts` (`FOR UPDATE`) -> insert `artifact_revisions` -> update `storage_reservations` -> `storage_accounts` -> `storage_instance`. |
| Storage retention and purge confirmation (`storage::retain_revision`, `restore_revision`, `begin_purge`, `confirm_purge`) | `artifact_revisions` (`FOR UPDATE`) -> `storage_accounts` -> `storage_instance` (never locks `artifacts` or `storage_reservations`, [`src/storage.rs`](../../src/storage.rs)). |
| Storage release (`storage::release`) | `runs` (`FOR NO KEY UPDATE SKIP LOCKED` in worker stale sweep, `FOR NO KEY UPDATE` on explicit release, if `run_id IS NOT NULL`) -> `storage_reservations` (`FOR UPDATE SKIP LOCKED` in sweep, `FOR UPDATE` on explicit release) -> `storage_accounts` -> `storage_instance`. |
| Override write (`openmettle_api` via `quota_upsert_scope_override` / `quota_revoke_scope_override`, `ManageQuotas`) | Inside `SECURITY DEFINER`: if `resource_kind IN ('executing_runs_per_actor', 'executing_runs_per_scope')`, acquire `run_dispatch_lock` (`FOR NO KEY UPDATE`) first -> target entity row (`projects` `FOR NO KEY UPDATE` for project scopes; personal owner `users` `FOR NO KEY UPDATE` for personal/actor scopes) -> if `storage_bytes`, `storage_accounts` (`FOR UPDATE`); if metered usage/device, current active `quota_budgets` (`FOR NO KEY UPDATE`, ascending) -> upsert/revoke `quota_overrides` (incrementing `revision` to re-arm warning watermarks); then caller inserts `authorization_audit` in the same transaction. Live-run and round-cap kinds (`live_runs_*`, `round_cap`) serialize on `projects`/`users` matching `lock_scope_actor`; `openmettle_owner` updates to `executing_runs_*` rows in `quota_defaults` also acquire `run_dispatch_lock` (`FOR NO KEY UPDATE`) first so default cap changes serialize with `claim_next`. |

During `quota_reserve`, the idempotency replay lookup performs a non-locking `SELECT` on
`quota_reservations` (matching `src/storage.rs`), so `quota_reserve` never waits on a reservation
row while holding a budget lock. `settle`, `allocate_round`, `commit_handoff`,
`commit_device_handoff`, `recover_lost_handoff`, `unwind_superseded_round` and `release` always
lock the run, gateway and reservation rows before budget rows.
`enforce_cost_denomination_immutability` never acquires `quota_cost_unit_lock` during `INSERT` or
rename (only under `BEFORE UPDATE` after the `quota_defaults` row lock is already held),
`enforce_gateway_report_cost_unit` never locks `quota_defaults` (only `quota_cost_unit_lock`),
`enforce_gateway_handoff_holds` and `enforce_worker_storage_volume_pinned` perform strictly
non-locking `SELECT`s (adding zero row locks, with `quota_enforcement` updated only once
write-once by `openmettle_owner`), and no path holding a `quota_reservations`, `quota_budgets`,
`storage_*` or `quota_overrides` lock waits on `quota_defaults`, `quota_cost_unit_lock` or
`quota_enforcement`. No path holding a `projects`, `users`, `runs`, quota or storage lock waits
on `run_dispatch_lock`, and no path holding a quota or storage lock waits on `projects`, `users`,
`runs`, `gateway_bindings`, `gateway_intents`, `gateway_reservations` or `gateway_requests`,
making the global lock graph strictly acyclic. If a caller composes multiple unrelated owners and
PostgreSQL reports SQLSTATE `40P01`, the caller rolls back the whole transaction and retries with
identical idempotency keys.

### Exact-once internal reconciliation

Reservation identity uses ADR 0004 length-prefixed framing with domain
`openmettle/quota-reservation/1\0` over caller-supplied inputs only: `scope_id`, `actor_user_id`,
`actor_scope_id`, `resource_kind`, `idempotency_key`, `reserved_units`, optional
`parent_reservation_id`, optional `run_id`, optional `operation_id`, optional
`gateway_request_id` and optional `device_grant_id`. Server-selected windows (`quota_budgets`
rows and `window_start` timestamps) are intentionally excluded from `request_identity`; on exact
idempotent replay, `quota_reserve` recovers the committed reservation and its exact
`quota_reservation_charges` budget IDs and windows from the database.

Each accepted reconciliation increments `quota_reservations.revision` and inserts
`quota_reconciliations` with `transition_revision` set to the next monotonic sequence on that
reservation. `usage_tokens` and `usage_cost_micros` settle independently on their own reservation
rows so a report confirming tokens while leaving cost `NULL` settles tokens and preserves the
cost hold until resolved.

| Event | State transition and exact-once accounting |
| --- | --- |
| Exact reservation replay | Same `(scope_id, actor_user_id, resource_kind, idempotency_key)` with matching `request_identity` and `request_digest` returns the existing reservation, state and server-selected charged windows without rechecking limits or double-charging. Changed input returns `409 idempotency_conflict`. |
| Atomic gateway request + metered hold creation (`authz::gateway::reserve_in` + `quota_reserve` / `quota_allocate_round`, ADR 0037 / Migration `0023`) | In Migration `0023`'s `src/authz/gateway.rs`, standalone `authz::gateway::reserve()` commits `gateway_requests` before returning, which would leave `gateway_reservations.allocated` stranded and occupy `gateway_requests_run_round_active_idx` if a process crashed before creating `quota_reservations`. PR2 therefore introduces in-transaction helpers `authz::gateway::reserve_in(&mut WriteTransaction, ...)` (alongside `handoff_in` and `release_in`) so **inserting the `'reserved'` `openmettle.gateway_requests` row (plus the caller `gateway_reservations` row when `run_id IS NULL`) and creating ALL corresponding metered `openmettle.quota_reservations` holds (`usage_tokens`, `usage_cost_micros` via `quota_reserve` for standalone calls or `quota_allocate_round` for run rounds) execute atomically in a single PostgreSQL `WriteTransaction`** — rolling back both if any quota hold fails or the process crashes before commit. Both `quota_reserve` and `quota_allocate_round` (reinforced by `quota_reservations_gateway_binding_guard`) verify `q.scope_id = scope_id`, `q.actor_user_id = actor_user_id`, `q.run_id IS NOT DISTINCT FROM run_id`, `q.state = 'reserved'`, and the caller's 32-byte `p_dispatch` secret (`q.dispatch_hash = sha256(p_dispatch)`). For run rounds, `quota_allocate_round` additionally verifies the worker's active `Step` lease on `runs` and transfers `slice_units <= parent.held_units` from the server-owned run's `held` parent reservation to a child round reservation in **`state = 'held'`** (pre-handoff) bound to `gateway_request_id`, copying `quota_reservation_charges`. Parent decrements `held_units` and increments `allocated_units`; `quota_budgets.reserved_held` changes by `0` (never double-debited). Because the child stays `'held'` until dispatch handoff, a pre-send failure never orphans it in `'handoff_committed'`. Unallocated parent remainder releases once when the run can start no further rounds. |
| Gateway & standalone pre-dispatch handoff (`authz::gateway::handoff_in` + `quota_commit_handoff`, `quota_enforce_gateway_handoff_holds`, plus `quota_recover_lost_handoff`) | For metered usage holds (`usage_tokens`, `usage_cost_micros`) — both standalone API calls (`openmettle_api`, `run_id IS NULL`) and worker run rounds (`openmettle_worker`, `run_id IS NOT NULL`) — `quota_commit_handoff` executes **atomically in the same `WriteTransaction` immediately after `authz::gateway::handoff_in` / `openmettle.gateway_handoff(...)`**, locking `gateway_requests` (`FOR SHARE`) to verify `gateway_requests.state = 'handed_off'` before transitioning the caller's matching `held` reservation (`origin_role` matching caller) to `'handoff_committed'`. At `COMMIT`, `DEFERRABLE INITIALLY DEFERRED` `CONSTRAINT TRIGGER quota_enforce_gateway_handoff_holds` (`openmettle.enforce_gateway_handoff_holds()`, `OMQ04`) unconditionally rejects any bound hold left outside `'handoff_committed'` (even while `metering_enforced = false`), and whenever `openmettle.quota_enforcement.metering_enforced = true` requires bound `'handoff_committed'` holds for `usage_tokens` and any applicable `usage_cost_micros` limit so any `N-1` `0023`-only `gateway_handoff` rolls back cleanly to `'reserved'`. Any pre-commit or commit-time refusal rolls back both transitions cleanly and prevents dispatch. On a **lost commit acknowledgement (`UnknownCommit`)** (connection drop during `COMMIT` reply, leaving commit outcome unknown in PostgreSQL), because Migration `0023` grants `SELECT` on `openmettle.gateway_requests` **only** to `openmettle_gateway` (never to `openmettle_api` or `openmettle_worker`), the caller **MUST suppress HTTP transport dispatch** (matching [ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md) and `src/authz/gateway.rs`) and invoke the caller-scoped `SECURITY DEFINER` recovery entrypoint **`openmettle.quota_recover_lost_handoff(p_request_id uuid, p_dispatch bytea, p_scope_id uuid, p_actor_user_id uuid, p_run_id uuid) RETURNS text`**. That function verifies caller role (`openmettle_api` for `p_run_id IS NULL`, `openmettle_worker` for `p_run_id IS NOT NULL`), `octet_length(p_dispatch) = 32`, and `gateway_requests` ownership + `dispatch_hash = sha256(p_dispatch)` (preserved by `0023`'s `gateway_handoff`), locks `(runs ->) gateway_reservations -> gateway_requests -> (parent ->) quota_reservations -> quota_budgets` in canonical `FOR NO KEY UPDATE` order, and resolves the outcome: (a) if `gateway_requests.state = 'handed_off'`, it preserves the committed handoff and all `'handoff_committed'` quota holds intact, asserting zero bound holds remain outside `'handoff_committed'`, requiring the same bound `'handoff_committed'` hold presence (`usage_tokens` plus applicable `usage_cost_micros`) whenever `metering_enforced = true` (`OMQ04` if missing), and returning `'handoff_committed'` — or explicitly returning `'unmetered_legacy_handoff'` if an unmetered legacy `'handed_off'` row (zero bound holds) is encountered during a pre-activation rolling upgrade while `metering_enforced = false`, still keeping HTTP dispatch suppressed for downstream gateway reconciliation; (b) if `gateway_requests.state = 'reserved'` (or `'released'` with remaining `'held'` bound holds), it atomically unwinds `gateway_requests.state := 'released'` and decrements `gateway_reservations.allocated` (if `'reserved'`), transitions bound `'held'` `quota_reservations` to `'released'` (returning round capacity to an active `'held'` parent or restoring `quota_budgets` on standalone/terminal runs, setting `closed_at`), and returns `'unwound_unsent'`. For standalone non-run device holds (`resource_kind = 'device_reservations' AND run_id IS NULL`), `quota_commit_handoff` binds `device_grant_id` on the caller's own `origin_role` `held` row. **Generic `quota_commit_handoff` explicitly rejects all run-linked device holds (`resource_kind = 'device_reservations' AND run_id IS NOT NULL`, SQLSTATE `42501`) for both `openmettle_api` and `openmettle_worker`**, forcing exclusive use of `quota_commit_device_handoff`. |
| Fenced successor-worker unwind of crashed post-commit `'reserved'` round (`quota_unwind_superseded_round`) | If Worker 1 commits `(reserve_in + quota_allocate_round)` for `(run_id, round)` and crashes immediately before `handoff_in`, its 32-byte `Pending.secret` is lost in process memory while Migration `0023`'s `gateway_requests_run_round_active_idx` blocks retrying `round` (`23505`). After Worker 1's lease expires and Worker 2 reclaims the still-live (`running`) run via `leases::reclaim_next` (minting a fresh `claim_token` that invalidates Worker 1 in `0023`'s `gateway_handoff`), Worker 2 invokes **`openmettle.quota_unwind_superseded_round(p_scope_id uuid, p_run_id uuid, p_claim_token uuid, p_round integer) RETURNS boolean`** (`SECURITY DEFINER`, `openmettle_worker` only). Acquiring canonical `FOR NO KEY UPDATE` locks on `runs -> gateway_reservations -> gateway_requests -> parent & child quota_reservations`, it verifies Worker 2 holds the current live lease (`r.claim_token = p_claim_token AND r.state IN ('running', 'cancelling', 'reconciling') AND r.lease_expires_at > clock_timestamp()`). If an active `gateway_requests` row for `(run_id = p_run_id, round = p_round)` is still `state = 'reserved'` (never `'handed_off'`), it atomically transitions `gateway_requests.state := 'released'`, restores `gateway_reservations.allocated := allocated - q.units`, transitions all bound `'held'` child `quota_reservations` rows to `'released'` (`held_units = 0`, `closed_at = clock_timestamp()`, inserting `quota_reconciliations` with `kind = 'release'`, `delta_active = 0`, `delta_reserved = 0`), returns their capacity directly to their active `'held'` parent run holds (`parent.allocated_units := parent.allocated_units - child.reserved_units`, `parent.held_units := parent.held_units + child.held_units`, `quota_budgets` delta = `0`), and returns `true` so Worker 2 can immediately retry `p_round` cleanly. If already `'handed_off'` (or no active `'reserved'` row exists), it leaves the row untouched and returns `false` so Worker 2 reconciles or advances. |
| Run-linked device handoff (`api` admission -> `worker` dispatch) | Run admission (`POST /v1/runs`) reserves `device_reservations` with `origin_role = 'api'`. At dispatch, `openmettle_worker` invokes `openmettle.quota_commit_device_handoff(...)` (the sole allowed transition path for run-linked device holds), which locks `runs -> quota_reservations` in canonical order, verifies the calling worker's active `Step` lease (`runs.state = 'running'`, `runs.cancel_reason IS NULL`, matching `claim_token`, `runs.lease_expires_at > clock_timestamp()`), requires `resource_kind = 'device_reservations'` (`run_id IS NOT NULL`, `origin_role IN ('api', 'worker')`) matching `(scope_id, run_id)`, binds the run's durable V1-18 `device_grant_id` and transitions `state = 'handoff_committed'` before external device activation. `openmettle_api` has zero `EXECUTE` grant on `quota_commit_device_handoff` and is rejected by `quota_commit_handoff` on any run-linked device hold; `openmettle_worker` remains forbidden from mutating `origin_role = 'api'` holds of any other resource kind or any unleased/cancelled run. |
| Pre-send abort, `gateway_release` unwind, queued cancellation, unallocated parent remainder or orphan `'reserved'` gateway sweep | Only while `state = 'held'`: for a hold bound to `gateway_request_id`, explicit pre-send unwind couples with `authz::gateway::release_in(&mut tx, ...)` / Migration `0023`'s `openmettle.gateway_release(p_request, p_dispatch)` (setting `gateway_requests.state = 'released'` and returning units to `gateway_reservations`), and `quota_release_unsent` verifies `gateway_requests.state = 'released'` before unwinding. In **both** explicit pre-send unwind and sweep mode, after acquiring canonical locks on `(runs ->) gateway_reservations -> gateway_requests -> (parent ->) quota_reservations`, `quota_release_unsent` **explicitly re-verifies `(q.scope_id, q.actor_user_id) = (qr.scope_id, qr.actor_user_id) AND q.run_id IS NOT DISTINCT FROM qr.run_id` before modifying either ledger** (raising an invariant error and mutating neither ledger on mismatch). When unwinding an unsent child round hold whose parent run hold is still active (`state = 'held'` on a non-terminal run), `quota_release_unsent` locks parent before child, returns `child.held_units` to `parent.held_units` (decrementing `parent.allocated_units`, `quota_budgets.reserved_held` delta = `0`), inserts `quota_reconciliations` (`kind = 'release'`, `delta_active = 0`, `delta_reserved = 0`), and sets child `state = 'released'`, `held_units = 0`, `closed_at = clock_timestamp()`. For standalone holds, parent remainders or terminal-run child holds (including stale sweep after a pre-handoff crash), `quota_release_unsent` (`SECURITY DEFINER`, owned by `openmettle_owner`) acquires locks internally in canonical order (`FOR NO KEY UPDATE SKIP LOCKED` on `runs`, `gateway_reservations`, `gateway_requests`, parent and target `quota_reservations` in sweep mode), re-verifies eligibility and ownership, and when `gateway_request_id IS NOT NULL`: proceeds if `gateway_requests.state = 'released'`; **atomically transitions `gateway_requests.state = 'released'` and restores `gateway_reservations.allocated = allocated - req.units` in the exact same transaction** if `gateway_requests.state = 'reserved'` (without needing the caller's lost dispatch secret, ensuring any delayed `openmettle.gateway_handoff` call fails closed); or leaves the local hold untouched if `gateway_requests.state = 'handed_off'` or locked. Eligible releases insert `quota_reconciliations` (`kind = 'release'`, `delta_active = 0`, `delta_reserved = -held_units`), decrement `reserved_held`, and set `state = 'released'`, `held_units = 0` and `closed_at = clock_timestamp()`. Repeating release is a no-op. For rolling-upgrade / defense-in-depth safety against pre-V1-17 `'reserved'` `gateway_requests` rows having zero bound `quota_reservations` rows, `openmettle_worker` also runs `openmettle.quota_release_orphan_gateway_requests(...)` using bounded raw `(created_at, id)` index-key paging over `gateway_requests_reserved_idx` to release aged unbound `'reserved'` requests and restore `gateway_reservations.allocated`. |
| Open partial gateway report or signed partial correction (ADR 0037 / Migration `0023`) | `quota_settle_gateway_usage` requires `state = 'handoff_committed'`, locates the single `openmettle.gateway_usage_reports` row matching `(request_id = qr.gateway_request_id, source = p_report_source, report_id = p_report_id, revision = p_source_revision)` (`revision >= 0`), verifies immutable deployment `cost_denomination` against `gateway_usage_reports.unit` (when `cost IS NOT NULL`) and requires **`accepted_source_revision IS NULL OR p_source_revision > accepted_source_revision`** (so valid `revision = 0` initial reports are accepted cleanly). For cumulative total `C` vs prior `settled_units = S` and `held_units = H`, compute `new_held = greatest(0, reserved_units - C)`, `delta_active = C - S` and **signed** `delta_reserved = new_held - H`. The single atomic `UPDATE` on `quota_reservations` persists `held_units = new_held`, `settled_units = C`, **`accepted_source_revision = p_source_revision`** and `revision = revision + 1` in the same transaction alongside the composite-FK `quota_reconciliations` row and `quota_budgets`, so delayed older reports (`p_source_revision <= accepted_source_revision`) can never pass the guard. Example: on a `100`-token hold (`accepted_source_revision IS NULL`) where `revision = 0` reports `60` partial (`60` measured, `40` held, `accepted_source_revision = 0`), an authoritative `revision = 1` partial correction to `20` applies `delta_active = -40` and `delta_reserved = +40` (`20` measured, `80` held, `accepted_source_revision = 1`, preserving `100` total exposure while open). |
| Authoritative final gateway report (including overage, zero charge or `revision = 0` final) | Requires `state = 'handoff_committed'`, matching `openmettle.gateway_usage_reports` row (`final = true`) and **`accepted_source_revision IS NULL OR p_source_revision > accepted_source_revision`** (accepting an immediate `revision = 0` final report cleanly). Applies `delta_active = C - S` (full overage if `C > reserved_units`) and `delta_reserved = -H`. The single atomic `UPDATE` sets `state = 'settled'`, `held_units = 0`, `settled_units = C`, **`accepted_source_revision = p_source_revision`**, `revision = revision + 1` and `closed_at = clock_timestamp()`. Closes the hold once per unit; a late partial report cannot reopen `settled`. |
| Post-final authoritative correction | Requires `state = 'settled'`, matching `openmettle.gateway_usage_reports` row and **`accepted_source_revision IS NULL OR p_source_revision > accepted_source_revision`**. Applies signed `delta_active = C_new - S` and `delta_reserved = 0` (rejecting negative `active_used`), atomically updating `settled_units = C_new`, `accepted_source_revision = p_source_revision` and `revision = revision + 1`. Same-revision duplicates with identical values are no-ops; differing values at an already accepted revision or mismatched `unit` denominations quarantine under ADR 0037 without mutating balances. |
| Failed upload, interrupted write or retention purge | Non-run upload failures unlink `staging/<id>` and call `storage::release` once; `settle` moves actual bytes to `active_bytes` and releases `max_bytes - size_bytes` once; `confirm_purge` decrements `retained_bytes` once after confirmed payload deletion (ADR 0005, ADR 0031). All worker storage cleaners — explicitly including `artifact_fs::purge_due` alongside `reconcile_expired`, run-linked `storage_reservations` recovery and `staging/` cleanup — verify non-null pinned `storage_instance.volume_id` <-> `<root>/.openmettle-volume-id` (`O_NOFOLLOW`, auto-pinned strictly on an empty storage ledger and otherwise requiring idempotent verified operator volume adoption that accepts missing `purging` files after independent verification) and exact `st_dev` match with open `revisions/` and `staging/` directory handles (failing closed with zero released holds, purges or unlinked files when `volume_id IS NULL` — backed in PostgreSQL by `enforce_worker_storage_volume_pinned()` (`OMQ03`) for unquiesced `N-1` workers — or on missing, mismatched, symlinked or different-`st_dev` sentinels or empty replacement directories). Run-linked `storage_reservations` recovery additionally requires directory-relative `ENOENT` proof that `revisions/<id>` does not exist before committing `storage::release` and unlinking `staging/<id>`, with retryable `staging/<id>` cleanup via persistent `StagingSweepState` (`Idle`/`Open`/`InFlight` + `pending_names` held outside `worker::sweep`'s 15 s `tokio::time::timeout`) for already-`released` rows; if `revisions/<id>` exists while `state = 'reserved'`, both hold and payload are preserved for settlement or operator reconciliation. |
| Terminal failed, cancelled or interrupted run | Unallocated `held` parent, standalone or unsent child quota holds release once. `handoff_committed` usage holds stay held until `openmettle_gateway` supplies an authoritative final report (including zero-charge final proof). `handoff_committed` device holds stay held until durable V1-18 confirmation of release or non-allocation. Run-linked `storage_reservations` stay held while any linked operation is `intent` or `outcome_unknown`, or while `revisions/<id>` exists on disk awaiting SQL settlement. |

**Independent drift verification and restore validation.** PR2 adds a read-only
`verify_accounting_drift` check that workers run on a bounded maintenance interval and operators
run during restore validation before reopening dispatch
([Architecture backup and restore](../../ARCHITECTURE-v1.md#backup-and-restore)). Because
Migration `0023` does **not** grant `openmettle_worker` direct `SELECT` on
`openmettle.gateway_usage_reports` (or other gateway tables), the SQL half runs through a narrow
read-only `SECURITY DEFINER` (`SET search_path = pg_catalog`, `STABLE`, owned by
`openmettle_owner`) function **`openmettle.quota_verify_accounting_drift()`** granted `EXECUTE`
only to `openmettle_worker` (plus `openmettle_owner` / operator diagnostics; zero grant to
`openmettle_api`, `openmettle_gateway` or `openmettle_issuance`), returning only aggregate and
mismatch summaries without exposing raw gateway rows:

1. **Storage DB consistency (inside `quota_verify_accounting_drift()`):** compares
   `storage_accounts` and `storage_instance` counters (`active_bytes`, `retained_bytes`,
   `reserved_bytes`) against sums recomputed from `artifact_revisions` (`state = 'active'` and
   `state IN ('retained', 'purging')`) and `storage_reservations` (`state = 'reserved'`).
2. **Storage DB-to-filesystem verification (`artifact_fs`):** first verifies non-null pinned
   `storage_instance.volume_id` <-> `<root>/.openmettle-volume-id` (`O_NOFOLLOW`) and exact
   `st_dev` match with open `revisions/` and `staging/` directory FDs (failing restore validation
   immediately when `volume_id IS NULL` or on missing, mismatched or different-`st_dev` sentinels):
   - *Active and retained revisions:* every `artifact_revisions` row in `state IN ('active',
     'retained')` MUST have a matching regular (non-symlink) file at `revisions/<reservation_id>`
     whose on-disk length equals `size_bytes`. Any missing, symlinked or wrong-sized payload for
     an `active` or `retained` revision is a **hard drift failure** that fails restore validation.
   - *Mid-purge crash state (`state = 'purging'`):* because `artifact_fs::purge_due` commits
     `storage::begin_purge` (`state = 'purging'`), unlinks `revisions/<reservation_id>` on disk
     and confirms `storage::confirm_purge` (`state = 'purged'`) in a second transaction
     ([`src/artifact_fs.rs`](../../src/artifact_fs.rs)), `revisions/<reservation_id>` being absent
     (`ENOENT` / `NotFound`) for a `purging` revision is recognized as a **valid mid-purge crash
     state**, not a hard restore failure. Restore validation verifies that any still-present file
     for a `purging` row is a regular file of `size_bytes` and reports `ENOENT` `purging` rows as
     resumable pending-confirmation purges so `purge_due` / `confirm_purge` can finish decrementing
     `retained_bytes` and re-verify storage accounting rather than blocking restore.
   - *Unsettled published payloads and orphan scan:* any `revisions/<id>` paired with
     `storage_reservations.state = 'reserved'` (post-rename, pre-settlement crash window) is
     reported explicitly as an unsettled published payload requiring deterministic retry settlement
     or operator reconciliation (never silently unlinked or released). Any file in `revisions/`
     lacking a matching `active`/`retained`/`purging` revision or `reserved` reservation, and any
     file in `staging/` lacking a matching `reserved` reservation (after worker startup/retryable
     cleanup of `released` rows), fails as an unreferenced orphan.
3. **Usage and device budget verification (inside `quota_verify_accounting_drift()`):** compares
   every `quota_budgets.reserved_held` row against `SUM(qr.held_units)` joined via
   `quota_reservation_charges` for `qr.state IN ('held', 'handoff_committed')`, compares
   `quota_budgets.active_used` against both `SUM(quota_reconciliations.delta_active)` and
   accepted Migration `0023` `openmettle.gateway_reservations` / `openmettle.gateway_requests` /
   `openmettle.gateway_usage_reports` / `openmettle.gateway_settlements` evidence, and verifies
   every `released` or `settled` reservation has `closed_at IS NOT NULL`.

Any hard drift mismatch raises an operational alert or fails restore validation. Runtime roles
never silently rewrite counters to mask drift; repair is an explicit `openmettle_owner` procedure.

## Renewal, stale recovery and database privileges

Every unsettled hold binds its `lease_expires_at` to the lifecycle of its live owner:

- **Multipart uploads (`storage_reservations`, `run_id IS NULL`).** Set `lease_expires_at =
  clock_timestamp() + UPLOAD_TIMEOUT + 300 s` (900 s, ADR 0031). Legacy upload rows with
  `lease_expires_at IS NULL` keep ADR 0031's `created_at + 900 s` rule.
- **Queued, leased and approval-waiting runs.** Admission sets `lease_expires_at` on run-linked
  holds to `queue_expires_at + 60 s`. When a worker claims or renews a run lease (ADR 0033,
  every `L/3`), it renews `lease_expires_at` on the run's active `held` reservations up to
  `execution_expires_at`. When parking for human approval (ADR 0035), the worker sets
  `lease_expires_at` on the run's active holds (including `StorageReservation` spills) to
  `resume_execution_expires_at` so a valid approval wait never expires its quota hold early.
- **Legacy run-linked storage rows (`run_id IS NOT NULL AND lease_expires_at IS NULL`).** Never
  expire while the linked run is non-terminal or has any `intent` or `outcome_unknown` operation.
  Derive eligibility only once the linked run is terminal (`succeeded`, `failed`, `cancelled`,
  `interrupted`) AND has zero unresolved operations, after a `900 s` grace window past
  `greatest(storage_reservations.created_at, coalesce(runs.execution_expires_at,
  runs.queue_expires_at, runs.created_at))`.
- **Gateway and device handoffs (`handoff_committed`).** Transitioning to `handoff_committed`
  freezes automatic expiry release. `lease_expires_at` becomes the overdue-reconciliation
  threshold for operator visibility and ADR 0037 backfill prioritization.

### Bounded stale-reservation recovery sweep

PR2 adds a `reconcile_stale_quotas(pool, store, limit)` sweep to `src/worker.rs` running on the
ADR 0033 `SWEEP_MS` maintenance interval (**default 60 s**, range `1,000–3,600,000 ms`, matching
[`README.md`](../../README.md)), with a **15 s per-sweep time budget** and batch size `1–1000`
(default `100`, alongside `artifact_fs::reconcile_expired` and `artifact_fs::purge_due`). To
eliminate cross-item budget deadlocks, lock-timeout stalls and head-of-line starvation — even
under continuously arriving tail expiries — every sweep phase separates non-locking bounded-pass
candidate scanning from **one-reservation-per-transaction** settlement:

1. **Non-storage holds (`quota_reservations`).**
   - *Bounded-pass starvation-free scan (`pass_upper_bound`):* At the start of each logical pass
     (starting from `last_attempted = ('-infinity'::timestamptz,
     '00000000-0000-0000-0000-000000000000'::uuid)`), capture a fixed snapshot upper bound
     `pass_upper_bound = (clock_timestamp(), 'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid)`. In a
     short plain non-locking read-only `SELECT`, fetch up to `batch_size` (`limit`) candidate
     `(id, lease_expires_at)` rows with `state = 'held' AND (lease_expires_at, id) >
     last_attempted AND (lease_expires_at, id) <= pass_upper_bound`, filtered **before `LIMIT`**
     to require either `run_id IS NULL` or a terminal linked run (`state IN ('succeeded',
     'failed', 'cancelled', 'interrupted')`) with `NOT EXISTS` any linked operation in
     `('intent', 'outcome_unknown')`, ordered by `(lease_expires_at ASC, id ASC)`. Advance
     `last_attempted` after each attempted item, persisting `(last_attempted, pass_upper_bound)`
     in memory across `SWEEP_MS` ticks whenever the **15 s sweep budget** expires mid-pass. Wrap
     `last_attempted` back to `('-infinity'::timestamptz,
     '00000000-0000-0000-0000-000000000000'::uuid)` and capture a fresh `pass_upper_bound`
     whenever a query returns fewer than `batch_size` rows **or** `last_attempted` reaches
     `pass_upper_bound`. Freezing `pass_upper_bound` prevents newly expiring tail rows from
     keeping later pages full indefinitely, guaranteeing bounded pass completion and eventual
     revisit of any early `SKIP LOCKED` row once its lock clears.
   - *One reservation per short transaction (via `SECURITY DEFINER`):* `openmettle_worker` holds
     `SELECT` only on `quota_reservations` and executes **no direct `SELECT ... FOR NO KEY UPDATE`**
     on any `quota_*` table. For each candidate, the worker opens a bounded `READ COMMITTED`
     transaction and invokes `openmettle.quota_release_unsent(...)` (`SECURITY DEFINER`,
     `SET search_path = pg_catalog`, owned by `openmettle_owner`) in sweep mode. Internally,
     `quota_release_unsent` acquires locks in canonical order — `runs` (`FOR NO KEY UPDATE SKIP
     LOCKED` when `run_id IS NOT NULL`) -> `gateway_reservations` (`FOR NO KEY UPDATE SKIP LOCKED`
     when `gateway_request_id IS NOT NULL`) -> `gateway_requests` (`FOR NO KEY UPDATE SKIP LOCKED`
     when `gateway_request_id IS NOT NULL`) -> parent `quota_reservations` (if child, `FOR NO KEY
     UPDATE SKIP LOCKED`) -> target `quota_reservations` (`FOR NO KEY UPDATE SKIP LOCKED`) —
     returning immediately as skipped without waiting if any row is contended. Once locked, it
     re-verifies `state = 'held'`, expiry, terminal run state and zero unresolved operations. When
     `gateway_request_id IS NOT NULL`, `quota_release_unsent` **explicitly re-verifies
     `(q.scope_id, q.actor_user_id) = (qr.scope_id, qr.actor_user_id) AND q.run_id IS NOT
     DISTINCT FROM qr.run_id` under lock before modifying either ledger** (raising an invariant
     error and mutating neither ledger on mismatch); it then checks `gateway_requests.state`:
     - if `gateway_requests.state = 'released'`, the gateway request is already closed and
       non-dispatchable, so `quota_release_unsent` proceeds to release the local
       `quota_reservations` hold;
     - if `gateway_requests.state = 'reserved'` (and stale expiry / terminal run preconditions
       hold), `quota_release_unsent` **atomically transitions `gateway_requests.state = 'released'`
       and restores its held units to `gateway_reservations` (`allocated = allocated - req.units`)
       in the exact same transaction** as releasing the local `quota_reservations` hold (without
       needing the caller's lost dispatch secret, because `quota_release_unsent` executes under
       `SECURITY DEFINER`), ensuring any delayed `openmettle.gateway_handoff` call fails closed;
     - if `gateway_requests.state = 'handed_off'`, `quota_release_unsent` leaves the local
       `quota_reservations` hold untouched for gateway reconciliation.
     When eligible, it locks charged `quota_budgets` via `quota_reservation_charges` (scope rows
     ascending then instance row last), inserts `quota_reconciliations` (`source_key =
     'stale_sweep'`), decrements `reserved_held` and sets `state = 'released'`, `held_units = 0`
     and `closed_at = clock_timestamp()`.
   - *Pre-upgrade / orphan `'reserved'` `gateway_requests` defense-in-depth sweep
     (`openmettle.quota_release_orphan_gateway_requests`, bounded raw index-key paging):* Although
     PR2 inserts `gateway_requests` and all bound metered `quota_reservations` atomically in one
     `WriteTransaction` via `authz::gateway::reserve_in`, rolling upgrades or pre-V1-17 crashes
     can leave `'reserved'` `gateway_requests` rows created before `quota_reservations` existed
     (stranding `gateway_reservations.allocated` and occupying Migration `0023`'s partial unique
     index `gateway_requests_run_round_active_idx` with zero bound `quota_reservations` rows).
     Because Migration `0023` grants `openmettle_worker` zero direct `SELECT` on
     `gateway_requests`, PR2 provides a bounded `SECURITY DEFINER` sweep helper
     **`openmettle.quota_release_orphan_gateway_requests(p_max_reserved_age interval,
     p_after_created_at timestamptz, p_after_id uuid, p_pass_upper_created_at timestamptz,
     p_pass_upper_id uuid, p_page_size integer)`** (owned by `openmettle_owner`, `SET search_path
     = pg_catalog`, `REVOKE ALL FROM PUBLIC`, granted `EXECUTE` only to `openmettle_worker`). To
     prevent an aged prefix of legitimately bound `'reserved'` entries from causing an unbounded
     index scan before `LIMIT`, each call **first materializes a bounded page of at most
     `p_page_size` raw `(created_at, id)` index keys** directly from Migration `0023`'s
     `gateway_requests_reserved_idx` (`WHERE state = 'reserved' AND created_at <= clock_timestamp()
     - p_max_reserved_age AND (created_at, id) > (p_after_created_at, p_after_id) AND (created_at,
     id) <= (p_pass_upper_created_at, p_pass_upper_id) ORDER BY created_at ASC, id ASC LIMIT
     p_page_size` — never applying `NOT EXISTS` before `LIMIT`). Only on those `<= p_page_size`
     materialized keys does it test binding absence (`NOT EXISTS (SELECT 1 FROM
     openmettle.quota_reservations qr WHERE qr.gateway_request_id = q.id)`) and (when `q.run_id IS
     NOT NULL`) run-lease/terminal eligibility, releasing at most one eligible orphan per short
     transaction by locking `(runs ->) gateway_reservations -> gateway_requests` with `FOR NO KEY
     UPDATE SKIP LOCKED`, re-verifying all preconditions under lock, transitioning `state :=
     'released'` and restoring `gateway_reservations.allocated = allocated - q.units`. Each call
     returns `(next_created_at, next_id, raw_keys_scanned, released_count)` and **always advances
     the persistent `(last_created_at, last_id)` cursor to the last inspected key of that
     `p_page_size` page even when the page contains zero orphans** (wrapping back to `('-infinity',
     nil UUID)` with a fresh `pass_upper_bound` only when fewer than `p_page_size` raw index keys
     were returned and all keys in that partial page were inspected, or when the cursor reaches
     `pass_upper_bound`).
2. **Storage holds (`storage_reservations`) and retention purges (`artifact_revisions`).**
   - *Durable artifact volume identity (`storage_instance.volume_id` <-> `<root>/.openmettle-volume-id`):*
     If the artifact volume unmounts, an ordinary empty `revisions/` directory can remain at the
     mount point — or `Store::open` ([`src/artifact_fs.rs`](../../src/artifact_fs.rs)) can create
     empty `staging/` and `revisions/` directories on worker restart — causing an open `revisions/`
     directory handle and `fstatat("<id>")` (or `N-1`'s `remove()` treating `ErrorKind::NotFound`
     as `Ok(())` in `reconcile_expired` and `purge_due`) to succeed while the original volume still
     holds the published payload. On a populated pre-V1-17 upgrade (`storage_instance.volume_id IS
     NULL`), naive auto-pinning would create `<root>/.openmettle-volume-id` on an empty replacement
     directory, and an unquiesced `N-1` worker could release `storage_reservations` or confirm
     `artifact_revisions` `'purged'` transitions against an empty mount. PR2 closes every layer
     with a durable volume identity sentinel between PostgreSQL
     (`openmettle.storage_instance.volume_id uuid`) and the artifact root
     (`<root>/.openmettle-volume-id`, regular file, `O_NOFOLLOW`, canonical lowercase UUID) plus a
     PostgreSQL `BEFORE UPDATE` worker volume-pin guard:
     - **Automatic pinning restricted strictly to an empty storage ledger
       (`storage_instance.volume_id IS NULL`), plus operational quiescing and PostgreSQL guard for
       `N-1` workers:** `openmettle.storage_pin_volume_id(uuid)` (locking
       `openmettle.storage_instance FOR UPDATE`) and `Store::open` bootstrap auto-pinning are
       permitted **ONLY when BOTH `NOT EXISTS (SELECT 1 FROM openmettle.storage_reservations)` AND
       `NOT EXISTS (SELECT 1 FROM openmettle.artifact_revisions)`**. On an empty fresh
       installation, `Store::open` creates `<root>/.openmettle-volume-id` exclusively (`O_CREAT |
       O_EXCL | O_NOFOLLOW`, mode `0600`), `fsync`s the sentinel and `<root>`, and pins that UUID
       write-once via `openmettle.storage_pin_volume_id(uuid)` (or reads an existing sentinel and
       pins it); if another replica concurrently pinned a different `volume_id`, startup refuses to
       proceed. If **any** row exists in `openmettle.storage_reservations` or
       `openmettle.artifact_revisions` while `storage_instance.volume_id IS NULL`:
       1. `openmettle.storage_pin_volume_id(uuid)` refuses with `ERRCODE = 'OMQ03'` and
          `Store::open` **MUST NOT** write `<root>/.openmettle-volume-id` on an unverified
          directory.
       2. All PR2 (`N`) worker storage cleaners — explicitly including **`artifact_fs::purge_due`**
          alongside `artifact_fs::reconcile_expired`, run-linked `ENOENT` storage recovery and
          `staging/` `ReadDir` cleanup — **remain disabled (fail closed with zero released holds,
          zero `begin_purge`/`confirm_purge` transitions and zero unlinked files)** while
          `storage_instance.volume_id IS NULL`.
       3. On populated upgrades, operators quiesce worker artifact cleaners
          (`OPENMETTLE_WORKER_ARTIFACTS_DIR` unset or workers scaled to `0` across migration +
          verified volume adoption), **AND** PR2's migration installs the `SECURITY DEFINER`
          `BEFORE UPDATE` trigger `openmettle.enforce_worker_storage_volume_pinned()` (`OMQ03`) on
          **both** `openmettle.storage_reservations` (`WHEN (OLD.state = 'reserved' AND NEW.state =
          'released')`) and `openmettle.artifact_revisions` (`WHEN (NEW.state IN ('purging',
          'purged'))`). Whenever `pg_has_role(session_user, 'openmettle_worker', 'USAGE')` holds
          and `(SELECT volume_id FROM openmettle.storage_instance WHERE id) IS NULL`, PostgreSQL
          aborts the update with `OMQ03` — ensuring even an unquiesced `N-1` worker running
          `reconcile_expired` or `purge_due` against an empty replacement mount fails closed
          without releasing a reservation or confirming a purge, while disjoint `openmettle_api`
          (ADR 0003) keeps in-flight upload abort/failure cleanup working.
     - **Verified, idempotent volume adoption required on populated upgrades
       (`storage_instance.volume_id IS NULL` with existing ledger rows):** Enabling storage
       cleaners on a populated upgraded installation requires an explicit verified volume-adoption
       step (executed by `openmettle_owner` / operator CLI `openmettle-admin` procedure documented
       in PR2's operator runbook update) **before** `Store::open` directory creation. Every
       invocation (including operator retries after a crash or lost DB connection following
       sentinel `fsync`) executes the complete idempotent sequence:
       1. *Pre-existing directory & single-device check:* Open `<root>`, `<root>/staging`, and
          `<root>/revisions` with `O_RDONLY | O_DIRECTORY | O_NOFOLLOW` (never auto-creating
          directories during adoption) and verify all three share the exact same `st_dev`.
       2. *Ledger payload verification (aligned with restore validation for `purging`):* Every
          `openmettle.artifact_revisions` row in `state IN ('active', 'retained')` **MUST** exist
          relative to `<root>/revisions` (`AT_SYMLINK_NOFOLLOW` regular file with exact
          `size_bytes`, plus sampled SHA-256 `content_digest` verification). Revisions in `state =
          'purging'` may be **either** present (regular file of exact `size_bytes`) **or** already
          unlinked (`ENOENT` from a mid-purge crash in `artifact_fs::purge_due`) once the volume's
          identity has been independently verified (by the `active`/`retained` revisions on disk,
          or by operator-verified volume/`staging/` evidence when zero `active`/`retained`
          revisions exist), and their byte charges remain retained until `purge_due` confirms
          `state = 'purged'` after adoption completes.
       3. *Idempotent sentinel creation / verification & DB pin:* Attempt `O_WRONLY | O_CREAT |
          O_EXCL | O_NOFOLLOW` (mode `0600`) on `<root>/.openmettle-volume-id`, writing a fresh
          canonical lowercase UUID (`sentinel_uuid`) and `fsync`ing the sentinel + `<root>`. If
          creation returns `EEXIST` (e.g., operator retry after a prior run crashed between
          sentinel `fsync` and PostgreSQL commit), open `<root>/.openmettle-volume-id` with
          `O_RDONLY | O_NOFOLLOW`, verify it is a regular file on the exact same `st_dev`
          containing a valid canonical lowercase UUID (`existing_uuid`, adopting `sentinel_uuid =
          existing_uuid`), and `fsync` the sentinel + `<root>` (failing closed if symlinked,
          non-regular, wrong `st_dev` or malformed). Then lock `openmettle.storage_instance FOR
          UPDATE` as `openmettle_owner`: if `volume_id IS NULL`, pin `volume_id = sentinel_uuid`;
          if `volume_id = sentinel_uuid`, succeed idempotently as a no-op; if `volume_id <>
          sentinel_uuid`, fail closed (`ERRCODE = 'OMQ03'`).
     - **Fail-closed verification once pinned (`storage_instance.volume_id IS NOT NULL`):** Once
       `storage_instance.volume_id` is non-null in PostgreSQL, `Store::open` and **every** worker
       cleaner — explicitly including **`artifact_fs::purge_due`**, `artifact_fs::reconcile_expired`,
       run-linked `ENOENT` storage recovery and `staging/` `ReadDir` cleanup — **MUST refuse to
       initialize a fresh sentinel** (and must not accept a newly created or empty replacement
       directory) and **MUST verify** that: (a) `<root>/.openmettle-volume-id` exists as a regular
       file opened with `O_RDONLY | O_NOFOLLOW` and matches non-null `storage_instance.volume_id`,
       and (b) its `fstat` device ID (`st_dev`) equals the exact `st_dev` of both the open
       `<root>/revisions` (`O_RDONLY | O_DIRECTORY | O_NOFOLLOW`) and `<root>/staging` (`O_RDONLY |
       O_DIRECTORY | O_NOFOLLOW`) directory file descriptors before unlinking relative to the
       verified directory FD or committing `begin_purge` / `confirm_purge` / `storage::release`. If
       the sentinel is missing, unreadable, symlinked/non-regular, mismatched or on a different
       `st_dev`, startup and all cleaners **fail closed immediately** with **zero released holds
       and zero confirmed purges**.
   - *Non-run uploads (`run_id IS NULL`) and retention purges (`artifact_fs::purge_due`):*
     Non-run uploads continue through `artifact_fs::reconcile_expired` and retention purges
     continue through `artifact_fs::purge_due` — **both** requiring configured
     `OPENMETTLE_WORKER_ARTIFACTS_DIR` and verified non-null pinned volume sentinel + `st_dev`
     identity across `<root>/.openmettle-volume-id`, `<root>/revisions` and `<root>/staging` before
     unlinking relative to the verified directory FD or committing `storage::release`,
     `storage::begin_purge` or `storage::confirm_purge`. `reconcile_expired` honors
     `coalesce(lease_expires_at, created_at + interval '900 seconds') <= clock_timestamp()`,
     locking one reservation `FOR UPDATE SKIP LOCKED` per transaction while unlinking its
     unsettled staging/upload paths relative to the verified FD before `storage::release`.
   - *Run-linked storage holds (`run_id IS NOT NULL`):* Requires configured
     `OPENMETTLE_WORKER_ARTIFACTS_DIR` (`ARTIFACTS_DIR`, `artifact_fs::Store`) with verified
     non-null pinned `storage_instance.volume_id` sentinel identity. If `ARTIFACTS_DIR` is
     unavailable, unset, `storage_instance.volume_id IS NULL`, or sentinel/`st_dev` verification
     fails, run-linked storage recovery **MUST NOT** call `storage::release` and skips this phase
     without mutating any reservation. Otherwise, scan
     candidates with `state = 'reserved'`, filtered **before `LIMIT`** for terminal linked runs,
     zero `intent`/`outcome_unknown` operations and expired `lease_expires_at` (or legacy
     `lease_expires_at IS NULL` meeting the terminal-run grace rule above), using the same
     bounded-pass cursor `(coalesce(lease_expires_at, created_at), id) > last_attempted AND
     (coalesce(lease_expires_at, created_at), id) <= pass_upper_bound ORDER BY
     coalesce(lease_expires_at, created_at) ASC, id ASC LIMIT batch_size`, advancing
     `last_attempted` after each attempted item across `SWEEP_MS` ticks (60 s default interval,
     15 s per-sweep budget) and wrapping to `(-infinity, nil UUID)` with a fresh
     `pass_upper_bound` whenever a query returns fewer than `batch_size` rows or reaches
     `pass_upper_bound`. Process **one reservation per short transaction**:
     1. Lock `runs` (`FOR NO KEY UPDATE SKIP LOCKED`) -> `storage_reservations` (`FOR UPDATE SKIP
        LOCKED`). If either row is contended, skip immediately without blocking.
     2. Re-verify under lock that `state = 'reserved'`, expiry holds, the run is terminal (no
        active worker lease) and zero linked operations are in `('intent', 'outcome_unknown')`.
     3. Verify the pinned volume sentinel, live `revisions/` and `staging/` directory handles and
        inspect leaf `<id>` relative to `revisions/`:
        - **Fail-closed volume sentinel and `revisions/` verification:** Before inspecting leaf
          `<id>`, recovery MUST open `<root>/.openmettle-volume-id` (`O_RDONLY | O_NOFOLLOW`),
          `<root>/revisions` (`O_RDONLY | O_DIRECTORY | O_NOFOLLOW`) and `<root>/staging`
          (`O_RDONLY | O_DIRECTORY | O_NOFOLLOW`), verify that the sentinel matches non-null
          `storage_instance.volume_id` and that all three FDs share the exact same `st_dev`. Any
          error, `volume_id IS NULL`, missing/unmounted directory, missing/mismatched sentinel or
          `st_dev` mismatch **fails closed immediately** with zero released holds.
        - **Directory-relative `ENOENT` proof required before release:** Perform the leaf `<id>`
          lookup relative to that verified `revisions/` directory handle (`openat` / `fstatat`
          with `AT_SYMLINK_NOFOLLOW`). Only when the volume sentinel + `st_dev` verification
          succeeds AND that directory-relative probe returns `ENOENT` (confirming atomic rename
          `staging/<id> -> revisions/<id>` never occurred on the pinned mounted volume and no
          published bytes still owe SQL settlement) may recovery execute and **commit
          `storage::release`** (or confirm `state = 'released'`), and then — only after commit —
          unlink `staging/<id>` relative to the verified `staging/` FD if present.
        - **Post-rename, pre-settlement crash window (`revisions/<id>` present):** If leaf `<id>`
          exists inside `revisions/` while `storage_reservations.state = 'reserved'` (or if the
          directory-relative probe returns any error other than `ENOENT`), recovery **MUST NOT**
          call `storage::release` and **MUST NOT** unlink `revisions/<id>`. Calling
          `storage::release` would release the held bytes and cause a later `storage::settle` to
          conflict while leaving an uncharged payload on disk. Recovery preserves both the
          `reserved` byte hold and `revisions/<id>` (surfacing overdue/drift visibility) until
          deterministic retry settlement (where durable artifact/spill context exists) settles it
          into `artifact_revisions` or explicit `openmettle_owner` reconciliation settles or
          purges it.
   - *Retryable `staging/` cleanup after post-release crashes (persistent `StagingSweepState` across
     `worker::sweep`'s 15 s outer `tokio::time::timeout`):*
     Because a worker may crash after committing `storage::release` (`state = 'released'`) and
     before unlinking `staging/<id>`, a sweep querying only `state = 'reserved'` would skip that
     `released` row permanently and leave an orphan `staging/<id>` file that fails
     `verify_accounting_drift`. Conversely, reading an entire large or slow `staging/` directory
     into memory and sorting it before applying a filename cursor could exhaust the entire 15 s
     sweep budget before advancing — and in [`src/worker.rs`](../../src/worker.rs), `worker::sweep`
     wraps each tick's future in `tokio::time::timeout(Duration::from_secs(15), work)`. If a single
     `<= 64`-entry `spawn_blocking` `readdir` slice exceeds 15 s on a slow/wedged volume, a
     locally owned `JoinHandle` would be dropped when `timeout` cancels the future, discarding both
     the `ReadDir` handle and its returned entries (forcing restart from entry 0 or leaking
     overlapping `spawn_blocking` readers). On startup recovery and during bounded worker storage
     sweeps, `worker::maintenance` therefore holds a persistent **`StagingSweepState`** across
     `SWEEP_MS` ticks **outside** the per-tick `tokio::time::timeout` future, owning **at most one
     in-flight `JoinHandle<io::Result<(ReadDir, Vec<String>, bool)>>` (`InFlight { dir_dev,
     dir_ino, handle }`)** (alongside `Idle` and `Open { dir_dev, dir_ino, reader }`) plus a
     **`VecDeque<String>` of undrained `pending_names`**:
     - At the start of each tick, verify `<root>/.openmettle-volume-id`, `<root>/revisions`, and
       `<root>/staging` (`O_NOFOLLOW`), confirming non-null pinned `storage_instance.volume_id` and
       `st_dev` equality across all three plus unchanged `(dir_dev, dir_ino)` of `<root>/staging`
       against any parked `Open`/`InFlight` state (failing closed with zero unlinks if verification
       fails; dropping the parked state, clearing `pending_names`, and resetting to `Idle` if
       `<root>/staging`'s `(dir_dev, dir_ino)` changed).
     - If `StagingSweepState` is `InFlight { dir_dev, dir_ino, handle }`, **first await the parked
       `&mut handle`** (never spawning a second concurrent `ReadDir` task; if the wedged slice
       exceeds this tick's 15 s `timeout` again, `InFlight` remains parked in `StagingSweepState`).
       When `handle` resolves, append its returned canonical UUIDs to `pending_names` and
       transition to `Open { dir_dev, dir_ino, reader }` (or `Idle` when the returned `eof` boolean
       is `true`).
     - Drain `pending_names` in bounded batches against `openmettle.storage_reservations` (`WHERE
       id = ANY($1)`) **exactly once** (popping entries only as processed, checking `Instant::now()
       < sweep_deadline` and `inspected_entries < batch_size`), idempotently unlinking
       `staging/<id>` relative to the verified `staging/` FD whenever the matching row is already
       `state = 'released'` (or `state = 'settled'`), or whenever no `storage_reservations` row
       exists and the file exceeds the `900 s` staging grace window (or during startup recovery).
       Never unlink a `staging/<id>` file whose `storage_reservations` row is still `state =
       'reserved'` outside the verified `reconcile_expired` / run-linked release path above.
     - Only once `pending_names` is empty and budget remains (`Instant::now() < sweep_deadline` and
       `inspected_entries < batch_size`), open a fresh `ReadDir` stream if `Idle` and **transition
       `StagingSweepState` from `Open { dir_dev, dir_ino, reader }` to `InFlight { dir_dev,
       dir_ino, handle }` before awaiting** the single `spawn_blocking` slice (at most `64`
       directory entries), so any 15 s `tokio::time::timeout` cancellation mid-slice leaves
       `InFlight` parked for the next tick rather than dropping the `ReadDir` stream or entries.
     - Stop the tick as soon as `Instant::now() >= sweep_deadline` (15 s budget) or
       `inspected_entries >= batch_size`, `fsync`ing `staging/` after any unlinks while preserving
       `StagingSweepState` (`Open`, `InFlight`, and any remaining `pending_names`) across ticks.
       When a slice yields `eof = true` and `pending_names` finishes draining, `fsync` `staging/`
       after any unlinks and leave `StagingSweepState` in `Idle` so a subsequent tick starts the
       next pass.
3. **Overdue post-handoff visibility.** A separate read-only bounded query counts
   `quota_reservations` in `state = 'handoff_committed'` with `lease_expires_at <=
   clock_timestamp()` and emits a low-cardinality telemetry gauge/counter registered under
   [ADR 0028](0028-telemetry-contract-and-metrics.md) without modifying any row.

### Database privileges (`src/boundaries.sql`) and rolling-upgrade safety

PR2 requires Migration `0023` (`V1-06` `openmettle_gateway` role provisioning) to have applied
first and version-gates every new table, trigger, column and function grant in
[`src/boundaries.sql`](../../src/boundaries.sql) ([ADR 0003](0003-schema-migrations.md)).

To prevent any runtime role from mutating another role's resource kinds, bypassing override or
dispatch invariants, forging settled usage, releasing post-handoff holds or bypassing V1-18 device
confirmation, **zero runtime roles hold direct `INSERT`, `UPDATE` or `DELETE` privileges on any
`quota_*` table (`quota_defaults`, `quota_cost_unit_lock`, `quota_enforcement`, `quota_overrides`,
`quota_budgets`, `quota_reservations`, `quota_reservation_charges`, `quota_reconciliations` or
`quota_warning_events`), and zero runtime roles hold even `SELECT` on `quota_cost_unit_lock`.**
Because PostgreSQL 18 requires `UPDATE` privilege to execute `SELECT ... FOR NO KEY UPDATE` or
`FOR UPDATE`, **no runtime role executes direct row-locking `SELECT` on any `quota_*` table**
either; all `quota_*` row locking and writes (as well as `quota_cost_unit_lock` locking inside the
`gateway_usage_reports_cost_unit_guard` trigger, gateway-binding verification inside
`quota_reservations_gateway_binding_guard`, commit-time handoff hold verification inside
`quota_enforce_gateway_handoff_holds` / `enforce_gateway_handoff_holds()`, unpinned worker storage
guarding inside `enforce_worker_storage_volume_pinned()`, and empty-ledger-only
`storage_instance.volume_id` bootstrapping) run strictly inside narrow `openmettle_owner`-owned
`SECURITY DEFINER` functions with `SET search_path = pg_catalog`, schema-qualified relations,
`REVOKE ALL ON FUNCTION ... FROM PUBLIC` and exact `oid::regprocedure` signatures audited in
`src/boundaries.sql` (following [ADR 0030](0030-session-issuance-database-boundary.md) and
ADR 0037). Neither `openmettle_api` nor `openmettle_worker` receives direct `SELECT` privileges on
Migration `0023`'s `openmettle.gateway_requests` or `openmettle.gateway_usage_reports` (or other
gateway tables): lost commit-ack handoff recovery runs solely through
`openmettle.quota_recover_lost_handoff(...)`, fenced successor-worker superseded-round unwind runs
solely through `openmettle.quota_unwind_superseded_round(...)`, pre-upgrade orphan `'reserved'`
gateway sweep runs solely through `openmettle.quota_release_orphan_gateway_requests(...)`, and SQL
drift verification runs solely through `openmettle.quota_verify_accounting_drift()`.

| Object or `SECURITY DEFINER` entrypoint | `openmettle_api` | `openmettle_worker` | `openmettle_gateway` (Migration `0023`) | `openmettle_issuance` (ADR 0030) |
| --- | --- | --- | --- | --- |
| `quota_defaults` | `SELECT` only | `SELECT` only | `SELECT` only | None |
| `quota_cost_unit_lock` | None | None | None (locked internally by `SECURITY DEFINER` trigger `enforce_gateway_report_cost_unit()`) | None |
| `quota_enforcement` | `SELECT` only | `SELECT` only | `SELECT` only | None |
| `quota_overrides` | `SELECT` only | `SELECT` only | `SELECT` only | None |
| `quota_budgets`, `quota_reservations`, `quota_reservation_charges`, `quota_reconciliations`, `quota_warning_events` | `SELECT` only | `SELECT` only | `SELECT` only | None |
| `openmettle.storage_pin_volume_id(uuid)` | `EXECUTE` (locks `storage_instance FOR UPDATE`; permits write-once `volume_id` pinning **only** while `volume_id IS NULL` AND BOTH `NOT EXISTS (SELECT 1 FROM openmettle.storage_reservations)` AND `NOT EXISTS (SELECT 1 FROM openmettle.artifact_revisions)`, refusing populated upgrades with `OMQ03`; never modifies or clears a non-null `volume_id`) | `EXECUTE` (same) | None | None |
| `openmettle.quota_upsert_scope_override(...)` and `openmettle.quota_revoke_scope_override(...)` | `EXECUTE` (validates caller role & scope/kind/bounds invariants, requiring `('instance', 'usage_cost_micros').cost_denomination IS NOT NULL` for `usage_cost_micros`; locks `run_dispatch_lock` for `executing_runs_*`, `projects`/`users`, and `storage_accounts` or active `quota_budgets` in canonical order; upserts/revokes `quota_overrides` and increments `revision` to re-arm warning watermarks) | None | None | None |
| `openmettle.quota_reserve(...)` | `EXECUTE` (tags `origin_role = 'api'`; when `gateway_request_id IS NOT NULL`, executes in the same `WriteTransaction` as `authz::gateway::reserve_in`, verifying `gateway_requests` ownership `(scope_id, actor_user_id, run_id IS NULL)`, `state = 'reserved'`, and 32-byte `p_dispatch` matching `dispatch_hash = sha256(p_dispatch)` reinforced by `quota_reservations_gateway_binding_guard`; locks `quota_budgets` internally and records `quota_warning_events`) | `EXECUTE` (tags `origin_role = 'worker'`; locks `quota_budgets` internally and records `quota_warning_events`) | None | None |
| `openmettle.quota_allocate_round(...)` | None | `EXECUTE` (executes in the same `WriteTransaction` as `authz::gateway::reserve_in`; verifies active `Step` lease on `runs`, `'reserved'` `gateway_requests` row matching `(scope_id, actor_user_id, run_id)`, and 32-byte `p_dispatch` matching `dispatch_hash = sha256(p_dispatch)` reinforced by `quota_reservations_gateway_binding_guard`; creates child `quota_reservations` row in `state = 'held'` via parent-to-child slice transfer with zero net budget debit) | None | None |
| `openmettle.quota_commit_handoff(...)` | `EXECUTE` (own `origin_role = 'api'` standalone `run_id IS NULL` `held` rows only; requires `gateway_requests.state = 'handed_off'` from `authz::gateway::handoff_in` / `openmettle.gateway_handoff` in the same tx for metered usage holds, verified at `COMMIT` by deferred `quota_enforce_gateway_handoff_holds`; **explicitly rejects all run-linked `device_reservations` holds (`run_id IS NOT NULL`, SQLSTATE `42501`)**) | `EXECUTE` (own `origin_role = 'worker'` `held` rows only, including run-round metered usage holds requiring `gateway_requests.state = 'handed_off'` from `authz::gateway::handoff_in` / `openmettle.gateway_handoff` in the same tx, verified at `COMMIT` by deferred `quota_enforce_gateway_handoff_holds`; **explicitly rejects all run-linked `device_reservations` holds (`run_id IS NOT NULL`, SQLSTATE `42501`)**) | None | None |
| `openmettle.quota_recover_lost_handoff(uuid, bytea, uuid, uuid, uuid)` (`RETURNS text`) | `EXECUTE` (`p_run_id IS NULL` only; verifies `pg_has_role(session_user, 'openmettle_api', 'USAGE')`, `octet_length(p_dispatch) = 32`, and matching `gateway_requests` `(id, dispatch_hash = sha256(p_dispatch), scope_id, actor_user_id, run_id)`; locks `(runs ->) gateway_reservations -> gateway_requests -> (parent ->) quota_reservations -> quota_budgets` in canonical `FOR NO KEY UPDATE` order; on `'handed_off'`, asserts zero bound holds remain outside `'handoff_committed'`, requires required `'handoff_committed'` holds (`usage_tokens` + applicable `usage_cost_micros`) whenever `metering_enforced = true` (`OMQ04` otherwise), and returns `'handoff_committed'` or `'unmetered_legacy_handoff'` (during pre-activation rolling upgrade while `metering_enforced = false`, keeping HTTP dispatch suppressed); otherwise atomically unwinds `'reserved'`/`'released'` request and bound `'held'` holds returning `'unwound_unsent'`) | `EXECUTE` (`p_run_id IS NOT NULL` only; verifies `pg_has_role(session_user, 'openmettle_worker', 'USAGE')`, `octet_length(p_dispatch) = 32`, and matching `gateway_requests`; same canonical locking and `'handoff_committed'` / `'unmetered_legacy_handoff'` / `'unwound_unsent'` resolution returning round capacity to an active `'held'` parent or restoring `quota_budgets` on terminal runs) | None | None |
| `openmettle.quota_unwind_superseded_round(uuid, uuid, uuid, integer)` (`RETURNS boolean`) | None | `EXECUTE` (fenced successor-worker unwind for a predecessor's crashed post-commit `'reserved'` round; locks `runs -> gateway_reservations -> gateway_requests -> parent & child quota_reservations` (`FOR NO KEY UPDATE`), verifies current live lease `r.claim_token = p_claim_token AND r.state IN ('running', 'cancelling', 'reconciling') AND r.lease_expires_at > clock_timestamp()`, transitions `'reserved'` `gateway_requests` to `'released'`, restores `gateway_reservations.allocated`, releases bound `'held'` child holds back to active `'held'` parent holds returning `true`, or leaves `'handed_off'` untouched returning `false`) | None | None |
| `openmettle.quota_commit_device_handoff(...)` | None | `EXECUTE` (**sole** transition path for run-linked `device_reservations` holds; locks `runs -> quota_reservations` in canonical order; verifies active `Step` lease `runs.state = 'running'`, `runs.cancel_reason IS NULL`, matching `claim_token`, `lease_expires_at > clock_timestamp()`; transitions that run's `device_reservations` `held` row with `origin_role IN ('api', 'worker')` to `handoff_committed` bound to durable `device_grant_id`) | None | None |
| `openmettle.quota_renew_lease(...)` | None | `EXECUTE` (`held` run-linked rows only, fenced to active run lease) | None | None |
| `openmettle.quota_release_unsent(...)` | `EXECUTE` (own `origin_role = 'api'` `held` rows only; explicit pre-send unwind couples with `authz::gateway::release_in` / `openmettle.gateway_release` / requires `gateway_requests.state = 'released'` for gateway-bound holds; re-verifies `(q.scope_id, q.actor_user_id) = (qr.scope_id, qr.actor_user_id) AND q.run_id IS NOT DISTINCT FROM qr.run_id` under lock before mutating either ledger; locks internally and sets `closed_at`) | `EXECUTE` (own `origin_role = 'worker'` `held` or eligible stale/terminal-run `held` rows; explicit pre-send unwind couples with `authz::gateway::release_in` / `openmettle.gateway_release` / verifies `gateway_requests.state = 'released'` and returns round capacity to an active `held` parent or releases on terminal runs; sweep mode locks `(runs ->) gateway_reservations -> gateway_requests -> (parent ->) quota_reservations` with `FOR NO KEY UPDATE SKIP LOCKED`; **explicitly re-verifies `(q.scope_id, q.actor_user_id) = (qr.scope_id, qr.actor_user_id) AND q.run_id IS NOT DISTINCT FROM qr.run_id` under lock** raising an invariant error without mutating either ledger on mismatch; proceeds if `gateway_requests.state = 'released'`, **atomically transitions stale `'reserved'` `gateway_requests` to `'released'` and restores `gateway_reservations.allocated` in the same transaction** when expiry/terminal preconditions hold, leaves `'handed_off'` or locked rows untouched, and sets `closed_at`) | None | None |
| `openmettle.quota_release_orphan_gateway_requests(interval, timestamptz, uuid, timestamptz, uuid, integer)` | None | `EXECUTE` (bounded defense-in-depth sweep materializing at most `p_page_size` raw `(created_at, id)` keys from `gateway_requests_reserved_idx` before testing `NOT EXISTS` bound `quota_reservations` and run-lease/terminal eligibility; locks `(runs ->) gateway_reservations -> gateway_requests` with `FOR NO KEY UPDATE SKIP LOCKED`, transitions `'reserved' -> 'released'`, restores `gateway_reservations.allocated`, and always advances the persistent cursor past inspected pages even on zero-orphan pages) | None | None |
| `openmettle.quota_settle_gateway_usage(...)` | None | None | `EXECUTE` (`usage_tokens`/`usage_cost_micros` only; validates single `openmettle.gateway_usage_reports` row matching `(request_id, source, report_id, revision)` with `revision >= 0`, immutable `cost_denomination` vs `gateway_usage_reports.unit` and `accepted_source_revision IS NULL OR p_source_revision > accepted_source_revision`; persists `accepted_source_revision` atomically with composite-FK `quota_reconciliations` and records `quota_warning_events`) | None |
| `openmettle.quota_release_device_slot(...)` | None | `EXECUTE` (`device_reservations` `handoff_committed` only; verifies durable V1-18 release/non-allocation record; sets `closed_at`) | None | None |
| `openmettle.quota_record_storage_warning(...)` | `EXECUTE` (evaluates storage threshold crossing from locked `storage_accounts`/`storage_instance` and records deduplicated `quota_warning_events`) | `EXECUTE` (same) | None | None |
| `openmettle.quota_verify_accounting_drift()` (`STABLE`) | None | `EXECUTE` (read-only aggregate/mismatch drift summaries across `storage_*`, `quota_*` and Migration `0023`'s `gateway_reservations`/`gateway_requests`/`gateway_usage_reports`/`gateway_settlements` without granting raw table `SELECT` on `gateway_usage_reports`; also callable by `openmettle_owner` during restore validation) | None | None |
| `storage_reservations.lease_expires_at` | `INSERT`, `UPDATE` (with migration 4 grants) | `INSERT`, `UPDATE` (with migration 4 grants; `reserved -> released` guarded by `enforce_worker_storage_volume_pinned()` (`OMQ03`) while `volume_id IS NULL`) | None | None |
| `storage_instance`, `storage_accounts`, `artifacts`, `artifact_revisions` | Existing migration 4 grants (`volume_id`, `warn_pct_*`, `config_revision` `SELECT` only) | Existing migration 4 grants (`volume_id`, `warn_pct_*`, `config_revision` `SELECT` only; `artifact_revisions` transitions to `'purging'`/`'purged'` guarded by `enforce_worker_storage_volume_pinned()` (`OMQ03`) while `volume_id IS NULL`) | None | None |

Only `openmettle_owner` writes `quota_defaults` (updating the migration-seeded `('instance',
'usage_cost_micros')` row strictly via direct `UPDATE` — never `INSERT ... ON CONFLICT` — subject
to `quota_defaults_cost_denomination_immutable` (`OMQ02`) serialized with `quota_cost_unit_lock`,
and acquiring `SELECT FROM openmettle.run_dispatch_lock FOR NO KEY UPDATE` before modifying
`executing_runs_*` defaults), `quota_enforcement` (flipping `metering_enforced` write-once `false
-> true` via `openmettle-admin`, subject to `quota_enforcement_write_once` (`OMQ04`)), and
`storage_instance` limits, warning thresholds and `config_revision` (with
`storage_instance.volume_id` auto-pinned write-once from `NULL` via `storage_pin_volume_id`
strictly on an empty storage ledger, or pinned via `openmettle_owner` idempotent verified volume
adoption on populated upgrades). `openmettle_issuance` receives zero quota or storage privileges.
No runtime role receives `DELETE`, `TRUNCATE`, DDL or grant options.

**Rolling-upgrade safety (ADR 0003).** Mixed-version deployments running `N-1` API/worker binaries
against the V1-17 PR2 schema are protected across three fail-closed database and rollout gates:

1. **Mandatory gateway metering activation (`quota_enforcement.metering_enforced` +
   `quota_enforce_gateway_handoff_holds`, `OMQ04`).** Because frozen Migration `0023` grants
   `EXECUTE` on `openmettle.gateway_handoff` to `openmettle_api` and `openmettle_worker`, an `N-1`
   binary can still commit `gateway_handoff` with zero `quota_reservations` rows. PR2 seeds
   `openmettle.quota_enforcement.metering_enforced = true` automatically on fresh installations
   (enforcing mandatory metering from transaction 1) and `false` on populated upgrades so `N-1`
   API/worker pods finish draining during rolling deployment. Immediately once all `N-1` replicas
   are replaced by `N`, `openmettle_owner` (`openmettle-admin`) flips `metering_enforced`
   irreversibly `false -> true`. Deferred `CONSTRAINT TRIGGER quota_enforce_gateway_handoff_holds`
   rejects any un-transitioned bound hold unconditionally (even while `false`) and, once `true`,
   aborts any `0023`-only `gateway_handoff` lacking required `'handoff_committed'` holds
   (`usage_tokens` plus applicable `usage_cost_micros`) at `COMMIT` with `OMQ04`, rolling back
   `gateway_requests` to `'reserved'`.
2. **Unpinned worker storage cleaners (`storage_instance.volume_id IS NULL` +
   `enforce_worker_storage_volume_pinned()`, `OMQ03`).** On populated upgrades, operators quiesce
   worker artifact cleaners (`OPENMETTLE_WORKER_ARTIFACTS_DIR` unset or workers scaled to `0`
   across migration and verified volume adoption). As a hard PostgreSQL backstop in case an `N-1`
   worker remains running against an empty replacement mount while `storage_instance.volume_id IS
   NULL`, `SECURITY DEFINER` `BEFORE UPDATE` trigger `openmettle.enforce_worker_storage_volume_pinned()`
   on `openmettle.storage_reservations` (`OLD.state = 'reserved' AND NEW.state = 'released'`) and
   `openmettle.artifact_revisions` (`NEW.state IN ('purging', 'purged')`) rejects any
   `openmettle_worker` mutation with `OMQ03` (leaving disjoint `openmettle_api` in-flight upload
   abort cleanup unaffected). All PR2 (`N`) worker cleaners — including `artifact_fs::purge_due`,
   `reconcile_expired`, run-linked `ENOENT` recovery and `staging/` cleanup — also verify non-null
   pinned `volume_id` + sentinel/`st_dev` identity before every unlink or DB transition.
3. **Lowered `storage_bytes` overrides (`enforce_storage_override()`, `OMQ01`).** Older API and
   worker binaries running `src/storage.rs` read only `storage_instance.personal_limit_bytes` /
   `project_limit_bytes` and would ignore a lowered `quota_overrides` row for `storage_bytes`
   during a mixed-version rollout. PR3 gates `/v1` `setQuotaOverride` writes behind
   rolling-upgrade completion, AND PR2 attaches a `BEFORE UPDATE` trigger
   (`openmettle.enforce_storage_override()`, owned by `openmettle_owner`, `SET search_path =
   pg_catalog`, `REVOKE ALL FROM PUBLIC`) on `openmettle.storage_accounts` that fires **only when
   total charged bytes strictly increase** (`NEW.active_bytes + NEW.retained_bytes +
   NEW.reserved_bytes > OLD.active_bytes + OLD.retained_bytes + OLD.reserved_bytes`). When an
   active `storage_bytes` override exists in `quota_overrides` and the new total exceeds
   `hard_limit`, the trigger aborts the statement with deterministic SQLSTATE `OMQ01`. Legacy
   `storage::reserve` calls therefore fail closed instead of oversubscribing a lowered override,
   while `settle`, `release`, `retain_revision`, `restore_revision` and `confirm_purge` never
   increase total charged bytes and continue working unaffected. Updated PR2 binaries evaluate
   `quota_overrides` before updating `storage_accounts` and return `Error::OwnerLimit` (`429
   quota`) cleanly. Legacy binaries also safely ignore `storage_reservations.lease_expires_at`
   (leaving it `NULL`).

## Authenticated visibility and refusal contract

PR3 exposes authenticated `/v1` routes following every [ADR 0007](0007-application-api-contract.md)
rule: `browserSession` (with configured `Origin` on writes) or `nativeSession`,
`OpenMettle-API-Version: 1.<minor>`, `Cache-Control: no-store`, canonical UUIDs, RFC 3339 UTC
`Timestamp`, `NonNegativeDecimal` counters, closed request schemas and extensible responses.

| Operation | Route | Authorization | Result |
| --- | --- | --- | --- |
| `getPersonalQuotas` | `GET /v1/quotas/personal` | Active principal (`401` if inactive) | `200` `QuotaSummary` for the caller's personal scope |
| `getProjectQuotas` | `GET /v1/projects/{project_id}/quotas` | Current project `Read` membership on primary (ADR 0027); non-member, deleted project or non-member `account_admin` receives `404 not_found` | `200` `QuotaSummary` for that project scope only |
| `setQuotaOverride` | `PUT /v1/admin/scopes/{scope_id}/quotas/{resource_kind}` | `Action::ManageQuotas` (`account_admin`), `Idempotency-Key`, closed JSON body `{ hard_limit, expires_at?, reason }` (`round_cap` validated `1..=1000`; `*_per_actor` valid on `personal` scopes only) | `200` `QuotaOverride` (`400 validation` on out-of-range/invalid target, `403 policy` for non-admin, `404 not_found` for missing scope, `409 idempotency_conflict` on changed replay) |
| `revokeQuotaOverride` | `POST /v1/admin/scopes/{scope_id}/quotas/{resource_kind}/revoke` | `Action::ManageQuotas`, `Idempotency-Key`, closed JSON body `{ reason }` | `200` `QuotaOverride` (revoked) |

`QuotaSummary` keeps all three resource classes distinct:

- `scope_id`, `scope_kind` (`personal` or `project`), `observed_at`.
- `storage`: `limit_bytes` (nullable), `limit_source` (`default`, `override`, `unconfigured`),
  `override_expires_at` (nullable), `active_bytes`, `retained_bytes`, `reserved_bytes`,
  `charged_bytes`, `remaining_bytes` (clamped at `0` or `null`), `warn_thresholds` (`[warn_pct_1,
  warn_pct_2]`), `status` (`ok`, `warning`, `hard_limit`, `unconfigured`).
- `usage`: array of metered budget items (`resource_kind`, `unit` — including the deployment
  `cost_denomination` for `usage_cost_micros`, `window_kind`, `window_start`, `window_end`,
  `limit`, `limit_source`, `override_expires_at`, `active_used`, `reserved_held`, `remaining`,
  `warn_thresholds`, `status`, `authoritative_source`, `last_reconciled_at`). A project query
  returns only the project's own budget items, never another member's personal usage.
- `execution`: `live_runs_per_scope` (`current`, `limit`, `limit_source`),
  `executing_runs_per_scope` (`current`, `limit`, `limit_source`), `round_cap` (`limit`,
  `limit_source`), plus `live_runs_per_actor` and `executing_runs_per_actor` on `personal`
  summaries.
- `device_capacity`: `active_reservations` (`reserved_held`, `limit`, `limit_source`,
  `warn_thresholds`, `status`), distinct from V1-18 physical VRAM telemetry.
- `warnings`: array of active deduplicated warning projections (`resource_kind`, `threshold_pct`,
  `dedupe_bucket`, `triggered_at`) for the requested scope only.

**Privacy and cross-tenant isolation.** `remaining_bytes` and `remaining` are computed solely
from `max(0, owner_limit - owner_charged)` so non-admin callers cannot infer another user's
usage by subtracting available instance headroom. `QuotaSummary` never returns reservation UUIDs
of other actors, artifact names, prompts, raw SQL state, override reasons or unshared project
data. `ManageQuotas` inspects and updates scope-level numeric limits only and confers zero access
to private projects, conversations, artifacts or memory (ADR 0027).

### Safe RFC 9457 refusal mapping

All quota and concurrency refusals align strictly with [ADR 0007](0007-application-api-contract.md),
[`src/v1.rs`](../../src/v1.rs) and [`src/v1/artifacts.rs`](../../src/v1/artifacts.rs):

| Condition | HTTP status and ADR 0007 code | Fixed public `detail` and additive metadata |
| --- | --- | --- |
| Storage owner or instance hard limit exceeded | `429 quota` | `"The storage quota does not allow this upload."` (or `"The storage quota does not allow this request."`); optional closed `quota: { resource_kind: "storage_bytes", scope_kind }` |
| Token or provider usage budget exceeded | `429 quota` | `"The usage budget does not allow this request."`; optional closed `quota: { resource_kind, scope_kind }` |
| Device reservation quota exceeded | `429 quota` | `"The device reservation quota does not allow this request."`; optional closed `quota: { resource_kind: "device_reservations", scope_kind }` |
| Live or executing run concurrency cap (ADR 0032) | `429 rate_limited` | Existing ADR 0032 rate-limit detail (kept distinct from consumed quota budgets) |
| Missing deployment default / denomination and no active override, or unset `ARTIFACTS_DIR` | `503 provisioning` | `"Quota limits are not configured for this resource."` (or existing storage provisioning detail) |
| Unauthorized or hidden project scope | `401 unauthenticated` / `404 not_found` / `403 policy` | Unchanged ADR 0027 concealment rules |

The additive `quota` extension carries only low-cardinality `resource_kind` and `scope_kind`
(`personal`, `project` or `instance`) strings, never byte counts, token counts, override reasons
or another user's identity. When `scope_kind` is `instance`, no capacity numbers are emitted. At
a hard limit (including `hard_limit = 0` or when a limit drops below usage), authorized reads,
downloads, run cancellation, artifact deletion or retention, and quota reads remain permitted.
Every quota refusal and warning stays redacted under
[ADR 0024](0024-process-telemetry-and-redaction.md).

## Delivery and verification

| Slice | Deliverable | Required evidence |
| --- | --- | --- |
| PR1 (this record) | ADR 0040 only. | Review against `#17`, `ARCHITECTURE-v1.md`, ADRs 0005/0007/0027/0031–0033/0035–0037, `ai-guardrails docs audit` (`0` findings) and `scripts/check_repository.py`. |
| PR2 · schema, store and worker recovery | Additive PostgreSQL 18 migration (after Migration `0023`, zero edits to frozen `0023`), `storage_instance.volume_id`, `quota_enforcement` singleton control table (`metering_enforced`, write-once `false -> true`, seeded `true` on fresh installs with zero `gateway_bindings`/`gateway_requests` and `false` on populated upgrades), seeded strictly-`UPDATE`-only `('instance', 'usage_cost_micros')` default row and `quota_cost_unit_lock`, scope-pinned composite FK `(scope_id, gateway_request_id) REFERENCES openmettle.gateway_requests (scope_id, id)`, `SECURITY DEFINER` transition, bootstrap, override, recovery and drift functions (`storage_pin_volume_id`, `quota_upsert_scope_override`, `quota_revoke_scope_override`, `quota_reserve`, `quota_allocate_round`, `quota_commit_handoff`, `quota_recover_lost_handoff`, `quota_commit_device_handoff`, `quota_renew_lease`, `quota_release_unsent`, `quota_unwind_superseded_round`, `quota_release_orphan_gateway_requests`, `quota_settle_gateway_usage`, `quota_release_device_slot`, `quota_record_storage_warning`, `quota_verify_accounting_drift`), `enforce_storage_override`, `quota_enforcement_write_once` (`OMQ04`), `SECURITY DEFINER` `DEFERRABLE INITIALLY DEFERRED` `CONSTRAINT TRIGGER quota_enforce_gateway_handoff_holds` (`openmettle.enforce_gateway_handoff_holds()`, `OMQ04`), `SECURITY DEFINER` `BEFORE UPDATE` `enforce_worker_storage_volume_pinned` triggers on `storage_reservations` and `artifact_revisions` (`OMQ03`), `SECURITY DEFINER` `BEFORE INSERT OR UPDATE` `enforce_quota_reservation_gateway_binding`, `BEFORE INSERT OR UPDATE OR DELETE` `enforce_cost_denomination_immutability` and `SECURITY DEFINER` `BEFORE INSERT` `enforce_gateway_report_cost_unit` triggers, versioned `src/boundaries.sql` entries, `authz::gateway::{reserve_in, handoff_in, release_in}` in-transaction helpers, `src/quotas.rs` store, `storage::reserve` override integration, `Store::open` empty-ledger-only volume sentinel pinning/verification, verified volume-identity gating across all worker artifact cleaners including `artifact_fs::purge_due` and `reconcile_expired`, idempotent `purging`-tolerant `openmettle-admin` verified populated-volume adoption CLI procedure and operator runbook update for populated upgrades (including cleaner quiescing and post-rollout `metering_enforced = true` activation), `claim_next` executing-cap override evaluation, DB-plus-filesystem `verify_accounting_drift`, bounded raw index-key paging (`<= p_page_size`) in `quota_release_orphan_gateway_requests`, and bounded-pass (`pass_upper_bound`) `SKIP LOCKED` one-per-tx `reconcile_stale_quotas` with persistent `StagingSweepState` (`Idle`/`Open`/`InFlight` + `pending_names: VecDeque<String>`) held outside `worker::sweep`'s 15 s `tokio::time::timeout` in `src/worker.rs`. | PostgreSQL 18 tests in `tests/schema/grants.rs` and `tests/schema/quotas.rs` executing all override, reservation, device-handoff, lost-handoff-recovery, superseded-round-unwind, orphan-gateway-sweep, gateway-settlement, drift-verification and stale-sweep paths **connected as the actual runtime roles** (`openmettle_api`, `openmettle_worker`, `openmettle_gateway`, `openmettle_issuance`) and asserting denial of direct `INSERT`/`UPDATE`/`DELETE`/`SELECT ... FOR NO KEY UPDATE` on all `quota_*` tables (plus zero privileges on `quota_cost_unit_lock`, `SELECT`-only on `quota_enforcement` and `storage_instance.volume_id`), denial of direct `SELECT` by `openmettle_api` and `openmettle_worker` on `openmettle.gateway_requests` and `openmettle.gateway_usage_reports` while qualifying `openmettle.quota_verify_accounting_drift()`, `openmettle.quota_unwind_superseded_round(...)` and `openmettle.quota_release_orphan_gateway_requests(...)` as `openmettle_worker` (and denying `EXECUTE` to `openmettle_api`, `openmettle_gateway` and `openmettle_issuance`) and qualifying `openmettle.quota_recover_lost_handoff(...)` as `openmettle_api` (`p_run_id IS NULL`) and `openmettle_worker` (`p_run_id IS NOT NULL`) while denying `openmettle_gateway` and `openmettle_issuance`, denial of `openmettle_api` calling either `quota_commit_handoff` or `quota_commit_device_handoff` on a run-linked `device_reservations` hold, denial of `openmettle_worker` calling generic `quota_commit_handoff` on a run-linked `device_reservations` hold, and denial of cross-role/unleased calls; N-way concurrent admission non-oversubscription across distinct project/actor/instance windows; non-windowed `device_reservations` surviving UTC rollover and `api`-admitted run device handoff exclusively via `quota_commit_device_handoff` under active `claim_token` lease (plus refusal for wrong resource kind or stale/unleased/cancelled run); cross-scope lock-order race with zero deadlocks; concurrent `executing_runs_per_actor` / `executing_runs_per_scope` cap lowering racing `claim_next` (and approval resume) serialized on `run_dispatch_lock` with zero overshoot; exact-once reconciliation across exact replay (recovering server-chosen windows), unique `(gateway_request_id, resource_kind)` enforcement rejecting duplicate keys, scope-pinned composite FK `(scope_id, gateway_request_id) REFERENCES openmettle.gateway_requests (scope_id, id)` and Migration `0023` composite FKs to `gateway_usage_reports` (`(request_id, revision)` and `(source, report_id, revision)`), **single-transaction atomic `authz::gateway::reserve_in` + `quota_reserve` / `quota_allocate_round` rollback test proving that when any metered quota hold fails or the transaction aborts before commit, neither `gateway_requests`, `gateway_reservations.allocated`, nor `quota_reservations` persists (and `gateway_requests_run_round_active_idx` is not stranded)**, **original `0023` `authz::gateway::reserve` + `Pending::handoff` rolling-upgrade activation test across `quota_enforcement.metering_enforced` (proving fresh installs auto-seed `metering_enforced = true`; populated upgrades seed `false` so `N-1` `0023`-only handoff succeeds during rolling deploy and `quota_recover_lost_handoff` reports `'unmetered_legacy_handoff'` while suppressing HTTP dispatch, whereas any bound `'held'`/`'released'` quota hold still fails at `COMMIT` with `OMQ04`; flipping write-once `metering_enforced = true` as `openmettle_owner` — rejecting `true -> false` with `OMQ04` — causes the `0023`-only handoff to fail at `COMMIT` with `OMQ04` and roll back `gateway_requests` to `'reserved'`, and requires both bound `'handoff_committed'` `usage_tokens` and applicable `usage_cost_micros` holds)**, **fenced successor-worker unwind test (`openmettle.quota_unwind_superseded_round`) simulating worker process death immediately between `(reserve_in + quota_allocate_round)` commit and handoff, lease expiry + `leases::reclaim_next` by a successor worker, fenced unwind transitioning `gateway_requests` to `'released'`, restoring `gateway_reservations.allocated` and parent run `quota_reservations` capacity (`allocated_units`/`held_units`) while releasing child holds and freeing `gateway_requests_run_round_active_idx`, and clean retry of the same round (plus `'handed_off'` left untouched returning `false`, and stale `claim_token` / non-worker calls refused)**, **pre-upgrade orphan `'reserved'` `gateway_requests` sweep test via `openmettle.quota_release_orphan_gateway_requests(...)` connected as `openmettle_worker` releasing aged unbound `'reserved'` rows while restoring `gateway_reservations.allocated`, freeing `gateway_requests_run_round_active_idx`, and skipping active leased runs or bound requests, PLUS a bounded raw index-key paging test with a multi-page prefix of aged legitimately bound `'reserved'` requests ahead of a trailing orphan proving each call inspects at most `p_page_size` raw `(created_at, id)` keys from `gateway_requests_reserved_idx`, advances the persistent cursor across zero-orphan pages without exhausting sweep budget, and releases the trailing orphan on a subsequent page**, **negative binding and ownership-recheck tests proving cross-scope, cross-actor, cross-run, non-`'reserved'` state, or wrong-`p_dispatch`-secret bind attempts in `quota_reserve` / `quota_allocate_round` (and `quota_reservations_gateway_binding_guard`) are rejected and that `quota_release_unsent` ownership rechecks fail closed with an invariant error mutating neither ledger on mismatch**, run-to-round `held` allocation without double-debit coupled atomically with `authz::gateway::handoff_in` (`openmettle.gateway_handoff`) + `quota_commit_handoff` (rolling back both on pre-commit refusal), **lost commit acknowledgement (`UnknownCommit`) integration tests connected directly as unprivileged `openmettle_api` and `openmettle_worker` logins exercising all `openmettle.quota_recover_lost_handoff(...)` outcomes — `'handoff_committed'` (preserving durable `gateway_requests.state = 'handed_off'` + all required `'handoff_committed'` quota holds when `metering_enforced = true`, asserting zero bound holds remain `'held'`, suppressing HTTP dispatch for gateway reconciliation), `'unmetered_legacy_handoff'` (when `metering_enforced = false` and zero bound holds exist, still suppressing HTTP dispatch), and `'unwound_unsent'` (atomically unwinding `'reserved'`/`'released'` `gateway_requests`, restoring `gateway_reservations.allocated`, and releasing bound `'held'` holds to an active parent or `quota_budgets`) plus wrong-role/wrong-secret/mismatched-ownership/missing-required-hold (`OMQ04`) refusals**, pre-send unwind via `authz::gateway::release_in` (`openmettle.gateway_release`) + `quota_release_unsent` returning capacity to an active parent run hold (or releasing on terminal runs), **stale sweep atomically transitioning a stale `'reserved'` `gateway_requests` row to `'released'` and restoring `gateway_reservations.allocated` in the same `SECURITY DEFINER` transaction as releasing `quota_reservations` (proving a delayed `openmettle.gateway_handoff` with the original dispatch secret fails closed while `'handed_off'` rows remain untouched)**, cancellation, pre-send abort (with `closed_at`), valid `revision = 0` initial partial and final reports accepted when `accepted_source_revision IS NULL` (persisting `accepted_source_revision = 0` and rejecting subsequent `revision <= 0`), signed downward partial correction (`delta_reserved > 0`), independent token/cost settlement, `BEFORE INSERT OR UPDATE OR DELETE` `cost_denomination` immutability trigger (`OMQ02`, proving `INSERT` — including `INSERT ... ON CONFLICT DO UPDATE` — `DELETE`, and rename into/out of the seeded `('instance', 'usage_cost_micros')` row unconditionally fail with `OMQ02` without acquiring `quota_cost_unit_lock`, eliminating any AB/BA lock cycle) plus `BEFORE INSERT` `gateway_usage_reports_cost_unit_guard` serialized via `quota_cost_unit_lock` with **explicit concurrency tests covering both commit orders with different units (direct `UPDATE quota_defaults` vs `openmettle_gateway` `INSERT INTO gateway_usage_reports` with `cost IS NOT NULL`, plus two concurrent `gateway_usage_reports` inserts with different units while `cost_denomination IS NULL`)** and mismatch quarantine, final overage settlement plus subsequent refusal, upload abort and `confirm_purge`; override raise/lower/expiry and `hard_limit = 0` preserving data and deletion grace; `round_cap` `1..=1000` validation; stale sweep using `FOR NO KEY UPDATE SKIP LOCKED` on `runs`, `gateway_reservations`, `gateway_requests` and `quota_reservations` (proving a locked gateway row is skipped immediately without stalling the sweep) with bounded-pass `pass_upper_bound` cursor + wraparound across `SWEEP_MS` ticks (60 s default interval, 15 s budget) proving continuously arriving tail rows and a multi-tick locked prefix never stall or starve later rows; **previous-version (`N-1`) worker unpinned-volume guard test exercising both `artifact_fs::reconcile_expired` and `artifact_fs::purge_due` as `openmettle_worker` against an empty replacement mount while `storage_instance.volume_id IS NULL`, proving both fail closed in PostgreSQL (`OMQ03` via `enforce_worker_storage_volume_pinned`) with zero released `storage_reservations` and zero `purging`/`purged` transitions or byte-charge reductions while disjoint `openmettle_api` in-flight upload abort `storage::release` remains permitted**; **populated-upgrade volume-identity acceptance tests (upgrade a database containing pre-existing `artifact_revisions` and `storage_reservations` with `storage_instance.volume_id IS NULL`, start against an empty replacement directory where `Store::open` creates empty `staging/` and `revisions/`, proving `volume_id` stays `NULL`, `storage_pin_volume_id` refuses with `OMQ03`, no `.openmettle-volume-id` sentinel is written, zero reservations are released and zero files unlinked, verified volume adoption rejects the empty replacement mount and missing `active`/`retained` files, verified volume adoption succeeds on the real original volume including when a mid-purge `state = 'purging'` revision's file is already unlinked while retaining its byte charge until `purge_due` confirms `'purged'`, and interrupting adoption after sentinel `fsync` and before DB commit allows operator retry to re-verify the volume and pin `storage_instance.volume_id` idempotently with the existing sentinel UUID while rejecting mismatched DB `volume_id` with `OMQ03`)**; run-linked storage recovery and `artifact_fs::purge_due` requiring configured `ARTIFACTS_DIR`, non-null pinned `storage_instance.volume_id` <-> `<root>/.openmettle-volume-id` (`O_NOFOLLOW`, `fsync`ed on empty-ledger bootstrap only; refusing fresh initialization once non-null) and exact `st_dev` match with open `revisions/` and `staging/` directory FDs before unlinking or committing `begin_purge` / `confirm_purge` / `storage::release` (preserving hold + payload when `revisions/<id>` exists while `state = 'reserved'`, and **proving worker restart with an accessible empty replacement directory while `storage_instance.volume_id` is pinned — as well as missing, mismatched, symlinked or different-`st_dev` sentinels — fails closed across both `reconcile_expired` and `purge_due` with zero released charges**), plus **persistent `StagingSweepState` `ReadDir` `staging/` cleanup tests covering both (a) directory enumeration spanning multiple ticks (parking the open `ReadDir` stream, resuming from the parked offset without restarting from entry 0, resetting cleanly on `(st_dev, st_ino)` change, and unlinking a `released` staging file near the end of the directory) and (b) a single `<= 64`-entry `spawn_blocking` `ReadDir` slice exceeding one tick's `worker::sweep` 15 s `tokio::time::timeout` deadline (proving Tick 1 times out cleanly without spawning duplicate `spawn_blocking` tasks while keeping `InFlight` parked in `StagingSweepState`, and Tick 2 re-verifies directory identity and consumes that completed slice's entries from `pending_names` exactly once)**; restore verification (`verify_accounting_drift` + `openmettle.quota_verify_accounting_drift()`) recognizing `state = 'purging'` with missing `revisions/<id>` (`ENOENT`) as a valid resumable mid-purge state while failing hard on `volume_id IS NULL`, missing `active`/`retained` payloads and DB/`0023` drift; and populated previous-writer rolling-upgrade test with a lowered `storage_bytes` override proving fail-closed refusal (`OMQ01`) on old `storage::reserve` while `settle`/`release`/`retain`/`purge` succeed. |
| PR3 · `/v1` API, OpenAPI and wired enforcement | `/v1` quota read (with `warnings` projection) and `ManageQuotas` routes (gated on rolling-upgrade completion), OpenAPI 3.2.1 schemas and regenerated `contracts/fixtures/`, independent consumer decoding, and wired quota enforcement in `src/v1/artifacts.rs`, `admit_run`, `claim_next` and ADR 0037 settlement paths. | Contract validation (`tests/contract.rs`) and PostgreSQL 18 HTTP tests on both session channels covering effective limits/usage/reservations/warnings visibility, warning deduplication and re-arming on override/config edits, concurrent `/v1` `setQuotaOverride` lowering of `executing_runs_*` caps racing `claim_next`, `404` concealment for non-members and non-member admins, audited override changes and replay conflicts, safe `429 quota` / `429 rate_limited` / `503 provisioning` RFC 9457 problems with redaction canaries, and allowed reads, downloads, cancellations and deletions at hard limit. |

**Boundaries.** V1-15 (`#15`) and V1-16 (`#16`) own artifact payload transport, retention
policies and deletion journals. V1-06 (`#7`, ADR 0037) owns Migration `0023`, gateway admin
provisioning and authoritative usage feed ingestion. V1-14 (`#14`) owns MCP tool schemas and spill
triggers. V1-18 (`#18`) owns the active GPU controller, DRA claims and physical VRAM handoffs.
V1-29 (`#26`) owns telemetry contract updates when PR2/PR3 register quota metrics.
