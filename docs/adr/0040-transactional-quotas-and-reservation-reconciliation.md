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
| [ADR 0005](0005-artifact-storage-accounting.md), [`src/storage.rs`](../../src/storage.rs) | Keep `storage_instance`, `storage_accounts`, `storage_reservations` and `artifact_revisions` as the single storage ledger. Add per-scope overrides, a fail-closed rolling-upgrade backstop trigger on `storage_accounts`, warning thresholds, reservation `lease_expires_at` and DB-plus-filesystem drift verification. |
| [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md), [`src/artifact_fs.rs`](../../src/artifact_fs.rs) | Bind upload reservations (`run_id IS NULL`) to `lease_expires_at` within the 600 s upload timeout plus 300 s settlement margin. Keep `reconcile_expired` and `purge_due` as the sole upload and purge cleaners. Preserve published revision payloads after post-rename/pre-settlement crashes and recognize missing `purging` payloads as a valid resumable mid-purge state during restore verification. |
| [ADR 0032](0032-durable-run-admission-and-fair-work-queue.md) and [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md), [`src/authz/runs.rs`](../../src/authz/runs.rs) | Keep exact partial-index counts on `runs` for live and executing runs. Resolve per-scope overrides for live caps and `round_cap` (`1..=1000`) at admission, and serialize `executing_runs_*` cap changes with `claim_next` (including approval resume) via `run_dispatch_lock`. Compose usage and device holds inside admission and renew run-bound holds on the worker lease cadence. |
| [ADR 0035](0035-approvals-permitted-yolo-and-effect-ledger.md), [`src/authz/approvals.rs`](../../src/authz/approvals.rs) | Keep `StorageReservation` for run-bound artifact and tool-result spills (including V1-14 (`#14`) bounded outputs). Align parked reservation expiry with `resume_execution_expires_at`. Require configured `ARTIFACTS_DIR` and positive `ENOENT` proof that `revisions/<id>` does not exist before committing `storage::release` and unlinking `staging/<id>`; never release or unlink when `revisions/<id>` exists while `state = 'reserved'`. |
| [ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md) | Reconcile local token and cost budget holds strictly from authoritative `openmettle_gateway` settlement reports via narrow `SECURITY DEFINER` transitions. Enforce unique `(gateway_request_id, resource_kind)` reservation binding, atomic `accepted_source_revision` persistence on partial/final reports, run-to-round hold allocation without double-debiting `reserved_held`, signed partial corrections and SQL-enforced write-once deployment denomination immutability. |
| [ADR 0007](0007-application-api-contract.md) and [ADR 0027](0027-authorization-and-private-projects.md) | Expose authenticated `/v1` effective-quota projections (including active threshold warnings), audited `ManageQuotas` override routes backed by `SECURITY DEFINER` functions and privacy-safe `429 quota` / `429 rate_limited` / `503 provisioning` RFC 9457 problems. |
| V1-18 (`#18`) shared capacity controller | Separate user and project concurrent device-slot quotas (`window_kind = 'concurrent'`) from GPU VRAM allocation. Gate admission in PostgreSQL, allow lease-fenced `openmettle_worker` handoff of API-admitted run device holds via `quota_commit_device_handoff`, and release device quota holds only after durable V1-18 confirmation of backend release or non-allocation. |

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
  enforces **one immutable deployment-wide denomination** (`cost_denomination` configured once on
  the `('instance', 'usage_cost_micros')` default row, such as `USD_MICROS` or `CREDITS_MICROS`).
  PostgreSQL enforces write-once immutability via trigger `quota_defaults_cost_denomination_immutable`
  (SQLSTATE `OMQ02`): once `cost_denomination` is set non-null — or if any `usage_cost_micros`
  override, budget, reservation or accepted ADR 0037 settlement report with a denomination exists —
  any `UPDATE` changing or clearing `cost_denomination` (or `DELETE` of that row) is rejected so
  existing balances cannot be silently reinterpreted and in-flight reports cannot be orphaned.
  Changing currency or credit unit in-place is permanently unsupported by operator contract and
  requires a separate deployment or an explicit offline `openmettle_owner` ledger migration after
  draining and archiving all prior cost balances and reports. `openmettle_gateway` refuses any
  provider report with a mismatched currency or credit unit and routes it to ADR 0037 quarantine
  without mutating balances.
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
    accepted_source_revision bigint NOT NULL DEFAULT 0 CHECK (accepted_source_revision >= 0),
    state text NOT NULL DEFAULT 'held'
        CHECK (state IN ('held', 'handoff_committed', 'settled', 'released')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    lease_expires_at timestamptz NOT NULL,
    closed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (scope_id, actor_user_id, resource_kind, idempotency_key),
    FOREIGN KEY (actor_scope_id, actor_user_id)
        REFERENCES openmettle.scopes (id, personal_user_id),
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
    gateway_report_id uuid,
    source_revision bigint CHECK (source_revision IS NULL OR source_revision >= 1),
    kind text NOT NULL CHECK (kind IN (
        'partial_settle', 'partial_correction', 'final_settle', 'final_correction', 'release'
    )),
    cumulative_units bigint NOT NULL CHECK (cumulative_units >= 0),
    delta_active bigint NOT NULL,
    delta_reserved bigint NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (reservation_id, transition_revision),
    UNIQUE (reservation_id, source_key),
    CHECK (
        (kind = 'release' AND gateway_report_id IS NULL AND source_revision IS NULL
            AND delta_active = 0 AND delta_reserved <= 0)
        OR (kind IN ('partial_settle', 'partial_correction', 'final_settle', 'final_correction')
            AND gateway_report_id IS NOT NULL AND source_revision IS NOT NULL)
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

CREATE FUNCTION openmettle.enforce_cost_denomination_immutability()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF OLD.scope_kind = 'instance' AND OLD.resource_kind = 'usage_cost_micros'
       AND (TG_OP = 'DELETE'
            OR NEW.scope_kind <> OLD.scope_kind
            OR NEW.resource_kind <> OLD.resource_kind
            OR NEW.cost_denomination IS DISTINCT FROM OLD.cost_denomination) THEN
        IF OLD.cost_denomination IS NOT NULL
           OR EXISTS (SELECT 1 FROM openmettle.quota_overrides
                       WHERE resource_kind = 'usage_cost_micros')
           OR EXISTS (SELECT 1 FROM openmettle.quota_budgets
                       WHERE resource_kind = 'usage_cost_micros')
           OR EXISTS (SELECT 1 FROM openmettle.quota_reservations
                       WHERE resource_kind = 'usage_cost_micros') THEN
            RAISE EXCEPTION 'cost_denomination is immutable once configured or used'
                USING ERRCODE = 'OMQ02';
        END IF;
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_cost_denomination_immutability() FROM PUBLIC;
CREATE TRIGGER quota_defaults_cost_denomination_immutable
    BEFORE UPDATE OR DELETE ON openmettle.quota_defaults
    FOR EACH ROW EXECUTE FUNCTION openmettle.enforce_cost_denomination_immutability();
```

- **Exact multi-budget addressing.** Consolidating scope and instance balances into one
  `quota_budgets` table and recording immutable `quota_reservation_charges` child rows eliminates
  lossy single-window addressing. A daily project budget, a weekly actor ceiling and a monthly
  instance cap each receive their own `budget_id` row at reservation time. Settlement, correction,
  run-to-round child allocation and release join `quota_reservation_charges` directly without
  recomputing `window_start`, even if deployment window lengths or defaults change later.
- **Unique external-request and device-grant binding.** The partial unique index
  `quota_reservations_gateway_request_kind_uidx` (`UNIQUE (gateway_request_id, resource_kind)
  WHERE gateway_request_id IS NOT NULL`) guarantees at most one `usage_tokens` reservation and at
  most one `usage_cost_micros` reservation can bind to a given `gateway_request_id`, preventing
  two distinct `idempotency_key`s from attaching duplicate holds to the same gateway request.
  Likewise, `quota_reservations_device_grant_uidx` binds each durable `device_grant_id` to at most
  one `device_reservations` hold.
- **Immutable deployment cost denomination.** `quota_defaults_cost_denomination_immutable`
  (`OMQ02`) enforces write-once semantics on `('instance', 'usage_cost_micros').cost_denomination`:
  once configured non-null, or whenever any `usage_cost_micros` row exists in `quota_overrides`,
  `quota_budgets`, `quota_reservations` or V1-06's accepted settlement reports (PR2 adds the
  Migration `0023` report-table `cost_denomination IS NOT NULL` check alongside the three local
  tables), PostgreSQL rejects any `UPDATE` changing or clearing `cost_denomination` and any
  `DELETE` of that row.
- **Composite personal-scope binding.** `quota_reservations` binds `(actor_scope_id,
  actor_user_id)` through a composite foreign key to `openmettle.scopes (id, personal_user_id)`
  ([`migrations/0001_identity_and_scopes.sql`](../../migrations/0001_identity_and_scopes.sql)),
  proving at the schema layer that `actor_scope_id` is the actor's genuine personal scope.
- **Reusing V1-06 report identity.** `quota_reconciliations` stores only the exact-once delta
  transition and references ADR 0037's accepted usage report row via `gateway_report_id` (foreign
  key to V1-06's accepted report table introduced in Migration `0023`), rather than duplicating
  raw provider token, cost or quarantine rows.
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
[ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md):

```text
account_admin_lock -> run_dispatch_lock -> projects -> users -> runs -> branch_heads
  -> gateway_bindings -> operations / gateway_operations -> gateway_requests (ADR 0037)
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
| Worker claim and approval resume (`openmettle_worker`, [`src/authz/runs.rs`](../../src/authz/runs.rs)) | `run_dispatch_lock` (`FOR NO KEY UPDATE`) -> one eligible `queued` or approved-`waiting` `runs` row (`FOR NO KEY UPDATE SKIP LOCKED`), evaluating effective `executing_runs_per_actor` and `executing_runs_per_scope` (active `quota_overrides` coalesced with `quota_defaults`) inside the claim query. Serializes directly on `run_dispatch_lock` with `executing_runs_*` override and default updates. `reclaim_next` ([`src/authz/leases.rs`](../../src/authz/leases.rs)) only re-leases already-executing runs (`running`, `cancelling`, `reconciling`) without increasing executing counts or taking `run_dispatch_lock`. |
| Run-to-round hold allocation (`openmettle_worker`, via `quota_allocate_round`) | Inside `SECURITY DEFINER`: `runs` (`FOR NO KEY UPDATE`, verifying active `Step` lease `state = 'running'`, `cancel_reason IS NULL`, `claim_token`, `lease_expires_at > clock_timestamp()`) -> `gateway_bindings` / `gateway_requests` (ADR 0037) -> parent `quota_reservations` (`FOR NO KEY UPDATE`) -> insert child `quota_reservations` (`handoff_committed`) + copy `quota_reservation_charges` -> decrement parent `held_units`, increment `allocated_units` (`quota_budgets.reserved_held` delta = `0`). |
| Run-linked device handoff (`openmettle_worker`, via `quota_commit_device_handoff`) | Inside `SECURITY DEFINER`: `runs` (`FOR NO KEY UPDATE`, verifying active `Step` lease `state = 'running'`, `cancel_reason IS NULL`, matching `claim_token`, `lease_expires_at > clock_timestamp()`) -> `quota_reservations` (`FOR NO KEY UPDATE`, `resource_kind = 'device_reservations'`, `origin_role IN ('api', 'worker')`, matching `scope_id` and `run_id`) -> bind durable `device_grant_id` and transition `held -> handoff_committed`. |
| Gateway usage settlement or correction (`openmettle_gateway`, via `quota_settle_gateway_usage`) | Inside `SECURITY DEFINER`: `runs` (if run-linked) -> `gateway_bindings` -> `operations` / gateway operation -> `gateway_requests` -> `quota_reservations` (`FOR NO KEY UPDATE`) -> charged `quota_budgets` via `quota_reservation_charges` (scope rows asc, instance row last) -> insert `quota_reconciliations` -> update reservation (`held_units`, `settled_units`, `accepted_source_revision`, `state`/`closed_at`), budget balances and `quota_warning_events`. |
| Pre-send abort, stale release or V1-18 device release (via `quota_release_unsent` / `quota_release_device_slot`) | **One reservation per short transaction, locks acquired inside `SECURITY DEFINER`:** `runs` (if run-linked: `FOR NO KEY UPDATE SKIP LOCKED` in stale sweep, `FOR NO KEY UPDATE` on explicit abort/release) -> `quota_reservations` (`FOR NO KEY UPDATE SKIP LOCKED` in stale sweep, `FOR NO KEY UPDATE` on explicit abort/release) -> charged `quota_budgets` via `quota_reservation_charges` (scope rows asc, instance row last) -> insert `quota_reconciliations` -> update reservation (`closed_at = clock_timestamp()`) and budget balances. |
| Storage upload reservation (`openmettle_api` / `openmettle_worker`) | `runs` (if run-linked) -> `storage_accounts` (`FOR UPDATE`) -> non-locking `SELECT` on `storage_reservations`, `artifacts`, `quota_overrides` -> `storage_instance` (`FOR UPDATE`) -> insert `storage_reservations` -> update `storage_accounts` then `storage_instance` -> call `quota_record_storage_warning(...)`. |
| Storage upload settlement (`storage::settle`) | `projects` (if authorized in tx) -> `storage_reservations` (`FOR UPDATE`) -> `artifacts` (`FOR UPDATE`) -> insert `artifact_revisions` -> update `storage_reservations` -> `storage_accounts` -> `storage_instance`. |
| Storage retention and purge confirmation (`storage::retain_revision`, `restore_revision`, `begin_purge`, `confirm_purge`) | `artifact_revisions` (`FOR UPDATE`) -> `storage_accounts` -> `storage_instance` (never locks `artifacts` or `storage_reservations`, [`src/storage.rs`](../../src/storage.rs)). |
| Storage release (`storage::release`) | `runs` (`FOR NO KEY UPDATE SKIP LOCKED` in worker stale sweep, `FOR NO KEY UPDATE` on explicit release, if `run_id IS NOT NULL`) -> `storage_reservations` (`FOR UPDATE SKIP LOCKED` in sweep, `FOR UPDATE` on explicit release) -> `storage_accounts` -> `storage_instance`. |
| Override write (`openmettle_api` via `quota_upsert_scope_override` / `quota_revoke_scope_override`, `ManageQuotas`) | Inside `SECURITY DEFINER`: if `resource_kind IN ('executing_runs_per_actor', 'executing_runs_per_scope')`, acquire `run_dispatch_lock` (`FOR NO KEY UPDATE`) first -> target entity row (`projects` `FOR NO KEY UPDATE` for project scopes; personal owner `users` `FOR NO KEY UPDATE` for personal/actor scopes) -> if `storage_bytes`, `storage_accounts` (`FOR UPDATE`); if metered usage/device, current active `quota_budgets` (`FOR NO KEY UPDATE`, ascending) -> upsert/revoke `quota_overrides` (incrementing `revision` to re-arm warning watermarks); then caller inserts `authorization_audit` in the same transaction. Live-run and round-cap kinds (`live_runs_*`, `round_cap`) serialize on `projects`/`users` matching `lock_scope_actor`; `openmettle_owner` updates to `executing_runs_*` rows in `quota_defaults` also acquire `run_dispatch_lock` (`FOR NO KEY UPDATE`) first so default cap changes serialize with `claim_next`. |

During `quota_reserve`, the idempotency replay lookup performs a non-locking `SELECT` on
`quota_reservations` (matching `src/storage.rs`), so `quota_reserve` never waits on a reservation
row while holding a budget lock. `settle`, `allocate_round`, `commit_device_handoff` and `release`
always lock the run and reservation rows before budget rows. No path holding a `projects`, `users`,
`runs`, quota or storage lock waits on `run_dispatch_lock`, and no path holding a quota or storage
lock waits on `projects`, `users`, `runs`, `gateway_bindings` or `gateway_requests`, making the
global lock graph strictly acyclic. If a caller composes multiple unrelated owners and PostgreSQL
reports SQLSTATE `40P01`, the caller rolls back the whole transaction and retries with identical
idempotency keys.

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
| Run-to-round hold allocation (ADR 0037) | `quota_allocate_round` verifies the worker's active `Step` lease on `runs` and transfers `slice_units <= parent.held_units` from a server-owned run's `held` parent reservation to a child round reservation bound to `gateway_request_id` (`state = 'handoff_committed'`), copying `quota_reservation_charges`. Parent decrements `held_units` and increments `allocated_units`; `quota_budgets.reserved_held` changes by `0` (never double-debited). Unallocated parent remainder releases once when the run can start no further rounds. |
| Standalone pre-dispatch handoff | For standalone completions or worker-originated holds, `quota_commit_handoff` locks the caller's own `origin_role` `held` reservation, binds `gateway_request_id` or `device_grant_id` (enforcing `quota_reservations_gateway_request_kind_uidx` / `quota_reservations_device_grant_uidx`), sets `state = 'handoff_committed'` and commits before bytes leave the process. A lost commit reply prevents dispatch. |
| Run-linked device handoff (`api` admission -> `worker` dispatch) | Run admission (`POST /v1/runs`) reserves `device_reservations` with `origin_role = 'api'`. At dispatch, `openmettle_worker` invokes `openmettle.quota_commit_device_handoff(...)`, which locks `runs -> quota_reservations` in canonical order, verifies the calling worker's active `Step` lease (`runs.state = 'running'`, `runs.cancel_reason IS NULL`, matching `claim_token`, `runs.lease_expires_at > clock_timestamp()`), requires `resource_kind = 'device_reservations'` (`origin_role IN ('api', 'worker')`) matching `(scope_id, run_id)`, binds the run's durable V1-18 `device_grant_id` and transitions `state = 'handoff_committed'` before external device activation. `openmettle_worker` remains forbidden from mutating `origin_role = 'api'` holds of any other resource kind or any unleased/cancelled run. |
| Pre-send abort, queued cancellation or unallocated parent remainder | Only while `state = 'held'`: `quota_release_unsent` acquires locks internally (`SKIP LOCKED` in sweep mode), re-verifies eligibility, inserts `quota_reconciliations` (`kind = 'release'`, `delta_active = 0`, `delta_reserved = -held_units`), decrements `reserved_held`, sets `state = 'released'`, `held_units = 0` and `closed_at = clock_timestamp()`. Repeating release is a no-op. |
| Open partial gateway report or signed partial correction (ADR 0037) | `quota_settle_gateway_usage` requires `state = 'handoff_committed'`, valid immutable deployment denomination and strictly increasing `p_source_revision > accepted_source_revision`. For cumulative total `C` vs prior `settled_units = S` and `held_units = H`, compute `new_held = greatest(0, reserved_units - C)`, `delta_active = C - S` and **signed** `delta_reserved = new_held - H`. The single atomic `UPDATE` on `quota_reservations` persists `held_units = new_held`, `settled_units = C`, **`accepted_source_revision = p_source_revision`** and `revision = revision + 1` in the same transaction alongside `quota_reconciliations` and `quota_budgets`, so delayed older reports (`p_source_revision <= accepted_source_revision`) can never pass the guard. Example: on a `100`-token hold where revision 1 reports `60` partial (`60` measured, `40` held, `accepted_source_revision = 1`), an authoritative revision 2 partial correction to `20` applies `delta_active = -40` and `delta_reserved = +40` (`20` measured, `80` held, `accepted_source_revision = 2`, preserving `100` total exposure while open). |
| Authoritative final gateway report (including overage or zero charge) | Requires `state = 'handoff_committed'` and strictly increasing `p_source_revision > accepted_source_revision`. Applies `delta_active = C - S` (full overage if `C > reserved_units`) and `delta_reserved = -H`. The single atomic `UPDATE` sets `state = 'settled'`, `held_units = 0`, `settled_units = C`, **`accepted_source_revision = GREATEST(accepted_source_revision, p_source_revision)`**, `revision = revision + 1` and `closed_at = clock_timestamp()`. Closes the hold once per unit; a late partial report cannot reopen `settled`. |
| Post-final authoritative correction | Requires `state = 'settled'` and strictly increasing `p_source_revision > accepted_source_revision`. Applies signed `delta_active = C_new - S` and `delta_reserved = 0` (rejecting negative `active_used`), atomically updating `settled_units = C_new`, `accepted_source_revision = p_source_revision` and `revision = revision + 1`. Same-revision duplicates with identical values are no-ops; differing values at an already accepted revision or mismatched denominations quarantine under ADR 0037 without mutating balances. |
| Failed upload, interrupted write or retention purge | Non-run upload failures unlink `staging/<id>` and call `storage::release` once; `settle` moves actual bytes to `active_bytes` and releases `max_bytes - size_bytes` once; `confirm_purge` decrements `retained_bytes` once after confirmed payload deletion (ADR 0005, ADR 0031). Run-linked `storage_reservations` recovery calls `storage::release` ONLY after positive `ENOENT` proof that `revisions/<id>` does not exist on disk; if `revisions/<id>` exists while `state = 'reserved'`, both hold and payload are preserved for settlement or operator reconciliation. |
| Terminal failed, cancelled or interrupted run | Unallocated `held` parent or standalone quota holds release once. `handoff_committed` usage holds stay held until `openmettle_gateway` supplies an authoritative final report (including zero-charge final proof). `handoff_committed` device holds stay held until durable V1-18 confirmation of release or non-allocation. Run-linked `storage_reservations` stay held while any linked operation is `intent` or `outcome_unknown`, or while `revisions/<id>` exists on disk awaiting SQL settlement. |

**Independent drift verification and restore validation.** PR2 adds a read-only
`verify_accounting_drift` check that workers run on a bounded maintenance interval and operators
run during restore validation before reopening dispatch
([Architecture backup and restore](../../ARCHITECTURE-v1.md#backup-and-restore)):

1. **Storage DB consistency:** compares `storage_accounts` and `storage_instance` counters
   (`active_bytes`, `retained_bytes`, `reserved_bytes`) against sums recomputed from
   `artifact_revisions` (`state = 'active'` and `state IN ('retained', 'purging')`) and
   `storage_reservations` (`state = 'reserved'`).
2. **Storage DB-to-filesystem verification (`artifact_fs`):**
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
     file in `staging/` lacking a matching `reserved` reservation, fails as an unreferenced orphan.
3. **Usage and device budget verification:** compares every `quota_budgets.reserved_held` row
   against `SUM(qr.held_units)` joined via `quota_reservation_charges` for
   `qr.state IN ('held', 'handoff_committed')`, compares `quota_budgets.active_used` against both
   `SUM(quota_reconciliations.delta_active)` and accepted V1-06 gateway settlement evidence, and
   verifies every `released` or `settled` reservation has `closed_at IS NOT NULL`.

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

PR2 adds a `reconcile_stale_quotas(pool, store, limit)` sweep to `src/worker.rs` on the ADR 0033
`SWEEP_MS` tick (batch 1–1000, default 100, 15 s budget, alongside `artifact_fs::reconcile_expired`
and `artifact_fs::purge_due`). To eliminate cross-item budget deadlocks, lock-timeout stalls and
head-of-line starvation, every sweep phase separates non-locking candidate scanning (with a
persistent keyset cursor across ticks) from **one-reservation-per-transaction** settlement:

1. **Non-storage holds (`quota_reservations`).**
   - *Starvation-free candidate scan with persistent cursor:* In a short plain non-locking read-only
     `SELECT`, fetch up to `limit` candidate `(id, lease_expires_at)` rows with `state = 'held'
     AND lease_expires_at <= clock_timestamp()` filtered **before `LIMIT`** to require either
     `run_id IS NULL` or a terminal linked run (`state IN ('succeeded', 'failed', 'cancelled',
     'interrupted')`) with `NOT EXISTS` any linked operation in `('intent', 'outcome_unknown')`.
     Order by `(lease_expires_at ASC, id ASC)` starting strictly after an **in-memory keyset
     cursor `(cursor_ts, cursor_id)` persisted across 15-second `SWEEP_MS` ticks**. After each
     batch, advance the cursor to the last scanned candidate; whenever a batch returns fewer than
     `limit` candidates (reaching the end of the eligible set), wrap the cursor back to
     `('-infinity'::timestamptz, '00000000-0000-0000-0000-000000000000'::uuid)` so the next tick
     revisits previously busy rows. This guarantees bounded eventual visitation of every
     uncontended eligible hold even when a prefix remains locked across multiple ticks.
   - *One reservation per short transaction (via `SECURITY DEFINER`):* `openmettle_worker` holds
     `SELECT` only on `quota_reservations` and executes **no direct `SELECT ... FOR NO KEY UPDATE`**
     on any `quota_*` table. For each candidate, the worker opens a bounded `READ COMMITTED`
     transaction and invokes `openmettle.quota_release_unsent(...)` (`SECURITY DEFINER`,
     `SET search_path = pg_catalog`) in sweep mode. Internally, `quota_release_unsent` acquires
     `runs` (`FOR NO KEY UPDATE SKIP LOCKED` when `run_id IS NOT NULL`) -> `quota_reservations`
     (`FOR NO KEY UPDATE SKIP LOCKED`), returning immediately as skipped without waiting if either
     row is contended. Once locked, it re-verifies `state = 'held'`, expiry, terminal run state
     and zero unresolved operations, locks charged `quota_budgets` via `quota_reservation_charges`
     (scope rows ascending then instance row last), inserts `quota_reconciliations` (`source_key =
     'stale_sweep'`), decrements `reserved_held` and sets `state = 'released'`, `held_units = 0`
     and `closed_at = clock_timestamp()`.
2. **Storage holds (`storage_reservations`).**
   - *Non-run uploads (`run_id IS NULL`):* Continue through `artifact_fs::reconcile_expired`
     (requiring `OPENMETTLE_WORKER_ARTIFACTS_DIR`, honoring `coalesce(lease_expires_at,
     created_at + interval '900 seconds') <= clock_timestamp()`), which locks one reservation
     `FOR UPDATE SKIP LOCKED` per transaction while unlinking its unsettled staging/upload paths
     before `storage::release`.
   - *Run-linked storage holds (`run_id IS NOT NULL`):* Requires configured
     `OPENMETTLE_WORKER_ARTIFACTS_DIR` (`ARTIFACTS_DIR`, `artifact_fs::Store`). If `ARTIFACTS_DIR`
     is unavailable or unset, run-linked storage recovery **MUST NOT** call `storage::release` and
     skips this phase without mutating any reservation. Otherwise, scan candidates with `state =
     'reserved'`, filtered **before `LIMIT`** for terminal linked runs, zero
     `intent`/`outcome_unknown` operations and expired `lease_expires_at` (or legacy
     `lease_expires_at IS NULL` meeting the terminal-run grace rule above), ordered by
     `(coalesce(lease_expires_at, created_at) ASC, id ASC)` using an **in-memory keyset cursor
     persisted across 15-second ticks with wraparound** when fewer than `limit` candidates return.
     Process **one reservation per short transaction**:
     1. Lock `runs` (`FOR NO KEY UPDATE SKIP LOCKED`) -> `storage_reservations` (`FOR UPDATE SKIP
        LOCKED`). If either row is contended, skip immediately without blocking.
     2. Re-verify under lock that `state = 'reserved'`, expiry holds, the run is terminal (no
        active worker lease) and zero linked operations are in `('intent', 'outcome_unknown')`.
     3. Inspect `revisions/<id>` under `ARTIFACTS_DIR` (`fs::symlink_metadata`):
        - **Positive `ENOENT` (`NotFound`) proof required before release:** Only when the
          filesystem proves `revisions/<id>` does **not** exist (confirming atomic rename
          `staging/<id> -> revisions/<id>` never occurred and no published bytes still owe SQL
          settlement) may recovery execute and **commit `storage::release`** (or confirm `state =
          'released'`), and then — only after commit — unlink `staging/<id>` if present.
        - **Post-rename, pre-settlement crash window (`revisions/<id>` present):** If
          `revisions/<id>` exists on disk while `storage_reservations.state = 'reserved'` (or if
          filesystem probing returns any error other than `NotFound`), recovery **MUST NOT** call
          `storage::release` and **MUST NOT** unlink `revisions/<id>`. Calling `storage::release`
          would release the held bytes and cause a later `storage::settle` to conflict while
          leaving an uncharged payload on disk. Recovery preserves both the `reserved` byte hold
          and `revisions/<id>` (surfacing overdue/drift visibility) until deterministic retry
          settlement (where durable artifact/spill context exists) settles it into
          `artifact_revisions` or explicit `openmettle_owner` reconciliation settles or purges it.
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
`quota_*` table (`quota_defaults`, `quota_overrides`, `quota_budgets`, `quota_reservations`,
`quota_reservation_charges`, `quota_reconciliations` or `quota_warning_events`).** Because
PostgreSQL 18 requires `UPDATE` privilege to execute `SELECT ... FOR NO KEY UPDATE` or
`FOR UPDATE`, **no runtime role executes direct row-locking `SELECT` on any `quota_*` table**
either; all `quota_*` row locking and writes run strictly inside narrow `openmettle_owner`-owned
`SECURITY DEFINER` functions with `SET search_path = pg_catalog`, schema-qualified relations,
`REVOKE ALL ON FUNCTION ... FROM PUBLIC` and exact `oid::regprocedure` signatures audited in
`src/boundaries.sql` (following [ADR 0030](0030-session-issuance-database-boundary.md) and
ADR 0037).

| Object or `SECURITY DEFINER` entrypoint | `openmettle_api` | `openmettle_worker` | `openmettle_gateway` (Migration `0023`) | `openmettle_issuance` (ADR 0030) |
| --- | --- | --- | --- | --- |
| `quota_defaults` | `SELECT` only | `SELECT` only | `SELECT` only | None |
| `quota_overrides` | `SELECT` only | `SELECT` only | `SELECT` only | None |
| `quota_budgets`, `quota_reservations`, `quota_reservation_charges`, `quota_reconciliations`, `quota_warning_events` | `SELECT` only | `SELECT` only | `SELECT` only | None |
| `openmettle.quota_upsert_scope_override(...)` and `openmettle.quota_revoke_scope_override(...)` | `EXECUTE` (validates caller role & scope/kind/bounds invariants; locks `run_dispatch_lock` for `executing_runs_*`, `projects`/`users`, and `storage_accounts` or active `quota_budgets` in canonical order; upserts/revokes `quota_overrides` and increments `revision` to re-arm warning watermarks) | None | None | None |
| `openmettle.quota_reserve(...)` | `EXECUTE` (tags `origin_role = 'api'`; locks `quota_budgets` internally and records `quota_warning_events`) | `EXECUTE` (tags `origin_role = 'worker'`; locks `quota_budgets` internally and records `quota_warning_events`) | None | None |
| `openmettle.quota_allocate_round(...)` | None | `EXECUTE` (verifies active `Step` lease on `runs`; run-to-round slice transfer only) | None | None |
| `openmettle.quota_commit_handoff(...)` | `EXECUTE` (own `origin_role = 'api'` `held` rows only) | `EXECUTE` (own `origin_role = 'worker'` `held` rows only) | None | None |
| `openmettle.quota_commit_device_handoff(...)` | None | `EXECUTE` (locks `runs -> quota_reservations` in canonical order; verifies active `Step` lease `runs.state = 'running'`, `runs.cancel_reason IS NULL`, matching `claim_token`, `lease_expires_at > clock_timestamp()`; transitions that run's `device_reservations` `held` row with `origin_role IN ('api', 'worker')` to `handoff_committed` bound to durable `device_grant_id`) | None | None |
| `openmettle.quota_renew_lease(...)` | None | `EXECUTE` (`held` run-linked rows only, fenced to active run lease) | None | None |
| `openmettle.quota_release_unsent(...)` | `EXECUTE` (own `origin_role = 'api'` `held` rows only; locks internally and sets `closed_at`) | `EXECUTE` (own `origin_role = 'worker'` `held` or eligible stale/terminal-run `held` rows; locks `runs` and `quota_reservations` internally with `FOR NO KEY UPDATE SKIP LOCKED` in sweep mode and re-verifies eligibility before setting `closed_at`) | None | None |
| `openmettle.quota_settle_gateway_usage(...)` | None | None | `EXECUTE` (`usage_tokens`/`usage_cost_micros` only; verifies accepted ADR 0037 `gateway_report_id`, immutable denomination and `source_revision > accepted_source_revision`; persists `accepted_source_revision` atomically and records `quota_warning_events`) | None |
| `openmettle.quota_release_device_slot(...)` | None | `EXECUTE` (`device_reservations` `handoff_committed` only; verifies durable V1-18 release/non-allocation record; sets `closed_at`) | None | None |
| `openmettle.quota_record_storage_warning(...)` | `EXECUTE` (evaluates storage threshold crossing from locked `storage_accounts`/`storage_instance` and records deduplicated `quota_warning_events`) | `EXECUTE` (same) | None | None |
| `storage_reservations.lease_expires_at` | `INSERT`, `UPDATE` (with migration 4 grants) | `INSERT`, `UPDATE` (with migration 4 grants) | None | None |
| `storage_instance`, `storage_accounts`, `artifacts`, `artifact_revisions` | Existing migration 4 grants (`warn_pct_*`, `config_revision` `SELECT` only) | Existing migration 4 grants (`warn_pct_*`, `config_revision` `SELECT` only) | None | None |

Only `openmettle_owner` writes `quota_defaults` (subject to the
`quota_defaults_cost_denomination_immutable` trigger `OMQ02`, and acquiring
`SELECT FROM openmettle.run_dispatch_lock FOR NO KEY UPDATE` before modifying `executing_runs_*`
defaults) and `storage_instance` limits, warning thresholds and `config_revision`.
`openmettle_issuance` receives zero quota or storage privileges. No runtime role receives
`DELETE`, `TRUNCATE`, DDL or grant options.

**Rolling-upgrade safety for lowered storage overrides.** Older API and worker binaries running
`src/storage.rs` read only `storage_instance.personal_limit_bytes` / `project_limit_bytes` and
would ignore a lowered `quota_overrides` row for `storage_bytes` during a mixed-version rollout.
V1-17 closes this gap with defense in depth:

1. **Activation gate.** `/v1` `setQuotaOverride` writes (PR3) are gated behind rolling-upgrade
   completion (all API and worker replicas running the V1-17 PR2 binary), preventing live clients
   from seeing mixed-version errors during normal deployment.
2. **Fail-closed database backstop trigger (`openmettle.enforce_storage_override()`).** PR2
   attaches a `BEFORE UPDATE` trigger (owned by `openmettle_owner`, `SET search_path = pg_catalog`,
   `REVOKE ALL FROM PUBLIC`) on `openmettle.storage_accounts` that fires **only when total charged
   bytes strictly increase** (`NEW.active_bytes + NEW.retained_bytes + NEW.reserved_bytes >
   OLD.active_bytes + OLD.retained_bytes + OLD.reserved_bytes`). When an active `storage_bytes`
   override exists in `quota_overrides` and the new total exceeds `hard_limit`, the trigger aborts
   the statement with deterministic SQLSTATE `OMQ01`. Legacy `storage::reserve` calls therefore
   fail closed instead of oversubscribing a lowered override, while `settle`, `release`,
   `retain_revision`, `restore_revision` and `confirm_purge` never increase total charged bytes
   and continue working unaffected. Updated PR2 binaries evaluate `quota_overrides` before
   updating `storage_accounts` and return `Error::OwnerLimit` (`429 quota`) cleanly. Legacy
   binaries also safely ignore `storage_reservations.lease_expires_at` (leaving it `NULL`).

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
| PR2 · schema, store and worker recovery | Additive PostgreSQL 18 migration (after Migration `0023`), `SECURITY DEFINER` transition and override functions (`quota_upsert_scope_override`, `quota_revoke_scope_override`, `quota_reserve`, `quota_allocate_round`, `quota_commit_handoff`, `quota_commit_device_handoff`, `quota_renew_lease`, `quota_release_unsent`, `quota_settle_gateway_usage`, `quota_release_device_slot`, `quota_record_storage_warning`), `enforce_storage_override` and `enforce_cost_denomination_immutability` triggers, versioned `src/boundaries.sql` entries, `src/quotas.rs` store, `storage::reserve` override integration, `claim_next` executing-cap override evaluation, DB-plus-filesystem `verify_accounting_drift`, and persistent-cursor `SKIP LOCKED` one-per-tx `reconcile_stale_quotas` in `src/worker.rs`. | PostgreSQL 18 tests in `tests/schema/grants.rs` and `tests/schema/quotas.rs` executing all override, reservation, device-handoff, gateway-settlement and stale-sweep paths **connected as the actual runtime roles** (`openmettle_api`, `openmettle_worker`, `openmettle_gateway`, `openmettle_issuance`) and asserting denial of direct `INSERT`/`UPDATE`/`DELETE`/`SELECT ... FOR NO KEY UPDATE` on all `quota_*` tables and cross-role/unleased calls; N-way concurrent admission non-oversubscription across distinct project/actor/instance windows; non-windowed `device_reservations` surviving UTC rollover and `api`-admitted run device handoff via `quota_commit_device_handoff` under active `claim_token` lease (plus refusal for wrong resource kind or stale/unleased/cancelled run); cross-scope lock-order race with zero deadlocks; concurrent `executing_runs_per_actor` / `executing_runs_per_scope` cap lowering racing `claim_next` (and approval resume) serialized on `run_dispatch_lock` with zero overshoot; exact-once reconciliation across exact replay (recovering server-chosen windows), unique `(gateway_request_id, resource_kind)` enforcement rejecting duplicate keys, run-to-round hold allocation without double-debit, cancellation, pre-send abort (with `closed_at`), partial report persisting `accepted_source_revision` and rejecting delayed older reports, signed downward partial correction (`delta_reserved > 0`), independent token/cost settlement, `cost_denomination` immutability trigger (`OMQ02`) and mismatch quarantine, final overage settlement plus subsequent refusal, upload abort and `confirm_purge`; override raise/lower/expiry and `hard_limit = 0` preserving data and deletion grace; `round_cap` `1..=1000` validation; stale sweep using `SKIP LOCKED` on `runs` and reservations with persistent cross-tick keyset cursor + wraparound proving a multi-tick locked prefix never stalls or starves later rows; run-linked storage recovery requiring configured `ARTIFACTS_DIR` + positive `ENOENT` on `revisions/<id>` before committing `storage::release` and unlinking `staging/<id>` (refusing release and preserving hold + payload when `revisions/<id>` exists while `state = 'reserved'` or `ARTIFACTS_DIR` is unset); restore verification (`verify_accounting_drift`) recognizing `state = 'purging'` with missing `revisions/<id>` (`ENOENT`) as a valid resumable mid-purge state while failing hard on missing `active`/`retained` payloads and DB/V1-06 drift; and populated previous-writer rolling-upgrade test with a lowered `storage_bytes` override proving fail-closed refusal (`OMQ01`) on old `storage::reserve` while `settle`/`release`/`retain`/`purge` succeed. |
| PR3 · `/v1` API, OpenAPI and wired enforcement | `/v1` quota read (with `warnings` projection) and `ManageQuotas` routes (gated on rolling-upgrade completion), OpenAPI 3.2.1 schemas and regenerated `contracts/fixtures/`, independent consumer decoding, and wired quota enforcement in `src/v1/artifacts.rs`, `admit_run`, `claim_next` and ADR 0037 settlement paths. | Contract validation (`tests/contract.rs`) and PostgreSQL 18 HTTP tests on both session channels covering effective limits/usage/reservations/warnings visibility, warning deduplication and re-arming on override/config edits, concurrent `/v1` `setQuotaOverride` lowering of `executing_runs_*` caps racing `claim_next`, `404` concealment for non-members and non-member admins, audited override changes and replay conflicts, safe `429 quota` / `429 rate_limited` / `503 provisioning` RFC 9457 problems with redaction canaries, and allowed reads, downloads, cancellations and deletions at hard limit. |

**Boundaries.** V1-15 (`#15`) and V1-16 (`#16`) own artifact payload transport, retention
policies and deletion journals. V1-06 (`#7`, ADR 0037) owns Migration `0023`, gateway admin
provisioning and authoritative usage feed ingestion. V1-14 (`#14`) owns MCP tool schemas and spill
triggers. V1-18 (`#18`) owns the active GPU controller, DRA claims and physical VRAM handoffs.
V1-29 (`#26`) owns telemetry contract updates when PR2/PR3 register quota metrics.
