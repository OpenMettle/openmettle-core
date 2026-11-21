# 0040 — Transactional quotas and reservation reconciliation

Proposed for V1-17 PR1, 21 November 2026. Refs #17. The base is schema 22 at
`45df33c60e7a84fe8a2db0a8e2d9b93a8d29e5a5`. This design depends on V1-02 (`#3`), V1-05 (`#6`),
V1-10 (`#10`), V1-15 (`#15`) and V1-06 (`#7`, [ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md)).
PR1 records the architecture decision. PR2 and PR3 own schema, store, worker sweeps, `/v1` routes
and verification. This design adds zero Cargo crates.

## Decision

PostgreSQL 18 enforces transactional user and project quotas across active usage, retained data
and outstanding reservations. One shared reservation protocol extends
[ADR 0005](0005-artifact-storage-accounting.md) and
[ADR 0032](0032-durable-run-admission-and-fair-work-queue.md) without adding a service or broker.
Storage bytes, token and provider usage budgets, and active execution or device capacity
reservations remain strictly separate resource classes. Concurrent admissions serialize on budget
rows in a deterministic lock order so competing requests cannot oversubscribe a budget.
Cancellations, aborts, failures, partial usage reports and purges reconcile each reservation
exactly once internally.

| Existing boundary | V1-17 addition |
| --- | --- |
| [ADR 0005](0005-artifact-storage-accounting.md), [`src/storage.rs`](../../src/storage.rs) | Keep `storage_instance`, `storage_accounts`, `storage_reservations` and `artifact_revisions` as the single storage ledger. Add per-scope overrides, warning thresholds, reservation `lease_expires_at` and drift verification. |
| [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md), [`src/artifact_fs.rs`](../../src/artifact_fs.rs) | Bind streaming upload reservations to `lease_expires_at` within the 600 s upload timeout plus 300 s settlement margin. Keep `reconcile_expired` and `purge_due` as the sole upload and purge cleaners. |
| [ADR 0032](0032-durable-run-admission-and-fair-work-queue.md) and [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md), [`src/authz/runs.rs`](../../src/authz/runs.rs) | Keep exact partial-index counts on `runs` for live and executing runs. Resolve per-scope overrides for run limits and `round_limit` at admission. Compose token and device reservation holds inside the `admit_run` transaction and renew run-bound holds on the worker lease cadence. |
| [ADR 0035](0035-approvals-permitted-yolo-and-effect-ledger.md), [`src/authz/approvals.rs`](../../src/authz/approvals.rs) | Keep `StorageReservation` for run-bound artifact and tool-result spills (including V1-14 (`#14`) bounded outputs). Align parked reservation expiry with `resume_execution_expires_at` and never release a hold while a linked operation is `intent` or `outcome_unknown`. |
| [ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md) | Reconcile local token and cost budget holds strictly from authoritative `openmettle_gateway` settlement reports. Protect post-handoff holds from timeout sweeps and record measured overage in full. |
| [ADR 0007](0007-application-api-contract.md) and [ADR 0027](0027-authorization-and-private-projects.md) | Expose authenticated `/v1` effective-quota projections, audited `ManageQuotas` override routes and privacy-safe `429 quota` / `503 provisioning` RFC 9457 problems. |
| V1-18 (`#18`) shared capacity controller | Separate user and project device-reservation quotas from GPU VRAM allocation. Gate admission in PostgreSQL and release device quota holds only after V1-18 confirms backend release or non-allocation. |

## Resource classes, ownership and precedence

OpenMettle separates three resource classes so bytes, provider tokens and device slots never share
a counter or unit. Every quota value is a signed 64-bit nonnegative integer in PostgreSQL and a
`NonNegativeDecimal` on `/v1`. Floating-point arithmetic is forbidden for balances.

| Resource class | Kinds and units | Authoritative store | Charged exposure | Reconciliation owner |
| --- | --- | --- | --- | --- |
| Storage bytes | `storage_bytes` (logical bytes) | `storage_instance`, `storage_accounts`, `storage_reservations`, `artifact_revisions` | `active_bytes + retained_bytes + reserved_bytes` | `openmettle_api` and `openmettle_worker` (`settle`, `release`, `confirm_purge`) |
| Token and provider usage budgets | `usage_tokens` (tokens), `usage_cost_micros` (integer currency micro-units or credits per profile) | `quota_budgets`, `quota_reservations`, `quota_reconciliations` | `active_used + reserved_held` per UTC window or static envelope | `openmettle_gateway` settles provider usage (ADR 0037); API and worker release only proven-unsent `held` holds |
| Active execution and device capacity | `execution_live_runs`, `execution_running_runs`, `execution_round_limit` (counts); `device_reservations` (active job/slot reservations) | Live/executing counts on `runs` (ADR 0032); `device_reservations` holds in `quota_budgets` and `quota_reservations` | Current non-terminal/executing counts on `runs`; `reserved_held` for `device_reservations` | Run transitions settle `runs` counts automatically; V1-18 (`#18`) confirmation settles `device_reservations` |

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
  included in `completion_tokens` so reasoning tokens are never counted twice.
- **Execution and device capacity.** ADR 0032 already enforces `execution_live_runs`,
  `execution_running_runs` and `execution_round_limit` directly from `runs` without a duplicate
  counter table. V1-17 adds optional per-scope overrides for those limits. For GPUs, V1-18 (`#18`)
  owns the active controller, Dynamic Resource Allocation (DRA) claims, physical VRAM observation
  and elastic KV tail handoffs. V1-17 `device_reservations` bounds how many active device-job
  reservations a user or project may hold concurrently without treating DRA claims or physical
  VRAM as storage bytes or token budgets.

### Ownership, scope charging and limit precedence

Every billable resource has one primary accounting scope (`scope_id` in `openmettle.scopes`,
either `personal` or `project`). Sharing a conversation or artifact never changes its accounting
owner or duplicates a charge ([Architecture quota policy](../../ARCHITECTURE-v1.md#quota-policy)).

| Target scope | Storage bytes | Token and provider usage | Execution and device capacity |
| --- | --- | --- | --- |
| `personal` | Charges owner `storage_accounts` and `storage_instance`. | Charges owner `quota_budgets` (and `instance` budget when configured). | Enforces personal actor/scope ceilings. |
| `project` | Charges project `storage_accounts` and `storage_instance`. Does not double-charge the uploading actor's personal storage. | Charges project `quota_budgets` when configured **and** enforces the acting user's personal `quota_budgets` ceiling, because ADR 0037 binds each gateway virtual key and family budget to `(gateway_installation, actor_user_id)`. Both rows reserve atomically in one transaction. | Enforces both project scope ceiling and actor ceiling (matching ADR 0032). |

Effective limits resolve in a strict three-level hierarchy with no implicit OIDC group-to-quota
composition:

1. **Instance hard ceiling.** Operator-configured `storage_instance.instance_budget_bytes` or
   `quota_defaults` row with `scope_kind = 'instance'`. Every new reservation must fit both its
   owner limit and available instance capacity. No administrator override can bypass the instance
   ceiling or physical headroom.
2. **Explicit active administrator override.** One row in `quota_overrides` for `(scope_id,
   resource_kind)` where `revoked_at IS NULL` and `(expires_at IS NULL OR expires_at >
   clock_timestamp())`. Only `account_admin` (`Action::ManageQuotas`, ADR 0027) may set or revoke
   an override.
3. **Operator deployment default.** `storage_instance.personal_limit_bytes` or
   `project_limit_bytes` for storage, or `quota_defaults` for `(scope_kind, resource_kind)`.
   Only `openmettle_owner` writes defaults. If no active override exists and the default is
   `NULL` or absent, admission fails closed with `503 provisioning` (`LimitUnconfigured`,
   matching ADR 0005).

An administrator override can raise or lower a limit and optionally set an expiry. If a reduced
or expired limit falls below current usage, existing artifacts, settled usage and in-flight
reservations remain intact. New reservations fail with `429 quota` until usage falls or the limit
rises. Limit changes never shorten the 30-day deletion grace period or trigger early purge.

Warning thresholds default to 80% and 90% of the effective limit, with hard-limit refusal at
100%. Threshold percentages are operator-configurable in `storage_instance` and `quota_defaults`.
Warning state derives from charged exposure divided by effective limit, and deduplicated warning
records write to `quota_warning_events` without blocking admission.

## Schema, lock order and exact-once reconciliation

PR2 adds the next available forward migration in schema `openmettle` (after schema 22 and any
concurrently landed migrations). The migration is additive and preserves all migration 4 storage
rows and older writers.

```sql
ALTER TABLE openmettle.storage_instance
    ADD COLUMN warn_pct_1 smallint NOT NULL DEFAULT 80 CHECK (warn_pct_1 BETWEEN 1 AND 99),
    ADD COLUMN warn_pct_2 smallint NOT NULL DEFAULT 90
        CHECK (warn_pct_2 BETWEEN 1 AND 99 AND warn_pct_2 > warn_pct_1);

ALTER TABLE openmettle.storage_reservations
    ADD COLUMN lease_expires_at timestamptz,
    ADD CONSTRAINT storage_reservations_lease_check
        CHECK (lease_expires_at IS NULL OR lease_expires_at > created_at);

CREATE TABLE openmettle.quota_defaults (
    scope_kind text NOT NULL CHECK (scope_kind IN ('instance', 'personal', 'project')),
    resource_kind text NOT NULL CHECK (resource_kind IN (
        'usage_tokens', 'usage_cost_micros',
        'execution_live_runs', 'execution_running_runs',
        'execution_round_limit', 'device_reservations'
    )),
    hard_limit bigint CHECK (hard_limit >= 0),
    window_seconds integer CHECK (window_seconds IS NULL OR window_seconds BETWEEN 60 AND 2678400),
    warn_pct_1 smallint NOT NULL DEFAULT 80 CHECK (warn_pct_1 BETWEEN 1 AND 99),
    warn_pct_2 smallint NOT NULL DEFAULT 90
        CHECK (warn_pct_2 BETWEEN 1 AND 99 AND warn_pct_2 > warn_pct_1),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_kind, resource_kind)
);

CREATE TABLE openmettle.quota_overrides (
    scope_id uuid NOT NULL REFERENCES openmettle.scopes (id),
    resource_kind text NOT NULL CHECK (resource_kind IN (
        'storage_bytes', 'usage_tokens', 'usage_cost_micros',
        'execution_live_runs', 'execution_running_runs',
        'execution_round_limit', 'device_reservations'
    )),
    hard_limit bigint NOT NULL CHECK (hard_limit >= 0),
    expires_at timestamptz,
    revoked_at timestamptz,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    reason text NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 256),
    updated_by_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (scope_id, resource_kind)
);

CREATE TABLE openmettle.quota_budgets (
    scope_id uuid NOT NULL REFERENCES openmettle.scopes (id),
    resource_kind text NOT NULL CHECK (resource_kind IN (
        'usage_tokens', 'usage_cost_micros', 'device_reservations'
    )),
    window_start timestamptz NOT NULL,
    window_end timestamptz CHECK (window_end IS NULL OR window_end > window_start),
    active_used bigint NOT NULL DEFAULT 0 CHECK (active_used >= 0),
    reserved_held bigint NOT NULL DEFAULT 0 CHECK (reserved_held >= 0),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (scope_id, resource_kind, window_start)
);

CREATE TABLE openmettle.quota_instance_budgets (
    resource_kind text NOT NULL CHECK (resource_kind IN (
        'usage_tokens', 'usage_cost_micros', 'device_reservations'
    )),
    window_start timestamptz NOT NULL,
    window_end timestamptz CHECK (window_end IS NULL OR window_end > window_start),
    active_used bigint NOT NULL DEFAULT 0 CHECK (active_used >= 0),
    reserved_held bigint NOT NULL DEFAULT 0 CHECK (reserved_held >= 0),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (resource_kind, window_start)
);

CREATE TABLE openmettle.quota_reservations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scope_id uuid NOT NULL REFERENCES openmettle.scopes (id),
    actor_user_id uuid NOT NULL REFERENCES openmettle.users (id),
    actor_scope_id uuid NOT NULL REFERENCES openmettle.scopes (id),
    charged_actor_scope boolean NOT NULL DEFAULT false,
    charged_instance boolean NOT NULL DEFAULT false,
    resource_kind text NOT NULL CHECK (resource_kind IN (
        'usage_tokens', 'usage_cost_micros', 'device_reservations'
    )),
    window_start timestamptz NOT NULL,
    idempotency_key text NOT NULL CHECK (octet_length(idempotency_key) BETWEEN 1 AND 128),
    request_identity bytea NOT NULL CHECK (octet_length(request_identity) <= 1024),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    run_id uuid,
    operation_id uuid,
    gateway_request_id uuid,
    device_grant_id uuid,
    reserved_units bigint NOT NULL CHECK (reserved_units > 0),
    held_units bigint NOT NULL CHECK (held_units >= 0 AND held_units <= reserved_units),
    settled_units bigint NOT NULL DEFAULT 0 CHECK (settled_units >= 0),
    state text NOT NULL DEFAULT 'held'
        CHECK (state IN ('held', 'handoff_committed', 'settled', 'released')),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    lease_expires_at timestamptz NOT NULL,
    closed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (scope_id, actor_user_id, resource_kind, idempotency_key),
    FOREIGN KEY (scope_id, run_id) REFERENCES openmettle.runs (scope_id, id),
    FOREIGN KEY (scope_id, run_id, operation_id)
        REFERENCES openmettle.operations (scope_id, run_id, id),
    CHECK (scope_id <> actor_scope_id OR NOT charged_actor_scope),
    CHECK (operation_id IS NULL OR run_id IS NOT NULL),
    CHECK (gateway_request_id IS NULL OR resource_kind IN ('usage_tokens', 'usage_cost_micros')),
    CHECK (device_grant_id IS NULL OR resource_kind = 'device_reservations'),
    CHECK (
        (state IN ('held', 'handoff_committed') AND closed_at IS NULL)
        OR (state = 'settled' AND held_units = 0 AND closed_at IS NOT NULL AND closed_at >= created_at)
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

CREATE TABLE openmettle.quota_reconciliations (
    reservation_id uuid NOT NULL REFERENCES openmettle.quota_reservations (id),
    transition_revision bigint NOT NULL CHECK (transition_revision >= 1),
    source_key text NOT NULL CHECK (octet_length(source_key) BETWEEN 1 AND 128),
    kind text NOT NULL CHECK (kind IN ('partial_settle', 'final_settle', 'correction', 'release')),
    cumulative_units bigint NOT NULL CHECK (cumulative_units >= 0),
    delta_active bigint NOT NULL,
    delta_reserved bigint NOT NULL CHECK (delta_reserved <= 0),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (reservation_id, transition_revision),
    UNIQUE (reservation_id, source_key)
);

CREATE TABLE openmettle.quota_warning_events (
    scope_id uuid NOT NULL REFERENCES openmettle.scopes (id),
    resource_kind text NOT NULL,
    window_start timestamptz NOT NULL,
    threshold_pct smallint NOT NULL CHECK (threshold_pct BETWEEN 1 AND 99),
    limit_revision bigint NOT NULL CHECK (limit_revision >= 0),
    triggered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (scope_id, resource_kind, window_start, threshold_pct, limit_revision)
);
```

`charged_actor_scope` and `charged_instance` are immutable server decisions recorded at
reservation time outside `request_identity`. Settlement, release and drift verification read
those flags so every reservation adjusts the exact set of `quota_budgets` and
`quota_instance_budgets` rows that `reserve` incremented, even if deployment defaults change
later.

PR2 also extends `authorization_audit` constraints to accept actions `quota.override.set` and
`quota.override.revoke` and target kind `quota_scope`. Audit `details` store only
`{scope_id, resource_kind, old_limit, new_limit, expires_at, revision}`.

### Invariants and post-dispatch overage

- **Nonnegativity.** `CHECK` constraints require `active_used >= 0`, `reserved_held >= 0`,
  `0 <= held_units <= reserved_units` and `settled_units >= 0` (alongside migration 4's
  nonnegative `storage_accounts` and `storage_instance` counters).
- **Non-oversubscription at reservation time.** Every reservation transaction runs at
  `READ COMMITTED` with `SET LOCAL lock_timeout = '2s'` and `statement_timeout = '3s'`. After
  acquiring `FOR NO KEY UPDATE` on each affected `quota_budgets` and `quota_instance_budgets`
  row (or `storage_accounts` then `storage_instance`), the store reads active `quota_overrides`
  and `quota_defaults` in a subsequent statement so any committed limit change is visible. It
  admits the hold only if `active_used + reserved_held + requested <= effective_limit` for every
  charged scope and instance ceiling.
- **Post-dispatch actual provider overage.** `quota_budgets` and `quota_instance_budgets`
  deliberately omit a table-level `CHECK (active_used <= hard_limit)`. Under ADR 0037, actual
  upstream provider usage may exceed the pre-dispatch estimate (`settled_units > reserved_units`).
  Settlement records the full measured overage in `active_used`, reduces `reserved_held` by the
  remaining `held_units`, and commits without failing. Subsequent new reservations then see
  `active_used + reserved_held + requested > effective_limit` and fail with `429 quota` until the
  next accounting window opens or an override raises the limit.

### Deterministic lock order

All quota operations extend the established lock order from
[ADR 0005](0005-artifact-storage-accounting.md),
[ADR 0032](0032-durable-run-admission-and-fair-work-queue.md),
[ADR 0036](0036-conversation-branches-presets-and-effective-model-config.md) and
[ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md):

```text
account_admin_lock -> projects -> users -> runs -> branch_heads
  -> quota_reservations (asc id) / storage_reservations
  -> artifacts -> artifact_revisions
  -> quota_budgets (FOR NO KEY UPDATE, asc (scope_id, resource_kind, window_start))
  -> quota_instance_budgets (FOR NO KEY UPDATE, asc (resource_kind, window_start))
  -> storage_accounts (asc scope_id) -> storage_instance
  -> quota_overrides (written only while holding matching quota_budgets or storage_accounts lock)
```

| Path | Exact lock sequence |
| --- | --- |
| Run admission with usage or device hold (`openmettle_api`) | `projects` (if project) -> actor `users` -> new `runs` row -> upsert and `FOR NO KEY UPDATE` affected `quota_budgets` in ascending `(scope_id, resource_kind, window_start)` order -> `quota_instance_budgets` (`FOR NO KEY UPDATE`, if configured) -> non-locking `SELECT` on `quota_overrides` and `quota_defaults` -> insert `quota_reservations` -> update `reserved_held`. |
| Artifact upload reservation (`openmettle_api` / `openmettle_worker`) | `runs` (if run-linked) -> `storage_accounts` -> non-locking `SELECT` on `quota_overrides` -> `storage_instance` -> insert `storage_reservations` -> update counters. |
| Gateway settlement, pre-send abort or release (`openmettle_gateway` / API / worker) | `runs` (if run-linked) -> `quota_reservations` (`FOR NO KEY UPDATE`) -> affected `quota_budgets` (`FOR NO KEY UPDATE`, asc `(scope_id, resource_kind, window_start)`) -> `quota_instance_budgets` (`FOR NO KEY UPDATE`, if `charged_instance`) -> insert `quota_reconciliations` -> update reservation and budget balances. |
| Storage settlement, release or purge confirmation | `runs` (if release is run-linked) -> `storage_reservations` / `artifact_revisions` -> `artifacts` -> `storage_accounts` -> `storage_instance` (unchanged from ADR 0005). |
| Override write (`openmettle_api`, `ManageQuotas`) | Target `projects` or `users` row -> matching `quota_budgets` (or `storage_accounts`) `FOR NO KEY UPDATE` -> upsert `quota_overrides` -> insert `authorization_audit`. |

During `reserve`, an idempotency replay check performs a non-locking `SELECT` on
`quota_reservations` (matching `src/storage.rs`), so `reserve` never waits on a reservation row
while holding a budget lock. `settle` and `release` always lock the reservation row before budget
rows. No path holding a quota or storage lock waits on `projects`, `users`, `runs` or
`run_dispatch_lock`. If a caller composes multiple unrelated owners and PostgreSQL reports
SQLSTATE `40P01`, the caller rolls back the whole transaction and retries with the identical
idempotency keys.

### Exact-once internal reconciliation

Reservation identity uses ADR 0004 length-prefixed framing with domain
`openmettle/quota-reservation/1\0` over `scope_id`, `actor_user_id`, `actor_scope_id`,
`resource_kind`, `window_start` (big-endian UTC microseconds), `idempotency_key`,
`reserved_units`, optional `run_id`, optional `operation_id`, optional `gateway_request_id` and
optional `device_grant_id`. Each accepted reconciliation increments `quota_reservations.revision`
and inserts `quota_reconciliations` with `transition_revision` set to the next monotonic
reconciliation sequence on that reservation.

| Event | State transition and exact-once accounting |
| --- | --- |
| Exact reservation replay | Same `(scope_id, actor_user_id, resource_kind, idempotency_key)` with matching `request_identity` and `request_digest` returns the existing reservation and state without rechecking limits or double-charging. Changed input returns `409 idempotency_conflict`. |
| Pre-dispatch handoff | Caller locks `quota_reservations` (`FOR NO KEY UPDATE`), requires `state = 'held'`, sets `state = 'handoff_committed'` and commits before sending bytes to the gateway or V1-18 controller. A lost commit reply prevents dispatch. |
| Pre-send abort or queued cancellation | Only while `state = 'held'`: insert `quota_reconciliations` (`kind = 'release'`, `source_key = 'pre_send_abort'` or `'run_cancelled'`), set `state = 'released'`, `held_units = 0`, `delta_reserved = -held_units`. Repeating release is a no-op. |
| Partial gateway usage report (ADR 0037) | Deduplicate `(reservation_id, source_key)`. For new cumulative total `C` above prior `settled_units = S`, compute `delta_active = C - S`, `new_held = max(0, reserved_units - C)` and `delta_reserved = new_held - held_units`. Total exposure (`active_used + reserved_held`) stays constant until `C > reserved_units`. |
| Final gateway report (including overage) | Deduplicate `(reservation_id, source_key)`. Apply `delta_active = C - S` (full overage if `C > reserved_units`) and `delta_reserved = -held_units`. Set `state = 'settled'`, `held_units = 0`, `settled_units = C`, `closed_at = clock_timestamp()`. A late partial report cannot reopen `settled`. |
| Authoritative higher-revision correction | Deduplicate `(reservation_id, source_key)` with `kind = 'correction'`. Require an ordered higher gateway revision; apply signed `delta_active = C_new - settled_units` (`delta_reserved = 0`, rejecting negative `active_used`). Conflicting values at an already accepted revision quarantine without mutating balances. |
| Failed upload, interrupted write or retention purge | Upload failures unlink `staging/<id>` and call `storage::release` once; `settle` moves actual bytes to `active_bytes` and releases `max_bytes - size_bytes` once; `confirm_purge` decrements `retained_bytes` once after confirmed payload deletion (ADR 0005, ADR 0031). |
| Terminal failed, cancelled or interrupted run | Any unallocated `held` quota reservation releases once. Any `handoff_committed` usage or device reservation stays held until `openmettle_gateway` or V1-18 supplies a final report or proof of no charge. Any run-linked `storage_reservations` row stays held while any linked operation is `intent` or `outcome_unknown`. |

**Drift verification and restore.** PR2 adds a read-only `verify_accounting_drift` check that
compares `storage_accounts` and `storage_instance` counters against sums recomputed from
`artifact_revisions` and `storage_reservations`, and compares `quota_budgets.reserved_held` and
`quota_instance_budgets.reserved_held` against
`SUM(quota_reservations.held_units WHERE state IN ('held', 'handoff_committed'))`. Workers run
the check on a bounded maintenance interval and operators run it during restore validation before
reopening dispatch ([Architecture backup and restore](../../ARCHITECTURE-v1.md#backup-and-restore)).
Any mismatch raises an operational alert or restore failure. Runtime roles never silently rewrite
counters to mask drift; repair is an explicit `openmettle_owner` procedure.

## Renewal, stale recovery and database privileges

Every unsettled hold binds its `lease_expires_at` to the lifecycle of its live owner:

- **Multipart uploads (`storage_reservations`, `run_id IS NULL`).** Set `lease_expires_at =
  clock_timestamp() + UPLOAD_TIMEOUT + 300 s` (900 s, ADR 0031). Legacy rows with
  `lease_expires_at IS NULL` keep ADR 0031's `created_at + 900 s` rule.
- **Queued, leased and approval-waiting runs.** Admission sets `lease_expires_at` on run-linked
  holds to `queue_expires_at + 60 s`. When a worker claims or renews a run lease (ADR 0033,
  every `L/3`), it renews `lease_expires_at` on the run's active `held` reservations up to
  `execution_expires_at`. When parking for human approval (ADR 0035), the worker sets
  `lease_expires_at` on the run's active holds (including `StorageReservation` spills) to
  `resume_execution_expires_at` so a valid approval wait never expires its quota hold early.
- **Gateway and device handoffs (`handoff_committed`).** Transitioning to `handoff_committed`
  freezes automatic expiry release. `lease_expires_at` becomes the overdue-reconciliation
  threshold for operator visibility and ADR 0037 backfill prioritization.

### Bounded stale-reservation recovery sweep

PR2 adds a `reconcile_stale_quotas(pool, limit)` sweep to `src/worker.rs` on the ADR 0033
`SWEEP_MS` tick (batch 1–1000, default 100, 15 s budget, alongside `artifact_fs::reconcile_expired`
and `artifact_fs::purge_due`):

1. **Non-storage holds (`quota_reservations`).** Lock up to `limit` rows using
   `WHERE state = 'held' AND lease_expires_at <= clock_timestamp() ORDER BY lease_expires_at, id
   LIMIT $1 FOR UPDATE SKIP LOCKED`. For each locked row, if `run_id IS NOT NULL`, require the
   linked run to be terminal (`succeeded`, `failed`, `cancelled` or `interrupted`) and verify
   zero linked operations in `('intent', 'outcome_unknown')`. Skip any row that fails those
   checks. For eligible rows, lock affected `quota_budgets` in ascending `(scope_id,
   resource_kind, window_start)` order (and `quota_instance_budgets` if `charged_instance`),
   insert `quota_reconciliations` (`kind = 'release'`, `source_key = 'stale_sweep'`), set
   `state = 'released'`, `held_units = 0`, `closed_at = clock_timestamp()`, and decrement
   `reserved_held`.
2. **Storage holds (`storage_reservations`).** Upload holds (`run_id IS NULL`) continue through
   `artifact_fs::reconcile_expired` (requiring `OPENMETTLE_WORKER_ARTIFACTS_DIR` so `staging/<id>`
   and `revisions/<id>` are unlinked under `FOR UPDATE SKIP LOCKED` before `storage::release`).
   Run-linked storage holds (`run_id IS NOT NULL`) whose `lease_expires_at <= clock_timestamp()`
   and whose linked run is terminal are unlinked and passed to `storage::release`, which enforces
   ADR 0005's `Unresolved` guard under the run lock.
3. **Overdue post-handoff visibility.** A separate read-only bounded query counts
   `quota_reservations` in `state = 'handoff_committed'` with `lease_expires_at <=
   clock_timestamp()` and emits a low-cardinality telemetry gauge/counter registered under
   [ADR 0028](0028-telemetry-contract-and-metrics.md) without modifying any row.

### Database privileges (`src/boundaries.sql`)

PR2 version-gates every new grant in [`src/boundaries.sql`](../../src/boundaries.sql) on its
applied migration version ([ADR 0003](0003-schema-migrations.md)). Grants for
`openmettle_gateway` align with the role provisioning introduced by V1-06 PR2 (ADR 0037). No
runtime role receives `DELETE`, `TRUNCATE`, DDL, function execution or grant options.

| Object | `openmettle_api` | `openmettle_worker` | `openmettle_gateway` (ADR 0037) | `openmettle_issuance` (ADR 0030) |
| --- | --- | --- | --- | --- |
| `quota_defaults` | `SELECT` | `SELECT` | `SELECT` | None |
| `quota_overrides` | `SELECT`, `INSERT` and `UPDATE` on non-key override columns | `SELECT` | `SELECT` | None |
| `quota_budgets`, `quota_instance_budgets` | `SELECT`, `INSERT` (key and window columns), `UPDATE (reserved_held, revision, updated_at)` | Same as API | `SELECT`, `UPDATE (active_used, reserved_held, revision, updated_at)` | None |
| `quota_reservations` | `SELECT`, `INSERT` (initial hold columns), `UPDATE (state, held_units, revision, lease_expires_at, closed_at)` | Same as API | `SELECT`, `UPDATE (state, held_units, settled_units, revision, closed_at)` | None |
| `quota_reconciliations` | `SELECT`, `INSERT` (pre-send and cancel releases) | `SELECT`, `INSERT` (pre-send and stale releases) | `SELECT`, `INSERT` (settlements, corrections, confirmed releases) | None |
| `quota_warning_events` | `SELECT`, `INSERT` | `SELECT`, `INSERT` | `SELECT`, `INSERT` | None |
| `storage_reservations.lease_expires_at` | `INSERT`, `UPDATE` (with existing migration 4 grants) | `INSERT`, `UPDATE` (with existing migration 4 grants) | None | None |
| `storage_instance`, `storage_accounts`, `artifacts`, `artifact_revisions` | Existing migration 4 grants (`warn_pct_*` `SELECT` only) | Existing migration 4 grants (`warn_pct_*` `SELECT` only) | None | None |

Only `openmettle_owner` writes `quota_defaults` and `storage_instance` limits and warning
thresholds. Only `openmettle_gateway` holds `UPDATE` on `quota_budgets.active_used` and
`quota_reservations.settled_units`, so API and worker processes cannot forge settled provider
usage. `openmettle_issuance` receives zero quota or storage privileges. As in ADR 0005 and ADR
0033, column privileges bound role authority while Rust helpers enforce reservation invariants;
arbitrary SQL by a role holding `UPDATE (reserved_held)` remains outside database trigger
enforcement and is detected by `verify_accounting_drift`.

During rolling upgrades, older API and worker binaries ignore `lease_expires_at` (leaving it
`NULL`) and continue using migration 4 storage paths safely until every replica upgrades.

## Authenticated visibility and refusal contract

PR3 exposes authenticated `/v1` routes following every [ADR 0007](0007-application-api-contract.md)
rule: `browserSession` (with configured `Origin` on writes) or `nativeSession`,
`OpenMettle-API-Version: 1.<minor>`, `Cache-Control: no-store`, canonical UUIDs, RFC 3339 UTC
`Timestamp`, `NonNegativeDecimal` counters, closed request schemas and extensible responses.

| Operation | Route | Authorization | Result |
| --- | --- | --- | --- |
| `getPersonalQuotas` | `GET /v1/quotas/personal` | Active principal (`401` if inactive) | `200` `QuotaSummary` for the caller's personal scope |
| `getProjectQuotas` | `GET /v1/projects/{project_id}/quotas` | Current project `Read` membership on primary (ADR 0027); non-member, deleted project or non-member `account_admin` receives `404 not_found` | `200` `QuotaSummary` for that project scope only |
| `setQuotaOverride` | `PUT /v1/admin/scopes/{scope_id}/quotas/{resource_kind}` | `Action::ManageQuotas` (`account_admin`), `Idempotency-Key`, closed JSON body `{ hard_limit, expires_at?, reason }` | `200` `QuotaOverride` (`403 policy` for non-admin, `404 not_found` for missing scope, `409 idempotency_conflict` on changed replay) |
| `revokeQuotaOverride` | `POST /v1/admin/scopes/{scope_id}/quotas/{resource_kind}/revoke` | `Action::ManageQuotas`, `Idempotency-Key`, closed JSON body `{ reason }` | `200` `QuotaOverride` (revoked) |

`QuotaSummary` keeps all three resource classes distinct:

- `scope_id`, `scope_kind` (`personal` or `project`), `observed_at`.
- `storage`: `limit_bytes` (nullable), `limit_source` (`default`, `override`, `unconfigured`),
  `override_expires_at` (nullable), `active_bytes`, `retained_bytes`, `reserved_bytes`,
  `charged_bytes`, `remaining_bytes` (clamped at `0` or `null`), `status` (`ok`, `warning_80`,
  `warning_90`, `hard_limit`, `unconfigured`).
- `usage`: array of metered budget items (`resource_kind`, `unit`, `window_start`, `window_end`,
  `limit`, `limit_source`, `override_expires_at`, `active_used`, `reserved_held`, `remaining`,
  `status`, `authoritative_source`, `last_reconciled_at`). A project query returns only the
  project's own budget items, never another member's personal usage.
- `execution`: `live_runs` (`current`, `limit`, `limit_source`), `executing_runs` (`current`,
  `limit`, `limit_source`), `round_limit` (`limit`, `limit_source`).
- `device_capacity`: `active_reservations` (`reserved_held`, `limit`, `limit_source`, `status`),
  distinct from V1-18 physical VRAM telemetry.

**Privacy and cross-tenant isolation.** `remaining_bytes` and `remaining` are computed solely
from `max(0, owner_limit - owner_charged)` so non-admin callers cannot infer another user's
usage by subtracting available instance headroom. `QuotaSummary` never returns reservation UUIDs
of other actors, artifact names, prompts, raw SQL state, override reasons or unshared project
data. `ManageQuotas` inspects and updates scope-level numeric limits only and confers zero access
to private projects, conversations, artifacts or memory (ADR 0027).

### Safe RFC 9457 refusal mapping

| Condition | HTTP status and ADR 0007 code | Fixed public `detail` and additive metadata |
| --- | --- | --- |
| Storage owner or instance hard limit exceeded | `429 quota` | `"The storage quota does not allow this upload."` (or `"The storage quota does not allow this request."`); optional closed `quota: { resource_kind: "storage_bytes", scope_kind }` |
| Token or provider usage budget exceeded | `429 quota` | `"The usage budget does not allow this request."`; optional closed `quota: { resource_kind, scope_kind }` |
| Device reservation quota exceeded | `429 quota` | `"The device reservation quota does not allow this request."`; optional closed `quota: { resource_kind: "device_reservations", scope_kind }` |
| Live or executing run concurrency cap (ADR 0032) | `429 rate_limited` | Existing ADR 0032 rate-limit detail (kept distinct from consumed quota budgets) |
| Missing deployment default and no active override | `503 provisioning` | `"Quota limits are not configured for this resource."` |
| Unauthorized or hidden project scope | `401 unauthenticated` / `404 not_found` / `403 policy` | Unchanged ADR 0027 concealment rules |

The additive `quota` extension carries only low-cardinality `resource_kind` and `scope_kind`
(`personal`, `project` or `instance`) strings, never byte counts, token counts, override reasons,
or another user's identity. When `scope_kind` is `instance`, no capacity numbers are emitted. At
a hard limit (or when a limit drops below usage), authorized reads, downloads, run cancellation,
artifact deletion or retention, and quota reads remain permitted. Every quota refusal and warning
stays redacted under [ADR 0024](0024-process-telemetry-and-redaction.md).

## Delivery and verification

| Slice | Deliverable | Required evidence |
| --- | --- | --- |
| PR1 (this record) | ADR 0040 only. | Review against `#17`, `ARCHITECTURE-v1.md`, ADRs 0005/0007/0027/0031–0033/0035–0037, `ai-guardrails docs audit` (`0` findings) and `scripts/check_repository.py`. |
| PR2 · schema, store and worker recovery | Additive PostgreSQL 18 migration, versioned `src/boundaries.sql` entries, `src/quotas.rs` store, `storage::reserve` override integration, `verify_accounting_drift`, and bounded `reconcile_stale_quotas` in `src/worker.rs`. | PostgreSQL 18 tests covering: N-way concurrent admission non-oversubscription; cross-scope lock-order race with zero deadlocks; exact-once reconciliation across exact replay, cancellation, pre-send abort, partial/final/duplicate/out-of-order gateway reports, post-dispatch provider overage settlement plus subsequent refusal, upload abort and `confirm_purge`; override raise/lower/expiry preserving data and deletion grace; lease renewal and stale-reservation sweep leaving `handoff_committed` and unresolved ADR 0035 operations untouched; drift detection; populated upgrade; and full privilege denials across `openmettle_api`, `openmettle_worker`, `openmettle_gateway` and `openmettle_issuance`. |
| PR3 · `/v1` API, OpenAPI and wired enforcement | `/v1` quota read and `ManageQuotas` routes, OpenAPI 3.2.1 schemas and regenerated `contracts/fixtures/`, independent consumer decoding, and wired quota enforcement in `src/v1/artifacts.rs`, `admit_run` and ADR 0037 settlement paths. | Contract validation (`tests/contract.rs`) and PostgreSQL 18 HTTP tests on both session channels covering effective limits/usage/reservations visibility, `404` concealment for non-members and non-member admins, audited override changes and replay conflicts, safe `429 quota` / `503 provisioning` RFC 9457 problems with redaction canaries, and allowed reads, downloads, cancellations and deletions at hard limit. |

**Boundaries.** V1-15 (`#15`) and V1-16 (`#16`) own artifact payload transport, retention
policies and deletion journals. V1-06 (`#7`, ADR 0037) owns gateway admin provisioning and
authoritative usage feed ingestion. V1-14 (`#14`) owns MCP tool schemas and spill triggers.
V1-18 (`#18`) owns the active GPU controller, DRA claims and physical VRAM handoffs. V1-29
(`#26`) owns telemetry contract updates when PR2/PR3 register quota metrics.
