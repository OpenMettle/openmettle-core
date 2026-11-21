# 0040 — Transactional quotas and reservation reconciliation

Proposed for V1-17 PR1, 21 November 2026. Refs #17. The base is schema 22 at
`45df33c60e7a84fe8a2db0a8e2d9b93a8d29e5a5`. This design depends on V1-02 (`#3`), V1-05 (`#6`),
V1-10 (`#10`), V1-15 (`#15`) and V1-06 (`#7`, [ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md)).
Migration `0023` (`V1-06` PR2 `openmettle_gateway` role provisioning and accepted usage report
schema) is a prerequisite before the V1-17 PR2 migration. PR1 records the architecture decision.
PR2 and PR3 own schema, store, worker sweeps, `/v1` routes and verification. Because `Cargo.toml`
enforces `unsafe_code = "forbid"`, pinned Rust 1.100 does not stabilize `std::fs::Dir` (`dirfd`),
and `Cargo.lock` has no safe directory-relative `*at` wrapper crate, PR2 adds **one minimal safe
POSIX `dirfd` dependency**: `rustix` (`default-features = false, features = ["fs", "std"]`,
`Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`, `https://github.com/bytecodealliance/rustix`;
`bitflags`, `cfg-if`, `errno` and `libc` are already locked in `Cargo.lock`) so all
directory-relative `openat`, `fstat`, `statat(..., AtFlags::SYMLINK_NOFOLLOW)`, `linkat`,
`renameat`, `unlinkat` and `fsync` operations compile safely with zero `unsafe` in `openmettle-core`
(updating the `Cargo.lock` distribution-blocker count per [ADR 0007](0007-application-api-contract.md)
and [ADR 0010](0010-provider-http-transport.md)).

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
| [ADR 0005](0005-artifact-storage-accounting.md), [`src/storage.rs`](../../src/storage.rs) | Keep `storage_instance`, `storage_accounts`, `storage_reservations` and `artifact_revisions` as the single storage ledger. Add `storage_instance.volume_id`, `storage_instance.bootstrap_auto_pin_allowed`, per-scope overrides, fail-closed rolling-upgrade PostgreSQL ledger backstop triggers on `storage_accounts` (`OMQ01`) and on `storage_reservations`/`artifact_revisions` for unpinned `openmettle_worker` releases/purges (`OMQ03`), warning thresholds, reservation `lease_expires_at` and `adoption_unverified` (`storage::settle` clears `adoption_unverified = false`), and DB-plus-filesystem drift verification. |
| [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md), [`src/artifact_fs.rs`](../../src/artifact_fs.rs) | Bind upload reservations (`run_id IS NULL`) to `lease_expires_at` within the 600 s upload timeout plus 300 s settlement margin. Retain `Arc`-shared verified directory descriptors (`root_fd`, `staging_dir_fd`, `revisions_dir_fd`: `OwnedFd` via `rustix::fs::openat` with `OFlags::RDONLY \| OFlags::DIRECTORY \| OFlags::NOFOLLOW`) across `artifact_fs::Store` and execute **all** writer, reader and cleaner operations (`Store::stage` opening with `OFlags::RDWR \| OFlags::CREATE \| OFlags::EXCL \| OFlags::NOFOLLOW` + `LOCK_SH`, `renameat` publication, `fsync`, error/cancellation/drop `unlinkat`, `Store::read`, and all worker cleaners) strictly relative to those verified directory FDs: re-verify `(st_dev, st_ino)` of `<root>`, `"staging"`, and `"revisions"` plus role-tagged sentinels before `Store::stage`, before `renameat`, **and again after `renameat` + `fsync(revisions_dir_fd)` + `fsync(staging_dir_fd)` strictly before `storage::settle`'s `tx.commit()`** (rolling back `storage::settle` with `Error::Io` **without** calling `storage::release` if displaced after `renameat`), while treating live host replacement of `<root>`/`staging`/`revisions` during or after `tx.commit()` as an operational-contract violation caught fail-closed by sentinel verification, `Error::Missing`, `OMQ03`, and `verify_accounting_drift`. Require `artifact_fs::abort` (and every non-run API pre-settlement error release path) to lock `storage_reservations FOR UPDATE` (`WHERE scope_id = $1::uuid AND id = $2::uuid`), verify `state = 'reserved' AND NOT adoption_unverified` and volume/directory identity across `(root_fd, staging_dir_fd, revisions_dir_fd)`, unlink `staging/<id>` relative to `staging_dir_fd` + `fsync(staging_dir_fd)`, and prove `statat(revisions_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` returns `ENOENT` strictly before committing `storage::release` (never releasing when `revisions/<id>` exists, `adoption_unverified = true`, or verification fails). Pin durable artifact volume identity (`storage_instance.volume_id` <-> role-tagged sentinels `<root>/.openmettle-volume-id`, `<root>/revisions/.openmettle-volume-id`, and `<root>/staging/.openmettle-volume-id` opened with `O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK` + `fstat` regular-file/`st_dev` verification and bounded `<= 64`-byte read via safe `rustix` `dirfd` ops, published atomically via unique `.openmettle-volume-id.tmp.<128bit_random_hex>` + `fsync` + `linkat` + own-`tmp_name` `unlinkat`, calling **`fsync(root_fd)` strictly before creating/linking either child sentinel**, then `fsync(revisions_dir_fd)` and `fsync(staging_dir_fd)` before DB update, with matching `st_dev` across all three open directory FDs): lock `openmettle.storage_instance FOR UPDATE` strictly **before** any sentinel write or stale (`st_mtime > 300 s`) `.tmp.*` cleanup on both fresh-bootstrap auto-pinning and `openmettle-admin` adoption (never writing missing sentinels when `volume_id IS NOT NULL`, re-verifying ledger emptiness/newly committed storage rows under `storage_instance FOR UPDATE` before publishing, and adopting any winning valid `:root` UUID on `EEXIST`); gate automatic bootstrap pinning strictly on `src/migrate.rs` fresh-from-zero history (`applied == 0`, `storage_instance.bootstrap_auto_pin_allowed = true`) AND an empty storage ledger (`OMQ03` on every upgrade); require **mandatory pre-migration quiescence of all `N-1` legacy artifact cleaners (unsetting `OPENMETTLE_WORKER_ARTIFACTS_DIR` and draining in-flight `worker::maintenance` sweeps)** before running `openmettle-migrate` (treating `enforce_worker_storage_volume_pinned()` (`OMQ03`) strictly as a PostgreSQL ledger backstop because `N-1` unlinks before mutating PostgreSQL); keep `storage_instance.volume_id IS NULL` across the entire `N-1 -> N` binary replacement; run verified volume adoption only after 100% `N-1 -> N` replacement (unconditionally re-verifying revisions and `'reserved'` payloads, requiring **both** `--expected-fs-uuid <fs_uuid>` **and** `--expected-revisions-inode <dev>:<ino>` whenever `>= 1` ledger row exists with zero digest-bearing revisions verified on disk, including on retry, executing the locked per-reservation accounting classification and `UPDATE openmettle.storage_reservations SET adoption_unverified = true ...` in the **common locked path on BOTH unpinned (`volume_id IS NULL`) AND already-pinned (`volume_id IS NOT NULL`) adoption/verification retries** — re-running on any newly committed `'reserved'` rows — while accepting missing `state = 'purging'` files once volume identity is established and re-querying concurrent `begin_purge` transitions on already-pinned retries; storage-disabled installations with `OPENMETTLE_API_ARTIFACTS_DIR`/`OPENMETTLE_ARTIFACTS_DIR` and `OPENMETTLE_WORKER_ARTIFACTS_DIR` unset and `0` rows in `storage_reservations`/`artifact_revisions` skip volume adoption, keep `volume_id IS NULL` and cleaners disabled, and still activate `metering_enforced = true`); and gate **all** `N` worker cleaners — explicitly including `artifact_fs::purge_due` (which unconditionally calls `fsync(revisions_dir_fd)` strictly before `storage::confirm_purge` **even when `unlinkat` returns `ENOENT`**) alongside `reconcile_expired`, run-linked `ENOENT` recovery and `staging/` cleanup — on verified non-null `volume_id` + all three role-tagged sentinels/`st_dev` before any unlink or DB mutation, excluding `adoption_unverified = true` rows from automatic `ENOENT` cleaners. Keep `reconcile_expired` and `purge_due` as the sole upload and purge cleaners, updating ADR 0031's `reconcile_expired` post-rename behavior (and `tests/schema/artifact_fs.rs`'s `renamed` test case) so non-run uploads (`run_id IS NULL`) enforce the exact same directory-relative `revisions_dir_fd` `ENOENT` proof (`statat(..., AtFlags::SYMLINK_NOFOLLOW)`) as run-linked recovery and never unlink `revisions/<id>` or call `storage::release` when `revisions/<id>` exists while `state = 'reserved'`. Preserve published revision payloads after post-rename/pre-settlement crashes and recognize missing `purging` payloads as a valid resumable mid-purge state during both adoption and restore verification. |
| [ADR 0032](0032-durable-run-admission-and-fair-work-queue.md) and [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md), [`src/authz/runs.rs`](../../src/authz/runs.rs) | Keep exact partial-index counts on `runs` for live and executing runs. Resolve per-scope overrides for live caps and `round_cap` (`1..=1000`) at admission, and serialize `executing_runs_*` cap changes with `claim_next` (including approval resume) via `run_dispatch_lock`. Compose usage and device holds inside admission and renew run-bound holds on the worker lease cadence. |
| [ADR 0035](0035-approvals-permitted-yolo-and-effect-ledger.md), [`src/authz/approvals.rs`](../../src/authz/approvals.rs) | Keep `StorageReservation` for run-bound artifact and tool-result spills (including V1-14 (`#14`) bounded outputs, while explicitly **excluding `idempotency_key LIKE 'tool-spill:%'` from ADR 0040's generic run-linked cleaner** so [ADR 0039](0039-scoped-mcp-adapter-and-bounded-tool-results.md)'s `reconcile_run_spills` is the single cleanup owner for tool spills). Align parked reservation expiry with `resume_execution_expires_at`. Require configured `ARTIFACTS_DIR`, verified non-null pinned `storage_instance.volume_id` <-> role-tagged `.openmettle-volume-id` sentinels in `<root>`, `<root>/revisions`, and `<root>/staging` (`O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK` + `fstat` `S_ISREG`, matching `st_dev` across open directory FDs, bounded `<= 64`-byte read), `NOT adoption_unverified`, and directory-relative `ENOENT` proof that `revisions/<id>` does not exist before committing `storage::release` and unlinking `staging/<id>`, plus retryable staging cleanup via persistent `StagingSweepState` (`Idle`/`Open`/`InFlight`/`InvalidatedInFlight`/`DrainingEof` + `pending_names` held outside `worker::sweep`'s 15 s `tokio::time::timeout`, retaining an open `dir_fd` across `Open`/`InFlight`/`DrainingEof` until `pending_names` is empty, requiring non-blocking `LOCK_EX` + verified `(st_dev, st_ino)` + `set_len(0)` -> `unlinkat` -> `fsync` before removing any `staging/<id>`, and for zero-row orphans additionally requiring `st_mtime > 900 s` on both startup and sweep plus a `storage_instance FOR UPDATE` serialized zero-row recheck while holding `LOCK_EX`); never release or unlink when `revisions/<id>` exists while `state = 'reserved'`, when `adoption_unverified = true`, or when `volume_id IS NULL` or volume identity/sentinel/`revisions/` verification fails. |
| [ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md) | Reconcile local token and cost budget holds strictly from authoritative `openmettle_gateway` settlement reports (`openmettle.gateway_usage_reports` and `openmettle.gateway_settlements` in Migration `0023`, widening `openmettle.gateway_settlements.measured` to `numeric(38, 0)` in PR2's migration with zero edits to frozen `0023`, coupling `quota_settle_gateway_usage` to `gateway_settlements` via `gs.request_id = qr.gateway_request_id AND gs.revision = p_source_revision AND gs.final = r.final` so reports rejected by `gateway_advance_settlement` can never mutate `quota_reservations`, requiring authoritative per-resource evidence before advancing or closing `usage_cost_micros` (`r.cost IS NOT NULL`, deterministic `ceil(r.cost)::numeric(38, 0)`) vs `usage_tokens` (skipping all-`NULL` cost-only reports, keeping partial/incomplete token reports in `'handoff_committed'`, and closing/correcting `'settled'` only on `r.final = true AND r.prompt_tokens IS NOT NULL AND r.completion_tokens IS NOT NULL`) into widened `numeric(38, 0)` aggregate/settlement accumulators) via narrow `SECURITY DEFINER` transitions. Introduce in-transaction `authz::gateway` helpers (`reserve_in`, `handoff_in`, `release_in`) so inserting `'reserved'` `openmettle.gateway_requests` and creating all metered `openmettle.quota_reservations` holds execute atomically in one `WriteTransaction`, backed by a two-phase ADR 0003 rolling-upgrade activation gate (`openmettle.quota_enforcement.metering_enforced`, seeded `true` **only** on genuine fresh-from-zero installs where `src/migrate.rs` observed `applied == 0` AND all core/storage/gateway tables are empty, and `false` on **every** upgrade `applied >= 1` — including unused upgrades with empty tables — until flipped irreversibly `false -> true` in a standalone single-statement transaction by `openmettle_owner`) plus a `DEFERRABLE INITIALLY DEFERRED` commit-time `CONSTRAINT TRIGGER quota_enforce_gateway_handoff_holds` (`openmettle.enforce_gateway_handoff_holds()`, recording handoff-time obligations in `openmettle.quota_gateway_handoffs` **before** acquiring `quota_enforcement FOR SHARE` as the final sink lock and verifying exact `usage_tokens` hold equality `qr.reserved_units = NEW.units AND qr.held_units = NEW.units AND qr.settled_units = 0 AND qr.accepted_source_revision IS NULL` plus ownership match, `OMQ04`, zero edits to frozen `0023`), lease-generation-fenced successor-worker unwind `openmettle.quota_unwind_superseded_round(...)` (checking `quota_reservations.allocating_claim_token` so replay never unwinds the successor's own attempt, and cleanly unwinding unbound `N-1` `'reserved'` rounds), lazy idempotent once-per-run parent hold initialization (`openmettle.quota_ensure_legacy_run_holds`, executed inside the round-allocation `WriteTransaction` strictly **before** `authz::gateway::reserve_in` under `runs` + `gateway_reservations FOR NO KEY UPDATE` reading `units - allocated`) when an `N` worker claims or reclaims an `N-1`-admitted run, and bounded raw index-key paging with a constant clamped age cutoff in `quota_release_orphan_gateway_requests` for pre-V1-17 orphan `'reserved'` rows. Enforce scope-pinned composite FK `(scope_id, gateway_request_id) REFERENCES openmettle.gateway_requests (scope_id, id)`, unique `(gateway_request_id, resource_kind)`, strict `quota_reservations` state `CHECK` constraints (`settled_units = 0 AND accepted_source_revision IS NULL` while `'held'`), a `SECURITY DEFINER` `BEFORE INSERT OR UPDATE` gateway-binding guard trigger enforcing exact `usage_tokens` hold size equality (`reserved_units = req.units`, pre-settlement `settled_units = 0 AND accepted_source_revision IS NULL AND held_units = req.units`, and partially settled `held_units = greatest(0, req.units - settled_units)` backed by `gateway_settlements`, `23514`) alongside `quota_reserve`/`quota_allocate_round`, 32-byte `p_dispatch` secret verification (`dispatch_hash = sha256(p_dispatch)`), ownership recheck under sweep locks, composite FKs to `gateway_usage_reports`, nullable `accepted_source_revision` supporting `revision >= 0` (including `revision = 0`), run-to-round `held` allocation coupled atomically with `openmettle.gateway_handoff` / `openmettle.gateway_release`, caller-scoped `SECURITY DEFINER` `openmettle.quota_recover_lost_handoff` for lost commit-ack recovery (without granting `SELECT` on `gateway_requests`, validating against recorded handoff-time obligations in `quota_gateway_handoffs` and recognizing `'handoff_committed'` and `'settled'` holds across activation), atomic stale-sweep closure of `'reserved'` `gateway_requests` (`'reserved' -> 'released'` + `gateway_reservations` restoration), signed partial corrections and SQL-enforced `BEFORE INSERT OR UPDATE OR DELETE` deployment denomination immutability (`OMQ02`) with the seeded `('instance', 'usage_cost_micros')` row strictly `UPDATE`-only after migration (serialized via `quota_cost_unit_lock` with zero lock cycle alongside a `BEFORE INSERT` guard trigger on `gateway_usage_reports` (`cost IS NOT NULL`, zero edits to frozen `0023`)). |
| [ADR 0007](0007-application-api-contract.md) and [ADR 0027](0027-authorization-and-private-projects.md) | Expose authenticated `/v1` effective-quota projections (including active threshold warnings, keeping `NonNegativeDecimal` (`0..=9223372036854775807`) for `bigint` fields and introducing dedicated `WideNonNegativeDecimal` (`0..=10^38 - 1`, `maxLength: 38`) for wide `numeric(38, 0)` `QuotaSummary` counters), audited `ManageQuotas` override routes backed by `SECURITY DEFINER` functions and privacy-safe `429 quota` / `429 rate_limited` / `503 provisioning` RFC 9457 problems. |
| V1-18 (`#18`) shared capacity controller | Separate user and project concurrent device-slot quotas (`window_kind = 'concurrent'`) from GPU VRAM allocation. Gate admission in PostgreSQL, reject run-linked `device_reservations` holds in generic `quota_commit_handoff`, require lease-fenced `openmettle_worker` handoff of run device holds exclusively via `quota_commit_device_handoff`, and release device quota holds only after durable V1-18 confirmation of backend release or non-allocation. |

## Resource classes, ownership and precedence

OpenMettle separates three resource classes so bytes, provider tokens, cost micro-units, run
concurrency and device slots never share a counter or unit. Per-request admission limits and
reservation inputs (`hard_limit`, `reserved_units`, `allocated_units`, `held_units`) are signed
64-bit nonnegative integers (`bigint`) in PostgreSQL, while aggregate balance and settlement
accumulators (`quota_budgets.active_used`, `quota_budgets.reserved_held`,
`quota_reservations.settled_units`, `quota_reconciliations.cumulative_units`,
`quota_reconciliations.delta_active`, `quota_reconciliations.delta_reserved`, and
`openmettle.gateway_settlements.measured` widened in PR2's migration) use exact 38-digit integer
`numeric(38, 0)` (`scale = 0`, exact integers up to `10^38 - 1`, mapped in Rust via `sqlx` `::text`
<-> `u128` / `i128` with zero new crates) so summing multiple valid overage reports, 3-column
token totals (`prompt_tokens + completion_tokens + reasoning_tokens`), or multi-scope holds into an
instance budget never overflows `bigint` (`22003`). On `/v1`, `bigint` limits and storage byte
counters keep `contracts/openapi/openmettle-v1.json`'s existing `NonNegativeDecimal`
(`0..=9223372036854775807`, `maxLength: 19`), while wide `numeric(38, 0)` `QuotaSummary` counters
(`active_used`, `reserved_held`, etc.) serialize as dedicated **`WideNonNegativeDecimal`**
(`0..=10^38 - 1`, `maxLength: 38`, canonical base-10 integer string without sign, leading zeros,
exponent or fraction). Floating-point arithmetic is forbidden for balances and threshold
comparisons.

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
  `100`) is crossed when `charged >= hard_limit` (short-circuited before multiplication) or
  `charged * 100 >= hard_limit * P` using overflow-safe exact `numeric` / 128-bit integer
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
    ADD COLUMN bootstrap_auto_pin_allowed boolean NOT NULL DEFAULT false,
    ADD COLUMN warn_pct_1 smallint NOT NULL DEFAULT 80 CHECK (warn_pct_1 BETWEEN 1 AND 99),
    ADD COLUMN warn_pct_2 smallint NOT NULL DEFAULT 90
        CHECK (warn_pct_2 BETWEEN 1 AND 99 AND warn_pct_2 > warn_pct_1),
    ADD COLUMN config_revision bigint NOT NULL DEFAULT 1 CHECK (config_revision >= 1),
    ADD CONSTRAINT storage_instance_auto_pin_check
        CHECK (volume_id IS NULL OR NOT bootstrap_auto_pin_allowed);

ALTER TABLE openmettle.storage_reservations
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN adoption_unverified boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT storage_reservations_lease_check
        CHECK (lease_expires_at IS NULL OR lease_expires_at > created_at),
    ADD CONSTRAINT storage_reservations_adoption_unverified_check
        CHECK (NOT adoption_unverified OR state IN ('reserved', 'released'));

-- Plain-column partial B-tree indexes (100% IMMUTABLE in PostgreSQL 18, avoiding
-- STABLE timestamptz + interval expressions) backing two-step raw-index-key paging
-- for both run-linked recovery and non-run reconcile_expired. Run-linked indexes
-- exclude `tool-spill:*` rows because ADR 0039 (`reconcile_run_spills`) is the
-- sole automatic cleanup owner for spilled tool-output reservations.
CREATE INDEX storage_reservations_run_expiry_idx
    ON openmettle.storage_reservations (lease_expires_at, id)
    WHERE state = 'reserved' AND run_id IS NOT NULL
      AND lease_expires_at IS NOT NULL AND NOT adoption_unverified
      AND idempotency_key NOT LIKE 'tool-spill:%';
CREATE INDEX storage_reservations_run_legacy_expiry_idx
    ON openmettle.storage_reservations (created_at, id)
    WHERE state = 'reserved' AND run_id IS NOT NULL
      AND lease_expires_at IS NULL AND NOT adoption_unverified
      AND idempotency_key NOT LIKE 'tool-spill:%';
CREATE INDEX storage_reservations_upload_expiry_idx
    ON openmettle.storage_reservations (lease_expires_at, id)
    WHERE state = 'reserved' AND run_id IS NULL
      AND lease_expires_at IS NOT NULL AND NOT adoption_unverified;
CREATE INDEX storage_reservations_upload_legacy_expiry_idx
    ON openmettle.storage_reservations (created_at, id)
    WHERE state = 'reserved' AND run_id IS NULL
      AND lease_expires_at IS NULL AND NOT adoption_unverified;

-- Widen frozen Migration 0023's gateway_settlements.measured from bigint to
-- numeric(38, 0) without editing Migration 0023. Preserves CHECK (measured >= 0)
-- and nullable measured (NULL for cost-only reports) while accommodating exact
-- 3-column token sums (prompt_tokens + completion_tokens + reasoning_tokens)
-- up to 3 * (2^63 - 1) without bigint overflow.
ALTER TABLE openmettle.gateway_settlements
    ALTER COLUMN measured TYPE numeric(38, 0);

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
-- Seeded true ONLY on genuine fresh-from-zero installations where src/migrate.rs's
-- migrate_within_boundaries captured applied == 0 in openmettle._sqlx_migrations
-- (exposed via pg_catalog.set_config('openmettle.bootstrap_from_zero', ..., false)
-- after RESET ALL before each version run) AND all core, storage and gateway tables
-- are empty. Seeded false on EVERY upgrade (applied >= 1, including unused existing
-- installations with empty users/storage_*/gateway_* tables) until flipped write-once
-- false -> true by openmettle_owner in a standalone single-statement transaction once
-- all N-1 replicas are replaced by N.
CREATE TABLE openmettle.quota_enforcement (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    metering_enforced boolean NOT NULL,
    metering_enforced_at timestamptz,
    CHECK (NOT metering_enforced OR metering_enforced_at IS NOT NULL)
);
WITH fresh AS (
    SELECT coalesce(pg_catalog.current_setting('openmettle.bootstrap_from_zero', true), 'false') = 'true'
           AND NOT EXISTS (SELECT 1 FROM openmettle.users)
           AND NOT EXISTS (SELECT 1 FROM openmettle.scopes)
           AND NOT EXISTS (SELECT 1 FROM openmettle.projects)
           AND NOT EXISTS (SELECT 1 FROM openmettle.runs)
           AND NOT EXISTS (SELECT 1 FROM openmettle.storage_reservations)
           AND NOT EXISTS (SELECT 1 FROM openmettle.artifact_revisions)
           AND NOT EXISTS (SELECT 1 FROM openmettle.gateway_bindings)
           AND NOT EXISTS (SELECT 1 FROM openmettle.gateway_reservations)
           AND NOT EXISTS (SELECT 1 FROM openmettle.gateway_requests) AS is_fresh_bootstrap
),
seed_enforcement AS (
    INSERT INTO openmettle.quota_enforcement (id, metering_enforced, metering_enforced_at)
    SELECT true, is_fresh_bootstrap, CASE WHEN is_fresh_bootstrap THEN clock_timestamp() END
      FROM fresh
)
UPDATE openmettle.storage_instance si
   SET bootstrap_auto_pin_allowed = fresh.is_fresh_bootstrap
  FROM fresh
 WHERE si.id;

-- Records exact handoff-time metering obligations at COMMIT inside
-- enforce_gateway_handoff_holds() (zero schema edits to frozen Migration 0023's
-- openmettle.gateway_requests). Owned by openmettle_owner, REVOKE ALL FROM PUBLIC,
-- zero direct DML grants to runtime roles. Pre-PR2 handed_off rows absent from this
-- table unambiguously had metering_enforced = false, cost_required = false.
CREATE TABLE openmettle.quota_gateway_handoffs (
    gateway_request_id uuid PRIMARY KEY
        REFERENCES openmettle.gateway_requests (id) ON DELETE CASCADE,
    metering_enforced boolean NOT NULL,
    cost_required boolean NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp()
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
    active_used numeric(38, 0) NOT NULL DEFAULT 0 CHECK (active_used >= 0),
    reserved_held numeric(38, 0) NOT NULL DEFAULT 0 CHECK (reserved_held >= 0),
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
    allocating_claim_token uuid,
    run_id uuid,
    operation_id uuid,
    gateway_request_id uuid,
    device_grant_id uuid,
    reserved_units bigint NOT NULL CHECK (reserved_units > 0),
    allocated_units bigint NOT NULL DEFAULT 0
        CHECK (allocated_units >= 0 AND allocated_units <= reserved_units),
    held_units bigint NOT NULL
        CHECK (held_units >= 0 AND held_units <= reserved_units - allocated_units),
    settled_units numeric(38, 0) NOT NULL DEFAULT 0 CHECK (settled_units >= 0),
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
    CHECK (parent_reservation_id IS NULL OR allocating_claim_token IS NOT NULL),
    CHECK (allocated_units = 0
        OR (run_id IS NOT NULL AND gateway_request_id IS NULL AND settled_units = 0)),
    CHECK (gateway_request_id IS NULL OR resource_kind IN ('usage_tokens', 'usage_cost_micros')),
    CHECK (device_grant_id IS NULL OR resource_kind = 'device_reservations'),
    CHECK (
        (state = 'held' AND settled_units = 0 AND accepted_source_revision IS NULL
            AND closed_at IS NULL)
        OR (state = 'handoff_committed' AND closed_at IS NULL
            AND ((accepted_source_revision IS NULL AND settled_units = 0)
                 OR accepted_source_revision IS NOT NULL))
        OR (state = 'settled' AND held_units = 0 AND allocated_units = 0
            AND closed_at IS NOT NULL AND closed_at >= created_at
            AND (gateway_request_id IS NULL OR accepted_source_revision IS NOT NULL))
        OR (state = 'released' AND held_units = 0 AND settled_units = 0
            AND accepted_source_revision IS NULL
            AND closed_at IS NOT NULL AND closed_at >= created_at)
    )
);
CREATE INDEX quota_reservations_held_expiry_idx
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
    cumulative_units numeric(38, 0) NOT NULL CHECK (cumulative_units >= 0),
    delta_active numeric(38, 0) NOT NULL,
    delta_reserved numeric(38, 0) NOT NULL,
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

-- Reinforces scope-pinned FK (scope_id, gateway_request_id) with actor, run,
-- initial 'reserved' state, and exact usage_tokens hold-size equality checks.
-- quota_reserve and quota_allocate_round additionally derive/enforce
-- reserved_units = req.units (held_units = req.units) and verify the caller's
-- 32-byte p_dispatch secret (q.dispatch_hash = sha256(p_dispatch)).
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
        IF NEW.resource_kind = 'usage_tokens' THEN
            IF NEW.reserved_units <> req.units THEN
                RAISE EXCEPTION 'usage_tokens reservation reserved_units must match gateway_requests.units'
                    USING ERRCODE = '23514';
            END IF;
            IF TG_OP = 'INSERT'
               OR NEW.state = 'held'
               OR (NEW.state = 'handoff_committed' AND NEW.accepted_source_revision IS NULL) THEN
                IF NEW.settled_units <> 0
                   OR NEW.accepted_source_revision IS NOT NULL
                   OR NEW.held_units <> req.units THEN
                    RAISE EXCEPTION 'pre-settlement usage_tokens reservation must hold exact gateway_requests.units with zero settled_units'
                        USING ERRCODE = '23514';
                END IF;
            ELSIF NEW.state = 'handoff_committed' AND NEW.accepted_source_revision IS NOT NULL THEN
                IF NEW.held_units <> greatest(0::numeric(38, 0), req.units::numeric(38, 0) - NEW.settled_units)::bigint
                   OR NOT EXISTS (
                       SELECT 1
                         FROM openmettle.gateway_settlements gs
                        WHERE gs.request_id = req.id
                          AND gs.revision >= NEW.accepted_source_revision
                   ) THEN
                    RAISE EXCEPTION 'partially settled usage_tokens reservation must match gateway_settlements and remaining held_units'
                        USING ERRCODE = '23514';
                END IF;
            END IF;
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
-- the same WriteTransaction. Acquires receipt-side locks on
-- openmettle.quota_gateway_handoffs (ROW EXCLUSIVE + FOR KEY SHARE on already-locked
-- gateway_requests(NEW.id)) BEFORE locking openmettle.quota_enforcement FOR SHARE as
-- the final sink lock (preserving ... -> quota_gateway_handoffs -> quota_enforcement
-- while serializing READ COMMITTED commits against openmettle_owner's standalone
-- UPDATE acquiring FOR NO KEY UPDATE).
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

    -- Compute cost requirement via non-locking reads before acquiring table/row locks.
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
    END IF;

    -- Acquire ROW EXCLUSIVE on quota_gateway_handoffs (and FOR KEY SHARE on
    -- gateway_requests(NEW.id), already held FOR UPDATE by gateway_handoff) BEFORE
    -- touching quota_enforcement so quota_enforcement is genuinely the final lock.
    INSERT INTO openmettle.quota_gateway_handoffs (
        gateway_request_id, metering_enforced, cost_required
    ) VALUES (
        NEW.id, false, v_cost_required
    );

    -- Final table/row lock of the transaction: FOR SHARE (not FOR KEY SHARE) conflicts
    -- with openmettle_owner's standalone UPDATE (FOR NO KEY UPDATE) while allowing
    -- concurrent handoffs to run in parallel.
    SELECT metering_enforced INTO STRICT v_enforced
      FROM openmettle.quota_enforcement
     WHERE id
       FOR SHARE;

    IF v_enforced THEN
        IF NOT EXISTS (
            SELECT 1
              FROM openmettle.quota_reservations qr
             WHERE qr.gateway_request_id = NEW.id
               AND qr.resource_kind = 'usage_tokens'
               AND qr.state = 'handoff_committed'
               AND qr.reserved_units = NEW.units
               AND qr.held_units = NEW.units
               AND qr.settled_units = 0
               AND qr.accepted_source_revision IS NULL
               AND qr.scope_id = NEW.scope_id
               AND qr.actor_user_id = NEW.actor_user_id
               AND qr.run_id IS NOT DISTINCT FROM NEW.run_id
        ) THEN
            RAISE EXCEPTION 'missing or mismatched handoff_committed usage_tokens reservation for gateway handoff'
                USING ERRCODE = 'OMQ04';
        END IF;

        IF v_cost_required AND NOT EXISTS (
            SELECT 1
              FROM openmettle.quota_reservations qr
             WHERE qr.gateway_request_id = NEW.id
               AND qr.resource_kind = 'usage_cost_micros'
               AND qr.state = 'handoff_committed'
               AND qr.settled_units = 0
               AND qr.accepted_source_revision IS NULL
               AND qr.scope_id = NEW.scope_id
               AND qr.actor_user_id = NEW.actor_user_id
               AND qr.run_id IS NOT DISTINCT FROM NEW.run_id
        ) THEN
            RAISE EXCEPTION 'missing or mismatched handoff_committed usage_cost_micros reservation for gateway handoff'
                USING ERRCODE = 'OMQ04';
        END IF;

        -- Updates only our own uncommitted tuple on already-locked quota_gateway_handoffs
        -- (no FK on metering_enforced), acquiring zero additional table or FK locks.
        UPDATE openmettle.quota_gateway_handoffs
           SET metering_enforced = true
         WHERE gateway_request_id = NEW.id;
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

-- Added in PR2's migration. PostgreSQL ledger defense-in-depth backstop while
-- storage_instance.volume_id IS NULL (protecting DB storage accounting if an operator
-- forgets mandatory pre-migration N-1 cleaner quiescence on an empty mount; NOT a
-- substitute for quiescing N-1 cleaners before migration because N-1 unlinks before
-- mutating PostgreSQL). openmettle_api (disjoint role per ADR 0003) keeps in-flight
-- upload abort cleanup working.
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
  The table `CHECK` constraints enforce that `state = 'held'` requires `settled_units = 0 AND
  accepted_source_revision IS NULL AND closed_at IS NULL`, `state = 'handoff_committed'` requires
  `closed_at IS NULL AND ((accepted_source_revision IS NULL AND settled_units = 0) OR
  accepted_source_revision IS NOT NULL)`, `state = 'settled'` requires `held_units = 0 AND
  allocated_units = 0 AND closed_at IS NOT NULL AND closed_at >= created_at AND
  (gateway_request_id IS NULL OR accepted_source_revision IS NOT NULL)`, and `state = 'released'`
  requires `held_units = 0 AND settled_units = 0 AND accepted_source_revision IS NULL AND
  closed_at IS NOT NULL AND closed_at >= created_at`. The `SECURITY DEFINER` `BEFORE INSERT OR
  UPDATE` trigger `quota_reservations_gateway_binding_guard`
  (`openmettle.enforce_quota_reservation_gateway_binding()`) enforces immutability of
  `gateway_request_id`, verifies against `openmettle.gateway_requests` that `q.scope_id =
  NEW.scope_id`, `q.actor_user_id = NEW.actor_user_id`, `q.run_id IS NOT DISTINCT FROM
  NEW.run_id`, and on `INSERT` that `q.state = 'reserved'`, and for `NEW.resource_kind =
  'usage_tokens'` enforces `NEW.reserved_units = req.units`, exact pre-settlement hold equality
  (`NEW.settled_units = 0 AND NEW.accepted_source_revision IS NULL AND NEW.held_units =
  req.units`) whenever `TG_OP = 'INSERT'`, `NEW.state = 'held'`, or `(NEW.state =
  'handoff_committed' AND NEW.accepted_source_revision IS NULL)`, and for partially settled
  `handoff_committed` rows (`accepted_source_revision IS NOT NULL`) requires `NEW.held_units =
  greatest(0::numeric(38, 0), req.units::numeric(38, 0) - NEW.settled_units)::bigint` backed by
  an `openmettle.gateway_settlements` row at `revision >= NEW.accepted_source_revision` (raising
  `ERRCODE = '23514'` on any violation). In addition, both `openmettle.quota_reserve(...)`
  (standalone `run_id IS NULL`, when `p_gateway_request_id IS NOT NULL` and `p_resource_kind =
  'usage_tokens'`) and `openmettle.quota_allocate_round(...)` (`run_id IS NOT NULL`, for
  `usage_tokens`) derive/enforce `reserved_units = req.units` (`held_units = req.units`) from the
  locked `gateway_requests` row (rejecting any mismatched caller amount with `ERRCODE = '23514'`)
  and require the caller to present the 32-byte `p_dispatch` secret matching
  `octet_length(p_dispatch) = 32 AND q.dispatch_hash = sha256(p_dispatch)` so no caller can bind
  an under-sized hold or bind to another request even within the same scope and actor. The partial
  unique index `quota_reservations_gateway_request_kind_uidx` (`UNIQUE (gateway_request_id,
  resource_kind) WHERE gateway_request_id IS NOT NULL`) guarantees at most one `usage_tokens`
  reservation and at most one `usage_cost_micros` reservation can bind to a given
  `gateway_request_id`, preventing two distinct `idempotency_key`s from attaching duplicate holds
  to the same gateway request. Likewise, `quota_reservations_device_grant_uidx` binds each durable
  `device_grant_id` to at most one `device_reservations` hold.
- **Commit-time mandatory gateway metering across rolling upgrades (`OMQ04`), strictly serialized
  under `READ COMMITTED`, and deployment-history freshness gating (`src/migrate.rs`).** Because
  frozen Migration `0023` leaves `EXECUTE` on `openmettle.gateway_handoff` granted to
  `openmettle_api` and `openmettle_worker`, an `N-1` binary (`src/authz/gateway.rs`) can still
  commit `gateway_handoff` on its own with zero `quota_reservations` rows. PR2 closes this without
  editing frozen `0023` via three coordinated layers: (a) `src/migrate.rs`'s
  `migrate_within_boundaries` — which already holds SQLx's session advisory lock and inspects
  `openmettle._sqlx_migrations` (`applied = coalesce(max(version), 0)`) before applying pending
  migrations — captures `applied` once before the version loop and executes `SELECT
  pg_catalog.set_config('openmettle.bootstrap_from_zero', CASE WHEN $1 = 0 THEN 'true' ELSE
  'false' END, false)` after `RESET ALL` before each `migrator.run_to(version, ...)` call. PR2's
  migration defines `is_fresh_bootstrap` strictly as `coalesce(pg_catalog.current_setting('openmettle.bootstrap_from_zero',
  true), 'false') = 'true'` **AND** empty `users`, `scopes`, `projects`, `runs`,
  `storage_reservations`, `artifact_revisions`, `gateway_bindings`, `gateway_reservations` and
  `gateway_requests`. The singleton `openmettle.quota_enforcement.metering_enforced` (`SELECT`-granted
  to runtime roles, write-once `false -> true` by `openmettle_owner` in a standalone
  single-statement transaction holding zero other locks, enforced by
  `quota_enforcement_write_once`) and `openmettle.storage_instance.bootstrap_auto_pin_allowed`
  seed `true` **iff `is_fresh_bootstrap`**, and `false` on **every** upgrade (`applied >= 1` —
  even an existing deployment that has never created users, artifacts or gateway rows yet!) so
  `N-1` replicas drain cleanly before `openmettle_owner` (`openmettle-admin`) flips
  `metering_enforced` irreversibly `false -> true`; (b) `DEFERRABLE INITIALLY DEFERRED`
  `CONSTRAINT TRIGGER quota_enforce_gateway_handoff_holds`
  (`openmettle.enforce_gateway_handoff_holds()`, `SECURITY DEFINER`, `SET search_path = pg_catalog`,
  audited in `src/boundaries.sql`) fires at `COMMIT` on `gateway_requests` `'reserved' ->
  'handed_off'`, unconditionally rejecting (`OMQ04`) any bound hold not in `'handoff_committed'`
  even while `metering_enforced = false`, computing `v_cost_required` via non-locking reads, and
  **inserting `(NEW.id, false, v_cost_required)` into `openmettle.quota_gateway_handoffs` FIRST**
  (acquiring `ROW EXCLUSIVE` on `quota_gateway_handoffs` and `FOR KEY SHARE` on already-`FOR
  UPDATE`-locked `gateway_requests(NEW.id)` **before** touching `quota_enforcement`), and **only
  then** locking the singleton `quota_enforcement` row with **`FOR SHARE`** as the **final
  table/row lock of the transaction** (specifically `FOR SHARE`, not `FOR KEY SHARE`, because
  `openmettle_owner`'s activation `UPDATE` acquires `FOR NO KEY UPDATE`, which conflicts with `FOR
  SHARE` while still allowing concurrent handoffs to proceed in parallel): if the trigger acquires
  `FOR SHARE` first, `openmettle_owner`'s `UPDATE` blocks until the handoff commits (so an
  unmetered handoff strictly commits *before* activation); if `openmettle_owner`'s `UPDATE`
  acquires `FOR NO KEY UPDATE` first, the deferred trigger blocks at `FOR SHARE` until activation
  commits, re-reads the committed `metering_enforced = true` row under PostgreSQL `READ COMMITTED`,
  aborts any unmetered `0023`-only handoff with `OMQ04` before `COMMIT` succeeds (rolling back
  both `gateway_requests` to `'reserved'` and the uncommitted `quota_gateway_handoffs` insert so
  `Dispatch` is never returned after activation), and on valid metered handoffs updates only its
  own uncommitted `quota_gateway_handoffs` tuple (`SET metering_enforced = true`, zero additional
  table or FK locks); and (c) `openmettle.quota_gateway_handoffs` (owned by `openmettle_owner`,
  `REVOKE ALL FROM PUBLIC`, zero direct DML grants to runtime roles) preserves exact handoff-time
  obligations so post-commit recovery (`quota_recover_lost_handoff`) validates against
  handoff-time obligations rather than live `quota_enforcement` or live `quota_defaults`.
- **Mandatory pre-migration `N-1` cleaner quiescence + unpinned worker storage volume backstop
  (`OMQ03`).** On **every** upgrade (`applied >= 1`, even with empty `storage_*` tables),
  `storage_instance.bootstrap_auto_pin_allowed` seeds `false` and `storage_instance.volume_id`
  stays `NULL` across the **entire `N-1 -> N` binary replacement** (until zero `N-1` worker
  processes remain running). Because `N-1`'s `artifact_fs::reconcile_expired` unlinks both payload
  paths *before* calling `storage::release` (`src/artifact_fs.rs:660-669`) and `N-1`'s
  `artifact_fs::purge_due` skips any `UPDATE` in `storage::begin_purge` for an already-`'purging'`
  revision (`src/storage.rs:628-636`) and unlinks `revisions/<reservation>` *before*
  `confirm_purge` executes (`src/artifact_fs.rs:694-707`), **operators MUST quiesce all `N-1`
  worker artifact cleaners (unset `OPENMETTLE_WORKER_ARTIFACTS_DIR` across all `N-1` workers and
  drain all in-flight `worker::maintenance` sweeps to completion) BEFORE running
  `openmettle-migrate`**. While `volume_id IS NULL`, `SECURITY DEFINER` `BEFORE UPDATE` trigger
  `openmettle.enforce_worker_storage_volume_pinned()` (`OMQ03`) on both
  `openmettle.storage_reservations` (`OLD.state = 'reserved' AND NEW.state = 'released'`) and
  `openmettle.artifact_revisions` (`NEW.state IN ('purging', 'purged')`) provides a **PostgreSQL
  ledger defense-in-depth backstop** (protecting DB storage accounting if an operator forgets
  quiescence on an empty mount, while leaving disjoint `openmettle_api` in-flight upload abort
  cleanup unaffected) — explicitly **NOT** a substitute for pre-migration `N-1` cleaner quiescence.
  Verified volume adoption pins `storage_instance.volume_id` only after 100% of `N-1` worker
  replicas are replaced by `N` binaries; starting or resuming any `N-1` worker after pinning is
  strictly forbidden by the rollout contract.
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
- **Post-dispatch actual provider overage (overflow-free `numeric(38, 0)` accumulators).**
  `quota_budgets` deliberately omits a table-level `CHECK (active_used <= hard_limit)`. Under
  ADR 0037, actual upstream provider usage may exceed the pre-dispatch estimate (`settled_units >
  reserved_units`). Because `quota_budgets.active_used`, `quota_budgets.reserved_held`,
  `quota_reservations.settled_units`, `quota_reconciliations.cumulative_units`, `delta_active`,
  and `delta_reserved` use exact `numeric(38, 0)` (`scale = 0`, exact 38-digit integer up to
  `10^38 - 1`), summing multiple individually valid large overage reports (or 3-column token
  totals `prompt_tokens + completion_tokens + reasoning_tokens`, or multi-scope holds into an
  `'instance'` budget) never overflows `bigint` (`22003`). Settlement records the full measured
  overage in `active_used`, reduces `reserved_held` by the remaining `held_units`, and commits
  without failing. Subsequent new reservations then see `active_used + reserved_held + requested >
  effective_limit` and fail with `429 quota` until the next accounting window opens or an override
  raises the limit.

### Deterministic lock order

All quota operations extend the established global lock order from
[ADR 0005](0005-artifact-storage-accounting.md),
[ADR 0032](0032-durable-run-admission-and-fair-work-queue.md),
[ADR 0036](0036-conversation-branches-presets-and-effective-model-config.md) and
[ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md) (Migration `0023`):

```text
account_admin_lock -> run_dispatch_lock -> projects -> users -> runs -> branch_heads -> operations
  -> gateway_bindings -> gateway_intents -> gateway_reservations -> gateway_requests (Migration 0023)
  -> gateway_settlements (Migration 0023)
  -> quota_defaults (openmettle_owner only) -> quota_cost_unit_lock (trigger serialization only)
  -> quota_reservations (parent before child) / storage_reservations
  -> artifacts (upload settlement only) / artifact_revisions (retention/purge only)
  -> quota_budgets (FOR NO KEY UPDATE: scope rows asc (scope_id, resource_kind, window_start, id),
                    then instance rows asc (resource_kind, window_start, id))
  -> storage_accounts (asc scope_id) -> storage_instance (singleton instance row last)
  -> quota_overrides (written only inside SECURITY DEFINER while holding matching dispatch/entity/budget lock)
  -> quota_gateway_handoffs (inserted at COMMIT under already-locked gateway_requests FOR UPDATE,
                             strictly BEFORE locking quota_enforcement)
  -> quota_enforcement (pure sink/leaf — final lock of the transaction: FOR SHARE at COMMIT in
                        enforce_gateway_handoff_holds; standalone single-statement UPDATE by
                        openmettle_owner holding zero other locks)
```

| Path | Exact lock sequence |
| --- | --- |
| Run admission with usage/device hold (`openmettle_api`) | `projects` (if project, `FOR NO KEY UPDATE`) -> actor `users` (`FOR NO KEY UPDATE`) -> new `runs` row -> inside `quota_reserve(...)` (`SECURITY DEFINER`): upsert and `FOR NO KEY UPDATE` affected `quota_budgets` (scope rows asc, then instance row last) -> non-locking `SELECT` on `quota_overrides` and `quota_defaults` -> insert `quota_reservations` + `quota_reservation_charges` -> update `reserved_held` and evaluate `quota_warning_events`. |
| Standalone gateway request + metered quota hold (`openmettle_api`, atomic `authz::gateway::reserve_in` + `quota_reserve`) | In **one PostgreSQL `WriteTransaction`**: `authz::gateway::reserve_in(&mut tx, ...)` inserts the caller `gateway_reservations` row (`run_id IS NULL`) and `'reserved'` `gateway_requests` row (whose `gateway_allocate` trigger updates `gateway_reservations.allocated`); immediately in the **same transaction**, `openmettle.quota_reserve(...)` (`SECURITY DEFINER`) locks `gateway_requests` (`FOR SHARE`, verifying `scope_id`, `actor_user_id`, `run_id IS NULL`, `state = 'reserved'`, exact `usage_tokens` hold equality `reserved_units = req.units` / `held_units = req.units` rejecting any mismatch with `23514`, and 32-byte `p_dispatch` matching `dispatch_hash = sha256(p_dispatch)`) -> upserts and `FOR NO KEY UPDATE` affected `quota_budgets` (scope rows asc, then instance row last) -> non-locking `SELECT` on `quota_overrides` and `quota_defaults` -> inserts ALL metered `quota_reservations` holds (`usage_tokens`, `usage_cost_micros`, reinforced by `quota_reservations_gateway_binding_guard`) + `quota_reservation_charges` -> updates `reserved_held` and evaluates `quota_warning_events`. Any quota refusal or pre-commit crash rolls back both `gateway_requests`/`gateway_reservations` and all quota holds atomically. |
| Worker claim and approval resume (`openmettle_worker`, [`src/authz/runs.rs`](../../src/authz/runs.rs)) | `run_dispatch_lock` (`FOR NO KEY UPDATE`) -> one eligible `queued` or approved-`waiting` `runs` row (`FOR NO KEY UPDATE SKIP LOCKED`), evaluating effective `executing_runs_per_actor` and `executing_runs_per_scope` (active `quota_overrides` coalesced with `quota_defaults`) inside the claim query. Serializes directly on `run_dispatch_lock` with `executing_runs_*` override and default updates. `reclaim_next` ([`src/authz/leases.rs`](../../src/authz/leases.rs)) only re-leases already-executing runs (`running`, `cancelling`, `reconciling`) without increasing executing counts or taking `run_dispatch_lock`. |
| Lazy once-per-run parent hold initialization for `N-1`-admitted runs (`openmettle_worker`, `quota_ensure_legacy_run_holds`) | Inside the round-allocation `WriteTransaction` (executed **after** any `quota_unwind_superseded_round` of a crashed predecessor round), **`openmettle.quota_ensure_legacy_run_holds(...)` MUST run strictly BEFORE `authz::gateway::reserve_in(&mut tx, ...)`** on a live leased run `(scope_id, run_id)` admitted by an `N-1` API replica (which created `runs` + `gateway_reservations` with zero local parent `quota_reservations` holds). Lock order: `runs` (`FOR NO KEY UPDATE`, verifying active `Step` lease `state = 'running'`, `cancel_reason IS NULL`, `claim_token = p_claim_token`, `lease_expires_at > clock_timestamp()`) -> non-locking `SELECT` for existing run-level parent `usage_tokens` hold (`parent_reservation_id IS NULL AND gateway_request_id IS NULL`; returns immediately if already present) -> **`gateway_reservations` (`FOR NO KEY UPDATE`**, matching `gateway_allocate`'s `UPDATE` lock mode so the immediately following `reserve_in` performs **zero `FOR SHARE -> FOR NO KEY UPDATE` lock upgrade** and cannot deadlock with `FOR SHARE` settlement readers) reading remaining unallocated admission budget **`units - allocated`** (Migration `0023`'s `units` column) -> upserts and `FOR NO KEY UPDATE` charged `quota_budgets` (scope rows asc, instance row last) -> non-locking `SELECT` on `quota_overrides` and `quota_defaults` (returning `OMQ01` if over budget) -> inserts the missing run-level parent `quota_reservations` hold(s) (`usage_tokens` for `units - allocated` plus applicable `usage_cost_micros` run ceiling, `origin_role = 'worker'`, deterministic idempotency key `("legacy-run-parent", run_id, resource_kind)`) + `quota_reservation_charges`, increments `reserved_held`, and evaluates `quota_warning_events`. Never locks any pre-existing `quota_reservations` row after `quota_budgets`. |
| Run-to-round gateway request + hold allocation (`openmettle_worker`, atomic `quota_ensure_legacy_run_holds` -> `authz::gateway::reserve_in` -> `quota_allocate_round`) | In **one PostgreSQL `WriteTransaction`** (after any `quota_unwind_superseded_round` of a crashed predecessor round): `openmettle.quota_ensure_legacy_run_holds(...)` runs **first** under `runs` (`FOR NO KEY UPDATE`, active `Step` lease) — returning immediately if the run-level parent hold already exists, or locking `gateway_reservations` (`FOR NO KEY UPDATE`), reading `units - allocated`, and inserting the missing parent hold(s) **strictly before `reserve_in` increments `allocated`** -> immediately in the **same transaction**, `authz::gateway::reserve_in(&mut tx, ...)` inserts the `'reserved'` `gateway_requests` row (`run_id IS NOT NULL`, whose `gateway_allocate` trigger updates `gateway_reservations.allocated` under the already-held `FOR NO KEY UPDATE` lock with zero lock upgrade) -> immediately in the **same transaction**, `openmettle.quota_allocate_round(...)` (`SECURITY DEFINER`) re-verifies `runs` (`FOR NO KEY UPDATE`) -> `gateway_reservations` (`FOR SHARE`) -> `gateway_requests` (`FOR SHARE`, verifying `state = 'reserved'`, matching `scope_id`, `actor_user_id`, `run_id`, exact `usage_tokens` hold equality `reserved_units = req.units` / `held_units = req.units` rejecting any mismatch with `23514`, and 32-byte `p_dispatch` matching `dispatch_hash = sha256(p_dispatch)`) -> requires the run-level parent `quota_reservations` hold to already exist and locks it (`FOR NO KEY UPDATE`) -> inserts ALL metered child `quota_reservations` (at least `usage_tokens`, plus `usage_cost_micros` when applicable) in **`state = 'held'`** bound to `gateway_request_id` with **`allocating_claim_token = p_claim_token`** (enforced by `CHECK (parent_reservation_id IS NULL OR allocating_claim_token IS NOT NULL)` and `quota_reservations_gateway_binding_guard`) + copies `quota_reservation_charges` -> decrements parent `held_units` (`slice_units <= parent.held_units`), increments `allocated_units` (`quota_budgets.reserved_held` delta = `0`). Any failure or pre-commit crash rolls back `gateway_requests`, `gateway_reservations.allocated`, any newly initialized legacy parent hold, and all child holds together without stranding `gateway_requests_run_round_active_idx`. |
| Gateway handoff (`openmettle_api` standalone or `openmettle_worker` run round, atomic `authz::gateway::handoff_in` + `quota_commit_handoff`) | In **one PostgreSQL `WriteTransaction`**: `authz::gateway::handoff_in(&mut tx, ...)` invokes `openmettle.gateway_handoff(...)` (Migration `0023`), which locks `account_admin_lock -> projects -> login_providers / local_identity_approvals -> users -> runs` (`FOR SHARE`, verifying active `Step` lease for run rounds) -> `local_sessions` (`FOR SHARE`) -> `gateway_bindings` (`FOR SHARE`) -> `gateway_reservations` (`FOR SHARE`) -> `gateway_requests` (`FOR UPDATE`) and transitions `gateway_requests.state` `'reserved' -> 'handed_off'`; immediately in the **same transaction**, `openmettle.quota_commit_handoff(...)` locks `gateway_requests` (`FOR SHARE`, no lock upgrade; verifying `state = 'handed_off'`) -> `quota_reservations` (`FOR NO KEY UPDATE`, verifying `state = 'held'`, matching `gateway_request_id`, caller role/`origin_role`, and rejecting any run-linked `device_reservations` hold) and transitions `quota_reservations.state` `'held' -> 'handoff_committed'`. At `COMMIT`, deferred `CONSTRAINT TRIGGER quota_enforce_gateway_handoff_holds` (`openmettle.enforce_gateway_handoff_holds()`, `SECURITY DEFINER`) verifies zero bound holds remain outside `'handoff_committed'`, computes `v_cost_required` via non-locking reads, **inserts `(NEW.id, false, v_cost_required)` into `openmettle.quota_gateway_handoffs` FIRST** (acquiring `ROW EXCLUSIVE` on `quota_gateway_handoffs` and `FOR KEY SHARE` on already-`FOR UPDATE`-locked `gateway_requests(NEW.id)` before touching `quota_enforcement`), and **then acquires `FOR SHARE` on singleton `openmettle.quota_enforcement` as the final table/row lock of the transaction** (strictly serializing both commit orders against `openmettle_owner`'s standalone single-statement `UPDATE` acquiring `FOR NO KEY UPDATE` while allowing concurrent handoffs in parallel); if `metering_enforced = true`, it verifies required `'handoff_committed'` holds (`usage_tokens` with exact `qr.reserved_units = NEW.units AND qr.held_units = NEW.units AND qr.settled_units = 0 AND qr.accepted_source_revision IS NULL` plus scope/actor/run ownership match, and applicable `usage_cost_micros` with `qr.settled_units = 0 AND qr.accepted_source_revision IS NULL` plus ownership match, rolling back `gateway_handoff` and the uncommitted `quota_gateway_handoffs` insert with `OMQ04` otherwise) and updates its own uncommitted `quota_gateway_handoffs` tuple (`SET metering_enforced = true`, acquiring zero additional table or FK locks). Any pre-commit or commit-time failure rolls back both transitions before ciphertext leaves the process; on lost commit acknowledgement (`UnknownCommit`), the caller suppresses HTTP dispatch and invokes `openmettle.quota_recover_lost_handoff(...)`. |
| Lost commit-ack handoff recovery (`openmettle_api` / `openmettle_worker`, via `quota_recover_lost_handoff`) | Inside `SECURITY DEFINER`: verify `pg_has_role(session_user, CASE WHEN p_run_id IS NULL THEN 'openmettle_api' ELSE 'openmettle_worker' END, 'USAGE')`, `octet_length(p_dispatch) = 32`, and matching `gateway_requests` (`id`, `dispatch_hash = sha256(p_dispatch)`, `scope_id`, `actor_user_id`, `run_id`) -> lock `(runs ->) gateway_reservations -> gateway_requests -> (parent ->) quota_reservations` (all bound rows in deterministic order, `FOR NO KEY UPDATE`) -> re-verify `(q.scope_id, q.actor_user_id) = (qr.scope_id, qr.actor_user_id) AND q.run_id IS NOT DISTINCT FROM qr.run_id` -> if `gateway_requests.state = 'handed_off'`, read recorded handoff-time obligations from `openmettle.quota_gateway_handoffs` (`COALESCE(metering_enforced, false)`, `COALESCE(cost_required, false)`), assert zero bound holds have `qr.state NOT IN ('handoff_committed', 'settled')` (`OMQ04` if any `'held'` or `'released'` bound row exists — explicitly recognizing `'settled'` as valid committed post-handoff evidence), evaluate required hold presence against `handoff.metering_enforced` and `handoff.cost_required` (NOT live `quota_enforcement` or live `quota_defaults`), and return `'handoff_committed'` (when `handoff.metering_enforced = true` with required `usage_tokens` matching `qr.reserved_units = q.units` and, iff `handoff.cost_required = true`, `usage_cost_micros` in `('handoff_committed', 'settled')`, raising `OMQ04` if missing or mismatched; or when `handoff.metering_enforced = false` and valid post-handoff bound holds exist) or `'unmetered_legacy_handoff'` (when `handoff.metering_enforced = false` and zero bound holds exist, even if live `quota_enforcement.metering_enforced` has since flipped to `true`, keeping HTTP dispatch suppressed in all `'handed_off'` outcomes); otherwise lock charged `quota_budgets` (if not returning to an active `'held'` parent), atomically unwind `'reserved'`/`'released'` `gateway_requests` + `gateway_reservations.allocated` + bound `'held'` `quota_reservations`, and return `'unwound_unsent'`. |
| Fenced successor-worker unwind of superseded `'reserved'` round (`openmettle_worker`, via `quota_unwind_superseded_round`) | Inside `SECURITY DEFINER`: verify `pg_has_role(session_user, 'openmettle_worker', 'USAGE')` and `p_round BETWEEN 1 AND 1000` -> lock `runs` (`FOR NO KEY UPDATE`, verifying current live worker lease `r.scope_id = p_scope_id AND r.id = p_run_id AND r.claim_token = p_claim_token AND r.state IN ('running', 'cancelling', 'reconciling') AND r.lease_expires_at > clock_timestamp()`) -> `gateway_reservations` (`FOR NO KEY UPDATE`) -> active `gateway_requests` `q` for `(run_id = p_run_id, round = p_round, state <> 'released')` (`FOR NO KEY UPDATE`) -> any existing parent `quota_reservations` (`FOR NO KEY UPDATE`, asc `id`) -> any bound child `quota_reservations` (`FOR NO KEY UPDATE`, asc `id`). If `EXISTS (SELECT 1 FROM openmettle.quota_reservations qr WHERE qr.gateway_request_id = q.id AND qr.allocating_claim_token = p_claim_token)`, `q` was allocated by the current lease generation `p_claim_token` itself, so leave `q` and its holds untouched and return `false` (idempotent replay no-op). Only when `q.state = 'reserved'` (never `'handed_off'`) AND zero bound holds carry `allocating_claim_token = p_claim_token`, atomically transition `gateway_requests.state := 'released'` and restore `gateway_reservations.allocated := allocated - q.units`: for an **unbound `N-1` `'reserved'` round** (zero bound child `quota_reservations` rows), this succeeds cleanly without requiring parent `quota_reservations` rows to exist yet; when bound `'held'` child holds exist (predecessor `N` attempt with `allocating_claim_token = T1 <> p_claim_token`), additionally transition all bound `'held'` child holds to `'released'` (`held_units = 0`, `closed_at = clock_timestamp()`) and return their capacity directly to their active `'held'` parent run holds (`allocated_units := allocated_units - child.reserved_units`, `held_units := held_units + child.held_units`, `quota_budgets` delta = `0`). Returns `true` on unwind, leaving `'handed_off'` untouched and returning `false`. |
| Run-linked device handoff (`openmettle_worker`, via `quota_commit_device_handoff`) | **Sole** transition path for run-linked `device_reservations` holds. Inside `SECURITY DEFINER`: `runs` (`FOR NO KEY UPDATE`, verifying active `Step` lease `state = 'running'`, `cancel_reason IS NULL`, matching `claim_token`, `lease_expires_at > clock_timestamp()`) -> `quota_reservations` (`FOR NO KEY UPDATE`, `resource_kind = 'device_reservations'`, `run_id IS NOT NULL`, `origin_role IN ('api', 'worker')`, matching `scope_id` and `run_id`) -> bind durable `device_grant_id` and transition `held -> handoff_committed`. |
| Gateway cost report insert & first `cost_denomination` configuration | `openmettle_owner` configures `('instance', 'usage_cost_micros')` in `quota_defaults` solely via direct `UPDATE` (never `INSERT ... ON CONFLICT`). `enforce_cost_denomination_immutability()` rejects `INSERT` (including `INSERT ... ON CONFLICT`), `DELETE`, and rename into/out of `('instance', 'usage_cost_micros')` with `OMQ02` **without acquiring `quota_cost_unit_lock`**, acquiring `quota_cost_unit_lock` (`FOR UPDATE`) exclusively under `BEFORE UPDATE` after PostgreSQL already holds the `quota_defaults` row lock (`quota_defaults` -> `quota_cost_unit_lock`). `openmettle_gateway` inserting `gateway_usage_reports` (`WHEN NEW.cost IS NOT NULL`) fires `BEFORE INSERT` trigger `enforce_gateway_report_cost_unit()` (`SECURITY DEFINER`), which performs a non-locking `SELECT` on `quota_defaults` (never locking `quota_defaults`) and, when `cost_denomination IS NULL`, locks `quota_cost_unit_lock` (`FOR UPDATE`) before re-checking `quota_defaults` and `gateway_usage_reports` — serializing both commit orders and concurrent unconfigured cost reports with zero lock cycle. |
| Gateway usage settlement or correction (`openmettle_gateway`, via `quota_settle_gateway_usage`) | `openmettle_gateway` first upserts/advances `openmettle.gateway_settlements` (validated by Migration `0023`'s `gateway_advance_settlement` trigger, with `measured` widened to `numeric(38, 0)` in PR2) in the same transaction or a prior committed transaction. Inside `quota_settle_gateway_usage` (`SECURITY DEFINER`): `runs` (if run-linked, `FOR SHARE`) -> `gateway_bindings` (`FOR SHARE`) -> `gateway_reservations` (`FOR SHARE`) -> `gateway_requests` (`FOR KEY SHARE`, non-conflicting with Migration `0023`'s `gateway_mark_settled_final()` `FOR NO KEY UPDATE` lock) -> **`gateway_settlements` (`FOR NO KEY UPDATE`, strictly requiring `gs.request_id = qr.gateway_request_id AND gs.revision = p_source_revision AND gs.final = r.final`)** -> `quota_reservations` (`FOR NO KEY UPDATE`) -> charged `quota_budgets` via `quota_reservation_charges` (scope rows asc, instance row last) -> insert `quota_reconciliations` (with composite FKs to `openmettle.gateway_usage_reports`) -> update reservation (`held_units`, `settled_units`, `accepted_source_revision`, `state`/`closed_at`), budget balances and `quota_warning_events` only when authoritative per-resource evidence is present (`r.cost IS NOT NULL` for `usage_cost_micros`; non-null token evidence / complete final `prompt_tokens IS NOT NULL AND completion_tokens IS NOT NULL` for `usage_tokens`). |
| Pre-send abort, stale release, orphan `'reserved'` gateway sweep or V1-18 device release (via `quota_release_unsent` / `quota_release_orphan_gateway_requests` / `quota_release_device_slot`) | **One reservation/request per short transaction, locks acquired inside `SECURITY DEFINER`:** `runs` (if run-linked: `FOR NO KEY UPDATE SKIP LOCKED` in stale/orphan sweep, `FOR NO KEY UPDATE` on explicit abort/release) -> if bound to `gateway_request_id`, `gateway_reservations` -> `gateway_requests` (explicit pre-send unwind couples with `authz::gateway::release_in(&mut tx, ...)` / `openmettle.gateway_release(p_request, p_dispatch)` after locking `runs`, or verifies `gateway_requests.state = 'released'` from a prior `gateway_release` commit; sweep mode acquires `FOR NO KEY UPDATE SKIP LOCKED` on `gateway_reservations` then `gateway_requests`, proceeds if `gateway_requests.state = 'released'`, **atomically transitions stale `'reserved'` `gateway_requests` to `'released'` and restores `gateway_reservations.allocated`** when expiry/terminal preconditions hold, and leaves `'handed_off'` or locked rows untouched) -> parent `quota_reservations` (if child, `FOR NO KEY UPDATE SKIP LOCKED` in sweep / `FOR NO KEY UPDATE` on explicit release) -> target `quota_reservations` (`FOR NO KEY UPDATE SKIP LOCKED` in stale sweep, `FOR NO KEY UPDATE` on explicit abort/release). Whenever `gateway_request_id IS NOT NULL`, `quota_release_unsent` **explicitly re-verifies `(q.scope_id, q.actor_user_id) = (qr.scope_id, qr.actor_user_id) AND q.run_id IS NOT DISTINCT FROM qr.run_id` under lock before mutating either ledger** (raising an invariant error and mutating neither ledger on mismatch). If unwinding an unsent child hold back to an active `held` parent run hold, transfer `held_units` back to parent (`quota_budgets` delta = `0`); otherwise lock charged `quota_budgets` via `quota_reservation_charges` (scope rows asc, instance row last) -> insert `quota_reconciliations` -> update reservation (`closed_at = clock_timestamp()`) and budget balances. Separately, `openmettle.quota_release_orphan_gateway_requests(...)` captures `v_age_cutoff := clock_timestamp() - p_max_reserved_age` once in PL/pgSQL, clamps scalar `v_upper_created_at` and `v_upper_id` via `IF (p_pass_upper_created_at, p_pass_upper_id) <= (v_age_cutoff, 'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid) THEN ... ELSE ... END IF;`, materializes a bounded page of at most `p_page_size` raw `(created_at, id)` index keys from `gateway_requests_reserved_idx` using only constant PL/pgSQL bounds (zero `clock_timestamp()` inside the `SELECT`), filters binding absence and run eligibility only on those keys, locks `(runs ->) gateway_reservations -> gateway_requests` (`FOR NO KEY UPDATE SKIP LOCKED`) for eligible orphans, and advances the persistent cursor across pages even when a page contains zero orphans. |
| Storage upload reservation (`openmettle_api` / `openmettle_worker`) | `runs` (if run-linked) -> `storage_accounts` (`FOR UPDATE`) -> non-locking `SELECT` on `storage_reservations`, `artifacts`, `quota_overrides` -> `storage_instance` (`FOR UPDATE`) -> insert `storage_reservations` -> update `storage_accounts` then `storage_instance` -> call `quota_record_storage_warning(...)`. |
| Storage upload settlement (`storage::settle`) | `projects` (if authorized in tx) -> `storage_reservations` (`FOR UPDATE`) -> `artifacts` (`FOR UPDATE`) -> insert `artifact_revisions` -> update `storage_reservations` (clearing `adoption_unverified = false`) -> `storage_accounts` -> `storage_instance` (preceded by post-`renameat` / post-`fsync` / pre-`commit` re-verification of `<root>`, `<root>/staging`, and `<root>/revisions`, rolling back without calling `storage::release` if displaced). |
| Storage retention and purge confirmation (`storage::retain_revision`, `restore_revision`, `confirm_purge`; and `begin_purge`) | `storage::retain_revision`, `restore_revision`, and `confirm_purge`: `artifact_revisions` (`FOR UPDATE`) -> `storage_accounts` -> `storage_instance`. `storage::begin_purge` updates only `artifact_revisions` without locking `storage_accounts` or `storage_instance` (none lock `artifacts` or `storage_reservations`, [`src/storage.rs`](../../src/storage.rs)). |
| Storage release (`storage::release` and `artifact_fs::abort`) | `runs` (`FOR NO KEY UPDATE SKIP LOCKED` in worker stale sweep, `FOR NO KEY UPDATE` on explicit release, if `run_id IS NOT NULL`) -> `storage_reservations` (`FOR UPDATE SKIP LOCKED` in sweep, `FOR UPDATE` on explicit release / `artifact_fs::abort`, verifying `state = 'reserved' AND NOT adoption_unverified`, three-directory volume/directory identity, `staging/<id>` unlink + `fsync(staging_dir_fd)`, and `statat(revisions_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` returning `ENOENT` strictly before releasing) -> `storage_accounts` -> `storage_instance`. |
| Storage volume adoption, fresh-bootstrap auto-pinning & `StagingSweepState` orphan recheck (`openmettle-admin` / `Store::open` / `openmettle_worker`) | For `openmettle-admin` adoption (common locked path on **both** initial unpinned `volume_id IS NULL` and already-pinned `volume_id IS NOT NULL` verification retries): `storage_reservations` (`WHERE state = 'reserved' ORDER BY id ASC FOR UPDATE`) -> `storage_instance` (`FOR UPDATE` strictly **before** any sentinel write or stale `.tmp.*` cleanup) -> non-locking `SELECT` re-check on `storage_reservations` and `artifact_revisions` (zero row locks acquired after `storage_instance`; rolling back and retrying from the top before any sentinel write if any newly committed `'reserved'` row appeared outside the locked set on **either** unpinned or already-pinned paths) -> locked per-reservation accounting classification (`staging/<id>` / `revisions/<id>` relative to verified `staging_dir_fd` / `revisions_dir_fd`) + `UPDATE openmettle.storage_reservations SET adoption_unverified = true WHERE id = ANY(...) AND state = 'reserved' AND NOT adoption_unverified` on **both** paths -> atomic sentinel publication (`fsync(root_fd)` strictly before creating/linking `:revisions` or `:staging`, then `fsync(revisions_dir_fd)` and `fsync(staging_dir_fd)` before updating `storage_instance.volume_id`). For `Store::open` fresh-bootstrap auto-pinning: `storage_instance` (`FOR UPDATE`) -> non-locking empty-ledger re-check -> atomic sentinel publication (`fsync(root_fd)` before child sentinels) -> `storage_pin_volume_id(sentinel_uuid)` in the same transaction. For `StagingSweepState` zero-row orphan `staging/<id>` verification: while holding non-blocking `LOCK_EX` on the verified `(st_dev, st_ino)` file (`st_mtime > 900 s`), run a short primary DB transaction acquiring `storage_instance` (`FOR UPDATE`) -> non-locking `NOT EXISTS (SELECT 1 FROM openmettle.storage_reservations WHERE id = $1::uuid)` -> end DB transaction before `set_len(0)` -> `unlinkat` -> `drop` -> `fsync(staging_dir_fd)`. All three serialize cleanly against `storage::reserve`, `settle`, `release`, `retain_revision`, `restore_revision`, and `confirm_purge` (NOT `begin_purge`, which updates only `artifact_revisions` and is handled via fresh `READ COMMITTED` state re-query on already-pinned retries) with zero deadlock. |
| Override write (`openmettle_api` via `quota_upsert_scope_override` / `quota_revoke_scope_override`, `ManageQuotas`) | Inside `SECURITY DEFINER`: if `resource_kind IN ('executing_runs_per_actor', 'executing_runs_per_scope')`, acquire `run_dispatch_lock` (`FOR NO KEY UPDATE`) first -> target entity row (`projects` `FOR NO KEY UPDATE` for project scopes; personal owner `users` `FOR NO KEY UPDATE` for personal/actor scopes) -> if `storage_bytes`, `storage_accounts` (`FOR UPDATE`); if metered usage/device, current active `quota_budgets` (`FOR NO KEY UPDATE`, ascending) -> upsert/revoke `quota_overrides` (incrementing `revision` to re-arm warning watermarks); then caller inserts `authorization_audit` in the same transaction. Live-run and round-cap kinds (`live_runs_*`, `round_cap`) serialize on `projects`/`users` matching `lock_scope_actor`; `openmettle_owner` updates to `executing_runs_*` rows in `quota_defaults` also acquire `run_dispatch_lock` (`FOR NO KEY UPDATE`) first so default cap changes serialize with `claim_next`. |

During `quota_reserve` and `quota_ensure_legacy_run_holds`, the idempotency / existing-parent
lookup performs a non-locking `SELECT` on `quota_reservations` (matching `src/storage.rs`), so
neither ever waits on a pre-existing reservation row while holding a budget lock. `settle`,
`allocate_round` (requiring parent holds to exist before `reserve_in`), `commit_handoff`,
`commit_device_handoff`, `recover_lost_handoff`, `unwind_superseded_round` and `release` always
lock the run, gateway and reservation rows before budget rows. Inside
`quota_settle_gateway_usage`, locking `gateway_requests` (`FOR KEY SHARE`) -> `gateway_settlements`
(`FOR NO KEY UPDATE`) strictly follows the global order and cannot deadlock with Migration
`0023`'s `gateway_mark_settled_final()` (`AFTER INSERT OR UPDATE OF final ON gateway_settlements`
-> `UPDATE gateway_requests SET settled_final = true`, acquiring `FOR NO KEY UPDATE`) because
`FOR KEY SHARE` and `FOR NO KEY UPDATE` on `gateway_requests` are mutually compatible in
PostgreSQL. Storage volume adoption (`storage_reservations` ascending `id` -> `storage_instance`),
fresh-bootstrap auto-pinning (`storage_instance` only), and `StagingSweepState` zero-row orphan
verification (`storage_instance` only) acquire zero row locks after `storage_instance FOR UPDATE`.
`enforce_cost_denomination_immutability` never acquires `quota_cost_unit_lock` during `INSERT` or
rename (only under `BEFORE UPDATE` after the `quota_defaults` row lock is already held),
`enforce_gateway_report_cost_unit` never locks `quota_defaults` (only `quota_cost_unit_lock`),
`enforce_worker_storage_volume_pinned` performs strictly a non-locking `SELECT`, and
`enforce_gateway_handoff_holds()` inserts into `openmettle.quota_gateway_handoffs` (referencing the
already-`FOR UPDATE`-locked `gateway_requests` row) **before** acquiring **`FOR SHARE`** on
`openmettle.quota_enforcement` as the final table/row lock of the transaction (updating only its
own uncommitted `quota_gateway_handoffs` tuple with zero additional locks when `metering_enforced
= true`), while `openmettle_owner` flips `openmettle.quota_enforcement` in a **standalone
single-statement transaction** holding zero other locks — strictly matching `... ->
quota_gateway_handoffs -> quota_enforcement` and making `quota_enforcement` a genuine pure
sink/leaf in the lock graph so no path holding `quota_enforcement` ever waits on another lock.
Likewise, no path holding a `quota_reservations`, `quota_budgets`, `storage_*` or `quota_overrides`
lock waits on `quota_defaults` or `quota_cost_unit_lock`; no path holding a `projects`, `users`,
`runs`, quota or storage lock waits on `run_dispatch_lock`; and no path holding a quota or storage
lock waits on `projects`, `users`, `runs`, `gateway_bindings`, `gateway_intents`,
`gateway_reservations`, `gateway_requests` or `gateway_settlements`, making the global lock graph
strictly acyclic. If a caller composes multiple unrelated owners and PostgreSQL reports SQLSTATE
`40P01`, the caller rolls back the whole transaction and retries with identical idempotency keys.

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
rows according to **strict per-resource authoritative evidence** (per
[ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md): absent fields stay unknown,
reported units settle independently, and unresolved reserved units remain held). Because frozen
Migration `0023` defines `gateway_usage_reports.cost` as `numeric CHECK (cost >= 0 AND cost < 1e18
AND scale(cost) <= 12)`, defines `prompt_tokens`, `completion_tokens`, and `reasoning_tokens` as
nullable `bigint` columns, and defines `gateway_settlements.measured` as `bigint` — where summing
several valid large overage reports into `quota_budgets.active_used` (or summing 3 `bigint` token
columns into `gateway_settlements.measured` or `quota_reservations.settled_units`, or summing
scope holds into the `'instance'` `quota_budgets.reserved_held` row) could exceed `bigint` max
(`9,223,372,036,854,775,807`) and fail with SQLSTATE `22003` — PR2's migration widens
`openmettle.gateway_settlements.measured` to **`numeric(38, 0)`** (zero edits to frozen `0023`,
preserving `CHECK (measured >= 0)` and nullable `measured` for cost-only reports) alongside exact
**`numeric(38, 0)`** (`scale = 0`, up to `10^38 - 1`, zero floating-point rounding) on
`quota_reservations.settled_units`, `quota_reconciliations.cumulative_units`,
`quota_reconciliations.delta_active`, `quota_reconciliations.delta_reserved`,
`quota_budgets.active_used`, and `quota_budgets.reserved_held`. Furthermore, `openmettle_gateway`
MUST advance `openmettle.gateway_settlements` first (in the same transaction or committed
beforehand), and `openmettle.quota_settle_gateway_usage(...)` locks `gateway_requests` (`FOR KEY
SHARE`) -> `gateway_settlements gs` (`FOR NO KEY UPDATE`) before locking `quota_reservations` and
strictly requires **`gs.request_id = qr.gateway_request_id AND gs.revision = p_source_revision AND
gs.final = r.final`**, guaranteeing that any report stored in `gateway_usage_reports` but rejected
by `gateway_settlements` (`gateway_advance_settlement`, such as a late partial report stored after
a final settlement) is rejected even for a lagging `handoff_committed` hold. Per-resource evidence
rules in `quota_settle_gateway_usage` (and `quota_verify_accounting_drift()`):

- **`usage_cost_micros`:** authoritative cost evidence requires **`r.cost IS NOT NULL`** (with
  `r.unit = cost_denomination`), computing **`C_cost = ceil(r.cost)::numeric(38, 0)`** directly
  from cumulative `r.cost` (ceiling toward `+infinity`, never rounding incremental deltas; `0 ->
  0`, `0.5 -> 1`, zero sub-micro-unit free-spend leakage). Whenever **`r.cost IS NULL`**
  (token-only partial, final, or post-final correction report), `quota_settle_gateway_usage`
  **skips `usage_cost_micros` completely** — preserving its current `state`, `held_units`
  exposure, `settled_units`, and `accepted_source_revision`.
- **`usage_tokens`:**
  - *Absent token evidence (`r.prompt_tokens IS NULL AND r.completion_tokens IS NULL AND
    r.reasoning_tokens IS NULL`, e.g., a cost-only report):* `C_tokens` is `NULL` (unknown);
    `quota_settle_gateway_usage` **skips `usage_tokens` completely** — preserving its current
    `state`, `held_units` exposure, `settled_units`, and `accepted_source_revision` on both
    `handoff_committed` and `settled` rows (never treating all-`NULL` token columns as `0`!).
  - *Partial or incomplete token evidence (`NOT r.final` with at least one non-null token column,
    OR `r.final = true` where `r.prompt_tokens IS NULL OR r.completion_tokens IS NULL` while at
    least one token column is non-null):* valid **only** while `qr.state = 'handoff_committed'`;
    computes confirmed partial tokens **`C_tokens = coalesce(r.prompt_tokens, 0)::numeric(38, 0) +
    coalesce(r.completion_tokens, 0)::numeric(38, 0) + CASE WHEN r.reasoning_included IS FALSE THEN
    coalesce(r.reasoning_tokens, 0)::numeric(38, 0) ELSE 0 END`**, updates `settled_units =
    C_tokens` and `held_units = greatest(0::numeric(38, 0), reserved_units::numeric(38, 0) -
    C_tokens)::bigint`, and **keeps `qr.state = 'handoff_committed'`** (never releasing unconfirmed
    remainder and never overwriting an already-`'settled'` `usage_tokens` row).
  - *Authoritative complete final token evidence (`r.final = true AND r.prompt_tokens IS NOT NULL
    AND r.completion_tokens IS NOT NULL`, with Migration `0023`'s `r.reasoning_tokens IS NULL OR
    r.reasoning_included IS NOT NULL`):* computes **`C_tokens = r.prompt_tokens::numeric(38, 0) +
    r.completion_tokens::numeric(38, 0) + CASE WHEN r.reasoning_included IS FALSE THEN
    coalesce(r.reasoning_tokens, 0)::numeric(38, 0) ELSE 0 END`**; transitions `handoff_committed
    -> settled` (`held_units = 0`, `settled_units = C_tokens`, including explicit `prompt_tokens =
    0, completion_tokens = 0` zero-token final proof) or applies a post-final authoritative
    correction on `state = 'settled'`.

| Event | State transition and exact-once accounting |
| --- | --- |
| Exact reservation replay | Same `(scope_id, actor_user_id, resource_kind, idempotency_key)` with matching `request_identity` and `request_digest` returns the existing reservation, state and server-selected charged windows without rechecking limits or double-charging. Changed input returns `409 idempotency_conflict`. |
| Atomic gateway request + metered hold creation (`authz::gateway::reserve_in` + `quota_reserve` / `quota_ensure_legacy_run_holds` -> `authz::gateway::reserve_in` -> `quota_allocate_round`, ADR 0037 / Migration `0023`) | In Migration `0023`'s `src/authz/gateway.rs`, standalone `authz::gateway::reserve()` commits `gateway_requests` before returning, which would leave `gateway_reservations.allocated` stranded and occupy `gateway_requests_run_round_active_idx` if a process crashed before creating `quota_reservations`. PR2 therefore introduces in-transaction helpers `authz::gateway::reserve_in(&mut WriteTransaction, ...)` (alongside `handoff_in` and `release_in`) so **inserting the `'reserved'` `openmettle.gateway_requests` row (plus the caller `gateway_reservations` row when `run_id IS NULL`) and creating ALL corresponding metered `openmettle.quota_reservations` holds (`usage_tokens`, `usage_cost_micros` via `quota_reserve` for standalone calls or `quota_allocate_round` for run rounds) execute atomically in a single PostgreSQL `WriteTransaction`** — rolling back both if any quota hold fails or the process crashes before commit. Both `quota_reserve` and `quota_allocate_round` (reinforced by `quota_reservations_gateway_binding_guard`) verify `q.scope_id = scope_id`, `q.actor_user_id = actor_user_id`, `q.run_id IS NOT DISTINCT FROM run_id`, `q.state = 'reserved'`, the caller's 32-byte `p_dispatch` secret (`q.dispatch_hash = sha256(p_dispatch)`), and — for `resource_kind = 'usage_tokens'` — **derive/enforce exact hold-size equality `reserved_units = q.units` (`held_units = q.units`)**, rejecting any mismatched caller amount (`<` or `>` `q.units`) with `ERRCODE = '23514'`. **Lazy once-per-run parent hold backfill for `N-1`-admitted runs (strictly before `reserve_in`):** because a run admitted by an `N-1` API replica created `runs` + `gateway_reservations` with zero local parent `quota_reservations` holds, and `gateway_allocate` immediately increments `gateway_reservations.allocated` as soon as `reserve_in` inserts `gateway_requests`, initializing the parent *after* `reserve_in` would subtract the replacement round twice. Therefore, inside the single round-allocation `WriteTransaction` (executed **after** any `quota_unwind_superseded_round` of a crashed predecessor round), **`openmettle.quota_ensure_legacy_run_holds(...)` MUST run strictly BEFORE `authz::gateway::reserve_in(&mut tx, ...)`**: under `runs` (`FOR NO KEY UPDATE`, active `Step` lease), it performs a non-locking `SELECT` for an existing run-level parent `usage_tokens` hold (`parent_reservation_id IS NULL AND gateway_request_id IS NULL`, returning immediately if present); if absent, it locks **`gateway_reservations` (`FOR NO KEY UPDATE`**, matching `gateway_allocate`'s `UPDATE` lock mode so the immediately following `reserve_in` performs zero `FOR SHARE -> FOR NO KEY UPDATE` lock upgrade and cannot deadlock with `FOR SHARE` settlement readers), reads remaining unallocated admission budget **`units - allocated`** (frozen Migration `0023`'s `units` column), locks charged `quota_budgets` (scope rows asc, instance row last, `FOR NO KEY UPDATE`), checks active hard limits (returning `OMQ01` if over budget), and inserts the missing run-level parent `quota_reservations` hold(s) (`usage_tokens` for `units - allocated` plus applicable `usage_cost_micros` run ceiling, `origin_role = 'worker'`, deterministic idempotency key `("legacy-run-parent", run_id, resource_kind)`) **exactly once** (terminal/settlement cleanup releases any unallocated remainder on that `origin_role = 'worker'` parent hold identically to normal parent holds; subsequent rounds and retries see the parent hold already present and allocate child holds normally without re-charging `quota_budgets`). Immediately in the **same `WriteTransaction`**, `authz::gateway::reserve_in(&mut tx, ...)` inserts the `'reserved'` `gateway_requests` row (updating `allocated` under the already-held `FOR NO KEY UPDATE` lock) and `quota_allocate_round` requires the parent hold to already exist, verifies the worker's active `Step` lease on `runs`, derives/enforces `slice_units = q.units` for `usage_tokens` (rejecting any mismatch with `23514`), and transfers `slice_units <= parent.held_units` from the server-owned run's `held` parent reservation to a child round reservation in **`state = 'held'`** (pre-handoff) bound to `gateway_request_id` with **`allocating_claim_token = p_claim_token`** (at least a `usage_tokens` child hold on every `N` round allocation, plus `usage_cost_micros` when applicable), copying `quota_reservation_charges`. Parent decrements `held_units` and increments `allocated_units`; `quota_budgets.reserved_held` changes by `0` (never double-debited). Because the child stays `'held'` until dispatch handoff, a pre-send failure never orphans it in `'handoff_committed'`. Unallocated parent remainder releases once when the run can start no further rounds. |
| Gateway & standalone pre-dispatch handoff (`authz::gateway::handoff_in` + `quota_commit_handoff`, `quota_enforce_gateway_handoff_holds`, plus `quota_recover_lost_handoff`) | For metered usage holds (`usage_tokens`, `usage_cost_micros`) — both standalone API calls (`openmettle_api`, `run_id IS NULL`) and worker run rounds (`openmettle_worker`, `run_id IS NOT NULL`) — `quota_commit_handoff` executes **atomically in the same `WriteTransaction` immediately after `authz::gateway::handoff_in` / `openmettle.gateway_handoff(...)`**, locking `gateway_requests` (`FOR SHARE`) to verify `gateway_requests.state = 'handed_off'` before transitioning the caller's matching `held` reservation (`origin_role` matching caller) to `'handoff_committed'`. At `COMMIT`, `DEFERRABLE INITIALLY DEFERRED` `CONSTRAINT TRIGGER quota_enforce_gateway_handoff_holds` (`openmettle.enforce_gateway_handoff_holds()`, `OMQ04`) unconditionally rejects any bound hold left outside `'handoff_committed'` (even while `metering_enforced = false`), computes `v_cost_required` via non-locking reads, **inserts `(NEW.id, false, v_cost_required)` into `openmettle.quota_gateway_handoffs` FIRST**, and **then acquires `FOR SHARE` on singleton `openmettle.quota_enforcement` as the final lock** (serializing both commit orders against `openmettle_owner`'s standalone `UPDATE` acquiring `FOR NO KEY UPDATE`); when `metering_enforced = true`, it requires a bound `'handoff_committed'` `usage_tokens` hold with **exact hold equality, zero pre-handoff settlement, and ownership match** (`qr.reserved_units = NEW.units AND qr.held_units = NEW.units AND qr.settled_units = 0 AND qr.accepted_source_revision IS NULL AND qr.scope_id = NEW.scope_id AND qr.actor_user_id = NEW.actor_user_id AND qr.run_id IS NOT DISTINCT FROM NEW.run_id`) plus any applicable `usage_cost_micros` hold (`qr.settled_units = 0 AND qr.accepted_source_revision IS NULL` matching `(scope_id, actor_user_id, run_id)`, rolling back any `N-1` `0023`-only `gateway_handoff`, mismatched hold, and the uncommitted `quota_gateway_handoffs` insert cleanly with `OMQ04`) and updates only its own uncommitted `quota_gateway_handoffs` row (`SET metering_enforced = true`, zero additional locks). Any pre-commit or commit-time refusal rolls back both transitions cleanly and prevents dispatch. On a **lost commit acknowledgement (`UnknownCommit`)** (connection drop during `COMMIT` reply, leaving commit outcome unknown in PostgreSQL), because Migration `0023` grants `SELECT` on `openmettle.gateway_requests` **only** to `openmettle_gateway` (never to `openmettle_api` or `openmettle_worker`), the caller **MUST suppress HTTP transport dispatch** (matching [ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md) and `src/authz/gateway.rs`) and invoke the caller-scoped `SECURITY DEFINER` recovery entrypoint **`openmettle.quota_recover_lost_handoff(p_request_id uuid, p_dispatch bytea, p_scope_id uuid, p_actor_user_id uuid, p_run_id uuid) RETURNS text`**. That function verifies caller role (`openmettle_api` for `p_run_id IS NULL`, `openmettle_worker` for `p_run_id IS NOT NULL`), `octet_length(p_dispatch) = 32`, and `gateway_requests` ownership + `dispatch_hash = sha256(p_dispatch)` (preserved by `0023`'s `gateway_handoff`), locks `(runs ->) gateway_reservations -> gateway_requests -> (parent ->) quota_reservations -> quota_budgets` in canonical `FOR NO KEY UPDATE` order, and resolves the outcome: (a) if `gateway_requests.state = 'handed_off'`, it reads the recorded handoff-time obligation from `openmettle.quota_gateway_handoffs` (`COALESCE(metering_enforced, false)`, `COALESCE(cost_required, false)` — any pre-PR2 `0023` handoff absent from the table unambiguously means `metering_enforced = false, cost_required = false`), asserts zero bound `quota_reservations` rows remain in pre-handoff or unsent states (**`qr.state NOT IN ('handoff_committed', 'settled')`**, raising `OMQ04` if any bound `'held'` or `'released'` row exists — explicitly recognizing **`'settled'`** from a fast final gateway usage report as valid committed post-handoff evidence), and evaluates required hold presence strictly against **handoff-time** `handoff.metering_enforced` and `handoff.cost_required` (NOT live `quota_enforcement.metering_enforced` or live `quota_defaults`): when `handoff.metering_enforced = true`, it requires bound `usage_tokens` (`qr.reserved_units = q.units`, and `qr.held_units = q.units` while `qr.state = 'handoff_committed' AND qr.settled_units = 0`) and `usage_cost_micros` iff `handoff.cost_required = true` in `state IN ('handoff_committed', 'settled')` (`OMQ04` if missing/mismatched) and returns `'handoff_committed'`; when `handoff.metering_enforced = false`, it returns `'handoff_committed'` if valid post-handoff bound holds exist or `'unmetered_legacy_handoff'` if zero bound holds exist (even if live `quota_enforcement.metering_enforced` has since flipped to `true`), keeping HTTP dispatch strictly suppressed in all `'handed_off'` outcomes for downstream gateway reconciliation; (b) if `gateway_requests.state = 'reserved'` (or `'released'` with remaining `'held'` bound holds), it atomically unwinds `gateway_requests.state := 'released'` and decrements `gateway_reservations.allocated` (if `'reserved'`), transitions bound `'held'` `quota_reservations` to `'released'` (returning round capacity to an active `'held'` parent or restoring `quota_budgets` on standalone/terminal runs, setting `closed_at`), and returns `'unwound_unsent'`. For standalone non-run device holds (`resource_kind = 'device_reservations' AND run_id IS NULL`), `quota_commit_handoff` binds `device_grant_id` on the caller's own `origin_role` `held` row. **Generic `quota_commit_handoff` explicitly rejects all run-linked device holds (`resource_kind = 'device_reservations' AND run_id IS NOT NULL`, SQLSTATE `42501`) for both `openmettle_api` and `openmettle_worker`**, forcing exclusive use of `quota_commit_device_handoff`. |
| Fenced successor-worker unwind of crashed post-commit `'reserved'` round (`quota_unwind_superseded_round`) | If Worker 1 (`T1`) commits `(reserve_in + quota_allocate_round)` (or an `N-1` worker commits an unbound `'reserved'` round via `0023` `authz::gateway::reserve`) for `(run_id, round)` and crashes immediately before `handoff_in`, its 32-byte `Pending.secret` is lost in process memory while Migration `0023`'s `gateway_requests_run_round_active_idx` blocks retrying `round` (`23505`). After Worker 1's lease expires and Worker 2 (`T2`) reclaims the still-live (`running`) run via `leases::reclaim_next` (minting a fresh `claim_token = T2` that invalidates Worker 1 in `0023`'s `gateway_handoff`), Worker 2 invokes **`openmettle.quota_unwind_superseded_round(p_scope_id uuid, p_run_id uuid, p_claim_token uuid, p_round integer) RETURNS boolean`** (`SECURITY DEFINER`, `openmettle_worker` only). Acquiring canonical `FOR NO KEY UPDATE` locks on `runs -> gateway_reservations -> active gateway_requests (q) -> any existing parent & bound child quota_reservations`, it verifies Worker 2 holds the current live lease (`r.claim_token = p_claim_token AND r.state IN ('running', 'cancelling', 'reconciling') AND r.lease_expires_at > clock_timestamp()`). Next, it checks whether any bound child `quota_reservations` row for `q.id` carries **`allocating_claim_token = p_claim_token`**: if `EXISTS (SELECT 1 FROM openmettle.quota_reservations qr WHERE qr.gateway_request_id = q.id AND qr.allocating_claim_token = p_claim_token)`, `q` was allocated by the **current** lease generation `p_claim_token` itself (not a superseded predecessor lease), so it leaves `q` and its holds completely untouched and returns `false` as an idempotent replay no-op (preventing a replayed unwind under `T2` from releasing Worker 2's own replacement request!). Only when an active `gateway_requests` row `q` for `(run_id = p_run_id, round = p_round)` is `state = 'reserved'` (never `'handed_off'`) **AND** zero bound holds carry `allocating_claim_token = p_claim_token`, it atomically transitions `gateway_requests.state := 'released'` and restores `gateway_reservations.allocated := allocated - q.units`: when zero bound child `quota_reservations` rows exist (an **unbound `N-1` `'reserved'` round**), this completes cleanly without requiring parent `quota_reservations` rows to exist yet (allowing Worker 2 to initialize the run's parent hold via `quota_ensure_legacy_run_holds` and allocate the replacement round); when bound `'held'` child `quota_reservations` rows exist (a predecessor `N` attempt carrying `allocating_claim_token = T1 <> p_claim_token`), it additionally transitions those child holds to `'released'` (`held_units = 0`, `closed_at = clock_timestamp()`, inserting `quota_reconciliations` with `kind = 'release'`, `delta_active = 0`, `delta_reserved = 0`) and returns their capacity directly to their active `'held'` parent run holds (`parent.allocated_units := parent.allocated_units - child.reserved_units`, `parent.held_units := parent.held_units + child.held_units`, `quota_budgets` delta = `0`). Returns `true` so Worker 2 can immediately retry `p_round` cleanly. If already `'handed_off'` (or no active `'reserved'` predecessor row exists), it leaves the row untouched and returns `false` so Worker 2 reconciles or advances. |
| Run-linked device handoff (`api` admission -> `worker` dispatch) | Run admission (`POST /v1/runs`) reserves `device_reservations` with `origin_role = 'api'`. At dispatch, `openmettle_worker` invokes `openmettle.quota_commit_device_handoff(...)` (the sole allowed transition path for run-linked device holds), which locks `runs -> quota_reservations` in canonical order, verifies the calling worker's active `Step` lease (`runs.state = 'running'`, `runs.cancel_reason IS NULL`, matching `claim_token`, `runs.lease_expires_at > clock_timestamp()`), requires `resource_kind = 'device_reservations'` (`run_id IS NOT NULL`, `origin_role IN ('api', 'worker')`) matching `(scope_id, run_id)`, binds the run's durable V1-18 `device_grant_id` and transitions `state = 'handoff_committed'` before external device activation. `openmettle_api` has zero `EXECUTE` grant on `quota_commit_device_handoff` and is rejected by `quota_commit_handoff` on any run-linked device hold; `openmettle_worker` remains forbidden from mutating `origin_role = 'api'` holds of any other resource kind or any unleased/cancelled run. |
| Pre-send abort, `gateway_release` unwind, queued cancellation, unallocated parent remainder or orphan `'reserved'` gateway sweep | Only while `state = 'held'`: for a hold bound to `gateway_request_id`, explicit pre-send unwind couples with `authz::gateway::release_in(&mut tx, ...)` / Migration `0023`'s `openmettle.gateway_release(p_request, p_dispatch)` (setting `gateway_requests.state = 'released'` and returning units to `gateway_reservations`), and `quota_release_unsent` verifies `gateway_requests.state = 'released'` before unwinding. In **both** explicit pre-send unwind and sweep mode, after acquiring canonical locks on `(runs ->) gateway_reservations -> gateway_requests -> (parent ->) quota_reservations`, `quota_release_unsent` **explicitly re-verifies `(q.scope_id, q.actor_user_id) = (qr.scope_id, qr.actor_user_id) AND q.run_id IS NOT DISTINCT FROM qr.run_id` before modifying either ledger** (raising an invariant error and mutating neither ledger on mismatch). When unwinding an unsent child round hold whose parent run hold is still active (`state = 'held'` on a non-terminal run), `quota_release_unsent` locks parent before child, returns `child.held_units` to `parent.held_units` (decrementing `parent.allocated_units`, `quota_budgets.reserved_held` delta = `0`), inserts `quota_reconciliations` (`kind = 'release'`, `delta_active = 0`, `delta_reserved = 0`), and sets child `state = 'released'`, `held_units = 0`, `closed_at = clock_timestamp()`. For standalone holds, parent remainders or terminal-run child holds (including stale sweep after a pre-handoff crash), `quota_release_unsent` (`SECURITY DEFINER`, owned by `openmettle_owner`) acquires locks internally in canonical order (`FOR NO KEY UPDATE SKIP LOCKED` on `runs`, `gateway_reservations`, `gateway_requests`, parent and target `quota_reservations` in sweep mode), re-verifies eligibility and ownership, and when `gateway_request_id IS NOT NULL`: proceeds if `gateway_requests.state = 'released'`; **atomically transitions `gateway_requests.state = 'released'` and restores `gateway_reservations.allocated = allocated - req.units` in the exact same transaction** if `gateway_requests.state = 'reserved'` (without needing the caller's lost dispatch secret, ensuring any delayed `openmettle.gateway_handoff` call fails closed); or leaves the local hold untouched if `gateway_requests.state = 'handed_off'` or locked. Eligible releases insert `quota_reconciliations` (`kind = 'release'`, `delta_active = 0`, `delta_reserved = -held_units`), decrement `reserved_held`, and set `state = 'released'`, `held_units = 0` and `closed_at = clock_timestamp()`. Repeating release is a no-op. For rolling-upgrade / defense-in-depth safety against pre-V1-17 `'reserved'` `gateway_requests` rows having zero bound `quota_reservations` rows, `openmettle_worker` also runs `openmettle.quota_release_orphan_gateway_requests(...)` using bounded raw `(created_at, id)` index-key paging over `gateway_requests_reserved_idx` with a single constant clamped age-cutoff upper bound (zero `clock_timestamp()` inside the scan query) to release aged unbound `'reserved'` requests and restore `gateway_reservations.allocated`. |
| Open partial gateway report or signed partial correction (ADR 0037 / Migration `0023`) | `openmettle_gateway` first upserts/advances `openmettle.gateway_settlements` (with `measured` widened to `numeric(38, 0)`). `quota_settle_gateway_usage` locks `gateway_requests` (`FOR KEY SHARE`) -> `gateway_settlements gs` (`FOR NO KEY UPDATE`) before `quota_reservations`, strictly requiring **`gs.request_id = qr.gateway_request_id AND gs.revision = p_source_revision AND gs.final = r.final`** (so any late partial report stored in `gateway_usage_reports` after a final settlement and rejected by `gateway_settlements` is rejected even for a lagging `handoff_committed` hold). Locates the single `openmettle.gateway_usage_reports` row `r` matching `(request_id = qr.gateway_request_id, source = p_report_source, report_id = p_report_id, revision = p_source_revision)` (`revision >= 0`), verifies `qr.state = 'handoff_committed'`, immutable deployment `cost_denomination` against `r.unit` (when `r.cost IS NOT NULL`), and **`accepted_source_revision IS NULL OR p_source_revision > accepted_source_revision`** (so valid `revision = 0` initial reports are accepted cleanly). Applies strict **per-resource authoritative evidence**: for `usage_cost_micros`, skips the hold completely whenever `r.cost IS NULL`, and otherwise computes `C_cost = ceil(r.cost)::numeric(38, 0)`; for `usage_tokens`, skips the hold completely whenever all three token fields are `NULL` (`prompt_tokens IS NULL AND completion_tokens IS NULL AND reasoning_tokens IS NULL`), and applies partial settlement whenever `NOT r.final` (with at least one non-null token field) **or** `r.final = true` with incomplete token fields (`prompt_tokens IS NULL OR completion_tokens IS NULL` while at least one token field is non-null), computing `C_tokens = coalesce(r.prompt_tokens, 0)::numeric(38, 0) + coalesce(r.completion_tokens, 0)::numeric(38, 0) + CASE WHEN r.reasoning_included IS FALSE THEN coalesce(r.reasoning_tokens, 0)::numeric(38, 0) ELSE 0 END` and keeping `qr.state = 'handoff_committed'`. Comparing cumulative total `C_new` (`numeric(38, 0)`) against prior `settled_units = S` (`numeric(38, 0)`) and `held_units = H` (`bigint`), compute `new_held = greatest(0::numeric(38, 0), reserved_units::numeric(38, 0) - C_new)::bigint`, `delta_active = C_new - S` (`numeric(38, 0)`) and **signed** `delta_reserved = (new_held - H)::numeric(38, 0)`. The single atomic `UPDATE` on `quota_reservations` persists `held_units = new_held`, `settled_units = C_new`, **`accepted_source_revision = p_source_revision`** and `revision = revision + 1` in the same transaction alongside the composite-FK `quota_reconciliations` row and `quota_budgets`, so delayed older reports (`p_source_revision <= accepted_source_revision`) can never pass the guard, repeated fractional cost updates never accumulate rounding drift, absent fields never release holds as zero, and large 3-column token sums or multi-report aggregates never overflow `bigint` (`22003`). Example: on a `100`-token hold (`accepted_source_revision IS NULL`) where `revision = 0` reports `60` partial (`60` measured, `40` held, `accepted_source_revision = 0`), an authoritative `revision = 1` partial correction to `20` applies `delta_active = -40` and `delta_reserved = +40` (`20` measured, `80` held, `accepted_source_revision = 1`, preserving `100` total exposure while open). |
| Authoritative final gateway report (including overage, explicit zero charge or `revision = 0` final) | Requires `openmettle.gateway_settlements gs` (`FOR NO KEY UPDATE`) matching **`gs.request_id = qr.gateway_request_id AND gs.revision = p_source_revision AND gs.final = true`**, `qr.state = 'handoff_committed'`, matching `openmettle.gateway_usage_reports` row `r` (`final = true`), and **`accepted_source_revision IS NULL OR p_source_revision > accepted_source_revision`** (accepting an immediate `revision = 0` final report cleanly). Evaluates each resource hold independently: for `usage_cost_micros`, settles to `'settled'` **only if `r.cost IS NOT NULL`** (`C_cost = ceil(r.cost)::numeric(38, 0)`, skipping completely when `r.cost IS NULL` so token-only finals keep the cost hold open in `'handoff_committed'`); for `usage_tokens`, settles to `'settled'` **only if `r.prompt_tokens IS NOT NULL AND r.completion_tokens IS NOT NULL`** (`C_tokens = r.prompt_tokens::numeric(38, 0) + r.completion_tokens::numeric(38, 0) + CASE WHEN r.reasoning_included IS FALSE THEN coalesce(r.reasoning_tokens, 0)::numeric(38, 0) ELSE 0 END`, including explicit `prompt_tokens = 0, completion_tokens = 0` zero-token final proof), whereas a cost-only final (`all three token columns NULL`) skips `usage_tokens` completely (keeping `state = 'handoff_committed'`, `held_units`, `settled_units`, and `accepted_source_revision` intact) and an incomplete final with partial token fields applies only the partial rule above while keeping `state = 'handoff_committed'`. For each resource with authoritative final evidence, applies `delta_active = C_new - S` (full overage in exact `numeric(38, 0)` even when cumulative `active_used` or 3-column token sum exceeds `bigint` max) and `delta_reserved = (-H)::numeric(38, 0)`. The single atomic `UPDATE` sets `state = 'settled'`, `held_units = 0`, `settled_units = C_new`, **`accepted_source_revision = p_source_revision`**, `revision = revision + 1` and `closed_at = clock_timestamp()`. Closes the hold once per unit; a late partial report cannot reopen `settled`. |
| Post-final authoritative correction | Requires `openmettle.gateway_settlements gs` (`FOR NO KEY UPDATE`) matching **`gs.request_id = qr.gateway_request_id AND gs.revision = p_source_revision AND gs.final = true`**, `qr.state = 'settled'`, matching `openmettle.gateway_usage_reports` row `r` (`final = true`, matching Migration `0023`'s `gateway_advance_settlement`) and **`accepted_source_revision IS NULL OR p_source_revision > accepted_source_revision`**. Applies strict per-resource authoritative evidence: updates `usage_cost_micros` **only when `r.cost IS NOT NULL`** (`C_cost = ceil(r.cost)::numeric(38, 0)`, skipping when `r.cost IS NULL`) and updates `usage_tokens` **only when `r.prompt_tokens IS NOT NULL AND r.completion_tokens IS NOT NULL`** (skipping completely on cost-only or incomplete-token corrections so a cost-only correction never erases `usage_tokens.settled_units` to `0`!). For each updated resource, applies signed `delta_active = C_new - S` and `delta_reserved = 0` (rejecting negative `active_used`), atomically updating `settled_units = C_new`, `accepted_source_revision = p_source_revision` and `revision = revision + 1` (e.g., fractional sequence `0.4 -> 0.8 -> 1.2` final -> `0.5` post-final correction -> `0` settles cumulative `ceil(r.cost)::numeric(38, 0)` values `1 -> 1 -> 2 -> 1 -> 0` with zero accumulated rounding drift). Same-revision duplicates with identical values are no-ops; differing values at an already accepted revision or mismatched `unit` denominations quarantine under ADR 0037 without mutating balances. |
| Failed upload, interrupted write or retention purge | All `artifact_fs::Store` writer and reader operations (`stage` using `OFlags::RDWR \| OFlags::CREATE \| OFlags::EXCL \| OFlags::NOFOLLOW` + immediate non-blocking `LOCK_SH` held for the staged writer lifetime, `renameat` publication + `fsync`, error/cancellation `unlinkat`, `read`) execute strictly relative to `Arc`-shared verified directory descriptors (`root_fd`, `staging_dir_fd`, `revisions_dir_fd`), re-verifying `(st_dev, st_ino)` + role-tagged sentinels before `stage`, before `renameat`, **AND post-`renameat` / post-`fsync` / strictly before `tx.commit()` of `storage::settle`** (rolling back `storage::settle` with `Error::Io` **without** calling `storage::release` if `<root>`, `<root>/staging`, or `<root>/revisions` was displaced after `renameat`, while narrowing the post-final-check live host replacement guarantee to explicit fail-closed sentinel/`Error::Missing`/`OMQ03`/`verify_accounting_drift` detection + operator recovery). **`artifact_fs::abort` (and every non-run API pre-settlement error release path)** locks `storage_reservations FOR UPDATE` (`WHERE scope_id = $1::uuid AND id = $2::uuid`), verifies `state = 'reserved' AND NOT adoption_unverified` and three-directory volume/directory identity across `(root_fd, staging_dir_fd, revisions_dir_fd)`, unlinks `staging/<id>` relative to `staging_dir_fd` + `fsync(staging_dir_fd)`, and proves **`statat(revisions_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` returns `ENOENT`** strictly before committing `storage::release` (refusing release and preserving both `revisions/<id>` and `reserved_bytes` if `adoption_unverified = true`, volume/directory verification fails, or `revisions/<id>` exists or returns any non-`ENOENT` error). `storage::settle` moves actual bytes to `active_bytes`, clears `adoption_unverified = false`, and releases `max_bytes - size_bytes` once; **`artifact_fs::purge_due` unconditionally calls `fsync(revisions_dir_fd)` (`Ok(())` required) strictly before committing `storage::confirm_purge` — explicitly including when `unlinkat` returns `ENOENT`** — decrementing `retained_bytes` once after durable payload deletion (ADR 0005, ADR 0031). **PR2 updates ADR 0031's post-rename `reconcile_expired` behavior** (and `tests/schema/artifact_fs.rs`'s `renamed` test case): non-run `artifact_fs::reconcile_expired` (`run_id IS NULL`) enforces the exact same directory-relative `revisions_dir_fd` `ENOENT` proof as run-linked storage recovery. On **every** upgrade (`applied >= 1`), operators **MUST quiesce all `N-1` worker artifact cleaners (unset `OPENMETTLE_WORKER_ARTIFACTS_DIR` and drain all in-flight `worker::maintenance` sweeps) BEFORE running `openmettle-migrate`**, `storage_instance.bootstrap_auto_pin_allowed` seeds `false`, and `storage_instance.volume_id` stays `NULL` throughout the entire `N-1 -> N` binary replacement (with `enforce_worker_storage_volume_pinned()` (`OMQ03`) acting as a PostgreSQL ledger backstop); verified volume adoption runs only after 100% `N-1 -> N` replacement, executing locked per-reservation accounting classification (`staging/<id>` / `revisions/<id>` relative to verified `staging_dir_fd` / `revisions_dir_fd`), rollback-and-retry on newly committed `'reserved'` rows, and `UPDATE openmettle.storage_reservations SET adoption_unverified = true WHERE id = ANY(...) AND state = 'reserved' AND NOT adoption_unverified` in the **common locked path on BOTH initial unpinned (`volume_id IS NULL`) AND already-pinned (`volume_id IS NOT NULL`) adoption/verification retries** (locking `storage_reservations WHERE state = 'reserved' ORDER BY id ASC FOR UPDATE` -> `storage_instance FOR UPDATE` before any sentinel write or stale `st_mtime > 300 s` `.tmp.*` cleanup, never writing missing sentinels when `volume_id IS NOT NULL`, re-querying `artifact_revisions.state` on already-pinned retry if a `'retained'` file returned `ENOENT` due to concurrent `begin_purge`, requiring **both** `--expected-fs-uuid <fs_uuid>` **AND** `--expected-revisions-inode <dev>:<ino>` whenever ledger rows exist with zero digest-bearing revisions verified on disk, adopting any winning valid `:root` UUID on `EEXIST`, publishing `(root_fd, "root")` and requiring **`fsync(root_fd)` strictly BEFORE creating/linking either child sentinel (`:revisions` or `:staging`)**, then `fsync(revisions_dir_fd)` and `fsync(staging_dir_fd)` before updating `storage_instance.volume_id`; storage-disabled installations with both `ARTIFACTS_DIR` env vars unset and `0` storage rows skip adoption, leave `volume_id IS NULL` and cleaners disabled, and still activate `metering_enforced = true`). ADR 0040's generic run-linked cleaner explicitly excludes `idempotency_key LIKE 'tool-spill:%'` (single cleanup owner: ADR 0039 `reconcile_run_spills`). All `N` worker storage cleaners verify non-null pinned `storage_instance.volume_id` <-> role-tagged `.openmettle-volume-id` sentinels in `<root>` (`:root`), `<root>/revisions` (`:revisions`), and `<root>/staging` (`:staging`) via `openat(..., O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK)` + `fstat` (`S_ISREG`, equal `st_dev`, bounded `<= 64`-byte read) on open directory FDs sharing equal `st_dev`, exclude `adoption_unverified = true` rows, and use two-step raw-index-key paging over plain-column partial indexes with `StagingSweepState` (`Idle`/`Open`/`InFlight`/`InvalidatedInFlight`/`DrainingEof` + `pending_names` outside `worker::sweep`'s 15 s timeout), which acquires non-blocking `LOCK_EX` + `(st_dev, st_ino)` re-verification on every `staging/<id>` before `set_len(0)` -> `unlinkat` -> `drop` -> `fsync(staging_dir_fd)`, and for zero-row orphans additionally requires `st_mtime > 900 s` (on both startup and periodic sweep) and a `storage_instance FOR UPDATE` serialized zero-row recheck while holding `LOCK_EX`. |
| Terminal failed, cancelled or interrupted run | Unallocated `held` parent, standalone or unsent child quota holds release once. `handoff_committed` usage holds stay held until `openmettle_gateway` supplies an authoritative final report (including explicit zero-token / zero-cost final proof). `handoff_committed` device holds stay held until durable V1-18 confirmation of release or non-allocation. Run-linked `storage_reservations` stay held while any linked operation is `intent` or `outcome_unknown`, while `adoption_unverified = true`, or while `revisions/<id>` exists on disk awaiting SQL settlement (and `idempotency_key LIKE 'tool-spill:%'` rows are owned solely by ADR 0039 `reconcile_run_spills`). |

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
   `state IN ('retained', 'purging')`) and `storage_reservations` (`state = 'reserved'`, including
   any `adoption_unverified = true` rows whose `max_bytes` remain charged).
2. **Storage DB-to-filesystem verification (`artifact_fs`):** when `ARTIFACTS_DIR` is unset (per
   ADR 0031, both `OPENMETTLE_API_ARTIFACTS_DIR`/`OPENMETTLE_ARTIFACTS_DIR` and
   `OPENMETTLE_WORKER_ARTIFACTS_DIR` unset), `storage_instance.volume_id IS NULL`, AND both
   `storage_reservations` and `artifact_revisions` contain `0` rows, filesystem sentinel checks are
   cleanly skipped as unconfigured. Otherwise — whenever `ARTIFACTS_DIR` is configured OR any row
   exists in `storage_reservations` / `artifact_revisions` — `storage_instance.volume_id IS NULL`
   remains a hard failure, and verification first opens `<root>`, `<root>/revisions` and
   `<root>/staging` (`O_RDONLY | O_DIRECTORY | O_NOFOLLOW`), verifies equal `st_dev` across all
   three FDs, and verifies via `openat(..., O_RDONLY | O_NOFOLLOW | O_NONBLOCK)` + `fstat` on each
   FD that its `.openmettle-volume-id` file is a regular file (`S_ISREG` — rejecting FIFOs,
   sockets, device nodes, directories and symlinks immediately without blocking) on that same
   `st_dev` whose bounded (`<= 64`-byte) content matches non-null pinned
   `storage_instance.volume_id` AND its exact `:root`, `:revisions`, or `:staging` role tag
   (failing restore validation immediately on `volume_id IS NULL` or on missing, mismatched,
   wrong-role, non-regular/FIFO/symlink or different-`st_dev` sentinels):
   - *Active and retained revisions:* every `artifact_revisions` row in `state IN ('active',
     'retained')` MUST have a matching regular (non-symlink) file at `revisions/<reservation_id>`
     whose on-disk length equals `size_bytes`. Any missing, symlinked or wrong-sized payload for
     an `active` or `retained` revision — explicitly including any revision committed into a
     displaced old `revisions/` directory during a live host directory replacement after the
     pre-`commit` re-verification check — is a **hard drift failure** that fails restore
     validation.
   - *Mid-purge crash state (`state = 'purging'`):* because `artifact_fs::purge_due` commits
     `storage::begin_purge` (`state = 'purging'`), unlinks `revisions/<reservation_id>` on disk,
     unconditionally `fsync`s `revisions_dir_fd` (including on `ENOENT`), and confirms
     `storage::confirm_purge` (`state = 'purged'`) in a second transaction
     ([`src/artifact_fs.rs`](../../src/artifact_fs.rs)), `revisions/<reservation_id>` being absent
     (`ENOENT` / `NotFound`) for a `purging` revision is recognized as a **valid mid-purge crash
     state**, not a hard restore failure. Restore validation verifies that any still-present file
     for a `purging` row is a regular file of `size_bytes` and reports `ENOENT` `purging` rows as
     resumable pending-confirmation purges so `purge_due` / `confirm_purge` can finish decrementing
     `retained_bytes` and re-verify storage accounting rather than blocking restore.
   - *Unsettled published payloads, adoption-unverified holds and orphan scan:* any
     `revisions/<id>` paired with `storage_reservations.state = 'reserved'` (post-rename,
     pre-settlement crash window — for both non-run uploads and run-linked spills) and any
     `storage_reservations` row marked `adoption_unverified = true` while `state = 'reserved'` are
     reported explicitly as unsettled payloads / unaccounted pre-adoption holds requiring
     deterministic retry settlement or explicit `openmettle_owner` reconciliation (never silently
     unlinked or released by automatic workers or `artifact_fs::abort`). Ignoring the verified
     `.openmettle-volume-id` sentinel file (strictly disjoint from canonical lowercase UUID
     payload filenames per `src/artifact_fs.rs`), any payload file in `revisions/` lacking a
     matching `active`/`retained`/`purging` revision or `reserved` reservation, and any payload
     file in `staging/` lacking a matching `reserved` reservation (after worker startup/retryable
     cleanup of `released` rows and `LOCK_EX` + `st_mtime > 900 s` orphan verification), fails as
     an unreferenced orphan.
3. **Usage and device budget verification (inside `quota_verify_accounting_drift()`):** compares
   every `quota_budgets.reserved_held` (`numeric(38, 0)`) row against `SUM(qr.held_units::numeric(38, 0))`
   joined via `quota_reservation_charges` for `qr.state IN ('held', 'handoff_committed')`, compares
   `quota_budgets.active_used` (`numeric(38, 0)`) against both
   `SUM(quota_reconciliations.delta_active)` and accepted Migration `0023`
   `openmettle.gateway_reservations` / `openmettle.gateway_requests` /
   `openmettle.gateway_usage_reports` / `openmettle.gateway_settlements` (with `measured` widened
   to `numeric(38, 0)`) evidence — applying the **exact same per-resource authoritative evidence
   and `gateway_settlements` coupling rules**: for `usage_cost_micros`, comparing against the
   latest `gateway_settlements`-accepted report with **`r.cost IS NOT NULL`** via **`C_cost =
   ceil(r.cost)::numeric(38, 0)`** (leaving cost holds without a `cost IS NOT NULL` report in
   `handoff_committed` with unchanged `settled_units`); for `usage_tokens`, comparing against the
   latest `gateway_settlements`-accepted report with non-null token evidence (`r.prompt_tokens IS
   NOT NULL OR r.completion_tokens IS NOT NULL OR r.reasoning_tokens IS NOT NULL`), distinguishing
   explicit `0` tokens (`prompt_tokens = 0, completion_tokens = 0`) from all-`NULL`/unknown token
   columns (cost-only reports), requiring complete final token evidence (`r.final = true AND
   r.prompt_tokens IS NOT NULL AND r.completion_tokens IS NOT NULL`) for `state = 'settled'`, and
   verifying exact `numeric(38, 0)` `C_tokens` and `gateway_settlements.measured` without `22003`
   overflow even on 3-column token totals exceeding `i64::MAX` — and verifies every `released` or
   `settled` reservation has `closed_at IS NOT NULL`.

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
   - *Bounded-pass two-step raw-index-key scan (`pass_upper_bound`, `quota_reservations_held_expiry_idx`):*
     At the start of each logical pass (starting from `last_attempted = ('-infinity'::timestamptz,
     '00000000-0000-0000-0000-000000000000'::uuid)`), capture a fixed constant snapshot upper bound
     `pass_upper_bound = (clock_timestamp(), 'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid)`. To
     prevent a long prefix of expired-but-ineligible holds (e.g., non-terminal runs or runs with
     unresolved `'intent'`/`'outcome_unknown'` operations) from exhausting `statement_timeout`
     without returning a row or advancing the cursor, each scan step uses **two-step raw-index-key
     paging** (matching `quota_release_orphan_gateway_requests`):
     1. In a short plain non-locking read-only `SELECT` backed by the plain-column partial B-tree
        index `quota_reservations_held_expiry_idx` (`ON openmettle.quota_reservations
        (lease_expires_at, id) WHERE state = 'held'`), materialize a bounded raw key page of at
        most `batch_size` (`limit`) `(lease_expires_at, id, run_id)` keys using **only** constant
        bounds — **zero joins, zero `EXISTS`, and zero `clock_timestamp()` calls before `LIMIT`**:
        `WHERE state = 'held' AND (lease_expires_at, id) > $1 AND (lease_expires_at, id) <= $2
        ORDER BY lease_expires_at ASC, id ASC LIMIT $3`.
     2. Evaluate eligibility (either `run_id IS NULL`, or linked `runs.state IN ('succeeded',
        'failed', 'cancelled', 'interrupted')` with `NOT EXISTS` any linked operation in
        `('intent', 'outcome_unknown')`) **only** on those `<= batch_size` materialized keys (and
        re-verify under lock inside `quota_release_unsent`).
     3. Advance `last_attempted` across **every inspected raw key** — **including when 100% of a
        page is ineligible** (persisting `(last_attempted, pass_upper_bound)` in memory across
        `SWEEP_MS` ticks whenever the **15 s sweep budget** expires mid-pass) — and wrap
        `last_attempted` back to `('-infinity'::timestamptz,
        '00000000-0000-0000-0000-000000000000'::uuid)` with a fresh `pass_upper_bound` **only when
        the raw key page returns fewer than `batch_size` rows** (and all keys in that partial page
        have been inspected) **or** `last_attempted` reaches `pass_upper_bound`. Freezing
        `pass_upper_bound` prevents newly expiring tail rows from keeping later pages full
        indefinitely, guaranteeing bounded query latency on every tick, forward progress across
        arbitrarily long ineligible prefixes, and eventual revisit of any early `SKIP LOCKED` row
        once its lock clears.
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
     (`openmettle.quota_release_orphan_gateway_requests`, bounded raw index-key paging with
     constant clamped age cutoff):* Although PR2 inserts `gateway_requests` and all bound metered
     `quota_reservations` atomically in one `WriteTransaction` via `authz::gateway::reserve_in`,
     rolling upgrades or pre-V1-17 crashes can leave `'reserved'` `gateway_requests` rows created
     before `quota_reservations` existed (stranding `gateway_reservations.allocated` and occupying
     Migration `0023`'s partial unique index `gateway_requests_run_round_active_idx` with zero
     bound `quota_reservations` rows). Because Migration `0023` grants `openmettle_worker` zero
     direct `SELECT` on `gateway_requests`, PR2 provides a bounded `SECURITY DEFINER` sweep helper
     **`openmettle.quota_release_orphan_gateway_requests(p_max_reserved_age interval,
     p_after_created_at timestamptz, p_after_id uuid, p_pass_upper_created_at timestamptz,
     p_pass_upper_id uuid, p_page_size integer)`** (owned by `openmettle_owner`, `SET search_path
     = pg_catalog`, `REVOKE ALL FROM PUBLIC`, granted `EXECUTE` only to `openmettle_worker`). Each
     sweep pass initializes `pass_upper_bound` to `(clock_timestamp() - max_reserved_age,
     'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid)`. Because `clock_timestamp()` is `VOLATILE` in
     PostgreSQL — which would force the planner to evaluate `created_at <= clock_timestamp() -
     p_max_reserved_age` as a per-row filter rather than a B-tree index range stop condition and
     could scan an arbitrarily large young tail whenever `p_pass_upper_created_at` extends past
     the age cutoff — at the start of `quota_release_orphan_gateway_requests(...)` the function
     captures **`v_age_cutoff timestamptz := clock_timestamp() - p_max_reserved_age;`** once in PL/pgSQL and
     clamps the scalar index-range upper bounds using valid PostgreSQL 18 PL/pgSQL assignments:
     `IF (p_pass_upper_created_at, p_pass_upper_id) <= (v_age_cutoff,
     'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid) THEN v_upper_created_at :=
     p_pass_upper_created_at; v_upper_id := p_pass_upper_id; ELSE v_upper_created_at :=
     v_age_cutoff; v_upper_id := 'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid; END IF;`. To prevent
     both an aged prefix of
     legitimately bound `'reserved'` entries and a young tail past `v_age_cutoff` from causing an
     unbounded index scan before `LIMIT`, each call **first materializes a bounded page of at most
     `p_page_size` raw `(created_at, id)` index keys** directly from Migration `0023`'s
     `gateway_requests_reserved_idx` using **only those constant PL/pgSQL parameters** (zero
     `clock_timestamp()` call inside the `SELECT`, and never applying `NOT EXISTS` before
     `LIMIT`): `WHERE state = 'reserved' AND (created_at, id) > (p_after_created_at, p_after_id)
     AND (created_at, id) <= (v_upper_created_at, v_upper_id) ORDER BY created_at ASC, id ASC
     LIMIT p_page_size` — guaranteeing PostgreSQL's B-tree index scan stops immediately at
     `v_upper_created_at` without touching younger rows. Only on those `<= p_page_size`
     materialized keys does it test binding absence (`NOT EXISTS (SELECT 1 FROM
     openmettle.quota_reservations qr WHERE qr.gateway_request_id = q.id)`) and (when `q.run_id IS
     NOT NULL`) run-lease/terminal eligibility, releasing at most one eligible orphan per short
     transaction by locking `(runs ->) gateway_reservations -> gateway_requests` with `FOR NO KEY
     UPDATE SKIP LOCKED`, re-verifying all preconditions under lock, transitioning `state :=
     'released'` and restoring `gateway_reservations.allocated = allocated - q.units`. Each call
     returns `(next_created_at, next_id, raw_keys_scanned, released_count)` and **always advances
     the persistent `(last_created_at, last_id)` cursor to the last inspected key of that
     `p_page_size` page even when the page contains zero orphans** (wrapping back to `('-infinity',
     nil UUID)` with a fresh `pass_upper_bound = (clock_timestamp() - max_reserved_age,
     'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid)` only when fewer than `p_page_size` raw index
     keys were returned and all keys in that partial page were inspected, or when the cursor
     reaches `(v_upper_created_at, v_upper_id)`).
2. **Storage holds (`storage_reservations`) and retention purges (`artifact_revisions`).**
   - *Durable artifact volume identity (`storage_instance.volume_id` <-> role-tagged sentinels in
     `<root>`, `<root>/revisions`, and `<root>/staging`):*
     If the artifact volume unmounts, an ordinary empty `revisions/` directory can remain at the
     mount point — or `Store::open` ([`src/artifact_fs.rs`](../../src/artifact_fs.rs)) can create
     empty `staging/` and `revisions/` directories on worker restart, or an operator/script can
     replace *only* `<root>/revisions` (or `<root>/staging`) with a fresh empty directory on the
     **same filesystem (`st_dev`)** — causing an open `revisions/` directory handle and
     `fstatat("<id>")` (or `N-1`'s `remove()` treating `ErrorKind::NotFound` as `Ok(())` in
     `reconcile_expired` and `purge_due`) to succeed while the original volume or directory still
     holds the published payload. Moreover, on an existing upgrade (`applied >= 1`), even empty
     `storage_*` tables cannot distinguish a fresh install from an existing unused deployment with
     live `N-1` pods; and in `N-1`, `reconcile_expired` unlinks both payload paths *before* calling
     `storage::release` (`src/artifact_fs.rs:660-669`) and `purge_due` skips any `UPDATE` in
     `storage::begin_purge` for an already-`'purging'` revision (`src/storage.rs:628-636`) and
     unlinks `revisions/<reservation>` *before* `confirm_purge` executes
     (`src/artifact_fs.rs:694-707`), meaning a PostgreSQL trigger alone rolls back the DB update
     *after* an `N-1` worker has already deleted the file. PR2 closes every layer with:
     - **Role-tagged sentinels across all three directories (namespace-disjoint from payloads,
       nonblocking safe `dirfd` verification via `rustix`):** Because payload filenames in
       `staging/` and `revisions/` are strictly canonical lowercase UUIDs (`runs::uuid` in
       `src/artifact_fs.rs:134-135`, never starting with `.`), `.openmettle-volume-id` (and
       temporary `.openmettle-volume-id.tmp.*`) is 100% namespace-disjoint from payload files and
       ignored by `StagingSweepState` UUID filtering and orphan scans. PR2 binds
       `openmettle.storage_instance.volume_id` **plus explicit directory role** across **all three
       directories** (regular files, mode `0600`), opening **every** `.openmettle-volume-id`
       sentinel across `Store::open`, all worker cleaners, `verify_accounting_drift`,
       fresh-bootstrap auto-pinning and `openmettle-admin` adoption via `rustix`
       `openat(..., OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK)` (`O_RDONLY |
       O_NOFOLLOW | O_NONBLOCK`), immediately running `fstat` on that FD to verify `S_ISREG`
       (regular file — rejecting writerless FIFOs/named pipes, sockets, device nodes, directories
       and symlinks immediately without blocking!) and exact `st_dev` match, and reading a bounded
       `<= 64` bytes:
       - `<root>/.openmettle-volume-id` -> `"<volume_uuid>:root\n"`
       - `<root>/revisions/.openmettle-volume-id` -> `"<volume_uuid>:revisions\n"`
       - `<root>/staging/.openmettle-volume-id` -> `"<volume_uuid>:staging\n"`
       Replacing `<root>/revisions` or `<root>/staging` (or swapping them) even on the exact same
       filesystem (`st_dev`) immediately fails closed with zero unlinks and zero DB mutations.
     - **Automatic bootstrap pinning gated strictly on `src/migrate.rs` fresh-from-zero history
       (`applied == 0`, `storage_instance.bootstrap_auto_pin_allowed = true`) AND empty storage
       ledger (serialized under `storage_instance FOR UPDATE` BEFORE any sentinel write):** In
       PR2's migration, `storage_instance.bootstrap_auto_pin_allowed` seeds `true` **ONLY when
       `is_fresh_bootstrap` holds** (`openmettle.bootstrap_from_zero = 'true'` set by
       `src/migrate.rs` when `applied == 0` in `openmettle._sqlx_migrations`, AND all core,
       storage and gateway tables are empty) and `false` on **EVERY** upgrade (`applied >= 1`,
       even an existing unused deployment with zero `users`, `storage_*`, or `gateway_*` rows!).
       `openmettle.storage_pin_volume_id(uuid)` and `Store::open` bootstrap auto-pinning are
       permitted **ONLY when `volume_id IS NULL AND bootstrap_auto_pin_allowed = true` AND BOTH
       `NOT EXISTS (SELECT 1 FROM openmettle.storage_reservations)` AND `NOT EXISTS (SELECT 1 FROM
       openmettle.artifact_revisions)`** — atomically setting `volume_id = p_volume_id,
       bootstrap_auto_pin_allowed = false` (enforced by `CHECK (volume_id IS NULL OR NOT
       bootstrap_auto_pin_allowed)`). On a genuine fresh-from-zero installation, `Store::open` opens
       `<root>`, `<root>/revisions`, and `<root>/staging` (`O_RDONLY | O_DIRECTORY | O_NOFOLLOW`,
       equal `st_dev`) and executes the unified `storage_instance FOR UPDATE`-first protocol in
       step 3 below **before** creating, writing, or linking any `.openmettle-volume-id` file or
       cleaning up stale `.tmp.*` files: if a concurrent replica already committed `volume_id IS
       NOT NULL`, `Store::open` **never writes any sentinel** and strictly verifies all three
       existing role-tagged sentinels against `storage_instance.volume_id` (so two concurrent
       fresh-bootstrap publishers starting simultaneously on an empty volume both succeed cleanly
       with zero `EEXIST` failure or `.tmp.*` deletion race); while `volume_id IS NULL`, it
       publishes and `fsync`s all three role-tagged sentinels atomically via the crash-safe
       `linkat` protocol below (adopting any winning valid `:root` UUID on `EEXIST`) and pins
       `sentinel_uuid` write-once via `openmettle.storage_pin_volume_id(sentinel_uuid)` in the
       **same transaction** before committing. On **every** upgrade (`bootstrap_auto_pin_allowed =
       false`) or whenever any row exists in `openmettle.storage_reservations` or
       `openmettle.artifact_revisions` while `storage_instance.volume_id IS NULL`:
       1. `openmettle.storage_pin_volume_id(uuid)` refuses with `ERRCODE = 'OMQ03'` and
          `Store::open` **MUST NOT** write any `.openmettle-volume-id` sentinel on an unverified
          directory.
       2. All PR2 (`N`) worker storage cleaners — explicitly including **`artifact_fs::purge_due`**
          alongside `artifact_fs::reconcile_expired`, run-linked `ENOENT` storage recovery and
          `staging/` `ReadDir` cleanup — **remain disabled (fail closed with zero unlinks, zero
          released holds, and zero `begin_purge`/`confirm_purge` transitions)** while
          `storage_instance.volume_id IS NULL` (while `N` workers still execute normal run turns
          cleanly).
       3. **Strict 4-step mandatory upgrade sequence (pre-migration `N-1` cleaner quiescence ->
          migration -> 100% `N-1 -> N` replacement -> verified adoption & activation):**
          - *Step 1 (Before migration — MANDATORY `N-1` cleaner quiescence & in-flight sweep
            drain):* Operators **MUST** unset `OPENMETTLE_WORKER_ARTIFACTS_DIR` across all `N-1`
            worker replicas (rolling restart with `OPENMETTLE_WORKER_ARTIFACTS_DIR` unset, or
            scaling `openmettle-worker` to `0`) and confirm zero `N-1` worker processes hold
            `OPENMETTLE_WORKER_ARTIFACTS_DIR` or have an in-flight `worker::maintenance` sweep
            **before** running `openmettle-migrate`, keeping legacy cleaners drained through 100%
            `N-1 -> N` replacement and verified adoption. The `SECURITY DEFINER` `BEFORE UPDATE`
            trigger `openmettle.enforce_worker_storage_volume_pinned()` (`OMQ03`) on
            `openmettle.storage_reservations` (`WHEN (OLD.state = 'reserved' AND NEW.state =
            'released')`) and `openmettle.artifact_revisions` (`WHEN (NEW.state IN ('purging',
            'purged'))`) is strictly a **PostgreSQL ledger defense-in-depth backstop** (protecting
            DB accounting if an operator forgets quiescence on an empty mount, while disjoint
            `openmettle_api` keeps in-flight upload abort cleanup working) — **NOT** a substitute
            for pre-migration `N-1` cleaner quiescence because `N-1` unlinks payload files before
            mutating PostgreSQL.
          - *Step 2 (Migration):* Run `openmettle-migrate` (`storage_instance.volume_id IS NULL`,
            `storage_instance.bootstrap_auto_pin_allowed = false`,
            `quota_enforcement.metering_enforced = false` on every upgrade where `applied >= 1`).
          - *Step 3 (100% `N-1 -> N` binary replacement):* Roll 100% of `openmettle-api` and
            `openmettle-worker` replicas from `N-1` to `N` (`N` workers may have
            `OPENMETTLE_WORKER_ARTIFACTS_DIR` configured because `N` cleaners verify non-null
            pinned `volume_id` + all three role-tagged directory sentinels/`st_dev` *before*
            touching any filesystem path, failing closed with zero unlinks while `volume_id IS
            NULL`). Confirm **zero `N-1` replicas remain running**.
          - *Step 4 (Verified adoption, pin & activation — with storage-disabled bypass per ADR
            0031):* **Only after zero `N-1` replicas remain**, on storage-enabled installations run
            `openmettle-admin` verified volume adoption (`volume_id` `NULL -> <uuid>`,
            `bootstrap_auto_pin_allowed = false`, locking `storage_reservations WHERE state =
            'reserved' ORDER BY id ASC FOR UPDATE` strictly before `storage_instance FOR UPDATE`
            and strictly before publishing and `fsync`ing all three role-tagged sentinels atomically
            via `linkat`, marking any individually unaccounted `'reserved'` row
            `adoption_unverified = true`), then run the pre-upgrade orphan gateway sweep
            (`quota_release_orphan_gateway_requests`) and flip `quota_enforcement.metering_enforced
            = true` in a standalone single-statement transaction. On **storage-disabled
            installations** (both `OPENMETTLE_API_ARTIFACTS_DIR`/`OPENMETTLE_ARTIFACTS_DIR` and
            `OPENMETTLE_WORKER_ARTIFACTS_DIR` unset per
            [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md) AND `0` rows in
            both `storage_reservations` and `artifact_revisions`), Step 4 **skips volume adoption**
            — leaving `storage_instance.volume_id IS NULL`, `bootstrap_auto_pin_allowed = false`,
            and all storage cleaners disabled — and proceeds directly after 100% `N-1 -> N` binary
            replacement to run `quota_release_orphan_gateway_requests` and flip
            `quota_enforcement.metering_enforced = true`. If artifact storage is provisioned later,
            operators run `openmettle-admin` verified volume adoption before enabling
            `OPENMETTLE_WORKER_ARTIFACTS_DIR`. **Starting, rolling back to, or resuming any `N-1`
            worker binary after `storage_instance.volume_id` is pinned is strictly forbidden by the
            rollout contract**, because `N-1` workers lack Rust role-tagged `.openmettle-volume-id`
            / `st_dev` verification and unlink before mutating PostgreSQL.
     - **Verified, idempotent volume adoption required on every storage-enabled upgrade
       (`storage_instance.volume_id IS NULL` with `bootstrap_auto_pin_allowed = false`, run ONLY
       after zero `N-1` replicas remain):** Enabling storage cleaners on an upgraded installation
       requires an explicit verified volume-adoption step (executed by `openmettle_owner` /
       operator CLI `openmettle-admin` procedure documented in PR2's operator runbook update)
       **before** `Store::open` directory creation. Every invocation — **both initial run and any
       operator retry after a crash or lost DB commit acknowledgement** — executes steps 1 and 2
       pre-scan unconditionally **before** step 3 locks `storage_reservations` (if any `'reserved'`
       rows exist) and `storage_instance FOR UPDATE` and verifies or publishes any
       `.openmettle-volume-id`:
       1. *Pre-existing directory & single-device pre-scan (no DB lock held):* Open `<root>`,
          `<root>/staging`, and `<root>/revisions` with `O_RDONLY | O_DIRECTORY | O_NOFOLLOW`
          (never auto-creating directories during adoption), verify all three share the exact same
          `st_dev`, and capture `fstat(revisions_dir_fd)`'s exact `(st_dev, st_ino)`.
       2. *Unconditional ledger payload & volume identity pre-scan (executed on every run and retry
          strictly before step 3 without holding a long DB lock during SHA-256 revision hashing):*
          Record the verified row set, the per-reservation on-disk verification result for every
          `'reserved'` row, and whether the ledger was empty on the current snapshot:
          - **Genuinely empty storage ledger on an unused upgrade (`0` rows in both
            `storage_reservations` and `artifact_revisions`):** If both `storage_reservations` and
            `artifact_revisions` contain zero rows on an upgraded deployment (`applied >= 1`,
            `bootstrap_auto_pin_allowed = false`), step 2 records `empty_ledger = true` and
            proceeds to step 3 **without requiring `--expected-fs-uuid` /
            `--expected-revisions-inode` for nonexistent ledger rows** — subject to mandatory
            re-verification of ledger emptiness under `storage_instance FOR UPDATE` in step 3
            before any sentinel is written.
          - **Published and purging revisions (`artifact_revisions`):** Every
            `openmettle.artifact_revisions` row in `state IN ('active', 'retained')` **MUST**
            exist relative to `<root>/revisions` (`AT_SYMLINK_NOFOLLOW` regular file on
            `revisions_dir_fd` with exact `size_bytes`, plus sampled SHA-256 `content_digest`
            verification). Every `state = 'purging'` row whose `<root>/revisions/<id>` file is
            still present on disk is likewise verified as a non-symlink regular file with exact
            `size_bytes` and `content_digest` (while missing `purging` files remain allowed once
            volume identity is established, retaining their byte charges until `purge_due`
            confirms `state = 'purged'` after adoption completes). **Concurrent `begin_purge`
            handling on already-pinned retries (`volume_id IS NOT NULL`):** because `begin_purge`
            in `src/storage.rs` updates `artifact_revisions` (`'retained' -> 'purging'`) without
            acquiring `storage_instance FOR UPDATE`, on an already-pinned retry a live `N` cleaner
            may legitimately advance a due `'retained'` revision to `'purging'` and unlink
            `revisions/<id>` (blocking only at `confirm_purge`) between step 2's snapshot and
            on-disk inspection. Therefore, whenever `volume_id IS NOT NULL` and on-disk inspection
            of a row scanned as `'retained'` returns `ENOENT` (during step 2 or step 3), the
            verifier **re-queries that revision's current `artifact_revisions.state` in a fresh
            `READ COMMITTED` `SELECT` statement**: if it transitioned to `state IN ('purging',
            'purged')`, `ENOENT` is accepted as valid concurrent `purge_due` progress; if it
            remains `state IN ('active', 'retained')`, verification fails closed with `OMQ03`.
            (During initial adoption while `volume_id IS NULL`, `N-1` cleaners are quiesced and
            `N` cleaners + `enforce_worker_storage_volume_pinned()` (`OMQ03`) forbid `begin_purge`,
            so zero concurrent `begin_purge` can occur and any missing `'active'`/`'retained'` file
            fails closed unconditionally.)
          - **Outstanding reservations (`storage_reservations` in `state = 'reserved'`) and
            per-reservation individual accounting guard:** Inspect **every individual**
            `storage_reservations` row in `state = 'reserved'` relative to `revisions_dir_fd` and
            `staging_dir_fd` (`AT_SYMLINK_NOFOLLOW` regular file, `size <= max_bytes`). Track the
            exact set of `'reserved'` rows where **neither** `revisions/<id>` **nor**
            `staging/<id>` is positively verified on disk. If **zero** digest-bearing revisions
            (`active`, `retained`, or still-present `purging`) were positively verified on disk
            AND `state = 'reserved'` rows exist while **neither** `revisions/<id>` nor
            `staging/<id>` exists on disk for any `'reserved'` row, default adoption **MUST fail
            closed (`OMQ03` / CLI error)** unless `--confirm-no-on-disk-payloads` is supplied
            alongside both `--expected-fs-uuid` and `--expected-revisions-inode`. Moreover — **even
            when digest-bearing revisions or other `'reserved'` rows (e.g., `R1` in `staging/`)
            are present on disk, or when `--expected-fs-uuid` and `--expected-revisions-inode` are
            supplied** — any individual `'reserved'` row (such as `R2`, renamed into an original
            `revisions/` before same-filesystem replacement) where neither `revisions/<id>` nor
            `staging/<id>` is positively verified on disk at adoption commit time is marked
            **`adoption_unverified = true`** in step 3 so automatic worker `ENOENT` cleaners can
            never silently release its `max_bytes` charge!
          - **General zero-verified-revision rule for populated ledgers (covering mixed
            reservation-only ledgers, missing-file `purging`-only ledgers, and historical
            `released`/`purged`-only ledgers, on both initial run and retry):** Whenever `>= 1`
            row exists in `storage_reservations` or `artifact_revisions` AND **zero**
            digest-bearing revisions (`active`, `retained`, or still-present `purging`) were
            positively verified on disk during step 2, revision checks alone have not
            cryptographically established directory identity — and filesystem UUID alone cannot
            detect replacing `<root>/revisions` with a fresh empty directory on the **same
            filesystem**. Therefore, `openmettle-admin` adoption **MUST require independent
            evidence for BOTH the mounted filesystem AND the exact `revisions/` directory**:
            **`--expected-fs-uuid <fs_uuid>`** (verified against the mounted filesystem backing
            `<root>`'s `st_dev`) **AND** **`--expected-revisions-inode <dev>:<ino>`** (verified
            against `fstat(revisions_dir_fd)`'s exact `(st_dev, st_ino)`, so replacing
            `<root>/revisions` with a new empty directory on the same filesystem fails
            `--expected-revisions-inode` immediately!), plus an explicit
            **`--confirm-no-on-disk-payloads`** flag alongside `--expected-fs-uuid` and
            `--expected-revisions-inode` for the rare case where every
            `'reserved'`/`'purging'`/`'purged'` row genuinely has zero surviving files on the real
            volume. Re-executing step 2 unconditionally before step 3 ensures a retry after crash
            still rejects an empty or wrong mount or same-filesystem `revisions/` replacement even
            if a stray `.openmettle-volume-id` file were present.
       3. *Lock `storage_reservations` (`state = 'reserved'`, asc `id`) strictly BEFORE
          `openmettle.storage_instance FOR UPDATE` and strictly BEFORE any sentinel write or
          `.tmp.*` cleanup, run common locked re-verification & `adoption_unverified = true`
          quarantine on BOTH unpinned and already-pinned runs, and publish atomically via `linkat`
          (unified protocol for BOTH `openmettle-admin` adoption AND `Store::open` fresh-bootstrap
          auto-pinning):*
          Open an `openmettle_owner` (adoption) or `openmettle_api`/`openmettle_worker`
          (fresh-bootstrap auto-pinning, committing through `openmettle.storage_pin_volume_id`
          `SECURITY DEFINER` in the same transaction) transaction. On `openmettle-admin` adoption,
          first lock all current `state = 'reserved'` rows via `SELECT id FROM
          openmettle.storage_reservations WHERE state = 'reserved' ORDER BY id ASC FOR UPDATE`
          **before** locking `storage_instance` (preserving the strictly acyclic
          `storage_reservations -> storage_instance` lock order with `storage::settle` and
          `storage::release`), and then execute `SELECT volume_id, bootstrap_auto_pin_allowed FROM
          openmettle.storage_instance WHERE id FOR UPDATE` **strictly before creating, writing, or
          linking any `.openmettle-volume-id` file or unlinking any `.tmp.*` file** (on
          fresh-bootstrap auto-pinning, the storage ledger is empty, so `Store::open` locks
          `storage_instance FOR UPDATE` directly and acquires zero row locks afterward). Because
          `storage::reserve`, `storage::settle`, `storage::release`, `retain_revision`,
          `restore_revision`, and `confirm_purge` in `src/storage.rs` acquire `storage_instance
          FOR UPDATE` before committing (whereas `begin_purge` updates only `artifact_revisions`
          without locking `storage_instance` — handled cleanly below on already-pinned retries and
          impossible while `volume_id IS NULL`), this serializes cleanly against all storage
          allocators, settlers, releasers, and concurrent publishers with zero deadlock:
          - **Common locked path on BOTH unpinned (`volume_id IS NULL`) AND already-pinned
            (`volume_id IS NOT NULL`) `openmettle-admin` adoption/verification runs (strictly
            BEFORE any sentinel write or idempotent return):**
            - Re-check under `storage_instance FOR UPDATE` for any `storage_reservations` or
              `artifact_revisions` rows committed since step 2. On **either** an unpinned
              (`volume_id IS NULL`) or an already-pinned (`volume_id IS NOT NULL`) run, if **any**
              newly committed `state = 'reserved'` row exists outside the initial locked set, roll
              back strictly before any sentinel write and retry from step 2/step 3 so every
              `'reserved'` row is locked in canonical ascending `id` order before `storage_instance
              FOR UPDATE` and classified under lock.
            - Verify any newly committed revisions on disk (on already-pinned retries, re-querying
              `artifact_revisions.state` in a fresh `READ COMMITTED` `SELECT` whenever a previously
              `'retained'` revision returns `ENOENT` on disk, accepting `state IN ('purging',
              'purged')` as valid concurrent `begin_purge` / `purge_due` progress and failing
              closed with `OMQ03` if still `'active'` or `'retained'`).
            - Classify **every** locked `state = 'reserved'` row against verified `revisions_dir_fd`
              and `staging_dir_fd` (`rustix::fs::statat(..., AtFlags::SYMLINK_NOFOLLOW)` regular
              file with `size <= max_bytes`). On **both** initial unpinned adoption (`volume_id IS
              NULL`) **and** every already-pinned (`volume_id IS NOT NULL`) adoption/verification
              retry, execute **`UPDATE openmettle.storage_reservations SET adoption_unverified =
              true WHERE id = ANY($unaccounted_reserved_ids) AND state = 'reserved' AND NOT
              adoption_unverified`** for every locked `'reserved'` row where neither
              `revisions/<id>` nor `staging/<id>` is positively verified on disk at adoption commit
              time. That quarantine keeps `max_bytes` charged and blocks **both** automatic worker
              `ENOENT` cleaners (`reconcile_expired`, run-linked recovery) **and**
              `artifact_fs::abort` from releasing the hold until settled by same-key retry (which
              clears `adoption_unverified = false`) or explicitly reconciled by `openmettle_owner`.
          - **Already-pinned branch (`volume_id IS NOT NULL` — lost commit-ack retry or second
            concurrent bootstrap/adoption publisher):** **NEVER create, write, or link any missing
            sentinel.** Verify that **all three** existing `.openmettle-volume-id` sentinels
            (`<root>` `:root`, `<root>/revisions` `:revisions`, `<root>/staging` `:staging`)
            already exist — each opened with `openat(..., O_RDONLY | O_NOFOLLOW | O_NONBLOCK)` +
            `fstat` verifying `S_ISREG` and exact `st_dev`, bounded `<= 64`-byte read — and **all
            three** match `storage_instance.volume_id` paired with their exact role tag, **failing
            closed immediately with `OMQ03`** if **any** sentinel is missing, mismatched,
            wrong-role, non-regular (including FIFO/symlink), or on a different `st_dev` (including
            post-commit replacement of `<root>/revisions` alone on an empty ledger!). Commit the
            common-path `adoption_unverified = true` `UPDATE`s (if any) and return idempotent
            success.
          - **Unpinned branch (`volume_id IS NULL`) — ledger re-verification strictly BEFORE
            publishing any sentinel:**
            - On fresh-bootstrap auto-pinning (`Store::open`), require `bootstrap_auto_pin_allowed
              = true` AND `NOT EXISTS (SELECT 1 FROM openmettle.storage_reservations) AND NOT
              EXISTS (SELECT 1 FROM openmettle.artifact_revisions)` under `storage_instance FOR
              UPDATE`, failing closed with `OMQ03` and writing zero sentinels otherwise.
            - On `openmettle-admin` adoption, if step 2 used the empty-ledger branch (`0` rows in
              both `storage_reservations` and `artifact_revisions` without `--expected-fs-uuid` /
              `--expected-revisions-inode`), re-check `EXISTS (SELECT 1 FROM
              openmettle.storage_reservations) OR EXISTS (SELECT 1 FROM
              openmettle.artifact_revisions)` under `storage_instance FOR UPDATE`. If any row
              committed between step 2 and `storage_instance FOR UPDATE`, the empty-ledger waiver
              is stale — **do NOT publish any sentinel**; roll back and re-run step 2's
              populated-ledger rules against the newly committed row(s) (which fails closed with
              `OMQ03` on an empty replacement directory without `--expected-fs-uuid`,
              `--expected-revisions-inode`, and on-disk payload verification). On a populated
              ledger, re-verify `--expected-fs-uuid` and `--expected-revisions-inode` whenever `0`
              digest-bearing revisions are verified.
          - **Crash-safe, race-free sentinel publication with root `fsync` barrier (only while
            `volume_id IS NULL` under `storage_instance FOR UPDATE`):** Never create
            `.openmettle-volume-id` directly with `O_CREAT | O_EXCL` before writing its payload (a
            crash between `openat` and `write` would leave a 0-byte sentinel that causes every
            retry to fail permanently). Instead:
            - *No live-peer `.tmp.*` interference:* Publishers **NEVER** run an uncoordinated
              wildcard unlink of `.openmettle-volume-id.tmp.*`. Each publisher creates a unique
              `.openmettle-volume-id.tmp.<128bit_random_hex>` (`OFlags::WRONLY | OFlags::CREATE |
              OFlags::EXCL | OFlags::NOFOLLOW`, `Mode::RUSR | Mode::WUSR`) and unlinks **only its
              own `tmp_name`** in an unconditional cleanup guard after `linkat` or error; leftover
              `.openmettle-volume-id.tmp.*` files from a prior `SIGKILL` are unlinked **only while
              holding `storage_instance FOR UPDATE`** when `rustix::fs::statat(...,
              AtFlags::SYMLINK_NOFOLLOW)` shows `st_mtime` older than `300 s`.
            - *Winning `:root` UUID adoption & mandatory `fsync(root_fd)` barrier before child
              sentinels:* Before generating a UUID, inspect `<root>/.openmettle-volume-id` via
              `openat(root_fd, ".openmettle-volume-id", OFlags::RDONLY | OFlags::NOFOLLOW |
              OFlags::NONBLOCK)` + `fstat` (`S_ISREG` on `<root>`'s `st_dev`, bounded `<= 64`-byte
              read) — if present, verify it contains valid `"<existing_uuid>:root\n"` and adopt
              `sentinel_uuid = existing_uuid` (failing closed with `OMQ03` if symlinked,
              FIFO/non-regular, wrong `st_dev`, or malformed); otherwise generate a fresh canonical
              lowercase v4 UUID. Publish `(root_fd, "root")` **first**: create unique `tmp_name =
              ".openmettle-volume-id.tmp.<128bit_random_hex>"` relative to `root_fd`
              (`OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW`, `Mode::RUSR |
              Mode::WUSR`), write the complete `"<sentinel_uuid>:root\n"` payload, **`fsync` the
              temp FD**, close it, publish via **`linkat(root_fd, tmp_name, root_fd,
              ".openmettle-volume-id", AtFlags::empty())`** (POSIX atomic hard-link creation, which
              never exposes a 0-byte or partial `.openmettle-volume-id` and fails with `EEXIST`
              without overwriting any existing sentinel), and unconditionally unlink **only its own
              `tmp_name`** in the cleanup guard. If `linkat` on `<root>/.openmettle-volume-id`
              returns `EEXIST` (from a prior interrupted run or local race), re-open and validate
              `<root>/.openmettle-volume-id` (`OFlags::RDONLY | OFlags::NOFOLLOW |
              OFlags::NONBLOCK` + `fstat` `S_ISREG` on `<root>`'s `st_dev`, bounded `<= 64`-byte
              read, `"<winning_uuid>:root\n"`) and **adopt `sentinel_uuid = winning_uuid`**
              (verifying `volume_id IS NULL OR volume_id = winning_uuid`) instead of rejecting a
              valid winning root sentinel. **Immediately after publishing (or adopting on `EEXIST`)
              `(root_fd, "root")`, call and require `Ok(())` from `fsync(root_fd)` strictly BEFORE
              creating or linking either child sentinel (`(revisions_dir_fd, "revisions")` or
              `(staging_dir_fd, "staging")`)** — preventing a storage-host crash from persisting a
              child sentinel while losing `<root>/.openmettle-volume-id` and causing a retry to
              generate a conflicting UUID (`OMQ03`). Only after `fsync(root_fd)` succeeds, publish
              `(revisions_dir_fd, "revisions")` and `(staging_dir_fd, "staging")` via the exact
              same unique `tmp_name` + `fsync(tmp_fd)` + `linkat` + own-`tmp_name` `unlinkat`
              protocol (on `EEXIST`, validating exact `"<sentinel_uuid>:<role>\n"` via
              `OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK` + `fstat` `S_ISREG` on the
              same `st_dev`, failing closed with `OMQ03` on mismatch/wrong-role/corruption), and
              then **call and require `Ok(())` from `fsync(revisions_dir_fd)` and
              `fsync(staging_dir_fd)` strictly BEFORE updating `storage_instance.volume_id`**.
            - Still inside the same `storage_instance FOR UPDATE` transaction (alongside any
              common-path `adoption_unverified = true` updates), set `volume_id = sentinel_uuid,
              bootstrap_auto_pin_allowed = false` (directly as `openmettle_owner` for adoption, or
              via `openmettle.storage_pin_volume_id(sentinel_uuid)` for fresh-bootstrap
              auto-pinning) and commit.
     - **Fail-closed verification once pinned (`storage_instance.volume_id IS NOT NULL`),
       directory-descriptor binding across ALL `artifact_fs::Store` operations, post-`renameat` /
       pre-`commit` re-verification, and guarded `artifact_fs::abort`:** Existing
       [`src/artifact_fs.rs`](../../src/artifact_fs.rs) stores `PathBuf`s, re-resolves
       `<root>/revisions` by pathname at `rename` time, and unconditionally releases reservations
       inside `abort()` (`src/artifact_fs.rs:505-510, 584-590`). PR2 closes every one of these
       windows:
       - `artifact_fs::Store` retains `Arc`-shared verified directory descriptors (`root_fd`,
         `staging_dir_fd`, `revisions_dir_fd`: `OwnedFd` opened via `rustix::fs::openat` with
         `OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW` plus their verified `(st_dev,
         st_ino)` pairs) and executes **ALL** `Store` filesystem operations — **`Store::stage`**
         (`rustix::fs::openat` on `staging_dir_fd` with **`OFlags::RDWR | OFlags::CREATE |
         OFlags::EXCL | OFlags::NOFOLLOW`** and `Mode::RUSR | Mode::WUSR` converted to
         `std::fs::File::from(owned_fd)`, immediately acquiring non-blocking shared flock
         **`file.try_lock_shared()`** (`LOCK_SH | LOCK_NB`, returning `Error::InProgress` on
         `WouldBlock`) and holding `LOCK_SH` for the lifetime of the staged upload writer),
         **upload publication** (`renameat(&staging_dir_fd, id, &revisions_dir_fd, id)` +
         `fsync(revisions_dir_fd)` + `fsync(staging_dir_fd)`), **upload error/cancellation/drop
         cleanup** (`unlinkat` on `staging_dir_fd` + `fsync(staging_dir_fd)`), **`Store::read`**
         (`openat` on `revisions_dir_fd` with `OFlags::RDONLY | OFlags::NOFOLLOW |
         OFlags::NONBLOCK` + `fstat` `S_ISREG`), and **all worker cleaners** — **strictly relative
         to those verified directory descriptors** (never resolving `<root>/staging` or
         `<root>/revisions` pathnames via `std::fs`).
       - **Pre-`stage`, pre-`renameat`, AND post-`renameat` / post-`fsync` / pre-SQL-`commit`
         re-verification:**
         1. *Pre-`stage` and pre-`renameat`:* Before `Store::stage` AND again before
            `renameat(&staging_dir_fd, id, &revisions_dir_fd, id)`, `Store` re-opens `<root>` at
            its configured path and `"staging"` / `"revisions"` relative to that fresh root FD
            (`OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW`), verifies all three still
            have the **exact same `(st_dev, st_ino)`** as the retained `(root_fd, staging_dir_fd,
            revisions_dir_fd)`, AND (when `storage_instance.volume_id IS NOT NULL`) verifies
            matching role-tagged `.openmettle-volume-id` sentinels (`:root`, `:staging`,
            `:revisions` via `openat(..., OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK)` +
            `fstat` `S_ISREG`, exact `st_dev`, bounded `<= 64`-byte read). If `<root>`,
            `<root>/staging`, or `<root>/revisions` was replaced or unlinked before `renameat`,
            publication **fails closed (`Error::Io`) strictly BEFORE `renameat` and BEFORE
            `storage::settle`**, unlinking `<id>` from `staging_dir_fd` + `fsync(staging_dir_fd)`
            and **refusing to call `storage::release`** (because directory/volume verification
            failed, keeping `reserved_bytes` charged fail-closed).
         2. *Post-`renameat` / post-`fsync` / strictly pre-SQL-`commit`:* After
            `renameat(&staging_dir_fd, id, &revisions_dir_fd, id)` + `fsync(revisions_dir_fd)` +
            `fsync(staging_dir_fd)` succeed and **strictly BEFORE `tx.commit()`** of
            `storage::settle`, `Store` performs the exact same fresh path re-open of `<root>`,
            `"staging"`, and `"revisions"` (`OFlags::RDONLY | OFlags::DIRECTORY |
            OFlags::NOFOLLOW`), verifies their `(st_dev, st_ino)` still equal `(root_fd,
            staging_dir_fd, revisions_dir_fd)` and their role-tagged `.openmettle-volume-id`
            sentinels match (when `volume_id IS NOT NULL`), and verifies
            `statat(revisions_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` is a regular file of
            `size_bytes`. If `<root>`, `<root>/staging`, or `<root>/revisions` was displaced before
            `tx.commit()`, `Store` rolls back the SQL transaction (`Error::Io`) **without** calling
            `storage::release` (because `revisions/<id>` now sits in the displaced
            `revisions_dir_fd`, keeping `reserved_bytes` charged).
         3. *Narrowed guarantee & fail-closed recovery for live host directory replacement AFTER
            the final pre-`commit` check:* Because POSIX provides no unprivileged cross-process
            lock preventing a privileged host process from renaming `<root>/revisions` while
            `tx.commit()` is in flight over PostgreSQL TCP (or post-commit), `Store`'s `dirfd`
            binding guarantees intra-process consistency (never splitting a write, read, or cleanup
            across two directory trees), while **live host replacement of `<root>`,
            `<root>/staging`, or `<root>/revisions` is forbidden by operational contract and caught
            fail-closed**:
            - Any newly created replacement `<root>/revisions` lacks `<volume_id>:revisions`,
              causing every subsequent `Store::stage`, `Store::publish`, `Store::read`, worker
              cleaner, and restarted process `Store::open` to fail sentinel verification closed
              (`Error::Io`, with zero silent reads, writes, releases, or purges).
            - Even if a privileged actor copies `<volume_id>:revisions` into a replacement
              `<root>/revisions`, any revision committed into the displaced old directory during
              the post-check `COMMIT` window is deterministically caught as `Error::Missing` on
              `Store::read`, `OMQ03` failure on `openmettle-migrate` / volume adoption verification
              (missing `'active'`/`'retained'` revision payload), and a hard missing-active-payload
              drift failure in `verify_accounting_drift`. Operator recovery restores the displaced
              `revisions/` directory (or moves its `<reservation_id>` files back into
              `<root>/revisions` and `fsync`s) and re-runs verified volume adoption +
              `verify_accounting_drift` before reopening traffic.
       - **Guarded `artifact_fs::abort` and every non-run API pre-settlement error release path
         ([`src/artifact_fs.rs`](../../src/artifact_fs.rs)):** After a post-rename, pre-settlement
         crash leaves `revisions/<id>` on disk while `storage_reservations.state = 'reserved'`, a
         same-key HTTP upload retry can create `staging/<id>`, fail multipart validation (or
         staging sync / pre-rename `Io`), and invoke `abort(pool, upload.scope, &id, error)`.
         Unconditionally calling `storage::release` inside `abort` would release bytes belonging to
         the earlier published `revisions/<id>` payload! PR2 therefore requires
         **`artifact_fs::abort` (and every non-run API pre-settlement error release path)** to:
         1. Open a transaction and lock `storage_reservations FOR UPDATE` (`WHERE scope_id =
            $1::uuid AND id = $2::uuid`),
         2. Verify **`state = 'reserved' AND NOT adoption_unverified`**,
         3. Verify three-directory identity across `(root_fd, staging_dir_fd, revisions_dir_fd)`:
            re-open `<root>`, `"staging"`, `"revisions"` (`OFlags::RDONLY | OFlags::DIRECTORY |
            OFlags::NOFOLLOW`) and verify matching `(st_dev, st_ino)` across all three open
            directories AND — whenever `storage_instance.volume_id IS NOT NULL` — verify matching
            role-tagged `.openmettle-volume-id` sentinels (`:root`, `:staging`, `:revisions` via
            `openat(..., OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK)` + `fstat`
            `S_ISREG`, equal `st_dev`, bounded `<= 64`-byte read) (before adoption while
            `volume_id IS NULL` on an unpinned in-flight upload, matching retained `(st_dev,
            st_ino)` of all three open directories is required),
         4. Unlink `staging/<id>` relative to `staging_dir_fd` (`ENOENT` allowed if never staged) +
            `fsync(staging_dir_fd)`, and
         5. Prove **`rustix::fs::statat(&revisions_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` returns
            `ENOENT`** strictly before committing `storage::release`.
         If `adoption_unverified = true`, directory/volume verification fails, or `revisions/<id>`
         exists (or returns any non-`ENOENT` error), `abort` **MUST NOT** call `storage::release`,
         preserving both `revisions/<id>` and `reserved_bytes`!
       - Once `storage_instance.volume_id` is non-null in PostgreSQL, `Store::open` and **every**
         worker cleaner — explicitly including **`artifact_fs::purge_due`**,
         `artifact_fs::reconcile_expired`, run-linked `ENOENT` storage recovery and `staging/`
         `ReadDir` cleanup — **MUST refuse to initialize a fresh sentinel** (and must not accept a
         newly created or empty replacement directory) and **MUST verify BEFORE touching any
         payload path or mutating PostgreSQL** that: (a) `<root>`, `revisions_dir_fd`
         (`<root>/revisions`), and `staging_dir_fd` (`<root>/staging`) all open with
         `OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW` and share the exact same
         `st_dev`, and (b) `.openmettle-volume-id` opened via `openat(..., OFlags::RDONLY |
         OFlags::NOFOLLOW | OFlags::NONBLOCK)` + `fstat` on **each** of `<root>`,
         `revisions_dir_fd`, and `staging_dir_fd` is a regular file (`S_ISREG` — rejecting FIFOs,
         sockets, device nodes, directories and symlinks immediately without blocking) on that
         exact same `st_dev` whose bounded (`<= 64`-byte) content contains non-null pinned
         `storage_instance.volume_id` paired with its exact `:root`, `:revisions`, or `:staging`
         role tag. All subsequent `statat`/`unlinkat` calls execute strictly relative to those
         verified `revisions_dir_fd` and `staging_dir_fd` descriptors. If any of the three
         sentinels is missing, unreadable, FIFO/symlink/non-regular, wrong-role, mismatched, or on
         a different `st_dev` (including if only `<root>/revisions` or `<root>/staging` was
         replaced or swapped on the same filesystem), startup and all cleaners **fail closed
         immediately** with **zero unlinked files, zero released holds, and zero confirmed
         purges**.
   - *Non-run uploads (`run_id IS NULL`, `artifact_fs::reconcile_expired`) and retention purges
     (`artifact_fs::purge_due`):*
     Non-run uploads continue through `artifact_fs::reconcile_expired` and retention purges
     continue through `artifact_fs::purge_due` — **both** requiring configured
     `OPENMETTLE_WORKER_ARTIFACTS_DIR` and verified non-null pinned volume identity across all
     three role-tagged `.openmettle-volume-id` sentinels (`<root>` `:root`, `<root>/revisions`
     `:revisions`, `<root>/staging` `:staging`, opened via `OFlags::RDONLY | OFlags::NOFOLLOW |
     OFlags::NONBLOCK` + `fstat` `S_ISREG`, bounded `<= 64`-byte read) and open directory FDs
     sharing equal `st_dev` **before** any `statat`/`unlinkat` relative to the verified
     `revisions_dir_fd` / `staging_dir_fd` or any `storage::release`, `storage::begin_purge`, or
     `storage::confirm_purge` call.
     - **Mandatory `fsync(revisions_dir_fd)` durability barrier on `artifact_fs::purge_due`
       (including `ENOENT` retries):** Existing `artifact_fs` removal helper
       ([`src/artifact_fs.rs`](../../src/artifact_fs.rs)) treats `ENOENT` as success without
       `fsync`ing `revisions_dir_fd`, which could commit `storage::confirm_purge` after an
       interrupted unlink + `ENOENT` retry before directory entry removal is durable on disk. PR2
       requires `artifact_fs::purge_due` (after verifying pinned three-directory volume sentinels)
       to execute `unlinkat(&revisions_dir_fd, reservation_id, AtFlags::empty())` and
       **unconditionally call and require `Ok(())` from `fsync(&revisions_dir_fd)` strictly BEFORE
       committing `storage::confirm_purge` — explicitly including when `unlinkat` returns
       `ENOENT`**.
     - **PR2 updates [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md)'s
       post-rename `reconcile_expired` behavior (and `tests/schema/artifact_fs.rs`'s `renamed`
       test case) to enforce the exact same directory-relative `revisions_dir_fd` `ENOENT` proof
       as run-linked storage recovery:** Under `storage_reservations FOR UPDATE SKIP LOCKED`
       (filtering `state = 'reserved' AND run_id IS NULL AND NOT adoption_unverified` — excluding
       all `adoption_unverified = true` rows from automatic `ENOENT` release!) and verified pinned
       volume sentinels, inspect leaf `<id>` relative to verified `revisions_dir_fd` via
       `rustix::fs::statat(revisions_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)`:
       - **Only when `revisions/<id>` returns `ENOENT`** may `reconcile_expired` unlink
         `staging/<id>` relative to verified `staging_dir_fd`, call `fsync(staging_dir_fd)`, and
         commit `storage::release`.
       - **When `revisions/<id>` exists** (or returns any non-`ENOENT` error) while `state =
         'reserved'`, `reconcile_expired` **MUST NOT unlink `revisions/<id>` and MUST NOT call
         `storage::release`** — preserving both the published payload and its `reserved_bytes`
         charge for deterministic same-key upload retry (ADR 0031) or explicit operator
         reconciliation, while advancing its bounded-pass cursor past `<id>` so subsequent expired
         uploads are never starved.
     - **Two-step raw-index-key paging for `reconcile_expired` (100% `IMMUTABLE` plain-column
       partial B-tree indexes):** Scan two independent bounded raw-key passes per sweep cycle with
       zero joins or `clock_timestamp()` inside the scan query: (a) modern rows with
       `lease_expires_at IS NOT NULL` over `storage_reservations_upload_expiry_idx` (`ON
       openmettle.storage_reservations (lease_expires_at, id) WHERE state = 'reserved' AND run_id
       IS NULL AND lease_expires_at IS NOT NULL AND NOT adoption_unverified`, constant upper bound
       `(v_now, max_uuid)`), and (b) legacy rows with `lease_expires_at IS NULL` over
       `storage_reservations_upload_legacy_expiry_idx` (`ON openmettle.storage_reservations
       (created_at, id) WHERE state = 'reserved' AND run_id IS NULL AND lease_expires_at IS NULL
       AND NOT adoption_unverified`, constant upper bound `(v_now - interval '900 seconds',
       max_uuid)`). Each pass materializes at most `batch_size` raw `(expiry_col, id)` keys using
       only `(expiry_col, id) > last_attempted AND (expiry_col, id) <= pass_upper_bound ORDER BY
       expiry_col ASC, id ASC LIMIT batch_size`, evaluates `revisions/<id>` `ENOENT` only on those
       `<= batch_size` keys, advances `last_attempted` across **every inspected raw key**
       (including 100%-ineligible pages of post-rename `'reserved'` files!), and wraps only when
       the raw key page returns `< batch_size` rows or reaches `pass_upper_bound`.
   - *Run-linked storage holds (`run_id IS NOT NULL`, excluding `idempotency_key LIKE
     'tool-spill:%'`):*
     **Single cleanup owner for `tool-spill:*` reservations:** Because
     [ADR 0039](0039-scoped-mcp-adapter-and-bounded-tool-results.md) (`V1-14` PR2, sequenced on
     `V1-17` PR2's `volume_id`/`dirfd` foundation) creates and `LOCK_SH`-locks `staging/<id>`
     under `idempotency_key LIKE 'tool-spill:%'` and may stream to it from a detached OS thread,
     ADR 0040's generic run-linked cleaner **explicitly excludes `idempotency_key LIKE
     'tool-spill:%'`** (`AND idempotency_key NOT LIKE 'tool-spill:%'`) in **both** partial index
     `WHERE` clauses AND Step 2's under-lock eligibility check. ADR 0039 (`reconcile_run_spills`,
     acquiring `LOCK_EX` -> `set_len(0)` -> `unlinkat` -> `fsync` strictly *before*
     `storage::release`) is the **sole automatic cleanup owner** for all `idempotency_key LIKE
     'tool-spill:%'` reservations. For all other run-linked storage holds, recovery requires
     configured `OPENMETTLE_WORKER_ARTIFACTS_DIR` (`ARTIFACTS_DIR`, `artifact_fs::Store`) with
     verified non-null pinned `storage_instance.volume_id` and all three role-tagged directory
     sentinels. If `ARTIFACTS_DIR` is unavailable, unset, `storage_instance.volume_id IS NULL`, or
     sentinel/`st_dev` verification fails, run-linked storage recovery **MUST NOT** unlink any file
     or call `storage::release` and skips this phase without mutating any reservation. Otherwise,
     run **two-step raw-index-key paging** across two independent bounded passes backed by 100%
     `IMMUTABLE` plain-column partial B-tree indexes — **zero joins, zero `EXISTS`, and zero
     `clock_timestamp()` calls before `LIMIT`** (preventing any long prefix of expired holds on
     non-terminal runs or runs with unresolved operations from exhausting `statement_timeout`):
     (a) modern rows with `lease_expires_at IS NOT NULL` over `storage_reservations_run_expiry_idx`
     (`ON openmettle.storage_reservations (lease_expires_at, id) WHERE state = 'reserved' AND
     run_id IS NOT NULL AND lease_expires_at IS NOT NULL AND NOT adoption_unverified AND
     idempotency_key NOT LIKE 'tool-spill:%'`, constant `pass_upper_bound = (v_now, max_uuid)`),
     and (b) legacy rows with `lease_expires_at IS NULL` over
     `storage_reservations_run_legacy_expiry_idx` (`ON openmettle.storage_reservations
     (created_at, id) WHERE state = 'reserved' AND run_id IS NOT NULL AND lease_expires_at IS NULL
     AND NOT adoption_unverified AND idempotency_key NOT LIKE 'tool-spill:%'`, constant
     `pass_upper_bound = (v_now - interval '900 seconds', max_uuid)`). Each pass materializes at
     most `batch_size` raw `(expiry_col, id)` keys using **only** `(expiry_col, id) >
     last_attempted AND (expiry_col, id) <= pass_upper_bound ORDER BY expiry_col ASC, id ASC LIMIT
     batch_size`, evaluates eligibility (terminal linked run, zero `'intent'`/`'outcome_unknown'`
     operations, and legacy terminal-run grace rule when `lease_expires_at IS NULL`) **only** on
     those `<= batch_size` materialized keys, advances `last_attempted` across **every inspected
     raw key** (including 100%-ineligible pages!) across `SWEEP_MS` ticks (60 s default interval,
     15 s per-sweep budget), and wraps to `(-infinity, nil UUID)` with a fresh `pass_upper_bound`
     **only when the raw key page returns fewer than `batch_size` rows** or `last_attempted`
     reaches `pass_upper_bound`. Process **one eligible reservation per short transaction**:
     1. Lock `runs` (`FOR NO KEY UPDATE SKIP LOCKED`) -> `storage_reservations` (`FOR UPDATE SKIP
        LOCKED`). If either row is contended, skip immediately without blocking.
     2. Re-verify under lock that `state = 'reserved'`, `NOT adoption_unverified`, **`idempotency_key
        NOT LIKE 'tool-spill:%'`**, expiry holds, the run is terminal (no active worker lease) and
        zero linked operations are in `('intent', 'outcome_unknown')`.
     3. Verify the pinned volume identity across `<root>`, `revisions_dir_fd`, and
        `staging_dir_fd` and inspect leaf `<id>` relative to `revisions_dir_fd`:
        - **Fail-closed volume sentinel and `revisions/` verification:** Before inspecting leaf
          `<id>`, recovery MUST open `<root>`, `revisions_dir_fd` (`<root>/revisions`), and
          `staging_dir_fd` (`<root>/staging`) with `OFlags::RDONLY | OFlags::DIRECTORY |
          OFlags::NOFOLLOW`, verify all three share the exact same `st_dev`, and verify via
          `openat(..., OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK)` + `fstat` on each of
          the three directory FDs that `.openmettle-volume-id` is a regular file (`S_ISREG`) on
          that same `st_dev` whose bounded (`<= 64`-byte) content matches non-null
          `storage_instance.volume_id` and its exact `:root`, `:revisions`, or `:staging` role tag.
          Any error, `volume_id IS NULL`, missing/unmounted directory,
          missing/mismatched/wrong-role/FIFO/symlink sentinel or `st_dev` mismatch **fails closed
          immediately** without blocking and with zero unlinks and zero released holds.
        - **Directory-relative `ENOENT` proof required before release:** Perform the leaf `<id>`
          lookup relative to that verified `revisions_dir_fd` (`rustix::fs::statat` with
          `AtFlags::SYMLINK_NOFOLLOW`). Only when the three-directory sentinel + `st_dev`
          verification succeeds AND that directory-relative probe returns `ENOENT` (confirming
          atomic rename `staging/<id> -> revisions/<id>` never occurred on the pinned mounted volume
          and no published bytes still owe SQL settlement) may recovery execute and **commit
          `storage::release`** (or confirm `state = 'released'`), and then — only after commit —
          unlink `staging/<id>` relative to the verified `staging_dir_fd` if present.
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
     `worker::sweep`'s 15 s outer `tokio::time::timeout`, retaining open `dir_fd` through EOF
     drain, with `LOCK_EX` and `storage_instance FOR UPDATE` orphan serialization):*
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
     overlapping `spawn_blocking` readers — because `JoinHandle::drop` detaches running blocking
     work rather than cancelling it). Furthermore, dropping the last open FD on `<root>/staging`
     when transitioning to `DrainingEof` would allow the filesystem to free and reuse `dir_ino` for
     a freshly recreated `<root>/staging` directory before the next tick! On startup recovery and
     during bounded worker storage sweeps, `worker::maintenance` therefore holds a persistent
     **`StagingSweepState`** across `SWEEP_MS` ticks **outside** the per-tick `tokio::time::timeout`
     future, carrying an open directory descriptor (`dir_fd: OwnedFd` / `std::fs::File` opened with
     `OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW` on the verified `<root>/staging`
     directory) across all active states — **`Idle`**, **`Open { dir_fd, dir_dev, dir_ino, reader
     }`**, **`InFlight { dir_fd, dir_dev, dir_ino, handle }`**, **`InvalidatedInFlight { handle
     }`**, and **`DrainingEof { dir_fd, dir_dev, dir_ino }`** (where `handle` is the sole
     `JoinHandle<io::Result<(ReadDir, Vec<String>, bool)>>` returning only canonical lowercase UUID
     names and ignoring `.openmettle-volume-id*`) — plus a **`VecDeque<String>` of undrained
     `pending_names`**, dropping `dir_fd` **only when `pending_names.is_empty()` and the state
     transitions to `Idle` (or when invalidated into `InvalidatedInFlight` / `Idle` after clearing
     `pending_names`)**:
     - At the start of each tick, open `<root>`, `<root>/revisions`, and `<root>/staging`
       (`OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW`), verify non-null pinned
       `storage_instance.volume_id`, equal `st_dev` across all three FDs, and valid role-tagged
       `.openmettle-volume-id` sentinels (`:root`, `:revisions`, `:staging` via `openat(...,
       OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK)` + `fstat` `S_ISREG` on each FD,
       bounded `<= 64`-byte read), and inspect `<root>/staging`'s live `(cur_dev, cur_ino)`:
       - *If volume sentinel/`st_dev` verification fails:* clear `pending_names` with zero unlinks;
         if `StagingSweepState` is `InFlight { handle, .. }`, drop `dir_fd` and transition to
         **`InvalidatedInFlight { handle }`** (never dropping the running `handle` into `Idle`); if
         `Open` or `DrainingEof`, drop `dir_fd` and transition to `Idle`; and fail closed for the
         tick without spawning any new reader.
       - *If `(cur_dev, cur_ino)` changed against parked `Open { dir_fd, dir_dev, dir_ino, .. }`,
         `InFlight { dir_fd, dir_dev, dir_ino, handle }`, or `DrainingEof { dir_fd, dir_dev,
         dir_ino }`:* clear `pending_names` with zero unlinks; drop `dir_fd` and transition `Open`
         or `DrainingEof` to `Idle`; and drop `dir_fd` while transitioning `InFlight { handle, ..
         }` to **`InvalidatedInFlight { handle }`** (never `Idle` — preserving the single-reader
         guarantee even across directory replacement and 15 s tick timeouts!). Because `dir_fd`
         remained open across `Open`, `InFlight`, and `DrainingEof`, removing and recreating
         `<root>/staging` on the same filesystem cannot reuse `dir_ino` while `pending_names` is
         non-empty.
     - If `StagingSweepState` is **`InvalidatedInFlight { handle }`**, **await `&mut handle` until
       the blocking slice finishes** (if it exceeds this tick's 15 s `timeout`,
       `InvalidatedInFlight { handle }` stays parked and zero new readers may start), **discard its
       returned `ReadDir` and names without touching `pending_names` or unlinking anything, and
       ONLY THEN transition to `Idle`**.
     - If `StagingSweepState` is **`InFlight { dir_fd, dir_dev, dir_ino, handle }`** (with verified
       matching `(cur_dev, cur_ino) == (dir_dev, dir_ino)`), **first await the parked `&mut
       handle`** (never spawning a second concurrent `ReadDir` task; if the wedged slice exceeds
       this tick's 15 s `timeout` again, `InFlight` remains parked in `StagingSweepState` holding
       `dir_fd`). When `handle` resolves, append its returned canonical UUIDs to `pending_names`
       and transition to `Open { dir_fd, dir_dev, dir_ino, reader }` when `eof == false`, or drop
       `reader` while **retaining `dir_fd`** and transition to **`DrainingEof { dir_fd, dir_dev,
       dir_ino }`** when `eof == true` (never dropping `dir_fd` or transitioning directly to `Idle`
       while `pending_names` is non-empty, so `dir_ino` cannot be reused across tick boundaries!).
     - Drain `pending_names` in bounded batches against `openmettle.storage_reservations` (`WHERE
       id = ANY($1)`) **exactly once** (popping entries only as processed, checking `Instant::now()
       < sweep_deadline` and `inspected_entries < batch_size`). Confirm `<root>/staging`
       (`OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW`) still has `(cur_dev, cur_ino) ==
       (dir_dev, dir_ino)` and valid `"<volume_uuid>:staging\n"` via `openat(..., OFlags::RDONLY |
       OFlags::NOFOLLOW | OFlags::NONBLOCK)` + `fstat` `S_ISREG`. **NEVER unlink any `staging/<id>`
       without holding non-blocking exclusive flock `LOCK_EX | LOCK_NB` on the verified `(st_dev,
       st_ino)` regular file** (open via `rustix::fs::openat(&dir_fd, id, OFlags::RDWR |
       OFlags::NOFOLLOW)` -> `std::fs::File::from(owned_fd)` -> `file.try_lock()`, skipping
       immediately on `WouldBlock` while any live `Store::stage` or ADR 0039 `tool-spill:*` writer
       holds `LOCK_SH`, and re-verifying `(st_dev, st_ino)` + `S_ISREG` via
       `rustix::fs::statat(&dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` against `fstat(&file)`):
       - *Confirmed `state = 'released'` (or `state = 'settled'`) row on the primary:* while
         holding `LOCK_EX` on that verified `(st_dev, st_ino)` file, call `file.set_len(0)` ->
         `unlinkat(&dir_fd, id, AtFlags::empty())` -> `drop(file)` -> `fsync(&dir_fd)`.
       - *Zero-row (`absent` in `storage_reservations`) orphan `staging/<id>` file:* require
         `st_mtime` age **`> 900 s`** on **both** startup recovery and periodic sweep (never
         unlinking fresh pre-commit `staging/<id>` files during startup recovery or periodic
         sweeps!), acquire non-blocking `LOCK_EX` (`file.try_lock()`, skipping on `WouldBlock`),
         re-verify `(st_dev, st_ino)` + `S_ISREG` via `statat`, then — **while still holding
         `LOCK_EX`** — open a short primary DB transaction acquiring **`SELECT 1 FROM
         openmettle.storage_instance WHERE id FOR UPDATE`** (serializing against every concurrent
         `storage::reserve`) and verifying **`NOT EXISTS (SELECT 1 FROM
         openmettle.storage_reservations WHERE id = $1::uuid)`**, end the DB transaction, and
         **only if zero rows exist** call `file.set_len(0)` -> `unlinkat(&dir_fd, id,
         AtFlags::empty())` -> `drop(file)` -> `fsync(&dir_fd)`.
       Never unlink a `staging/<id>` file whose `storage_reservations` row is still `state =
       'reserved'` outside the verified `reconcile_expired` / run-linked release / ADR 0039
       `reconcile_run_spills` paths. When `StagingSweepState` is **`DrainingEof { dir_fd, dir_dev,
       dir_ino }`**, drop `dir_fd` and transition to `Idle` **only once `pending_names.is_empty()`**
       (if budget is exhausted mid-drain, keep `DrainingEof { dir_fd, dir_dev, dir_ino }` parked
       holding `dir_fd` so the next tick re-verifies `(cur_dev, cur_ino) == (dir_dev, dir_ino)` and
       valid `:staging` sentinel before draining the remaining names).
     - Only once `pending_names` is empty, `StagingSweepState` is `Idle` or `Open`, and budget
       remains (`Instant::now() < sweep_deadline` and `inspected_entries < batch_size`), open a
       verified `dir_fd` (`OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW`) plus a fresh
       `ReadDir` stream if `Idle` and **transition `StagingSweepState` from `Open { dir_fd,
       dir_dev, dir_ino, reader }` to `InFlight { dir_fd, dir_dev, dir_ino, handle }` before
       awaiting** the single `spawn_blocking` slice (at most `64` directory entries), so any 15 s
       `tokio::time::timeout` cancellation mid-slice leaves `InFlight` (and its open `dir_fd`)
       parked for the next tick rather than dropping the `ReadDir` stream or entries.
     - Stop the tick as soon as `Instant::now() >= sweep_deadline` (15 s budget) or
       `inspected_entries >= batch_size`, `fsync`ing `dir_fd` after any unlinks while preserving
       `StagingSweepState` (`Open`, `InFlight`, `InvalidatedInFlight`, `DrainingEof`, and any
       remaining `pending_names`) across ticks. When `DrainingEof` finishes draining
       (`pending_names.is_empty()`), `fsync` `dir_fd` after any unlinks, drop `dir_fd`, and leave
       `StagingSweepState` in `Idle` so a subsequent tick starts the next pass.
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
`quota_*` table (`quota_defaults`, `quota_cost_unit_lock`, `quota_enforcement`,
`quota_gateway_handoffs`, `quota_overrides`, `quota_budgets`, `quota_reservations`,
`quota_reservation_charges`, `quota_reconciliations` or `quota_warning_events`), and zero runtime
roles hold even `SELECT` on `quota_cost_unit_lock` or `quota_gateway_handoffs`.**
Because PostgreSQL 18 requires `UPDATE` privilege to execute `SELECT ... FOR NO KEY UPDATE` or
`FOR UPDATE`, **no runtime role executes direct row-locking `SELECT` on any `quota_*` table**
either; all `quota_*` row locking and writes (as well as `quota_cost_unit_lock` locking inside the
`gateway_usage_reports_cost_unit_guard` trigger, gateway-binding verification inside
`quota_reservations_gateway_binding_guard`, commit-time handoff hold verification,
`quota_gateway_handoffs` recording before `quota_enforcement FOR SHARE` locking inside
`quota_enforce_gateway_handoff_holds` / `enforce_gateway_handoff_holds()`, PostgreSQL ledger
backstop guarding for unpinned worker storage mutations inside
`enforce_worker_storage_volume_pinned()`, lazy legacy-run parent hold initialization inside
`quota_ensure_legacy_run_holds()`, and fresh-bootstrap-only `storage_instance.volume_id`
auto-pinning) run strictly inside narrow `openmettle_owner`-owned `SECURITY DEFINER` functions
with `SET search_path = pg_catalog`, schema-qualified relations, `REVOKE ALL ON FUNCTION ... FROM
PUBLIC` and exact `oid::regprocedure` signatures audited in `src/boundaries.sql` (following
[ADR 0030](0030-session-issuance-database-boundary.md) and ADR 0037). Neither `openmettle_api` nor
`openmettle_worker` receives direct `SELECT` privileges on Migration `0023`'s
`openmettle.gateway_requests` or `openmettle.gateway_usage_reports` (or other gateway tables):
lost commit-ack handoff recovery runs solely through `openmettle.quota_recover_lost_handoff(...)`,
lazy legacy-run parent hold backfill runs solely through
`openmettle.quota_ensure_legacy_run_holds(...)`, fenced successor-worker superseded-round unwind
runs solely through `openmettle.quota_unwind_superseded_round(...)`, pre-upgrade orphan
`'reserved'` gateway sweep runs solely through
`openmettle.quota_release_orphan_gateway_requests(...)`, and SQL drift verification runs solely
through `openmettle.quota_verify_accounting_drift()`.

| Object or `SECURITY DEFINER` entrypoint | `openmettle_api` | `openmettle_worker` | `openmettle_gateway` (Migration `0023`) | `openmettle_issuance` (ADR 0030) |
| --- | --- | --- | --- | --- |
| `quota_defaults` | `SELECT` only | `SELECT` only | `SELECT` only | None |
| `quota_cost_unit_lock` | None | None | None (locked internally by `SECURITY DEFINER` trigger `enforce_gateway_report_cost_unit()`) | None |
| `quota_enforcement` | `SELECT` only | `SELECT` only | `SELECT` only | None |
| `quota_gateway_handoffs` | None (written at `COMMIT` by `SECURITY DEFINER` `enforce_gateway_handoff_holds()` before locking `quota_enforcement FOR SHARE`; read internally by `SECURITY DEFINER` `quota_recover_lost_handoff()`) | None (same, plus `quota_verify_accounting_drift()`) | None | None |
| `quota_overrides` | `SELECT` only | `SELECT` only | `SELECT` only | None |
| `quota_budgets`, `quota_reservations`, `quota_reservation_charges`, `quota_reconciliations`, `quota_warning_events` | `SELECT` only | `SELECT` only | `SELECT` only | None |
| `openmettle.storage_pin_volume_id(uuid)` | `EXECUTE` (invoked by `Store::open` inside the same transaction that already holds `SELECT volume_id, bootstrap_auto_pin_allowed FROM openmettle.storage_instance FOR UPDATE` before any sentinel write or stale `.tmp.*` cleanup; permits write-once `volume_id` auto-pinning **only** while `volume_id IS NULL AND bootstrap_auto_pin_allowed = true` AND BOTH `NOT EXISTS (SELECT 1 FROM openmettle.storage_reservations)` AND `NOT EXISTS (SELECT 1 FROM openmettle.artifact_revisions)`, atomically setting `volume_id = p_volume_id` and clearing `bootstrap_auto_pin_allowed = false`; refuses every upgraded deployment (`bootstrap_auto_pin_allowed = false`, even with empty storage tables) and every populated ledger with `OMQ03`; never modifies or clears a non-null `volume_id`) | `EXECUTE` (same) | None | None |
| `openmettle.quota_upsert_scope_override(...)` and `openmettle.quota_revoke_scope_override(...)` | `EXECUTE` (validates caller role & scope/kind/bounds invariants, requiring `('instance', 'usage_cost_micros').cost_denomination IS NOT NULL` for `usage_cost_micros`; locks `run_dispatch_lock` for `executing_runs_*`, `projects`/`users`, and `storage_accounts` or active `quota_budgets` in canonical order; upserts/revokes `quota_overrides` and increments `revision` to re-arm warning watermarks) | None | None | None |
| `openmettle.quota_reserve(...)` | `EXECUTE` (tags `origin_role = 'api'`; when `gateway_request_id IS NOT NULL`, executes in the same `WriteTransaction` as `authz::gateway::reserve_in`, verifying `gateway_requests` ownership `(scope_id, actor_user_id, run_id IS NULL)`, `state = 'reserved'`, 32-byte `p_dispatch` matching `dispatch_hash = sha256(p_dispatch)`, and exact `usage_tokens` hold equality `reserved_units = q.units` (`23514`), reinforced by `quota_reservations_gateway_binding_guard`; locks `quota_budgets` internally and records `quota_warning_events`) | `EXECUTE` (tags `origin_role = 'worker'`; locks `quota_budgets` internally and records `quota_warning_events`) | None | None |
| `openmettle.quota_ensure_legacy_run_holds(...)` | None | `EXECUTE` (lazy, idempotent once-per-run parent hold backfill for a live leased `N-1`-admitted run `(scope_id, run_id)` that lacks run-level parent `quota_reservations` holds; **MUST execute inside the round-allocation `WriteTransaction` strictly BEFORE `authz::gateway::reserve_in(&mut tx, ...)`** (after any `quota_unwind_superseded_round` of a crashed predecessor); acquires locks in canonical `runs` (`FOR NO KEY UPDATE`, verifying active `Step` lease) -> non-locking check for existing run-level parent hold -> `gateway_reservations` (`FOR NO KEY UPDATE`, matching `gateway_allocate` so the immediately following `reserve_in` performs zero lock upgrade, reading Migration `0023`'s `units - allocated`) -> charged `quota_budgets` (`FOR NO KEY UPDATE`) order before locking any `quota_reservations` row; inserts missing run-level parent hold(s) (`usage_tokens` for `units - allocated` plus applicable `usage_cost_micros` ceiling, `origin_role = 'worker'`, deterministic idempotency key `("legacy-run-parent", run_id, resource_kind)`), enforcing active `quota_budgets` hard limits (`OMQ01`) and returning immediately on retries/subsequent rounds once present) | None | None |
| `openmettle.quota_allocate_round(...)` | None | `EXECUTE` (executes in the same `WriteTransaction` immediately after `quota_ensure_legacy_run_holds(...)` -> `authz::gateway::reserve_in(&mut tx, ...)`; requires the run-level parent `quota_reservations` hold to already exist and slices `slice_units <= parent.held_units`; verifies active `Step` lease on `runs`, `'reserved'` `gateway_requests` row matching `(scope_id, actor_user_id, run_id)`, 32-byte `p_dispatch` matching `dispatch_hash = sha256(p_dispatch)`, and exact `usage_tokens` hold equality `slice_units = q.units` (`23514`) reinforced by `quota_reservations_gateway_binding_guard`; creates child `quota_reservations` row in `state = 'held'` with `allocating_claim_token = p_claim_token` via parent-to-child slice transfer with zero net budget debit) | None | None |
| `openmettle.quota_commit_handoff(...)` | `EXECUTE` (own `origin_role = 'api'` standalone `run_id IS NULL` `held` rows only; requires `gateway_requests.state = 'handed_off'` from `authz::gateway::handoff_in` / `openmettle.gateway_handoff` in the same tx for metered usage holds, verified at `COMMIT` by deferred `quota_enforce_gateway_handoff_holds` inserting `quota_gateway_handoffs` first and then locking `quota_enforcement FOR SHARE` as the final lock and requiring exact `usage_tokens` `qr.reserved_units = NEW.units AND qr.held_units = NEW.units AND qr.settled_units = 0 AND qr.accepted_source_revision IS NULL` + ownership match (`OMQ04`), plus `qr.settled_units = 0 AND qr.accepted_source_revision IS NULL` on `usage_cost_micros`; **explicitly rejects all run-linked `device_reservations` holds (`run_id IS NOT NULL`, SQLSTATE `42501`)**) | `EXECUTE` (own `origin_role = 'worker'` `held` rows only, including run-round metered usage holds requiring `gateway_requests.state = 'handed_off'` from `authz::gateway::handoff_in` / `openmettle.gateway_handoff` in the same tx, verified at `COMMIT` by deferred `quota_enforce_gateway_handoff_holds` inserting `quota_gateway_handoffs` first and then locking `quota_enforcement FOR SHARE` as the final lock and requiring exact `usage_tokens` `qr.reserved_units = NEW.units AND qr.held_units = NEW.units AND qr.settled_units = 0 AND qr.accepted_source_revision IS NULL` + ownership match (`OMQ04`), plus `qr.settled_units = 0 AND qr.accepted_source_revision IS NULL` on `usage_cost_micros`; **explicitly rejects all run-linked `device_reservations` holds (`run_id IS NOT NULL`, SQLSTATE `42501`)**) | None | None |
| `openmettle.quota_recover_lost_handoff(uuid, bytea, uuid, uuid, uuid)` (`RETURNS text`) | `EXECUTE` (`p_run_id IS NULL` only; verifies `pg_has_role(session_user, 'openmettle_api', 'USAGE')`, `octet_length(p_dispatch) = 32`, and matching `gateway_requests` `(id, dispatch_hash = sha256(p_dispatch), scope_id, actor_user_id, run_id)`; locks `(runs ->) gateway_reservations -> gateway_requests -> (parent ->) quota_reservations -> quota_budgets` in canonical `FOR NO KEY UPDATE` order; on `'handed_off'`, reads recorded handoff-time obligations from `quota_gateway_handoffs` (`COALESCE(metering_enforced, false)`, `COALESCE(cost_required, false)`), asserts zero bound holds have `qr.state NOT IN ('handoff_committed', 'settled')` (`OMQ04` on `'held'`/`'released'`), evaluates required hold presence and exact `usage_tokens` hold size against `handoff.metering_enforced` / `handoff.cost_required` (NOT live `quota_enforcement` or `quota_defaults`), and returns `'handoff_committed'` (including when bound holds already settled to `'settled'`) or `'unmetered_legacy_handoff'` (when `handoff.metering_enforced = false` and zero bound holds exist, even after live activation, keeping HTTP dispatch suppressed); otherwise atomically unwinds `'reserved'`/`'released'` request and bound `'held'` holds returning `'unwound_unsent'`) | `EXECUTE` (`p_run_id IS NOT NULL` only; verifies `pg_has_role(session_user, 'openmettle_worker', 'USAGE')`, `octet_length(p_dispatch) = 32`, and matching `gateway_requests`; same canonical locking, `quota_gateway_handoffs` obligation validation, `'settled'` recognition, and `'handoff_committed'` / `'unmetered_legacy_handoff'` / `'unwound_unsent'` resolution returning round capacity to an active `'held'` parent or restoring `quota_budgets` on terminal runs) | None | None |
| `openmettle.quota_unwind_superseded_round(uuid, uuid, uuid, integer)` (`RETURNS boolean`) | None | `EXECUTE` (lease-generation-fenced successor-worker unwind for a predecessor's crashed post-commit `'reserved'` round — including an unbound `N-1` `'reserved'` round with zero bound child `quota_reservations` rows and no parent `quota_reservations` row yet; locks `runs -> gateway_reservations -> active gateway_requests (q) -> (if bound) parent & child quota_reservations` (`FOR NO KEY UPDATE`), verifies current live lease `r.claim_token = p_claim_token AND r.state IN ('running', 'cancelling', 'reconciling') AND r.lease_expires_at > clock_timestamp()`, returns `false` without mutating if `EXISTS` any bound hold with `allocating_claim_token = p_claim_token` so replay never unwinds the successor's own replacement request, and otherwise transitions `'reserved'` `gateway_requests` to `'released'`, restores `gateway_reservations.allocated`, and releases any bound `'held'` child holds back to active `'held'` parent holds returning `true`, leaving `'handed_off'` untouched returning `false`) | None | None |
| `openmettle.quota_commit_device_handoff(...)` | None | `EXECUTE` (**sole** transition path for run-linked `device_reservations` holds; locks `runs -> quota_reservations` in canonical order; verifies active `Step` lease `runs.state = 'running'`, `runs.cancel_reason IS NULL`, matching `claim_token`, `lease_expires_at > clock_timestamp()`; transitions that run's `device_reservations` `held` row with `origin_role IN ('api', 'worker')` to `handoff_committed` bound to durable `device_grant_id`) | None | None |
| `openmettle.quota_renew_lease(...)` | None | `EXECUTE` (`held` run-linked rows only, fenced to active run lease) | None | None |
| `openmettle.quota_release_unsent(...)` | `EXECUTE` (own `origin_role = 'api'` `held` rows only; explicit pre-send unwind couples with `authz::gateway::release_in` / `openmettle.gateway_release` / requires `gateway_requests.state = 'released'` for gateway-bound holds; re-verifies `(q.scope_id, q.actor_user_id) = (qr.scope_id, qr.actor_user_id) AND q.run_id IS NOT DISTINCT FROM qr.run_id` under lock before mutating either ledger; locks internally and sets `closed_at`) | `EXECUTE` (own `origin_role = 'worker'` `held` or eligible stale/terminal-run `held` rows; explicit pre-send unwind couples with `authz::gateway::release_in` / `openmettle.gateway_release` / verifies `gateway_requests.state = 'released'` and returns round capacity to an active `held` parent or releases on terminal runs; sweep mode locks `(runs ->) gateway_reservations -> gateway_requests -> (parent ->) quota_reservations` with `FOR NO KEY UPDATE SKIP LOCKED`; **explicitly re-verifies `(q.scope_id, q.actor_user_id) = (qr.scope_id, qr.actor_user_id) AND q.run_id IS NOT DISTINCT FROM qr.run_id` under lock** raising an invariant error without mutating either ledger on mismatch; proceeds if `gateway_requests.state = 'released'`, **atomically transitions stale `'reserved'` `gateway_requests` to `'released'` and restores `gateway_reservations.allocated` in the same transaction** when expiry/terminal preconditions hold, leaves `'handed_off'` or locked rows untouched, and sets `closed_at`) | None | None |
| `openmettle.quota_release_orphan_gateway_requests(interval, timestamptz, uuid, timestamptz, uuid, integer)` | None | `EXECUTE` (bounded defense-in-depth sweep capturing `v_age_cutoff := clock_timestamp() - p_max_reserved_age` once in PL/pgSQL, clamping scalar `v_upper_created_at` and `v_upper_id` via a PostgreSQL 18 `IF (p_pass_upper_created_at, p_pass_upper_id) <= (v_age_cutoff, 'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid) THEN ... ELSE ... END IF;` block, and materializing at most `p_page_size` raw `(created_at, id)` keys from `gateway_requests_reserved_idx` using only constant PL/pgSQL bounds — zero `clock_timestamp()` inside the `SELECT` — before testing `NOT EXISTS` bound `quota_reservations` and run-lease/terminal eligibility; locks `(runs ->) gateway_reservations -> gateway_requests` with `FOR NO KEY UPDATE SKIP LOCKED`, transitions `'reserved' -> 'released'`, restores `gateway_reservations.allocated`, and always advances the persistent cursor past inspected pages even on zero-orphan pages) | None | None |
| `openmettle.quota_settle_gateway_usage(...)` | None | None | `EXECUTE` (`usage_tokens`/`usage_cost_micros` only; requires `openmettle_gateway` to have already advanced `openmettle.gateway_settlements` (with `measured` widened to `numeric(38, 0)` in PR2's migration) in the same tx or prior commit; locks `openmettle.gateway_requests FOR KEY SHARE` -> `openmettle.gateway_settlements gs FOR NO KEY UPDATE` -> `quota_reservations` -> `quota_budgets`, requiring `gs.request_id = qr.gateway_request_id AND gs.revision = p_source_revision AND gs.final = r.final` so stored reports rejected by `gateway_settlements` / `gateway_advance_settlement` can never mutate `quota_reservations`; validates single `openmettle.gateway_usage_reports` row matching `(request_id, source, report_id, revision)` with `revision >= 0`, immutable `cost_denomination` vs `gateway_usage_reports.unit`, and `accepted_source_revision IS NULL OR p_source_revision > accepted_source_revision`; enforces strict per-resource authoritative evidence rules: for `usage_cost_micros`, requires `r.cost IS NOT NULL` (`C_cost = ceil(r.cost)::numeric(38, 0)`) and skips `usage_cost_micros` completely when `r.cost IS NULL`; for `usage_tokens`, treats all-`NULL` token columns (`r.prompt_tokens IS NULL AND r.completion_tokens IS NULL AND r.reasoning_tokens IS NULL`) as unknown and skips `usage_tokens` completely (preserving `state`, `held_units`, `settled_units`, and `accepted_source_revision`), applies partial/incomplete token evidence (`NOT r.final` with `>= 1` non-null token field, or `r.final = true` missing `prompt_tokens` or `completion_tokens` with `>= 1` non-null token field) only while `handoff_committed` (keeping `state = 'handoff_committed'`), and settles `handoff_committed -> settled` (including explicit `0 + 0` zero-token proof) or corrects `'settled'` only when `r.final = true AND r.prompt_tokens IS NOT NULL AND r.completion_tokens IS NOT NULL`; persists `accepted_source_revision` atomically with composite-FK `quota_reconciliations` and records `quota_warning_events`) | None |
| `openmettle.quota_release_device_slot(...)` | None | `EXECUTE` (`device_reservations` `handoff_committed` only; verifies durable V1-18 release/non-allocation record; sets `closed_at`) | None | None |
| `openmettle.quota_record_storage_warning(...)` | `EXECUTE` (evaluates storage threshold crossing from locked `storage_accounts`/`storage_instance` and records deduplicated `quota_warning_events`) | `EXECUTE` (same) | None | None |
| `openmettle.quota_verify_accounting_drift()` (`STABLE`) | None | `EXECUTE` (read-only aggregate/mismatch drift summaries across `storage_*`, `quota_*` and Migration `0023`'s `gateway_reservations`/`gateway_requests`/`gateway_usage_reports`/`gateway_settlements` — comparing `numeric(38, 0)` `settled_units` / `active_used` / `reserved_held` and widened `gateway_settlements.measured` (`numeric(38, 0)`) against the latest `gateway_settlements`-accepted `gateway_usage_reports` row with per-resource authoritative evidence (`cost IS NOT NULL` for `usage_cost_micros`, `C_cost = ceil(r.cost)::numeric(38, 0)`; non-absent token evidence for `usage_tokens`, distinguishing explicit `0` tokens from `NULL`/unknown tokens) without `bigint` overflow — without granting raw table `SELECT` on `gateway_usage_reports`; also callable by `openmettle_owner` during restore validation) | None | None |
| `storage_reservations.lease_expires_at`, `storage_reservations.adoption_unverified` | `INSERT`, `UPDATE` (with migration 4 grants; `adoption_unverified` defaults `false`, cleared to `false` by `storage::settle`, set `true` only by `openmettle_owner` during adoption; `artifact_fs::abort` and every non-run API pre-settlement error release path MUST lock `storage_reservations FOR UPDATE` (`WHERE scope_id = $1::uuid AND id = $2::uuid`), verify `state = 'reserved' AND NOT adoption_unverified` and `(root_fd, staging_dir_fd, revisions_dir_fd)` volume/directory identity, unlink `staging/<id>` + `fsync(staging_dir_fd)`, and prove `statat(revisions_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` returns `ENOENT` before calling `storage::release`) | `INSERT`, `UPDATE` (with migration 4 grants; `reserved -> released` guarded by PostgreSQL ledger backstop `enforce_worker_storage_volume_pinned()` (`OMQ03`) while `volume_id IS NULL`; all automatic worker `ENOENT` cleaners exclude `adoption_unverified = true`; generic run-linked cleaner excludes `idempotency_key LIKE 'tool-spill:%'` (owned exclusively by ADR 0039 `reconcile_run_spills`); `storage::settle` clears `adoption_unverified = false`) | None | None |
| `storage_instance`, `storage_accounts`, `artifacts`, `artifact_revisions` | Existing migration 4 grants (`volume_id`, `bootstrap_auto_pin_allowed`, `warn_pct_*`, `config_revision` `SELECT` only) | Existing migration 4 grants (`volume_id`, `bootstrap_auto_pin_allowed`, `warn_pct_*`, `config_revision` `SELECT` only; `artifact_revisions` transitions to `'purging'`/`'purged'` guarded by PostgreSQL ledger backstop `enforce_worker_storage_volume_pinned()` (`OMQ03`) while `volume_id IS NULL`) | None | None |

Only `openmettle_owner` writes `quota_defaults` (updating the migration-seeded `('instance',
'usage_cost_micros')` row strictly via direct `UPDATE` — never `INSERT ... ON CONFLICT` — subject
to `quota_defaults_cost_denomination_immutable` (`OMQ02`) serialized with `quota_cost_unit_lock`,
and acquiring `SELECT FROM openmettle.run_dispatch_lock FOR NO KEY UPDATE` before modifying
`executing_runs_*` defaults), `quota_enforcement` (flipping `metering_enforced` write-once `false
-> true` via `openmettle-admin` in a standalone single-statement transaction holding zero other
locks, subject to `quota_enforcement_write_once` (`OMQ04`)), and `storage_instance` limits,
warning thresholds, `bootstrap_auto_pin_allowed` and `config_revision` (with
`storage_instance.volume_id` auto-pinned write-once from `NULL` via `storage_pin_volume_id`
strictly when `bootstrap_auto_pin_allowed = true` on a fresh `applied == 0` bootstrap with an
empty storage ledger under `storage_instance FOR UPDATE`, or pinned via `openmettle_owner`
idempotent verified volume adoption on every storage-enabled upgrade **only after mandatory
pre-migration `N-1` cleaner quiescence and 100% `N-1 -> N` replacement confirm zero `N-1` worker
processes remain running**, while storage-disabled installations with both `ARTIFACTS_DIR` env
vars unset and empty storage tables leave `volume_id IS NULL` and `bootstrap_auto_pin_allowed =
false`). `openmettle_issuance` receives zero quota or storage privileges. No runtime role receives
`DELETE`, `TRUNCATE`, DDL or grant options.

**Rolling-upgrade safety (ADR 0003).** Mixed-version deployments running `N-1` API/worker binaries
against the V1-17 PR2 schema are protected across three fail-closed database and rollout gates:

1. **Deployment-history fresh-install detection and mandatory gateway metering activation
   (`openmettle.bootstrap_from_zero` + `quota_enforcement.metering_enforced` +
   `quota_enforce_gateway_handoff_holds` + `quota_gateway_handoffs` +
   `quota_ensure_legacy_run_holds`, `OMQ04`).** Because frozen Migration `0023` grants `EXECUTE`
   on `openmettle.gateway_handoff` to `openmettle_api` and `openmettle_worker`, an `N-1` binary
   can still commit `gateway_handoff` with zero `quota_reservations` rows — including on an
   existing deployment upgraded from `0023 -> 0024` that has never used gateway or artifacts yet
   (empty `gateway_*` and `storage_*` tables while `N-1` pods are still live). To eliminate any
   false-fresh classification, PR2 updates `migrate_within_boundaries` in `src/migrate.rs` (which
   already holds SQLx's advisory lock and reads `applied = coalesce(max(version), 0)` from
   `openmettle._sqlx_migrations` before applying pending migrations) to execute
   `SELECT pg_catalog.set_config('openmettle.bootstrap_from_zero', CASE WHEN $1 = 0 THEN 'true'
   ELSE 'false' END, false)` (bound to `applied`, re-applied after each `RESET ALL` before every
   `migrator.run_to(version, ...)`) so `is_fresh_bootstrap` requires **both**
   `coalesce(pg_catalog.current_setting('openmettle.bootstrap_from_zero', true), 'false') = 'true'`
   AND empty core/storage/gateway tables (`users`, `scopes`, `projects`, `runs`,
   `storage_reservations`, `artifact_revisions`, `gateway_bindings`, `gateway_reservations`,
   `gateway_requests`). `quota_enforcement.metering_enforced` therefore seeds `true` **iff
   `is_fresh_bootstrap`**, and `false` on **every** upgrade (`applied >= 1`, even with 100% empty
   tables) so `N-1` API/worker pods finish draining during rolling deployment. When an `N` worker
   claims or reclaims an `N-1`-admitted run (which created `runs` + `gateway_reservations` with
   zero parent `quota_reservations` holds), `quota_unwind_superseded_round` cleanly unwinds any
   unbound `N-1` `'reserved'` round without requiring parent holds yet; then in the single
   round-allocation `WriteTransaction`, `quota_ensure_legacy_run_holds` runs **strictly BEFORE
   `authz::gateway::reserve_in(&mut tx, ...)`**, lazily initializing the run's parent hold(s)
   exactly once in canonical `runs` (`FOR NO KEY UPDATE`) -> `gateway_reservations` (`FOR NO KEY
   UPDATE`, reading Migration `0023`'s `units - allocated` with zero lock upgrade before
   `reserve_in`) -> `quota_budgets` (`FOR NO KEY UPDATE`) order, after which `reserve_in` runs and
   `quota_allocate_round` slices `slice_units <= parent.held_units` (enforcing `slice_units =
   q.units` for `usage_tokens`). Immediately once all `N-1` replicas are replaced by `N`,
   `openmettle_owner` (`openmettle-admin`) flips `metering_enforced` irreversibly `false -> true`
   in a **standalone single-statement transaction** holding zero other locks. Deferred `CONSTRAINT
   TRIGGER quota_enforce_gateway_handoff_holds` rejects any un-transitioned bound hold
   unconditionally (even while `false`), inserts the handoff receipt into
   `openmettle.quota_gateway_handoffs` **first** (`metering_enforced = false`), and then acquires
   `SELECT metering_enforced ... FROM openmettle.quota_enforcement WHERE id FOR SHARE` as the
   **final table/row lock** of the transaction (strictly serializing both commit orders against
   `openmettle_owner`'s `FOR NO KEY UPDATE` activation `UPDATE` under `READ COMMITTED` so no
   unmetered `0023` handoff can commit *after* activation). When `v_enforced = true`, it aborts
   any `0023`-only `gateway_handoff` lacking required `'handoff_committed'` holds (`usage_tokens`
   matching `qr.reserved_units = NEW.units AND qr.held_units = NEW.units AND qr.settled_units = 0
   AND qr.accepted_source_revision IS NULL` + ownership match, plus applicable `usage_cost_micros`
   with `qr.settled_units = 0 AND qr.accepted_source_revision IS NULL`) at `COMMIT` with `OMQ04`
   (rolling back both `gateway_requests` to `'reserved'` and the `quota_gateway_handoffs` insert)
   or marks the uncommitted receipt `metering_enforced = true` (zero additional table/FK locks) so
   post-activation `quota_recover_lost_handoff` still recognizes pre-activation unmetered handoffs
   and bound holds already transitioned to `'settled'` cleanly.
2. **Mandatory pre-migration `N-1` cleaner quiescence, deployment-history auto-pin gating, and
   verified three-directory adoption (`storage_instance.bootstrap_auto_pin_allowed`,
   `storage_reservations.adoption_unverified`, `enforce_worker_storage_volume_pinned()`, `OMQ03`).**
   On **every** upgrade (`applied >= 1`, including completely unused installations with empty
   `storage_*` tables), `storage_instance.bootstrap_auto_pin_allowed` seeds `false` and
   `storage_instance.volume_id` **MUST remain `NULL`** across the entire `N-1 -> N` binary
   replacement so no `N` replica can auto-pin the volume while `N-1` workers remain alive.
   Operators follow the mandatory four-step upgrade sequence:
   - **Step 1 (Mandatory — before migration):** Quiesce all `N-1` legacy artifact cleaners by
     unsetting `OPENMETTLE_WORKER_ARTIFACTS_DIR` across all `N-1` worker replicas (rolling restart
     with `OPENMETTLE_WORKER_ARTIFACTS_DIR` unset, or scaling `openmettle-worker` to `0`) and
     confirming zero `N-1` worker processes hold `OPENMETTLE_WORKER_ARTIFACTS_DIR` or have an
     in-flight `worker::maintenance` sweep. Because `N-1` `reconcile_expired` unlinks payload
     paths before calling `storage::release` and an already-`'purging'` revision passes
     `begin_purge` without an `UPDATE` so `N-1` `purge_due` unlinks the file before `confirm_purge`
     fires `OMQ03`, **`enforce_worker_storage_volume_pinned()` (`OMQ03`) is strictly a PostgreSQL
     ledger defense-in-depth backstop** (protecting DB byte accounting if an operator forgets
     quiescence on an empty replacement mount), **NOT a substitute for pre-migration `N-1`
     quiescence**. Disjoint `openmettle_api` in-flight upload abort cleanup continues unaffected
     while `volume_id IS NULL` via the guarded `artifact_fs::abort` protocol (locking
     `storage_reservations FOR UPDATE`, checking `state = 'reserved' AND NOT adoption_unverified`,
     verifying retained `(st_dev, st_ino)` across `(root_fd, staging_dir_fd, revisions_dir_fd)`,
     unlinking `staging/<id>` + `fsync(staging_dir_fd)`, and proving `revisions/<id>` `ENOENT`
     before `storage::release`).
   - **Step 2:** Run `openmettle-migrate` (`volume_id IS NULL`, `bootstrap_auto_pin_allowed =
     false`, `metering_enforced = false`).
   - **Step 3:** Roll 100% of `openmettle-api` and `openmettle-worker` replicas from `N-1` to `N`
     and confirm zero `N-1` replicas remain. `N` workers may already have
     `OPENMETTLE_WORKER_ARTIFACTS_DIR` configured during rollout because every `N` cleaner checks
     non-null pinned `volume_id` and all three role-tagged directory sentinels *before* touching
     any filesystem path, failing closed while `volume_id IS NULL`. All `N` `artifact_fs::Store`
     writers and readers execute strictly relative to verified `Arc`-shared `root_fd`,
     `staging_dir_fd`, and `revisions_dir_fd` (`Store::stage` opening `staging/<id>` with
     `OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW` + `Mode::RUSR | Mode::WUSR`
     and acquiring non-blocking shared `file.try_lock_shared()`), re-verifying `(st_dev, st_ino)`
     + role-tagged sentinels before `stage`, before `renameat`, **AND post-`renameat` /
     post-`fsync` / strictly before `tx.commit()` of `storage::settle`** (rolling back
     `storage::settle` without calling `storage::release` if any directory was displaced before
     commit, while live host directory replacement after that final pre-`commit` check is forbidden
     by operational contract and caught fail-closed by missing sentinels, `Error::Missing`,
     `verify_accounting_drift`, and adoption `OMQ03`).
   - **Step 4:** **Only after zero `N-1` workers remain**:
     - On **storage-disabled installations** (both `OPENMETTLE_API_ARTIFACTS_DIR` /
       `OPENMETTLE_ARTIFACTS_DIR` and `OPENMETTLE_WORKER_ARTIFACTS_DIR` unset per ADR 0031 AND `0`
       rows in both `storage_reservations` and `artifact_revisions`), skip volume adoption —
       leaving `storage_instance.volume_id IS NULL`, `bootstrap_auto_pin_allowed = false`, and all
       storage cleaners disabled — and proceed directly to `quota_release_orphan_gateway_requests`
       and flipping `quota_enforcement.metering_enforced = true`. If artifact storage is
       provisioned later, run `openmettle-admin` verified volume adoption before enabling
       `OPENMETTLE_WORKER_ARTIFACTS_DIR`.
     - On **storage-enabled installations** (any `ARTIFACTS_DIR` configured or any row in
       `storage_reservations` / `artifact_revisions`), operators run `openmettle-admin` verified
       volume adoption (Step 2 snapshot verification of revisions and every individual `'reserved'`
       payload, requiring **both** `--expected-fs-uuid <fs_uuid>` **AND**
       `--expected-revisions-inode <dev>:<ino>` whenever the ledger is non-empty with zero
       digest-bearing revisions verified on disk, and linking cleanly without those flags when an
       upgraded deployment's storage ledger is genuinely empty; Step 3 executing the locked
       per-reservation accounting classification, rollback-and-retry on newly committed `'reserved'`
       rows, and `UPDATE openmettle.storage_reservations SET adoption_unverified = true WHERE id =
       ANY(...) AND state = 'reserved' AND NOT adoption_unverified` in the **common locked path on
       BOTH initial unpinned adoption (`volume_id IS NULL`) AND every already-pinned (`volume_id IS
       NOT NULL`) retry** under `storage_reservations WHERE state = 'reserved' ORDER BY id ASC FOR
       UPDATE` -> `openmettle.storage_instance FOR UPDATE` strictly before any sentinel write or
       stale `.tmp.*` cleanup — on already-pinned `volume_id IS NOT NULL`, **never writing any
       missing sentinel**, re-querying `artifact_revisions.state` in a fresh `READ COMMITTED`
       `SELECT` if a previously `'retained'` revision returns `ENOENT` due to concurrent
       `begin_purge`, and strictly verifying all three existing sentinels match
       `storage_instance.volume_id` via `OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK` +
       `fstat` `S_ISREG`; on unpinned `volume_id IS NULL`, re-verifying ledger emptiness under lock,
       adopting any winning `<root>/.openmettle-volume-id` UUID on `EEXIST`, publishing `(root_fd,
       "root")` via unique `.openmettle-volume-id.tmp.<128bit_hex>` -> `fsync` -> `linkat` ->
       own-`tmp_name` `unlinkat` and **calling `fsync(root_fd)` strictly BEFORE creating/linking
       either `:revisions` or `:staging`**, then publishing `:revisions` and `:staging` + calling
       `fsync(revisions_dir_fd)` and `fsync(staging_dir_fd)` before updating
       `storage_instance.volume_id`), enabling all PR2 (`N`) worker cleaners
       (`artifact_fs::purge_due` — unconditionally calling `fsync(revisions_dir_fd)` strictly
       before `storage::confirm_purge` including on `ENOENT` — `reconcile_expired` with post-rename
       `revisions_dir_fd` `ENOENT` preservation, generic run-linked `ENOENT` recovery excluding
       `idempotency_key LIKE 'tool-spill:%'` so ADR 0039 `reconcile_run_spills` remains the single
       cleanup owner for `tool-spill:*`, and `StagingSweepState` `staging/` cleanup acquiring
       non-blocking `LOCK_EX` + `(st_dev, st_ino)` re-verify + `st_mtime > 900 s` and
       `storage_instance FOR UPDATE` serialized zero-row rechecks), which verify non-null pinned
       `volume_id`, equal `st_dev`, and all three role-tagged sentinels via `openat(...,
       OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK)` + `fstat` `S_ISREG` (bounded `<=
       64`-byte read) before every `statat` / `unlinkat` or DB transition, exclude
       `adoption_unverified = true` rows, and page via two-step raw-index-key scans over
       plain-column partial indexes; then run the gateway orphan sweep and flip `metering_enforced
       = true`.
   - **Starting, rolling back to, or resuming any `N-1` worker binary after
     `storage_instance.volume_id` is pinned is strictly forbidden by the rollout contract**,
     because `N-1` lacks Rust `.openmettle-volume-id` / `st_dev` checks and unlinks files before
     mutating PostgreSQL.
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
   (leaving it `NULL`) and `storage_reservations.adoption_unverified` (defaulting `false`).

## Authenticated visibility and refusal contract

PR3 exposes authenticated `/v1` routes following every [ADR 0007](0007-application-api-contract.md)
rule: `browserSession` (with configured `Origin` on writes) or `nativeSession`,
`OpenMettle-API-Version: 1.<minor>`, `Cache-Control: no-store`, canonical UUIDs, RFC 3339 UTC
`Timestamp`, `NonNegativeDecimal` (for `bigint` fields) and `WideNonNegativeDecimal` (for
`numeric(38, 0)` counters), closed request schemas and extensible responses.

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
  `warn_thresholds`, `status`, `authoritative_source`, `last_reconciled_at`). Because
  `quota_budgets.active_used`, `quota_budgets.reserved_held`, `quota_reservations.settled_units`,
  `openmettle.gateway_settlements.measured` (widened to `numeric(38, 0)` in PR2's migration), and
  `quota_reconciliations` deltas are exact PostgreSQL `numeric(38, 0)` integers (mapped in Rust
  via `sqlx` `::text` <-> `u128` / `i128` with zero new crates) whereas existing
  [`contracts/openapi/openmettle-v1.json`](../../contracts/openapi/openmettle-v1.json) caps
  `NonNegativeDecimal` at `19` characters / `9223372036854775807` (`i64::MAX`), PR3 leaves
  `NonNegativeDecimal` (`0..=9223372036854775807`) **untouched** for all `bigint` fields
  (`hard_limit`, `effective_limit`, `limit`, `remaining`, storage byte counters, etc.) and defines
  a dedicated **`WideNonNegativeDecimal`** schema in `contracts/openapi/openmettle-v1.json`
  (`type: "string"`, `minLength: 1`, `maxLength: 38`, `pattern: "^(?:0|[1-9][0-9]{0,37})$"`,
  canonical base-10 integer from `0` to `10^38 - 1` without sign, leading zeros, exponent, or
  fraction) for `QuotaSummary`'s wide `numeric(38, 0)` counters (`usage[].active_used`,
  `usage[].reserved_held`, and `device_capacity.active_reservations.reserved_held`) so JavaScript
  and Dart clients and OpenAPI schema validators never lose precision or reject valid values even
  when a 3-column token sum or multi-report overage aggregate exceeds `2^53 - 1` or `bigint` max
  (`9,223,372,036,854,775,807`). A project query returns only the project's own budget items,
  never another member's personal usage.
- `execution`: `live_runs_per_scope` (`current`, `limit`, `limit_source`),
  `executing_runs_per_scope` (`current`, `limit`, `limit_source`), `round_cap` (`limit`,
  `limit_source`), plus `live_runs_per_actor` and `executing_runs_per_actor` on `personal`
  summaries.
- `device_capacity`: `active_reservations` (`reserved_held` as `WideNonNegativeDecimal`, `limit`,
  `limit_source`, `warn_thresholds`, `status`), distinct from V1-18 physical VRAM telemetry.
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
| PR2 · schema, store and worker recovery | Additive PostgreSQL 18 migration (after Migration `0023`, zero edits to frozen `0023`), including `ALTER TABLE openmettle.gateway_settlements ALTER COLUMN measured TYPE numeric(38, 0)` (preserving `CHECK (measured >= 0)` and nullable `measured = NULL` for cost-only reports so 3-column token sums up to `3 * (2^63 - 1)` never overflow `bigint`), `rustix` minimal safe POSIX `dirfd` dependency (`default-features = false, features = ["fs", "std"]`, `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`; `Cargo.lock` distribution-blocker count updated per ADR 0007/0010 so all `openat`/`fstat`/`statat`/`renameat`/`linkat`/`unlinkat`/`fsync` calls using verified `rustix 1.1.6` `OFlags::CREATE` / `OFlags::RDONLY` / `OFlags::RDWR` / `OFlags::EXCL` / `OFlags::DIRECTORY` / `OFlags::NOFOLLOW` / `OFlags::NONBLOCK`, `AtFlags::SYMLINK_NOFOLLOW`, `AtFlags::empty()`, and `Mode::RUSR \| Mode::WUSR` compile safely under `Cargo.toml`'s `unsafe_code = "forbid"` on Rust 1.100), `src/migrate.rs` (`migrate_within_boundaries` capturing `applied = coalesce(max(version), 0)` once under SQLx's advisory lock and setting `openmettle.bootstrap_from_zero` via `pg_catalog.set_config` after each `RESET ALL` before every `migrator.run_to(version, ...)`), `storage_instance.volume_id` and `storage_instance.bootstrap_auto_pin_allowed` (`CHECK (volume_id IS NULL OR NOT bootstrap_auto_pin_allowed)`, seeded `true` iff `is_fresh_bootstrap` — requiring both `openmettle.bootstrap_from_zero = 'true'` and empty core/storage/gateway tables — and `false` on every upgrade `applied >= 1`), `storage_reservations.adoption_unverified` (`boolean NOT NULL DEFAULT false CHECK (NOT adoption_unverified OR state IN ('reserved', 'released'))`, cleared `false` by `storage::settle`, excluded by all automatic worker `ENOENT` cleaners and `artifact_fs::abort`), 100% `IMMUTABLE` PostgreSQL 18 plain-column partial B-tree indexes for two-step raw-index-key stale-hold paging (`quota_reservations_held_expiry_idx`, `storage_reservations_run_expiry_idx` and `storage_reservations_run_legacy_expiry_idx` both excluding `idempotency_key LIKE 'tool-spill:%'` so ADR 0039 `reconcile_run_spills` is the single automatic cleanup owner for `tool-spill:*`, `storage_reservations_upload_expiry_idx`, `storage_reservations_upload_legacy_expiry_idx`), strengthened `quota_reservations` state `CHECK` constraints prohibiting `settled_units > 0` or `accepted_source_revision IS NOT NULL` while `state = 'held'` or unaccepted `handoff_committed`, exact `numeric(38, 0)` aggregate and settlement accumulators (`quota_budgets.active_used`, `quota_budgets.reserved_held`, `quota_reservations.settled_units`, `quota_reconciliations.cumulative_units`, `delta_active`, `delta_reserved`, mapped in Rust via `sqlx` `::text` <-> `u128`/`i128` with zero new crates), `quota_enforcement` singleton control table (`metering_enforced`, write-once `false -> true`, seeded `true` iff `is_fresh_bootstrap` and `false` on every upgrade `applied >= 1`), `quota_gateway_handoffs` handoff-time obligation ledger (`gateway_request_id` PK referencing `gateway_requests(id) ON DELETE CASCADE`, `metering_enforced`, `cost_required`, `committed_at`, zero direct DML grants to runtime roles), `quota_reservations.allocating_claim_token` (`CHECK (parent_reservation_id IS NULL OR allocating_claim_token IS NOT NULL)`), seeded strictly-`UPDATE`-only `('instance', 'usage_cost_micros')` default row and `quota_cost_unit_lock`, scope-pinned composite FK `(scope_id, gateway_request_id) REFERENCES openmettle.gateway_requests (scope_id, id)`, `SECURITY DEFINER` transition, bootstrap, override, recovery and drift functions (`storage_pin_volume_id`, `quota_upsert_scope_override`, `quota_revoke_scope_override`, `quota_reserve` and `quota_allocate_round` enforcing exact `usage_tokens` hold equality `reserved_units = q.units` / `slice_units = q.units` (`23514`), `quota_ensure_legacy_run_holds` — running strictly before `authz::gateway::reserve_in` in the round-allocation `WriteTransaction` while locking `gateway_reservations FOR NO KEY UPDATE` and reading `units - allocated` — `quota_commit_handoff`, `quota_recover_lost_handoff`, `quota_commit_device_handoff`, `quota_renew_lease`, `quota_release_unsent`, `quota_unwind_superseded_round`, `quota_release_orphan_gateway_requests`, `quota_settle_gateway_usage` locking `gateway_requests FOR KEY SHARE` -> `gateway_settlements gs FOR NO KEY UPDATE` before `quota_reservations` to require `gs.request_id = qr.gateway_request_id AND gs.revision = p_source_revision AND gs.final = r.final` and applying strict per-resource authoritative evidence rules for `usage_cost_micros` (`r.cost IS NOT NULL`, `C_cost = ceil(r.cost)::numeric(38, 0)`) and `usage_tokens` (skipping all-`NULL` unknown tokens, applying partial/incomplete tokens only while `handoff_committed`, closing/correcting only on `r.final = true AND prompt_tokens IS NOT NULL AND completion_tokens IS NOT NULL`), `quota_release_device_slot`, `quota_record_storage_warning`, `quota_verify_accounting_drift` applying the same `gateway_settlements` coupling and per-resource authoritative evidence rules over `numeric(38, 0)` without `bigint` overflow), `enforce_storage_override`, `quota_enforcement_write_once` (`OMQ04`), `SECURITY DEFINER` `DEFERRABLE INITIALLY DEFERRED` `CONSTRAINT TRIGGER quota_enforce_gateway_handoff_holds` (`openmettle.enforce_gateway_handoff_holds()`, inserting into `openmettle.quota_gateway_handoffs` first and then locking `openmettle.quota_enforcement WHERE id FOR SHARE` as the final lock and requiring exact `usage_tokens` `qr.reserved_units = NEW.units AND qr.held_units = NEW.units AND qr.settled_units = 0 AND qr.accepted_source_revision IS NULL` + ownership match, plus `qr.settled_units = 0 AND qr.accepted_source_revision IS NULL` on `usage_cost_micros`, `OMQ04`), `SECURITY DEFINER` `BEFORE UPDATE` PostgreSQL ledger defense-in-depth backstop `enforce_worker_storage_volume_pinned` triggers on `storage_reservations` and `artifact_revisions` (`OMQ03`), `SECURITY DEFINER` `BEFORE INSERT OR UPDATE` `enforce_quota_reservation_gateway_binding` (enforcing `reserved_units = req.units`, pre-settlement `settled_units = 0 AND accepted_source_revision IS NULL AND held_units = req.units`, and partially-settled `held_units = greatest(0, req.units - settled_units)` backed by `gateway_settlements` with `23514`), `BEFORE INSERT OR UPDATE OR DELETE` `enforce_cost_denomination_immutability` and `SECURITY DEFINER` `BEFORE INSERT` `enforce_gateway_report_cost_unit` triggers, versioned `src/boundaries.sql` entries, `authz::gateway::{reserve_in, handoff_in, release_in}` in-transaction helpers, `src/quotas.rs` store, `storage::reserve` override integration, `artifact_fs::Store` retaining `Arc`-shared verified directory descriptors (`root_fd`, `staging_dir_fd`, `revisions_dir_fd`) across ALL writer/reader/cleaner operations (`Store::stage` creating `staging/<id>` via `openat` `OFlags::RDWR \| OFlags::CREATE \| OFlags::EXCL \| OFlags::NOFOLLOW` + `Mode::RUSR \| Mode::WUSR` -> `File::from(owned_fd)` -> non-blocking `file.try_lock_shared()` (`LOCK_SH \| LOCK_NB`), `renameat` publication + `fsync`, guarded `artifact_fs::abort` locking `storage_reservations FOR UPDATE` + verifying `state = 'reserved' AND NOT adoption_unverified` + verifying `(root_fd, staging_dir_fd, revisions_dir_fd)` identity + `unlinkat` `staging/<id>` + `fsync(staging_dir_fd)` + proving `statat(revisions_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` `ENOENT` before calling `storage::release`, `Store::read`, and cleaners — never resolving `<root>/staging` or `<root>/revisions` via `std::fs`) with `(st_dev, st_ino)` + role-tagged sentinel re-verification before `stage`, before `renameat`, **AND post-`renameat` / post-`fsync` / strictly before `tx.commit()` of `storage::settle`** (rolling back `storage::settle` without calling `storage::release` on displacement, and fail-closed detection/operator recovery for post-check live host directory replacement), `Store::open` fresh-bootstrap-only (`bootstrap_auto_pin_allowed = true` + empty ledger) three-directory role-tagged volume sentinel pinning (`<root>/.openmettle-volume-id` `:root`, `<root>/revisions/.openmettle-volume-id` `:revisions`, `<root>/staging/.openmettle-volume-id` `:staging`) locking `openmettle.storage_instance FOR UPDATE` **strictly before** any sentinel write or stale `.tmp.*` cleanup (never writing sentinels when `volume_id IS NOT NULL`, adopting winning `:root` UUID on `EEXIST`, publishing `(root_fd, "root")` via unique `.openmettle-volume-id.tmp.<128bit_random_hex>` -> `fsync` -> `linkat` -> own-`tmp_name` `unlinkat` + **mandatory `fsync(root_fd)` strictly BEFORE creating/linking either child sentinel**, then publishing `:revisions` / `:staging` + `fsync(revisions_dir_fd)` / `fsync(staging_dir_fd)` before updating `storage_instance.volume_id`, with stale `st_mtime > 300 s` cleanup only under lock), verified three-directory sentinel (`openat(..., OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK)` + `fstat` `S_ISREG`, exact `st_dev`, bounded `<= 64`-byte read) + open-FD (`statat`/`unlinkat`) gating across all worker artifact cleaners (`artifact_fs::purge_due` — unconditionally calling `fsync(revisions_dir_fd)` strictly before `storage::confirm_purge` including on `ENOENT` — `reconcile_expired` explicitly updating ADR 0031's post-rename behavior and `tests/schema/artifact_fs.rs`'s `renamed` test case to enforce directory-relative `revisions_dir_fd` `ENOENT` proof and preserve post-rename `revisions/<id>` + `reserved_bytes` while advancing cursor, generic run-linked `ENOENT` recovery excluding `idempotency_key LIKE 'tool-spill:%'`, and `StagingSweepState` `staging/` sweep acquiring non-blocking `LOCK_EX` + `(st_dev, st_ino)` re-verify + `st_mtime > 900 s` and `storage_instance FOR UPDATE` serialized zero-row rechecks), idempotent `purging`-tolerant `openmettle-admin` verified volume adoption CLI procedure (running Step 2 snapshot verification unconditionally, executing locked per-reservation accounting classification, rollback-and-retry on newly committed `'reserved'` rows, and `UPDATE openmettle.storage_reservations SET adoption_unverified = true WHERE id = ANY(...) AND state = 'reserved' AND NOT adoption_unverified` in the **common locked path on BOTH initial unpinned adoption (`volume_id IS NULL`) AND every already-pinned (`volume_id IS NOT NULL`) retry** under `storage_reservations WHERE state = 'reserved' ORDER BY id ASC FOR UPDATE` -> `storage_instance FOR UPDATE` strictly before any sentinel write or stale `.tmp.*` cleanup — on already-pinned `volume_id IS NOT NULL` verifying all three existing sentinels match `storage_instance.volume_id` without writing any missing sentinel and re-querying `artifact_revisions.state` in a fresh `READ COMMITTED` `SELECT` if a previously `'retained'` revision returns `ENOENT` due to concurrent `begin_purge`, and on unpinned `volume_id IS NULL` re-verifying ledger emptiness under lock, adopting any winning `:root` UUID on `EEXIST`, publishing `(root_fd, "root")` + `fsync(root_fd)` strictly before child sentinels, publishing `:revisions`/`:staging` + directory `fsync`s before updating `volume_id`, requiring **both** `--expected-fs-uuid <fs_uuid>` **AND** `--expected-revisions-inode <dev>:<ino>` — plus `--confirm-no-on-disk-payloads` when genuinely payload-empty — whenever a non-empty storage ledger has zero digest-bearing revisions verified on disk, and linking cleanly without those flags on upgraded deployments with an empty storage ledger) and operator runbook update mandating the four-step upgrade sequence (Step 1 mandatory pre-migration `N-1` worker cleaner quiescence + draining in-flight `worker::maintenance` sweeps, documenting `OMQ03` strictly as a PostgreSQL ledger defense-in-depth backstop rather than a substitute for quiescence; Step 2 `openmettle-migrate`; Step 3 100% `N-1 -> N` worker and API replacement with `storage_instance.volume_id IS NULL`; Step 4 verified adoption on storage-enabled installations — or skipping adoption cleanly on storage-disabled installations with both `OPENMETTLE_API_ARTIFACTS_DIR` / `OPENMETTLE_ARTIFACTS_DIR` and `OPENMETTLE_WORKER_ARTIFACTS_DIR` unset and empty `storage_reservations`/`artifact_revisions` — followed by gateway orphan sweep + standalone single-statement `metering_enforced = true` activation, forbidding `N-1` start/resume after pinning), `claim_next` executing-cap override evaluation, DB-plus-filesystem `verify_accounting_drift` (cleanly skipping filesystem sentinel checks when `ARTIFACTS_DIR` is unset, `volume_id IS NULL`, and both storage tables are empty, while failing hard when `ARTIFACTS_DIR` is configured or any storage row exists with `volume_id IS NULL`), bounded two-step raw-index-key paging (`<= batch_size` / `p_page_size`, zero joins/`EXISTS`/`clock_timestamp()` before `LIMIT`) across `quota_release_orphan_gateway_requests` (with once-captured constant `v_age_cutoff` clamped via valid PostgreSQL 18 scalar `IF` assignments), `quota_reservations`, run-linked `storage_reservations` (excluding `tool-spill:*`), and non-run `reconcile_expired`, and `SKIP LOCKED` one-per-tx `reconcile_stale_quotas` with persistent 5-state `StagingSweepState` (`Idle`/`Open`/`InFlight`/`InvalidatedInFlight`/`DrainingEof` + `pending_names: VecDeque<String>`) retaining an open verified `dir_fd` across `Open`, `InFlight`, and `DrainingEof` until `pending_names` is empty and held outside `worker::sweep`'s 15 s `tokio::time::timeout` in `src/worker.rs`. | PostgreSQL 18 tests in `tests/schema/grants.rs`, `tests/schema/artifact_fs.rs`, and `tests/schema/quotas.rs` executing all override, reservation, legacy-run-hold-backfill, device-handoff, lost-handoff-recovery, superseded-round-unwind, orphan-gateway-sweep, gateway-settlement, drift-verification and stale-sweep paths **connected as the actual runtime roles** (`openmettle_api`, `openmettle_worker`, `openmettle_gateway`, `openmettle_issuance`) and asserting denial of direct `INSERT`/`UPDATE`/`DELETE`/`SELECT ... FOR NO KEY UPDATE` on all `quota_*` tables (plus zero privileges on `quota_cost_unit_lock` and `quota_gateway_handoffs`, `SELECT`-only on `quota_enforcement`, `storage_instance.volume_id`, and `storage_instance.bootstrap_auto_pin_allowed`), denial of direct `SELECT` by `openmettle_api` and `openmettle_worker` on `openmettle.gateway_requests` and `openmettle.gateway_usage_reports` while qualifying `openmettle.quota_verify_accounting_drift()`, `openmettle.quota_ensure_legacy_run_holds(...)`, `openmettle.quota_unwind_superseded_round(...)` and `openmettle.quota_release_orphan_gateway_requests(...)` as `openmettle_worker` (and denying `EXECUTE` to `openmettle_api`, `openmettle_gateway` and `openmettle_issuance`) and qualifying `openmettle.quota_recover_lost_handoff(...)` as `openmettle_api` (`p_run_id IS NULL`) and `openmettle_worker` (`p_run_id IS NOT NULL`) while denying `openmettle_gateway` and `openmettle_issuance`, denial of `openmettle_api` calling either `quota_commit_handoff` or `quota_commit_device_handoff` on a run-linked `device_reservations` hold, denial of `openmettle_worker` calling generic `quota_commit_handoff` on a run-linked `device_reservations` hold, and denial of cross-role/unleased calls; N-way concurrent admission non-oversubscription across distinct project/actor/instance windows; non-windowed `device_reservations` surviving UTC rollover and `api`-admitted run device handoff exclusively via `quota_commit_device_handoff` under active `claim_token` lease (plus refusal for wrong resource kind or stale/unleased/cancelled run); cross-scope lock-order race with zero deadlocks; concurrent `executing_runs_per_actor` / `executing_runs_per_scope` cap lowering racing `claim_next` (and approval resume) serialized on `run_dispatch_lock` with zero overshoot; exact-once reconciliation across exact replay (recovering server-chosen windows), unique `(gateway_request_id, resource_kind)` enforcement rejecting duplicate keys, scope-pinned composite FK `(scope_id, gateway_request_id) REFERENCES openmettle.gateway_requests (scope_id, id)` and Migration `0023` composite FKs to `gateway_usage_reports` (`(request_id, revision)` and `(source, report_id, revision)`), **single-transaction atomic `authz::gateway::reserve_in` + `quota_reserve` / `quota_allocate_round` rollback test proving that when any metered quota hold fails or the transaction aborts before commit, neither `gateway_requests`, `gateway_reservations.allocated`, nor `quota_reservations` persists (and `gateway_requests_run_round_active_idx` is not stranded)**, **exact `usage_tokens` hold-size equality and pre-handoff `settled_units > 0` schema guard tests exercising mismatched amounts (`<` and `>` `gateway_requests.units`) on BOTH standalone (`run_id IS NULL`) and run-round (`run_id IS NOT NULL`) requests AND attempting `INSERT` and `UPDATE` in `state = 'held'` (and unaccepted `state = 'handoff_committed'` with `accepted_source_revision IS NULL`) with `settled_units > 0` and reduced `held_units`, proving deterministic rejection across `quota_reservations` `CHECK` constraints, `quota_reserve` / `quota_allocate_round` / `enforce_quota_reservation_gateway_binding` (`23514`), and `enforce_gateway_handoff_holds` (`OMQ04`)**, **deployment-history fresh-vs-upgrade seeding and `0023` rolling-upgrade activation tests across `openmettle.bootstrap_from_zero`, `quota_enforcement.metering_enforced`, and `storage_instance.bootstrap_auto_pin_allowed`: (a) fresh `applied == 0` bootstrap via `migrate_within_boundaries` auto-seeds `metering_enforced = true` and `bootstrap_auto_pin_allowed = true` (permitting `Store::open` auto-pinning once and clearing `bootstrap_auto_pin_allowed = false`); (b) an existing, completely unused `0001..0023` installation (`applied = 23`, zero rows in `users`, `scopes`, `projects`, `runs`, `storage_*`, and `gateway_*`) upgraded to `0024` via `migrate_within_boundaries` seeds `metering_enforced = false`, `bootstrap_auto_pin_allowed = false`, and `volume_id IS NULL`, proving legacy `0023` handoff succeeds during rollout, `N` startup (`Store::open` / `storage_pin_volume_id`) refuses to auto-pin (`OMQ03`), and post-replacement `openmettle-admin` adoption (cleanly linking all three role-tagged sentinels without `--expected-fs-uuid` / `--expected-revisions-inode` on the empty storage ledger) plus `metering_enforced = true` activation completes cleanly; (c) storage-disabled installation activation test (both `OPENMETTLE_API_ARTIFACTS_DIR` / `OPENMETTLE_ARTIFACTS_DIR` and `OPENMETTLE_WORKER_ARTIFACTS_DIR` unset and `0` rows in `storage_reservations` and `artifact_revisions`) proving Step 4 skips volume adoption cleanly (`volume_id IS NULL`, `bootstrap_auto_pin_allowed = false`, cleaners disabled), runs `quota_release_orphan_gateway_requests`, flips `metering_enforced = true`, and passes `verify_accounting_drift` (while `verify_accounting_drift` still fails hard whenever `ARTIFACTS_DIR` is configured or any storage row exists with `volume_id IS NULL`); (d) Step 1 pre-migration `N-1` `worker::maintenance` sweep-drain test proving an in-flight `N-1` sweep finishes cleanly before `openmettle-migrate` starts; (e) populated upgrades (including an existing `openmettle.gateway_reservations` row with zero `gateway_bindings`/`gateway_requests` rows) seed `false` so `N-1` `0023`-only handoff succeeds during rolling deploy and `quota_recover_lost_handoff` reports `'unmetered_legacy_handoff'` while suppressing HTTP dispatch, whereas any bound `'held'`/`'released'` quota hold still fails at `COMMIT` with `OMQ04`; flipping write-once `metering_enforced = true` as `openmettle_owner` in a standalone single-statement transaction — rejecting `true -> false` with `OMQ04` — causes `0023`-only handoffs to fail at `COMMIT` with `OMQ04` and roll back `gateway_requests` to `'reserved'`, requiring both bound `'handoff_committed'` `usage_tokens` (exact `reserved_units = NEW.units AND held_units = NEW.units AND settled_units = 0 AND accepted_source_revision IS NULL` + ownership match) and applicable `usage_cost_micros` holds (`settled_units = 0 AND accepted_source_revision IS NULL`); PLUS (f) a two-connection concurrency test covering both commit orders between an unmetered `0023` `gateway_handoff` commit (inserting `quota_gateway_handoffs` first and then locking `quota_enforcement FOR SHARE` as the final lock) and `openmettle_owner`'s `metering_enforced = true` activation (`FOR NO KEY UPDATE`), proving zero deadlock, strict lock-order serialization, and that an unmetered handoff can never observe `metering_enforced = false` and commit after activation**, **rolling-upgrade legacy-run reclaim and pre-`reserve_in` lazy parent-hold initialization test (`quota_unwind_superseded_round` -> `quota_ensure_legacy_run_holds` -> `authz::gateway::reserve_in` -> `quota_allocate_round`) where an `N-1` API replica admits a run (`runs` + `gateway_reservations` with `units = 100`, zero parent `quota_reservations`) and an `N-1` worker commits an unbound `'reserved'` round before crashing, and an `N` worker reclaims the run, cleanly unwinds the unbound legacy `'reserved'` round via `quota_unwind_superseded_round` (with zero parent `quota_reservations` present, freeing `gateway_requests_run_round_active_idx` and restoring `gateway_reservations.allocated = 0`), then inside the single round-allocation `WriteTransaction` executes `quota_ensure_legacy_run_holds` strictly BEFORE `authz::gateway::reserve_in` (locking `gateway_reservations FOR NO KEY UPDATE` with zero lock upgrade before `reserve_in` and reading `units - allocated = 100`, initializing the parent hold to `100`, enforcing `quota_budgets` hard limits with `OMQ01` when over budget and staying idempotent across retries and subsequent rounds), followed by a `60`-unit `reserve_in` + `quota_allocate_round` proving the child slices `60` without double-subtraction, `40` remains `held_units` on the parent, and settlement completes cleanly**, **fenced successor-worker unwind test (`openmettle.quota_unwind_superseded_round`) simulating worker process death immediately between `(reserve_in + quota_allocate_round)` commit and handoff, lease expiry + `leases::reclaim_next` by a successor worker, fenced unwind transitioning `gateway_requests` to `'released'`, restoring `gateway_reservations.allocated` and parent run `quota_reservations` capacity (`allocated_units`/`held_units`) while releasing child holds and freeing `gateway_requests_run_round_active_idx`, clean retry of the same round, and a replay test calling `quota_unwind_superseded_round` again with the same live `claim_token` after the successor worker has already unwound the predecessor and reserved the same `round` again (proving the successor's replacement `'reserved'` request and child holds carrying `allocating_claim_token = p_claim_token` remain intact and `false` is returned, plus `'handed_off'` left untouched returning `false`, and stale `claim_token` / non-worker calls refused)**, **pre-upgrade orphan `'reserved'` `gateway_requests` sweep test via `openmettle.quota_release_orphan_gateway_requests(...)` (using valid scalar PostgreSQL 18 `IF` upper-bound clamping) connected as `openmettle_worker` releasing aged unbound `'reserved'` rows while restoring `gateway_reservations.allocated`, freeing `gateway_requests_run_round_active_idx`, and skipping active leased runs or bound requests, PLUS (a) a bounded raw index-key paging test with a multi-page prefix of aged legitimately bound `'reserved'` requests ahead of a trailing orphan proving each call inspects at most `p_page_size` raw `(created_at, id)` keys from `gateway_requests_reserved_idx`, advances the persistent cursor across zero-orphan pages without exhausting sweep budget, and releases the trailing orphan on a subsequent page, and (b) a large all-young `'reserved'` tail test verifying bounded index buffer/key touches (`raw_keys_scanned = 0` past `v_age_cutoff`) with zero per-row `clock_timestamp()` filtering**, **negative binding and ownership-recheck tests proving cross-scope, cross-actor, cross-run, non-`'reserved'` state, or wrong-`p_dispatch`-secret bind attempts in `quota_reserve` / `quota_allocate_round` (and `quota_reservations_gateway_binding_guard`) are rejected and that `quota_release_unsent` ownership rechecks fail closed with an invariant error mutating neither ledger on mismatch**, run-to-round `held` allocation without double-debit coupled atomically with `authz::gateway::handoff_in` (`openmettle.gateway_handoff`) + `quota_commit_handoff` (rolling back both on pre-commit refusal), **lost commit acknowledgement (`UnknownCommit`) integration tests connected directly as unprivileged `openmettle_api` and `openmettle_worker` logins exercising all `openmettle.quota_recover_lost_handoff(...)` outcomes — `'handoff_committed'` (preserving durable `gateway_requests.state = 'handed_off'` + all required `'handoff_committed'`/`'settled'` quota holds recorded in `quota_gateway_handoffs`, including a test where `quota_settle_gateway_usage` has already moved bound holds to `'settled'` before recovery runs, asserting zero bound holds remain `'held'`/`'released'`, suppressing HTTP dispatch for gateway reconciliation), `'unmetered_legacy_handoff'` (including a pre-activation unmetered handoff committed while `metering_enforced = false` and recovered via `quota_recover_lost_handoff` *after* live `metering_enforced` flipped `true`, still returning `'unmetered_legacy_handoff'` with zero `OMQ04` and suppressing HTTP dispatch), and `'unwound_unsent'` (atomically unwinding `'reserved'`/`'released'` `gateway_requests`, restoring `gateway_reservations.allocated`, and releasing bound `'held'` holds to an active parent or `quota_budgets`) plus wrong-role/wrong-secret/mismatched-ownership/missing-required-hold (`OMQ04`) refusals**, pre-send unwind via `authz::gateway::release_in` (`openmettle.gateway_release`) + `quota_release_unsent` returning capacity to an active parent run hold (or releasing on terminal runs), **stale sweep atomically transitioning a stale `'reserved'` `gateway_requests` row to `'released'` and restoring `gateway_reservations.allocated` in the same `SECURITY DEFINER` transaction as releasing `quota_reservations` (proving a delayed `openmettle.gateway_handoff` with the original dispatch secret fails closed while `'handed_off'` rows remain untouched)**, cancellation, pre-send abort (with `closed_at`), valid `revision = 0` initial partial and final reports accepted when `accepted_source_revision IS NULL` (persisting `accepted_source_revision = 0` and rejecting subsequent `revision <= 0`), signed downward partial correction (`delta_reserved > 0`), **per-resource authoritative evidence settlement tests exercising (a) an explicit zero-token final report (`prompt_tokens = 0, completion_tokens = 0`) settling `usage_tokens` to `'settled'` (`settled_units = 0, held_units = 0`) and releasing the token hold, (b) a cost-only final report (`cost` present, `prompt_tokens`/`completion_tokens`/`reasoning_tokens` all `NULL`) settling `usage_cost_micros` to `'settled'` while keeping `usage_tokens` in `handoff_committed` with full `held_units` and last confirmed `settled_units` untouched (never turning `NULL` tokens into `0`), (c) a cost-only post-final correction updating `usage_cost_micros` without erasing `usage_tokens.settled_units` or altering `usage_tokens.accepted_source_revision`, (d) a token-only report (`r.cost IS NULL`) skipping `usage_cost_micros` completely, and (e) an incomplete final token report (`r.final = true` with `prompt_tokens` present and `completion_tokens IS NULL`) updating `usage_tokens` partial exposure while keeping `state = 'handoff_committed'`, all matching `quota_verify_accounting_drift()`**, **`gateway_settlements`-coupled rejection test reproducing `tests/schema/gateway.rs`'s `revision = 1 (partial) -> 2 (final) -> 3 (late partial stored in gateway_usage_reports, rejected by gateway_settlements) -> 4 (final correction)` against a lagging `handoff_committed` `quota_reservations` hold, proving `quota_settle_gateway_usage` rejects `revision = 3` without mutating balances while `revision = 2` and `revision = 4` settle cleanly (with zero deadlock between `gateway_requests FOR KEY SHARE -> gateway_settlements FOR NO KEY UPDATE` and Migration `0023`'s `gateway_mark_settled_final()`)**, **fractional `usage_cost_micros` cumulative `ceil(r.cost)::numeric(38, 0)` rounding and correction test across integer boundaries (`0.4 -> 0.8 -> 1.2` final -> `0.5` post-final correction -> `0`, proving `settled_units` / `active_used` track `1 -> 1 -> 2 -> 1 -> 0` with zero accumulated rounding drift and matching `quota_verify_accounting_drift()`)**, **`numeric(38, 0)` end-to-end oversized 3-column token and multi-report aggregate overflow test exercising BOTH multiple large overage reports AND a single oversized 3-column token report (`prompt_tokens + completion_tokens + reasoning_tokens > 9_223_372_036_854_775_807`) all the way through widened `openmettle.gateway_settlements.measured` (`numeric(38, 0)`), `quota_settle_gateway_usage`, `quota_verify_accounting_drift()`, Rust `u128`/`i128` decoding, subsequent `429 quota` refusal, and `/v1` `QuotaSummary` OpenAPI schema validation against `WideNonNegativeDecimal` (`^(?:0\|[1-9][0-9]{0,37})$`) without `22003` overflow or schema rejection**, `BEFORE INSERT OR UPDATE OR DELETE` `cost_denomination` immutability trigger (`OMQ02`, proving `INSERT` — including `INSERT ... ON CONFLICT DO UPDATE` — `DELETE`, and rename into/out of the seeded `('instance', 'usage_cost_micros')` row unconditionally fail with `OMQ02` without acquiring `quota_cost_unit_lock`, eliminating any AB/BA lock cycle) plus `BEFORE INSERT` `gateway_usage_reports_cost_unit_guard` serialized via `quota_cost_unit_lock` with **explicit concurrency tests covering both commit orders with different units (direct `UPDATE quota_defaults` vs `openmettle_gateway` `INSERT INTO gateway_usage_reports` with `cost IS NOT NULL`, plus two concurrent `gateway_usage_reports` inserts with different units while `cost_denomination IS NULL`)** and mismatch quarantine, final overage settlement plus subsequent refusal, upload abort and `confirm_purge`; override raise/lower/expiry and `hard_limit = 0` preserving data and deletion grace; `round_cap` `1..=1000` validation; **two-step raw-index-key paging tests across `quota_reservations`, run-linked `storage_reservations` (proving `idempotency_key LIKE 'tool-spill:%'` rows are excluded from both partial indexes and Step 2 under-lock release so ADR 0039 `reconcile_run_spills` remains the single cleanup owner), and non-run `reconcile_expired` exercising a full page containing ONLY ineligible expired holds (non-terminal runs, unresolved operations, or post-rename `revisions/<id>` files) followed by eligible holds on the next page, proving zero joins/`EXISTS`/`clock_timestamp()` before `LIMIT`, exact advancement of `last_attempted` across 100%-ineligible pages without wrapping prematurely, `FOR NO KEY UPDATE SKIP LOCKED` skipping contended rows without stalling, and release of eligible holds on the next page across `SWEEP_MS` ticks (60 s default interval, 15 s budget)**; **post-rename pre-settlement preservation tests across BOTH worker `reconcile_expired` (updating `tests/schema/artifact_fs.rs`'s `renamed` test case) AND API `artifact_fs::abort` (failed same-key HTTP upload retry creating `staging/<id>` and failing multipart/staging validation after a post-rename, pre-settlement crash left `revisions/<id>` on disk while `state = 'reserved'`), proving BOTH `reconcile_expired` and `artifact_fs::abort` lock `storage_reservations FOR UPDATE`, verify `NOT adoption_unverified` and `(root_fd, staging_dir_fd, revisions_dir_fd)` identity, unlink only `staging/<id>` + `fsync(staging_dir_fd)`, prove `statat(revisions_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` `ENOENT` before calling `storage::release`, and preserve BOTH `revisions/<id>` and `reserved_bytes` whenever `revisions/<id>` exists, `adoption_unverified = true`, or volume/directory verification fails**; **live `artifact_fs::Store` directory-descriptor binding and directory-replacement tests covering (a) replacing `<root>/revisions` between `Store::stage` and pre-`renameat` verification (failing closed with `Error::Io`, unlinking `<id>` from `staging_dir_fd` + `fsync(staging_dir_fd)`, and refusing `storage::release` with zero settled revision in PostgreSQL), (b) replacing `<root>/revisions` AFTER `renameat` + `fsync` and strictly BEFORE the post-`renameat` / pre-SQL-`commit` re-verification check (rolling back `storage::settle` with `Error::Io` without calling `storage::release`, keeping `reserved_bytes` charged), AND (c) replacing `<root>/revisions` AFTER the last successful pre-`commit` check (proving an un-sentineled replacement fails closed across `Store` and all cleaners, and even a sentinel-copied replacement deterministically surfaces `Error::Missing` on `Store::read`, `verify_accounting_drift` drift, and adoption `OMQ03` until the displaced payload is restored)**; **directory `fsync` durability barrier tests verifying (a) sentinel publication calls `fsync(root_fd)` strictly BEFORE creating/linking either `:revisions` or `:staging` (and `fsync(revisions_dir_fd)` / `fsync(staging_dir_fd)` before updating `storage_instance.volume_id`), and (b) `artifact_fs::purge_due` unconditionally calls `fsync(revisions_dir_fd)` strictly BEFORE `storage::confirm_purge` — explicitly including when `unlinkat(revisions_dir_fd, id, AtFlags::empty())` returns `ENOENT`**; **unpinned-volume DB-guard backstop and `N` cleaner pre-unlink safety tests covering (a) `enforce_worker_storage_volume_pinned` (`OMQ03`) exercising both `reconcile_expired` and `purge_due` DB transitions as `openmettle_worker` on an empty replacement mount while `storage_instance.volume_id IS NULL` (proving zero released `storage_reservations` and zero `purging`/`purged` transitions or byte-charge reductions while disjoint `openmettle_api` in-flight upload abort `storage::release` remains permitted under the guarded `artifact_fs::abort` protocol), AND (b) `N` cleaners (`purge_due`, `reconcile_expired`, run-linked `ENOENT` recovery, and `staging/` sweep) run against BOTH an existing on-disk payload and an empty replacement mount while `volume_id IS NULL` or when any directory sentinel is missing/mismatched (proving `N` cleaners verify non-null pinned `volume_id`, equal `st_dev`, and all three role-tagged sentinels *before* touching or unlinking any file, leaving existing on-disk payloads completely untouched and committing zero DB mutations)**; **post-pinning same-filesystem subdirectory-replacement test preserving valid `<root>/.openmettle-volume-id` (`:root`) and `<root>/staging/.openmettle-volume-id` (`:staging`) while replacing `<root>/revisions` with a fresh empty directory on the same filesystem (`st_dev`) — plus swapped `:root`/`:revisions`/`:staging` role sentinels — proving all `N` cleaners (`purge_due`, `reconcile_expired`, run-linked `ENOENT` recovery, and `staging/` sweep) fail closed with zero unlinks and retaining all holds/revisions**; **writerless FIFO (named pipe) `.openmettle-volume-id` sentinel test placing a writerless FIFO at `<root>/.openmettle-volume-id`, `<root>/revisions/.openmettle-volume-id`, or `<root>/staging/.openmettle-volume-id` and proving `Store::open`, `openmettle-admin` adoption, `verify_accounting_drift`, and all worker cleaners open with `OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + `fstat` (`S_ISREG`) and fail closed immediately without blocking**; **sentinel atomic `linkat` concurrency, crash/interruption, concurrent `begin_purge` retry, already-pinned `adoption_unverified` quarantine, and pre-sentinel lock tests covering (a) lost commit-ack adoption retry after replacing `<root>/revisions` on an empty ledger (proving Step 3 locks `storage_instance FOR UPDATE` first, observes `volume_id IS NOT NULL`, never writes a missing sentinel into the replacement `<root>/revisions`, and fails closed with `OMQ03`), (b) already-pinned (`volume_id IS NOT NULL`) adoption retry with an unflagged (`adoption_unverified = false`) unaccounted `'reserved'` row (plus a newly committed `'reserved'` row racing the pre-scan), proving the common locked path executes rollback-and-retry + `UPDATE storage_reservations SET adoption_unverified = true` even when `volume_id IS NOT NULL` and blocks BOTH worker and API `abort` `ENOENT` release, (c) concurrent `begin_purge` (`'retained' -> 'purging'` + unlink) during an already-pinned (`volume_id IS NOT NULL`) adoption retry (proving fresh `READ COMMITTED` re-query of `artifact_revisions.state` accepts `state IN ('purging', 'purged')` cleanly while failing closed with `OMQ03` if still `state IN ('active', 'retained')`), (d) `storage::reserve` committing between Step 2's empty-ledger check and Step 3's `storage_instance FOR UPDATE` on an empty replacement directory (proving Step 3 re-verifies ledger emptiness under `storage_instance FOR UPDATE`, rejects the stale empty-ledger waiver, writes zero sentinels, leaves `volume_id IS NULL`, and fails closed with `OMQ03`), (e) two concurrent fresh-bootstrap publishers (`Store::open`, `bootstrap_auto_pin_allowed = true`) starting simultaneously on an empty volume (proving both serialize cleanly on `storage_instance FOR UPDATE`, adopt any winning `:root` UUID on `EEXIST` without unlinking a live peer's `.tmp.<128bit_random_hex>`, and succeed with zero `OMQ03` / `EEXIST` failure or `.tmp.*` deletion race), (f) crash/interruption after temp-file creation or partial write (`.openmettle-volume-id.tmp.<128bit_random_hex>`) before `linkat` publication (proving own-`tmp_name` cleanup + stale `st_mtime > 300 s` cleanup under `storage_instance FOR UPDATE` leaves zero 0-byte `.openmettle-volume-id` corruption and publishes all three role-tagged sentinels cleanly), and (g) crash after linking a subset of the three directory sentinels (`<root>`, `<root>/revisions`, `<root>/staging`) while `volume_id IS NULL` before DB commit (proving retry locks `storage_instance FOR UPDATE`, re-verifies already-linked sentinels, adopts the winning `:root` `sentinel_uuid` on `EEXIST`, completes the remaining sentinels after `fsync(root_fd)`, and pins `storage_instance.volume_id` cleanly)**; **populated-upgrade and mixed-reservation volume-identity acceptance tests (upgrade a database containing pre-existing `artifact_revisions` and `storage_reservations` with `storage_instance.volume_id IS NULL`, start against an empty replacement directory where `Store::open` creates empty `staging/` and `revisions/`, proving `volume_id` stays `NULL`, `storage_pin_volume_id` refuses with `OMQ03`, no `.openmettle-volume-id` sentinel is written, zero reservations are released and zero files unlinked, verified volume adoption rejects the empty replacement mount and missing `active`/`retained` files, verified volume adoption succeeds on the real original volume including when a mid-purge `state = 'purging'` revision's file is already unlinked while retaining its byte charge until `purge_due` confirms `'purged'`, interrupting adoption after sentinel `fsync` and before DB commit allows operator retry to re-verify the volume unconditionally and pin `storage_instance.volume_id` idempotently with the existing sentinel UUID while rejecting mismatched DB `volume_id` with `OMQ03`; PLUS a mixed-reservation same-filesystem `revisions/` replacement test with `0` settled revisions and `2` `'reserved'` rows — `R1` present in `staging/`, `R2` renamed into original `revisions/` before `<root>/revisions` was replaced with a fresh empty directory on the same filesystem / unchanged `fs_uuid` — proving (i) first adoption fails closed immediately on `--expected-revisions-inode <dev>:<ino>` mismatch even though `R1` is on disk and `--expected-fs-uuid` matches, and (ii) on any adoption where an individual `'reserved'` row such as `R2` has neither `revisions/<id>` nor `staging/<id>` verified on disk, adoption sets `adoption_unverified = true` under `storage_reservations (asc id) FOR UPDATE -> storage_instance FOR UPDATE`, keeping `R2`'s `max_bytes` charged and excluding `R2` from `reconcile_expired`, run-linked `ENOENT` cleaners, AND `artifact_fs::abort` while `storage::settle` clears `adoption_unverified = false` on later retry settlement; PLUS a reservation-only populated ledger test with `1` post-rename `'reserved'` payload at `revisions/<id>` and `0` `artifact_revisions` rows proving adoption and retry — even with a stray `.openmettle-volume-id` — fail closed on empty replacement directories without pinning `volume_id`, and succeed on the real volume only with both `--expected-fs-uuid` and `--expected-revisions-inode`, plus `--confirm-no-on-disk-payloads` for genuinely payload-empty ledgers)**; run-linked storage recovery (excluding `tool-spill:*`) and `artifact_fs::purge_due` requiring configured `ARTIFACTS_DIR`, non-null pinned `storage_instance.volume_id` <-> all three role-tagged `.openmettle-volume-id` sentinels (`OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + `fstat` `S_ISREG`, `fsync`ed via `linkat` on fresh `bootstrap_auto_pin_allowed = true` empty-ledger bootstrap under `storage_instance FOR UPDATE` only; refusing fresh initialization once non-null or on upgrades) and exact `st_dev` match across open `<root>`, `revisions_dir_fd`, and `staging_dir_fd` before executing relative `statat`/`unlinkat` or committing `begin_purge` / `confirm_purge` / `storage::release` (preserving hold + payload when `revisions/<id>` exists while `state = 'reserved'`, excluding `adoption_unverified = true`, and **proving worker restart with an accessible empty replacement directory while `storage_instance.volume_id` is pinned — as well as missing, mismatched, wrong-role, symlinked, FIFO/non-regular, or different-`st_dev` sentinels — fails closed across both `reconcile_expired` and `purge_due` with zero released charges**), plus **persistent 5-state `StagingSweepState` `ReadDir` `staging/` cleanup tests covering (a) directory enumeration spanning multiple ticks (parking the open `dir_fd` + `ReadDir` stream, resuming from the parked offset without restarting from entry 0, and acquiring `LOCK_EX` -> `(st_dev, st_ino)` re-verify -> `set_len(0)` -> `unlinkat` -> `drop` -> `fsync` on a `released` staging file near the end of the directory), (b) a `LOCK_SH`-held active pre-commit `staging/<id>` file (including an ADR 0039 `tool-spill:*` writer) present during BOTH startup recovery AND periodic sweep (proving `try_lock()` `WouldBlock` and the `st_mtime > 900 s` grace window skip it untouched, and proving an aged zero-row orphan `staging/<id>` is unlinked ONLY after `st_mtime > 900 s`, non-blocking `LOCK_EX`, `(st_dev, st_ino)` re-verify, and a `storage_instance FOR UPDATE`-serialized `NOT EXISTS` check while still holding `LOCK_EX`), (c) a single `<= 64`-entry `spawn_blocking` `ReadDir` slice exceeding one tick's `worker::sweep` 15 s `tokio::time::timeout` deadline (proving Tick 1 times out cleanly without spawning duplicate `spawn_blocking` tasks while keeping `InFlight` and its open `dir_fd` parked in `StagingSweepState`, and Tick 2 re-verifies directory identity and consumes that completed slice's entries from `pending_names` exactly once), and (d) `<root>/staging` directory replacement during both windows — while `InFlight` is parked across ticks (`InvalidatedInFlight` awaits the handle to completion, discards its `ReadDir` and names, and starts no second reader until it transitions to `Idle`) and after an `eof = true` slice leaves undrained `pending_names` in `DrainingEof` across a tick boundary, explicitly removing the old `<root>/staging` directory and immediately creating a replacement `<root>/staging` directory on the same filesystem to exercise inode-reuse pressure (proving the retained open `dir_fd` prevents `dir_ino` reuse so `(cur_dev, cur_ino) == (dir_dev, dir_ino)` cannot match, zero entries are unlinked from the replacement directory, and `dir_fd` is dropped only when `StagingSweepState` transitions to `Idle`)**; restore verification (`verify_accounting_drift` + `openmettle.quota_verify_accounting_drift()`) recognizing `state = 'purging'` with missing `revisions/<id>` (`ENOENT`) as a valid resumable mid-purge state while cleanly skipping filesystem checks on storage-disabled installations (`ARTIFACTS_DIR` unset, `volume_id IS NULL`, `0` storage rows) and failing hard on `volume_id IS NULL` whenever `ARTIFACTS_DIR` is configured or any storage row exists, missing `active`/`retained` payloads, missing/mismatched/FIFO role-tagged sentinels in `<root>`, `<root>/revisions`, or `<root>/staging`, and DB/`0023` drift (including `numeric(38, 0)` `gateway_settlements.measured`, `usage_cost_micros` vs `ceil(r.cost)::numeric(38, 0)`, and `usage_tokens` vs `C_tokens` past `bigint` max with per-resource authoritative evidence matching); and populated previous-writer rolling-upgrade test with a lowered `storage_bytes` override proving fail-closed refusal (`OMQ01`) on old `storage::reserve` while `settle`/`release`/`retain`/`purge` succeed. |
| PR3 · `/v1` API, OpenAPI and wired enforcement | `/v1` quota read (with `warnings` projection) and `ManageQuotas` routes (gated on rolling-upgrade completion), OpenAPI 3.2.1 schemas (defining dedicated `WideNonNegativeDecimal` — `type: "string"`, `minLength: 1`, `maxLength: 38`, `pattern: "^(?:0\|[1-9][0-9]{0,37})$"` — for `QuotaSummary`'s wide `numeric(38, 0)` counters while keeping `NonNegativeDecimal` `0..=9223372036854775807` untouched for `bigint` fields) and regenerated `contracts/fixtures/`, independent consumer decoding, and wired quota enforcement in `src/v1/artifacts.rs`, `admit_run`, `claim_next` and ADR 0037 settlement paths. | Contract validation (`tests/contract.rs`, including OpenAPI validation of `QuotaSummary` counters `> 9223372036854775807` against `WideNonNegativeDecimal` while keeping `NonNegativeDecimal` `i64::MAX` bounds intact) and PostgreSQL 18 HTTP tests on both session channels covering effective limits/usage/reservations/warnings visibility, warning deduplication and re-arming on override/config edits, concurrent `/v1` `setQuotaOverride` lowering of `executing_runs_*` caps racing `claim_next`, `404` concealment for non-members and non-member admins, audited override changes and replay conflicts, safe `429 quota` / `429 rate_limited` / `503 provisioning` RFC 9457 problems with redaction canaries, and allowed reads, downloads, cancellations and deletions at hard limit. |

**Boundaries.** V1-15 (`#15`) and V1-16 (`#16`) own artifact payload transport, retention
policies and deletion journals. V1-06 (`#7`, ADR 0037) owns Migration `0023`, gateway admin
provisioning and authoritative usage feed ingestion. V1-14 (`#14`, ADR 0039) owns MCP tool
schemas, spill triggers, and exclusive automatic cleanup of `idempotency_key LIKE 'tool-spill:%'`
`storage_reservations` rows via `reconcile_run_spills` (sequenced on V1-17 PR2's `volume_id` /
`dirfd` foundation). V1-18 (`#18`) owns the active GPU controller, DRA claims and physical VRAM
handoffs. V1-29 (`#26`) owns telemetry contract updates when PR2/PR3 register quota metrics.
