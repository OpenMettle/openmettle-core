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
`unlinkat` and `fsync` operations compile safely with zero `unsafe` in `openmettle-core` (updating
the `Cargo.lock` distribution-blocker count per [ADR 0007](0007-application-api-contract.md) and
[ADR 0010](0010-provider-http-transport.md)).

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
| [ADR 0005](0005-artifact-storage-accounting.md), [`src/storage.rs`](../../src/storage.rs) | Keep `storage_instance`, `storage_accounts`, `storage_reservations` and `artifact_revisions` as the single storage ledger, adding `warn_pct_1`, `warn_pct_2`, and `config_revision` on `storage_instance`, **`purge_stage text NOT NULL DEFAULT 'none'`** on `artifact_revisions` (`CHECK (purge_stage IN ('none', 'anchor_pending_unlink') AND (purge_stage = 'none' OR state = 'purged'))`, backed by partial index `artifact_revisions_purge_anchor_idx` and `GRANT UPDATE (purge_stage) TO openmettle_worker`), plus a dedicated 1-row read-mostly control table **`openmettle.storage_volume_control (id, volume_id, bootstrap_auto_pin_allowed, adoption_run_id)`** with **ONLY `GRANT SELECT ON openmettle.storage_volume_control TO openmettle_api, openmettle_worker;`** (zero `INSERT`/`UPDATE`/`DELETE`/`TRUNCATE` for runtime roles, eliminating both PostgreSQL 18 `42501` `FOR SHARE` permission failures and direct pin rewrites as well as `storage_instance` `FOR SHARE` -> `FOR NO KEY UPDATE` deadlocks with `storage::adjust` in `src/storage.rs:289-310`). Expose narrow `openmettle_owner`-owned `SECURITY DEFINER` **`openmettle.storage_lock_pinned_volume() RETURNS uuid`** (executing `SELECT volume_id, adoption_run_id INTO v_vol, v_adopt FROM openmettle.storage_volume_control WHERE id FOR SHARE` and raising `OMQ03` on `NOT FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL`, granted `EXECUTE` to `openmettle_api, openmettle_worker`) and **`openmettle.storage_pin_volume_id(p_volume_id uuid) RETURNS uuid`** (granted `EXECUTE` to **`openmettle_api` ONLY** — `openmettle_worker` never initializes sentinels and never calls `storage_pin_volume_id(uuid)`, instead observing `OMQ03` / unpinned state via `storage_lock_pinned_volume()` without `42501` and failing closed until `openmettle_api` or `openmettle storage adopt` pins `volume_id`; internally acquiring `FOR UPDATE` on `storage_volume_control` as `openmettle_owner` so API `Store::open` never executes an invoker `FOR UPDATE`). Add per-scope overrides, fail-closed rolling-upgrade PostgreSQL ledger backstop triggers on `storage_accounts` (`OMQ01`), on `storage_reservations`/`artifact_revisions` for unpinned or adopting runtime releases/purges (**`SECURITY INVOKER`** `enforce_runtime_storage_volume_pinned()`, `OMQ03`, evaluating `NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')` across both `INHERIT` and `NOINHERIT`/`SET ROLE` logins and invoking `PERFORM openmettle.storage_lock_pinned_volume()` so in-flight `storage::release` strictly serializes with adoption Step 1b's `FOR UPDATE` on `storage_volume_control` with zero deadlock and zero `42501`), **`SECURITY INVOKER` `enforce_storage_reservation_monotonic_guards()`** (`OMQ03`, preventing any non-`openmettle_owner` role from clearing `adoption_unverified`, mutating or clearing non-null `payload_ino`, or clearing `stage_claimed`), `storage_reservations_tool_spill_binding_guard` (`23514`) enforcing `run_id IS NOT NULL AND operation_id IS NOT NULL` for all new/updated `tool-spill:*` rows, warning thresholds, reservation `lease_expires_at`, **`stage_claimed boolean NOT NULL DEFAULT false`** (`CHECK (payload_ino IS NULL OR stage_claimed)`), nullable **`payload_ino numeric(20, 0)`** (`CHECK (payload_ino IS NULL OR payload_ino >= 0)`, exact unsigned 64-bit `u64` `MetadataExt::ino()`, dropping host-local `payload_dev` because Linux NFS assigns client-local anonymous `st_dev` via `get_anon_bdev`; verified locally per host via `file_meta.dev() == dir_fd_meta.dev() == root_fd_meta.dev()` plus role-tagged sentinels and `file_meta.ino() == payload_ino`, write-once and **never** cleared to `NULL`, retained on `'settled'` and `'released'` rows, and backfilled by adoption Step 3 **strictly ONLY in the success branch onto positively verified non-quarantined** `'reserved'`, `'active'`/`'retained'`, and Case 6a surviving legacy `'purging'` rows — never onto any row remaining `adoption_unverified = true`), **`publish_pending`** (`CHECK (NOT publish_pending OR (state = 'reserved' AND payload_ino IS NOT NULL))`, committed `true` strictly before `linkat` publication and cleared `false` by `storage::settle` or on transition to `reclaim_state = 'truncated'`), unified 4-state cleaner lease **`reclaim_state text NOT NULL DEFAULT 'none' CHECK (reclaim_state IN ('none', 'claiming', 'truncated', 'anchor_pending_unlink'))`**, **`reclaim_claim_token uuid`**, **`reclaim_lease_until timestamptz`** (with partial index `storage_reservations_reclaim_anchor_idx` for bounded DB-driven Step 4 sweep across all reservation kinds, `CHECK ((state = 'reserved' AND reclaim_state IN ('none', 'claiming', 'truncated')) OR (state = 'released' AND reclaim_state IN ('none', 'anchor_pending_unlink')) OR (state = 'settled' AND reclaim_state = 'none'))`, `CHECK ((reclaim_state IN ('claiming', 'truncated') AND reclaim_claim_token IS NOT NULL AND reclaim_lease_until IS NOT NULL) OR (reclaim_state IN ('none', 'anchor_pending_unlink') AND reclaim_claim_token IS NULL AND reclaim_lease_until IS NULL))`, `CHECK (reclaim_state NOT IN ('truncated', 'anchor_pending_unlink') OR NOT publish_pending)`), tightened **`adoption_unverified` (`CHECK (NOT adoption_unverified OR state = 'reserved')`)** so combined with `enforce_storage_reservation_monotonic_guards()` **no non-owner role can EVER transition a quarantined `'reserved'` row to `'released'` or `'settled'`** (cleared **solely** by `openmettle_owner` reconciliation or verified `openmettle-admin` adoption), and DB-plus-filesystem drift verification (with concurrent `begin_purge` re-query, `staging/.reclaim.<id>` and `revisions/.purge.<id>` anchor recognition, Stage A `'purging'` crash-state recognition, and post-pinning `payload_ino IS NULL` hard failure). |
| [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md), [`src/artifact_fs.rs`](../../src/artifact_fs.rs) | Bind upload reservations (`run_id IS NULL`) to `lease_expires_at` within the 600 s upload timeout plus 300 s settlement margin. Retain `Arc`-shared verified directory descriptors (`root_fd`, `staging_dir_fd`, `revisions_dir_fd`: `OwnedFd` via `rustix::fs::openat` with `OFlags::RDONLY \| OFlags::DIRECTORY \| OFlags::NOFOLLOW`) across `artifact_fs::Store` and execute **all** writer, reader and cleaner operations strictly relative to those verified directory FDs. Enforce the **unified rollout rule**: HTTP `Store::stage` and `Store::publish` (`openmettle_api`) succeed when `storage_volume_control.adoption_run_id IS NULL` both when `volume_id IS NOT NULL` (locking via `SELECT openmettle.storage_lock_pinned_volume()` and verifying role-tagged sentinels) and during mixed-version rolling upgrade while `volume_id IS NULL` (non-locking `SELECT` confirming row present and `adoption_run_id IS NULL`, skipping sentinel reads while still setting `stage_claimed = true` and binding `payload_ino = staged_ino`), whereas ADR 0039 worker `publish_bytes` spills and all 4 cleaners strictly require `storage_volume_control.volume_id IS NOT NULL AND adoption_run_id IS NULL` via `openmettle.storage_lock_pinned_volume()`. `Store::stage` executes **Step 1a** (short lock-ordered `FOR UPDATE` tx + `storage_lock_pinned_volume()` when pinned or non-locking `SELECT` while `volume_id IS NULL` committing `SET stage_claimed = true` strictly BEFORE touching disk), **Step 1b** (re-verify directory FDs + sentinels when `volume_id IS NOT NULL`, `openat(&staging_dir_fd, id, OFlags::CREATE \| OFlags::EXCL \| OFlags::RDWR \| OFlags::NOFOLLOW)` `0` bytes -> `LOCK_SH` `try_lock_shared()` -> verify `file_meta` vs `statat` `S_ISREG` + local `st_dev` + `staged_ino = file_meta.ino()` -> **`fsync(&staging_dir_fd)`** crash-durable strictly BEFORE binding `payload_ino`), and **Step 1c** (short lock-ordered `FOR UPDATE` tx + `storage_lock_pinned_volume()` when pinned committing `SET payload_ino = staged_ino` where `state = 'reserved' AND NOT adoption_unverified AND stage_claimed AND payload_ino IS NULL AND reclaim_state = 'none'`). **`StagedFile::drop` (and all writer error/cancellation paths in `Store::stage`, `Store::publish`, and ADR 0039 `publish_bytes`) is 100% non-destructive — it NEVER calls `set_len(0)` and NEVER calls `unlinkat`, ONLY closing the file descriptor (releasing `LOCK_SH`/`LOCK_EX`)**; on ambiguous `storage::settle` commit, callers never call `artifact_fs::abort` blindly and first inspect `storage_reservations.state` under `(runs FOR NO KEY UPDATE ->) storage_reservations FOR UPDATE` (if `'settled'`, publication succeeded). `Store::publish` commits `SET publish_pending = true` under `FOR UPDATE` (`state = 'reserved' AND NOT adoption_unverified AND payload_ino = staged_ino AND reclaim_state = 'none'`) strictly before publishing exclusively via **`rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id, AtFlags::empty())`**, while ADR 0039 `publish_bytes` executes the synchronized **5-step sequence** (Step 1: create `0`-byte `staging/<id>` under continuous `LOCK_EX` -> `fsync(&staging_dir_fd)` -> bind write-once `stage_claimed = true, payload_ino = COALESCE(payload_ino, $3)` via `storage_lock_pinned_volume()` leaving `publish_pending = false`; Step 2: write payload + verify `actual_size == reserved_bytes` & SHA-256 + `file.sync_all()` under continuous `LOCK_EX`; Step 3: still holding `LOCK_EX`, re-stat `fd` + `statat` and execute `SELECT openmettle.storage_lock_pinned_volume(); UPDATE openmettle.storage_reservations SET publish_pending = true WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved' AND NOT adoption_unverified AND reclaim_state = 'none' AND payload_ino = $3 RETURNING id;` so adoption (`OMQ03`) or cleaner claim aborts strictly BEFORE `linkat`; Step 4: still holding `staged_fd` (`LOCK_EX`), execute `linkat` + `fsync(&revisions_dir_fd)` + post-`linkat` re-verify and **carry `staged_fd` (`LOCK_EX`) into Step 5** without dropping it; Step 5: execute a **single atomic `Fence::Step` `WriteTransaction` committing BOTH `storage::settle` (`state = 'settled', publish_pending = false`, retaining `payload_ino`) AND `runs::record_observation`**, dropping `staged_fd` (`LOCK_EX`) **only AFTER** that `Fence::Step` transaction commits, followed by post-commit best-effort `LOCK_SH` `unlinkat(&staging_dir_fd, id)` (`OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + immediate `is_file()`, without `set_len(0)`) + `fsync(&staging_dir_fd)`). `linkat` **atomically fails with `Errno::EXIST` (`EEXIST`) without overwriting any existing `revisions/<id>`** AND **keeps `staging/<id>` present on disk throughout the entire unsettled `state = 'reserved'` window** so any mixed-version same-key retry routed to an `N-1` API replica hits `OpenOptions::create_new(true)` -> `AlreadyExists` -> `Err(Error::InProgress)` (`src/artifact_fs.rs:474-475`) without staging or replacing `revisions/<id>`! **`Store::read`** joins `storage_reservations` (`storage::read_revision`) to load `(r.size_bytes, sr.payload_ino, sr.adoption_unverified)`, rejects `sr.adoption_unverified = true` (`Error::Io`), re-verifies `<root>` and `"revisions"` pathname-to-FD `(st_dev, st_ino)` (+ `:root`/`:revisions` sentinels when `volume_id IS NOT NULL`), opens `revisions/<reservation>` via `openat(&revisions_dir_fd, reservation, OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK, Mode::empty())` (`O_RDONLY` is valid for shared `LOCK_SH` / `F_RDLCK` on Linux NFS, and `O_NONBLOCK` prevents blocking indefinitely on writerless FIFOs), **immediately checks `file.metadata()?.file_type().is_file()`** (failing closed with `Err(Error::Missing)` on FIFOs/sockets/devices/directories without blocking!), acquires non-blocking **`file.try_lock_shared()`** (`LOCK_SH \| LOCK_NB`, returning `Err(Error::Missing)` on `WouldBlock`), **strictly AFTER acquiring `LOCK_SH`** re-verifies `file.metadata()?` (`is_file()`, `st_dev == store.root_dev`, `st_ino == sr.payload_ino` whenever non-null, `len() == expected_size`) and `statat(&revisions_dir_fd, reservation, AtFlags::SYMLINK_NOFOLLOW)` namespace identity, seeks to `start`, and **retains that locked `fs::File` inside `Content` for the entire streaming response body lifetime** so `purge_due` Stage A (`LOCK_EX \| LOCK_NB`) receives `WouldBlock` and never truncates an in-flight download (allowing `sr.payload_ino IS NULL` **ONLY** during pre-adoption rolling upgrade while `volume_id IS NULL AND adoption_run_id IS NULL`, failing closed `Error::Io` once `volume_id IS NOT NULL`). Enforce **one unified 4-step reclamation protocol with fenced Step 2a lease revalidation under `LOCK_EX`, `staging/.reclaim.<id>` link anchor, and bounded DB-driven Step 4 sweep** across all 4 cleaners (`artifact_fs::abort`, non-run `reconcile_expired`, generic run-linked recovery, and ADR 0039 `reconcile_run_spills`) with **ZERO filesystem I/O inside Step 1 or Step 3 DB transactions** (and **every `LOCK_EX` descriptor opened with `OFlags::RDWR \| OFlags::NOFOLLOW` explicitly WITHOUT `OFlags::TRUNC`** because Linux NFS maps `flock(LOCK_EX)` to `fcntl(F_SETLK, F_WRLCK)` and returns `EBADF` on `O_RDONLY`!) so **`payload_ino` NEVER drops to `nlink = 0` before Step 3 commits**: **Step 1** serialized DB claim under `(runs FOR NO KEY UPDATE [SKIP LOCKED] ->) storage_reservations FOR UPDATE [SKIP LOCKED]` + `SELECT openmettle.storage_lock_pinned_volume()` (`== store.volume_id`) setting `reclaim_state = CASE WHEN reclaim_state = 'truncated' THEN 'truncated' ELSE 'claiming' END, reclaim_claim_token = $my_token, reclaim_lease_until = clock_timestamp() + interval '60 seconds'`; **Step 2** outside DB tx: in **Case 1a (`payload_ino IS NOT NULL`, `'claiming'`)**, probe `staging/.reclaim.<id>` first if present, else `staging/<id>` (and check `revisions/<id>`): any foreign/non-regular/different-local-`st_dev`/`st_ino != payload_ino` or all-three `ENOENT` -> ZERO `set_len(0)`/`unlinkat`, quarantine under `reclaim_claim_token = $my_token` guard; matched `st_ino == payload_ino` -> open `OFlags::RDWR \| OFlags::NOFOLLOW` (no `OFlags::TRUNC`) -> `LOCK_EX` (`try_lock()`) -> re-verify `fstat` + `statat` -> **Step 2a fenced DB revalidation & 300 s lease renewal UNDER `LOCK_EX` strictly BEFORE `set_len(0)`/`linkat`/`unlinkat`** (`SELECT openmettle.storage_lock_pinned_volume(); UPDATE openmettle.storage_reservations SET reclaim_lease_until = clock_timestamp() + interval '300 seconds' WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved' AND NOT adoption_unverified AND payload_ino = $3 AND reclaim_state = 'claiming' AND reclaim_claim_token = $4::uuid RETURNING id;`, aborting immediately with ZERO truncation/link/unlink if `0` rows returned!) -> `probe_file.set_len(0)?` + `probe_file.sync_all()?` -> create/verify hard-link anchor `staging/.reclaim.<id>` via `linkat` + **unconditional `fsync(&staging_dir_fd)?` for BOTH newly created and recovered anchors** BEFORE unlinking `<id>` in `revisions/<id>` & `staging/<id>` + dual `fsync` -> while still holding `LOCK_EX` on `probe_file`, commit short `FOR UPDATE` tx setting `reclaim_state = 'truncated', publish_pending = false`; in **Case 1b (`payload_ino IS NOT NULL`, `'truncated'`)**, **NEVER touch `staging/<id>` or `revisions/<id>`**, probe **`staging/.reclaim.<id>` ONLY** (`S_ISREG`, local `st_dev`, `st_ino == payload_ino`, `st_size == 0`, else quarantine) -> open **`OFlags::RDWR \| OFlags::NOFOLLOW` (without `OFlags::TRUNC`, zero `set_len(0)`)** -> `LOCK_EX` -> Step 2a revalidation -> dual `fsync` -> Step 3; in **Case 2 (`payload_ino IS NULL`)**, quarantine any `revisions/<id>`, `staging/.reclaim.<id>`, or non-`0`-byte/foreign `staging/<id>`; for a `0`-byte regular `staging/<id>` on `store.root_dev` with `revisions/<id>` and `staging/.reclaim.<id>` `ENOENT`, open with **`OFlags::RDWR \| OFlags::NOFOLLOW` (without `OFlags::TRUNC`, zero `set_len(0)`)** -> `LOCK_EX` -> re-verify `S_ISREG`, `st_dev == store.root_dev`, `st_size == 0`, `statat` `(fd_dev, fd_ino)` match, and `revisions/<id>`/`staging/.reclaim.<id>` `ENOENT` -> **Step 2a fenced DB SQL UNDER `LOCK_EX` atomically binding `stage_claimed = true, payload_ino = fd_ino`** (`storage_lock_pinned_volume()` + `UPDATE ... SET stage_claimed = true, payload_ino = $3, reclaim_lease_until = clock_timestamp() + interval '300 seconds' WHERE state = 'reserved' AND NOT adoption_unverified AND payload_ino IS NULL AND reclaim_state = 'claiming' AND reclaim_claim_token = $4::uuid RETURNING id;`, aborting with ZERO FS mutations on `0` rows/`OMQ03`!) -> still holding `LOCK_EX`, promote directly into the standard `.reclaim.<id>` anchor sequence (`linkat` -> unconditional `fsync(&staging_dir_fd)?` -> `unlinkat` `staging/<id>` -> dual `fsync` -> commit `reclaim_state = 'truncated', publish_pending = false` -> Step 3 `'anchor_pending_unlink'` -> Step 4; leaving `payload_ino` `NULL` through Step 3 **ONLY** when all three names are already `ENOENT`, with **ZERO `unlinkat` calls**!); **Step 3** locks `(runs ->) storage_reservations` with **ZERO FS I/O**, sets `reclaim_state = CASE WHEN payload_ino IS NOT NULL THEN 'anchor_pending_unlink' ELSE 'none' END, reclaim_claim_token = NULL, reclaim_lease_until = NULL`, and commits `storage::release` (trigger calls `storage_lock_pinned_volume()`, `adjust` updates `storage_accounts -> storage_instance`, **retaining `payload_ino`** on `'released'`); **Step 4** (post-release detach when `payload_ino IS NOT NULL`, plus bounded DB-driven pass over `storage_reservations_reclaim_anchor_idx` across ALL reservation kinds using wrapping per-worker keyset cursor **`reclaim_anchor_cursor: Option<(DateTime<Utc>, Uuid)>`** paired with a pass-start fixed upper watermark **`reclaim_anchor_pass_upper: Option<(DateTime<Utc>, Uuid)>`**, constraining every page with `AND (closed_at, id) <= ($3::timestamptz, $4::uuid)`, advancing past every inspected key, and resetting BOTH cursor and pass-upper to `None` on `< LIMIT` OR reaching `(upper_ts, upper_id)` so neither persistent anomalous anchors nor sustained `>= LIMIT` arrivals per tick starve earlier rows) verifies `staging/.reclaim.<id>` under `LOCK_EX` (**`OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC`**, `st_ino == payload_ino`, `st_size == 0`, never `set_len(0)`) -> `unlinkat(&staging_dir_fd, &reclaim_name, AtFlags::empty())` -> `drop` -> `fsync(&staging_dir_fd)` -> `SET reclaim_state = 'none' WHERE id = $1::uuid AND state = 'released' AND reclaim_state = 'anchor_pending_unlink'` (clearing on `ENOENT` after `fsync(&staging_dir_fd)`). Enforce the **3-stage inode-preserving `artifact_fs::purge_due` protocol (`revisions/.purge.<id>` + `artifact_revisions.purge_stage`)** so `payload_ino` NEVER reaches `nlink = 0` while `state = 'purging'`: `begin_purge` requires `NOT sr.adoption_unverified AND sr.payload_ino IS NOT NULL`; Stage A probes `revisions/.purge.<id>` then `revisions/<id>` (stopping immediately with zero `set_len(0)`/`unlinkat` and zero `confirm_purge` on `ENOENT` or foreign inode!), acquires `LOCK_EX` (`OFlags::RDWR \| OFlags::NOFOLLOW`, no `OFlags::TRUNC`), revalidates `storage_lock_pinned_volume()` + `state = 'purging'`, executes `set_len(0)? + sync_all()?` -> `linkat` `revisions/.purge.<id>` + unconditional `fsync(&revisions_dir_fd)?` strictly BEFORE unlinking `revisions/<id>` and any `st_ino == payload_ino` `staging/<id>` alias + dual `fsync`; Stage B commits `storage::confirm_purge` setting `state = 'purged', purged_at = now(), purge_stage = 'anchor_pending_unlink'`; Stage C (immediately + bounded DB pass over `artifact_revisions_purge_anchor_idx` using wrapping per-worker keyset cursor **`purge_anchor_cursor: Option<(DateTime<Utc>, Uuid)>`** paired with a pass-start fixed upper watermark **`purge_anchor_pass_upper: Option<(DateTime<Utc>, Uuid)>`**, constraining every page with `AND (r.purged_at, r.id) <= ($3::timestamptz, $4::uuid)`, advancing past every inspected key, and resetting BOTH cursor and pass-upper to `None` on `< LIMIT` OR reaching `(upper_ts, upper_id)`) detaches `revisions/.purge.<id>` under `LOCK_EX` (**`OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC`**, never `set_len(0)`) + `fsync(&revisions_dir_fd)` + `SET purge_stage = 'none'`. Pin durable artifact volume identity (`storage_volume_control.volume_id` <-> role-tagged sentinels `<root>/.openmettle-volume-id`, `<root>/revisions/.openmettle-volume-id`, `<root>/staging/.openmettle-volume-id` via safe `rustix` `dirfd` ops, unique `.tmp.<128bit_random_hex>` + `fsync` + `linkat` + `fsync(root_fd)` barrier before child sentinels); serialize adoption via unique `my_adoption_run_id = uuid_v4()` in **Step 1b** (`SELECT ... INTO STRICT ... FROM storage_volume_control WHERE id FOR UPDATE`, rejecting non-null `adoption_run_id` with `OMQ03` unless `--replace-adoption-run <stale_uuid>` matches), Step 2 scan (acquiring non-blocking `LOCK_EX` via `OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC` + `try_lock()` on every `payload_ino IS NULL` `'reserved'` backfill candidate — clearing `adoption_run_id = NULL` without quarantining/backfilling and returning retryable `OMQ03` on `WouldBlock`, else holding those `LOCK_EX` descriptors through Phase 3C commit; any failure clears `storage_volume_control.adoption_run_id = NULL` only `WHERE id AND adoption_run_id = $my_adoption_run_id`), and **Step 3** (`storage_reservations -> artifact_revisions -> storage_volume_control -> storage_accounts -> storage_instance FOR UPDATE`, requiring `adoption_run_id = $my_adoption_run_id`, enforcing **cross-reservation live inode uniqueness** in Phase 3A strictly across live payloads, surviving anchors, and backfill/unquarantine candidates — `artifact_revisions` (`'active'`, `'retained'`, surviving `'purging'`, `'purged'` + `anchor_pending_unlink`) AND `storage_reservations` (`(state = 'reserved' AND (payload_ino IS NOT NULL OR candidate for payload_ino backfill / adoption_unverified = false clearance — explicitly INCLUDING previously quarantined adoption_unverified = true rows present on disk))` OR `(state = 'released' AND reclaim_state = 'anchor_pending_unlink')`), **explicitly EXCLUDING retired historical rows** (`(state = 'released' AND reclaim_state = 'none')` AND `'settled'` rows whose revision is `(state = 'purged' AND purge_stage = 'none')`) — failing closed on `cross_reservation_inode_alias` or `intra_reservation_inode_mismatch`, supporting intermediate crash states `'claiming'`+`.reclaim.<id>` (kept as `'claiming'` with expired `reclaim_lease_until = clock_timestamp()`, NEVER promoted to `'truncated'`), `'truncated'`+`.reclaim.<id>` (requiring `staging/<id>` and `revisions/<id>` `ENOENT`), post-upgrade `sr.payload_ino IS NOT NULL` `'purging'` Stage A (`size_bytes` or `0`-byte `revisions/<id>` or `.purge.<id>`), `'purged'`+`anchor_pending_unlink`, AND legacy `sr.payload_ino IS NULL` `'purging'` Case 6a requiring **exact recorded `(size_bytes, content_digest)`** (rejecting `st_size == 0` when `size_bytes > 0` with `size_or_digest_mismatch`) & Case 6b absent-file completion (never counting as positive on-disk file evidence!), evaluating all checks BEFORE writing `payload_ino` and committing `payload_ino` backfills **strictly ONLY in the success branch onto positively verified non-quarantined rows**, quarantining missing/mismatched `'reserved'` rows, pinning `volume_id`, and clearing `adoption_run_id = NULL`); qualify `O_CREAT \| O_EXCL \| O_NOFOLLOW`, `linkat(..., AtFlags::empty())`, file+dir `fsync`, AND on `ReadWriteMany` shared volumes both two-client `flock(2)` coherence (including Linux NFS `OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC` for `LOCK_EX` across `'truncated'` reopen, Step 4, Stage C, and `StagingSweepState`) and stable 64-bit `st_ino` coherence + second-client recovery; gate all `N` cleaners (`purge_due`, `reconcile_expired`, run-linked recovery, `StagingSweepState`) on `openmettle.storage_lock_pinned_volume()` (`volume_id IS NOT NULL AND adoption_run_id IS NULL`). |
| [ADR 0032](0032-durable-run-admission-and-fair-work-queue.md) and [ADR 0033](0033-worker-leases-deadlines-and-restart-recovery.md), [`src/authz/runs.rs`](../../src/authz/runs.rs) | Keep exact partial-index counts on `runs` for live and executing runs. Resolve per-scope overrides for live caps and `round_cap` (`1..=1000`) at admission, and serialize `executing_runs_*` cap changes with `claim_next` (including approval resume) via `run_dispatch_lock`. Compose usage and device holds inside admission and renew run-bound holds on the worker lease cadence. |
| [ADR 0035](0035-approvals-permitted-yolo-and-effect-ledger.md), [`src/authz/approvals.rs`](../../src/authz/approvals.rs) | Keep `StorageReservation` for run-bound artifact and tool-result spills (including V1-14 (`#14`) bounded outputs, while narrowing ADR 0040's generic run-linked cleaner predicate to **`run_id IS NOT NULL AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')`** — the exact logical complement of [ADR 0039](0039-scoped-mcp-adapter-and-bounded-tool-results.md)'s `operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%'` `reconcile_run_spills` — backed by `storage_reservations_tool_spill_binding_guard` rejecting any new/updated `tool-spill:*` row with `run_id IS NULL OR operation_id IS NULL`). Align parked reservation expiry with `resume_execution_expires_at`. Require configured `ARTIFACTS_DIR`, verified non-null pinned `storage_volume_control.volume_id` (`AND adoption_run_id IS NULL`, locked via `openmettle.storage_lock_pinned_volume()`) <-> role-tagged `.openmettle-volume-id` sentinels in `<root>`, `<root>/revisions`, and `<root>/staging` (`O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK` + `fstat` `S_ISREG`, matching local `st_dev` across open directory FDs, bounded `<= 64`-byte read), `NOT adoption_unverified`, and the unified 4-step durable-identity (`payload_ino`, 4-state `reclaim_state`/`reclaim_claim_token`/`reclaim_lease_until`, fenced Step 2a `LOCK_EX` lease revalidation + 300 s renewal strictly before `set_len(0)` or Case 2 anchor promotion, `staging/.reclaim.<id>` link anchor with unconditional `fsync(&staging_dir_fd)`, and bounded DB-driven Step 4 pass with wrapping keyset cursor `reclaim_anchor_cursor` + pass-start fixed upper watermark `(upper_ts, upper_id)`) reclamation contract (**Step 1** DB claim with zero FS I/O; **Step 2** outside DB tx: Case 1a `payload_ino IS NOT NULL` `'claiming'` probing `.reclaim.<id>` first then `staging/<id>`/`revisions/<id>`, quarantining foreign/all-three-`ENOENT` untouched, else under `OFlags::RDWR \| OFlags::NOFOLLOW` (no `OFlags::TRUNC`) + `LOCK_EX` running Step 2a DB claim/lease revalidation before `probe_file.set_len(0)?` + `probe_file.sync_all()?` -> `linkat` anchor `staging/.reclaim.<id>` + unconditional `fsync(&staging_dir_fd)?` BEFORE unlinking `<id>` + dual `fsync` -> committing `'truncated'` keeping `payload_ino` non-null; Case 1b `'truncated'` probing `staging/.reclaim.<id>` ONLY and NEVER touching `staging/<id>` or `revisions/<id>`, opening `OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC` and zero `set_len(0)` for `LOCK_EX`; Case 2 `payload_ino IS NULL` quarantining any `revisions/<id>`, `staging/.reclaim.<id>`, or `st_size > 0`/non-regular `staging/<id>`, opening `0`-byte regular `staging/<id>` on `store.root_dev` with `revisions/<id>` & `staging/.reclaim.<id>` `ENOENT` via `OFlags::RDWR \| OFlags::NOFOLLOW` (no `OFlags::TRUNC`, zero `set_len(0)`) -> `LOCK_EX` -> Step 2a DB SQL atomically binding `stage_claimed = true, payload_ino = fd_ino` (`reclaim_claim_token = $4::uuid`, aborting with zero FS mutations on `0` rows/`OMQ03`) -> promoting directly into the standard `.reclaim.<id>` anchor sequence -> `'truncated'` -> Step 3 `'anchor_pending_unlink'` -> Step 4 (leaving `payload_ino` `NULL` through Step 3 ONLY when all three names are already `ENOENT`, ZERO `unlinkat` calls); **Step 3** `storage::release` with **zero FS I/O** setting `reclaim_state = CASE WHEN payload_ino IS NOT NULL THEN 'anchor_pending_unlink' ELSE 'none' END` and retaining `payload_ino` on `'released'`; **Step 4** post-release `unlinkat` of `staging/.reclaim.<id>` under `LOCK_EX` (**`OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC`**, never `set_len(0)`) -> `drop` -> `fsync(&staging_dir_fd)` -> `SET reclaim_state = 'none'`), plus retryable staging cleanup via persistent **zero-truncation** `StagingSweepState` (`Idle`/`Open`/`InFlight`/`InvalidatedInFlight`/`DrainingEof` + `pending_names` held outside `worker::sweep`'s 15 s `tokio::time::timeout`, retaining an open `dir_fd` across `Open`/`InFlight`/`DrainingEof` until `pending_names` is empty, verifying `openmettle.storage_lock_pinned_volume()` == `store.volume_id`, skipping `adoption_unverified = true`, **NEVER calling `set_len(0)` in ANY branch — including `0`-row orphans and `.reclaim.<id>`**, opening all `LOCK_EX` targets with **`OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC`** for Linux NFS `F_WRLCK` compatibility: on `.reclaim.<id>`, skipping `'reserved'` untouched, unlinking `('released', 'anchor_pending_unlink')` with `st_ino == payload_ino && st_size == 0` under `LOCK_EX` (`OFlags::RDWR \| OFlags::NOFOLLOW`, no `OFlags::TRUNC`) -> `fsync` -> `SET reclaim_state = 'none'`, and unlinking aged `> 900 s` `0`-row / `('released', 'none')` / `'settled'` entries after `storage_lock_pinned_volume()` + `storage_instance FOR NO KEY UPDATE` recheck without `set_len(0)`; on `'settled'` `staging/<id>`, preserving untouched whenever `adoption_unverified = true`, `payload_ino IS NULL`, OR `staging_ino != payload_ino`, and when `staging_ino == payload_ino` unlinking ONLY under `LOCK_EX` strictly when `artifact_revisions.state IN ('active', 'retained')` AND `revisions/<id>` exists as `S_ISREG` on `store.root_dev` with `rev_ino == payload_ino` — never unlinking by historical `payload_ino` once `'purging'`/`'purged'`; on `'released'` `staging/<id>`, NEVER touching when `payload_ino IS NOT NULL` and unlinking `0`-byte `staging/<id>` under `LOCK_EX` when `payload_ino IS NULL`; and on aged `> 900 s` `0`-row / non-UUID regular files, unlinking under `LOCK_EX` after `storage_lock_pinned_volume()` + `storage_instance FOR NO KEY UPDATE` recheck strictly WITHOUT `set_len(0)`); never release or unlink when `adoption_unverified = true`, when `storage_volume_control.volume_id IS NULL OR adoption_run_id IS NOT NULL`, or when volume identity/sentinel/`revisions/` verification fails. |
| [ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md) | Reconcile local token and cost budget holds strictly from authoritative `openmettle_gateway` settlement reports (`openmettle.gateway_usage_reports` and `openmettle.gateway_settlements` in Migration `0023`, widening `openmettle.gateway_settlements.measured` to `numeric(38, 0)` in PR2's migration with zero edits to frozen `0023`, recording every accepted `(request_id, revision, final)` in append-only **`openmettle.quota_accepted_gateway_reports`** via `SECURITY DEFINER` `AFTER INSERT OR UPDATE OF revision, final` trigger `quota_record_accepted_gateway_settlement` on `gateway_settlements`, binding `quota_reconciliations` via composite FK `(gateway_request_id, source_revision) REFERENCES openmettle.quota_accepted_gateway_reports (request_id, revision)`, verifying exact acceptance in `quota_settle_gateway_usage` via `EXISTS (SELECT 1 FROM openmettle.quota_accepted_gateway_reports a WHERE a.request_id = qr.gateway_request_id AND a.revision = p_source_revision)` and **deterministically folding all unapplied accepted revisions `a.revision` in `(coalesce(qr.accepted_source_revision, -1), p_source_revision]` in ascending `ORDER BY a.revision ASC` order** — plus ascending worker catch-up iteration — while **unconditionally advancing `qr.accepted_source_revision = p_source_revision`** on every processed accepted revision even on `0`-delta/no-op/other-resource reports, writing `quota_reconciliations` and adjusting `quota_budgets` iff `(new_state, new_settled, new_held) IS DISTINCT FROM (old_state, old_settled, old_held)` so out-of-order replay such as `rev 2` before `rev 1` converges to the exact same state and `pending_gateway_reconciliations` simplifies cleanly to `a.revision > coalesce(qr.accepted_source_revision, -1)` without aging no-op reports forever; eliminating settlement/recovery lock cycles by requiring **every** `openmettle_gateway` transaction inserting or updating `openmettle.gateway_settlements` — **both** settlement-only transactions **and** combined single-transaction writes — to call `openmettle.quota_lock_gateway_request_for_settlement(p_request_id)` (`gateway_requests FOR NO KEY UPDATE`) strictly before `INSERT`/`UPDATE` on `gateway_settlements` and keeping `quota_settle_gateway_usage` strictly `gateway_requests FOR KEY SHARE -> quota_reservations (ORDER BY resource ASC FOR UPDATE) -> quota_budgets FOR NO KEY UPDATE` without locking `runs` or `gateway_reservations`; and enforcing strict per-resource authoritative evidence for `usage_cost_micros` (`r_step.cost IS NOT NULL`, deterministic `ceil(r_step.cost)::numeric(38, 0)`) vs `usage_tokens` with **included reasoning tokens as a non-double-counted lower bound on completion** (`K_known = CASE WHEN rev_R >= rev_K THEN greatest(K_raw, R_latest) ELSE K_raw END` and `X_known = 0` when `inc_latest IS TRUE`, vs `K_known = K_raw, X_known = R_latest` when `inc_latest IS FALSE`, so `reasoning_tokens = 150, reasoning_included = true` with `completion_tokens = NULL` immediately charges `C_floor = 150` while keeping `is_complete_tokens = false`, `completion_tokens = 200, reasoning_tokens = 150, reasoning_included = true` charges `200` with zero double-counting, and a newer complete `rev_K > rev_R` honors `K_raw`; closing `state = 'settled'` only when `is_complete_tokens = true AND r_step.final = true`, and monotonically applying `C_effective = greatest(settled, C_floor)` on incomplete reports) into widened `numeric(38, 0)` aggregate/settlement accumulators, with `quota_verify_accounting_drift()` replaying the exact same ascending fold and joining `gateway_settlements gs` to `gateway_usage_reports r_curr` strictly on `(gs.request_id = r_curr.request_id AND gs.revision = r_curr.revision AND gs.final = r_curr.final)` reading `r_curr.source` and `r_curr.report_id`) via narrow `SECURITY DEFINER` transitions. Introduce in-transaction `authz::gateway` helpers (`reserve_in`, `handoff_in`, `release_in`) so inserting `'reserved'` `openmettle.gateway_requests` and creating all metered `openmettle.quota_reservations` holds execute atomically in one `WriteTransaction`, backed by a two-phase ADR 0003 rolling-upgrade activation gate (`openmettle.quota_enforcement.metering_enforced`, seeded `true` **only** on genuine fresh-from-zero installs where `src/migrate.rs` observed `applied == 0` AND all core/storage/gateway tables are empty, and `false` on **every** upgrade `applied >= 1` — including unused upgrades with empty tables — until flipped irreversibly `false -> true` in a standalone single-statement transaction by `openmettle_owner`) plus a `DEFERRABLE INITIALLY DEFERRED` commit-time `CONSTRAINT TRIGGER quota_enforce_gateway_handoff_holds` (`openmettle.enforce_gateway_handoff_holds()`, recording handoff-time obligations in `openmettle.quota_gateway_handoffs` **before** acquiring `quota_enforcement FOR SHARE` as the final sink lock and verifying exact `usage_tokens` hold equality `qr.reserved_units = NEW.units AND qr.held_units = NEW.units AND qr.settled_units = 0 AND qr.accepted_source_revision IS NULL` plus ownership match, `OMQ04`, zero edits to frozen `0023`), lease-generation-fenced successor-worker unwind `openmettle.quota_unwind_superseded_round(...)` (checking `quota_reservations.allocating_claim_token` so replay never unwinds the successor's own attempt, and cleanly unwinding unbound `N-1` `'reserved'` rounds), lazy idempotent once-per-run parent hold initialization (`openmettle.quota_ensure_legacy_run_holds`, executed inside the round-allocation `WriteTransaction` strictly **before** `authz::gateway::reserve_in` under `runs` + `gateway_reservations FOR NO KEY UPDATE` reading `units - allocated`) when an `N` worker claims or reclaims an `N-1`-admitted run, and bounded raw index-key paging with a constant clamped age cutoff in `quota_release_orphan_gateway_requests` for pre-V1-17 orphan `'reserved'` rows. Enforce scope-pinned composite FK `(scope_id, gateway_request_id) REFERENCES openmettle.gateway_requests (scope_id, id)`, unique `(gateway_request_id, resource_kind)`, strict `quota_reservations` state `CHECK` constraints (`settled_units = 0 AND accepted_source_revision IS NULL` while `'held'`), a `SECURITY DEFINER` `BEFORE INSERT OR UPDATE` gateway-binding guard trigger enforcing exact `usage_tokens` hold size equality (`reserved_units = req.units`, pre-settlement `settled_units = 0 AND accepted_source_revision IS NULL AND held_units = req.units`, and exact membership in `quota_accepted_gateway_reports` for every `accepted_source_revision IS NOT NULL` alongside `held_units = greatest(0, req.units - settled_units)` on partial `handoff_committed`, `23514`) alongside `quota_reserve`/`quota_allocate_round`, 32-byte `p_dispatch` secret verification (`dispatch_hash = sha256(p_dispatch)`), ownership recheck under sweep locks, composite FKs to `quota_accepted_gateway_reports` and `gateway_usage_reports`, nullable `accepted_source_revision` supporting `revision >= 0` (including `revision = 0`), run-to-round `held` allocation coupled atomically with `openmettle.gateway_handoff` / `openmettle.gateway_release`, caller-scoped `SECURITY DEFINER` `openmettle.quota_recover_lost_handoff` for lost commit-ack recovery (without granting `SELECT` on `gateway_requests`, validating against recorded handoff-time obligations in `quota_gateway_handoffs` and recognizing `'handoff_committed'` and `'settled'` holds across activation), atomic stale-sweep closure of `'reserved'` `gateway_requests` (`'reserved' -> 'released'` + `gateway_reservations` restoration), signed partial corrections and SQL-enforced `BEFORE INSERT OR UPDATE OR DELETE` deployment denomination immutability (`OMQ02`) with the seeded `('instance', 'usage_cost_micros')` row strictly `UPDATE`-only after migration (serialized via `quota_cost_unit_lock` with zero lock cycle alongside a `BEFORE INSERT` guard trigger on `gateway_usage_reports` (`cost IS NOT NULL`, zero edits to frozen `0023`)). |
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
    ADD COLUMN warn_pct_1 smallint NOT NULL DEFAULT 80 CHECK (warn_pct_1 BETWEEN 1 AND 99),
    ADD COLUMN warn_pct_2 smallint NOT NULL DEFAULT 90
        CHECK (warn_pct_2 BETWEEN 1 AND 99 AND warn_pct_2 > warn_pct_1),
    ADD COLUMN config_revision bigint NOT NULL DEFAULT 1 CHECK (config_revision >= 1);

-- Dedicated 1-row read-mostly volume control table separated from storage_instance
-- (whose counters are updated FOR NO KEY UPDATE on every storage::adjust in
-- src/storage.rs:289-310). Because PostgreSQL 18 requires UPDATE privilege on a
-- table to execute raw SELECT ... FOR SHARE, neither openmettle_api nor
-- openmettle_worker receives INSERT, UPDATE, DELETE, or TRUNCATE on
-- storage_volume_control (preventing direct pin rewrites AND eliminating 42501
-- FOR SHARE failures): runtime reserve, settle, release, purge, and
-- StagingSweepState acquire FOR SHARE strictly through narrow SECURITY DEFINER
-- openmettle.storage_lock_pinned_volume() (owned by openmettle_owner), while
-- one-time empty-ledger API Store::open bootstrap pins strictly through SECURITY
-- DEFINER openmettle.storage_pin_volume_id(uuid) (granted EXECUTE to
-- openmettle_api ONLY; acquiring FOR UPDATE internally as openmettle_owner),
-- eliminating FOR SHARE -> FOR NO KEY UPDATE deadlocks between concurrent
-- releases/reserves while strictly serializing against openmettle-admin adoption
-- Step 1b.
CREATE TABLE openmettle.storage_volume_control (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    volume_id uuid,
    bootstrap_auto_pin_allowed boolean NOT NULL DEFAULT false,
    adoption_run_id uuid,
    CONSTRAINT storage_volume_control_auto_pin_check
        CHECK (volume_id IS NULL OR NOT bootstrap_auto_pin_allowed)
);
INSERT INTO openmettle.storage_volume_control (id) VALUES (true);
GRANT SELECT ON openmettle.storage_volume_control TO openmettle_api, openmettle_worker;

ALTER TABLE openmettle.storage_reservations
    ADD COLUMN lease_expires_at timestamptz,
    ADD COLUMN adoption_unverified boolean NOT NULL DEFAULT false,
    ADD COLUMN stage_claimed boolean NOT NULL DEFAULT false,
    ADD COLUMN payload_ino numeric(20, 0),
    ADD COLUMN publish_pending boolean NOT NULL DEFAULT false,
    ADD COLUMN reclaim_state text NOT NULL DEFAULT 'none'
        CHECK (reclaim_state IN ('none', 'claiming', 'truncated', 'anchor_pending_unlink')),
    ADD COLUMN reclaim_claim_token uuid,
    ADD COLUMN reclaim_lease_until timestamptz,
    ADD CONSTRAINT storage_reservations_lease_check
        CHECK (lease_expires_at IS NULL OR lease_expires_at > created_at),
    ADD CONSTRAINT storage_reservations_adoption_unverified_check
        CHECK (NOT adoption_unverified OR state = 'reserved'),
    ADD CONSTRAINT storage_reservations_payload_ino_nonneg_check
        CHECK (payload_ino IS NULL OR payload_ino >= 0),
    ADD CONSTRAINT storage_reservations_stage_claimed_check
        CHECK (payload_ino IS NULL OR stage_claimed),
    ADD CONSTRAINT storage_reservations_publish_pending_check
        CHECK (NOT publish_pending OR (state = 'reserved' AND payload_ino IS NOT NULL)),
    ADD CONSTRAINT storage_reservations_reclaim_state_check
        CHECK (
            (state = 'reserved' AND reclaim_state IN ('none', 'claiming', 'truncated'))
            OR (state = 'released' AND reclaim_state IN ('none', 'anchor_pending_unlink'))
            OR (state = 'settled' AND reclaim_state = 'none')
        ),
    ADD CONSTRAINT storage_reservations_reclaim_lease_check
        CHECK (
            (reclaim_state IN ('claiming', 'truncated')
                AND reclaim_claim_token IS NOT NULL
                AND reclaim_lease_until IS NOT NULL)
            OR (reclaim_state IN ('none', 'anchor_pending_unlink')
                AND reclaim_claim_token IS NULL
                AND reclaim_lease_until IS NULL)
        ),
    ADD CONSTRAINT storage_reservations_reclaim_truncated_publish_check
        CHECK (reclaim_state NOT IN ('truncated', 'anchor_pending_unlink') OR NOT publish_pending);

-- Exact unsigned 64-bit u64 MetadataExt::ino() (0..=18446744073709551615) stored
-- in numeric(20, 0) (zero signed-i64 cast ambiguity; mapped via sqlx ::text <-> u64).
-- Host-local st_dev is intentionally NOT persisted because Linux NFS assigns
-- client-local anonymous st_dev via get_anon_bdev; each host verifies local
-- same-mount equality (file_meta.dev() == dir_fd_meta.dev() == root_fd_meta.dev())
-- using only its own open FDs, role-tagged .openmettle-volume-id sentinels when
-- volume_id IS NOT NULL, and file_meta.ino() == payload_ino.
-- Runtime monotonic invariants (owner-only adoption_unverified clearance,
-- write-once non-null payload_ino, write-once stage_claimed) are enforced in
-- PostgreSQL by SECURITY INVOKER trigger enforce_storage_reservation_monotonic_guards().
GRANT INSERT (lease_expires_at, stage_claimed)
    ON openmettle.storage_reservations TO openmettle_api, openmettle_worker;
GRANT UPDATE (lease_expires_at, adoption_unverified, stage_claimed, payload_ino,
              publish_pending, reclaim_state, reclaim_claim_token, reclaim_lease_until)
    ON openmettle.storage_reservations TO openmettle_api, openmettle_worker;

-- Plain-column partial B-tree indexes (100% IMMUTABLE in PostgreSQL 18, avoiding
-- STABLE timestamptz + interval expressions) backing two-step raw-index-key paging
-- for both run-linked recovery and non-run reconcile_expired. Run-linked indexes
-- use `run_id IS NOT NULL AND (operation_id IS NULL OR idempotency_key NOT LIKE
-- 'tool-spill:%')` — the exact logical complement of ADR 0039's `operation_id IS
-- NOT NULL AND idempotency_key LIKE 'tool-spill:%'` (`reconcile_run_spills`) — so
-- pre-existing legacy rows with `operation_id IS NULL` remain owned by ADR 0040's
-- generic run-linked cleaner while ADR 0039 remains the sole owner for
-- operation-bound tool-result spills. Rows with `payload_ino IS NOT NULL`,
-- `publish_pending = true`, or expired `reclaim_state IN ('claiming', 'truncated')`
-- remain visible to cleaners so foreign/replacement-leaf, dual-ENOENT, or crashed
-- cleaner leases either reclaim cleanly or promote to `adoption_unverified = true,
-- publish_pending = false, reclaim_state = 'none', reclaim_claim_token = NULL,
-- reclaim_lease_until = NULL` (dropping out of the partial index once quarantined).
CREATE INDEX storage_reservations_run_expiry_idx
    ON openmettle.storage_reservations (lease_expires_at, id)
    WHERE state = 'reserved' AND run_id IS NOT NULL
      AND lease_expires_at IS NOT NULL AND NOT adoption_unverified
      AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%');
CREATE INDEX storage_reservations_run_legacy_expiry_idx
    ON openmettle.storage_reservations (created_at, id)
    WHERE state = 'reserved' AND run_id IS NOT NULL
      AND lease_expires_at IS NULL AND NOT adoption_unverified
      AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%');
CREATE INDEX storage_reservations_upload_expiry_idx
    ON openmettle.storage_reservations (lease_expires_at, id)
    WHERE state = 'reserved' AND run_id IS NULL
      AND lease_expires_at IS NOT NULL AND NOT adoption_unverified;
CREATE INDEX storage_reservations_upload_legacy_expiry_idx
    ON openmettle.storage_reservations (created_at, id)
    WHERE state = 'reserved' AND run_id IS NULL
      AND lease_expires_at IS NULL AND NOT adoption_unverified;
-- Bounded DB-driven Step 4 retry across ALL reservation kinds (non-run uploads,
-- generic run-linked holds, and tool-spill:% holds) so a crash after
-- unlinkat(".reclaim.<id>") + fsync(&staging_dir_fd) and before the SQL clear
-- sees Errno::NOENT, calls fsync(&staging_dir_fd), and clears reclaim_state = 'none'.
CREATE INDEX storage_reservations_reclaim_anchor_idx
    ON openmettle.storage_reservations (closed_at, id)
    WHERE state = 'released' AND reclaim_state = 'anchor_pending_unlink';

-- Durable purge anchor tracking on openmettle.artifact_revisions (synchronized
-- verbatim with ADR 0039): revisions/.purge.<id> pins payload_ino (nlink >= 1)
-- across Stage A -> Stage B (confirm_purge setting state = 'purged', purge_stage =
-- 'anchor_pending_unlink'), and Stage C detaches revisions/.purge.<id> and clears
-- purge_stage = 'none' immediately and via a bounded DB pass in purge_due.
ALTER TABLE openmettle.artifact_revisions
    ADD COLUMN purge_stage text NOT NULL DEFAULT 'none',
    ADD CONSTRAINT artifact_revisions_purge_stage_check
        CHECK (
            purge_stage IN ('none', 'anchor_pending_unlink')
            AND (purge_stage = 'none' OR state = 'purged')
        );
CREATE INDEX artifact_revisions_purge_anchor_idx
    ON openmettle.artifact_revisions (purged_at, id)
    WHERE state = 'purged' AND purge_stage = 'anchor_pending_unlink';
GRANT UPDATE (purge_stage) ON openmettle.artifact_revisions TO openmettle_worker;

-- Widen frozen Migration 0023's gateway_settlements.measured from bigint to
-- numeric(38, 0) without editing Migration 0023. Preserves CHECK (measured >= 0)
-- and nullable measured (NULL for cost-only reports) while accommodating exact
-- 3-column token sums (prompt_tokens + completion_tokens + reasoning_tokens)
-- up to 3 * (2^63 - 1) without bigint overflow.
ALTER TABLE openmettle.gateway_settlements
    ALTER COLUMN measured TYPE numeric(38, 0);

-- Append-only durable per-revision acceptance ledger for Migration 0023's
-- gateway_settlements (owned by openmettle_owner, REVOKE ALL FROM PUBLIC, zero
-- direct DML grants to runtime roles). Populated exclusively by the AFTER INSERT
-- OR UPDATE trigger on gateway_settlements so every accepted (request_id, revision,
-- final) — and ONLY revisions accepted past gateway_advance_settlement — survives
-- later revision advances (e.g., token-only final rev 1 followed by cost-only
-- final rev 2 before local catch-up) while rejected intermediate revisions (e.g.,
-- partial rev 3 after final rev 2) never appear here.
CREATE TABLE openmettle.quota_accepted_gateway_reports (
    request_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision >= 0),
    final boolean NOT NULL,
    accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (request_id, revision),
    UNIQUE (request_id, revision, final),
    FOREIGN KEY (request_id, revision, final)
        REFERENCES openmettle.gateway_usage_reports (request_id, revision, final)
);
INSERT INTO openmettle.quota_accepted_gateway_reports (request_id, revision, final)
SELECT request_id, revision, final FROM openmettle.gateway_settlements
ON CONFLICT (request_id, revision) DO NOTHING;

CREATE FUNCTION openmettle.record_accepted_gateway_settlement()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    INSERT INTO openmettle.quota_accepted_gateway_reports (
        request_id, revision, final
    ) VALUES (
        NEW.request_id, NEW.revision, NEW.final
    ) ON CONFLICT (request_id, revision) DO NOTHING;
    RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.record_accepted_gateway_settlement() FROM PUBLIC;
CREATE TRIGGER quota_record_accepted_gateway_settlement
    AFTER INSERT OR UPDATE OF revision, final ON openmettle.gateway_settlements
    FOR EACH ROW
    EXECUTE FUNCTION openmettle.record_accepted_gateway_settlement();

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
UPDATE openmettle.storage_volume_control svc
   SET bootstrap_auto_pin_allowed = fresh.is_fresh_bootstrap
  FROM fresh
 WHERE svc.id;

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
        REFERENCES openmettle.quota_accepted_gateway_reports (request_id, revision),
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
-- initial 'reserved' state, exact accepted_source_revision membership in
-- quota_accepted_gateway_reports, and exact usage_tokens hold-size equality
-- checks. quota_reserve and quota_allocate_round additionally derive/enforce
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
        IF NEW.accepted_source_revision IS NOT NULL THEN
            IF NOT EXISTS (
                SELECT 1
                  FROM openmettle.quota_accepted_gateway_reports a
                 WHERE a.request_id = req.id
                   AND a.revision = NEW.accepted_source_revision
            ) THEN
                RAISE EXCEPTION 'quota reservation accepted_source_revision must exist in quota_accepted_gateway_reports'
                    USING ERRCODE = '23514';
            END IF;
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
                IF NEW.held_units <> greatest(0::numeric(38, 0), req.units::numeric(38, 0) - NEW.settled_units)::bigint THEN
                    RAISE EXCEPTION 'partially settled usage_tokens reservation must match remaining held_units'
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

-- Added in PR2's migration (zero edits to frozen Migration 0023). Because
-- Migration 0023 grants openmettle_gateway only SELECT on gateway_requests,
-- this narrow SECURITY DEFINER helper acquires FOR NO KEY UPDATE on
-- gateway_requests strictly BEFORE EVERY openmettle_gateway INSERT or UPDATE
-- on openmettle.gateway_settlements — BOTH settlement-only transactions AND
-- combined single-transaction gateway_settlements upsert +
-- quota_settle_gateway_usage writes (matching canonical lock order
-- runs -> gateway_reservations -> gateway_requests -> gateway_settlements ->
-- quota_accepted_gateway_reports -> quota_reservations -> quota_budgets and
-- eliminating any lock cycle across settlement-only writers, combined writers,
-- gateway_mark_settled_final, and worker recovery).
CREATE FUNCTION openmettle.quota_lock_gateway_request_for_settlement(
    p_request_id uuid
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
    IF NOT pg_has_role(session_user, 'openmettle_gateway', 'USAGE') THEN
        RAISE EXCEPTION 'quota_lock_gateway_request_for_settlement requires openmettle_gateway role'
            USING ERRCODE = '42501';
    END IF;
    PERFORM 1
      FROM openmettle.gateway_requests
     WHERE id = p_request_id
       FOR NO KEY UPDATE;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.quota_lock_gateway_request_for_settlement(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.quota_lock_gateway_request_for_settlement(uuid) TO openmettle_gateway;

-- Added in PR2's migration. Enforces the tool-spill:* ownership namespace
-- invariant on all newly inserted or updated storage_reservations rows so
-- tool-spill holds always carry both run_id and operation_id (owned solely by
-- ADR 0039 reconcile_run_spills), while any pre-existing row with
-- operation_id IS NULL is cleanly owned by ADR 0040's generic run-linked cleaner
-- (`run_id IS NOT NULL AND (operation_id IS NULL OR idempotency_key NOT LIKE
-- 'tool-spill:%')`).
CREATE FUNCTION openmettle.enforce_tool_spill_reservation_binding()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.idempotency_key LIKE 'tool-spill:%'
       AND (NEW.run_id IS NULL OR NEW.operation_id IS NULL) THEN
        RAISE EXCEPTION 'tool-spill storage reservations require non-null run_id and operation_id'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_tool_spill_reservation_binding() FROM PUBLIC;
CREATE TRIGGER storage_reservations_tool_spill_binding_guard
    BEFORE INSERT OR UPDATE OF idempotency_key, run_id, operation_id
    ON openmettle.storage_reservations
    FOR EACH ROW EXECUTE FUNCTION openmettle.enforce_tool_spill_reservation_binding();

-- Added in PR2's migration. Narrow openmettle_owner-owned SECURITY DEFINER helper
-- acquiring FOR SHARE on openmettle.storage_volume_control without granting
-- UPDATE on storage_volume_control to openmettle_api or openmettle_worker
-- (PostgreSQL 18 requires UPDATE privilege for raw SELECT ... FOR SHARE). Fails
-- closed with OMQ03 on missing singleton row, unpinned volume_id IS NULL, or
-- active adoption_run_id IS NOT NULL.
CREATE FUNCTION openmettle.storage_lock_pinned_volume()
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_vol uuid;
    v_adopt uuid;
BEGIN
    SELECT volume_id, adoption_run_id
      INTO v_vol, v_adopt
      FROM openmettle.storage_volume_control
     WHERE id
       FOR SHARE;
    IF NOT FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL THEN
        RAISE EXCEPTION 'runtime storage operations require pinned, non-adopting storage_volume_control.volume_id'
            USING ERRCODE = 'OMQ03';
    END IF;
    RETURN v_vol;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.storage_lock_pinned_volume() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.storage_lock_pinned_volume() TO openmettle_api, openmettle_worker;

-- Added in PR2's migration. Narrow openmettle_owner-owned SECURITY DEFINER helper
-- for one-time fresh-from-zero API Store::open bootstrap auto-pinning (granted
-- EXECUTE to openmettle_api ONLY; openmettle_worker never initializes sentinels
-- and never calls storage_pin_volume_id). Acquires FOR UPDATE on
-- openmettle.storage_volume_control internally as openmettle_owner (API
-- Store::open never issues an invoker SELECT ... FOR UPDATE beforehand!),
-- returns existing volume_id if already equal to p_volume_id (idempotent across
-- concurrent fresh-bootstrap API pods adopting the same winning :root UUID),
-- raises OMQ03 if missing/adopting/mismatched/not bootstrap_auto_pin_allowed/
-- non-empty ledger, and atomically pins volume_id while clearing
-- bootstrap_auto_pin_allowed.
CREATE FUNCTION openmettle.storage_pin_volume_id(p_volume_id uuid)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_vol uuid;
    v_auto boolean;
    v_adopt uuid;
BEGIN
    IF p_volume_id IS NULL THEN
        RAISE EXCEPTION 'storage_pin_volume_id requires non-null volume_id'
            USING ERRCODE = 'OMQ03';
    END IF;
    SELECT volume_id, bootstrap_auto_pin_allowed, adoption_run_id
      INTO v_vol, v_auto, v_adopt
      FROM openmettle.storage_volume_control
     WHERE id
       FOR UPDATE;
    IF NOT FOUND OR v_adopt IS NOT NULL THEN
        RAISE EXCEPTION 'storage_volume_control is missing or undergoing adoption'
            USING ERRCODE = 'OMQ03';
    END IF;
    IF v_vol IS NOT NULL THEN
        IF v_vol = p_volume_id THEN
            RETURN v_vol;
        END IF;
        RAISE EXCEPTION 'storage_volume_control.volume_id is already pinned to a different volume'
            USING ERRCODE = 'OMQ03';
    END IF;
    IF NOT v_auto
       OR EXISTS (SELECT 1 FROM openmettle.storage_reservations)
       OR EXISTS (SELECT 1 FROM openmettle.artifact_revisions) THEN
        RAISE EXCEPTION 'bootstrap auto-pin requires bootstrap_auto_pin_allowed = true and empty storage ledger'
            USING ERRCODE = 'OMQ03';
    END IF;
    UPDATE openmettle.storage_volume_control
       SET volume_id = p_volume_id,
           bootstrap_auto_pin_allowed = false
     WHERE id;
    RETURN p_volume_id;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.storage_pin_volume_id(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION openmettle.storage_pin_volume_id(uuid) TO openmettle_api;

-- Added in PR2's migration. PostgreSQL ledger defense-in-depth backstop while
-- storage_volume_control.volume_id IS NULL, storage_volume_control.adoption_run_id
-- IS NOT NULL, or the singleton row is missing: SECURITY INVOKER evaluates
-- current_user accurately across BOTH INHERIT logins AND NOINHERIT logins
-- assuming SET ROLE openmettle_api / openmettle_worker, then delegates the
-- FOR SHARE lock and pin check to SECURITY DEFINER storage_lock_pinned_volume()
-- so openmettle_api / openmettle_worker succeed without 42501 on a healthy pinned
-- volume and fail closed with OMQ03 otherwise, while active openmettle_owner
-- reconciliation bypasses the guard.
-- In src/storage.rs:289-310 and 496-505, storage::release locks
-- storage_reservations FOR UPDATE and runs UPDATE storage_reservations
-- SET state = 'released' BEFORE adjust() updates storage_accounts ->
-- storage_instance (FOR NO KEY UPDATE). Acquiring FOR SHARE via
-- storage_lock_pinned_volume() on the dedicated read-mostly storage_volume_control
-- singleton (NEVER updated by runtime ops!) strictly preserves canonical storage
-- lock order (runs -> storage_reservations -> artifacts -> artifact_revisions ->
-- storage_volume_control [via storage_lock_pinned_volume()] -> storage_accounts ->
-- storage_instance), eliminates FOR SHARE -> FOR NO KEY UPDATE deadlocks between
-- concurrent releases/reserves, fails closed if the singleton row is missing
-- (NOT FOUND), and conflicts directly with adoption Step 1b's
-- storage_volume_control FOR UPDATE (which locks ONLY storage_volume_control, so
-- zero deadlock cycle is possible): any in-flight storage::release either finishes
-- its entire transaction strictly BEFORE Step 1b acquires FOR UPDATE, OR blocks on
-- Step 1b's FOR UPDATE and fails closed with OMQ03 once Step 1b commits
-- adoption_run_id. Normal storage::reserve and storage::settle remain unaffected.
-- NOT a substitute for quiescing N-1 worker cleaners before migration because N-1
-- workers unlink before mutating PostgreSQL.
CREATE FUNCTION openmettle.enforce_runtime_storage_volume_pinned()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE') THEN
        PERFORM openmettle.storage_lock_pinned_volume();
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_runtime_storage_volume_pinned() FROM PUBLIC;
CREATE TRIGGER storage_reservations_runtime_volume_pin_guard
    BEFORE UPDATE ON openmettle.storage_reservations
    FOR EACH ROW
    WHEN (OLD.state = 'reserved' AND NEW.state = 'released')
    EXECUTE FUNCTION openmettle.enforce_runtime_storage_volume_pinned();
CREATE TRIGGER artifact_revisions_runtime_volume_pin_guard
    BEFORE UPDATE ON openmettle.artifact_revisions
    FOR EACH ROW
    WHEN (NEW.state IN ('purging', 'purged'))
    EXECUTE FUNCTION openmettle.enforce_runtime_storage_volume_pinned();

-- Added in PR2's migration. Enforces runtime monotonic invariants directly in
-- PostgreSQL for openmettle_api and openmettle_worker (SECURITY INVOKER evaluating
-- current_user across both INHERIT and NOINHERIT/SET ROLE logins):
--   1. Only openmettle_owner (or verified openmettle-admin adoption) may clear
--      adoption_unverified = true -> false. Combined with CHECK (NOT
--      adoption_unverified OR state = 'reserved'), NO non-owner role can EVER
--      transition a quarantined 'reserved' row to 'released' or 'settled'
--      (neither keeping adoption_unverified = true nor clearing it to false),
--      while openmettle_owner releases a quarantined row cleanly in one UPDATE
--      setting state = 'released', adoption_unverified = false.
--   2. Once bound, payload_ino is strictly write-once and NEVER mutated or cleared
--      to NULL (retained across 'reserved' -> 'settled' and 'reserved' -> 'released').
--   3. Once claimed, stage_claimed is strictly write-once (true -> false forbidden).
CREATE FUNCTION openmettle.enforce_storage_reservation_monotonic_guards()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
    IF NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE') THEN
        IF OLD.adoption_unverified AND NOT NEW.adoption_unverified THEN
            RAISE EXCEPTION 'only openmettle_owner may clear storage_reservations.adoption_unverified'
                USING ERRCODE = 'OMQ03';
        END IF;
        IF OLD.payload_ino IS NOT NULL AND NEW.payload_ino IS DISTINCT FROM OLD.payload_ino THEN
            RAISE EXCEPTION 'storage_reservations.payload_ino is write-once and immutable for runtime roles'
                USING ERRCODE = 'OMQ03';
        END IF;
        IF OLD.stage_claimed AND NOT NEW.stage_claimed THEN
            RAISE EXCEPTION 'storage_reservations.stage_claimed is write-once for runtime roles'
                USING ERRCODE = 'OMQ03';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION openmettle.enforce_storage_reservation_monotonic_guards() FROM PUBLIC;
CREATE TRIGGER storage_reservations_monotonic_guards
    BEFORE UPDATE ON openmettle.storage_reservations
    FOR EACH ROW
    EXECUTE FUNCTION openmettle.enforce_storage_reservation_monotonic_guards();
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
  NEW.run_id`, and on `INSERT` that `q.state = 'reserved'`, verifies exact membership in the
  durable acceptance ledger **`EXISTS (SELECT 1 FROM openmettle.quota_accepted_gateway_reports a
  WHERE a.request_id = req.id AND a.revision = NEW.accepted_source_revision)`** whenever
  `NEW.accepted_source_revision IS NOT NULL` (so a rejected intermediate revision stored in
  `gateway_usage_reports`, such as partial `revision = 3` between accepted `2` and `4`, can never
  match), and for `NEW.resource_kind = 'usage_tokens'` enforces `NEW.reserved_units = req.units`,
  exact pre-settlement hold equality (`NEW.settled_units = 0 AND NEW.accepted_source_revision IS
  NULL AND NEW.held_units = req.units`) whenever `TG_OP = 'INSERT'`, `NEW.state = 'held'`, or
  `(NEW.state = 'handoff_committed' AND NEW.accepted_source_revision IS NULL)`, and for partially
  settled `handoff_committed` rows (`accepted_source_revision IS NOT NULL`) requires
  `NEW.held_units = greatest(0::numeric(38, 0), req.units::numeric(38, 0) -
  NEW.settled_units)::bigint` (raising `ERRCODE = '23514'` on any violation). In addition, both
  `openmettle.quota_reserve(...)` (standalone `run_id IS NULL`, when `p_gateway_request_id IS NOT
  NULL` and `p_resource_kind = 'usage_tokens'`) and `openmettle.quota_allocate_round(...)`
  (`run_id IS NOT NULL`, for `usage_tokens`) derive/enforce `reserved_units = req.units`
  (`held_units = req.units`) from the locked `gateway_requests` row (rejecting any mismatched
  caller amount with `ERRCODE = '23514'`) and require the caller to present the 32-byte
  `p_dispatch` secret matching `octet_length(p_dispatch) = 32 AND q.dispatch_hash =
  sha256(p_dispatch)` so no caller can bind an under-sized hold or bind to another request even
  within the same scope and actor. The partial unique index
  `quota_reservations_gateway_request_kind_uidx` (`UNIQUE (gateway_request_id, resource_kind)
  WHERE gateway_request_id IS NOT NULL`) guarantees at most one `usage_tokens` reservation and at
  most one `usage_cost_micros` reservation can bind to a given `gateway_request_id`, preventing
  two distinct `idempotency_key`s from attaching duplicate holds to the same gateway request.
  Likewise, `quota_reservations_device_grant_uidx` binds each durable `device_grant_id` to at most
  one `device_reservations` hold.
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
  `quota_enforcement_write_once`) and `openmettle.storage_volume_control.bootstrap_auto_pin_allowed`
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
- **Mandatory pre-migration `N-1` cleaner quiescence + dedicated read-mostly
  `openmettle.storage_volume_control` singleton + serialized unpinned/adopting runtime storage
  volume backstop & monotonic reservation guards (`OMQ03`).** Keeping `(volume_id,
  bootstrap_auto_pin_allowed, adoption_run_id)` on dedicated 1-row read-mostly control table
  **`openmettle.storage_volume_control`** (`GRANT SELECT` ONLY to `openmettle_api,
  openmettle_worker` — zero `INSERT`/`UPDATE`/`DELETE`/`TRUNCATE` grants to any runtime role)
  instead of `openmettle.storage_instance` eliminates any lock-upgrade deadlock with
  `storage::adjust` (`src/storage.rs:289-310`), which updates `storage_accounts ->
  storage_instance` (`FOR NO KEY UPDATE`) on every `reserve`, `settle`, `release`, and
  `confirm_purge`: runtime `reserve`, `settle`, `release`, and `purge` **ONLY ever acquire
  `FOR SHARE` on `storage_volume_control` via `SECURITY DEFINER`
  `openmettle.storage_lock_pinned_volume()`** (avoiding PostgreSQL 18's `42501` requirement for
  table `UPDATE` privilege on `SELECT ... FOR SHARE`) and **NEVER `UPDATE`
  `storage_volume_control`** (only `openmettle-admin` adoption Steps 1b/3 and one-time
  empty-ledger API `Store::open` bootstrap inside `SECURITY DEFINER`
  `openmettle.storage_pin_volume_id(uuid)` — granted `EXECUTE` to `openmettle_api` ONLY —
  acquire `FOR UPDATE` on `storage_volume_control` as `openmettle_owner`).
  On **every** upgrade (`applied >= 1`, even with empty `storage_*` tables),
  `storage_volume_control.bootstrap_auto_pin_allowed` seeds `false`,
  `storage_volume_control.adoption_run_id` defaults `NULL`, and `storage_volume_control.volume_id`
  stays `NULL` across the **entire `N-1 -> N` binary replacement** (until zero `N-1` worker or API
  processes remain running). Because `N-1`'s `artifact_fs::reconcile_expired` unlinks both payload
  paths *before* calling `storage::release` (`src/artifact_fs.rs:660-669`) and `N-1`'s
  `artifact_fs::purge_due` skips any `UPDATE` in `storage::begin_purge` for an already-`'purging'`
  revision (`src/storage.rs:628-636`) and unlinks `revisions/<reservation>` *before*
  `confirm_purge` executes (`src/artifact_fs.rs:694-707`), **operators MUST quiesce all `N-1`
  worker artifact cleaners (unset `OPENMETTLE_WORKER_ARTIFACTS_DIR` across all `N-1` workers and
  drain all in-flight `worker::maintenance` sweeps to completion) BEFORE running
  `openmettle-migrate`**. Furthermore, an `N-1` `openmettle_api` replica's unconditional
  `artifact_fs::abort()` (`src/artifact_fs.rs:584-591`) ignores errors from `storage::release`
  (`let _ = committed(pool, async |tx| storage::release(...)).await; error`) and could otherwise
  release a post-publication `revisions/<id>` charge on a failed same-key upload retry during
  rolling upgrade; and during `openmettle-admin` adoption's Step 2 pre-scan on an already-pinned
  volume, `storage_volume_control.adoption_run_id = $my_adoption_run_id` (committed in Step 1b
  under explicit `storage_volume_control FOR UPDATE` strictly before Step 2 starts, rejecting any
  concurrent second adopter unless `--replace-adoption-run <stale_uuid>` matches, and cleared
  atomically in Step 3's final commit) must strictly serialize against any in-flight
  `storage::release` or purge. Therefore, **`SECURITY INVOKER`** `BEFORE UPDATE` trigger
  `openmettle.enforce_runtime_storage_volume_pinned()` (`SET search_path = pg_catalog`, `OMQ03`)
  on both `openmettle.storage_reservations` (`OLD.state = 'reserved' AND NEW.state = 'released'`)
  and `openmettle.artifact_revisions` (`NEW.state IN ('purging', 'purged')`) checks `NOT
  pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')` as the invoker and calls
  `PERFORM openmettle.storage_lock_pinned_volume()`, which executes `SELECT volume_id,
  adoption_run_id INTO v_vol, v_adopt FROM openmettle.storage_volume_control WHERE id FOR SHARE;`
  as `openmettle_owner` (zero PostgreSQL 18 `42501`!) and raises `OMQ03` whenever **`NOT FOUND OR
  v_vol IS NULL OR v_adopt IS NOT NULL`** (failing closed even if the singleton row is missing!):
  because `FOR SHARE` on `storage_volume_control` is 100% mutually compatible across concurrent
  runtime reserves/releases/purges, conflicts directly with Step 1b's standalone
  `storage_volume_control FOR UPDATE`, and sits strictly before `storage_accounts ->
  storage_instance` in canonical storage lock order (`runs -> storage_reservations -> artifacts ->
  artifact_revisions -> storage_volume_control [via storage_lock_pinned_volume()] ->
  storage_accounts -> storage_instance`), concurrent releases/reserves/purges **NEVER deadlock**,
  and any in-flight `storage::release` either completes its entire transaction strictly before Step
  1b acquires `FOR UPDATE` OR blocks on Step 1b's `FOR UPDATE` and fails closed with `OMQ03` once
  Step 1b commits `adoption_run_id`.
  Because `SECURITY INVOKER` evaluates `current_user` as the active effective role executing the
  `UPDATE`, both `INHERIT` runtime logins AND `NOINHERIT` logins assuming `SET ROLE openmettle_api`
  or `SET ROLE openmettle_worker` fail closed with `OMQ03`, while active `openmettle_owner`
  reconciliation succeeds. Companion **`SECURITY INVOKER`** `BEFORE UPDATE` trigger
  `openmettle.enforce_storage_reservation_monotonic_guards()` (`SET search_path = pg_catalog`,
  `OMQ03`) combined with tightened `storage_reservations_adoption_unverified_check` (`CHECK (NOT
  adoption_unverified OR state = 'reserved')`) additionally enforces directly in PostgreSQL that
  no non-`openmettle_owner` role can EVER transition a quarantined `'reserved'` row (`adoption_unverified = true`) to `'released'` or `'settled'` (neither keeping `adoption_unverified = true` nor clearing it `true -> false`), mutate or clear a non-null `payload_ino`, or clear `stage_claimed` (`true -> false`), while `openmettle_owner` releases a quarantined row cleanly in one `UPDATE` setting `state = 'released', adoption_unverified = false`. Normal `N-1` and `N` HTTP uploads (`storage::reserve`, `Store::stage`, `Store::publish`, `storage::settle`) continue uninterrupted while `volume_id IS NULL AND adoption_run_id IS NULL` (whereas ADR 0039 worker `publish_bytes` spills and all four cleaners strictly require `volume_id IS NOT NULL AND adoption_run_id IS NULL`), and any failed upload's `abort()` receives `OMQ03` (preserving the `'reserved'` charge and any published `revisions/<id>` until post-adoption `N` `reconcile_expired` completes verified cleanup on the pinned volume). This trigger is a PostgreSQL ledger defense-in-depth backstop — explicitly **NOT** a substitute for pre-migration `N-1` worker cleaner quiescence. Verified volume adoption pins `storage_volume_control.volume_id` only after 100% of `N-1` API and worker replicas are replaced by `N` binaries; starting or resuming any `N-1` replica after pinning is strictly forbidden by the rollout contract.
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
- **Composite personal-scope binding and `tool-spill:*` ownership partition.**
  `quota_reservations` binds `(actor_scope_id, actor_user_id)` through a composite foreign key to
  `openmettle.scopes (id, personal_user_id)`
  ([`migrations/0001_identity_and_scopes.sql`](../../migrations/0001_identity_and_scopes.sql)),
  proving at the schema layer that `actor_scope_id` is the actor's genuine personal scope. On
  `openmettle.storage_reservations`, `storage_reservations_tool_spill_binding_guard`
  (`openmettle.enforce_tool_spill_reservation_binding()`, `BEFORE INSERT OR UPDATE OF
  idempotency_key, run_id, operation_id`, `23514`) ensures every new or updated `tool-spill:*` row
  carries non-null `run_id` and `operation_id` (owned exclusively by ADR 0039
  `reconcile_run_spills`: `operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%'`),
  while ADR 0040's generic run-linked cleaner indexes and predicate (`run_id IS NOT NULL AND
  (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')`) form the exact logical
  complement so any pre-existing row with `operation_id IS NULL` is cleanly owned by ADR 0040.
- **Durable per-revision gateway acceptance ledger (`quota_accepted_gateway_reports`) and Migration
  `0023` report identity.** In Migration `0023`, `openmettle.gateway_usage_reports` has `PRIMARY
  KEY (source, report_id, revision)`, `UNIQUE (request_id, revision)`, `UNIQUE (request_id,
  revision, final)` and `revision >= 0` (`0` is a valid initial report revision), while
  `openmettle.gateway_settlements` keeps only one latest row per `request_id`. Without a
  per-revision acceptance ledger, advancing `gateway_settlements` from token-only final `revision =
  1` to cost-only final `revision = 2` before local token catch-up would strand the `usage_tokens`
  hold open (since `gs.revision = 1` would no longer match while `revision = 2` has no token
  evidence), and `gs.revision >= accepted_source_revision` could falsely match a rejected
  intermediate revision `3` between accepted `2` and `4`. PR2 therefore adds append-only
  `openmettle.quota_accepted_gateway_reports` (populated exclusively by `SECURITY DEFINER` `AFTER
  INSERT OR UPDATE OF revision, final` trigger `quota_record_accepted_gateway_settlement` on
  `openmettle.gateway_settlements`, which runs strictly after Migration `0023`'s `BEFORE UPDATE`
  `gateway_advance_settlement` rejects invalid revisions with `23514`, plus an upgrade backfill
  from existing `gateway_settlements`). `quota_reservations.accepted_source_revision` is nullable
  (`NULL` = no report accepted yet; `CHECK (accepted_source_revision IS NULL OR
  accepted_source_revision >= 0)`), and `quota_reconciliations` binds each gateway settlement via
  three composite foreign keys: `(reservation_id, gateway_request_id) REFERENCES
  openmettle.quota_reservations (id, gateway_request_id)`, **`(gateway_request_id, source_revision)
  REFERENCES openmettle.quota_accepted_gateway_reports (request_id, revision)`** and
  `(gateway_report_source, gateway_report_id, source_revision) REFERENCES
  openmettle.gateway_usage_reports (source, report_id, revision)` (with `source_revision >= 0`).
  Inside `quota_settle_gateway_usage`, matching `(request_id, source, report_id, revision)` on
  `openmettle.gateway_usage_reports` alongside `EXISTS` in
  `openmettle.quota_accepted_gateway_reports` on `(request_id, revision, final)` proves exact
  acceptance of that historical or current revision without duplicating raw provider token, cost or
  quarantine rows.
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
  -> gateway_settlements (Migration 0023) -> quota_accepted_gateway_reports
  -> quota_defaults (openmettle_owner only) -> quota_cost_unit_lock (trigger serialization only)
  -> quota_reservations (parent before child) / storage_reservations
  -> artifacts (upload settlement only) / artifact_revisions (retention/purge only)
  -> storage_volume_control [via storage_lock_pinned_volume()]
       (FOR SHARE via SECURITY DEFINER in runtime reserve/settle/release/purge & StagingSweepState;
        FOR UPDATE ONLY in openmettle-admin adoption Steps 1b/3 and internally inside
        API-only SECURITY DEFINER storage_pin_volume_id(uuid))
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
| Gateway usage settlement or correction (`openmettle_gateway`, via `quota_settle_gateway_usage`) | **Every** `openmettle_gateway` write transaction that inserts or updates `openmettle.gateway_settlements` — **both** settlement-only transactions **and** combined single-transaction (`gateway_settlements` upsert + `quota_settle_gateway_usage`) writes — MUST call **`openmettle.quota_lock_gateway_request_for_settlement(p_request_id)`** (`FOR NO KEY UPDATE` on `gateway_requests`, and if any caller ever touches upstream rows, `(runs ->) gateway_reservations` BEFORE `gateway_requests`) **strictly BEFORE** `INSERT`/`UPDATE` on `openmettle.gateway_settlements` (whose `AFTER INSERT OR UPDATE` trigger `quota_record_accepted_gateway_settlement` appends `(NEW.request_id, NEW.revision, NEW.final)` to `openmettle.quota_accepted_gateway_reports`, establishing the strictly acyclic global DAG `runs -> gateway_reservations -> gateway_requests -> gateway_settlements -> quota_accepted_gateway_reports -> quota_reservations -> quota_budgets` with zero cycles across settlement-only writers, combined writers, `gateway_mark_settled_final`, and worker recovery). Inside `quota_settle_gateway_usage` (`SECURITY DEFINER`), holds must already be in `state IN ('handoff_committed', 'settled')` (so `gateway_requests.state = 'handed_off'`); the function **never locks `runs`, `gateway_bindings`, `gateway_reservations`, or `gateway_settlements`** — its lock sequence is strictly **`gateway_requests` (`FOR KEY SHARE`, non-conflicting with `FOR NO KEY UPDATE`) -> `quota_reservations` (`ORDER BY resource_kind ASC FOR UPDATE`) -> charged `quota_budgets` (`FOR NO KEY UPDATE`, scope rows asc, instance row last)**, verifying `(p_report_source, p_report_id, p_source_revision)` matches `openmettle.gateway_usage_reports` and `EXISTS (SELECT 1 FROM openmettle.quota_accepted_gateway_reports a WHERE a.request_id = qr.gateway_request_id AND a.revision = p_source_revision)`. When `qr.accepted_source_revision IS NOT NULL AND p_source_revision <= qr.accepted_source_revision`, it returns an idempotent no-op; otherwise it **deterministically folds every unapplied accepted revision `a.revision` in `(coalesce(qr.accepted_source_revision, -1), p_source_revision]` in ascending `ORDER BY a.revision ASC`** (applying included-reasoning lower bound `K_known = CASE WHEN rev_R >= rev_K THEN greatest(K_raw, R_latest) ELSE K_raw END` when `inc_latest IS TRUE`, complete-evidence close gate, and monotonic lower bound on incomplete reports), **unconditionally advancing `qr.accepted_source_revision = p_source_revision`** on `openmettle.quota_reservations` (writing `quota_reconciliations` and adjusting `quota_budgets` + `quota_warning_events` iff `(new_state, new_settled, new_held) IS DISTINCT FROM (old_state, old_settled, old_held)`). |
| Pre-send abort, stale release, orphan `'reserved'` gateway sweep or V1-18 device release (via `quota_release_unsent` / `quota_release_orphan_gateway_requests` / `quota_release_device_slot`) | **One reservation/request per short transaction, locks acquired inside `SECURITY DEFINER`:** `runs` (if run-linked: `FOR NO KEY UPDATE SKIP LOCKED` in stale/orphan sweep, `FOR NO KEY UPDATE` on explicit abort/release) -> if bound to `gateway_request_id`, `gateway_reservations` -> `gateway_requests` (explicit pre-send unwind couples with `authz::gateway::release_in(&mut tx, ...)` / `openmettle.gateway_release(p_request, p_dispatch)` after locking `runs`, or verifies `gateway_requests.state = 'released'` from a prior `gateway_release` commit; sweep mode acquires `FOR NO KEY UPDATE SKIP LOCKED` on `gateway_reservations` then `gateway_requests`, proceeds if `gateway_requests.state = 'released'`, **atomically transitions stale `'reserved'` `gateway_requests` to `'released'` and restores `gateway_reservations.allocated`** when expiry/terminal preconditions hold, and leaves `'handed_off'` or locked rows untouched) -> parent `quota_reservations` (if child, `FOR NO KEY UPDATE SKIP LOCKED` in sweep / `FOR NO KEY UPDATE` on explicit release) -> target `quota_reservations` (`FOR NO KEY UPDATE SKIP LOCKED` in stale sweep, `FOR NO KEY UPDATE` on explicit abort/release). Whenever `gateway_request_id IS NOT NULL`, `quota_release_unsent` **explicitly re-verifies `(q.scope_id, q.actor_user_id) = (qr.scope_id, qr.actor_user_id) AND q.run_id IS NOT DISTINCT FROM qr.run_id` under lock before mutating either ledger** (raising an invariant error and mutating neither ledger on mismatch). If unwinding an unsent child hold back to an active `held` parent run hold, transfer `held_units` back to parent (`quota_budgets` delta = `0`); otherwise lock charged `quota_budgets` via `quota_reservation_charges` (scope rows asc, instance row last) -> insert `quota_reconciliations` -> update reservation (`closed_at = clock_timestamp()`) and budget balances. Separately, `openmettle.quota_release_orphan_gateway_requests(...)` captures `v_age_cutoff := clock_timestamp() - p_max_reserved_age` once in PL/pgSQL, clamps scalar `v_upper_created_at` and `v_upper_id` via `IF (p_pass_upper_created_at, p_pass_upper_id) <= (v_age_cutoff, 'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid) THEN ... ELSE ... END IF;`, materializes a bounded page of at most `p_page_size` raw `(created_at, id)` index keys from `gateway_requests_reserved_idx` using only constant PL/pgSQL bounds (zero `clock_timestamp()` inside the `SELECT`), filters binding absence and run eligibility only on those keys, locks `(runs ->) gateway_reservations -> gateway_requests` (`FOR NO KEY UPDATE SKIP LOCKED`) for eligible orphans, and advances the persistent cursor across pages even when a page contains zero orphans. |
| Storage upload reservation (`openmettle_api` / `openmettle_worker`) | `runs` (if run-linked, `FOR NO KEY UPDATE`) -> `storage_volume_control` via `SELECT openmettle.storage_lock_pinned_volume()` (or non-locking `SELECT volume_id, adoption_run_id` solely during unpinned `volume_id IS NULL AND adoption_run_id IS NULL` `openmettle_api` rolling upgrade; `openmettle_worker` always calls `storage_lock_pinned_volume()`) -> `storage_accounts` (`FOR UPDATE`) -> non-locking `SELECT` on `storage_reservations`, `artifacts`, `quota_overrides` -> `storage_instance` (`FOR UPDATE`) -> insert `storage_reservations` (setting `lease_expires_at` and optionally `stage_claimed = true`) -> update `storage_accounts` then `storage_instance` -> call `quota_record_storage_warning(...)`. |
| Storage staging, `linkat` publication & upload settlement (`Store::stage`, `Store::publish`, ADR 0039 5-step `publish_bytes`, `storage::settle`) | **HTTP `Store::stage` / `Store::publish` (`openmettle_api`):** (Step 1a) short lock-ordered primary tx `(runs FOR NO KEY UPDATE ->) storage_reservations FOR UPDATE` -> `SELECT openmettle.storage_lock_pinned_volume()` when pinned (or non-locking `SELECT volume_id, adoption_run_id` while `volume_id IS NULL AND adoption_run_id IS NULL`) commits `SET stage_claimed = true WHERE scope_id = $1 AND id = $2 AND state = 'reserved' AND NOT adoption_unverified AND NOT stage_claimed AND payload_ino IS NULL AND reclaim_state = 'none'`; (Step 1b) re-verify `<root>`, `"staging"`, `"revisions"` directory FDs (+ sentinels when pinned), `openat(&staging_dir_fd, id, OFlags::CREATE \| OFlags::EXCL \| OFlags::RDWR \| OFlags::NOFOLLOW)` (`0` bytes) -> `LOCK_SH` (`try_lock_shared()`) -> verify `file_meta` vs `statat` (`S_ISREG`, local `st_dev` match, `staged_ino = file_meta.ino()`) -> **`fsync(&staging_dir_fd)`**; (Step 1c) short lock-ordered `FOR UPDATE` tx (`storage_reservations FOR UPDATE` -> `storage_lock_pinned_volume()` when pinned) commits write-once `SET payload_ino = $3::text::numeric(20, 0)` leaving **`publish_pending = false`** while streaming. **ADR 0039 worker 5-step `publish_bytes` (`openmettle_worker`, always pinned):** (Step 1) create `0`-byte `staging/<id>` (`create_new(true)`), acquire continuous `LOCK_EX`, `fsync(&staging_dir_fd)`, bind write-once `stage_claimed = true, payload_ino = COALESCE(payload_ino, $3)` via `storage_lock_pinned_volume()` leaving **`publish_pending = false`** while empty; (Step 2) write payload + verify `actual_size == reserved_bytes` & SHA-256 + `file.sync_all()` under continuous `LOCK_EX`; (Step 3) still holding `LOCK_EX`, re-stat `fd` (`st_size == reserved_bytes`) & `statat(&staging_dir_fd, id)` (`st_ino == payload_ino`), execute `SELECT openmettle.storage_lock_pinned_volume(); UPDATE openmettle.storage_reservations SET publish_pending = true WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved' AND NOT adoption_unverified AND reclaim_state = 'none' AND payload_ino = $3 RETURNING id;` (failing strictly BEFORE `linkat` if adoption started with `OMQ03` or a cleaner claimed `reclaim_state <> 'none'` during Step 2!); (Step 4) still holding `staged_fd` (`LOCK_EX`), execute `rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id, AtFlags::empty())` + `fsync(&revisions_dir_fd)` + post-`linkat` re-verify and **carry `staged_fd` (`LOCK_EX`) into Step 5** without dropping it; (Step 5) execute a **single atomic `Fence::Step` `WriteTransaction` committing BOTH `storage::settle` (`state = 'settled', publish_pending = false`, retaining `payload_ino`) AND `runs::record_observation`**, dropping `staged_fd` (`LOCK_EX`) **only AFTER** that `Fence::Step` transaction commits, followed by post-commit best-effort `LOCK_SH` `unlinkat(&staging_dir_fd, id)` (`OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + immediate `is_file()`, never `set_len(0)`) + `fsync(&staging_dir_fd)`. **`StagedFile::drop` & all writer errors:** 100% non-destructive (NEVER `set_len(0)` or `unlinkat`). **Pre-`linkat` publication marker (`Store::publish`) & `storage::settle`:** short lock-ordered `FOR UPDATE` tx commits `SET publish_pending = true` under `storage_lock_pinned_volume()` (when pinned) strictly before `linkat` (quarantining on `Errno::EXIST`), then `fsync(&revisions_dir_fd)` + post-`linkat` re-verify -> `storage::settle`: `projects` (if authorized in tx) -> `storage_reservations` (`FOR UPDATE`, requiring `state = 'reserved' AND NOT adoption_unverified AND payload_ino = $staged_ino AND reclaim_state = 'none'`) -> `artifacts` (`FOR UPDATE`) -> insert `artifact_revisions` -> update `storage_reservations` (`SET state = 'settled', publish_pending = false`, **retaining `payload_ino`**) -> `storage_accounts` -> `storage_instance` -> post-commit best-effort `LOCK_SH` `unlinkat(&staging_dir_fd, id)` (`OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + immediate `is_file()`, NEVER `set_len(0)`!) -> `drop(file)` -> `fsync(&staging_dir_fd)`. On ambiguous `storage::settle` commit, inspect `storage_reservations.state` under lock first rather than calling `artifact_fs::abort` blindly. |
| Storage retention and 3-stage inode-preserving purge (`storage::retain_revision`, `restore_revision`, `begin_purge`, `artifact_fs::purge_due`, `confirm_purge`) | `storage::retain_revision` and `restore_revision`: `artifact_revisions` (`FOR UPDATE`) -> `storage_accounts` (`FOR UPDATE`) -> `storage_instance` (`FOR UPDATE`). `storage::begin_purge` joins `storage_reservations` requiring `NOT adoption_unverified AND payload_ino IS NOT NULL` and sets `state = 'purging', purge_stage = 'none'` (firing `enforce_runtime_storage_volume_pinned()`, which calls `storage_lock_pinned_volume()` acquiring `storage_volume_control FOR SHARE` as `openmettle_owner`). **Stage A (`purge_due`, keeping `revisions/.purge.<id>` linked with `nlink >= 1` so `payload_ino` never recycles before `confirm_purge`):** verify `storage_lock_pinned_volume()` + sentinels -> probe `revisions/.purge.<id>` (else `revisions/<id>`; stop immediately with ZERO `set_len(0)`/`unlinkat` and NO `confirm_purge` if both `ENOENT` or foreign/non-regular/wrong-`st_dev`/wrong-`st_ino`) -> open `OFlags::RDWR \| OFlags::NOFOLLOW` (without `OFlags::TRUNC`) -> `LOCK_EX` (`try_lock()`) -> re-verify `fstat` + `statat` -> revalidate `storage_lock_pinned_volume()` + `artifact_revisions.state = 'purging'` -> `set_len(0)?` + `sync_all()?` -> ensure `revisions/.purge.<id>` via `linkat` (verify `st_ino == payload_ino` on `EEXIST`) -> **unconditional `fsync(&revisions_dir_fd)?` strictly BEFORE unlinking `revisions/<id>`** -> under continuous `LOCK_EX`, unlink matching-inode `revisions/<id>` and matching-inode `staging/<id>` (leaving foreign entries untouched) -> **unconditional dual `fsync(&revisions_dir_fd)` + `fsync(&staging_dir_fd)`** -> drop `LOCK_EX` (`.purge.<id>` stays linked!). **Stage B (`storage::confirm_purge`):** `artifact_revisions` (`FOR UPDATE`, setting `state = 'purged', purged_at = now(), purge_stage = 'anchor_pending_unlink'` and firing `enforce_runtime_storage_volume_pinned()` -> `storage_lock_pinned_volume()`) -> `storage_accounts` (`FOR UPDATE`) -> `storage_instance` (`FOR UPDATE`). **Stage C (immediate + bounded DB pass over `artifact_revisions_purge_anchor_idx` with wrapping keyset cursor `purge_anchor_cursor: Option<(DateTime<Utc>, Uuid)>` paired with pass-start fixed upper watermark `purge_anchor_pass_upper: Option<(DateTime<Utc>, Uuid)>`, constraining every page by `AND (r.purged_at, r.id) <= ($3::timestamptz, $4::uuid)`, advancing past every inspected key, and resetting BOTH cursor and pass-upper to `None` on `< LIMIT` OR reaching `(upper_ts, upper_id)`):** under `LOCK_EX` (**`OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC`**, verifying `st_ino == payload_ino` & `st_size == 0`, **never `set_len(0)`**), `unlinkat(&revisions_dir_fd, ".purge.<id>")` -> `drop` -> `fsync(&revisions_dir_fd)` -> `UPDATE artifact_revisions SET purge_stage = 'none' WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'purged' AND purge_stage = 'anchor_pending_unlink'` (`ENOENT` -> `fsync(&revisions_dir_fd)` + `SET purge_stage = 'none'`). |
| Storage release (`artifact_fs::abort`, non-run `reconcile_expired`, generic run-linked `storage_reservations` recovery, and ADR 0039 `reconcile_run_spills`) | **Unified 4-step reclamation protocol with `staging/.reclaim.<id>` anchor & fenced Step 2a shared by ALL 4 cleaners (ZERO FS I/O inside DB txs in Steps 1 & 3; `payload_ino` NEVER drops to `nlink = 0` before Step 3 commits; every `LOCK_EX` descriptor opened with `OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC` for Linux NFS `F_WRLCK` compatibility):** **Step 1 (Serialized DB Claim):** lock `(runs FOR NO KEY UPDATE [SKIP LOCKED] ->) storage_reservations FOR UPDATE [SKIP LOCKED]` -> `SELECT openmettle.storage_lock_pinned_volume()` (verifying `v_vol == $expected_volume_id`, else abort `OMQ03`), requiring `state = 'reserved' AND NOT adoption_unverified AND (reclaim_state = 'none' OR reclaim_lease_until <= clock_timestamp())` (+ path preconditions), committing `reclaim_state = CASE WHEN reclaim_state = 'truncated' THEN 'truncated' ELSE 'claiming' END, reclaim_claim_token = $my_token, reclaim_lease_until = clock_timestamp() + interval '60 seconds'`. **Step 2 (Fenced Step 2a Lease Revalidation Under `LOCK_EX`, Durable `0`-Byte Truncation & `staging/.reclaim.<id>` Anchor — NEVER clearing `payload_ino`):** verify sentinels + local `st_dev`. *Case 1a (`payload_ino IS NOT NULL`, `'claiming'`):* probe **`staging/.reclaim.<id>` first** (covering crash after `linkat`+`unlinkat` before SQL `'truncated'`), else `staging/<id>` (and check `revisions/<id>`); any foreign/non-regular/different-`st_dev`/`st_ino != payload_ino` OR all-three `ENOENT` -> ZERO `set_len(0)`/`unlinkat`, quarantine (`adoption_unverified = true, publish_pending = false, reclaim_state = 'none', reclaim_claim_token = NULL, reclaim_lease_until = NULL`) under `FOR UPDATE` + `storage_lock_pinned_volume()`; exact match -> open `OFlags::RDWR \| OFlags::NOFOLLOW` (no `OFlags::TRUNC`) -> **`LOCK_EX` (`try_lock()`)** -> re-verify `fstat` + `statat` -> **Step 2a (while CONTINUING to hold `LOCK_EX`, strictly BEFORE `set_len(0)`/`linkat`/`unlinkat`):** execute fenced DB tx `SELECT openmettle.storage_lock_pinned_volume(); UPDATE openmettle.storage_reservations SET reclaim_lease_until = clock_timestamp() + interval '300 seconds' WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved' AND NOT adoption_unverified AND payload_ino = $3 AND reclaim_state = 'claiming' AND reclaim_claim_token = $4::uuid RETURNING id;` (if `0` rows returned or volume mismatch, **abort immediately and drop FD with ZERO `set_len(0)`/`linkat`/`unlinkat`**!) -> (1) `probe_file.set_len(0)?` + `probe_file.sync_all()?` -> (2) create/verify hard-link anchor `staging/.reclaim.<id>` via `linkat` (verifying `S_ISREG`/`st_dev`/`st_ino == payload_ino` on `EEXIST`) -> **UNCONDITIONAL `fsync(&staging_dir_fd)?` for BOTH newly created AND recovered anchors strictly BEFORE unlinking `<id>`** -> (3) unlink matching-inode `revisions/<id>` and `staging/<id>` + dual `fsync` -> (4) keeping `LOCK_EX` held on `probe_file`, commit `reclaim_state = 'truncated', publish_pending = false` via `storage_lock_pinned_volume()`. *Case 1b (`payload_ino IS NOT NULL`, `'truncated'`):* probe `staging/.reclaim.<id>` ONLY -> open **`OFlags::RDWR \| OFlags::NOFOLLOW` (without `OFlags::TRUNC`, zero `set_len(0)`)** -> `LOCK_EX` -> re-verify -> Step 2a claim revalidation (`reclaim_state = 'truncated' AND reclaim_claim_token = $my_token`) -> dual `fsync` -> Step 3 keeping `LOCK_EX`. *Case 2 (`payload_ino IS NULL`):* any `revisions/<id>`, `staging/.reclaim.<id>`, or non-regular/wrong-`st_dev`/`st_size > 0` `staging/<id>` -> quarantine; `0`-byte regular `staging/<id>` on `store.root_dev` with `revisions/<id>` and `staging/.reclaim.<id>` `ENOENT` -> open **`OFlags::RDWR \| OFlags::NOFOLLOW` (without `OFlags::TRUNC`, zero `set_len(0)`)** -> `LOCK_EX` -> re-verify `S_ISREG`, `st_dev == store.root_dev`, `st_size == 0`, `statat` `(fd_dev, fd_ino)` match, and `revisions/<id>`/`staging/.reclaim.<id>` `ENOENT` -> **Step 2a SQL UNDER `LOCK_EX` atomically binding `stage_claimed = true, payload_ino = fd_ino`** (`SELECT openmettle.storage_lock_pinned_volume(); UPDATE openmettle.storage_reservations SET stage_claimed = true, payload_ino = $3, reclaim_lease_until = clock_timestamp() + interval '300 seconds' WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved' AND NOT adoption_unverified AND payload_ino IS NULL AND reclaim_state = 'claiming' AND reclaim_claim_token = $4::uuid RETURNING id;`, aborting with ZERO FS mutations on `0` rows/`OMQ03`!) -> still holding `LOCK_EX`, promote directly into the standard `.reclaim.<id>` anchor sequence (`linkat` -> unconditional `fsync(&staging_dir_fd)?` -> `unlinkat` `staging/<id>` -> dual `fsync` -> commit `reclaim_state = 'truncated', publish_pending = false` -> Step 3 `'anchor_pending_unlink'` -> Step 4; leaving `payload_ino` `NULL` through Step 3 **ONLY** when all three names are already `ENOENT`, with **ZERO `unlinkat` calls**!). **Step 3 (Final `storage::release` — ZERO FS I/O inside DB tx):** lock `(runs ->) storage_reservations`, verify `state = 'reserved' AND NOT adoption_unverified AND NOT publish_pending AND reclaim_claim_token = $my_token AND (payload_ino IS NULL OR reclaim_state = 'truncated')`, set `reclaim_state = CASE WHEN payload_ino IS NOT NULL THEN 'anchor_pending_unlink' ELSE 'none' END, reclaim_claim_token = NULL, reclaim_lease_until = NULL`, and commit `storage::release` (trigger calls `storage_lock_pinned_volume()` -> `adjust()` updates `storage_accounts FOR UPDATE -> storage_instance FOR UPDATE`, retaining `payload_ino`). **Step 4 (Post-release `LOCK_EX` detach + bounded DB pass over `storage_reservations_reclaim_anchor_idx` with wrapping keyset cursor `reclaim_anchor_cursor: Option<(DateTime<Utc>, Uuid)>` paired with pass-start fixed upper watermark `reclaim_anchor_pass_upper: Option<(DateTime<Utc>, Uuid)>`, constraining every page by `AND (closed_at, id) <= ($3::timestamptz, $4::uuid)`, advancing past every inspected key, and resetting BOTH cursor and pass-upper to `None` on `< LIMIT` OR reaching `(upper_ts, upper_id)`):** under `LOCK_EX` (**`OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC`**, verifying `st_ino == payload_ino` & `st_size == 0`, **never `set_len(0)`**), `unlinkat(&staging_dir_fd, ".reclaim.<id>")` -> `drop` -> `fsync(&staging_dir_fd)` -> `SET reclaim_state = 'none' WHERE id = $1::uuid AND state = 'released' AND reclaim_state = 'anchor_pending_unlink'` (with bounded DB-driven retry across ALL reservation kinds handling `ENOENT` -> `fsync(&staging_dir_fd)` + `SET reclaim_state = 'none'`). |
| Storage volume adoption, fresh-bootstrap auto-pinning & zero-truncation `StagingSweepState` (`openmettle-admin` / API `Store::open` / `openmettle_worker`) | For `openmettle-admin` adoption: mint `my_adoption_run_id = uuid_v4()`. **Step 1b (strictly BEFORE Step 2 pre-scan):** short `openmettle_owner` tx locking ONLY `storage_volume_control WHERE id FOR UPDATE` (conflicting directly with `storage_lock_pinned_volume()` `FOR SHARE`), setting `adoption_run_id = $my_adoption_run_id` (`OMQ03` if already set unless `--replace-adoption-run` matches). **Step 2:** scan `<root>/revisions` and `<root>/staging` outside DB locks; for every `'reserved'` row with `payload_ino IS NULL` whose on-disk file (`staging/<id>`, `staging/.reclaim.<id>`, or `revisions/<id>`) is a backfill candidate, open `OFlags::RDWR \| OFlags::NOFOLLOW` (no `OFlags::TRUNC`), acquire non-blocking `try_lock()` (`LOCK_EX \| LOCK_NB`; `WouldBlock` -> Step 3 clears `adoption_run_id = NULL` without quarantining/backfilling and returns retryable `OMQ03`), re-verify `fstat` + `statat`, and hold that `LOCK_EX` descriptor continuously through Phase 3C commit. **Step 3:** lock `storage_reservations` (`ORDER BY id ASC FOR UPDATE`) -> `artifact_revisions` (`ORDER BY id ASC FOR UPDATE`) -> `storage_volume_control` (`WHERE id FOR UPDATE`, requiring `adoption_run_id = $my_adoption_run_id`) -> `storage_accounts` (`ORDER BY scope_id ASC FOR UPDATE`) -> `storage_instance` (`WHERE id FOR UPDATE`). **Phase 3A** enforces **cross-reservation live inode uniqueness** (`ino(R1) <> ino(R2)`) strictly across live payloads, surviving anchors, and backfill/unquarantine candidates — `artifact_revisions` (`'active'`/`'retained'`/surviving `'purging'`/`'purged'`+`anchor_pending_unlink`) AND `storage_reservations` (`(state = 'reserved' AND (payload_ino IS NOT NULL OR candidate for payload_ino backfill / adoption_unverified = false clearance — explicitly INCLUDING previously quarantined adoption_unverified = true rows present on disk))` OR `(state = 'released' AND reclaim_state = 'anchor_pending_unlink')`), **explicitly EXCLUDING retired historical rows** (`(state = 'released' AND reclaim_state = 'none')` AND `'settled'` rows whose revision is `(state = 'purged' AND purge_stage = 'none')`) — failing closed with `cross_reservation_inode_alias` or `intra_reservation_inode_mismatch` with zero `payload_ino` backfills!, accepts valid crash-boundary states (`'claiming'`+`.reclaim.<id>`, `'truncated'`+`.reclaim.<id>` requiring `staging/<id>` and `revisions/<id>` `ENOENT`, post-upgrade `sr.payload_ino IS NOT NULL` `'purging'` with `size_bytes`/`0`-byte `revisions/<id>` or `0`-byte `revisions/.purge.<id>`, `'purged'`+`anchor_pending_unlink`+`.purge.<id>`, plus legacy `sr.payload_ino IS NULL` `'purging'` Case 6a requiring **exact recorded `(size_bytes, content_digest)`** and rejecting `st_size == 0` on `size_bytes > 0` with `size_or_digest_mismatch` & Case 6b absent-file completion never counting as positive on-disk evidence); **Phase 3C (success branch ONLY)** commits `payload_ino` backfills **strictly ONLY onto positively verified non-quarantined rows** (never onto rows staying `adoption_unverified = true`), legacy `'purging'` Case 6a backfills & Case 6b atomic `purged` completion + `retained_bytes` decrement, **keeps `'claiming'` as `'claiming'` with expired `reclaim_lease_until = clock_timestamp()`** (NEVER promoting `'claiming'` to `'truncated'`), expires `'truncated'` lease, quarantines missing/mismatched `'reserved'` rows, publishes sentinels, pins `volume_id`, and clears `adoption_run_id = NULL`. For **API `Store::open` (`openmettle_api` ONLY)** fresh-bootstrap auto-pinning (`openmettle_worker` never initializes sentinels or calls `storage_pin_volume_id`): non-locking `SELECT` precheck -> sentinel publication (`:root` + `fsync` -> `:revisions`/`:staging` + dual `fsync`) -> `SELECT openmettle.storage_pin_volume_id($sentinel_uuid)` (acquiring `storage_volume_control FOR UPDATE` **internally** as `openmettle_owner`; API `Store::open` never issues raw invoker `FOR UPDATE`). For **zero-truncation `StagingSweepState`** (ZERO `set_len(0)` calls in ANY branch!): open **`OFlags::RDWR \| OFlags::NOFOLLOW` (without `OFlags::TRUNC`, preserving zero `set_len(0)`)** -> `LOCK_EX` (`try_lock()`) -> re-verify `fstat` + `statat` -> serialize in PostgreSQL (`SELECT openmettle.storage_lock_pinned_volume()` -> `SELECT FROM openmettle.storage_instance FOR NO KEY UPDATE` -> re-check `storage_reservations` row state) -> **`unlinkat` STRICTLY WITHOUT `set_len(0)`** -> `drop` -> `fsync(&staging_dir_fd)`. All three serialize cleanly with zero deadlock. |
| Override write (`openmettle_api` via `quota_upsert_scope_override` / `quota_revoke_scope_override`, `ManageQuotas`) | Inside `SECURITY DEFINER`: if `resource_kind IN ('executing_runs_per_actor', 'executing_runs_per_scope')`, acquire `run_dispatch_lock` (`FOR NO KEY UPDATE`) first -> target entity row (`projects` `FOR NO KEY UPDATE` for project scopes; personal owner `users` `FOR NO KEY UPDATE` for personal/actor scopes) -> if `storage_bytes`, `storage_accounts` (`FOR UPDATE`); if metered usage/device, current active `quota_budgets` (`FOR NO KEY UPDATE`, ascending) -> upsert/revoke `quota_overrides` (incrementing `revision` to re-arm warning watermarks); then caller inserts `authorization_audit` in the same transaction. Live-run and round-cap kinds (`live_runs_*`, `round_cap`) serialize on `projects`/`users` matching `lock_scope_actor`; `openmettle_owner` updates to `executing_runs_*` rows in `quota_defaults` also acquire `run_dispatch_lock` (`FOR NO KEY UPDATE`) first so default cap changes serialize with `claim_next`. |

During `quota_reserve` and `quota_ensure_legacy_run_holds`, the idempotency / existing-parent
lookup performs a non-locking `SELECT` on `quota_reservations` (matching `src/storage.rs`), so
neither ever waits on a pre-existing reservation row while holding a budget lock. `settle`,
`allocate_round` (requiring parent holds to exist before `reserve_in`), `commit_handoff`,
`commit_device_handoff`, `recover_lost_handoff`, `unwind_superseded_round` and `release` always
lock the run, gateway and reservation rows before budget rows. For gateway usage settlement,
`quota_settle_gateway_usage` operates strictly on `'handoff_committed'` / `'settled'` holds and
**never locks `runs`, `gateway_bindings`, `gateway_reservations`, or `gateway_settlements`** —
its lock sequence is strictly `gateway_requests` (`FOR KEY SHARE`) -> `quota_reservations`
(`ORDER BY resource_kind ASC FOR UPDATE`) -> `quota_budgets` (`FOR NO KEY UPDATE`). **Every**
`openmettle_gateway` write transaction that inserts or updates `openmettle.gateway_settlements` —
**both** settlement-only transactions **and** combined single-transaction writes
(`gateway_settlements` upsert + `quota_settle_gateway_usage`) — MUST call
`openmettle.quota_lock_gateway_request_for_settlement(p_request_id)` (`FOR NO KEY UPDATE` on
`gateway_requests`, and `(runs ->) gateway_reservations` first if any caller ever touches upstream
rows) strictly **before** `INSERT`/`UPDATE` on `gateway_settlements` (whose `AFTER INSERT OR
UPDATE` trigger appends to `quota_accepted_gateway_reports`), so Migration `0023`'s
`gateway_mark_settled_final()` (`UPDATE gateway_requests SET settled_final = true`) re-uses the
already-held `FOR NO KEY UPDATE` lock on `gateway_requests`, eliminating any lock cycle across
settlement-only writers, combined writers, and `runs -> gateway_reservations -> gateway_requests`
recovery. Storage operations follow the strict canonical lock order `runs -> storage_reservations
-> artifacts -> artifact_revisions -> storage_volume_control [via storage_lock_pinned_volume()] ->
storage_accounts -> storage_instance`: neither `openmettle_api` nor `openmettle_worker` has ANY
`UPDATE` privilege on `openmettle.storage_volume_control` (`SELECT` only), so runtime `reserve`,
`settle`, `release`, `purge`, and `StagingSweepState` **NEVER execute raw invoker `SELECT ... FOR
SHARE` or `FOR UPDATE` on `storage_volume_control`** (which PostgreSQL 18 would reject with
`42501`); instead they invoke `SELECT openmettle.storage_lock_pinned_volume()` (`SECURITY
DEFINER`, owned by `openmettle_owner`, acquiring `FOR SHARE` and failing closed with `OMQ03` on
missing row, `volume_id IS NULL`, or `adoption_run_id IS NOT NULL`), while `storage::adjust`
(`src/storage.rs:289-310`) updates `storage_accounts -> storage_instance` (`FOR NO KEY UPDATE`)
strictly afterward without any prior `FOR SHARE` on `storage_instance` — so concurrent releases,
reserves, and purges **NEVER deadlock**. Only `openmettle-admin` adoption (Step 1b locking ONLY
`storage_volume_control FOR UPDATE`; Step 3 locking `storage_reservations` ascending `id` ->
`artifact_revisions` ascending `id` -> `storage_volume_control FOR UPDATE` -> `storage_accounts`
ascending `scope_id` -> `storage_instance FOR UPDATE`) and API-only `SECURITY DEFINER`
`openmettle.storage_pin_volume_id(uuid)` (granted `EXECUTE` to `openmettle_api` ONLY; acquiring
`storage_volume_control FOR UPDATE` internally as `openmettle_owner` during one-time empty-ledger
API `Store::open` fresh-bootstrap auto-pinning) acquire `FOR UPDATE` on `storage_volume_control`.
`enforce_cost_denomination_immutability` never acquires `quota_cost_unit_lock` during `INSERT` or
rename (only under `BEFORE UPDATE` after the `quota_defaults` row lock is already held),
`enforce_gateway_report_cost_unit` never locks `quota_defaults` (only `quota_cost_unit_lock`),
`SECURITY INVOKER` `enforce_runtime_storage_volume_pinned` evaluates `NOT
pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')` as the invoker and delegates to
`PERFORM openmettle.storage_lock_pinned_volume()` while the caller holds `storage_reservations` or
`artifact_revisions` `FOR UPDATE` (strictly preserving canonical lock order `... ->
storage_reservations / artifact_revisions -> storage_volume_control [via
storage_lock_pinned_volume()] -> storage_accounts -> storage_instance`, succeeding without `42501`
on a healthy pinned volume, failing closed with `OMQ03` on missing singleton row or `volume_id IS
NULL OR adoption_run_id IS NOT NULL`, and serializing directly against Step 1b's standalone
`storage_volume_control FOR UPDATE` with zero deadlock cycle;
`enforce_storage_reservation_monotonic_guards` acquires zero additional locks), and
`enforce_gateway_handoff_holds()` inserts into `openmettle.quota_gateway_handoffs` (referencing
the already-`FOR UPDATE`-locked `gateway_requests` row) **before** acquiring **`FOR SHARE`** on
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
`gateway_reservations`, `gateway_requests`, `gateway_settlements` or
`quota_accepted_gateway_reports`, making the global lock graph strictly acyclic. If a caller
composes multiple unrelated owners and PostgreSQL reports SQLSTATE `40P01`, the caller rolls back
the whole transaction and retries with identical idempotency keys.

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
`quota_budgets.active_used`, and `quota_budgets.reserved_held`. Furthermore, **every**
`openmettle_gateway` write transaction that inserts or updates `openmettle.gateway_settlements` —
**both** settlement-only transactions **and** combined single-transaction writes — MUST call
`openmettle.quota_lock_gateway_request_for_settlement(p_request_id)` (`SELECT 1 FROM
openmettle.gateway_requests WHERE id = $1::uuid FOR NO KEY UPDATE`) strictly before `INSERT` or
`UPDATE` on `gateway_settlements` (preserving the global acyclic DAG `runs -> gateway_reservations
-> gateway_requests -> gateway_settlements -> quota_accepted_gateway_reports -> quota_reservations
-> quota_budgets`), and must advance `openmettle.gateway_settlements` first (in the same
transaction or in a prior committed transaction) so `AFTER INSERT OR UPDATE OF revision, final`
trigger `quota_record_accepted_gateway_settlement` durably records every accepted `(request_id,
revision, final)` in append-only `openmettle.quota_accepted_gateway_reports`. Inside `openmettle.quota_settle_gateway_usage(...)`, the function locks strictly
`gateway_requests` (`FOR KEY SHARE`) -> `quota_reservations` (`ORDER BY resource_kind ASC FOR
UPDATE`) -> charged `quota_budgets` (`FOR NO KEY UPDATE`) (never locking `runs`,
`gateway_bindings`, `gateway_reservations`, or `gateway_settlements`), verifies `(p_report_source,
p_report_id, p_source_revision)` matches `openmettle.gateway_usage_reports` for
`qr.gateway_request_id` AND **`EXISTS (SELECT 1 FROM openmettle.quota_accepted_gateway_reports a
WHERE a.request_id = qr.gateway_request_id AND a.revision = p_source_revision)`**. Consequently:
(i) any report stored in `gateway_usage_reports` but rejected by `gateway_settlements`
(`gateway_advance_settlement`, such as a late partial `revision = 3` stored after final `revision =
2`) is absent from `quota_accepted_gateway_reports` and rejected; and (ii) settlement is
**strictly deterministic and order-independent**:

- **Idempotent replay & deterministic ascending revision fold:** If `qr.accepted_source_revision IS
  NOT NULL AND p_source_revision <= qr.accepted_source_revision`, `quota_settle_gateway_usage`
  returns an idempotent no-op immediately. Otherwise, **instead of evaluating `p_source_revision` in
  isolation**, `quota_settle_gateway_usage` queries **all unapplied accepted revisions `a.revision`
  in `(coalesce(qr.accepted_source_revision, -1), p_source_revision]`**:
  ```sql
  SELECT r_step.*
    FROM openmettle.quota_accepted_gateway_reports a
    JOIN openmettle.gateway_usage_reports r_step
      ON r_step.request_id = a.request_id
     AND r_step.revision = a.revision
     AND r_step.final = a.final
   WHERE a.request_id = qr.gateway_request_id
     AND a.revision > coalesce(qr.accepted_source_revision, -1)
     AND a.revision <= p_source_revision
   ORDER BY a.revision ASC
  ```
  and **folds each `r_step` sequentially in ascending revision order** (likewise, worker catch-up
  reconciliation iterates pending accepted revisions in `ORDER BY a.revision ASC`). For example, on
  hold `H = 200` with `rev 1`: `prompt_tokens = 60, completion_tokens = 20, final = true` and
  `rev 2`: `prompt_tokens = NULL, completion_tokens = 25, final = true`:
  - calling `rev 1` then `rev 2` folds `[1]` -> `('settled', settled = 80, held = 0,
    accepted_source_revision = 1)` then `[2]` -> **`('settled', settled = 85, held = 0,
    accepted_source_revision = 2)`**;
  - calling `rev 2` **first** folds `[1, 2]` in ascending order inside
    `quota_settle_gateway_usage(..., 2)`: step `1` closes to `('settled', 80, 0)`, step `2` applies
    the monotonic post-final upward adjustment to **`('settled', settled = 85, held = 0,
    accepted_source_revision = 2)`**, and a subsequent call with `rev 1` (`1 <= 2`) is an
    idempotent no-op. Both call orderings end at the exact same `(state = 'settled', settled_units
    = 85, held_units = 0)`.
- **Unconditional `accepted_source_revision` advancement (including 0-delta / no-op /
  other-resource reports):** After folding through `p_source_revision` — **including** an
  incomplete post-final report whose `C_effective <= qr.settled_units` (such as an unchanged
  `completion_tokens = 25` repeat), an incomplete open report within already-settled units, or a
  single-resource report (`r_step.cost IS NULL` on `usage_cost_micros` / all-`NULL` tokens on
  `usage_tokens`) — `quota_settle_gateway_usage` **unconditionally advances
  `qr.accepted_source_revision = p_source_revision`** on `openmettle.quota_reservations`, while
  writing a `quota_reconciliations` row and adjusting `quota_budgets` + `quota_warning_events`
  **iff `(new_state, new_settled, new_held) IS DISTINCT FROM (old_state, old_settled, old_held)`**!
  Processed no-op and single-resource accepted reports therefore clear
  `pending_gateway_reconciliations` immediately instead of aging forever.

Per-resource authoritative evidence rules for each folded step `r_step` at `r_eval_rev =
r_step.revision` in `quota_settle_gateway_usage` (and replayed identically in
`quota_verify_accounting_drift()`):

- **`usage_cost_micros`:** authoritative cost evidence requires **`r_step.cost IS NOT NULL`** (with
  `r_step.unit = cost_denomination`), computing **`C_cost = ceil(r_step.cost)::numeric(38, 0)`**
  directly from cumulative `r_step.cost` (ceiling toward `+infinity`, never rounding incremental
  deltas; `0 -> 0`, `0.5 -> 1`, zero sub-micro-unit free-spend leakage). Whenever **`r_step.cost IS
  NULL`** (token-only partial, final, or post-final correction report), the fold step leaves
  `state`, `held_units`, and `settled_units` unchanged while still advancing
  `accepted_source_revision` through `p_source_revision` at the end of the fold.
- **`usage_tokens`:** across accepted revisions `a.revision <= r_eval_rev` in
  `openmettle.quota_accepted_gateway_reports a JOIN openmettle.gateway_usage_reports gr ON
  gr.request_id = a.request_id AND gr.revision = a.revision AND gr.final = a.final WHERE
  a.request_id = qr.gateway_request_id`, define the cumulative known token components
  (`numeric(38, 0)`):
  - **`P_known`:** `gr.prompt_tokens::numeric(38, 0)` from the highest accepted revision `<=
    r_eval_rev` where `gr.prompt_tokens IS NOT NULL` (else `0::numeric(38, 0)`).
  - **`K_raw` & `rev_K`:** `gr.completion_tokens::numeric(38, 0)` from the highest accepted
    revision `<= r_eval_rev` where `gr.completion_tokens IS NOT NULL` (else `0::numeric(38, 0)`
    with `rev_K = -1`).
  - **`(R_latest, inc_latest, rev_R)`:** `(gr.reasoning_tokens::numeric(38, 0),
    gr.reasoning_included, gr.revision)` from the highest accepted revision `<= r_eval_rev` where
    `gr.reasoning_tokens IS NOT NULL` (if any):
    - If no revision `<= r_eval_rev` has `gr.reasoning_tokens IS NOT NULL`: **`K_known = K_raw`**,
      **`X_known = 0::numeric(38, 0)`**.
    - If **`inc_latest IS FALSE`** (separate reasoning): **`K_known = K_raw`**, **`X_known =
      R_latest`**.
    - If **`inc_latest IS TRUE`** (included reasoning): **`X_known = 0::numeric(38, 0)`**, and
      **`K_known = CASE WHEN rev_R >= rev_K THEN greatest(K_raw, R_latest) ELSE K_raw END`**!
    This treats included reasoning tokens as a lower bound on completion tokens without ever
    double-counting:
    - on a `100`-token hold with `reasoning_tokens = 150, reasoning_included = true` and
      `prompt_tokens = NULL, completion_tokens = NULL` (`rev_R = 0 >= rev_K = -1`): `P_known = 0,
      K_known = greatest(0, 150) = 150, X_known = 0, C_floor = 150`, immediately charging
      `settled_units = 150, held_units = 0` (`+50` confirmed overage) while keeping
      `is_complete_tokens = false` (`completion_tokens` itself is still `NULL`, so a `final = true`
      report with `prompt_tokens = 60, completion_tokens = NULL, reasoning_tokens = 150,
      reasoning_included = true` charges `210` and stays `'handoff_committed'` until explicit
      `completion_tokens IS NOT NULL` arrives);
    - when `completion_tokens = 200, reasoning_tokens = 150, reasoning_included = true` on the same
      report (`rev_R = rev_K`): `K_known = greatest(200, 150) = 200, X_known = 0` (zero
      double-counting; and on a malformed report with `completion_tokens = 100 < reasoning_tokens =
      150, reasoning_included = true`, `greatest(100, 150) = 150` still protects the confirmed
      `150`-token lower bound);
    - when a newer complete revision (`rev_K > rev_R`) reports `completion_tokens = 120,
      reasoning_tokens = NULL`: `K_known = 120` honors the newer authoritative `completion_tokens`
      measurement.

  Define **complete authoritative token evidence (`is_complete_tokens`)** on an accepted report
  `r_step` at `r_eval_rev` as:
  ```sql
  r_step.prompt_tokens IS NOT NULL
  AND r_step.completion_tokens IS NOT NULL
  AND NOT (
      r_step.reasoning_tokens IS NULL
      AND EXISTS (
          SELECT 1
            FROM openmettle.quota_accepted_gateway_reports a
            JOIN openmettle.gateway_usage_reports prev
              ON prev.request_id = a.request_id
             AND prev.revision = a.revision
             AND prev.final = a.final
           WHERE a.request_id = r_step.request_id
             AND a.revision < r_step.revision
             AND prev.reasoning_tokens IS NOT NULL
             AND prev.reasoning_included IS FALSE
      )
  )
  ```
  (Migration `0023` already enforces `r_step.reasoning_tokens IS NULL OR r_step.reasoning_included IS
  NOT NULL`.) Normatively, `prompt_tokens` and `completion_tokens` **MUST both be explicitly
  non-null on `r_step` itself** (never pieced together across separate partial and incomplete-final
  revisions!). Evaluating each folded step `r_step` at `r_eval_rev` follows three disjoint cases
  (while always advancing `qr.accepted_source_revision = p_source_revision` at the end of the fold):
  1. *Zero token components on `r_step` (`r_step.prompt_tokens IS NULL AND r_step.completion_tokens
     IS NULL AND r_step.reasoning_tokens IS NULL`, e.g., a pure cost-only partial, final, or
     post-final correction report):* leave `state`, `settled_units`, and `held_units` unchanged for
     this step (advancing `qr.accepted_source_revision = p_source_revision` at the end of the fold
     with zero `quota_reconciliations` row or budget delta when unchanged).
  2. *Complete authoritative token evidence (`is_complete_tokens = true`):* compute **`C_tokens =
     P_known + K_known + X_known`** (where `K_known` protects `greatest(completion_tokens,
     reasoning_tokens)` if a malformed report carries `reasoning_included = true` with
     `reasoning_tokens > completion_tokens`, and equals `completion_tokens` otherwise):
     - If `NOT r_step.final` (valid **only** while `state = 'handoff_committed'`): update
       `settled_units = C_tokens`, `held_units = greatest(0::numeric(38, 0),
       qr.reserved_units::numeric(38, 0) - C_tokens)::bigint`, keep **`state =
       'handoff_committed'`** (allowing signed downward partial corrections while preserving full
       open hold exposure and never overwriting an already-`'settled'` row).
     - If `r_step.final = true`: update `settled_units = C_tokens`, `held_units = 0`, transition
       **`state = 'settled'`** with `closed_at = coalesce(closed_at, now())` (including explicit
       `prompt_tokens = 0, completion_tokens = 0` zero-token final proof when no prior non-included
       reasoning tokens were omitted), or apply a signed post-final authoritative correction on an
       already-`'settled'` row.
  3. *Partial/incomplete token evidence with `>= 1` non-null token component on `r_step` (`NOT
     is_complete_tokens`, **even if `r_step.final = true`!**):* compute the component-aware
     monotonic lower bound **`C_floor = P_known + K_known + X_known`** (`numeric(38, 0)`) and
     **`C_effective = greatest(cur_settled, C_floor)`**:
     - While `state = 'handoff_committed'`: set `settled_units = C_effective` and `held_units =
       greatest(0::numeric(38, 0), qr.reserved_units::numeric(38, 0) - C_effective)::bigint`,
       **keeping `state = 'handoff_committed'`** (charging any confirmed overage immediately — e.g.,
       `hold = 100` with `prompt_tokens = 150, completion_tokens = NULL` OR `reasoning_tokens = 150,
       reasoning_included = true` immediately sets `settled_units = 150, held_units = 0, state =
       'handoff_committed'`, adding `+50` `active_used` exposure — while retaining `reserved_units -
       C_effective` unresolved `held_units` exposure whenever below the hold, e.g., `hold = 200`
       with `prompt_tokens = 60, completion_tokens = NULL, final = true` sets `settled_units = 60,
       held_units = 140, state = 'handoff_committed'`, and on a `200`-token hold, a prompt-only
       partial (`rev 0: prompt_tokens = 60, completion_tokens = NULL, final = false`) followed by a
       completion-only final (`rev 1: prompt_tokens = NULL, completion_tokens = 25, final = true`)
       has **`is_complete_tokens(rev 1) = false`** and produces **`85 settled, 115 held, state =
       'handoff_committed'`** — requiring both `prompt_tokens` and `completion_tokens` explicitly
       non-null on a single `final = true` `r_step` itself to close `state = 'settled'`!). Likewise,
       if `revision = 1` confirmed `prompt_tokens = 120, completion_tokens = 30` (`settled_units =
       150, held_units = 0`) and `revision = 2` omits `prompt_tokens` (`NULL`, `completion_tokens =
       30`), `P_known = 120`, `K_known = 30`, `C_floor = 150`, and `C_effective = 150`, preserving all
       `150` confirmed units without erasing confirmed overage exposure!
     - If `state = 'settled'` already: advance `settled_units = C_effective` (`held_units = 0`)
       when `C_effective > cur_settled` (charging any confirmed monotonic increase immediately,
       while **never** decreasing `settled_units` without complete authoritative token evidence),
       and still advance `qr.accepted_source_revision = p_source_revision` even when `C_effective <=
       cur_settled` (with zero `quota_reconciliations` row or budget delta when unchanged!).

| Event | State transition and exact-once accounting |
| --- | --- |
| Exact reservation replay | Same `(scope_id, actor_user_id, resource_kind, idempotency_key)` with matching `request_identity` and `request_digest` returns the existing reservation, state and server-selected charged windows without rechecking limits or double-charging. Changed input returns `409 idempotency_conflict`. |
| Atomic gateway request + metered hold creation (`authz::gateway::reserve_in` + `quota_reserve` / `quota_ensure_legacy_run_holds` -> `authz::gateway::reserve_in` -> `quota_allocate_round`, ADR 0037 / Migration `0023`) | In Migration `0023`'s `src/authz/gateway.rs`, standalone `authz::gateway::reserve()` commits `gateway_requests` before returning, which would leave `gateway_reservations.allocated` stranded and occupy `gateway_requests_run_round_active_idx` if a process crashed before creating `quota_reservations`. PR2 therefore introduces in-transaction helpers `authz::gateway::reserve_in(&mut WriteTransaction, ...)` (alongside `handoff_in` and `release_in`) so **inserting the `'reserved'` `openmettle.gateway_requests` row (plus the caller `gateway_reservations` row when `run_id IS NULL`) and creating ALL corresponding metered `openmettle.quota_reservations` holds (`usage_tokens`, `usage_cost_micros` via `quota_reserve` for standalone calls or `quota_allocate_round` for run rounds) execute atomically in a single PostgreSQL `WriteTransaction`** — rolling back both if any quota hold fails or the process crashes before commit. Both `quota_reserve` and `quota_allocate_round` (reinforced by `quota_reservations_gateway_binding_guard`) verify `q.scope_id = scope_id`, `q.actor_user_id = actor_user_id`, `q.run_id IS NOT DISTINCT FROM run_id`, `q.state = 'reserved'`, the caller's 32-byte `p_dispatch` secret (`q.dispatch_hash = sha256(p_dispatch)`), and — for `resource_kind = 'usage_tokens'` — **derive/enforce exact hold-size equality `reserved_units = q.units` (`held_units = q.units`)**, rejecting any mismatched caller amount (`<` or `>` `q.units`) with `ERRCODE = '23514'`. **Lazy once-per-run parent hold backfill for `N-1`-admitted runs (strictly before `reserve_in`):** because a run admitted by an `N-1` API replica created `runs` + `gateway_reservations` with zero local parent `quota_reservations` holds, and `gateway_allocate` immediately increments `gateway_reservations.allocated` as soon as `reserve_in` inserts `gateway_requests`, initializing the parent *after* `reserve_in` would subtract the replacement round twice. Therefore, inside the single round-allocation `WriteTransaction` (executed **after** any `quota_unwind_superseded_round` of a crashed predecessor round), **`openmettle.quota_ensure_legacy_run_holds(...)` MUST run strictly BEFORE `authz::gateway::reserve_in(&mut tx, ...)`**: under `runs` (`FOR NO KEY UPDATE`, active `Step` lease), it performs a non-locking `SELECT` for an existing run-level parent `usage_tokens` hold (`parent_reservation_id IS NULL AND gateway_request_id IS NULL`, returning immediately if present); if absent, it locks **`gateway_reservations` (`FOR NO KEY UPDATE`**, matching `gateway_allocate`'s `UPDATE` lock mode so the immediately following `reserve_in` performs zero `FOR SHARE -> FOR NO KEY UPDATE` lock upgrade and cannot deadlock with `FOR SHARE` settlement readers), reads remaining unallocated admission budget **`units - allocated`** (frozen Migration `0023`'s `units` column), locks charged `quota_budgets` (scope rows asc, instance row last, `FOR NO KEY UPDATE`), checks active hard limits (returning `OMQ01` if over budget), and inserts the missing run-level parent `quota_reservations` hold(s) (`usage_tokens` for `units - allocated` plus applicable `usage_cost_micros` run ceiling, `origin_role = 'worker'`, deterministic idempotency key `("legacy-run-parent", run_id, resource_kind)`) **exactly once** (terminal/settlement cleanup releases any unallocated remainder on that `origin_role = 'worker'` parent hold identically to normal parent holds; subsequent rounds and retries see the parent hold already present and allocate child holds normally without re-charging `quota_budgets`). Immediately in the **same `WriteTransaction`**, `authz::gateway::reserve_in(&mut tx, ...)` inserts the `'reserved'` `gateway_requests` row (updating `allocated` under the already-held `FOR NO KEY UPDATE` lock) and `quota_allocate_round` requires the parent hold to already exist, verifies the worker's active `Step` lease on `runs`, derives/enforces `slice_units = q.units` for `usage_tokens` (rejecting any mismatch with `23514`), and transfers `slice_units <= parent.held_units` from the server-owned run's `held` parent reservation to a child round reservation in **`state = 'held'`** (pre-handoff) bound to `gateway_request_id` with **`allocating_claim_token = p_claim_token`** (at least a `usage_tokens` child hold on every `N` round allocation, plus `usage_cost_micros` when applicable), copying `quota_reservation_charges`. Parent decrements `held_units` and increments `allocated_units`; `quota_budgets.reserved_held` changes by `0` (never double-debited). Because the child stays `'held'` until dispatch handoff, a pre-send failure never orphans it in `'handoff_committed'`. Unallocated parent remainder releases once when the run can start no further rounds. |
| Gateway & standalone pre-dispatch handoff (`authz::gateway::handoff_in` + `quota_commit_handoff`, `quota_enforce_gateway_handoff_holds`, plus `quota_recover_lost_handoff`) | For metered usage holds (`usage_tokens`, `usage_cost_micros`) — both standalone API calls (`openmettle_api`, `run_id IS NULL`) and worker run rounds (`openmettle_worker`, `run_id IS NOT NULL`) — `quota_commit_handoff` executes **atomically in the same `WriteTransaction` immediately after `authz::gateway::handoff_in` / `openmettle.gateway_handoff(...)`**, locking `gateway_requests` (`FOR SHARE`) to verify `gateway_requests.state = 'handed_off'` before transitioning the caller's matching `held` reservation (`origin_role` matching caller) to `'handoff_committed'`. At `COMMIT`, `DEFERRABLE INITIALLY DEFERRED` `CONSTRAINT TRIGGER quota_enforce_gateway_handoff_holds` (`openmettle.enforce_gateway_handoff_holds()`, `OMQ04`) unconditionally rejects any bound hold left outside `'handoff_committed'` (even while `metering_enforced = false`), computes `v_cost_required` via non-locking reads, **inserts `(NEW.id, false, v_cost_required)` into `openmettle.quota_gateway_handoffs` FIRST**, and **then acquires `FOR SHARE` on singleton `openmettle.quota_enforcement` as the final lock** (serializing both commit orders against `openmettle_owner`'s standalone `UPDATE` acquiring `FOR NO KEY UPDATE`); when `metering_enforced = true`, it requires a bound `'handoff_committed'` `usage_tokens` hold with **exact hold equality, zero pre-handoff settlement, and ownership match** (`qr.reserved_units = NEW.units AND qr.held_units = NEW.units AND qr.settled_units = 0 AND qr.accepted_source_revision IS NULL AND qr.scope_id = NEW.scope_id AND qr.actor_user_id = NEW.actor_user_id AND qr.run_id IS NOT DISTINCT FROM NEW.run_id`) plus any applicable `usage_cost_micros` hold (`qr.settled_units = 0 AND qr.accepted_source_revision IS NULL` matching `(scope_id, actor_user_id, run_id)`, rolling back any `N-1` `0023`-only `gateway_handoff`, mismatched hold, and the uncommitted `quota_gateway_handoffs` insert cleanly with `OMQ04`) and updates only its own uncommitted `quota_gateway_handoffs` row (`SET metering_enforced = true`, zero additional locks). Any pre-commit or commit-time refusal rolls back both transitions cleanly and prevents dispatch. On a **lost commit acknowledgement (`UnknownCommit`)** (connection drop during `COMMIT` reply, leaving commit outcome unknown in PostgreSQL), because Migration `0023` grants `SELECT` on `openmettle.gateway_requests` **only** to `openmettle_gateway` (never to `openmettle_api` or `openmettle_worker`), the caller **MUST suppress HTTP transport dispatch** (matching [ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md) and `src/authz/gateway.rs`) and invoke the caller-scoped `SECURITY DEFINER` recovery entrypoint **`openmettle.quota_recover_lost_handoff(p_request_id uuid, p_dispatch bytea, p_scope_id uuid, p_actor_user_id uuid, p_run_id uuid) RETURNS text`**. That function verifies caller role (`openmettle_api` for `p_run_id IS NULL`, `openmettle_worker` for `p_run_id IS NOT NULL`), `octet_length(p_dispatch) = 32`, and `gateway_requests` ownership + `dispatch_hash = sha256(p_dispatch)` (preserved by `0023`'s `gateway_handoff`), locks `(runs ->) gateway_reservations -> gateway_requests -> (parent ->) quota_reservations -> quota_budgets` in canonical `FOR NO KEY UPDATE` order, and resolves the outcome: (a) if `gateway_requests.state = 'handed_off'`, it reads the recorded handoff-time obligation from `openmettle.quota_gateway_handoffs` (`COALESCE(metering_enforced, false)`, `COALESCE(cost_required, false)` — any pre-PR2 `0023` handoff absent from the table unambiguously means `metering_enforced = false, cost_required = false`), asserts zero bound `quota_reservations` rows remain in pre-handoff or unsent states (**`qr.state NOT IN ('handoff_committed', 'settled')`**, raising `OMQ04` if any bound `'held'` or `'released'` row exists — explicitly recognizing **`'settled'`** from a fast final gateway usage report as valid committed post-handoff evidence), and evaluates required hold presence strictly against **handoff-time** `handoff.metering_enforced` and `handoff.cost_required` (NOT live `quota_enforcement.metering_enforced` or live `quota_defaults`): when `handoff.metering_enforced = true`, it requires bound `usage_tokens` (`qr.reserved_units = q.units`, and `qr.held_units = q.units` while `qr.state = 'handoff_committed' AND qr.settled_units = 0`) and `usage_cost_micros` iff `handoff.cost_required = true` in `state IN ('handoff_committed', 'settled')` (`OMQ04` if missing/mismatched) and returns `'handoff_committed'`; when `handoff.metering_enforced = false`, it returns `'handoff_committed'` if valid post-handoff bound holds exist or `'unmetered_legacy_handoff'` if zero bound holds exist (even if live `quota_enforcement.metering_enforced` has since flipped to `true`), keeping HTTP dispatch strictly suppressed in all `'handed_off'` outcomes for downstream gateway reconciliation; (b) if `gateway_requests.state = 'reserved'` (or `'released'` with remaining `'held'` bound holds), it atomically unwinds `gateway_requests.state := 'released'` and decrements `gateway_reservations.allocated` (if `'reserved'`), transitions bound `'held'` `quota_reservations` to `'released'` (returning round capacity to an active `'held'` parent or restoring `quota_budgets` on standalone/terminal runs, setting `closed_at`), and returns `'unwound_unsent'`. For standalone non-run device holds (`resource_kind = 'device_reservations' AND run_id IS NULL`), `quota_commit_handoff` binds `device_grant_id` on the caller's own `origin_role` `held` row. **Generic `quota_commit_handoff` explicitly rejects all run-linked device holds (`resource_kind = 'device_reservations' AND run_id IS NOT NULL`, SQLSTATE `42501`) for both `openmettle_api` and `openmettle_worker`**, forcing exclusive use of `quota_commit_device_handoff`. |
| Fenced successor-worker unwind of crashed post-commit `'reserved'` round (`quota_unwind_superseded_round`) | If Worker 1 (`T1`) commits `(reserve_in + quota_allocate_round)` (or an `N-1` worker commits an unbound `'reserved'` round via `0023` `authz::gateway::reserve`) for `(run_id, round)` and crashes immediately before `handoff_in`, its 32-byte `Pending.secret` is lost in process memory while Migration `0023`'s `gateway_requests_run_round_active_idx` blocks retrying `round` (`23505`). After Worker 1's lease expires and Worker 2 (`T2`) reclaims the still-live (`running`) run via `leases::reclaim_next` (minting a fresh `claim_token = T2` that invalidates Worker 1 in `0023`'s `gateway_handoff`), Worker 2 invokes **`openmettle.quota_unwind_superseded_round(p_scope_id uuid, p_run_id uuid, p_claim_token uuid, p_round integer) RETURNS boolean`** (`SECURITY DEFINER`, `openmettle_worker` only). Acquiring canonical `FOR NO KEY UPDATE` locks on `runs -> gateway_reservations -> active gateway_requests (q) -> any existing parent & bound child quota_reservations`, it verifies Worker 2 holds the current live lease (`r.claim_token = p_claim_token AND r.state IN ('running', 'cancelling', 'reconciling') AND r.lease_expires_at > clock_timestamp()`). Next, it checks whether any bound child `quota_reservations` row for `q.id` carries **`allocating_claim_token = p_claim_token`**: if `EXISTS (SELECT 1 FROM openmettle.quota_reservations qr WHERE qr.gateway_request_id = q.id AND qr.allocating_claim_token = p_claim_token)`, `q` was allocated by the **current** lease generation `p_claim_token` itself (not a superseded predecessor lease), so it leaves `q` and its holds completely untouched and returns `false` as an idempotent replay no-op (preventing a replayed unwind under `T2` from releasing Worker 2's own replacement request!). Only when an active `gateway_requests` row `q` for `(run_id = p_run_id, round = p_round)` is `state = 'reserved'` (never `'handed_off'`) **AND** zero bound holds carry `allocating_claim_token = p_claim_token`, it atomically transitions `gateway_requests.state := 'released'` and restores `gateway_reservations.allocated := allocated - q.units`: when zero bound child `quota_reservations` rows exist (an **unbound `N-1` `'reserved'` round**), this completes cleanly without requiring parent `quota_reservations` rows to exist yet (allowing Worker 2 to initialize the run's parent hold via `quota_ensure_legacy_run_holds` and allocate the replacement round); when bound `'held'` child `quota_reservations` rows exist (a predecessor `N` attempt carrying `allocating_claim_token = T1 <> p_claim_token`), it additionally transitions those child holds to `'released'` (`held_units = 0`, `closed_at = clock_timestamp()`, inserting `quota_reconciliations` with `kind = 'release'`, `delta_active = 0`, `delta_reserved = 0`) and returns their capacity directly to their active `'held'` parent run holds (`parent.allocated_units := parent.allocated_units - child.reserved_units`, `parent.held_units := parent.held_units + child.held_units`, `quota_budgets` delta = `0`). Returns `true` so Worker 2 can immediately retry `p_round` cleanly. If already `'handed_off'` (or no active `'reserved'` predecessor row exists), it leaves the row untouched and returns `false` so Worker 2 reconciles or advances. |
| Run-linked device handoff (`api` admission -> `worker` dispatch) | Run admission (`POST /v1/runs`) reserves `device_reservations` with `origin_role = 'api'`. At dispatch, `openmettle_worker` invokes `openmettle.quota_commit_device_handoff(...)` (the sole allowed transition path for run-linked device holds), which locks `runs -> quota_reservations` in canonical order, verifies the calling worker's active `Step` lease (`runs.state = 'running'`, `runs.cancel_reason IS NULL`, matching `claim_token`, `runs.lease_expires_at > clock_timestamp()`), requires `resource_kind = 'device_reservations'` (`run_id IS NOT NULL`, `origin_role IN ('api', 'worker')`) matching `(scope_id, run_id)`, binds the run's durable V1-18 `device_grant_id` and transitions `state = 'handoff_committed'` before external device activation. `openmettle_api` has zero `EXECUTE` grant on `quota_commit_device_handoff` and is rejected by `quota_commit_handoff` on any run-linked device hold; `openmettle_worker` remains forbidden from mutating `origin_role = 'api'` holds of any other resource kind or any unleased/cancelled run. |
| Pre-send abort, `gateway_release` unwind, queued cancellation, unallocated parent remainder or orphan `'reserved'` gateway sweep | Only while `state = 'held'`: for a hold bound to `gateway_request_id`, explicit pre-send unwind couples with `authz::gateway::release_in(&mut tx, ...)` / Migration `0023`'s `openmettle.gateway_release(p_request, p_dispatch)` (setting `gateway_requests.state = 'released'` and returning units to `gateway_reservations`), and `quota_release_unsent` verifies `gateway_requests.state = 'released'` before unwinding. In **both** explicit pre-send unwind and sweep mode, after acquiring canonical locks on `(runs ->) gateway_reservations -> gateway_requests -> (parent ->) quota_reservations`, `quota_release_unsent` **explicitly re-verifies `(q.scope_id, q.actor_user_id) = (qr.scope_id, qr.actor_user_id) AND q.run_id IS NOT DISTINCT FROM qr.run_id` before modifying either ledger** (raising an invariant error and mutating neither ledger on mismatch). When unwinding an unsent child round hold whose parent run hold is still active (`state = 'held'` on a non-terminal run), `quota_release_unsent` locks parent before child, returns `child.held_units` to `parent.held_units` (decrementing `parent.allocated_units`, `quota_budgets.reserved_held` delta = `0`), inserts `quota_reconciliations` (`kind = 'release'`, `delta_active = 0`, `delta_reserved = 0`), and sets child `state = 'released'`, `held_units = 0`, `closed_at = clock_timestamp()`. For standalone holds, parent remainders or terminal-run child holds (including stale sweep after a pre-handoff crash), `quota_release_unsent` (`SECURITY DEFINER`, owned by `openmettle_owner`) acquires locks internally in canonical order (`FOR NO KEY UPDATE SKIP LOCKED` on `runs`, `gateway_reservations`, `gateway_requests`, parent and target `quota_reservations` in sweep mode), re-verifies eligibility and ownership, and when `gateway_request_id IS NOT NULL`: proceeds if `gateway_requests.state = 'released'`; **atomically transitions `gateway_requests.state = 'released'` and restores `gateway_reservations.allocated = allocated - req.units` in the exact same transaction** if `gateway_requests.state = 'reserved'` (without needing the caller's lost dispatch secret, ensuring any delayed `openmettle.gateway_handoff` call fails closed); or leaves the local hold untouched if `gateway_requests.state = 'handed_off'` or locked. Eligible releases insert `quota_reconciliations` (`kind = 'release'`, `delta_active = 0`, `delta_reserved = -held_units`), decrement `reserved_held`, and set `state = 'released'`, `held_units = 0` and `closed_at = clock_timestamp()`. Repeating release is a no-op. For rolling-upgrade / defense-in-depth safety against pre-V1-17 `'reserved'` `gateway_requests` rows having zero bound `quota_reservations` rows, `openmettle_worker` also runs `openmettle.quota_release_orphan_gateway_requests(...)` using bounded raw `(created_at, id)` index-key paging over `gateway_requests_reserved_idx` with a single constant clamped age-cutoff upper bound (zero `clock_timestamp()` inside the scan query) to release aged unbound `'reserved'` requests and restore `gateway_reservations.allocated`. |
| Open partial gateway report or signed partial correction (ADR 0037 / Migration `0023`) | **Every** `openmettle_gateway` transaction upserting/advancing `openmettle.gateway_settlements` (both settlement-only and combined writes) calls `openmettle.quota_lock_gateway_request_for_settlement(p_request_id)` strictly before `INSERT`/`UPDATE` on `gateway_settlements` (`measured` widened to `numeric(38, 0)`), which durably appends `(NEW.request_id, NEW.revision, NEW.final)` to `openmettle.quota_accepted_gateway_reports`. `quota_settle_gateway_usage` locks strictly `gateway_requests` (`FOR KEY SHARE`) -> `quota_reservations` (`ORDER BY resource_kind ASC FOR UPDATE`) -> `quota_budgets` (`FOR NO KEY UPDATE`), verifies `(p_report_source, p_report_id, p_source_revision)` matches `openmettle.gateway_usage_reports` AND **`EXISTS (SELECT 1 FROM openmettle.quota_accepted_gateway_reports a WHERE a.request_id = qr.gateway_request_id AND a.revision = p_source_revision)`** (rejecting any late partial stored in `gateway_usage_reports` but rejected by `gateway_settlements`), verifies `qr.state IN ('handoff_committed', 'settled')` and immutable deployment `cost_denomination` against `r_step.unit` (when `r_step.cost IS NOT NULL`), returns an idempotent no-op if `qr.accepted_source_revision IS NOT NULL AND p_source_revision <= qr.accepted_source_revision` (accepting valid `revision = 0` initial reports cleanly), and otherwise **deterministically folds all unapplied accepted revisions `a.revision` in `(coalesce(qr.accepted_source_revision, -1), p_source_revision]` in ascending `ORDER BY a.revision ASC`**. For each folded step `r_step`: `usage_cost_micros` computes `C_cost = ceil(r_step.cost)::numeric(38, 0)` when `r_step.cost IS NOT NULL` (leaving balances unchanged when `r_step.cost IS NULL`); `usage_tokens` (1) leaves balances unchanged when all three token columns on `r_step` are `NULL`, (2) when `is_complete_tokens = true` (`NOT r_step.final`), sets `C_tokens = P_known + K_known + X_known` (allowing signed downward partial corrections while keeping `state = 'handoff_committed'`), and (3) when `NOT is_complete_tokens` with `>= 1` non-null token component on `r_step`, computes `C_floor = P_known + K_known + X_known` (including `K_known = CASE WHEN rev_R >= rev_K THEN greatest(K_raw, R_latest) ELSE K_raw END` when `inc_latest IS TRUE`) and `C_effective = greatest(cur_settled, C_floor)` — immediately charging confirmed overage (e.g., `hold = 100` with `prompt_tokens = 150, completion_tokens = NULL` OR `reasoning_tokens = 150, reasoning_included = true` immediately sets `settled_units = 150, held_units = 0, state = 'handoff_committed'`) while keeping `state = 'handoff_committed'` and never erasing prior confirmed usage. Comparing the final folded `(new_state, new_settled, new_held)` against prior `(old_state, S, H)`: `quota_settle_gateway_usage` **unconditionally advances `qr.accepted_source_revision = p_source_revision`** on `openmettle.quota_reservations`, and writes a composite-FK `quota_reconciliations` row (`delta_active = new_settled - S`, signed `delta_reserved = (new_held - H)::numeric(38, 0)`) and adjusts `quota_budgets` + `quota_warning_events` + `revision = revision + 1` **iff `(new_state, new_settled, new_held) IS DISTINCT FROM (old_state, S, H)`**. Example: on a `100`-token hold (`accepted_source_revision IS NULL`) where `revision = 0` reports complete `prompt_tokens = 40, completion_tokens = 20` partial (`60` measured, `40` held, `accepted_source_revision = 0`), an authoritative complete `revision = 1` partial correction to `prompt_tokens = 15, completion_tokens = 5` applies `delta_active = -40` and `delta_reserved = +40` (`20` measured, `80` held, `accepted_source_revision = 1`, preserving `100` total exposure while open); whereas on a `100`-token hold where `revision = 0` reports `reasoning_tokens = 150, reasoning_included = true` (`prompt_tokens = NULL, completion_tokens = NULL`), `K_known = greatest(0, 150) = 150, X_known = 0, C_floor = 150` immediately charges `settled_units = 150, held_units = 0` (`+50` active exposure) while remaining `'handoff_committed'`. |
| Authoritative final gateway report (including overage, explicit zero charge, multi-revision catch-up, out-of-order call, or `revision = 0` final) | Verifies `(p_report_source, p_report_id, p_source_revision)` matches `openmettle.gateway_usage_reports` AND **`EXISTS (SELECT 1 FROM openmettle.quota_accepted_gateway_reports a WHERE a.request_id = qr.gateway_request_id AND a.revision = p_source_revision)`**, returns an idempotent no-op if `qr.accepted_source_revision IS NOT NULL AND p_source_revision <= qr.accepted_source_revision` (accepting immediate `revision = 0` finals cleanly), and otherwise **folds all unapplied accepted revisions `a.revision` in `(coalesce(qr.accepted_source_revision, -1), p_source_revision]` in deterministic `ORDER BY a.revision ASC`**. Consequently, even if `gateway_settlements` has already advanced from token-only final `rev 1` to cost-only final `rev 2`, or a caller invokes `quota_settle_gateway_usage(..., rev 2)` before `rev 1` (e.g., `H = 200`, `rev 1`: `prompt = 60, completion = 20, final = true`; `rev 2`: `prompt = NULL, completion = 25, final = true`), the ascending fold processes `[1, 2]` in exact order: step `1` closes `usage_tokens` to `('settled', 80, 0)`, step `2` applies the monotonic post-final upward adjustment to `('settled', 85, 0)`, and a subsequent `rev 1` call (`1 <= 2`) is an idempotent no-op! For each folded step `r_step` with `r_step.final = true`: `usage_cost_micros` closes to `'settled'` only when `r_step.cost IS NOT NULL` (`C_cost = ceil(r_step.cost)::numeric(38, 0)`); `usage_tokens` (1) leaves balances unchanged when all three token columns are `NULL`, (2) when **`is_complete_tokens = true`**, transitions `handoff_committed -> settled` (`settled_units = C_tokens = P_known + K_known + X_known`, `held_units = 0`, `closed_at = coalesce(closed_at, now())`, including explicit `prompt_tokens = 0, completion_tokens = 0` zero-token final proof when no prior non-included reasoning tokens were omitted; and with `completion_tokens = 200, reasoning_tokens = 150, reasoning_included = true` computing `K_known = greatest(200, 150) = 200, X_known = 0` with zero double-counting), and (3) when **`NOT is_complete_tokens`** with `>= 1` non-null token component on `r_step` (**even though `r_step.final = true`!**), computes `C_effective = greatest(cur_settled, C_floor)`, sets `settled_units = C_effective`, `held_units = greatest(0::numeric(38, 0), qr.reserved_units::numeric(38, 0) - C_effective)::bigint`, and **keeps `state = 'handoff_committed'`** (e.g., `hold = 200` + `prompt_tokens = 60, completion_tokens = NULL, reasoning_tokens = 150, reasoning_included = true, final = true` charges `210` and stays `'handoff_committed'` until explicit `completion_tokens IS NOT NULL` arrives). Always advances `qr.accepted_source_revision = p_source_revision`; writes `quota_reconciliations` and adjusts `quota_budgets` iff `(new_state, new_settled, new_held) IS DISTINCT FROM (old_state, old_settled, old_held)`. |
| Post-final authoritative correction | Processed by the **same deterministic ascending fold** over `(coalesce(qr.accepted_source_revision, -1), p_source_revision]` inside `quota_settle_gateway_usage(...)`. When `state = 'settled'` already and a folded `r_step` (`final = true`) arrives: `usage_cost_micros` updates `settled_units = ceil(r_step.cost)::numeric(38, 0)` when `r_step.cost IS NOT NULL` (leaving balances unchanged when `r_step.cost IS NULL`); `usage_tokens` (1) leaves balances unchanged when all three token columns on `r_step` are `NULL`, (2) when `is_complete_tokens = true`, updates `settled_units = C_tokens` with signed `delta_active = C_tokens - S` (`delta_reserved = 0`, rejecting negative `active_used`, and honoring a newer complete revision `rev_K > rev_R` such as `completion_tokens = 120, reasoning_tokens = NULL` with `K_known = 120`), and (3) when `NOT is_complete_tokens` with `>= 1` non-null token component on `r_step`, advances `settled_units = C_effective = greatest(cur_settled, C_floor)` (`held_units = 0`) when `C_effective > cur_settled` (never decreasing `settled_units` without complete authoritative token evidence!). Crucially, **even on a 0-delta / no-op post-final correction** (such as an unchanged incomplete `completion_tokens = 25` repeat where `C_effective <= cur_settled`, or an other-resource report), `quota_settle_gateway_usage` **still unconditionally advances `qr.accepted_source_revision = p_source_revision`** on `openmettle.quota_reservations` (writing `quota_reconciliations` and incrementing `revision` iff `(new_state, new_settled, new_held) IS DISTINCT FROM (old_state, old_settled, old_held)`), clearing `pending_gateway_reconciliations` immediately! Fractional cost sequence `0.4 -> 0.8 -> 1.2` final -> `0.5` post-final correction -> `0` settles cumulative `ceil(r.cost)::numeric(38, 0)` values `1 -> 1 -> 2 -> 1 -> 0` with zero accumulated rounding drift. Same-revision duplicates with identical values are no-ops; differing values at an already accepted revision or mismatched `unit` denominations quarantine under ADR 0037 without mutating balances. |
| Failed upload, interrupted write or retention purge | All `artifact_fs::Store` writer and reader operations execute strictly relative to `Arc`-shared verified directory descriptors (`root_fd`, `staging_dir_fd`, `revisions_dir_fd`), verifying local same-mount equality (`file_meta.dev() == dir_fd_meta.dev() == root_fd_meta.dev()`) without storing client-local NFS `st_dev` in PostgreSQL (`payload_dev` is dropped; only unsigned 64-bit **`payload_ino numeric(20, 0)`** is stored). **Unified rollout & volume-lock rule:** neither `openmettle_api` nor `openmettle_worker` has `UPDATE` on `openmettle.storage_volume_control` (`SELECT` only); all pinned runtime volume locks go through `SELECT openmettle.storage_lock_pinned_volume()` (`SECURITY DEFINER`, `FOR SHARE`, raising `OMQ03` on missing row / unpinned / active adoption), and only `openmettle_api` holds `EXECUTE` on `openmettle.storage_pin_volume_id(uuid)` for empty fresh-bootstrap auto-pinning (`openmettle_worker` never initializes sentinels or calls `storage_pin_volume_id(uuid)`). HTTP `Store::stage` and `Store::publish` (`openmettle_api`) succeed when `storage_volume_control.adoption_run_id IS NULL` both when `volume_id IS NOT NULL` (via `storage_lock_pinned_volume()` + sentinels) and during mixed-version rolling upgrade while `volume_id IS NULL` (plain non-locking `SELECT`, skipping sentinel reads while still binding `stage_claimed = true` and `payload_ino`), whereas ADR 0039 worker `publish_bytes` spills and all 4 cleaners strictly require `storage_lock_pinned_volume()`. **`Store::stage` (`openmettle_api`):** (Step 1a) short lock-ordered primary tx commits `SET stage_claimed = true`; (Step 1b) re-verify directory FDs (+ sentinels when pinned), `openat(&staging_dir_fd, id, OFlags::CREATE \| OFlags::EXCL \| OFlags::RDWR \| OFlags::NOFOLLOW)` (`0` bytes) -> `LOCK_SH` (`try_lock_shared()`) -> verify `file_meta` vs `statat` -> **`fsync(&staging_dir_fd)`**; (Step 1c) short lock-ordered `FOR UPDATE` tx commits write-once `SET payload_ino = $3::text::numeric(20, 0)` leaving `publish_pending = false`. **ADR 0039 5-step `publish_bytes` (`openmettle_worker`):** (Step 1) create `0`-byte `staging/<id>` (`create_new(true)`), acquire continuous `LOCK_EX`, `fsync(&staging_dir_fd)`, bind write-once `stage_claimed = true, payload_ino = COALESCE(payload_ino, $3)` via `storage_lock_pinned_volume()` leaving **`publish_pending = false`**; (Step 2) write payload + verify `actual_size == reserved_bytes` & SHA-256 + `file.sync_all()` under continuous `LOCK_EX`; (Step 3) still holding `LOCK_EX`, re-stat `fd` (`st_size == reserved_bytes`) & `statat(&staging_dir_fd, id)` (`st_ino == payload_ino`), execute `SELECT openmettle.storage_lock_pinned_volume(); UPDATE openmettle.storage_reservations SET publish_pending = true WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved' AND NOT adoption_unverified AND reclaim_state = 'none' AND payload_ino = $3 RETURNING id;` (failing strictly BEFORE `linkat` on adoption `OMQ03` or cleaner claim `reclaim_state <> 'none'`); (Step 4) `rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id, AtFlags::empty())` + `fsync(&revisions_dir_fd)` + post-`linkat` re-verify **carrying the open `staged_fd` (`LOCK_EX`) into Step 5 (NOT dropping `LOCK_EX` at the end of Step 4!)**; (Step 5) execute a **single atomic `Fence::Step` `WriteTransaction` committing BOTH `storage::settle` (`state = 'settled', publish_pending = false`, retaining `payload_ino`) AND `runs::record_observation`**, drop `staged_fd` (`LOCK_EX`) **only AFTER** that `Fence::Step` tx commits, and run post-commit best-effort `LOCK_SH` `unlinkat(&staging_dir_fd, id)` (`OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + immediate `is_file()`, never `set_len(0)`) + `fsync(&staging_dir_fd)`. **100% non-destructive `Drop` & writer errors:** `StagedFile::drop` and all writer error/cancellation paths NEVER call `set_len(0)` or `unlinkat` — they only close the FD. On ambiguous `storage::settle` commit, inspect `storage_reservations.state` under lock first rather than calling `artifact_fs::abort` blindly. **`Store::publish` & `storage::settle`:** set `publish_pending = true` under lock strictly before `linkat` (quarantining on `Errno::EXIST`), `fsync(&revisions_dir_fd)` + post-`linkat` re-verify -> commit `storage::settle` (`state = 'settled', publish_pending = false`, retaining `payload_ino`) -> post-commit best-effort `LOCK_SH` `unlinkat(&staging_dir_fd, id)` (`OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + immediate `is_file()`, never `set_len(0)`) + `fsync(&staging_dir_fd)`. **`Store::read`:** joins `storage_reservations`, rejects `adoption_unverified = true`, opens `revisions/<reservation>` via `openat(&revisions_dir_fd, reservation, OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK, Mode::empty())`, **immediately checks `file.metadata()?.file_type().is_file()`** (failing closed with `Err(Error::Missing)` on FIFOs/sockets/devices/directories without blocking!), acquires non-blocking **`file.try_lock_shared()`** (`LOCK_SH \| LOCK_NB`, returning `Err(Error::Missing)` on `WouldBlock`), **strictly AFTER acquiring `LOCK_SH`** re-verifies `file.metadata()?` (`is_file()`, `st_dev == store.root_dev`, `st_ino == payload_ino` when non-null — permitting `payload_ino IS NULL` ONLY while `volume_id IS NULL AND adoption_run_id IS NULL` — `len() == size`) and `statat(&revisions_dir_fd, reservation, AtFlags::SYMLINK_NOFOLLOW)` namespace identity, seeks to `start`, and retains that locked `fs::File` inside `Content` for the entire streaming response body lifetime so `purge_due` Stage A (`LOCK_EX \| LOCK_NB`) receives `WouldBlock` and never truncates an in-flight download. **Unified 4-step reclamation protocol with `staging/.reclaim.<id>` anchor, Linux NFS-safe `OFlags::RDWR \| OFlags::NOFOLLOW` (without `OFlags::TRUNC`) on every `LOCK_EX` open, & fenced Step 2a across ALL 4 cleaners (`artifact_fs::abort`, non-run `reconcile_expired`, generic run-linked cleaner, ADR 0039 `reconcile_run_spills`):** (Step 1) lock `(runs ->) storage_reservations` -> `SELECT openmettle.storage_lock_pinned_volume()` (`v_vol == store.volume_id`), commit `reclaim_state` (`'claiming'` or `'truncated'`), `reclaim_claim_token = $my_token`, `reclaim_lease_until = clock_timestamp() + interval '60 seconds'`; (Step 2, outside DB tx, NEVER clearing `payload_ino`) *Case 1a (`payload_ino IS NOT NULL`, `'claiming'`):* probe **`staging/.reclaim.<id>` first**, else `staging/<id>` (and check `revisions/<id>`); foreign/mismatched or all-three `ENOENT` -> ZERO `set_len(0)`/`unlinkat`, quarantine; exact match -> open `OFlags::RDWR \| OFlags::NOFOLLOW` (without `OFlags::TRUNC`) -> **`LOCK_EX`** -> re-verify `fstat` + `statat` -> **Step 2a (while STILL holding `LOCK_EX`, strictly BEFORE `set_len(0)`/`linkat`/`unlinkat`):** execute `SELECT openmettle.storage_lock_pinned_volume(); UPDATE openmettle.storage_reservations SET reclaim_lease_until = clock_timestamp() + interval '300 seconds' WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved' AND NOT adoption_unverified AND payload_ino = $3 AND reclaim_state = 'claiming' AND reclaim_claim_token = $4::uuid RETURNING id;` (`0` rows or volume mismatch -> **abort immediately and drop FD with ZERO `set_len(0)`/`linkat`/`unlinkat`**!) -> (1) `set_len(0)?` + `sync_all()?` -> (2) create/verify `staging/.reclaim.<id>` via `linkat` -> **UNCONDITIONAL `fsync(&staging_dir_fd)?` for BOTH newly created AND recovered anchors strictly BEFORE unlinking `<id>`** -> (3) unlink matching `revisions/<id>` and `staging/<id>` + dual `fsync` -> (4) keeping `LOCK_EX`, commit `reclaim_state = 'truncated', publish_pending = false`; *Case 1b (`'truncated'`):* probe `staging/.reclaim.<id>` ONLY -> open `OFlags::RDWR \| OFlags::NOFOLLOW` (without `OFlags::TRUNC`, zero `set_len(0)`) -> `LOCK_EX` -> re-verify -> Step 2a revalidation -> dual `fsync` -> Step 3; *Case 2 (`payload_ino IS NULL`):* quarantine on `revisions/<id>`, `staging/.reclaim.<id>`, or non-zero/foreign `staging/<id>`, else for a `0`-byte regular `staging/<id>` on `store.root_dev` with `revisions/<id>` & `staging/.reclaim.<id>` `ENOENT`: open `OFlags::RDWR \| OFlags::NOFOLLOW` (without `OFlags::TRUNC`, zero `set_len(0)`) -> `LOCK_EX` -> re-verify `S_ISREG`, `st_dev == store.root_dev`, `st_size == 0`, `statat` `(fd_dev, fd_ino)` match, and `revisions/<id>`/`staging/.reclaim.<id>` `ENOENT` -> **while STILL holding `LOCK_EX`, run Step 2a SQL atomically binding `stage_claimed = true, payload_ino = fd_ino` (`reclaim_claim_token = $4::uuid`, aborting with ZERO FS mutations on `0` rows/`OMQ03`)** -> promote directly into the standard `.reclaim.<id>` anchor sequence (`linkat` -> unconditional `fsync(&staging_dir_fd)?` -> `unlinkat` `staging/<id>` -> dual `fsync` -> commit `reclaim_state = 'truncated', publish_pending = false` -> Step 3 `'anchor_pending_unlink'` -> Step 4; leaving `payload_ino` `NULL` through Step 3 **ONLY** when all three names are already `ENOENT`, with **ZERO `unlinkat` calls**!); (Step 3, ZERO FS I/O inside DB tx) commit `storage::release` (`reclaim_state = 'anchor_pending_unlink'` when `payload_ino IS NOT NULL`, firing `enforce_runtime_storage_volume_pinned()` -> `storage_lock_pinned_volume()`, retaining `payload_ino`); (Step 4) under `LOCK_EX` (`OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC`, verifying `st_ino == payload_ino` & `st_size == 0`, **never `set_len(0)`**), `unlinkat(".reclaim.<id>")` -> `drop` -> `fsync(&staging_dir_fd)` -> `SET reclaim_state = 'none'` (+ bounded DB-driven Step 4 retry over `storage_reservations_reclaim_anchor_idx` across ALL reservation kinds using per-worker wrapping keyset cursor `reclaim_anchor_cursor: Option<(DateTime<Utc>, Uuid)>` paired with a pass-start fixed upper watermark `(upper_ts, upper_id)`, constraining pages by `AND (closed_at, id) <= ($3::timestamptz, $4::uuid)`, advancing past every inspected key including anomalous/WouldBlock rows, and resetting BOTH cursor and pass-upper to `None` on `< LIMIT` OR reaching `(upper_ts, upper_id)`). **`enforce_storage_reservation_monotonic_guards()`** + **`CHECK (NOT adoption_unverified OR state = 'reserved')`** block non-owner release/settlement of quarantined rows, clearing `adoption_unverified`/`stage_claimed`, or mutating `payload_ino`. **3-stage inode-preserving `artifact_fs::purge_due` (`revisions/.purge.<id>` + `artifact_revisions.purge_stage`):** `storage::begin_purge` requires `NOT sr.adoption_unverified AND sr.payload_ino IS NOT NULL` and sets `state = 'purging', purge_stage = 'none'`; **Stage A** probes `revisions/.purge.<id>` else `revisions/<id>` (stopping with ZERO `set_len(0)`/`unlinkat` and NO `confirm_purge` on dual-`ENOENT` or foreign/mismatched inode), opens `OFlags::RDWR \| OFlags::NOFOLLOW` (without `OFlags::TRUNC`) -> `LOCK_EX` -> revalidates `storage_lock_pinned_volume()` + `state = 'purging'` -> `set_len(0)?` + `sync_all()?` -> creates/verifies `revisions/.purge.<id>` via `linkat` -> **unconditional `fsync(&revisions_dir_fd)?` BEFORE unlinking `revisions/<id>`** -> under continuous `LOCK_EX` while `.purge.<id>` pins `payload_ino` (`nlink >= 1`), unlinks matching `revisions/<id>` and matching `staging/<id>` (leaving foreign entries untouched) -> **unconditional dual `fsync(&revisions_dir_fd)` + `fsync(&staging_dir_fd)`** -> drops `LOCK_EX` keeping `.purge.<id>` linked; **Stage B** (`storage::confirm_purge`) sets `state = 'purged', purged_at = now(), purge_stage = 'anchor_pending_unlink'` and decrements `retained_bytes`; **Stage C** (immediate + bounded DB pass over `artifact_revisions_purge_anchor_idx` using per-worker wrapping keyset cursor `purge_anchor_cursor: Option<(DateTime<Utc>, Uuid)>` paired with a pass-start fixed upper watermark `(upper_ts, upper_id)`, constraining pages by `AND (r.purged_at, r.id) <= ($3::timestamptz, $4::uuid)`, advancing past every inspected key, and resetting BOTH cursor and pass-upper to `None` on `< LIMIT` OR reaching `(upper_ts, upper_id)`) detaches `revisions/.purge.<id>` under `LOCK_EX` (`OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC`, **never `set_len(0)`**) + `fsync(&revisions_dir_fd)` + `SET purge_stage = 'none'` (`ENOENT` -> `fsync` + `SET purge_stage = 'none'`). **PR2 updates ADR 0031's post-publication `reconcile_expired` behavior** (and `tests/schema/artifact_fs.rs`'s `renamed` test case). On **every** upgrade (`applied >= 1`), operators MUST quiesce `N-1` worker cleaners BEFORE `openmettle-migrate`. `openmettle-admin` adoption holds non-blocking `LOCK_EX` (`OFlags::RDWR \| OFlags::NOFOLLOW`, no `OFlags::TRUNC`, `try_lock()` — on `WouldBlock`, clearing `adoption_run_id = NULL` without quarantining/backfilling and returning retryable `OMQ03`) on every `payload_ino IS NULL` `'reserved'` backfill candidate continuously through Phase 3C commit; enforces **cross-reservation live inode uniqueness** in Phase 3A strictly across live payloads, surviving anchors, and backfill/unquarantine candidates — `artifact_revisions` (`'active'`, `'retained'`, surviving `'purging'`, `'purged'`+`anchor_pending_unlink`) AND `storage_reservations` (`(state = 'reserved' AND (payload_ino IS NOT NULL OR candidate for payload_ino backfill / adoption_unverified = false clearance — explicitly INCLUDING previously quarantined adoption_unverified = true rows on disk))` OR `(state = 'released' AND reclaim_state = 'anchor_pending_unlink')`), **explicitly EXCLUDING retired historical rows** (`(state = 'released' AND reclaim_state = 'none')` AND `'settled'` rows whose revision is `(state = 'purged' AND purge_stage = 'none')`), failing closed with `cross_reservation_inode_alias` / `intra_reservation_inode_mismatch` and zero `payload_ino` backfills!; handles crash-boundary anchors (**keeping `reclaim_state = 'claiming'` as `'claiming'` with `reclaim_lease_until = clock_timestamp()` — NEVER promoting `'claiming'` to `'truncated'**; requiring `staging/.reclaim.<id>` (`st_size == 0`) AND `staging/<id>`/`revisions/<id>` `ENOENT` on already-`'truncated'` rows; reserving the `st_size == 0` Stage A `'purging'` exception strictly for already-bound `sr.payload_ino IS NOT NULL AND st_ino == sr.payload_ino`; preserving `.purge.<id>` in `'purged'`+`anchor_pending_unlink`) and legacy `payload_ino IS NULL` `'purging'` rows (**Case 6a requiring exact recorded `st_size == size_bytes` AND `sha256 == content_digest` — rejecting `st_size == 0` when `size_bytes > 0` with `size_or_digest_mismatch`!**; Case 6b atomic `purged` completion + `retained_bytes` decrement, rejecting `ambiguous_legacy_purging_staging_survivor`, and **never counting Case 6b absent rows as positive on-disk file evidence** toward volume-identity verification), and commits `payload_ino` backfills ONLY in Phase 3C (success branch) strictly ONLY onto positively verified non-quarantined rows (never writing `payload_ino` onto rows staying `adoption_unverified = true`). **Zero-truncation `StagingSweepState`** requires `volume_id IS NOT NULL AND adoption_run_id IS NULL` and **NEVER calls `set_len(0)` in ANY branch (including `0`-row orphans and `.reclaim.<id>`)**: opens `OFlags::RDWR \| OFlags::NOFOLLOW` (without `OFlags::TRUNC`, required for Linux NFS `LOCK_EX` -> `F_WRLCK`), acquires `LOCK_EX`, serializes via `storage_lock_pinned_volume()` + `storage_instance FOR NO KEY UPDATE`, detaches `staging/<id>` for `state = 'settled'` **STRICTLY ONLY when `artifact_revisions.state IN ('active', 'retained')` AND `revisions/<id>` exists on disk with `st_ino == payload_ino`** (post-purge `'purged'` `ENOENT` exception removed completely!), and detaches aged `> 900 s` `0`-row orphans / unowned `.reclaim.<id>` via `unlinkat` strictly without `set_len(0)`. |
| Terminal failed, cancelled or interrupted run | Unallocated `held` parent, standalone or unsent child quota holds release once. `handoff_committed` usage holds stay held until `openmettle_gateway` supplies an authoritative final report (including explicit zero-token / zero-cost final proof; partial/incomplete token reports charge `C_effective = greatest(cur_settled, C_floor)` immediately — including `reasoning_included = true` lower bound — while keeping `state = 'handoff_committed'` until complete final evidence arrives). `handoff_committed` device holds stay held until durable V1-18 confirmation of release or non-allocation. Run-linked `storage_reservations` stay held while any linked operation is `intent` or `outcome_unknown`, while `adoption_unverified = true`, while `storage_volume_control.adoption_run_id IS NOT NULL`, while `payload_ino IS NOT NULL` with a foreign/replacement leaf or `'claiming'` all-three `ENOENT` or `'truncated'` missing/mismatched `staging/.reclaim.<id>` (which promotes to `adoption_unverified = true, publish_pending = false, reclaim_state = 'none', reclaim_claim_token = NULL, reclaim_lease_until = NULL` rather than releasing), or while an active publisher holds `LOCK_SH`/`LOCK_EX` on `staging/<id>` / `revisions/<id>` awaiting SQL settlement (`operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%'` rows are owned solely by ADR 0039 `reconcile_run_spills`, while the exact logical complement `run_id IS NOT NULL AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')` is owned by ADR 0040). |

**Independent drift verification and restore validation.** PR2 adds a read-only
`verify_accounting_drift` check that workers run on a bounded maintenance interval and operators
run during restore validation before reopening dispatch
([Architecture backup and restore](../../ARCHITECTURE-v1.md#backup-and-restore)). Because
Migration `0023` does **not** grant `openmettle_worker` direct `SELECT` on
`openmettle.gateway_usage_reports` (or other gateway tables), the SQL half runs through a narrow
read-only `SECURITY DEFINER` (`SET search_path = pg_catalog`, `STABLE`, owned by
`openmettle_owner`) function **`openmettle.quota_verify_accounting_drift()`** granted `EXECUTE`
only to `openmettle_worker` (plus `openmettle_owner` / operator diagnostics; zero grant to
`openmettle_api`, `openmettle_gateway` or `openmettle_issuance`), returning only aggregate,
pending-catch-up lag, and hard-mismatch summaries without exposing raw gateway rows:

1. **Storage DB consistency (inside `quota_verify_accounting_drift()`):** compares
   `storage_accounts` and `storage_instance` counters (`active_bytes`, `retained_bytes`,
   `reserved_bytes`) against sums recomputed from `artifact_revisions` (`state = 'active'` and
   `state IN ('retained', 'purging')`) and `storage_reservations` (`state = 'reserved'`, including
   any `adoption_unverified = true`, `publish_pending = true`, or `reclaim_state <> 'none'` rows
   whose `max_bytes` remain charged). Once `storage_volume_control.volume_id IS NOT NULL`, also
   verifies that **zero** `'active'`, `'retained'`, or `'purging'` `artifact_revisions` join to a
   `storage_reservations` row with `payload_ino IS NULL` (failing hard if any post-adoption live or
   in-flight purge revision lacks a backfilled `payload_ino`).
2. **Storage DB-to-filesystem verification (`artifact_fs`):** when `ARTIFACTS_DIR` is unset (per
   ADR 0031, both `OPENMETTLE_API_ARTIFACTS_DIR`/`OPENMETTLE_ARTIFACTS_DIR` and
   `OPENMETTLE_WORKER_ARTIFACTS_DIR` unset), `storage_volume_control.volume_id IS NULL`, AND both
   `storage_reservations` and `artifact_revisions` contain `0` rows, filesystem sentinel checks are
   cleanly skipped as unconfigured. Otherwise — whenever `ARTIFACTS_DIR` is configured OR any row
   exists in `storage_reservations` / `artifact_revisions` — `storage_volume_control.volume_id IS
   NULL` remains a hard failure, and verification first opens `<root>`, `<root>/revisions` and
   `<root>/staging` (`O_RDONLY | O_DIRECTORY | O_NOFOLLOW`), verifies equal local `st_dev` across
   all three FDs, and verifies via `openat(..., O_RDONLY | O_NOFOLLOW | O_NONBLOCK)` + `fstat` on
   each FD that its `.openmettle-volume-id` file is a regular file (`S_ISREG` — rejecting FIFOs,
   sockets, device nodes, directories and symlinks immediately without blocking) on that same local
   `st_dev` whose bounded (`<= 64`-byte) content matches non-null pinned
   `storage_volume_control.volume_id` AND its exact `:root`, `:revisions`, or `:staging` role tag
   (failing restore validation immediately on `volume_id IS NULL` or on missing, mismatched,
   wrong-role, non-regular/FIFO/symlink or different-`st_dev` sentinels):
   - *Active and retained revisions (concurrent `begin_purge`-safe, strict `payload_ino` match):*
     every `artifact_revisions` row in `state IN ('active', 'retained')` MUST join to a
     `storage_reservations` row with **`sr.payload_ino IS NOT NULL`** (failing hard in
     `verify_accounting_drift` whenever `volume_id IS NOT NULL` and `sr.payload_ino IS NULL`!) and
     have a matching regular (non-symlink) file at `revisions/<reservation_id>` on the same local
     `st_dev` whose on-disk length equals `size_bytes` AND whose **`file_meta.ino() ==
     sr.payload_ino`**. Whenever periodic `verify_accounting_drift` observes `ENOENT` on
     `statat(revisions_dir_fd, reservation_id, AtFlags::SYMLINK_NOFOLLOW)` for a revision initially
     read as `'retained'`, it **re-queries `SELECT state FROM openmettle.artifact_revisions WHERE
     id = $1::uuid` in a fresh `READ COMMITTED` snapshot** (matching volume adoption's
     concurrent-purge rule): if `state IN ('purging', 'purged')`, the `ENOENT` is accepted as a
     valid concurrent `begin_purge` transition with **zero drift alert**. Any missing, symlinked,
     wrong-sized, or wrong-inode (`st_ino != sr.payload_ino`) payload for a revision that remains
     `'active'` or `'retained'` — explicitly including any same-sized replacement file or any
     revision committed into a displaced old `revisions/` directory during a live host directory
     replacement — is a **hard drift failure** that fails restore validation.
   - *Mid-purge crash states (`state = 'purging'`) and post-confirm purge anchors (`state =
     'purged' AND purge_stage = 'anchor_pending_unlink'`):* under the 3-stage inode-preserving
     `artifact_fs::purge_due` protocol, `payload_ino` NEVER drops to `nlink = 0` while `state =
     'purging'` — Stage A truncates `revisions/<reservation_id>`, links and `fsync`s
     `revisions/.purge.<reservation_id>`, unlinks visible `revisions/<reservation_id>` and matching
     `staging/<reservation_id>`, and calls `storage::confirm_purge` (Stage B: `state = 'purged',
     purge_stage = 'anchor_pending_unlink'`) while `revisions/.purge.<reservation_id>` still pins
     `payload_ino` alive before Stage C detaches `.purge.<reservation_id>`. Consequently, for every
     `artifact_revisions` row in `state = 'purging'` (`sr.payload_ino IS NOT NULL`),
     `verify_accounting_drift` accepts **all valid Stage A crash states matching `sr.payload_ino`**
     on `store.root_dev` (`S_ISREG`) with zero false drift:
     (i) `revisions/<reservation_id>` present with `st_size == size_bytes` and `st_ino ==
     sr.payload_ino`,
     (ii) `revisions/<reservation_id>` present with `st_size == 0` and `st_ino == sr.payload_ino`
     (crash between `sync_all()` and `linkat(".purge.<id>")` / `unlinkat`), OR
     (iii) `revisions/.purge.<reservation_id>` present with `st_size == 0` and `st_ino ==
     sr.payload_ino` (with `revisions/<reservation_id>` either `ENOENT` or also `S_ISREG` with
     `st_ino == sr.payload_ino` and `st_size == 0`),
     reporting valid `purging` rows as resumable pending-confirmation purges for `purge_due`. If
     **BOTH** `revisions/<reservation_id>` AND `revisions/.purge.<reservation_id>` return `ENOENT`
     for a post-adoption (`sr.payload_ino IS NOT NULL`) `'purging'` row, `verify_accounting_drift`
     re-queries `SELECT state FROM openmettle.artifact_revisions WHERE id = $1::uuid` in a fresh
     `READ COMMITTED` snapshot: if `state = 'purged'`, a concurrent Stage B -> C completion explains
     the `ENOENT` with zero drift; if `state <> 'purged'` (still `'purging'`), dual-`ENOENT` is a
     **hard drift failure** (as is any foreign wrong-inode / non-regular file at `revisions/<id>` or
     `revisions/.purge.<id>`). Likewise, `revisions/.purge.<reservation_id>` (`S_ISREG`, `st_dev ==
     root_dev`, `st_ino == sr.payload_ino`, `st_size == 0`) is recognized explicitly as a **valid
     non-orphan purge anchor** when the revision is `(state = 'purging' AND NOT
     sr.adoption_unverified)` OR `(state = 'purged' AND purge_stage = 'anchor_pending_unlink' AND
     NOT sr.adoption_unverified)` (whereas any `.purge.<id>` with `st_size > 0`, wrong `st_ino`, or
     lacking such a matching row fails as an orphan / hard drift).
   - *Unsettled published payloads, adoption-unverified holds, valid `.reclaim.<id>` / `.purge.<id>`
     anchors, and orphan scan:* any `revisions/<id>` paired with unflagged
     `storage_reservations.state = 'reserved'` (`NOT adoption_unverified`, post-`linkat`,
     pre-settlement crash window — for both non-run uploads and run-linked spills) is reported
     explicitly as an unsettled payload awaiting deterministic retry settlement or explicit
     `openmettle_owner` reconciliation; any `storage_reservations` row marked `adoption_unverified
     = true` while `state = 'reserved'` (and any `payload_ino IS NOT NULL` or `publish_pending =
     true` row with `reclaim_state <> 'truncated'` lacking its matching `payload_ino` on-disk
     payload or valid `staging/.reclaim.<id>` anchor) is reported explicitly as a quarantined hold
     requiring **explicit `openmettle_owner` reconciliation (or a subsequent verified
     `openmettle-admin` adoption run on the restored original directory tree where `revisions/<id>`
     or `staging/<id>` is positively verified under lock)** — never cleared by runtime roles
     (`enforce_storage_reservation_monotonic_guards()` and `CHECK (NOT adoption_unverified OR state
     = 'reserved')` block non-owner release/clearance in PostgreSQL) and never silently unlinked or
     released by automatic workers or `artifact_fs::abort`. A `staging/.reclaim.<id>` regular file
     on the same local `st_dev` with **`st_size == 0` and `st_ino == payload_ino`** paired with a
     `storage_reservations` row in **`(state = 'reserved' AND NOT adoption_unverified AND
     reclaim_state IN ('claiming', 'truncated'))` OR `(state = 'released' AND NOT
     adoption_unverified AND reclaim_state = 'anchor_pending_unlink')`** is recognized explicitly
     as a **valid non-orphan reclamation anchor** (covering crashes both after `linkat`+`unlinkat`
     before SQL `'truncated'` and after Step 3 `storage::release` before Step 4 detach; whereas any
     `.reclaim.<id>` with `st_size > 0`, wrong `st_ino`, or lacking such a matching row is flagged
     as an orphan / drift failure!). Ignoring the verified `.openmettle-volume-id` sentinel file
     (strictly disjoint from canonical lowercase UUID, `.reclaim.<uuid>`, and `.purge.<uuid>`
     filenames per `src/artifact_fs.rs`), any payload file in `revisions/` lacking a matching
     `active`/`retained`/`purging` revision, valid `.purge.<id>` anchor, or `reserved` reservation,
     and any payload file in `staging/` lacking a matching `reserved` reservation or valid
     `.reclaim.<id>` anchor (including any foreign-inode `staging/<id>` preserved by
     zero-truncation `StagingSweepState` on a `'settled'` or `'released'` row, after worker cleanup
     of valid `staging/.reclaim.<id>` anchors, active/retained `payload_ino`-matched `'settled'`
     aliases, `0`-byte `payload_ino IS NULL` `'released'` entries, and `LOCK_EX` + `st_mtime > 900
     s` zero-truncation orphan detachment), fails as an unreferenced orphan.
3. **Usage and device budget verification (inside `quota_verify_accounting_drift()`):**
   - *Local balance verification strictly against each reservation's applied
     `qr.accepted_source_revision` via exact ascending-fold replay (zero false hard drift during
     split-commit catch-up or after no-op/other-resource revisions):* compares every
     `quota_budgets.reserved_held` (`numeric(38, 0)`) row against
     `SUM(qr.held_units::numeric(38, 0))` joined via `quota_reservation_charges` for `qr.state IN
     ('held', 'handoff_committed')`, compares `quota_budgets.active_used` (`numeric(38, 0)`)
     against `SUM(quota_reconciliations.delta_active)`, and verifies each gateway-bound
     `quota_reservations` row (`settled_units`, `held_units`, `state`) strictly against its **own
     applied `qr.accepted_source_revision`** over `openmettle.quota_accepted_gateway_reports` joined
     with `openmettle.gateway_usage_reports`:
     - When `qr.accepted_source_revision IS NULL`: requires `qr.settled_units = 0`, `qr.held_units =
       qr.reserved_units` (while `state IN ('held', 'handoff_committed')`), and `qr.state <>
       'settled'`.
     - When `qr.accepted_source_revision IS NOT NULL`: replays the **exact same ascending fold
       across `a.revision <= qr.accepted_source_revision` (`ORDER BY a.revision ASC`)** from
       initial `(state = 'handoff_committed', held = qr.reserved_units, settled = 0)` using the
       identical per-resource rules (`usage_cost_micros`: `C_cost = ceil(r_step.cost)::numeric(38,
       0)` when `r_step.cost IS NOT NULL`; `usage_tokens`: `P_known`, `K_raw`/`rev_K`,
       `(R_latest, inc_latest, rev_R)`, included-reasoning lower bound `K_known`, `X_known`,
       `C_floor = P_known + K_known + X_known`, `is_complete_tokens`, and monotonic lower bound
       `C_effective = greatest(cur_settled, C_floor)` without `bigint` overflow even past
       `i64::MAX`), verifies exact equality with `qr.settled_units`, `qr.held_units`, and
       `qr.state`, and requires `qr.state = 'settled'` **iff at least one `final = true` accepted
       revision `<= qr.accepted_source_revision` established complete authoritative evidence for
       that resource** (so a subsequent cost-only or incomplete-token no-op revision advancing
       `qr.accepted_source_revision` on an already-`'settled'` row verifies cleanly with zero false
       drift!).
     Healthy split-commit catch-up between `gateway_settlements` commit and
     `quota_settle_gateway_usage` commit therefore produces **zero hard drift alerts**!
   - *Pending catch-up operational summary (`pending_gateway_reconciliations`):* because
     `quota_settle_gateway_usage` unconditionally advances `qr.accepted_source_revision =
     p_source_revision` on every processed accepted revision (including unchanged no-op post-final
     corrections and single-resource reports!), `pending_gateway_reconciliations` is simply:
     ```sql
     EXISTS (
         SELECT 1
           FROM openmettle.quota_accepted_gateway_reports a
          WHERE a.request_id = qr.gateway_request_id
            AND a.revision > coalesce(qr.accepted_source_revision, -1)
     )
     ```
     reported as a distinct **`pending_gateway_reconciliations`** lag summary (count + oldest
     pending age), kept strictly separate from hard accounting drift — clearing immediately once
     processed instead of aging forever!
   - *Own-revision validation of `openmettle.gateway_settlements.measured`:* frozen Migration `0023`
     defines `openmettle.gateway_settlements (request_id, revision, final, measured, outstanding,
     updated_at)` with `FOREIGN KEY (request_id, revision, final) REFERENCES
     openmettle.gateway_usage_reports (request_id, revision, final)` (it has **no `source` or
     `report_id` columns**). `quota_verify_accounting_drift()` therefore joins
     `openmettle.gateway_settlements gs` to `openmettle.gateway_usage_reports r_curr` strictly on
     **`(gs.request_id = r_curr.request_id AND gs.revision = r_curr.revision AND gs.final =
     r_curr.final)`**, reads `r_curr.source` and `r_curr.report_id` from `r_curr`, and validates
     `gs.measured` (`numeric(38, 0)`) strictly against **`r_curr` at `gs.revision` itself**
     (`gs.measured IS NULL` is valid whenever `r_curr` at `gs.revision` has no measured token total
     — e.g., cost-only `rev 2` after token-only `rev 1` — and when non-null must equal `r_curr`'s
     exact `numeric(38, 0)` token total at `gs.revision` without `22003` overflow; drift
     verification **never** compares `gs.measured` against a different revision's token total!).
   - Verifies every `released` or `settled` reservation has `closed_at IS NOT NULL`.

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
   - *Durable artifact volume identity (`storage_volume_control.volume_id` <-> role-tagged sentinels
     in `<root>`, `<root>/revisions`, and `<root>/staging`):*
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
     - **Dedicated read-mostly 1-row `openmettle.storage_volume_control` singleton (`SELECT`-only for
       runtime roles, locked via narrow `SECURITY DEFINER` `storage_lock_pinned_volume()`):**
       Because `storage::adjust` (`src/storage.rs:289-310`) updates `storage_accounts ->
       storage_instance` (`FOR NO KEY UPDATE`) on every `reserve`, `settle`, `release`, and
       `confirm_purge`, placing `(volume_id, bootstrap_auto_pin_allowed, adoption_run_id)` on
       `storage_instance` and taking `storage_instance FOR SHARE` earlier would cause concurrent
       releases or reserves to deadlock upgrading `storage_instance` to `FOR NO KEY UPDATE`. PR2
       therefore keeps only `(warn_pct_1, warn_pct_2, config_revision)` on
       `openmettle.storage_instance` and stores `(volume_id, bootstrap_auto_pin_allowed,
       adoption_run_id)` on dedicated 1-row **`openmettle.storage_volume_control`**. Because
       PostgreSQL 18 requires `UPDATE` privilege on at least one column to execute raw `SELECT ...
       FOR SHARE`, while granting direct `UPDATE` on `storage_volume_control` to runtime roles
       would allow pin rewrites outside `storage_pin_volume_id(uuid)`, PR2 grants **ONLY `GRANT
       SELECT ON openmettle.storage_volume_control TO openmettle_api, openmettle_worker;`** (zero
       `INSERT`, `UPDATE`, `DELETE`, or `TRUNCATE`!) and routes all runtime volume-pin locks
       through narrow `openmettle_owner`-owned `SECURITY DEFINER`
       **`openmettle.storage_lock_pinned_volume() RETURNS uuid`** (`SET search_path = pg_catalog`,
       acquiring `FOR SHARE` on `storage_volume_control WHERE id` and raising `OMQ03` on missing
       row, `volume_id IS NULL`, or `adoption_run_id IS NOT NULL`). Only `openmettle-admin`
       adoption (Steps 1b/3 as `openmettle_owner`) and `SECURITY DEFINER`
       `openmettle.storage_pin_volume_id(uuid)` (acquiring `FOR UPDATE` internally as
       `openmettle_owner`) acquire `FOR UPDATE` on `storage_volume_control`, so canonical lock
       order `runs -> storage_reservations -> artifacts -> artifact_revisions ->
       storage_volume_control [via storage_lock_pinned_volume()] -> storage_accounts ->
       storage_instance` has zero lock upgrades, zero `42501` errors under PostgreSQL 18, and zero
       deadlocks across concurrent releases, reserves, and purges.
     - **Role-tagged sentinels across all three directories (namespace-disjoint from payloads,
       nonblocking safe `dirfd` verification via `rustix`):** Because payload filenames in
       `staging/` and `revisions/` are strictly canonical lowercase UUIDs (`runs::uuid` in
       `src/artifact_fs.rs:134-135`, never starting with `.`), `.openmettle-volume-id` (and
       temporary `.openmettle-volume-id.tmp.*`) is 100% namespace-disjoint from payload files,
       `staging/.reclaim.<uuid>` reclamation anchors, and `revisions/.purge.<uuid>` purge anchors,
       and is ignored by `StagingSweepState` and orphan scans. PR2 binds
       `openmettle.storage_volume_control.volume_id` **plus explicit directory role** across **all
       three directories** (regular files, mode `0600`), opening **every** `.openmettle-volume-id`
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
       (`applied == 0`, `storage_volume_control.bootstrap_auto_pin_allowed = true`) AND empty
       storage ledger (via API-only `SECURITY DEFINER` `openmettle.storage_pin_volume_id(uuid)`
       acquiring `FOR UPDATE` internally as `openmettle_owner`):** In PR2's migration,
       `storage_volume_control.bootstrap_auto_pin_allowed` seeds `true` **ONLY when
       `is_fresh_bootstrap` holds** (`openmettle.bootstrap_from_zero = 'true'` set by
       `src/migrate.rs` when `applied == 0` in `openmettle._sqlx_migrations`, AND all core,
       storage and gateway tables are empty) and `false` on **EVERY** upgrade (`applied >= 1`,
       even an existing unused deployment with zero `users`, `storage_*`, or `gateway_*` rows!).
       `openmettle.storage_pin_volume_id(p_volume_id uuid)` (`SECURITY DEFINER`, owned by
       `openmettle_owner`, `SET search_path = pg_catalog`, **`GRANT EXECUTE ON FUNCTION
       openmettle.storage_pin_volume_id(uuid) TO openmettle_api;` — API-only, zero `EXECUTE` grant
       to `openmettle_worker`!**) itself acquires **`SELECT volume_id, bootstrap_auto_pin_allowed,
       adoption_run_id INTO v_vol, v_auto, v_adopt FROM openmettle.storage_volume_control WHERE id
       FOR UPDATE`** internally — **`Store::open` NEVER issues an invoker `SELECT ... FOR UPDATE`
       on `storage_volume_control` beforehand!** — raises `OMQ03` if `NOT FOUND OR v_adopt IS NOT
       NULL`, returns existing `v_vol` if already equal to `p_volume_id` (or raises `OMQ03` if
       already pinned to a different UUID), requires `v_auto = true` AND BOTH `NOT EXISTS (SELECT 1
       FROM openmettle.storage_reservations)` AND `NOT EXISTS (SELECT 1 FROM
       openmettle.artifact_revisions)`, and atomically sets `volume_id = p_volume_id,
       bootstrap_auto_pin_allowed = false` (enforced by `storage_volume_control_auto_pin_check`:
       `CHECK (volume_id IS NULL OR NOT bootstrap_auto_pin_allowed)`), returning `volume_id`. On a
       genuine fresh-from-zero installation, **`openmettle_api` (`Store::open` in API)** opens
       `<root>`, `<root>/revisions`, and `<root>/staging` (`O_RDONLY | O_DIRECTORY | O_NOFOLLOW`,
       equal `st_dev`) and performs a plain non-locking `SELECT volume_id,
       bootstrap_auto_pin_allowed, adoption_run_id FROM openmettle.storage_volume_control WHERE
       id`:
       - If `volume_id IS NOT NULL`, `Store::open` **never writes any sentinel** and strictly
         verifies all three existing role-tagged sentinels against `volume_id`.
       - If `volume_id IS NULL AND bootstrap_auto_pin_allowed = true AND adoption_run_id IS NULL`
         (and non-locking empty-ledger precheck passes), **`openmettle_api` (`Store::open` in API
         ONLY)** publishes and `fsync`s all three role-tagged sentinels atomically via the
         crash-safe `linkat` protocol below (adopting any winning valid `:root` UUID on `EEXIST` —
         so two concurrent fresh-bootstrap API pods racing on an empty volume converge on the exact
         same `:root` UUID!), and then calls **`SELECT
         openmettle.storage_pin_volume_id($sentinel_uuid)`** (which acquires `FOR UPDATE`
         internally as `openmettle_owner`, pins `sentinel_uuid` on the first pod, and returns the
         same `sentinel_uuid` cleanly on the second pod with zero `EEXIST` failure or `42501`
         permission error!).
       - **`openmettle_worker` startup contract (never initializes sentinels, never calls
         `storage_pin_volume_id(uuid)`):** `openmettle_worker` has **zero `EXECUTE` privilege** on
         `openmettle.storage_pin_volume_id(uuid)` and **NEVER creates or writes
         `.openmettle-volume-id` sentinels**. If a worker boots while `volume_id IS NULL`
         (worker-first fresh boot or pre-adoption upgrade), worker storage ticks and `publish_bytes`
         observe `OMQ03` / unpinned state cleanly via `openmettle.storage_lock_pinned_volume()`
         (with zero `42501` permission error!) and skip/fail closed cleanly until `volume_id` is
         pinned by `openmettle_api` (fresh bootstrap) or `openmettle storage adopt` (upgrade).
       On **every** upgrade (`bootstrap_auto_pin_allowed = false`) or whenever any row exists in
       `openmettle.storage_reservations` or `openmettle.artifact_revisions` while
       `storage_volume_control.volume_id IS NULL`:
       1. `openmettle.storage_pin_volume_id(uuid)` refuses with `ERRCODE = 'OMQ03'` and
          `Store::open` **MUST NOT** write any `.openmettle-volume-id` sentinel on an unverified
          directory.
       2. All PR2 (`N`) worker storage cleaners — explicitly including **`artifact_fs::purge_due`**
          alongside `artifact_fs::reconcile_expired`, run-linked storage recovery, ADR 0039
          `reconcile_run_spills`, and `staging/` `ReadDir` cleanup — plus ADR 0039 worker
          `publish_bytes` spills **remain disabled (fail closed with zero unlinks, zero released
          holds, and zero `begin_purge`/`confirm_purge` transitions)** while
          `storage_volume_control` is missing or `storage_volume_control.volume_id IS NULL OR
          storage_volume_control.adoption_run_id IS NOT NULL` (while HTTP `Store::stage` and
          `Store::publish` (`openmettle_api`) continue succeeding when `storage_volume_control` is
          present and `adoption_run_id IS NULL` both when `volume_id IS NOT NULL` — via
          `storage_lock_pinned_volume()` + sentinels — and during mixed-version rolling upgrade
          while `volume_id IS NULL`, using plain non-locking `SELECT` and skipping sentinel reads
          while still setting `stage_claimed = true` and binding `payload_ino = staged_ino`).
       3. **Strict 4-step mandatory upgrade sequence (pre-migration `N-1` cleaner quiescence ->
          migration -> 100% `N-1 -> N` replacement -> verified adoption & activation):**
          - *Step 1 (Before migration — MANDATORY `N-1` cleaner quiescence & in-flight sweep
            drain):* Operators **MUST** unset `OPENMETTLE_WORKER_ARTIFACTS_DIR` across all `N-1`
            worker replicas (rolling restart with `OPENMETTLE_WORKER_ARTIFACTS_DIR` unset, or
            scaling `openmettle-worker` to `0`) and confirm zero `N-1` worker processes hold
            `OPENMETTLE_WORKER_ARTIFACTS_DIR` or have an in-flight `worker::maintenance` sweep
            **before** running `openmettle-migrate`, keeping legacy cleaners drained through 100%
            `N-1 -> N` replacement and verified adoption. The **`SECURITY INVOKER`** `BEFORE UPDATE`
            trigger `openmettle.enforce_runtime_storage_volume_pinned()` (`OMQ03`, checking `NOT
            pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')` as the invoker so
            **both** `INHERIT` runtime logins **and** `NOINHERIT` logins executing `SET ROLE
            openmettle_api` or `SET ROLE openmettle_worker` evaluate accurately, and then calling
            `PERFORM openmettle.storage_lock_pinned_volume()`!) on `openmettle.storage_reservations`
            (`WHEN (OLD.state = 'reserved' AND NEW.state = 'released')`) and
            `openmettle.artifact_revisions` (`WHEN (NEW.state IN ('purging', 'purged'))`) executes
            `SELECT ... FROM openmettle.storage_volume_control WHERE id FOR SHARE` as
            `openmettle_owner` (zero `42501` under PostgreSQL 18!) and fails closed with `OMQ03`
            whenever **`NOT FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL`** (failing closed on a
            missing singleton row too!), guarding **BOTH `openmettle_worker` AND `openmettle_api`**:
            it blocks `N-1` `openmettle_api`'s unconditional `abort()` (`src/artifact_fs.rs:584-591`
            executes `let _ = committed(pool, async |tx| storage::release(tx, scope,
            reservation).await).await; error`, ignoring the `OMQ03` release error and returning the
            upload error while leaving the `'reserved'` row intact so a failed same-key upload retry
            during rolling upgrade can never release published `revisions/<id>` bytes; normal `N-1`
            and `N` `reserve` + `settle` uploads continue succeeding without interruption, and any
            failed upload's `'reserved'` row is cleanly reconciled by post-adoption `N`
            `reconcile_expired` once reclaimed on the pinned volume), serializes strictly against
            `openmettle-admin` Step 1b's `storage_volume_control FOR UPDATE` barrier so zero
            in-flight `storage::release` can pass the trigger before Step 1b and commit during Step
            2 (with zero deadlock against `storage_accounts -> storage_instance` updates in
            `storage::adjust`!), and serves as a **PostgreSQL ledger defense-in-depth backstop** for
            `openmettle_worker` — **NOT** a substitute for pre-migration `N-1` worker cleaner
            quiescence because `N-1` workers unlink payload files before mutating PostgreSQL.
          - *Step 2 (Migration):* Run `openmettle-migrate` (`storage_volume_control.volume_id IS
            NULL`, `storage_volume_control.adoption_run_id IS NULL`,
            `storage_volume_control.bootstrap_auto_pin_allowed = false`,
            `quota_enforcement.metering_enforced = false` on every upgrade where `applied >= 1`).
          - *Step 3 (100% `N-1 -> N` binary replacement):* Roll 100% of `openmettle-api` and
            `openmettle-worker` replicas from `N-1` to `N` (`N` workers may have
            `OPENMETTLE_WORKER_ARTIFACTS_DIR` configured because `N` cleaners and ADR 0039
            `publish_bytes` spills invoke `storage_lock_pinned_volume()` + verify all three
            role-tagged directory sentinels/local `st_dev` *before* touching any filesystem path,
            failing closed with zero unlinks while `volume_id IS NULL` or `adoption_run_id IS NOT
            NULL`; meanwhile `N` HTTP `Store::stage` and `Store::publish` continue operating
            smoothly while `adoption_run_id IS NULL`, setting `stage_claimed = true`, binding
            `payload_ino = staged_ino`, and publishing via `linkat` so `staging/<id>` stays present
            on disk until `storage::settle` commits and any mixed-version `N-1` same-key retry hits
            `OpenOptions::create_new(true)` -> `Err(Error::InProgress)` without replacing
            `revisions/<id>`). Confirm **zero `N-1` replicas remain running**.
          - *Step 4 (Verified adoption, pin & activation — with storage-disabled bypass per ADR
            0031):* **Only after zero `N-1` replicas remain**, on storage-enabled installations run
            `openmettle-admin` verified volume adoption (`openmettle storage adopt`, minting
            `my_adoption_run_id = uuid_v4()`, acquiring `storage_volume_control WHERE id FOR UPDATE`
            in Step 1b to set `adoption_run_id = $my_adoption_run_id` strictly before Step 2
            pre-scan, scanning outside DB locks in Step 2, and in Step 3 locking
            `storage_reservations (ORDER BY id ASC FOR UPDATE) -> artifact_revisions (ORDER BY id
            ASC FOR UPDATE) -> storage_volume_control (WHERE id FOR UPDATE) -> storage_accounts
            (ORDER BY scope_id ASC FOR UPDATE) -> storage_instance (WHERE id FOR UPDATE)`, verifying
            `adoption_run_id = $my_adoption_run_id`, enforcing **cross-reservation live inode
            uniqueness** and evaluating ALL `'active'`/`'retained'`/`'purging'`/`'purged'` and
            volume checks **BEFORE** writing any `payload_ino`, preserving valid crash-boundary
            anchors (`.reclaim.<id>` in `'claiming'`/`'truncated'`/`'anchor_pending_unlink'` —
            keeping `'claiming'` as `'claiming'` and requiring `ENOENT` visible names on `'truncated'`
            — `.purge.<id>` & `0`-byte `revisions/<id>` strictly on already-bound `payload_ino IS NOT
            NULL` `'purging'`, `.purge.<id>` in `'purged'`+`anchor_pending_unlink`), handling legacy
            `payload_ino IS NULL` `'purging'` rows (Case 6a exact `(size_bytes, content_digest)` &
            Case 6b non-positive-evidence completion), committing `payload_ino` backfills **ONLY in
            Phase 3C (success branch) strictly onto positively verified non-quarantined rows** when
            volume verification completely succeeds, quarantining missing or
            mismatched `'reserved'` rows with `adoption_unverified = true, publish_pending = false,
            reclaim_state = 'none', reclaim_claim_token = NULL, reclaim_lease_until = NULL`,
            publishing and `fsync`ing all three role-tagged sentinels atomically via `linkat`,
            pinning `storage_volume_control.volume_id`, and clearing `adoption_run_id = NULL` in the
            exact same commit — or omitting/rolling back ALL `payload_ino` backfills and committing
            ONLY `adoption_unverified = true` on missing/mismatched `'reserved'` rows when
            `volume_id IS NOT NULL` plus clearing `adoption_run_id = NULL` before returning `OMQ03`
            on verification failure), then run the pre-upgrade orphan gateway sweep
            (`quota_release_orphan_gateway_requests`) and flip `quota_enforcement.metering_enforced
            = true` in a standalone single-statement transaction. On **storage-disabled
            installations** (both `OPENMETTLE_API_ARTIFACTS_DIR`/`OPENMETTLE_ARTIFACTS_DIR` and
            `OPENMETTLE_WORKER_ARTIFACTS_DIR` unset per
            [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md) AND `0` rows in
            both `storage_reservations` and `artifact_revisions`), Step 4 **skips volume adoption**
            — leaving `storage_volume_control.volume_id IS NULL`, `bootstrap_auto_pin_allowed =
            false`, and all storage cleaners disabled — and proceeds directly after 100% `N-1 -> N`
            binary replacement to run `quota_release_orphan_gateway_requests` and flip
            `quota_enforcement.metering_enforced = true`. If artifact storage is provisioned later,
            operators run `openmettle-admin` verified volume adoption before enabling
            `OPENMETTLE_WORKER_ARTIFACTS_DIR`. **Starting, rolling back to, or resuming any `N-1`
            worker binary after `storage_volume_control.volume_id` is pinned is strictly forbidden
            by the rollout contract**, because `N-1` workers lack Rust role-tagged
            `.openmettle-volume-id` / `payload_ino` / `linkat` verification and unlink before
            mutating PostgreSQL.
     - **Verified, idempotent volume adoption (`openmettle storage adopt`) required on every
       storage-enabled upgrade (`storage_volume_control.volume_id IS NULL` with
       `bootstrap_auto_pin_allowed = false`, run ONLY after zero `N-1` replicas remain):** Enabling
       storage cleaners on an upgraded installation requires an explicit verified volume-adoption
       step (executed by `openmettle_owner` / operator CLI `openmettle-admin` / `openmettle storage
       adopt` procedure documented in PR2's operator runbook update) **before** `Store::open`
       directory creation. Every invocation — **both initial unpinned run and any already-pinned
       operator retry/re-verification after a crash or lost DB commit acknowledgement** — mints a
       unique **`my_adoption_run_id = uuid_v4()`**, executes Step 1a, commits Step 1b's exclusive
       **`storage_volume_control.adoption_run_id = $my_adoption_run_id` pre-scan barrier** strictly
       before Step 2 begins, executes Step 2 pre-scan unconditionally outside DB locks **before**
       Step 3 locks `storage_reservations -> artifact_revisions -> storage_volume_control ->
       storage_accounts -> storage_instance` in canonical order, enforces **cross-reservation live
       inode uniqueness** (explicitly including previously quarantined `adoption_unverified = true`
       candidates on disk) and evaluates ALL `'active'`/`'retained'`/`'purging'`/`'purged'` revision
       and volume checks in Phase 3A **BEFORE** writing any `payload_ino`, preserves verified
       crash-boundary states (`.reclaim.<id>` in `'claiming'`/`'truncated'`/`'anchor_pending_unlink'`
       — keeping `'claiming'` as `'claiming'` — and `.purge.<id>` / already-bound `payload_ino IS
       NOT NULL` `0`-byte `revisions/<id>` in `'purging'`/`'purged'`), handles legacy
       mid-purge `payload_ino IS NULL` `'purging'` rows (Case 6a exact `(size_bytes, content_digest)`
       & Case 6b non-positive-evidence completion), commits `payload_ino`
       backfills **ONLY in Phase 3C (success branch) strictly onto positively verified
       non-quarantined rows** when volume verification completely succeeds
       (omitting/rolling back ALL `payload_ino` backfills on failed adoption!), verifies or
       publishes `.openmettle-volume-id`, and atomically clears `adoption_run_id = NULL` in Step 3's
       exact commit that completes adoption OR (on verification failure) omits all `payload_ino`
       backfills, durably quarantines unaccounted `'reserved'` rows when `volume_id IS NOT NULL`,
       and clears `adoption_run_id = NULL` BEFORE returning `OMQ03`:
       1. *Step 1a — Pre-existing directory, filesystem capability & single-device pre-check (no DB
          lock held):* Open `<root>`, `<root>/staging`, and `<root>/revisions` with `O_RDONLY |
          O_DIRECTORY | O_NOFOLLOW` (never auto-creating directories during adoption), verify local
          same-mount equality (`root_fd_meta.dev() == staging_dir_fd_meta.dev() ==
          revisions_dir_fd_meta.dev()`), qualify mandatory filesystem capabilities (`O_CREAT |
          O_EXCL | O_NOFOLLOW`, `rustix::fs::linkat(..., AtFlags::empty())` rejecting
          `ENOSYS`/`EOPNOTSUPP`/`EINVAL` fail-closed and verifying `Errno::EXIST` on an existing
          target without overwriting it, plus file and directory `fsync`), and capture
          `fstat(revisions_dir_fd)`'s exact `(st_dev, st_ino)`. Also inspect
          `storage_volume_control.volume_id` (failing closed with `OMQ03` if the singleton row is
          missing): if `volume_id IS NOT NULL`, validate all three existing role-tagged
          `.openmettle-volume-id` sentinels (`:root`, `:revisions`, `:staging` via `OFlags::RDONLY |
          OFlags::NOFOLLOW | OFlags::NONBLOCK` + `fstat` `S_ISREG`, local `st_dev` match, bounded
          `<= 64`-byte read) against `volume_id` up front (failing immediately with `OMQ03` without
          mutating DB if sentinels do not match the pinned volume).
       2. *Step 1b — Serialized exclusive adoption-ownership barrier
          (`storage_volume_control.adoption_run_id = $my_adoption_run_id`, committed strictly BEFORE
          Step 2 begins on BOTH unpinned AND already-pinned runs):* Mint unique `my_adoption_run_id
          = uuid_v4()`. Open a short `openmettle_owner` transaction locking **ONLY**
          `storage_volume_control`: **`SELECT volume_id, adoption_run_id INTO STRICT ... FROM
          openmettle.storage_volume_control WHERE id FOR UPDATE`** (failing closed on a missing
          singleton row; because Step 1b locks *only* `storage_volume_control`, zero deadlock cycle
          is possible!). If `adoption_run_id IS NOT NULL`, **fail closed (`OMQ03`) without modifying
          `adoption_run_id`** unless the operator explicitly passed **`--replace-adoption-run
          <stale_uuid>`** matching `adoption_run_id = $stale_uuid` — guaranteeing two concurrent
          adopters can NEVER both enter Step 2 or clear each other's barrier! Execute **`UPDATE
          openmettle.storage_volume_control SET adoption_run_id = $my_adoption_run_id WHERE id`**
          and commit Step 1b immediately **before** Step 2 starts scanning the filesystem or ledger.
          Because `storage_lock_pinned_volume()` (invoked by `enforce_runtime_storage_volume_pinned()`
          and all pinned runtime storage paths) acquires **`FOR SHARE`** on
          `openmettle.storage_volume_control WHERE id` (which conflicts directly with Step 1b's
          **`FOR UPDATE`**, while never touching `storage_instance`!):
          - **Strict serialization with in-flight `storage::release` / `begin_purge` /
            `confirm_purge`:** Any in-flight runtime `storage::release` (or purge) either finishes
            its entire transaction (including `storage_accounts -> storage_instance` counter
            adjustment) and commits strictly **BEFORE** Step 1b acquires `FOR UPDATE`, OR blocks on
            Step 1b's `FOR UPDATE` and fails closed with `OMQ03` once Step 1b commits
            `adoption_run_id = $my_adoption_run_id` — **zero release can ever pass the trigger
            before Step 1b and commit during Step 2, and zero deadlock occurs!**
          - From the instant Step 1b commits until Step 3's final commit clears `adoption_run_id =
            NULL`, **`SECURITY INVOKER` `openmettle.enforce_runtime_storage_volume_pinned()`**
            delegating to **`storage_lock_pinned_volume()`** (`OMQ03`, failing closed on `NOT FOUND
            OR v_vol IS NULL OR v_adopt IS NOT NULL`) blocks every runtime `storage_reservations`
            `'reserved' -> 'released'` transition and every runtime `artifact_revisions` `'->
            purging/purged'` transition across both `openmettle_worker` and `openmettle_api`
            (covering `INHERIT` and `NOINHERIT`/`SET ROLE` logins with zero `42501`), **and** all
            runtime cleaners (`reconcile_expired`, run-linked recovery, ADR 0039
            `reconcile_run_spills`, `purge_due`, `StagingSweepState`), `artifact_fs::abort`,
            `Store::stage`, `Store::publish`, and ADR 0039 `publish_bytes` check
            `adoption_run_id IS NULL` (via `storage_lock_pinned_volume()` when pinned or non-locking
            `SELECT` during unpinned HTTP rolling upgrade)!
          - Normal `storage::reserve` remains allowed (`storage_lock_pinned_volume() ->
            storage_accounts FOR UPDATE -> storage_instance FOR UPDATE -> INSERT
            storage_reservations` when pinned); if a new `'reserved'` row commits during Step 2,
            Step 3 locks every `'reserved'` row in canonical ascending `id` order before
            `storage_volume_control FOR UPDATE` and classifies it under lock.
          - If `openmettle-admin` fails with an I/O or pre-Step-3 error during Step 2, its cleanup
            handler clears `adoption_run_id = NULL` **ONLY `WHERE id AND adoption_run_id =
            $my_adoption_run_id`** under `SELECT adoption_run_id INTO STRICT ... FROM
            openmettle.storage_volume_control WHERE id FOR UPDATE` (never clearing another adopter's
            run ID!); if `openmettle-admin` hard-crashes (`SIGKILL`) mid-Step-2, `adoption_run_id`
            stays `$my_adoption_run_id` fail-closed until the operator explicitly re-runs with
            `--replace-adoption-run <stale_uuid>`.
       3. *Step 2 — Unconditional ledger payload & volume identity pre-scan (executed outside DB
          locks under Step 1b's `storage_volume_control.adoption_run_id = $my_adoption_run_id`
          barrier; defers post-sentinel `OMQ03` failure until Step 3 has cleared `adoption_run_id =
          NULL` and — when `volume_id IS NOT NULL` — durably quarantined unaccounted `'reserved'`
          rows while omitting all `payload_ino` backfills):*
          Record the verified row set, the per-reservation on-disk verification result and verified
          on-disk `st_ino` for every `'reserved'`, `'active'`, `'retained'`, and `'purging'` row
          (plus any valid `revisions/.purge.<id>` anchor on `'purged' AND purge_stage =
          'anchor_pending_unlink'`), whether the ledger was empty on the current snapshot, and any
          post-sentinel verification failure (`deferred_verification_error`):
          - **Genuinely empty storage ledger on an unused upgrade (`0` rows in both
            `storage_reservations` and `artifact_revisions`):** If both `storage_reservations` and
            `artifact_revisions` contain zero rows on an upgraded deployment (`applied >= 1`,
            `bootstrap_auto_pin_allowed = false`), Step 2 records `empty_ledger = true` and
            proceeds to Step 3 **without requiring `--expected-fs-uuid` /
            `--expected-revisions-inode` for nonexistent ledger rows** — subject to mandatory
            re-verification of ledger emptiness under `storage_volume_control FOR UPDATE` in Step 3
            before any sentinel is written.
          - **Published revisions (`artifact_revisions` in `state IN ('active', 'retained')`):**
            Every `openmettle.artifact_revisions` row in `state IN ('active', 'retained')` **MUST**
            exist relative to `<root>/revisions` (`AT_SYMLINK_NOFOLLOW` regular file on
            `revisions_dir_fd`'s local `st_dev` with exact `size_bytes`, matching `sr.payload_ino`
            whenever already non-null, plus sampled SHA-256 `content_digest` verification —
            capturing its verified `file_meta.ino()` in memory for Step 3's **success-only**
            `payload_ino` backfill!). If a `staging/<id>` alias also exists on disk for that
            reservation, it MUST be `S_ISREG` on the same local `st_dev` with the exact same
            `st_ino` as `revisions/<id>` (else record `intra_reservation_inode_mismatch` /
            `foreign_staging_collision` failure!).
            **In-flight `begin_purge` handling on already-pinned retries (`volume_id IS NOT NULL`):**
            although Step 1b's `storage_volume_control FOR UPDATE` barrier serialized every
            in-flight `begin_purge` / `confirm_purge` strictly before Step 2 started, a `purge_due`
            worker that had already committed `begin_purge` (`'retained' -> 'purging'`) immediately
            *before* Step 1b acquired `FOR UPDATE` may finish Stage A -> B -> C concurrently.
            Therefore, whenever `volume_id IS NOT NULL` and on-disk inspection of a row scanned as
            `'retained'` returns `ENOENT`, the verifier **re-queries that revision's current
            `artifact_revisions.state` in a fresh `READ COMMITTED` `SELECT` statement**: if it
            transitioned to `state IN ('purging', 'purged')`, `ENOENT` is accepted as valid
            concurrent `purge_due` progress (subject to the `'purging'` rules below if still
            `'purging'`); if it remains `state IN ('active', 'retained')`, record a post-sentinel
            `OMQ03` verification failure. (During initial adoption while `volume_id IS NULL`, `N-1`
            cleaners are quiesced and `N` cleaners + `enforce_runtime_storage_volume_pinned()`
            forbid `begin_purge`, so any missing `'active'`/`'retained'` file records an
            unconditional post-sentinel `OMQ03` failure.)
          - **In-flight purges (`artifact_revisions` in `state = 'purging'`) & post-confirm purge
            anchors (`state = 'purged' AND purge_stage = 'anchor_pending_unlink'`):**
            - *Post-adoption `'purging'` rows (`sr.payload_ino IS NOT NULL`):* Reserve the
              `st_size == 0` Stage A crash exception **strictly for already-bound post-upgrade
              revisions (`sr.payload_ino IS NOT NULL` AND `st_ino == sr.payload_ino`)**, accepting
              all valid Stage A crash states matching `sr.payload_ino` (`S_ISREG` on `root_dev`):
              (i) `revisions/<id>` with `st_size == size_bytes` (plus SHA-256 `content_digest`
              match),
              (ii) `revisions/<id>` with `st_size == 0` (crash between `sync_all()` and
              `linkat(".purge.<id>")` / `unlinkat`), OR
              (iii) `revisions/.purge.<id>` with `st_size == 0` (with `revisions/<id>` either
              `ENOENT` or also `S_ISREG` with `st_ino == sr.payload_ino` and `st_size == 0`).
              If **BOTH** `revisions/<id>` AND `revisions/.purge.<id>` return `ENOENT` (and a fresh
              `READ COMMITTED` re-query confirms `state <> 'purged'`), OR if either file has
              `st_ino != sr.payload_ino` / wrong type / wrong `st_dev` / wrong size, record a
              post-sentinel `OMQ03` verification failure!
            - *Post-confirm purge anchors (`state = 'purged' AND purge_stage =
              'anchor_pending_unlink' AND NOT sr.adoption_unverified`):* Recognize
              `revisions/.purge.<id>` (`S_ISREG`, `st_dev == root_dev`, `st_ino == sr.payload_ino`,
              `st_size == 0`) as a **valid non-orphan anchor** preserved untouched for Stage C
              cleanup after adoption!
            - *Legacy mid-purge `'purging'` rows (`state = 'purging' AND sr.payload_ino IS NULL`,
              from an interrupted `N-1` purge before migration — pinned `main`'s `purge_due` at
              `src/artifact_fs.rs:227-232, 700-706` calls `fs::remove_file` + `sync_dir` and NEVER
              truncates!):*
              - **Case 6a — Surviving legacy `'purging'` file (`sr.payload_ino IS NULL` and
                `revisions/<id>` present on candidate volume):** Require **exact recorded
                `st_size == size_bytes` AND `sha256 == content_digest`** (identical to `'active'`
                and `'retained'` revisions, plus `S_ISREG`, `st_dev == root_dev`, cross-reservation
                live inode uniqueness below, and `staging_ino == rev_ino` if `staging/<id>` exists,
                else reject adoption with `foreign_staging_collision`!). **NEVER accept `st_size ==
                0` on a surviving non-empty (`size_bytes > 0`) legacy `sr.payload_ino IS NULL`
                `'purging'` revision — if `size_bytes > 0` and `st_size == 0` (or digest differs),
                REJECT adoption with `size_or_digest_mismatch`!** (The `st_size == 0` Stage A crash
                exception is reserved strictly for already-bound post-upgrade revisions with
                `sr.payload_ino IS NOT NULL` AND `st_ino == sr.payload_ino`.) Record `rev_ino` in
                memory for Phase 3C's **success-only** `payload_ino` backfill so normal runtime
                `purge_due` completes Stage A -> B -> C!
              - **Case 6b — Already-absent legacy `'purging'` file (`sr.payload_ino IS NULL` with
                `ENOENT` on `revisions/<id>`, `revisions/.purge.<id>`, AND `staging/<id>`):** If
                `staging/<id>` exists while `revisions/<id>` is `ENOENT`, **reject adoption with
                `ambiguous_legacy_purging_staging_survivor`**! When ALL THREE (`revisions/<id>`,
                `revisions/.purge.<id>`, `staging/<id>`) are `ENOENT`, because `N-1` cleaners are
                drained and Step 1b's `adoption_run_id` blocks all runtime paths, record the row as
                a verified Case 6b legacy completed purge to be finalized atomically in Phase 3C
                (success branch ONLY: `state = 'purged', purged_at = clock_timestamp(), purge_stage
                = 'none'` + decrementing `retained_bytes` on `storage_accounts` and
                `storage_instance`, rolling back and failing adoption if `retained_bytes <
                size_bytes`). **Case 6b absent rows NEVER count as positive on-disk file evidence
                toward volume-identity verification** — volume identity MUST still be established by
                positive `'active'`/`'retained'`/Case 6a SHA-256-verified payloads (or
                `--expected-fs-uuid` + `--expected-revisions-inode`, plus
                `--confirm-no-on-disk-payloads` when zero on-disk payloads exist!).
          - **Outstanding reservations (`storage_reservations` in `state = 'reserved'`), preserving
            valid crash-boundary anchors (`staging/.reclaim.<id>` in `'claiming'`/`'truncated'`),
            and per-reservation individual accounting guard:** Inspect **every individual**
            `storage_reservations` row in `state = 'reserved'`:
            - **Verified `'truncated'` hold preservation:** If `reclaim_state = 'truncated'`, probe
              **`staging/.reclaim.<id>`** (`reclaim_name = format!(".reclaim.{id}")`) AND both
              visible names **`staging/<id>`** and **`revisions/<id>`** via `statat(...,
              AtFlags::SYMLINK_NOFOLLOW)`:
              - Require `staging/.reclaim.<id>` to exist as `S_ISREG` on `staging_dir_fd`'s local
                `st_dev` with **`st_ino as u64 == payload_ino` AND `st_size == 0`**, **AND require
                BOTH `staging/<id>` AND `revisions/<id>` to be `ENOENT`**!
              - If a visible name (`staging/<id>` or `revisions/<id>`) still exists sharing that
                inode on an already-`'truncated'` row, **reject adoption (`OMQ03` /
                `truncated_visible_name_present`)** so visible orphans never pass adoption!
              - When `staging/.reclaim.<id>` matches (`st_ino == payload_ino`, `st_size == 0`) AND
                both `staging/<id>` and `revisions/<id>` are `ENOENT`, Step 2 **positively verifies
                this `'truncated'` hold** so Phase 3C **PRESERVES `reclaim_state = 'truncated'`**
                and expires `reclaim_lease_until = clock_timestamp()` so the next cleaner tick
                finishes Step 3 -> Step 4 cleanly instead of falsely quarantining! Only if
                `staging/.reclaim.<id>` is missing, non-regular, wrong local `st_dev`, `st_ino !=
                payload_ino`, or `st_size != 0` is the `'truncated'` row classified for quarantine
                (`adoption_unverified = true`).
            - **Non-`'truncated'` `'reserved'` holds (`reclaim_state IN ('none', 'claiming')`):**
              Inspect relative to `revisions_dir_fd` and `staging_dir_fd` (`AT_SYMLINK_NOFOLLOW`
              regular file, same local `st_dev`, `0..=max_bytes`, matching `payload_ino` when
              non-null):
              - **Mandatory `LOCK_EX` serialization on every `payload_ino IS NULL` `'reserved'`
                backfill candidate (serializing against cleaner Case 2):** For **every** `'reserved'`
                row with `payload_ino IS NULL` whose on-disk file (`staging/<id>`,
                `staging/.reclaim.<id>`, or `revisions/<id>`) is a candidate for `payload_ino`
                backfill, `openmettle storage adopt` MUST open that file via `openat(...,
                OFlags::RDWR | OFlags::NOFOLLOW, Mode::empty())` (**explicitly WITHOUT
                `OFlags::TRUNC`**), acquire non-blocking **`try_lock()` (`LOCK_EX | LOCK_NB`)** —
                if `WouldBlock` because an in-flight cleaner holds `LOCK_EX`, Step 2 records a
                busy conflict so Step 3 clears `adoption_run_id = NULL` **without quarantining or
                backfilling** and returns a retryable **`OMQ03` busy error**! — re-verify
                `fstat(fd)` (`S_ISREG`, `st_dev == root_dev`, `0..=max_bytes`, and `st_size == 0`
                for `.reclaim.<id>`) and `statat` `(fd_dev, fd_ino)` namespace identity, and
                **hold that `LOCK_EX` file descriptor continuously through Phase 3C's backfill
                commit** (dropping it only after Step 3 commits or aborts)!
              - If `reclaim_state = 'claiming'` and `staging/.reclaim.<id>` exists as `S_ISREG` on
                `root_dev` with `st_size == 0` (matching `payload_ino` if non-null, and with any
                coexisting `staging/<id>` or `revisions/<id>` sharing the exact same `st_ino` and
                `st_size == 0`), **positively verify it as a crash-boundary `'claiming'` anchor** so
                Phase 3C (success branch ONLY) **KEEPS `reclaim_state = 'claiming'` as `'claiming'`
                (NEVER promotes `'claiming'` to `'truncated'`!)** and expires
                **`reclaim_lease_until = clock_timestamp()`** (backfilling `payload_ino` if `NULL`
                on positively verified non-quarantined rows while holding the candidate's `LOCK_EX`
                descriptor) so Step 2 repeats its directory syncs and detaches any surviving
                `staging/<id>` and `revisions/<id>`!
              - If `reclaim_state = 'claiming'` with `staging/<id>` (`0..=max_bytes`, matching
                `payload_ino` when non-null, and any coexisting `revisions/<id>` sharing the exact
                same `st_ino`), positively verify it so Phase 3C **keeps `reclaim_state =
                'claiming'`** and expires `reclaim_lease_until = clock_timestamp()` (backfilling
                `payload_ino` if `NULL` while holding the candidate's `LOCK_EX` descriptor) for
                clean cleaner resumption.
              - Track both the exact set of `'reserved'` rows that are NOT positively verified on
                disk AND every candidate `'reserved'` row's on-disk `st_ino` in memory (explicitly
                including previously quarantined `adoption_unverified = true` rows present on the
                candidate volume, for Phase 3A's cross-reservation live inode uniqueness check and
                Phase 3C's **success-only** `payload_ino` backfill strictly onto positively verified
                non-quarantined rows). Also recognize `staging/.reclaim.<id>` (`S_ISREG`,
                `root_dev`, `st_ino == payload_ino`, `st_size == 0`) on `(state = 'released' AND NOT
                adoption_unverified AND reclaim_state = 'anchor_pending_unlink')` as a valid
                non-orphan anchor.
              - If **zero** digest-bearing revisions (`active`, `retained`, or still-present Case
                6a / post-upgrade `purging` — **never counting Case 6b absent rows!**) were
                positively verified on disk AND `state = 'reserved'` rows exist while zero
                `'reserved'` rows are positively verified on disk, default adoption **MUST fail
                closed (`OMQ03` / CLI error)** unless `--confirm-no-on-disk-payloads` is supplied
                alongside both `--expected-fs-uuid` and `--expected-revisions-inode` — **AND MUST
                NOT return that `OMQ03` early before Step 3 clears `adoption_run_id = NULL` (and
                commits `adoption_unverified = true` when `volume_id IS NOT NULL`, omitting all
                `payload_ino` backfills)**! Moreover — **even when digest-bearing revisions or other
                `'reserved'` rows are present on disk, or when `--expected-fs-uuid` and
                `--expected-revisions-inode` are supplied** — any individual `'reserved'` row that
                is NOT positively verified on disk at adoption commit time is marked
                **`adoption_unverified = true`** in Step 3 so automatic worker cleaners can never
                silently release its `max_bytes` charge!
          - **General zero-verified-revision rule for populated ledgers (covering mixed
            reservation-only ledgers, Case 6b missing-file `purging`-only ledgers, and historical
            `released`/`purged`-only ledgers, on both initial run and retry):** Whenever `>= 1`
            row exists in `storage_reservations` or `artifact_revisions` AND **zero**
            digest-bearing revisions (`active`, `retained`, or positively SHA-256-verified
            still-present Case 6a / post-upgrade `purging` — **Case 6b absent rows NEVER count as
            positive on-disk file evidence!**) were positively verified on disk during Step 2,
            revision checks alone have not cryptographically established directory identity — and
            filesystem UUID alone cannot detect replacing `<root>/revisions` with a fresh empty
            directory on the **same filesystem**. Therefore, `openmettle-admin` adoption **MUST
            require independent evidence for BOTH the mounted filesystem AND the exact `revisions/`
            directory**: **`--expected-fs-uuid <fs_uuid>`** (verified against the mounted filesystem
            backing `<root>`'s `st_dev`) **AND** **`--expected-revisions-inode <dev>:<ino>`**
            (verified against `fstat(revisions_dir_fd)`'s exact `(st_dev, st_ino)`, so replacing
            `<root>/revisions` with a new empty directory on the same filesystem fails
            `--expected-revisions-inode` immediately!), plus an explicit
            **`--confirm-no-on-disk-payloads`** flag alongside `--expected-fs-uuid` and
            `--expected-revisions-inode` for the rare case where every
            `'reserved'`/`'purging'`/`'purged'` row genuinely has zero surviving files on the real
            volume. Whenever this rule fails, Step 2 **records the post-sentinel `OMQ03` error and
            still enters Step 3 first** (protected throughout by Step 1b's `adoption_run_id =
            $my_adoption_run_id` barrier!) so Step 3 omits all `payload_ino` backfills, commits
            `adoption_unverified = true` on unaccounted `'reserved'` rows when `volume_id IS NOT
            NULL`, and clears `adoption_run_id = NULL` BEFORE returning `OMQ03`.
       4. *Step 3 — Canonical full-ledger lock (`storage_reservations -> artifact_revisions ->
          storage_volume_control -> storage_accounts -> storage_instance`), `adoption_run_id =
          $my_adoption_run_id` ownership check, Phase 3A cross-reservation live inode uniqueness &
          verification-first gating, Phase 3B zero-backfill failure branch, and Phase 3C
          success-only `payload_ino` backfill, legacy `'purging'` Cases 6a/6b completion, verified
          crash-state normalization, sentinel publication via `linkat`, and atomic `adoption_run_id
          = NULL` clear:*
          Open an `openmettle_owner` transaction and acquire locks in strict canonical order:
          1. `SELECT id FROM openmettle.storage_reservations ORDER BY id ASC FOR UPDATE`
          2. `SELECT id FROM openmettle.artifact_revisions ORDER BY id ASC FOR UPDATE`
          3. `SELECT volume_id, bootstrap_auto_pin_allowed, adoption_run_id INTO STRICT ... FROM
             openmettle.storage_volume_control WHERE id FOR UPDATE` **strictly before creating,
             writing, or linking any `.openmettle-volume-id` file or unlinking any `.tmp.*` file**
          4. `SELECT scope_id FROM openmettle.storage_accounts ORDER BY scope_id ASC FOR UPDATE`
          5. `SELECT id FROM openmettle.storage_instance WHERE id FOR UPDATE`
          **Immediately assert `adoption_run_id = $my_adoption_run_id`** (aborting with `OMQ03` and
          zero writes if displaced by an operator `--replace-adoption-run`!). Because
          `storage::reserve`, `storage::settle`, `storage::release`, `retain_revision`,
          `restore_revision`, and `confirm_purge` in `src/storage.rs` respect this exact canonical
          DAG (`runs -> storage_reservations -> artifacts -> artifact_revisions ->
          storage_volume_control [via storage_lock_pinned_volume()] -> storage_accounts ->
          storage_instance`), this serializes cleanly against every concurrent storage operation
          with zero deadlock:
          - **Phase 3A — Read-only verification & cross-reservation live inode uniqueness under lock
            BEFORE writing ANY `payload_ino`:**
            - Verify sentinel preconditions under lock: if `volume_id IS NOT NULL`, re-verify all
              three existing `.openmettle-volume-id` sentinels (`:root`, `:revisions`, `:staging`
              via `openat(..., O_RDONLY | O_NOFOLLOW | O_NONBLOCK)` + `fstat` `S_ISREG` and local
              `st_dev` match, bounded `<= 64`-byte read) match `volume_id` — if any sentinel is
              missing, mismatched, wrong-role, non-regular (including FIFO/symlink), or on a
              different local `st_dev`, roll back immediately with `OMQ03` without writing any
              sentinel or `payload_ino`.
            - Re-check under lock for any `storage_reservations` or `artifact_revisions` rows
              committed since Step 2. If **any** newly committed `'reserved'` or
              `'active'`/`'retained'`/`'purging'` row exists outside the locked set (or if Step 2
              used the empty-ledger waiver while `volume_id IS NULL` and any row now exists), roll
              back strictly before any sentinel or `payload_ino` write (keeping `adoption_run_id =
              $my_adoption_run_id` across the retry!) and retry from Step 2/Step 3 so every row is
              locked and classified under lock.
            - **Mandatory cross-reservation live inode uniqueness (and intra-reservation inode
              agreement), explicitly EXCLUDING retired historical inodes:** Restrict Phase 3A's
              cross-reservation live inode uniqueness comparison **strictly to live payloads,
              surviving anchors, and all candidates for `payload_ino` backfill or
              `adoption_unverified = false` clearance** — namely:
              - `artifact_revisions` with `state IN ('active', 'retained')`, surviving `state =
                'purging'`, OR `(state = 'purged' AND purge_stage = 'anchor_pending_unlink')`; AND
              - `storage_reservations` with `(state = 'reserved' AND (payload_ino IS NOT NULL OR
                candidate for payload_ino backfill or adoption_unverified = false clearance —
                explicitly INCLUDING previously quarantined adoption_unverified = true rows whose
                on-disk file is present on the candidate volume!))` OR `(state = 'released' AND
                reclaim_state = 'anchor_pending_unlink')`.
              - **Explicitly EXCLUDE retired historical rows whose files and anchors have already
                been detached:** `(state = 'released' AND reclaim_state = 'none')` AND `state =
                'settled'` rows whose revision is `(artifact_revisions.state = 'purged' AND
                purge_stage = 'none')`! (After Step 4 or Stage C unlinks a retired file's last
                anchor, the filesystem may legitimately reassign that freed inode number to a new
                upload; excluding retired historical rows prevents false
                `cross_reservation_inode_alias` failures during re-adoption on a healthy volume.)
              Considering BOTH pre-populated `payload_ino` and newly observed on-disk `st_ino`
              values across that strictly live/anchor/candidate comparison set:
              1. *Intra-reservation agreement:* Within a **single** reservation `R`, its verified
                 on-disk names (`staging/R`, `staging/.reclaim.R`, `revisions/R`,
                 `revisions/.purge.R`) and any existing non-null `R.payload_ino` MAY share one
                 common inode `ino(R)` and **MUST agree on that single inode** — if `staging/R` and
                 `revisions/R` have distinct inodes on a `'settled'`, `'purging'`, or `'reserved'`
                 row, fail Phase 3A with **`intra_reservation_inode_mismatch` /
                 `foreign_staging_collision`**! For any row already in `reclaim_state =
                 'truncated'`, Phase 3A additionally requires `staging/.reclaim.R` (`st_size == 0`,
                 `st_ino == payload_ino`) AND requires BOTH `staging/R` and `revisions/R` to be
                 `ENOENT` (failing Phase 3A with **`truncated_visible_name_present`** if visible
                 names still share that inode!).
              2. *Cross-reservation uniqueness (`R1 <> R2 => ino(R1) <> ino(R2)`):* Across
                 **distinct** reservations `R1 <> R2` in the live/anchor/candidate comparison set
                 above (excluding retired historical rows `(state = 'released' AND reclaim_state =
                 'none')` and `'settled'` rows with `(artifact_revisions.state = 'purged' AND
                 purge_stage = 'none')`), **`ino(R1)` MUST NOT equal `ino(R2)`!** If any two
                 distinct reservation IDs in that set resolve to the same `st_ino` (for example, a
                 legacy `'reserved'` row `A` — OR a previously quarantined `adoption_unverified =
                 true, payload_ino IS NULL` row `A` — whose `staging/A` is a hard link to active
                 `revisions/B` of another reservation `B`!), Phase 3A **fails adoption closed with
                 `cross_reservation_inode_alias`** — entering Phase 3B with **ZERO `payload_ino`
                 backfills** so `A`'s cleaner can never pass `st_ino == A.payload_ino` and truncate
                 `revisions/B`!
            - **Adoption `LOCK_EX` serialization for `payload_ino IS NULL` `'reserved'` backfill
              candidates:** For every locked `'reserved'` row with `payload_ino IS NULL` whose
              on-disk file (`staging/<id>`, `staging/.reclaim.<id>`, or `revisions/<id>`) is a
              candidate for `payload_ino` backfill, `openmettle storage adopt` MUST hold an open
              descriptor opened with **`OFlags::RDWR | OFlags::NOFOLLOW` (explicitly WITHOUT
              `OFlags::TRUNC`)** with non-blocking **`try_lock()` (`LOCK_EX | LOCK_NB`)** and
              re-verified `fstat(fd)` + `statat` namespace identity (acquired in Step 2 or before
              Phase 3C). If `try_lock()` returns **`WouldBlock`** (because an in-flight cleaner
              currently holds `LOCK_EX` on that file), Step 3 **MUST clear `adoption_run_id = NULL`
              (`WHERE id AND adoption_run_id = $my_adoption_run_id`) without quarantining or
              backfilling any row and return a retryable `OMQ03` busy error!** Otherwise, keep all
              acquired `LOCK_EX` descriptors open **continuously through Phase 3C's backfill
              commit** (dropping them only AFTER the Step 3 transaction commits or rolls back).
            - Evaluate EVERY `'active'`/`'retained'`/`'purging'` revision check (including legacy
              `'purging'` Case 6a exact recorded `(size_bytes, content_digest)` verification —
              rejecting `st_size == 0` when `size_bytes > 0` with `size_or_digest_mismatch` — Case
              6b `ambiguous_legacy_purging_staging_survivor` rejection and non-positive evidence
              rule), every `'purged' AND purge_stage = 'anchor_pending_unlink'` anchor check, every
              already-`'truncated'` `ENOENT` visible-name check, AND every volume-identity check
              (`--expected-fs-uuid`, `--expected-revisions-inode`, `--confirm-no-on-disk-payloads`
              when `0` digest-bearing revisions are verified — never counting Case 6b absent rows!)
              **BEFORE mutating any `payload_ino` column**!
          - **Phase 3B — Failure branch (`deferred_verification_error` is set, including
            `cross_reservation_inode_alias`, `intra_reservation_inode_mismatch`,
            `foreign_staging_collision`, `size_or_digest_mismatch`,
            `truncated_visible_name_present`, or `ambiguous_legacy_purging_staging_survivor` —
            NEVER commit `payload_ino` backfills on failed adoption!):**
            - **Omit / roll back ALL `payload_ino` backfills and ALL Case 6b purge completions!**
              Never write `payload_ino` from an unverified or failed tree (for example, a partial
              copied tree, a `0`-byte replacement for a non-empty legacy `'purging'` revision, or a
              hard-linked `staging/A -> revisions/B` alias), so retrying adoption after remediation
              succeeds cleanly with real inodes! (And on a retryable `LOCK_EX` `WouldBlock` busy
              error, commit ONLY `UPDATE openmettle.storage_volume_control SET adoption_run_id =
              NULL WHERE id AND adoption_run_id = $my_adoption_run_id` with zero quarantine and
              zero backfill before returning `OMQ03`!)
            - If `volume_id IS NOT NULL` (already-pinned verification failure on a volume whose
              three role-tagged sentinels matched `volume_id`), commit ONLY `UPDATE
              openmettle.storage_reservations SET adoption_unverified = true, publish_pending =
              false, reclaim_state = 'none', reclaim_claim_token = NULL, reclaim_lease_until = NULL
              WHERE id = ANY($unaccounted_or_mismatched_reserved_ids) AND state = 'reserved' AND NOT
              adoption_unverified` together with **`UPDATE openmettle.storage_volume_control SET
              adoption_run_id = NULL WHERE id AND adoption_run_id = $my_adoption_run_id`** (writing
              zero sentinels and zero `payload_ino` backfills!), commit, and return `OMQ03`.
            - If `volume_id IS NULL` (initial unpinned adoption failed verification — e.g., wrong,
              partial, or cross-aliased tree), commit ONLY **`UPDATE
              openmettle.storage_volume_control SET adoption_run_id = NULL WHERE id AND
              adoption_run_id = $my_adoption_run_id`** (zero sentinels written, zero `payload_ino`
              backfills, leaving `volume_id IS NULL` so all cleaners stay disabled until the
              operator resolves the anomaly!), and return `OMQ03`.
          - **Phase 3C — Success branch (ALL sentinel, cross-reservation uniqueness, revision, and
            volume verification checks passed!):**
            - **Quarantine missing/mismatched `'reserved'` rows and explicitly un-quarantine only
              positively verified previously-quarantined rows (strictly BEFORE `payload_ino`
              backfill):** Execute **`UPDATE openmettle.storage_reservations SET adoption_unverified
              = true, publish_pending = false, reclaim_state = 'none', reclaim_claim_token = NULL,
              reclaim_lease_until = NULL WHERE id = ANY($unaccounted_or_mismatched_reserved_ids) AND
              state = 'reserved' AND NOT adoption_unverified`** for every locked `'reserved'` row
              that was NOT positively verified on disk (including any `'truncated'` row whose
              `staging/.reclaim.<id>` was missing or mismatched). Conversely, any locked
              `'reserved'` row previously marked `adoption_unverified = true` that IS now positively
              verified on disk (matching `payload_ino` when non-null and passing Phase 3A's live
              cross-reservation inode uniqueness check) on the restored original directory tree may
              be explicitly un-quarantined (`SET adoption_unverified = false`) by `openmettle-admin`
              adoption (`openmettle_owner`) in this locked success transaction.
            - **Success-only `payload_ino` backfill (`openmettle_owner` privilege — strictly ONLY
              onto positively verified non-quarantined rows; NEVER onto any row remaining
              `adoption_unverified = true`!):** Commit `payload_ino` backfills (`WHERE payload_ino
              IS NULL AND NOT adoption_unverified`) **ONLY here in Phase 3C** (while continuously
              holding the `LOCK_EX` descriptors acquired on all `payload_ino IS NULL` `'reserved'`
              backfill candidates through this commit!):
              - For every locked `'active'`/`'retained'` `artifact_revisions` row positively
                verified on disk at `revisions/<reservation_id>`, AND every **Case 6a surviving
                legacy `'purging'` row** (`sr.payload_ino IS NULL` with exact recorded `st_size ==
                size_bytes` AND `sha256 == content_digest` at `revisions/<reservation_id>`), execute
                `UPDATE openmettle.storage_reservations SET stage_claimed = true, payload_ino =
                $file_ino::text::numeric(20, 0) WHERE scope_id = $scope_id AND id = $reservation_id
                AND payload_ino IS NULL AND NOT adoption_unverified` (enabling normal runtime
                `purge_due` to complete Stage A -> B -> C on Case 6a rows!).
              - For every locked non-`'truncated'` `'reserved'` row that is positively verified on
                disk at `revisions/<id>`, `staging/<id>`, or `staging/.reclaim.<id>` AND is
                non-quarantined (`NOT adoption_unverified`), execute `UPDATE
                openmettle.storage_reservations SET stage_claimed = true, payload_ino =
                $file_ino::text::numeric(20, 0) WHERE scope_id = $scope_id AND id = $id AND state =
                'reserved' AND payload_ino IS NULL AND NOT adoption_unverified` (**NEVER writing
                `payload_ino` onto any row that stays `adoption_unverified = true`!**).
            - **Case 6b legacy already-absent `'purging'` completion (inside this atomic Step 3
              `openmettle_owner` transaction holding `storage_reservations -> artifact_revisions ->
              storage_volume_control -> storage_accounts -> storage_instance FOR UPDATE`):** For
              every verified Case 6b legacy `'purging'` row (`sr.payload_ino IS NULL` with `ENOENT`
              on `revisions/<id>`, `revisions/.purge.<id>`, AND `staging/<id>`), directly finalize
              the interrupted `N-1` purge: `UPDATE openmettle.artifact_revisions SET state =
              'purged', purged_at = clock_timestamp(), purge_stage = 'none' WHERE scope_id =
              $scope_id AND id = $rev_id AND state = 'purging'` and decrement `retained_bytes =
              retained_bytes - $size_bytes` on `openmettle.storage_accounts` (`WHERE scope_id =
              $scope_id`) and `openmettle.storage_instance` (`WHERE id`) — rolling back the entire
              transaction and failing adoption if `retained_bytes < $size_bytes` on either row!
            - **Preserve verified crash-boundary `'reserved'` holds (NEVER promote `'claiming'` to
              `'truncated'`!):**
              - For every locked non-quarantined `'reserved'` row in `reclaim_state = 'claiming'`
                positively verified via `staging/.reclaim.<id>` (`st_size == 0`, cross-reservation
                unique, with any coexisting `staging/<id>`/`revisions/<id>` sharing the exact same
                `st_ino` and `st_size == 0`) OR via `staging/<id>` (`0..=max_bytes`), **KEEP
                `reclaim_state = 'claiming'` as `'claiming'` (do NOT promote `'claiming'` to
                `'truncated'`)** and expire its lease (**`UPDATE openmettle.storage_reservations SET
                reclaim_lease_until = clock_timestamp() WHERE id = $id AND state = 'reserved' AND
                NOT adoption_unverified AND reclaim_state = 'claiming'`** after backfilling
                `payload_ino` if `NULL`), so Step 2 repeats its directory syncs and detaches any
                surviving `staging/<id>` and `revisions/<id>` cleanly!
              - For every locked non-quarantined `'reserved'` row already in `reclaim_state =
                'truncated'` whose `staging/.reclaim.<id>` was positively verified (`S_ISREG`, same
                local `st_dev`, `st_ino == payload_ino`, `st_size == 0`) AND whose `staging/<id>`
                and `revisions/<id>` were both `ENOENT`, **PRESERVE `reclaim_state = 'truncated'`**
                and expire its lease (`UPDATE openmettle.storage_reservations SET
                reclaim_lease_until = clock_timestamp() WHERE id = $id AND state = 'reserved' AND
                NOT adoption_unverified AND reclaim_state = 'truncated'`) so the next cleaner tick
                finishes Step 3 -> Step 4 cleanly instead of quarantining!
            - **Already-pinned success sub-branch (`volume_id IS NOT NULL` — lost commit-ack retry
              or re-verification):** **NEVER create, write, or link any missing sentinel.** Having
              already verified all three existing `.openmettle-volume-id` sentinels (`:root`,
              `:revisions`, `:staging`) match `storage_volume_control.volume_id`, execute **`UPDATE
              openmettle.storage_volume_control SET adoption_run_id = NULL WHERE id AND
              adoption_run_id = $my_adoption_run_id`** alongside the success-branch updates above,
              commit atomically, and return idempotent success.
            - **Unpinned success sub-branch (`volume_id IS NULL`) — crash-safe, race-free sentinel
              publication with root `fsync` barrier (shared protocol with `openmettle_api`
              `Store::open` fresh-bootstrap auto-pinning):**
              - Never create `.openmettle-volume-id` directly with `O_CREAT | O_EXCL` before writing
                its payload (a crash between `openat` and `write` would leave a 0-byte sentinel that
                causes every retry to fail permanently). Instead:
                - *No live-peer `.tmp.*` interference:* Publishers **NEVER** run an uncoordinated
                  wildcard unlink of `.openmettle-volume-id.tmp.*`. Each publisher creates a unique
                  `.openmettle-volume-id.tmp.<128bit_random_hex>` (`OFlags::WRONLY | OFlags::CREATE |
                  OFlags::EXCL | OFlags::NOFOLLOW`, `Mode::RUSR | Mode::WUSR`) and unlinks **only its
                  own `tmp_name`** in an unconditional cleanup guard after `linkat` or error;
                  leftover `.openmettle-volume-id.tmp.*` files from a prior `SIGKILL` are unlinked
                  **only by `openmettle_owner` while holding `storage_volume_control FOR UPDATE`**
                  when `rustix::fs::statat(..., AtFlags::SYMLINK_NOFOLLOW)` shows `st_mtime` older
                  than `300 s`.
                - *Winning `:root` UUID adoption & mandatory `fsync(root_fd)` barrier before child
                  sentinels:* Before generating a UUID, inspect `<root>/.openmettle-volume-id` via
                  `openat(root_fd, ".openmettle-volume-id", OFlags::RDONLY | OFlags::NOFOLLOW |
                  OFlags::NONBLOCK)` + `fstat` (`S_ISREG` on `<root>`'s local `st_dev`, bounded `<=
                  64`-byte read) — if present, verify it contains valid `"<existing_uuid>:root\n"`
                  and adopt `sentinel_uuid = existing_uuid` (failing closed with `OMQ03` if
                  symlinked, FIFO/non-regular, wrong local `st_dev`, or malformed); otherwise
                  generate a fresh canonical lowercase v4 UUID. Publish `(root_fd, "root")` **first**:
                  create unique `tmp_name = ".openmettle-volume-id.tmp.<128bit_random_hex>"` relative
                  to `root_fd` (`OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW`,
                  `Mode::RUSR | Mode::WUSR`), write the complete `"<sentinel_uuid>:root\n"` payload,
                  **`fsync` the temp FD**, close it, publish via **`linkat(root_fd, tmp_name,
                  root_fd, ".openmettle-volume-id", AtFlags::empty())`** (POSIX atomic hard-link
                  creation, which never exposes a 0-byte or partial `.openmettle-volume-id` and fails
                  with `EEXIST` without overwriting any existing sentinel), and unconditionally
                  unlink **only its own `tmp_name`** in the cleanup guard. If `linkat` on
                  `<root>/.openmettle-volume-id` returns `EEXIST`, re-open and validate
                  `<root>/.openmettle-volume-id` (`OFlags::RDONLY | OFlags::NOFOLLOW |
                  OFlags::NONBLOCK` + `fstat` `S_ISREG` on `<root>`'s local `st_dev`, bounded `<=
                  64`-byte read, `"<winning_uuid>:root\n"`) and **adopt `sentinel_uuid =
                  winning_uuid`** (verifying `volume_id IS NULL OR volume_id = winning_uuid`).
                  **Immediately after publishing (or adopting on `EEXIST`) `(root_fd, "root")`, call
                  and require `Ok(())` from `fsync(root_fd)` strictly BEFORE creating or linking
                  either child sentinel (`(revisions_dir_fd, "revisions")` or `(staging_dir_fd,
                  "staging")`)** — preventing a storage-host crash from persisting a child sentinel
                  while losing `<root>/.openmettle-volume-id`. Only after `fsync(root_fd)` succeeds,
                  publish `(revisions_dir_fd, "revisions")` and `(staging_dir_fd, "staging")` via the
                  exact same unique `tmp_name` + `fsync(tmp_fd)` + `linkat` + own-`tmp_name`
                  `unlinkat` protocol (on `EEXIST`, validating exact `"<sentinel_uuid>:<role>\n"` via
                  `OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK` + `fstat` `S_ISREG` on the
                  same local `st_dev`, failing closed with `OMQ03` on mismatch/wrong-role/corruption),
                  and then **call and require `Ok(())` from `fsync(revisions_dir_fd)` and
                  `fsync(staging_dir_fd)` strictly BEFORE pinning `storage_volume_control.volume_id`**.
                - On `openmettle-admin` adoption (`openmettle_owner`), still inside the Step 3
                  `storage_volume_control FOR UPDATE` transaction (alongside the Phase 3C
                  quarantine/un-quarantine updates, non-quarantined `payload_ino` backfills, Case 6b
                  completions, and verified crash-state lease expirations), set **`volume_id =
                  sentinel_uuid, bootstrap_auto_pin_allowed = false, adoption_run_id = NULL`**
                  (`WHERE id AND adoption_run_id = $my_adoption_run_id`) and commit atomically. On
                  fresh-bootstrap `Store::open` (**`openmettle_api` ONLY — `openmettle_worker` never
                  initializes sentinels and never calls `storage_pin_volume_id(uuid)`!**), call
                  **`SELECT openmettle.storage_pin_volume_id($sentinel_uuid)`** (`SECURITY DEFINER`,
                  acquiring `storage_volume_control FOR UPDATE` internally as `openmettle_owner` and
                  converging idempotently across concurrent fresh-bootstrap API pods adopting the
                  same winning `:root` UUID!).
     - **Unified rollout rule, directory-descriptor binding across ALL `artifact_fs::Store`
       operations, durable `Store::stage` (Steps 1a/1b/1c with `fsync` before `payload_ino`),
       100% non-destructive `Drop`, `linkat` no-replace publication keeping `staging/<id>` present
       until `storage::settle` commits (closing mixed-version `N-1` HTTP retry replacement),
       `Store::read` `payload_ino` verification, filesystem & `ReadWriteMany` qualification, and
       unified 4-step reclamation with `staging/.reclaim.<id>` anchor across ALL 4 cleaners
       (`abort`, `reconcile_expired`, generic run-linked recovery, ADR 0039
       `reconcile_run_spills`):**
       Existing [`src/artifact_fs.rs`](../../src/artifact_fs.rs) stores `PathBuf`s, re-resolves
       `<root>/revisions` by pathname at `rename` time, drops its staging sink (unlinking by
       pathname) before DB locking, and unconditionally releases reservations inside `abort()`
       (`src/artifact_fs.rs:505-520, 584-591`). PR2 closes every one of these windows:
       - **Unified rollout rule (synchronized verbatim with ADR 0039):** HTTP `Store::stage` and
         `Store::publish` (`openmettle_api`) succeed when `storage_volume_control` is present and
         `adoption_run_id IS NULL` both when `volume_id IS NOT NULL` (verifying role-tagged
         sentinels) and during mixed-version rolling upgrade while `volume_id IS NULL` (skipping
         sentinel reads while still setting `stage_claimed = true` and binding `payload_ino =
         staged_ino`), whereas ADR 0039 worker `publish_bytes` spills and all 4 cleaners
         (`artifact_fs::abort`, non-run `reconcile_expired`, generic run-linked recovery, ADR 0039
         `reconcile_run_spills`) plus `artifact_fs::purge_due` and `StagingSweepState` strictly
         require **`storage_volume_control` present AND `volume_id IS NOT NULL AND adoption_run_id
         IS NULL`**!
       - **Directory-descriptor binding & local-only `st_dev` verification (`payload_dev` dropped;
         only unsigned 64-bit `payload_ino numeric(20, 0)` stored in PostgreSQL):** Because Linux
         NFS assigns client-local anonymous `st_dev` via `get_anon_bdev` (causing cross-node false
         mismatches), PostgreSQL stores **only `payload_ino numeric(20, 0)`** (`CHECK (payload_ino
         IS NULL OR payload_ino >= 0)`). On each host, `artifact_fs::Store` retains `Arc`-shared
         verified directory descriptors (`root_fd`, `staging_dir_fd`, `revisions_dir_fd`: `OwnedFd`
         opened via `rustix::fs::openat` with `OFlags::RDONLY | OFlags::DIRECTORY |
         OFlags::NOFOLLOW` plus their host-local `(st_dev, st_ino)` pairs), verifies host-local
         same-mount equality (`file_meta.dev() == dir_fd_meta.dev() == root_fd_meta.dev()`) using
         only that host's open FDs, verifies role-tagged `.openmettle-volume-id` sentinels when
         `storage_volume_control.volume_id IS NOT NULL`, compares `file_meta.ino() == payload_ino`,
         and executes **ALL** `Store` filesystem operations strictly relative to those verified
         directory descriptors.
       - **Filesystem & `ReadWriteMany` shared-volume qualification (`O_CREAT | O_EXCL | O_NOFOLLOW`,
         `linkat`, file + directory `fsync`, cross-client `flock(2)`, AND stable 64-bit `st_ino`
         coherence + second-client recovery):** Startup (`Store::open`), adoption (Step 1a), and
         shared-volume qualification probe and require:
         1. `O_CREAT | O_EXCL | O_NOFOLLOW`,
         2. **`rustix::fs::linkat(..., AtFlags::empty())`** (mandatory POSIX/NFS `LINK` — rejecting
            `ENOSYS`/`EOPNOTSUPP`/`EINVAL` fail-closed and verifying `Errno::EXIST` on an existing
            target without overwriting it!),
         3. file and directory `fsync` (`sync_all`), AND
         4. for multi-node `ReadWriteMany` shared volumes (POSIX/NFS mounts shared across API and
            worker replicas): **BOTH** two-client / separate-mount `flock(2)` (`LOCK_SH` vs
            `LOCK_EX | LOCK_NB` `WouldBlock`) coherence (strictly forbidding client-local flock
            options such as Linux NFS `-o local_lock=flock` / `-o local_lock=all` or NFSv3 without
            working `lockd`) **AND** **stable 64-bit `st_ino` coherence + second-client recovery**
            across clients and remounts! Because on Linux NFS (`man 2 flock`), `flock(LOCK_EX)` maps
            to `fcntl(F_SETLK, F_WRLCK)` and fails with `EBADF` on `O_RDONLY` file descriptors
            (whereas `LOCK_SH` maps to `F_RDLCK` and works on `O_RDONLY`), **EVERY `LOCK_EX` /
            `try_lock()` open across all cleaners, anchor detaches, and `StagingSweepState` MUST
            open with `OFlags::RDWR | OFlags::NOFOLLOW` (explicitly WITHOUT `OFlags::TRUNC` and
            preserving zero `set_len(0)` on reopen/detach/sweep paths!)**, while `OFlags::RDONLY |
            OFlags::NOFOLLOW | OFlags::NONBLOCK` (followed by immediate `is_file()` check) remains
            valid for shared `LOCK_SH` (`Store::read` and post-`settle` publisher detach).
       - **`Store::stage` (`openmettle_api` — Steps 1a/1b/1c, crash-durable `fsync` strictly BEFORE
         binding `payload_ino`, and 100% non-destructive `Drop`):**
         1. *Step 1a (DB Stage Claim strictly BEFORE touching disk):* Run a short lock-ordered
            primary DB transaction (`(runs FOR NO KEY UPDATE ->) storage_reservations FOR UPDATE` +
            when pinned, `SELECT openmettle.storage_lock_pinned_volume()` verifying returned
            `volume_id == expected_volume_id` and failing `OMQ03` if missing, unpinned, or adopting;
            during the pre-adoption rolling-upgrade window while `volume_id IS NULL`, a plain
            non-locking `SELECT volume_id, adoption_run_id FROM openmettle.storage_volume_control
            WHERE id` failing closed if missing or `adoption_run_id IS NOT NULL` — since runtime
            roles hold `SELECT`-only on `storage_volume_control` and never execute invoker `FOR
            SHARE`) committing: `UPDATE openmettle.storage_reservations SET stage_claimed = true
            WHERE scope_id = $1 AND id = $2 AND state = 'reserved' AND NOT adoption_unverified AND
            NOT stage_claimed AND payload_ino IS NULL AND reclaim_state = 'none'`. If rejected (0
            rows updated), **zero disk files are created**!
         2. *Step 1b (Create & durably sync `staging/<id>` strictly BEFORE binding `payload_ino`):*
            Re-verify `<root>`, `"staging"`, and `"revisions"` directory FDs via fresh pathname
            re-open (`OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW`, equal local `(st_dev,
            st_ino)` + role-tagged `:root`/`:staging`/`:revisions` sentinels when `volume_id IS NOT
            NULL`). Create `staging/<id>` via `rustix::fs::openat(&staging_dir_fd, id,
            OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW, Mode::RUSR |
            Mode::WUSR)` (`0` bytes) -> `std::fs::File::from(owned_fd)` -> immediately acquire
            non-blocking shared flock **`file.try_lock_shared()`** (`LOCK_SH | LOCK_NB`, returning
            `Error::InProgress` on `WouldBlock`) -> verify `file_meta = file.metadata()?` against
            `rustix::fs::statat(&staging_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` (`S_ISREG`, local
            same-mount `file_meta.dev() == staging_dir_fd_dev == root_fd_dev`, `staged_ino =
            file_meta.ino()`) -> **call and require `Ok(())` from `fsync(&staging_dir_fd)`** so
            `staging/<id>` is crash-durable on disk **strictly BEFORE `payload_ino` can ever commit
            in PostgreSQL**!
         3. *Step 1c (DB Bind `payload_ino`):* While holding `LOCK_SH`, run a short lock-ordered
            `FOR UPDATE` transaction (`(runs FOR NO KEY UPDATE ->) storage_reservations FOR UPDATE`
            + `SELECT openmettle.storage_lock_pinned_volume()` when pinned, or plain `SELECT` check
            of `adoption_run_id IS NULL` while `volume_id IS NULL`) committing `UPDATE
            openmettle.storage_reservations SET payload_ino = $3::text::numeric(20, 0) WHERE
            scope_id = $1 AND id = $2 AND state = 'reserved' AND NOT adoption_unverified AND
            stage_claimed AND payload_ino IS NULL AND reclaim_state = 'none'`.
         4. *100% Non-Destructive `Drop` & Writer Error Handling (zero `set_len(0)` or `unlinkat`
            on `Drop`; ambiguous `storage::settle` inspection):* **`StagedFile::drop` (and all
            writer error/cancellation paths in `Store::stage`, `Store::publish`, and ADR 0039
            `publish_bytes`) NEVER calls `set_len(0)` and NEVER calls `unlinkat` — it ONLY closes
            the file descriptor (releasing `LOCK_SH`/`LOCK_EX`)!** `StagedFile` retains `LOCK_SH`
            continuously through `Store::publish`, `linkat`, directory `fsync`, `storage::settle`'s
            `tx.commit()`, AND the post-`commit` `staging/<id>` alias detach:
            - If Step 1c commits in PostgreSQL and the client loses the commit acknowledgement,
              `staging/<id>` (`st_ino == payload_ino`, already `fsync`ed in Step 1b!) remains
              durably linked on disk so `reconcile_expired` / `artifact_fs::abort` cleanly reclaims
              it with **zero false quarantine**!
            - If `storage::settle` commits in PostgreSQL and the client loses the commit
              acknowledgement or cancels the future, dropping `StagedFile` **NEVER zeroes published
              `revisions/<id>`** (and any remaining `staging/<id>` alias sharing `payload_ino` is
              cleanly detached by `StagingSweepState` without `set_len(0)`)!
            - On an ambiguous `storage::settle` commit outcome (`UnknownCommit`), callers **MUST
              NEVER invoke `artifact_fs::abort` blindly**: inspect `storage_reservations.state`
              under `(runs FOR NO KEY UPDATE ->) storage_reservations FOR UPDATE` first — if `state
              = 'settled'`, publication succeeded!
       - **No-replace `linkat` publication keeping `staging/<id>` present until `storage::settle`
         commits (`Store::publish` & synchronized 5-step ADR 0039 `publish_bytes` pre-publication
         `publish_pending` fence — closing mixed-version `N-1` HTTP retry replacement):**
         1. *HTTP `Store::publish` (`openmettle_api`):*
            - *Pre-`linkat` verification & durable `publish_pending = true` commit:* While
              `StagedFile` holds `LOCK_SH`, re-verify `<root>`, `"staging"`, and `"revisions"` FDs
              via fresh pathname re-open (`OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW`,
              matching local `(st_dev, st_ino)` + role-tagged sentinels when `volume_id IS NOT
              NULL`) and verify `statat(&staging_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` is
              `S_ISREG` on `staging_dir_fd`'s local `st_dev` with `st_ino as u64 == staged_ino` and
              `st_size == size_bytes`. Commit a short lock-ordered primary DB transaction (`(runs
              FOR NO KEY UPDATE ->) storage_reservations FOR UPDATE` + `SELECT
              openmettle.storage_lock_pinned_volume()` when pinned, or plain `SELECT` check of
              `adoption_run_id IS NULL` while `volume_id IS NULL`) setting **`UPDATE
              openmettle.storage_reservations SET publish_pending = true WHERE scope_id = $1 AND id
              = $2 AND state = 'reserved' AND NOT adoption_unverified AND payload_ino =
              $3::text::numeric(20, 0) AND reclaim_state = 'none'`** (`CHECK (NOT publish_pending OR
              (state = 'reserved' AND payload_ino IS NOT NULL))`).
            - *Atomic no-replace hard-link (`linkat`) keeping `staging/<id>` present:* Publish
              exclusively via **`rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id,
              AtFlags::empty())`**!
              - If a foreign file already sits at `revisions/<id>`, `linkat` fails atomically with
                **`Errno::EXIST` (`EEXIST`) without overwriting or modifying `revisions/<id>`**, and
                the publisher commits quarantine (`UPDATE openmettle.storage_reservations SET
                adoption_unverified = true, publish_pending = false WHERE scope_id = $1 AND id = $2
                AND state = 'reserved'`) before returning `Error::Io` (keeping `revisions/<id>` 100%
                untouched and `reserved_bytes` 100% charged!).
              - **Mixed-version `N-1` HTTP retry safety:** Because `linkat` **keeps `staging/<id>`
                present on disk throughout the entire unsettled `state = 'reserved'` window** (even
                if the `N` writer crashes right after `linkat` and before `storage::settle`
                commits!), any same-key retry routed to an **`N-1` API replica** hits
                `store.stage(&id)` -> `OpenOptions::create_new(true)` (`src/artifact_fs.rs:474`) ->
                `AlreadyExists` -> **`Err(Error::InProgress)` (`src/artifact_fs.rs:475`)** and
                returns immediately **without** calling `abort()`, **without** staging a replacement
                file, and **without** calling replacing `fs::rename`!
            - *Post-`linkat` `fsync` & `storage::settle` (`Reserved` branch):* Call and require
              `Ok(())` from `fsync(&revisions_dir_fd)`, re-verify `<root>`, `"staging"`,
              `"revisions"` FDs (+ sentinels when pinned) and `statat(&revisions_dir_fd, id,
              AtFlags::SYMLINK_NOFOLLOW)` (`S_ISREG`, local `st_dev` match, `st_ino as u64 ==
              staged_ino`, `st_size == size_bytes`) strictly before `tx.commit()` of
              `storage::settle`. `storage::settle`'s `Reserved` branch locks `(runs FOR NO KEY
              UPDATE ->) storage_reservations FOR UPDATE -> artifacts -> artifact_revisions ->
              storage_volume_control [via storage_lock_pinned_volume() when pinned] ->
              storage_accounts -> storage_instance`, requires **`state = 'reserved' AND NOT
              adoption_unverified AND payload_ino = $staged_ino AND reclaim_state = 'none'`**,
              inserts `artifact_revisions`, and atomically commits **`SET state = 'settled',
              publish_pending = false` while retaining `payload_ino`** on the `'settled'` row
              (`enforce_storage_reservation_monotonic_guards()` prevents any non-`openmettle_owner`
              role from clearing or mutating `payload_ino` or clearing `adoption_unverified` /
              `stage_claimed`). On post-`linkat` pre-`commit` displacement, rolling back
              `storage::settle` leaves `(payload_ino, publish_pending = true)` already durable in
              PostgreSQL, and the publisher best-effort commits `adoption_unverified = true,
              publish_pending = false` before returning `Error::Io`.
            - *Post-`commit` best-effort detach of `staging/<id>` alias (strictly AFTER
              `storage::settle` commits):* While still holding `LOCK_SH` on `StagedFile` (or if
              reopening `staging/<id>`, opening via `OFlags::RDONLY | OFlags::NOFOLLOW |
              OFlags::NONBLOCK`, immediately checking `file.metadata()?.file_type().is_file()`, and
              acquiring `LOCK_SH` so neither `StagingSweepState` nor `purge_due` can acquire
              `LOCK_EX`, while `state = 'settled'` and `stage_claimed = true` prevent any `N-1` or
              `N` writer from staging), verify `statat(&staging_dir_fd, id,
              AtFlags::SYMLINK_NOFOLLOW).st_ino as u64 == staged_ino` AND `statat(&revisions_dir_fd,
              id, AtFlags::SYMLINK_NOFOLLOW).st_ino as u64 == staged_ino`, call
              **`unlinkat(&staging_dir_fd, id, AtFlags::empty())`** (**NEVER `set_len(0)`!**) ->
              `drop(file)` -> `fsync(&staging_dir_fd)`. (If the process crashes after
              `storage::settle` commits and before detaching `staging/<id>`, `StagingSweepState` or
              `purge_due` cleanly detaches the matching `payload_ino` alias.)
         2. *Unified 5-step worker `publish_bytes` pre-publication `publish_pending` fence
            (synchronized verbatim with ADR 0039):*
            - *Step 1:* Create `0`-byte `staging/<id>` (`create_new(true)` via `openat`
              `OFlags::CREATE | OFlags::EXCL | OFlags::RDWR | OFlags::NOFOLLOW`), acquire continuous
              `LOCK_EX`, call and require `Ok(())` from `fsync(&staging_dir_fd)`, and bind
              write-once `stage_claimed = true, payload_ino = COALESCE(payload_ino, $3)` via
              `SELECT openmettle.storage_lock_pinned_volume()` (verifying returned `volume_id ==
              store.volume_id`) **leaving `publish_pending = false`** while empty.
            - *Step 2:* Write payload, verify `actual_size == reserved_bytes` & SHA-256, and call
              `file.sync_all()` under continuous `LOCK_EX`.
            - *Step 3:* Still holding `LOCK_EX`, re-stat `fd` (`st_size == reserved_bytes`) and
              `statat(&staging_dir_fd, id, AtFlags::SYMLINK_NOFOLLOW)` (`st_ino == payload_ino`),
              then execute:
              ```sql
              SELECT openmettle.storage_lock_pinned_volume();
              UPDATE openmettle.storage_reservations
                 SET publish_pending = true
               WHERE scope_id = $1::uuid
                 AND id = $2::uuid
                 AND state = 'reserved'
                 AND NOT adoption_unverified
                 AND reclaim_state = 'none'
                 AND payload_ino = $3
              RETURNING id;
              ```
              Confirming returned `volume_id == store.volume_id`. If adoption started (`OMQ03`) or a
              cleaner claimed `reclaim_state <> 'none'` during Step 2's write (`0` rows returned),
              Step 3 fails **strictly BEFORE `linkat`** so `publish_bytes` aborts cleanly without
              creating `revisions/<id>`!
            - *Step 4:* Execute `rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id,
              AtFlags::empty())` (quarantining on `Errno::EXIST` without overwriting foreign
              `revisions/<id>`) + `fsync(&revisions_dir_fd)` + post-`linkat` re-verify — **do NOT
              drop `LOCK_EX` at the end of Step 4!** Carry the open `staged_fd` (`LOCK_EX`) from
              Step 4 directly into Step 5.
            - *Step 5:* Still holding `staged_fd` (`LOCK_EX`), execute a **single atomic
              `Fence::Step` `WriteTransaction` committing BOTH `storage::settle` (`state =
              'settled', publish_pending = false`, retaining `payload_ino`) AND
              `runs::record_observation`**, dropping `staged_fd` (`LOCK_EX`) **only AFTER** that
              `Fence::Step` transaction commits, followed by post-commit best-effort `LOCK_SH`
              (`OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK` + immediate
              `file.metadata()?.file_type().is_file()` check before `try_lock_shared()`)
              `unlinkat(&staging_dir_fd, id, AtFlags::empty())` (**never `set_len(0)`**) +
              `fsync(&staging_dir_fd)`.
         3. *Narrowed guarantee & fail-closed recovery for live host directory replacement AFTER
            the final pre-`commit` check:* Live host replacement of `<root>`, `<root>/staging`, or
            `<root>/revisions` is forbidden by operational contract and caught fail-closed: any
            fresh replacement directory lacks `<volume_id>:revisions`, failing every subsequent
            `Store::stage`, `Store::publish`, `Store::read`, cleaner, and `Store::open` with
            `Error::Io`; even if a privileged actor copies `<volume_id>:revisions`, any revision
            whose file was displaced or replaced by a same-sized foreign file fails `Store::read`'s
            `file_meta.ino() == sr.payload_ino` check (`Error::Io`), `openmettle-admin` adoption
            (`OMQ03`), and `verify_accounting_drift` (hard drift failure).
       - **Mandatory `Store::read` (`src/artifact_fs.rs:190-208, 300-355`) non-blocking open,
         `LOCK_SH` acquisition before metadata re-verification, retention inside `Content`,
         `payload_ino` verification, & explicit legacy-row rule (synchronized verbatim with ADR
         0039):**
         - `storage::read_revision` joins `openmettle.storage_reservations sr ON sr.scope_id =
           r.scope_id AND sr.id = r.reservation_id` to load **`(r.size_bytes, sr.payload_ino,
           sr.adoption_unverified)`**.
         - `Store::read` immediately rejects **`sr.adoption_unverified = true` (`Error::Io`)**,
           re-opens `<root>` and `"revisions"` by configured pathname (`OFlags::RDONLY |
           OFlags::DIRECTORY | OFlags::NOFOLLOW`) verifying local `(st_dev, st_ino)` match
           `(root_fd, revisions_dir_fd)` (+ `:root`/`:revisions` `.openmettle-volume-id` sentinels
           when `storage_volume_control.volume_id IS NOT NULL`), opens `revisions/<reservation>`
           relative to `revisions_dir_fd` via **`openat(&revisions_dir_fd, reservation,
           OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK, Mode::empty())`** (preventing
           indefinite blocking on a writerless FIFO per `man 7 fifo` while remaining valid for
           `LOCK_SH` -> `F_RDLCK` on Linux NFS), **immediately checks
           `file.metadata()?.file_type().is_file()`** (failing closed with **`Err(Error::Missing)`**
           on FIFOs, sockets, devices, or directories without blocking!), acquires non-blocking
           **`file.try_lock_shared()`** (`LOCK_SH | LOCK_NB`, returning **`Err(Error::Missing)`**
           on `WouldBlock` before response headers), and **strictly AFTER acquiring `LOCK_SH`
           re-verifies `file.metadata()?` (`is_file()`, `st_dev == store.root_dev`, `st_ino ==
           sr.payload_ino` when non-null, `len() == size`) AND `statat(&revisions_dir_fd,
           reservation, AtFlags::SYMLINK_NOFOLLOW)` namespace identity matching `(fd_dev,
           fd_ino)`**, seeks to `start`, and **retains that locked `fs::File` inside `Content` for
           the entire streaming response body lifetime** so `purge_due` Stage A (`LOCK_EX |
           LOCK_NB`) receives `WouldBlock` and never truncates an in-flight download!
           - Whenever **`sr.payload_ino IS NOT NULL`**: **requires `file_meta.ino() ==
             sr.payload_ino`** (rejecting any same-sized replacement file with `Error::Io`!).
           - **Explicit legacy-row rule (`sr.payload_ino IS NULL`):** Permitted **ONLY** while
             `storage_volume_control` is present AND `volume_id IS NULL AND adoption_run_id IS
             NULL` (pre-adoption rolling-upgrade window for legacy revisions settled by `N-1`
             binaries before `openmettle-admin` adoption runs). Because `openmettle-admin` adoption
             Step 3 backfills `payload_ino` on all verified `'active'` and `'retained'` revisions
             before pinning `volume_id`, once `storage_volume_control.volume_id IS NOT NULL`, **any
             `'active'`/`'retained'` revision with `sr.payload_ino IS NULL` fails closed
             (`Error::Io`) in `Store::read` and fails hard in `verify_accounting_drift`**!
       - **Unified 4-step reclamation protocol preserving `payload_ino` allocation via
         `staging/.reclaim.<id>` + `anchor_pending_unlink` across ALL FOUR storage release paths
         (`artifact_fs::abort`, non-run `reconcile_expired`, generic run-linked
         `storage_reservations` recovery, AND ADR 0039 `reconcile_run_spills`) — ZERO filesystem
         I/O inside DB transactions in Step 1 and Step 3:**
         Unlinking the last hard link and closing the FD before Step 3 commits would free
         `payload_ino` and allow the filesystem to reuse the same `st_ino` for a newly created
         foreign file at `<id>`, which a `'truncated'` retry or `'released'` sweep could then
         unlink. Likewise, if Cleaner 1 pauses after Step 1 while Cleaner 2 takes over an expired
         lease, finishes Steps 2–4, and frees `payload_ino`, Cleaner 1 waking up without revalidating
         its claim under `LOCK_EX` could truncate a recycled inode. All four cleaners therefore
         share the exact same 4-state lease (`reclaim_state IN ('none', 'claiming', 'truncated',
         'anchor_pending_unlink')`, `reclaim_claim_token uuid`, `reclaim_lease_until timestamptz`)
         and execute the exact same 4-step protocol with **fenced Step 2a lease revalidation under
         `LOCK_EX` strictly before `set_len(0)` / `linkat` / `unlinkat`**, **unconditional
         `fsync(&staging_dir_fd)` on BOTH newly created and recovered anchors before unlinking
         `<id>`**, and **bounded DB-driven Step 4 retry across all reservation kinds**, keeping
         `payload_ino` anchored (`nlink >= 1`) at `staging/.reclaim.<id>` until AFTER Step 3 commits
         `state = 'released'`, without ever clearing `payload_ino`:
         - **Step 1 (Serialized DB Claim strictly BEFORE any truncation/unlink — ZERO filesystem
           I/O inside DB tx):**
           Lock `(runs FOR NO KEY UPDATE [SKIP LOCKED] ->) storage_reservations FOR UPDATE [SKIP
           LOCKED] -> storage_volume_control [via SELECT openmettle.storage_lock_pinned_volume()]`
           (abort immediately on `OMQ03` or if returned `v_vol IS DISTINCT FROM
           $expected_volume_id`), requiring **`state = 'reserved' AND NOT adoption_unverified AND
           (reclaim_state = 'none' OR reclaim_lease_until <= clock_timestamp())`** (plus
           path-specific preconditions: expiry for `reconcile_expired`, expiry + terminal run + zero
           `'intent'`/`'outcome_unknown'` operations + `(operation_id IS NULL OR idempotency_key NOT
           LIKE 'tool-spill:%')` for generic run-linked recovery, or ADR 0039's spill
           preconditions). Commit:
           ```sql
           UPDATE openmettle.storage_reservations
              SET reclaim_state = CASE
                      WHEN reclaim_state = 'truncated' THEN 'truncated'
                      ELSE 'claiming'
                  END,
                  reclaim_claim_token = $my_token,
                  reclaim_lease_until = clock_timestamp() + interval '60 seconds'
            WHERE scope_id = $1 AND id = $2
              AND state = 'reserved'
              AND NOT adoption_unverified
              AND (reclaim_state = 'none' OR reclaim_lease_until <= clock_timestamp())
           ```
           Acquiring `FOR UPDATE` on `storage_reservations` in Step 1 **resolves any in-flight
           `storage::settle` commit strictly BEFORE Step 2 can ever truncate**, and setting
           `reclaim_state != 'none'` blocks `Store::stage`, `Store::publish`, `publish_bytes`,
           `storage::settle`, and any second healthy cleaner! (In `artifact_fs::abort`, if another
           cleaner holds an unexpired `reclaim_lease_until > clock_timestamp()`, `abort` returns
           without touching disk or quarantining.)
         - **Step 2 (Fenced Step 2a Lease Revalidation Under `LOCK_EX` Strictly Before `set_len(0)`,
           Durable `0`-Byte Truncation & Unconditionally `fsync`ed `staging/.reclaim.<id>` Anchor —
           `payload_ino` NEVER drops to `nlink = 0` before Step 3 commits!):**
           Verify pinned three-directory `.openmettle-volume-id` sentinels (`:root`, `:revisions`,
           `:staging` via `openat(..., OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK)` +
           `fstat` `S_ISREG`, local `st_dev` match, bounded `<= 64`-byte read) and host-local
           same-mount `st_dev` across `(root_fd, staging_dir_fd, revisions_dir_fd)`. Let
           `reclaim_name = format!(".reclaim.{id}")`. Branch strictly on `(payload_ino,
           reclaim_state)`:
           - **Case 1a (`payload_ino IS NOT NULL` and `reclaim_state = 'claiming'`):**
             Probe **`staging/.reclaim.<id>` first if present** (covering a crash after
             `linkat(".reclaim.<id>")` + `unlinkat("<id>")` before SQL committed `'truncated'`),
             else **`staging/<id>`**, and check **`revisions/<id>`** (from an aborted pre-settle
             `linkat`) using `rustix::fs::statat(..., AtFlags::SYMLINK_NOFOLLOW)`:
             1. *Foreign / mismatched entry:* If ANY existing entry among `staging/.reclaim.<id>`,
                `staging/<id>`, or `revisions/<id>` is non-regular, has a different host-local
                `st_dev`, or has **`st_ino as u64 != payload_ino`**: **ZERO `set_len(0)` and ZERO
                `unlinkat`**; commit quarantine (`SET adoption_unverified = true, publish_pending =
                false, reclaim_state = 'none', reclaim_claim_token = NULL, reclaim_lease_until =
                NULL`) under lock-ordered `FOR UPDATE` **re-verifying `state = 'reserved' AND NOT
                adoption_unverified AND reclaim_claim_token = $my_token AND reclaim_state =
                'claiming' AND payload_ino = $expected_ino`** + `SELECT
                openmettle.storage_lock_pinned_volume()`!
             2. *All three `ENOENT`:* ONLY if ALL THREE (`staging/.reclaim.<id>`, `staging/<id>`,
                `revisions/<id>`) return `ENOENT`: commit quarantine (`adoption_unverified = true,
                publish_pending = false, reclaim_state = 'none', reclaim_claim_token = NULL,
                reclaim_lease_until = NULL`) under the exact same `FOR UPDATE` guard **`state =
                'reserved' AND NOT adoption_unverified AND reclaim_claim_token = $my_token AND
                reclaim_state = 'claiming' AND payload_ino = $expected_ino`** + `SELECT
                openmettle.storage_lock_pinned_volume()`!
             3. *Exact match (`S_ISREG`, same local `st_dev`, `st_ino == payload_ino`) — Step 2a
                fenced DB revalidation under `LOCK_EX` BEFORE any mutation:* Open the matched target
                (`staging/.reclaim.<id>` first if present, else `staging/<id>`, else
                `revisions/<id>`) via `rustix::fs::openat(&src_dir_fd, src_name, OFlags::RDWR |
                OFlags::NOFOLLOW)` (explicitly **WITHOUT `OFlags::TRUNC`**!) ->
                `std::fs::File::from(owned_fd)` -> **`probe_file.try_lock()`**
                (`LOCK_EX | LOCK_NB`; on `WouldBlock`, abort Step 2 immediately with zero truncation
                and zero unlink!) -> verify open-FD `S_ISREG`, `st_dev == store.root_dev`,
                `probe_file.metadata().ino() == payload_ino`, and `statat(&src_dir_fd, src_name,
                AtFlags::SYMLINK_NOFOLLOW)` namespace identity:
                1. **Step 2a — Fenced PostgreSQL claim revalidation & 300 s lease renewal UNDER
                   `LOCK_EX` strictly BEFORE `set_len(0)` / `linkat` / `unlinkat`:** While
                   **continuing to hold `LOCK_EX`** on `probe_file`, execute:
                   ```sql
                   SELECT openmettle.storage_lock_pinned_volume();
                   UPDATE openmettle.storage_reservations
                      SET reclaim_lease_until = clock_timestamp() + interval '300 seconds'
                    WHERE scope_id = $1::uuid
                      AND id = $2::uuid
                      AND state = 'reserved'
                      AND NOT adoption_unverified
                      AND payload_ino = $3
                      AND reclaim_state = 'claiming'
                      AND reclaim_claim_token = $4::uuid
                   RETURNING id;
                   ```
                   Confirming returned `volume_id == store.volume_id`. If `0` rows are returned
                   (e.g., Cleaner 1 paused after Step 1 while Cleaner 2 took over, completed Steps
                   2–4, released the reservation, and detached `.reclaim.<id>`), **abort immediately
                   and drop `probe_file` with ZERO `set_len(0)`, ZERO `linkat`, and ZERO
                   `unlinkat`!** Paired with `LOCK_EX` in Step 4 (`OFlags::RDWR | OFlags::NOFOLLOW`
                   without `OFlags::TRUNC`, zero `set_len(0)`, + `LOCK_EX` on
                   `staging/.reclaim.<id>` before `unlinkat`), once Cleaner 1 passes
                   Step 2a while holding `LOCK_EX`, no successor cleaner can detach `.reclaim.<id>`
                   or free `payload_ino`!
                2. Call **`probe_file.set_len(0)?`** AND **`probe_file.sync_all()?`** (`0` bytes
                   durable on disk!).
                3. Ensure hard-link anchor **`staging/.reclaim.<id>`** exists and is crash-durable:
                   if `staging/.reclaim.<id>` was `ENOENT`, call
                   **`rustix::fs::linkat(&src_dir_fd, src_name, &staging_dir_fd, &reclaim_name,
                   AtFlags::empty())`** (if `EEXIST`, verify `statat(&staging_dir_fd, &reclaim_name,
                   AtFlags::SYMLINK_NOFOLLOW)` is `S_ISREG` on `store.root_dev` with `st_ino as u64
                   == payload_ino`), and **UNCONDITIONALLY call and require `Ok(())` from
                   `fsync(&staging_dir_fd)` for BOTH newly created AND recovered existing anchors**,
                   strictly BEFORE calling `unlinkat(&staging_dir_fd, id)` or
                   `unlinkat(&revisions_dir_fd, id)` (`nlink` is durably `>= 1` at `.reclaim.<id>`
                   before `<id>` is unlinked, so **`payload_ino` NEVER hits `nlink = 0` and CANNOT
                   be reused by the filesystem!**).
                4. While `staging/.reclaim.<id>` holds `nlink >= 1` and `probe_file` holds
                   `LOCK_EX`: unlink any existing `<id>` entry in `revisions/<id>` and
                   `staging/<id>` (re-verifying `statat(&dir_fd, id,
                   AtFlags::SYMLINK_NOFOLLOW).st_ino as u64 == payload_ino` right before each
                   `unlinkat`) + **`fsync(&revisions_dir_fd)?`** + **`fsync(&staging_dir_fd)?`**.
                5. Still holding `LOCK_EX` on `probe_file` (anchored at `staging/.reclaim.<id>`!),
                   commit a short lock-ordered `FOR UPDATE` tx setting **`reclaim_state =
                   'truncated', publish_pending = false`** (`WHERE scope_id = $1 AND id = $2 AND
                   state = 'reserved' AND NOT adoption_unverified AND reclaim_claim_token =
                   $my_token AND reclaim_state = 'claiming' AND payload_ino = $expected_ino`, with
                   `SELECT openmettle.storage_lock_pinned_volume()` verifying `volume_id ==
                   store.volume_id` — **`payload_ino` stays non-null!**), and keep `probe_file` open
                   with `LOCK_EX` into Step 3!
           - **Case 1b (`payload_ino IS NOT NULL` and `reclaim_state = 'truncated'` — crash
             recovery before Step 3):**
             - **NEVER truncate or unlink `staging/<id>` or `revisions/<id>` in `'truncated'`!**
               Any entry appearing at `staging/<id>` or `revisions/<id>` after `'truncated'` is
               preserved 100% untouched!
             - Probe **`staging/.reclaim.<id>` ONLY** via `statat(&staging_dir_fd, &reclaim_name,
               AtFlags::SYMLINK_NOFOLLOW)`: it **MUST** exist, be `S_ISREG`, on `staging_dir_fd`'s
               local `st_dev`, with **`st_ino as u64 == payload_ino` AND `st_size == 0`**!
               (Otherwise — missing, non-regular, wrong `st_dev`, `st_ino != payload_ino`, or
               `st_size != 0` — commit quarantine under lock-ordered `FOR UPDATE` verifying
               `reclaim_claim_token = $my_token AND reclaim_state = 'truncated' AND payload_ino =
               $expected_ino` + `SELECT openmettle.storage_lock_pinned_volume()`!)
             - Open `staging/.reclaim.<id>` with **`OFlags::RDWR | OFlags::NOFOLLOW` (explicitly
               WITHOUT `OFlags::TRUNC`, required on Linux NFS where `LOCK_EX` maps to `F_WRLCK` and
               preserving zero `set_len(0)` when already `'truncated'` and `st_size == 0`!)** ->
               `probe_file.try_lock()` (`LOCK_EX | LOCK_NB`; abort on `WouldBlock`) -> re-verify
               open-FD and `statat` `st_ino == payload_ino` and `st_size == 0` -> execute fenced
               lease renewal (`SELECT openmettle.storage_lock_pinned_volume(); UPDATE
               openmettle.storage_reservations SET reclaim_lease_until = clock_timestamp() +
               interval '300 seconds' WHERE scope_id = $1::uuid AND id = $2::uuid AND state =
               'reserved' AND NOT adoption_unverified AND payload_ino = $3 AND reclaim_state =
               'truncated' AND reclaim_claim_token = $4::uuid RETURNING id;` — aborting on `0` rows)
               -> unconditional **`fsync(&staging_dir_fd)?` + `fsync(&revisions_dir_fd)?`** ->
               proceed to Step 3 keeping `probe_file` open with `LOCK_EX`!
           - **Case 2 (`payload_ino IS NULL` — reservation never bound a writer inode; adoption
             backfilled all on-disk upgrade rows and `reclaim_state != 'none'` blocks
             `Store::stage`):**
             - If `revisions/<id>` exists (any type) OR `staging/.reclaim.<id>` exists (any type)
               OR `staging/<id>` exists and is non-regular, different host-local `st_dev`, or
               **`st_size > 0`**: **ZERO `set_len(0)` and ZERO `unlinkat`**, commit quarantine
               (`adoption_unverified = true, publish_pending = false, reclaim_state = 'none',
               reclaim_claim_token = NULL, reclaim_lease_until = NULL`) under lock-ordered `FOR
               UPDATE` verifying `state = 'reserved' AND NOT adoption_unverified AND
               reclaim_claim_token = $my_token AND payload_ino IS NULL` + `SELECT
               openmettle.storage_lock_pinned_volume()`.
             - If `staging/<id>` is a `0`-byte regular file on `store.root_dev` (`st_size == 0`)
               with `revisions/<id>` and `staging/.reclaim.<id>` `ENOENT`: open `staging/<id>`
               with **`OFlags::RDWR | OFlags::NOFOLLOW` (explicitly WITHOUT `OFlags::TRUNC`, zero
               `set_len(0)`!)** -> acquire `LOCK_EX` via `probe_file.try_lock()` (`LOCK_EX |
               LOCK_NB`; on `WouldBlock`, abort Step 2 untouched) -> re-verify `S_ISREG`, `st_dev
               == store.root_dev`, `st_size == 0`, `statat(&staging_dir_fd, id,
               AtFlags::SYMLINK_NOFOLLOW)` `(fd_dev, fd_ino)` match, and `revisions/<id>` (and
               `staging/.reclaim.<id>`) `ENOENT`. Then **Step 2a — WHILE HOLDING `LOCK_EX`**,
               execute fenced PostgreSQL SQL **atomically binding `stage_claimed = true,
               payload_ino = fd_ino`**:
               ```sql
               SELECT openmettle.storage_lock_pinned_volume();
               UPDATE openmettle.storage_reservations
                  SET stage_claimed = true,
                      payload_ino = $3,
                      reclaim_lease_until = clock_timestamp() + interval '300 seconds'
                WHERE scope_id = $1::uuid
                  AND id = $2::uuid
                  AND state = 'reserved'
                  AND NOT adoption_unverified
                  AND payload_ino IS NULL
                  AND reclaim_state = 'claiming'
                  AND reclaim_claim_token = $4::uuid
               RETURNING id;
               ```
               (Confirming returned `volume_id == store.volume_id`; aborting immediately and
               dropping `probe_file` (`LOCK_EX`) with **ZERO filesystem mutations** on `0` rows or
               `OMQ03`, e.g., if `openmettle storage adopt` backfilled `payload_ino IS NOT NULL`
               or superseded the claim while the Case 2 claimant was paused.) On `1` returned row
               (**still holding `LOCK_EX` via `probe_file`**), promote directly into the standard
               `.reclaim.<id>` anchor sequence: `linkat(&staging_dir_fd, id, &staging_dir_fd,
               ".reclaim.<id>", AtFlags::empty())` -> unconditional **`fsync(&staging_dir_fd)?`**
               -> `unlinkat(&staging_dir_fd, id, AtFlags::empty())` (**never `set_len(0)`**) ->
               unconditional **`fsync(&staging_dir_fd)?` + `fsync(&revisions_dir_fd)?`** -> commit
               short DB update setting **`reclaim_state = 'truncated', publish_pending = false`**
               (`WHERE scope_id = $1::uuid AND id = $2::uuid AND state = 'reserved' AND NOT
               adoption_unverified AND payload_ino = $3 AND reclaim_state = 'claiming' AND
               reclaim_claim_token = $4::uuid` + `storage_lock_pinned_volume()`) -> proceed to
               Step 3 (`storage::release` setting `reclaim_state = 'anchor_pending_unlink'` and
               retaining `payload_ino`) -> Step 4!
             - If `staging/<id>`, `staging/.reclaim.<id>`, and `revisions/<id>` are **ALL**
               already `ENOENT`: execute unconditional **`fsync(&staging_dir_fd)?` +
               `fsync(&revisions_dir_fd)?`** and proceed directly to Step 3 with **ZERO `unlinkat`
               calls**. (Thus `payload_ino` stays `NULL` through Step 3 **ONLY** when
               `staging/<id>`, `staging/.reclaim.<id>`, and `revisions/<id>` are ALL already
               `ENOENT`, where the cleaner performs **ZERO `unlinkat` calls** — eliminating the
               post-Step-2a-commit pause race with `openmettle storage adopt`!)
         - **Step 3 (Final `storage::release` — ZERO filesystem I/O inside DB tx in BOTH ADR 0039
           and ADR 0040!):**
           Because `reclaim_state != 'none'` already blocks `Store::stage`, `Store::publish`,
           `publish_bytes`, and `storage::settle` from creating or settling any file for `<id>`,
           **ALL 4 cleaners perform ZERO filesystem I/O (`statat`, `openat`, `unlinkat`, `fsync`)
           inside Step 3's DB release transaction!** Step 3 locks `(runs FOR NO KEY UPDATE [SKIP
           LOCKED] ->) storage_reservations FOR UPDATE [SKIP LOCKED]`, verifies **`state =
           'reserved' AND NOT adoption_unverified AND NOT publish_pending AND reclaim_claim_token =
           $my_token AND (payload_ino IS NULL OR reclaim_state = 'truncated')`** (plus path-specific
           preconditions), sets **`reclaim_state = CASE WHEN payload_ino IS NOT NULL THEN
           'anchor_pending_unlink' ELSE 'none' END, reclaim_claim_token = NULL, reclaim_lease_until
           = NULL`**, and commits `storage::release` (firing `enforce_runtime_storage_volume_pinned()`
           calling `storage_lock_pinned_volume()` -> `adjust()` updating `storage_accounts ->
           storage_instance` with zero deadlock, **retaining `payload_ino` on the `'released'`
           row**)!
         - **Step 4 (Post-release detach of `staging/.reclaim.<id>` under `LOCK_EX` strictly AFTER
           Step 3 commits + bounded DB-driven Step 4 retry with wrapping keyset cursor and
           pass-start fixed upper watermark across ALL reservation kinds):**
           When `payload_ino IS NOT NULL` (holding `LOCK_EX` via `probe_file`, or opening
           `staging/.reclaim.<id>` with **`OFlags::RDWR | OFlags::NOFOLLOW` explicitly WITHOUT
           `OFlags::TRUNC` and preserving zero `set_len(0)`** + `LOCK_EX` `try_lock()` on retry,
           strictly paired with Step 2a's `LOCK_EX`!): verify
           `statat(&staging_dir_fd, &reclaim_name, AtFlags::SYMLINK_NOFOLLOW)` has `S_ISREG`, same
           local `st_dev`, **`st_ino as u64 == payload_ino`**, and **`st_size == 0`**, call
           **`unlinkat(&staging_dir_fd, &reclaim_name, AtFlags::empty())`** (**never `set_len(0)`**)
           -> `drop(probe_file)` -> `fsync(&staging_dir_fd)` -> commit best-effort **`UPDATE
           openmettle.storage_reservations SET reclaim_state = 'none' WHERE id = $1::uuid AND state
           = 'released' AND reclaim_state = 'anchor_pending_unlink'`**! To guarantee convergence even
           after a crash between `unlinkat(".reclaim.<id>")` + `fsync(&staging_dir_fd)` and the SQL
           update (when `.reclaim.<id>` is already absent from `ReadDir`) **without starvation from
           persistent leading anomalous foreign-inode / `WouldBlock` anchors OR sustained arrivals
           of `>= LIMIT` new pending rows per tick**, `StagingSweepState` / `reconcile_expired`
           maintains a per-worker wrapping keyset cursor **`reclaim_anchor_cursor:
           Option<(DateTime<Utc>, Uuid)>`** and a pass-start fixed upper watermark
           **`reclaim_anchor_pass_upper: Option<(DateTime<Utc>, Uuid)>`** over partial index
           `storage_reservations_reclaim_anchor_idx` across **ALL** reservation kinds (non-run
           uploads, generic run-linked holds, and `tool-spill:%` holds). At the start of each sweep
           pass (when `reclaim_anchor_pass_upper` is `None`), capture the fixed upper watermark
           `(upper_ts, upper_id)` (returning immediately if `None`):
           ```sql
           SELECT closed_at, id
             FROM openmettle.storage_reservations
            WHERE state = 'released'
              AND reclaim_state = 'anchor_pending_unlink'
              AND NOT adoption_unverified
              AND payload_ino IS NOT NULL
            ORDER BY closed_at DESC, id DESC
            LIMIT 1;
           ```
           Then constrain every page in that pass by `(upper_ts, upper_id)`:
           ```sql
           SELECT id::text, payload_ino, closed_at
             FROM openmettle.storage_reservations
            WHERE state = 'released'
              AND reclaim_state = 'anchor_pending_unlink'
              AND NOT adoption_unverified
              AND payload_ino IS NOT NULL
              AND ($1::timestamptz IS NULL OR (closed_at, id) > ($1::timestamptz, $2::uuid))
              AND (closed_at, id) <= ($3::timestamptz, $4::uuid)
            ORDER BY closed_at ASC, id ASC
            LIMIT $5;
           ```
           For each row, if `staging/.reclaim.<id>` exists, detach it under **`OFlags::RDWR |
           OFlags::NOFOLLOW` (explicitly WITHOUT `OFlags::TRUNC`, zero `set_len(0)`)** + `LOCK_EX`
           (verifying `S_ISREG`, `store.root_dev`, `st_ino == payload_ino`, `st_size == 0`, never
           `set_len(0)`) -> `drop` -> `fsync(&staging_dir_fd)` -> `SET reclaim_state = 'none'`
           (preserving untouched and logging an anomaly on foreign inode or non-zero size, or
           skipping on `WouldBlock`); if `staging/.reclaim.<id>` returns `Errno::NOENT`, call
           `fsync(&staging_dir_fd)` and clear `reclaim_state = 'none'`. **Advance
           `reclaim_anchor_cursor = Some((row.closed_at, row.id))` past EVERY inspected key
           (including anomalous foreign-inode anchors and `WouldBlock` rows!), and reset BOTH
           `reclaim_anchor_cursor = None` AND `reclaim_anchor_pass_upper = None` whenever a page
           returns `< LIMIT` rows OR reaches `(upper_ts, upper_id)`** so neither persistent
           anomalous anchors nor sustained arrivals of `>= LIMIT` new pending rows per tick can
           starve earlier `WouldBlock` or trailing anchors!
       - Once `storage_volume_control.volume_id` is non-null in PostgreSQL, `Store::open` and
         **every** worker cleaner — explicitly including **`artifact_fs::purge_due`**,
         `artifact_fs::reconcile_expired`, run-linked storage recovery, ADR 0039
         `reconcile_run_spills`, and `staging/` `ReadDir` cleanup — **MUST refuse to initialize a
         fresh sentinel** (and must not accept a newly created or empty replacement directory) and
         **MUST verify BEFORE touching any payload path or mutating PostgreSQL** that: (a)
         `storage_volume_control` is present AND `volume_id IS NOT NULL AND adoption_run_id IS
         NULL`, (b) `<root>`, `revisions_dir_fd` (`<root>/revisions`), and `staging_dir_fd`
         (`<root>/staging`) all open with `OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW`
         and share the exact same host-local `st_dev`, and (c) `.openmettle-volume-id` opened via
         `openat(..., OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK)` + `fstat` on **each**
         of `<root>`, `revisions_dir_fd`, and `staging_dir_fd` is a regular file (`S_ISREG` —
         rejecting FIFOs, sockets, device nodes, directories and symlinks immediately without
         blocking) on that exact same local `st_dev` whose bounded (`<= 64`-byte) content contains
         non-null pinned `storage_volume_control.volume_id` paired with its exact `:root`,
         `:revisions`, or `:staging` role tag. If `storage_volume_control` is missing,
         `adoption_run_id IS NOT NULL`, `volume_id IS NULL`, or any sentinel fails verification,
         startup (on sentinel mismatch) and all cleaners **fail closed immediately** with **zero
         unlinked files, zero released holds, and zero confirmed purges**.
   - *Non-run uploads (`run_id IS NULL`, `artifact_fs::reconcile_expired`) and retention purges
     (`artifact_fs::purge_due`):*
     Non-run uploads continue through `artifact_fs::reconcile_expired` and retention purges
     continue through `artifact_fs::purge_due` — **both** requiring configured
     `OPENMETTLE_WORKER_ARTIFACTS_DIR`, verified **`storage_volume_control` present AND
     `volume_id IS NOT NULL AND adoption_run_id IS NULL`**, and verified non-null pinned volume
     identity across all three role-tagged `.openmettle-volume-id` sentinels and host-local
     same-mount `st_dev`.
     - **3-stage inode-preserving `artifact_fs::purge_due` protocol (`revisions/.purge.<id>` +
       `artifact_revisions.purge_stage` — `payload_ino` NEVER reaches `nlink = 0` while `state =
       'purging'`):**
       1. *`storage::begin_purge`:* Joins `openmettle.storage_reservations sr ON sr.scope_id =
          r.scope_id AND sr.id = r.reservation_id` to load `(r.reservation_id, r.size_bytes,
          sr.payload_ino, sr.adoption_unverified)`, requiring **`NOT sr.adoption_unverified AND
          sr.payload_ino IS NOT NULL`** (failing closed without touching disk or calling
          `confirm_purge` otherwise), invoking `storage_lock_pinned_volume()` via
          `enforce_runtime_storage_volume_pinned()`, and setting `state = 'purging'`
          (`purge_stage = 'none'`).
       2. *Stage A (Anchor + Truncate + Visible-Name Detach BEFORE `confirm_purge`, keeping
          `revisions/.purge.<id>` linked with `nlink >= 1`, where `<id>` is `reservation_id`):*
          Verify `SELECT openmettle.storage_lock_pinned_volume()` == `store.volume_id` and all
          three `:root`, `:revisions`, `:staging` role-tagged `.openmettle-volume-id` sentinels.
          Probe `revisions/.purge.<id>` (`AtFlags::SYMLINK_NOFOLLOW`):
          - **If `revisions/.purge.<id>` exists:** require `S_ISREG`, `st_dev == store.root_dev`,
            and `st_ino as u64 == payload_ino` (otherwise **STOP IMMEDIATELY with ZERO
            `set_len(0)`, ZERO `unlinkat`, and DO NOT call `confirm_purge`**). Open
            `revisions/.purge.<id>` (`OFlags::RDWR | OFlags::NOFOLLOW`, explicitly **WITHOUT
            `OFlags::TRUNC`**) -> `LOCK_EX` (`try_lock()`, aborting on `WouldBlock` — including when
            an in-flight `Store::read` holds `LOCK_SH` inside `Content`!) -> re-verify `fstat` +
            `statat` -> revalidate in PostgreSQL (`SELECT openmettle.storage_lock_pinned_volume();
            SELECT 1 FROM openmettle.artifact_revisions WHERE scope_id = $1::uuid AND id = $2::uuid
            AND state = 'purging'`, aborting on `0` rows or volume mismatch) -> `set_len(0)?` +
            `sync_all()?` -> **unconditional `fsync(&revisions_dir_fd)?`**. Keep `LOCK_EX` held
            through Stage A.
          - **If `revisions/.purge.<id>` is `Errno::NOENT`:** probe `revisions/<id>`
            (`AtFlags::SYMLINK_NOFOLLOW`). If `revisions/<id>` is `Errno::NOENT`, non-regular, on a
            different host-local `st_dev`, or has **`rev_stat.st_ino as u64 != payload_ino`** (a
            foreign replacement regular file or unexpectedly missing file): **STOP IMMEDIATELY with
            ZERO `set_len(0)`, ZERO `unlinkat` (do NOT touch `staging/<id>`!), and DO NOT call
            `storage::confirm_purge`** (leaving `artifact_revisions.state = 'purging'` and
            `retained_bytes` 100% charged for `verify_accounting_drift` and `openmettle_owner`
            reconciliation!). Otherwise open `revisions/<id>` (`OFlags::RDWR | OFlags::NOFOLLOW`,
            explicitly **WITHOUT `OFlags::TRUNC`**) -> `LOCK_EX` (`try_lock()`, aborting on
            `WouldBlock` so an active `Store::read` stream holding `LOCK_SH` inside `Content` is
            never truncated!) -> re-verify `fstat` + `statat` -> revalidate in PostgreSQL (`SELECT
            openmettle.storage_lock_pinned_volume()` + `state = 'purging'`) -> `set_len(0)?` +
            `sync_all()?` -> **`rustix::fs::linkat(&revisions_dir_fd, id, &revisions_dir_fd,
            ".purge.<id>", AtFlags::empty())`** (if `EEXIST`, verify `revisions/.purge.<id>` is
            `S_ISREG` on `store.root_dev` with `st_ino as u64 == payload_ino`) -> **unconditional
            `fsync(&revisions_dir_fd)?` strictly BEFORE unlinking `revisions/<id>`**! Keep `LOCK_EX`
            held through Stage A.
          - Still holding `LOCK_EX` while `revisions/.purge.<id>` keeps `payload_ino` pinned at
            `nlink >= 1`:
            - If `revisions/<id>` exists with `S_ISREG`, `st_dev == store.root_dev`, and `st_ino as
              u64 == payload_ino`, call `unlinkat(&revisions_dir_fd, id, AtFlags::empty())?` (leave
              untouched if `st_ino != payload_ino`).
            - If `staging/<id>` exists with `S_ISREG`, `st_dev == store.root_dev`, and `st_ino as
              u64 == payload_ino` (guaranteed NOT to be a recycled inode because
              `revisions/.purge.<id>` still pins `payload_ino`!), call `unlinkat(&staging_dir_fd,
              id, AtFlags::empty())?` (**never `set_len(0)`**; leave foreign `staging/<id>` 100%
              untouched!).
            - Unconditionally call and require `Ok(())` from **BOTH `fsync(&revisions_dir_fd)` AND
              `fsync(&staging_dir_fd)`**, then drop the `LOCK_EX` FD (`revisions/.purge.<id>`
              remains durably linked on disk!).
       3. *Stage B (`storage::confirm_purge` while `revisions/.purge.<id>` still holds `nlink >=
          1`):* Sets **`state = 'purged', purged_at = now(), purge_stage = 'anchor_pending_unlink'`**
          and decrements `retained_bytes` via `adjust()` (with `enforce_runtime_storage_volume_pinned()`
          calling `storage_lock_pinned_volume()`).
       4. *Stage C (Post-`confirm_purge` detach of `revisions/.purge.<id>` + bounded `LIMIT` DB
          pass with wrapping keyset cursor and pass-start fixed upper watermark):* Immediately
          after `confirm_purge` commits AND in a bounded DB pass inside `purge_due` maintaining a
          per-worker wrapping keyset cursor **`purge_anchor_cursor: Option<(DateTime<Utc>, Uuid)>`**
          and a pass-start fixed upper watermark **`purge_anchor_pass_upper: Option<(DateTime<Utc>,
          Uuid)>`** backed by partial index `artifact_revisions_purge_anchor_idx`. At the start of
          each sweep pass (when `purge_anchor_pass_upper` is `None`), capture the fixed upper
          watermark `(upper_ts, upper_id)` (returning immediately if `None`):
          ```sql
          SELECT r.purged_at, r.id
            FROM openmettle.artifact_revisions r
            JOIN openmettle.storage_reservations sr
              ON sr.scope_id = r.scope_id AND sr.id = r.reservation_id
           WHERE r.state = 'purged'
             AND r.purge_stage = 'anchor_pending_unlink'
             AND NOT sr.adoption_unverified
             AND sr.payload_ino IS NOT NULL
           ORDER BY r.purged_at DESC, r.id DESC
           LIMIT 1;
          ```
          Then constrain every page in that pass by `(upper_ts, upper_id)`:
          ```sql
          SELECT r.scope_id::text, r.id::text, r.reservation_id::text, sr.payload_ino, r.purged_at
            FROM openmettle.artifact_revisions r
            JOIN openmettle.storage_reservations sr
              ON sr.scope_id = r.scope_id AND sr.id = r.reservation_id
           WHERE r.state = 'purged'
             AND r.purge_stage = 'anchor_pending_unlink'
             AND NOT sr.adoption_unverified
             AND sr.payload_ino IS NOT NULL
             AND ($1::timestamptz IS NULL OR (r.purged_at, r.id) > ($1::timestamptz, $2::uuid))
             AND (r.purged_at, r.id) <= ($3::timestamptz, $4::uuid)
           ORDER BY r.purged_at ASC, r.id ASC
           LIMIT $5;
          ```
          Detach `revisions/.purge.<id>` under `LOCK_EX` (**`OFlags::RDWR | OFlags::NOFOLLOW`
          explicitly WITHOUT `OFlags::TRUNC` and preserving zero `set_len(0)`**, verifying `S_ISREG`,
          `st_dev == store.root_dev`, `st_ino as u64 == payload_ino`, and `st_size == 0`, **never
          `set_len(0)`**) -> `drop` -> `fsync(&revisions_dir_fd)` -> `UPDATE
          openmettle.artifact_revisions SET purge_stage = 'none' WHERE scope_id = $1::uuid AND id =
          $2::uuid AND state = 'purged' AND purge_stage = 'anchor_pending_unlink'` (preserving
          untouched and logging an anomaly on foreign inode or non-zero size, or skipping on
          `WouldBlock`; if `revisions/.purge.<id>` returns `Errno::NOENT`, call
          `fsync(&revisions_dir_fd)` and clear `purge_stage = 'none'`). **Advance
          `purge_anchor_cursor = Some((r.purged_at, r.id))` past EVERY inspected key (including
          anomalous foreign-inode anchors and `WouldBlock` rows!), and reset BOTH
          `purge_anchor_cursor = None` AND `purge_anchor_pass_upper = None` whenever a page returns
          `< LIMIT` rows OR reaches `(upper_ts, upper_id)`** so neither persistent anomalous anchors
          nor sustained arrivals of `>= LIMIT` new pending rows per tick can starve earlier
          `WouldBlock` or trailing anchors!
     - **PR2 updates [ADR 0031](0031-filesystem-artifact-storage-and-streaming-multipart.md)'s
       `reconcile_expired` behavior (and `tests/schema/artifact_fs.rs`'s `renamed` test case) to
       execute the unified 4-step reclamation protocol above:** For each expired `state =
       'reserved' AND run_id IS NULL AND NOT adoption_unverified` candidate from the raw-key pass
       below, run Step 1 (serialized DB lease claim `reclaim_state = 'claiming' | 'truncated'` via
       `storage_lock_pinned_volume()`, zero FS I/O) -> Step 2 (outside DB tx: Case 1a/1b
       `payload_ino IS NOT NULL` probing `.reclaim.<id>` first, Step 2a fenced DB claim
       revalidation & 300 s lease renewal under `LOCK_EX` (`OFlags::RDWR | OFlags::NOFOLLOW`
       without `OFlags::TRUNC`) strictly before `set_len(0)` + `sync_all()` -> `linkat` anchor
       `staging/.reclaim.<id>` + unconditional `fsync(&staging_dir_fd)` on both new and recovered
       anchors -> unlink `<id>` + dual `fsync` -> `'truncated'` keeping `payload_ino` non-null and
       `nlink >= 1`, or Case 2 `payload_ino IS NULL` opening `0`-byte regular `staging/<id>` with
       `revisions/<id>` and `staging/.reclaim.<id>` `ENOENT` via `OFlags::RDWR | OFlags::NOFOLLOW`
       without `OFlags::TRUNC` + `LOCK_EX` + Step 2a SQL atomically binding `stage_claimed = true,
       payload_ino = fd_ino` and promoting directly into the standard `.reclaim.<id>` ->
       `'truncated'` -> Step 3 `'anchor_pending_unlink'` -> Step 4 sequence, leaving `payload_ino`
       `NULL` through Step 3 ONLY when all three names are already `ENOENT` with ZERO `unlinkat`
       calls) -> Step 3 (`storage::release` with ZERO FS I/O inside DB tx, setting `reclaim_state =
       'anchor_pending_unlink'` when `payload_ino IS NOT NULL` and retaining `payload_ino` on
       `'released'`) -> Step 4 (post-release `OFlags::RDWR | OFlags::NOFOLLOW` without
       `OFlags::TRUNC` + `LOCK_EX` `unlinkat` of `staging/.reclaim.<id>` (never `set_len(0)`) +
       `fsync(&staging_dir_fd)` + best-effort `reclaim_state = 'none'`, reinforced by the bounded
       DB-driven Step 4 pass over `storage_reservations_reclaim_anchor_idx` across all reservation
       kinds with wrapping keyset cursor `reclaim_anchor_cursor` + pass-start fixed upper watermark
       `(upper_ts, upper_id)`). A cancelled
       mid-stream `StagedFile` whose non-destructive `Drop` closed its FD without unlinking leaves
       its `st_ino == payload_ino` file at `staging/<id>`, and a crashed post-`linkat` unsettled
       file leaves `st_ino == payload_ino` hard-linked at both `staging/<id>` and `revisions/<id>`
       — both are cleanly reclaimed by Case 1a with zero false quarantine, while any foreign
       replacement leaf or `'claiming'` all-three `ENOENT` quarantines to `adoption_unverified =
       true` with zero truncation or unlink!
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
       expiry_col ASC, id ASC LIMIT batch_size`, runs the unified 4-step reclamation protocol on
       those `<= batch_size` keys, advances `last_attempted` across **every inspected raw key**
       (including 100%-ineligible pages), and wraps only when the raw key page returns `<
       batch_size` rows or reaches `pass_upper_bound`.
   - *Run-linked storage holds (`run_id IS NOT NULL`, exact logical complement `(operation_id IS
     NULL OR idempotency_key NOT LIKE 'tool-spill:%')`):*
     **Single cleanup owner for `tool-spill:*` reservations with zero ownership gap:**
     [ADR 0039](0039-scoped-mcp-adapter-and-bounded-tool-results.md) (`V1-14` PR2, sequenced on
     `V1-17` PR2's `storage_volume_control`/`dirfd`/`payload_ino`/4-step-cleaner foundation)
     `reconcile_run_spills` **exclusively owns `operation_id IS NOT NULL AND idempotency_key LIKE
     'tool-spill:%'`** (executing the exact same unified 4-step reclamation protocol with fenced
     Step 2a DB revalidation under `LOCK_EX`, unconditional anchor `fsync`, and ZERO filesystem I/O
     in Step 1 and Step 3, and requiring `storage_volume_control` present AND `volume_id IS NOT
     NULL AND adoption_run_id IS NULL` for both `publish_bytes` and `reconcile_run_spills`), while
     ADR 0040's generic run-linked cleaner **exclusively owns the exact logical complement `run_id
     IS NOT NULL AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')`** in
     **both** partial index `WHERE` clauses AND Step 1 / Step 3 under-lock eligibility checks (so
     any pre-existing row with `run_id IS NOT NULL AND operation_id IS NULL AND idempotency_key
     LIKE 'tool-spill:%'` is cleanly owned by ADR 0040's generic cleaner with zero unowned gap, and
     `storage_reservations_tool_spill_binding_guard` (`23514`) enforces for all new/updated rows
     that `idempotency_key LIKE 'tool-spill:%'` requires BOTH `run_id IS NOT NULL AND operation_id
     IS NOT NULL`). For all run-linked holds in ADR 0040's complement partition, recovery requires
     configured `OPENMETTLE_WORKER_ARTIFACTS_DIR` (`ARTIFACTS_DIR`, `artifact_fs::Store`) with
     verified **`storage_volume_control` present AND `volume_id IS NOT NULL AND adoption_run_id IS
     NULL`** and all three role-tagged directory sentinels (skipping cleanly with zero unlinks or
     releases if unavailable or unverified). Otherwise, run **two-step raw-index-key paging**
     across two independent bounded passes backed by 100% `IMMUTABLE` plain-column partial B-tree
     indexes — **zero joins, zero `EXISTS`, and zero `clock_timestamp()` calls before `LIMIT`**:
     (a) modern rows with `lease_expires_at IS NOT NULL` over `storage_reservations_run_expiry_idx`
     (`ON openmettle.storage_reservations (lease_expires_at, id) WHERE state = 'reserved' AND
     run_id IS NOT NULL AND lease_expires_at IS NOT NULL AND NOT adoption_unverified AND
     (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')`, constant `pass_upper_bound
     = (v_now, max_uuid)`), and (b) legacy rows with `lease_expires_at IS NULL` over
     `storage_reservations_run_legacy_expiry_idx` (`ON openmettle.storage_reservations (created_at,
     id) WHERE state = 'reserved' AND run_id IS NOT NULL AND lease_expires_at IS NULL AND NOT
     adoption_unverified AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')`,
     constant `pass_upper_bound = (v_now - interval '900 seconds', max_uuid)`). Each pass
     materializes at most `batch_size` raw `(expiry_col, id)` keys, evaluates eligibility (terminal
     linked run, zero `'intent'`/`'outcome_unknown'` operations, and legacy terminal-run grace rule
     when `lease_expires_at IS NULL`) only on those `<= batch_size` keys, advances `last_attempted`
     across every inspected raw key across `SWEEP_MS` ticks (60 s default interval, 15 s per-sweep
     budget), and processes **one eligible reservation per unified 4-step reclamation cycle**
     (Step 1 DB lease claim -> Step 2 outside-DB-tx Case 1a/1b / Case 2 with Step 2a fenced DB
     revalidation under `LOCK_EX` (`OFlags::RDWR | OFlags::NOFOLLOW` without `OFlags::TRUNC`)
     strictly before `set_len(0)` + `sync_all()` -> `linkat` `staging/.reclaim.<id>` +
     unconditional `fsync(&staging_dir_fd)` -> unlink `<id>` -> `'truncated'` -> Step 3 zero-FS-IO
     `storage::release` setting `'anchor_pending_unlink'` and retaining `payload_ino` on
     `'released'` -> Step 4 post-release `OFlags::RDWR | OFlags::NOFOLLOW` (without `OFlags::TRUNC`,
     zero `set_len(0)`) + `LOCK_EX` `unlinkat` of `staging/.reclaim.<id>` + `fsync` +
     `reclaim_state = 'none'`).
   - *Retryable zero-truncation `staging/` cleanup after post-release / post-`settle` crashes
     (persistent `StagingSweepState` across `worker::sweep`'s 15 s outer `tokio::time::timeout`,
     retaining open `dir_fd` through EOF drain, with Linux NFS-safe `OFlags::RDWR |
     OFlags::NOFOLLOW` without `OFlags::TRUNC` + `LOCK_EX`, `adoption_unverified` skip, **ZERO
     `set_len(0)` calls in ANY branch**, and cleanly partitioned 3-bucket `ReadDir`
     classification):*
     Because a worker or API replica may crash after committing `storage::release` (`state =
     'released'`, `reclaim_state = 'anchor_pending_unlink'`) or `storage::settle` (`state =
     'settled'`) with a stranded `staging/.reclaim.<id>` anchor or `staging/<id>` alias, a sweep
     querying only `state = 'reserved'` would skip that row permanently and leave an orphan
     `staging/` entry that fails `verify_accounting_drift`. Conversely, reading an entire large or
     slow `staging/` directory into memory and sorting it before applying a filename cursor could
     exhaust the entire 15 s sweep budget before advancing — and in
     [`src/worker.rs`](../../src/worker.rs), `worker::sweep` wraps each tick's future in
     `tokio::time::timeout(Duration::from_secs(15), work)`. On startup recovery and during bounded
     worker storage sweeps, `worker::maintenance` therefore holds a persistent
     **`StagingSweepState`** across `SWEEP_MS` ticks **outside** the per-tick `tokio::time::timeout`
     future, carrying an open directory descriptor (`dir_fd: OwnedFd` / `std::fs::File` opened with
     `OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW` on the verified `<root>/staging`
     directory) across all active states — **`Idle`**, **`Open { dir_fd, dir_dev, dir_ino, reader
     }`**, **`InFlight { dir_fd, dir_dev, dir_ino, handle }`**, **`InvalidatedInFlight { handle
     }`**, and **`DrainingEof { dir_fd, dir_dev, dir_ino }`** (where `handle` is the sole
     `JoinHandle<io::Result<(ReadDir, Vec<StagingEntry>, bool)>>`) — plus a
     **`VecDeque<StagingEntry>` of undrained `pending_names`**, dropping `dir_fd` **only when
     `pending_names.is_empty()` and the state transitions to `Idle` (or when invalidated into
     `InvalidatedInFlight` / `Idle` after clearing `pending_names`)**:
     - At the start of each tick, open `<root>`, `<root>/revisions`, and `<root>/staging`
       (`OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW`), verify **`storage_volume_control`
       present AND `volume_id IS NOT NULL AND adoption_run_id IS NULL`** (via
       `storage_lock_pinned_volume()`), equal host-local `st_dev` across all three FDs, and valid
       role-tagged `.openmettle-volume-id` sentinels (`:root`, `:revisions`, `:staging` via
       `openat(..., OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK)` + `fstat` `S_ISREG` on
       each FD, bounded `<= 64`-byte read), and inspect `<root>/staging`'s live `(cur_dev,
       cur_ino)`:
       - *If `storage_volume_control` is missing, `volume_id IS NULL`, `adoption_run_id IS NOT
         NULL`, or volume sentinel/local `st_dev` verification fails:* clear `pending_names` with
         zero unlinks; if `StagingSweepState` is `InFlight { handle, .. }`, drop `dir_fd` and
         transition to **`InvalidatedInFlight { handle }`** (never dropping the running `handle`
         into `Idle`); if `Open` or `DrainingEof`, drop `dir_fd` and transition to `Idle`; and fail
         closed for the tick without spawning any new reader.
       - *If `(cur_dev, cur_ino)` changed against parked `Open`, `InFlight`, or `DrainingEof`:*
         clear `pending_names` with zero unlinks; drop `dir_fd` and transition `Open` or
         `DrainingEof` to `Idle`; and drop `dir_fd` while transitioning `InFlight { handle, .. }`
         to **`InvalidatedInFlight { handle }`** (preserving the single-reader guarantee across
         directory replacement and 15 s tick timeouts).
     - If `StagingSweepState` is **`InvalidatedInFlight { handle }`**, **await `&mut handle` until
       the blocking slice finishes**, **discard its returned `ReadDir` and names without touching
       `pending_names` or unlinking anything, and ONLY THEN transition to `Idle`**.
     - If `StagingSweepState` is **`InFlight { dir_fd, dir_dev, dir_ino, handle }`** (with verified
       matching `(cur_dev, cur_ino) == (dir_dev, dir_ino)`), **first await the parked `&mut
       handle`** (never spawning a second concurrent `ReadDir` task). When `handle` resolves,
       append its returned entries to `pending_names` and transition to `Open { dir_fd, dir_dev,
       dir_ino, reader }` when `eof == false`, or drop `reader` while **retaining `dir_fd`** and
       transition to **`DrainingEof { dir_fd, dir_dev, dir_ino }`** when `eof == true`.
     - **Zero-Truncation Guarantee & Clean 3-Bucket `ReadDir` Entry Classification (synchronized
       verbatim with ADR 0039):** **`StagingSweepState` NEVER calls `set_len(0)` in ANY branch —
       ZERO `set_len(0)` calls anywhere in `StagingSweepState`!** Unlinking (`unlinkat`) removes
       only the `staging/` directory entry (`nlink -= 1`): if `nlink == 1`, blocks are freed
       immediately when the FD drops; if `nlink > 1` (e.g., an aged `staging/A` or unowned
       `staging/.reclaim.<id>` hard-linked to active `revisions/B`), `revisions/B` retains 100% of
       its bytes and SHA-256! Before draining `ReadDir` entries, also execute the bounded DB-driven
       Step 4 pass over `storage_reservations_reclaim_anchor_idx` across all reservation kinds using
       per-worker wrapping keyset cursor `reclaim_anchor_cursor` + pass-start fixed upper watermark
       `(upper_ts, upper_id)` (see Step 4 above). Drain
       `pending_names` in bounded batches against `openmettle.storage_reservations` (`SELECT id,
       state, adoption_unverified, payload_ino, reclaim_state FROM openmettle.storage_reservations
       WHERE id = ANY($1)`) **exactly once** (popping entries only as processed, checking
       `Instant::now() < sweep_deadline` and `inspected_entries < batch_size`, and confirming
       `<root>/staging` still has `(cur_dev, cur_ino) == (dir_dev, dir_ino)` and valid
       `"<volume_uuid>:staging\n"`). **NEVER unlink any `staging/` entry without holding
       non-blocking exclusive flock `LOCK_EX | LOCK_NB` on the verified `(staging_dev, staging_ino)`
       regular file** (open via **`rustix::fs::openat(&dir_fd, entry_name, OFlags::RDWR |
       OFlags::NOFOLLOW)` — explicitly WITHOUT `OFlags::TRUNC`, required on Linux NFS where
       `flock(LOCK_EX)` maps to `F_WRLCK` and fails `EBADF` on `O_RDONLY`, while preserving ZERO
       `set_len(0)` calls anywhere in `StagingSweepState`!** -> `std::fs::File::from(owned_fd)` ->
       `file.try_lock()`, skipping immediately on `WouldBlock`, and re-verifying local `st_dev`,
       `staging_ino`, `staging_size`, and `S_ISREG` via `statat(&dir_fd, entry_name,
       AtFlags::SYMLINK_NOFOLLOW)` against `fstat(&file)`). Partition every `ReadDir` entry into
       exactly three buckets:
       1. *`.openmettle-volume-id`:* skip unconditionally.
       2. *`.reclaim.<id>` (canonical lowercase UUID `<id>`):*
          - `state = 'reserved'` (any `reclaim_state`, including `'claiming'` and `'truncated'`):
            **skip 100% untouched**.
          - `state = 'released' AND reclaim_state = 'anchor_pending_unlink' AND NOT
            adoption_unverified AND payload_ino IS NOT NULL`: verify `S_ISREG`, `st_dev ==
            store.root_dev`, **`st_ino == payload_ino`**, and **`st_size == 0`** -> open
            `OFlags::RDWR | OFlags::NOFOLLOW` (without `OFlags::TRUNC`) -> `LOCK_EX` (`try_lock()`)
            -> re-verify `fstat` + `statat` -> `unlinkat(&staging_dir_fd, ".reclaim.<id>",
            AtFlags::empty())` (**never `set_len(0)`**) -> `drop` -> `fsync(&staging_dir_fd)` ->
            `UPDATE openmettle.storage_reservations SET reclaim_state = 'none' WHERE id = $1::uuid
            AND state = 'released' AND reclaim_state = 'anchor_pending_unlink'` (preserve untouched
            and log anomaly on foreign inode or non-zero size).
          - `0` rows in `storage_reservations` (`st_mtime > 900 s`), OR `(state = 'released' AND
            reclaim_state = 'none' AND st_mtime > 900 s)`, OR `(state = 'settled' AND st_mtime >
            900 s)`: open `OFlags::RDWR | OFlags::NOFOLLOW` (without `OFlags::TRUNC`) -> `LOCK_EX`
            (`try_lock()`) -> re-verify `fstat` (`S_ISREG`, `st_dev == store.root_dev`, `st_mtime >
            900 s`) + `statat` -> serialize in PostgreSQL (`SELECT
            openmettle.storage_lock_pinned_volume()` + `SELECT id FROM openmettle.storage_instance
            WHERE id FOR NO KEY UPDATE` + re-check `storage_reservations WHERE id = <id>` still
            matches `0` rows / `released+none` / `settled`) -> **`unlinkat(&staging_dir_fd,
            ".reclaim.<id>", AtFlags::empty())` WITHOUT `set_len(0)`** -> `drop` ->
            `fsync(&staging_dir_fd)`.
       3. *Regular UUID entries `<id>` (and any aged non-UUID / malformed regular files in the
          `0`-row branch):*
          - `state = 'reserved'`: **skip 100% untouched**.
          - `state = 'released'`: skip untouched if `payload_ino IS NOT NULL` OR
            `adoption_unverified = true` OR `st_size > 0`; when `payload_ino IS NULL AND NOT
            adoption_unverified AND st_size == 0`, open `OFlags::RDWR | OFlags::NOFOLLOW` (without
            `OFlags::TRUNC`) -> `LOCK_EX` (`try_lock()`) -> re-verify `statat` + `st_size == 0` ->
            `unlinkat(&staging_dir_fd, id, AtFlags::empty())` **WITHOUT `set_len(0)`** -> `drop` ->
            `fsync(&staging_dir_fd)`.
          - `state = 'settled'`: skip untouched if `adoption_unverified = true` OR `payload_ino IS
            NULL` OR `staging_ino != payload_ino`. When `staging_ino == payload_ino`, detach
            `staging/<id>` (`OFlags::RDWR | OFlags::NOFOLLOW` without `OFlags::TRUNC` -> `LOCK_EX`
            (`try_lock()`) -> re-verify `statat` -> `unlinkat(&staging_dir_fd, id, AtFlags::empty())`
            **WITHOUT `set_len(0)`** -> `drop` -> `fsync(&staging_dir_fd)`) **STRICTLY ONLY when
            `artifact_revisions.state IN ('active', 'retained')` AND `revisions/<id>` currently
            exists on disk as `S_ISREG` on `store.root_dev` with `rev_stat.st_ino as u64 ==
            payload_ino`**! (There is **NO** post-purge `artifact_revisions.state = 'purged'`
            `ENOENT` exception: `purge_due` Stage A already detaches any matching `staging/<id>`
            alias while `revisions/.purge.<id>` pins `payload_ino` alive before `confirm_purge`;
            once `artifact_revisions.state IN ('purging', 'purged')`, `StagingSweepState` never
            unlinks `staging/<id>` by historical `payload_ino`!)
          - `0` rows in `storage_reservations` (`st_mtime > 900 s`, plus aged non-UUID / malformed
            regular files): open `OFlags::RDWR | OFlags::NOFOLLOW` (without `OFlags::TRUNC`) ->
            `LOCK_EX` (`try_lock()`, skipping active pre-commit writers holding `LOCK_EX`/`LOCK_SH`)
            -> re-verify `fstat` (`S_ISREG`, `st_dev == store.root_dev`, `st_mtime > 900 s`) and
            `statat` -> serialize in PostgreSQL (`SELECT openmettle.storage_lock_pinned_volume()` ->
            `SELECT id FROM openmettle.storage_instance WHERE id FOR NO KEY UPDATE` -> confirm `0`
            rows if UUID) -> **`unlinkat(&staging_dir_fd, entry_name, AtFlags::empty())` STRICTLY
            WITHOUT `set_len(0)`** -> `drop` -> `fsync(&staging_dir_fd)`.
       Never unlink a `staging/<id>` or `staging/.reclaim.<id>` file whose `storage_reservations`
       row is still `state = 'reserved'` (or has `adoption_unverified = true`) outside the verified
       4-step reclamation paths. When `StagingSweepState` is **`DrainingEof { dir_fd, dir_dev,
       dir_ino }`**, drop `dir_fd` and transition to `Idle` **only once `pending_names.is_empty()`**.
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
`quota_gateway_handoffs`, `quota_accepted_gateway_reports`, `quota_overrides`, `quota_budgets`,
`quota_reservations`, `quota_reservation_charges`, `quota_reconciliations` or
`quota_warning_events`), and zero runtime roles hold even `SELECT` on `quota_cost_unit_lock`,
`quota_gateway_handoffs`, or `quota_accepted_gateway_reports`.**
Because PostgreSQL 18 requires `UPDATE` privilege to execute `SELECT ... FOR NO KEY UPDATE` or
`FOR UPDATE`, **no runtime role executes direct row-locking `SELECT` on any `quota_*` table**
either; all `quota_*` row locking and writes (as well as `quota_cost_unit_lock` locking inside the
`gateway_usage_reports_cost_unit_guard` trigger, gateway-binding verification inside
`quota_reservations_gateway_binding_guard`, durable per-revision acceptance recording into
`quota_accepted_gateway_reports` inside `quota_record_accepted_gateway_settlement`, pre-upsert
gateway-request locking inside `quota_lock_gateway_request_for_settlement(uuid)`, commit-time
handoff hold verification, `quota_gateway_handoffs` recording before `quota_enforcement FOR SHARE`
locking inside `quota_enforce_gateway_handoff_holds` / `enforce_gateway_handoff_holds()`,
`tool-spill:%` namespace binding inside `enforce_tool_spill_reservation_binding()`, lazy legacy-run
parent hold initialization inside `quota_ensure_legacy_run_holds()`, runtime pinned-volume `FOR
SHARE` locking inside `openmettle.storage_lock_pinned_volume()`, and fresh-bootstrap-only
`storage_volume_control.volume_id` auto-pinning inside `openmettle.storage_pin_volume_id(uuid)`)
run strictly inside narrow `openmettle_owner`-owned `SECURITY DEFINER` functions with `SET
search_path = pg_catalog`, schema-qualified relations, `REVOKE ALL ON FUNCTION ... FROM PUBLIC` and
exact `oid::regprocedure` signatures audited in `src/boundaries.sql` (following
[ADR 0030](0030-session-issuance-database-boundary.md) and ADR 0037). Because PostgreSQL 18 requires
`UPDATE` privilege on at least one column to execute `SELECT ... FOR SHARE` or `FOR UPDATE`, neither
`openmettle_api` nor `openmettle_worker` receives `INSERT`, `UPDATE`, `DELETE`, or `TRUNCATE` on
`openmettle.storage_volume_control` (`SELECT`-only for both runtime roles); instead, PostgreSQL
ledger backstop guarding for unpinned or adopting runtime storage mutations
(`openmettle.enforce_runtime_storage_volume_pinned()`, `OMQ03`) and monotonic storage-reservation
column guards (`openmettle.enforce_storage_reservation_monotonic_guards()`, `OMQ03`, paired with
tightened `storage_reservations_adoption_unverified_check`: `CHECK (NOT adoption_unverified OR state
= 'reserved')` so non-`openmettle_owner` roles can never clear `adoption_unverified`, release a
quarantined reservation, mutate or clear non-null `payload_ino`, or clear `stage_claimed`) run
strictly as **`SECURITY INVOKER`** (`SET search_path = pg_catalog`) so `NOT
pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')` evaluates the active effective
role accurately across **both** `INHERIT` logins and `NOINHERIT` logins executing `SET ROLE
openmettle_api` / `SET ROLE openmettle_worker`, with `enforce_runtime_storage_volume_pinned()`
delegating `PERFORM openmettle.storage_lock_pinned_volume();` to acquire `SELECT ... FOR SHARE` on
`openmettle.storage_volume_control` as `openmettle_owner` without `42501` and raise `OMQ03` on
missing row, `volume_id IS NULL`, or `adoption_run_id IS NOT NULL`! Neither `openmettle_api` nor
`openmettle_worker` receives direct `SELECT` privileges on Migration `0023`'s
`openmettle.gateway_requests` or `openmettle.gateway_usage_reports` (or other gateway tables): lost
commit-ack handoff recovery runs solely through `openmettle.quota_recover_lost_handoff(...)`, lazy
legacy-run parent hold backfill runs solely through `openmettle.quota_ensure_legacy_run_holds(...)`,
fenced successor-worker superseded-round unwind runs solely through
`openmettle.quota_unwind_superseded_round(...)`, pre-upgrade orphan `'reserved'` gateway sweep runs
solely through `openmettle.quota_release_orphan_gateway_requests(...)`, and SQL drift verification
runs solely through `openmettle.quota_verify_accounting_drift()`.

| Object or `SECURITY DEFINER` entrypoint | `openmettle_api` | `openmettle_worker` | `openmettle_gateway` (Migration `0023`) | `openmettle_issuance` (ADR 0030) |
| --- | --- | --- | --- | --- |
| `quota_defaults` | `SELECT` only | `SELECT` only | `SELECT` only | None |
| `quota_cost_unit_lock` | None | None | None (locked internally by `SECURITY DEFINER` trigger `enforce_gateway_report_cost_unit()`) | None |
| `quota_enforcement` | `SELECT` only | `SELECT` only | `SELECT` only | None |
| `quota_gateway_handoffs` | None (written at `COMMIT` by `SECURITY DEFINER` `enforce_gateway_handoff_holds()` before locking `quota_enforcement FOR SHARE`; read internally by `SECURITY DEFINER` `quota_recover_lost_handoff()`) | None (same, plus `quota_verify_accounting_drift()`) | None | None |
| `quota_accepted_gateway_reports` | None | None (read internally by `SECURITY DEFINER` `quota_verify_accounting_drift()`) | None (populated automatically by `SECURITY DEFINER` `AFTER INSERT OR UPDATE OF revision, final` trigger `quota_record_accepted_gateway_settlement` on `gateway_settlements`; read internally by `SECURITY DEFINER` `quota_settle_gateway_usage()` and `enforce_quota_reservation_gateway_binding()`) | None |
| `quota_overrides` | `SELECT` only | `SELECT` only | `SELECT` only | None |
| `quota_budgets`, `quota_reservations`, `quota_reservation_charges`, `quota_reconciliations`, `quota_warning_events` | `SELECT` only | `SELECT` only | `SELECT` only | None |
| `openmettle.storage_lock_pinned_volume()` (`RETURNS uuid`) | `EXECUTE` (`SECURITY DEFINER`, `SET search_path = pg_catalog`; executes `SELECT volume_id, adoption_run_id INTO v_vol, v_adopt FROM openmettle.storage_volume_control WHERE id FOR SHARE` as `openmettle_owner` without requiring table `UPDATE` privilege; raises `OMQ03` if `NOT FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL` and returns `v_vol`; called both directly by runtime storage paths and via `PERFORM openmettle.storage_lock_pinned_volume()` from `SECURITY INVOKER` `enforce_runtime_storage_volume_pinned()`) | `EXECUTE` (same) | None | None |
| `openmettle.storage_pin_volume_id(uuid)` (`RETURNS uuid`) | `EXECUTE` (`SECURITY DEFINER`, `SET search_path = pg_catalog`; granted **solely to `openmettle_api`** — only `openmettle_api` (`Store::open` in API) initializes fresh `.openmettle-volume-id` sentinels and calls `storage_pin_volume_id(uuid)` on an empty fresh bootstrap; acquires `SELECT volume_id, bootstrap_auto_pin_allowed, adoption_run_id FROM openmettle.storage_volume_control WHERE id FOR UPDATE` internally as `openmettle_owner` — `Store::open` does NOT issue an invoker `SELECT ... FOR UPDATE`; raises `OMQ03` if `NOT FOUND OR adoption_run_id IS NOT NULL`; returns existing `volume_id` if already equal to `p_volume_id` or raises `OMQ03` on mismatch; otherwise permits write-once auto-pinning **only** while `bootstrap_auto_pin_allowed = true` AND BOTH `NOT EXISTS (SELECT 1 FROM openmettle.storage_reservations)` AND `NOT EXISTS (SELECT 1 FROM openmettle.artifact_revisions)`, atomically setting `volume_id = p_volume_id, bootstrap_auto_pin_allowed = false` and returning `volume_id`; refuses every upgraded deployment (`bootstrap_auto_pin_allowed = false`, even with empty storage tables) and every populated ledger with `OMQ03`) | None (`openmettle_worker` never initializes sentinels and never calls `storage_pin_volume_id(uuid)`; when `volume_id IS NULL` on worker-first fresh boot or pre-adoption upgrade, worker storage ticks and `publish_bytes` observe `OMQ03` / unpinned state via `storage_lock_pinned_volume()` without `42501` and skip/fail closed cleanly until `volume_id` is pinned by `openmettle_api` or `openmettle storage adopt`) | None | None |
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
| `openmettle.quota_lock_gateway_request_for_settlement(uuid)` | None | None | `EXECUTE` (**unconditionally** called strictly BEFORE `INSERT`/`UPDATE` on `openmettle.gateway_settlements` by **every** `openmettle_gateway` write transaction — **both** settlement-only transactions **and** combined single-transaction writes (`gateway_settlements` upsert + `quota_settle_gateway_usage`); acquires `SELECT 1 FROM openmettle.gateway_requests WHERE id = $1::uuid FOR NO KEY UPDATE` so `gateway_mark_settled_final` never upgrades locks and every settlement writer follows the strictly acyclic global DAG `runs -> gateway_reservations -> gateway_requests -> gateway_settlements -> quota_accepted_gateway_reports -> quota_reservations -> quota_budgets` with zero cycles across settlement-only writers, combined writers, and worker recovery) | None |
| `openmettle.quota_settle_gateway_usage(...)` | None | None | `EXECUTE` (`usage_tokens`/`usage_cost_micros` only; operates strictly on `state IN ('handoff_committed', 'settled')` holds and **never locks `runs` or `gateway_reservations`**; requires `openmettle_gateway` to have already advanced `openmettle.gateway_settlements` (with `measured` widened to `numeric(38, 0)` in PR2's migration, preceded by `quota_lock_gateway_request_for_settlement` and triggering `quota_record_accepted_gateway_settlement` into `quota_accepted_gateway_reports`) in the same tx or a prior commit; locks `gateway_requests FOR KEY SHARE` -> `quota_reservations (ORDER BY resource ASC FOR UPDATE)` -> `quota_budgets FOR NO KEY UPDATE`, verifying `(p_report_source, p_report_id, p_source_revision)` matches `openmettle.gateway_usage_reports` (`revision >= 0`, immutable `cost_denomination` vs `unit`) and `EXISTS (SELECT 1 FROM openmettle.quota_accepted_gateway_reports a WHERE a.request_id = qr.gateway_request_id AND a.revision = p_source_revision)`; returns idempotent no-op when `qr.accepted_source_revision IS NOT NULL AND p_source_revision <= qr.accepted_source_revision`; otherwise **folds ALL unapplied accepted revisions `a.revision` in `(coalesce(qr.accepted_source_revision, -1), p_source_revision]` sequentially in `ORDER BY a.revision ASC`** so out-of-order invocations such as `rev 2` before `rev 1` converge to the exact same state as ascending order; at each folded step `r_step`, enforces strict per-resource authoritative evidence rules: for `usage_cost_micros`, applies `C_cost = ceil(r_step.cost)::numeric(38, 0)` when `r_step.cost IS NOT NULL` (closing `'settled'` iff `r_step.final = true`) and leaves balance/state unchanged when `r_step.cost IS NULL`; for `usage_tokens`, computes cumulative `P_known`, `K_raw`/`rev_K`, and `(R_latest, inc_latest, rev_R)` across accepted revisions `<= r_step.revision`, setting `K_known = K_raw, X_known = R_latest` when `inc_latest IS FALSE` and **`K_known = CASE WHEN rev_R >= rev_K THEN greatest(K_raw, R_latest) ELSE K_raw END, X_known = 0`** when `inc_latest IS TRUE` (protecting included reasoning tokens as a lower bound on completion without double-counting): (1) zero token components on `r_step` -> leave balance/state unchanged; (2) complete authoritative token evidence **`is_complete_tokens(r_step) = true`** (**iff on `r_step` itself, `r_step.prompt_tokens IS NOT NULL AND r_step.completion_tokens IS NOT NULL` AND (`r_step.reasoning_tokens IS NOT NULL` whenever any earlier accepted revision `< r_step.revision` reported `reasoning_tokens IS NOT NULL AND reasoning_included = false`)** — `prompt_tokens` and `completion_tokens` MUST both be explicitly non-null **on `r_step` itself**, never pieced together from separate partial + incomplete-final revisions; e.g., on a `200`-token hold, `rev 0: prompt_tokens = 60, completion_tokens = NULL, final = false` followed by `rev 1: prompt_tokens = NULL, completion_tokens = 25, final = true` has `is_complete_tokens(rev 1) = false` and produces **`85 settled, 115 held, state = 'handoff_committed'`**) -> apply exact `C_tokens = P_known + K_known + X_known`, closing `state = 'settled'` (`held_units = 0`) iff `r_step.final = true`; (3) partial/incomplete token evidence with `>= 1` non-null token component on `r_step` (even when `r_step.final = true`) -> apply monotonic lower bound `C_effective = greatest(settled_units, P_known + K_known + X_known)`, immediately charging confirmed overage while keeping `state = 'handoff_committed'` until complete final evidence arrives (or advancing `settled_units` monotonically if already `'settled'`); **unconditionally advances `qr.accepted_source_revision = p_source_revision` on every processed accepted revision (including `0`-delta / no-op / other-resource revisions)**, writing composite-FK `quota_reconciliations` (referencing BOTH `gateway_usage_reports` and `quota_accepted_gateway_reports`), adjusting `quota_budgets`, and recording `quota_warning_events` iff `(new_state, new_settled, new_held) IS DISTINCT FROM (old_state, old_settled, old_held)`) | None |
| `openmettle.quota_release_device_slot(...)` | None | `EXECUTE` (`device_reservations` `handoff_committed` only; verifies durable V1-18 release/non-allocation record; sets `closed_at`) | None | None |
| `openmettle.quota_record_storage_warning(...)` | `EXECUTE` (evaluates storage threshold crossing from locked `storage_accounts`/`storage_instance` and records deduplicated `quota_warning_events`) | `EXECUTE` (same) | None | None |
| `openmettle.quota_verify_accounting_drift()` (`STABLE`) | None | `EXECUTE` (read-only aggregate, pending-catch-up lag, and hard-mismatch summaries across `storage_*`, `quota_*`, `quota_accepted_gateway_reports`, and Migration `0023`'s `gateway_reservations`/`gateway_requests`/`gateway_usage_reports`/`gateway_settlements` — (1) verifying each `quota_reservations` row (`settled_units`, `held_units`, `state`) strictly against its **applied `qr.accepted_source_revision`** by replaying the **exact same ascending fold across `a.revision <= qr.accepted_source_revision` (`ORDER BY a.revision ASC`)** from `(state = 'handoff_committed', held = qr.reserved_units, settled = 0)` (including `K_known`/`X_known` included reasoning lower bound and requiring `is_complete_tokens(r_step)` to verify `r_step.prompt_tokens IS NOT NULL AND r_step.completion_tokens IS NOT NULL` on `r_step` itself plus `r_step.reasoning_tokens IS NOT NULL` whenever an earlier accepted revision had `reasoning_included = false`, requiring `qr.state = 'settled'` iff **at least one** `final = true` accepted revision `<= qr.accepted_source_revision` established complete authoritative evidence for that resource so subsequent no-op/other-resource revisions advancing `accepted_source_revision` verify with zero false drift, and producing zero hard drift during healthy split-commit catch-up); (2) reporting unapplied accepted revisions via `EXISTS (SELECT 1 FROM openmettle.quota_accepted_gateway_reports a WHERE a.request_id = qr.gateway_request_id AND a.revision > coalesce(qr.accepted_source_revision, -1))` in a distinct **`pending_gateway_reconciliations`** operational lag summary with age (cleared immediately whenever `accepted_source_revision` advances, even on `0`-delta no-op post-final corrections); (3) validating widened `gateway_settlements.measured` (`numeric(38, 0)`) strictly against its **own `gs.revision`** row `r_curr` in `gateway_usage_reports` joined strictly on **`(gs.request_id = r_curr.request_id AND gs.revision = r_curr.revision AND gs.final = r_curr.final)`** reading `r_curr.source` and `r_curr.report_id` from `r_curr` (`gs.measured IS NULL` valid when `r_curr` has no measured token total, e.g., cost-only `rev 2` after token-only `rev 1`) without `bigint` overflow; and (4) once `storage_volume_control.volume_id IS NOT NULL`, failing hard on any `'active'`/`'retained'` revision whose `storage_reservations.payload_ino IS NULL`, while recognizing `staging/.reclaim.<id>` (`st_size == 0`, `st_ino == payload_ino`) paired with `(state = 'reserved' AND NOT adoption_unverified AND reclaim_state IN ('claiming', 'truncated'))` or `(state = 'released' AND NOT adoption_unverified AND reclaim_state = 'anchor_pending_unlink')`, `revisions/.purge.<id>` (`st_size == 0`, `st_ino == payload_ino`) paired with `(state = 'purging' AND NOT sr.adoption_unverified)` or `(state = 'purged' AND purge_stage = 'anchor_pending_unlink' AND NOT sr.adoption_unverified)`, and all valid Stage A `'purging'` crash states (`revisions/<id>` at `size_bytes` or `0`, or `revisions/.purge.<id>` at `0`, all matching `sr.payload_ino`) as valid non-orphan crash-boundary states in the companion filesystem check — without granting raw table `SELECT` on `gateway_usage_reports` or `quota_accepted_gateway_reports`; also callable by `openmettle_owner` during restore validation) | None | None |
| `storage_reservations.lease_expires_at`, `storage_reservations.adoption_unverified`, `storage_reservations.stage_claimed`, `storage_reservations.payload_ino`, `storage_reservations.publish_pending`, `storage_reservations.reclaim_state`, `storage_reservations.reclaim_claim_token`, `storage_reservations.reclaim_lease_until` | `INSERT (lease_expires_at, stage_claimed)`, `UPDATE (lease_expires_at, adoption_unverified, stage_claimed, payload_ino, publish_pending, reclaim_state, reclaim_claim_token, reclaim_lease_until)` (with migration 4 grants; `reserved -> released` guarded by **`SECURITY INVOKER` `enforce_runtime_storage_volume_pinned()`** (`OMQ03`, delegating `PERFORM openmettle.storage_lock_pinned_volume()` to acquire `FOR SHARE` on `storage_volume_control` as `openmettle_owner` without `42501` and failing closed on `NOT FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL` for non-`openmettle_owner` across both `INHERIT` and `NOINHERIT`/`SET ROLE` logins, never taking `FOR SHARE` on `storage_instance`); tightened **`CHECK (NOT adoption_unverified OR state = 'reserved')`** combined with **`SECURITY INVOKER` `enforce_storage_reservation_monotonic_guards()`** (`OMQ03`: owner-only `adoption_unverified` clearance, write-once never-cleared `payload_ino`, and monotonic `stage_claimed`) prevents any non-owner role from ever transitioning an `adoption_unverified = true` `'reserved'` row to `'released'` or `'settled'` while `openmettle_owner` releases cleanly in one `UPDATE`; `storage_reservations_tool_spill_binding_guard` (`23514`) forbids `tool-spill:%` without `run_id` and `operation_id`; `payload_dev` is NOT stored (cross-node NFS `st_dev` varies per mount); `payload_ino numeric(20, 0)` (`CHECK (payload_ino IS NULL OR payload_ino >= 0)`), `stage_claimed` (`CHECK (payload_ino IS NULL OR stage_claimed)`), `publish_pending` (`CHECK (NOT publish_pending OR (state = 'reserved' AND payload_ino IS NOT NULL))`), and 4-state cleaner lease (`reclaim_state IN ('none', 'claiming', 'truncated', 'anchor_pending_unlink')`, `reclaim_claim_token`, `reclaim_lease_until`, indexed by `storage_reservations_reclaim_anchor_idx`); under the unified rollout rule, HTTP `Store::stage`/`Store::publish` succeed when `storage_volume_control.adoption_run_id IS NULL` both pinned (`volume_id IS NOT NULL`, calling `storage_lock_pinned_volume()`) and during rolling upgrade (`volume_id IS NULL`, skipping sentinels while setting `stage_claimed = true` -> creating `staging/<id>` + `fsync(&staging_dir_fd)` -> binding `payload_ino = staged_ino`); `StagedFile::drop` is **100% non-destructive** (NEVER `set_len(0)` or `unlinkat`); `Store::publish` commits `publish_pending = true` before **`rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id, AtFlags::empty())`** (failing `Errno::EXIST` without overwriting `revisions/<id>` AND keeping `staging/<id>` present until `storage::settle` commits so `N-1` API retries hit `OpenOptions::create_new(true)` -> `Err(Error::InProgress)` without replacing `revisions/<id>`), `storage::settle` commits `state = 'settled', publish_pending = false` while **retaining `payload_ino`**, and post-commit best-effort detaches `staging/<id>` (holding `LOCK_SH` or reopening via `OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + immediate `file.metadata()?.file_type().is_file()` + `LOCK_SH`; `unlinkat`, never `set_len(0)`); **`Store::read`** opens `revisions/<reservation>` via **`OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK`**, immediately checks `file.metadata()?.file_type().is_file()` (failing closed with `Err(Error::Missing)` on FIFOs/sockets/devices/directories without blocking), acquires non-blocking **`file.try_lock_shared()`** (`LOCK_SH \| LOCK_NB`, returning `Err(Error::Missing)` on `WouldBlock`), **strictly AFTER acquiring `LOCK_SH`** re-verifies `file.metadata()?` (`is_file()`, local `st_dev`, `st_ino == payload_ino` whenever non-null, `len() == size`) and `statat` namespace identity (allowing `payload_ino IS NULL` legacy rows ONLY while `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL`), seeks to `start`, and **retains that locked `fs::File` inside `Content` for the entire streaming response body lifetime** so `purge_due` Stage A (`LOCK_EX \| LOCK_NB`) gets `WouldBlock` and never truncates an in-flight download; `artifact_fs::abort` requires `storage_volume_control.volume_id IS NOT NULL AND adoption_run_id IS NULL` and executes the unified 4-step reclamation protocol with Linux-NFS-safe **`OFlags::RDWR \| OFlags::NOFOLLOW` (explicitly WITHOUT `OFlags::TRUNC`, preserving zero `set_len(0)` on `'truncated'`/Case 2/Step 4 paths)** on EVERY `LOCK_EX` open, Step 2a fenced DB lease revalidation under `LOCK_EX` before `set_len(0)` (and in Case 2 `payload_ino IS NULL` for a `0`-byte regular `staging/<id>` with `revisions/<id>` and `staging/.reclaim.<id>` `ENOENT`, atomically binding `stage_claimed = true, payload_ino = fd_ino` in Step 2a under `LOCK_EX` and promoting directly into the standard `.reclaim.<id>` -> `'truncated'` -> Step 3 `'anchor_pending_unlink'` -> Step 4 sequence so `payload_ino` stays `NULL` through Step 3 ONLY when all three names are already `ENOENT` with ZERO `unlinkat` calls), unconditional anchor `fsync(&staging_dir_fd)` on both new and recovered `staging/.reclaim.<id>` anchors, and ZERO filesystem I/O inside DB Steps 1 and 3) | `INSERT (lease_expires_at, stage_claimed)`, `UPDATE (lease_expires_at, adoption_unverified, stage_claimed, payload_ino, publish_pending, reclaim_state, reclaim_claim_token, reclaim_lease_until)` (with migration 4 grants; guarded by BOTH **`SECURITY INVOKER` `enforce_runtime_storage_volume_pinned()`** (`OMQ03`, delegating `PERFORM openmettle.storage_lock_pinned_volume()` to acquire `FOR SHARE` on `storage_volume_control` as `openmettle_owner`) AND **`SECURITY INVOKER` `enforce_storage_reservation_monotonic_guards()`** (`OMQ03`, plus `CHECK (NOT adoption_unverified OR state = 'reserved')` blocking non-owner `reserved -> released` on quarantined rows, write-once `payload_ino`, and monotonic `stage_claimed`); `storage_reservations_tool_spill_binding_guard` (`23514`) forbids `tool-spill:%` without `run_id` and `operation_id`; under the unified rollout rule, ADR 0039 worker `publish_bytes` spills (5-step `publish_pending` fence strictly before `linkat`, **carrying `staged_fd` (`LOCK_EX`) from Step 4 into Step 5's single atomic `Fence::Step` `WriteTransaction` committing BOTH `storage::settle` AND `runs::record_observation`**, dropping `LOCK_EX` only AFTER commit + post-commit best-effort `LOCK_SH` (`OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + immediate `is_file()`) detach) and ALL 4 cleaners (`artifact_fs::abort`, `reconcile_expired`, generic run-linked cleaner, ADR 0039 `reconcile_run_spills`) strictly require `storage_volume_control.volume_id IS NOT NULL AND adoption_run_id IS NULL`; all 4 cleaners execute the unified 4-step reclamation protocol using Linux-NFS-safe **`OFlags::RDWR \| OFlags::NOFOLLOW` (explicitly WITHOUT `OFlags::TRUNC`)** on EVERY `LOCK_EX` open — Step 1 serialized DB claim via `storage_lock_pinned_volume()` (`reclaim_state = 'claiming'`, zero FS I/O) -> Step 2 outside-DB probe (`.reclaim.<id>` first)/quarantine or `LOCK_EX` + Step 2a fenced DB revalidation & 300 s lease renewal strictly before `set_len(0) + sync_all()` (and in Case 2 `payload_ino IS NULL` for a `0`-byte regular `staging/<id>` with `revisions/<id>` and `staging/.reclaim.<id>` `ENOENT`, atomically binding `stage_claimed = true, payload_ino = fd_ino` in Step 2a under `LOCK_EX` without `set_len(0)` and promoting directly into the standard `.reclaim.<id>` -> `'truncated'` -> Step 3 `'anchor_pending_unlink'` -> Step 4 sequence so `payload_ino` stays `NULL` through Step 3 ONLY when all three names are already `ENOENT` with ZERO `unlinkat` calls) -> `linkat` anchor `staging/.reclaim.<id>` + unconditional `fsync(&staging_dir_fd)` on both new and recovered anchors -> `unlinkat` `<id>` from `revisions/`/`staging/` + dual `fsync` -> short DB commit `reclaim_state = 'truncated', publish_pending = false` (retaining `payload_ino`! `'truncated'` crash recovery probes ONLY `staging/.reclaim.<id>` via `OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC` and zero `set_len(0)` and never touches `staging/<id>`/`revisions/<id>`) -> Step 3 final `storage::release` with **ZERO filesystem I/O inside DB tx** (`reclaim_state = 'anchor_pending_unlink'` when `payload_ino IS NOT NULL`, retaining `payload_ino`) -> Step 4 post-release **`OFlags::RDWR \| OFlags::NOFOLLOW` (no `OFlags::TRUNC`, zero `set_len(0)`)** + `LOCK_EX` `unlinkat` of `staging/.reclaim.<id>` + `fsync(&staging_dir_fd)` + best-effort `reclaim_state = 'none'` reinforced by bounded DB-driven Step 4 retry over `storage_reservations_reclaim_anchor_idx` with wrapping keyset cursor `reclaim_anchor_cursor` + pass-start fixed upper watermark `(upper_ts, upper_id)` resetting both on `< LIMIT` or reaching `(upper_ts, upper_id)` across all reservation kinds; `StagingSweepState` has **ZERO `set_len(0)` calls in ANY branch** (including `0`-row orphans and `.reclaim.<id>`), uses **`OFlags::RDWR \| OFlags::NOFOLLOW` (explicitly WITHOUT `OFlags::TRUNC`)** + `LOCK_EX`, serializes `0`-row/aged `.reclaim.<id>` via `storage_lock_pinned_volume()` + `storage_instance FOR NO KEY UPDATE`, detaches `'settled'` `staging/<id>` strictly ONLY when `artifact_revisions.state IN ('active', 'retained')` and `revisions/<id>` matches `payload_ino` on disk (no `'purged'` `ENOENT` exception), never touches `staging/<id>` on `'released'` when `payload_ino IS NOT NULL`, and cleans `staging/.reclaim.<id>` anchors; `artifact_fs::purge_due` executes the 3-stage inode-preserving protocol (`revisions/.purge.<id>` + `artifact_revisions.purge_stage` + Stage C immediate and bounded DB pass over `artifact_revisions_purge_anchor_idx` with **`OFlags::RDWR \| OFlags::NOFOLLOW` (no `OFlags::TRUNC`, zero `set_len(0)`)** + `LOCK_EX` and wrapping keyset cursor `purge_anchor_cursor` + pass-start fixed upper watermark `(upper_ts, upper_id)` resetting both on `< LIMIT` or reaching `(upper_ts, upper_id)`); generic run-linked cleaner owns exact complement `run_id IS NOT NULL AND (operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')` while ADR 0039 `reconcile_run_spills` owns `operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%'` with zero gap; **`adoption_unverified = true` is cleared solely by `openmettle_owner` reconciliation or verified `openmettle-admin` adoption**) | None | None |
| `storage_volume_control` | `SELECT` only (dedicated 1-row read-mostly volume-identity singleton separating `(volume_id, bootstrap_auto_pin_allowed, adoption_run_id)` from frequently-updated `storage_instance`; **NO `INSERT`, `UPDATE`, `DELETE`, or `TRUNCATE` granted to any runtime role** — preventing direct pin rewrites outside `openmettle.storage_pin_volume_id(uuid)`; runtime `FOR SHARE` locking runs exclusively via `SECURITY DEFINER` `openmettle.storage_lock_pinned_volume()` and one-time fresh-bootstrap auto-pinning runs exclusively via `SECURITY DEFINER` `openmettle.storage_pin_volume_id(uuid)` (API-only `EXECUTE`) as `openmettle_owner`, eliminating both PostgreSQL 18 `42501` `FOR SHARE` permission errors and `FOR SHARE -> FOR NO KEY UPDATE` deadlocks on `storage_instance`, with `adoption_run_id` writable solely by `openmettle_owner`) | `SELECT` only (**NO `INSERT`, `UPDATE`, `DELETE`, or `TRUNCATE`**, and **NO `EXECUTE` on `openmettle.storage_pin_volume_id(uuid)`**; runtime cleaners/workers acquire `FOR SHARE` on `storage_volume_control` exclusively via `SECURITY DEFINER` `openmettle.storage_lock_pinned_volume()` directly or via `SECURITY INVOKER` `enforce_runtime_storage_volume_pinned()`, never direct invoker `FOR SHARE` or `UPDATE`, and cleanly skip/fail closed on `OMQ03` without `42501` while `volume_id IS NULL`) | None | None |
| `storage_instance`, `storage_accounts`, `artifacts`, `artifact_revisions` | Existing migration 4 grants (`storage_instance` retains only `warn_pct_*`, `config_revision`, and capacity limits — `SELECT` only on `warn_pct_*`/`config_revision`, updated strictly after `storage_accounts` with zero prior `FOR SHARE`; `artifact_revisions` transitions to `'purging'`/`'purged'` guarded by **`SECURITY INVOKER` `enforce_runtime_storage_volume_pinned()`** (`OMQ03`, delegating `PERFORM openmettle.storage_lock_pinned_volume()` as `openmettle_owner` and failing closed on `NOT FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL` across `INHERIT` and `NOINHERIT`/`SET ROLE` logins)) | Existing migration 4 grants PLUS **`UPDATE (purge_stage)` on `openmettle.artifact_revisions`** (for 3-stage `purge_due` Stage B `'anchor_pending_unlink'` and Stage C `'none'` transitions; `storage_instance` retains only `warn_pct_*`, `config_revision`, and capacity limits — `SELECT` only on `warn_pct_*`/`config_revision`, updated strictly after `storage_accounts` with zero prior `FOR SHARE`; `artifact_revisions` transitions to `'purging'`/`'purged'` guarded by **`SECURITY INVOKER` `enforce_runtime_storage_volume_pinned()`** (`OMQ03`, delegating `PERFORM openmettle.storage_lock_pinned_volume()` as `openmettle_owner` and failing closed on `NOT FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL` across `INHERIT` and `NOINHERIT`/`SET ROLE` logins)) | None | None |

Only `openmettle_owner` writes `quota_defaults` (updating the migration-seeded `('instance',
'usage_cost_micros')` row strictly via direct `UPDATE` — never `INSERT ... ON CONFLICT` — subject
to `quota_defaults_cost_denomination_immutable` (`OMQ02`) serialized with `quota_cost_unit_lock`,
and acquiring `SELECT FROM openmettle.run_dispatch_lock FOR NO KEY UPDATE` before modifying
`executing_runs_*` defaults), `quota_enforcement` (flipping `metering_enforced` write-once `false
-> true` via `openmettle-admin` in a standalone single-statement transaction holding zero other
locks, subject to `quota_enforcement_write_once` (`OMQ04`)), `storage_instance` limits, warning
thresholds, and `config_revision`, and `storage_volume_control`'s `bootstrap_auto_pin_allowed` and
`adoption_run_id` (nullable `uuid` set to a unique per-invocation `my_adoption_run_id = uuid_v4()`
in Step 1b under `SELECT volume_id, adoption_run_id INTO STRICT ... FROM
openmettle.storage_volume_control WHERE id FOR UPDATE` — strictly serialized against
`storage_lock_pinned_volume()`'s `FOR SHARE` on `storage_volume_control`, refusing concurrent
adopters with `OMQ03` unless `--replace-adoption-run <stale_uuid>` matches `adoption_run_id`,
cleared on Step 2 failure only `WHERE id AND adoption_run_id = $my_adoption_run_id`, and
atomically cleared to `NULL` in Step 3's commit requiring `adoption_run_id = $my_adoption_run_id`
that evaluates all `'active'`/`'retained'`/`'purging'` revisions, cross-reservation live inode
uniqueness strictly across live payloads, surviving anchors, and all candidates for `payload_ino`
backfill or `adoption_unverified = false` clearance — namely `artifact_revisions` with `state IN
('active', 'retained')`, surviving `state = 'purging'`, or `(state = 'purged' AND purge_stage =
'anchor_pending_unlink')`, AND `storage_reservations` with `(state = 'reserved' AND (payload_ino IS
NOT NULL OR candidate for backfill/un-quarantine — explicitly including previously quarantined
adoption_unverified = true rows present on disk))` OR `(state = 'released' AND reclaim_state =
'anchor_pending_unlink')`, **explicitly EXCLUDING retired historical rows `(state = 'released' AND
reclaim_state = 'none')` and `'settled'` rows whose revision is `(artifact_revisions.state =
'purged' AND purge_stage = 'none')`** (`cross_reservation_inode_alias` /
`intra_reservation_inode_mismatch` / `foreign_staging_collision`), opening every `payload_ino IS
NULL` `'reserved'` backfill candidate with `OFlags::RDWR | OFlags::NOFOLLOW` (without
`OFlags::TRUNC`), acquiring non-blocking `try_lock()` (`LOCK_EX | LOCK_NB` — clearing
`adoption_run_id = NULL` without quarantining or backfilling and returning retryable `OMQ03` on
`WouldBlock`), re-verifying `fstat(fd)` + `statat`, and holding that `LOCK_EX` descriptor through
Phase 3C's backfill commit, legacy `'purging'` Case 6a (requiring exact recorded
`st_size == size_bytes` AND `sha256 == content_digest`, rejecting `st_size == 0` when
`size_bytes > 0` with `size_or_digest_mismatch` and reserving the `st_size == 0` Stage A crash
exception strictly for already-bound `sr.payload_ino IS NOT NULL AND st_ino == sr.payload_ino`) &
Case 6b (all-names-absent owner completion, NEVER counting as positive on-disk file evidence
toward volume-identity verification, with `ambiguous_legacy_purging_staging_survivor` rejection),
intermediate crash states (`'claiming'`+`.reclaim.<id>`, already-`'truncated'`+`.reclaim.<id>`
requiring `staging/<id>` and `revisions/<id>` `ENOENT` or rejecting with
`truncated_visible_name_present`, `'purging'` Stage A, `'purged'`+`anchor_pending_unlink`+`.purge.<id>`),
and volume checks **BEFORE** writing any `payload_ino`, committing `payload_ino` backfills (`WHERE
payload_ino IS NULL`) **strictly ONLY on positively verified non-quarantined rows** (never writing
`payload_ino` onto any row that stays `adoption_unverified = true`), Case 6b legacy `'purging'`
direct completion + `retained_bytes` decrement, and **keeping `reclaim_state = 'claiming'` as
`'claiming'` (never promoting `'claiming'` to `'truncated'`) with `reclaim_lease_until =
clock_timestamp()`** **ONLY in the success branch** while on failed adoption **omitting / rolling
back ALL `payload_ino` backfills** and committing only `adoption_unverified = true` quarantine on
missing `'reserved'` rows when `volume_id IS NOT NULL` and clearing `adoption_run_id = NULL`
before returning `OMQ03`). `storage_volume_control.volume_id` is auto-pinned write-once from
`NULL` solely via API-only `SECURITY DEFINER` `openmettle.storage_pin_volume_id(uuid)` (granted
exclusively to `openmettle_api`; acquiring `storage_volume_control FOR UPDATE` internally as
`openmettle_owner`, whereas `openmettle_worker` never initializes sentinels and never calls it)
strictly when `bootstrap_auto_pin_allowed = true` on a fresh `applied == 0` bootstrap with an
empty storage ledger, or pinned via `openmettle_owner` idempotent verified volume adoption on
every storage-enabled upgrade **only after mandatory pre-migration `N-1` cleaner quiescence and
100% `N-1 -> N` replacement confirm zero `N-1` worker processes remain running**, while
storage-disabled installations with both `ARTIFACTS_DIR` env vars unset and empty storage tables
leave `volume_id IS NULL` and `bootstrap_auto_pin_allowed = false`. `openmettle_issuance` receives
zero quota or storage privileges. No runtime role receives `DELETE`, `TRUNCATE`, DDL or grant
options.

**Rolling-upgrade safety (ADR 0003).** Mixed-version deployments running `N-1` API/worker binaries
against the V1-17 PR2 schema are protected across four fail-closed database and rollout gates:

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
   and bound holds already transitioned to `'settled'` cleanly. Run `device_reservations` holds
   are V1-17 metered quota holds under the same contract: admission, `quota_prepare_turn_round`
   and request binding create or require them only after activation, so the trigger refuses a
   device-slot request without a granted, `'handoff_committed'` run device hold only when
   `v_enforced = true`, while an existing run device hold must carry its grant in both states.
2. **Unconditional `quota_lock_gateway_request_for_settlement` rollout guarantee across all
   `gateway_settlements` writers.** Every `openmettle_gateway` write transaction that inserts or
   updates `openmettle.gateway_settlements` — **both** settlement-only transactions **and**
   combined single-transaction writes (`gateway_settlements` upsert + `quota_settle_gateway_usage`)
   — MUST call `openmettle.quota_lock_gateway_request_for_settlement(p_request_id)` (`SELECT 1 FROM
   openmettle.gateway_requests WHERE id = $1::uuid FOR NO KEY UPDATE`) strictly **before**
   `INSERT`/`UPDATE` on `openmettle.gateway_settlements`, establishing the global acyclic DAG
   `runs -> gateway_reservations -> gateway_requests -> gateway_settlements ->
   quota_accepted_gateway_reports -> quota_reservations -> quota_budgets` with zero lock cycles.
   Because `PR #129` (`V1-06` PR2) introduced only the `0023` schema and admin key client (**zero
   `N-1` runtime `gateway_settlements` writer binary exists on `main`**), every
   `openmettle_gateway` settlement writer ships with `quota_lock_gateway_request_for_settlement`
   from inception; if any environment ever upgrades from a hypothetical un-prelocked settlement
   writer, operators MUST drain all un-prelocked writers before running
   `quota_lock_gateway_request_for_settlement` / combined writers so `gateway_requests ->
   gateway_settlements` and `gateway_settlements -> gateway_requests` lock orders never overlap.
3. **Mandatory pre-migration `N-1` cleaner quiescence, dedicated read-mostly
   `storage_volume_control` (`SELECT`-only for runtime roles + `SECURITY DEFINER`
   `storage_lock_pinned_volume()` / `storage_pin_volume_id(uuid)`), deployment-history auto-pin
   gating, serialized adoption ownership (`adoption_run_id`), write-once inode identity
   (`payload_ino`), DB-enforced monotonic & quarantined-release guards
   (`enforce_storage_reservation_monotonic_guards()` + `CHECK (NOT adoption_unverified OR state =
   'reserved')`), `linkat` no-replace publication & 5-step `publish_bytes` fence, unified 4-step
   cleaner lease (`reclaim_state`, `reclaim_claim_token`, `reclaim_lease_until`,
   `staging/.reclaim.<id>`, Step 2a fenced DB revalidation under `LOCK_EX`, unconditional anchor
   `fsync`, bounded DB-driven Step 4 retry), zero-truncation `StagingSweepState`, 3-stage
   inode-preserving `purge_due` (`revisions/.purge.<id>` + `artifact_revisions.purge_stage`), and
   verified three-directory adoption with cross-reservation inode uniqueness (`OMQ03`).** On
   **every** upgrade (`applied >= 1`, including completely unused installations with empty
   `storage_*` tables), `storage_volume_control.bootstrap_auto_pin_allowed` seeds `false`,
   `storage_volume_control.adoption_run_id` defaults `NULL`, and `storage_volume_control.volume_id`
   **MUST remain `NULL`** across the entire `N-1 -> N` binary replacement so no `N` replica can
   auto-pin the volume while `N-1` workers remain alive. Operators follow the mandatory four-step
   upgrade sequence:
   - **Step 1 (Mandatory — before migration):** Quiesce all `N-1` legacy artifact cleaners by
     unsetting `OPENMETTLE_WORKER_ARTIFACTS_DIR` across all `N-1` worker replicas (rolling restart
     with `OPENMETTLE_WORKER_ARTIFACTS_DIR` unset, or scaling `openmettle-worker` to `0`) and
     confirming zero `N-1` worker processes hold `OPENMETTLE_WORKER_ARTIFACTS_DIR` or have an
     in-flight `worker::maintenance` sweep. Because `N-1` `reconcile_expired` unlinks payload
     paths before calling `storage::release` and an already-`'purging'` revision passes
     `begin_purge` without an `UPDATE` so `N-1` `purge_due` unlinks the file before `confirm_purge`
     fires `OMQ03`, **`SECURITY INVOKER` `enforce_runtime_storage_volume_pinned()` (`OMQ03`,
     evaluating `NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')` as invoker
     and delegating `PERFORM openmettle.storage_lock_pinned_volume()` to acquire `FOR SHARE` on
     `openmettle.storage_volume_control` as `openmettle_owner` without `42501` and fail closed on
     `NOT FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL`, never locking `storage_instance FOR
     SHARE`) covers EVERY non-`openmettle_owner` role across both `INHERIT` and `NOINHERIT` / `SET
     ROLE` logins (`openmettle_worker` AND `openmettle_api`)**: it blocks `N-1` `openmettle_api`'s
     unconditional `abort()` (`src/artifact_fs.rs:584-591`, leaving the `'reserved'` row intact
     for post-adoption `N` `reconcile_expired` while normal `N-1` and `N` `reserve` + `settle`
     uploads continue succeeding!) and acts as a **PostgreSQL ledger defense-in-depth backstop**
     for `openmettle_worker` — **NOT** a substitute for pre-migration `N-1` worker cleaner
     quiescence.
   - **Step 2:** Run `openmettle-migrate` (`storage_volume_control.volume_id IS NULL`,
     `bootstrap_auto_pin_allowed = false`, `adoption_run_id IS NULL`, `metering_enforced = false`).
   - **Step 3:** Roll 100% of `openmettle-api` and `openmettle-worker` replicas from `N-1` to `N`
     and confirm zero `N-1` replicas remain. Under the **unified rollout rule** (synchronized
     verbatim with ADR 0039), HTTP `Store::stage` and `Store::publish` (`openmettle_api`) succeed
     when `storage_volume_control.adoption_run_id IS NULL` both when `volume_id IS NOT NULL`
     (calling `SELECT openmettle.storage_lock_pinned_volume()` and verifying role-tagged sentinels)
     and during mixed-version rolling upgrade while `volume_id IS NULL` (using a plain non-locking
     `SELECT` check and skipping sentinel reads while still setting `stage_claimed = true` and
     binding `payload_ino = staged_ino`), whereas ADR 0039 worker `publish_bytes` spills and all 4
     cleaners strictly require `storage_volume_control.volume_id IS NOT NULL AND adoption_run_id IS
     NULL` (via `storage_lock_pinned_volume()`, so `N` workers may already have
     `OPENMETTLE_WORKER_ARTIFACTS_DIR` configured during rollout — never initializing sentinels and
     never calling API-only `storage_pin_volume_id(uuid)` — while observing `OMQ03` / unpinned
     state cleanly without `42501` until Step 4 pins `volume_id`). All `N` `artifact_fs::Store`
     writers and readers execute strictly relative to verified `Arc`-shared `root_fd`,
     `staging_dir_fd`, and `revisions_dir_fd` (verifying local same-mount `st_dev` equality without
     persisting `payload_dev`): `Store::stage` executes Step 1a (commit `stage_claimed = true`
     under `(runs FOR NO KEY UPDATE ->) storage_reservations FOR UPDATE` +
     `storage_lock_pinned_volume()` when pinned BEFORE touching disk), Step 1b (`openat`
     `OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW` + `LOCK_SH` + verify
     `S_ISREG` & local `st_dev` + **`fsync(&staging_dir_fd)`** BEFORE binding `payload_ino`), and
     Step 1c (commit `payload_ino = staged_ino` under `FOR UPDATE` + `storage_lock_pinned_volume()`
     when pinned). **`StagedFile::drop` and all writer error/cancellation paths are 100%
     non-destructive** — they NEVER call `set_len(0)` and NEVER call `unlinkat`, only closing the
     FD (releasing `LOCK_SH`/`LOCK_EX`) so lost Step 1c acks reclaim cleanly with zero false
     quarantine and lost `storage::settle` acks never zero published `revisions/<id>`.
     `Store::publish` (and ADR 0039's 5-step `publish_bytes` fence: Step 1 `0`-byte create +
     `LOCK_EX` + `fsync` + bind `payload_ino` with `publish_pending = false` -> Step 2 write +
     verify size & SHA-256 + `sync_all()` under `LOCK_EX` -> Step 3 fenced `storage_lock_pinned_volume()`
     + `SET publish_pending = true` under `LOCK_EX` strictly before `linkat` -> Step 4 `linkat` +
     `fsync(&revisions_dir_fd)` + post-`linkat` re-verify **without dropping `LOCK_EX`** -> Step 5
     carrying `staged_fd` (`LOCK_EX`) through a single atomic `Fence::Step` `WriteTransaction`
     committing BOTH `storage::settle` AND `runs::record_observation`, dropping `staged_fd`
     (`LOCK_EX`) only AFTER commit, then post-commit best-effort `LOCK_SH` (`OFlags::RDONLY |
     OFlags::NOFOLLOW | OFlags::NONBLOCK` + immediate `file.metadata()?.file_type().is_file()`
     check) `unlinkat(&staging_dir_fd, id)` without `set_len(0)` + `fsync(&staging_dir_fd)`)
     commits `publish_pending = true` under `FOR UPDATE`, publishes exclusively via
     **`rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id, AtFlags::empty())`** +
     `fsync(&revisions_dir_fd)` + post-`linkat` re-verify — which atomically fails `Errno::EXIST`
     without overwriting foreign `revisions/<id>` (quarantining to `adoption_unverified = true,
     publish_pending = false`) **AND keeps `staging/<id>` present on disk until `storage::settle`
     commits `state = 'settled'`** so even if an `N` writer crashes post-`linkat` before
     `storage::settle` commits, any same-key retry routed to an `N-1` API replica hits
     `store.stage(&id)` -> `OpenOptions::create_new(true)` -> `AlreadyExists` ->
     **`Err(Error::InProgress)` (`src/artifact_fs.rs:474-475`)** without calling `abort()`, without
     staging a replacement, and without calling replacing `fs::rename`! Then `storage::settle`
     commits `state = 'settled', publish_pending = false` while **retaining `payload_ino`**,
     followed by post-commit best-effort detach of the `staging/<id>` alias while still holding
     `LOCK_SH` (or reopening via `OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK` + immediate
     `file.metadata()?.file_type().is_file()` + `LOCK_SH`; `unlinkat(&staging_dir_fd, id,
     AtFlags::empty())`, **NEVER `set_len(0)`** -> `drop` -> `fsync(&staging_dir_fd)`).
     **`Store::read`** verifies `NOT sr.adoption_unverified`, re-verifies `<root>`/`"revisions"`
     FDs + sentinels (when pinned), opens `revisions/<reservation>` via `openat(&revisions_dir_fd,
     reservation, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK, Mode::empty())`,
     immediately checks `file.metadata()?.file_type().is_file()` (failing closed with
     `Err(Error::Missing)` on FIFOs/sockets/devices/directories without blocking), acquires
     non-blocking **`file.try_lock_shared()`** (`LOCK_SH | LOCK_NB`, returning
     `Err(Error::Missing)` on `WouldBlock`), **strictly AFTER acquiring `LOCK_SH`** re-verifies
     `file.metadata()?` (`is_file()`, `st_dev == store.root_dev`, `st_ino == sr.payload_ino`
     whenever non-null, `len() == size`) and `statat(&revisions_dir_fd, reservation,
     AtFlags::SYMLINK_NOFOLLOW)` namespace identity — permitting legacy `sr.payload_ino IS NULL`
     rows **ONLY** while `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL`
     (failing closed with `Error::Io` once `volume_id IS NOT NULL`) — seeks to `start`, and
     **retains that locked `fs::File` inside `Content` for the entire streaming response body
     lifetime** so `purge_due` Stage A (`LOCK_EX | LOCK_NB`) receives `WouldBlock` and never
     truncates an in-flight download. Startup / adoption / shared-volume qualification probes and
     requires `O_CREAT | O_EXCL | O_NOFOLLOW`, `rustix::fs::linkat(..., AtFlags::empty())`
     (rejecting `ENOSYS`/`EOPNOTSUPP`/`EINVAL` and verifying `Errno::EXIST` without overwriting and
     shared `st_ino` between both names), file + directory `fsync`, AND for `ReadWriteMany` shared
     volumes **both** two-client / separate-mount Linux NFS `flock(2)` coherence (specifically
     `LOCK_SH` on `OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK` vs `LOCK_EX | LOCK_NB`
     `WouldBlock` on `OFlags::RDWR | OFlags::NOFOLLOW` without `OFlags::TRUNC` across `'truncated'`
     reopen, Step 4, Stage C, and `StagingSweepState`) **and** stable 64-bit `st_ino` coherence +
     second-client recovery across clients and remounts!
   - **Step 4:** **Only after zero `N-1` workers remain**:
     - On **storage-disabled installations** (both `OPENMETTLE_API_ARTIFACTS_DIR` /
       `OPENMETTLE_ARTIFACTS_DIR` and `OPENMETTLE_WORKER_ARTIFACTS_DIR` unset per ADR 0031 AND `0`
       rows in both `storage_reservations` and `artifact_revisions`), skip volume adoption —
       leaving `storage_volume_control.volume_id IS NULL`, `bootstrap_auto_pin_allowed = false`,
       `adoption_run_id IS NULL`, and all storage cleaners disabled — and proceed directly to
       `quota_release_orphan_gateway_requests` and flipping `quota_enforcement.metering_enforced =
       true`. If artifact storage is provisioned later, run `openmettle-admin` verified volume
       adoption before enabling `OPENMETTLE_WORKER_ARTIFACTS_DIR`.
     - On **storage-enabled installations** (any `ARTIFACTS_DIR` configured or any row in
       `storage_reservations` / `artifact_revisions`), operators run `openmettle-admin` verified
       volume adoption: mint `my_adoption_run_id = uuid_v4()`; **Step 1b** acquires ONLY `SELECT
       volume_id, adoption_run_id INTO STRICT ... FROM openmettle.storage_volume_control WHERE id
       FOR UPDATE` (strictly serialized against `storage_lock_pinned_volume()`'s `FOR SHARE` on
       `storage_volume_control`, refusing any concurrent adopter with `OMQ03` unless
       `--replace-adoption-run <stale_uuid>` matches `adoption_run_id`) and commits `SET
       adoption_run_id = $my_adoption_run_id`; **Step 2** scans `<root>/revisions` and
       `<root>/staging` outside DB locks (clearing `adoption_run_id = NULL` on Step 2 failure ONLY
       `WHERE id AND adoption_run_id = $my_adoption_run_id` under `FOR UPDATE`, requiring both
       `--expected-fs-uuid <fs_uuid>` AND `--expected-revisions-inode <dev>:<ino>` whenever a
       non-empty ledger has zero positive SHA-256-verified on-disk revisions — noting Case 6b
       absent legacy `'purging'` rows NEVER count as positive on-disk file evidence — or
       `--confirm-no-on-disk-payloads` when zero on-disk payloads exist, and linking cleanly
       without those flags on an empty ledger); **Step 3** locks `storage_reservations (ORDER BY id
       ASC FOR UPDATE) -> artifact_revisions (ORDER BY id ASC FOR UPDATE) -> storage_volume_control
       (WHERE id FOR UPDATE) -> storage_accounts (ORDER BY scope_id ASC FOR UPDATE) ->
       storage_instance (WHERE id FOR UPDATE)`, **requires `adoption_run_id =
       $my_adoption_run_id`** (aborting `OMQ03` if displaced), executes Phase 3A read-only
       verification evaluating ALL `'active'`/`'retained'`/`'purging'` revisions (including legacy
       `sr.payload_ino IS NULL` `'purging'` Case 6a requiring **exact recorded `st_size ==
       size_bytes` AND `sha256 == content_digest`** — rejecting `st_size == 0` when `size_bytes >
       0` with `size_or_digest_mismatch` and reserving the `st_size == 0` Stage A crash exception
       strictly for already-bound `sr.payload_ino IS NOT NULL AND st_ino == sr.payload_ino` — &
       Case 6b all-names-absent owner completion which NEVER counts as positive on-disk file
       evidence, plus `ambiguous_legacy_purging_staging_survivor` rejection), cross-reservation
       live inode uniqueness strictly across live payloads, surviving anchors, and all candidates
       for `payload_ino` backfill or `adoption_unverified = false` clearance — namely
       `artifact_revisions` with `state IN ('active', 'retained')`, surviving `state = 'purging'`,
       or `(state = 'purged' AND purge_stage = 'anchor_pending_unlink')`, AND
       `storage_reservations` with `(state = 'reserved' AND (payload_ino IS NOT NULL OR candidate
       for backfill/un-quarantine — explicitly including previously quarantined
       adoption_unverified = true rows present on disk))` OR `(state = 'released' AND
       reclaim_state = 'anchor_pending_unlink')`, **explicitly EXCLUDING retired historical rows
       `(state = 'released' AND reclaim_state = 'none')` and `'settled'` rows whose revision is
       `(artifact_revisions.state = 'purged' AND purge_stage = 'none')`**
       (`cross_reservation_inode_alias` / `intra_reservation_inode_mismatch` /
       `foreign_staging_collision`), opening every `payload_ino IS NULL` `'reserved'` backfill
       candidate with `OFlags::RDWR | OFlags::NOFOLLOW` (without `OFlags::TRUNC`), acquiring
       non-blocking `try_lock()` (`LOCK_EX | LOCK_NB` — clearing `adoption_run_id = NULL` without
       quarantining or backfilling and returning retryable `OMQ03` on `WouldBlock`), re-verifying
       `fstat(fd)` + `statat`, and holding that `LOCK_EX` descriptor through Phase 3C's backfill
       commit, intermediate crash states (`'claiming'`+`.reclaim.<id>`,
       already-`'truncated'`+`.reclaim.<id>` requiring `staging/<id>` and `revisions/<id>` `ENOENT`
       or rejecting with `truncated_visible_name_present`, `'purging'` Stage A,
       `'purged'`+`anchor_pending_unlink`+`.purge.<id>`), and volume checks **BEFORE** writing any
       `payload_ino`: on **failure** (Phase 3B), omits / rolls back ALL `payload_ino` backfills
       (committing only `adoption_unverified = true` quarantine on missing `'reserved'` rows when
       `volume_id IS NOT NULL` and clearing `adoption_run_id = NULL WHERE id AND adoption_run_id =
       $my_adoption_run_id` before returning `OMQ03` so retrying on the real directory tree
       succeeds cleanly with true inodes); on **success** (Phase 3C), quarantines/un-quarantines
       `'reserved'` rows first and commits `payload_ino` backfills (`WHERE payload_ino IS NULL`)
       **strictly ONLY on positively verified non-quarantined rows** (never writing `payload_ino`
       onto any row that stays `adoption_unverified = true`), completes Case 6b already-absent
       legacy `'purging'` rows (`state = 'purged', purge_stage = 'none'` + `retained_bytes`
       decrement), **keeps `reclaim_state = 'claiming'` as `'claiming'` (NEVER promoting
       `'claiming'` to `'truncated'`) with `reclaim_lease_until = clock_timestamp()`** (backfilling
       `payload_ino` if `NULL` on verified non-quarantined rows so Step 2 repeats its directory
       syncs and detaches any surviving `staging/<id>`/`revisions/<id>`), and **positively verifies
       and PRESERVES already-`'truncated'` holds whose `staging/.reclaim.<id>` exists as `S_ISREG`
       with `st_ino == payload_ino`, `st_size == 0`, and `staging/<id>`/`revisions/<id>` `ENOENT`**
       (expiring `reclaim_lease_until = clock_timestamp()` so the next cleaner tick finishes Step 3
       -> Step 4 cleanly instead of quarantining!), ensures non-owner roles can never transition
       quarantined `'reserved'` rows (`adoption_unverified = true`) to `'released'` or `'settled'`
       under tightened `CHECK (NOT adoption_unverified OR state = 'reserved')` +
       `enforce_storage_reservation_monotonic_guards()`, pins `storage_volume_control.volume_id`
       (after publishing role-tagged sentinels with `fsync(root_fd)` strictly before
       `:revisions`/`:staging`), and atomically clears `adoption_run_id = NULL`. Pinning enables
       all PR2 (`N`) worker cleaners (`artifact_fs::purge_due` executing the 3-stage
       inode-preserving protocol keeping `revisions/.purge.<id>` linked until after `confirm_purge`
       sets `purge_stage = 'anchor_pending_unlink'`, plus Stage C immediate and bounded DB-driven
       detach over `artifact_revisions_purge_anchor_idx` using Linux-NFS-safe `OFlags::RDWR |
       OFlags::NOFOLLOW` without `OFlags::TRUNC`, zero `set_len(0)`, and wrapping keyset cursor
       `purge_anchor_cursor` + pass-start fixed upper watermark `(upper_ts, upper_id)` resetting
       both on `< LIMIT` or reaching `(upper_ts, upper_id)`, `reconcile_expired`, generic
       run-linked recovery owning exact logical complement `run_id IS NOT NULL AND (operation_id IS
       NULL OR idempotency_key NOT LIKE 'tool-spill:%')`, ADR 0039 `reconcile_run_spills` owning
       `operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%'`, and zero-truncation
       3-bucket `StagingSweepState`), all executing the unified **4-step reclamation protocol**
       with **ZERO filesystem I/O inside DB Steps 1 and 3** and Linux-NFS-safe **`OFlags::RDWR |
       OFlags::NOFOLLOW` (explicitly WITHOUT `OFlags::TRUNC`)** on EVERY `LOCK_EX` open
       (`reclaim_state = 'claiming'` -> Step 2a fenced DB revalidation & 300 s lease renewal under
       `LOCK_EX` strictly before `set_len(0) + sync_all()` — and in Case 2 `payload_ino IS NULL`,
       opening a `0`-byte regular `staging/<id>` with `revisions/<id>` and `staging/.reclaim.<id>`
       `ENOENT` via `OFlags::RDWR | OFlags::NOFOLLOW` without `OFlags::TRUNC` and zero `set_len(0)`,
       acquiring `LOCK_EX`, atomically binding `stage_claimed = true, payload_ino = fd_ino` in Step
       2a while asserting `payload_ino IS NULL`, `'reserved'`, matching token, and pinned volume,
       and promoting directly into `.reclaim.<id>` -> `fsync(&staging_dir_fd)` -> `unlinkat` `<id>`
       -> dual `fsync` -> `'truncated'` -> Step 3 `'anchor_pending_unlink'` -> Step 4 so
       `payload_ino` stays `NULL` through Step 3 ONLY when `staging/<id>`, `staging/.reclaim.<id>`,
       and `revisions/<id>` are ALL already `ENOENT` with ZERO `unlinkat` calls -> `linkat` anchor
       `staging/.reclaim.<id>` + unconditional `fsync(&staging_dir_fd)` on both new and recovered
       anchors -> `unlinkat` `<id>` from `revisions/`/`staging/` + dual `fsync` -> `'truncated'`
       retaining `payload_ino` (`'truncated'` crash recovery probes ONLY `staging/.reclaim.<id>`
       via `OFlags::RDWR | OFlags::NOFOLLOW` without `OFlags::TRUNC`, zero `set_len(0)`, and never
       touches `staging/<id>`/`revisions/<id>`) -> Step 3 `storage::release` setting `reclaim_state
       = 'anchor_pending_unlink'` when `payload_ino IS NOT NULL` and retaining `payload_ino` ->
       Step 4 post-release **`OFlags::RDWR | OFlags::NOFOLLOW` (no `OFlags::TRUNC`, zero
       `set_len(0)`)** + `LOCK_EX` `unlinkat` of `staging/.reclaim.<id>` + `fsync(&staging_dir_fd)`
       + best-effort `reclaim_state = 'none'` reinforced by the bounded DB-driven Step 4 pass over
       `storage_reservations_reclaim_anchor_idx` with wrapping keyset cursor
       `reclaim_anchor_cursor` + pass-start fixed upper watermark `(upper_ts, upper_id)` resetting
       both on `< LIMIT` or reaching `(upper_ts, upper_id)`) and `StagingSweepState`'s
       zero-truncation **`OFlags::RDWR | OFlags::NOFOLLOW` (no `OFlags::TRUNC`)** + `LOCK_EX` rules
       (ZERO `set_len(0)` in ANY branch, no `'purged'` `ENOENT` exception for `'settled'`
       `staging/<id>`); then run the gateway orphan sweep and flip `metering_enforced = true`.
   - **Starting, rolling back to, or resuming any `N-1` worker binary after
     `storage_volume_control.volume_id` is pinned is strictly forbidden by the rollout contract**,
     because `N-1` lacks Rust `.openmettle-volume-id` / local `st_dev` / `payload_ino` /
     `stage_claimed` / `publish_pending` / `reclaim_state` / `purge_stage` / `adoption_run_id` /
     `linkat` checks and unlinks files before mutating PostgreSQL.
4. **Lowered `storage_bytes` overrides (`enforce_storage_override()`, `OMQ01`).** Older API and
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
   (leaving it `NULL`), `storage_reservations.adoption_unverified` (defaulting `false`),
   `storage_reservations.stage_claimed` (defaulting `false`), `storage_reservations.payload_ino`
   (leaving it `NULL`, backfilled on adoption Step 3 success for verified on-disk payloads),
   `storage_reservations.publish_pending` (defaulting `false`), `storage_reservations.reclaim_state`
   (defaulting `'none'`, with `reclaim_claim_token` and `reclaim_lease_until` `NULL`),
   `artifact_revisions.purge_stage` (defaulting `'none'`), and `storage_volume_control` (`volume_id
   IS NULL`, `adoption_run_id IS NULL`).


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
  summaries. When neither `quota_overrides` nor `quota_defaults` is configured for
  `executing_runs_per_scope` or `executing_runs_per_actor`, the API reports `limit: null` and
  `limit_source: "worker"` to reflect that executing-run concurrency is governed by worker-local
  claim settings.
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
| PR2 · schema, store and worker recovery | Additive PostgreSQL 18 migration (after Migration `0023`, zero edits to frozen `0023`), including `ALTER TABLE openmettle.gateway_settlements ALTER COLUMN measured TYPE numeric(38, 0)` (preserving `CHECK (measured >= 0)` and nullable `measured = NULL` for cost-only reports so 3-column token sums up to `3 * (2^63 - 1)` never overflow `bigint`), append-only `openmettle.quota_accepted_gateway_reports` ledger (owned by `openmettle_owner`, zero direct DML or `SELECT` grants to runtime roles, populated automatically by `SECURITY DEFINER` `AFTER INSERT OR UPDATE OF revision, final` trigger `quota_record_accepted_gateway_settlement` on `openmettle.gateway_settlements`, with historical backfill and composite FK `(gateway_request_id, source_revision) REFERENCES openmettle.quota_accepted_gateway_reports (request_id, revision)` on `openmettle.quota_reconciliations`), `rustix` minimal safe POSIX `dirfd` dependency (`default-features = false, features = ["fs", "std"]`, `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT`; `Cargo.lock` distribution-blocker count updated per ADR 0007/0010 so all `openat`/`fstat`/`statat`/`linkat`/`unlinkat`/`fsync` calls using verified `rustix 1.1.6` `OFlags::CREATE` / `OFlags::RDONLY` / `OFlags::RDWR` / `OFlags::EXCL` / `OFlags::DIRECTORY` / `OFlags::NOFOLLOW` / `OFlags::NONBLOCK`, `AtFlags::SYMLINK_NOFOLLOW`, `AtFlags::empty()`, and `Mode::RUSR \| Mode::WUSR` compile safely under `Cargo.toml`'s `unsafe_code = "forbid"` on Rust 1.100), `src/migrate.rs` (`migrate_within_boundaries` capturing `applied = coalesce(max(version), 0)` once under SQLx's advisory lock and setting `openmettle.bootstrap_from_zero` via `pg_catalog.set_config` after each `RESET ALL` before every `migrator.run_to(version, ...)`), dedicated 1-row read-mostly volume-identity singleton **`openmettle.storage_volume_control (id boolean PRIMARY KEY DEFAULT true CHECK (id), volume_id uuid, bootstrap_auto_pin_allowed boolean NOT NULL DEFAULT false, adoption_run_id uuid, CONSTRAINT storage_volume_control_auto_pin_check CHECK (volume_id IS NULL OR NOT bootstrap_auto_pin_allowed))`** (`GRANT SELECT` ONLY to `openmettle_api, openmettle_worker` — zero `INSERT`/`UPDATE`/`DELETE`/`TRUNCATE` grants to any runtime role; seeded `bootstrap_auto_pin_allowed = true` iff `is_fresh_bootstrap` — requiring both `openmettle.bootstrap_from_zero = 'true'` and empty core/storage/gateway tables — and `false` on every upgrade `applied >= 1`; keeping only `warn_pct_1`, `warn_pct_2`, `config_revision` on `openmettle.storage_instance` so runtime `reserve`/`settle`/`release`/`purge` ONLY ever acquire `FOR SHARE` on `storage_volume_control` via `SECURITY DEFINER` `openmettle.storage_lock_pinned_volume()` and NEVER `UPDATE` it, eliminating `FOR SHARE -> FOR NO KEY UPDATE` deadlocks on `storage_instance`), `storage_reservations.adoption_unverified` (`boolean NOT NULL DEFAULT false` with tightened **`CHECK (NOT adoption_unverified OR state = 'reserved')`**, combined with `SECURITY INVOKER` `enforce_storage_reservation_monotonic_guards()` (`OMQ03`) preventing any non-owner role from ever transitioning a quarantined `'reserved'` row to `'released'` or `'settled'` while `openmettle_owner` releases cleanly in one `UPDATE` setting `state = 'released', adoption_unverified = false`), **`storage_reservations.stage_claimed boolean NOT NULL DEFAULT false`** (`CHECK (payload_ino IS NULL OR stage_claimed)`), **`storage_reservations.payload_ino numeric(20, 0)`** (`CHECK (payload_ino IS NULL OR payload_ino >= 0)`, exact unsigned 64-bit `u64` `MetadataExt::ino()`, dropping cross-node-unsafe NFS `payload_dev` completely and verifying same-mount `file_meta.dev() == dir_fd_meta.dev() == root_fd_meta.dev()` locally per host), `storage_reservations.publish_pending` (`boolean NOT NULL DEFAULT false CHECK (NOT publish_pending OR (state = 'reserved' AND payload_ino IS NOT NULL))`), the unified **4-state** cleaner lease on `openmettle.storage_reservations` (**`reclaim_state text NOT NULL DEFAULT 'none' CHECK (reclaim_state IN ('none', 'claiming', 'truncated', 'anchor_pending_unlink'))`**, **`reclaim_claim_token uuid`**, **`reclaim_lease_until timestamptz`**, with `CHECK ((state = 'reserved' AND reclaim_state IN ('none', 'claiming', 'truncated')) OR (state = 'released' AND reclaim_state IN ('none', 'anchor_pending_unlink')) OR (state = 'settled' AND reclaim_state = 'none'))`, `CHECK ((reclaim_state IN ('claiming', 'truncated') AND reclaim_claim_token IS NOT NULL AND reclaim_lease_until IS NOT NULL) OR (reclaim_state IN ('none', 'anchor_pending_unlink') AND reclaim_claim_token IS NULL AND reclaim_lease_until IS NULL))`, and `CHECK (reclaim_state NOT IN ('truncated', 'anchor_pending_unlink') OR NOT publish_pending)`), narrow runtime grants `GRANT INSERT (lease_expires_at, stage_claimed)` and `GRANT UPDATE (lease_expires_at, adoption_unverified, stage_claimed, payload_ino, publish_pending, reclaim_state, reclaim_claim_token, reclaim_lease_until)` on `openmettle.storage_reservations` to `openmettle_api, openmettle_worker`, 100% `IMMUTABLE` PostgreSQL 18 plain-column partial B-tree indexes for two-step raw-index-key stale-hold paging (`quota_reservations_held_expiry_idx`, `storage_reservations_run_expiry_idx` and `storage_reservations_run_legacy_expiry_idx` both narrowed to `(operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')` — exact logical complement of ADR 0039 `reconcile_run_spills` — `storage_reservations_upload_expiry_idx`, `storage_reservations_upload_legacy_expiry_idx`, `storage_reservations_reclaim_anchor_idx`), `openmettle.artifact_revisions.purge_stage` (`text NOT NULL DEFAULT 'none'`, `CHECK (purge_stage IN ('none', 'anchor_pending_unlink') AND (purge_stage = 'none' OR state = 'purged'))`, partial index `artifact_revisions_purge_anchor_idx`, and narrow `GRANT UPDATE (purge_stage) ON openmettle.artifact_revisions TO openmettle_worker`), `BEFORE INSERT OR UPDATE OF idempotency_key, run_id, operation_id` trigger `storage_reservations_tool_spill_binding_guard` (`23514`, rejecting `idempotency_key LIKE 'tool-spill:%' AND (run_id IS NULL OR operation_id IS NULL)`), strengthened `quota_reservations` state `CHECK` constraints prohibiting `settled_units > 0` or `accepted_source_revision IS NOT NULL` while `state = 'held'` or unaccepted `handoff_committed`, exact `numeric(38, 0)` aggregate and settlement accumulators (`quota_budgets.active_used`, `quota_budgets.reserved_held`, `quota_reservations.settled_units`, `quota_reconciliations.cumulative_units`, `delta_active`, `delta_reserved`, mapped in Rust via `sqlx` `::text` <-> `u128`/`i128` canonical base-10 strings with zero new crates), `quota_enforcement` singleton control table (`metering_enforced`, write-once `false -> true`, seeded `true` iff `is_fresh_bootstrap` and `false` on every upgrade `applied >= 1`), `quota_gateway_handoffs` handoff-time obligation ledger (`gateway_request_id` PK referencing `gateway_requests(id) ON DELETE CASCADE`, `metering_enforced`, `cost_required`, `committed_at`, zero direct DML grants to runtime roles), `quota_reservations.allocating_claim_token` (`CHECK (parent_reservation_id IS NULL OR allocating_claim_token IS NOT NULL)`), seeded strictly-`UPDATE`-only `('instance', 'usage_cost_micros')` default row and `quota_cost_unit_lock`, scope-pinned composite FK `(scope_id, gateway_request_id) REFERENCES openmettle.gateway_requests (scope_id, id)`, `SECURITY DEFINER` transition, bootstrap, override, recovery and drift functions (`storage_lock_pinned_volume` — executing `SELECT volume_id, adoption_run_id ... FOR SHARE` as `openmettle_owner` without PostgreSQL 18 `42501` and raising `OMQ03` on missing row, `volume_id IS NULL`, or `adoption_run_id IS NOT NULL`, `EXECUTE` to `openmettle_api, openmettle_worker` — `storage_pin_volume_id` (`EXECUTE` granted **solely to `openmettle_api`**; acquiring `SELECT ... FROM openmettle.storage_volume_control WHERE id FOR UPDATE` internally as `openmettle_owner`, while `openmettle_worker` never initializes sentinels and never calls it), `quota_upsert_scope_override`, `quota_revoke_scope_override`, `quota_reserve` and `quota_allocate_round` enforcing exact `usage_tokens` hold equality `reserved_units = q.units` / `slice_units = q.units` (`23514`), `quota_ensure_legacy_run_holds` — running strictly before `authz::gateway::reserve_in` in the round-allocation `WriteTransaction` while locking `gateway_reservations FOR NO KEY UPDATE` and reading `units - allocated` — `quota_commit_handoff`, `quota_recover_lost_handoff`, `quota_commit_device_handoff`, `quota_renew_lease`, `quota_release_unsent`, `quota_unwind_superseded_round`, `quota_release_orphan_gateway_requests`, `quota_lock_gateway_request_for_settlement(uuid)` (`EXECUTE` to `openmettle_gateway` only, called unconditionally strictly BEFORE **every** `openmettle_gateway` `INSERT`/`UPDATE` on `openmettle.gateway_settlements` — both settlement-only transactions and combined single-transaction writes — to guarantee the globally acyclic lock DAG `runs -> gateway_reservations -> gateway_requests -> gateway_settlements -> quota_accepted_gateway_reports -> quota_reservations -> quota_budgets`), `quota_settle_gateway_usage` operating strictly on `state IN ('handoff_committed', 'settled')` holds without locking `runs` or `gateway_reservations` (`gateway_requests FOR KEY SHARE -> quota_reservations (ORDER BY resource ASC FOR UPDATE) -> quota_budgets FOR NO KEY UPDATE`), verifying exact `EXISTS` acceptance membership in `quota_accepted_gateway_reports`, **folding all unapplied accepted revisions `a.revision` in `(coalesce(qr.accepted_source_revision, -1), p_source_revision]` sequentially in `ORDER BY a.revision ASC`** (making settlement order-independent across out-of-order invocations such as `rev 2` before `rev 1`, with worker catch-up also iterating in `ORDER BY a.revision ASC`), enforcing per-resource authoritative evidence rules for `usage_cost_micros` (`r_step.cost IS NOT NULL`, `C_cost = ceil(r_step.cost)::numeric(38, 0)`) and `usage_tokens` (computing cumulative `P_known`, `K_raw`/`rev_K`, and `(R_latest, inc_latest, rev_R)` across accepted revisions `<= r_step.revision`, setting `K_known = K_raw, X_known = R_latest` when `inc_latest IS FALSE` and **`K_known = CASE WHEN rev_R >= rev_K THEN greatest(K_raw, R_latest) ELSE K_raw END, X_known = 0`** when `inc_latest IS TRUE` so included reasoning tokens act as a lower bound on completion without double-counting, while **`is_complete_tokens(r_step)` is `true` iff on `r_step` itself, `r_step.prompt_tokens IS NOT NULL AND r_step.completion_tokens IS NOT NULL` AND (`r_step.reasoning_tokens IS NOT NULL` whenever any earlier accepted revision `< r_step.revision` reported `reasoning_tokens IS NOT NULL AND reasoning_included = false`)** — never pieced together from separate partial + incomplete-final revisions), and **unconditionally advancing `qr.accepted_source_revision = p_source_revision`** on every processed accepted revision including `0`-delta / no-op / other-resource revisions while writing `quota_reconciliations` and adjusting `quota_budgets` iff `(new_state, new_settled, new_held) IS DISTINCT FROM (old_state, old_settled, old_held)`, `quota_release_device_slot`, `quota_record_storage_warning`, `quota_verify_accounting_drift` replaying the exact same ascending fold across `a.revision <= qr.accepted_source_revision` (`ORDER BY a.revision ASC`, including `K_known`/`X_known` included reasoning lower bound, requiring `qr.state = 'settled'` iff at least one `final = true` accepted revision `<= qr.accepted_source_revision` established complete authoritative evidence for that resource), reporting unapplied accepted revisions via `EXISTS (SELECT 1 FROM openmettle.quota_accepted_gateway_reports a WHERE a.request_id = qr.gateway_request_id AND a.revision > coalesce(qr.accepted_source_revision, -1))` in `pending_gateway_reconciliations`, validating widened `gateway_settlements.measured` (`numeric(38, 0)`) joined to `openmettle.gateway_usage_reports r_curr` strictly on **`(gs.request_id = r_curr.request_id AND gs.revision = r_curr.revision AND gs.final = r_curr.final)`** reading `r_curr.source` and `r_curr.report_id` from `r_curr`, and failing hard once `storage_volume_control.volume_id IS NOT NULL` on any `'active'`/`'retained'` revision with `payload_ino IS NULL`), `enforce_storage_override`, `quota_enforcement_write_once` (`OMQ04`), `SECURITY DEFINER` `DEFERRABLE INITIALLY DEFERRED` `CONSTRAINT TRIGGER quota_enforce_gateway_handoff_holds` (`OMQ04`), **`SECURITY INVOKER`** `BEFORE UPDATE` `enforce_runtime_storage_volume_pinned` triggers (`SET search_path = pg_catalog`, evaluating `NOT pg_catalog.pg_has_role(current_user, 'openmettle_owner', 'USAGE')` as `SECURITY INVOKER` across both `INHERIT` and `NOINHERIT`/`SET ROLE` logins and delegating via `PERFORM openmettle.storage_lock_pinned_volume()` so `SELECT ... FOR SHARE` runs as `openmettle_owner` without PostgreSQL 18 `42501` and fails closed on `NOT FOUND OR v_vol IS NULL OR v_adopt IS NOT NULL` with `OMQ03`, never locking `storage_instance FOR SHARE`), **`SECURITY INVOKER`** `BEFORE UPDATE` `enforce_storage_reservation_monotonic_guards` trigger (`SET search_path = pg_catalog`, raising `OMQ03` for non-`openmettle_owner` clearing `adoption_unverified`, mutating/clearing non-null `payload_ino`, or clearing `stage_claimed`), `SECURITY DEFINER` `BEFORE INSERT OR UPDATE` `enforce_quota_reservation_gateway_binding` (`23514`), `BEFORE INSERT OR UPDATE OR DELETE` `enforce_cost_denomination_immutability` (`OMQ02`) and `SECURITY DEFINER` `BEFORE INSERT` `enforce_gateway_report_cost_unit` triggers, versioned `src/boundaries.sql` entries, `authz::gateway::{reserve_in, handoff_in, release_in}` in-transaction helpers, `src/quotas.rs` store, `storage::reserve` override integration, `artifact_fs::Store` retaining `Arc`-shared verified directory descriptors (`root_fd`, `staging_dir_fd`, `revisions_dir_fd`) with startup/adoption capability probes (`O_CREAT \| O_EXCL \| O_NOFOLLOW`, `rustix::fs::linkat(..., AtFlags::empty())` rejecting `ENOSYS`/`EOPNOTSUPP`/`EINVAL` and verifying `Errno::EXIST` without overwriting and shared `st_ino`, file+dir `fsync`, plus `ReadWriteMany` two-client Linux NFS `flock(2)` coherence — specifically `LOCK_SH` on `OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` vs `LOCK_EX \| LOCK_NB` `WouldBlock` on `OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC` across `'truncated'` reopen, Step 4, Stage C, and `StagingSweepState` — AND stable 64-bit `st_ino` coherence + second-client recovery qualification), unified rollout rule (`Store::stage`/`Store::publish` succeeding when `storage_volume_control.adoption_run_id IS NULL` both pinned and while `volume_id IS NULL`, while ADR 0039 worker `publish_bytes` and all 4 cleaners strictly require `storage_volume_control.volume_id IS NOT NULL AND adoption_run_id IS NULL`), `Store::stage` Steps 1a/1b/1c (`stage_claimed = true` before disk write -> `openat` + `LOCK_SH` + `fsync(&staging_dir_fd)` BEFORE binding `payload_ino` -> commit `payload_ino = staged_ino`), **100% non-destructive `StagedFile::drop` and writer error/cancellation paths** (NEVER calling `set_len(0)` or `unlinkat`; ambiguous `storage::settle` inspecting `storage_reservations.state` under `FOR UPDATE` before `abort`), `Store::publish` committing `publish_pending = true` before **`rustix::fs::linkat(&staging_dir_fd, id, &revisions_dir_fd, id, AtFlags::empty())`** + `fsync(&revisions_dir_fd)` + post-`linkat` re-verify (quarantining `Errno::EXIST` without overwriting foreign `revisions/<id>` AND keeping `staging/<id>` present on disk until `storage::settle` commits so `N-1` API retries hit `OpenOptions::create_new(true)` -> `Err(Error::InProgress)`), synchronized 5-step ADR 0039 `publish_bytes` pre-publication `publish_pending` fence (Step 1 `0`-byte `staging/<id>` + continuous `LOCK_EX` + `fsync(&staging_dir_fd)` + write-once `stage_claimed = true, payload_ino` via `storage_lock_pinned_volume()` leaving `publish_pending = false` -> Step 2 write + verify + `sync_all()` under `LOCK_EX` -> Step 3 re-stat + `storage_lock_pinned_volume()` + `SET publish_pending = true WHERE ... state = 'reserved' AND NOT adoption_unverified AND reclaim_state = 'none' AND payload_ino = $3` strictly BEFORE `linkat` -> Step 4 `linkat` + `fsync(&revisions_dir_fd)` + post-`linkat` re-verify **without dropping `LOCK_EX`** -> Step 5 carrying `staged_fd` (`LOCK_EX`) through a single atomic `Fence::Step` `WriteTransaction` committing BOTH `storage::settle` AND `runs::record_observation`, dropping `staged_fd` (`LOCK_EX`) only AFTER commit, then post-commit best-effort `LOCK_SH` (`OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + immediate `file.metadata()?.file_type().is_file()` check) `unlinkat(&staging_dir_fd, id)` without `set_len(0)` + `fsync(&staging_dir_fd)`), `storage::settle` committing `state = 'settled', publish_pending = false` while **retaining `payload_ino`**, and post-commit best-effort detach of `staging/<id>` while holding `LOCK_SH` (or reopening via `OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + `is_file()` + `LOCK_SH`; `unlinkat`, never `set_len(0)` -> `drop` -> `fsync(&staging_dir_fd)`), **`Store::read`** joining `storage_reservations` to verify `NOT sr.adoption_unverified`, opening `revisions/<reservation>` via **`OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK`**, immediately checking `file.metadata()?.file_type().is_file()` (failing closed with `Err(Error::Missing)` on FIFOs/sockets/devices/directories without blocking), acquiring non-blocking **`file.try_lock_shared()`** (`LOCK_SH \| LOCK_NB`, returning `Err(Error::Missing)` on `WouldBlock`), **strictly AFTER acquiring `LOCK_SH`** re-verifying `file.metadata()?` (`is_file()`, local `st_dev`, `st_ino == sr.payload_ino` whenever non-null, `len() == size`) and `statat(&revisions_dir_fd, reservation, AtFlags::SYMLINK_NOFOLLOW)` `(fd_dev, fd_ino)` match (permitting legacy `payload_ino IS NULL` ONLY while `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL`, failing closed with `Error::Io` once `volume_id IS NOT NULL`), seeking to `start`, and **retaining that locked `fs::File` inside `Content` for the entire streaming response body lifetime** so `purge_due` Stage A (`LOCK_EX \| LOCK_NB`) gets `WouldBlock` and never truncates an in-flight download, API-only `Store::open` (`openmettle_api` only; `openmettle_worker` never initializes sentinels and never calls `storage_pin_volume_id(uuid)`) fresh-bootstrap-only three-directory role-tagged volume sentinel pinning (`:root` + `fsync(root_fd)` strictly before `:revisions`/`:staging`) invoking `openmettle.storage_pin_volume_id(uuid)` directly (zero invoker `FOR UPDATE`), unified **4-step reclamation protocol** across ALL 4 cleaners (`artifact_fs::abort`, `reconcile_expired` updating ADR 0031 & `tests/schema/artifact_fs.rs`'s `renamed` test case, generic run-linked recovery narrowed to `(operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')`, and ADR 0039 `reconcile_run_spills`) with **ZERO filesystem I/O inside DB Steps 1 and 3** and Linux-NFS-safe **`OFlags::RDWR \| OFlags::NOFOLLOW` (explicitly WITHOUT `OFlags::TRUNC`)** on EVERY `LOCK_EX` open (`reclaim_state = 'claiming'` -> outside-DB probe checking `staging/.reclaim.<id>` first before `staging/<id>`/`revisions/<id>` -> `LOCK_EX` + **Step 2a fenced PostgreSQL claim revalidation & 300 s lease renewal via `storage_lock_pinned_volume()` strictly BEFORE `set_len(0)`/`linkat`/`unlinkat`** (and in Case 2 `payload_ino IS NULL`, opening a `0`-byte regular `staging/<id>` with `revisions/<id>` and `staging/.reclaim.<id>` `ENOENT` via `OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC` and zero `set_len(0)`, acquiring `LOCK_EX`, executing Step 2a SQL atomically binding `stage_claimed = true, payload_ino = fd_ino` while asserting `payload_ino IS NULL`, `'reserved'`, matching token, and pinned volume, and promoting directly into the standard `linkat` `.reclaim.<id>` -> `fsync(&staging_dir_fd)` -> `unlinkat` `<id>` -> dual `fsync` -> `'truncated'` -> Step 3 `'anchor_pending_unlink'` -> Step 4 sequence so `payload_ino` stays `NULL` through Step 3 ONLY when `staging/<id>`, `staging/.reclaim.<id>`, and `revisions/<id>` are ALL already `ENOENT` with ZERO `unlinkat` calls) -> `set_len(0) + sync_all()` -> `linkat` hard-link anchor `staging/.reclaim.<id>` + **unconditional `fsync(&staging_dir_fd)` on BOTH new and recovered anchors** strictly before `unlinkat` `<id>` from `revisions/`/`staging/` + dual `fsync` -> short DB commit `reclaim_state = 'truncated', publish_pending = false` retaining `payload_ino`, with `'truncated'` crash recovery probing ONLY `staging/.reclaim.<id>` via `OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC`, zero `set_len(0)`, and never touching `staging/<id>`/`revisions/<id>` -> Step 3 final `storage::release` setting `reclaim_state = 'anchor_pending_unlink'` when `payload_ino IS NOT NULL` and retaining `payload_ino` -> Step 4 post-release **`OFlags::RDWR \| OFlags::NOFOLLOW` (no `OFlags::TRUNC`, zero `set_len(0)`)** + `LOCK_EX` `unlinkat` of `staging/.reclaim.<id>` + `fsync(&staging_dir_fd)` + `reclaim_state = 'none'` backed by a bounded DB-driven Step 4 pass over `storage_reservations_reclaim_anchor_idx` with per-worker wrapping keyset cursor `reclaim_anchor_cursor` + fixed pass-start upper watermark `(upper_ts, upper_id)` resetting both on `< LIMIT` or reaching `(upper_ts, upper_id)` across all reservation kinds), **3-stage inode-preserving `artifact_fs::purge_due`** (`begin_purge` -> Stage A `revisions/.purge.<id>` anchor + `LOCK_EX` + DB revalidation via `storage_lock_pinned_volume()` + `set_len(0) + sync_all()` + unconditional `fsync(&revisions_dir_fd)` strictly before visible-name unlink of `revisions/<id>` and matching `staging/<id>` + dual `fsync(&revisions_dir_fd)`/`fsync(&staging_dir_fd)` keeping `payload_ino` pinned at `nlink >= 1` -> Stage B `storage::confirm_purge` setting `state = 'purged', purge_stage = 'anchor_pending_unlink'` -> Stage C immediate + bounded `LIMIT` DB pass over `artifact_revisions_purge_anchor_idx` with per-worker wrapping keyset cursor `purge_anchor_cursor` + fixed pass-start upper watermark `(upper_ts, upper_id)` resetting both on `< LIMIT` or reaching `(upper_ts, upper_id)` detaching `revisions/.purge.<id>` under `LOCK_EX` with **`OFlags::RDWR \| OFlags::NOFOLLOW` (no `OFlags::TRUNC`, zero `set_len(0)`)** + `fsync(&revisions_dir_fd)` + `SET purge_stage = 'none'`), **zero-truncation 3-bucket `StagingSweepState` (ZERO `set_len(0)` calls in ANY branch, including `0`-row orphans and `.reclaim.<id>` entries, **`OFlags::RDWR \| OFlags::NOFOLLOW` explicitly WITHOUT `OFlags::TRUNC`**, `storage_lock_pinned_volume()` + `storage_instance FOR NO KEY UPDATE`, and zero post-purge `'purged'` `ENOENT` exception)**, idempotent `purging`-tolerant `openmettle-admin` verified volume adoption CLI procedure (`my_adoption_run_id = uuid_v4()`, Step 1b locking ONLY `storage_volume_control WHERE id FOR UPDATE` serialized against `storage_lock_pinned_volume()` `FOR SHARE` with `--replace-adoption-run <stale_uuid>`, Step 2 outside-DB scan clearing `adoption_run_id = NULL` on failure only `WHERE id AND adoption_run_id = $my_adoption_run_id`, Step 3 canonical lock order `storage_reservations -> artifact_revisions -> storage_volume_control -> storage_accounts -> storage_instance FOR UPDATE` requiring `adoption_run_id = $my_adoption_run_id`, Phase 3A read-only verification enforcing **cross-reservation live inode uniqueness strictly across live payloads, surviving anchors, and all candidates for `payload_ino` backfill or `adoption_unverified = false` clearance — namely `artifact_revisions` with `state IN ('active', 'retained')`, surviving `state = 'purging'`, or `(state = 'purged' AND purge_stage = 'anchor_pending_unlink')`, AND `storage_reservations` with `(state = 'reserved' AND (payload_ino IS NOT NULL OR candidate for backfill/un-quarantine — explicitly including previously quarantined adoption_unverified = true rows present on disk))` OR `(state = 'released' AND reclaim_state = 'anchor_pending_unlink')`, explicitly EXCLUDING retired historical rows `(state = 'released' AND reclaim_state = 'none')` and `'settled'` rows whose revision is `(state = 'purged' AND purge_stage = 'none')` (`cross_reservation_inode_alias` / `intra_reservation_inode_mismatch` / `foreign_staging_collision`)** and holding non-blocking `OFlags::RDWR \| OFlags::NOFOLLOW` (without `OFlags::TRUNC`) `LOCK_EX` (`try_lock()`) across every `payload_ino IS NULL` `'reserved'` backfill candidate through Phase 3C's backfill commit (clearing `adoption_run_id = NULL` without quarantining/backfilling and returning retryable `OMQ03` on `WouldBlock`) and recognizing valid crash-boundary states (`'claiming'`+`.reclaim.<id>`, already-`'truncated'`+`.reclaim.<id>` requiring `staging/<id>` and `revisions/<id>` `ENOENT` or rejecting with `truncated_visible_name_present`, `'purging'` Stage A, `'purged'`+`anchor_pending_unlink`+`.purge.<id>`) plus legacy `'purging'` (`sr.payload_ino IS NULL`) **Case 6a (requiring exact recorded `st_size == size_bytes` AND `sha256 == content_digest`, rejecting `st_size == 0` when `size_bytes > 0` with `size_or_digest_mismatch` and reserving `st_size == 0` strictly for already-bound `sr.payload_ino IS NOT NULL AND st_ino == sr.payload_ino`) & Case 6b (all-names-absent owner completion, NEVER counting as positive on-disk file evidence toward volume-identity verification)** BEFORE writing any `payload_ino`, committing `payload_ino` backfills **strictly ONLY on positively verified non-quarantined rows** (never writing `payload_ino` onto rows staying `adoption_unverified = true`), **keeping `reclaim_state = 'claiming'` as `'claiming'` (never promoting `'claiming'` to `'truncated'`) with `reclaim_lease_until = clock_timestamp()`**, and Case 6b direct legacy-purge completion + `retained_bytes` decrement ONLY in the success branch, omitting/rolling back ALL `payload_ino` backfills on failed adoption, quarantining missing/mismatched `'reserved'` rows, pinning `storage_volume_control.volume_id`, and clearing `adoption_run_id = NULL`) and operator runbook update mandating the 4-step upgrade sequence, `claim_next` executing-cap override evaluation, DB-plus-filesystem `verify_accounting_drift`, bounded two-step raw-index-key paging across `quota_release_orphan_gateway_requests`, `quota_reservations`, run-linked `storage_reservations`, and non-run `reconcile_expired`, and `SKIP LOCKED` one-per-tx `reconcile_stale_quotas` with persistent 5-state `StagingSweepState` held outside `worker::sweep`'s 15 s `tokio::time::timeout` in `src/worker.rs`. | PostgreSQL 18 tests in `tests/schema/grants.rs`, `tests/schema/artifact_fs.rs`, and `tests/schema/quotas.rs` executing all override, reservation, legacy-run-hold-backfill, device-handoff, lost-handoff-recovery, superseded-round-unwind, orphan-gateway-sweep, gateway-settlement, drift-verification and stale-sweep paths **connected as the actual runtime roles** (`openmettle_api`, `openmettle_worker`, `openmettle_gateway`, `openmettle_issuance`) and asserting denial of direct `INSERT`/`UPDATE`/`DELETE`/`SELECT ... FOR NO KEY UPDATE` on all `quota_*` tables (plus zero privileges on `quota_cost_unit_lock`, `quota_gateway_handoffs`, and `quota_accepted_gateway_reports`, `SELECT`-only on `quota_enforcement`, `SELECT`-only on `storage_volume_control` for BOTH `openmettle_api` and `openmettle_worker` (asserting `42501` denial of direct `INSERT`/`UPDATE`/`DELETE`/`TRUNCATE`, including direct `UPDATE (volume_id, bootstrap_auto_pin_allowed)` by `openmettle_api`), `EXECUTE` on `openmettle.storage_lock_pinned_volume()` for `openmettle_api`/`openmettle_worker` and **API-only `EXECUTE` on `openmettle.storage_pin_volume_id(uuid)` strictly for `openmettle_api`** (explicitly testing under `SET ROLE openmettle_api` that empty fresh-bootstrap pinning succeeds, and under `SET ROLE openmettle_worker` that direct invocation of `openmettle.storage_pin_volume_id(uuid)` fails with `42501` while worker startup/ticks cleanly await pin via `storage_lock_pinned_volume()` observing `OMQ03` without `42501`), `UPDATE (purge_stage)` on `openmettle.artifact_revisions` for `openmettle_worker`, plus `INSERT (lease_expires_at, stage_claimed)` and `UPDATE (lease_expires_at, adoption_unverified, stage_claimed, payload_ino, publish_pending, reclaim_state, reclaim_claim_token, reclaim_lease_until)` on `storage_reservations` for `openmettle_api`/`openmettle_worker`, plus schema tests for `payload_ino` non-negative CHECK, `CHECK (payload_ino IS NULL OR stage_claimed)`, `CHECK (NOT publish_pending OR (state = 'reserved' AND payload_ino IS NOT NULL))`, all three `reclaim_state`/`reclaim_claim_token`/`reclaim_lease_until` CHECK constraints, and `artifact_revisions_purge_stage_check`, AND **`SECURITY INVOKER` `enforce_storage_reservation_monotonic_guards()` assumed-role tests under BOTH `openmettle_api` and `openmettle_worker` (both `INHERIT` and `NOINHERIT`/`SET ROLE` logins) proving `OMQ03` on clearing `adoption_unverified`, mutating or clearing non-null `payload_ino`, or clearing `stage_claimed` while `openmettle_owner` succeeds**), denial of direct `SELECT` by `openmettle_api` and `openmettle_worker` on `openmettle.gateway_requests` and `openmettle.gateway_usage_reports` while qualifying `openmettle.quota_verify_accounting_drift()`, `openmettle.quota_ensure_legacy_run_holds(...)`, `openmettle.quota_unwind_superseded_round(...)` and `openmettle.quota_release_orphan_gateway_requests(...)` as `openmettle_worker` (and denying `EXECUTE` to `openmettle_api`, `openmettle_gateway` and `openmettle_issuance`), qualifying `openmettle.quota_lock_gateway_request_for_settlement(uuid)` strictly as `openmettle_gateway` (and denying `EXECUTE` to all other runtime roles), and qualifying `openmettle.quota_recover_lost_handoff(...)` as `openmettle_api` (`p_run_id IS NULL`) and `openmettle_worker` (`p_run_id IS NOT NULL`) while denying `openmettle_gateway` and `openmettle_issuance`, denial of `openmettle_api` calling either `quota_commit_handoff` or `quota_commit_device_handoff` on a run-linked `device_reservations` hold, denial of `openmettle_worker` calling generic `quota_commit_handoff` on a run-linked `device_reservations` hold, and denial of cross-role/unleased calls; N-way concurrent admission non-oversubscription across distinct project/actor/instance windows; non-windowed `device_reservations` surviving UTC rollover and `api`-admitted run device handoff exclusively via `quota_commit_device_handoff` under active `claim_token` lease (plus refusal for wrong resource kind or stale/unleased/cancelled run); cross-scope lock-order race with zero deadlocks; concurrent `executing_runs_per_actor` / `executing_runs_per_scope` cap lowering racing `claim_next` (and approval resume) serialized on `run_dispatch_lock` with zero overshoot; exact-once reconciliation across exact replay (recovering server-chosen windows), unique `(gateway_request_id, resource_kind)` enforcement rejecting duplicate keys, scope-pinned composite FK `(scope_id, gateway_request_id) REFERENCES openmettle.gateway_requests (scope_id, id)` and composite FKs to `gateway_usage_reports` (`(request_id, revision)` and `(source, report_id, revision)`) and `quota_accepted_gateway_reports` (`(request_id, revision)`), **single-transaction atomic `authz::gateway::reserve_in` + `quota_reserve` / `quota_allocate_round` rollback test proving that when any metered quota hold fails or the transaction aborts before commit, neither `gateway_requests`, `gateway_reservations.allocated`, nor `quota_reservations` persists (and `gateway_requests_run_round_active_idx` is not stranded)**, **exact `usage_tokens` hold-size equality and pre-handoff `settled_units > 0` schema guard tests exercising mismatched amounts (`<` and `>` `gateway_requests.units`) on BOTH standalone (`run_id IS NULL`) and run-round (`run_id IS NOT NULL`) requests AND attempting `INSERT` and `UPDATE` in `state = 'held'` (and unaccepted `state = 'handoff_committed'` with `accepted_source_revision IS NULL`) with `settled_units > 0` and reduced `held_units`, proving deterministic rejection across `quota_reservations` `CHECK` constraints, `quota_reserve` / `quota_allocate_round` / `enforce_quota_reservation_gateway_binding` (`23514`), and `enforce_gateway_handoff_holds` (`OMQ04`)**, **deployment-history fresh-vs-upgrade seeding and `0023` rolling-upgrade activation tests across `openmettle.bootstrap_from_zero`, `quota_enforcement.metering_enforced`, and `storage_volume_control.bootstrap_auto_pin_allowed`: (a) fresh `applied == 0` bootstrap via `migrate_within_boundaries` auto-seeds `metering_enforced = true` and `bootstrap_auto_pin_allowed = true` (permitting `Store::open` auto-pinning once and clearing `bootstrap_auto_pin_allowed = false`); (b) an existing, completely unused `0001..0023` installation (`applied = 23`, zero rows in `users`, `scopes`, `projects`, `runs`, `storage_*`, and `gateway_*`) upgraded to `0024` via `migrate_within_boundaries` seeds `metering_enforced = false`, `bootstrap_auto_pin_allowed = false`, and `volume_id IS NULL`, proving legacy `0023` handoff succeeds during rollout, `N` API startup (`Store::open` / `storage_pin_volume_id`) refuses to auto-pin (`OMQ03`) while `N` worker never initializes sentinels or calls `storage_pin_volume_id` and cleanly skips/fails closed on `OMQ03` via `storage_lock_pinned_volume()` without `42501`, and post-replacement `openmettle-admin` adoption (cleanly linking all three role-tagged sentinels without `--expected-fs-uuid` / `--expected-revisions-inode` on the empty storage ledger) plus `metering_enforced = true` activation completes cleanly; (c) storage-disabled installation activation test (both `OPENMETTLE_API_ARTIFACTS_DIR` / `OPENMETTLE_ARTIFACTS_DIR` and `OPENMETTLE_WORKER_ARTIFACTS_DIR` unset and `0` rows in `storage_reservations` and `artifact_revisions`) proving Step 4 skips volume adoption cleanly (`volume_id IS NULL`, `bootstrap_auto_pin_allowed = false`, cleaners disabled), runs `quota_release_orphan_gateway_requests`, flips `metering_enforced = true`, and passes `verify_accounting_drift` (while `verify_accounting_drift` still fails hard whenever `ARTIFACTS_DIR` is configured or any storage row exists with `volume_id IS NULL`); (d) Step 1 pre-migration `N-1` `worker::maintenance` sweep-drain test proving an in-flight `N-1` sweep finishes cleanly before `openmettle-migrate` starts; (e) populated upgrades (including an existing `openmettle.gateway_reservations` row with zero `gateway_bindings`/`gateway_requests` rows) seed `false` so `N-1` `0023`-only handoff succeeds during rolling deploy and `quota_recover_lost_handoff` reports `'unmetered_legacy_handoff'` while suppressing HTTP dispatch, whereas any bound `'held'`/`'released'` quota hold still fails at `COMMIT` with `OMQ04`; flipping write-once `metering_enforced = true` as `openmettle_owner` in a standalone single-statement transaction — rejecting `true -> false` with `OMQ04` — causes `0023`-only handoffs to fail at `COMMIT` with `OMQ04` and roll back `gateway_requests` to `'reserved'`, requiring both bound `'handoff_committed'` `usage_tokens` (exact `reserved_units = NEW.units AND held_units = NEW.units AND settled_units = 0 AND accepted_source_revision IS NULL` + ownership match) and applicable `usage_cost_micros` holds (`settled_units = 0 AND accepted_source_revision IS NULL`); PLUS (f) a two-connection concurrency test covering both commit orders between an unmetered `0023` `gateway_handoff` commit (inserting `quota_gateway_handoffs` first and then locking `quota_enforcement FOR SHARE` as the final lock) and `openmettle_owner`'s `metering_enforced = true` activation (`FOR NO KEY UPDATE`), proving zero deadlock, strict lock-order serialization, and that an unmetered handoff can never observe `metering_enforced = false` and commit after activation**, **rolling-upgrade legacy-run reclaim and pre-`reserve_in` lazy parent-hold initialization test (`quota_unwind_superseded_round` -> `quota_ensure_legacy_run_holds` -> `authz::gateway::reserve_in` -> `quota_allocate_round`) where an `N-1` API replica admits a run (`runs` + `gateway_reservations` with `units = 100`, zero parent `quota_reservations`) and an `N-1` worker commits an unbound `'reserved'` round before crashing, and an `N` worker reclaims the run, cleanly unwinds the unbound legacy `'reserved'` round via `quota_unwind_superseded_round` (with zero parent `quota_reservations` present, freeing `gateway_requests_run_round_active_idx` and restoring `gateway_reservations.allocated = 0`), then inside the single round-allocation `WriteTransaction` executes `quota_ensure_legacy_run_holds` strictly BEFORE `authz::gateway::reserve_in` (locking `gateway_reservations FOR NO KEY UPDATE` with zero lock upgrade before `reserve_in` and reading `units - allocated = 100`, initializing the parent hold to `100`, enforcing `quota_budgets` hard limits with `OMQ01` when over budget and staying idempotent across retries and subsequent rounds), followed by a `60`-unit `reserve_in` + `quota_allocate_round` proving the child slices `60` without double-subtraction, `40` remains `held_units` on the parent, and settlement completes cleanly**, **fenced successor-worker unwind test (`openmettle.quota_unwind_superseded_round`) simulating worker process death immediately between `(reserve_in + quota_allocate_round)` commit and handoff, lease expiry + `leases::reclaim_next` by a successor worker, fenced unwind transitioning `gateway_requests` to `'released'`, restoring `gateway_reservations.allocated` and parent run `quota_reservations` capacity (`allocated_units`/`held_units`) while releasing child holds and freeing `gateway_requests_run_round_active_idx`, clean retry of the same round, and a replay test calling `quota_unwind_superseded_round` again with the same live `claim_token` after the successor worker has already unwound the predecessor and reserved the same `round` again (proving the successor's replacement `'reserved'` request and child holds carrying `allocating_claim_token = p_claim_token` remain intact and `false` is returned, plus `'handed_off'` left untouched returning `false`, and stale `claim_token` / non-worker calls refused)**, **pre-upgrade orphan `'reserved'` `gateway_requests` sweep test via `openmettle.quota_release_orphan_gateway_requests(...)` (using valid scalar PostgreSQL 18 `IF` upper-bound clamping) connected as `openmettle_worker` releasing aged unbound `'reserved'` rows while restoring `gateway_reservations.allocated`, freeing `gateway_requests_run_round_active_idx`, and skipping active leased runs or bound requests, PLUS (a) a bounded raw index-key paging test with a multi-page prefix of aged legitimately bound `'reserved'` requests ahead of a trailing orphan proving each call inspects at most `p_page_size` raw `(created_at, id)` keys from `gateway_requests_reserved_idx`, advances the persistent cursor across zero-orphan pages without exhausting sweep budget, and releases the trailing orphan on a subsequent page, and (b) a large all-young `'reserved'` tail test verifying bounded index buffer/key touches (`raw_keys_scanned = 0` past `v_age_cutoff`) with zero per-row `clock_timestamp()` filtering**, **negative binding and ownership-recheck tests proving cross-scope, cross-actor, cross-run, non-`'reserved'` state, or wrong-`p_dispatch`-secret bind attempts in `quota_reserve` / `quota_allocate_round` (and `quota_reservations_gateway_binding_guard`) are rejected and that `quota_release_unsent` ownership rechecks fail closed with an invariant error mutating neither ledger on mismatch**, run-to-round `held` allocation without double-debit coupled atomically with `authz::gateway::handoff_in` (`openmettle.gateway_handoff`) + `quota_commit_handoff` (rolling back both on pre-commit refusal), **lost commit acknowledgement (`UnknownCommit`) integration tests connected directly as unprivileged `openmettle_api` and `openmettle_worker` logins exercising all `openmettle.quota_recover_lost_handoff(...)` outcomes — `'handoff_committed'` (preserving durable `gateway_requests.state = 'handed_off'` + all required `'handoff_committed'`/`'settled'` quota holds recorded in `quota_gateway_handoffs`, including a test where `quota_settle_gateway_usage` has already moved bound holds to `'settled'` before recovery runs, asserting zero bound holds remain `'held'`/`'released'`, suppressing HTTP dispatch for gateway reconciliation), `'unmetered_legacy_handoff'` (including a pre-activation unmetered handoff committed while `metering_enforced = false` and recovered via `quota_recover_lost_handoff` *after* live `metering_enforced` flipped `true`, still returning `'unmetered_legacy_handoff'` with zero `OMQ04` and suppressing HTTP dispatch), and `'unwound_unsent'` (atomically unwinding `'reserved'`/`'released'` `gateway_requests`, restoring `gateway_reservations.allocated`, and releasing bound `'held'` holds to an active parent or `quota_budgets`) plus wrong-role/wrong-secret/mismatched-ownership/missing-required-hold (`OMQ04`) refusals**, pre-send unwind via `authz::gateway::release_in` (`openmettle.gateway_release`) + `quota_release_unsent` returning capacity to an active parent run hold (or releasing on terminal runs), **stale sweep atomically transitioning a stale `'reserved'` `gateway_requests` row to `'released'` and restoring `gateway_reservations.allocated` in the same `SECURITY DEFINER` transaction as releasing `quota_reservations` (proving a delayed `openmettle.gateway_handoff` with the original dispatch secret fails closed while `'handed_off'` rows remain untouched)**, cancellation, pre-send abort (with `closed_at`), valid `revision = 0` initial partial and final reports accepted when `accepted_source_revision IS NULL` (persisting `accepted_source_revision = 0` and rejecting subsequent `revision <= 0`), signed downward partial correction (`delta_reserved > 0`), **per-resource complete authoritative evidence and incomplete-component deferral tests exercising (a) an explicit zero-token final report (`prompt_tokens = 0, completion_tokens = 0`) settling `usage_tokens` to `'settled'` (`settled_units = 0, held_units = 0`) and releasing the token hold, (b) a cost-only final report (`cost` present, token columns `NULL`) settling `usage_cost_micros` to `'settled'` while keeping `usage_tokens` in `handoff_committed` with full `held_units` and last confirmed `settled_units` untouched (never turning `NULL` tokens into `0`), (c) a cost-only post-final correction updating `usage_cost_micros` without erasing `usage_tokens.settled_units` or altering `usage_tokens.accepted_source_revision`, (d) a token-only report (`r.cost IS NULL`) skipping `usage_cost_micros` completely, and (e) component-aware `C_floor` and complete-evidence close-gate tests proving (i) `hold = 100` + `prompt_tokens = 150, completion_tokens = NULL` immediately sets `settled_units = 150, held_units = 0` (`+50` confirmed overage exposure) in BOTH `quota_settle_gateway_usage` and `quota_verify_accounting_drift()` while keeping `state = 'handoff_committed'`, (ii) `hold = 200` + `prompt_tokens = 60, completion_tokens = NULL, final = true` keeps `settled_units = 60, held_units = 140, state = 'handoff_committed'` (refusing to close `'settled'` without complete evidence) until complete final `prompt_tokens = 60, completion_tokens = 20` settles `80` (`held_units = 0, state = 'settled'`), (iii) `revision = 1` (`120 + 30 = 150`) followed by `revision = 2` (`prompt_tokens = NULL, completion_tokens = 30`, plus omitting a previously-confirmed non-included `reasoning_tokens`) preserves `settled_units = 150` (`0` confirmed exposure lost) across both settlement and drift verification until complete authoritative `revision = 3` resolves it, (iv) **included reasoning tokens lower-bound tests (`reasoning_included = true`) proving (1) `hold = 100` + `prompt_tokens = NULL, completion_tokens = NULL, reasoning_tokens = 150, reasoning_included = true` immediately charges `settled_units = 150, held_units = 0` (`+50` confirmed overage) while keeping `is_complete_tokens = false` / `state = 'handoff_committed'`, (2) `final = true, prompt_tokens = 60, completion_tokens = NULL, reasoning_tokens = 150, reasoning_included = true` charges `210` and stays `handoff_committed` until explicit `completion_tokens IS NOT NULL` arrives, (3) `completion_tokens = 200, reasoning_tokens = 150, reasoning_included = true` yields `K_known = greatest(200, 150) = 200, X_known = 0` with zero double-counting (and malformed `completion_tokens = 100 < reasoning_tokens = 150, reasoning_included = true` yields `K_known = 150`), and (4) a newer complete revision (`rev_K > rev_R`) with `completion_tokens = 120, reasoning_tokens = NULL` honors `K_known = 120`**, (v) **out-of-order ascending revision fold test (`H = 200`, `rev 1`: `prompt_tokens = 60, completion_tokens = 20, final = true`; `rev 2`: `prompt_tokens = NULL, completion_tokens = 25, final = true`) calling `quota_settle_gateway_usage(..., 2)` BEFORE `rev 1` and proving it folds `[1, 2]` in `ORDER BY a.revision ASC` to the exact same `('settled', 85, 0, accepted_source_revision = 2)` as `rev 1` then `rev 2` (with subsequent `rev 1` returning idempotent no-op)**, (vi) **unchanged incomplete post-final correction test (`completion_tokens = 25 -> 25`) proving `qr.accepted_source_revision` advances unconditionally with zero `quota_reconciliations` row, zero budget delta, zero hard drift, and `pending_gateway_reconciliations = 0`**, and (vii) **split-report `is_complete_tokens(r_step)` non-stitching test (`200`-token hold: `rev 0: prompt_tokens = 60, completion_tokens = NULL, final = false` followed by `rev 1: prompt_tokens = NULL, completion_tokens = 25, final = true`) proving `is_complete_tokens(rev 1) = false` (both `prompt_tokens` and `completion_tokens` must be non-null on `r_step` itself) and producing `85 settled, 115 held, state = 'handoff_committed'`** (and `quota_verify_accounting_drift()` joining `openmettle.gateway_settlements gs` to `openmettle.gateway_usage_reports r_curr` strictly on `(gs.request_id = r_curr.request_id AND gs.revision = r_curr.revision AND gs.final = r_curr.final)` reading `r_curr.source` and `r_curr.report_id` from `r_curr`)**, **`quota_accepted_gateway_reports` historical catch-up, rejected-revision guard, and zero-deadlock concurrency tests covering (a) `revision = 1` (complete token-only final) AND `revision = 2` (cost-only final) both committing in `gateway_settlements` before local catch-up runs, proving `quota_accepted_gateway_reports` durably records both `(request_id, 1, true)` and `(request_id, 2, true)` so local catch-up settles `usage_tokens` from `revision = 1` and `usage_cost_micros` from `revision = 2` cleanly without stranding the token hold, (b) `tests/schema/gateway.rs`'s `revision = 1 (partial) -> 2 (final) -> 3 (late partial stored in gateway_usage_reports, rejected by gateway_settlements) -> 4 (final correction)` against a lagging `handoff_committed` hold proving `revision = 3` is absent from `quota_accepted_gateway_reports` and rejected by BOTH `quota_settle_gateway_usage` and `enforce_quota_reservation_gateway_binding` (`23514`) while `revision = 2` and `revision = 4` settle cleanly, AND (c) racing settlement-only (`quota_lock_gateway_request_for_settlement` -> `gateway_settlements` upsert), combined single-transaction (`quota_lock_gateway_request_for_settlement` -> `gateway_settlements` upsert -> `quota_record_accepted_gateway_settlement` -> `quota_settle_gateway_usage`), and worker recovery (`quota_release_unsent` / `quota_release_orphan_gateway_requests`) transactions concurrently on the same `request_id`, proving unconditional `quota_lock_gateway_request_for_settlement` maintains the globally acyclic lock order with zero deadlock**, **fractional `usage_cost_micros` cumulative `ceil(r.cost)::numeric(38, 0)` rounding and correction test across integer boundaries (`0.4 -> 0.8 -> 1.2` final -> `0.5` post-final correction -> `0`, proving `settled_units` / `active_used` track `1 -> 1 -> 2 -> 1 -> 0` with zero accumulated rounding drift and matching `quota_verify_accounting_drift()`)**, **`numeric(38, 0)` DB-to-Rust end-to-end oversized 3-column token and multi-report aggregate overflow test exercising BOTH multiple large overage reports AND a single oversized 3-column token report (`prompt_tokens + completion_tokens + reasoning_tokens > 9_223_372_036_854_775_807`) all the way through widened `openmettle.gateway_settlements.measured` (`numeric(38, 0)`), `quota_accepted_gateway_reports`, `quota_settle_gateway_usage`, `quota_verify_accounting_drift()`, Rust `u128`/`i128` decoding and canonical base-10 string formatting, and subsequent `429 quota` refusal without `22003` overflow** (with `/v1` HTTP `QuotaSummary` route and OpenAPI `WideNonNegativeDecimal` schema validation owned by PR3), `BEFORE INSERT OR UPDATE OR DELETE` `cost_denomination` immutability trigger (`OMQ02`, proving `INSERT` — including `INSERT ... ON CONFLICT DO UPDATE` — `DELETE`, and rename into/out of the seeded `('instance', 'usage_cost_micros')` row unconditionally fail with `OMQ02` without acquiring `quota_cost_unit_lock`, eliminating any AB/BA lock cycle) plus `BEFORE INSERT` `gateway_usage_reports_cost_unit_guard` serialized via `quota_cost_unit_lock` with **explicit concurrency tests covering both commit orders with different units (direct `UPDATE quota_defaults` vs `openmettle_gateway` `INSERT INTO gateway_usage_reports` with `cost IS NOT NULL`, plus two concurrent `gateway_usage_reports` inserts with different units while `cost_denomination IS NULL`)** and mismatch quarantine, final overage settlement plus subsequent refusal, upload abort and `confirm_purge`; override raise/lower/expiry and `hard_limit = 0` preserving data and deletion grace; `round_cap` `1..=1000` validation; **two-step raw-index-key paging and `tool-spill:*` ownership-partition tests across `quota_reservations`, run-linked `storage_reservations` (proving `operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%'` rows remain exclusively owned by ADR 0039 `reconcile_run_spills`, a pre-existing `run_id IS NOT NULL AND operation_id IS NULL AND idempotency_key LIKE 'tool-spill:%'` row is cleanly owned and recovered by ADR 0040's generic cleaner via the exact logical complement `(operation_id IS NULL OR idempotency_key NOT LIKE 'tool-spill:%')`, and `storage_reservations_tool_spill_binding_guard` rejects any new/updated `tool-spill:%` row lacking `run_id` or `operation_id` with `23514`), and non-run `reconcile_expired` exercising a full page containing ONLY ineligible expired holds (non-terminal runs, unresolved operations, `adoption_unverified = true`, or `LOCK_SH`-active `staging/<id>` / `revisions/<id>` files) followed by eligible holds on the next page, proving zero joins/`EXISTS`/`clock_timestamp()` before `LIMIT`, exact advancement of `last_attempted` across 100%-ineligible pages without wrapping prematurely, `FOR NO KEY UPDATE SKIP LOCKED` skipping contended rows without stalling, and release of eligible holds on the next page across `SWEEP_MS` ticks (60 s default interval, 15 s budget)**; **unified 4-step reclamation protocol (`staging/.reclaim.<id>` + `anchor_pending_unlink`), `stage_claimed`, write-once `payload_ino`, `linkat` no-replace publication, non-destructive `StagedFile::drop`, `Store::read` inode verification, and writer-admission race tests across `Store::stage`, `Store::publish`, `Store::read`, `artifact_fs::abort`, `reconcile_expired`, generic run-linked recovery, and ADR 0039 `reconcile_run_spills` covering (a) startup/adoption capability probe tests verifying `O_CREAT \| O_EXCL \| O_NOFOLLOW`, `rustix::fs::linkat(..., AtFlags::empty())` (rejecting `ENOSYS`/`EOPNOTSUPP`/`EINVAL` fail-closed and verifying `Errno::EXIST` on an existing target without overwriting and shared `st_ino` between both names), and file + directory `fsync`, (b) `Store::stage` Steps 1a/1b/1c tests proving `stage_claimed = true` commits BEFORE disk creation (zero file created if rejected), `fsync(&staging_dir_fd)` completes BEFORE binding `payload_ino`, lost Step 1c ack leaves `staging/<id>` (`st_ino == payload_ino`) durably on disk and cleanly reclaimed by `reconcile_expired`/`abort` with zero false quarantine, and unified rollout rule permits HTTP `Store::stage`/`Store::publish` while `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL` (setting `stage_claimed` + `payload_ino`) while rejecting ADR 0039 worker `publish_bytes` and all 4 cleaners until `volume_id IS NOT NULL`, (c) **100% non-destructive `StagedFile::drop` & ambiguous `storage::settle` tests** proving `StagedFile::drop` and all writer error/cancellation paths NEVER call `set_len(0)` and NEVER call `unlinkat` (lost `storage::settle` ack or cancelled future never zeroes published `revisions/<id>`, and ambiguous `storage::settle` inspects `storage_reservations.state` under `(runs FOR NO KEY UPDATE ->) storage_reservations FOR UPDATE` before calling `abort`), (d) **`Store::publish` `linkat` `Errno::EXIST` quarantine, `N` post-`linkat` crash + `N-1` same-key HTTP retry interleaving, and post-commit detach tests**: placing a foreign file at `revisions/<id>` proves `linkat` fails atomically with `Errno::EXIST` leaving foreign `revisions/<id>` bytes untouched and quarantining (`adoption_unverified = true, publish_pending = false`); crashing an `N` writer right after `linkat` before `storage::settle` commits leaves `staging/<id>` present on disk so a same-key retry routed to an **`N-1` API replica** hits `store.stage(&id)` -> `OpenOptions::create_new(true)` -> `AlreadyExists` -> **`Err(Error::InProgress)` (`src/artifact_fs.rs:474-475`)** without calling `abort()`, without staging a replacement file, and without calling replacing `fs::rename`; and post-commit detach under `LOCK_SH` unlinks `staging/<id>` (`unlinkat`, never `set_len(0)`) -> `drop` -> `fsync(&staging_dir_fd)`, PLUS **unified 5-step `publish_bytes` pre-publication `publish_pending` fence & Step 4–5 `LOCK_EX` carry-through test** proving adoption (`OMQ03`) or a cleaner claim (`reclaim_state <> 'none'`) during Step 2's write fails Step 3 strictly BEFORE `linkat` without creating `revisions/<id>`, and Step 4 (`linkat` + `fsync(&revisions_dir_fd)` + post-`linkat` re-verify) carries `staged_fd` (`LOCK_EX`) without dropping into Step 5's single atomic `Fence::Step` `WriteTransaction` committing BOTH `storage::settle` AND `runs::record_observation`, dropping `LOCK_EX` only AFTER commit followed by post-commit best-effort `LOCK_SH` (`OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + immediate `is_file()` check) detach, (e) **`Store::read` `LOCK_SH`-in-`Content`, `OFlags::NONBLOCK` writerless FIFO rejection, `payload_ino`, and explicit legacy-row tests** proving `Store::read` opens `revisions/<reservation>` via **`OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK`**, immediately checks `file.metadata()?.file_type().is_file()` (explicitly testing a writerless FIFO at `revisions/<reservation>` returning `Err(Error::Missing)` immediately without blocking!), acquires non-blocking `file.try_lock_shared()` (`LOCK_SH \| LOCK_NB`, returning `Err(Error::Missing)` on `WouldBlock` once `purge_due` Stage A holds `LOCK_EX`), **strictly AFTER acquiring `LOCK_SH`** re-verifies `file.metadata()?` (`is_file()`, `st_dev == store.root_dev`, `st_ino == sr.payload_ino` whenever non-null, `len() == size`) and `statat(&revisions_dir_fd, reservation, AtFlags::SYMLINK_NOFOLLOW)` `(fd_dev, fd_ino)` match, rejects `adoption_unverified = true`, rejects a same-sized foreign replacement file (`file_meta.ino() != sr.payload_ino`) with `Error::Io`, permits legacy `sr.payload_ino IS NULL` rows ONLY while `storage_volume_control.volume_id IS NULL AND adoption_run_id IS NULL` (failing closed with `Error::Io` and hard drift in `verify_accounting_drift` once `volume_id IS NOT NULL`), and **retains the locked `fs::File` inside `Content` for the entire streaming response body lifetime** so concurrent `purge_due` Stage A (`LOCK_EX \| LOCK_NB`) receives `WouldBlock` without truncating an in-flight download, (f) updating `tests/schema/artifact_fs.rs`'s `renamed` test case and exercising ALL 4 cleaners (`artifact_fs::abort`, `reconcile_expired`, generic run-linked cleaner, ADR 0039 `reconcile_run_spills`) through the **unified 4-step reclamation protocol with `staging/.reclaim.<id>` anchor, Linux-NFS-safe `OFlags::RDWR \| OFlags::NOFOLLOW` (explicitly WITHOUT `OFlags::TRUNC`) on EVERY `LOCK_EX` open, and ZERO filesystem I/O inside DB Steps 1 and 3**: proving Step 1 (`reclaim_state = 'claiming'`) resolves any in-flight `storage::settle` BEFORE Step 2 can truncate and blocks concurrent writers/cleaners (`abort` yields cleanly on an unexpired peer lease), Step 2 probes `staging/.reclaim.<id>` first when `reclaim_state = 'claiming'` before `staging/<id>`/`revisions/<id>`, acquires `LOCK_EX` (`WouldBlock` skips live `LOCK_SH` publishers), executes **Step 2a fenced PostgreSQL claim revalidation & 300 s lease renewal (`storage_lock_pinned_volume()` + `UPDATE ... WHERE reclaim_state = 'claiming' AND reclaim_claim_token = $4::uuid`) under `LOCK_EX` strictly BEFORE `set_len(0)`/`linkat`/`unlinkat`** (explicitly testing the Cleaner 1 pause-after-Step-1 / Cleaner 2 takeover-and-release race so stale Cleaner 1 aborts at Step 2a with zero `set_len(0)`/`linkat`/`unlinkat`), then `probe_file.set_len(0)?` + `probe_file.sync_all()?` -> `linkat` anchor `staging/.reclaim.<id>` + **unconditional `fsync(&staging_dir_fd)` on BOTH newly created and recovered anchors strictly before unlinking `<id>`** (so `payload_ino` NEVER drops to `nlink = 0` before Step 3 commits!) -> `unlinkat` `<id>` from `revisions/`/`staging/` + dual `fsync` -> short DB commit `reclaim_state = 'truncated', publish_pending = false` (**retaining `payload_ino`**!), crash recovery across BOTH `'claiming'` (`.reclaim.<id>`-first probe; all-three `ENOENT` -> quarantine guarded by `reclaim_claim_token = $my_token`; foreign inode -> quarantine with ZERO `set_len(0)`/`unlinkat`) AND `'truncated'` (reopening ONLY `staging/.reclaim.<id>` with `OFlags::RDWR \| OFlags::NOFOLLOW`, no `OFlags::TRUNC`, zero `set_len(0)` when already `'truncated'` and `st_size == 0`, and NEVER touching any file at `staging/<id>` or `revisions/<id>`; missing/mismatched `.reclaim.<id>` -> quarantine), **Case 2 (`payload_ino IS NULL`) anchor-promotion & pause-across-adopt test** opening `0`-byte regular `staging/<id>` (with `revisions/<id>` and `staging/.reclaim.<id>` `ENOENT`) with `OFlags::RDWR \| OFlags::NOFOLLOW` (no `OFlags::TRUNC`, zero `set_len(0)`), quarantining `revisions/<id>`, `staging/.reclaim.<id>`, or non-zero/non-regular `staging/<id>`, atomically binding `stage_claimed = true, payload_ino = fd_ino` under `LOCK_EX` in Step 2a and promoting into the standard `.reclaim.<id>` -> `'truncated'` -> Step 3 (`'anchor_pending_unlink'`) -> Step 4 sequence (leaving `payload_ino IS NULL` through Step 3 ONLY when `staging/<id>`, `staging/.reclaim.<id>`, and `revisions/<id>` are ALL already `ENOENT` with **ZERO `unlinkat`**), and explicitly testing (i) pausing a Case 2 claimant **before Step 2a** across `openmettle storage adopt` backfilling `payload_ino IS NOT NULL` (proving Step 2a returns `0` rows and aborts with **ZERO `unlinkat`**), (ii) pausing a Case 2 claimant **immediately AFTER the Step 2a commit** across `openmettle storage adopt` (proving `payload_ino` is already durably bound to `fd_ino`, and while the cleaner holds `LOCK_EX` adoption's `try_lock()` gets `WouldBlock`, clears `adoption_run_id = NULL` without quarantining/backfilling, and returns retryable `OMQ03`, whereas after cleaner crash/resume the bound `.reclaim.<id>` promotion and Step 3/Step 4 complete cleanly with zero quarantine or lost inode), and (iii) concurrent `openmettle storage adopt` acquiring non-blocking `OFlags::RDWR \| OFlags::NOFOLLOW` `LOCK_EX` across `payload_ino IS NULL` `'reserved'` backfill candidates through Phase 3C commit, Step 3 executing final `storage::release` with **ZERO filesystem I/O inside the DB transaction** setting `reclaim_state = 'anchor_pending_unlink'` when `payload_ino IS NOT NULL` while retaining `payload_ino`, and Step 4 detaching `staging/.reclaim.<id>` under **`OFlags::RDWR \| OFlags::NOFOLLOW` (no `OFlags::TRUNC`, zero `set_len(0)`)** + `LOCK_EX` (`unlinkat`) -> `drop` -> `fsync(&staging_dir_fd)` -> `reclaim_state = 'none'` PLUS **bounded DB-driven Step 4 retry pass across all reservation kinds (`storage_reservations_reclaim_anchor_idx`) with wrapping keyset cursor `reclaim_anchor_cursor` + pass-start fixed upper watermark `(upper_ts, upper_id)` starvation-prevention test** (planting persistent leading anomalous foreign-inode / `WouldBlock` anchors exceeding `LIMIT` ahead of trailing `ENOENT` rows AND continuously arriving `>= LIMIT` new `anchor_pending_unlink` rows per tick, proving the pass captures `(upper_ts, upper_id)` at pass start, constrains pages with `(closed_at, id) <= (upper_ts, upper_id)`, advances past every inspected key, and resets both `reclaim_anchor_cursor = None` and `pass_upper = None` on `< LIMIT` or reaching `(upper_ts, upper_id)` so earlier `WouldBlock` and trailing rows are revisited without starvation), AND (g) live directory-displacement tests covering displacement between `Store::stage` and `Store::publish`, post-`linkat`/pre-`commit` displacement + hard crash after rollback (exercising BOTH all-three `ENOENT` and foreign replacement regular file subcases, proving foreign replacement files are NEVER truncated/unlinked and `reserved_bytes` stays 100% charged under `adoption_unverified = true`), and `Store::read` pathname-to-FD re-verification failing closed (`Error::Io`) on displacement**; **mandatory `ReadWriteMany` multi-client Linux NFS shared-volume qualification tests covering BOTH two-client / separate-mount Linux NFS `flock(2)` coherence (explicitly exercising `'truncated'` reopen-and-`LOCK_EX`, Step 4, Stage C, and `StagingSweepState` via `OFlags::RDWR \| OFlags::NOFOLLOW` without `OFlags::TRUNC` and zero `set_len(0)` across two NFS clients with zero `EBADF`, plus `LOCK_SH` on `OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` vs `LOCK_EX \| LOCK_NB` `WouldBlock`, rejecting `-o local_lock=flock`/`local_lock=all`) AND stable 64-bit `st_ino` coherence + second-client recovery across clients and remounts (explicitly exercising differing client-local `st_dev` values to confirm zero `payload_dev` cross-node dependency)**; **directory `fsync` durability barrier and `artifact_fs::purge_due` leaf-verification + hard-link detach tests verifying (a) sentinel publication calls `fsync(root_fd)` strictly BEFORE creating/linking either `:revisions` or `:staging` (and `fsync(revisions_dir_fd)` / `fsync(staging_dir_fd)` before updating `storage_volume_control.volume_id`), (b) `Store::stage` Step 1b calls `fsync(&staging_dir_fd)` strictly BEFORE Step 1c binds `payload_ino`, (c) 3-stage `artifact_fs::purge_due` `ENOENT`/foreign replacement regular file test at `revisions/<id>` (`st_ino != payload_ino` or missing both `.purge.<id>` and `<id>`) proving Stage A stops immediately with ZERO `set_len(0)`, ZERO `unlinkat` (never touching `staging/<id>`!), and WITHOUT calling `storage::confirm_purge` (leaving `artifact_revisions.state = 'purging'` and `retained_bytes` 100% charged for `verify_accounting_drift` and `openmettle_owner` reconciliation), (d) 3-stage `artifact_fs::purge_due` (`revisions/.purge.<id>` + `purge_stage`) running *before* `StagingSweepState` when `staging/<id>` and `revisions/<id>` share `payload_ino` proving Stage A links `revisions/.purge.<id>` + unconditional `fsync(&revisions_dir_fd)` strictly BEFORE visible-name unlink of `revisions/<id>` and matching `staging/<id>` (pinning `payload_ino` at `nlink >= 1`, leaving any foreign `staging/<id>` untouched, and requiring BOTH `fsync(&revisions_dir_fd)` and `fsync(&staging_dir_fd)` before Stage B `confirm_purge` sets `state = 'purged', purge_stage = 'anchor_pending_unlink'`), followed by Stage C immediate + bounded `LIMIT` DB pass (`artifact_revisions_purge_anchor_idx`) detaching `revisions/.purge.<id>` under **`OFlags::RDWR \| OFlags::NOFOLLOW` (no `OFlags::TRUNC`, zero `set_len(0)`)** + `LOCK_EX` + `fsync(&revisions_dir_fd)` + `SET purge_stage = 'none'` PLUS **Stage C wrapping keyset cursor (`purge_anchor_cursor`) + pass-start fixed upper watermark `(upper_ts, upper_id)` starvation-prevention test** (planting persistent leading anomalous foreign-inode / `WouldBlock` `.purge.<id>` anchors exceeding `LIMIT` ahead of trailing `ENOENT` rows AND continuously arriving `>= LIMIT` new `anchor_pending_unlink` rows per tick, proving the pass captures `(upper_ts, upper_id)` at pass start, constrains pages with `(r.purged_at, r.id) <= (upper_ts, upper_id)`, advances past every inspected key, and resets both `purge_anchor_cursor = None` and `pass_upper = None` on `< LIMIT` or reaching `(upper_ts, upper_id)` so earlier `WouldBlock` and trailing rows are revisited without starvation)**; **unpinned/adopting DB-guard (`enforce_runtime_storage_volume_pinned` + `SECURITY DEFINER` `storage_lock_pinned_volume()`, `OMQ03`), zero-deadlock `storage_volume_control` concurrency, missing-row fail-closed, direct-`UPDATE`-denial (`42501`), non-owner quarantined-release guard, serialized `adoption_run_id` race, and `N` cleaner pre-unlink safety tests executed explicitly under actual runtime roles `SET ROLE openmettle_worker` and `SET ROLE openmettle_api` (both `INHERIT` and `NOINHERIT`/`SET ROLE` logins) covering (a) **concurrent two-release + two-reserve & healthy-pinned-volume execution test** under `SET ROLE openmettle_worker` and `SET ROLE openmettle_api` proving zero `42501` and zero deadlock under `storage_volume_control [via storage_lock_pinned_volume()] -> storage_accounts (FOR UPDATE) -> storage_instance (FOR UPDATE)` (runtime roles hold `SELECT`-only on `storage_volume_control`, never `UPDATE` it — asserting direct `UPDATE` returns `42501` for BOTH `openmettle_api` and `openmettle_worker` — and never take `storage_instance FOR SHARE`), (b) **missing `storage_volume_control` singleton row fail-closed test** under `SET ROLE openmettle_worker` and `SET ROLE openmettle_api` proving `enforce_runtime_storage_volume_pinned()` -> `storage_lock_pinned_volume()` raises `OMQ03` (not `42501`) when `storage_volume_control` has `0` rows, (c) **non-owner `reserved -> released` guard test on an `adoption_unverified = true` row** proving both keeping `adoption_unverified = true` (`CHECK (NOT adoption_unverified OR state = 'reserved')`) and clearing `adoption_unverified = false` (`enforce_storage_reservation_monotonic_guards()`, `OMQ03`) fail closed for `openmettle_api` and `openmettle_worker` while `openmettle_owner` releases cleanly in one `UPDATE` setting `state = 'released', adoption_unverified = false`, (d) exercising BOTH `SET ROLE openmettle_worker` (`reconcile_expired` and `purge_due`) AND `SET ROLE openmettle_api` (`N-1`'s unconditional `storage::release` `abort()`) — explicitly including `NOINHERIT` logins — while `storage_volume_control.volume_id IS NULL OR adoption_run_id IS NOT NULL`, proving `SECURITY INVOKER` `enforce_runtime_storage_volume_pinned()` delegating via `PERFORM openmettle.storage_lock_pinned_volume()` blocks release/purge with `OMQ03` (not `42501`) while normal `reserve` + `settle` uploads and active `openmettle_owner` reconciliation succeed, (e) **adoption Step 1b concurrency race tests exercising BOTH (i) a cleaner entering `storage::release` while Step 1b holds `storage_volume_control FOR UPDATE` uncommitted (proving strict `FOR SHARE` vs `FOR UPDATE` serialization with zero release passing the trigger before Step 1b and committing during Step 2, zero rows escaping Step 3's `'reserved'` set), AND (ii) a concurrent second adopter failing closed (`OMQ03`) during Step 2 without clearing Adopter 1's `adoption_run_id` (plus `--replace-adoption-run <stale_uuid>` stale recovery and Step 2 failure clearing `adoption_run_id = NULL` only `WHERE id AND adoption_run_id = $my_adoption_run_id`)**, AND (f) `N` cleaners run against existing on-disk payloads and empty replacement mounts while `volume_id IS NULL` or when any directory sentinel is missing/mismatched/FIFO/wrong-role/different-`st_dev`, failing closed with zero unlinks and zero DB mutations**; **post-pinning same-filesystem subdirectory-replacement & writerless FIFO `.openmettle-volume-id` sentinel tests proving `Store::open`, `openmettle-admin` adoption, `verify_accounting_drift`, and all worker cleaners open sentinels with `OFlags::RDONLY \| OFlags::NOFOLLOW \| OFlags::NONBLOCK` + `fstat` (`S_ISREG`) and fail closed immediately without blocking or unlinking**; **sentinel atomic `linkat` concurrency, crash/interruption, concurrent `begin_purge` retry, Step 3 `payload_ino` backfill, and populated-upgrade adoption tests covering (a) lost commit-ack adoption retry after replacing `<root>/revisions` (never writing a missing sentinel when `volume_id IS NOT NULL`, failing closed with `OMQ03`), (b) Step 3 canonical lock order (`storage_reservations -> artifact_revisions -> storage_volume_control -> storage_accounts -> storage_instance FOR UPDATE`) requiring `adoption_run_id = $my_adoption_run_id`, evaluating all `'active'`/`'retained'`/`'purging'` revisions and volume checks BEFORE writing any `payload_ino`, committing `payload_ino` backfills (`WHERE payload_ino IS NULL`) ONLY in the success branch, quarantining missing/mismatched `'reserved'` rows (`adoption_unverified = true`) on BOTH initial unpinned and already-pinned runs, pinning `storage_volume_control.volume_id`, and clearing `adoption_run_id = NULL`, (c) **adoption crash-boundary & cross-reservation inode uniqueness & legacy mid-purge Cases 6a/6b tests**: (i) **cross-reservation live inode uniqueness test** with both a legacy `'reserved'` row `A` (`payload_ino IS NULL`) and a previously quarantined `adoption_unverified = true, payload_ino IS NULL` row `A'` whose `staging/<id>` is a hard link to active `revisions/B` (or a `'purged'` revision with `purge_stage = 'anchor_pending_unlink'`) of matching byte size proving `openmettle storage adopt` fails closed with `cross_reservation_inode_alias`, performs zero `payload_ino` backfills, NEVER writes `payload_ino` onto any row staying `adoption_unverified = true`, and leaves `revisions/B` intact (plus `intra_reservation_inode_mismatch` / `foreign_staging_collision`), AND a **retired historical inode reuse test** proving re-adoption succeeds cleanly when a new active revision reuses the retired `payload_ino` of an already-released (`state = 'released' AND reclaim_state = 'none'`) or already-purged (`state = 'settled'` with `artifact_revisions.state = 'purged' AND purge_stage = 'none'`) reservation whose last anchor has already been detached, (ii) **legacy mid-purge (`state = 'purging', payload_ino IS NULL`) Cases 6a & 6b tests**: Case 6a requiring **exact recorded `st_size == size_bytes` AND `sha256 == content_digest`** to backfill `payload_ino` on surviving `revisions/<id>` (explicitly testing a partial restore with a `0`-byte `revisions/<id>` for a non-empty `size_bytes > 0` legacy `sr.payload_ino IS NULL` `'purging'` row rejecting adoption with `size_or_digest_mismatch` — reserving the `st_size == 0` Stage A crash exception strictly for already-bound `sr.payload_ino IS NOT NULL AND st_ino == sr.payload_ino` — and rejecting `foreign_staging_collision`), and Case 6b directly completing already-absent legacy `'purging'` (`state = 'purged', purge_stage = 'none'`) + decrementing `retained_bytes` (rejecting `ambiguous_legacy_purging_staging_survivor` if `staging/<id>` exists while `revisions/<id>` is `ENOENT`) while proving Case 6b absent rows **NEVER count as positive on-disk file evidence** toward volume-identity verification (still requiring positive `'active'`/`'retained'`/Case 6a SHA-256-verified payloads + `--expected-fs-uuid` / `--expected-revisions-inode`, or `--confirm-no-on-disk-payloads` when zero on-disk payloads exist), AND (iii) **explicit crash-injection boundary tests** at each boundary (`claiming` + `.reclaim.<id>` with coexisting `staging/<id>`/`revisions/<id>` **kept as `'claiming'` with `reclaim_lease_until = clock_timestamp()` — NEVER promoted to `'truncated'`, so resumed Step 2 repeats directory syncs and detaches surviving visible names**, already-`'truncated'` + `.reclaim.<id>` requiring `staging/<id>` and `revisions/<id>` `ENOENT` and rejecting with `truncated_visible_name_present` if visible names exist while keeping `'truncated'` with `reclaim_lease_until = clock_timestamp()` when `ENOENT`, already-bound `payload_ino IS NOT NULL` `purging` + `0`-byte `revisions/<id>` before `.purge.<id>`, `purging` + `.purge.<id>` after `unlinkat(revisions/<id>)`, and `purged` + `anchor_pending_unlink` + `.purge.<id>`) verifying `verify_accounting_drift` reports zero false drift, `openmettle storage adopt` verifies/preserves them cleanly without rejecting, and runtime cleaners/`purge_due` resume them to completion!, (d) **failed unpinned adoption on a partial copied tree** (containing legacy revision A's copy with a new inode and missing revision B) proving ALL `payload_ino` backfills are omitted/rolled back so retrying adoption on the real original directory tree succeeds cleanly with A's real inode, (e) concurrent `begin_purge` (`'retained' -> 'purging'` + unlink) during already-pinned adoption retry (fresh `READ COMMITTED` re-query accepting `'purging'`/`'purged'`), (f) `storage::reserve` racing Step 2 empty-ledger check -> Step 3 `storage_volume_control FOR UPDATE`, (g) two concurrent fresh-bootstrap `Store::open` publishers serializing on `storage_volume_control FOR UPDATE`, (h) crash after `.openmettle-volume-id.tmp.<128bit_random_hex>` or subset sentinel linking recovering idempotently, and (i) populated-upgrade, mixed-reservation (`--expected-fs-uuid` + `--expected-revisions-inode`), and reservation-only (`--confirm-no-on-disk-payloads`) acceptance tests proving quarantined `adoption_unverified = true` rows stay charged and excluded from all cleaners until `openmettle_owner` reconciliation or verified adoption on the restored tree**; **persistent 5-state zero-truncation `StagingSweepState` `ReadDir` `staging/` cleanup tests covering (a) multi-tick enumeration resuming from parked open `dir_fd`, verifying **ZERO `set_len(0)` calls in ANY branch of `StagingSweepState`** (all entries opened `OFlags::RDWR \| OFlags::NOFOLLOW` explicitly WITHOUT `OFlags::TRUNC`, preserving ZERO `set_len(0)` calls in ANY branch): on `'released'` `staging/<id>`, skipping 100% untouched whenever `payload_ino IS NOT NULL` (even if an inode number is reused!), `adoption_unverified = true`, or `st_size > 0`, and calling `LOCK_EX` -> `unlinkat` ONLY (never `set_len(0)`) -> `drop` -> `fsync(&staging_dir_fd)` when `payload_ino IS NULL AND NOT adoption_unverified AND st_size == 0`; on `staging/.reclaim.<id>`, skipping `'reserved'` untouched, detaching `('released', 'anchor_pending_unlink')` under `LOCK_EX` (`unlinkat` ONLY, never `set_len(0)`) -> `drop` -> `fsync(&staging_dir_fd)` -> `reclaim_state = 'none'` (verifying `st_size == 0` and `st_ino == payload_ino`), and detaching aged `> 900 s` `0`-row / `('released', 'none')` / `'settled'` `.reclaim.<id>` entries under `LOCK_EX` + DB serialization (`storage_lock_pinned_volume()` + `storage_instance FOR NO KEY UPDATE`) via `unlinkat` ONLY (ZERO `set_len(0)`), (b) **extended two-artifact hard-link & `'settled'` `payload_ino` tests**: (i) `staging/A` hard-linked to active `revisions/B` while `revisions/A` matches `A.payload_ino` (`staging_ino != A.payload_ino`) preserves BOTH `staging/A` and `revisions/B` untouched (`verify_accounting_drift` flags `staging/A`), (ii) **missing `A` row (`0` rows in `storage_reservations`, aged `> 900 s`) with `staging/A` hard-linked to active `revisions/B`**, AND (iii) **unowned anchor `staging/.reclaim.<untracked_uuid>` (`0` rows, aged `> 900 s`) hard-linked to active `revisions/B`** — proving `StagingSweepState` detaches the `staging/` alias with **ZERO `set_len(0)` calls** and `revisions/B` retains 100% of its bytes and SHA-256!; skipping `adoption_unverified = true` or `payload_ino IS NULL`; and on `'settled'` with `staging_ino == payload_ino`, calling `LOCK_EX` -> `unlinkat` ONLY (NEVER `set_len(0)`) -> `drop` -> `fsync(&staging_dir_fd)` strictly ONLY when `artifact_revisions.state IN ('active', 'retained')` AND live `revisions/<id>` is `S_ISREG` on same local `st_dev` with `rev_stat.st_ino as u64 == payload_ino` (NEVER unlinking `staging/<id>` once `artifact_revisions.state IN ('purging', 'purged')`), (c) `LOCK_SH`-held active pre-commit `staging/<id>` skip + `st_mtime > 900 s` + `storage_lock_pinned_volume() -> storage_instance FOR NO KEY UPDATE` serialized zero-row orphan recheck (`unlinkat` strictly WITHOUT `set_len(0)`), (d) `spawn_blocking` slice exceeding 15 s `tokio::time::timeout` parking `InFlight` cleanly across ticks, and (e) `<root>/staging` replacement during `InFlight` (`InvalidatedInFlight`) and `DrainingEof` preventing inode reuse via retained open `dir_fd`**; restore and periodic drift verification (`verify_accounting_drift` + `openmettle.quota_verify_accounting_drift()`) **including concurrent `begin_purge` interleaving (fresh `READ COMMITTED` re-query yielding zero false hard drift), failing hard once `storage_volume_control.volume_id IS NOT NULL` on any `'active'`/`'retained'` revision with `payload_ino IS NULL` or on-disk `payload_ino` mismatch, recognizing `staging/.reclaim.<id>` (`st_size == 0`, `st_ino == payload_ino`, paired with `('reserved', 'claiming' \| 'truncated')` or `('released', 'anchor_pending_unlink')`), `revisions/.purge.<id>` (`st_size == 0`, `st_ino == payload_ino`, paired with `'purging'` or `('purged', 'anchor_pending_unlink')`), and all valid `'purging'` Stage A crash states (`revisions/<id>` at `size_bytes` or `0` bytes, or `revisions/.purge.<id>` at `0` bytes, while flagging hard drift if BOTH `revisions/<id>` and `revisions/.purge.<id>` are `ENOENT` after fresh `READ COMMITTED` re-query confirming `state <> 'purged'`) as valid, skipping filesystem checks on storage-disabled installations (`ARTIFACTS_DIR` unset, `volume_id IS NULL`, `0` storage rows), and validating DB/`0023` drift via the exact ascending fold across `a.revision <= qr.accepted_source_revision` (`ORDER BY a.revision ASC`, `K_known`/`X_known` included reasoning lower bound, `numeric(38, 0)` past `bigint` max), simplified `pending_gateway_reconciliations`, and `gateway_settlements` joined to `gateway_usage_reports` strictly on `(gs.request_id = r_curr.request_id AND gs.revision = r_curr.revision AND gs.final = r_curr.final)` reading `r_curr.source` and `r_curr.report_id` from `r_curr`**; and populated previous-writer rolling-upgrade test with a lowered `storage_bytes` override proving fail-closed refusal (`OMQ01`) on old `storage::reserve` while `settle`/`release`/`retain`/`purge` succeed. |
| PR3 · `/v1` API, OpenAPI and wired enforcement | `/v1` quota read (with `warnings` projection) and `ManageQuotas` routes (gated on rolling-upgrade completion via `quota_enforcement.overrides_enforced` / `overrides_enforced_at`, seeded `true` only on fresh `0 -> 26` bootstraps and `false` across `<= 25 -> 26` upgrades even when `metering_enforced` was already `true` so override writes stay refused with `503 provisioning` until `N-1` pods drain and `openmettle-admin quota activate` runs), OpenAPI 3.2.1 schemas (defining dedicated `WideNonNegativeDecimal` — `type: "string"`, `minLength: 1`, `maxLength: 38`, `pattern: "^(?:0\|[1-9][0-9]{0,37})$"` — for `QuotaSummary`'s wide `numeric(38, 0)` counters while keeping `NonNegativeDecimal` `0..=9223372036854775807` untouched for `bigint` fields) and regenerated `contracts/fixtures/`, independent consumer decoding, and wired quota enforcement in `src/v1/artifacts.rs`, `admit_run`, `claim_next` and ADR 0037 settlement paths. | Contract validation (`tests/contract.rs`) and PostgreSQL 18 HTTP tests on both session channels covering **end-to-end `/v1` `QuotaSummary` HTTP route + OpenAPI `WideNonNegativeDecimal` (`^(?:0\|[1-9][0-9]{0,37})$`) schema validation on an oversized 3-column token report (`prompt_tokens + completion_tokens + reasoning_tokens > 9_223_372_036_854_775_807`, while keeping `NonNegativeDecimal` `i64::MAX` bounds intact)**, effective limits/usage/reservations/warnings visibility, warning deduplication and re-arming on override/config edits, concurrent `/v1` `setQuotaOverride` lowering of `executing_runs_*` caps racing `claim_next`, `404` concealment for non-members and non-member admins, audited override changes and replay conflicts, safe `429 quota` / `429 rate_limited` / `503 provisioning` RFC 9457 problems with redaction canaries, and allowed reads, downloads, cancellations and deletions at hard limit. |

**Boundaries.** V1-15 (`#15`) and V1-16 (`#16`) own artifact payload transport, retention
policies and deletion journals. V1-06 (`#7`, ADR 0037) owns Migration `0023`, gateway admin
provisioning and authoritative usage feed ingestion. V1-14 (`#14`, ADR 0039) owns MCP tool
schemas, spill triggers, companion 1-row `openmettle.runtime_feature_gates (id boolean PRIMARY
KEY DEFAULT true CHECK (id), two_phase_effect_intents_enabled boolean NOT NULL DEFAULT false)`
(`GRANT SELECT` to `openmettle_api, openmettle_worker`), and exclusive automatic cleanup of
`operation_id IS NOT NULL AND idempotency_key LIKE 'tool-spill:%'` `storage_reservations` rows
via `reconcile_run_spills` (sequenced on V1-17 PR2's `storage_volume_control` / `dirfd` /
`payload_ino` / `linkat` / 4-step cleaner foundation, while ADR 0040's generic run-linked cleaner
owns the exact logical complement `(operation_id IS NULL OR idempotency_key NOT LIKE
'tool-spill:%')`). V1-18 (`#18`) owns the active GPU controller, DRA claims and physical VRAM
handoffs. V1-29 (`#26`) owns telemetry contract updates when PR2/PR3 register quota metrics.

## Amendment (24 November 2026): rebind after a file-copy restore

Refs #27, #16. Delivered with `openmettle-admin storage rebind`
([`src/artifact_fs/rebind.rs`](../../src/artifact_fs/rebind.rs)); the operator procedure is
[Restore the artifact volume](../operator/restore-artifact-volume.md).

**Problem.** [Architecture backup and restore](../../ARCHITECTURE-v1.md#backup-and-restore)
restores by file copy into fresh volumes. A copy keeps every byte and the volume sentinels and
creates new files, whose inode numbers usually differ from the originals and can be equal by
chance. This record pins each payload to `payload_ino` and recognised only the "restored
original directory tree", so on a copied volume every read, release and purge of an existing
reservation failed closed, start-up accepted the volume, and no supported step recovered it.
The owner decided on 24 November 2026 to keep file-copy restores and add a supported rebind
step.

**Amended invariant.** "Once bound, `payload_ino` is strictly write-once and never mutated"
now reads: the owner-run rebind may replace a bound `payload_ino`, under the adoption barrier,
on content or empty-file evidence. Every runtime role stays write-once, and `payload_ino` is
still never written from an unverified tree. The schema already allowed this:
`enforce_storage_reservation_monotonic_guards()` has always exempted `openmettle_owner`. The
amendment makes one bounded procedure supported; it does not loosen the database, and it ships
no migration.

**Evidence.** An inode number is never evidence: an equal number does not show that a file was
not copied. Rebind accepts a file on exactly one of two grounds, whether or not its number
changed.

- *Content.* For a revision in `active` or `retained`, or in `purging` with its bytes still
  present: `revisions/<id>` has the ledger's `size_bytes` and SHA-256 `content_digest`.
- *Empty file.* For every other bound reservation that owns a file (an unsettled upload, a
  reclaim or purge anchor, a truncated purge): the file is empty. This is the evidence
  `reclaim::release` already requires before it binds a file it did not create.

The ledger holds no size or digest for an unsettled upload, and no writer survives a restore
to settle it: a claimed reservation cannot be resumed by a retry, and a spill uses a fresh
reservation per attempt. Rebind therefore discards those bytes. It truncates the file, binds
the row to the emptied file and clears `publish_pending`. The row stays `reserved` and charged
until the reconciler releases it under its normal lease, run and operation rules. Nothing that
was acknowledged before the recovery point is touched, and nothing unsettled becomes settled.
Rebind is a post-restore command: on a volume that was not copied it verifies settled payloads
and leaves them as they are, and it still empties interrupted uploads.

A file is truncated only when no other reservation shares its inode and its link count equals
the number of that reservation's own names. Both, and the exact names the reservation owns,
are checked again on the descriptor immediately before the truncation. Rebind detects only
what these checks can see; that no restore, repair or other process touches the volume during
the run is an operator precondition.

**Procedure invariants.**

- Owner login, a pinned volume and matching sentinels are required. Rebind takes the same
  `adoption_run_id` barrier as adoption, so runtime storage operations fail closed while it runs.
- It scans without SQL locks and keeps no descriptor between steps. It then applies in one
  transaction that locks `storage_reservations`, `artifact_revisions` and
  `storage_volume_control` (a prefix of adoption's order), requires the scanned ledger and
  files unchanged, and reopens, locks and revalidates each file before acting on it.
- Every name of a reservation is validated against its lifecycle state, with the layouts the
  drift check accepts. Results are per reservation. A reservation that verifies is rebound and
  committed. One that does not is left untouched and reported with its reason; an open error
  that concerns one file (a wrong mode, an I/O error) is such a failure, not a refusal of the
  run, while lock contention, an identity change and descriptor exhaustion refuse the run.
  Rebind writes no accounting row.
- A reservation that never recorded an inode is validated too and never bound. One with bytes
  under its staging name is reported as a warning that does not keep the barrier: the
  reconciler quarantines it when it expires, as on a running system.
- Before the commit, every accepted file, whatever its inode number, and the root, `staging/` and
  `revisions/` directories are synced.
- **Rebind never releases the barrier on a volume with a file mismatch.** Its last step,
  inside the same transaction, is the verification that `openmettle-admin quota verify ROOT`
  performs. The barrier is released only when every reservation verified and that
  verification finds no file mismatch: no recorded inode, size or digest that disagrees with a
  file, and no name the lifecycle does not allow. Otherwise the run keeps it, and the volume
  stays closed until a later run that names the barrier completes.
- Quarantined reservations and accounting drift that is not a file mismatch do not keep the
  barrier. A running system tolerates both, and a restore must not turn a state the system
  tolerated before the backup into a volume that cannot reopen. Rebind reports them, with the
  quarantined reservation ids, leaves them unchanged and exits 0 if nothing else failed.
- A refused run (wrong login, unpinned volume, a locked payload, a changed ledger) changes no
  file and no row and hands the barrier back as it found it. Once a run has started to empty
  a file, any later failure keeps the barrier and reports its value. The rule above therefore
  holds for a run that reached its apply step: a run refused before any write restores the
  barrier it found, even if its scan had already seen a damaged payload.
- A commit that gets no answer is indeterminate. Rebind then claims neither barrier state: it
  reports the value it used and directs the operator to read `adoption_run_id`.
- A `storage adopt` that is refused or fails verification hands the barrier back as it found
  it, so it cannot release a barrier that an incomplete rebind holds. A successful adoption
  clears the barrier as before. A replacement
  UUID can take over a run that is still scanning; the takeover fences that run's apply
  (`adoption ownership changed`). No liveness check is added.
- It does not repair a copy that split hard links, bind a reservation that never had an inode
  (adoption's task), or clear a quarantine.
- The API and worker sample up to 16 live settled revisions before any artifact work and
  refuse the volume when a published name carries another inode than the ledger. The check
  runs in the path every store operation takes, so a process whose start-up check could not
  complete repeats it until it has passed once. It cannot refuse a healthy volume and can
  miss a copied one. The start-up refusal and `quota verify ROOT`, which is refused the same
  way, name `storage rebind`. `storage rebind` and `storage adopt` are not behind the check.

**Restore validation.** The filesystem drift check (`openmettle-admin quota verify ROOT`) is the
required post-restore check. `quota_verify_accounting_drift()` alone compares no file and
reports a copied, unbound volume as healthy.

**Consequences and known gaps.** A settled payload that cannot be recovered keeps the volume
closed until the owner resolves that row by hand; a supported step to declare a payload lost
does not exist yet. A quarantined reservation stays quarantined, and `quota verify ROOT` stays
unhealthy for it as it was before the backup. A worker that got past the start-up check
before rebind can quarantine unsettled uploads, which rebind leaves quarantined. Only `cp -a`,
GNU `tar` and restic 0.14 copies were exercised; Velero, NFS and CSI snapshots were not.
