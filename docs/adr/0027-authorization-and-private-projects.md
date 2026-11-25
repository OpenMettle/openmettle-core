# 0027 — Central authorization policy and private-by-default projects

Status: accepted with its implementation; V1-05 increments 1–3, 4a and 5 (19 November 2026) and 4b (20 November
2026). Agent-authored; implements the owner decisions recorded on #6. Owner approval of this
record, independent review and CI acceptance are separate gates. Refs #6 and #34. #6 remains
open.

## Problem

ARCHITECTURE-v1.md requires private accounts and resource permissions, projects whose
membership never publishes a member's private history or memory, and an application
administrator who gains no implicit access to private content. ADR 0006 stores grant
assignments with opaque vocabulary and requires V1-05 to reject unknown vocabulary rather
than infer permission. ADR 0021 records login-time project membership evidence. Neither
decides access.

This increment adds `src/authz.rs`: one pure policy evaluator with no I/O, persistence,
route or enforcement point. Later increments hydrate its inputs and call it:

| Increment | Scope |
| --- | --- |
| PR1 (this) | Policy evaluator, vocabulary parser, this record. No migration, route or dependency. |
| PR2 | Migration 15: local groups, project-role and resource-grant writers, capability denies, `account_admin`, audit table and worker grants. |
| PR3 | Principal hydration per request; admin and membership API with audit. |
| PR4a | Migration 16 group and project-wide grantees; project, membership and share store. |
| PR4b | Project, conversation and artifact routes enforcing the evaluator. |
| PR5 | Worker execution-time recheck and run invalidation. |

## Principal

`Principal` is hydrated from the **primary** database for every request and every
execution-time recheck. It is never cached in a session cookie, token or process memory, so
a revocation applies to the next request. It holds only stable internal identifiers: user
UUID, personal scope UUID, local group IDs, OIDC group IDs and capability names. Emails,
display names and raw claims are excluded.

`is_active` requires an enabled user, an active unexpired identity approval and a provider
that is not retired at its current authority epoch (ADRs 0012 and 0013). An inactive
principal is refused before any grant is read (`InactivePrincipal`, 401 `unauthenticated`).
A request with no principal is `Unauthenticated`.

## Groups

Local groups and OIDC groups are separate namespaces (`Grantee::LocalGroup`,
`Grantee::OidcGroup`). A local group with the same identifier as an OIDC group, or a group
with the same identifier as a user, grants nothing across namespaces. Groups are
**non-nested**: a principal carries a flat set of direct memberships and no group is a member
of another group. An OIDC group appears in the principal only with current `Present` ADR 0021
evidence.

## Grant vocabulary

`GrantVocabulary::parse(format, version, key)` is the only interpretation of ADR 0006
`(assignment_format, assignment_version, assignment_key)`. Matching is exact, with no
trimming, case folding, prefix or numeric coercion.

| Format | Version | Key | Meaning |
| --- | --- | --- | --- |
| `openmettle.project-member` | 1 | Canonical lowercase approval UUID (ADR 0021) | `Viewer`, never more |
| `openmettle.project-role` | 1 | `viewer`, `editor`, `owner` | That project role |
| `openmettle.resource-grant` | 1 | `read`, `write` | That resource access; `write` implies `read` |

Any other format is `UnknownFormat`, another version `UnsupportedVersion` and another key
`UnknownKey`, including NUL bytes, padding and other case. A project role on a resource
target, or resource access on a project target, is `WrongTarget`. Hydration omits every row
that fails, so an invalid row grants nothing; it is never defaulted.

An assignment is effective only if its current ADR 0006 head is an active grant
(`recorded_active`) and, for a mapped origin, its ADR 0021 observation is `Present`. Every
other observation, including `Stale` and `Failed`, is inactive.

## Project roles

`Owner > Editor > Viewer`. Among effective allow grants (direct, local group, OIDC mapped) the
**highest role wins**. There are no per-project or per-resource denies in V1-05.

| Action | Viewer | Editor | Owner |
| --- | --- | --- | --- |
| Read, stream, search, download project metadata | yes | yes | yes |
| Read items explicitly shared with them | yes | yes | yes |
| Write, create in scope, start runs | no | yes | yes |
| Share or unshare **own** conversation/artifact | no | yes | yes |
| Share or revoke on a project-shared item they can see | no | no | yes |
| Project settings, instructions, defaults | no | no | yes |
| Manage members and roles; delete or transfer project | no | no | yes |

A viewer's effective resource access is capped at `Read` whatever a share row says. A
creator demoted to viewer keeps read access to their own items and loses edit and share.

The project must keep at least one owner. `authorize_member_change` refuses removing or
demoting the last **distinct user with an active direct `Owner` grant**. Group and mapped
owners do not count, because they can lapse without an owner action. PR3 hydration filters
disabled user accounts out of `Project.grants` (or counts enabled direct owners
transactionally) so a disabled user cannot satisfy the last-owner invariant. Transfer is: add
the new direct owner, then step down.

## Private by default

Every conversation, artifact and memory record starts private to its creator. Project
membership alone never publishes a member's private conversations, artifacts or memory. Even
a project owner cannot read another member's unshared item. Memory, tools and connections are
not shareable in V1-05: share rows on those kinds are ignored and new shares are refused.
Publishing memory into shared project memory is a separate future action.

Personal-scope items belong to their scope owner. The owner can share them directly with a
user or with a local or OIDC group. Sharing never changes accounting ownership, and non-owners
cannot execute runs (`RunExecute`) inside another user's personal scope even with a `Write`
share. A project-wide share is invalid outside a project and grants nothing.

### Sharing inside a project

- The creator, holding `Editor` or `Owner`, can share or unshare their own item with another
  member, a group or the whole project.
- A project owner can also share or revoke on items already visible to them through a share.
- An editor cannot reshare another person's item. A viewer cannot share anything.
- The grantee must hold **active project membership** when the share is created: a user
  grantee is evaluated from their own hydrated principal; a group grantee must itself hold an
  effective project grant in the same namespace.
- On every access the caller's current membership is evaluated first. If it has lapsed
  through direct removal, local group removal or OIDC revocation or staleness, every item in
  that project is concealed, including the caller's own items, even if share rows remain.
  Likewise, a group share inside a project is effective only while that group still holds
  active project membership, even if the caller holds a separate direct grant on the project.
- Revocation does not require the grantee to remain a member, so share managers can always
  retire stale rows.

## Concealment and ADR 0007

| Denial | Status and code | When |
| --- | --- | --- |
| `Unauthenticated`, `InactivePrincipal` | 401 `unauthenticated` | No principal; disabled account, withdrawn approval or retired provider |
| `NotFound` | 404 `not_found` | Non-member, cross-user, cross-project or unshared private target |
| `Policy(_)` | 403 `policy` | Target visible to the caller but action not permitted; admin actions; capability denies; last-admin or last-owner refusal; forbidden share |

`PolicyReason` is internal for audit and tests. Callers emit only the ADR 0007 code. A caller
first learns existence through a visible grant; a share manager attempting a share on an item
they cannot see receives `NotFound`, not `Policy`.

## Account administration

`account_admin` can manage accounts, local groups, user capability denies and quotas or
overrides, and promote or demote other account administrators. It is never consulted for
project, resource, memory, run or share decisions, so it confers **no** implicit
read, write, stream, search, download or run access to another user's private projects,
conversations, artifacts or memory. An administrator who is also a project member has exactly
that member's access. Directory roles never map to `account_admin`.

Five guardrails apply:

1. **Bootstrap and break-glass** remain `openmettle_owner` `psql` operator scripts outside
   the application API (PR2).
2. **Last enabled administrator.** Demoting or disabling an enabled `account_admin` is
   refused when the transactionally counted enabled administrators number one or fewer. PR3
   counts them on the primary under the lock that serializes admin changes and applies the
   change in the same transaction.
3. **Append-only audit.** Every admin, membership, share and capability change records actor,
   target, reason, request key and timestamp in an append-only table (PR2 schema, PR3–PR5
   writers). Rows are never updated or deleted by the application roles.
4. **Immediate revocation** follows from per-request primary hydration.
5. **Content isolation** as above, covered by negative tests for every resource kind and
   action.

### Canonical lock order and serialization for administrative writes

Every `openmettle_api` administrative write (`src/authz/store.rs`, `src/quotas.rs` scope
overrides, and `openmettle.retention_set_grace` from migration 38) and every concurrent
project, share, conversation, branch, run, session or gateway path acquires row locks in one
strict global order so administrative writes serialize with demotion, user disablement,
approval withdrawal and provider retirement without wait cycles:

```text
account_admin_lock
  -> projects
  -> login_providers
  -> local_identity_approvals
  -> users (ascending id when locking two rows)
  -> domain targets (local_groups | family_policies | retention_policy | storage_volume_control -> run_dispatch_lock -> storage_accounts | quota_budgets)
  -> runs (ORDER BY id)
```

Each path takes only the prefix it needs:

| Path | Row-lock sequence |
| --- | --- |
| `authz::store` writes (account admins, user lifecycle, local groups, platform/user capability flags, family policies) | `account_admin_lock FOR UPDATE` -> actor `login_providers FOR SHARE` -> actor `local_identity_approvals FOR SHARE` -> `users` (actor `FOR SHARE` plus any target user `FOR SHARE` or `FOR NO KEY UPDATE` in ascending `id` order; same-user disable/enable locks once `FOR NO KEY UPDATE`) -> target `local_groups` / `family_policies` -> `runs ORDER BY id FOR NO KEY UPDATE` (user disable only) |
| `quotas::set_scope_override`, `quotas::revoke_scope_override` (and SQL `quota_lock_override` from migration 38) | `account_admin_lock FOR UPDATE` (`FOR NO KEY UPDATE` in SQL) -> fast fail-closed admin pre-check (no target locks held for non-admins) -> `projects FOR NO KEY UPDATE` (project scope only) -> actor `login_providers FOR SHARE` -> actor `local_identity_approvals FOR SHARE` -> `users` (personal scope owner `FOR NO KEY UPDATE` and actor `FOR SHARE` in ascending `id` order, or once `FOR NO KEY UPDATE` when identical) -> `storage_volume_control FOR SHARE` (`storage_lock_not_adopting`) -> `run_dispatch_lock FOR NO KEY UPDATE` (`executing_runs_*` only) -> `storage_accounts FOR UPDATE` or `quota_budgets ORDER BY window_start, id FOR NO KEY UPDATE` |
| `openmettle.retention_set_grace` (migration 38, 5-arg approval-bound) | `account_admin_lock FOR UPDATE` -> actor `login_providers FOR SHARE` -> actor `local_identity_approvals FOR SHARE` -> actor `users FOR SHARE` -> `retention_policy FOR UPDATE` -> `authorization_audit` insert -> final live authority check |
| Project, share and conversation writes (`authz::projects`, `authz::branches`, `authz::runs`) | `[account_admin_lock FOR SHARE]` (two-user non-admin paths: `set_project_member_role` for distinct user grantee, and `lock_scope_actor` when `actor != personal_owner`) -> `projects FOR NO KEY UPDATE` (project scope only) -> actor `login_providers FOR SHARE` -> actor `local_identity_approvals FOR SHARE` -> `users` (ascending `id` order when locking two rows: actor `FOR SHARE` plus target user `FOR SHARE` on `set_project_member_role`; owner `FOR NO KEY UPDATE` plus actor `FOR SHARE` on `create_branch` / `prepare_turn` in personal scope; owner `FOR NO KEY UPDATE` when actor is owner else actor `FOR SHARE` for personal shares and conversation creates) -> target `local_groups` / `branch_heads FOR NO KEY UPDATE` / `runs ORDER BY id FOR NO KEY UPDATE` (archive/delete) / `quota_budgets` (run admission) |
| Gateway handoff and proxy dispatch (`gateway_handoff_round`, `gateway_dispatch_scoped`) | `account_admin_lock FOR SHARE` -> `projects FOR SHARE` -> `login_providers FOR SHARE` -> `local_identity_approvals FOR SHARE` -> `users FOR SHARE` -> `runs FOR SHARE` -> `gateway_reservations` -> `gateway_requests` |
| Standalone revocations and session paths | `sessions::disable_user`: single `users FOR NO KEY UPDATE`; `identity-approval-change.psql`: single `local_identity_approvals FOR UPDATE`; provider retirement/recovery: single `login_providers FOR UPDATE`; `sessions::validate`: `login_providers -> local_identity_approvals -> users -> local_sessions` (all `FOR SHARE`) |

Four invariants make this order deadlock-free and race-free:

1. **Multi-row `users` locks follow ascending UUID order, and rolling upgrades serialize two-user non-admin paths on `account_admin_lock FOR SHARE`.**
   Every write that locks two `users` rows (`authz::store` user-targeted writes, personal-scope
   quota overrides in both Rust and `quota_lock_override`, `projects::set_project_member_role` for
   user grantees, and `runs::lock_scope_actor` for collaborator branch writes on shared personal
   conversations) acquires them in ascending `users.id` order (taking the stronger lock once when
   both sides name the same user). Two-user non-admin writes (`actor != second_user`) also acquire
   `account_admin_lock FOR SHARE` first so concurrent collaborator writes run in parallel with each
   other while serializing cleanly against `N-1` (schema-37) API binaries running unordered
   `disable_user` during a rolling upgrade.
2. **`openmettle.users` lifecycle writers use `FOR NO KEY UPDATE`, never `FOR UPDATE`.**
   Account lifecycle mutations (`store::disable_user`, `store::enable_user`, `sessions::disable_user`)
   never update or delete primary key `users.id`. Using `FOR NO KEY UPDATE` still conflicts with
   `FOR SHARE`, `FOR NO KEY UPDATE` and `FOR UPDATE` (preserving full serialization with authority
   and scope locks) while admitting PostgreSQL's `FOR KEY SHARE` foreign-key checks from concurrent
   `grant_assignments` and `storage_reservations` inserts (`projects::share_change`, fenced worker
   tool spills holding `runs`).
3. **Project locks precede actor authority locks, and quota overrides fail fast for non-admins.**
   Quota overrides on a project scope lock `projects FOR NO KEY UPDATE` before
   `login_providers -> local_identity_approvals -> users(actor)`, matching `authz::projects`,
   `authz::branches`, `runs::admit_run` and gateway handoff/dispatch so an administrator modifying
   quotas on a project while acting inside that project cannot form a `projects`/`users` cycle.
   Both Rust `quotas.rs` and SQL `quota_lock_override` perform a fast read-only administrator check
   under `account_admin_lock` before locking any target `projects` or personal `users` row so
   unprivileged callers fail immediately (`42501` / `Denied`) without stalling `account_admin_lock`
   on contended target locks.
4. **Post-lock and post-write full authority re-verification.**
   Every administrative, project, share, conversation, branch, quota-override and run-admission
   write advances its decision clock monotonically to the primary's post-lock `clock_timestamp()`
   (`caller_now_ms.max(post_lock_ms)` in Rust and session-bound run admission; `clock_timestamp()`
   directly in SQL `retention_set_grace`) before judging authority, and re-verifies the **complete
   live authorization predicate** (active user, active unexpired approval, non-retired provider,
   live local groups, live OIDC `membership_observations`, project role, resource share and
   recipient eligibility, input attachment readability, required capabilities, originating session,
   and family policy for new run admissions and newly backfilled queued replay holds) after the
   **very last blocking SQL write** in the transaction (`apply`, `set_direct`, `insert_branch`,
   `publish`, `authorization_audit` insert, `quota_upsert_scope_override` /
   `quota_revoke_scope_override`, `reserve_admitted_run_budget` / `backfill_replayed_run_budget`,
   including when a queued replay backfill hits a quota refusal) immediately before commit.
   Role and share mutations restore only the changed grantee's pre-write direct assignment when
   re-checking post-write authority so newly written roles or shares cannot self-authorize while
   valid self-demotions, group self-demotions and share revocations remain permitted.

## Capabilities and explicit denies

Explicit denies exist only at **platform and user capability level**, for example family
controls denying `web_search` or `runs.use_yolo`. A deny at either level always wins, including
over an assignment and for an `account_admin`. Opt-in capabilities such as `runs.use_yolo` also
require an explicit user assignment; administration does not imply them. Capability names are
lowercase ASCII, digits, `.`, `_` and `-`, at most 128 bytes; anything else is refused.
Per-project and per-resource explicit denies are **out of scope** for V1-05.

`Decision::caller` maps a decision onto the existing `capabilities::Caller`: `Allow` is
`Visible(Allowed)`, a policy refusal is `Visible(Denied)` and a concealed or inactive outcome
is `Hidden`. Existing callers of `capabilities::evaluate` are unchanged.

## Runs, logout and execution-time recheck

Logging out of one session does **not** cancel queued or running background runs:
`RunAuthority::originating_session_active` is deliberately ignored. Account disablement,
approval withdrawal, provider retirement, a platform or user capability deny, loss of an
opt-in assignment, loss of project membership or role, and revocation of the target's share
each make `authorize_run_continuation` return `Invalidate(reason)` at the next recheck. The
recheck rehydrates the run owner's principal from the primary and requires `RunExecute` on
the run scope, write access on the target resource in that same scope and every capability
the run uses. A target outside the run scope is concealed.

### Worker database boundary (PR2 specification)

PR2 grants `openmettle_worker` direct `SELECT` on the five non-secret authority and membership
tables it needs for the recheck: `membership_observations`, `local_identity_approvals`,
`login_providers`, `login_provider_revisions` and `user_identities`. It grants
`UPDATE (state, wait_reason)` on `runs` so the worker can invalidate work immediately. The
worker already reads `users`, `scopes`, `projects`, `grant_assignments` and `grant_changes`
(migrations 1 and 5). Any new V1-05 table the recheck must read (local groups, capability
denies and assignments) needs the same read-only grant; PR2 records it. No secret column, key
material or session credential is granted. PR5 performs the recheck before dispatch and at
each tool or provider step.

### Migration 15 (PR2)

`migrations/0015_authorization_and_projects.sql` adds persistence only; no route reads it yet.

- `project_settings`: name, instructions, `defaults` (a JSON object of at most 16 KiB with no
  top-level `folder_id`, `folder_ids`, `collection_id` or `collection_ids`), revision and
  `archived_at`/`deleted_at`, keyed by the stable project and scope IDs. A project without a
  row, including every pre-15 project, has no name, empty instructions and `{}` defaults.
- `local_groups` (flat; no nesting column) and `local_group_memberships`: one current-state
  row per group and user with `active` and a revision, so removal and re-adding need no
  `DELETE`.
- `account_admins` with `active` and a revision. Every administrator change and user
  disablement first locks the single `account_admin_lock` row `FOR UPDATE`; the API can take
  it only through an inert `lock_guard` column. Bootstrap and break-glass use
  `docs/operator/grant-account-admin.psql`.
- `platform_capability_denies`, `user_capability_denies` and `user_capability_grants`, whose
  capability check mirrors `valid_capability` in `src/authz.rs` exactly.
- `authorization_audit`: append-only. Actor is a user or an operator UUID, never both; the
  request key is unique per actor. The API may insert only user-actor rows (its column grant
  excludes the ID, time, actor kind and operator) and can never update or delete.
- Grants as specified above, plus API column-level writes on the new tables and
  `UPDATE (state, wait_reason)` on `runs` for both roles. No `DELETE` or `TRUNCATE`.

Group grantees on ADR 0006 assignments (`grant_assignments.grantee_user_id` is `NOT NULL`)
are not part of this migration; sharing with or granting project roles to a group needs a
later additive migration before PR3/PR4 writes them.

### PR3: Hydration and administration store

`src/authz/store.rs` reads and writes the migration 15 tables through the existing bounded
roles. It adds no migration, route or dependency.

- **Hydration.** `hydrate_api_principal` and `hydrate_worker_principal` share one query path
  and read the primary on every call; nothing is cached. The principal is `None` for an
  unknown user or one without a personal scope. `approval_active` and `provider_active` use
  the session-validation rules of ADR 0013 for the exact approval, which must belong to one
  of the user's identities. Local groups are active memberships of enabled groups. An OIDC
  group is the claim value of a `group` selector whose ADR 0021 evidence is `present` at
  `now_ms`, using the same SQL predicate as `membership::current`. The worker variant never
  selects `account_admins` and reports `account_admin = false`.
  `load_platform_capabilities` returns the platform denies for either role.
- **Writes** run only as `openmettle_api`, each in one READ COMMITTED transaction following the
  [canonical lock order and serialization rules](#canonical-lock-order-and-serialization-for-administrative-writes):
  1. Every administrative write locks `account_admin_lock FOR UPDATE`, then the actor's
     `login_providers` and `local_identity_approvals` rows `FOR SHARE`, then the actor's `users`
     row `FOR SHARE` (or `FOR UPDATE` on a self-disable or self-enable so it never upgrades).
  2. The primary's `clock_timestamp()` is re-read after the locks, and the actor is re-hydrated
     at the post-lock instant and must pass `require` and `authorize_admin`.
  3. The `authorization_audit` row is inserted next with `ON CONFLICT DO NOTHING` on
     `(actor_user_id, request_key)`. A recorded key with the same action, target and details
     returns `Replayed` without writing. A different change returns `Conflict`.
  4. The target is checked and the change applied (re-deciding last-admin removal under
     `account_admin_lock`), and approval expiry is re-checked against `clock_timestamp()` after
     any target lock wait before committing.
- A change that would not alter the current state returns `Conflict` and writes no audit
  row. Rows are never deleted. Every update advances `revision` and records
  `updated_at = clock_timestamp()` and the actor. Disabling a user also advances
  `session_generation`, so re-enabling never revives an earlier session or membership
  observation.
- Audit `details` hold only request identifiers: a group `name`, or the member or capability
  `user_id`. Capability changes use target kind `capability` with the capability name as the
  target.

### PR4a: Group grantees and project/resource store

`migrations/0016_grant_group_grantees.sql` is additive. It adds no route, worker loop or
dependency.

- `grant_assignments.grantee_kind` is `user` (the default), `local_group`, `oidc_group` or
  `project`. Exactly the matching column is set: `grantee_user_id` (now nullable),
  `grantee_local_group_id` (references `local_groups`) or `grantee_oidc_group_id` (1 to 1024
  bytes, no control character). A `project` grantee names no column and applies only to
  conversation and artifact targets. Every version 5 to 15 row reads `user` with NULL group
  columns. Writers that name only `grantee_user_id` keep working.
- The migration 5 natural key, whose generated name is not part of any contract, is found by
  its exact column list and replaced by `grant_assignments_unique_key`, which adds the kind
  and group columns, `NULLS NOT DISTINCT`. Partial indexes serve group lookups.
- `projects.lock_guard` is an inert column (`CHECK (lock_guard = false)`). Its API
  `UPDATE` grant only lets the API lock a project row `FOR NO KEY UPDATE`, serialising
  project writers without blocking concurrent foreign-key `FOR KEY SHARE` locks, as
  `login_providers` does since migration 8. The API also gains `INSERT` on the three grantee
  columns.

`grants::Assignment.grantee` is a borrowed `grants::Grantee`. A user grantee keeps the exact
ADR 0006 version 1 request identity, so earlier requests replay unchanged. Other kinds encode
`kind NUL id`. `grants::find_assignment` reads an assignment by its natural key.

`src/authz/projects.rs`:

- **Hydration** works as `openmettle_api` and `openmettle_worker`, reads the primary on every
  call and never reads `account_admins` or `project_settings`. `hydrate_project` returns
  current assignments whose vocabulary parses for the target, with their recorded head and,
  for mapped rows, ADR 0021 evidence from the shared `membership_state` predicate. Rows naming
  a disabled user or a disabled local group are omitted, so a disabled owner never satisfies
  the last-owner invariant. `hydrate_resource` returns a conversation or artifact with its
  creator, personal or project scope and parsed shares. Lifecycle state is read separately
  with `load_project_settings` (API only). A project without a settings row reads an empty
  name, empty instructions, `{}` and revision 0.
- **Writes** run as `openmettle_api` with the PR3 protocol in one transaction: lock, re-hydrate
  the actor, authorize with this module's policy, insert or replay the audit row, then apply.
  A change that alters nothing returns `Conflict` and writes no audit row.
  - `create_project` (any active principal) creates the scope, project and settings and grants
    the creator a direct `owner` role. Audit details hold a SHA-256 digest of the settings
    request, never the name or instructions.
  - `update_project_settings`, `archive_project`, `restore_project` and `delete_project` lock
    the project row and need `Owner` (`ManageProjectSettings`, `DeleteProject`). The update
    writes the first row of a pre-15 project. Archive, restore and delete need an existing
    row. Delete sets `deleted_at`. A deleted project is then concealed from every write.
  - `set_project_member_role` and `revoke_project_member` lock the project row, so concurrent
    owner changes serialize and `authorize_member_change` decides on the hydrated project. A
    grantee holds at most one active direct `openmettle.project-role`: a new role revokes the
    superseded one, so demoting an owner removes the `owner` grant. A user or local group
    grantee must exist and be enabled to receive a role. Revocation needs neither.
  - `share_resource` and `unshare_resource` lock the project row, or the personal scope
    owner's user row. They hydrate the resource and require a share manager
    (`authorize_revoke`). A new share also needs `authorize_share` with the recipient's own
    principal, hydrated through each of its approvals, or the group's effective project
    membership. One active `openmettle.resource-grant` key is kept per grantee. Revocation
    never checks the grantee's membership.
  - Each ADR 0006 change uses a request key derived from the audit request key, so an audited
    replay never re-writes a grant.

Run invalidation on share, revoke or disable remains PR5. Hydration does not conceal archived
or deleted projects from the worker; PR5 cancels their runs and PR4b settles reads and writes.

### PR5: Worker execution-time recheck and live run invalidation

`src/authz/runs.rs` adds no migration, route, worker loop or dependency. It uses the migration
15 grants: `UPDATE (state, wait_reason)` on `runs` for both roles and worker `SELECT` on the
authority, membership, group and capability tables.

- **Recheck.** `recheck_run` takes a `RunRecheckRequest`: the run's scope and ID, the approval
  the run was admitted under, the capabilities the next step uses and, optionally, one extra
  conversation or artifact the step writes. It validates every identifier and capability name
  before any query. It works as `openmettle_worker` or `openmettle_api` and runs one bounded
  READ COMMITTED transaction:
  1. Lock the run row `FOR NO KEY UPDATE`. A missing run is `NotFound`. A terminal run
     (`succeeded`, `failed`, `cancelled`, `interrupted`) returns `Terminal` unchanged.
  2. Re-hydrate the run owner with `hydrate_worker_principal` and load the platform denies.
  3. Hydrate the run scope from `scopes` independently of its targets. Hydrate the run's
     conversation and any extra target with `hydrate_resource`.
  4. Decide with `authorize_run_continuation`, with `originating_session_active: false`. A
     missing principal, scope, conversation or extra target invalidates as `NotFound`. A
     target in another scope is concealed. The extra target needs the same write access as
     the conversation, so a share downgraded to `Read` invalidates a step that writes it.
  5. On `Continue`, change nothing. On `Invalidate(reason)`, set the run to `cancelled` with
     no wait reason and return `Invalidated(reason)`. A repeated recheck returns `Terminal`.

  An approval that is not one of the owner's reads as inactive, so the recheck fails closed.
  The recheck never reads `account_admins`, `project_settings`, `authorization_audit` or
  `local_sessions`. Logout is not consulted and `sessions::logout` is unchanged, so logging out
  never cancels queued or running work.
- **Lifecycle and disablement.** The worker has no `SELECT` on `project_settings` and must not
  gain one. The API therefore cancels runs in the lifecycle transaction itself:
  `archive_project` and `delete_project` cancel every non-terminal run in the project's scope,
  and `disable_user` cancels every non-terminal run the user owns. A replay, a refused change
  or `restore_project` cancels nothing, and restore or re-enable revives no run. The other
  revocations (approval, provider, capability, membership, group, OIDC evidence, share) take
  effect at the worker's next recheck, which PR5 requires before dispatch and before each tool
  or provider step.
- **Lock order.** The recheck locks one run row, then only reads without row locks and updates
  the row it holds, so it never waits while holding a run lock. Bulk cancellation is the last
  statement of its transaction, after the project row lock (archive, delete) or after
  `account_admin_lock` and the user row (disable). It locks every affected run row in ascending
  `id` order through a materialized CTE before updating any. No path locks a run row and then
  waits on a project, user or `account_admin_lock` row, so the recheck and bulk cancellations
  cannot form a wait cycle, and two overlapping bulk cancellations take their shared rows in
  the same order.
- **Limits.** A `Continue` is valid only for the observation it made. A revocation that
  commits during a step is seen at the next recheck. Cancellation moves `cancelling` and
  `reconciling` runs to `cancelled` as well. Their operation records, including unknown
  outcomes, are not changed. `sessions::disable_user` (the ADR 0013 internal operation) does
  not cancel runs; the next recheck invalidates them. Run admission is not part of PR5: it
  must refuse new runs in an archived or deleted project and serialize with archive on the
  project row. Otherwise a run admitted concurrently with an archive survives it, and the
  worker cannot see the archive.

### PR4b: Authenticated `/v1` routes

`src/v1.rs` is the enforcement surface. It adds no migration or dependency. `crate::app` mounts
it beside the sign-in routes only when `OPENMETTLE_API_AUTH_CONFIG` is set; without it every
`/v1` path stays `404`. The fifteen operations of ADR 0007 are:

| Operation | Route | Store call |
| --- | --- | --- |
| `listCapabilities` | `GET /v1/capabilities` | Principal hydration and `require`; an empty, core-only list |
| `createProject` | `POST /v1/projects` | `create_project`, then `read_project` (`201`) |
| `getProject` | `GET /v1/projects/{project_id}` | `read_project` |
| `updateProjectSettings` | `PUT /v1/projects/{project_id}` | `update_project_settings`, then `read_project` |
| `archiveProject`, `restoreProject` | `POST /v1/projects/{project_id}/archive`, `/restore` | `archive_project`, `restore_project`, then `read_project` |
| `deleteProject` | `DELETE /v1/projects/{project_id}` | `delete_project` (`204`) |
| `setProjectMemberRole` | `PUT /v1/projects/{project_id}/members` | `set_project_member_role` |
| `revokeProjectMember` | `POST /v1/projects/{project_id}/members/revoke` | `revoke_project_member` (`204`) |
| `getConversation`, `getArtifact` | `GET /v1/conversations/{id}`, `/v1/artifacts/{id}` | `read_resource` |
| `shareConversation`, `shareArtifact` | `PUT …/shares` | `share_resource` |
| `revokeConversationShare`, `revokeArtifactShare` | `POST …/shares/revoke` | `unshare_resource` (`204`) |

There is no list, message, run, upload or streaming operation: cursor MACs (ADR 0007), run
creation (V1-07, V1-10), SSE (V1-12) and artifact upload (V1-15) remain with their tickets.
V1-15 PR2 has since added artifact uploads, revision metadata and downloads, decided by
`authorize_create_in_scope` and `authorize_artifact` (ADR 0031).

- **Sessions.** A request presents exactly one channel: the `__Host-openmettle-session` cookie
  (found by the handoff's single-cookie rule) or one `Authorization: Bearer` native credential,
  accepted only when a native profile is mounted. Both, neither, a repeated field, another
  scheme or a malformed cookie or bearer is `401` before any database work. The cookie channel binds the
  configured browser origin as ADR 0019 does for logout: an unsafe method needs exactly one
  `Origin` with those bytes, and a safe method that sends `Origin` must send that one. A missing,
  `null`, repeated or foreign `Origin` is `401`, not `403`, so `policy` still implies the caller
  may know the target. `BrowserAuth::validate` and `NativeAuth::validate` return the ADR 0029
  context on the primary; a refused credential is `401`, a deadline `504`, any other failure
  `503`.
- **Hydration.** Each request hydrates the principal with `hydrate_api_principal` at the
  context's approval and observed time, and every project and resource on the primary. Nothing
  is cached between requests, so disablement, logout, group, membership, evidence and share
  changes apply to the next request. Writes re-hydrate inside their own transaction as before.
- **Connections.** All database work of one request runs on one pooled connection in the
  `Checkout` guard of ADR 0016, inside a 10 s deadline. A `StoreError::Database`, an elapsed
  deadline or a dropped future closes the connection instead of returning it, because the
  outcome of a statement or commit is unknown. The guard closes rather than detaches, so the
  pool never exceeds its size.
- **Request keys.** The client `Idempotency-Key` (1–128 visible ASCII characters) is checked
  before any database work. The audit `request_key` is the lowercase hex SHA-256 of
  `openmettle/v1-idempotency/1`, the `operationId`, the path identifier and the client key,
  length-prefixed. The audit table is unique per actor, so a client key is scoped to the
  actor, the operation and its target, and the same key on another operation is a new request.
  `KEY_REUSED` is `409 idempotency_conflict`; every other store conflict is `409 conflict`.
  The audit reason is the request's optional `reason`, or the `operationId`.
- **Validation before the database.** Bodies decode into closed types: unknown, duplicate and
  mistyped members, a non-object body, a grantee kind the operation does not accept, a role or
  access outside the grant vocabulary, and settings that `ProjectSettingsInput::validate`
  refuses (including the legacy `folder_id` and `collection_id` defaults) are `400`.
- **Bounds.** 256 requests in flight (`503` beyond, never queued), the browser router's target
  and header ceilings, and 64 KiB JSON bodies read within 2 s.
- **Paths.** The browser and native settings checks reserve `/v1` and every path under it as
  they reserve `/healthz` and `/readyz` (`browser_auth::router::reserved`). A sign-in route, a
  native callback on any origin, and an app link on the issuer or browser origin there is
  `Collision`, offline and at startup, so `Router::merge` cannot panic.

**Lifecycle** is decided in `src/authz/projects.rs`, once for the store and the routes:

- A **deleted** project, and every item in it, is `404` on every read and write, also to its
  owner. The one exception is an exact replay of the delete: the same actor, still allowed to
  delete it, with the same request key that recorded `project.delete` receives `Replayed`
  (`204`). Any other key is concealed, and the audit row it would add is rolled back. An
  inactive actor still receives `InactivePrincipal`.
- An **archived** project stays readable to its members and grantees. Its items report access
  `read`; `can_manage_shares` stays the share-manager decision, because revocation remains
  available. `update_project_settings`, `set_project_member_role` and `share_resource` refuse
  with `ARCHIVED` (`409 conflict`) after the lock, re-hydration and authorization, so a
  non-member still receives `404` and a viewer `403`. `restore_project`, `delete_project`,
  `revoke_project_member` and `unshare_resource` stay available.
- `lock_project` now reads lifecycle in a second statement after the row lock is granted. A
  single statement's snapshot predates the lock wait and could miss an archive or delete
  committed by the writer it waited for.

## Verification

`src/authz/tests.rs` covers vocabulary acceptance and rejection, the role matrix,
highest-wins precedence, namespace separation, mapped-evidence staleness, private-by-default
concealment, account-admin non-escalation for every kind and action, sharing rules 2a and 2b,
personal sharing, last-owner and last-admin invariants, capability denies and opt-in, ADR 0007
mapping and run continuation. They are unit tests of the pure policy. They do not prove
hydration, persistence, transactional counting or route enforcement, which PR2–PR5 must test
against PostgreSQL and HTTP.

For PR3, `tests/schema/authz_store.rs` runs against PostgreSQL 18 as the bounded roles. It
covers hydration for both roles, OIDC evidence states, every write with its audit row,
replays, request-key conflicts, refusals and the last-administrator race under
`account_admin_lock`. Route enforcement is covered under PR4b below.

For PR4a, `tests/schema/authz_projects.rs` covers:

- the version 15 to 16 upgrade, including a version-15 user grant replayed byte for byte;
- constraints and role boundaries for every grantee kind;
- project creation, settings, archive, restore, delete and pre-15 defaults;
- role precedence across direct, local-group, OIDC-group and mapped grants, including stale
  evidence, namespaces and disabled users and groups;
- the last-direct-owner race serialized on the project row;
- private-by-default sharing for every role, personal and project scopes, stale-row
  revocation and lapsed membership;
- account-admin non-escalation;
- worker hydration.

Its pure tests cover settings validation. The PostgreSQL tests are `#[ignore]` and need the
CI PostgreSQL 18 service.

For PR5, unit tests in `src/authz/runs.rs` cover request validation, the terminal-state
vocabulary and its SQL predicate, and the pure decision: missing or inactive owner, missing
or out-of-scope targets, project role, extra-target access and capabilities.
`tests/schema/authz_runs.rs` runs against PostgreSQL 18 and covers:

| Cause | Effect |
| --- | --- |
| Authorized personal and project runs; logout of the originating sessions | `Continue` for both roles; state unchanged |
| Approval withdrawal, approval expiry at `now_ms`, provider retirement, an approval of another user | Worker recheck cancels (`InactivePrincipal`) |
| Withdrawn `runs.use_yolo`, user deny, platform deny | Cancelled (`Policy`) only for runs that use the capability |
| `revoke_project_member`; demotion from `Editor` to `Viewer` | Cancelled (`NotFound`; `Policy`) |
| `remove_local_group_member`, `disable_local_group`, stale OIDC evidence | Cancelled (`NotFound`) |
| `unshare_resource`; share downgraded to `Read` on the conversation or on an extra artifact target; extra target out of scope or missing | Cancelled (`NotFound`; `Policy`) |
| `disable_user`, `archive_project`, `delete_project` | Every live run cancelled when the change commits; terminal and unrelated runs untouched; replay, restore and re-enable revive nothing |

Every invalidation is checked to be idempotent: the row is `cancelled` with no wait reason
and a repeated recheck returns `Terminal`. Terminal runs are never changed. The tests also
show the worker cannot read `account_admins`, `project_settings`, `authorization_audit` or
`local_sessions`, or update any run column except its lifecycle columns. Three concurrency
checks complete without deadlock or lock timeout: a held recheck performs its reads while an
archive waits on the run row; a worker cancels the row a waiting disablement needs; and
rechecks race a disablement and an archive over the same runs.

For PR4b:

- `src/v1/tests.rs` checks that the served routes are exactly the contract's implemented
  operations, the ADR 0007 mapping of every denial and store error, the media-type,
  `Idempotency-Key` and body rules, request-key scoping and timestamp format.
- `src/tests.rs` drives the mounted `app()` without PostgreSQL. Missing, ambiguous and
  repeated credentials, every refused `Origin` on the cookie channel, invalid keys, unknown or
  legacy body members, wrong media types, oversized heads and bodies, malformed identifiers and
  undefined operations are refused before the pool is dialled. Each response is versioned and
  uncacheable, names the request ID that telemetry logged, and is recorded under its route
  template and the `v1` route class, with no planted value in a response or telemetry. A
  well-formed credential on either channel reaches the primary (`503` when it cannot connect);
  a bearer without a native profile is `401`.
- `src/browser_auth/router.rs` and `src/auth_config/tests.rs` show `/v1` and paths under it
  refused as browser paths, native callbacks and app links, and a shared prefix such as `/v10`
  accepted.
- `tests/contract.rs` validates the problems of the mounted binary against the contract.
- `tests/schema/authz_http.rs` runs the real API binary over PostgreSQL 18 as
  `openmettle_api`, with seeded browser sessions (sent with the configured `Origin`) and native
  bearers. It covers capabilities for active, withdrawn, logged-out and disabled callers; project
  create with replay across channels, reused keys and legacy defaults; reads, settings, roles and
  the viewer's refusals; archive cancelling a live run and freezing settings, roles and new
  shares while reads, revocations and restore stay available; delete with its exact replay and
  concealment of a new key, the project and its items. A third test covers role precedence across
  direct, local-group and OIDC-group grants, the last direct owner, private-by-default project
  conversations and personal artifacts with user, group and whole-project shares, refused
  reshares and non-member grantees, account-administrator `404` on all thirteen project and item
  routes, and revocation on the next request after member removal, group disablement, stale OIDC
  evidence and native logout. These tests are `#[ignore]` and need the CI PostgreSQL 18
  service.

## Amendment by ADR 0033

Authorization loss cancels queued and waiting runs immediately. For executing runs, the API
records a cooperative cancellation request. The lease holder calls `recheck_leased` before
each step. It supplies the lease settings so a revoked run can settle against the operations
ledger and the remaining execution time in the same transaction.
See [Worker leases, deadlines, fencing and restart recovery](0033-worker-leases-deadlines-and-restart-recovery.md).
