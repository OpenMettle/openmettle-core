# 0027 — Central authorization policy and private-by-default projects

Status: proposed V1-05 increment 1 of 5, 19 November 2026. Agent-authored; implements the
owner decisions recorded on #6 the same day. Owner approval of this record, independent
review and CI acceptance are separate gates. Refs #6. #6 remains open.

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
- **Writes** run only as `openmettle_api`, each in one READ COMMITTED transaction:
  1. Account-administrator changes and user disable or enable first lock
     `account_admin_lock`, matching `docs/operator/grant-account-admin.psql`.
  2. The actor is re-hydrated inside the transaction and must pass `require` and
     `authorize_admin`.
  3. The `authorization_audit` row is inserted next with `ON CONFLICT DO NOTHING` on
     `(actor_user_id, request_key)`. A recorded key with the same action, target and details
     returns `Replayed` without writing. A different change returns `Conflict`.
  4. The target is checked and the change applied. Removing an enabled administrator is
     re-decided with the enabled count taken under the lock (`LastAccountAdmin`).
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
or deleted projects from the worker; PR4b and PR5 must decide how lifecycle affects reads and
running work.

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
`account_admin_lock`. Route enforcement remains PR4b.

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
