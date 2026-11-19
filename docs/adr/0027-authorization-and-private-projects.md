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
| PR4 | Project, conversation and artifact routes enforcing the evaluator. |
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
owners do not count, because they can lapse without an owner action. Transfer is: add the new
direct owner, then step down.

## Private by default

Every conversation, artifact and memory record starts private to its creator. Project
membership alone never publishes a member's private conversations, artifacts or memory. Even
a project owner cannot read another member's unshared item. Memory, tools and connections are
not shareable in V1-05: share rows on those kinds are ignored and new shares are refused.
Publishing memory into shared project memory is a separate future action.

Personal-scope items belong to their scope owner. The owner can share them directly with a
user or with a local or OIDC group. Sharing never changes accounting ownership. A
project-wide share is invalid outside a project and grants nothing.

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
   target, reason, request key and timestamp in an append-only table (PR2 schema, PR3 and PR5
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

## Verification

`src/authz/tests.rs` covers vocabulary acceptance and rejection, the role matrix,
highest-wins precedence, namespace separation, mapped-evidence staleness, private-by-default
concealment, account-admin non-escalation for every kind and action, sharing rules 2a and 2b,
personal sharing, last-owner and last-admin invariants, capability denies and opt-in, ADR 0007
mapping and run continuation. They are unit tests of the pure policy. They do not prove
hydration, persistence, transactional counting or route enforcement, which PR2–PR5 must test
against PostgreSQL and HTTP.
