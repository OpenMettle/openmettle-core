# 0030 — Session issuance database boundary

Status: proposed AUTHSEC-01 design, 20 November 2026. Agent-authored; owner approval,
independent review and CI acceptance are separate gates. Refs #73; Refs #5. Core PR2
implements migration 18, the boundary audit, the issuance pool and its settings (see
[Remaining](#remaining)). #73 remains open.

## Problem

The database trusts the API process to have verified an OIDC proof before it issues a
session (ADR 0013: single-use login markers are "trusted API protocols, not protection from
arbitrary API SQL"). Every write that issuance needs is granted to `openmettle_api`, the role
behind every pooled API query. A principal limited to SQL as `openmettle_api`, such as the
holder of a SQL injection in any API query or of `OPENMETTLE_API_DATABASE_URL`, can therefore
mint a valid session for any existing `local_identity_approvals` row, including the owner's.

### Confirmed forgery path

On schema 16, every statement below is within the `boundaries.sql` contract for
`openmettle_api`. `:k`, `:n`, `:l` and `:s` are values the principal chooses.

1. `SELECT` the target from `local_identity_approvals` (`id`, `provider_id`, `identity_id`,
   `revision`, `access_generation`), `user_identities.user_id`, `users.session_generation`,
   `login_providers` (`client_id`, `access_generation`) and the latest
   `login_provider_revisions.epoch`. All are `SELECT`-visible.
2. `INSERT INTO login_nonce_reservations (key_id, nonce) VALUES (:k, :n)`.
3. `INSERT INTO login_transactions (id, binding, expires_ms, state_hash, nonce_hash,
   caller_hash, key_id, nonce, ciphertext)` with `id = :l`, any 1–12 288-byte binding, any
   32-byte digests and 76 arbitrary ciphertext bytes. Nothing opens that ciphertext.
4. `UPDATE login_transactions SET consumed = true, ciphertext = NULL WHERE id = :l`.
5. `INSERT INTO local_sessions (id, secret_hash, login_id, provider_id, identity_id,
   approval_id, user_id, issued_client, issued_epoch, issued_revision, provider_generation,
   approval_generation, user_generation, created_ms, expires_ms)` with `id = :s`,
   `login_id = :l`, the values read in step 1, and `secret_hash` computed from a secret the
   principal chose under the credential format of ADR 0013 (`sessions::digest`). Nothing
   bounds `expires_ms` by the session policy.
6. `UPDATE login_transactions SET session_issued = true WHERE id = :l` (optional: validation
   never reads the marker).

`sessions::validate_inner` then accepts the credential `:s` plus that secret: every column it
compares was copied from current rows. The same role can also
`UPDATE membership_observations`, the mapped-membership evidence that only issuance records,
and `INSERT INTO native_handoffs` with `sealed = NULL` and a chosen
`audience`, which makes the forged session a valid native bearer for that audience.

### First-account creation is already closed

ADR 0022 closed the equivalent path for first-account creation. `openmettle_api` has no
privilege on `home_invitations` and no `INSERT` on `local_identity_approvals`. The only way to
create an approval is the `SECURITY DEFINER` function
`redeem_home_invitation(uuid,text,text,text,bigint,bytea)`, which requires the operator's
unforgeable 16-byte invitation code. A forged login row satisfies everything the function
checks except the code. This decision keeps that layer.

## Decision

**Option 1, layered with ADR 0022.** A narrow PostgreSQL group role, `openmettle_issuance`,
holds every write that only session issuance performs. `openmettle-api` reaches it through a
second, separate `PgPool` with its own credential. `openmettle_api` loses those writes.
First-account creation keeps the operator code as an independent proof inside the function.

### Rejected alternatives

| Alternative | Reason |
| --- | --- |
| `SECURITY DEFINER` issuance function granted to `openmettle_api`, with no independent proof | Injected API-role SQL calls the function directly with fabricated arguments. It moves the writes, not the boundary. |
| In-database OIDC ID-token verification for routine sign-in (#73 option 2) | Stock PostgreSQL and `pgcrypto` cannot verify RS256 (ADR 0008) or ES256 JWS signatures. A third-party C extension breaks portability to managed PostgreSQL and the provenance rules. Supplying the JWKs from `openmettle_api` re-trusts the compromised caller; static owner-pinned keys break the signing-key refresh of ADR 0011. |
| Separate authentication service or deployment | YAGNI. ARCHITECTURE-v1.md keeps authentication "inside the API authentication module rather than requiring another identity microservice". A process boundary is not needed for the threat below. |

### Role and privilege split

From schema 18. Every other privilege of `openmettle_api` and `openmettle_worker` is unchanged.

**Move from `openmettle_api` to `openmettle_issuance`.** Every caller of these privileges in
`src/` runs inside the issuance transaction of `sessions::issue`:

| Object | Privilege | Caller |
| --- | --- | --- |
| `local_sessions` | `INSERT` on the 15 migration 8 columns | `sessions::issue` |
| `login_transactions.session_issued` | `UPDATE` (also enables the `FOR UPDATE` gate) | `sessions::issue` |
| `membership_observations` | `UPDATE` on `issued_ms`, `expires_ms`, `observation`, `epoch`, `approval_generation`, `user_generation` | `membership::reconcile`; `sessions::issue` (stale marking) |
| `native_handoffs` | `INSERT` on `session_id`, `code_hash`, `registration`, `audience`, `challenge`, `sealed`, `expires_ms` | `native::Attempt::store` |
| `redeem_home_invitation(uuid,text,text,text,bigint,bytea)` | `EXECUTE` | `sessions::resolve_identity` |

**Also granted to `openmettle_issuance`** (shared with `openmettle_api`, needed by the same
transaction):

- `SELECT` on `login_transactions`, `login_providers`, `login_provider_revisions`,
  `user_identities`, `users`, `scopes`, `local_identity_approvals`, `local_sessions`,
  `membership_observations`, `grant_mapping_rules`, `grant_mapping_revisions`,
  `grant_assignments` and `grant_changes`.
- `UPDATE (lock_guard)` on `login_providers` and `local_identity_approvals` for their
  `FOR SHARE` locks.
- The mapped-membership grant writer of `grants::change_grant`: `INSERT` on the 15
  `grant_assignments` columns and 13 `grant_changes` columns of the schema 5 and 16 contract,
  and `UPDATE (last_revision)` on `grant_assignments`.

**Rule for row locks.** PostgreSQL needs `UPDATE` on some column for a locking `SELECT`. The
issuance role never holds `UPDATE` on a column it does not write. Migration 18 adds the inert
guard of ADR 0013 (`boolean NOT NULL DEFAULT false CHECK (lock_guard = false)`) to `users`
(locked `FOR NO KEY UPDATE`) and to `grant_mapping_rules` (locked `FOR NO KEY UPDATE`), and
grants `UPDATE (lock_guard)` on both to the issuance role only.

**Remains on `openmettle_api`:**

- Login initiation and callback: `INSERT` on `login_nonce_reservations` and
  `login_transactions`, and `UPDATE (consumed, ciphertext)` for consumption.
- Session validation: `SELECT` and the `FOR SHARE` locks of `validate_inner`, including the
  post-commit validation of a newly issued session (below).
- Logout: `UPDATE (revoked)` on `local_sessions`.
- Native token exchange: `SELECT` and `UPDATE (sealed)` on `native_handoffs`.
- `disable_user` and V1-05 account administration: `UPDATE (disabled_at, session_generation)`
  on `users`.
- `SELECT` on `membership_observations` for callback consumption (which reads the
  membership configuration revision) and authorization hydration.

`openmettle_worker` gains nothing. `PUBLIC` gains nothing.

### Issuance connection

`sessions::issue` takes its transaction on an issuance-pool connection. The post-commit
`validate_inner` that gates credential release (ADR 0013) runs on a primary-pool connection,
acquired only after the issuance checkout is settled. A callback phase therefore holds at most
one connection at a time: consumption (primary), token exchange (none), issuance (issuance),
post-commit validation (primary). No phase waits on one pool while holding the other.

The issuance pool runs only the fixed, parameter-bound statements of `sessions::issue`,
`sessions::resolve_identity`, `membership::reconcile`, `grants::change_grant` (mapped path)
and `native::Attempt::store`. Its inputs come from the sealed exchanged proof.

### Boundary audit (`src/boundaries.sql`)

- `openmettle_issuance` joins `openmettle_api` and `openmettle_worker` as a privilege role.
  It, every login role that is a member of it and `PUBLIC` may hold only its contract,
  `CONNECT` and `USAGE` on schema `openmettle`. The attribute, membership, grant-option,
  default-privilege and ownership checks apply to it unchanged.
- **Disjoint login roles.** The existing "both API and worker" check generalises: a role
  that reaches more than one of `openmettle_api`, `openmettle_issuance` and
  `openmettle_worker` is a violation, and none of them or their login roles may be a member of
  `openmettle_owner` or any other role (the existing membership checks).
- **Version gate.** The moved rows are allowed for `openmettle_api` at `$1 < 18` and for
  `openmettle_issuance` at `$1 >= 18`. The redemption `EXECUTE` exception names the issuance
  role from version 18. Before version 18, an existing `openmettle_issuance` has an empty
  contract. From version 18 a missing `openmettle_issuance` is a violation.

## Runtime configuration

| Setting | Rule |
| --- | --- |
| `OPENMETTLE_API_ISSUANCE_DATABASE_URL` | Required when `OPENMETTLE_API_AUTH_CONFIG` is set; refused (exit 78) when `AUTH_CONFIG` is unset. Same scheme, TLS and redaction rules as `DATABASE_URL` (ADR 0002); never logged. |
| `OPENMETTLE_API_ISSUANCE_DB_MAX_CONNECTIONS` | 1–64, default 2. Refused when the URL is unset. |

- The API refuses (exit 78) an issuance URL whose resolved user equals the primary URL's
  user, including users filled from `PG*` defaults. The two pools must not collapse into one
  role.
- The issuance pool is lazy, uses `DB_TIMEOUT_MS` for acquisition and disables statement
  logging, like the primary pool. Readiness stays one primary query; an unusable issuance
  pool refuses sign-ins only.
- The worker and the migrator never read the setting, and exit 78 if
  `OPENMETTLE_API_ISSUANCE_DATABASE_URL` is present in their environment.
- `openmettle-deploy` adds a `database.issuance` Secret reference mounted into the API
  container only.

Connection budget: `api_replicas × (API DB_MAX_CONNECTIONS + ISSUANCE_DB_MAX_CONNECTIONS) +
worker_replicas × worker DB_MAX_CONNECTIONS + 1 migrator + headroom`, counting surge replicas.
For example, 2 × (4 + 2) + 2 × 4 + 1 + 3 = 24. Enforce the issuance share with the issuance
login role's `CONNECTION LIMIT`.

## Upgrade

**Provisioning.** Before migrating, a superuser creates the role, for example
`CREATE ROLE openmettle_issuance LOGIN PASSWORD :'issuance_password' CONNECTION LIMIT 4;`.
A separate login role that is a member of `openmettle_issuance` and of nothing else is also
accepted. Fresh installations provision all four roles before migration 1.

**Fail closed.** Migration 18 raises and rolls back, leaving the previous schema, if
`openmettle_issuance` does not exist. The boundary audit refuses unsafe provisioning before
any statement runs.

**Populated databases (schema 2 onward, including 17).** Migration 18 preserves every
`local_sessions`, `login_transactions`, `native_handoffs` and `membership_observations` row.
Existing sessions stay valid. Sessions forged before the upgrade are indistinguishable from
real ones. Where API-role SQL may have been exposed, revoke every pre-upgrade session after
migration 18 commits and before the new release serves sign-ins, as `openmettle_owner` on the
primary:

```sql
UPDATE openmettle.local_sessions SET revoked = true WHERE NOT revoked;
```

When the migrate-then-roll-out order below is followed, no session can be issued between the
migration and the new release, so this revokes exactly the pre-upgrade sessions. Each person signs in again.

**Order and rolling update.** Migrate, then roll out.

- **Previous release on schema 18.** Validation, logout and login initiation continue. Its
  issuance runs as `openmettle_api`, which now lacks the writes, so every sign-in completion
  and first-account redemption fails closed. This is an explicit exception to the README rule
  that each migration stays compatible with the previous API: keeping the writes for one more
  release would keep the forgery path open.
- **Current release on schema 17.** The issuance role has no grants, so sign-in completion
  fails closed until the migration runs.

## Threat model

**Defends against:**

- SQL injection in any query on the `openmettle_api` pool: `/v1/*`, `/readyz`, session
  validation, logout, login initiation and callback consumption, native token exchange;
- disclosure of `OPENMETTLE_API_DATABASE_URL` or of the `openmettle_api` password alone.

Either principal can no longer insert a session, mark a login issued, record membership
evidence, create a native handoff or call the redemption function.

**Out of scope:**

- full `openmettle-api` process compromise: the process holds both URLs;
- compromise of `openmettle_issuance` credentials, which retain issuance and the mapped grant
  writer by design;
- compromise of `openmettle_owner`, the database host or its superuser;
- compromise of the upstream OIDC provider or its signing keys.

**Unchanged API-role powers that need a credential the principal does not hold.**
`openmettle_api` can still set `local_sessions.revoked` back to `false`, and can still change
`users.disabled_at` and `session_generation`. These can revive an existing session, but using
it still requires that session's secret, which the database stores only as a digest. Raw
API-role SQL can also still reset login consumption (ADR 0009).

## Compatibility

- **Migrations.** Migration 18: role precondition, two inert guards, the grant move and the
  boundary contract. Migrations 1–17 are unchanged.
- **Configuration.** Two new API settings. Behaviour change: an API with `AUTH_CONFIG` and
  no issuance URL exits 78.
- **Deployment.** A new role, Secret and connection share.
- **Unchanged.** HTTP routes and responses, credential formats, OpenAPI, the auth settings
  document, telemetry, the worker's privileges and the invitation code.

## Evidence required for acceptance

PR2 adds the tests below; they are accepted only once they pass on CI PostgreSQL 18. PR2 must
show:

- each step of the forgery path above, run as `openmettle_api`, is refused with
  `insufficient_privilege`, and `redeem_home_invitation` is not executable by it;
- the boundary audit refuses a missing issuance role at version 18, an issuance role with an
  extra privilege, and a login role in both `openmettle_api` and `openmettle_issuance`;
- migration 18 refuses to run without the role, and a populated upgrade from the earlier
  authentic binaries preserves sessions, which still validate;
- complete browser, native and first-account sign-ins through the two pools, with the
  existing single-use, revocation, approval, disablement, audience and membership tests
  passing;
- the configuration refusals above, offline.

Where PR2 provides it:

- forgery refusals and the issuance role's exact ACL: `tests/schema/issuance.rs`
  (`api_sql_cannot_issue_and_the_issuance_role_holds_exactly_its_writes`), with the layered
  invitation case in `src/provider_keys/tests/postgres/invitations.rs`;
- boundary audit and migration 18 refusals: `tests/schema/issuance.rs`, and the generalised
  disjoint-role message in `tests/schema.rs`;
- populated upgrades from the authentic v4–v13 binaries, where the retained pre-upgrade
  session validates after migration 18: `tests/schema/grants.rs` (`populated_upgrade`);
- sign-ins through two pools: every `provider_keys::tests::postgres` flow issues on an
  `openmettle_issuance` connection and validates on an `openmettle_api` one, and
  `pooled.rs` shows the issuance checkout returned before the primary is requested;
- configuration refusals: `tests/runtime.rs`
  (`issuance_settings_are_refused_with_a_fixed_line`), `tests/schema.rs` (migrator) and
  `src/tests.rs`.

## Remaining

Core PR2 is implemented: migration 18, `boundaries.sql`, the issuance pool and settings,
tests, README and operator guides. Its PostgreSQL evidence is pending CI. `openmettle-deploy`
still needs the Secret and the connection budget. #73 stays open until both land and the
owner accepts.
