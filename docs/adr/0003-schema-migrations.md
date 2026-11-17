# 0003 — Schema ownership, migrations and bounded database roles

Status: implementation decision for review, 17 November 2026. Implements the first increment of V1-02 (#3); follows ADR 0002 and architecture v1. V1-02 remains open. ADR 0004 extends this first increment with run/event/operation persistence; admission, grants, artifacts and reservations remain outstanding.

## Decision

A separate one-shot `openmettle-migrate` binary and `migrate` image target apply forward-only, transactional migrations embedded at build time from `migrations/`. Deploy runs it once per release, before new API and worker versions roll out. The API and worker never invoke migrations and receive no DDL privilege. PostgreSQL 18 is the only qualified major version; CI uses the digest-pinned 18.1 image from ADR 0002. No other major version is claimed.

### Execution model

- Configuration uses the `OPENMETTLE_MIGRATE_` prefix: mandatory `DATABASE_URL` (postgres/postgresql URI), `CONNECT_TIMEOUT_MS` (1–60000, default 5000), `LOCK_TIMEOUT_MS` (1–600000, default 15000) and `STATEMENT_TIMEOUT_MS` (1–3600000, default 300000). Exit codes: 0 success, 78 invalid configuration, 1 any connection, boundary, lock, migration or signal failure. Messages report a category, migration version, SQLSTATE and, for boundary violations, role and object names only; they never include the URL, SQL text or row values.
- One dedicated, non-pooled connection is opened per run and closed on every outcome. The session sets `lock_timeout`, `statement_timeout`, `client_connection_check_interval=1000ms`, `search_path=pg_catalog,pg_temp`, `standard_conforming_strings=on` and `application_name=openmettle-migrate`. Startup options override database and role defaults. Migrations therefore schema-qualify every OpenMettle object.
- Before SQLx creates any schema or history object, on every run, a read-only boundary check (`src/boundaries.sql`, described under Roles and ownership) runs on the same connection. Any violation exits 1 with nothing changed; the operator corrects provisioning and reruns. The check runs again after migrating; a violation then means a migration over-granted and exits 1 after that migration committed.
- Migrations are applied one version at a time with `RESET ALL` before each, restoring the startup settings. PostgreSQL scans a whole simple-query migration before executing it, so a setting committed by one migration (for example `standard_conforming_strings = off`) cannot change how the next migration is scanned.
- SQLx 0.9.0's migrator takes a session-level advisory lock derived from the database name, creates schema `openmettle` and the history table `openmettle._sqlx_migrations`, verifies checksums and applies each pending migration plus its history row in one transaction. Concurrent runs wait for the lock and then find nothing to do.
- SQLx returns without releasing the advisory lock when a migration fails. Ending the session releases it, which is why the process never reuses the connection. SIGTERM/SIGINT drop the connection and exit 1; PostgreSQL rolls back the open transaction. A killed process is detected by `client_connection_check_interval`, including while waiting for the lock.
- Migrations are never edited after release. An edited applied migration is refused (`VersionMismatch`); a database containing a version unknown to the binary is refused (`VersionMissing`). There are no down migrations and no automated destructive recovery. Recovery from a bad release is a corrective forward migration or a restore (V1-30/V1-31).
- Each migration must stay compatible with the previous release's API and worker so a rolling upgrade can run old and new processes together: add first, remove only in a later release after no running version uses the object.
- Non-transactional migrations are prohibited. Migrations are built with SQLx's `no_tx` flag false, and a lexical check refuses top-level transaction control (`BEGIN`, `COMMIT`, `ROLLBACK`, `END`, `ABORT`, `START`, `SAVEPOINT`, `RELEASE`, `PREPARE`) and the SQLx `-- no-transaction` directive before connecting. It follows PostgreSQL 18's scanner (`scan.l`) for the cases it models: `--` comments end at LF or CR; whitespace includes vertical tab; `E'…'` escape strings start only at a standalone `E`, so a typed literal such as `time'\'` is a standard string; standard strings assume `standard_conforming_strings = on`, which the session pins. It ignores dollar-quoted bodies, strings, quoted identifiers and comments, and fails closed on SQL-standard `BEGIN ATOMIC` bodies. Adjacent string literals, including newline- or comment-separated continuations, are refused because PostgreSQL retains escape-string mode across them. Use one literal or explicit concatenation. It is not a SQL parser. PostgreSQL rejects statements that cannot run in a transaction block, such as `CREATE INDEX CONCURRENTLY`.

### Roles and ownership

Deploy or an operator provisions roles and the database; migrations never create, alter or grant cluster roles and add no global role privileges. The fixed initial names are:

| Role | Purpose | Granted by migrations |
| --- | --- | --- |
| `openmettle_owner` | Migration login; owns the dedicated database, schema `openmettle`, all tables and the history | Owns objects |
| `openmettle_api` | API privileges | `CONNECT`; schema `USAGE`; `SELECT, INSERT` on users, identities, scopes, projects, conversations, messages; `UPDATE (disabled_at)` on users |
| `openmettle_worker` | Worker privileges | `CONNECT`; schema `USAGE`; `SELECT` on users, scopes, projects, conversations; `SELECT, INSERT` on messages |

Application principals are `openmettle_api`, `openmettle_worker`, every role that is directly or indirectly a member of either (their login roles), and `PUBLIC`. The boundary check refuses to migrate unless:

- the session and current user are `openmettle_owner`, it owns the database, and all three roles exist;
- neither the owner nor any principal is superuser or holds CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS;
- `openmettle_owner`, `openmettle_api` and `openmettle_worker` are members of no role at all. Any membership, whether inherited or assumable only with `SET ROLE`, can carry privileges such as `pg_read_all_data`, `pg_write_all_data` or `pg_read_server_files`. Login roles may be members of `openmettle_api` or `openmettle_worker` (or of groups that are), but of nothing else, and never of both;
- principals hold no privilege on the database, any non-system schema, relation, column or `openmettle` function beyond the contract below: `CONNECT` on the database, `USAGE` on schema `openmettle` for the two privilege roles, and the table and column grants in the table above. Before migration 1 has applied, `PUBLIC`'s PostgreSQL defaults (database `CONNECT`/`TEMPORARY`, `public` schema `USAGE`) are tolerated because migration 1 revokes them;
- no audited privilege held by an application principal may carry a grant option, even if the base privilege is permitted;
- `openmettle_owner`'s default privileges (global or per schema) grant nothing to a principal;
- principals own no schema, relation, function or type, and `openmettle_owner` owns schema `openmettle` and every relation in it.

Application roles therefore cannot `SET ROLE` to the owner or obtain DDL, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN, `TEMP` or history access. The check never changes cluster roles, memberships or default privileges; it reports what to fix. It does not inspect large objects, foreign data wrappers, languages or `GRANT … ON PARAMETER`; the migration contract uses none of them. ADR 0004 adds explicit migration-3 table/column privileges only after its successful history record. `src/boundaries.sql` is the authoritative privilege contract; migrations must grant within it, and the post-migration check enforces that.

Role names are cluster-global. Each installation uses one dedicated database. Installations sharing one PostgreSQL cluster would share these role names and therefore each other's database access; this increment does not isolate them. Parameterized role names are a future change if that layout is needed. Unrelated cluster roles and databases are not modified.

Bounded roles constrain processes, not users. The API and worker roles can read every scope's rows. Per-user authorization is application policy owned by V1-05, which is a prerequisite before any product endpoint exposes this data; this schema exposes no user endpoints. Row-level security is not used in this schema-only increment; that is not a permanent product decision.

### Schema

- `users`: internal UUID; email and names are not keys. `user_identities`: exact OIDC issuer/subject pair, `UNIQUE (issuer, subject)`, many pairs per user only through explicit linking.
- `scopes`: the stable ownership and accounting key. A scope is exactly one personal user (at most one personal scope per user) or exactly one project. `projects` and project scopes reference each other through deferred composite foreign keys, so neither can exist without the other after commit.
- `conversations`: `scope_id`, `scope_kind` and `owner_user_id`. A composite foreign key checks the scope kind; a second one, through a stored generated column, requires a personal conversation's owner to be the scope's user. In a project scope the owner records the private creator. Project scope or accounting does not let members read private conversations.
- `messages`: parent-linked skeleton. A composite key keeps a message in its conversation's scope; the parent must be in the same conversation and cannot be the message itself. Content, roles and branch semantics belong to V1-07.
- Foreign keys use the default `NO ACTION`, with no cascades; application roles cannot delete or change ownership keys. Tenant-leading indexes cover conversations and messages by scope.

Composite keys prove relational integrity only. They do not prove that a caller may read or write a row.

### Connection budget

Bound the aggregate at the PostgreSQL server:

`api_replicas × OPENMETTLE_API_DB_MAX_CONNECTIONS + worker_replicas × OPENMETTLE_WORKER_DB_MAX_CONNECTIONS + 1 migrator + admin/backup headroom ≤ max_connections − superuser_reserved_connections − reserved_connections`

Example (illustrative, not qualified sizing): 2 × 4 + 2 × 4 + 1 + 3 = 20 of PostgreSQL's default 100 − 3. During a rolling update, old and new replicas coexist; budget for the surge count. Deploy should enforce each process's share with `ALTER ROLE … CONNECTION LIMIT` on login roles; the CI fixture test checks that a limit refuses the next session (SQLSTATE 53300). Future `LISTEN` connections count outside the pools.

## Dependencies

SQLx 0.9.0 always compiles `sqlx-core`'s migration code, so `sha2` and `crc` were already in the compiled graph. Enabling `sqlx/migrate` was rejected: its weak features (`sqlx-mysql?/migrate`, `sqlx-sqlite?/migrate`) add `sqlx-mysql`, `sqlx-sqlite`, `libsqlite3-sys` and six further packages to `Cargo.lock` (cargo issue 10801), even though they would not compile. Instead `Cargo.toml` adds exact `=0.9.0` direct dependencies on `sqlx-core` (no features) and `sqlx-postgres` (`migrate` feature only). The `Cargo.lock` change is two dependency edges on `openmettle-core`; the compiled package set is unchanged (149 packages by `cargo tree -e normal`). Both crates are from https://github.com/launchbadge/sqlx (MIT OR Apache-2.0). SQLx documents these crates as internal; the exact pins mean any SQLx upgrade must revisit this module. No `uuid`, `time` or macro crates are used; tests read UUIDs and timestamps as text.

## Evidence and limits

`tests/schema.rs` runs against the isolated CI PostgreSQL service: fresh install and idempotent rerun, populated version 1 → 2 upgrade preserving rows, four concurrent migrators, held-lock timeout (SQLSTATE 55P03), SIGTERM/SIGKILL of a lock waiter and of a migrator holding the lock inside migration 2's uncommitted DDL (rollback, session and lock removal, immediate rerun), failed and timed-out migrations leaving no partial state followed by an immediate retry, refusal of non-transactional migrations including a CR-terminated comment and a committed `standard_conforming_strings` change, checksum drift and newer databases, wrong-login refusal before bootstrap followed by an immediate owner success, refused role memberships (direct, `SET`-only, indirect, login roles, both privilege roles, owner) and attributes, refused database, schema, table, column, default and ownership privileges on fresh and migrated databases, a post-migration over-grant, the privilege matrix and actual denied operations, cross-scope and wrong-parent rejection, a concurrent unique identity race, a role connection limit, and API/worker readiness under the bounded roles without migrating. `runtime/verify-migrate-image.sh` checks the image's non-root user, exit 78, fresh install and rerun.

Not covered by the original increment (run/event/operation extensions are in ADR 0004): grants, artifacts, reservations, admission policy, a schema-compatibility readiness gate, Helm Job/hook and production role provisioning (V1-32), backup/restore of roles (V1-30/V1-31), and connection sizing under load.

The dedicated migrator connection holds the SQLx advisory lock from before boundary validation until connection closure, including between version steps. This prevents concurrent upgrades from changing grants between reading migration history and checking ACLs. SQLx version steps acquire the same lock reentrantly; their unlock does not release the outer acquisition.
