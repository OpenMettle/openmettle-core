# 0003 — Schema ownership, migrations and bounded database roles

Status: implementation decision for review, 17 November 2026. Implements the first increment of V1-02 (#3); follows ADR 0002 and architecture v1. V1-02 remains open: runs, events, admission, grants, artifacts, reservations and operation records are not implemented here.

## Decision

A separate one-shot `openmettle-migrate` binary and `migrate` image target apply forward-only, transactional migrations embedded at build time from `migrations/`. Deploy runs it once per release, before new API and worker versions roll out. The API and worker never invoke migrations and receive no DDL privilege. PostgreSQL 18 is the only qualified major version; CI uses the digest-pinned 18.1 image from ADR 0002. No other major version is claimed.

### Execution model

- Configuration uses the `OPENMETTLE_MIGRATE_` prefix: mandatory `DATABASE_URL` (postgres/postgresql URI), `CONNECT_TIMEOUT_MS` (1–60000, default 5000), `LOCK_TIMEOUT_MS` (1–600000, default 15000) and `STATEMENT_TIMEOUT_MS` (1–3600000, default 300000). Exit codes: 0 success, 78 invalid configuration, 1 any connection, lock, migration or signal failure. Messages report a category, migration version and SQLSTATE only; they never include the URL, SQL text or row values.
- One dedicated, non-pooled connection is opened per run and closed on every outcome. The session sets `lock_timeout`, `statement_timeout`, `client_connection_check_interval=1000ms`, `search_path=pg_catalog,pg_temp` and `application_name=openmettle-migrate`. Migrations therefore schema-qualify every OpenMettle object.
- SQLx 0.9.0's migrator takes a session-level advisory lock derived from the database name, creates schema `openmettle` and the history table `openmettle._sqlx_migrations`, verifies checksums and applies each pending migration plus its history row in one transaction. Concurrent runs wait for the lock and then find nothing to do.
- SQLx returns without releasing the advisory lock when a migration fails. Ending the session releases it, which is why the process never reuses the connection. SIGTERM/SIGINT drop the connection and exit 1; PostgreSQL rolls back the open transaction. A killed process is detected by `client_connection_check_interval`, including while waiting for the lock.
- Migrations are never edited after release. An edited applied migration is refused (`VersionMismatch`); a database containing a version unknown to the binary is refused (`VersionMissing`). There are no down migrations and no automated destructive recovery. Recovery from a bad release is a corrective forward migration or a restore (V1-30/V1-31).
- Each migration must stay compatible with the previous release's API and worker so a rolling upgrade can run old and new processes together: add first, remove only in a later release after no running version uses the object.
- Non-transactional migrations are prohibited. Migrations are built with SQLx's `no_tx` flag false, and a lexical check refuses top-level transaction control (`BEGIN`, `COMMIT`, `ROLLBACK`, `END`, `ABORT`, `START`, `SAVEPOINT`, `RELEASE`, `PREPARE`) and the SQLx `-- no-transaction` directive before connecting. It ignores dollar-quoted bodies, strings, identifiers and comments, and fails closed on SQL-standard `BEGIN ATOMIC` bodies. PostgreSQL rejects statements that cannot run in a transaction block, such as `CREATE INDEX CONCURRENTLY`.

### Roles and ownership

Deploy or an operator provisions roles and the database; migrations never create, alter or grant cluster roles and add no global role privileges. The fixed initial names are:

| Role | Purpose | Granted by migrations |
| --- | --- | --- |
| `openmettle_owner` | Migration login; owns the dedicated database, schema `openmettle`, all tables and the history | Owns objects |
| `openmettle_api` | API privileges | `CONNECT`; schema `USAGE`; `SELECT, INSERT` on users, identities, scopes, projects, conversations, messages; `UPDATE (disabled_at)` on users |
| `openmettle_worker` | Worker privileges | `CONNECT`; schema `USAGE`; `SELECT` on users, scopes, projects, conversations; `SELECT, INSERT` on messages |

Migration 1 fails unless it runs as `openmettle_owner` in a database owned by `openmettle_owner`, both application roles exist, none of the three roles is superuser or holds CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS, and neither application role is a member of the owner or of the other application role. Application roles therefore cannot `SET ROLE` to the owner. Application roles get no DELETE, TRUNCATE, REFERENCES, TRIGGER, DDL, `TEMP` or history access. Migration 1 revokes all database privileges and all `public` schema privileges from `PUBLIC`, so other logins cannot connect to the dedicated database.

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

`tests/schema.rs` runs against the isolated CI PostgreSQL service: fresh install and idempotent rerun, populated version 1 → 2 upgrade preserving rows, four concurrent migrators, held-lock timeout (SQLSTATE 55P03), SIGTERM/SIGKILL session cleanup, failed and timed-out migrations leaving no partial state followed by an immediate retry, refusal of non-transactional migrations, checksum drift and newer databases, non-owner refusal, the privilege matrix and actual denied operations, cross-scope and wrong-parent rejection, a concurrent unique identity race, a role connection limit, and API/worker readiness under the bounded roles without migrating. `runtime/verify-migrate-image.sh` checks the image's non-root user, exit 78, fresh install and rerun.

Not covered: runs, events and admission idempotency, grants, artifacts, reservations, operation records, a schema-compatibility readiness gate, Helm Job/hook and production role provisioning (V1-32), backup/restore of roles (V1-30/V1-31), and connection sizing under load.
