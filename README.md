# OpenMettle core

Rust API and worker foundation for OpenMettle. Both processes serve CPU-only health and PostgreSQL readiness endpoints. The worker does not execute jobs yet. A separate one-shot migrate process creates identities, ownership scopes, projects, conversations, a message graph skeleton, branch identities and run/event/operation persistence. No product API, authentication, per-user authorization or GPU orchestration is implemented. Runtime qualification and deployment acceptance remain separate gates.

## Start here

- [Accepted architecture v1](ARCHITECTURE-v1.md), including service diagrams and all 43 delivery tickets.
- [Repository boundaries](REPOSITORIES.md), [decisions](DECISIONS.md) and [provenance](UPSTREAM.md).
- [Live delivery tracker](https://github.com/orgs/OpenMettle/projects/1/views/1?filterQuery=%5BV1-00%5D&pane=issue&itemId=307308630).

## Development

Install Rust through the [official rustup installer](https://rustup.rs/). The repository pins Rust 1.100.0 with rustfmt and Clippy; Cargo installs the selected components through rustup when required. Python 3.10+ runs the repository check.

```sh
python3 scripts/check_repository.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
```

API and worker share operational code and build independently with `cargo build --locked --bin openmettle-api` and `cargo build --locked --bin openmettle-worker`. After `cargo fetch --locked`, add `--offline` to build, Clippy and test commands. Locked resolution and digest-pinned images constrain inputs; they do not prove bit-for-bit reproducibility.

### CI caching

The Rust runtime job restores Cargo downloads and `target/` build outputs before
running the normal checks. Every format, lint, build, unit test and PostgreSQL
integration command still runs; a cache hit never substitutes for a test result.
Keys separate operating systems and architectures and include the toolchain,
Cargo manifests/lockfiles, Cargo configuration and workflow. Each commit can save
an updated build cache while restoring a compatible earlier entry. Cargo decides
which outputs need rebuilding. Incremental compiler state is excluded.

Only successful pushes to `main` save caches. Pull requests restore them without
writing. A miss rebuilds normally with `cargo fetch --locked`; subsequent checks
remain locked and offline. Do not add credentials, database data, kubeconfigs or
qualification reports to the cached paths. The pinned GitHub `actions/cache` v5
restore/save actions are MIT-licensed CI tooling (see `provenance/register.json`).

For a cold verification run, dispatch **CI** with **use_cache** disabled. To
invalidate the shared cache namespace, increment `cargo-v1` in both key prefixes.
Compare the Rust job's restore, compile/test and save durations on cold and warm
runs before claiming a speed improvement. Cache storage and transfer overhead
must remain worthwhile as the workspace grows. This cache does not accelerate
the separate Docker image or kind build jobs; those need BuildKit layer caching.

## Runtime

Read [runtime ADR 0002](docs/adr/0002-cpu-runtime.md) for dependency origins, licences, configuration bounds and shutdown behavior. Supply each process's database URI through deployment-managed environment configuration. Do not commit credentials. For an isolated local test database only:

```sh
export OPENMETTLE_API_DATABASE_URL='postgres://fixture:fixture@127.0.0.1:5432/fixture?sslmode=disable'
cargo run --locked --bin openmettle-api
```

In another terminal, `curl --fail http://127.0.0.1:8080/healthz` returns `ok`. `/readyz` returns `ready` after a successful database query, or HTTP 503 if PostgreSQL is unavailable. Restoring PostgreSQL allows a later probe to succeed without restarting the process. The API and worker never create or migrate tables, and readiness does not check the schema version. These endpoints are operational and must not be exposed as a public product API.

The worker uses `OPENMETTLE_WORKER_DATABASE_URL` and port 8081. Every setting is independent: `BIND`, `DATABASE_URL`, `DB_MAX_CONNECTIONS`, `DB_TIMEOUT_MS` and `SHUTDOWN_TIMEOUT_MS` use the corresponding `OPENMETTLE_API_` or `OPENMETTLE_WORKER_` prefix. Defaults bind loopback; containers bind all interfaces unless overridden. Send SIGTERM or SIGINT to drain and stop. Invalid configuration exits 78; runtime failures or shutdown deadline expiry exit 1. Correct configuration and restart after these errors. Database failures affect readiness, not liveness.

Run the real PostgreSQL subprocess test against an isolated test database:

```sh
export TEST_DATABASE_URL='postgres://fixture:fixture@127.0.0.1:5432/fixture?sslmode=disable'
cargo test --locked --test runtime -- --ignored
```

The normal test suite covers configuration rejection, bind failure, database timeout, liveness and shutdown without PostgreSQL. CI separately requires the PostgreSQL tests, builds the API, worker and migrate Docker targets and exercises database loss/recovery and API survival after stopping the worker. Test credentials above are synthetic and must never be used for a deployment.

Build separate images with `docker build --target api -t openmettle-api:test .` and `docker build --target worker -t openmettle-worker:test .`. No images are published by CI. The [process contract fixture](runtime/process-contract.json) supplies separate service-account names, resource request examples and probes for deploy. The [Kubernetes qualification](tests/kubernetes/README.md) workflow runs that contract on an ephemeral kind cluster classified dev. It observes separate ServiceAccounts with token automount disabled, the requested resources, independent process settings, readiness, API survival with the worker scaled to zero, independent scaling and clean shutdown. Its manifests are test fixtures. Resource sizing is unqualified, and generic Helm packaging and RBAC belong to deploy (V1-32).

## Schema migrations

Read [ADR 0003](docs/adr/0003-schema-migrations.md) for the migration, role and ownership contract and [ADR 0004](docs/adr/0004-run-persistence.md) for run/event/operation persistence, limits and replay semantics. PostgreSQL 18 is the only qualified major version. Migrations in `migrations/` are embedded in the `openmettle-migrate` binary, forward-only and transactional; released migrations are never edited. Run the migrate image once per release, before rolling out new API and worker versions. Each release's migrations must remain compatible with the previous API and worker.

Provision the roles and one dedicated database before the first migration, using deployment-managed secrets for passwords. Before creating anything, and on every later run, the migrator checks the provisioning and exits 1 with nothing changed if it is unsafe. Log in as `openmettle_owner`, which must own the database. Do not make any of these roles superuser or give them CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS. Keep `openmettle_owner`, `openmettle_api` and `openmettle_worker` out of every other role, including predefined roles such as `pg_read_all_data` and `pg_write_all_data`; this applies to `SET ROLE`-only memberships too. Separate login roles may be members of exactly one of `openmettle_api` or `openmettle_worker` and of nothing else. Do not grant those roles, their logins or `PUBLIC` any database, schema or table privilege yourself, and do not set default privileges for `openmettle_owner`; the migrations grant exactly what [ADR 0003](docs/adr/0003-schema-migrations.md) lists. The error names each violation to fix. Role names are cluster-global: installations sharing a PostgreSQL cluster would share these roles and so each other's database access, which this increment does not isolate. A superuser runs, for example (psql variables):

```sql
CREATE ROLE openmettle_owner LOGIN PASSWORD :'owner_password';
CREATE ROLE openmettle_api LOGIN PASSWORD :'api_password' CONNECTION LIMIT 8;
CREATE ROLE openmettle_worker LOGIN PASSWORD :'worker_password' CONNECTION LIMIT 8;
CREATE DATABASE openmettle OWNER openmettle_owner;
```

Then run the migrator with the owner's URL. It reads `OPENMETTLE_MIGRATE_DATABASE_URL` and optional `OPENMETTLE_MIGRATE_CONNECT_TIMEOUT_MS` (default 5000), `OPENMETTLE_MIGRATE_LOCK_TIMEOUT_MS` (default 15000) and `OPENMETTLE_MIGRATE_STATEMENT_TIMEOUT_MS` (default 300000). It exits 0 on success, 78 on invalid configuration and 1 on any other failure, including a lock wait past its deadline. Concurrent runs are serialized. A failed or interrupted run leaves no partial migration and can be retried immediately. A checksum mismatch or a database newer than the binary is refused. Do not delete history rows or rerun edited files; ship a corrective migration or restore a backup instead.

```sh
export OPENMETTLE_MIGRATE_DATABASE_URL='postgres://openmettle_owner:<password>@127.0.0.1:5432/openmettle?sslmode=disable'
cargo run --locked --bin openmettle-migrate
```

Give the API `openmettle_api` credentials and the worker `openmettle_worker` credentials, never the owner's. These roles bound each process, not each user: both can read every scope's rows. Per-user authorization (V1-05) is required before any product endpoint uses this data.

Connection budget: `api_replicas × API DB_MAX_CONNECTIONS + worker_replicas × worker DB_MAX_CONNECTIONS + 1 migrator + admin/backup headroom` must not exceed `max_connections − superuser_reserved_connections − reserved_connections`. Count surge replicas during a rolling update. For example, 2 × 4 + 2 × 4 + 1 + 3 = 20. Enforce each process's share with its login role's `CONNECTION LIMIT`. These figures are illustrative, not qualified sizing.

The schema tests also require `OLD_BINARY_DIR` pointing to binaries built from release `18f52463c9d6bc12dda4bd1558e4597e067018f8`; CI builds that exact archive for compatibility checks. Do not substitute the current binary with a truncated migration list.

The schema tests need a superuser on an isolated, disposable PostgreSQL 18 service. They create synthetic `openmettle_*` cluster roles with a test-only password and one database per test. Never point them at a shared server.

```sh
export TEST_DATABASE_URL='postgres://fixture:fixture@127.0.0.1:5432/fixture?sslmode=disable'
cargo test --locked --test schema -- --ignored
```

Build the migrate image with `docker build --target migrate -t openmettle-migrate:test .`; it runs as the same non-root user as the other images. Deploy (V1-32) owns the Kubernetes Job or hook, production role provisioning and secrets.

## Ownership

V1-02 owns schema/migrations (run/event/operation persistence is implemented; admission, grants, artifacts and reservations remain open), V1-03 owns application/event/capacity contracts, and V1-42 owns transitive provenance and distribution clearance. Supported runtime targets for this increment are Linux containers and Unix development hosts; Windows signal behavior is not implemented.

The app repository consumes core APIs. The deploy repository owns generic Helm packages. Private site values and curated fork implementations stay outside this tree.

## Baseline maintenance

The baseline is the complete accepted document exported from the [planning Page](https://chatgpt.com/space/page_fef707d85d8c8191a14f162d6281307d). SOURCE-REFERENCES.md retains neutral aliases, source pins and paths for personal repository citations; the Page retains original URLs. The native workbook reference points back to that archive. These portability/privacy changes do not amend the accepted architecture. Record subsequent decisions in DECISIONS.md and link implementation tickets.
