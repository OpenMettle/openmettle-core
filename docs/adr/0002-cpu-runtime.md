# 0002 — CPU process and database health runtime

Status: implementation decision for review, 16 November 2026. Implements the bounded runtime portion of V1-01 (#2); follows decision 0001 and architecture v1.

## Decision

Use Axum HTTP/1, Tokio and SQLx PostgreSQL in one Rust library with separate API and worker entry points and image targets. The worker currently serves process/database health only; it does not claim jobs. No schema, migrations, application endpoints, identity, broker, GPU, DRA or Flutter dependency is introduced.

Each process reads only its own `OPENMETTLE_API_` or `OPENMETTLE_WORKER_` variables: `BIND` (numeric socket address, default loopback ports 8080/8081), mandatory `DATABASE_URL` (postgres/postgresql URI), `DB_MAX_CONNECTIONS` (1–64, default 4), `DB_TIMEOUT_MS` (1–30000, default 2000), and `SHUTDOWN_TIMEOUT_MS` (1–60000, default 5000). Invalid configuration exits 78 without logging values. Bind/signal/server failures exit 1. The URL retains SQLx TLS options; deployments must supply their required TLS policy and trust roots. No database URL is logged.

`GET /healthz` returns 200 `ok` while serving. `GET /readyz` returns 200 `ready` only after a successful `SELECT 1`; connection acquisition and query together have the configured deadline. Failure returns 503 `not ready` without database details. Startup does not wait for PostgreSQL. Readiness recovers on a subsequent successful probe. API readiness never queries the worker. These unauthenticated operational endpoints carry no user data; deploy must restrict network exposure. There is no product API or authorization claim.

SIGINT/SIGTERM stops admission, drains HTTP requests, and closes the pool within one shutdown deadline. Deadline expiry exits 1. There are no durable tasks to drain yet. Runtime thread count is two per process; connection pools and configuration are independent.

## Dependencies and alternatives

Direct crates are exact pins from the crates.io registry (`https://github.com/rust-lang/crates.io-index`); Cargo.lock records resolved versions and checksums for the full graph. Metadata was verified with `cargo info` before reuse.

| Crate | Version | Origin | Declared licence | Purpose |
| --- | --- | --- | --- | --- |
| axum | 0.8.9 | https://github.com/tokio-rs/axum | MIT | HTTP routing and graceful server shutdown |
| tokio | 1.54.1 | https://github.com/tokio-rs/tokio | MIT | Async runtime, sockets, signals and deadlines |
| sqlx | 0.9.0 | https://github.com/launchbadge/sqlx | MIT OR Apache-2.0 | PostgreSQL pool and queries, rustls TLS |

Default features are disabled. SQLx macros, migration support and other database drivers are excluded. `SELECT 1` uses runtime queries, so build/lint/unit tests need no database or generated SQL metadata. Fetch dependencies once, then run locked offline checks. V1-42 owns the dynamically resolved transitive licence/notice inventory and distribution clearance; these direct declarations do not clear images or the complete graph for publication.

A hand-written HTTP server would add protocol maintenance. A synchronous database client would block async request execution. An external broker and domain scaffolding have no consumer in this increment. Keep shared code limited to the actual process contract.

## Delivery and evidence boundary

Docker targets produce separate non-root images. Base images are digest pinned in Dockerfile; PostgreSQL is a digest-pinned test service in CI. These are build/test fixtures, not release approval. `runtime/process-contract.json` specifies separate readiness, service-account names and example resource requests for deploy to consume. It is not a Helm chart or evidence of Kubernetes execution. Deploy owns manifests, RBAC and resource qualification. V1-02 owns schema; V1-03 owns product APIs; V1-29 owns telemetry.

Tests exercise real subprocesses, invalid configuration, unavailable database, database recovery, signal shutdown and API survival after a worker stops. The PostgreSQL test is explicitly ignored in the offline suite and required separately in CI. No domain data is created. Rollback restores the previous binary/image; no schema rollback is necessary.

Image inputs were resolved with `docker buildx imagetools inspect` on 16 November 2026: `docker.io/library/rust:1.100.0-slim-bookworm` (`sha256:7c7d4eb4d05b7781187a327809466cfddf29753f6defdc3d19a0e291951b7a37`), `docker.io/library/debian:bookworm-slim` (`sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc`), and test-only `docker.io/library/postgres:18.1-bookworm` (`sha256:cc9f4143a8d2fa8cf3749d0cb4d26ecf2d53a77a2ac807e9ebd67ae22426221a`). Image recipes originate at https://github.com/rust-lang/docker-rust (Apache-2.0), https://github.com/debuerreotype/docker-debian-artifacts and https://github.com/docker-library/postgres (MIT); PostgreSQL itself uses the PostgreSQL License. Debian and bundled packages have individual licences: no single image-wide licence or redistribution clearance is asserted. V1-42 must inventory those packages before distribution.
