# 0031 — Filesystem artifact storage and streaming multipart uploads

Status: accepted with its implementation; V1-15 implementation contract. PR1 (storage engine) and PR2 (HTTP routes and
OpenAPI, [below](#pr2-http-routes)), 20 November 2026. Agent-authored; owner approval,
independent review and CI acceptance are separate gates. Refs #15; Refs #62. #15 remains open
for the work listed under [Consequences](#consequences).

## Problem

ADR 0005 accounts for artifact bytes but stores no payload. V1-15 needs uploaded files on a
persistent volume, written so that a crash, a cancelled request or a retried request never
leaves a charged revision without a payload, or a payload that nobody is charged for. The
upload format is `multipart/form-data`, and no new crate may be added to parse it.

## Decision

PR1 adds the storage engine; PR2 serves it through `/v1` ([PR2: HTTP routes](#pr2-http-routes)).

| Item | Location |
| --- | --- |
| Directory validation, staging, publication, ingest and reconciliation | `src/artifact_fs.rs` |
| Streaming RFC 7578 parser | `src/multipart.rs` |
| `display_name` on `artifact_revisions` | `migrations/0017_artifact_revision_display_name.sql` |
| `display_name` in `storage::settle` and its exact replay | `src/storage.rs` |
| `CreateInScope` with project lifecycle | `authz::projects::authorize_create_in_scope` |

### Configuration

`OPENMETTLE_API_ARTIFACTS_DIR` and `OPENMETTLE_WORKER_ARTIFACTS_DIR` are optional and
independent, like every other ADR 0002 setting. The migrator never reads
`OPENMETTLE_MIGRATE_ARTIFACTS_DIR`. Unset, no directory is opened and the process starts exactly
as before; `runtime/process-contract.json` is unchanged.

A set value must be an absolute path to an existing directory whose leaf is not a symbolic link.
At startup, before telemetry or the listener, the process creates `staging` and `revisions`
(mode 0700) if they are absent, requires each to be a real readable directory and `fsync`s the
root. A non-UTF-8, empty, relative or otherwise refused value exits 78 with exactly
`configuration error: invalid ARTIFACTS_DIR` (or `configuration must be UTF-8`), never the path
or an OS message. Symbolic links above the leaf are allowed, so a mount point may be reached
through one.

### Layout

```text
<ARTIFACTS_DIR>/
  staging/<reservation_id>     in-progress upload, mode 0600, created exclusively
  revisions/<reservation_id>   published payload of one settled (or settling) revision
```

`reservation_id` is the server-generated UUID that `storage::reserve` returns. A name is used
only after it passes the canonical lower-case UUID check, so it contains no separator, dot or
NUL. No client file name, request value or database path column ever forms a path. One
reservation settles into exactly one revision (ADR 0005), so the reservation UUID identifies
the payload of that revision for its whole life.

### Display names

Migration 17 adds a nullable `artifact_revisions.display_name`: 1 to 255 characters, no control
character and no leading or trailing white space. The database checks ASCII classes; the Rust
check (`storage::valid_display_name`) also refuses Unicode controls and white space. The
parser takes the multipart `filename`, drops any directory part as RFC 7578 §4.2 advises, and
treats an absent or empty result as no name. The name is display metadata only. The column is
insert-only for both application roles and is part of `settle` replay: the same reservation
settled again with another name, size, digest or media type returns `Conflict`. Rows written
before version 17 have no name and replay with `None`. Older binaries keep working: they never
name the column.

### Upload and publication order

`artifact_fs::ingest` composes the ADR 0005 helpers with the filesystem. Each database step is
its own committed transaction; no transaction stays open while the body streams.

1. Parse the request `Content-Type`. A refusal reserves nothing.
2. `reserve` with `(scope, actor, Idempotency-Key, artifact, max_bytes)`.
3. Create `staging/<id>` with `create_new` and mode 0600 (blocking I/O runs in
   `spawn_blocking`).
4. Feed body chunks to the parser and write the file part's bytes. The sink counts observed
   bytes against `max_bytes`, whether or not the request declared a length, and computes
   SHA-256 incrementally.
5. After the closing delimiter, the caller's check sees the media type, display name and raw
   metadata JSON.
6. `fsync` the file.
7. In one transaction: lock the reservation row; if it is still `reserved`, `rename` the file
   to `revisions/<id>` and `fsync` `revisions/`; otherwise unlink the staging file. Then
   `settle` with size, digest, media type and display name, and commit.

Before step 7, any refusal (multipart, ceiling, caller check, body read or I/O) unlinks the
staging file and then releases the reservation. A cancelled request future unlinks its staging
file when dropped, but leaves its reservation `reserved`. A failed rename unlinks both paths,
rolls back and releases. A failed `settle` or commit after the rename leaves `revisions/<id>`:
the commit may have succeeded, so only a retry or the reconciler can decide.

The row lock serializes publication with other requests under the same key and with
`reconcile_expired`. A request that staged after another one published therefore never renames
over a settled payload: it finds the reservation `settled`, discards its file and `settle`
replays or conflicts. A reservation released meanwhile gets no file and conflicts.

### Retry identity

The idempotency identity is the ADR 0005 reservation identity: the `Idempotency-Key`, scope,
actor, target artifact and byte ceiling. The multipart boundary, part order and chunking are not
part of it. PR2 must take `max_bytes` from a stable value (the route's configured ceiling or a
declared file size), never from the multipart `Content-Length`, which changes with the boundary.

| Reservation state on retry | Behaviour |
| --- | --- |
| `reserved`, no staging file | A crashed or failed earlier attempt: stream again. A leftover `revisions/<id>` is replaced by the rename. |
| `reserved`, staging file exists | Another request is streaming, or a crash awaits reconciliation: `InProgress`, nothing touched |
| `settled` | Re-read the body without writing, then `settle` as an exact replay: the same revision, no second charge. A changed body or name conflicts; a missing payload file is `Missing`, never recreated |
| `released` | The key is spent: `Conflict` |

### Reconciliation

`reconcile_expired(pool, store, older_than, limit)` releases up to `limit` (1 to 1000) upload
reservations (no run link) still `reserved` more than `older_than` after creation, oldest first.
For each, it locks the reservation row, rechecks the state, unlinks `staging/<id>` and
`revisions/<id>`, then calls `release` in the same transaction, so no uncharged file remains.
`older_than` must exceed the longest permitted upload plus settlement; an upload still running
past it would lose its reservation, and its `settle` would then conflict. After reconciliation
the client must retry with a new key. Either application role can run it.

`purge_due(pool, store, limit)` claims expired `retained` revisions with `begin_purge`, resumes
claims left by a crash, unlinks `revisions/<reservation>` and syncs the directory, then calls
`confirm_purge` in a later transaction, as ADR 0005 requires. It needs the worker's purge column
grants. A revision restored since the scan is skipped. No scheduler calls either helper yet.

### Multipart parser

`multipart::Parser` is sans-I/O. It accepts chunks of any size, down to one byte. Memory is the
current chunk, a carry of at most one header block (8 KiB) or one delimiter (at most 73 bytes),
and the metadata part (64 KiB). Preamble and epilogue are each limited to 1 KiB. The file bytes
are handed out as soon as they cannot be part of a delimiter.

A form is exactly one `file` part, with an explicit `Content-Type` (not `multipart/*`) and an
optional `filename`, and one `metadata` part of `application/json` (optionally
`charset=utf-8`), in either order. Any other part name, a repeated part, a third part, a part
header other than `Content-Disposition` and `Content-Type` (including
`Content-Transfer-Encoding`), `filename*`, obs-fold, control characters, non-UTF-8 headers or a
stream without its closing `--boundary--` is refused. The boundary must be 1 to 70 RFC 2046
`bchars`. Errors are fixed categories; none carries request bytes.

### Creating in a scope

`authorize_scope(CreateInScope)` is a pure decision with no project lifecycle. No creation path
consulted the lifecycle, so PR1 adds `authorize_create_in_scope`: a personal scope admits its
owner; a project scope needs an editor, conceals a missing, deleted or invisible project, and
refuses an archived one with `project is archived` after authorization. PR2 calls it before
`reserve`.

## PR2: HTTP routes

| Item | Location |
| --- | --- |
| The four operations, query, `Range` and problem mapping | `src/v1/artifacts.rs`, routed by `src/v1.rs` |
| The store opened once at startup and handed to the router | `src/lib.rs` |
| Artifact read, download and write decisions with lifecycle | `authz::projects::authorize_artifact` |
| Retry artifact lookup and revision reads | `storage::upload_artifact`, `storage::read_revision` |
| Bounded streaming body over a payload range | `artifact_fs::Store::read`, `artifact_fs::Content` |
| Operations, schemas, multipart wire examples and fixtures | `contracts/openapi/openmettle-v1.json`, `contracts/fixtures/` |

The contract is in ADR 0007 ([Artifact payload operations](0007-application-api-contract.md#artifact-payload-operations-v1-15-pr2)).
This section records the storage decisions behind it.

- **Store.** `run` opens `ARTIFACTS_DIR` once and passes the `Store` to the router. Without it
  the uploads and the content download answer `503 provisioning` before the session is
  validated, so nothing is reserved or staged; revision metadata and every other route work.
- **Target before reservation.** The scope comes from the query, never from the `metadata`
  part: either part may arrive first, and the reservation must exist before the first file
  byte is written. `createArtifact` authorizes `CreateInScope` with the project lifecycle
  (`authorize_create_in_scope`); `createArtifactRevision` authorizes `Write` on the artifact
  with its lifecycle (`authorize_artifact`). Both run on the primary before `reserve`. A
  grant revoked while the body streams does not stop that upload; the next request is
  decided again.
- **Retry identity.** `max_bytes` is the query value or the 64 MiB route ceiling, never the
  body length. The reservation key is the ADR 0007 request key (operation, target and client
  key, SHA-256). A new artifact's UUID is random; `upload_artifact` returns the one an earlier
  reservation with the same key chose, so an exact retry reserves the same identity. Two first
  attempts racing on one key may pick different artifacts: the later `reserve` conflicts and
  that request is `409 idempotency_conflict`.
- **Metadata part.** A closed JSON object with no members (`{}`), decoded in the `ingest`
  check. Unknown members are `400 validation`. New optional members are additive; one that
  changes the stored revision must join the settlement replay comparison.
- **Error mapping.** Multipart, body, metadata and ceiling refusals are `400 validation`;
  `InProgress` is `409 conflict`; a reservation or settlement conflict, including a key whose
  earlier upload was released, is `409 idempotency_conflict`; owner and instance limits are
  `429 quota`; unconfigured limits are `503 provisioning`; I/O failures and a missing settled
  payload are `500 internal`.
- **Deadline.** Authorization, reservation, streaming and settlement run within 600 s
  (`UPLOAD_TIMEOUT`). An elapsed upload drops its future: the staging file is unlinked and the
  reservation stays `reserved` until a retry or `reconcile_expired`, whose `older_than` must
  exceed 600 s plus settlement. The upload holds one of the 256 in-flight permits throughout.
- **Downloads.** `Download` (equal to `Read` for artifacts) is decided on the primary for every
  request. Only an `active` revision serves bytes; `retained`, `purging` and `purged` are
  `409 conflict`, while their metadata stays readable. `Store::read` requires a regular file
  of exactly the settled size, seeks to the range and streams 64 KiB reads from the blocking
  pool with an exact `Content-Length`; a missing or resized file is `500 internal` without a
  path. The in-flight permit is released when the response is returned, before its body
  streams; the body holds an open file and at most one 64 KiB buffer.

## Topology limits

The engine assumes one filesystem visible to every process that writes or purges payloads.

- **Single node, `ReadWriteOnce`.** API and worker pods must run on the node that mounts the
  volume. Rename, `fsync` and exclusive creation are local-filesystem guarantees.
- **Several nodes, `ReadWriteMany`.** Every writer must see the same directory with POSIX
  `rename`, `O_EXCL` creation and `fsync` semantics. Many network filesystems weaken some of
  these. Qualify the storage class before relying on it; this ADR does not.
- Payloads are not encrypted at rest by OpenMettle; use volume encryption.
- Backups must capture PostgreSQL and the volume consistently. A database restored without its
  payloads yields `Missing`; payloads without rows are uncharged files that only a manual sweep
  finds.

## Consequences

- No new crate. The parser, store and engine use `std`, Tokio, `sha2`, `http-body-util` and
  `axum`'s re-exported body trait, all already locked.
- `max_bytes` stays reserved for the whole upload and is charged against quotas until
  settlement. A crashed upload holds its reservation until `reconcile_expired` runs.
- Retries that hit a crashed upload's staging file get `InProgress` until reconciliation.
- Not implemented: a reconciliation or purge schedule (the worker calls neither helper), a sweep
  for files without rows, media-type allowlists, metadata members, a per-chunk idle deadline
  (only the 600 s upload deadline), a separate bound on concurrent uploads, entity tags,
  multi-range responses, and throughput or storage-class qualification.
