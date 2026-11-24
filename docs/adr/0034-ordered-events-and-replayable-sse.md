# 0034 — Ordered run events, cursor MACs and replayable `/v1` SSE

Status: accepted with its implementation; V1-12 design (PR1), 20 November 2026. Agent-authored; owner approval,
independent review and CI acceptance are separate gates. Refs #12 and #63. PR1 recorded this
design and a pointer from ADR 0007. Implementation status: PR2 implemented the cursor MAC codec,
`cursor_keys` configuration, and `GET /v1/runs/{run_id}` / `GET /v1/runs/{run_id}/events`
routes on `main`. #12 and #63 remain open.

## Problem

ADRs 0004 and 0032 persist an ordered, append-only event log per run, but no client can read
it. ADR 0007 publishes the `RunEvent` envelope, the `RunEventItem` item schema, the
`RunEventStream` media type and the `Last-Event-ID`/`after` parameters, and leaves to V1-12
the cursor integrity, the event types, retention, resynchronization, snapshots, buffering and
authorization during replay. A client that connects at any time (queued, running or long after
completion), disconnects, or lands on another API pod must reconstruct the run with no lost or
duplicated UI effect, and must stop receiving events as soon as it loses access.

### What `main` (`3613a51`) already provides

| Need | Present | Gap |
| --- | --- | --- |
| Per-run order | `append_event` locks the run row, increments `runs.last_event_sequence` and inserts the event in one transaction, so later sequences never commit before earlier ones | None; reused |
| Index for forward reads | `run_events` primary key `(run_id, sequence)` and `run_events_scope_run_idx (scope_id, run_id, sequence)` (migration 3) | None; no migration needed |
| Lifecycle events | `run-created` (empty payload, sequence 1); `openmettle.run-claimed` v1 `{}` under `claim:<token>`; one terminal event under `run-terminal`: `openmettle.run-cancelled` v1 `{"reason":"requested"\|"revoked"}`, `openmettle.run-expired` v1 `{}` | No wire types; V1-11 adds `succeeded`, `failed` and `interrupted` under `run-terminal` |
| Internal events | `openmettle.operation-intent` (payload: operation UUID) and caller-defined observation evidence | Must never reach a client |
| Read authorization | `read_resource` (ADR 0027): principal, membership, project lifecycle and shares, decided on the primary per request | Not applied to runs |
| Wire envelope | `RunEvent`, `RunEventItem`, `RunEventStream`, `Cursor` (base64url, at most 512), `invalid_cursor` (400) | No operation uses them; no MAC |
| Keys | Login `KeyRing` (ADR 0009): 32-byte files named by `auth.json`, exclusive to login | No cursor key |
| Shutdown | `axum::serve(..).with_graceful_shutdown` waits for open responses within `SHUTDOWN_TIMEOUT_MS` | An endless stream would always exhaust the drain deadline |

## Decision

Two read-only operations. `GET /v1/runs/{run_id}` returns a snapshot with a resume cursor.
`GET /v1/runs/{run_id}/events` streams the run's visible events after a cursor as
`text/event-stream`, polls PostgreSQL with short pooled reads, re-authorizes before every
delivery, and ends after the terminal event. Cursors are HMAC-SHA256 tokens under a dedicated
key ring. No broker, `LISTEN`/`NOTIFY`, pod-local state, migration or new crate.

### Event invariants

1. **One order.** A run's events are totally ordered by `sequence` (1, 2, …, with no reuse).
   The stream sends events in ascending sequence and never sends a sequence at or below the
   cursor. `occurred_at` is `run_events.created_at` (transaction start), which is not
   monotonic; clients order by `sequence` only.
2. **State follows events.** Every writer that changes `runs.state` appends exactly one event
   in the same transaction. This already holds for creation, claim, caller cancellation,
   queue expiry, recheck and the bulk revocations (ADR 0032). V1-11 and V1-13 must keep it for
   every transition they add, including `cancelling`, `reconciling`, `waiting` and any requeue.
   So the run state is a function of the event prefix, and a snapshot taken at
   `last_event_sequence` equals the result of applying events `1..=last_event_sequence`.
3. **One terminal event, last.** The unique `(run_id, append_key)` with key `run-terminal`
   admits at most one terminal event; a racing second terminal transition conflicts and rolls
   back. No writer appends a visible event after it. Rows written before migration 19 may be
   terminal without a terminal event; for them the snapshot's `terminal` is `null` and the
   state alone is authoritative.

### Wire events

The wire projection is an allowlist keyed on `(format, format_version)`. Each entry names one
wire `type`, its `type_version` and a closed set of `data` members, built from fixed values
or from validated enum members of the payload. Everything else in a row (append key, format,
digest, identity, claim token, approval, storage path, raw bytes, SQL or provider error) is
never serialized. A row without an entry is **hidden**: it emits no item but still advances
the stream's position.

| Internal format, version | Append key | Wire `type` | `type_version` | `data` |
| --- | --- | --- | --- | --- |
| `openmettle.run-created` 1 | `run-created` | `run.created` | 1 | `{}` |
| `openmettle.run-claimed` 1 | `claim:<token>` | `run.started` | 1 | `{}` |
| `openmettle.run-cancelled` 1 | `run-terminal` | `run.cancelled` | 1 | `{"reason": "requested" \| "revoked"}` |
| `openmettle.run-expired` 1 | `run-terminal` | `run.failed` | 1 | `{"reason": "queue_expired"}` |
| `openmettle.operation-intent` 1, observation formats | `intent:<id>`, caller keys | hidden | — | — |

- **Terminal types are terminal states.** Exactly four wire types are terminal:
  `run.succeeded`, `run.failed`, `run.cancelled` and `run.interrupted`, one per terminal state.
  V1-11 maps its `run-terminal` formats onto them; `run.failed` and `run.interrupted` carry an
  open `reason` vocabulary (`queue_expired` here; for example `execution_expired` from V1-11),
  never an error message. `run.succeeded` carries `{}`: the answer is the conversation's
  message (V1-07), not event data.
- **Reasons are open vocabulary.** Consumers map unknown `reason` and `type` values to an
  explicit unknown case (ADR 0007).
- **Extension point.** A ticket that adds a visible event (V1-11 steps, V1-13 approvals, V1-14
  tools) adds one allowlist entry, a contract `if`/`then` data schema bound to its `type`
  (as `Problem` binds `code` to `status`), fixtures, and a row in this table. Until then its
  events are hidden. A stored payload that does not match its entry is a server fault: the
  stream ends without a frame and logs an `internal` category, rather than emitting a partial
  projection; `getRun` answers `500 internal`.

### Snapshot: `getRun` `GET /v1/runs/{run_id}`

`Run` (new response schema, extensible):

| Member | Type | Meaning |
| --- | --- | --- |
| `run_id`, `conversation_id` | `Uuid` | Identity |
| `state` | open string | `queued`, `running`, `waiting`, `cancelling`, `succeeded`, `failed`, `cancelled`, `interrupted`; storage `reconciling` is reported as `running` |
| `created_at` | `Timestamp` | Admission time |
| `last_sequence` | `PositiveSequence` | `runs.last_event_sequence` |
| `resume_cursor` | `Cursor` | Cursor at `last_sequence` for this caller |
| `terminal` | `RunEvent` or `null` | The terminal event exactly as streamed; `null` while live (and for pre-19 terminal rows) |

One statement reads the run and its terminal event, so state, counter and terminal event come
from one snapshot:

```sql
SELECT r.scope_id::text, r.conversation_id::text, r.state, r.last_event_sequence,
       (extract(epoch FROM r.created_at) * 1000000)::bigint,
       t.sequence, t.format, t.format_version, t.payload,
       (extract(epoch FROM t.created_at) * 1000000)::bigint
  FROM openmettle.runs r
  LEFT JOIN openmettle.run_events t ON t.run_id = r.id AND t.append_key = 'run-terminal'
 WHERE r.id = $1::uuid;
```

A client reconstructs any run deterministically: apply the snapshot, then stream with
`after=resume_cursor`. A terminal snapshot needs no stream.

### Stream: `streamRunEvents` `GET /v1/runs/{run_id}/events`

**Framing.** UTF-8, one frame per visible event, no `event:` and no `retry:` field:

```text
id: <cursor at this event's sequence>
data: {"run_id":"…","sequence":"7","type":"run.cancelled","type_version":1,"occurred_at":"2026-11-20T09:00:01.000000Z","data":{"reason":"requested"}}

```

`data` is one compact `serde_json` line (it escapes every control character, so it contains no
CR or LF; the encoder asserts it) of at most 131 072 characters, the `RunEventItem` bound.
Heartbeats are the comment `: heartbeat\n\n`. The type travels inside `data`, not in `event:`:
a browser `EventSource` delivers named events only to listeners registered for that exact
name, so `onmessage` would miss every type and future types would be silently dropped. The
contract's `named-sse-event` compatible fixture still requires consumers to tolerate one.

**Headers.** `200`, `Content-Type: text/event-stream`, `Cache-Control: no-store`,
`X-Accel-Buffering: no` (nginx-family proxies flush per write) and `OpenMettle-API-Version`.
No `Content-Length`; HTTP/1.1 chunked framing.

**OpenAPI 3.2.1.** The operation references the existing reusable media type; each parsed item
is a `RunEventItem`, and its `data` content is a `RunEvent`:

```json
"/v1/runs/{run_id}/events": {
  "get": {
    "operationId": "streamRunEvents",
    "x-openmettle-implementation": "implemented",
    "security": [{"browserSession": []}, {"nativeSession": []}],
    "parameters": [
      {"$ref": "#/components/parameters/RunId"},
      {"$ref": "#/components/parameters/LastEventId"},
      {"$ref": "#/components/parameters/After"}
    ],
    "responses": {
      "200": {
        "headers": {"OpenMettle-API-Version": {"$ref": "#/components/headers/ApiVersion"}},
        "content": {"text/event-stream": {"$ref": "#/components/mediaTypes/RunEventStream"}}
      },
      "204": {"description": "The run is terminal and the cursor is at its last event."},
      "400": {"$ref": "#/components/responses/BadRequest"},
      "401": {"$ref": "#/components/responses/Unauthenticated"},
      "404": {"$ref": "#/components/responses/NotFound"},
      "500": {"$ref": "#/components/responses/Internal"},
      "503": {"$ref": "#/components/responses/Unavailable"},
      "504": {"$ref": "#/components/responses/Timeout"}
    }
  }
}
```

(Descriptions, the `204` version header and examples omitted.) A `serializedValue` example of a
whole stream (a heartbeat, three items, end) is parsed by `tests/contract.rs` into items that
must equal the `dataValue` items.

### Cursor MAC

Cursors are issued only by these two operations and are opaque to clients (ADR 0007). Token
bytes, then unpadded base64url:

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 1 | Format `0x01` |
| 1 | 1 | `kid` length *k*, 1–64 |
| 2 | *k* | `kid`, the key's configured identifier |
| 2+*k* | 8 | `sequence`, signed big-endian i64, 0 to `i64::MAX` |
| 10+*k* | 32 | HMAC-SHA256 tag |

At most 106 bytes, 142 characters. The token carries no scope, run or user identifier: the
verifier supplies them from the request path, the run row and the session, so a cursor reveals
only a sequence the caller already saw.

The MAC input follows the ADR 0004 identity encoding: the domain `openmettle/v1-cursor/1` and
a zero byte, then each field as its unsigned 64-bit big-endian length and bytes, in order:
kind `run-events`, `kid`, `scope_id`, `run_id`, caller `user_id` (lowercase canonical UUID
text) and `sequence` (8 bytes). `ring::hmac::Key::new(HMAC_SHA256, material)` signs;
`ring::hmac::verify` checks in constant time. `base64::URL_SAFE_NO_PAD` decodes, and the
decoded bytes must re-encode to the same text (as `sessions.rs` does), refusing
non-canonical trailing bits. Binding each field means a cursor of another run, scope, user or
operation kind, a tampered byte, an unknown `kid` and a truncated or extended token all fail
the same way. Binding the user keeps ADR 0007's "valid only for the caller" rule; a cursor
never grants access, because every use is authorized first. Telemetry records the route
template, never the target or header values (ADR 0024), so cursors are not logged.

**Keys.** Version 2 of `auth.json` gains one optional top-level member, without a version bump
(as the 19 November amendment did for `uncacheable_reuse_seconds`):

```json
"cursor_keys": {
  "active": {"id": "cursor-b", "path": "/etc/openmettle/auth-keys/cursor-b"},
  "verify_only": [{"id": "cursor-a", "path": "/etc/openmettle/auth-keys/cursor-a"}]
}
```

The loader reuses `KeyFile` and the bounded reader: absolute paths, regular files of exactly
32 bytes, identifiers by the login `name` rule (1–64 URL-safe bytes), one active plus at most
three verify-only keys, distinct identifiers and material, and material different from every
login key (compared with `subtle::ConstantTimeEq`), so each key stays exclusive to its purpose
(ADR 0009). `--check-auth-config` validates it offline. The active key signs; any configured
key verifies. Without `cursor_keys` both run operations answer `503 provisioning`, as the
artifact operations do without `ARTIFACTS_DIR`.

**Rotation.** As for login keys (ADR 0015): add the new key to `verify_only` on every replica;
make it active and move the old one to `verify_only`; remove the old one when its cursors no
longer matter. A removed key's cursors resynchronize (below); nothing else breaks, so there is
no grace period or expiry timestamp in the token. **After a database restore** remove every
pre-restore key: restored counters may reissue a sequence with different content, and only a
new key guarantees that no pre-restore cursor resumes against it.

### Resume and resynchronization

- **Cursor source.** `EventSource` resends the original URL and adds `Last-Event-ID` with the
  last `id` it received; a page reload can only pass a stored cursor in the URL. So the URL's
  `after` is always the older value once events arrive. **When both are present,
  `Last-Event-ID` is used** and `after` must only be a well-formed cursor. This supersedes
  ADR 0007's "both present and differ is `validation`", which would make every reconnect of an
  `EventSource` opened with `after` fail permanently; accepting a request that was refused is
  an additive change, and no consumer implements the old rule. Each source may appear at most
  once (`400 validation` otherwise); `cursor` and every other query member are
  `400 validation`.
- **No cursor** replays from sequence 1.
- **Every cursor failure is `400 invalid_cursor`**: malformed, foreign (run, scope, user,
  kind), tampered, unknown or removed `kid`, or a sequence above `last_event_sequence`. ADR 0007
  already assigns expired and foreign cursors to this code. There is one client action for all
  of them: discard the run's derived local state, `GET` the snapshot, render it and stream from
  its `resume_cursor`. A second code such as `cursor_expired` would add a branch with the same
  action.
- **Retention.** V1 keeps every event while its run exists: no role has `DELETE` on
  `run_events` (ADR 0004). V1-16 may purge only whole runs (row and events together); the
  snapshot and stream then answer `404`. Trimming a run's events partially is not allowed
  without amending this record, which would add a first retained sequence and map cursors below
  it to `invalid_cursor`.
- **Before the `200`.** Cursor syntax, authorization, MAC, `kid` and range are all decided
  before the response head is written. After a `200` the only signal is the end of the stream,
  which a client cannot distinguish from a network drop: an error found later would loop
  `EventSource` reconnects forever. Problem responses are terminal for `EventSource` (any
  non-`200` fails the connection), so browser clients re-create it, with backoff, from the
  snapshot.
- **Completion.** A terminal run streams the remaining events through the terminal event and
  ends. A request whose cursor is already at the last event of a terminal run gets
  `204 No Content`, which `EventSource` treats as "do not reconnect". So reconnects after
  completion stop instead of replaying.

### Request order

The existing `/v1` order (`src/v1.rs`) with these changes for `streamRunEvents`; `getRun` is a
normal unary operation that runs steps 4–6 without the stream.

1. Route, method and head bounds, as today. `HEAD` stays "`GET` without a body": it decides
   steps 2–7 and starts no stream.
2. One `SSE_MAX_IN_FLIGHT` permit, never awaited, held by the stream until it ends, instead of
   a `MAX_IN_FLIGHT` permit. None free, or the process is stopping: `503 unavailable`.
3. Session channel: cookie with the `same_origin` rule (a `GET` may omit `Origin`, any `Origin`
   sent must match) or one `Bearer` credential; otherwise `401 unauthenticated`.
4. Shape: canonical `run_id`; the cursor rules above; an empty body. Then no `cursor_keys`:
   `503 provisioning`.
5. Session validation on the primary (`401`, `503`, `504` as today).
6. One database phase within `OPERATION_TIMEOUT` (below): read the run and the first batch;
   a missing run is `404`; authorize; verify the cursor against the run's scope and the
   session's user (`400 invalid_cursor`). Authorization precedes the MAC, so `invalid_cursor`
   never confirms that a hidden run exists.
7. Terminal run and cursor at `last_event_sequence`: `204`. Otherwise `200` and the stream.

### Authorization

A run is readable exactly by those who may read its conversation: hydrate the principal
(`hydrate_api_principal` with the session's approval) and call `read_resource(Conversation,
run.conversation_id)` (ADR 0027 `Action::Read`, the same read class as `Stream`). A deleted or
invisible project, a missing share or lapsed membership is `404`; an inactive principal is
`401`. An archived project stays readable.

During the stream every phase that has events to deliver re-runs session validation and this
decision **after** reading the batch and **before** writing it. A revocation, logout, session
expiry, approval withdrawal, disablement or project deletion that committed before an event
also committed before the batch read, so the re-authorization sees it: the stream ends without
sending the batch. No event committed after a revocation is ever delivered. An idle stream is
re-authorized at least every `REAUTH_INTERVAL`, so it closes within
`REAUTH_INTERVAL + POLL_INTERVAL + OPERATION_TIMEOUT` of a revocation. A refusal ends the
stream with no frame; the reconnect receives the `401` or `404`.

### Polling, pool and memory discipline

The stream is one task per connection that owns the permit and the sending half of a bounded
channel; the response body is a small `HttpBody` over the receiving half, written beside
`artifact_fs::Content`. axum's `Sse` needs a `futures` `Stream`, which is not a direct
dependency; the hand-written body needs nothing new. Each iteration:

1. Wait for the earliest of `POLL_INTERVAL`, the stop signal or the client going away
   (`Sender::closed`), holding **no** database connection.
2. One phase through `Api::database`: `Checkout::acquire`, the statement below, then the
   authorization when due, then release. A failed or timed-out phase discards the connection
   (ADR 0016) and ends the stream; the client reconnects.
3. Project the rows, then send each frame with `WRITE_TIMEOUT`, still holding no connection.
4. Advance the position over every returned row, hidden ones included. End after the last
   event when the run is terminal and the position reaches `last_event_sequence`. If the batch
   was full, poll again at once; otherwise wait.

```sql
SELECT r.scope_id::text, r.conversation_id::text, r.state, r.last_event_sequence,
       e.sequence, e.format, e.format_version, e.payload,
       (extract(epoch FROM e.created_at) * 1000000)::bigint
  FROM openmettle.runs r
  LEFT JOIN LATERAL (
       SELECT sequence, format, format_version, payload, created_at
         FROM openmettle.run_events
        WHERE scope_id = r.scope_id AND run_id = r.id AND sequence > $2
        ORDER BY sequence
        LIMIT $3) e ON true
 WHERE r.id = $1::uuid
 ORDER BY e.sequence;
```

One statement, so the state and counter are consistent with the batch (invariant 2): if the
state is terminal, the batch can reach the terminal event. The run is found by its primary key.
The inner predicate is equality on `(scope_id, run_id)` and a range on `sequence`, ordered by
`sequence` with a limit: `run_events_scope_run_idx` serves it exactly, and the primary key
`(run_id, sequence)` with a scope filter also does, both in index order with no sort and at
most `$3` index entries. PR2 asserts the plan.

| Constant (per API process) | Initial value | Bounds |
| --- | --- | --- |
| `SSE_MAX_IN_FLIGHT` | 128 | Open streams, separate from the 256 unary permits |
| `POLL_INTERVAL` | 500 ms | Idle delivery latency; a full batch re-polls at once |
| `BATCH_LIMIT` | 16 events | Rows per read |
| `CHANNEL_FRAMES` | 8 frames | Frames queued for one connection |
| `WRITE_TIMEOUT` | 10 s | Wait for room in the channel |
| `HEARTBEAT_INTERVAL` | 15 s | Since the last frame; one heartbeat also follows the `200` at once |
| `REAUTH_INTERVAL` | 10 s | Longest idle period without re-authorization |

These are starting values, not measured capacity; PR3 records the measurements. Streams use
their own permits because they are long-lived: sharing the unary bound would let open streams
refuse every short request. Worst-case transient memory per stream is `BATCH_LIMIT` rows of at
most 64 KiB payload plus `CHANNEL_FRAMES` frames of at most 128 KiB, about 2 MiB; today's
projections are under 200 bytes. A stream holds a pool connection only for the length of one
phase, so open streams never pin connections and the ADR 0003 connection budget is unchanged.

**Slow and dead clients.** A frame that cannot enter the channel within `WRITE_TIMEOUT` ends
the task, which releases the permit; queued frames are flushed if the client resumes reading,
then the body ends and the client resumes from its last `id`. Durable events are never
dropped, only not yet delivered. Heartbeats keep intermediaries from closing quiet streams and
make the kernel detect a dead peer, which drops the body and ends the task through
`Sender::closed`. A peer that keeps the TCP connection open but never reads still holds its
socket until the kernel or ingress times it out, as an artifact download can; PR3 records the
ingress idle and send timeouts.

**Known limit.** One user can hold every stream permit of a pod. A per-user stream limit
belongs with V1-17 rate and quota limits; it is not claimed here.

### Read-only with respect to execution

The stream and snapshot run as `openmettle_api` and issue only `SELECT`s on `runs` and
`run_events` (no row locks), plus the existing session validation and hydration reads. They
never call `append_event`, `cancel_run`, `recheck_run`, `claim_next` or any V1-11 lease
function. The API role has no `UPDATE` on `queue_expires_at` (insert-only, ADR 0032) or on the
claim columns, and V1-11 must keep lease renewal and execution deadlines worker-only. So no
client traffic, heartbeat or reconnect can renew a lease, extend a deadline or hide a stalled
worker: deadlines are decided on the database clock by the worker's claim and sweeps, and their
terminal events reach the stream like any other.

### Shutdown and pod replacement

`crate::serve` gives the `/v1` router a `tokio::sync::watch` stop signal and sets it on
`SIGTERM` or `SIGINT` before starting the graceful drain. Each stream ends at its next frame
boundary, dropping a frame that was waiting for room, and new stream requests answer
`503 unavailable`. The drain then completes within `SHUTDOWN_TIMEOUT_MS` unless a peer stops
reading, as for any response. Clients reconnect with `Last-Event-ID` to any other replica:
cursors, events and authorization live in PostgreSQL and the shared key ring, so no affinity
is needed.

### Rejected alternatives

- **`LISTEN`/`NOTIFY` wake-ups.** A dedicated session per pod outside the pool, notifications
  lost while disconnected (polling is still required), and work on every appending commit. As
  in ADR 0032 it may be added as a hint if PR3 shows the poll interval matters.
- **Holding a connection or transaction per stream.** Pins pool slots and snapshots for the
  stream's lifetime and starves unary requests (ADRs 0003 and 0016).
- **In-memory fan-out between pods.** Pod-local state; a replacement pod could not resume.
- **Reusing the login keys.** ADR 0009 requires login key material to stay exclusive.
- **Signing scope, run and user into a readable token.** Leaks identifiers and lengthens the
  cursor; the verifier already has them.
- **Expiry timestamps in cursors.** Events are retained, so an old cursor is still exact; key
  removal already retires cursors.
- **Exposing `event:` per type, or every internal event.** See framing; hidden events carry
  internal identifiers and caller-defined evidence.
- **A distinct `cursor_expired` code or a `409` for retention.** Same client action as
  `invalid_cursor`, already reserved for expired cursors.
- **Re-authorizing on a timer only.** Could deliver events committed after a revocation; the
  read-then-authorize order cannot.

## Delivery and evidence

| PR | Content | Evidence |
| --- | --- | --- |
| PR1 | This record and a pointer from ADR 0007 | Review |
| PR2 | Cursor codec and `cursor_keys` loading; wire projection; `getRun` and `streamRunEvents` with the stop signal; contract: `Run`, `RunId`, both operations, `if`/`then` data schemas for the four lifecycle types, the `Last-Event-ID` precedence in both parameter descriptions, examples, a `serializedValue` stream, regenerated fixtures and consumer decoding; README and ADR 0015 operator steps for cursor keys | Tests below pass in CI |
| PR3 (#63) | An ephemeral `kind` cluster with the deployed ingress and two API replicas | Owner-run; results, ingress settings and rerun steps recorded on #63 |

PR2 unit tests (no database): known-answer cursor vectors for a fixed key; every single-byte
tamper, truncation, extension, non-canonical base64 and foreign field fails; key ring loading
refusals, including material shared with a login key; frame encoding never contains CR or LF;
hidden formats emit nothing; the snapshot state mapping.

PR2 PostgreSQL 18 tests (`tests/schema`, both session channels, shortened intervals through a
test-only constructor):

- **Disconnect and resume.** Read *k* events, drop the connection, resume with
  `Last-Event-ID`, then with `after`, then with both (header wins): every event exactly once,
  in order. Conflicting duplicate fields are `400 validation`.
- **Repeated cursor.** Two concurrent streams from one cursor receive identical items.
- **API replacement.** Two routers on one database. Stream from A while the run is queued and
  again while running; set A's stop signal; A's streams end and its drain finishes; resume on
  B with no loss or duplicate.
- **Slow client.** A reader that stops consuming: the task ends after `WRITE_TIMEOUT`, the
  permit is free and the pool idle count returns; resuming loses nothing.
- **Pool discipline.** With a one-connection pool, an idle open stream does not delay a unary
  request.
- **Revocation mid-stream.** Share revoke, membership revoke, project delete, user disable,
  approval withdrawal and logout each end the stream; an event appended after the revocation
  commits is never received; the reconnect is `404` or `401`.
- **Completion racing cancellation.** Concurrent `cancel_run` and a second `run-terminal`
  append: one terminal event commits; stream and snapshot agree.
- **Heartbeat and deadline.** A queued run with a short queue timeout while heartbeats flush:
  `expire_queued` fails it, the stream delivers `run.failed` with `queue_expired` and ends;
  no stream request changed a run row.
- **Completion.** No cursor on a terminal run replays to the terminal event and ends; its
  terminal cursor is `204`; `getRun` returns the same terminal event.
- **Cursors.** Foreign run, scope and user, removed `kid`, a cursor above
  `last_event_sequence`, and a rotation where a verify-only key still resumes.
- **Index.** `EXPLAIN (FORMAT JSON)` of the batch read after `ANALYZE` on a fixture with many
  runs shows an index scan with no sort node.

PR3 (#63), through the deployed ingress: admit a run and hold it for capacity, disconnect, resume
from the last cursor, and repeat across replacement of the serving API pod; verify one
execution, one reservation, ordered replay and one terminal UI effect. Observe flushed
heartbeats during a quiet interval, and show that a queue or execution deadline still expires
and no lease is renewed by client traffic.

## Boundaries

- **V1-07 (#8):** run creation routes and messages; its run responses may reuse `Run`.
- **V1-11 (#11):** `succeeded`, `failed` and `interrupted` terminal formats mapped onto the wire
  types above, step events, and events for every state change it adds.
- **V1-13 (#13), V1-14:** approval, waiting and tool events through the extension point.
- **V1-16:** retention, whole runs only.
- **V1-17 (#17):** per-user stream limits.

## Consequences

- No new crate, migration, pool, listener or pod-local state. One optional `auth.json`
  member and one more key set to provision and rotate.
- Idle delivery latency is up to `POLL_INTERVAL`; each open stream costs at most one indexed
  read per interval and one authorization per delivery or `REAUTH_INTERVAL`.
- ADR 0007's `Last-Event-ID`/`after` conflict rule is replaced by header precedence.
- Not implemented here: everything above. Measured stream capacity, ingress behaviour and
  latency are PR3 evidence.
