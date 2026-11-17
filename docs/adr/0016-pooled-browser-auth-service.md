# 0016 — Pooled browser-auth service and connection discard

Status: coordinator-agreed V1-04 implementation contract, 17 November 2026.
Refs #5; Refs #34. Independent review and CI acceptance are separate gates. #5 remains open.

## Problem

ADRs 0009–0014 take a caller-owned `&mut PgConnection` and tell the caller to discard it
after cancellation, a timeout or a `Database` error. Nothing implemented that rule. ADR 0014
made it an exposure gate: a dropped future can leave the admission singleton or a login row
locked on a connection that goes back to a pool.

The managed `begin` and `consume` also held the caller's connection while their preflight
could fetch provider documents. With a pool, a slow provider would hold a database slot.

## Decision

`src/browser_auth.rs` adds one internal service, `BrowserAuth`. It is built from the
validated `AuthConfig` (ADR 0015) and a handle to the API's existing primary pool. It opens
no pool, reads no setting and adds no pool abstraction.

| Operation | Result | Stages |
| --- | --- | --- |
| `begin(provider_id)` | `login::Started` | preflight, then database |
| `complete(provider_id, login::Callback)` | `sessions::Credential` | consume, one token request, issue |
| `validate(credential)` | `sessions::Context` | database only |
| `logout(credential)` | `()` | database only |

**No running process constructs this service.** The API, worker and migrator do not load
auth settings, `/readyz` still checks the database only, and there is no route, cookie, CSRF
handling, native handoff or rate policy.

### Unchanged contracts

- A provider is selected only by an exact match with a configured provider UUID. An unknown
  identifier is `Login(Rejected)` and causes no provider request and no checkout. No caller
  value selects a URL, a transport or trust.
- `login::Callback` carries the received issuer and callback URL for exact comparison with
  configuration (ADR 0009). Neither is ever used as a request destination.
- Issuance takes only the sealed `ExchangedIdentity` from this service's own exchange. No
  `VerifiedIdentity` reaches it (ADR 0013).
- Durable epoch, approval and generation fences, the original login expiry on the primary
  clock, and the issuance and postcommit checks are the existing code, called unchanged.
- No step is retried: one consumption, one token request, one issuance. After a failure,
  cancellation or uncertain commit the login must be restarted.
- Errors are `Error::Login(login::Error)` or `Error::Session(sessions::Error)`: the existing
  fixed categories with their existing text. No new category and no value is added.

### Phase split

`provider_keys.rs` gains four crate-internal steps. The caller-owned `ManagedProvider::begin`
and `consume` now run exactly these steps, so each check exists once:

1. `login_phase`: manager admission and the phase deadline.
2. `fresh`: managed preflight. It may fetch documents and uses no connection.
3. `login_provider`: active configuration, unexpired keys and unspent deadline. No network
   or database work.
4. `confirm`: keys still fresh and deadline unspent after the database work.

The pooled service checks a connection out between steps 2 and 3. Validity is therefore
checked after the wait for a connection and before any write. `issue_session` is split the
same way into `session_phase` (handle binding, admission, deadline) and `issue_admitted`.

One caller-visible tightening: step 3 now also refuses when the phase deadline has already
passed. The low-level APIs keep their signatures and remain usable.

### Connection ownership

| Stage | Pooled connection held |
| --- | --- |
| Preflight (discovery and key documents) | No |
| Begin: precheck, reservation, insert | Yes, one checkout |
| Consume transaction | Yes; settled and dropped before the stage returns |
| Token request and a following unknown-key refresh | No |
| Issuance transaction and postcommit validation | Yes, one checkout |
| Validate, logout | Yes, one checkout |

Manager admission is taken before the wait for a connection, so login-stage waiters are
bounded by the configured caller capacity (ADR 0011). `validate` and `logout` take no
manager admission and contact no provider. A malformed credential is refused before any
checkout.

### Deadlines

No new deadline or default is introduced. Pool acquisition is inside the existing ones.

| Stage | Deadline | On expiry |
| --- | --- | --- |
| Begin, consume | Manager refresh deadline from stage start; covers preflight, the pool wait and the database work | `Login(Rejected)` |
| Exchange | Unchanged (ADR 0011) | `Login(Exchange)` |
| Issue | The proof's original exchange deadline, further limited by the session deadline measured from before the pool wait; covers the wait, the transaction and postcommit validation | `Session(Timeout)` |
| Validate, logout | Session deadline from the call; covers the pool wait | `Session(Timeout)` |

A pool wait never starts a new window and never extends the login's expiry. Issuance after
a wait is still refused by the primary clock once the original login expiry has passed. The
pool's own acquire timeout (`DB_TIMEOUT_MS`) also applies; reaching it first is a `Database`
error. A consume that committed before its deadline check failed has spent the login, as
before.

### Discard guard

Each database stage owns a private `Checkout` over SQLx 0.9.0 `PoolConnection`. It is
created inside the future that the stage deadline wraps, so an elapsed deadline drops the
guard together with the cancelled borrow.

- A checkout that was never lent returns to the pool.
- From the first lend, dropping the guard closes the connection, unless the stage settled
  it as reusable.
- A stage settles as reusable only from the returned result: success, or a denial that is
  returned before any statement or after an awaited COMMIT or ROLLBACK. The guard also
  refuses reuse when SQLx still tracks an open transaction.

| Result | Connection |
| --- | --- |
| `Ok` | Reused |
| `login`: `Configuration`, `Random`, `Rejected`, `Protection`, `Capacity`, `Unconfigured` | Reused |
| `sessions`: `Configuration`, `Rejected`, `Capacity`, `Random` | Reused |
| `login::Database`, `sessions::Database`, `sessions::Timeout` | Closed |
| `login::Exchange`, `login::Verification` (not produced by database stages) | Closed |
| Cancellation, stage deadline, panic, early return after a lend | Closed |

Each reusable category was checked against the helper that returns it: every such return
happens before the first statement, between transactions, or after `finish` awaited the
rollback, and a failed rollback is reported as `Database` instead (ADRs 0013 and 0014). The
match is exhaustive, so a new category must be classified before the crate compiles.
SQLx's tracked depth can clear when it queues a rollback. Reuse relies on the helper
finishing each transaction explicitly. SQLx flushes any queued work during the pool return
ping before making the connection available.

`Database` is closed even when its rollback succeeded, because the category alone cannot
show that. This is deliberately conservative.

The guard uses `PoolConnection::close_on_drop`, not `detach`. A detached connection frees
its pool slot at once and lets the pool exceed its configured size. The service spawns no
task and never retries.

## Limits

These are properties of SQLx 0.9.0 and PostgreSQL, not qualified operating bounds.

- **Close is asynchronous.** `close_on_drop` only marks the connection. When the guard
  drops, SQLx spawns a task on its runtime that sends `Terminate` and shuts the socket down,
  for at most 5 seconds. The pool slot stays counted until that task ends, so a waiting
  caller can wait that long inside its own deadline. Returning a reusable connection is also
  an SQLx task (a liveness round trip, then release).
- **Shutdown waits for connection cleanup.** The API shutdown path drains requests and then
  waits for `pool.close()` within the same deadline. A discard can hold a pool permit for up
  to 5 seconds, which is also the default `SHUTDOWN_TIMEOUT_MS` budget. When integrating the
  service, allow for both request drain and connection cleanup. The process exits 1 if the
  shutdown deadline elapses first.
- **Closing the socket does not interrupt the backend.** A backend that is executing a
  statement sees the disconnect only when the statement returns. A cancelled backend that is
  waiting for a row lock keeps the locks it already holds until its wait ends. Every
  transaction here first sets `lock_timeout = 2s` and `statement_timeout = 3s`, so that is
  normally within about 3 seconds. A cancellation before those settings are applied holds no
  row lock yet. A COMMIT that is waiting on synchronous replication is not bounded by this
  record.
- **Server connections can briefly exceed the pool size.** The slot is released when the
  socket is closed, which can be before the old backend exits. The replacement then
  coexists with it. If the role's `CONNECTION LIMIT` or `max_connections` has no headroom,
  the replacement fails and that caller receives `Database`. The connection budget in the
  README does not include this overlap; size it before exposure.
- **Discard costs a reconnect.** Lock timeouts under contention and other `Database` errors
  each replace a connection. The resulting churn is unmeasured.
- **The pool is shared.** Auth work competes with `/readyz` for the same slots. `validate`
  and `logout` concurrency is not bounded here.
- **An uncertain commit stays uncertain.** A commit whose acknowledgement is lost can leave
  a consumed login, or an issued session whose credential was never returned (ADRs 0009 and
  0013). The service returns nothing and does not look the outcome up.

## Evidence

Managed PostgreSQL tests (`provider_keys::tests::postgres::pooled`) run in the existing CI
step and filter, against the isolated PostgreSQL 18 service, with a one-slot pool, the
synthetic TLS provider and a separate administrator connection to observe fixture backends
and signal the backend selected for the connection-loss case:

- begin, consume, exchange, issue, validate and logout on one slot and one backend; callback
  replay refused with exactly one token POST; no lock left and the same backend afterwards;
  validation and logout during a provider outage with no provider request;
- a key-document GET held open during preflight and a token POST held open after
  consumption, each while an unrelated query obtains the only slot;
- cancellation while issuance holds the login row lock and waits for a user row: the slot
  returns with a different backend. The cancelled backend exits and the login row becomes
  lockable while the fixture still holds the user row;
- a session-deadline timeout during a blocked validation, a `Database` error with a
  successful rollback, and a terminated backend (statement and rollback both fail): each
  replaces the backend, leaves no lock and loses no capacity;
- cancellation at a COMMIT whose acknowledgement the existing response proxy withholds, for
  consume and for issue: the row is committed, nothing is returned, the token POST count
  does not change, a retry is refused and the backend is replaced;
- a slot held past the manager deadline and past the proof's original deadline (no write,
  nothing issued, nothing discarded), a slot released after the login's expiry (refused by
  the primary clock), and a configuration retired during the wait (refused before any write).

Local tests without PostgreSQL cover provider selection, refusal of malformed credentials
and failed preflight before any checkout, document fetches preceding the checkout attempt,
`Send` futures, and the reuse classification table.

Not claimed: the PostgreSQL tests were not run locally. No real provider, route, image
behaviour, cluster or rollout was exercised. The asynchronous close, lock-release delay and
connection overlap above are described from SQLx source and PostgreSQL behaviour; only the
single-slot cases listed are tested, and nothing was measured under load.

## Compatibility

No dependency, Cargo feature, lockfile, migration (1–9 unchanged), process contract, HTTP
contract, CI workflow or provenance-register change. New public items: the `browser_auth`
module (`BrowserAuth`, `Error`). The loader, approval model, session preservation across
routine revisions and explicit generation revocation are unchanged.

## Remaining

This supplies the pool integration that ADR 0014 required for its connection-discard gate;
CI and independent review decide whether the gate is met. Public routes, cookies and CSRF,
runtime loading and enabling of settings, native handoff, request, rate and concurrency
controls, operated cleanup, retired-key reservation reclamation, connection-budget sizing,
real-provider qualification, provisioning, resource authorization (V1-05), reconciliation
and audited recovery remain downstream. #5 stays open.
