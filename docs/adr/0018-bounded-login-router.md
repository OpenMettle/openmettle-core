# 0018 — Bounded browser login router

Status: proposed V1-04 implementation contract, 18 November 2026.
Refs #5; Refs #34. Independent review and CI acceptance are separate gates. #5 remains open.

[ADR 0022](0022-home-invitation-codes.md) lets the initiation route accept one small form
body. See [the amendment](#amendment-initiation-form-body-adr-0022) below.

## Problem

ADR 0017 added `LoginHandoff`, which turns one request head into one response. Nothing
routed requests to it, and ADRs 0009, 0014, 0016 and 0017 list request, rate and
concurrency controls as exposure gates. A successful initiation records a permanent nonce
reservation and a login row. A callback that passes consumption can spend a token request.
Without a bound in front of the handoff, a client can ask for that work as fast as it can
send requests.

## Decision

`src/browser_auth/router.rs` adds `router(handoff, settings)`. It validates every setting,
then returns an ordinary Axum `Router` with two literal routes over one `LoginHandoff`.

**The router is not mounted.** No listener or running process constructs it. The API and
worker are unchanged: they serve `/healthz` and `/readyz` only and answer `404` for the
login paths. Auth settings version 1, the OpenAPI contract, the handoff's responses and the
service below it are unchanged.

### Settings

| Setting | Rule |
| --- | --- |
| `initiation` | Exact literal path for the form `POST` |
| `begin` | Rate budget for initiations: `burst` 1–65 536, `interval` 1 ms–1 hour |
| `callback` | Separate rate budget for callbacks, same ranges |
| `in_flight` | Requests inside the handoff at once, across both routes: 1–4096 |

The callback path is the registered callback's path, taken from the handoff. Nothing has a
default, and these ranges are implementation ceilings, not recommended values. Settings are
not part of the auth settings document. A later runtime-enablement increment decides where
they come from.

Both paths must start with `/` and contain only ASCII letters, digits and `/ - . _ ~`.
There is no empty inner segment, dot segment, escape, query or fragment, and a path has at
most 256 bytes. A trailing `/` is allowed and is matched literally. Construction refuses
with one of five fixed categories and carries no value:

| Category | Cause |
| --- | --- |
| `Pattern` | A path contains route syntax: `{`, `}`, `*` or `:` |
| `Path` | A path is not of the shape above |
| `Collision` | The paths are equal, or one is `/healthz` or `/readyz` |
| `Rate` | A burst or interval is outside its range |
| `InFlight` | The in-flight cap is outside its range |

Validation runs before any route is added, so Axum cannot panic on these paths.

### Request order

Each request is decided in this order. Steps 1–4 do no provider, pool or database work.

1. **Route and method.** Axum matches the request path exactly. The initiation route
   accepts `POST` and the callback route accepts `GET`. Any other method, including `HEAD`,
   is `405` with `Allow`. The routes use `any` rather than `get`, because Axum also runs
   `get` handlers for `HEAD`.
2. **Request bounds.** Measured on what HTTP parsing produced. The body is never polled.
3. **In-flight permit.** `Semaphore::try_acquire`, which never waits. With no free permit
   the request is `503` and spends no rate.
4. **Rate.** One unit of the route's budget. With none left the request is `429` and the
   permit is released.
5. **Handoff.** `initiate` or `callback` with the original request head. The permit is held
   until the handoff returns or its future is dropped.

**When rate is spent.** A request spends one unit of its route's budget after it passes
steps 1–3, before the handoff runs. The unit is never refunded, including when the handoff
then refuses the request without calling the service. Method, bound and concurrency
refusals spend nothing.

### Request bounds

| Bound | Ceiling | Status |
| --- | --- | --- |
| Request target: path and query, plus scheme and authority for an absolute-form target | 33 792 bytes | `414` |
| Header fields, each repeated field counted | 64 | `431` |
| Header name and value bytes, delimiters excluded | 24 576 bytes | `431` |
| Body | Empty only | `413` |

The target and header ceilings leave room for the handoff's own ceilings (ADR 0017): a
32 KiB query on a 256-byte path, and 16 KiB of cookies. Those ceilings are unchanged and
still apply inside the handoff.

The empty form and navigation profile is the only accepted body: no `Transfer-Encoding`,
every `Content-Length` equal to `0`, and a parsed body whose exact size is zero. An HTML
form with no fields sends that profile. A nonzero declared length or a chunked body is
refused from the request metadata, without reading or waiting for body bytes.

**What this measures.** The bounds run after the HTTP server has read and parsed the
request head. They limit what reaches the handoff, not what the server reads to parse
it. Under `axum::serve`, hyper 1.12 limits an HTTP/1 head to 100 fields and its read buffer
to 417 792 bytes, and the `http` crate refuses targets longer than 65 534 bytes. These are
library defaults that this router does not set. A deployment needs its own ingress and
server limits for header size, header read time, connection count and idle connections.

### Admission

Each budget is a generic cell rate algorithm over `std::time::Instant`, which is monotonic.
Its whole state is one instant behind a mutex. That instant is when the budget would be
full again. A request at `now` is admitted when that instant is at most
`interval × (burst − 1)` ahead of `now`, and the instant then advances by one `interval`.
A full budget therefore admits `burst` requests at once and then one per `interval`. Idle
time refills to `burst` and no further. A refusal changes nothing.

The begin and callback budgets are separate, so exhausted initiations do not block
callbacks for logins that have already started. The in-flight cap is common to both
routes, because both reach the same pool and provider manager.

All state lives behind one `Arc`. Every clone of the returned router, and every connection
it serves, shares it. The state has constant size. There is no client-keyed map, wait
queue or spawned task, and no forwarded header is read. The lock covers only the
arithmetic, so a poisoned lock still holds a consistent instant.

The permit is an RAII guard inside the handler future. A refusal, a returned response, a
panic and a dropped future all release it. In the dispatch test, closing an HTTP/1
keep-alive connection while the handoff waits makes hyper drop the handler future. That
releases the permit and cancels the service call under the cancellation rules of ADR 0016.
The crate enables HTTP/1 only.

### Responses

| Status | Fixed line | Cause |
| --- | --- | --- |
| `405` | `method not allowed` (with `Allow`) | Wrong method, before admission |
| `414` | `login request target too long` | Target bound |
| `431` | `login request headers too large` | Header count or byte bound |
| `413` | `login request body not accepted` | Body not empty |
| `503` | `login busy; try again later` | No in-flight permit |
| `429` | `login rate limit reached; try again later` | Route budget spent |

These use the handoff's response builder: `Cache-Control: no-store`,
`Referrer-Policy: no-referrer`, a plain-text fixed line, no cookie and no `Location`. The
`503` busy line differs from the handoff's `503` unavailable line. No response carries a
retry time, a count or a request value. Every other response is the handoff's own (ADR
0017). An unrouted path gets the host router's fallback. Standalone, that is Axum's empty
`404`.

### Amendment: initiation form body (ADR 0022)

The initiation route accepts a second body profile, so that an HTML form can carry the
invitation code field. This replaces "Empty only" in the bounds table and "The body is never
polled" in the request order, for the initiation route alone. The callback, session and
logout routes still require the empty profile.

| Profile | Rule |
| --- | --- |
| Empty | Unchanged: no `Transfer-Encoding`, every `Content-Length` equal to `0`, parsed size zero |
| Form | No `Transfer-Encoding`; exactly one `Content-Type` equal to `application/x-www-form-urlencoded`, compared without case and with no parameter; exactly one `Content-Length` of 1–256 in plain decimal; a parsed body whose exact size is that length |

The profile is still decided in step 2 from request metadata. A body outside both profiles
is `413` with the existing line. That includes a chunked body, a declared length over 256, a
repeated `Content-Type` or `Content-Length` and any other media type. Nothing is read and
nothing is spent.

A declared form is kept unread through steps 3 and 4. Step 5 then reads it before calling
the handoff, while the request holds its in-flight permit:

- at most 256 bytes, the declared length;
- within 2 seconds (`FORM_READ_TIMEOUT`), measured from the start of the read;
- a body that does not arrive completely in that time, or whose size differs from the
  declared length, is `408`. The handoff is not called.

The rate unit spent in step 4 is not refunded, however the read ends.

| Status | Fixed line | Cause |
| --- | --- | --- |
| `408` | `login request body not received` | A declared initiation form did not arrive within 2 seconds |

The handoff's own `400` form refusal is described in
[ADR 0017](0017-browser-login-handoff.md#amendment-invitation-code-field-adr-0022).

**Limits added.** A stalled form holds one in-flight permit for up to 2 seconds. The cap
bounds how many wait at once, and each has spent a rate unit. The 256-byte ceiling limits
what the router reads, not what the HTTP server buffers while parsing. A request refused
before its body is read leaves that body to the HTTP server, which may close the connection.

New public item: `router::FORM_READ_TIMEOUT`. Evidence is listed in ADR 0022. Mutating the
router to read the form before taking the permit, or to read it without the timeout, makes
the dispatch test fail.

### Mounting rules

Merge the router into the host router with `Router::merge`. Do not use `Router::nest`: the
handoff compares the original callback path, and nesting strips a prefix. Ingress must not
rewrite or normalize the path. The router has no fallback, so it does not conflict with the
host router's fallback.

## Limits

- **Per router value, per process.** Each independently constructed router has its own
  budgets and in-flight cap. Aggregate capacity adds the limits of all router instances,
  including instances in surge replicas.
- **No per-client fairness.** One client can spend a whole budget and deny logins to
  everyone else on that replica until it refills. Per-client limits need trusted client
  identity at ingress. This router trusts no forwarded header.
- **Not a parser or transport limit.** See [What this measures](#request-bounds). Slow or
  oversized heads, idle connections and connection floods are outside this router.
- **Not durable or a storage bound.** Restarting a process refills its budgets. Each
  successful initiation still records a permanent nonce reservation and a login row
  (ADRs 0009 and 0014). The rate bounds how fast these records can accumulate on one
  replica. Cleanup and retired-key reservation reclamation remain required.
- **Rate is spent before the handoff decides.** A client with a stale or malformed callback
  spends callback budget that a valid callback could have used.
- **The in-flight cap is independent of other caps.** It is checked before the provider
  manager's caller admission (ADR 0011) and the pool's connection limit. No relation between
  the three is chosen here.
- **No operating values.** Burst, interval and in-flight values must come from measurement
  and deployment policy.

## Evidence

Unit tests (`cargo test --locked --offline --lib browser_auth::router`) cover path
validation, rate ranges, the target and header
measurements, the body metadata rule, and budget refill from injected `Instant` values:
a full burst, no refill before an interval, one unit per interval, refusals spend nothing,
idle refill stops at the burst and an earlier instant is not a refill.

Dispatch tests (`cargo test --locked --offline --lib provider_keys::tests::router`) serve
the router with `axum::serve` on loopback and send raw HTTP/1.1 bytes. They use the
synthetic TLS provider and a database stand-in that never speaks PostgreSQL:

- invalid paths, rate settings and in-flight caps are refused through `router` without a
  panic or any provider or database contact;
- wrong methods, including `HEAD` on both routes, receive `405`. Case, slash, escape and prefix variants
  of both paths and the operational paths are `404`, and none reaches the provider or the
  database;
- one byte over the target, field and header-byte ceilings is refused. Declared, chunked
  and present bodies are refused, and the reply arrives although no body byte was sent;
- requests exactly at the target, field and header-byte ceilings, and a callback with the
  handoff's maximal query and maximal cookie field, pass the bounds. A valid form `POST` and
  a valid callback reach the service through dispatch;
- two listeners serving clones of one router share both budgets. Method and bound refusals
  spend no rate, handoff refusals do, the two budgets are independent, and a valid request
  over budget never reaches the provider or the database;
- with `in_flight` 1, a stalled initiation makes both routes on both clones answer the busy
  refusal with no provider or database contact and no rate spent. Closing that client's
  connection cancels the provider request and releases the permit, and later requests are
  admitted.

Mutating the router to skip the method check, the in-flight check, the body or target
check, or to share one budget between routes makes these tests fail.

The managed PostgreSQL case `provider_keys::tests::postgres::handoff` keeps every ADR 0017
assertion. It then completes a second login through the router over loopback HTTP: a `303`
with the caller cookie and a new login row, a `429` initiation that adds no row, a `303` to
the landing with a session cookie that validates for the seeded user, a replay refused by
the handoff with no token request, and a `429` callback. It runs in the existing CI step and
filter only.

The process test (`cargo test --locked --offline --test runtime`) still checks that the API
and worker answer `404` for the login paths and set no cookie.

Not claimed: the PostgreSQL case was compiled and listed locally, not run. No browser, real
provider, ingress, image, cluster, load test or rollout was exercised. The hyper and `http`
limits above come from the locked library sources, not from a measured deployment.

## Compatibility

No dependency, Cargo feature, lockfile, migration (1–9 unchanged), auth settings document,
process contract, HTTP contract, CI workflow or provenance-register change. API and worker
startup are unchanged. New public items: `browser_auth::router` (`router`, `Settings`,
`Rate`, `SettingsError` and eight constants). `handoff::respond`, `handoff::wrong_method`
and `LoginHandoff::callback_path` become visible to the router module only. The handoff's
behaviour, responses and errors are unchanged.

## Remaining

Still outstanding before any exposure: runtime enablement (settings source, construction and
mounting in the API); trusted ingress routing, transport limits and telemetry redaction;
browser qualification; session validation and logout handlers with CSRF protection; operated
cleanup and retired-key reservation reclamation; and operating values for these bounds from
measurement. Native handoff, real-provider qualification, provisioning, resource
authorization (V1-05), reconciliation and audited recovery also remain. #5 stays open.
