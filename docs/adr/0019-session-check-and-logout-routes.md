# 0019 — Session check and local logout routes

Status: accepted with its implementation; V1-04 implementation contract, 18 November 2026.
Refs #5; Refs #34. Independent review and CI acceptance are separate gates. #5 remains open.

## Problem

ADR 0017 issues the `__Host-openmettle-session` cookie, and ADR 0018 bounds the login routes.
A browser could not ask whether its session was still valid or end it. ADRs 0017 and 0018
list session validation and logout handlers, with CSRF protection for unsafe methods, as
exposure gates. `BrowserAuth::validate` and `BrowserAuth::logout` (ADR 0016) already do the
database work. Nothing turns a browser request into a call to them.

## Decision

`src/browser_auth/router.rs` adds `router_with_sessions(handoff, settings, sessions)`. It
returns the ADR 0018 router plus two literal routes:

| Route | Method | Handoff entry point | Success |
| --- | --- | --- | --- |
| Session check | `GET` only | `LoginHandoff::session` | `204`, empty |
| Logout | `POST` only | `LoginHandoff::logout` | `204` that deletes the session cookie |

**The router is not mounted.** No listener or running process constructs it. The API and
worker still serve `/healthz` and `/readyz` only and answer `404` for every login and session
path. `router(handoff, settings)` is unchanged: it still builds the two login routes only.
Auth settings version 1, the OpenAPI contract, the service and the database are unchanged.

### Settings

`SessionSettings` is explicit, with no defaults, and is not part of the auth settings
document:

| Setting | Rule |
| --- | --- |
| `session` | Exact literal path of the session check |
| `logout` | Exact literal path of logout |
| `checks` | Rate budget for session checks: `burst` 1–65 536, `interval` 1 ms–1 hour |
| `logouts` | Separate rate budget for logouts, same ranges |

Both paths follow the ADR 0018 path shape. All four paths (initiation, callback, session,
logout) must differ from each other and from `/healthz` and `/readyz`. A failure uses the
existing fixed categories (`Pattern`, `Path`, `Collision`, `Rate`, `InFlight`) and carries no
value. Validation runs before any route is added.

The ranges are implementation ceilings, not operating values. A later runtime-enablement
increment decides where the settings come from.

### Request order

Every route uses the same dispatch function as the login routes, in the ADR 0018 order:

1. Method (`405` with `Allow`). `HEAD` is refused.
2. Request bounds: target, header count, header bytes and an empty body. The body is
   judged from metadata and never read.
3. One permit from the in-flight cap. The cap is shared by all four routes (`503`).
4. One unit of the route's own budget (`429`). Each of the four routes has a separate budget.
   Session polling therefore cannot spend logout or login rate.
5. The handoff, with the original request head. A dropped request releases its permit and
   cancels the service call under ADR 0016.

Steps 1–4 do no provider, pool or database work. A unit spent in step 4 is never refunded.

### Session check

1. Require exactly one `Sec-Fetch-Site: same-origin` field before reading cookies. Refuse
   missing or repeated fields, other origins on the same site, cross-site requests and
   address-bar navigation (`none`). [Fetch Metadata](https://www.w3.org/TR/fetch-metadata/#sec-fetch-site-header)
2. Require exactly one `__Host-openmettle-session` cookie within the 16 KiB total cookie
   field limit. Cookie names compare exactly, as for the login caller cookie.
3. Call `BrowserAuth::validate` once. Its session parser refuses a malformed credential
   before requesting a pooled connection (ADR 0016).
4. Return an empty `204` for a valid session. Discard the identity and personal scope.

The check reads no `Origin`, path, query or other cookie. It sets and deletes no cookie and
never redirects.

### Logout

1. Exactly one `Origin` field whose bytes equal the configured application origin, using the
   same function as initiation. A missing, `null`, repeated, listed or different `Origin` is
   refused before any cookie is read and before any service call. This is the CSRF control
   for this unsafe method.
2. The session cookie rule above.
3. `BrowserAuth::logout` is called once, with no eligibility check before it. Possession of
   an issued credential revokes it after expiry, disablement, approval withdrawal or
   provider retirement (ADR 0013).
4. Only after the revocation transaction's commit is acknowledged, the response is `204`
   with one `Set-Cookie`:

   ```text
   __Host-openmettle-session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax
   ```

   The name, `Path`, `Secure`, `HttpOnly`, `SameSite` and the absence of `Domain` match the
   issued cookie, so browsers replace and expire it. The value carries no credential.

A refusal, a database failure, a timeout and an uncertain commit delete nothing. The caller
cookie `__Host-openmettle-login` is never touched. Logout revokes only the presented session.
Other sessions of the same user stay valid until they expire or are revoked.

### Responses

| Status | Fixed line | Cause |
| --- | --- | --- |
| `204` | (empty) | Valid session, or acknowledged logout |
| `403` | `session origin refused` | Session check Fetch Metadata rule |
| `403` | `session not valid` | Session cookie absent, repeated or malformed, or credential unknown, revoked, expired or no longer eligible |
| `403` | `logout origin refused` | Logout `Origin` rule |
| `503` | `session unavailable; try again later` | Any other service category: database, timeout, configuration, capacity or randomness |
| `405` | `method not allowed` (with `Allow`) | Wrong method |
| `414` | `session request target too long` | Target bound |
| `431` | `session request headers too large` | Header count or byte bound |
| `413` | `session request body not accepted` | Body not empty |
| `503` | `session busy; try again later` | No in-flight permit |
| `429` | `session rate limit reached; try again later` | Route budget spent |

Every response uses the handoff's builder: `Cache-Control: no-store` and
`Referrer-Policy: no-referrer`. A non-empty body is one plain-text fixed line. No response
has a `Location`, a retry time, a count or a request value. Only the acknowledged-logout
`204` has a `Set-Cookie`. The mapping from service errors is exhaustive, so a new category
must be classified before the crate compiles. The login routes keep their ADR 0018 lines.

These staged routes use `403` for cookie credential refusals. The versioned application
API has its own unauthenticated response contract (ADR 0007). Any `401` response requires
an applicable challenge. [RFC 9110, §15.5.2](https://www.rfc-editor.org/rfc/rfc9110.html#name-401-unauthorized)

### Repeated and concurrent responses

- **Repeated logout.** Logout is idempotent while the revoked row is retained. A second logout
  with the same credential is acknowledged and deletes the cookie again. After operator
  cleanup removes the row (ADR 0013), the same credential receives `403 session not valid`.
- **Uncertain logout.** After a `503`, the revocation may or may not have committed and the
  browser keeps its cookie. Retrying logout is safe. A later `session not valid` refusal
  means that the presented credential failed validation.
- **Deletion and a new session cookie.** A browser applies `Set-Cookie` in the order it
  processes responses, not the order requests were sent. If a login callback in another tab
  stores a new session cookie before a logout response arrives, the deletion removes the new
  cookie. The new session is not revoked. It stays valid until expiry and counts toward the
  retained-session allowance, but the browser no longer holds it. If the callback response
  arrives after the deletion, the browser holds the new session.
- **Requests in flight.** A request sent before the deletion still carries the old
  credential. After the revocation commits, validation refuses that credential. A check
  whose transaction ran before the commit may still return `204`. The database orders
  validation and logout; the browser's cookie jar does not.

## Limits

- **Per router value, per process.** As in ADR 0018: budgets and the in-flight cap are not
  cluster-wide, durable or fair between clients. The session check budget is shared by every
  browser on the replica. One client, or a deployment where many browsers poll often, can
  spend it for everyone until it refills. Size it from measured polling, or poll less.
- **Validation cost.** Each admitted check with a cookie takes a pooled connection and the
  SHARE locks of ADR 0013. Their throughput and latency are unmeasured.
- **Browser check profile.** Call the check from a page on the application origin. The
  browser must send Fetch Metadata and ingress must preserve it. The session cookie still
  has to validate. Use a dedicated application hostname as in ADR 0017.
- **Origin depends on the browser.** The rule assumes a browser that sends `Origin` on form
  `POST`. A page with `Referrer-Policy: no-referrer` sends `Origin: null`, which is refused.
  Non-browser clients without `Origin` cannot log out through this route. No browser has
  been qualified.
- **Session cookies have no expiry attribute.** A refused or uncertain logout leaves the
  cookie in place until the browser session ends. The database remains authoritative.
- **Not a parser or transport limit, and no telemetry redaction.** Ingress and server limits
  and redaction of cookies and request targets remain required before mounting.

## Evidence

Unit tests (`cargo test --locked --offline --lib browser_auth`) cover the deletion string
against the issued attributes, the logout `204` builder, the exhaustive error mapping, the
exact session-cookie rule beside the unchanged caller-cookie rule and four-path validation.

Dispatch tests (`cargo test --locked --offline --lib provider_keys::tests::session_routes`)
serve the router with `axum::serve` on loopback and send raw HTTP/1.1 bytes. They use the
synthetic TLS provider and a database stand-in that never speaks PostgreSQL:

- invalid session and logout paths and rates are refused through `router_with_sessions`
  without contact, and the login-only `router` answers `404` for both session paths;
- wrong methods, including `HEAD`, are `405`; path variants are `404`; target, header and
  body bounds use the session lines;
- missing, repeated (in one field and across fields), misnamed, truncated, non-canonical,
  caller-cookie-only and oversized cookies receive `403 session not valid` on both routes
  with no checkout;
- missing, repeated, same-site or cross-site Fetch Metadata on the session check is refused
  before the cookie rule or any checkout;
- every wrong logout `Origin` is `403` before the cookie rule, with no checkout. The check
  reads no `Origin`;
- a well-formed cookie reaches the service, and the stand-in's failed checkout is a `503`
  with no `Set-Cookie`;
- check, logout and login budgets are independent, and clones share them;
- with `in_flight` 1, a stalled initiation makes both session routes on both clones busy,
  with no rate spent. A disconnect releases the permit.

Mutating logout to read the cookie before `Origin`, letting session routes skip the
in-flight cap, or sharing the check budget with logout makes these tests fail.

The managed PostgreSQL case
`provider_keys::tests::postgres::handoff::issued_cookies_validate_and_logout_revokes_without_current_eligibility`
completes a login through the router and then:

- validates the issued cookie beside the caller cookie;
- refuses a wrong-`Origin` logout, leaving the row unrevoked and the cookie valid;
- logs out with one exact deletion after the revocation is committed, then refuses the
  credential on the route and in the service;
- acknowledges a repeated logout with the retained row;
- refuses a second issued session after approval withdrawal, revokes it by logout and keeps
  both refused after approval is restored;
- refuses an unknown credential without a deletion, with no provider request during any
  check or logout.

The existing routed login case is unchanged. Both run in the existing CI step and filter
only.

The process test (`cargo test --locked --offline --test runtime`) also checks that the API
and worker answer `404` for `GET /session` and `POST /logout` with a session cookie and set
or delete no cookie.

Not claimed: the PostgreSQL case was compiled and listed locally, not run. No browser, real
provider, ingress, image, cluster, load test or rollout was exercised.

## Compatibility

No dependency, Cargo feature, lockfile, migration (1–9 unchanged), auth settings document,
process contract, HTTP contract, CI workflow or provenance-register change. API and worker
startup are unchanged. New public items: `router::router_with_sessions`,
`router::SessionSettings`, `LoginHandoff::session` and `LoginHandoff::logout`. `router`,
its settings, its responses and the handoff's login behaviour are unchanged. Initiation
now shares its `Origin` check with logout, with identical behaviour.

## Remaining

Still outstanding before any exposure: runtime enablement (settings source, construction and
mounting in the API); trusted ingress routing, transport limits and telemetry redaction;
browser qualification, including Fetch Metadata, `Origin` and concurrent cookie ordering;
operating values from measurement; operated cleanup and
retired-key reservation reclamation. Native handoff, real-provider qualification,
provisioning, resource authorization (V1-05), reconciliation and audited recovery also
remain. #5 stays open.
