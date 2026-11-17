# 0017 — Same-origin browser login handoff

Status: coordinator-agreed V1-04 implementation contract, 17 November 2026.
Refs #5; Refs #34. Independent review and CI acceptance are separate gates. #5 remains open.

## Problem

ADR 0009 requires the caller secret to reach only the initiating browser in a Secure,
HttpOnly, host-only cookie, and requires HTTP parsing that refuses repeated or ambiguous
callback parameters and never discloses provider errors. ADR 0016 supplies `begin` and
`complete` over the pool. Nothing translated a browser request into those calls or their
results into cookies and redirects.

## Decision

`src/browser_auth/handoff.rs` adds one adapter, `LoginHandoff`, built from a shared
`BrowserAuth` and three explicit settings. It has two entry points. Each takes the head of
one HTTP request (`http::request::Parts`) and returns one response whose body is empty or a
fixed line.

| Entry point | Accepts | Success |
| --- | --- | --- |
| `initiate` | A form `POST` whose single `Origin` is the application origin | `303` to the provider, with the caller cookie |
| `callback` | A `GET` on the registered callback path carrying one authorization success response and the matching caller cookie | `303` to the landing, with the session cookie |

**The adapter is not mounted.** No router, listener or running process constructs it. The
API still serves `/healthz` and `/readyz` only, loads no auth settings and answers `404`
for a callback path. Qualification in a browser is outstanding.

### Settings

| Setting | Rule |
| --- | --- |
| `origin` | Exactly the ASCII origin serialization browsers send: `https`, lowercase host, a port only when it is not 443, nothing after it |
| `landing` | A path starting with one `/`, made of ASCII letters, digits and `/ - . _ ~`, with no dot segment, query or fragment |
| `provider` | A configured provider UUID, matched exactly by the existing lookup (ADR 0016) |

None has a default, and none is part of the version-1 auth settings document (ADR 0015),
which is unchanged. A later runtime-enablement increment decides where they come from.
Construction refuses with one of four fixed categories and carries no value.

The adapter reads the issuer and the exact registered callback string from the provider
registered under that UUID, through two crate-internal accessors. The callback must be the
application origin followed by a plain path; otherwise construction is refused. One adapter
serves one provider. Nothing in a request selects a provider, an issuer, a callback or a
destination.

### Initiation

Decisions are made in this order. The first two happen before any service call.

1. The method is `POST`. Otherwise `405` with `Allow: POST`.
2. There is exactly one `Origin` field and its bytes equal the configured origin. A missing
   field, `null`, a repeated field, a list and any other scheme, host or port are `403`.
3. `BrowserAuth::begin` for the configured provider. Any failure is `503`.
4. `303`. `Location` is the authorization URL exactly as `begin` returned it. `Set-Cookie`
   is the caller cookie.

The path, query, body, `Host`, `Forwarded`, `X-Forwarded-*`, `Referer`, fetch metadata and
cookies are not read. No custom header is required, so an HTML form works and the browser
follows the `303` to the provider as a navigation.

```text
__Host-openmettle-login=<locator>.<caller secret>; Max-Age=<login lifetime in seconds>; Path=/; Secure; HttpOnly; SameSite=Lax
```

The cookie has no `Domain`, so it is host-only. `Max-Age` is the configured login lifetime
(ADR 0009, 1–600 seconds). The locator is the public transaction locator that also starts
`state`; the caller secret appears nowhere else.

### One caller-cookie slot

A browser holds one caller cookie for the origin. A later initiation replaces it. The
callback requires the cookie's locator to equal the locator in `state`, so the callback of
an older login is refused once the newer cookie is stored. That refusal happens before any
service call and consumes neither login.

The callback never deletes the caller cookie. A deletion sent with the response to login A
could arrive after login B's cookie was stored and erase it. The retained value is harmless:
the login it names is consumed on success, and both the cookie and the transaction expire
with the login lifetime.

### Callback

All of these are decided before any service call, in this order:

1. The request path equals the registered callback path byte for byte. Otherwise `404`.
2. The method is `GET`. Otherwise `405` with `Allow: GET`.
3. The raw query is at most 32 KiB and has at most 32 parameters. Both are checked before
   decoding.
4. Every name and value decodes strictly as `application/x-www-form-urlencoded`: visible
   ASCII, `+` as a space, `%` followed by two hexadecimal digits, and UTF-8 after decoding.
   Empty parameters and empty names are refused.
5. No decoded name occurs twice, whether recognized or not (RFC 6749 §3.1). `code` and
   `%63ode` are the same name.
6. `error`, `error_description` and `error_uri` are absent. A provider error, and error
   detail beside a code, are refused without reflecting any text.
7. `code`, `state` and `iss` are present. The code is 1–4096 visible ASCII bytes. The state
   is two 43-character base64url tokens joined by a dot. `iss` equals the configured issuer
   as an exact string (RFC 9207 §2).
8. The `Cookie` fields total at most 16 KiB and contain the caller cookie exactly once
   across all fields, with the same two-token shape.
9. The cookie's locator equals the state's locator.

Other well-formed parameters are ignored. The adapter then builds the existing
`login::Callback` from the decoded state, code and issuer, the cookie's caller secret and
the configured callback string, and calls `BrowserAuth::complete` once. Consumption,
exchange and issuance repeat their own checks unchanged (ADRs 0009–0016).

`complete` returns a credential only after acknowledged issuance and a fresh validation
(ADR 0013). Only that result sets the session cookie:

```text
__Host-openmettle-session=<credential>; Path=/; Secure; HttpOnly; SameSite=Lax
```

`Location` is the configured origin followed by the configured landing. The session cookie
has no `Max-Age` or `Expires`: expiry in the primary database stays authoritative, and a
browser may keep the cookie after the session has ended. The name matches the provisional
`browserSession` scheme of ADR 0007, which stays provisional; the contract is unchanged.

The size ceilings are implementation bounds, not operating values. The query ceiling admits
a 4096-byte code, a 2048-byte issuer and the state with every byte percent-encoded.

### Responses

| Status | Fixed line | Cause |
| --- | --- | --- |
| `405` | `method not allowed` | Wrong method |
| `403` | `login origin refused` | Initiation `Origin` rule |
| `404` | `not found` | Callback path |
| `400` | `login response refused; restart login` | Callback rules 3–7 |
| `400` | `login browser binding missing or superseded; restart login` | Callback rules 8–9 |
| `403` | `login denied` | `complete` returned `Rejected` or `Verification` |
| `503` | `login unavailable; restart login` | Any `begin` failure; every other `complete` failure |

- Every response has `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
- A refusal sets no cookie, deletes no cookie and has no `Location`. A denied or replayed
  callback therefore leaves an existing session cookie in place.
- No credential, code, state or caller secret is placed in a response body or in the
  landing URL.
- `Location` and `Set-Cookie` values are marked sensitive, which keeps them out of `Debug`
  output. An HTTP/2 encoder that honors the mark does not index them.
- The adapter writes no log. Its `Debug` output and its errors carry no value.
- The mapping from service errors is exhaustive, so a new category must be classified
  before the crate compiles.

These follow RFC 9700 §§4.1–4.4: the exact registered callback and no caller-chosen
destination, no referrer from the callback response, a single-use code that is never
stored, and the issuer check against mix-up.

## Limits

- **Concurrent initiations.** The browser keeps the cookie from whichever initiation
  response it stores last, which need not be the last one started. Only that login can
  complete. The other is refused at its callback and keeps its row until expiry.
- **Refused logins keep their admission slot.** A stale, provider-denied or abandoned login
  is not consumed and counts against the outstanding limit until it expires (ADR 0014).
- **A new login does not end the previous session.** The browser's session cookie is
  overwritten. The earlier session stays valid until expiry or logout and still counts
  toward the retained-session allowance (ADR 0013).
- **The form page's referrer policy matters.** Under the Fetch standard a form `POST` from
  a page with `Referrer-Policy: no-referrer` sends `Origin: null`, which is refused.
- **The callback must be a top-level `GET` navigation.** `SameSite=Lax` withholds the
  caller cookie from embedded and cross-site `POST` requests. `response_mode=form_post` is
  unsupported.
- **`__Host-` and `SameSite` are enforced by the browser.** The binding assumes a browser
  that refuses a `__Host-` cookie set by another host or without `Secure`, including through
  a nameless cookie. No browser has been qualified.
- **The request's authority is not checked.** `Host`, forwarded headers and an
  absolute-form target are ignored. Trusted ingress must terminate TLS for the application
  origin and route only that host to the adapter.
- **Telemetry is outside the adapter.** An access log or trace that records request
  targets or headers would capture codes, states and cookies. Redaction must be in place
  before mounting.
- **No request control.** Every admissible `POST` spends a permanent nonce reservation and
  a login row (ADR 0014). The parsing ceilings do not replace request-size, rate or
  concurrency limits at the server and ingress, which may also be lower than these.
- **No protection for later session-authenticated requests.** `SameSite=Lax` on the
  session cookie is not a CSRF mechanism for unsafe methods. Session validation and logout
  handlers are not integrated.

## Evidence

Local tests without PostgreSQL (`cargo test --locked --offline --lib provider_keys::tests::handoff`)
call the two entry points over the synthetic TLS provider and a listener that never speaks
the PostgreSQL protocol:

- settings: valid and refused origins, landings and provider identifiers, a callback at
  another origin, a retired provider and redacted `Debug` output;
- initiation: wrong methods; missing, `null`, repeated, listed and mismatched `Origin`
  values while `Host`, forwarded and `Referer` headers name the application; then the
  admissible `POST`;
- callback: wrong paths and methods; malformed escapes and UTF-8; repeated members
  including decoded aliases; incomplete responses; wrong issuers; provider errors with
  marker text; unsafe code and state shapes; one parameter and one byte over the query
  ceilings; a missing, misnamed, malformed, repeated (within and across fields) and
  oversized caller cookie; and a cookie that names another login;
- every refusal has the fixed line, `no-store`, `no-referrer`, no `Set-Cookie` and no
  `Location`. After all refusals the provider has received no request and the database
  stand-in no connection;
- requests at exactly the query, parameter and cookie ceilings, with a maximal
  percent-encoded code, reach the service. They end as `503` because the stand-in never
  answers.

No login can start without PostgreSQL, so unit tests
(`cargo test --locked --offline --lib browser_auth::handoff`) check the two success
responses through the builders the entry points use: `303`, an empty body, exactly one
`Location` and one `Set-Cookie`, the exact cookie strings above, sensitive values absent
from `Debug` output, and a value that cannot be a header ending as `503` with no cookie.
They also pin the status and line for every service error category.

One managed PostgreSQL test (`provider_keys::tests::postgres::handoff`) runs in the existing
CI step and filter against the isolated PostgreSQL 18 service. It covers two initiations
with their `Location`, cookie attributes and sensitive headers; the older login's callback
refused with the newer cookie, with no provider request and nothing consumed; a provider
error that spends nothing; completion with one token request, the landing redirect and a
session cookie whose credential validates for the seeded user; and a replay refused with no
second token request, no cookie and the session still valid.

The process test (`cargo test --locked --offline --test runtime`) checks that the API and
worker answer `404` for the synthetic callback path and for form `POST`s, set no cookie,
send no redirect, and still answer `GET` alone on `/healthz` and `/readyz`.

Not claimed: the PostgreSQL test was compiled and listed locally, not run. No browser, real
provider, ingress, image, cluster or rollout was exercised. Browser behaviour described
above comes from the Fetch and cookie specifications, not from observation.

## Compatibility

No dependency, Cargo feature, lockfile, migration (1–9 unchanged), auth settings document,
process contract, HTTP contract, CI workflow or provenance-register change. `http` and `url`
types come through the existing `axum` and `openidconnect` dependencies. New public items:
`browser_auth::handoff` (`LoginHandoff`, `Settings`, `SettingsError` and five constants).
New crate-internal accessors: `ManagedProvider::issuer` and `ManagedProvider::callback`.
`BrowserAuth`, the approval model, session preservation across routine revisions, explicit
generation revocation, the callback transaction and pooled connection ordering are
unchanged.

## Remaining

This is one internal increment toward the browser handoff criterion of #5. Still
outstanding before any exposure: browser qualification; trusted ingress routing and
telemetry redaction; session validation and logout handlers, with CSRF protection for
unsafe methods; request, rate and concurrency controls; operated cleanup and retired-key
reservation reclamation; and runtime enablement (startup loading of settings, construction
and route mounting). Native handoff, real-provider qualification, provisioning, resource
authorization (V1-05), reconciliation and audited recovery also remain. #5 stays open.
