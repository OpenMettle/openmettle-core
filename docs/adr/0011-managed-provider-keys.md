# 0011 — Configured discovery and managed signing keys

Status: coordinator-agreed V1-04 implementation contract, 17 November 2026.
Refs #5; Refs #34. Independent review remains required. #5 remains open.
[ADR 0012](0012-login-provider-authority.md) replaces the process-generation login binding
and makes identical re-registration a no-op; the rest of this record still applies.
The [amendment of 19 November 2026](#amendment-19-nov-2026) replaces the token-endpoint
authentication rule and the treatment of `no-store` and `no-cache` responses.

After local identity admission, [ADR 0037](0037-gateway-provisioning-and-usage-reconciliation.md)
governs per-user gateway credentials, entitlement changes and inference usage reconciliation.

## Boundary

`provider_keys` connects configured discovery and signing-key refresh to the existing
single-use browser exchange permit. It supplies internal `begin`, `consume`, `preflight`
and `exchange_with_keys` operations. There is no authentication route, browser cookie,
native handoff, application session, admission, provisioning or account recovery.
`VerifiedIdentity` remains a provider assertion, with private construction. Existing
identities still require current admission and disablement checks before access.

The offline `TrustedProvider`, login `Provider`, `begin`, `consume` and injected-client
`exchange` APIs retain their behavior. Online key validation is deliberately stricter.
A managed permit cannot use the offline exchange entry point. Only the private managed
path can release its identity after current-generation checks.

## Configuration and compatibility

Deployment constructs a keyless `ProviderIdentity`, then a `ProviderConfig`, then registers
it with one process-owned `ProviderManager`. No dummy signing key or verified identity is
needed to fetch documents. The filesystem/environment loader remains separate work.

Configuration fixes the UUID, issuer, client, revision, authorization/token endpoints,
callback/destination, discovery and JWKS URLs, trust roots and private CIDRs. Discovery
compares issuer and authorization/token/JWKS endpoints exactly. Metadata never authorizes
another destination. The client does not use `openidconnect::discover_async`, which fetches
the metadata's JWKS URI before our consistency check could intervene.

The required metadata fields follow [OIDC Discovery section 3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata):
issuer, authorization endpoint, token endpoint for this code flow, JWKS URI, response types,
subject types and ID-token signing algorithms. This client requires `code`, a supported
public/pairwise subject type, and RS256. Optional grants default to the standard code/implicit
set; an explicit grants list must include `authorization_code`. If response modes are
advertised, `query` must be present. Scope advertising is optional and not exhaustive.
No implicit-flow implementation, userinfo, registration or logout endpoint is required.

This initial metadata-qualified public-client profile also requires advertised token
endpoint authentication `none`, PKCE `S256`, and RFC 9207 issuer-response support `true`.
These are compatibility limits, not claims that every OIDC document must advertise them.
Absent authentication advertising defaults to Basic in OIDC Discovery; absent PKCE
advertising indicates no support in [RFC 8414 section 2](https://www.rfc-editor.org/rfc/rfc8414.html#section-2);
the issuer-response flag defaults false in [RFC 9207 section 3](https://www.rfc-editor.org/rfc/rfc9207.html#section-3).
There is no fallback to confidential authentication, plain PKCE or issuer-less callbacks.

`ProviderDocuments` exposes only configured discovery and JWKS fetch operations. The
existing transport constructor and `AsyncHttpClient` remain POST-only. GET uses the same
caller-driven TLS, all-answer DNS validation, process-wide eight DNS slots, hard-denied
addresses, explicit private CIDRs, 32-header/8-KiB-header/64-KiB-body limits and deadlines.
GET has an empty body and fixed Accept header. Neither operation follows redirects,
proxies, retries, token-header URLs or key certificate URLs. Production exposes no test
resolver, loopback exemption, fake clock or arbitrary GET destination.

## Online documents and keys

Only HTTP 200 with `application/json` is accepted for discovery. JWKS also accepts
`application/jwk-set+json`. One optional UTF-8 charset parameter is supported. Duplicate
content types, other encodings/parameters and unsolicited 304 responses fail.

The bounded JSON reader rejects duplicate members at every depth, including ignored
extensions. The existing Serde JSON recursion limit remains enabled. Typed metadata rejects
malformed known fields; unknown extensions are ignored within those document bounds.

JWKS has at most 16 **raw** keys before filtering. Every recognized field is checked before
it can be ignored. Private/symmetric material is refused. Only public RSA signing keys
compatible with RS256 are selected; ordinary public keys for other algorithms/use can be
filtered. Eligible RSA moduli must have 2048–8192 effective bits; leading zeros do not add
strength. Moduli must be odd. Exponents must be odd, at least 3, smaller than the
modulus, and fit in 32 bits. The maintained openidconnect 4.1.0 verifier calls
`rsa::RsaPublicKey::new`, whose limit is 4096 bits. Structurally valid 4097–8192-bit
keys are therefore filtered as unsupported; a set containing only these keys retires the
old set and remains unavailable. The 8192-bit document bound is not an interoperability
claim. Supporting larger signatures requires separately reviewed library work.

`alg`, `use` and `kid` are optional. A supplied `kid` is at most 256 UTF-8 bytes, NUL-free,
and compared exactly. Duplicate eligible signing-key identifiers are refused. If
`key_ops` is present, this profile accepts exactly `["verify"]`; signing, encryption,
private/mixed operations, duplicates and conflicts with `use` fail. This is a deliberately
restricted public-verification profile, beyond the optional-member rules in
[RFC 7517 sections 4–5](https://www.rfc-editor.org/rfc/rfc7517.html#section-4).
Signature verification and all existing issuer/audience/azp/nonce/time/subject checks
remain in the maintained verifier plus ADR 0008's local checks.

## Freshness and replacement

`RefreshPolicy::new` requires every value; there is no `Default`:

| Parameter | Implementation bounds |
| --- | --- |
| Maximum freshness | 1 second through 24 hours |
| Refresh cooldown | 1 second through 1 hour |
| Whole operation deadline | 10 milliseconds through 60 seconds |
| Registered provider UUIDs, including retired entries | 1–64 |
| Concurrent admitted callers, including waiters | 1–1024 |
| Concurrent document GETs | 1–64 |

These ceilings bound resources, not recommended deployment settings. The owner must supply
operational values before exposure. This implementation needs no stale-key grace decision.

Cooldown is a hard availability trade-off: if a response's remaining freshness is shorter
than cooldown, logins fail after expiry until the next attempt is allowed. Age and network
delay can shorten that window even when the configured freshness cap exceeds cooldown.
Re-registering even identical configuration clears keys and preserves cooldown, so a reload
can block logins for the remaining interval (up to the configured one-hour ceiling).
The future loader must avoid unnecessary re-registration; deployment qualification must
compare cooldown with observed remaining document freshness and tolerate this outage.
Reducing cooldown permits more provider traffic; increasing freshness does not override a
shorter provider lifetime. This increment supplies no proactive refresh or stale-key fallback.
The strict future-Date rejection below can also make a replacement unavailable when provider
and local clocks differ. Clock synchronization is therefore part of provider qualification.

The first profile uses unconditional GET, explicit `max-age`, a valid Date, and optional
Age. It subtracts the larger of apparent age and Age plus monotonic request delay, then
uses a monotonic expiry capped by the configured lifetime. Duplicate headers/directives,
invalid or overflowing numbers, future Date, wall-clock rollback, and unsupported cache
semantics make a representation non-reusable. Quoted numeric max-age is accepted.
Metadata and keys must **both** remain fresh; the snapshot uses their minimum deadline.
This is a restricted profile of [RFC 9111 sections 4–5](https://www.rfc-editor.org/rfc/rfc9111.html#section-4),
not a general HTTP cache.

There are no conditional requests, heuristic freshness, Expires fallback or stale grace.
`no-store`, `no-cache`, missing freshness and expired responses yield no reusable snapshot.
Stale-if-error and stale-while-revalidate never authorize expired verification.

A fully validated replacement atomically retires the old set, including an empty set.
A valid replacement without reusable freshness also retires old keys and makes the provider
unavailable. HTTP, media or parse failure cannot publish a partial candidate or extend the
old deadline. Previously valid keys may remain usable only through their original deadline.
A metadata issuer/endpoint/capability mismatch immediately invalidates readiness.
Valid metadata without reusable freshness also invalidates readiness before any JWKS fetch.

No fetch can detect an upstream removal before observing it. A known-key signature failure
never triggers refresh, including a provider that reuses a kid for new key material; such a
rollover becomes usable after the next permitted refresh. Providers should use distinct
identifiers during rotation. There is no retained-key union or hidden grace period.

## Concurrency, cancellation and configuration lifecycle

One manager must own registration for the process. It retains bounded UUID entries after
retirement, so re-registration cannot reset cooldown or bypass an outstanding flight.
Changing issuer/client requires a new UUID. Re-registration increments the entry generation,
invalidates old handles and keys, and keeps the previous attempt's cooldown. Capacity is
rejected immediately; callers and GETs do not form an unbounded semaphore queue.

Every refresh fetches at most one discovery and one JWKS document. A single flight coalesces
callers, with watch-channel subscription providing missed-notification protection. Cooldown
is recorded before capacity acquisition or outbound work, including failed/cancelled attempts.
Unknown kids share this provider-wide budget; there is no attacker-keyed negative-cache map.
Waiters receive that flight's outcome and do not take over a cancelled leader immediately.

The leader owns the HTTP future. Its drop guard records cancellation, clears the flight and
wakes waiters. Dropping HTTP closes the socket; only ADR 0010's bounded OS DNS work may
outlive the caller. Locks protect short state transitions; no network or database await
holds a cache lock. No background refresh or detached credential-bearing task is created.

Managed transaction binding uses a new domain and includes configured endpoints, effective
TLS-root fingerprint/private CIDRs, and the registration generation. It does not rely on a
caller policy label. Old offline bindings fail managed comparison without a schema change.
Construction also bounds the complete framed binding to migration 6's existing 12-KiB
limit, so individually valid long URLs cannot cause a late database constraint failure.
The in-memory registration serial is not a durable configuration registry: deployment must
coordinate revision changes and registration lifecycle across replicas/restarts. Pending
managed logins cannot be assumed portable across differing registration histories. A future
loader must persist/coordinate revisions and invalidate pending logins when retiring or
restoring configuration. This increment supplies no recovery or cross-replica invalidation.

The bounded provider/key cache is process-local. Replicas multiply the permitted request
budget and can temporarily hold different key generations. A manager is a long-lived owner,
not something a request handler may construct per request.

## Managed login and verification

Managed begin and consume perform document preflight before entering existing database
transactions. Consumption still commits before returning a non-cloneable permit. Cancellation,
uncertain commit or exchange failure requires a new login; no code replay is introduced.

Exchange uses one overall deadline covering preflight, code POST and possible key refresh.
The complete permit binding is checked before dispatch. An already dispatched POST cannot
be recalled when configuration changes, but its identity cannot escape afterward.

Only a bounded genuinely absent kid can trigger one refresh after verification reports no
matching key. A missing kid with ambiguous candidates, invalid header, disallowed algorithm,
claim failure or known-key invalid signature does not refresh. An identifier present on an
ineligible raw key also suppresses refresh; the snapshot retains all bounded raw identifiers
separately from eligible signing keys. After an allowed refresh, the same original signed ID
token and nonce digest are verified once more after waiting, using a fresh wall clock.
Access/refresh tokens remain discarded; no unverified token becomes an API credential.

The result's linearization point is the final state-lock check: configuration is still active,
the key generation is current, and metadata/key freshness has not expired. Private verified
claim evidence rechecks expiration and issue-time age at release, without a third signature
verification. Clock rollback or a generation change fails closed rather than looping.
Fieldless errors and redacted Debug implementations never include provider/token values.

## Dependencies and evidence

The sole dependency change promotes already-locked `httpdate = 1.0.3` to a direct dependency
for HTTP-date parsing. Origin: https://github.com/pyfisch/httpdate; licence: MIT OR Apache-2.0.
The lockfile remains at 333 packages: no additions/removals or changed existing versions,
origins/checksums. Only the workspace dependency edge changes; httpdate adds no features.
No scanner suppression, advisory waiver or distribution clearance is implied. ADR 0008's
RSA private-key advisory and V1-42 provenance blockers remain visible.

Tests use the existing synthetic RSA and in-memory TLS fixtures, counted requests, barriers
and a private injected clock. They cover configured GET admission/bounds, metadata defaults
and mismatches, raw/duplicate/private/oversized keys, cache arithmetic and directives,
replacement/removal, one code POST, unknown-kid floods, cancellation/capacity recovery,
configuration changes during HTTP and verification, and expiration after waiting.
Existing offline verifier/login/transport tests remain regression coverage.

The managed exchange fixture constructs a permit inside cfg(test); it does not establish new
PostgreSQL consumption evidence. Existing real PostgreSQL commit/replay/compatibility tests
remain required CI gates. No local database, real provider, native-root deployment image,
GPU, release or rollout qualification is claimed. Browser/native sessions, admission,
reconciliation and audited recovery remain outstanding V1-04 acceptance work.

Observed local checks for this increment: repository hygiene and 180-fixture freshness,
52 Python tests, Rust formatting, all-target Clippy with warnings denied, locked offline
workspace build, and 111 non-PostgreSQL Rust tests passed. The 2 PostgreSQL process and 59
schema integration tests were not run locally; they remain CI gates, together with images
and kind. The proxy child test is exercised by its parent and is not counted twice.
Two generated provenance inventories were identical. Distribution readiness failed closed
with the existing 433 blockers; no package or licence-review clearance changed.

## Amendment, 19 Nov 2026

The [owner decision of 19 November 2026](https://github.com/OpenMettle/openmettle-core/issues/5#issuecomment-7002907924)
makes Keycloak the V1-04 real-provider target and approves two relaxations ("option B").
Stock Keycloak 26.8.2 failed this profile before sign-in in the PR #72 observation. Its
discovery omits `none` from `token_endpoint_auth_methods_supported` and sends
`Cache-Control: no-cache, no-store, must-revalidate, no-transform`. Its JWKS sends
`no-cache`. Neither response carries `Date` or `Age`.

### Client authentication advertising

Discovery no longer has to advertise `none`, and may omit the list. If present, the list must
still be an array. The list describes the provider, not this client. The client remains a
public PKCE client that sends no secret, and its binding still records `public-pkce`.
PKCE `S256` and `authorization_response_iss_parameter_supported: true` remain required.
There is still no fallback to confidential authentication, plain PKCE or callbacks without
an issuer.

### Responses that refuse caching

A response whose `Cache-Control` contains `no-store` or `no-cache` without a value is
reused for a short window that the operator sets. It is then fetched again.

**Owner decision.** The first D1 rule served such a document only to the operations already
running and fetched again at every start. Starts are preflight, login begin and callback
consumption. That rule conflicts with the provider refresh cooldown: a callback, or another
person's sign-in, arriving within the cooldown was refused, so Keycloak sign-in would mostly
fail. The [owner decision of 19 November 2026](https://github.com/OpenMettle/openmettle-core/issues/5#issuecomment-7005252283)
replaces that rule:

- A document that refuses caching is reused for an operator-set window: 60 seconds by
  default, 300 seconds at most.
- The refresh cooldown and the unknown-`kid` refresh are unchanged.
- **Accepted trade-off:** a key that the provider removes can stay trusted until the window
  ends, at most 300 seconds after the fetch. This bound assumes the response is fresh from the
  origin. An intermediary that serves an old copy with its original `Date` and no `Age` adds
  its own staleness, because `Date` does not age the window (see Validation).

The owner rejected three alternatives. Exempting these providers from cooldown would let
outbound fetches grow with unauthenticated sign-in attempts. Adding cache headers at a reverse
proxy was also rejected, as was keeping the D1 rule.

**Validation.** Validation is unchanged:

- Every directive is still validated first. A malformed, unknown or repeated directive fails
  as before, wherever it appears. So do a repeated `Cache-Control`, `Date` or `Age` header,
  an invalid `Age`, an invalid or future `Date`, and wall-clock rollback during the request.
  A field-qualified `no-cache="…"` fails closed. Such failures make the provider unavailable.
- `Date` is optional for these responses. When present it must be valid, but it does not age
  the window. A refusal overrides any `max-age` in the same header.
- Responses with `max-age` behave as before, and still require `Date`. Missing freshness,
  `max-age=0` and expired responses still make the provider unavailable.

**Lifetime.** The window counts from when the request was sent. Any `Age` the response
carries is subtracted, and the configured maximum freshness caps the result. An `Age` that
uses the whole window makes the document unusable. The snapshot expires at the earlier of
its two documents' lifetimes, as before. A provider can therefore mix a `max-age` discovery
with a refused JWKS. The snapshot stays in the existing process-local entry, and there are no
storage or schema changes. Every start and continuation uses a cached snapshot until it
expires, whether or not its documents refused caching.

**Setting.** `provider_refresh.uncacheable_reuse_seconds` in the auth settings document
([ADR 0015](0015-offline-auth-config-check.md)) is optional in versions 1 and 2:

```json
"provider_refresh": {
  "freshness_seconds": 3600,
  "cooldown_seconds": 60,
  "uncacheable_reuse_seconds": 60,
  "deadline_milliseconds": 5000,
  "max_providers": 2,
  "max_callers": 32,
  "max_document_gets": 2
}
```

| State | Rule | Reason |
| --- | --- | --- |
| Absent | 60 seconds, capped by `freshness_seconds` | Documents written before this member existed still load |
| Present | 1–300 seconds | The owner's bounds |
| Present | At least `cooldown_seconds` | Cooldown is set when a refresh starts, and the window counts from a request sent after that. A shorter window would expire while a refresh is still blocked, refusing every sign-in in between. A response `Age` can still shorten the window |
| Present | At most `freshness_seconds` | Freshness is the operator's cap on how long any document is trusted. The window must not exceed it |

A value outside these rules fails the offline check with "provider refresh policy is out of
range". The cooldown rule applies only to an explicit value. A document without the member
and with a cooldown above 60 seconds still loads. It then has the gap described above for
such a provider, just as a `max-age` shorter than cooldown already does. Operators of a
provider that refuses caching should therefore set the member. A cooldown above 300 seconds,
or above `freshness_seconds`, leaves no valid explicit window.

For such a provider:

- **Key rotation.** A new key becomes usable at the next fetch: when the window ends, or
  earlier through the unknown-`kid` refresh. As before, the replacement retires the old
  generation. A removed key stays trusted until then, which is the accepted trade-off.
- **Unknown `kid`.** The refresh rule is unchanged and shares the cooldown. Inside cooldown the
  token fails without a fetch. After cooldown a refresh fetches both documents, and the
  replacement starts a new window.
- **Concurrent sign-ins.** Cooldown, admitted callers, GET slots, size limits and deadlines
  are unchanged. Starts during a refresh share it, and later starts reuse its result until the
  window ends. A begin and a callback inside one window share its fetch.
- **Unreachable provider.** Within the window, operations continue on the held snapshot, as
  for any cached document. After it ends, sign-in fails until a fetch succeeds, and a fetch is
  attempted at most once per cooldown. There is no outage grace. Such a provider refreshes once
  per window rather than at its `max-age`, so one transient fetch failure or leader timeout
  refuses sign-ins for up to a full cooldown, and does so more often than for a cacheable
  provider. An operation that straddles the end of a window is refused rather than refreshed
  (for example at `confirm` or `check_assertion`). That is negligible at 60 seconds and
  noticeable near the 1-second minimum.

**Operational cost.** At most one discovery and one JWKS fetch per window, plus any
unknown-`kid` refreshes, which cooldown already limits. That is one of each per minute at
the default, per provider and process.

Unchanged and still mandatory: PKCE S256, the exact registered callback, issuer and
endpoint equality, the RFC 9207 issuer flag and callback `iss` check, HTTPS-only transport,
document size and time bounds, and every key validation above.

New public items: `RefreshPolicy::with_uncacheable_reuse`, `DEFAULT_UNCACHEABLE_REUSE` and
`MAX_UNCACHEABLE_REUSE` in `provider_keys`. `RefreshPolicy::new` keeps its signature and
selects the default window.

Evidence for this amendment comes from in-process tests with synthetic TLS fixtures. They
use Keycloak's exact header strings, a JWKS response without `Date`, and the same
start/continuation sequence as sign-in. They cover reuse within the window and a fetch after
it, a callback inside cooldown that needs no fetch, concurrent starts sharing one fetch,
unknown-`kid` rotation, `max-age` lifetimes, the freshness cap, and the setting's bounds,
default and cross-field rules in the loader. No PostgreSQL test was added because the cache
is process-local. No real-provider sign-in, deployment or Keycloak support is claimed. That
needs the separate hosted Keycloak qualification.


### Hosted Keycloak 26.8.2 CI qualification (V1-04 block D, increment D2)

Increment D2 adds the hosted CI browser sign-in qualification against pinned stock Keycloak
26.8.2 (`quay.io/keycloak/keycloak@sha256:c68e286cacd87b942ac1939a0a1481461109d6acd3a57dc496969a319a76bbf0`)
in `.github/workflows/keycloak-qualification.yml`, `tests/keycloak/`, `tests/browser/keycloak.py`
and `provider_keys::tests::postgres::browser::keycloak_browser_sign_in_qualification`.

- **Transport and trust.** Keycloak runs with `--http-enabled=false` on an `--internal` Docker
  bridge network (no egress) using a per-run server certificate signed by a per-run test CA
  (`provider-ca.pem`). `fixture.py` writes a version-2 auth settings document validated offline
  with `openmettle-api --check-auth-config`, selecting `trust.roots = "bundle"` against that
  single CA and `private_cidrs` for the container's single IPv4 `/32`. Production TLS defaults,
  egress policy and migrations are unchanged.
- **Reuse window verification.** The qualification sets `cooldown_seconds: 60` and
  `uncacheable_reuse_seconds: 300`, loading `AuthConfig` through `auth_config::load` and
  exercising `BrowserAuth`, `LoginHandoff` and `router_with_sessions`. It verifies that discovery
  and JWKS are fetched once over HTTPS at the first login initiation and reused without refetch
  across the callback and a second full browser sign-in inside the same reuse window.
- **Sign-in coverage.** Chrome completes two isolated journeys against Keycloak's public PKCE
  `S256` client with exact redirect URI and RFC 9207 `iss`: an existing identity approved via
  `docs/operator/first-identity-approval.psql` (ADR 0013) and a first-account home invitation
  redemption with a one-time code created via `docs/operator/home-invitation-create.psql`
  (ADR 0022), each followed by same-origin session check, logout and post-logout refusal.
- **Provider observation alignment.** `tests/provider_observation/observe.py` now classifies
  stock Keycloak 26.8.2's observed headers and omitted `none` as
  `compatible-with-bounded-uncacheable-reuse` under this amendment while keeping all raw header
  and metadata facts verbatim and failing on any wire conflict with the current profile.
- **Boundaries.** This increment qualifies pinned stock Keycloak 26.8.2 in hosted CI only (live
  CI pass requires pushing to GitHub Actions; Docker and PostgreSQL are not run locally). It is
  not owner deployment evidence or general provider support, and the browser login router remains
  unmounted in `openmettle-api`.
