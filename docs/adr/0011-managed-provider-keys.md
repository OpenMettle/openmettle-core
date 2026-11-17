# 0011 — Configured discovery and managed signing keys

Status: coordinator-agreed V1-04 implementation contract, 17 November 2026.
Refs #5; Refs #34. Independent review remains required. #5 remains open.

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
claim failure or known-key invalid signature does not refresh. The same original signed ID
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
