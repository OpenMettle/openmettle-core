# 0009 — Protected browser login transactions

Status: coordinator-approved development contract, 17 November 2026. V1-04 core #5;
sprint #34. Implementation and independent qualification are separate gates.

## Boundary

`src/login.rs` provides executable internal browser login initiation, durable callback
consumption and library-constructed authorization-code exchange through an injected
`AsyncHttpClient`. Migration 6 adds protected transactions and nonce reservations.
There is no route, cookie, production HTTP adapter, discovery, JWKS refresh, application
session, admission, account creation or grant creation. `VerifiedIdentity` remains a
provider assertion; it does not authenticate an API request. Existing identities must
still pass current admission and disablement checks before access or provisioning.

Only a public Authorization Code client with S256 PKCE is supported in this increment.
Confidential-client authentication needs a separately reviewed secret lifecycle.
No interoperability claim follows for a provider that requires client authentication.
No offline-access scope is requested. Refresh and access tokens are discarded after
parsing; no upstream credential is persisted.

## Trusted configuration and browser binding

The future deployment loader supplies `Provider`, its `TrustedProvider`, and `KeyRing`.
Issuer, client, provider UUID, revision, authorization endpoint, token endpoint, callback
and fixed destination identifier are configuration, never token-selected values.
URLs require HTTPS and reject user information, queries, fragments, whitespace and
backslashes. This deliberately restricted initial profile does not support endpoints
with configured query parameters. Validation is not endpoint reachability approval.
No forwarded host or arbitrary return URL is accepted.

The deployment authority must assign a new provider UUID when replacing an issuer or
client registration, and must never silently rebind identity. The transaction compares
all configuration binding bytes, not just the revision. Disabled or changed configurations
fail. JWKS content is deliberately outside that binding; the caller supplies a currently
trusted key set when consuming the transaction. There is no configuration registry or
automatic rotation in this increment.

Each login generates independent 256-bit state secret, nonce, verifier and caller secret
using fallible `ring::rand::SystemRandom`. A separate random 256-bit public locator is
included in state. Base64url encoding has no padding. State has 87 bytes; the other secrets
have 43. Database uniqueness protects locators and state digests. An insertion conflict
fails the login rather than silently reusing it. The library derives the S256 challenge.
State and caller comparisons use `subtle::ConstantTimeEq` over SHA-256 digests after lookup
by the public locator. Database index lookup is not claimed to be constant-time.

The future browser route must deliver the caller secret only to the initiating browser
using a Secure, HttpOnly, host-only cookie, with suitable SameSite and expiry rules.
Initiation CSRF and concurrent-tab behavior require qualification. State alone is
insufficient to consume a transaction. Cookie transport is not implemented here;
[ADR 0017](0017-browser-login-handoff.md) adds an unmounted adapter for it.
Native flow and native-to-API handoff remain deferred; this module accepts no native flow.

The initial callback profile requires RFC 9207 `iss`, exactly equal to the configured
issuer, before consumption or exchange. Missing or mismatched issuer fails closed.
The callback URI must exactly match the configured value. Future HTTP parsing must reject
duplicate or ambiguous parameters and handle provider errors without disclosure.
Providers without response issuer identification need a separately qualified callback
strategy; ID-token issuer checking alone is not enough to protect code dispatch.

## Protected storage and keys

The only encrypted value is the 43-byte PKCE verifier. The fixed format is
`aes256gcm-v1`: AES-256-GCM through ring, 12-byte nonce and 16-byte authentication tag.
Ciphertext is exactly 59 bytes. State, OIDC nonce and caller secret have SHA-256 digests
only. There is no algorithm negotiation or plaintext fallback.

Authenticated data uses the existing length-framing convention: fixed domain including
trailing NUL, then u64 big-endian lengths and field bytes. Expiry is a signed i64 in
big-endian milliseconds. The outer domain `openmettle/login/1` includes format, locator,
provider binding, expiry, state digest, nonce digest, caller digest and key ID.
The nested `openmettle/login-provider/1` binds provider UUID, revision, issuer, client,
authorization endpoint, token endpoint, callback, browser flow, destination and
`public-pkce` client-authentication mode. No delimiter-based concatenation is used.

`KeyRing` accepts one active key and at most three decrypt-only keys. IDs are 1–64 ASCII
letters, digits, underscores or hyphens. Duplicate IDs and equal key material under
multiple IDs are rejected within a ring. Deployment must preserve that rule across
replicas and rotations, never rebind a historical ID, and use keys exclusive to this
purpose. The module has no key file, CLI, credential loader or key-generation command.

Before **each encryption**, reserve an OS-random 96-bit nonce under `(key_id, nonce)` in
its own bounded root transaction. PostgreSQL uniqueness serializes replica collisions.
Only an acknowledged reservation commit permits encryption. Collision retries are
limited to three. An error, cancellation or unknown commit abandons that candidate;
no encryption follows it. A later login uses fresh randomness. Reservations remain after
failed initiation and ciphertext scrubbing. Both root transactions explicitly use
READ COMMITTED and synchronous commit. Database storage durability remains a deployment
prerequisite; asynchronous failover that loses acknowledged reservations is unsafe.

Rotation: distribute the new key to all replicas, switch the first/active entry, retain
previous keys through the maximum login lifetime and rollout overlap, then retire them.
A missing key or failed authentication tag requires a new login. There is no re-encryption
or key recovery fallback. Before writing after database restore or lost acknowledged
state, invalidate all restored pending login transactions and provision a new active key.
Do not resume restored logins with old keys. Those deployment operations are not supplied
or authorized by this module.

Protection covers database-only disclosure and authenticated-field tampering without
keys. It does not cover API-process compromise, combined database/key compromise,
privileged rollback, or a malicious deployment authority. Application SQL privileges
bound the process, not individual users, and cannot enforce the helper's whole protocol.
In particular, raw API-role SQL can reset consumption and restore previously captured
ciphertext. Single-use consumption is enforced by the helper, not a database trigger.
Secrets and permits redact Debug; errors are fixed enums. Memory zeroization, swap and
core-dump protection are not claimed. URLs, callbacks, bodies and secret wrappers must
not be logged by future callers or transports.

## Consumption and failures

`begin` returns browser material only after insertion commit acknowledgement. `consume`
owns its root transaction and returns a non-cloneable permit only after consumption commit
acknowledgement. No uncommitted savepoint can return an exchange permit. The permit owns
the validated callback code, immutable provider/client/callback configuration, verifier
and expected nonce digest; exchange accepts no replacement code or provider.

Acquire the row lock first, then obtain `clock_timestamp()` in a separate statement.
Transaction-start `now()` is not used. Lifetime is 1–600 seconds; lock and statement
limits are 2 and 3 seconds, and each complete operation has a 10-second deadline.
Wrong state, caller, issuer, callback, configuration or expiry does not consume the row.
The winning consumer decrypts, sets `consumed=true`, scrubs ciphertext and commits.
Concurrent callbacks have one winner. Consumed rows never return another permit.

Cancellation/error drops the transaction owner. Discard the connection whenever protocol
cleanup or commit outcome is uncertain. The helper never resets or leases a consumed
transaction for retry. Crash after commit but before exchange loses that login. Unknown commit emits
no permit. Exchange cancellation, timeout, error or ambiguous response requires a new
login; never retry the authorization code automatically. There is no external HTTP under
a database lock and no exactly-once claim across PostgreSQL and the provider.

`ExchangePermit::exchange` calls the existing library's `exchange_code`, S256 verifier,
exact redirect and `request_async` once. Codes are bounded to 4096 visible ASCII bytes.
The injected adapter's returned body is limited to 64 KiB, 32 headers and 8 KiB header
bytes before library parsing; the complete exchange has a 10-second deadline. These
checks cannot prevent an injected adapter from allocating an oversized body first.
Future production transport must stream with bounds, avoid retries/detached work and
implement TLS, redirects, DNS/IP binding and SSRF policy. No such adapter is provided.

An ID token is mandatory. The original compact token retains its signed `nbf` claim through
library parsing and reaches the existing verifier. `ExpectedNonceDigest` uses the library
nonce callback with explicit bounds and constant-time digest equality. The existing
plaintext API delegates to that same path. All ADR 0008 signature, RSA-strength, issuer,
audience, authorized-party, time and subject checks remain required. Safe errors discard
provider and library diagnostic text. Unknown-key refresh is deferred; no code retry occurs.

## Migration and qualification

Migration 6 is additive; released migrations 1–5 are unchanged. API receives SELECT and
explicit INSERT columns on the two new tables, plus UPDATE only on consumed/ciphertext.
Worker and PUBLIC receive no login access. Neither application role can delete reservations,
change immutable bindings, grant privileges or perform DDL. Nonsecret consumption and
reservation tombstones remain. Public route exposure is blocked until bounded pruning,
retention, initiation rate limits and outstanding-transaction limits are agreed.

CI builds authentic schema-v5 binaries from
`4a51242839e16e1d7b8ad3538887bf8e41081e6e`, preserving v2–v4 checks. The populated upgrade
fixture includes every prior domain and grants; old API/worker readiness remains required,
and the old migrator must refuse without mutation. Migration image expectations include 6.

Tests cover real fake-provider challenge/client/callback checks, signed claim failures,
redaction, key aliases/rotation, authenticated-data tampering, PostgreSQL consumption races,
expiry after lock wait, duplicate-reservation refusal by SQL uniqueness, denied roles and
over-grants. The random-reservation retry/exhaustion path is not directly tested. Protocol
barriers hold observed PostgreSQL responses for cancellation, process kill and lost commit
acknowledgement. The fake transport does not establish TLS, DNS, redirect, streaming or
real-provider interoperability. PostgreSQL tests require isolated CI PostgreSQL 18; they
must not run against a workstation/shared database.

This partly addresses #5's identity/state/nonce/PKCE criterion and protects transient login
secrets. Browser/native handoff, application sessions, logout/revocation, invitation or
approved tenant/group admission, collisions/disablement, bounded membership reconciliation
and audited account recovery remain outstanding. No issue acceptance is closed.

## Dependencies and provenance

Direct exact dependencies added: ring 0.17.14 (https://github.com/briansmith/ring,
Apache-2.0 AND ISC; defaults disabled, `std`) and subtle 2.6.1
(https://github.com/dalek-cryptography/subtle, BSD-3-Clause; defaults disabled).
Both were already locked and used transitively. Cargo.lock adds only two workspace edges;
no package version, checksum or package count changes. The direct ring dependency adds the `std` feature to the previous
`alloc`, `default`, `dev_urandom_fallback` feature set. Subtle features remain unchanged
(`const-generics`, `default`, `i128`, `std`) through existing transitive consumers. No HTTP client is added.
Existing V1-42 blockers and ADR 0008's RSA private-key advisory remain visible. No scanner
suppression, waiver, licence clearance or distribution approval is implied.
