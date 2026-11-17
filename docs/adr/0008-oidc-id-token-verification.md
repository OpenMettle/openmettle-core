# 0008 — Offline OIDC ID-token verification core

Status: coordinator-agreed first V1-04 increment, 17 November 2026. Related: core #5 and
sprint #34. Independent review remains required. This increment partly addresses the first
#5 acceptance criterion only. #5 stays open.

## Decision

`src/auth.rs` verifies untrusted ID-token bytes against explicitly trusted provider inputs
using `openidconnect`. A valid token produces a `VerifiedIdentity` holding only the provider
configuration UUID, the exact issuer and the subject. Every failure maps to a fixed
`VerifyError` category.

The module has no route, network I/O, discovery, key refresh, state, PKCE, code exchange,
persistence, session, account lookup or admission. A verified identity only shows that a
trusted provider asserted this issuer/subject pair for this client and nonce. It does not
authenticate a session, admit an account or grant access. An identity that already exists
is not an admission bypass either: future login flows must recheck current admission and
disablement.

## Inputs and trust

| Type | Source | Bounds |
| --- | --- | --- |
| `TrustedProvider` | Deployment configuration, via a future owner | Canonical lowercase provider UUID; exact HTTPS issuer with a host and no user information, query or fragment, ≤ 2048 bytes; client ID of 1–255 printable ASCII bytes; JWKS document ≤ 64 KiB with 1–16 keys the library can use |
| `ExpectedNonce` | A future login-transaction owner | 22–512 visible ASCII bytes. The caller must generate ≥ 128 random bits |
| `UnverifiedIdToken` | Untrusted | 1–16 KiB, exactly two dots, base64url alphabet only. Checked before any parsing |
| `Policy` | Implementation policy | Issue-time age 1 s–1 h (default 5 min); future skew 0–5 min (default 60 s), shorter than the age |
| `now` | Trusted clock supplied by the caller | Must be at or after the Unix epoch and representable |

The token cannot select the issuer, client, audience or key set. Issuer comparison is the
library's exact string match, so trailing slashes and case differences fail. An HTTPS issuer
is required in every configuration, including tests, because the module makes no network
request.

The default durations are implementation choices, not owner-approved product values.
Deployment profiles can tighten them within the bounds above.

## Verification

Before token verification, our configuration check requires every parsed RSA key to have
an effective modulus of at least 2048 bits ([RFC 7518 §3.3](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3)).
Leading zero bytes do not count toward strength. A missing, zero or too-small RSA modulus
rejects the whole key set. Signature verification remains in the library.

The library, using `IdTokenVerifier::new_public_client` with the explicit trusted issuer,
client ID and JWKS, performs these checks:

- JOSE header: an absent `typ` or one of the library's default types (`application/jwt`,
  `application/jose`, after normalization); no `cty`, `crit` or JWE.
- Exact issuer, and an audience that contains the client. Untrusted extra audiences are
  rejected, because the default "other audience" policy is not relaxed.
- An algorithm allowlist of exactly RS256. `alg: none`, every HMAC algorithm (the public-client
  mode holds no secret) and other RSA or EC algorithms are rejected.
- Key selection by `kid` and algorithm compatibility, never trusting the header's key. No match
  or an ambiguous match is `UnknownKey`.
- RSA PKCS#1 v1.5 signature verification with the trusted public key.
- `exp` against the injected clock (`now >= exp` fails). No leeway is applied, and expiry is
  never disabled.
- A mandatory nonce. The library compares SHA-256 digests of the expected and received values.

`openidconnect` 4.1.0 leaves `azp` validation commented out (see `verification/mod.rs`), accepts
any `iat` by default and ignores `nbf`. After the library has verified the signature and claims,
this module therefore also enforces:

- exactly one audience. Multiple audiences are rejected even with a matching `azp`. This is a
  disclosed provider limit for this increment;
- `azp`, if present, equal to the client ID;
- `iat` no more than the future skew ahead of `now`, and no older than the issue-time age;
- the RFC 7519 `nbf`, if present, no later than `now` plus the future skew. A non-numeric `nbf`
  is malformed. No other claim is read;
- a NUL-free ASCII subject of 1–255 bytes, without trimming or normalization, matching `user_identities.subject`. The issuer is already bounded
  to the 2048 bytes `user_identities.issuer` allows.

Email, names, groups and tenant claims are ignored. Nothing links or merges accounts.

The `timing-resistant-secret-traits` feature is not enabled. It only changes `PartialEq` on
secret wrappers, and this module never compares secrets with `==`. Nonce comparison happens
inside the library's digest-based verifier.

## Diagnostics

`VerifyError` and `ConfigError` are fieldless enums with fixed `Display` text. Library error
messages are discarded unread, because they can quote issuers, audiences, algorithms and key
identifiers. The raw-input wrappers (`UnverifiedIdToken`, `ExpectedNonce`) print `..` in
`Debug` and have no `Display`. The `Debug` output of `TrustedProvider` and `VerifiedIdentity`
shows only the provider UUID. This is internal verification hygiene. It is not HTTP
problem-response redaction, which remains with the future endpoint owner.

## Dependencies

| Crate | Version | Origin | Licence | Use |
| --- | --- | --- | --- | --- |
| openidconnect | 4.1.0, `default-features = false` | https://github.com/ramosbugs/openidconnect-rs | MIT | ID-token parsing and verification; minimum Rust 1.88. Registry checksum `df0d098a59353679624d406825940139e2b2d554a52b64c9fb1b1bc42a11fe5c` |
| chrono | 0.4.45 (`std`) | https://github.com/chronotope/chrono | MIT OR Apache-2.0 | Clock type the verifier requires; already a transitive dependency |
| serde, serde_json | 1.0.229, 1.0.154 | serde-rs | MIT OR Apache-2.0 | Moved from dev to production for the `nbf` claim type and JWKS parsing; already locked |
| rsa, rand_core (dev only) | 0.9.10, 0.6.4 | RustCrypto, rust-random | MIT OR Apache-2.0 | In-memory test signing keys; already locked by this change |
| base64 | 0.22.1 | https://github.com/marshallpierce/rust-base64 | MIT OR Apache-2.0 | Production RSA modulus decoding for the strength check; also used by malformed-token tests; already locked |

Disabling the default features removes `oauth2`'s HTTP clients, so no reqwest, curl or ureq is
present. Choosing an HTTP transport is deferred. A custom hyper transport is not approved just to
avoid duplicating reqwest; a simpler maintained adapter should be evaluated first.

Measured `Cargo.lock` change: 226 → 317 packages, 91 added and none removed. The version and
checksum of every existing package are unchanged; existing entries changed only through
feature-unification edges and dependency-name disambiguation. On the macOS development host,
62 of the new packages compile for the normal and build graph, 9 only for other targets
(Windows, Android, Haiku, wasm) and 20 are lock-only optional entries that no enabled feature
compiles (jiff, time, schemars and others). Declared licences are MIT, Apache-2.0, BSD-3-Clause
(`curve25519-dalek`, `ed25519-dalek`), Unlicense OR MIT, and MIT OR Apache-2.0 OR BSD-1-Clause.

The library always compiles its RSA, P-256/P-384 and Ed25519 key types. The RS256 allowlist
means only RSA verification is reachable at run time. By the existing V1-42 convention, every
new lock package is an automatic distribution blocker with no exact-version review: the gate
now reports 318 Cargo blockers. No clearance is claimed and the register is unchanged.

### RUSTSEC-2023-0071

`openidconnect` 4.1.0 requires `rsa ^0.9`, which resolves to 0.9.10. The advisory
(https://rustsec.org/advisories/RUSTSEC-2023-0071.html, patched in ≥ 0.10.0) describes a timing
side channel in RSA **private-key** operations that can leak the key. Production code reaches
`rsa` only through `openidconnect`'s public-key signature verification. It performs no RSA
signing or decryption and holds no RSA private key. The library's signing types are linked but
never called in production. Tests generate and use private keys in memory, and those keys are
never written to disk.

This analysis is not a waiver. The repository runs no advisory scanner today; a future
`cargo audit` or `cargo deny` step will report this advisory and must surface it rather than
ignore it. Before any production private-key use, upgrading to an `openidconnect` release that
uses `rsa` 0.10 is required.

## Evidence

`tests/auth.rs` runs offline in the normal `cargo test` suite. Keys are generated in memory
per process. All values are synthetic, and the clock is fixed.

- A valid RS256 token yields only the provider, issuer and subject. Email claims do not change
  the identity.
- Rejection cases:
  - wrong, trailing-slash and case-changed issuers;
  - a wrong audience, an extra untrusted audience, and a duplicated audience with a matching
    `azp`;
  - an `azp` mismatch;
  - a missing or wrong nonce, and invalid expected nonces;
  - `exp` equal to or before now;
  - `iat` past the skew or past the age (including with a stricter injected policy), and `nbf`
    past the skew;
  - an empty or oversized subject.
- Malformed input: empty, wrong segment counts, illegal characters, oversized tokens,
  non-JSON headers and payloads, a missing `sub` and a non-numeric `nbf`.
- Algorithm attacks: `alg: none` with and without a signature; HS256 keyed with the trusted
  JWKS bytes or the client ID; RS384 using the trusted key.
- Signature attacks: a different key claiming the trusted `kid`, a spliced payload and a
  truncated signature.
- Key sets: an unknown `kid`; an explicit replacement key set that accepts the new key and
  rejects the old one; a two-key set.
- Configuration bounds for the provider UUID, issuer, client ID and JWKS (empty, non-JSON, no
  usable keys, oversized, 17 keys); `Policy` bounds; clock range.
- Synthetic marker values in the issuer, audience, `azp`, subject and nonce never appear in
  error `Display`/`Debug` text or in the wrappers' `Debug` output.

A replacement key set is a caller input. These tests do not qualify automatic rotation,
caching or JWKS refresh.

## Not covered

This increment cannot claim state, PKCE, callback-replay or authorization-code protection. Those
need persistent transaction ownership and a code exchange. It also does not establish nonce
single use: the expected nonce is trusted input, and replay acceptance is the future
transaction owner's responsibility.

Also outside this increment: discovery, SSRF controls, JWKS fetch/refresh/caching, any HTTP
transport, migrations, sessions, admission, account creation, browser and native flows, group
reconciliation, operator recovery, and real-provider interoperability. No issuer has been tested
except synthetic in-process tokens.

## Notes for follow-on design

- The future transaction design must settle how the upstream PKCE verifier is stored, because
  it has to be recovered for the code exchange; hashing state or nonce does not explain that.
  It must also keep comparisons of hashed values constant-time.
- Operator recovery must not infer authorization or administrator semantics. Those belong to
  V1-05.
- The native broker proposal and the provider-outage freshness policy remain open owner
  decisions. They are deferred until an increment needs them.

The minimum-strength check uses already-locked `base64` 0.22.1 (MIT OR Apache-2.0) as a direct production dependency to decode the library-parsed public modulus. It adds no lock package or feature; it replaces the previous dev-only declaration. Tests sign with ephemeral 512/1024-bit keys and reject their configuration, including zero padding, and retain a valid 2048-bit control. Signed subject tests reject NUL and non-ASCII values and preserve valid boundary values exactly.
