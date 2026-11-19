# 0022 — Home invitation codes

Status: owner-approved V1-04 design, 18 November 2026
([owner decisions](https://github.com/OpenMettle/openmettle-core/issues/5#issuecomment-6987200982)).
Refs #5; Refs #34; Refs #73. Independent review and CI acceptance are separate gates. #5
remains open.

## Problem

A [home invitation](../operator/home-invitations.md) (migration 12) lets an operator approve
first-account creation for one exact provider, issuer and subject. Redemption ran through an
owner-defined function that checked the originating login row, the provider authority and the
pending invitation.

The API role writes every one of those rows itself. It inserts login rows with their
binding, marks them consumed and knows the provider's current epoch. A principal limited to
SQL as `openmettle_api`, such as a holder of the API's database credentials or of a SQL
injection in the API, could therefore fabricate a consumed login and redeem any pending
invitation without an OIDC sign-in.

## Decision

Each invitation carries a random one-time code that only the operator's create command ever
shows. The person enters it when they start their sign-in. Redemption requires it.

Delivered in two commits:

1. **Migration 13, operator command and consumer rule.** The code is generated and hashed in
   the database, redemption takes it as a sixth argument, and the session consumer refuses a
   missing identity that presents no code.
2. **This change.** The browser initiation route accepts the code, the login seals it and
   the sealed proof carries it to redemption.

**The browser routes are still not mounted.** No listener or running process constructs the
handoff or the router (ADRs 0017–0019).

### Code

| Property | Value |
| --- | --- |
| Secret | 16 bytes |
| Display | `omh1-` and 32 lowercase hexadecimal digits in eight groups of four |
| Stored | `sha256("openmettle/home-invitation-code/1" ‖ 0x00 ‖ code)`, 32 bytes, in `home_invitations.code_hash` |
| Lifetime | While the invitation is pending and before `redeem_before_ms`. No separate expiry |
| Use | Once. Redemption sets `approval_id`. The hash is kept afterwards |

The create command computes the code in a materialized CTE as the first 16 bytes of
`sha256(uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid()))`. It needs no
extension. In PostgreSQL 18, `gen_random_uuid()` (`src/backend/utils/adt/uuid.c`) fills the
UUID's 16 bytes from `pg_strong_random()` and raises "could not generate random values" if
that fails, then sets the version and variant bits, so each UUID contributes 122 random
bits. Review confirmed this in `REL_18_1` (`uuid.c:528-535`) and `REL_18_STABLE`
(`uuid.c:545-552`).

A plain domain-separated SHA-256 is enough for a 128-bit random value. There is no pepper,
slow hash or constant-time comparison: the database compares hashes with `=`.

The command prints the code once, after `COMMIT` is acknowledged. It refuses a redemption
window longer than seven days. The operator guide covers delivery, redaction, a lost code
and an uncertain create.

### Accepted input

`InvitationCode::parse` (`src/invitation.rs`) decides syntax only, before any provider or
database work:

- at most 64 bytes, ASCII only;
- ASCII spaces and `-` are removed, and letters are lowercased;
- what remains is 32 hexadecimal digits, with or without the `omh1` prefix.

`InvitationCode` has no `Display`. Its `Debug` output is `InvitationCode(..)`. The types that
carry it, `ExchangePermit` and `ExchangedIdentity`, print fixed text, and `Issuance` has no
`Debug` implementation.

### Browser initiation

The initiation route (ADRs 0017 and 0018) accepts one of two bodies.

| Body | Rule |
| --- | --- |
| Empty | Unchanged: no `Transfer-Encoding`, every `Content-Length` is `0` |
| Form | Exactly one `Content-Type: application/x-www-form-urlencoded`, exactly one `Content-Length` of 1–256 in plain decimal, no `Transfer-Encoding` |

The form holds exactly one field, `invitation_code`. An empty value means that no code was
entered. Any other field gets the fixed `400`, so a page that submits this form must not
name its submit control or add hidden fields such as a framework CSRF token. The media type is compared without case and takes no parameter, so
`application/x-www-form-urlencoded; charset=UTF-8` is refused. An HTML form sends the bare
media type. The 256-byte ceiling admits a 64-byte value with every byte percent-encoded.

Requests are decided in this order:

1. Method (`405`).
2. Head bounds, from metadata alone. A body outside both profiles is `413`
   `login request body not accepted`, including a chunked body, a declared length over 256
   and another media type. Nothing is read and nothing is spent.
3. In-flight permit (`503`).
4. One unit of the initiation budget (`429`).
5. The declared form is read under the permit: at most 256 bytes within 2 seconds
   (`FORM_READ_TIMEOUT`). A body that does not arrive completely in that time is `408`
   `login request body not received`. The rate unit stays spent.
6. The handoff: method, then `Origin`, then the form.

The handoff decides `Origin` before it parses the form, so a page on another origin gets the
origin refusal whatever its form holds. An unknown, repeated or malformed field and a
malformed code all get one fixed `400` `login request refused`. That refusal happens before
`BrowserAuth::begin`, so it costs no provider request, pooled connection, nonce reservation
or login row.

Every other route still requires an empty body.

### Sealed login

The code is sealed with the PKCE verifier in the login row, in a new format beside the one
ADR 0009 defined.

| Format | Authenticated-data domain | Plaintext | Ciphertext |
| --- | --- | --- | --- |
| `aes256gcm-v1` | `openmettle/login/1` | verifier (43) | 59 bytes |
| `aes256gcm-v2` | `openmettle/login/2` | verifier (43) ‖ flag (1) ‖ code (16) | 76 bytes |

- The flag is `1` with a code and `0` without. Without a code the 16 code bytes are zero.
  The ciphertext is 76 bytes either way, so a stored row does not show whether a code was
  entered.
- The authenticated data keeps the fields of ADR 0009. Only the domain and the format label
  differ, so neither format opens as the other.
- `begin` writes v2 only. `consume` selects the format by ciphertext length and opens both.
  A v1 login carries no code. Any other length, a failed tag, a malformed verifier, an
  unknown flag and code bytes without the flag are `Protection`.
- Consumption still clears the ciphertext in the same commit.

The opened code exists only in process memory:
`ExchangePermit` → `ExchangedIdentity` → `Issuance` → one bind parameter of
`redeem_home_invitation`. Nothing else reads it.

### Redemption

`sessions::resolve_identity` runs inside the issuance transaction, after the login and
provider locks and the authority check.

| Identity | Code | Result |
| --- | --- | --- |
| Exists | Any or none | The code is dropped without being evaluated. Ordinary approval, disablement and session checks decide |
| Missing | None | `Rejected`. The function is not called |
| Missing | Present | The six-argument function is called. An empty result is `Rejected` |

The function (migration 13) keeps the lock order and checks of migration 12. It then requires
a 16-byte code and locates the pending invitation by issuer, subject, provider, generation
**and** code hash, `FOR UPDATE`. A wrong code therefore follows the path of a missing
invitation: no invitation row is locked and nothing is written. The five-argument function
no longer exists.

### No signal to the person signing in

- At initiation only syntax is checked. A well-formed wrong code, a correct code, an empty
  field and an empty body all get the same `303`: same status, header names, parameter names
  and value lengths.
- At the callback, no invitation, a wrong code, no code, and a withdrawn, expired or fenced
  invitation all return the same `403` `login refused. Start a new login.` bytes.
- There is no counter or lockout (owner decision). A wrong code spends that login and leaves
  the invitation pending, so the correct code still works with a new sign-in. Each guess
  costs one initiation rate unit, one callback rate unit, one single-use login and a full
  provider sign-in as the exact invited subject.

## Trust boundary

**Closed.** A principal limited to SQL as `openmettle_api` can no longer redeem a pending
invitation:

- The API role has no privilege on `home_invitations`, and no function returns `code_hash`.
- The only redemption function requires the code.
- A sealed code in `login_transactions` is AES-256-GCM ciphertext under the login key ring,
  which is held outside the database, and it exists only until consumption.
- Guessing a 128-bit code is not feasible.

**Still trusted with the code:**

- the invited person, their browser and the device they sign in from;
- the channel that delivers the code, and the operator and terminal that ran the create
  command;
- a TLS-terminating ingress or proxy that logs request bodies. Ingress must not log
  initiation request bodies;
- the API process, which holds the code in memory from initiation until it is sealed, and
  from consumption until redemption;
- a holder of both the login key ring and read access to `login_transactions`, for the login
  lifetime of at most 600 seconds;
- the database owner, and anyone who can read server logs that record bind parameters. The
  operator guide lists the settings.

**Unchanged.** The database still cannot verify an OIDC proof. API-role SQL that holds a
code can satisfy the function and the commit gate without one. The same principal can still
issue sessions for any approved existing identity, which
[#73](https://github.com/OpenMettle/openmettle-core/issues/73) tracks. A leaked code alone
creates no account: redemption still needs a consumed login for the exact subject under the
current provider epoch.

## Upgrade and rolling update

- **Precondition (owner decision).** Migration 13 refuses to run while any invitation is
  pending. Withdraw pending invitations, migrate, then invite again. The operator guide has
  the steps.
- **Order.** Migrate first, then roll out. The current release cannot start a login on
  schema 12, whose check admits 59-byte ciphertext only.
- **Previous release on schema 13.** It cannot call the dropped function, so first sign-ins
  fail closed while ordinary sign-ins continue. It refuses a v2 ciphertext with
  `Protection`, and the person starts again.
- **Current release.** It completes a v1 login started before the upgrade, as a login
  without a code.
- **Later.** A corrective migration removes 59-byte acceptance after one release (owner
  decision). It is not part of this change.

## Native sign-in (block C)

**Adopted.** [ADR 0023](0023-native-sign-in.md) and migration 14 implement the three points
below: the native start takes the optional code, the system-browser confirmation form
carries it under the body rules of browser initiation, and the redemption function also
admits the native binding layout. The text below is the contract as this change set it.

Native start is not implemented here. Block C must adopt this contract:

- `BrowserAuth::start`, `ManagedProvider::begin` and `login::begin` take
  `Option<InvitationCode>`. A new start path cannot compile without deciding where the
  person enters the code.
- The system-browser confirmation page takes an optional `invitation_code` form field under
  the same body rules as browser initiation. The code never appears in a `GET` query, and
  the app never handles it (owner decision).
- The redemption function accepts only the managed login binding layout. Block C's migration
  must extend that check to the native binding. Until then, native first-account redemption
  fails closed.

## Limits

- **Not mounted.** The routes exist as library code only.
- **The form is a top-level HTML form `POST`.** A script that sends a `charset` parameter, a
  chunked body or a multipart body is refused.
- **A stalled body holds an in-flight permit for up to 2 seconds.** The permit bounds how
  many such requests wait at once, and each has already spent a rate unit. The cap is shared
  by every route, so stalled forms can delay callbacks, session checks and logouts until the
  read gives up. Operating values for the cap and the initiation budget must allow for that.
- **No per-invitation attempt limit.** Guessing is bounded by entropy and by the cost of
  each attempt, not by a counter.
- **Memory.** The code is not zeroized, and swap and core-dump protection are not claimed
  (as ADR 0009).
- **Telemetry is outside this code.** An access log, trace or proxy that records initiation
  request bodies would capture codes. Redaction must be in place before mounting.

## Evidence

Local, without PostgreSQL:

- `invitation`: accepted and refused code forms, and redacted `Debug` output.
- `login`: v2 round trip with and without a code at one length; v1 still opens and cannot
  hold a code; a flipped bit at every position and lengths on either side of 59 and 76 are
  refused; neither format opens under the other's domain; an unknown flag, code bytes without the flag and a
  malformed verifier are refused; the authenticated data binds every field in both formats.
- `browser_auth::handoff`: the form parser's accepted and refused bodies, and the fixed
  `400`.
- `browser_auth::router`: the form profile from metadata, and its refusal on the callback,
  session and logout routes.
- `provider_keys::tests::handoff`: method and `Origin` are decided before the form; a
  malformed form reaches neither the provider nor the database stand-in; a code, an empty
  value and an empty body reach the service with the same response.
- `provider_keys::tests::router`, through Axum dispatch on loopback: metadata refusals,
  including with no body byte sent; the foreign-origin and malformed-form refusals; a body
  that stalls after five bytes holds the only permit, then gets `408` after at least 2
  seconds and releases it; complete forms reach the service; and the initiation budget
  equals the number of admitted requests.
- `provider_keys::tests`: the code travels from the permit to the sealed proof.

Reordering the form before `Origin`, removing the read timeout and reading the body before
the permit each make one of these tests fail. This was checked by mutation.

PostgreSQL, in the existing CI steps and filters only:

- `provider_keys::tests::postgres::handoff::first_sign_in_needs_the_invitation_code_entered_in_the_initiation_form`
  runs complete sign-ins through the router. Uninvited, no code, an empty field, a code that
  differs in one bit and another well-formed code are each refused with the same status,
  headers and body (`Date` aside), spend their login and leave the invitation pending. A malformed code adds no login row and
  no provider request. The correct code then creates the account. Afterwards the spent
  code, a wrong code and no code all sign in to that one account, and a disabled account
  stays refused.
- The managed invitation tests of migration 13 now seal the code at `begin` instead of
  attaching it to the proof, so each one exercises seal, consume, exchange and redemption.
- A login sealed as v1 on schema 12 completes after the upgrade, a current start is refused
  on schema 12, and a start after the upgrade stores 76 bytes.
- The Chrome journey submits the application form with the field filled in and checks the
  media type and length that the browser declared.

Not claimed: the PostgreSQL and Chrome cases were compiled and listed locally, not run. No
real provider, ingress, image, cluster or rollout was exercised.

## Compatibility

- **Migrations.** None in this change. Migrations 1–13 are unchanged.
- **Public Rust items.** `login::begin`, `ManagedProvider::begin` and `BrowserAuth::begin`
  take the optional code. `LoginHandoff::initiate` takes the request body. New:
  `handoff::MAX_FORM_BYTES`, `handoff::INVITATION_FIELD` and `router::FORM_READ_TIMEOUT`.
  `invitation::InvitationCode` arrived with migration 13.
- **HTTP.** The initiation route gains the form profile, the `400` form refusal and the
  `408` body refusal. An empty-body initiation behaves as before.
- **Unchanged.** Dependencies, Cargo features, the lockfile, the auth settings document, the
  OpenAPI contract, the process contract and the CI workflow.

## Remaining

Block C adopted the code for native sign-in ([ADR 0023](0023-native-sign-in.md)). Still
open: the corrective migration that drops v1 acceptance, and the
Flutter web field: an optional "invitation code" input submitted as a top-level form `POST`
whose only field is `invitation_code`, never placed in a route, query, deep link or storage. Every exposure gate of ADRs 0017–0020
still applies. #5 stays open.
