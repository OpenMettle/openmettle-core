# 0023 — Native sign-in with one-use code delivery

Status: proposed V1-04 implementation contract, 19 November 2026.
Refs #5; Refs #34. Independent review and CI acceptance are separate gates. #5 remains open.

## Problem

ADRs 0016–0019 give a browser a session cookie. A native app cannot use that cookie: it
signs in through the system browser and needs a credential it can keep in platform secure
storage. ADR 0022 also left native first sign-in closed. The redemption function accepted
only the browser login's binding, and no native start existed that could take the
invitation code.

## Decision

`src/browser_auth/native.rs` adds `NativeAuth`, a second adapter over the pooled service
(ADR 0016). It brokers the provider sign-in for one registered native client and delivers
the resulting local session once, as a short-lived code that the app redeems with its own
PKCE verifier.

**The router is not mounted.** No listener or running process constructs it. The API and
worker still serve `/healthz` and `/readyz` only. The browser handoff and its routes are
unchanged.

### Registration

`NativeAuth::new` takes the pooled service, an active provider UUID, and:

| Input | Rule |
| --- | --- |
| Deployment issuer | Canonical HTTPS origin, at most 2048 bytes |
| Upstream callback | HTTPS URL on that origin with its own path. Register it with the provider beside the browser callback |
| Client ID | 1–128 bytes of ASCII letters, digits, `-`, `.` and `_` |
| App link | Canonical HTTPS URL with a path, no query, fragment or user information |
| Concurrency | 1–1024 operations in flight |

The constructor refuses a registration whose routes collide with each other, with the
operational routes, or with the configured browser routes and landing path on the same
origin. It refuses an app link that equals a provider callback or one of its own routes.
There is no settings-document form yet: the registration is programmatic.

Two digests are computed once. Both are SHA-256 over a domain-separated, length-prefixed
encoding.

| Digest | Inputs | Stored in | Used for |
| --- | --- | --- | --- |
| Registration (`openmettle/native-login/1`) | Provider configuration binding, deployment issuer, upstream callback, client ID, app link | `native_handoffs.registration` | Fences a pending code to the exact configuration that issued it |
| Session audience (`openmettle/native-session-audience/1`) | Deployment issuer, client ID, app link, provider UUID and issuer | `native_handoffs.audience` | Names the downstream registration a delivered bearer belongs to |

This change stores the audience with every delivery. Enforcement on validation and logout
is a separate change (see Remaining).

### Sign-in

1. **App.** For each attempt the app generates 32 random bytes of state and a PKCE verifier
   of 43–128 unreserved characters. It keeps the verifier and the expected deployment
   issuer with the attempt.
2. **Confirmation page.** The app opens the system browser at `/auth/native/authorize` with
   exactly `response_type=code`, `client_id`, `redirect_uri`, `code_challenge_method=S256`,
   `code_challenge` and `state`. `GET` validates these and returns a static form. It
   contacts neither the provider nor the database. The page sends
   `Referrer-Policy: same-origin` and forbids framing.
3. **Confirmed start.** The form posts back to the same URL. Only a `POST` whose single
   `Origin` equals the deployment issuer can start a login. The API starts the managed
   provider login with fresh upstream state, nonce, verifier and caller binding. A host-only
   `Secure`, `HttpOnly`, `SameSite=Lax` cookie, `__Host-openmettle-native-login`, carries the
   login locator, the caller binding and the app's challenge and state for the login
   lifetime.
4. **Upstream callback.** The API checks the provider issuer and the cookie, consumes the
   login, exchanges the provider code once and verifies the ID token. It issues a local
   session only for an eligible identity with a personal scope, or for a first sign-in that
   redeems an invitation. It redirects to the app link with exactly `code`, the app's
   `state` and `iss`, the deployment issuer.
5. **Redemption.** The app checks the link, state and issuer against its attempt, then
   sends `POST /auth/native/token` with `Content-Type: application/json`:

   | Member | Value |
   | --- | --- |
   | `grant_type` | `authorization_code` |
   | `iss` | The expected deployment issuer |
   | `client_id`, `redirect_uri` | The exact registration |
   | `code`, `code_verifier` | The returned code and the app's verifier |

   Success is `200` with `token_type` `Bearer` and the opaque `access_token`. Any other
   member, a missing member, a wrong binding, a second use and an expired code are refused.

`GET /auth/native/session` and `POST /auth/native/logout` take one
`Authorization: Bearer` header and answer an empty `204`. The three back-channel routes
refuse a cookie, an `Origin` header and a query. Provider tokens stay in the API.

### Invitation code

The native flow adopts the ADR 0022 contract. The person enters the code in the system
browser, on the confirmation page, and nowhere else.

- **Field.** The confirmation form has one field, `invitation_code`. Its submit button has
  no name, because any other field is refused. An empty value means that no code was
  entered.
- **Body rules.** The confirmed start accepts the two bodies of browser initiation and
  nothing else: an empty body, or one `application/x-www-form-urlencoded` body of 1–256
  bytes with one plain-decimal `Content-Length` and no `Transfer-Encoding`.
- **Never in a URL.** The authorization query admits exactly its six protocol parameters,
  so `invitation_code` in a query is refused on `GET` and `POST` alike. The code is not
  placed in the cookie, the provider request, the app link or any response.
- **The app never handles it.** The app builds the authorization URL and receives the
  handoff code. Neither carries the invitation code (owner decision, ADR 0022).
- **Sealed with the login.** The code goes from the form to `BrowserAuth::start` and is
  sealed with the PKCE verifier in the `aes256gcm-v2` login format. The stored ciphertext is
  76 bytes with or without a code. Consumption opens it and clears it in the same commit.
- **Redemption.** `sessions::resolve_identity` treats a native login exactly as a browser
  login: an existing identity ignores the code, a missing identity without a code is
  refused without calling the function, and a missing identity with a code calls
  `redeem_home_invitation`.
- **No signal.** A well-formed wrong code, a correct code, an empty field and an empty body
  get the same `303` at the start. At the callback, no invitation, a wrong code, no code and
  another invitation's code get the same `403`. A wrong code spends that login and leaves
  the invitation pending.

Requests to the confirmed start are decided in this order:

1. Head bounds (`403`).
2. The body profile, from metadata alone (`413` `native sign-in request body not
   accepted`). Nothing is read and nothing is spent.
3. A request slot (`503`), then one unit of the route's budget (`429`).
4. The declared form is read: at most 256 bytes within 2 seconds, or `408`
   `native sign-in request body not received`.
5. The query, the method and `Origin` (`403`), then the form (`400`
   `native sign-in request refused`).

`Origin` is decided before the form, so a page on another origin gets the origin refusal
whatever its form holds. A malformed form costs no provider request, pooled connection,
nonce reservation or login row.

### Stored login binding

A native login must not complete through the browser callback, another native registration
or another attempt. Its stored binding therefore differs from the browser login's
(ADR 0012), and both are length-prefixed encodings with a u64 big-endian length before
every field.

| Login | Domain | Fields |
| --- | --- | --- |
| Browser | `openmettle/managed-login/2` | Provider configuration, epoch |
| Native | `openmettle/native-managed-login/1` | Provider configuration, attempt, epoch |

The attempt is the 32-byte digest of the registration digest and the app's challenge and
state. Consumption compares the whole stored binding, so changing the cookie's challenge or
state, or finishing at another registration, refuses the callback. The handle that
exchanges the provider code and the handle that issues the session must carry the same
attempt.

The provider configuration and epoch stay in clear in both layouts. That is what lets the
database check them (next section).

### Migration 14

`migrations/0014_native_handoffs.sql` does two things.

**Delivery table.** `openmettle.native_handoffs` holds one row per native session: the
digest of the handoff code, the registration and audience digests, the app's challenge, the
sealed bearer and an absolute expiry. Deleting the session deletes the row. The API role
may read rows, insert whole rows and clear `sealed`. It cannot change another column or
delete a row, and the worker has no access.

**Redemption binding check.** `redeem_home_invitation` is replaced in place. Its
signature, owner, security mode, search path and grants are unchanged, and so are its lock
order and every other check. Only the binding check differs:

| Stored binding | Migration 13 | Migration 14 |
| --- | --- | --- |
| Browser layout of this provider configuration and epoch | Redeems | Redeems |
| Native layout of this provider configuration and epoch | Refused | Redeems |
| Anything else | Refused | Refused |

For the native layout the function checks the domain, the configuration's leading fields
(provider UUID, issuer, client and current revision), that the attempt field is 32 bytes
long, and the epoch. It cannot recompute the attempt digest, and it does not need to: the
attempt binds a login to an app and a registration, which the API checks at consumption.
The function's own purpose is unchanged. It ties redemption to a consumed login of the
exact provider configuration and current epoch, and to the invitation code.

The change opens no new path for a principal limited to SQL as `openmettle_api`. That
principal could already write a login row with the browser layout. The code is what it
lacks (ADR 0022), and the native path requires the same code under the same comparison.

### Delivery and redemption

The session, the login's issued marker and the delivery row commit together. The handoff
code is 32 random bytes. AES-256-GCM seals the bearer under that code as a single-use key,
with the session locator as associated data. The database stores the code's SHA-256 and the
ciphertext, so a database snapshot alone does not reveal the bearer.

A code lives for at most 30 seconds, clipped to the login expiry, the session expiry, the
remaining proof budget (token expiry, maximum token age and signing-key freshness) and the
operation deadline.

Redemption matches the code digest, the S256 challenge and the registration, locks the row
and clears the ciphertext under synchronous commit. A second transaction then rechecks
session eligibility, the grant expiry and that the issuing provider epoch is still the
current one. Concurrent redeemers receive at most one bearer. After an uncertain commit the
app starts a new sign-in.

### Bearer

A native bearer has the same shape as the session cookie value, and its secret digest has a
separate domain (`openmettle/native-session-secret/1`). A browser session therefore never
validates as a bearer, and a bearer never validates as a cookie. Validation and logout also
require a delivered row for the session, so an unredeemed session has no usable credential.
Logout needs only possession: it records local revocation whatever the current eligibility.

## Limits

| Budget | Value |
| --- | --- |
| Upstream login | The configured login lifetime of 1–600 seconds and the outstanding-login cap (ADR 0014) |
| Handoff code | At most 30 seconds, clipped as described above |
| Local session | The existing session policy (ADR 0013). Retained sessions per user include both channels and undelivered sessions |
| HTTP | 1–1024 requests in flight per native router. One rate budget per route at the supplied rate. The token body allows 8192 bytes and 2 seconds. The authorization query allows 4096 bytes. Request heads use the browser router's limits |
| Database | The existing primary pool and session operation deadline |

- **Not mounted.** The routes exist as library code only.
- **A stalled form holds a request slot for up to 2 seconds**, as in ADR 0022.
- **The login cookie has one slot.** A later start replaces the cookie of an earlier
  attempt in the same browser, and a completed callback deletes it (see Remaining).
- **Expired undelivered rows** count toward retained-session capacity until the owner's
  session cleanup removes them (ADR 0013).
- **No refresh credential.** The app signs in again when the session expires.
- **Ingress.** It must enforce the deployment's HTTPS authority, preserve paths, and keep
  request targets, headers and bodies that carry authentication material or an invitation
  code out of logs.
- **Memory.** The invitation code is not zeroized (as ADR 0022).

## Trust boundary

For the invitation code this is the boundary of ADR 0022, with the system browser in place
of the application page. The code is trusted to the invited person, their device and system
browser, the delivery channel, a TLS-terminating ingress, the API process and the database
owner. The native app, the provider and the app link's destination never receive it.

The handoff code is trusted to the system browser, the operating system's link delivery and
the app. It is useless without the app's PKCE verifier and the exact registration.

## Upgrade and rolling update

- **Order.** Migrate first, then roll out.
- **Previous release on schema 14.** It keeps working. The redemption function keeps its
  signature, and a browser login redeems as before. The previous release has no native
  routes.
- **No precondition.** Migration 14 changes no existing row. A pending invitation keeps its
  code hash and stays pending.

## Evidence

Local, without PostgreSQL:

- `provider_keys::tests::stored_managed_binding_layout_matches_invitation_redemption`: the
  exact bytes of both stored layouts.
- `provider_keys::tests::permit_is_exchanged_only_by_the_handle_of_its_own_attempt`: a
  browser permit, a native permit and another attempt's permit are each refused by the
  wrong handle before any token request.
- `provider_keys::tests::postgres::native::confirmation_and_invalid_registrations_need_no_database_or_provider_request`:
  refused registrations; the page's single field; a code in the query; `Origin` before the
  form; the fixed `400`.
- `…::native::confirmed_start_takes_one_bounded_invitation_form_before_any_service_work`,
  through Axum dispatch: metadata refusals with no body sent, a stalled form, forms that
  reach the service with one reply, and a budget spent by admitted requests only.
- `…::native::native_http_refusals_do_not_checkout_or_exchange`: back-channel refusals.

Reordering the form before `Origin`, treating a malformed form as no code, admitting the
field in the query, naming the submit button, removing the read timeout, admitting every
body profile, ignoring the attempt at exchange and changing either stored layout each make
one of these tests fail. This was checked by mutation.

PostgreSQL and Chrome, in CI only:

- `…::native::first_native_sign_in_needs_the_invitation_code_entered_in_the_confirmation_form`
  runs complete sign-ins through two replicas. Uninvited, no code, an empty field, a code
  that differs in one bit, another pending invitation's code and an unassigned code are
  each refused with the same reply, spend their login and leave every invitation pending.
  The correct code creates the account. Afterwards the spent code, a wrong code, the other
  invitation's code and no code all sign in to that one account, the other invitation stays
  pending, and a disabled account stays refused.
- `…::native::redemption_admits_exactly_the_managed_and_native_binding_layouts` calls the
  function with the correct code and thirteen stored bindings. Two redeem. The others differ
  from them in one respect each: epoch, revision, domain, a missing or extra attempt, an
  attempt of 31 or 33 bytes, a mislabelled attempt length, a trailing byte and a missing
  byte.
- `…::native::two_replicas_deliver_once_with_exact_pkce_registration_and_channel`,
  `grant_expiry_withdrawal_disablement_and_retirement_prevent_delivery` and
  `handoff_cannot_outlive_remaining_assertion_age_on_another_replica`: delivery, races,
  wrong bindings, expiry and authority changes.
- Schema suite: `migration_14_keeps_the_redemption_contract_and_gates_the_native_grants`,
  and a populated upgrade from the authentic schema-13 release, which then refuses the
  newer schema for the native grants alone.
- Chrome: `cross_site_native_code_delivery` submits the confirmation form with its field
  left empty and redeems the code from an independent HTTPS client.

Not claimed: the PostgreSQL and Chrome cases were compiled and listed locally, not run. No
real provider, ingress, image, cluster, device or rollout was exercised.

## Compatibility

- **Migrations.** Migration 14. Migrations 1–13 are unchanged.
- **Public Rust items.** New: `browser_auth::native::{NativeAuth, Redemption}`.
- **HTTP.** New unmounted routes only. Browser routes behave as before.
- **Unchanged.** Dependencies, Cargo features, the lockfile, the auth settings document, the
  OpenAPI contract and the process contract.

## Remaining

- Review corrections that follow this change: stricter callback and app-link validation,
  and binding a delivered bearer's validation and logout to its stored audience.
- A settings-document form for the native registration, and runtime construction.
- Simulator qualification in the companion app project: the system browser, not an embedded
  web view; operating-system delivery of the link to the registered app; state and issuer
  checks; secure storage; and a second installed registration that cannot use the bearer.
  Production app links stay HTTPS only, and device ownership of an HTTPS link needs its own
  qualification.
- The gates of ADRs 0017–0022 that also apply here: ingress limits and log redaction,
  operated cleanup, and telemetry that never records a code. #5 stays open.
