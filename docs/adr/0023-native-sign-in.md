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

> [ADR 0029](0029-native-sign-in-mounting-and-session-context.md) adds the settings-document form (`native` in version 2), one
> offline settings check and runtime mounting beside the browser routes, off by default.

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
origin. It also refuses an app link that is:

- a provider callback or one of the native routes;
- `/healthz` or `/readyz` on the deployment origin;
- a browser route, the landing path, `/healthz` or `/readyz` on the configured browser
  origin, whether or not the native deployment shares that origin.

Choose a dedicated app-link path. There is no settings-document form yet: the registration
is programmatic.

Two digests are computed once. Both are SHA-256 over a domain-separated, length-prefixed
encoding.

| Digest | Inputs | Stored in | Used for |
| --- | --- | --- | --- |
| Registration (`openmettle/native-login/1`) | Provider configuration binding, deployment issuer, upstream callback, client ID, app link | `native_handoffs.registration` | Fences a pending code to the exact configuration that issued it |
| Session audience (`openmettle/native-session-audience/1`) | Deployment issuer, client ID, app link, provider UUID and issuer | `native_handoffs.audience` | Binds a delivered bearer's validation and logout to the registration that delivered it |

The two digests change at different times. A router built from any other provider
configuration, including a routine revision, endpoint or transport-trust change, has
another registration digest, and a new provider epoch also fences a pending code. The
audience changes only with the deployment issuer, client ID, app link, provider UUID or
provider issuer. Replicas built from the same inputs share both.

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
   login, exchanges the provider code once and verifies the ID token. The callback parser
   refuses a provider code that is not 1–4096 visible ASCII bytes, before the service is
   called. The browser callback shares that parser and rule. It issues a local
   session only for an eligible identity with a personal scope, or for a first sign-in that
   redeems an invitation. It redirects to the app link with exactly `code`, the app's
   `state` and `iss`, the deployment issuer. The callback sets and deletes no cookie,
   whatever its outcome. The login cookie stays until the login lifetime ends or a later
   start replaces it, so a completed or replayed callback cannot erase the binding of a
   newer overlapping attempt.
5. **Redemption.** The app checks the link, state and issuer against its attempt, then
   sends `POST /auth/native/token` with `Content-Type: application/json`:

   | Member | Value |
   | --- | --- |
   | `grant_type` | `authorization_code` |
   | `iss` | The expected deployment issuer |
   | `client_id`, `redirect_uri` | The exact registration |
   | `code`, `code_verifier` | The returned code and the app's verifier |

   Send the six named members in one JSON object. Success is `200` with `token_type`
   `Bearer` and the opaque `access_token`. A positional array, any other member, a missing
   member, a wrong binding, a second use and an expired code are refused.

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

1. Head bounds, then the method (`403`). Each route accepts only its own methods, and any
   other method is refused here, before a slot is taken or a unit is spent.
2. The body profile, from metadata alone (`413` `native sign-in request body not
   accepted`). Nothing is read and nothing is spent.
3. A request slot (`503`), then one unit of the budget of this route and method (`429`).
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

#### Stored grant lifetime

The stored expiry is what the app redeems against, on any replica. It is the earliest of
four terms and nothing else:

| Term | Reason |
| --- | --- |
| 30 seconds after the final primary-clock read of the issuing transaction | The delivery window |
| The login expiry | The sign-in attempt has ended |
| The session expiry | Nothing remains to deliver |
| The remaining age of the ID token: its expiry and its maximum age | A bearer is never first delivered on a proof that is no longer acceptable |

With ordinary login and session lifetimes the app has the full 30 seconds for the redirect,
the operating system's link delivery, its own launch and the token request. A sign-in that
completes within 30 seconds of its login expiry, or on an ID token within 30 seconds of its
age limit, has a correspondingly shorter window.

Three bounds of the issuing process are deliberately **not** terms of the stored grant:

- the freshness of its signing-key snapshot (ADR 0011), including the reuse window for
  documents that refuse caching;
- the provider HTTP deadline of 10 ms–60 s, which starts before the token request;
- the session operation deadline (ADRs 0013 and 0016).

They must not bound redemption, for these reasons:

- **They belong to one process, not to the grant.** Redemption makes no provider request
  and uses no signing key. It can run on another replica, which has its own snapshot and
  deadlines and cannot evaluate the issuing replica's.
- **They were satisfied when it mattered.** The ID token was verified, and the session
  committed, while all three held. The code delivers that already-issued session. A browser
  session from the same proof is not bounded by them after issuance either (ADR 0013).
- **What must end a pending code is decided from the database at redemption:** the
  registration, the issuing provider epoch, session eligibility and the stored expiry (see
  Bearer). A configuration or trust change that should end pending codes is a provider
  revision or retirement, which fences them. Routine key rotation at the provider ends no
  session that is already issued, and so no pending code.
- **Clipping to them made the window unreachable.** With a 5-second provider deadline and
  1.5 seconds spent in the exchange and issuance, the app had about 3.5 seconds. With the
  default 60-second reuse window, a snapshot has under 5 seconds left for 5 seconds in
  every 60.

#### Release from the issuing process

The issuing process releases a code only before a conservative monotonic deadline. That
deadline is the earliest of:

- the stored expiry, converted to the monotonic clock through each of the two paired
  samples below;
- the process's proof budget: the ID token's remaining age, key freshness, the provider
  HTTP deadline and the session operation deadline.

Issuance fixes the proof budget, and separately the ID token's remaining age, on the
monotonic clock before its first await. It pairs each primary-clock read with a monotonic
sample taken before the query is sent, and discards one millisecond for the floored
result. A late acknowledgement, a lock wait, a rollback or a wall-clock change can
therefore only shorten either lifetime.

The code is held in a value that yields it only through the deadline check. The callback
makes that check immediately before it writes the redirect, and it is the authoritative
one. Issuance also refuses a code whose deadline has passed when it returns. That earlier
refusal is defence in depth: every case it refuses, the callback's check refuses too. A
late callback answers the fixed `403` with no code, cookie or redirect.

A code that misses the release deadline never leaves the process. Its stored grant remains
until its own expiry and cannot be redeemed, because nothing else holds the code.

Redemption matches the code digest, the S256 challenge and the registration, locks the row
and clears the ciphertext under synchronous commit. It converts the remaining grant time
from its own sample in the same way. A second transaction then rechecks session
eligibility, the grant expiry, the audience and that the issuing provider epoch is still
the current one. Concurrent redeemers receive at most one bearer. After an uncertain commit
the app starts a new sign-in.

### Bearer

A native bearer has the same shape as the session cookie value, and its secret digest has a
separate domain (`openmettle/native-session-secret/1`). A browser session therefore never
validates as a bearer, and a bearer never validates as a cookie. Validation and logout also
require a delivered row for the session, so an unredeemed session has no usable credential.

**A bearer works only through the registration that delivered it.** Validation and logout
compare the row's audience with the serving registration's audience, in the same
transaction as the session check. Another native registration on the same database refuses
the bearer with `403` and revokes nothing.

A pending code and a delivered session follow different rules:

| | Fenced by | Kept across |
| --- | --- | --- |
| Pending code | The registration digest and the issuing provider epoch, so every configuration change | Nothing |
| Delivered session | Its audience, and the ADR 0013 rules: explicit revocation, retirement, withdrawal and disablement | Routine provider revisions, approval edits, and key or trust maintenance |

Changing the deployment issuer, client ID, app link, provider UUID or provider issuer
creates a new audience. Bearers of the old audience can then be neither validated nor signed out through
the new registration. They end at expiry, or when the owner revokes or cleans up their
sessions.

Logout needs possession of the bearer and the matching audience, and nothing else. It
records local revocation whatever the current user, approval or provider eligibility, and
makes no provider request.

## Limits

| Budget | Value |
| --- | --- |
| Upstream login | The configured login lifetime of 1–600 seconds and the outstanding-login cap (ADR 0014) |
| Handoff code | At most 30 seconds, clipped only by the login expiry, the session expiry and the ID token's remaining age (Stored grant lifetime) |
| Local session | The existing session policy (ADR 0013). Retained sessions per user include both channels and undelivered sessions |
| HTTP | 1–1024 requests in flight per native router. One rate budget per route and accepted method at the supplied rate, so the confirmation `GET` and the confirmed `POST` on `/auth/native/authorize` spend separately. The token body allows 8192 bytes and 2 seconds. The authorization query allows 4096 bytes. Request heads use the browser router's limits |
| Database | The existing primary pool and session operation deadline |

- **Not mounted.** The routes exist as library code only.
- **A stalled form holds a request slot for up to 2 seconds**, as in ADR 0022.
- **The login cookie has one slot.** A later start replaces the cookie of an earlier
  attempt in the same browser. An earlier attempt whose callback the browser has not yet
  sent can then no longer complete. No callback deletes the cookie: it expires with the
  login lifetime.
- **An old audience cannot sign out.** After a change to the deployment issuer, client ID,
  app link, provider UUID or provider issuer, the bearers of the old audience last until
  expiry or owner cleanup.
- **An unreleased code leaves its row.** A code that misses the release deadline is never
  delivered. Its session and grant rows stay, unredeemable, until expiry and cleanup.
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
- `…::native::native_http_refusals_do_not_checkout_or_exchange`: back-channel refusals,
  including a positional token request, each missing member and a provider code outside
  the syntax rule.
- `auth_config::tests::native_app_links_cannot_target_configured_browser_routes`: app links
  on the browser origin, from a shared and from a separate native origin.
- `…::native::preview_and_start_spend_separate_budgets_and_other_methods_spend_none`: with a
  burst of one, the confirmation `GET` and the confirmed `POST` are both admitted and each
  is then limited; an unsupported method on every route is refused without spending a unit
  or taking a request slot.
- `browser_auth::handoff::tests::redirects_carry_one_protected_cookie_and_stay_out_of_debug_output`:
  a redirect without a cookie carries no `Set-Cookie` and keeps the protected `Location`.
- `sessions::native::tests`: the monotonic conversion discards one millisecond and never
  extends a spent remainder, and a code is not released at or after its deadline.
- `sessions::native::tests::stored_grant_has_exactly_four_clips_and_the_process_deadline_is_not_one`:
  the stored expiry is 30 seconds with 3.5 seconds, one second and nothing left of the
  process budget; each of the four terms clips alone; a spent grant stores nothing.
- `…::release_deadline_takes_the_earlier_sample_and_never_passes_the_process_deadline`: the
  release deadline follows whichever sample is earlier and stops at the process budget
  while the stored grant keeps 30 seconds.
- `…::issuance_refuses_a_code_that_is_past_its_release_deadline`: issuance's own refusal,
  apart from the callback's check.
- `provider_keys::tests::proof_budget_reports_assertion_age_apart_from_key_freshness_and_the_deadline`:
  with two seconds of a ten-second reuse window left, or half a second of the deadline,
  the ID token's remaining age is reported unchanged and only the process budget shrinks.

Reordering the form before `Origin`, treating a malformed form as no code, admitting the
field in the query, naming the submit button, removing the read timeout, admitting every
body profile, ignoring the attempt at exchange and changing either stored layout each make
one of these tests fail. So do admitting any provider code in the callback parser,
admitting a positional token request, and dropping any one of the app-link checks. So do
sharing one budget between the methods of a route, letting an unsupported method reach a
budget, adding a cookie to the cookie-less redirect, keeping the discarded millisecond and
releasing a code at its deadline. So do clipping the stored expiry to the process budget,
dropping the process budget from the release deadline, reporting the process budget as the
ID token's age, and removing either issuance's refusal or the callback's check of a late
code. This was checked by mutation.

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
- `…::native::registrations_isolate_codes_bearers_and_logout_across_revisions`: two
  registrations on one database. Neither redeems the other's code, validates the other's
  bearer or signs it out, before and after routine provider and approval revisions, for a
  disabled user and for a retired provider. A refused foreign logout leaves the bearer
  valid.
- `…::native::overlapping_attempt_keeps_its_binding_cookie_and_completes`: an older callback
  held at its token response completes after a newer start replaced the cookie. It changes
  no cookie, and the newer attempt completes with its own.
- `…::native::grant_expiry_during_final_validation_acknowledgement_releases_no_code`,
  `pending_grant_expiry_alone_refuses_while_session_is_unexpired` and
  `withheld_claim_acknowledgement_releases_once_and_never_retries`: a grant that expires
  while a commit acknowledgement is withheld releases no code and no bearer, although its
  session is unexpired.
- `…::native::slow_exchange_under_the_provider_deadline_leaves_the_app_its_window`: the
  token response takes 1.5 seconds of a 5-second provider deadline. The stored grant is
  the full 30 seconds, and the app redeems after the provider deadline has passed.
- `…::native::short_key_reuse_window_bounds_the_release_and_not_the_stored_grant`: with two
  seconds of a ten-second reuse window left, the stored grant is the full 30 seconds and
  is redeemed after the snapshot has expired. When the final validation's acknowledgement
  is withheld past those two seconds, the callback releases nothing, although every later
  proof check passes and the stored grant is whole.
- `…::native::stored_audience_alone_refuses_a_pending_code_and_its_redemption`: the owner
  changes a grant's stored audience and nothing else. Issuance's final validation then
  releases no code, and a delivered code's redemption claims the grant and releases no
  bearer. The same steps without the change succeed.
- The synthetic provider accepts a token request only with the callback and PKCE challenge
  recorded for that authorization, so a login finished through another registration's
  callback fails at the provider as well.
- Schema suite: `migration_14_keeps_the_redemption_contract_and_gates_the_native_grants`,
  and a populated upgrade from the authentic schema-13 release, which then refuses the
  newer schema for the native grants alone.
- Chrome: `cross_site_native_code_delivery` submits the confirmation form with its field
  left empty and redeems the code from an independent HTTPS client. It records booleans
  only: no `Referer` or `Cookie` reaches the provider authorization page or the app link,
  the callback carries one binding cookie and changes no cookie, no browser session cookie
  is issued, and the back-channel requests carry no `Referer` or `Cookie`.

Not claimed: the PostgreSQL and Chrome cases were compiled and listed locally, not run, and
so were not checked by mutation. No real provider, ingress, image, cluster, device or
rollout was exercised.

## Compatibility

- **Migrations.** Migration 14. Migrations 1–13 are unchanged.
- **Public Rust items.** New: `browser_auth::native::{NativeAuth, Redemption}`.
- **HTTP.** New unmounted routes only. Browser routes behave as before.
- **Unchanged.** Dependencies, Cargo features, the lockfile, the auth settings document, the
  OpenAPI contract and the process contract.

## Remaining

> [ADR 0029](0029-native-sign-in-mounting-and-session-context.md) supplies the settings-document form and runtime construction.
> The other items stand.

- A settings-document form for the native registration, and runtime construction.
- Simulator qualification in the companion app project: the system browser, not an embedded
  web view; operating-system delivery of the link to the registered app; state and issuer
  checks; secure storage; and a second installed registration that cannot use the bearer.
  Production app links stay HTTPS only, and device ownership of an HTTPS link needs its own
  qualification.
- The gates of ADRs 0017–0022 that also apply here: ingress limits and log redaction,
  operated cleanup, and telemetry that never records a code. #5 stays open.
