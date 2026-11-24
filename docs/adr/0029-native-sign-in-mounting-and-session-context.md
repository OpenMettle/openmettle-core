# 0029 — Native sign-in profile, runtime mounting and session authorization context

Status: accepted with its implementation; V1-04/V1-05 implementation contract, 20 November 2026. Agent-authored; owner
approval, independent review and CI acceptance are separate gates. Refs #5; Refs #6;
Refs #34. #5 and #6 remain open.

## Problem

ADR 0023 built `NativeAuth` and its router but left two items open: a settings-document form
for the native registration and runtime construction. ADR 0025 mounted the browser routes
only. Its settings were checked in `NativeAuth::new` and `NativeAuth::router` alone, so
`--check-auth-config` could not judge them. `NativeAuth::router` also consumed the service,
so a caller could not keep it to validate bearers elsewhere.

Separately, `authz::store::hydrate_api_principal` and `AuditContext` (ADR 0027) need the
session's approval UUID and a primary-database time. Session validation already locks and
checks that approval at a primary-clock instant, but `sessions::Context` discarded both.

## Decision

### Optional `native` profile in version 2

The document version stays 2. A version-2 document may carry one optional `native` object.

```json
"native": {
  "provider_id": "0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f",
  "issuer": "https://app.example.test",
  "callback": "https://app.example.test/auth/native/callback",
  "client_id": "openmettle-desktop",
  "redirect_uri": "https://app.example.test/native/complete",
  "rate": {"burst": 20, "interval_milliseconds": 500},
  "max_in_flight": 64
}
```

- **Shape.** Absent is no profile. A present member must be an object; `null` or another type
  is `Field`. All seven members and both rate members are required. Unknown, missing,
  repeated or mistyped members are refused exactly as in the browser profile. An integer
  larger than `u32` saturates and is refused by the range check, never clamped into
  acceptance.
- **Version 1** does not read the member, so a present `native` is `UnknownField`. Every
  existing version-1 and version-2 document has the same outcome as before.
- **Validated state.** `AuthConfig::native()` returns a `NativeProfile` (`Debug`:
  `NativeProfile(..)`) with `settings()` (`browser_auth::native::Settings`, `Debug`:
  `NativeSettings(..)`) and `rate()`.

### One settings check

`browser_auth::native::check` judges every setting that `NativeAuth::new` and
`NativeAuth::router_shared` need, against the configured providers and the checked browser
profile. It needs no pool, service, async runtime, listener or network, so the loader and
the constructors run the same rules, as ADR 0020 does for the browser profile. The first
refusal ends the check, in this order:

| Order | `SettingsError` | Display | Rule |
| --- | --- | --- | --- |
| 1 | `Provider` | `native provider is not configured` | Exact configured provider UUID (no case folding), and its registration binding can be stored |
| 2 | `Issuer` | `native issuer is not a canonical HTTPS origin` | Canonical HTTPS origin of at most 2048 bytes |
| 3 | `Callback` | `native callback is not a plain HTTPS path on the issuer origin` | Exact HTTPS link: canonical, no credentials, query or fragment, a plain non-root path not starting `//`, at most 2048 bytes, on the issuer origin |
| 4 | `Client` | `native client identifier is not acceptable` | 1–128 bytes of ASCII letters, digits, `-`, `.` or `_` |
| 5 | `Redirect` | `native app link is not a canonical HTTPS URL` | Exact HTTPS link, as for the callback, on any origin |
| 6 | `Route` | `native callback path is not a plain literal path` | The callback path passes the router's path rules (at most 256 bytes, no empty or dot segment) |
| 6 | `Collision` | `native routes or app link collide with another route` | See below |
| 7 | `Rate` | `native rate is outside its allowed range` | Burst 1–65 536 and interval 1 ms–3 600 000 ms, the browser router's bounds |
| 8 | `InFlight` | `native in-flight cap is outside its allowed range` | 1–1024 |

Collisions. The five native paths (`/auth/native/authorize`, `/auth/native/token`,
`/auth/native/session`, `/auth/native/logout` and the callback path) are distinct and are
not `/healthz` or `/readyz`. On the issuer origin they also avoid every browser path
(initiation, session check, logout and landing) when the browser origin is the issuer, and
every configured provider's registered callback path on that origin. The app link is not
any configured provider's registered callback, not a native or operational path when it is
on the issuer, and not a browser or operational path when it is on the browser origin.
These are the rules `NativeAuth::new` applied before.

One rule is new. The API serves both route sets from one Axum router, which matches paths
without the host, so a repeated path would make `Router::merge` panic. A native path
therefore never equals a mounted browser route on any origin: the initiation, session
check and logout paths and the selected provider's callback path. The landing is not a
route, so only a shared origin protects it.

A refusal is `auth_config::Error::Native(SettingsError)`. Its `Display` is
`native profile refused: ` followed by the table's text. No variant, line, `Display` or
`Debug` carries a path, URL, origin, UUID, client identifier or other value. The loader judges
the browser profile first and the native profile last, so earlier refusals keep their
order. `openmettle-api --check-auth-config PATH` therefore checks the native profile offline.

`NativeAuth::new` keeps its signature and delegates to the same check without a rate; every
refusal is still `sessions::Error::Configuration`. The crate-internal `NativeAuth::checked`
returns the category and also checks the rate.

### Runtime mounting

When `OPENMETTLE_API_AUTH_CONFIG` names a version-2 document, `app()` mounts the browser
routes as in ADR 0025. If the document has a native profile it then builds `NativeAuth` on
the same `Arc<BrowserAuth>`, so one provider manager and the primary pool serve both, and
merges the five native routes. Otherwise nothing changes:

- Unset: `/healthz` and `/readyz` only; every `/auth/` path, including `/auth/native/*`, is
  `404`.
- A version-2 document without `native` mounts the browser routes only.
- A refused native profile exits 78 with
  `auth configuration error: native profile refused: ...` before telemetry or the listener.
  There is no partial mount.
- The worker never reads `AUTH_CONFIG` and answers `404` on every native path. The
  migrator is unchanged.
- Readiness stays one database query.

`NativeAuth::router_shared(self: &Arc<Self>, rate)` builds the router over a shared service
that the caller may keep, for example for later `/v1/*` bearer validation.
`NativeAuth::router(self, rate)` wraps it. The router's request slots number the configured
in-flight cap. Each route and accepted method has its own budget at `rate`, as in ADR 0023.

`telemetry::observe` wraps the merged router, so native requests get server-generated
request IDs, the allowlisted `http.request.completed` event, a request span and the
`auth` route class, as for the browser routes (ADRs 0024 and 0028). No query, cookie,
header, body, code or bearer is recorded.

### Session authorization context

`sessions::validate_inner` reads `s.approval_id` in the same post-lock statement that checks
the approval is active and unexpired at the primary-clock `timestamp`. `sessions::Context`
keeps both:

- `approval_id()`: the approval the session was issued under.
- `observed_ms()`: the primary database's Unix-millisecond clock when eligibility was
  observed, inside the session's `[created_ms, expires_ms)` window.

Browser and native validation both fill them. A caller passes `user_id()`, `approval_id()`
and `observed_ms()` straight to `authz::store::hydrate_api_principal`. The `Debug` output is
still `SessionContext(..)`. The context remains an observation, not a capability: hydration
re-reads authority in its own statement.

## Limits

- All exposure gates of ADRs 0023 and 0025 still apply: TLS and ingress for the issuer,
  path preservation, access-log redaction and transport limits. Setting a native profile
  exposes the native routes to whatever can reach the API port.
- Budgets and in-flight caps are per process, and the native cap is separate from the
  browser cap. Both use the same pool, bounded by `DB_MAX_CONNECTIONS`.
- `http.route` carries the operator-configured callback path, a bounded literal.
- No device, simulator, real provider, image or cluster was exercised.

## Compatibility

- No version change. Version-1 documents and version-2 documents without `native` have the
  same outcomes. `NativeAuth::new`, `NativeAuth::router` and `sessions::Context`'s existing
  accessors are unchanged.
- **Behaviour change:** an API whose document contains a valid `native` member now mounts
  the native routes. Such a document was refused before.
- **Behaviour change:** with a browser profile, `NativeAuth::new` now also refuses a native
  path equal to a mounted browser route on another origin (`Configuration`, as before).
- New public items: `auth_config::{NativeProfile, AuthConfig::native, Error::Native}`,
  `browser_auth::native::{Settings, SettingsError, MAX_IN_FLIGHT}`,
  `NativeAuth::router_shared`, `sessions::Context::{approval_id, observed_ms}` and `Debug`
  for `NativeAuth`.
- No dependency, Cargo feature, lockfile, migration, OpenAPI, telemetry contract, process
  contract or CI workflow change.

## Evidence

- `auth_config::tests::native_*`: optional shape, strictness, every category in order with
  controls, value-free diagnostics, and identical outcomes from the loader,
  `NativeAuth::checked`, `NativeAuth::new` and `router_shared`.
- `tests::native_profile_mounts_the_native_routes_beside_the_browser_routes` and
  `tests::refused_native_profile_mounts_nothing`: in-process mounting under production
  telemetry, with no pool connection on preview or refusal and no planted value in events.
- `tests/runtime.rs`: `--check-auth-config` accepts the profile and prints each category;
  the API mounts both route sets, refuses a bad profile with exit 78 before listening; the
  worker ignores it; `postgres_mounted_session_routes_use_the_primary_database` (ignored,
  CI PostgreSQL 18) checks the mounted native session and logout routes against
  `openmettle_api`.
- `provider_keys::tests::postgres::sessions::routine_changes_preserve_sessions_and_explicit_revocations_do_not_revive`
  and `...::native::two_replicas_deliver_once_with_exact_pkce_registration_and_channel`
  (ignored, CI PostgreSQL 18): browser and native contexts carry the session's approval and a
  primary instant inside its window, and hydrate an API principal.

Not claimed: the PostgreSQL cases were compiled locally and not run.

## Remaining

Wave 10 `/v1/*` bearer validation and principal hydration on requests; deployment, ingress
and device qualification of the native routes; the companion app's simulator qualification
(ADR 0023); and the other V1-04 and V1-05 gates. #5 and #6 stay open.
