# 0020 — Versioned browser-routing profile

Status: accepted with its implementation; V1-04 implementation contract, 18 November 2026.
Refs #5; Refs #34. Independent review and CI acceptance are separate gates. #5 remains open.

## Problem

ADRs 0017–0019 give the unmounted handoff and router explicit settings with no defaults:
an application origin, a landing path, a provider, route paths, four rate budgets and an
in-flight cap. They are not in the version-1 auth settings document (ADR 0015). A
deployment could not check these values before a runtime used them.

## Decision

Auth settings document **version 2** is every version-1 member unchanged, with `version`
set to `2` and one required `browser` object. The existing offline check validates it:

```sh
openmettle-api --check-auth-config /etc/openmettle/auth/auth.json
```

The arguments, success line, exit codes, file checks, 1 MiB document limit and existing
diagnostic categories are those of ADR 0015. Version 1 keeps its accepted shape and
outcomes.

> [ADR 0025](0025-browser-auth-runtime-mounting.md) adds the consumer: the API mounts the
> profile's routes when `OPENMETTLE_API_AUTH_CONFIG` names the document. Without that
> setting the paragraph below still holds.

**Nothing consumes the profile yet.** The API without arguments and the worker run as
before. They serve `/healthz` and `/readyz` only, load no auth file and answer `404` for
every login and session path. There is no new serve flag, environment variable, live reload
or mounted route.

### Document

The member below is added to the ADR 0015 example. Its provider is registered with the
callback `https://app.example.test/callback`. The values are synthetic and illustrate the
format only. No operational value is recommended or selected.

```json
"browser": {
  "provider_id": "0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f",
  "origin": "https://app.example.test",
  "landing_path": "/home",
  "paths": {
    "initiation": "/auth/login",
    "session_check": "/auth/session",
    "logout": "/auth/logout"
  },
  "rates": {
    "initiation": {"burst": 20, "interval_milliseconds": 500},
    "callback": {"burst": 20, "interval_milliseconds": 500},
    "session_check": {"burst": 120, "interval_milliseconds": 100},
    "logout": {"burst": 20, "interval_milliseconds": 500}
  },
  "max_in_flight": 64
}
```

Every member is required and none has a default. The callback path is not configured here.
It is the path of the selected provider's registered `callback`, as in ADRs 0017 and 0018.

| Field | Rule (existing check) |
| --- | --- |
| `provider_id` | Exactly one configured `providers[].id`; no case folding (handoff) |
| `origin` | Canonical HTTPS origin as browsers send it; the selected provider's callback must be this origin followed by a plain path (handoff) |
| `landing_path` | Plain absolute path on that origin (handoff) |
| `paths.initiation`, `paths.session_check`, `paths.logout` | Plain literal paths of at most 256 bytes. All four paths, including the callback path, differ from each other, from `/healthz` and `/readyz`, and from `/v1` and every path under it, which the application API serves (router; ADR 0027 PR4b) |
| `rates.<route>.burst` | 1–65 536 (router) |
| `rates.<route>.interval_milliseconds` | 1–3 600 000, the router's 1 ms–1 hour (router) |
| `max_in_flight` | 1–4096, shared by all four routes (router) |

The ranges are the router's implementation ceilings, not recommendations. Each budget
applies per API process: replicas do not share budgets (ADR 0018).

### Strictness

Version 2 uses the same duplicate-refusing parser and the same object rules as version 1.
`version` is read first.

- `1` and `2` are supported. Any other value, type or a missing `version` is
  `configuration version is missing or unsupported`.
- A version-1 document with a `browser` member is refused as an unknown field. A version-2
  document without one lacks a required field.
- Each new object refuses unknown, missing, repeated and mistyped members. Integers are
  plain non-negative JSON integers.

### One implementation

The loader adds no route or origin rule of its own. Two crate-internal checks were split out
of the existing constructors:

- `handoff::check(providers, settings)` judges the origin, landing, provider selection and
  callback. `LoginHandoff::new` calls it with the service's providers.
- `router::check(callback_path, settings, sessions)` runs the router's single settings
  validation: paths, collisions, each budget and the in-flight cap. `router` and
  `router_with_sessions` use the same validation before adding any route.

Neither check needs a service, pool, async runtime, listener or network. The loader calls
both after the version-1 settings, key files and providers pass, so the profile is judged
against the registered callback. A burst or cap larger than `u32` saturates and is refused by
the router's range check. No value is clamped into acceptance.

The constructors' outcomes are unchanged. Their existing tests pass without modification.

### Diagnostics

A refused profile writes one fixed line to stderr and exits with 78:
`auth configuration error: browser profile refused: ` followed by the existing category text.

| Category text | Source |
| --- | --- |
| `application origin is not a canonical HTTPS origin` | Handoff |
| `landing is not a plain absolute path` | Handoff |
| `provider is not configured` | Handoff |
| `registered callback is not a plain path on the application origin` | Handoff |
| `login path contains route syntax` | Router |
| `login path is not a plain literal path` | Router |
| `login paths collide` | Router |
| `login rate is outside its allowed range` | Router |
| `login in-flight cap is outside its allowed range` | Router |

The router's texts say "login" for all four routes, as in ADR 0019. The profile is checked
in this order: handoff, then paths, then budgets (initiation, callback, session check,
logout), then the in-flight cap. The first refusal ends the check. Earlier version-1
refusals come first. No path, origin, UUID, URL or value appears in output, `Display` or
`Debug`.

### Validated state

`AuthConfig::browser()` returns the `BrowserProfile` for version 2 and `None` for version 1.
Its `Debug` output is `BrowserProfile(..)`. A caller can clone the profile before moving
`AuthConfig` into `BrowserAuth`. `handoff()`, `router()` and `sessions()` return the settings
for `LoginHandoff::new` and `router_with_sessions`. Both constructors repeat the checks.
The profile holds settings only.

## What a successful check does not establish

All limits in ADR 0015 apply. In addition, the check does not show that:

- ingress terminates TLS for this origin, routes only this origin to the API, preserves
  paths without rewriting, enforces transport limits or redacts targets and cookies;
- the provider's own client registration lists the configured callback;
- browsers send the expected `Origin` and `Sec-Fetch-Site` values or honor `__Host-`
  cookies;
- the budgets suit any load, or replicas share them (they do not);
- the database authority agrees (ADRs 0012–0014).

## Compatibility

- Version-1 documents are accepted and refused exactly as before, and yield no profile.
- **Behaviour change:** a document with `"version": 2` was refused as unsupported and is
  now judged as version 2. A version-1 body labelled `2` reports a missing field.
- `auth_config::VERSION` still identifies version 1. `VERSION_2` identifies the new shape.
  New public items include `BrowserProfile`, `AuthConfig::browser`, `Error::BrowserHandoff`
  and `Error::BrowserRouter`.
- No dependency, Cargo feature, lockfile, migration (1–9 unchanged), process argument, serve
  flag, environment variable, HTTP or OpenAPI contract, image, CI workflow or provenance
  change.

## Evidence

Local, without PostgreSQL, network or provider:

- `cargo test --locked --offline --lib auth_config`: valid version 1 and 2 with the typed
  profile and redacted `Debug`; unsupported versions; the profile refused in version 1 and
  required in version 2; missing and unknown members in all 17 objects (61 required members);
  repeated and mistyped members; provider, origin, callback and landing refusals; path,
  collision, budget and in-flight refusals at and beyond each bound, for every route;
  refusal order; and redaction.
- The same filter tests building a router from the profile returned by the v2 loader.
  It also compares the loader and constructor outcomes for success and all nine settings
  refusal categories. The lazy pool never connects.
- `cargo test --locked --offline --test runtime` runs the built API binary with no
  `OPENMETTLE_*` or `PG*` variables. Versions 1 and 2 succeed while serving settings are
  unusable and the listener address is occupied. Refusals print one fixed line with exit 78.
  The existing health, readiness and login-path `404` tests are unchanged.

Not claimed: no PostgreSQL, browser, real provider, ingress, image, cluster or rollout was
exercised.

## Remaining

> [ADR 0025](0025-browser-auth-runtime-mounting.md) supplies runtime enablement, off by
> default. The other items stand.

> [ADR 0029](0029-native-sign-in-mounting-and-session-context.md) adds an optional `native` member to version 2, judged by the
> native service's own settings check in the same way, and mounts it beside the browser
> routes.

Runtime enablement remains open: startup loading, constructing the service, handoff and
router, and mounting. Deployment and browser qualification, ingress routing and telemetry
redaction, operated cleanup and retired-key reservation reclamation, native handoff,
provisioning, reconciliation and audited recovery also remain. #5 stays open.
