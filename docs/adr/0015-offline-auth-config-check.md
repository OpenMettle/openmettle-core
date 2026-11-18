# 0015 — Offline browser-auth configuration check

Status: coordinator-agreed V1-04 implementation contract, 17 November 2026.
Refs #5; Refs #34. Independent review and CI acceptance are separate gates. #5 remains open.

## Problem

ADRs 0009–0014 each take validated in-memory values and defer "the loader". Nothing read a
file, so a deployment could not learn whether this build would accept its mounted
browser-auth settings before installing them. A mistake would surface only once a later
runtime consumed the settings.

## Decision

`src/auth_config.rs` adds one typed loader, `auth_config::load`, and the API binary gains
one argument form that calls it and exits:

```sh
openmettle-api --check-auth-config /etc/openmettle/auth/auth.json
```

| Outcome | Exit | Output |
| --- | --- | --- |
| Validation succeeds and the success line is written | 0 | stdout: `auth configuration valid (local files only)` |
| Writing the success line fails | 1 | No success line guaranteed |
| A file or value is refused | 78 | stderr: `auth configuration error: ` and one fixed category |
| Any other argument list | 78 | stderr: `usage error: expected no arguments or --check-auth-config PATH` |

Use the exit status to check the result. The check runs before the async runtime starts.
It reads no `OPENMETTLE_*` setting, needs no `DATABASE_URL`, opens no listener and makes no
DNS, HTTP or database request. Native trust follows ADR 0010, including `SSL_CERT_FILE`
and `SSL_CERT_DIR`. The check never creates a file, changes a permission or generates a key.

Starting the API without arguments is unchanged: it serves `/healthz` and `/readyz` and
loads no auth file. **Nothing in the running API consumes these settings yet**, and there is
no live reload. The worker and migrator have no check mode and read none of these files.

Behaviour change: the API binary previously ignored its arguments. It now refuses every
argument list except the exact two-argument form, so a mistyped check cannot fall through to
serving. `--check-auth-config=PATH` is not accepted. The image entry point and the
Kubernetes qualification fixtures pass no arguments.

## Document

> [ADR 0020](0020-browser-routing-profile.md) adds version 2: this shape plus one required
> browser-routing profile. Version 1 below is unchanged and still accepted. Where this
> record says the version must be `1`, read "must be `1` or `2`".

One JSON shape, version 1. The values below are synthetic and illustrate the format only;
no operational value is recommended or selected by this record.

```json
{
  "version": 1,
  "login": {
    "lifetime_seconds": 300,
    "keys": {
      "active": {"id": "login-b", "path": "/etc/openmettle/auth-keys/login-b"},
      "decrypt_only": [
        {"id": "login-a", "path": "/etc/openmettle/auth-keys/login-a"}
      ]
    }
  },
  "id_token": {"max_issued_at_age_seconds": 300, "future_skew_seconds": 60},
  "provider_refresh": {
    "freshness_seconds": 3600,
    "cooldown_seconds": 60,
    "deadline_milliseconds": 5000,
    "max_providers": 2,
    "max_callers": 32,
    "max_document_gets": 2
  },
  "session": {
    "lifetime_seconds": 28800,
    "retained_per_user": 16,
    "deadline_milliseconds": 5000
  },
  "providers": [
    {
      "id": "0b5c6f4e-2a1d-4c3b-9e8f-7a6b5c4d3e2f",
      "issuer": "https://issuer.example.test/realm",
      "client_id": "synthetic-client",
      "revision": "r1",
      "authorization_endpoint": "https://issuer.example.test/authorize",
      "token_endpoint": "https://issuer.example.test/token",
      "discovery_url": "https://issuer.example.test/realm/.well-known/openid-configuration",
      "jwks_url": "https://issuer.example.test/jwks",
      "callback": "https://app.example.test/callback",
      "destination": "web",
      "private_cidrs": ["10.20.0.0/16"],
      "trust": {"roots": "bundle", "bundle_path": "/etc/openmettle/auth/provider-ca.pem"}
    }
  ]
}
```

Every field is required and none has a default. Units are part of the field name. The loader
adds no bound of its own to these values; each is judged by the existing constructor:

| Field | Constructor | Existing implementation bounds |
| --- | --- | --- |
| `login.lifetime_seconds` | ADR 0009 lifetime, now `login::MIN_`/`MAX_LOGIN_LIFETIME` | 1–600 |
| `id_token.max_issued_at_age_seconds` | `auth::Policy::new` | 1–3600 |
| `id_token.future_skew_seconds` | `auth::Policy::new` | 0–300 and below the age |
| `provider_refresh.freshness_seconds` | `RefreshPolicy::new` | 1–86 400 |
| `provider_refresh.cooldown_seconds` | `RefreshPolicy::new` | 1–3600 |
| `provider_refresh.deadline_milliseconds` | `RefreshPolicy::new` | 10–60 000 |
| `provider_refresh.max_providers` | `RefreshPolicy::new` | 1–64 |
| `provider_refresh.max_callers` | `RefreshPolicy::new` | 1–1024 |
| `provider_refresh.max_document_gets` | `RefreshPolicy::new` | 1–64 |
| `session.lifetime_seconds` | `sessions::Policy::new` | 1–86 400 |
| `session.retained_per_user` | `sessions::Policy::new` | 1–1024 |
| `session.deadline_milliseconds` | `sessions::Policy::new` | 10–60 000 |

These remain resource ceilings, not recommendations (ADRs 0008, 0011, 0013). No rate policy
is introduced.

`providers` holds at least one entry. Each `id` is a canonical lowercase UUID, unique within
the document. Each entry passes through `ProviderIdentity::new`, `ProviderConfig::new` and
`ProviderManager::register`, so the exact issuer and client rules (ADR 0008), HTTPS endpoint,
callback, revision and destination rules (ADRs 0009–0011), the private-CIDR allowlist and
trust-anchor rules (ADR 0010) and the 12 KiB binding bound (ADR 0011) are unchanged and live
in one place. The loader checks the provider count against `max_providers` before reading
key or bundle files. Registration uses the same capacity.
`trust.roots` is `"native"` (no other member) or `"bundle"` with one `bundle_path`. A bundle
replaces the native roots, as before. The file lists enabled providers only; retirement is a
database authority change (ADR 0012).

### Strictness

- The loader applies a 1 MiB limit to the serialized JSON before parsing, including
  whitespace and escaped characters. The provider count and binding limits also apply.
- A repeated member name is refused at every depth, known or not, using the duplicate-refusing
  parser that ADR 0011 already applies to provider documents.
- `version` is checked first, so a later version is reported as unsupported, not as unknown
  fields.
- Every object refuses unknown and missing members. Objects are JSON objects only, and
  integers are plain non-negative JSON integers: fractions, exponents, strings and `null`
  are refused.

Derived Serde structs are deliberately not used for this document. With `serde_json` they
also accept a positional array in place of an object and `null` for optional fields, which
would give the configuration more than one accepted shape. The loader walks the parsed value
with a small private helper instead. No dependency or generic configuration framework is
added.

## Files

Every path, including the command-line `PATH`, must be absolute. Each file is read once:

1. `stat` through symbolic links. The target must be a regular file no longer than its limit.
   A directory, FIFO, socket or device is refused here and is **never opened**.
2. Open, then check type and length again on the opened handle.
3. Read at most the limit plus one byte, and refuse a longer result.

| File | Limit |
| --- | --- |
| Configuration document | 1 MiB |
| Login key | exactly 32 raw bytes: no text encoding or trailing newline |
| Trust bundle | 1 MiB, the existing transport ceiling; contents are judged by ADR 0010 |

Following symbolic links keeps Kubernetes projected-volume entries usable (`name` →
`..data/name`). A dangling link or one that resolves to a non-regular file is refused.

Keys are loaded in a fixed order: the `active` key first, then `decrypt_only` in document
order. At most three decrypt-only keys are accepted, and that count is checked before any
key file is read. `KeyRing::new` then applies its existing identifier, repeated-identifier
and repeated-material checks.

The document has no member that can carry key material, and unknown members are refused, so
secrets cannot be inlined. No secret is read from the environment.

### Filesystem expectations and limits

The loader does **not** inspect file ownership or mode. A non-root API process normally
reads Secret volumes owned by another user, so an ownership test would refuse valid mounts.
The deployment must therefore provide all of the following:

- the document, key and bundle directories, and every directory above them, are writable
  only by the deployment authority;
- the mounts are read-only in the API container;
- key files come from a secret store, not from a ConfigMap or the image.

The checks narrow obvious mistakes. They are not a defence against a hostile local writer:
a file replaced between the first check and the open can still be opened, and opening a
FIFO substituted at that moment can block. Key bytes are not zeroized (as in ADR 0009).

## Diagnostics

Each refusal is one fixed line. No path, URL, identifier, key byte, configuration value,
parser message or filesystem error appears in the output, in `Error`'s `Display` and `Debug`,
or in `AuthConfig`'s `Debug`.

| Category text | Cause |
| --- | --- |
| a path is not absolute | The argument or a referenced path is relative |
| configuration is not a readable regular file within bounds | Missing, unreadable, non-regular or over 1 MiB |
| configuration is not valid JSON | Syntax, encoding, trailing data or nesting depth |
| configuration repeats a field | A repeated member name at any depth |
| configuration version is missing or unsupported | Root is not an object, or `version` is not `1` (or `2`, ADR 0020) |
| configuration lacks a required field | Any absent member |
| configuration has an unknown field | Any extra member |
| a configuration field has the wrong type or keyword | Wrong JSON type, non-integer number, unknown `roots` |
| login lifetime is out of range | ADR 0009 bounds |
| ID-token age or skew is out of range | `auth::Policy::new` |
| provider refresh policy is out of range | `RefreshPolicy::new` |
| session policy is out of range | `sessions::Policy::new` |
| a login key is not a readable regular file of exactly 32 bytes | Key file checks above |
| login key count, identifiers or material are not acceptable | More than three decrypt-only keys, or `KeyRing::new` |
| provider count is outside the configured capacity | No provider, or more than `max_providers` |
| a provider identity is invalid | `ProviderIdentity::new` |
| provider identifiers are not unique | A repeated provider UUID |
| a trust bundle is not a readable regular file within bounds | Bundle file checks above |
| a provider definition, endpoint, trust or address policy is invalid | `ProviderConfig::new` or registration |

The whole shape is checked before any policy is evaluated or any other file is read. The
first refusal ends the check; later problems are not listed.

## Validated state

`load` returns an `AuthConfig` only when everything passed: the `KeyRing`, login lifetime,
ID-token and session policies, one `ProviderManager` and one `ManagedProvider` handle per
provider in document order. A refusal returns no partial state. A later runtime is expected
to call `load` once at startup and keep that manager for the process lifetime, as ADR 0011
requires. This increment does not do so.

## What a successful check does not establish

The check validates local files against this build. It does not show that:

- a provider is reachable, resolves to permitted addresses, presents a certificate under the
  configured roots, or publishes metadata that matches the configured endpoints;
- the database authority agrees. `revision` must equal the latest non-retired revision
  recorded for that provider (ADRs 0012 and 0013). Durable epochs and revisions remain the
  authority: a locally valid file with a retired or different revision still refuses every
  login, and an unset admission limit (ADR 0014) still refuses every initiation;
- replicas agree. The database stores revisions, not configuration, and does not detect
  drift. Keep the document, keys and bundles identical on every replica for a revision;
- key identifiers and material are exclusive to this purpose and were never used before.
  `KeyRing` can compare only the keys in one ring;
- another host would accept the same files. With `"roots": "native"` the result depends on
  the platform roots, including `SSL_CERT_FILE` and `SSL_CERT_DIR`, of the machine running
  the check. Run it in the API image with the mounts and environment the API will use.

## Rotation and restore

These are deployment procedures. The check validates each step's files; it cannot show that
a step was performed on every replica or in the database.

**Login key rotation** (ADR 0009). Never reuse an identifier or key material.

1. Add the new key under a new identifier to `decrypt_only`, and roll that out to every
   replica.
2. Make the new key `active` and move the previous active key to `decrypt_only`. Roll out.
3. After the maximum login lifetime plus the rollout overlap, remove the old key.

**Provider configuration change** (ADRs 0012 and 0013). Choose a new `revision`, append it
with the owner write protocol, and roll the changed document out. Replicas whose revision
differs from the current database row refuse logins during the rollout. Replacing an issuer
or client registration needs a new provider UUID.

**After a database restore**, the requirements of ADRs 0009 and 0012–0014 are unchanged:
append a fresh epoch for every provider, advance access generations, review the restored
admission limit, and rotate the active login key to a new identifier and new material
before reopening. Never resume restored logins.

## Compatibility

No dependency, Cargo feature, lockfile, migration (1–9 are unchanged), CI gate, image, HTTP
contract or provenance-register change. New public items: the `auth_config` module,
`login::MIN_LOGIN_LIFETIME`, `login::MAX_LOGIN_LIFETIME`, `login::MAX_KEYS` and
`provider_http::MAX_TRUST_BUNDLE_BYTES`. The last four name bounds that already existed
inline; their values and the checks using them are unchanged. The transport test fixture's
synthetic CA moved to its own file unchanged so the process tests can use it.

## Evidence

Loader tests (`cargo test --locked --offline --lib auth_config`) use real files in a per-test
temporary directory and the existing synthetic CA:

- a valid document, the state it yields, redacted `Debug` output and no created file;
- projected-volume symbolic links, links to a directory and dangling links;
- relative paths, directories, missing files and FIFOs for the document, keys and bundle;
- real file lengths: the document at and one byte over 1 MiB, keys of 0, 31, 32, 33, 44 and
  64 bytes, and a bundle at and one byte over the transport ceiling;
- an unknown member and each of the 39 required members removed, in all ten objects;
- repeated members in every object; version, JSON and type refusals, including positional
  arrays;
- each policy bound; key ordering, the four-key limit, repeated identifiers and material;
- provider count against the document's own manager policy, repeated UUIDs, and identity,
  endpoint, CIDR and bundle refusals from the managed constructors.

Process tests (`cargo test --locked --offline --test runtime`) run the built API binary with
inherited `OPENMETTLE_*` and `PG*` variables removed. They cover success with no database
setting, success while serving settings are unusable and the listener address is occupied,
exact one-line redacted refusals with exit 78, malformed invocations, and the unchanged
worker. The existing liveness, readiness, invalid-configuration and bind-failure tests
continue to cover ordinary startup.

Not claimed: native-root loading is not tested (ADR 0010); no provider, DNS, PostgreSQL,
container image, kind cluster or rollout was exercised by these tests. PostgreSQL, image and
kind qualification remain CI-only gates.

## Remaining

#5 stays open. Browser and native handoff, cookies and CSRF, routes, runtime loading of this
state, connection-discard qualification (ADR 0014), request, rate and concurrency controls,
operated cleanup and retired-key reservation reclamation, real-provider qualification,
provisioning, resource authorization (V1-05), group reconciliation and audited recovery
remain downstream.
