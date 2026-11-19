# Hosted Keycloak 26.8.2 sign-in qualification fixture

V1-04 ([#5](https://github.com/OpenMettle/openmettle-core/issues/5)) fixture for qualifying OpenMettle's unmounted browser login and session lifecycle (`src/browser_auth/`) against a real pinned stock Keycloak 26.8.2 container over HTTPS in CI.

## Scope and boundaries

- **CI qualification only.** This fixture runs on a hosted GitHub Actions runner against an ephemeral PostgreSQL 18 service and a pinned Keycloak 26.8.2 container (`quay.io/keycloak/keycloak@sha256:c68e286cacd87b942ac1939a0a1481461109d6acd3a57dc496969a319a76bbf0`). It is not a deployment template, Helm package or owner configuration.
- **Routes served by the test.** The qualification test loads the generated version-2 auth settings through `openmettle_core::auth_config::load` and serves `BrowserAuth` / `LoginHandoff` / `router_with_sessions` in-process on loopback HTTPS. The `openmettle-api` binary is not exercised: it mounts these routes only when `OPENMETTLE_API_AUTH_CONFIG` is set (ADR 0025) and serves `/healthz` and `/readyz` only by default.
- **No weakening of TLS or production defaults.** Keycloak serves HTTPS only (`--http-enabled=false`) with a per-run certificate signed by a per-run test CA (`provider-ca.pem`). OpenMettle's `ProviderTransport` (via `trust.roots = "bundle"`) and `fixture.py` trust only `provider-ca.pem`; headless Chrome adds the run's test CAs as its only added trust in its private NSS database and blocks all other hosts via `--host-resolver-rules`.

## How the fixture works

`fixture.py` exposes three commands over a private per-run directory (`0700`):

1. `fixture.py prepare --directory DIR`
   - Creates `DIR` (`0700`) and two bind-mount subdirectories (`provider/`, `import/`, mode `0755`).
   - Generates a per-run 2048-bit RSA test CA (`provider-ca.pem`) and a leaf certificate for `DNS:keycloak.provider.test` (`provider/tls-certificate.pem`, `provider/tls-key.pem`, mode `0644`), then deletes the CA private key and CSR.
   - Generates random per-run passwords for two synthetic users (`synthetic-approved` and `synthetic-invited`), writes the realm import (`import/realm.json`) and private account file (`accounts.json`, mode `0600`), and writes a random 32-byte login key (`login-key.bin`, mode `0600`).
2. `fixture.py settings --directory DIR --address IP`
   - Validates `IP` is a canonical private RFC 1918 IPv4 address (the provider container's IP on the `--internal` Docker bridge network).
   - Writes a version-2 auth settings document (`auth-settings.json`, mode `0600`) with `provider_refresh.uncacheable_reuse_seconds = 300`, `cooldown_seconds = 60`, `freshness_seconds = 3600`, `private_cidrs = ["<IP>/32"]`, and `trust = {"roots": "bundle", "bundle_path": "<DIR>/provider-ca.pem"}`.
   - Checked offline with `openmettle-api --check-auth-config DIR/auth-settings.json` before starting the browser test.
3. `fixture.py wait --directory DIR`
   - Polls `https://keycloak.provider.test:8443/realms/openmettle-qualification/.well-known/openid-configuration` over HTTPS verified solely against `provider-ca.pem` until Keycloak serves discovery matching the expected issuer and endpoints. Fails immediately on certificate or realm mismatch.

## Realm and client settings

The imported realm (`openmettle-qualification`) configures:

- `sslRequired: "all"`, `registrationAllowed: false`
- One **public** OpenID Connect client (`openmettle-browser`) with standard authorization code flow only (`implicitFlowEnabled: false`, `directAccessGrantsEnabled: false`, `serviceAccountsEnabled: false`, `consentRequired: false`)
- Exact redirect URI `https://app.relying.test:18443/callback` (`webOrigins: []`)
- Required PKCE `S256` (`pkce.code.challenge.method = "S256"`)
- RFC 9207 `iss` authorization response parameter enabled (`exclude.issuer.from.auth.response = "false"`)
- Two synthetic users whose UUIDs become their ID-token `sub` claims:
  - `synthetic-approved` (`00000000-0000-4000-8000-0000000000a1`): seeded and approved via `docs/operator/first-identity-approval.psql` (ADR 0013)
  - `synthetic-invited` (`00000000-0000-4000-8000-0000000000b2`): no pre-existing account; redeems a single-use home invitation code created via `docs/operator/home-invitation-create.psql` (ADR 0022)

## Phase output and redaction

Neither `fixture.py`, `tests/browser/keycloak.py`, nor the Rust test prints passwords, login keys, invitation codes, authorization codes, ID tokens, cookies or raw provider responses. Every failure is reported by a fixed phase name or fixed refusal line. The CI container runs with `--network <internal>` (no egress) and `--log-driver none`.

## Local offline checks

```sh
python3 -m unittest discover -s tests/keycloak -v
python3 -m unittest discover -s tests/browser -v
```
