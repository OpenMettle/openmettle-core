# OpenMettle core

Rust API and worker foundation for OpenMettle. Both processes serve CPU-only health and PostgreSQL readiness endpoints. The worker does not execute jobs yet. A separate one-shot migrate process creates identities, ownership scopes, projects, conversations, a message graph skeleton, branch identities, run/event/operation persistence, artifact revision and storage-accounting persistence, and typed grant assignments with immutable provenance and revision-guarded history. A versioned application API contract is published with generated consumer fixtures, but no `/v1` route serves it. Internal managed login, an owner-configured outstanding-login cap, local identity approval and opaque-session primitives are implemented, with an offline check for mounted browser-auth settings that the running API does not load yet, an internal pooled browser-auth service that no process constructs yet, and an unmounted Axum router for the same-origin browser login handoff, session check and local logout. No product API, upload service, request authentication, per-user authorization or GPU orchestration is exposed. Runtime qualification and deployment acceptance remain separate gates.

## Start here

- [Accepted architecture v1](ARCHITECTURE-v1.md), including service diagrams and all 43 delivery tickets.
- [Repository boundaries](REPOSITORIES.md), [decisions](DECISIONS.md) and [provenance](UPSTREAM.md).
- [Live delivery tracker](https://github.com/orgs/OpenMettle/projects/1/views/1?filterQuery=%5BV1-00%5D&pane=issue&itemId=307308630).

## Development

Install Rust through the [official rustup installer](https://rustup.rs/). The repository pins Rust 1.100.0 with rustfmt and Clippy; Cargo installs the selected components through rustup when required. Python 3.10+ runs the repository check.

```sh
python3 scripts/check_repository.py
python3 scripts/contract_fixtures.py --check
python3 -m unittest discover -s scripts/tests
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
```

API and worker share operational code and build independently with `cargo build --locked --bin openmettle-api` and `cargo build --locked --bin openmettle-worker`. After `cargo fetch --locked`, add `--offline` to build, Clippy and test commands. Locked resolution and digest-pinned images constrain inputs; they do not prove bit-for-bit reproducibility.

### CI caching

The Rust runtime job restores Cargo downloads and `target/` build outputs before
running the normal checks. Every format, lint, build, unit test and PostgreSQL
integration command still runs; a cache hit never substitutes for a test result.
Keys separate operating systems and architectures and include the toolchain,
Cargo manifests/lockfiles, Cargo configuration and workflow. Each commit can save
an updated build cache while restoring a compatible earlier entry. Cargo decides
which outputs need rebuilding. Incremental compiler state is excluded.

Only successful pushes to `main` save caches. Pull requests restore them without
writing. A miss rebuilds normally with `cargo fetch --locked`; subsequent checks
remain locked and offline. Do not add credentials, database data, kubeconfigs or
qualification reports to the cached paths. The pinned GitHub `actions/cache` v5
restore/save actions are MIT-licensed CI tooling (see `provenance/register.json`).

For a cold verification run, dispatch **CI** with **use_cache** disabled. To
invalidate the shared cache namespace, increment `cargo-v1` in both key prefixes.
Compare the Rust job's restore, compile/test and save durations on cold and warm
runs before claiming a speed improvement. Cache storage and transfer overhead
must remain worthwhile as the workspace grows. This cache does not accelerate
the separate Docker image or kind build jobs; those need BuildKit layer caching.

## Runtime

Read [runtime ADR 0002](docs/adr/0002-cpu-runtime.md) for dependency origins, licences, configuration bounds and shutdown behavior. Supply each process's database URI through deployment-managed environment configuration. Do not commit credentials. For an isolated local test database only:

```sh
export OPENMETTLE_API_DATABASE_URL='postgres://fixture:fixture@127.0.0.1:5432/fixture?sslmode=disable'
cargo run --locked --bin openmettle-api
```

In another terminal, `curl --fail http://127.0.0.1:8080/healthz` returns `ok`. `/readyz` returns `ready` after a successful database query, or HTTP 503 if PostgreSQL is unavailable. Restoring PostgreSQL allows a later probe to succeed without restarting the process. The API and worker never create or migrate tables, and readiness does not check the schema version. These endpoints are operational and must not be exposed as a public product API.

The worker uses `OPENMETTLE_WORKER_DATABASE_URL` and port 8081. Every setting is independent: `BIND`, `DATABASE_URL`, `DB_MAX_CONNECTIONS`, `DB_TIMEOUT_MS` and `SHUTDOWN_TIMEOUT_MS` use the corresponding `OPENMETTLE_API_` or `OPENMETTLE_WORKER_` prefix. Defaults bind loopback; containers bind all interfaces unless overridden. Send SIGTERM or SIGINT to drain and stop. Invalid configuration exits 78; runtime failures or shutdown deadline expiry exit 1. Correct configuration and restart after these errors. Database failures affect readiness, not liveness.

Run the real PostgreSQL subprocess test against an isolated test database:

```sh
export TEST_DATABASE_URL='postgres://fixture:fixture@127.0.0.1:5432/fixture?sslmode=disable'
cargo test --locked --test runtime -- --ignored
```

The normal test suite covers configuration rejection, bind failure, database timeout, liveness and shutdown without PostgreSQL. CI separately requires the PostgreSQL tests, builds the API, worker and migrate Docker targets and exercises database loss/recovery and API survival after stopping the worker. Test credentials above are synthetic and must never be used for a deployment.

Build separate images with `docker build --target api -t openmettle-api:test .` and `docker build --target worker -t openmettle-worker:test .`. No images are published by CI. The [process contract fixture](runtime/process-contract.json) supplies separate service-account names, resource request examples and probes for deploy. The [Kubernetes qualification](tests/kubernetes/README.md) workflow runs that contract on an ephemeral kind cluster classified dev. It observes separate ServiceAccounts with token automount disabled, the requested resources, independent process settings, readiness, API survival with the worker scaled to zero, independent scaling and clean shutdown. Its manifests are test fixtures. Resource sizing is unqualified, and generic Helm packaging and RBAC belong to deploy (V1-32).

## Application API contract

[ADR 0007](docs/adr/0007-application-api-contract.md) defines the v1 HTTP/JSON contract in [contracts/](contracts/README.md): one canonical OpenAPI 3.2.1 document, fixtures generated from its examples and offline compatibility checks that need no Flutter client. It specifies errors, pagination, idempotency, run-event SSE items and capabilities with independent installed, authorization and readiness dimensions. Only `GET /v1/capabilities` is described, as an authenticated, unimplemented operation; the running API returns 404 for it. Security schemes are provisional until V1-04. After editing the document, run `python3 scripts/contract_fixtures.py` and commit the regenerated fixtures. `cargo test --test contract` validates the document against the vendored official OpenAPI 3.2 schema, checks every fixture with a JSON Schema 2020-12 validator (a development-only dependency) and decodes fixtures with an independent typed consumer.

The internal evaluator in `src/capabilities.rs` keeps installation, supplied caller decisions and observed readiness separate. Hidden entries are omitted; absent, disabled and non-authorized entries never call the observer. Failures map to a bounded unavailable reason; timeouts remain unknown. No authorization policy or HTTP serialization is implemented. Isolation currently holds because no runtime path calls the evaluator. The ignored runtime suite guards the real PostgreSQL `/readyz` against regression while optional evaluation runs separately in the test harness. CI uses isolated PostgreSQL; the test does not inject providers into the API. The first V1-04/05 handler that hosts an observer must qualify isolation within that process. See ADR 0007 for the acceptance evidence and limits.

## OIDC ID-token verification

[ADR 0008](docs/adr/0008-oidc-id-token-verification.md) adds `src/auth.rs`, an offline verifier for the first V1-04 increment. It uses `openidconnect` to check untrusted ID-token bytes against an explicitly trusted provider (exact HTTPS issuer, client ID and JWKS), an expected nonce and an injected clock. Only RS256 tokens with a single audience pass. A valid token yields only the provider UUID, issuer and subject; failures are fixed categories that never echo token or claim values. The verifier itself has no route, discovery, network access, state/PKCE handling, session, admission or account creation, so it does not authenticate requests. `cargo test --test auth` runs the negative tests offline with in-memory keys.

## Internal browser login transactions

[ADR 0009](docs/adr/0009-protected-login-transactions.md) adds protected PKCE storage,
separately committed AEAD nonce reservations and single-use callback consumption.
An exchange permit owns the callback code and trusted configuration and reaches the
library exchange only after commit acknowledgement. An injected fake transport exercises
code/challenge/client/callback binding. The production transport is described below; there
is no login route.
The nonce verifier accepts stored digests without weakening the existing token checks.

Native handoff and account creation remain unimplemented; the browser cookie handoff below is
not mounted. Key files are read only by the offline check below. Internal local approval and sessions are described below. The outstanding-login
cap below is not a rate limit. The unmounted login router below adds per-process request,
rate and concurrency bounds; public exposure remains blocked on runtime enablement, ingress
transport limits, operated cleanup and retired-key reservation reclamation. After database restore, invalidate pending login transactions and
rotate the active login encryption key before any encryption; never resume restored logins.
These are deployment requirements, not provided recovery commands. Lost/ambiguous logins
restart rather than retrying single-use authorization codes.

## Provider token transport

[ADR 0010](docs/adr/0010-provider-http-transport.md) adds `src/provider_http.rs`, the HTTPS
transport for that exchange. It sends one token `POST` per TLS connection (hyper HTTP/1.1 and
rustls with ring) to an exact configured `https` endpoint. That endpoint must use a DNS host
name. Every DNS answer must pass an address policy before any connection: loopback,
link-local, metadata, IPv6 transition forms and unallocated space are refused. Private
addresses need an explicit per-provider CIDR allowlist. A configured CA bundle replaces the
native roots.

Responses are capped at 32 headers, 8 KiB of header bytes and 64 KiB of body. Ambiguous
framing, compression and trailers are refused. The transport never follows redirects,
retries, pools connections or reads proxy environment variables. Abandoned OS DNS lookups are
the only work that can outlive a dropped request, limited to 8 process-wide slots.

Deployments behind an egress proxy are unsupported. Network policy remains a deployment
control. Managed discovery/JWKS support is described below. Runtime configuration loading and routes
remain unimplemented, and no real provider has been qualified.

## Managed discovery and signing keys

[ADR 0011](docs/adr/0011-managed-provider-keys.md) adds an internal managed login path.
Deployment supplies a keyless identity, exact discovery/JWKS and login endpoints, TLS/egress
configuration, and explicit freshness/cooldown/deadline/capacity policy. A process-owned
`ProviderManager` registers generation-bound handles for preflight, begin, consume,
`ExchangePermit::exchange_with_keys` and `ManagedProvider::release`. Discovery confirms configured destinations; it never
selects URLs. The existing offline APIs and POST-only transport remain available.

Managed exchange sends the authorization code once, then verifies the original ID token with
fresh current keys. A bounded unknown-key refresh can reverify that token once. Valid
replacements retire removed keys, and expired keys never receive outage grace. Both metadata
and keys must remain fresh. The initial profile requires advertised public-client `none`,
S256 and RFC 9207 support, and reusable responses with explicit max-age/Date. These are
compatibility limits, not real-provider qualification. The maintained verifier supports RSA
through 4096 bits; the online document parser's 8192-bit ceiling does not expand that support.

Keep the manager alive across requests. Registering identical configuration is a no-op;
a changed configuration or a retire/restore retains cooldown and invalidates keys. A document
expiring before cooldown ends blocks login until another refresh is allowed. Provider Age,
short cache lifetimes and clock skew can reduce availability; qualify policy values against
actual provider behavior. The offline check below validates configuration files; the running API
does not load them.
The managed provider path itself provides no route, cookie or account creation. Its sealed
proof now has the internal local-approval/session consumer described below. `cargo test --lib provider_keys --locked --offline` exercises isolated TLS,
rotation, cancellation, capacity and freshness behavior without PostgreSQL.

## Login provider authority

[ADR 0012](docs/adr/0012-login-provider-authority.md) makes managed login depend on a durable,
operator-owned authority in migration 7. `openmettle.login_providers` fixes each provider
UUID to its issuer and client; `openmettle.login_provider_revisions` is an append-only log
whose latest epoch per provider is current, with a `NULL` revision meaning retired. Only
`openmettle_owner` writes these tables, using the locked protocol transaction in ADR 0012;
the API can only read them. Stored logins bind the full configuration and that epoch, never a
process counter.

Begin and consume read authority inside their transactions. A managed exchange returns a sealed
result; `ManagedProvider::release` rechecks authority in a fresh read-only transaction before
returning an identity. Retiring or changing a revision therefore refuses pending logins and
in-flight exchanges on every replica at their next authority read. Release linearizes at its
read snapshot; a change committed after that snapshot is ordered after the release. After an
upgrade the tables are empty and managed login fails closed until providers are recorded.

After restoring the database, append the current revision for every provider and rotate the
ADR 0009 login key before reopening. Authority reads must use the primary, and acknowledged
commits must survive failover; lagging standbys and asynchronous failover are unsupported.
The database stores revisions, not full configuration: keep configuration identical across
replicas for the same revision. `cargo test --locked --offline --lib provider_keys::tests::postgres -- --ignored`
runs the managed PostgreSQL tests against an isolated test database only.

## Local identity approval and sessions

[ADR 0013](docs/adr/0013-local-identity-sessions.md) adds internal sessions for already-existing
exact issuer/subject identities with a personal scope and owner-recorded local approval. This
is not invitation delivery or account provisioning. `ManagedProvider::issue_session` consumes
only its sealed online proof; an offline `VerifiedIdentity` cannot mint a session.

Routine configuration/approval revisions preserve sessions. Explicit revoke, provider retirement,
approval withdrawal and user disablement advance access generations; restoration never revives
old sessions. Follow ADR 0013's updated owner write protocol, including the provider lock before
epoch allocation. Validation and logout use the primary database without provider network access.
Session context does not grant resource access; V1-05 checks remain required before exposure.

Credentials are random opaque values; only domain-separated digests are stored. Lifetime,
retained-row allowance and operation deadline are explicit bounded inputs with no deployment
defaults. Issuance must finish before the originating login's existing expiry. A delayed commit
can leave an undisclosed row but never returns a credential after failed final checks. Remove
revoked and expired sessions, then the login gates they referenced, only with the
[session and login-gate cleanup procedure](docs/operator/session-cleanup.md): two exact psql
scripts in separate transactions, each an explicit 1–1000-row batch with `SKIP LOCKED`.
Session cleanup deletes session rows only, so replay markers survive until the gate is
removed. It never purges nonce reservations. No schedule, batch or retention value is
selected, and CI evidence is not approval to run it against a real database.

There are no routes, native handoff, runtime loader, tenant/group qualification or reconciliation; the cookie handoff below is not mounted.
Run the managed PostgreSQL tests only in isolated CI with the explicit module filter above;
normal workspace tests leave them ignored. Migration 8 and authentic v7 compatibility are CI gates.

## Outstanding login admission

[ADR 0014](docs/adr/0014-login-admission.md) adds migration 9: one owner-configured limit on
outstanding login rows (unexpired, no issued session, consumed or not). It is an
outstanding-work cap, not a rate limiter, request/concurrency control or storage bound. The
limit installs as NULL, so **every login initiation is refused until the owner sets it**; 65 536
is an implementation ceiling, not a deployment default. The API can read and lock the row
but not change it.

Initiation first runs an advisory read-only precheck, so unconfigured, full or
stale-authority attempts spend no nonce reservation. It then reserves a nonce as before and
rechecks under an exclusive lock with the primary clock sampled after the wait. Concurrent,
cancelled or refused-after-precheck attempts still spend one permanent reservation each;
reservations keep growing by design. Begin and consume now await rollback on every returned
error so idle connections never keep row or admission locks.

Change the limit only with
[`docs/operator/login-admission-limit.psql`](docs/operator/login-admission-limit.psql)
(compare-and-set; lowering preserves existing rows). Remove expired, unreferenced login gates
with [`docs/operator/login-gate-cleanup.psql`](docs/operator/login-gate-cleanup.psql)
(batch 1–1000, `SKIP LOCKED`; never deletes nonce reservations), as the second step of the
cleanup procedure above. CI runs these scripts unchanged with the pinned PostgreSQL 18
`psql`. No limit, schedule or retention value is selected. Old version-8 replicas do not
enforce the cap during a rolling upgrade.

## Offline browser-auth configuration check

[ADR 0015](docs/adr/0015-offline-auth-config-check.md) adds `src/auth_config.rs`, a typed
loader for mounted browser-auth settings, and one API argument form that runs it and exits:

```sh
openmettle-api --check-auth-config /etc/openmettle/auth/auth.json
```

Use the exit status to check the result. Exit 0 indicates success and writes
`auth configuration valid (local files only)` to stdout. A write error returns 1.
Invalid configuration returns 78 with `auth configuration error:` and one fixed category.
Invalid arguments also return 78. The check needs no `DATABASE_URL`, opens no listener and
makes no DNS, provider or database request. Run it in the API image with the mounts and
environment the API will use before installing changed settings.

Starting the API without arguments is unchanged and loads none of these files. The worker and
migrator never read them. Nothing consumes the settings at runtime yet, and there is no live
reload.

The check reads one JSON document, version 1 or 2, and the files it names. Native trust also
loads platform roots and honors `SSL_CERT_FILE` and `SSL_CERT_DIR` under ADR 0010. ADR 0015
gives the version-1 shape with synthetic values. Version 2 adds one required browser-routing
profile, described below.

- Every setting is required, with its unit in the field name. There are no defaults, and no
  operational value is selected. Unknown, repeated, missing or mistyped fields are refused in
  every object.
- At least one provider, each with a unique canonical UUID, exact issuer and client, revision,
  HTTPS endpoints, callback, destination tag, private CIDRs and either native roots or one PEM
  bundle. The existing constructors (ADRs 0008–0013) judge every value.
- Every path is absolute. Symbolic links are followed, so Kubernetes projected volumes work,
  but each must resolve to a regular file. Directories, FIFOs, sockets and devices are
  refused without being opened.
- Login keys are files of exactly 32 raw bytes: the active key first, then up to three
  decrypt-only keys. Secrets cannot be inlined or supplied through the environment. The check
  never creates a file, changes a permission or generates a key.

File ownership and mode are not inspected. Mount the document, keys and bundles read-only
from directories that only the deployment authority can write. The check does not defend
against a hostile local writer.

A successful check covers local files only. It does not show that a provider is reachable or
that the database agrees: each `revision` must equal the current revision recorded under
ADR 0012, and the ADR 0014 limit must be set. Keep the document, keys and bundles identical
on every replica for a revision. Follow ADR 0015 for login-key rotation, provider revision
changes and the unchanged restore requirements. `cargo test --locked --offline --lib auth_config`
runs the loader tests without PostgreSQL or network access.

### Browser-routing profile (version 2)

[ADR 0020](docs/adr/0020-browser-routing-profile.md) defines version 2: every version-1
member plus one required `browser` object. It selects one configured provider UUID and
sets the canonical HTTPS application origin, the landing path, three literal paths
(initiation, session check and logout), four rate budgets (initiation, callback, session
check and logout, each a burst and `interval_milliseconds`) and one shared `max_in_flight`
cap. The callback path comes from the selected provider's registered callback. Nothing has
a default.

The same checks as the unmounted handoff and router (ADRs 0017–0019) judge these values,
without a database, async runtime, listener or provider request. A refusal is
`auth configuration error: browser profile refused: ` followed by one fixed category. A
version-1 document still passes unchanged and must not contain `browser`. **Nothing
consumes the profile yet.** The API still serves `/healthz` and `/readyz` only, and the
check cannot show that ingress, browsers or the provider registration agree with it.

## Pooled browser-auth service

[ADR 0016](docs/adr/0016-pooled-browser-auth-service.md) adds `src/browser_auth.rs`, one
internal service built from the validated settings above and a handle to the API's existing
primary pool. It starts a login for an exactly configured provider UUID, completes a
callback (committed consumption, one token request, session issuance from the sealed proof)
and validates or logs out local sessions. **No process constructs it**: the API, worker and
migrator are unchanged, `/readyz` checks the database only, and there is no route, native
handoff or rate policy. The service handles no request or cookie itself; the unmounted
adapter below does.

The service holds a pooled connection only while database work runs, never during a
provider document fetch or the token request. Waiting for a connection counts against the
existing deadlines and never extends the login's expiry or the proof's original deadline.
Validation and logout contact no provider.

A connection returns to the pool only after success or an ordinary denial whose COMMIT or
ROLLBACK was acknowledged. After cancellation, a deadline, a panic or a `Database` or
`Timeout` error it is closed and the pool opens a replacement. Nothing is retried; restart
the login after any failure. Limits to plan for before exposure:

- SQLx closes the connection on its own task (at most 5 seconds) and keeps the pool slot
  counted until then.
- Closing the socket does not interrupt PostgreSQL. A cancelled backend can keep row locks
  until its statement ends, normally within the 2-second lock and 3-second statement
  timeouts these transactions set.
- A replacement can briefly coexist with the old backend, so server connections can exceed
  `DB_MAX_CONNECTIONS` for that process. The connection budget below does not include this.

ADR 0016 lists the reuse rules per error category and the evidence. Its PostgreSQL tests run
only in isolated CI, under the existing `provider_keys::tests::postgres` filter. Locally,
`cargo test --locked --offline --lib browser_auth` and
`cargo test --locked --offline --lib provider_keys::tests::service` run the tests that need
no database. Connection churn and capacity under load are unmeasured.

## Browser login handoff

[ADR 0017](docs/adr/0017-browser-login-handoff.md) adds `src/browser_auth/handoff.rs`, an
adapter that turns one browser request into one response over the service above. **It is
not mounted**: no process constructs it, the API still serves `/healthz` and `/readyz` only
and answers `404` for a callback path, and no browser has been qualified.

It takes three explicit settings with no defaults: the canonical HTTPS application origin,
a landing path on that origin and one configured provider UUID. Auth settings version 2
carries them and the offline check applies the adapter's own checks (ADR 0020). The issuer and the exact registered callback
come from that provider. `Host`, forwarded headers, callback fields and return URLs never
select an origin, provider, callback or destination.

- **Initiation** accepts a form `POST` with exactly one `Origin` equal to the application
  origin. It answers `303` to the provider's authorization URL and sets
  `__Host-openmettle-login` (`Secure`, `HttpOnly`, `Path=/`, `SameSite=Lax`, `Max-Age` equal
  to the login lifetime). The page with the form must not use `Referrer-Policy: no-referrer`,
  which makes browsers send `Origin: null`.
- **Callback** accepts a `GET` on the exact registered callback path. It refuses malformed
  escapes, repeated parameters, provider errors, an incomplete response, a missing or
  different `iss` and a missing, repeated or mismatched caller cookie before calling the
  service. Success answers `303` to the landing and sets `__Host-openmettle-session` with
  the same attributes and no `Max-Age`; expiry in the database stays authoritative.
- **Every response** has `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
  Refusals are fixed lines that set and delete no cookie. The landing URL and response
  bodies carry no credential, code, state or caller secret.

A browser holds one caller cookie for the application hostname. If a callback carries
another login's cookie, the transaction named by the callback stays unconsumed and holds its
admission slot until expiry. A callback already sent with its matching cookie can still
finish. A new login replaces the browser's session cookie. The earlier session stays valid
until expiry or revocation.

Before any exposure these remain outstanding: browser qualification; trusted ingress
routing for the application origin and redaction of request targets and cookies in
telemetry; ingress transport limits; operated cleanup and retired-key reservation
reclamation; and runtime enablement. The router below supplies per-process request, rate and
concurrency bounds, and the unmounted session check and logout routes. `cargo test --locked --offline --lib handoff` runs the tests that need no database;
the end-to-end test runs only in isolated CI under the existing
`provider_keys::tests::postgres` filter.

## Bounded browser login router

[ADR 0018](docs/adr/0018-bounded-login-router.md) adds `src/browser_auth/router.rs`, which
builds an Axum router over the handoff above. **It is not mounted**: no process constructs
it, and the API and worker still serve `/healthz` and `/readyz` only.

It routes two exact literal paths: an explicit initiation path for the form `POST`, and the
provider's registered callback path for `GET`. Both are validated before any route is
built. Route syntax, escapes, dot or empty segments, a shared path and `/healthz` or
`/readyz` are refused with fixed categories, never a panic. Any other method, including
`HEAD`, is `405` and reaches no login work.

Every other setting is explicit, with no defaults: a rate budget for initiations, a separate
one for callbacks (burst and refill interval each) and one in-flight cap shared by both
routes. The ranges in ADR 0018 are implementation ceilings, not operating values. Auth
settings version 2 carries these settings, and the offline check runs the router's own
validation (ADR 0020). Requests
are decided in this order, and the first four steps do no provider, pool or database work:

1. Method (`405`).
2. Request bounds measured after HTTP parsing: a target of at most 33 792 bytes (`414`), at
   most 64 header fields and 24 576 header bytes (`431`), and an empty body (`413`). The body
   is judged from its metadata and never read, so a nonzero declared length or chunked body
   is refused without waiting for it. The handoff's query and cookie ceilings still fit and still apply.
3. An in-flight permit, without waiting (`503`, `login busy; try again later`).
4. One unit of the route's rate budget (`429`). A unit is spent here, before the handoff
   decides, and is never refunded. Earlier refusals spend nothing.
5. The handoff, with the original request head. A dropped request releases its permit.

These refusals are fixed lines with `no-store`, `no-referrer`, no cookie and no `Location`.
Mount the router with `Router::merge`, never `Router::nest`, and keep ingress from
rewriting the path.

The bounds hold per router value and its clones in one process. They are not cluster-wide,
fair between clients, durable across restarts or a limit on what the HTTP server reads
while parsing a request head. Deployments still need ingress and server transport limits
before exposure. `cargo test --locked --offline --lib browser_auth::router` and
`cargo test --locked --offline --lib provider_keys::tests::router` run the local tests,
which serve the router on loopback. The PostgreSQL handoff case also completes a login
through the router, in isolated CI only.

## Session check and logout routes

[ADR 0019](docs/adr/0019-session-check-and-logout-routes.md) adds `router_with_sessions`,
which builds the router above plus two explicit literal routes. **They are not mounted**: no
process constructs the router, and the API and worker still answer `404` for every login
and session path. `router` itself is unchanged and still builds only the login routes.

The session and logout paths obey the same shape and collision rules as the login paths.
All four must differ. Each route has its own rate budget (burst and refill interval,
explicit, no defaults), so session polling cannot spend logout or login rate. The in-flight
cap is shared by all four. Requests pass the same method, bound, permit and rate steps
before any service call.

- **Session check** accepts a `GET` with exactly one `Sec-Fetch-Site: same-origin` field.
  The browser must supply this field before the check reads cookies. The check requires
  exactly one `__Host-openmettle-session` cookie. A valid session gets an empty `204` with
  no identity, cookie or redirect. An invalid credential gets `403 session not valid`.
  Operational failures get `503`.
- **Logout** accepts a form `POST` with an empty body and exactly one `Origin` equal to the
  application origin, by the same rule as initiation. Any other `Origin` is `403` before
  the cookie is read. `BrowserAuth::logout` then revokes by possession, with no eligibility
  check, so an issued session can be ended after expiry, disablement or lost approval.
  Only after the commit is acknowledged does the response become `204` with one deletion:
  `__Host-openmettle-session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`.
  Refusals and failures delete nothing. The caller cookie is left alone. Other sessions of
  the same user are not revoked.

Every response has `no-store` and `no-referrer`. Fixed lines carry no request, cookie or
credential value. Repeated logout with the same credential is acknowledged again while the
revoked row is retained. After cleanup removes the row, logout returns `403 session not
valid`. A browser applies `Set-Cookie` in response processing order. A logout deletion can
remove a new cookie set in another tab while that new session stays valid in the database.
ADR 0019 describes these orderings and the per-process budget limits.

Browser qualification, runtime enablement, ingress limits and telemetry redaction remain
outstanding. `cargo test --locked --offline --lib provider_keys::tests::session_routes`
runs the loopback tests. The PostgreSQL case
`provider_keys::tests::postgres::handoff::issued_cookies_validate_and_logout_revokes_without_current_eligibility`
runs only in isolated CI under the existing filter.

## Schema migrations

Read [ADR 0003](docs/adr/0003-schema-migrations.md) for the migration, role and ownership contract and [ADR 0004](docs/adr/0004-run-persistence.md) for run/event/operation persistence, limits and replay semantics, [ADR 0005](docs/adr/0005-artifact-storage-accounting.md) for artifact revisions, storage reservations and byte accounting, and [ADR 0006](docs/adr/0006-grant-persistence.md) for grant provenance, replay and revocation persistence. PostgreSQL 18 is the only qualified major version. Migrations in `migrations/` are embedded in the `openmettle-migrate` binary, forward-only and transactional; released migrations are never edited. Run the migrate image once per release, before rolling out new API and worker versions. Each release's migrations must remain compatible with the previous API and worker.

Provision the roles and one dedicated database before the first migration, using deployment-managed secrets for passwords. Before creating anything, and on every later run, the migrator checks the provisioning and exits 1 with nothing changed if it is unsafe. Log in as `openmettle_owner`, which must own the database. Do not make any of these roles superuser or give them CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS. Keep `openmettle_owner`, `openmettle_api` and `openmettle_worker` out of every other role, including predefined roles such as `pg_read_all_data` and `pg_write_all_data`; this applies to `SET ROLE`-only memberships too. Separate login roles may be members of exactly one of `openmettle_api` or `openmettle_worker` and of nothing else. Do not grant those roles, their logins or `PUBLIC` any database, schema or table privilege yourself, and do not set default privileges for `openmettle_owner`; the migrations grant exactly what [ADR 0003](docs/adr/0003-schema-migrations.md) lists. The error names each violation to fix. Role names are cluster-global: installations sharing a PostgreSQL cluster would share these roles and so each other's database access, which this increment does not isolate. A superuser runs, for example (psql variables):

```sql
CREATE ROLE openmettle_owner LOGIN PASSWORD :'owner_password';
CREATE ROLE openmettle_api LOGIN PASSWORD :'api_password' CONNECTION LIMIT 8;
CREATE ROLE openmettle_worker LOGIN PASSWORD :'worker_password' CONNECTION LIMIT 8;
CREATE DATABASE openmettle OWNER openmettle_owner;
```

Then run the migrator with the owner's URL. It reads `OPENMETTLE_MIGRATE_DATABASE_URL` and optional `OPENMETTLE_MIGRATE_CONNECT_TIMEOUT_MS` (default 5000), `OPENMETTLE_MIGRATE_LOCK_TIMEOUT_MS` (default 15000) and `OPENMETTLE_MIGRATE_STATEMENT_TIMEOUT_MS` (default 300000). It exits 0 on success, 78 on invalid configuration and 1 on any other failure, including a lock wait past its deadline. Concurrent runs are serialized. A failed or interrupted run leaves no partial migration and can be retried immediately. A checksum mismatch or a database newer than the binary is refused. Do not delete history rows or rerun edited files; ship a corrective migration or restore a backup instead.

```sh
export OPENMETTLE_MIGRATE_DATABASE_URL='postgres://openmettle_owner:<password>@127.0.0.1:5432/openmettle?sslmode=disable'
cargo run --locked --bin openmettle-migrate
```

Give the API `openmettle_api` credentials and the worker `openmettle_worker` credentials, never the owner's. These roles bound each process, not each user: both can read every scope's rows. Per-user authorization (V1-05) is required before any product endpoint uses this data.

Storage limits are durable deployment inputs that only `openmettle_owner` sets, in the single `openmettle.storage_instance` row: `instance_budget_bytes` (the logical ceiling left after operational headroom, not measured disk capacity), `personal_limit_bytes` and `project_limit_bytes`. Migrations install them as NULL, which refuses every new storage reservation until the deployment configures them; see [ADR 0005](docs/adr/0005-artifact-storage-accounting.md#limits). Lowering a limit preserves existing data and reservations and refuses only new reservations.

Connection budget: `api_replicas × API DB_MAX_CONNECTIONS + worker_replicas × worker DB_MAX_CONNECTIONS + 1 migrator + admin/backup headroom` must not exceed `max_connections − superuser_reserved_connections − reserved_connections`. Count surge replicas during a rolling update. For example, 2 × 4 + 2 × 4 + 1 + 3 = 20. Enforce each process's share with its login role's `CONNECTION LIMIT`. These figures are illustrative, not qualified sizing.

The schema tests also require `OLD_BINARY_DIR` pointing to binaries built from release `18f52463c9d6bc12dda4bd1558e4597e067018f8` and `V3_BINARY_DIR` pointing to binaries built from release `2f1be947aa933177c2e407cd7290bf9909bd08ca`; CI builds those exact archives for compatibility checks. Set `V4_BINARY_DIR` to binaries built from `d80e37819f847072dfa272bdddcc1fbee6d622ef` for migration 5 compatibility; CI builds that archive too. Set `V5_BINARY_DIR` to authentic binaries from `4a51242839e16e1d7b8ad3538887bf8e41081e6e` for migration 6 compatibility, and `V6_BINARY_DIR` to authentic binaries from `3978dff2864488bbdd9e748afd7116f39683f129` for migration 7 compatibility. `V7_BINARY_DIR` (`5ff1d2a8ed5e7424be006e78c16f0c30e784336d`) and `V8_BINARY_DIR` (`e55aff07527ad6452f8a0d49953b3fc2ffc51352`) cover migrations 8 and 9. The ADR 0014 operator-script tests also need `POSTGRES_CONTAINER`, the isolated CI PostgreSQL service container whose `psql` runs them. Do not substitute the current binary with a truncated migration list.

The schema tests need a superuser on an isolated, disposable PostgreSQL 18 service. They create synthetic `openmettle_*` cluster roles with a test-only password and one database per test. Never point them at a shared server.

```sh
export TEST_DATABASE_URL='postgres://fixture:fixture@127.0.0.1:5432/fixture?sslmode=disable'
cargo test --locked --test schema -- --ignored
```

Build the migrate image with `docker build --target migrate -t openmettle-migrate:test .`; it runs as the same non-root user as the other images. Deploy (V1-32) owns the Kubernetes Job or hook, production role provisioning and secrets.

## Ownership

V1-02 owns schema/migrations (run/event/operation, artifact/reservation/accounting and grant persistence are implemented; final acceptance and independent review remain open), V1-03 owns application/event/capacity contracts (the first contract increment is published; internal evaluation is implemented; final qualification and coordinator acceptance remain open), and V1-42 owns transitive provenance and distribution clearance. Supported runtime targets for this increment are Linux containers and Unix development hosts; Windows signal behavior is not implemented.

The app repository consumes core APIs. The deploy repository owns generic Helm packages. Private site values and curated fork implementations stay outside this tree.

## Baseline maintenance

The baseline is the complete accepted document exported from the [planning Page](https://chatgpt.com/space/page_fef707d85d8c8191a14f162d6281307d). SOURCE-REFERENCES.md retains neutral aliases, source pins and paths for personal repository citations; the Page retains original URLs. The native workbook reference points back to that archive. These portability/privacy changes do not amend the accepted architecture. Record subsequent decisions in DECISIONS.md and link implementation tickets.
