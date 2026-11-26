# ADR 0045 — Credential vault and external connection lifecycle

- **Status:** accepted (implemented in this PR)
- **Date:** 26 November 2026
- **Ticket:** Refs #25 (`[V1-28] Credential vault and external connection lifecycle`), Refs #14
- **Companion ADRs:** [ADR 0003](0003-schema-migrations.md), [ADR 0007](0007-application-api-contract.md), [ADR 0010](0010-provider-http-transport.md), [ADR 0024](0024-process-telemetry-and-redaction.md), [ADR 0027](0027-authorization-and-private-projects.md), [ADR 0035](0035-approvals-permitted-yolo-and-effect-ledger.md), [ADR 0039](0039-scoped-mcp-adapter-and-bounded-tool-results.md), [ADR 0041](0041-retention-purge-and-deletion-journal.md)

## Triggering problem

[ADR 0039](0039-scoped-mcp-adapter-and-bounded-tool-results.md) delivered the scoped external MCP adapter (`ExternalMcpAdapter`), reviewed tool contracts, and the `McpCredentialProvider` / `DestinationAuthorizer` seams while keeping external credential storage fail-closed behind `GatedCredentialProvider`. Satisfying `V1-28` in `ARCHITECTURE-v1.md` requires a server-side credential vault and external connection lifecycle that guarantees:

1. **Private-by-default ownership and explicit sharing:** external connections belong to a personal scope or a project scope, enforce non-widening scope ceilings, support explicit revocable execution-use shares, and never expose provider tokens or keys to browsers or unauthorized callers.
2. **Versioned-key encryption and backup isolation:** credentials are encrypted with master keys stored outside PostgreSQL and artifact PVC backups, bind ciphertext integrity to row identity and scopes, and support online key rotation without downtime.
3. **Deterministic connection lifecycle and race-safe refresh:** connections move through `pending_auth`, `authorized`, `reauth_required`, and terminal `disconnected` states with DB-backed single-flight token refresh fenced against concurrent disconnects, share revocations, and upstream scope widening.
4. **Least-privilege execution injection and error redaction:** workers inject only the minimum required bearer credential at execution time after verifying live principal authority, pinned HTTPS destination origin, granted scopes, and an open restore reconciliation gate, with zero secret leakage into API replies, audit rows, operations, or logs.

## Decision

### 1. Ownership, allowed scopes, and explicit sharing

Migration `0043_credential_vault_and_connections.sql` adds `openmettle.external_connections` and `openmettle.external_connection_shares`:

- **Personal ownership (`scope_kind = 'personal'`):** bound to the personal scope owner via a composite foreign key `(scope_id, personal_owner_user_id) -> openmettle.scopes (id, personal_user_id)`. Only the personal scope owner can register, authorize, share, revoke shares on, or disconnect the connection. Non-owners without an active share receive `404 not_found` concealment; non-owners holding an active `'use'` share may inspect non-secret metadata and execute permitted operations, and receive `403 policy` on management mutations.
- **Project ownership (`scope_kind = 'project'`):** bound to the project scope (`owner_user_id` records creator provenance). Only active `ProjectRole::Owner` members can register, authorize, share, revoke shares on, or disconnect project connections. `account_admin` never grants access to private personal or project connections ([ADR 0027](0027-authorization-and-private-projects.md)).
- **Explicit execution-use sharing:** `openmettle.external_connection_shares` records revocable `'use'` grants for `user`, `local_group`, `oidc_group`, and (for project scopes only) whole-`project` grantees. Project shares enforce ADR 0027 Gate 2b: grantees must hold active project membership, disabled users or disabled local groups are excluded immediately, lapsed OIDC group evidence ceases to grant access, non-owner project `Editor` members have zero implicit access until explicitly shared, and read-only `Viewer` members can never execute external tools.
- **Project lifecycle and restore gate:** deleted projects conceal all connections (`404 not_found`). Archived projects keep metadata readable and permit `disconnect` and share revocations while refusing `create`, `authorize`, new `share` grants (`409 conflict`), and execution-time credential resolution. Every non-owner mutation and worker credential/reconcile check enforces an open `openmettle.restore_reconciliation_gate` ([ADR 0041](0041-retention-purge-and-deletion-journal.md), SQLSTATE `OMR02` / `503 unavailable`).
- **Origin pinning and non-widening scopes:** `endpoint_origin` is validated in Rust and PostgreSQL as a canonical `https://host[:port]` DNS origin (rejecting `http://`, IP literals, default `:443`, paths, queries, fragments, and userinfo). `allowed_scopes` (`1..=64` sorted unique lowercase ASCII tokens) is immutable after creation; `granted_scopes` (`0..=64`) enforces `granted_scopes <@ allowed_scopes` in both Rust and SQL so authorization and upstream token refresh can never widen scopes beyond the connection's ceiling.
- **No browser-direct provider keys:** `/v1/connections*` responses carry non-secret metadata only (`connection_id`, `scope_kind`, `scope_id`, `project_id`, `provider_kind`, `account_id`, `origin`, `allowed_scopes`, `granted_scopes`, `state`, `expires_at`, `has_refresh`, `generation`, `revocation_generation`, `share_revision`, timestamps, `can_manage`). `POST /v1/connections/{connection_id}/authorize` is write-only over authenticated `/v1` with `Idempotency-Key` and same-origin CSRF enforcement on browser sessions.

### 2. Versioned-key cryptographic envelope and separate custody

- **Master keyring (`VaultKeyRing`, `src/vault.rs`):** loaded from an optional JSON manifest (`OPENMETTLE_API_VAULT_KEYS_CONFIG` / `OPENMETTLE_WORKER_VAULT_KEYS_CONFIG`) pointing to absolute, regular, owner-only (`mode & 0o077 == 0` on Unix) 32-byte raw master key files mounted from Kubernetes Secrets or external secret stores outside PostgreSQL and artifact PVC backups. Up to 16 versioned keys are supported (`active_key_id` plus historical decrypt keys). Validation rejects malformed manifests, duplicate `key_id`s, all-zero keys, and duplicate key bytes using `subtle::ConstantTimeEq`. Invalid config exits `78` with a fixed redacted line before telemetry or listeners start. Master keys and decrypted tokens live in zeroizing `rustls::crypto::SharedSecret` wrappers under `unsafe_code = "forbid"`, adding zero new Cargo dependencies.
- **Per-seal HKDF-SHA256 + AES-256-GCM envelope:** each seal generates a fresh 32-byte CSPRNG `salt` and 12-byte `nonce` via `ring::rand::SystemRandom`, derives a single-use 256-bit DEK with `HKDF-SHA256(salt, master_key, "openmettle.vault.dek/1")`, and encrypts with `ring::aead::AES_256_GCM`. Canonical length-prefixed AAD (`"openmettle.vault.aad/1\0"`) binds `(connection_id, scope_id, account_id, secret_kind["access"|"refresh"], key_id, credential_generation, allowed_scopes)`. Moving ciphertext across connections, scopes, accounts, access/refresh slots, generations, or altered scope sets fails AEAD verification fail-closed.
- **Online rotation and key retention (`openmettle-admin vault`):** all new authorizations, refreshes, and rotations seal under `active_key_id`, while reads decrypt any configured historical `key_id`. `openmettle-admin vault status` prints non-secret counts by state and `encryption_key_id`. `openmettle-admin vault rotate` verifies every stored source `key_id` is present in the keyring before modifying any row, re-encrypts authorized rows in bounded `READ COMMITTED` `FOR UPDATE SKIP LOCKED` batches with `credential_generation` compare-and-set, and records an audited `vault.rotated` operator event. Operators retain retired key versions in separate secret backups across the full database backup retention window (`7d/4w/3m`).

### 3. Connection state machine and single-flight refresh fencing

| State | Secret columns | Transitions |
| --- | --- | --- |
| `pending_auth` | All `NULL`, `granted_scopes = {}` | Initial state on create -> `authorized` or `disconnected` |
| `authorized` | `encryption_key_id` + `access_*` non-null; optional `refresh_*`; `granted_scopes` non-empty | Refresh in place (`credential_generation + 1`), re-authorize, `reauth_required`, or `disconnected` |
| `reauth_required` | All `NULL`, `granted_scopes = {}` | Entered on expiry without refresh, deterministic upstream refusal (`400`/`401`/`403`), or scope widening/omission -> re-authorize (`authorized`) or `disconnected` |
| `disconnected` | All `NULL`, `granted_scopes = {}`, `disconnected_at` set | Terminal; enforced by SQL trigger |

- **Single-flight refresh leasing:** when `VaultCredentialProvider` observes an `authorized` connection with `expires_at <= now + refresh_skew` and `has_refresh = true`, one worker acquires `(refresh_claim_token, refresh_lease_until)` under `FOR UPDATE`, decrypts only the refresh secret, and commits the lease so zero database locks or pooled connections are held across network I/O. Concurrent callers seeing an unexpired lease poll briefly within the call budget and consume the leader's committed `credential_generation + 1` without duplicating upstream refresh requests.
- **Disconnect and scope-policy fencing:** the upstream refresh runs over `HttpsRefreshClient` built on [ADR 0010](0010-provider-http-transport.md) `provider_http::transport::Route` (dedicated 8-slot DNS pool, strict TLS 1.2/1.3, SSRF CIDR policy, `<= 64 KiB` body cap, zero redirects/retries). Before committing, the leader re-locks the row `FOR UPDATE` and verifies `state = 'authorized'`, matching `refresh_claim_token`, unchanged `credential_generation`, and unchanged `revocation_generation`. Any concurrent `disconnect` or share revocation wins immediately and discards the in-flight refresh. Upstream scope widening beyond `allowed_scopes`, omission of required scopes, or HTTP `400`/`401`/`403` transitions to `reauth_required` and wipes stored ciphertexts; transient `408`/`429`/`502`/`503`/`504` or transport timeouts release only the lease and preserve the refresh secret.

### 4. Execution-time injection, role boundaries, and redaction

- **`VaultCredentialProvider` and `VaultDestinationAuthorizer`:** implement `McpCredentialProvider` and `DestinationAuthorizer` ([ADR 0039](0039-scoped-mcp-adapter-and-bounded-tool-results.md)). `ExternalMcpAdapter` passes `run.claim.actor_approval_id`, `McpTransport::origin()`, and `contract.action` on catalog verification, tool dispatch, and reconciliation, evicting cached `tools/list` entries on credential failure. Both providers verify on the primary database: open `restore_reconciliation_gate`, live principal + active approval + non-retired login provider, non-archived/non-deleted scope lifecycle, owner or explicit share authority, exact origin match, and containment of the required action in `granted_scopes`. Only the required bearer token (`McpCredential::bearer`) is injected into the outbound request.
- **Least-privilege database roles (`src/boundaries.sql`):**
  - `openmettle_api`: column-scoped `SELECT` excluding all ciphertext, salt, nonce, `encryption_key_id`, and refresh-lease columns (write-only to secrets); column-scoped `INSERT`/`UPDATE` for metadata, authorization, disconnect, and sharing.
  - `openmettle_worker`: `SELECT` on `external_connections` and `external_connection_shares`; trigger-guarded `UPDATE` limited to refresh leasing, refresh commit, and `reauth_required` transitions; `EXECUTE` on two `SECURITY DEFINER` (`SET search_path = pg_catalog`) helpers (`external_connection_scope_lifecycle` and `external_connection_audit_worker`) so the worker never gains direct `SELECT` on `project_settings` or `authorization_audit`.
  - `openmettle_issuance` and `openmettle_gateway`: zero privileges on vault tables or functions.
- **Redaction:** `SecretText`, `SealedSecret`, `VaultKeyRing`, `RefreshRequest`, `RefreshedCredential`, and `VaultError` emit only fixed redacted text in `Debug`/`Display`; `/v1` problems return ADR 0007 fixed messages; `authorization_audit` records only non-secret identifiers, scope counts, and generation numbers.

## Alternatives considered

1. **Database-resident encryption keys (`pgcrypto`):** rejected because storing wrapping keys in PostgreSQL collapses database backup disclosure into credential disclosure, violating `ARCHITECTURE-v1.md` key/backup separation.
2. **Mandatory external KMS/HSM network dependency in v1:** rejected to keep self-hosted deployments offline-capable and dependency-free (`Cargo.toml` unchanged); the versioned `VaultKeyRing` seam permits adding external KMS key unwrapping later without changing schema or API contracts.
3. **Storing connection shares in `openmettle.grant_assignments`:** rejected to couple share revocation directly to `external_connections.share_revision` and `revocation_generation` fencing under one canonical lock order (`projects -> login_providers -> local_identity_approvals -> users -> external_connections -> external_connection_shares -> restore_reconciliation_gate`).

## Consequences

- **Graceful key-loss isolation:** losing vault key files renders encrypted connection credentials unrecoverable without impairing recovery of PostgreSQL users, projects, conversations, artifacts, or audit logs. Owners recover affected connections via `authorize` (overwriting under a fresh key) or `disconnect` (wiping ciphertexts).
- **Safe default provisioning:** omitting `VAULT_KEYS_CONFIG` on `openmettle-api` keeps all non-secret connection routes operational while failing `POST /v1/connections/{connection_id}/authorize` closed with `503 provisioning`.
- **Auditable lifecycle:** every create, authorize, share, share revoke, worker refresh, reauth-required transition, disconnect, and operator key rotation writes a non-secret row in `openmettle.authorization_audit`.

## Affected contracts and delivery split

- **Database schema and boundaries:** `migrations/0043_credential_vault_and_connections.sql`, `src/migrate.rs`, `src/boundaries.sql`, `tests/schema.rs`.
- **Vault, MCP, runtime, and admin CLI:** `src/vault.rs`, `src/mcp/external.rs`, `src/provider_http/mcp.rs`, `src/provider_http/transport.rs`, `src/lib.rs`, `src/bin/admin.rs`.
- **Application API contract:** `contracts/openapi/openmettle-v1.json` (7 implemented operations under `/v1/connections*`), `contracts/fixtures/`, `src/v1/connections.rs`, `src/v1/pagination.rs`, `src/v1.rs`, `tests/contract.rs`, `tests/contract/consumer.rs`.
- **Operator documentation:** `docs/operator/credential-vault-and-key-recovery.md`, `docs/operator/restore-artifact-volume.md`, `README.md`, `DECISIONS.md`.
- **Delivery:** bundled in one focused PR targeting `main` with unit, OpenAPI contract, and PostgreSQL 18.1 + synthetic TLS (`rcgen`) integration coverage (`tests/schema/vault.rs`).
