# Credential vault and key recovery

External connection credentials (`openmettle.external_connections`, [ADR 0045](../adr/0045-credential-vault-and-external-connection-lifecycle.md)) are encrypted at rest using per-seal HKDF-SHA256 + AES-256-GCM under versioned 256-bit master keys stored **outside** PostgreSQL and **outside** artifact volume backups.

## Key custody and provisioning

Mount vault keys read-only from a dedicated Kubernetes Secret (or external secret manager) separate from PostgreSQL backups and PVC snapshots.

1. Generate a 32-byte random master key per version (`key_id` matching `^[A-Za-z0-9_-]{1,64}$`):

   ```sh
   umask 077
   head -c 32 /dev/urandom > /run/secrets/openmettle-vault/vault-k1
   chmod 0400 /run/secrets/openmettle-vault/vault-k1
   ```

2. Write a version-1 keyring manifest referencing the absolute paths of the active key and any historical decrypt-only keys (up to 16 keys total):

   ```json
   {
     "version": 1,
     "active_key_id": "vault-k2",
     "keys": [
       { "id": "vault-k1", "file": "/run/secrets/openmettle-vault/vault-k1" },
       { "id": "vault-k2", "file": "/run/secrets/openmettle-vault/vault-k2" }
     ]
   }
   ```

3. Set `OPENMETTLE_API_VAULT_KEYS_CONFIG` on `openmettle-api` and `OPENMETTLE_WORKER_VAULT_KEYS_CONFIG` on `openmettle-worker` to the absolute path of the manifest.
   - In Kubernetes, mount the Secret volume with `defaultMode: 0400` so every key file restricts group and world permissions (`(mode & 0o077) == 0`).
   - On startup, invalid manifests, relative paths, world/group-readable key files, non-32-byte key files, all-zero keys, or duplicate key material cause an immediate exit `78` with a redacted `vault configuration error:` line before telemetry or listeners start.
   - Leaving `VAULT_KEYS_CONFIG` unset disables `POST /v1/connections/{connection_id}/authorize` (`503 provisioning`) without affecting other `/v1` routes.

## Online key rotation

Rotation runs online alongside active `openmettle-api` and `openmettle-worker` traffic using bounded `READ COMMITTED` `FOR UPDATE SKIP LOCKED` batches and `credential_generation` compare-and-set:

1. **Distribute the new key version** (e.g. `vault-k2`) alongside the existing key (`vault-k1`) in the Secret mounted to all API and worker replicas while keeping `active_key_id` at `vault-k1` until every replica has restarted and can decrypt `vault-k2`.
2. **Promote `active_key_id` to `vault-k2`** in the keyring manifest and restart API and worker replicas so all new authorizations and refreshes seal under `vault-k2` while existing `vault-k1` rows remain readable.
3. **Inspect current key distribution** as `openmettle_owner` (zero secrets printed):

   ```sh
   export OPENMETTLE_ADMIN_DATABASE_URL='postgres://openmettle_owner:...@db.example.test/openmettle'
   openmettle-admin vault status
   ```

4. **Re-encrypt historical rows** in batches and record an audited `vault.rotated` event:

   ```sh
   openmettle-admin vault rotate \
     --vault-keys /run/secrets/openmettle-vault/keyring.json \
     --operator-id 00000000-0000-4000-8000-000000000001 \
     --request-key rotate-vault-k2-2026-11-26 \
     --reason "Scheduled quarterly master key rotation to vault-k2" \
     --batch-size 100
   ```

   - If any stored `encryption_key_id` in PostgreSQL is missing from `--vault-keys`, `vault rotate` refuses fail-closed before modifying any row.
   - Rows holding an active worker refresh claim (`refresh_claim_token IS NOT NULL AND refresh_lease_until > clock_timestamp()`) are deferred rather than overwritten mid-flight. `vault rotate` retries briefly; if any old-key rows remain deferred (`skipped > 0` / `deferred_active_refresh > 0`), it exits non-zero **without** consuming `--request-key` so you can re-run with the same `--request-key` once in-flight refreshes settle.
   - Re-running with the same `--operator-id` and `--request-key` for the same `active_key_id` after completion (`skipped=0`) replays cleanly without modifying rows.
   - Verify `openmettle-admin vault status` shows zero remaining rows under `vault-k1` (`skipped=0 deferred_active_refresh=0`).

## Worker external MCP & refresh-route configuration

When `openmettle-worker` executes reviewed external MCP tools (`OPENMETTLE_WORKER_INFERENCE_CONFIG`), configure an optional `external_mcp` block with pinned HTTPS `connections`, reviewed `tools` (including `reconcile.lookup_scope` when reconciliation is enabled), and optional provider-bound `refresh_routes` mapping `(provider_kind, allowed_origins)` to each provider's trusted OAuth token endpoint URI. Mount `OPENMETTLE_WORKER_VAULT_KEYS_CONFIG` alongside it so `VaultCredentialProvider` and `VaultDestinationAuthorizer` are wired at worker startup; omitting `OPENMETTLE_WORKER_VAULT_KEYS_CONFIG` keeps external MCP tool dispatch fail-closed.

## Backup retention and retired key retention

- **Never store vault master keys inside PostgreSQL dumps, WAL archives, or artifact volume snapshots.** Back up the vault Secret material in a separate encrypted secret store or offline key escrow.
- **Retain retired key versions across the full backup retention window (`7d / 4w / 3m`)**: even after `vault rotate` completes on the live database, older PostgreSQL backups taken before rotation still contain ciphertexts encrypted under earlier `key_id`s. Removing a retired key from secret backups before older PostgreSQL backups expire prevents decrypting those historical connection rows if you restore an older snapshot.

## Recovery after backup restore or key loss

### Normal database + artifact restore

1. Complete the PostgreSQL and artifact restore reconciliation runbook ([Restoring a matched database and artifact volume](restore-artifact-volume.md)), passing `--required-connection-origin` from the schema-43+ `journal export` when locking the gate. Replaying the complete journal enforces post-backup connection disconnects, transitions superseded credentials to `reauth_required`, and deactivates revoked shares; if journal coverage is incomplete, `openmettle-admin restore accept-coverage-gap` transitions all `authorized` connections to `reauth_required` and deactivates all active shares before the gate can open. While `restore_reconciliation_gate` is closed, all connection writes (`POST`/`PUT`) and worker credential lookups fail closed (`503 unavailable` / `CredentialOutcome::Unavailable`).
2. Ensure the mounted `VAULT_KEYS_CONFIG` on `openmettle-api` and `openmettle-worker` includes every `encryption_key_id` reported by `openmettle-admin vault status` against the restored database.
3. After the restore gate opens, if the restored snapshot contains rows under an older key version, run `openmettle-admin vault rotate` to re-encrypt them under the current `active_key_id`.

### Key loss (partial recovery without losing PostgreSQL)

Because vault master keys are isolated from PostgreSQL:

- Losing a vault master key makes stored `external_connections` ciphertexts encrypted under that `key_id` permanently unrecoverable, **without** affecting users, projects, conversations, artifacts, runs, quotas, or audit history in PostgreSQL.
- Execution calls against affected connections fail closed (`CredentialOutcome::Unavailable`) rather than leaking errors or corrupt data.
- To recover cleanly:
  1. Provision a fresh master key version (`vault-k-new`) as `active_key_id` on `openmettle-api` and `openmettle-worker`.
  2. Connection owners (personal owner or project `Owner`) either re-authorize existing connections via `POST /v1/connections/{connection_id}/authorize` (which overwrites the unreadable ciphertext under `vault-k-new` and advances `credential_generation`) or retire them via `POST /v1/connections/{connection_id}/disconnect` (which wipes the unreadable ciphertext columns to `NULL`).
  3. Confirm with `openmettle-admin vault status` that no connections remain referencing the lost `key_id`.
