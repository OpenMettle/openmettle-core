# Restore a retired login provider

Use this procedure when a deployment operator has confirmed that a retired provider should resume service with its last active configuration revision. The change applies to **all identities eligible to use that provider**. It requires migration 10, a primary database connection as `openmettle_owner`, and the deployment's normal controls for using that account. It can run while OIDC is unavailable.

## Inspect the target

1. Identify the provider UUID from the approved deployment configuration. Confirm the reason for its retirement has been resolved and the configuration identified by the previous revision is still trusted. The database stores a revision label. The deployment supplies the matching configuration and key material.
2. In a fresh owner connection to the primary, supply the canonical lowercase UUID as the psql variable `provider` and inspect its state.

   ```sql
   SELECT p.access_generation AS expected_generation, latest.epoch AS retired_epoch,
          previous.epoch AS source_epoch, previous.revision AS revision_to_restore
     FROM openmettle.login_providers p
     CROSS JOIN LATERAL (SELECT epoch, revision FROM openmettle.login_provider_revisions
       WHERE provider_id = p.id ORDER BY epoch DESC LIMIT 1) latest
     CROSS JOIN LATERAL (SELECT epoch, revision FROM openmettle.login_provider_revisions
       WHERE provider_id = p.id AND revision IS NOT NULL ORDER BY epoch DESC LIMIT 1) previous
    WHERE p.id = :'provider'::uuid AND latest.revision IS NULL;
   ```

3. Stop if the query returns no row or the revision differs from the approved configuration. Record the provider, both epochs, and the generation in the deployment change record. Assign a fresh request UUID to this action and record it before execution. Supply a deployment-assigned opaque operator UUID attributable through that record. Use canonical lowercase UUIDs and the exact decimal counters from the query. Keep credentials, names and identity claims out of these inputs.

## Apply the restoration

From the repository root, run the [owner script](restore-login-provider.psql) in a new psql process. Use deployment-managed connection credentials.

```sh
psql -X -q -v provider="$provider" -v request="$request" -v operator="$operator" \
  -v expected_generation="$expected_generation" -v retired_epoch="$retired_epoch" \
  -v source_epoch="$source_epoch" -f docs/operator/restore-login-provider.psql
```

The script locks the provider, checks the observed state after any wait and appends the same revision with a new epoch. It preserves the access generation and the retirement row. One synchronously committed transaction updates the provider's latest-change fields and inserts the recovery event. A successful command prints `provider restoration committed` after commit acknowledgement. A stale inspection, a reused request UUID, or a lock or SQL error prevents a second restoration. Sequence gaps after rollback are expected.

Old sessions and pending logins stay fenced. A fresh login requires a working OIDC exchange, current provider configuration, an approved existing identity, its personal scope and an enabled user. An ongoing provider outage still prevents a fresh session. The procedure can repair local provider authority during that outage. It issues no credential and changes no identity, approval or grant.

If a committed restoration must be reversed, inspect the current epoch and generation and retire the provider under the [ADR 0013 owner protocol](../adr/0013-local-identity-sessions.md#provider-revision-revocation-retirement-and-restoration). Keep the recovery event and revision history.

## Resolve an uncertain outcome

If the connection or success output is lost, reconnect to the primary. Use the original request UUID.

```sql
SELECT operator_id, provider_id, source_epoch, retired_epoch, access_generation,
       restored_epoch, recorded_at
  FROM openmettle.provider_recoveries WHERE request_id = :'request'::uuid;
```

A row matching the recorded request proves the change committed, even if a later action retired the provider again. A mismatched row indicates request ID reuse. Stop and investigate. If no row is visible, the original transaction may still be running. Retry only with the **same request UUID and original inputs**, then check again. If the observed provider state has changed, inspect it before authorizing another action.

The event records the successful restoration and its database timestamp. Only the database owner has ordinary access. The procedure only appends events. The database owner and a superuser retain the ability to alter stored evidence. The operator UUID is an owner-supplied reference to the deployment change record. Attribution to a person depends on those external controls. Authority and receipt reads require the primary and the existing deployment guarantee that acknowledged commits survive failover.

First application administrator designation and the identity evidence required for that grant remain outstanding for V1-05 under [ADR 0008](../adr/0008-oidc-id-token-verification.md#notes-for-follow-on-design).
