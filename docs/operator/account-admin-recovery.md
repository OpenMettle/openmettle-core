# Designate or recover an account administrator

Use this procedure to designate the first `account_admin` of an installation, or to restore
administration when no trusted enabled administrator remains (break-glass). Both are the same
owner command: it makes one enabled user an active `account_admin` and records an immutable
audit row. It requires schema version 15, a direct primary connection as `openmettle_owner`
and the deployment's normal controls for using that account. The application API cannot
perform it, and directory roles never map to `account_admin` (ADR 0027).

`account_admin` manages accounts, local groups and user capability policy. It grants **no**
access to any user's private projects, conversations, artifacts or memory, and it implies no
opt-in capability such as `runs.use_yolo`.

## Inspect the target

1. Identify the person's internal user UUID from an approved identity record, for example
   the approval created with the [first identity approval](first-identity-approval.md)
   procedure. Confirm the account is enabled and has an active approval, otherwise the new
   administrator cannot sign in.
2. In a fresh owner connection to the primary, supply the canonical lowercase UUID as the
   psql variable `user_id` and inspect the account and every current administrator.

   ```sql
   SELECT u.id, u.disabled_at, a.active, a.revision
     FROM openmettle.users u
     LEFT JOIN openmettle.account_admins a ON a.user_id = u.id
    WHERE u.id = :'user_id'::uuid;
   SELECT a.user_id, a.revision, a.updated_at, u.disabled_at
     FROM openmettle.account_admins a JOIN openmettle.users u ON u.id = a.user_id
    WHERE a.active ORDER BY a.user_id;
   ```

3. Stop if the account is missing or disabled. This command never re-enables a user: restore
   the account under the deployment's owner change control first, or choose another enabled
   user. Stop if the user is already an active administrator; there is nothing to do.
4. Assign a fresh request UUID and record it with a deployment-assigned opaque operator UUID,
   the reason and the inspected rows in the deployment change record. Keep credentials,
   names and identity claims out of these inputs. The reason (1 to 512 bytes) is stored.

## Apply the grant

From the repository root, run the [owner script](grant-account-admin.psql) in a new psql
process with deployment-managed connection credentials.

```sh
psql -X -q -v user_id="$user_id" -v request="$request" -v operator="$operator" \
  -v reason="$reason" -f docs/operator/grant-account-admin.psql
```

The script locks the single `account_admin_lock` row, which every administrator change and
user disablement takes first, then holds the user row so it cannot be disabled concurrently.
In a fresh statement it inserts the administrator row, or reactivates an inactive one at its
next revision, and inserts one `authorization_audit` row with actor kind `operator`, the
operator UUID, action `account_admin.grant`, the user as target, the request UUID as request
key, the reason and the count of enabled administrators before the change. Both rows commit in
one synchronously committed transaction. After commit acknowledgement it prints
`account admin grant committed`.

It refuses with one fixed line, and changes nothing, for another role, missing or invalid
input, an unknown or disabled user, a user who is already an active administrator, and a
request UUID this operator already used for a different change.

## Break-glass recovery

When every remaining administrator is disabled, unavailable or untrusted, grant a trusted
enabled user with this procedure. That administrator then demotes or disables compromised
administrators through the application, which enforces the last-enabled-administrator rule
and records its own audit rows. Review the audit rows of the affected period afterwards.

## Resolve an uncertain outcome

If the connection or the success line is lost, rerun the **same command with the same
request, operator and user**. A committed request prints `account admin grant already
committed` and changes nothing, so the audit row is never duplicated. If the original
transaction has not yet finished, the rerun waits for it (bounded by the lock timeout); retry
after a timeout. To inspect directly:

```sql
SELECT occurred_at, action, target_kind, target_id, reason, details
  FROM openmettle.authorization_audit
 WHERE actor_kind = 'operator' AND operator_id = :'operator'::uuid
   AND request_key = :'request';
```

A refusal stating the request was used for another change indicates request UUID reuse. Stop
and investigate.

## Limits

The operator UUID is an owner-supplied reference to the deployment change record; attribution
to a person depends on those external controls. The application roles can only insert and
read audit rows. The database owner and a superuser can still alter stored evidence.
