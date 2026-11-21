# Designate or recover an account administrator

Use this procedure to designate the first `account_admin` of an installation, or to restore
administration when no trusted enabled administrator remains (break-glass). Both are the same
owner command: it makes one enabled user an active `account_admin` and records an immutable
audit row. It requires schema version 15 or later, a direct primary connection as `openmettle_owner`
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

3. If the account is missing or disabled, stop. This command never re-enables a user: restore
   the account under the deployment's owner change control first, or choose another enabled
   user. If the user is already an active administrator, stop; there is nothing to do.
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
enabled user with this procedure first so an enabled administrator remains. `/v1` does not
yet expose HTTP endpoints to demote an administrator or disable a user account (the
`authz::store` functions are internal-only). To cut off a compromised administrator
immediately today, run **`withdraw`** on **every** approval held by the compromised account
using the [local identity approval change procedure](identity-approval-change.md) (which
advances each approval's `access_generation` and sets `active = false`, stopping existing
sessions immediately and refusing new logins), or perform a controlled owner account-wide
disablement under [ADR 0013's user disablement protocol](../adr/0013-local-identity-sessions.md#user-disablement-and-re-enable).
ADR 0013's standalone disablement SQL predates schema 15's `account_admin_lock` and locks
only the target user row, so on schema 15 or later you must first lock the single
`openmettle.account_admin_lock` row `FOR UPDATE` before locking the target `openmettle.users`
row `FOR UPDATE` (matching the `account_admin_lock` -> `users` lock order used by
`authz::store` and [`grant-account-admin.psql`](grant-account-admin.psql)), and verify in the
**same transaction** that at least one other active `openmettle.account_admins` row belongs to
an enabled user (`disabled_at IS NULL`) before setting `disabled_at` and advancing
`session_generation` on `openmettle.users`—otherwise a concurrent administrator demotion could
leave zero enabled administrators.

Unlike `authz::store::disable_user` (which calls `authz::runs::cancel_user_runs` in the same
transaction), ADR 0013's standalone owner disablement SQL updates only `openmettle.users`
(`disabled_at` and `session_generation`) and does **not** cancel or fence the user's
non-terminal `openmettle.runs` rows, so a `queued` or `waiting` run could otherwise remain
non-terminal and resume if the account were later re-enabled. As part of the same owner
disablement recovery procedure, cancel or fence every non-terminal `openmettle.runs` row for
that `actor_user_id` (`state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')`
where `state IN ('queued', 'waiting') OR cancel_reason IS NULL`), matching
`authz::store::disable_user` and `authz::runs::cancel_user_runs` lock order and semantics:
lock affected `openmettle.runs` rows in ascending `id` order (`ORDER BY id FOR NO KEY UPDATE`)
**after** locking `openmettle.account_admin_lock` and `openmettle.users`; transition `queued`
and `waiting` runs directly to `state = 'cancelled'` with `wait_reason = NULL` and
`cancel_reason = coalesce(cancel_reason, 'revoked')`, appending the terminal
`openmettle.run_events` row (`append_key = 'run-terminal'`, `format = 'openmettle.run-cancelled'`,
`format_version = 1`, payload `{"reason":"revoked"}`, advancing `last_event_sequence` with
matching ADR 0004 `identity` and `digest`); transition `running` runs to `state = 'cancelling'`
and leave `reconciling` runs in `state = 'reconciling'`, in both cases clearing
`wait_reason = NULL`, setting `cancel_reason = coalesce(cancel_reason, 'revoked')`, and
appending the cancellation-request event (`append_key = 'cancel-requested'`,
`format = 'openmettle.run-cancel-requested'`, `format_version = 1`, payload
`{"reason":"revoked"}`) so leased workers stop and settle in-flight work rather than
overwriting an executing run directly to `cancelled`. Wait for any `cancelling` or
`reconciling` runs to settle and verify that **zero** non-terminal `openmettle.runs` rows
(`state NOT IN ('succeeded', 'failed', 'cancelled', 'interrupted')`) remain for that
`actor_user_id` before re-enabling the account.

Do **not** rely on `revoke` or the
[session cleanup procedure](session-cleanup.md) to cut off a compromised administrator:
`revoke` advances an approval's `access_generation` to end existing sessions for that approval
while leaving an unexpired approval eligible for immediate re-sign-in, whereas
[`session-cleanup.psql`](session-cleanup.psql) deletes only explicitly revoked or expired
`openmettle.local_sessions` rows and leaves unexpired, unrevoked sessions untouched and
usable. Use the [session cleanup procedure](session-cleanup.md) afterwards to remove expired or
revoked session rows as needed, and record any direct owner SQL demotion or account
disablement under deployment change controls. Review the `openmettle.authorization_audit` rows
of the affected period afterwards.

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
