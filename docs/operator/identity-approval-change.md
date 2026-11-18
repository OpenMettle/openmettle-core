# Local identity approval change

Use this procedure to change one existing local identity approval: a routine edit, an
explicit session revocation, withdrawal, or reapproval. It implements
[ADR 0013's approval change protocol](../adr/0013-local-identity-sessions.md#approval-edits-revocation-withdrawal-and-reapproval).
It requires schema version 8 or later.

It updates only the selected approval row. It never creates an approval, changes the
approval's provider or identity, or changes sessions, users, identities, scopes, grants or
providers. Create a first approval with the
[first local identity approval procedure](first-identity-approval.md). Provider and user
changes use ADR 0013's separate provider and user protocols.

## Actions

Each action advances the revision by one. Generation is the approval's access generation.
Sessions record the generation in effect when they were issued and stop validating when it
changes.

| `action` | Allowed when | Generation | Active | Expiry | Effect on sessions |
| --- | --- | --- | --- | --- | --- |
| `routine` | Active and unexpired | Unchanged | Unchanged | Set to `expires_ms` | Existing sessions keep validating, subject to the new expiry and their own. |
| `revoke` | Active, expired or not | +1 | Unchanged | Kept | Existing sessions stop validating. New logins are still admitted while the approval is unexpired. |
| `withdraw` | Active, expired or not | +1 | Set to false | Kept | Existing sessions stop validating. New logins are refused. |
| `restore` | Inactive, or active but expired | +1 | Set to true | Set to `expires_ms` | Old sessions stay invalid. A fresh login is admitted. |

"Expired" means the stored expiry is at or before the primary database clock, read after the
script acquires the row lock. An approval that only expired still needs `restore`, not
`routine`, and restoring it advances the generation. A routine edit can shorten or extend
the expiry. Validation checks the approval's current expiry, so no session validates after it.

## Find the approval and its counters

Run the read-only inspection query from the
[first approval procedure](first-identity-approval.md#unknown-outcome) with the exact provider
UUID, issuer and subject. It matches bytes exactly and never searches for similar values.
Use its `id` as `approval`, its `revision` as `expected_revision` and its
`access_generation` as `expected_generation`. Check `active` and `unexpired` against the
action table.

## Inputs

Supply every variable. There are no defaults.

| Variable | Value |
| --- | --- |
| `approval` | Approval UUID in canonical lowercase form. |
| `expected_revision` | The revision you inspected: plain decimal, 1 to 9223372036854775807. |
| `expected_generation` | The access generation you inspected: plain decimal, 0 to 9223372036854775807. |
| `action` | `routine`, `revoke`, `withdraw` or `restore`, in lowercase. |
| `expires_ms` | Unix milliseconds, 1 to 9223372036854775807 in plain decimal without a leading zero. For `routine` and `restore`, supply a future expiry. For `revoke` and `withdraw`, you can pass the current expiry. These actions preserve it. |
| `actor`, `reason` | Operator identifier (1–128 bytes) and change reason (1–512 bytes). |

`actor`, `reason` and the change time are latest-change provenance. The next change
overwrites them, so they are not an audit log. Use deployment-controlled operator
identifiers, not personal details or credentials.

## Run the script

Run [`identity-approval-change.psql`](identity-approval-change.psql) unchanged from the
repository root. Connect to the primary as `openmettle_owner` with the deployment's normal
credential handling, under deployment change controls. Quote each value for your shell.

```sh
psql -X -q -v approval="$approval" -v expected_revision="$expected_revision" \
  -v expected_generation="$expected_generation" -v action="$action" \
  -v expires_ms="$expires_ms" -v actor="$actor" -v reason="$reason" \
  -f docs/operator/identity-approval-change.psql
```

On success it exits 0 and prints one line after the commit is acknowledged, for example
`approval change committed: revision 4 access_generation 1`. Those are the new counters for
the next change.

The script validates every input before it reads a table. It then runs one transaction with
`lock_timeout` 2s, `statement_timeout` 5s and `synchronous_commit = on`. It locks only the
approval row `FOR UPDATE`, so it waits for in-progress session issuance or validation that
holds the row, and they wait for it. After the lock, a fresh statement reads the stored
values and the primary clock. The update repeats the expected counters as a compare-and-set.
Operator values reach SQL only as quoted psql variables.

## Refusals

Every refusal exits non-zero, prints a fixed reason, and commits nothing. Supplied values are
never printed. Checks run in the order of this table.

| Reason starts `approval change refused:` | Meaning | Action |
| --- | --- | --- |
| `missing or invalid input` | A variable is absent, empty, out of range or malformed. | Correct the input. |
| `no approval has this ID` | No row has that UUID. | Inspect by provider, issuer and subject. |
| `expected revision or generation is not current` | Another change committed since you inspected, or this is a retry of a change that already committed. | Inspect again before deciding. Do not copy the new counters blindly. |
| `revision or generation would overflow` | A counter is at the bigint maximum. | Owner repair outside this procedure. |
| `action does not apply to the approval's current state` | See the action table. For example, `routine` on an expired approval, or `restore` on an active, unexpired one. | Choose the action that matches the current state. |
| `expiry is not after the primary database clock` | `routine` or `restore` with an `expires_ms` that has passed. | Choose a future expiry. |

A lock or statement timeout, lost connection or other SQL error also exits non-zero without
a success line. A lock timeout means PostgreSQL could not acquire a required lock within 2s.

## Unknown outcome

If the connection fails while the script waits for `COMMIT`, the change might have
committed. Do not assume either result. Inspect the approval and compare its counters with
the values you supplied:

- If the revision advanced by one and the generation, active flag, expiry, actor and reason
  match the requested action, the requested state is visible. An identical concurrent
  command can produce the same result.
- If both counters still equal the expected values, the query saw the previous state.
  The original transaction might still be finishing. You can retry with the same counters.
- If the row is missing or the values differ, review the current state before choosing a
  new action.

Retrying with the same expected counters is safe. A retry of a committed change refuses
because its counters are no longer current; it never applies the action twice.

## Sensitive values

The inspection query takes the issuer and subject, which identify a person at the provider.
Treat them as personal data, as described in the
[first approval procedure](first-identity-approval.md#sensitive-values). This script takes
the approval UUID, counters, action, expiry, actor and reason. Command-line `-v` values can
appear in shell history and process listings. PostgreSQL can log statement text, which
includes the quoted actor and reason.

## Evidence and limits

CI runs the exact script with the pinned PostgreSQL 18 psql. Schema tests in
`tests/schema/approval_change.rs` run under
`cargo test --locked --offline --test schema -- --ignored` with `TEST_DATABASE_URL` and
`POSTGRES_CONTAINER`. They cover each action's stored result, unchanged other rows, stale and
repeated counters, invalid inputs, ineligible states, counter overflow, and real lock waits for
a competing change, expiry passing during the wait and lock timeout.

`provider_keys::tests::postgres::approval_change` runs the same script between managed logins
under `cargo test --locked --offline --lib provider_keys::tests::postgres -- --ignored --skip provider_keys::tests::postgres::browser::`.
It checks that a routine edit preserves a session, revoke invalidates it while allowing a
fresh login, withdrawal denies existing and new sessions, and restoration admits a fresh
login while old credentials stay invalid. It also covers an approval that expires and is then
restored. Check those jobs' results before relying on them as evidence.

This procedure does not provide an audit trail, an API, bulk changes, identity linking,
provisioning, or provider and user changes. Session rows are not updated: sessions stop
validating because their recorded generation or the approval's eligibility no longer
matches. Revoked or expired session rows stay until
[session cleanup](session-cleanup.md) removes them. Owner writes that bypass this script are
outside its concurrency guarantee.
