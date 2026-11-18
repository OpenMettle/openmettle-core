# First local identity approval

Use this procedure to approve one existing OIDC identity for one login provider for the
first time. It creates the approval row that managed login requires (ADR 0013). It does not
create a user, identity, personal scope, resource grant or session. It requires schema
version 8 or later.

Every later change uses [ADR 0013's approval change protocol](../adr/0013-local-identity-sessions.md#approval-edits-revocation-withdrawal-and-reapproval):
routine edits, expiry changes, revocation, withdrawal and reapproval. That includes an
approval that is withdrawn or has expired. This procedure never updates an existing approval.

## Before you start

Confirm these facts from deployment records. The script checks them, but it never searches
for or guesses a value.

- The provider row exists and its latest revision is not retired.
- An identity row has exactly this issuer and subject. Linking an identity to a user is a
  separate, explicit owner decision; this procedure does not do it.
- The identity's user is enabled and has a personal scope.
- No approval exists yet for this provider and identity.

## Inputs

Supply every variable. There are no defaults.

| Variable | Value |
| --- | --- |
| `provider` | Login provider UUID in canonical lowercase form. |
| `issuer` | The provider's issuer, byte for byte. It must also be the identity's issuer. |
| `subject` | The identity's subject, byte for byte: 1–255 ASCII bytes. Case and spaces are significant and never trimmed. |
| `expires_ms` | Approval expiry in Unix milliseconds. Supply 1–18 decimal digits without a leading zero. The expiry must still be in the future after the script's lock waits. Session issuance uses the approval expiry in effect at issuance. |
| `actor`, `reason` | Operator identifier (1–128 bytes) and change reason (1–512 bytes). |

`actor` and `reason` are latest-change provenance. A later change overwrites them, so they
are not an audit log. Use deployment-controlled operator identifiers, not personal details
or credentials.

## Run the script

Run [`first-identity-approval.psql`](first-identity-approval.psql) unchanged from the
repository root. Connect to the primary as `openmettle_owner` with the deployment's
normal credential handling. Pass each value exactly. Quote it for your shell so that spaces
and apostrophes reach psql unchanged.

```sh
psql -X -q -v provider="$provider" -v issuer="$issuer" -v subject="$subject" \
  -v expires_ms="$expires_ms" -v actor="$actor" -v reason="$reason" \
  -f docs/operator/first-identity-approval.psql
```

On success it exits 0 and prints exactly `first approval committed`. The new approval is
active, with revision 1 and access generation 0. No other row changes.

The script runs one transaction with `lock_timeout` 2s, `statement_timeout` 5s and
`synchronous_commit = on`. It locks the existing provider row for share and checks its
current revision and issuer in a fresh statement. If the provider first appears after the
lock attempt, rerun the command. It then inserts the approval and locks the existing user
row for share. It checks the user's eligibility and the primary clock after those waits.
If another operator creates the same approval concurrently, the script waits for that
transaction. If the other transaction commits, this command refuses the duplicate.

## Refusals

Every refusal exits non-zero, prints a fixed reason, and commits nothing. Supplied values are
never printed.

| Reason starts `first approval refused:` | Meaning | Action |
| --- | --- | --- |
| `missing or invalid input` | A variable is absent, empty, out of range or malformed. | Correct the input. |
| `provider is missing, retired or has a different issuer` | No such provider, no current revision, retired, or the issuer differs. | Check the provider record and issuer. |
| `no identity has exactly this issuer and subject` | No exact match. No similar value is tried. | Check the exact subject. Creating or linking identities is out of scope. |
| `identity user is disabled or has no personal scope` | The user is not eligible. | Resolve it under its own procedure, then rerun. |
| `an approval already exists for this provider and identity` | Created earlier, by someone else, or in a run whose result you did not see. | Inspect it. Use ADR 0013's change protocol for any change. |
| `expiry is not after the primary database clock` | `expires_ms` has passed. | Choose a future expiry and rerun. |

A lock or statement timeout, lost connection or other SQL error also exits non-zero without
a success line.

## Unknown outcome

If the connection fails while the script waits for `COMMIT`, the approval might exist. Do not
assume either result. Inspect the provider and identity with this read-only query, run with
`psql -X -v provider=... -v issuer=... -v subject=... -f -`:

```sql
SELECT a.active, a.expires_ms,
       a.expires_ms > floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS unexpired,
       a.revision, a.access_generation, a.changed_by, a.change_reason, a.changed_at
  FROM openmettle.local_identity_approvals AS a
  JOIN openmettle.user_identities AS i ON i.id = a.identity_id
 WHERE a.provider_id = :'provider'::uuid AND i.issuer = :'issuer' AND i.subject = :'subject';
```

- If the query returns zero rows, no approval was visible at the time of the read. The
  original transaction may still be finishing. You can retry with the same inputs.
- If an active row matches the requested expiry, actor and reason at revision 1 and
  generation 0, the requested state exists. A concurrent request can produce the same state.
- If any field differs, review the existing approval and use ADR 0013's change protocol.

Rerunning the script is also safe: it either creates the approval or refuses because one
exists. It never replaces or extends an existing approval.

## Sensitive values

The issuer and subject identify a person at the provider. Treat them as personal data.

- Command-line `-v` values can appear in shell history and in process listings on the client
  host. Use your deployment's approved method to supply them.
- psql does not write `-f` script statements to its own history file.
- The script sends the values to PostgreSQL as quoted literals inside SQL text. Server
  logging records that text when `log_statement` covers it, and also records a failing
  statement under the default `log_min_error_statement = error`. A running statement's text
  is visible in `pg_stat_activity` to roles allowed to see it. Issuer and subject appear only
  in the input check and in the reads of the provider and identity, none of which takes a row
  lock. DDL can make these reads wait for a relation lock while their text remains visible
  to authorized observers. The deliberate row-lock waits use UUIDs, expiry, actor and reason.
- Normal output is a fixed success line or a fixed refusal reason. PostgreSQL lock and
  timeout errors can name a relation or index, but not the supplied values.

## Evidence and limits

CI runs the exact script and the inspection query above with the pinned PostgreSQL 18 psql
through `cargo test --locked --offline --test schema -- --ignored`, which needs
`TEST_DATABASE_URL` and `POSTGRES_CONTAINER`. The tests cover the created row, unchanged
other tables, exact matching with case, space and apostrophe variants, every refusal reason,
refusals of repeated and extended attempts, and real lock waits for concurrent creators,
user disablement, provider revisions and expiry. The suite also checks a provider created
between the lock attempt and the authority read, and high-bit subject bytes on SQL_ASCII.
The operator tests do not exercise session issuance. The
managed-session tests in `provider_keys::tests::postgres::sessions` show that an approval
admits an identity; those tests insert approvals directly.

Not provided: identity linking, account or scope provisioning, bulk approval, an API, a
default expiry, or qualification against a real or restored database.
