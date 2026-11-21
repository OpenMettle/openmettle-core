# Session and login-gate cleanup

Use this procedure to free retained-session capacity and remove expired login gates.
Connect to the primary database as `openmettle_owner` using your deployment’s approved
connection settings. Session cleanup requires schema version 8 or later. Gate cleanup
requires version 9 or later. Each script commits its own batch.

## What each script deletes

| Step | Script | Deletes | Never deletes |
| --- | --- | --- | --- |
| 1 | [`session-cleanup.psql`](session-cleanup.psql) | Sessions that are revoked, or whose `expires_ms` is at or before the primary clock (from schema version 14, deleting a native session cascades to its linked `openmettle.native_handoffs` row) | Unexpired, unrevoked sessions; locked sessions; login gates, approvals, users, providers, nonce reservations, or run/approval receipts |
| 2 | [`login-gate-cleanup.psql`](login-gate-cleanup.psql) | Login gates whose original expiry has passed and that no session references | Unexpired gates; referenced gates; locked gates; nonce reservations |

Step 1 targets only `openmettle.local_sessions`; from schema version 14, deleting a native
session also removes its linked `openmettle.native_handoffs` row via `ON DELETE CASCADE`.
It never changes login gates or their `session_issued` markers, approvals, users, provider
rows or generations, or AEAD nonce reservations, and `openmettle.runs` and
`openmettle.run_approval_decisions` have no foreign key to `local_sessions` so their
receipts are preserved. Validation accepts a session only while `expires_ms` is after the
primary clock, so step 1 never removes a session that validation would accept.

**Never delete active-key nonce reservations.** Reclaiming retired-key reservations has no
supported procedure yet (ADR 0014).

A deleted session is refused exactly like an unknown credential. The logout route
answers `403 session not valid` for it instead of an acknowledgement (ADR 0019). Deleting rows frees
the user's retained-session allowance, which counts expired and revoked rows until they are
removed. Deleted rows are not archived. Retain any evidence your deployment requires before
running the procedure.

Deleting revoked or expired `openmettle.local_sessions` rows does not break
`openmettle.runs` or `openmettle.run_approval_decisions` receipts: those tables hold session
locators without a foreign key to `local_sessions`, and missing sessions fail effect checks
closed (ADR 0035). Cleanup runs safely alongside `openmettle_worker`'s non-secret `SELECT`
reads on `openmettle.local_sessions`.

## Run one cleanup pass

From the repository root, set the shell variable `batch` to a decimal integer from 1 to
1000. The commands require this value and ignore local `psqlrc` files. Run each in a
fresh connection with the deployment's normal credential handling.

1. Delete one batch of sessions:

   ```sh
   psql -X -q -v batch="${batch:?set batch to an integer from 1 to 1000}" -f docs/operator/session-cleanup.psql
   ```

   On success it exits 0 and prints one line:
   `session cleanup committed: <n> session rows deleted`.

2. Only after step 1 exits 0, delete one batch of login gates in a separate transaction:

   ```sh
   psql -X -q -v batch="${batch:?set batch to an integer from 1 to 1000}" -f docs/operator/login-gate-cleanup.psql
   ```

   It exits 0 and prints nothing on success.

Repeat either step as needed. Neither script retries, sleeps or loops.

## Failure, retry and idle batches

Each script commits with `synchronous_commit = on` or rolls back completely. Both set a
2-second `lock_timeout` and a 5-second `statement_timeout`, and select rows with
`FOR UPDATE SKIP LOCKED`, so a row held by a concurrent validation, logout or issuance is
skipped rather than awaited.

| Situation | Result | Action |
| --- | --- | --- |
| Session script receives a missing, empty, out-of-range, signed, zero-padded or non-decimal `batch` | The script exits non-zero with `session cleanup refused: batch must be 1-1000; nothing deleted`. With the commands above, the shell reports a missing or empty variable before starting psql. | Correct the value. |
| Step 2 `batch` invalid | Exits non-zero with nothing deleted. | Correct the value. |
| Timeout or other SQL error in step 1 | Exits non-zero. The transaction rolls back and no session is deleted. | Investigate, then rerun step 1. |
| Step 1 committed, then step 2 failed or was not run | The sessions are gone. Their gates remain with `session_issued` set. | Rerun step 2 later. Nothing else is needed. |
| Step 2 run without step 1 | Only already unreferenced expired gates are removed. | None; it is safe. |
| Connection lost while a script waits for `COMMIT` | The outcome is unknown; no success line is printed. | Rerun the same step. It selects whatever is eligible at that time. |
| `<n>` equals `batch` | More eligible sessions may remain. | Run another batch. |
| `<n>` is less than `batch`, including zero | The batch committed. Locked rows may still be eligible, and other sessions can expire later. | Resume at the next planned cleanup. |

The interval between the steps is safe for replay. Issuance requires the original gate,
consumed, without an issuance marker and before its original expiry. A retained gate with its
marker refuses a second issuance, and a missing gate refuses it too. Neither script recreates
a gate, clears a marker or deletes a nonce reservation.

## Evidence and limits

CI runs the cleanup tests with the other schema tests through
`cargo test --locked --offline --test schema -- --ignored`. They require an isolated PostgreSQL 18 service (`TEST_DATABASE_URL`) and
its container (`POSTGRES_CONTAINER`), and execute both files unchanged with the pinned
service image's `psql`. They cover refusal without effects, both eligibility rules, locked and
live sessions, exact batch limits, idle retries, preserved gates, markers and reservations,
and the chained gate cleanup. Replay refusal after session or gate deletion is covered by the
managed PostgreSQL tests under `provider_keys::tests::postgres`.

Not provided: a schedule, a recommended batch, measured query cost or lock impact, a bound on
global storage, audited recovery, or qualification against a real or restored database.
