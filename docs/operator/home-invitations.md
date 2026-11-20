# Invite a home user before first sign-in

An operator can approve first-account creation for one named OIDC principal. The create command prints a one-time invitation code, which the operator delivers to that person privately. The person signs in with the configured provider and presents the code. OpenMettle consumes the invitation when it issues the first local session. That transaction creates one user, the exact bound identity, a private personal scope and an ordinary provider-specific approval. It creates no resource grant, membership or administrator role.

Invitations are migration 12, applied after project membership (migration 11). Invitation codes are migration 13. Migration 14 lets a login started by a native sign-in redeem, and changes no invitation. The schema suite upgrades populated databases migrated by the authentic membership (v11), invitation (v12) and invitation-code (v13) binaries and checks that those binaries then refuse the newer schema. An invitation-created approval can be enrolled in and withdrawn from [project membership](../adr/0021-project-membership.md) like any other approval. Its first sign-in creates no membership, because no enrollment can exist before the approval does.

The database requires the code from schema 13. The browser sign-in form carries it in one optional field, `invitation_code`, submitted with the form `POST` that starts the sign-in ([ADR 0022](../adr/0022-home-invitation-codes.md)). From schema 14, native sign-in carries the same field on its system-browser confirmation page, so a first sign-in from a native app redeems under the same rules ([ADR 0023](../adr/0023-native-sign-in.md)). The app itself never handles the code. The managed session consumer is internal, and the browser and native routes remain unmounted.

## Before upgrading to schema 13

Migration 13 refuses to run while any invitation is pending. Schema 12 issued invitations without a code, and a pending one could never be redeemed afterwards. The migration fails with SQLSTATE `23514`, rolls back and leaves schema 12 unchanged.

1. On the primary, list the pending invitations.

   ```sql
   SELECT id, issuer, subject, redeem_before_ms FROM openmettle.home_invitations
    WHERE withdrawn_at IS NULL AND approval_id IS NULL;
   ```

2. Withdraw each one with the [withdrawal command](#create-or-withdraw). Expired invitations count as pending until withdrawn.
3. Run the migration.
4. Invite each person again with a new invitation UUID. Deliver the new code.

Redeemed and withdrawn invitations are kept unchanged and have no code. During a rolling update, replicas from the previous release cannot redeem an invitation on schema 13, so first sign-ins are refused until every replica is updated. Sign-in for existing users continues, with one exception: a previous-release replica cannot complete a sign-in that an updated replica started, and the person must start again. A sign-in started before the update completes on an updated replica.

Migration 14 has no precondition and changes no invitation. A previous-release replica on schema 14 still redeems an invitation for a browser sign-in. It has no native routes.

## Identify the person and authorize the window

Use a trusted provider administration record or a provider-supported lookup for the configured client to establish the person's stable OIDC `sub`. Providers with pairwise subjects can issue different values for the same person across clients or sectors. Verify the issuer, client and person through the deployment's administrative process. Stop if the provider cannot establish that exact subject. Email, display names, directory labels and claims supplied by the applicant cannot identify an invitation recipient.

On the primary, inspect the configured provider by UUID. Check its issuer and client against the deployment records and record its current generation. A NULL or missing latest revision means the provider cannot admit a user.

```sql
SELECT p.id, p.issuer, p.client_id, p.access_generation, r.epoch AS current_epoch,
       r.revision AS current_revision
  FROM openmettle.login_providers p
  LEFT JOIN LATERAL (SELECT epoch, revision FROM openmettle.login_provider_revisions
                      WHERE provider_id = p.id ORDER BY epoch DESC LIMIT 1) r ON true
 WHERE p.id = :'provider'::uuid;
```

Choose a new opaque invitation UUID. Record it, the operator UUID and the decision in your deployment change record. Both UUIDs and the provider UUID must use canonical lowercase form. Use the issuer byte for byte and the subject exactly as issued, including case and spaces (1–255 ASCII bytes). The UUID identifies an operator record. Possession gives the recipient no sign-in capability. Only the invitation code does.

Set both cutoffs as absolute Unix milliseconds, 1–18 decimal digits without leading zeros.

- `redeem_before_ms` is the exclusive deadline for first-account redemption, measured on the primary after waits. Choose it in the future and at most seven days ahead. The command refuses a longer window. To give someone more time, withdraw the invitation and create a new one.
- `approval_until_ms` is the exclusive expiry of the resulting ordinary approval. Choose a time at or after the redemption cutoff. A late redemption receives only the remaining approval time. The session policy can shorten individual sessions.

## Create or withdraw

From the repository root, connect a new psql process to the primary as `openmettle_owner` using deployment-managed credentials. Supply the inspected values as separately quoted shell variables. Protect the shell, process arguments and database logs that may contain the principal's identifiers.

Run the create command in a terminal that is not being recorded. Do not pipe it through `tee`, run it under `script`, or run it from a ticket system, CI job or shared session. Its second output line is a secret.

```sh
psql -X -q -v invitation="$invitation" -v operator="$operator" \
  -v provider="$provider" -v issuer="$issuer" -v subject="$subject" \
  -v expected_generation="$expected_generation" -v redeem_before_ms="$redeem_before_ms" \
  -v approval_until_ms="$approval_until_ms" -f docs/operator/home-invitation-create.psql
```

Success prints two lines, after the commit is acknowledged:

```text
home invitation created
invitation code (shown once; deliver privately): omh1-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx
```

Each `x` is a lowercase hexadecimal digit. A refused or failed command prints no code.

The command records the provider's current epoch while it holds the provider lock. Creation refuses an existing issuer/subject identity, an occupied invitation UUID or an outstanding invitation for the same issuer and subject across all provider configurations.

Revocation fences the outstanding invitation through the generation. Any retirement recorded after creation also fences it, even when a later restoration makes the provider usable again. This includes the legacy migration 7 retirement recipe, which leaves the generation unchanged. Routine configuration revisions preserve the invitation. Each login still requires proof under the current provider epoch. After a restoration, withdraw the fenced invitation and create a new one if the decision still stands.

To cancel a pending decision, use its original UUID and the withdrawing operator's UUID.

```sh
psql -X -q -v invitation="$invitation" -v operator="$operator" \
  -f docs/operator/home-invitation-withdraw.psql
```

Success prints `home invitation withdrawn`. An expired or generation-fenced invitation still reserves its principal until explicitly withdrawn. Use a new UUID and a fresh decision to invite again. Withdrawal and redemption lock the same invitation. When redemption commits first, withdraw the resulting approval through the [approval change procedure](identity-approval-change.md). Both operator commands use synchronous commit, a two-second lock timeout and a five-second statement timeout.

## Handle the invitation code

The code is 128 random bits, generated in the database inside the create transaction. The database stores only a SHA-256 hash of it. The code is shown once and cannot be recovered or shown again.

- **Deliver it privately** to the invited person over a channel you trust for a password. Anyone who has the code and can sign in to the provider as the invited subject can create the account.
- **Record only the first output line.** Keep the code line out of tickets, change records, chat, CI output, shell history and terminal recordings.
- **Single use.** The code works only while the invitation is pending, before `redeem_before_ms`. It has no separate expiry. Redemption or withdrawal ends it.
- **Entered when sign-in starts.** The person types or pastes the code into the sign-in form before they are sent to the provider. It is not asked for again afterwards. In a native app, that form is the confirmation page the system browser shows before the provider. The app never asks for the code.
- **Entry is forgiving.** The person may type it in upper or lower case, with or without the `omh1-` prefix, hyphens and spaces.
- **A mistyped code is caught in two places.** A code of the wrong length or with other characters is refused at once with `login request refused`, before the provider is contacted. A well-formed but wrong code is refused only after the provider sign-in, with the same `login refused. Start a new login.` message as any other refused sign-in. Neither message says whether an invitation exists. The native confirmation page answers `native sign-in request refused` and `native sign-in refused` in the same two places.
- **No lockout.** A wrong code refuses that sign-in and leaves the invitation pending. The person starts a new sign-in and enters the correct code.
- **Ignored for existing accounts.** Once the account exists, a code entered at sign-in is ignored.

To share the code as a QR image, encode the bare code text only. Generate the image locally and offline, for example `qrencode -t ANSIUTF8` reading the code from standard input in the same unrecorded terminal. Never encode a sign-in URL that contains the code, and never use an online QR generator: the code must not appear in URLs, `Referer` headers or another service's logs.

**Lost code.** Withdraw the invitation by its original UUID, then create a new one with a new UUID and deliver the new code.

## Resolve failure or lost acknowledgement

Reconnect to the primary as owner. Query the original UUID and compare the decision, actor and cutoffs with the change record.

```sql
SELECT id, provider_id, provider_generation, provider_epoch, issuer, subject, created_at, created_by,
       redeem_before_ms, approval_until_ms, withdrawn_at, withdrawn_by, redeemed_at, approval_id
  FROM openmettle.home_invitations WHERE id = :'invitation'::uuid;
```

- After an uncertain create, inspect the UUID before anything else.
  - If the row exists, the create committed but its code was never shown. Withdraw it and create again with a new UUID.
  - If the row is absent, rerun the original command with identical inputs. A refusal then means the first attempt committed late. Inspect again, withdraw it and create with a new UUID.
  - A mismatched record under that UUID requires investigation.
- A withdrawal timestamp and operator identify a committed withdrawal. If the row is still pending after an uncertain withdrawal, retry the same UUID. A redeemed row names the resulting approval.
- An unknown principal, byte mismatch, stale proof, later provider retirement, collision, timed-out lock or expired decision cannot authorize creation. A competing transaction can create the identity after the operator checks it. Redemption refuses the collision. Inspect the existing identity and use the established first-approval procedure only if independent approval is intended.
- If acknowledgement of session issuance is lost, discard the uncertain connection and start a fresh verified login. A committed first login leaves the consumed invitation and approval even if no credential reached the person. The new proof then follows ordinary approval, disablement, session limits and revocation checks. Replaying the original login cannot issue another session. A rolled-back redemption leaves the invitation and its code usable until withdrawal or expiry.
- Keep consumed and withdrawn invitation records through session and login cleanup. A database restore can rewind the decision history. Keep authentication closed while reconciling restored pending invitations against current operator records, withdrawing stale decisions and applying the existing login/session restore procedure.

## Database trust boundary

The code reaches the database by one path. The sign-in form submits it, the API seals it with the login's PKCE verifier (AES-256-GCM under the login key ring), and the callback opens it and passes it to the redemption function. Every stored login ciphertext has the same length, so a row does not show whether a code was entered, and the ciphertext is cleared when the login is consumed.

Only the managed consumer accepts the sealed online proof. It locks the originating login and provider and checks the proof binding and authority before looking up the identity. An existing identity always follows ordinary approval checks, and a code presented with it is ignored. For an absent identity without a code, the consumer refuses and writes nothing; the database function would also refuse a missing code. For an absent identity with a code, it calls the owner-defined redemption function. From schema 18 the API calls it on its issuance connection, as `openmettle_issuance`, the only role that can execute it ([ADR 0030](../adr/0030-session-issuance-database-boundary.md)); before schema 18 the API role executed it. Neither role has a table privilege on invitations. The function fixes its search path and uses schema-qualified tables.

The function inserts fresh records only when all of these hold:

- The originating login row exists, is consumed and has no session yet.
- Its stored managed binding names the supplied provider UUID and issuer, the provider's client, the current revision and the supplied epoch.
- The supplied epoch is the provider's latest epoch, and its revision is not a retirement.
- The supplied code is 16 bytes, and an exact pending invitation exists for the provider, current generation, issuer, subject and the hash of that code.
- No retirement was recorded for the provider after the invitation's epoch.
- Primary time is before the invitation and login cutoffs.

A wrong code is handled exactly like a missing invitation: no invitation row is locked and nothing is written. A global issuer/subject uniqueness conflict rolls back the attempted creation. The caller cannot set the new account ID, choose the approval expiry, restore an approval or change invitation provenance.

The database cannot verify an OIDC proof. It trusts the application to do so, as it does for ordinary session issuance. Two layers keep a principal limited to SQL as one application role from creating an account.

From schema 18, a principal limited to SQL as `openmettle_api`, for example a holder of the API's primary database credentials or of a SQL injection in an API query, can still insert and consume login rows, but it cannot execute the redemption function, insert a session row or mark a login session-issued. It can therefore neither redeem an invitation nor issue a session for an approved existing identity ([ADR 0030](../adr/0030-session-issuance-database-boundary.md), [#73](https://github.com/OpenMettle/openmettle-core/issues/73)).

The `openmettle_issuance` role holds those writes and the function's `EXECUTE`. A principal that can run arbitrary SQL as that role, or as the API role before schema 18, can fabricate everything the function checks except the code. Without the code it cannot redeem an invitation:

- Neither role can read `code_hash`, and no function returns it.
- The code-less function of schema 12 no longer exists.
- A code that a person has entered is stored only as ciphertext in the login row, under a key ring the database does not hold, and only until that login is consumed.
- Guessing a 128-bit code is not feasible.

Such an issuance-role principal can still issue sessions for any approved existing identity, by design. Protect the issuance credential like the API's and mount it into the API container only. Sessions issued before the upgrade to schema 18 cannot be told apart from forged ones; [ADR 0030](../adr/0030-session-issuance-database-boundary.md#upgrade) gives the optional revocation step.

These remain trusted with the code:

- the invited person, their browser and the device they sign in from;
- the channel that delivers the code;
- the terminal and operator that ran the create command;
- the ingress or proxy that terminates TLS for the application. The code travels in the body of the sign-in form `POST`. Do not log request bodies for the sign-in start path, and treat any capture of them as secret;
- the API process, which holds the code in memory while it starts and completes the sign-in;
- anyone who holds both the login key ring and read access to the login table, for an unconsumed login's lifetime (at most 600 seconds);
- the database owner and anyone who can read the database server's logs. The API passes the code to the redemption function as a bind parameter, as `openmettle_issuance` from schema 18 and as `openmettle_api` before. A server that logs statements with their parameters records those bytes: `log_statement` or `log_min_duration_statement` unless `log_parameter_max_length` is `0`, and failed statements when `log_parameter_max_length_on_error` is not `0`. Disable parameter logging for that role or treat those logs as secret.

A leaked code alone creates no account. Redemption still needs a consumed login for the exact subject under the current provider epoch. Keep redemption windows short and withdraw invitations that are no longer needed.

A deferred constraint trigger fires when an invitation update records a redemption. At commit it reads only the rows for that login and approval: the session row, the identity's user and the login's consumed and session-issued markers. It compares primary time with the invitation, login and session cutoffs. It does not show that a proof was verified or that a credential reached the person. It does not constrain later changes to those rows. A cutoff that passes before commit is refused with SQLSTATE `OMH01`, which the managed consumer reports as a rejected sign-in. Other commit failures remain uncertain, and the connection must be discarded. The existing postcommit checks still control credential release. The receipt survives session cleanup. The database owner retains administrative control of these records.
