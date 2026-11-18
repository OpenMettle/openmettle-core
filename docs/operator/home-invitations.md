# Invite a home user before first sign-in

An operator can approve first-account creation for one named OIDC principal. The person signs in with the configured provider. OpenMettle consumes the invitation when it issues the first local session. That transaction creates one user, the exact bound identity, a private personal scope and an ordinary provider-specific approval. It creates no resource grant, membership or administrator role.

This private candidate uses provisional migration 11 on the v10 base. Membership reserves v11 and native follows if it needs a migration. Assign the final number and qualify the actual merged predecessor before release. The managed session consumer is internal and the browser routes remain unmounted.

## Identify the person and authorize the window

Use a trusted provider administration record or a provider-supported lookup for the configured client to establish the person's stable OIDC `sub`. Providers with pairwise subjects can issue different values for the same person across clients or sectors. Verify the issuer, client and person through the deployment's administrative process. Stop if the provider cannot establish that exact subject. Email, display names, directory labels and claims supplied by the applicant cannot identify an invitation recipient.

On the primary, inspect the configured provider by UUID. Check its issuer and client against the deployment records and record its current generation. A NULL or missing latest revision means the provider cannot admit a user.

```sql
SELECT p.id, p.issuer, p.client_id, p.access_generation,
       (SELECT revision FROM openmettle.login_provider_revisions
         WHERE provider_id = p.id ORDER BY epoch DESC LIMIT 1) AS current_revision
  FROM openmettle.login_providers p WHERE p.id = :'provider'::uuid;
```

Choose a new opaque invitation UUID. Record it, the operator UUID and the decision in your deployment change record. Both UUIDs and the provider UUID must use canonical lowercase form. Use the issuer byte for byte and the subject exactly as issued, including case and spaces (1–255 ASCII bytes). The UUID identifies an operator record. Possession gives the recipient no sign-in capability.

Set both cutoffs as absolute Unix milliseconds, 1–18 decimal digits without leading zeros.

- `redeem_before_ms` is the exclusive deadline for first-account redemption, measured on the primary after waits. Choose it in the future.
- `approval_until_ms` is the exclusive expiry of the resulting ordinary approval. Choose a time at or after the redemption cutoff. A late redemption receives only the remaining approval time. The session policy can shorten individual sessions.

## Create or withdraw

From the repository root, connect a new psql process to the primary as `openmettle_owner` using deployment-managed credentials. Supply the inspected values as separately quoted shell variables. Protect the shell, process arguments and database logs that may contain the principal's identifiers.

```sh
psql -X -q -v invitation="$invitation" -v operator="$operator" \
  -v provider="$provider" -v issuer="$issuer" -v subject="$subject" \
  -v expected_generation="$expected_generation" -v redeem_before_ms="$redeem_before_ms" \
  -v approval_until_ms="$approval_until_ms" -f docs/operator/home-invitation-create.psql
```

Success prints `home invitation created`. Creation refuses an existing issuer/subject identity, an occupied invitation UUID or an outstanding invitation for the same issuer and subject across all provider configurations. Explicit provider revocation or retirement fences the outstanding invitation by generation. Routine configuration revision preserves it. Each login still requires proof under the current provider epoch.

To cancel a pending decision, use its original UUID and the withdrawing operator's UUID.

```sh
psql -X -q -v invitation="$invitation" -v operator="$operator" \
  -f docs/operator/home-invitation-withdraw.psql
```

Success prints `home invitation withdrawn`. An expired or generation-fenced invitation still reserves its principal until explicitly withdrawn. Use a new UUID and a fresh decision to invite again. Withdrawal and redemption lock the same invitation. When redemption commits first, withdraw the resulting approval through the [approval change procedure](identity-approval-change.md). Both operator commands use synchronous commit, a two-second lock timeout and a five-second statement timeout.

## Resolve failure or lost acknowledgement

Reconnect to the primary as owner. Query the original UUID and compare the decision, actor and cutoffs with the change record.

```sql
SELECT id, provider_id, provider_generation, issuer, subject, created_at, created_by,
       redeem_before_ms, approval_until_ms, withdrawn_at, withdrawn_by, redeemed_at, approval_id
  FROM openmettle.home_invitations WHERE id = :'invitation'::uuid;
```

- After an uncertain create, an exact matching record proves creation committed. A mismatched UUID requires investigation. An absent record may still be uncommitted. Retry only the original command with identical inputs and inspect again.
- A withdrawal timestamp and operator identify a committed withdrawal. If the row is still pending after an uncertain withdrawal, retry the same UUID. A redeemed row names the resulting approval.
- An unknown principal, byte mismatch, stale proof, collision, timed-out lock or expired decision cannot authorize creation. A competing transaction can create the identity after the operator checks it. Redemption refuses the collision. Inspect the existing identity and use the established first-approval procedure only if independent approval is intended.
- If acknowledgement of session issuance is lost, discard the uncertain connection and start a fresh verified login. A committed first login leaves the consumed invitation and approval even if no credential reached the person. The new proof then follows ordinary approval, disablement, session limits and revocation checks. Replaying the original login cannot issue another session. A rolled-back redemption leaves the invitation available until withdrawal or expiry.
- Keep consumed and withdrawn invitation records through session and login cleanup. A database restore can rewind the decision history. Keep authentication closed while reconciling restored pending invitations against current operator records, withdrawing stale decisions and applying the existing login/session restore procedure.

## Database trust boundary

Only the managed consumer accepts the sealed online proof. It locks the originating login and provider and checks the proof binding and authority before looking up the identity. An existing identity always follows ordinary approval checks. For an absent identity, the owner-defined redemption function locks the exact pending invitation, checks the current generation and primary time, and inserts fresh records. A global issuer/subject uniqueness conflict rolls back the attempted creation.

The API can execute this one function. It has no table privilege on invitations and cannot set the new account ID, choose the approval expiry, restore an approval or change invitation provenance through it. The function fixes its search path and uses schema-qualified tables. The database trusts the application to verify the OIDC proof, as it does for ordinary session issuance. A deferred constraint checks the first session and its issued login marker before the redemption transaction can commit. The existing postcommit checks still control credential release. The receipt survives session cleanup. The database owner retains administrative control of these records.
