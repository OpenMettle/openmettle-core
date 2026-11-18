# 0021 — Login-time project membership for approved identities

Proposed V1-04 increment for #5 and #34. Migration 11 builds on schema 10.

## Deployment and enrollment

Upgrade the schema, every login-serving replica and all participating grant writers and
membership readers before the first enrollment. A v10 readiness probe establishes binary
and schema compatibility only. A v10 login can issue an exact-approval session without
reconciling membership. The running processes expose no new route.

Each existing exact identity approval can enroll **one rule revision and one project**.
The approval identifies a provider UUID and an issuer/subject identity. The provider fixes
the issuer and client. Check the enabled user, personal scope and approval under ADR 0013.
Confirm with the provider operator that the chosen claim supplies a complete list of direct
memberships for this client.

Record an enabled v5 revision with the same provider and issuer. Select `group` with
`groups` or `app_role` with `roles`, and the exact directory identifier. Use binding
format `openmettle.project-member`, version 1, and the ASCII bytes of the canonical
lowercase project UUID. Choose an evidence age of 1 through 3600 seconds. There is no
deployment default.

### Owner configuration procedure

Use the [configuration script](../operator/configure-project-membership.psql) for initial
enrollment, interval changes, target replacement, suspension and deliberate resynchronization
with an independent grant writer. Connect directly to the primary as `openmettle_owner`
under the deployment's normal owner controls. These guarantees depend on writers following
the documented protocols. Direct owner edits, deleting enrollment rows or resetting the
revision sequence can bypass them.

1. Inspect the intended approval, user, provider, rule revision, project and scope. Inspect
   the current enrollment's `config_revision` (use 0 for first enrollment). For the desired
   target, identify the v5 assignment with that scope, project, grantee, rule, format
   `openmettle.project-member`, version 1 and the approval UUID text as its assignment key.
   Inspect its change at `grant_assignments.last_revision`, including decision and cycle.
   Supply that exact change UUID as `baseline`, including for an inactive assignment.
   Use `none` only when this target has no history. Adopting an independently revoked
   head explicitly allows a later eligible assertion to grant a new cycle.
2. Choose a new request UUID and record it with the operator's UUID, reason and inspected
   inputs. Supply canonical lowercase UUIDs. For suspension use the existing target,
   revision and `enabled=false`. For initial enrollment, replacement or resynchronization
   choose the current enabled rule revision and `enabled=true`. Run the script once.

   ```sh
   psql -X -q -v approval="$approval" -v expected_revision="$expected_revision" \
     -v rule="$rule" -v rule_revision="$rule_revision" -v project="$project" -v scope="$scope" \
     -v age="$age_seconds" -v enabled="$enabled" -v baseline="$baseline" \
     -v request="$request" -v actor="$operator" -v reason="$reason" \
     -f docs/operator/configure-project-membership.psql
   ```

3. An acknowledged commit prints `membership configuration committed`. The script locks
   the owner receipt table, approval, enrollment and selected mapping rule, then rechecks
   the inspected revision and target head. One transaction records the immutable owner
   receipt, installs the new configuration and baseline, clears prior evidence and preserves
   the largest signed issue time recorded for that approval. Every reset, including tightening or relaxing an
   interval, requires a later callback and strictly newer signed issue time. A replacement
   immediately withdraws confirmation on the old target. It does not revoke the old
   target's derived grant. Its v5 history remains available for inspection and for explicit
   retirement with the withdrawal script below.
4. On an uncertain outcome, reconnect as owner to the primary. In a new READ COMMITTED
   transaction acquire `LOCK TABLE openmettle.membership_configuration_changes IN EXCLUSIVE MODE`
   with the same bounded lock timeout, then select the receipt by `request_id` and end the
   transaction. Compare the actor, approval, old revision, target, baseline, age and enabled
   state with the recorded request. A matching receipt proves that change committed even if
   a later change superseded it. After a confirmed absence, re-inspect the current state
   before retrying with the same request and expected revision. A timeout or conflicting
   receipt requires investigation.

### Withdraw enrollment-derived grants

Use the [withdrawal script](../operator/withdraw-project-membership.psql) to revoke every
still-active enrollment-derived grant of one approval. It selects `mapped` v5 assignments with
target kind `project`, the approval's user as grantee, format `openmettle.project-member`,
version 1 and the approval UUID text as assignment key, under any rule. This includes grants
left on superseded targets. It never touches direct grants. Connect directly to the primary
as `openmettle_owner` under the deployment's normal owner controls.

1. Inspect the approval's derived assignments and their current heads.

   ```sql
   SELECT g.id, g.scope_id, g.project_id, g.mapping_rule_id, g.last_revision, h.decision, h.cycle_id
     FROM openmettle.local_identity_approvals a
     JOIN openmettle.user_identities i ON i.id = a.identity_id
     JOIN openmettle.grant_assignments g ON g.grantee_user_id = i.user_id
          AND g.assignment_key = a.id::text AND g.source_kind = 'mapped'
          AND g.target_kind = 'project' AND g.assignment_format = 'openmettle.project-member'
          AND g.assignment_version = 1
     JOIN openmettle.grant_changes h ON h.assignment_id = g.id AND h.revision = g.last_revision
    WHERE a.id = :'approval'::uuid ORDER BY g.id;
   ```

2. Choose a new request UUID and record it with a deployment-assigned opaque operator UUID,
   the reason and the inspected rows in the deployment change record. Supply canonical
   lowercase UUIDs. Run the script once.

   ```sh
   psql -X -q -v approval="$approval" -v request="$request" -v actor="$operator" \
     -f docs/operator/withdraw-project-membership.psql
   ```

3. An acknowledged commit prints `membership withdrawal committed: N assignments`. The script
   takes the owner receipt table lock, then the approval, user `FOR NO KEY UPDATE`, enrollment,
   every owning rule in UUID order and every derived assignment in UUID order. That is issuance
   order, so a concurrent issuance waits for the withdrawal. In a fresh statement it revokes
   each active head at its next revision with its exact cycle and original mapping revision.
   It commits only if at least one grant was revoked and no derived grant of the approval
   remains active. Otherwise it rolls back and prints a fixed refusal. Refusals cover another
   role, invalid input, an unknown approval, a reused request and nothing to withdraw.
4. Each revoke is an ordinary immutable v5 change with an ADR 0006 request identity and
   digest. It records the grantee as actor and the request key
   `membership-withdraw/<request>/<operator>/<n>`, numbered per scope. The script does not
   store the reason. Keep it in the change record.
5. The enrollment is not modified. Its stored change no longer matches the withdrawn head,
   so reconciliation stays fenced. No held or later proof can regrant, and `current` reports
   `Failed` for that target. To re-enable, resynchronize through the configuration script
   with the withdrawal revoke as `baseline` and a strictly newer signed proof.
6. On an uncertain outcome, reconnect as owner to the primary. In a new READ COMMITTED
   transaction acquire `LOCK TABLE openmettle.membership_configuration_changes IN EXCLUSIVE MODE`
   with the same bounded lock timeout. Select the grant changes whose request key starts with
   `membership-withdraw/<request>/`, then end the transaction. Matching receipts prove that
   withdrawal committed. After a confirmed absence, re-inspect step 1 before retrying with the
   same request. A conflicting receipt or a timeout requires investigation.

### Rollback and restore

First quiesce membership-dependent admission, queued work and independent mapped writers.
Drain in-flight issuance and consumers before switching versions. Suspend each enrolled
approval with the script and verify the receipts. Before starting any older reader or writer,
run the withdrawal script for each enrolled approval. It withdraws still-active
enrollment-derived assignments through v5 CAS using their exact cycles, including assignments
left on superseded targets. A refusal because nothing is active is expected for an approval
without derived grants. Re-run the step 1 inspection and verify the resulting revisions.
Keep any consumer that lacks freshness and cycle checks disabled. Retain the v11 schema, receipts,
high-water marks and grant history through binary rollback. After database restore, advance
provider epochs using ADR 0013 before reopening login. To re-enable, upgrade all participants,
resynchronize through the script and require a fresh eligible assertion for each approval.

## Assertion and grant ordering

The verifier inspects the signed payload after ordinary token verification and rejects
ambiguous JSON as membership evidence. A complete array supports up to 128 distinct
nonempty strings of up to 1024 bytes. A missing claim yields missing evidence. Wrong
types, repeated values and control characters yield ambiguity. An oversized list is partial.
A disclosed overage or distributed-claim marker withholds **both groups and roles**, even
when one array contains the selector. A provider-qualified independent claim contract would
be needed to relax that rule. No token selects a directory destination.

Managed callback consumption captures the highest committed configuration revision before
the single token exchange. The lookup uses a uniquely indexed revision column. Owner edits serialize
revision allocation and commit. Issuance ignores a proof for membership if its approval's
enrollment was created or reset after that snapshot, including a proof whose signed issue
time exceeds the previous high-water. A pending login whose callback is consumed after reset can reconcile if its signed evidence
is fresh and exceeds the preserved issue-time floor. Other approvals continue using their own revisions.
An earlier issue time cannot replace a newer observation. Conflicting decisions at the same
issue time yield ambiguity. A matching repeat can only shorten expiry.

The verifier accepts an issue time up to its configured future skew ahead of its own clock.
Issuance compares the signed issue time with the primary clock. A proof issued after the
primary clock is `Stale` and records nothing: no evidence, no grant transition and no
issue-time high-water. A clock-skewed provider therefore cannot block later correctly clocked
proofs. This assumes the provider, verifier and primary clocks are synchronized. A provider
clock running ahead yields no membership evidence for that skew.

Issuance locks the consumed login, provider and approval, then the user with
`FOR NO KEY UPDATE`, the enrollment and the rule. The user lock serializes capacity checks
and conflicts with disablement while admitting the actor/grantee FK `KEY SHARE` locks of a
v5 writer already holding the rule. Both mapped writers take the rule before the assignment.
Direct grants do not take the rule. Session validation takes shared provider, approval and
user locks in the same order. Logout takes only its session row. Owner configuration writers
serialize only with one another on the receipt table and take approval, enrollment and rule
in issuance order. They do not modify users or assignments. The owner withdrawal writer also
takes the receipt table first, then approval, user, enrollment, rules and assignments in
issuance order.

Under the rule lock the reconciler compares its stored change UUID with the exact target's
current immutable v5 change. The UUID identifies the assignment, revision and cycle. Any
independent transition, including revoke/regrant on the same assignment, fences further
mapped writes until explicit owner resynchronization. A fresh match can establish or confirm
one mapped grant. A fresh complete absence revokes its active cycle. Evidence already expired when first evaluated
under the locks advances the issue-time fence without a grant transition. Missing, partial or
ambiguous evidence withholds confirmation without recording a removal. Direct grants and
other approvals retain independent origins.

Reconciled grant changes name the grantee user as actor. ADR 0006 has no service account.
Their provenance is `source_kind = 'mapped'`, the enrollment's rule and mapping revision, and
the request key `membership-grant/<login>` or `membership-revoke/<login>`, which names the
consumed login transaction. Operator withdrawals use the same actor and a
`membership-withdraw/` request key. The actor is attribution only and is not proof of a user
action.

The newer observation and its issue-time fence commit with the identity session. If the
membership deadline crosses during issuance, the identity session can still commit and a
completed removal remains recorded. A normal identity, approval, proof, operation-deadline
or transaction failure retains the ADR 0013 issuance behavior. Committed evidence always
carries its expiry, including if commit acknowledgement is delayed. Failed verification
has no trusted subject against which to write.

## Current decisions and qualification

Use `membership::current` on the primary. Only `Present` confirms membership at the read
snapshot. The reader checks the enabled configuration and exact scoped assignment, current
mapping revision and confirmed v5 change and grant cycle. It also checks user status,
approval activity and expiry, the **provider authority epoch**, the **user session generation**
and the **approval access generation**. The provider epoch identifies the current durable
authority revision. The two generations fence local revocations. The reader uses the earliest
of signed token expiry, verifier age bound and owner age bound. Keep the primary and verifier
clocks synchronized. No fresh login means evidence expires, including during an outage.

V5 `recorded_active` and `mapping_eligible` can never establish current project membership
alone. V1-05 and queued-work consumers must require current membership evidence and their
own server-authoritative permission checks. Treat a read error as a failed observation.

Offline tests exercise signed claims and managed loopback TLS. The hosted PostgreSQL
suite exercises real exchanges, independent v5 writes, configuration and withdrawal
scripts, expiry, concurrent issuance, and independent provider approvals. The schema suite
uses authentic v10 binaries at 05dd18489242e545e3529b4e3750c74837b05638 for populated
upgrade and refusal checks. First-account invitations follow as migration 12
([home invitations](../operator/home-invitations.md)). Authentic v11 binaries at
0ab3401714762f28a730eae4cd7c91052648dabd qualify the populated upgrade from this schema and
refuse schema 12. An invited first sign-in has no enrollment and reconciles nothing. The
owner can then enroll and withdraw its approval like any other. Periodic directory collection,
provider qualification, native handoff and resource authorization remain separate work.
