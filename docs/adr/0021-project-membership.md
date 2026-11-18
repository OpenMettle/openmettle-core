# 0021 — Login-time project membership for approved identities

Proposed V1-04 increment for #5 and #34, based on schema 10.

## Enrollment

Migration 11 adds an empty enrollment and observation table. The primary key limits work to
one row for each existing exact identity approval. Both the direct managed issuance path and
the pooled browser service reach this operation. The running processes expose no new route.

1. Establish an existing enabled user, personal scope and exact provider/issuer/subject approval
   with the ADR 0013 procedure. Confirm that the provider UUID identifies the intended issuer
   and client. Verify with the provider operator that the chosen claim is a complete list of
   direct memberships for this client. A successful signing test alone cannot establish that
   directory contract.
2. Record an enabled v5 mapping revision for that provider and issuer. Select either
   `group` with `groups` or `app_role` with `roles`. Set the selector value to the exact
   directory identifier. Use binding format `openmettle.project-member`, version 1, and the
   ASCII bytes of the canonical lowercase project UUID as the binding.
3. As database owner, insert the inspected `approval_id`, `rule_id`, `rule_revision`,
   `project_id`, its `scope_id`, and `max_age_seconds` into
   `openmettle.membership_observations`. Leave the evidence columns null. The project/scope pair
   and mapping revision have foreign keys. Choose an age from 1 to 3600 seconds based on the
   deployment's membership freshness requirement. There is no default. The API role can
   update only the evidence columns. The worker has no access to the table.

Use a distinct rule and explicit enrollment for each independently managed mapping. Keep the
binding fixed. Disable or supersede the v5 rule to withdraw it. Before replacing enrollment,
retire the old mapped grant through the v5 revision and cycle protocol and retain its history.
Preserve the issue-time fence across reconfiguration. A replacement requires fresh evidence.
Apply the existing provider epoch advancement procedure after a database restore, before
reopening login. A previous epoch cannot produce a current decision.

## Decisions and ordering

After ordinary token verification, inspect the original signed payload with duplicate-member
detection. Compare claim values exactly. A complete array supports up to 128 distinct,
nonempty strings of up to 1024 bytes each. A missing claim yields missing evidence.
Wrong types, repeated values, control characters or ambiguous JSON yield ambiguous evidence.
An oversized list or distributed/overage marker yields partial evidence. The application
does not resolve a claim source or follow a destination in the token. Email, hosted domain
and external administrator role names have no special meaning.

Issuance checks the consumed login, current provider/client/epoch, exact approved identity,
approval expiry and enabled user under the existing locks. The transaction then locks the
enrollment and mapping rule. A complete match can create one typed project assignment.
A fresh complete absence revokes its active cycle. The assignment carries the rule,
revision and approval-specific key. The verified user is the actor who triggered the
observation. Direct grants and grants from other rules have independent assignment IDs.
Existing exact approval can still issue an identity session when group evidence is absent.

The primary stores the signed issue time even for a no-change or incomplete observation.
An older assertion cannot overwrite it. Conflicting decisions at the same issue time
produce ambiguity until a newer observation arrives. Matching repeats cannot extend the
original expiry or replay a withdrawn grant. Grant changes use the v5 revision and cycle
checks inside the session transaction. A failed transaction rolls back the fence and grant
together. An uncertain commit follows the existing issuance protocol. Restart login with a
fresh proof. Failed token verification has no trusted subject against which to write.

Read current evidence with `membership::current` on a primary connection. It checks the
approval, user and provider generations, enabled current rule, exact project, issue time,
expiry and mapped grant at one database snapshot. Only `Present` confirms membership.
A committed incomplete observation immediately withholds confirmation without recording a
directory removal. A failed exchange or rolled-back issuance cannot replace the prior
observation. Its original expiry still applies. The earlier v5 grant can remain recorded. Treat a read error as a failed observation.
Keep the verifier clock and primary clock synchronized. The reader uses the earliest of
the token expiry, verifier age bound and owner age bound. Reconciliation happens during
successful login. Without a fresh login the evidence expires, even during a provider outage.

## Qualification and remaining decisions

The offline signed-token test covers both selectors, wrong nonce, missing, malformed, overage
and mixed-type claims. A loopback TLS test passes synthetic group and overage assertions through
the managed code exchange. Hosted PostgreSQL tests exercise the exchange, session, scoped
assignment history, concurrent removal, rollback and current decision. The schema suite builds the authentic
v10 binaries from 05dd18489242e545e3529b4e3750c74837b05638 for populated upgrade and refusal
checks. Hosted execution and independent review are required before integration.

This increment supplies no periodic directory collector, invitation delivery, new-account
creation or resource authorization. Before extending group admission to automatic creation,
decide which owner policy authorizes creation of the first identity and personal scope, how
to resolve concurrent first logins, and how withdrawal affects sessions and owned resources.
Provider-specific completeness, nested groups and native handoff require separate qualification.
