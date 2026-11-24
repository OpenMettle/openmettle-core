# 0006 — Grant persistence and immutable provenance

Status: accepted with its implementation; V1-02 implementation contract, 17 November 2026. Related: core
#3 and sprint #34. Independent review and qualification remain required. This increment
adds migration 5 without changing released migrations 1–4. It exposes no product API.

## Scope and storage vocabulary

Four tables store project assignments and resource assignments for existing conversations
and artifacts. `assignment_format`, positive `assignment_version` and `assignment_key` are
opaque identifiers. No read/write/admin meanings, role precedence or permission policy is
assigned. Tests use `test.assignment` and synthetic values. Future V1-05 authorization must
reject unknown vocabulary rather than infer a permission.

- `grant_mapping_rules`: stable UUID, immutable provider-configuration UUID and exact issuer,
  creating internal actor, timestamp and current revision counter. The provider UUID is a
  provenance reference until a provider-configuration schema exists. It does not prove issuer
  trust or successful OIDC validation. Rebinding provider or issuer requires a new rule UUID.
- `grant_mapping_revisions`: append-only observations with `(rule_id, revision)` primary key,
  enabled flag, group/app-role selector, claim name/value, bounded versioned binding bytes,
  recording actor, request key, complete identity, digest and timestamp. Binding bytes record
  configuration; the helper does not interpret them or evaluate membership.
- `grant_assignments`: immutable scope, typed target, internal grantee, vocabulary and direct
  or mapped origin; creating actor/time and current change counter. Natural uniqueness includes
  scope, target kind/ID, grantee, vocabulary and mapping-rule UUID, with NULLs not distinct for
  direct assignments. Direct and multiple mapped sources remain independent.
- `grant_changes`: append-only changes, unique `(assignment_id, revision)` and
  `(scope_id, actor_user_id, request_key)`, with grant/revoke decision, cycle, mapping revision,
  actor, timestamp and exact request identity. Each grant's change UUID is its fresh cycle UUID.

An assignment requires exactly one non-NULL project/conversation/artifact UUID. Explicit CHECK
branches and typed composite FKs validate the resource in its scope. History also binds scope,
source kind, mapping rule/revision and cycle to the correct assignment. A cycle FK references
only a grant decision. Required nullable-branch fields are checked explicitly for non-NULL.
All FKs use NO ACTION. Tenant-leading indexes cover scope/target and scope/grantee assignment
lookups, replay and history. A mapping-rule/grantee index supports future reconciliation.

There are no unvalidated polymorphic resource IDs. Memory, tool and connection assignments
require future migrations with actual target tables and scoped FKs. The shared lifecycle
representation does not enable arbitrary new target kinds.

The grantee and actor reference stable internal users, never emails or directory claims.
The creator is provenance, not proof of authorization. Future automated reconciliation must
supply its explicitly defined internal actor; this increment invents no service account.
Resource ownership remains in the existing target row. A project's creator is not a complete
ownership-transfer model. A scope identifies accounting ownership, not publication or access.
Sharing never changes ownership, counters, limits, reservations or retained-byte charging.

## Inputs and identity

Strings are exact UTF-8 without normalization. Helpers reject NUL; PostgreSQL text also
rejects NUL. UUID arguments use lowercase canonical spelling.

| Input | Bound |
| --- | --- |
| Assignment/request/format identifiers and selector claim name | 1–128 bytes |
| Issuer | 1–2048 bytes |
| Selector value | 1–1024 bytes |
| Mapping binding payload | 0–16384 bytes |
| Format versions | Positive i32 |
| Expected revisions | 0 through i64::MAX−1; increment checked |
| Stored request identity | 1–32768 bytes |
| SHA-256 digest | Exactly 32 bytes |

Never include credentials, tokens or full claim documents. These are persistence bounds, not
measured sizing or final wire contracts. The identity repeats binding bytes; budget for both.

Reuse ADR 0004 encoding: fixed ASCII domain including trailing NUL, then each field's u64
big-endian byte length and exact bytes. Numbers are signed big-endian i32/i64 inside fields.
The digest is computed internally. Replay compares identity, digest and reconstructed immutable
fields, so the digest is not treated as a substitute for equality.

| Domain | Ordered fields |
| --- | --- |
| `openmettle/grant-mapping/1` | rule, provider, issuer, actor, request key, expected revision, enabled byte (0/1), selector kind, claim name, claim value, binding format, binding version, binding bytes |
| `openmettle/grant-change/1` | scope, target kind, target ID, grantee, assignment format, assignment version, assignment key, mapping rule or empty, mapping revision or zero, actor, request key, expected revision, decision, revoke cycle or empty |

Absence cannot collide with a valid UUID or positive mapping revision. Grant cycles are generated
inside the transaction, not supplied as grant input. The maximum mapping identity is 20,100 bytes
(27-byte domain, 13 length prefixes and 19,969 field bytes); the 32 KiB column bound accommodates
all legal mapping and change inputs without truncation. Unit tests calculate the actual maximum.

## Transactions, replay and stale observations

`record_mapping_revision` and `change_grant` borrow the existing `WriteTransaction` and use its
savepoint ownership protocol. Only the caller commits. Ordinary returned errors roll back the
helper savepoint and preserve previous caller writes. Cancellation at savepoint open, release or
rollback consumes the owner; cleanup failure never restores a commit-capable handle. Discard
uncertain connections. No raw nested transaction, new pool or dependency is introduced.

Use READ COMMITTED with bounded statement and lock deadlines. Lock the mapping rule first,
then the assignment. Read mapping revision data in a separate statement after obtaining its
lock. This avoids combining an updated counter with a pre-wait join snapshot. Multi-assignment
callers should use a consistent order; arbitrary composition can still deadlock. On 40P01, roll
back the entire transaction and retry its stable keys. Keep transactions short and perform no
external I/O while holding them. Existing run/storage composition constraints still apply.

Replay is checked before current revision/enabled checks and again after waiting for locks.
An equal replay returns its immutable historical receipt, even after revoke, regrant or mapping
disable. It does not alter state and does not imply current access. Changed input under the same
key conflicts. Global scope/actor request keys span assignments; INSERT ON CONFLICT DO NOTHING
and a subsequent statement inspect a concurrent winner without leaving an aborted transaction.
A losing different request rolls back its provisional assignment.

New changes compare the expected assignment revision under the assignment lock. Granting an
already recorded-active assignment conflicts. A grant from inactive state creates a fresh cycle.
Revoke names the current cycle and its original mapping revision, even after mapping disable or
replacement. Revoke with no cycle is valid only when recorded inactive; this permits an initial
revocation tombstone. Every new accepted change advances the revision, including an inactive
observation. Old expected revisions fail. Old cycle IDs cannot revoke a later regrant.

Mapping revisions have a separate `(rule, actor, request key)` replay namespace. New revisions
compare the rule counter, preserve provider/issuer binding and append immutable data. New mapped
grants require the current enabled mapping revision. Mapped revokes can bind an older existing
revision, so disabling or replacing a mapping cannot prevent cleanup. No automatic fan-out update
rewrites prior grants. Earlier mapping grants remain recorded but are no longer current candidates.
Direct grants and grants from other rules remain unaffected.

`read_assignment(scope, assignment_id)` uses one SQL statement snapshot. It returns recorded
activity and current mapping eligibility separately, plus the last change's cycle and revision.
A revoked row may retain its historical cycle. Mapping eligibility for direct assignments is true;
for mapped assignments it requires the last change's revision to match the current enabled mapping.
Neither field is authorization. A disabled user, missing resource permission or expired artifact
can still have recorded-active persistence state.

Database revision order is not directory freshness. A future reconciler must capture expected
revisions before observing upstream state. On a stale result it must establish freshness again,
not attach a new revision to old observations. Concurrent observations can have either commit
winner; no timestamp ordering or OIDC push guarantee is claimed. Upstream changes reconcile at
V1-04's configured bounded interval. Local disablement must take immediate effect at V1-05's
future authorization boundary, including sessions and queued execution.

After an unknown commit, replay the same key and bytes. Do not infer failure, change the key or
interpret an old receipt as permission. History and keys are retained; no deletion window or
retention service is introduced.

## Security and enforcement boundary

Project membership never publishes private conversations, artifacts or memory. Directory roles
and account administration never imply private-history access. No OIDC flow, mapping evaluator,
permission precedence, session service, queued-work cancellation, ownership transfer or quota
policy is implemented. RLS remains a future decision. Bounded process roles can read all scopes;
per-user denials must precede any product exposure.

API receives SELECT, explicit immutable-input INSERT columns and UPDATE only on the two revision
counters. Worker receives SELECT only on new tables. Neither receives immutable-column UPDATE,
history UPDATE, DELETE, TRUNCATE, DDL, grant options or function execution. Default privileges,
PUBLIC restrictions and existing role memberships remain unchanged.

SQL enforces typed references, uniqueness, required fields and column permissions. Helpers enforce
monotonic counters, transition order, exact replay and current mapping checks. Arbitrary API SQL
with counter UPDATE/INSERT privileges can bypass that protocol; this is not database-enforced
permission evaluation or fencing. History rows cannot be mutated by either application role.

For login-derived project membership, neither `recorded_active` nor `mapping_eligible`
establishes current membership. V1-05 and queued-work consumers also need the current
approval, signed observation, expiry and exact confirmed change described in
[ADR 0021](0021-project-membership.md).

## Migration, compatibility and verification

The new allowlist applies only after successful migration 5. The migrator keeps one dedicated
connection and its advisory lock across preflight, version steps and postflight. Failed migration
DDL/history rolls back; retry the unchanged release. Postflight over-grant refusal can occur after
commit, as in ADR 0003. Do not edit released migrations or delete history to recover.

CI builds authentic v4 binaries from d80e37819f847072dfa272bdddcc1fbee6d622ef with V4_BINARY_DIR,
alongside existing v2/v3 binaries. The old API/worker retain operational readiness after upgrade;
the old migrator must refuse without mutation, potentially at boundary preflight rather than
VersionMissing. These are test requirements, not a claim of observed CI success.

The aggregate pool budget remains the README/ADR 0003 formula, including surge replicas, one
migrator and administrative headroom. Grant lock waits occupy existing pool connections. No
connection-sizing, hot-rule throughput or production benchmark claim is made.

The grant schema suite covers independent provenance/cycles, mapping replacement, replay and
CAS races, direct SQL privileges and NULL/scoped-key denials, caller composition, deterministic
savepoint cancellation and lost commit acknowledgement. Migration tests cover failure, timeout,
SIGTERM/SIGKILL and concurrent retry. The populated v4 upgrade snapshots every existing domain,
including nonempty accounting limits/counters, and tests authentic prior binaries. Existing tests
remain required, as do repository, Rust, isolated PostgreSQL, image, kind and provenance checks.

V1-02 remains open until final-head evidence and independent review reconcile all acceptance.
V1-04 owns issuer validation, provider configuration and bounded membership reconciliation;
V1-05 owns authorization and effective-access invalidation; V1-15/16/17 own artifact delivery,
retention execution and quota services. None is claimed complete by this schema increment.
